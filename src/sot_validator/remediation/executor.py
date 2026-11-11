"""Phase 2 approval-gated SoT remediation executor, reversible SQL generator, and rollback journal."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Optional
import uuid

from sot_validator.extraction.batch import SnapshotStore
from sot_validator.models import (
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineManifestEntry,
    RemediationApprovalManifest,
    RemediationOperation,
    _coerce_remediation_operation,
)
from sot_validator.remediation.sink import _resolve_plan_timestamp


class RemediationExecutionError(Exception):
    """Raised when remediation execution gates fail or an unapproved/invalid action is requested."""


class ManifestVerificationError(RemediationExecutionError):
    """Raised when a RemediationApprovalManifest fails SHA-256 digest verification."""


class _UnknownExecutionIdError(RemediationExecutionError, KeyError):
    """Raised when an execution_id is not found in the rollback journal."""


_TABLE_SQL_COLUMNS: dict[str, tuple[str, ...]] = {
    "equipment": (
        "equipment_id",
        "site_id",
        "hostname",
        "equipment_type",
        "vendor",
        "model",
        "primary_ip",
        "mac_address",
        "vcenter_instance",
        "vcenter_bios_uuid",
        "vcenter_moref",
        "connected_port_id",
        "last_seen",
        "status",
    ),
    "network_devices": (
        "device_id",
        "site_id",
        "hostname",
        "vendor",
        "model",
        "role",
        "mgmt_ip",
        "mac_address",
        "room",
        "os_version",
        "serial_number",
        "last_seen",
        "status",
    ),
    "ip_arp_entries": (
        "ip_id",
        "site_id",
        "subnet_id",
        "ip_address",
        "mac_address",
        "assigned_target_type",
        "assigned_target_id",
        "arp_last_seen",
        "arp_source_device_id",
        "status",
    ),
    "ports": (
        "port_id",
        "device_id",
        "port_name",
        "if_index",
        "admin_status",
        "oper_status",
        "poe_status",
        "poe_power_w",
        "vlan_id",
        "connected_equipment_id",
        "connected_mac",
        "description",
        "last_change",
        "status",
    ),
}

_TABLE_ORDER: tuple[str, ...] = (
    "equipment",
    "network_devices",
    "ip_arp_entries",
    "ports",
)


def _format_sql_datetime(value: Optional[datetime | str]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    iso = value.isoformat()
    if iso.endswith("+00:00"):
        return iso[:-6] + "Z"
    return iso


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, datetime):
        formatted = _format_sql_datetime(value) or ""
        return "'" + formatted.replace("'", "''") + "'"
    if isinstance(value, Enum):
        return "'" + str(value.value).replace("'", "''") + "'"
    return "'" + str(value).replace("'", "''") + "'"


def _resolve_target_table(
    item_type: str, operation: RemediationOperation
) -> str:
    norm_type = re.sub(r"[^a-z0-9]+", "", item_type.lower())
    if (
        norm_type in ("ipaddress", "ip", "iparpentry", "iparpentries")
        or operation is RemediationOperation.RECLAIM_STALE_IP
    ):
        return "ip_arp_entries"
    if (
        norm_type in ("port", "ports", "switchport")
        or operation is RemediationOperation.PROPOSE_PORT_SHUTDOWN
    ):
        return "ports"
    if norm_type in ("networkdevice", "device", "switch", "router"):
        return "network_devices"
    if norm_type in (
        "equipment",
        "vm",
        "virtualmachine",
        "server",
        "san",
        "nas",
        "ups",
    ) or operation in (
        RemediationOperation.FLAG_STALE_IN_SOT,
        RemediationOperation.DECOMMISSION_VM_RECORD,
    ):
        return "equipment"
    raise RemediationExecutionError(
        f"Unsupported item_type={item_type!r} (operation={operation.value!r}) for SQL remediation"
    )


@dataclass(init=False)
class RollbackJournalEntry:
    """Single audit and rollback record persisted in the append-only remediation journal."""

    execution_id: str
    executed_at: datetime
    reviewer: str
    item_type: str
    item_id: str
    site_id: str
    operation: RemediationOperation
    pre_change_snapshot: dict[str, Any]
    post_change_state: dict[str, Any]
    rollback_sql: str

    def __init__(
        self,
        execution_id: str,
        executed_at: Optional[datetime | str] = None,
        reviewer: Optional[str] = None,
        item_type: str = "",
        item_id: str = "",
        site_id: str = "",
        operation: RemediationOperation | str = RemediationOperation.FLAG_STALE_IN_SOT,
        pre_change_snapshot: Optional[Mapping[str, Any]] = None,
        post_change_state: Optional[Mapping[str, Any]] = None,
        rollback_sql: str = "",
        *,
        target_operation: Optional[RemediationOperation | str] = None,
    ) -> None:
        self.execution_id = _require_non_empty_str(
            execution_id, "execution_id"
        ).strip()
        self.executed_at = _resolve_plan_timestamp(executed_at)
        resolved_reviewer = reviewer if reviewer is not None else "system"
        self.reviewer = _require_non_empty_str(
            resolved_reviewer, "reviewer"
        ).strip()
        self.item_type = _require_non_empty_str(item_type, "item_type").strip()
        self.item_id = _require_non_empty_str(item_id, "item_id").strip()
        self.site_id = _require_non_empty_str(site_id, "site_id").strip()
        op_raw = target_operation if target_operation is not None else operation
        self.operation = _coerce_remediation_operation(op_raw, "operation")
        if pre_change_snapshot is None or not isinstance(
            pre_change_snapshot, Mapping
        ):
            raise ValueError("pre_change_snapshot must be a mapping")
        if post_change_state is None or not isinstance(
            post_change_state, Mapping
        ):
            raise ValueError("post_change_state must be a mapping")
        self.pre_change_snapshot = dict(pre_change_snapshot)
        self.post_change_state = dict(post_change_state)
        self.rollback_sql = _require_non_empty_str(
            rollback_sql, "rollback_sql"
        ).strip()

    @property
    def target_operation(self) -> RemediationOperation:
        """Alias for operation."""
        return self.operation

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "executed_at": _format_optional_datetime(self.executed_at),
            "reviewer": self.reviewer,
            "item_type": self.item_type,
            "item_id": self.item_id,
            "site_id": self.site_id,
            "operation": self.operation.value,
            "pre_change_snapshot": dict(self.pre_change_snapshot),
            "post_change_state": dict(self.post_change_state),
            "rollback_sql": self.rollback_sql,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RollbackJournalEntry:
        op_val = data.get("operation") or data.get("target_operation")
        if op_val is None:
            raise ValueError("Missing operation in RollbackJournalEntry data")
        return cls(
            execution_id=data["execution_id"],
            executed_at=_parse_optional_datetime(
                data.get("executed_at"), "executed_at"
            ),
            reviewer=data.get("reviewer") or "system",
            item_type=data["item_type"],
            item_id=data["item_id"],
            site_id=data["site_id"],
            operation=op_val,
            pre_change_snapshot=data.get("pre_change_snapshot", {}),
            post_change_state=data.get("post_change_state", {}),
            rollback_sql=data["rollback_sql"],
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> RollbackJournalEntry:
        return cls.from_dict(json.loads(raw))


class RollbackPlan(str):
    """Transaction-wrapped rollback SQL script with journal entries and pre-change snapshots."""

    execution_id: str
    entries: list[RollbackJournalEntry]
    rollback_sql: str
    pre_change_snapshots: list[dict[str, Any]]

    def __new__(
        cls,
        rollback_sql_or_execution_id: str = "",
        *,
        execution_id: Optional[str] = None,
        entries: Optional[Sequence[RollbackJournalEntry]] = None,
        rollback_sql: Optional[str] = None,
        pre_change_snapshots: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> RollbackPlan:
        if rollback_sql is not None:
            sql_str = rollback_sql
            exec_id = (
                execution_id
                if execution_id is not None
                else rollback_sql_or_execution_id
            )
        else:
            sql_str = rollback_sql_or_execution_id
            exec_id = execution_id or ""

        resolved_entries = list(entries) if entries is not None else []
        if not exec_id and resolved_entries:
            exec_id = resolved_entries[0].execution_id

        instance = super().__new__(cls, sql_str)
        instance.execution_id = exec_id
        instance.entries = resolved_entries
        instance.rollback_sql = sql_str
        if pre_change_snapshots is not None:
            instance.pre_change_snapshots = [
                dict(s) for s in pre_change_snapshots
            ]
        else:
            instance.pre_change_snapshots = [
                dict(e.pre_change_snapshot) for e in resolved_entries
            ]
        return instance

    @property
    def sql(self) -> str:
        """Alias for rollback_sql."""
        return self.rollback_sql

    @property
    def statements(self) -> list[str]:
        """Individual per-item rollback SQL statements in execution order of the plan."""
        return [e.rollback_sql for e in self.entries]

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "rollback_sql": self.rollback_sql,
            "entries": [e.to_dict() for e in self.entries],
            "pre_change_snapshots": [dict(s) for s in self.pre_change_snapshots],
        }


def _build_rollback_transaction_sql(
    entries_in_reverse_order: Sequence[RollbackJournalEntry],
) -> str:
    lines: list[str] = ["BEGIN TRANSACTION;"]
    tables_to_drop_status: list[str] = []

    for entry in entries_in_reverse_order:
        stmt = entry.rollback_sql.strip()
        if not stmt.endswith(";"):
            stmt += ";"
        lines.append(stmt)
        table = _resolve_target_table(entry.item_type, entry.operation)
        if (
            "status" not in entry.pre_change_snapshot
            and table not in tables_to_drop_status
        ):
            tables_to_drop_status.append(table)

    for table in tables_to_drop_status:
        lines.append(f"ALTER TABLE {table} DROP COLUMN status;")

    lines.append("COMMIT;")
    return "\n".join(lines) + "\n"


class RollbackJournal:
    """Append-only JSONL journal (`remediation_journal.jsonl`) for remediation audit and rollback."""

    DEFAULT_FILENAME = "remediation_journal.jsonl"

    def __init__(
        self,
        journal_path: Path | str = Path(DEFAULT_FILENAME),
    ) -> None:
        candidate = Path(journal_path)
        if candidate.exists() and candidate.is_dir():
            self.journal_path = candidate / self.DEFAULT_FILENAME
        else:
            self.journal_path = candidate

    @property
    def path(self) -> Path:
        """Alias for journal_path."""
        return self.journal_path

    def append(self, entry: RollbackJournalEntry) -> RollbackJournalEntry:
        """Append a single RollbackJournalEntry to the JSONL journal file."""
        if not isinstance(entry, RollbackJournalEntry):
            entry = RollbackJournalEntry.from_dict(entry)
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(entry.to_json(indent=None) + "\n")
        return entry

    def record(self, entry: RollbackJournalEntry) -> RollbackJournalEntry:
        """Alias for append()."""
        return self.append(entry)

    def append_entries(
        self, entries: Iterable[RollbackJournalEntry]
    ) -> list[RollbackJournalEntry]:
        """Append multiple RollbackJournalEntry items atomically in append-only mode."""
        normalized: list[RollbackJournalEntry] = [
            e
            if isinstance(e, RollbackJournalEntry)
            else RollbackJournalEntry.from_dict(e)
            for e in entries
        ]
        if not normalized:
            return []
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8") as handle:
            for entry in normalized:
                handle.write(entry.to_json(indent=None) + "\n")
        return normalized

    def read_entries(
        self, execution_id: Optional[str] = None
    ) -> list[RollbackJournalEntry]:
        """Read all journal entries from disk, optionally filtered by execution_id."""
        if not self.journal_path.exists():
            return []
        entries: list[RollbackJournalEntry] = []
        with self.journal_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                entry = RollbackJournalEntry.from_json(stripped)
                if execution_id is None or entry.execution_id == execution_id:
                    entries.append(entry)
        return entries

    def list_entries(
        self, execution_id: Optional[str] = None
    ) -> list[RollbackJournalEntry]:
        """Alias for read_entries()."""
        return self.read_entries(execution_id=execution_id)

    def get_entries(
        self, execution_id: Optional[str] = None
    ) -> list[RollbackJournalEntry]:
        """Alias for read_entries()."""
        return self.read_entries(execution_id=execution_id)

    def generate_rollback_plan(self, execution_id: str) -> RollbackPlan:
        """Generate a transaction-wrapped RollbackPlan restoring all items from execution_id."""
        if not isinstance(execution_id, str) or not execution_id.strip():
            raise RemediationExecutionError(
                "execution_id must be a non-empty string"
            )
        clean_id = execution_id.strip()
        matching = self.read_entries(execution_id=clean_id)
        if not matching:
            raise _UnknownExecutionIdError(
                f"No rollback journal entries found for execution_id={clean_id!r}"
            )
        reversed_entries = list(reversed(matching))
        rollback_sql = _build_rollback_transaction_sql(reversed_entries)
        return RollbackPlan(
            rollback_sql,
            execution_id=clean_id,
            entries=reversed_entries,
            pre_change_snapshots=[
                dict(e.pre_change_snapshot) for e in reversed_entries
            ],
        )


@dataclass
class SqlRemediationScripts:
    """Paired forward (`remediate.sql`) and reverse (`rollback.sql`) SQL scripts."""

    remediate_sql: str
    rollback_sql: str
    entries: list[QuarantineManifestEntry] = field(default_factory=list)
    journal_entries: list[RollbackJournalEntry] = field(default_factory=list)

    def __iter__(self) -> Iterator[str]:
        yield self.remediate_sql
        yield self.rollback_sql

    def write_scripts(
        self,
        output_dir: Path | str,
        *,
        remediate_filename: str = "remediate.sql",
        rollback_filename: str = "rollback.sql",
    ) -> tuple[Path, Path]:
        """Write remediate.sql and rollback.sql to output_dir and return their Paths."""
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        remediate_path = target_dir / remediate_filename
        rollback_path = target_dir / rollback_filename
        remediate_path.write_text(self.remediate_sql, encoding="utf-8")
        rollback_path.write_text(self.rollback_sql, encoding="utf-8")
        return remediate_path, rollback_path

    def to_dict(self) -> dict[str, Any]:
        return {
            "remediate_sql": self.remediate_sql,
            "rollback_sql": self.rollback_sql,
            "entries": [e.to_dict() for e in self.entries],
            "journal_entries": [j.to_dict() for j in self.journal_entries],
        }


def _normalize_sites_lookup(
    sites: Optional[Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]],
) -> dict[str, Site]:
    if sites is None:
        return {}
    if isinstance(sites, Site):
        return {sites.site_id: sites}
    if isinstance(sites, Mapping):
        if "site_id" in sites and "name" in sites:
            site_obj = Site.from_dict(sites)
            return {site_obj.site_id: site_obj}
        result: dict[str, Site] = {}
        for key, val in sites.items():
            if isinstance(val, Site):
                result[val.site_id] = val
            elif isinstance(val, Mapping) and "site_id" in val:
                site_obj = Site.from_dict(val)
                result[site_obj.site_id] = site_obj
            else:
                raise ValueError(f"Unsupported site mapping value for {key!r}")
        return result
    if isinstance(sites, Sequence) and not isinstance(sites, (str, bytes)):
        result = {}
        for item in sites:
            site_obj = item if isinstance(item, Site) else Site.from_dict(item)
            result[site_obj.site_id] = site_obj
        return result
    raise ValueError(f"Unsupported sites argument: {type(sites)!r}")


def _validate_and_filter_manifest_entries(
    manifest: RemediationApprovalManifest,
    *,
    strict_approval: bool = False,
) -> tuple[list[QuarantineManifestEntry], list[QuarantineManifestEntry]]:
    if not isinstance(manifest, RemediationApprovalManifest):
        raise ManifestVerificationError(
            "manifest must be a RemediationApprovalManifest instance"
        )
    if not manifest.verify_digest():
        raise ManifestVerificationError(
            f"Manifest {manifest.manifest_id!r} failed SHA-256 digest verification; "
            "manifest content or signature has been tampered with"
        )

    if strict_approval:
        unapproved = [
            e
            for e in manifest.entries
            if e.approval_status not in (ApprovalStatus.APPROVED, ApprovalStatus.EXEMPT)
        ]
        if unapproved:
            ids = ", ".join(e.item_id for e in unapproved)
            raise RemediationExecutionError(
                f"Manifest {manifest.manifest_id!r} contains unapproved entries under strict_approval=True: {ids}"
            )

    approved = [
        e
        for e in manifest.entries
        if e.approval_status is ApprovalStatus.APPROVED
    ]
    skipped = [
        e
        for e in manifest.entries
        if e.approval_status is not ApprovalStatus.APPROVED
    ]
    if not approved:
        raise RemediationExecutionError(
            f"Manifest {manifest.manifest_id!r} has no APPROVED entries to execute"
        )

    approved.sort(key=lambda e: (e.site_id, e.item_type, e.item_id))
    return approved, skipped


def _table_has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cursor = conn.execute(f'PRAGMA table_info("{table}")')
    for row in cursor.fetchall():
        col_name = row[1] if not isinstance(row, sqlite3.Row) else row["name"]
        if str(col_name).lower() == column.lower():
            return True
    return False


def _query_sqlite_snapshot(
    conn: sqlite3.Connection,
    table: str,
    entry: QuarantineManifestEntry,
) -> dict[str, Any]:
    if table == "equipment":
        cursor = conn.execute(
            "SELECT * FROM equipment WHERE equipment_id = ? AND site_id = ?",
            (entry.item_id, entry.site_id),
        )
    elif table == "network_devices":
        cursor = conn.execute(
            "SELECT * FROM network_devices WHERE device_id = ? AND site_id = ?",
            (entry.item_id, entry.site_id),
        )
    elif table == "ip_arp_entries":
        cursor = conn.execute(
            "SELECT * FROM ip_arp_entries WHERE site_id = ? AND (ip_id = ? OR ip_address = ?)",
            (entry.site_id, entry.item_id, entry.item_id),
        )
    elif table == "ports":
        cursor = conn.execute(
            "SELECT * FROM ports WHERE port_id = ?",
            (entry.item_id,),
        )
    else:
        raise RemediationExecutionError(f"Unsupported SQL table: {table!r}")

    row = cursor.fetchone()
    if row is None:
        raise RemediationExecutionError(
            f"Target {entry.item_type} {entry.item_id!r} in site {entry.site_id!r} not found in table {table!r}"
        )
    col_names = [desc[0] for desc in cursor.description]
    return dict(zip(col_names, row))


def _resolve_site_snapshot(
    sites_by_id: Mapping[str, Site],
    table: str,
    entry: QuarantineManifestEntry,
) -> dict[str, Any]:
    site = sites_by_id.get(entry.site_id)
    if site is None:
        raise RemediationExecutionError(
            f"Site {entry.site_id!r} not found in provided sites for item {entry.item_id!r}"
        )

    if table == "equipment":
        for eq in site.equipment:
            if eq.equipment_id == entry.item_id:
                snap: dict[str, Any] = {
                    "equipment_id": eq.equipment_id,
                    "site_id": eq.site_id,
                    "hostname": eq.name,
                    "name": eq.name,
                    "category": eq.category.value,
                    "assigned_ips": list(eq.assigned_ips),
                    "connected_ports": list(eq.connected_ports),
                    "hypervisor_id": eq.hypervisor_id,
                    "power_state": eq.power_state,
                    "last_seen": _format_sql_datetime(eq.last_seen),
                }
                if eq.assigned_ips:
                    snap["primary_ip"] = eq.assigned_ips[0]
                if eq.connected_ports:
                    snap["connected_port_id"] = eq.connected_ports[0]
                if eq.hypervisor_id is not None:
                    snap["vcenter_instance"] = eq.hypervisor_id
                return snap
        raise RemediationExecutionError(
            f"Equipment {entry.item_id!r} not found in site {entry.site_id!r}"
        )

    if table == "network_devices":
        for dev in site.devices:
            if dev.device_id == entry.item_id:
                snap = {
                    "device_id": dev.device_id,
                    "site_id": dev.site_id,
                    "hostname": dev.hostname,
                    "management_ip": dev.management_ip,
                    "vendor": dev.vendor,
                    "model": dev.model,
                    "role": dev.role,
                    "last_seen": _format_sql_datetime(dev.last_seen),
                }
                if dev.management_ip is not None:
                    snap["mgmt_ip"] = dev.management_ip
                return snap
        raise RemediationExecutionError(
            f"NetworkDevice {entry.item_id!r} not found in site {entry.site_id!r}"
        )

    if table == "ip_arp_entries":
        matched_ip: Optional[IPAddress] = None
        for ip_obj in site.ip_addresses:
            if ip_obj.ip == entry.item_id or ip_obj.ip == entry.name:
                matched_ip = ip_obj
                break
        if matched_ip is None:
            idx_match = re.match(r"^ip-[^-]+-(\d+)$", entry.item_id)
            if idx_match:
                idx = int(idx_match.group(1)) - 1
                if 0 <= idx < len(site.ip_addresses):
                    matched_ip = site.ip_addresses[idx]
        if matched_ip is None:
            for ip_obj in site.ip_addresses:
                if ip_obj.assigned_object_id == entry.item_id:
                    matched_ip = ip_obj
                    break
        if matched_ip is None:
            raise RemediationExecutionError(
                f"IPAddress {entry.item_id!r} not found in site {entry.site_id!r}"
            )
        snap = {
            "site_id": site.site_id,
            "subnet_id": matched_ip.subnet_id,
            "ip": matched_ip.ip,
            "ip_address": matched_ip.ip,
            "mac_address": matched_ip.arp_mac,
            "arp_mac": matched_ip.arp_mac,
            "assigned_object_type": matched_ip.assigned_object_type,
            "assigned_object_id": matched_ip.assigned_object_id,
            "assigned_target_type": matched_ip.assigned_object_type or "unassigned",
            "assigned_target_id": matched_ip.assigned_object_id or "",
            "arp_last_seen": _format_sql_datetime(matched_ip.arp_last_seen),
            "arp_source_device_id": matched_ip.arp_source_device_id,
        }
        if entry.item_id.startswith("ip-"):
            snap["ip_id"] = entry.item_id
        return snap

    if table == "ports":
        for dev in site.devices:
            for port in dev.ports:
                if port.port_id == entry.item_id:
                    vlan_val: Any = port.vlan_id
                    if isinstance(vlan_val, str) and vlan_val.isdigit():
                        vlan_val = int(vlan_val)
                    return {
                        "port_id": port.port_id,
                        "device_id": port.device_id,
                        "name": port.name,
                        "port_name": port.name,
                        "admin_status": port.admin_status or "up",
                        "oper_status": port.oper_status,
                        "poe_status": port.poe_status,
                        "vlan_id": vlan_val,
                        "connected_device_id": port.connected_device_id,
                        "connected_equipment_id": port.connected_device_id,
                        "connected_mac": port.connected_mac,
                    }
        raise RemediationExecutionError(
            f"Port {entry.item_id!r} not found in site {entry.site_id!r}"
        )

    raise RemediationExecutionError(f"Unsupported table: {table!r}")


def _resolve_fallback_snapshot(
    table: str, entry: QuarantineManifestEntry
) -> dict[str, Any]:
    if table == "equipment":
        snap: dict[str, Any] = {
            "equipment_id": entry.item_id,
            "site_id": entry.site_id,
        }
        if entry.name and entry.name != entry.item_id:
            snap["hostname"] = entry.name
        return snap
    if table == "network_devices":
        snap = {
            "device_id": entry.item_id,
            "site_id": entry.site_id,
        }
        if entry.name and entry.name != entry.item_id:
            snap["hostname"] = entry.name
        return snap
    if table == "ip_arp_entries":
        snap = {
            "site_id": entry.site_id,
            "assigned_target_type": "equipment",
            "assigned_target_id": (
                entry.name if entry.name and entry.name != entry.item_id else ""
            ),
        }
        if entry.item_id.startswith("ip-"):
            snap["ip_id"] = entry.item_id
        else:
            snap["ip_address"] = entry.item_id
        return snap
    if table == "ports":
        snap = {
            "port_id": entry.item_id,
            "admin_status": "up",
        }
        if entry.name and entry.name != entry.item_id:
            snap["port_name"] = entry.name
        return snap
    raise RemediationExecutionError(f"Unsupported table: {table!r}")


def _build_remediate_and_rollback_row_sql(
    table: str,
    entry: QuarantineManifestEntry,
    pre_snapshot: Mapping[str, Any],
    *,
    from_sqlite: bool,
) -> tuple[str, str, dict[str, Any]]:
    site_lit = _sql_literal(entry.site_id)
    item_lit = _sql_literal(entry.item_id)

    if table == "equipment":
        where_clause = f"equipment_id = {item_lit} AND site_id = {site_lit}"
        remediate_stmt = (
            f"UPDATE equipment SET status = 'QUARANTINED_STALE' WHERE {where_clause};"
        )
        post_state = {**pre_snapshot, "status": "QUARANTINED_STALE"}
    elif table == "network_devices":
        where_clause = f"device_id = {item_lit} AND site_id = {site_lit}"
        remediate_stmt = (
            f"UPDATE network_devices SET status = 'QUARANTINED_STALE' WHERE {where_clause};"
        )
        post_state = {**pre_snapshot, "status": "QUARANTINED_STALE"}
    elif table == "ip_arp_entries":
        where_clause = (
            f"site_id = {site_lit} AND (ip_id = {item_lit} OR ip_address = {item_lit})"
        )
        remediate_stmt = (
            "UPDATE ip_arp_entries SET status = 'AVAILABLE_RECLAIMED', "
            f"assigned_target_type = 'unassigned', assigned_target_id = '' WHERE {where_clause};"
        )
        post_state = {
            **pre_snapshot,
            "status": "AVAILABLE_RECLAIMED",
            "assigned_target_type": "unassigned",
            "assigned_target_id": "",
        }
        if "assigned_object_type" in post_state:
            post_state["assigned_object_type"] = "unassigned"
        if "assigned_object_id" in post_state:
            post_state["assigned_object_id"] = ""
    elif table == "ports":
        where_clause = f"port_id = {item_lit}"
        remediate_stmt = (
            f"UPDATE ports SET admin_status = 'down', status = 'QUARANTINED_STALE' WHERE {where_clause};"
        )
        post_state = {
            **pre_snapshot,
            "admin_status": "down",
            "status": "QUARANTINED_STALE",
        }
    else:
        raise RemediationExecutionError(f"Unsupported table: {table!r}")

    allowed_cols = _TABLE_SQL_COLUMNS[table]
    ordered_cols: list[str] = [c for c in allowed_cols if c in pre_snapshot]
    if from_sqlite:
        for extra_col in pre_snapshot:
            if extra_col not in ordered_cols:
                ordered_cols.append(extra_col)

    assignments: list[str] = []
    for col in ordered_cols:
        val = pre_snapshot[col]
        if not from_sqlite and val is None:
            continue
        assignments.append(f"{col} = {_sql_literal(val)}")

    if not assignments:
        if table == "equipment":
            assignments.append(f"equipment_id = {item_lit}")
        elif table == "network_devices":
            assignments.append(f"device_id = {item_lit}")
        elif table == "ip_arp_entries":
            assignments.append(f"site_id = {site_lit}")
        elif table == "ports":
            assignments.append(f"port_id = {item_lit}")

    set_clause = ", ".join(assignments)
    rollback_stmt = f"UPDATE {table} SET {set_clause} WHERE {where_clause};"
    return remediate_stmt, rollback_stmt, post_state


class SqlRemediationScriptGenerator:
    """Generates transaction-wrapped paired `remediate.sql` and `rollback.sql` scripts."""

    def generate(
        self,
        manifest: RemediationApprovalManifest,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        *,
        sqlite_conn: Optional[sqlite3.Connection] = None,
        execution_id: Optional[str] = None,
        executed_at: Optional[datetime | str] = None,
        reviewer: Optional[str] = None,
        strict_approval: bool = False,
    ) -> SqlRemediationScripts:
        """Build deterministic forward and rollback SQL scripts from an approved manifest."""
        approved_entries, _ = _validate_and_filter_manifest_entries(
            manifest, strict_approval=strict_approval
        )
        sites_by_id = _normalize_sites_lookup(sites)
        resolved_exec_id = (
            _require_non_empty_str(execution_id, "execution_id").strip()
            if execution_id is not None
            else f"exec-{uuid.uuid4().hex[:12]}"
        )
        resolved_executed_at = _resolve_plan_timestamp(executed_at)

        tables_needing_status_col: list[str] = []
        remediate_updates: list[str] = []
        journal_entries: list[RollbackJournalEntry] = []

        for entry in approved_entries:
            table = _resolve_target_table(entry.item_type, entry.target_operation)
            from_sqlite = False
            if sqlite_conn is not None:
                pre_snapshot = _query_sqlite_snapshot(sqlite_conn, table, entry)
                from_sqlite = True
            elif sites is not None:
                pre_snapshot = _resolve_site_snapshot(sites_by_id, table, entry)
            else:
                pre_snapshot = _resolve_fallback_snapshot(table, entry)

            if (
                "status" not in pre_snapshot
                and table not in tables_needing_status_col
            ):
                if sqlite_conn is None or not _table_has_column(
                    sqlite_conn, table, "status"
                ):
                    tables_needing_status_col.append(table)

            remediate_stmt, rollback_stmt, post_state = (
                _build_remediate_and_rollback_row_sql(
                    table, entry, pre_snapshot, from_sqlite=from_sqlite
                )
            )
            remediate_updates.append(remediate_stmt)

            entry_reviewer = (
                reviewer
                or entry.reviewed_by
                or "system"
            )
            journal_entries.append(
                RollbackJournalEntry(
                    execution_id=resolved_exec_id,
                    executed_at=resolved_executed_at,
                    reviewer=entry_reviewer,
                    item_type=entry.item_type,
                    item_id=entry.item_id,
                    site_id=entry.site_id,
                    operation=entry.target_operation,
                    pre_change_snapshot=pre_snapshot,
                    post_change_state=post_state,
                    rollback_sql=rollback_stmt,
                )
            )

        remediate_lines: list[str] = ["BEGIN TRANSACTION;"]
        for table in tables_needing_status_col:
            remediate_lines.append(
                f"ALTER TABLE {table} ADD COLUMN status TEXT DEFAULT 'ACTIVE';"
            )
        remediate_lines.extend(remediate_updates)
        remediate_lines.append("COMMIT;")
        remediate_sql = "\n".join(remediate_lines) + "\n"

        rollback_sql = _build_rollback_transaction_sql(
            list(reversed(journal_entries))
        )

        return SqlRemediationScripts(
            remediate_sql=remediate_sql,
            rollback_sql=rollback_sql,
            entries=approved_entries,
            journal_entries=journal_entries,
        )

    def generate_scripts(
        self,
        manifest: RemediationApprovalManifest,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        **kwargs: Any,
    ) -> SqlRemediationScripts:
        """Alias for generate()."""
        return self.generate(manifest, sites=sites, **kwargs)


@dataclass
class RemediationExecutionResult:
    """Outcome summary and artifacts produced by RemediationExecutor.execute()."""

    execution_id: str
    manifest_id: str
    executed_at: datetime
    dry_run: bool
    executed_entries: list[QuarantineManifestEntry]
    skipped_entries: list[QuarantineManifestEntry]
    journal_entries: list[RollbackJournalEntry]
    remediate_sql: str
    rollback_sql: str
    remediate_sql_path: Optional[Path] = None
    rollback_sql_path: Optional[Path] = None
    journal_path: Optional[Path] = None

    @property
    def approved_entries(self) -> list[QuarantineManifestEntry]:
        """Alias for executed_entries."""
        return self.executed_entries

    @property
    def applied_count(self) -> int:
        """Number of approved entries processed."""
        return len(self.executed_entries)

    @property
    def skipped_count(self) -> int:
        """Number of non-approved entries skipped."""
        return len(self.skipped_entries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "manifest_id": self.manifest_id,
            "executed_at": _format_optional_datetime(self.executed_at),
            "dry_run": self.dry_run,
            "applied_count": len(self.executed_entries),
            "skipped_count": len(self.skipped_entries),
            "executed_entries": [e.to_dict() for e in self.executed_entries],
            "skipped_entries": [e.to_dict() for e in self.skipped_entries],
            "journal_entries": [j.to_dict() for j in self.journal_entries],
            "remediate_sql": self.remediate_sql,
            "rollback_sql": self.rollback_sql,
            "remediate_sql_path": (
                str(self.remediate_sql_path)
                if self.remediate_sql_path is not None
                else None
            ),
            "rollback_sql_path": (
                str(self.rollback_sql_path)
                if self.rollback_sql_path is not None
                else None
            ),
            "journal_path": (
                str(self.journal_path)
                if self.journal_path is not None
                else None
            ),
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _apply_remediation_to_site(
    site: Site, entry: QuarantineManifestEntry
) -> None:
    table = _resolve_target_table(entry.item_type, entry.target_operation)
    if table == "equipment":
        for eq in site.equipment:
            if eq.equipment_id == entry.item_id:
                eq.power_state = "QUARANTINED_STALE"
                return
    elif table == "network_devices":
        for dev in site.devices:
            if dev.device_id == entry.item_id:
                dev.role = "QUARANTINED_STALE"
                return
    elif table == "ip_arp_entries":
        for ip_obj in site.ip_addresses:
            if ip_obj.ip == entry.item_id or ip_obj.ip == entry.name:
                ip_obj.assigned_object_type = "unassigned"
                ip_obj.assigned_object_id = ""
                return
        idx_match = re.match(r"^ip-[^-]+-(\d+)$", entry.item_id)
        if idx_match:
            idx = int(idx_match.group(1)) - 1
            if 0 <= idx < len(site.ip_addresses):
                site.ip_addresses[idx].assigned_object_type = "unassigned"
                site.ip_addresses[idx].assigned_object_id = ""
                return
    elif table == "ports":
        for dev in site.devices:
            for port in dev.ports:
                if port.port_id == entry.item_id:
                    port.admin_status = "down"
                    return


def _restore_site_from_journal_entry(
    site: Site, entry: RollbackJournalEntry
) -> None:
    table = _resolve_target_table(entry.item_type, entry.operation)
    snap = entry.pre_change_snapshot
    if table == "equipment":
        for eq in site.equipment:
            if eq.equipment_id == entry.item_id:
                eq.power_state = snap.get("power_state")
                if "name" in snap or "hostname" in snap:
                    eq.name = str(snap.get("name") or snap.get("hostname"))
                return
    elif table == "network_devices":
        for dev in site.devices:
            if dev.device_id == entry.item_id:
                dev.role = snap.get("role")
                return
    elif table == "ip_arp_entries":
        target_ip = snap.get("ip_address") or snap.get("ip") or entry.item_id
        for ip_obj in site.ip_addresses:
            if ip_obj.ip == target_ip or ip_obj.ip == entry.item_id:
                ip_obj.assigned_object_type = snap.get(
                    "assigned_object_type", snap.get("assigned_target_type")
                )
                ip_obj.assigned_object_id = snap.get(
                    "assigned_object_id", snap.get("assigned_target_id")
                )
                return
    elif table == "ports":
        for dev in site.devices:
            for port in dev.ports:
                if port.port_id == entry.item_id:
                    port.admin_status = snap.get("admin_status")
                    return


class RemediationExecutor:
    """Strictly gated Phase 2 remediation executor with SHA-256 verification and rollback journal."""

    def __init__(
        self,
        *,
        dry_run: bool = True,
        confirm_write: bool = False,
        journal: Optional[RollbackJournal | Path | str] = None,
        journal_path: Optional[Path | str] = None,
        script_generator: Optional[SqlRemediationScriptGenerator] = None,
        strict_approval: bool = False,
    ) -> None:
        if not isinstance(dry_run, bool):
            raise RemediationExecutionError("dry_run must be a boolean")
        if not isinstance(confirm_write, bool):
            raise RemediationExecutionError("confirm_write must be a boolean")
        if dry_run is False and confirm_write is not True:
            raise RemediationExecutionError(
                "RemediationExecutor requires confirm_write=True when dry_run=False"
            )

        self.dry_run = dry_run
        self.confirm_write = confirm_write
        self.strict_approval = bool(strict_approval)

        resolved_journal_arg = journal if journal is not None else journal_path
        if isinstance(resolved_journal_arg, RollbackJournal):
            self.journal = resolved_journal_arg
        elif resolved_journal_arg is not None:
            self.journal = RollbackJournal(resolved_journal_arg)
        else:
            self.journal = RollbackJournal()

        self.script_generator = (
            script_generator
            if script_generator is not None
            else SqlRemediationScriptGenerator()
        )

    def execute(
        self,
        manifest: RemediationApprovalManifest,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        *,
        sqlite_conn: Optional[sqlite3.Connection] = None,
        snapshot_store: Optional[SnapshotStore] = None,
        sql_output_dir: Optional[Path | str] = None,
        dry_run: Optional[bool] = None,
        confirm_write: Optional[bool] = None,
        strict_approval: Optional[bool] = None,
        execution_id: Optional[str] = None,
        executed_at: Optional[datetime | str] = None,
        reviewer: Optional[str] = None,
    ) -> RemediationExecutionResult:
        """Execute an operator-approved RemediationApprovalManifest after gate verification."""
        effective_dry_run = self.dry_run if dry_run is None else dry_run
        effective_confirm_write = (
            self.confirm_write if confirm_write is None else confirm_write
        )
        effective_strict_approval = (
            self.strict_approval if strict_approval is None else strict_approval
        )

        if not isinstance(effective_dry_run, bool):
            raise RemediationExecutionError("dry_run must be a boolean")
        if effective_dry_run is False and effective_confirm_write is not True:
            raise RemediationExecutionError(
                "confirm_write=True is required when executing with dry_run=False"
            )

        approved_entries, skipped_entries = _validate_and_filter_manifest_entries(
            manifest, strict_approval=bool(effective_strict_approval)
        )

        resolved_exec_id = (
            _require_non_empty_str(execution_id, "execution_id").strip()
            if execution_id is not None
            else f"exec-{uuid.uuid4().hex[:12]}"
        )
        resolved_executed_at = _resolve_plan_timestamp(executed_at)

        effective_sites = sites
        if effective_sites is None and snapshot_store is not None:
            loaded_sites = snapshot_store.load_all_sites()
            if loaded_sites:
                effective_sites = loaded_sites

        scripts = self.script_generator.generate(
            manifest,
            sites=effective_sites,
            sqlite_conn=sqlite_conn,
            execution_id=resolved_exec_id,
            executed_at=resolved_executed_at,
            reviewer=reviewer,
            strict_approval=bool(effective_strict_approval),
        )

        remediate_sql_path: Optional[Path] = None
        rollback_sql_path: Optional[Path] = None
        journal_path: Optional[Path] = None

        if not effective_dry_run:
            if sql_output_dir is not None:
                remediate_sql_path, rollback_sql_path = scripts.write_scripts(
                    sql_output_dir
                )

            if sqlite_conn is not None:
                sqlite_conn.executescript(scripts.remediate_sql)
                for j_entry, m_entry in zip(
                    scripts.journal_entries, approved_entries
                ):
                    table = _resolve_target_table(
                        m_entry.item_type, m_entry.target_operation
                    )
                    j_entry.post_change_state = _query_sqlite_snapshot(
                        sqlite_conn, table, m_entry
                    )

            if snapshot_store is not None:
                affected_site_ids = {e.site_id for e in approved_entries}
                for site_id in sorted(affected_site_ids):
                    if snapshot_store.is_completed(site_id):
                        site_obj = snapshot_store.load_site(site_id)
                        for m_entry in approved_entries:
                            if m_entry.site_id == site_id:
                                _apply_remediation_to_site(site_obj, m_entry)
                        snapshot_store.save_site(site_obj)

            self.journal.append_entries(scripts.journal_entries)
            journal_path = self.journal.journal_path

        return RemediationExecutionResult(
            execution_id=resolved_exec_id,
            manifest_id=manifest.manifest_id,
            executed_at=resolved_executed_at,
            dry_run=effective_dry_run,
            executed_entries=approved_entries,
            skipped_entries=skipped_entries,
            journal_entries=scripts.journal_entries,
            remediate_sql=scripts.remediate_sql,
            rollback_sql=scripts.rollback_sql,
            remediate_sql_path=remediate_sql_path,
            rollback_sql_path=rollback_sql_path,
            journal_path=journal_path,
        )

    def execute_entry(
        self,
        entry: QuarantineManifestEntry,
        *,
        dry_run: Optional[bool] = None,
        confirm_write: Optional[bool] = None,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        sqlite_conn: Optional[sqlite3.Connection] = None,
        snapshot_store: Optional[SnapshotStore] = None,
        sql_output_dir: Optional[Path | str] = None,
        execution_id: Optional[str] = None,
        executed_at: Optional[datetime | str] = None,
        reviewer: Optional[str] = None,
    ) -> RemediationExecutionResult:
        """Execute a single QuarantineManifestEntry, raising RemediationExecutionError if not APPROVED."""
        if not isinstance(entry, QuarantineManifestEntry):
            raise RemediationExecutionError(
                "entry must be a QuarantineManifestEntry instance"
            )
        if entry.approval_status is not ApprovalStatus.APPROVED:
            raise RemediationExecutionError(
                f"Cannot execute manifest entry {entry.item_id!r} with approval_status={entry.approval_status.value!r}; "
                "ApprovalStatus.APPROVED is required"
            )
        manifest = RemediationApprovalManifest(entries=[entry])
        return self.execute(
            manifest,
            sites=sites,
            sqlite_conn=sqlite_conn,
            snapshot_store=snapshot_store,
            sql_output_dir=sql_output_dir,
            dry_run=dry_run,
            confirm_write=confirm_write,
            strict_approval=True,
            execution_id=execution_id,
            executed_at=executed_at,
            reviewer=reviewer,
        )

    def generate_rollback_plan(self, execution_id: str) -> RollbackPlan:
        """Generate a RollbackPlan for execution_id from the rollback journal."""
        return self.journal.generate_rollback_plan(execution_id)

    def rollback(
        self,
        execution_id: str,
        *,
        sqlite_conn: Optional[sqlite3.Connection] = None,
        snapshot_store: Optional[SnapshotStore] = None,
    ) -> RollbackPlan:
        """Generate and optionally execute a RollbackPlan for execution_id against sqlite_conn/snapshot_store."""
        plan = self.journal.generate_rollback_plan(execution_id)
        if sqlite_conn is not None:
            sqlite_conn.executescript(plan.rollback_sql)
        if snapshot_store is not None:
            affected_site_ids = {e.site_id for e in plan.entries}
            for site_id in sorted(affected_site_ids):
                if snapshot_store.is_completed(site_id):
                    site_obj = snapshot_store.load_site(site_id)
                    for j_entry in plan.entries:
                        if j_entry.site_id == site_id:
                            _restore_site_from_journal_entry(site_obj, j_entry)
                    snapshot_store.save_site(site_obj)
        return plan


__all__ = [
    "ManifestVerificationError",
    "RemediationExecutionError",
    "RemediationExecutionResult",
    "RemediationExecutor",
    "RollbackJournal",
    "RollbackJournalEntry",
    "RollbackPlan",
    "SqlRemediationScriptGenerator",
    "SqlRemediationScripts",
]
