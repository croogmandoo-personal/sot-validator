"""Curation overlay store, modifiable inventory CRUD operations, and immutable audit log."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Optional
import uuid

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.signals.base import normalize_utc_datetime

_CANONICAL_TARGET_TYPES: dict[str, str] = {
    "networkdevice": "NetworkDevice",
    "network_device": "NetworkDevice",
    "device": "NetworkDevice",
    "port": "Port",
    "vlan": "VLAN",
    "subnet": "Subnet",
    "ipaddress": "IPAddress",
    "ip_address": "IPAddress",
    "ip": "IPAddress",
    "equipment": "Equipment",
}

VALID_TARGET_TYPES: tuple[str, ...] = (
    "NetworkDevice",
    "Port",
    "VLAN",
    "Subnet",
    "IPAddress",
    "Equipment",
)

GENESIS_HASH: str = "0" * 64

# Reserved target type accepted only by AuditLogEntry, for chain migration markers.
_AUDIT_LOG_TARGET_TYPE = "AuditLog"

_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")

_MIGRATION_REASON = (
    "Audit entries before this marker were recorded before hash chaining and were "
    "chained retroactively during migration; their integrity before migration is "
    "not attested."
)


def _normalize_target_type(value: Any, field_name: str = "target_type") -> str:
    raw = _require_non_empty_str(value, field_name).strip()
    canonical = _CANONICAL_TARGET_TYPES.get(raw.lower())
    if canonical is None:
        raise ValueError(
            f"Invalid {field_name}: {value!r}. Expected one of {VALID_TARGET_TYPES}"
        )
    return canonical


def _normalize_optional_hash(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or _HASH_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be 64 lowercase hex characters or None")
    return value


def _normalize_optional_str(value: Optional[str], field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    stripped = value.strip()
    return stripped if stripped else None


def _normalize_optional_utc_datetime(
    value: Optional[datetime | str], field_name: str
) -> Optional[datetime]:
    if value is None:
        return None
    return normalize_utc_datetime(value, field_name=field_name)


def _coerce_equipment_category(
    value: EquipmentCategory | str, field_name: str = "category"
) -> EquipmentCategory:
    if isinstance(value, EquipmentCategory):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        for candidate in (stripped, stripped.lower()):
            try:
                return EquipmentCategory(candidate)
            except ValueError:
                pass
        for member in EquipmentCategory:
            if member.name.lower() == stripped.lower():
                return member
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_validation_classification(
    value: ValidationClassification | str,
    field_name: str = "pinned_classification",
) -> ValidationClassification:
    if isinstance(value, ValidationClassification):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        try:
            return ValidationClassification(stripped)
        except ValueError:
            pass
        lower = stripped.lower()
        for member in ValidationClassification:
            if member.value.lower() == lower or member.name.lower() == lower:
                return member
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _require_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


@dataclass
class ItemEditPatch:
    """Operator modification patch for an inventory item in the curation overlay."""

    target_type: str
    target_id: str
    site_id: Optional[str] = None
    name: Optional[str] = None
    hostname: Optional[str] = None
    category: Optional[EquipmentCategory | str] = None
    role: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    vlan_id: Optional[str] = None
    subnet_id: Optional[str] = None
    room: Optional[str] = None
    notes: Optional[str] = None
    pinned_classification: Optional[ValidationClassification | str] = None
    custom_attributes: dict[str, Any] = field(default_factory=dict)
    deleted: bool = False
    updated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.target_type = _normalize_target_type(self.target_type, "target_type")
        self.target_id = _require_non_empty_str(self.target_id, "target_id").strip()
        self.site_id = _normalize_optional_str(self.site_id, "site_id")
        self.name = _normalize_optional_str(self.name, "name")
        self.hostname = _normalize_optional_str(self.hostname, "hostname")
        if self.category is not None:
            self.category = _coerce_equipment_category(self.category, "category")
        self.role = _normalize_optional_str(self.role, "role")
        self.vendor = _normalize_optional_str(self.vendor, "vendor")
        self.model = _normalize_optional_str(self.model, "model")
        self.vlan_id = _normalize_optional_str(self.vlan_id, "vlan_id")
        self.subnet_id = _normalize_optional_str(self.subnet_id, "subnet_id")
        self.room = _normalize_optional_str(self.room, "room")
        self.notes = _normalize_optional_str(self.notes, "notes")
        if self.pinned_classification is not None:
            self.pinned_classification = _coerce_validation_classification(
                self.pinned_classification, "pinned_classification"
            )
        if self.custom_attributes is None:
            self.custom_attributes = {}
        elif isinstance(self.custom_attributes, Mapping):
            self.custom_attributes = dict(self.custom_attributes)
        else:
            raise ValueError("custom_attributes must be a mapping or None")
        if not isinstance(self.deleted, bool):
            raise ValueError("deleted must be a boolean")
        self.updated_at = _normalize_optional_utc_datetime(
            self.updated_at, "updated_at"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_id": self.target_id,
            "site_id": self.site_id,
            "name": self.name,
            "hostname": self.hostname,
            "category": (
                self.category.value
                if isinstance(self.category, EquipmentCategory)
                else self.category
            ),
            "role": self.role,
            "vendor": self.vendor,
            "model": self.model,
            "vlan_id": self.vlan_id,
            "subnet_id": self.subnet_id,
            "room": self.room,
            "notes": self.notes,
            "pinned_classification": (
                self.pinned_classification.value
                if isinstance(self.pinned_classification, ValidationClassification)
                else self.pinned_classification
            ),
            "custom_attributes": dict(self.custom_attributes),
            "deleted": self.deleted,
            "updated_at": _format_optional_datetime(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ItemEditPatch:
        if not isinstance(data, Mapping):
            raise ValueError("ItemEditPatch data must be a mapping")
        return cls(
            target_type=data["target_type"],
            target_id=data["target_id"],
            site_id=data.get("site_id"),
            name=data.get("name"),
            hostname=data.get("hostname"),
            category=data.get("category"),
            role=data.get("role"),
            vendor=data.get("vendor"),
            model=data.get("model"),
            vlan_id=data.get("vlan_id"),
            subnet_id=data.get("subnet_id"),
            room=data.get("room"),
            notes=data.get("notes"),
            pinned_classification=data.get("pinned_classification"),
            custom_attributes=dict(data.get("custom_attributes") or {}),
            deleted=bool(data.get("deleted", False)),
            updated_at=_normalize_optional_utc_datetime(
                data.get("updated_at"), "updated_at"
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ItemEditPatch:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class AuditLogEntry:
    """Immutable audit log record for an inventory curation mutation."""

    entry_id: str = field(default_factory=lambda: f"audit-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "operator"
    action: str = ""
    target_type: str = ""
    target_id: str = ""
    changes: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    site_id: Optional[str] = None
    prev_hash: Optional[str] = None
    entry_hash: Optional[str] = None

    def __post_init__(self) -> None:
        resolved_entry_id = (
            f"audit-{uuid.uuid4().hex[:12]}"
            if self.entry_id is None
            else _require_non_empty_str(self.entry_id, "entry_id").strip()
        )
        object.__setattr__(self, "entry_id", resolved_entry_id)

        resolved_ts = (
            datetime.now(timezone.utc)
            if self.timestamp is None
            else normalize_utc_datetime(self.timestamp, field_name="timestamp")
        )
        object.__setattr__(self, "timestamp", resolved_ts)

        clean_actor = _require_non_empty_str(self.actor, "actor").strip()
        object.__setattr__(self, "actor", clean_actor)

        clean_action = _require_non_empty_str(self.action, "action").strip()
        object.__setattr__(self, "action", clean_action)

        raw_target_type = _require_non_empty_str(self.target_type, "target_type").strip()
        norm_target_type = (
            _AUDIT_LOG_TARGET_TYPE
            if raw_target_type.lower() == _AUDIT_LOG_TARGET_TYPE.lower()
            else _normalize_target_type(raw_target_type, "target_type")
        )
        object.__setattr__(self, "target_type", norm_target_type)

        clean_target_id = _require_non_empty_str(self.target_id, "target_id").strip()
        object.__setattr__(self, "target_id", clean_target_id)

        if self.changes is None:
            object.__setattr__(self, "changes", {})
        elif isinstance(self.changes, Mapping):
            object.__setattr__(self, "changes", dict(self.changes))
        else:
            raise ValueError("changes must be a mapping or None")

        if self.reason is None:
            object.__setattr__(self, "reason", "")
        elif isinstance(self.reason, str):
            object.__setattr__(self, "reason", self.reason)
        else:
            raise ValueError("reason must be a string")

        norm_site_id = _normalize_optional_str(self.site_id, "site_id")
        object.__setattr__(self, "site_id", norm_site_id)

        _normalize_optional_hash(self.prev_hash, "prev_hash")
        _normalize_optional_hash(self.entry_hash, "entry_hash")

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "timestamp": _format_optional_datetime(self.timestamp),
            "actor": self.actor,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "changes": dict(self.changes),
            "reason": self.reason,
            "site_id": self.site_id,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AuditLogEntry:
        if not isinstance(data, Mapping):
            raise ValueError("AuditLogEntry data must be a mapping")
        return cls(
            entry_id=data.get("entry_id") or f"audit-{uuid.uuid4().hex[:12]}",
            timestamp=normalize_utc_datetime(
                data["timestamp"], field_name="timestamp"
            )
            if "timestamp" in data and data["timestamp"] is not None
            else datetime.now(timezone.utc),
            actor=data.get("actor", "operator"),
            action=data["action"],
            target_type=data["target_type"],
            target_id=data["target_id"],
            changes=dict(data.get("changes") or {}),
            reason=data.get("reason") or "",
            site_id=data.get("site_id"),
            prev_hash=data.get("prev_hash"),
            entry_hash=data.get("entry_hash"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> AuditLogEntry:
        return cls.from_dict(json.loads(raw))


def _compute_entry_hash(entry: AuditLogEntry) -> str:
    """Return SHA-256 of `prev_hash` followed by the canonical JSON of `entry` without `entry_hash`."""
    if entry.prev_hash is None:
        raise ValueError("prev_hash must be set to compute entry_hash")
    payload = entry.to_dict()
    del payload["entry_hash"]
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(entry.prev_hash.encode("ascii") + canonical).hexdigest()


def _chain_entries(
    entries: Sequence[AuditLogEntry], prev_hash: str = GENESIS_HASH
) -> list[AuditLogEntry]:
    """Return copies of `entries` hash-chained in order, starting from `prev_hash`."""
    chained: list[AuditLogEntry] = []
    for entry in entries:
        linked = replace(entry, prev_hash=prev_hash, entry_hash=None)
        linked = replace(linked, entry_hash=_compute_entry_hash(linked))
        chained.append(linked)
        prev_hash = linked.entry_hash
    return chained


@dataclass(frozen=True)
class AuditChainReport:
    """Result of walking the curation audit log hash chain."""

    ok: bool
    entries_checked: int
    broken_index: Optional[int] = None
    reason: Optional[str] = None


class _HybridImportMethod:
    """Descriptor allowing import_json to be invoked on either CurationStore class or instance."""

    def __init__(self, func: Any) -> None:
        self._func = func

    def __get__(self, instance: Any, owner: Any = None) -> Any:
        target = owner if instance is None else instance

        def _bound(*args: Any, **kwargs: Any) -> CurationStore:
            return self._func(target, *args, **kwargs)

        return _bound


_PATCH_MERGEABLE_FIELDS: tuple[str, ...] = (
    "site_id",
    "name",
    "hostname",
    "category",
    "role",
    "vendor",
    "model",
    "vlan_id",
    "subnet_id",
    "room",
    "notes",
    "pinned_classification",
)


class CurationStore:
    """SQLite-backed curation overlay store for inventory edits, custom items, and audit logs."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        if isinstance(db_path, Path):
            self.db_path: Path | str = db_path
            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn_target = str(db_path)
        elif isinstance(db_path, str):
            raw = db_path.strip()
            if not raw:
                raise ValueError("db_path must not be an empty string")
            if raw == ":memory:":
                self.db_path = ":memory:"
                conn_target = ":memory:"
            else:
                path_obj = Path(raw)
                path_obj.parent.mkdir(parents=True, exist_ok=True)
                self.db_path = path_obj
                conn_target = str(path_obj)
        else:
            raise ValueError("db_path must be a Path or string")

        self._conn = sqlite3.connect(conn_target)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS item_patches (
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    site_id TEXT,
                    patch_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (target_type, target_id)
                );

                CREATE TABLE IF NOT EXISTS custom_devices (
                    device_id TEXT PRIMARY KEY,
                    site_id TEXT NOT NULL,
                    device_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS custom_equipment (
                    equipment_id TEXT PRIMARY KEY,
                    site_id TEXT NOT NULL,
                    equipment_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS custom_vlans (
                    site_id TEXT NOT NULL,
                    vlan_id TEXT NOT NULL,
                    vlan_json TEXT NOT NULL,
                    PRIMARY KEY (site_id, vlan_id)
                );

                CREATE TABLE IF NOT EXISTS custom_subnets (
                    site_id TEXT NOT NULL,
                    subnet_id TEXT NOT NULL,
                    subnet_json TEXT NOT NULL,
                    PRIMARY KEY (site_id, subnet_id)
                );

                CREATE TABLE IF NOT EXISTS custom_ports (
                    device_id TEXT NOT NULL,
                    port_id TEXT NOT NULL,
                    site_id TEXT,
                    port_json TEXT NOT NULL,
                    PRIMARY KEY (device_id, port_id)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    changes_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    site_id TEXT,
                    prev_hash TEXT,
                    entry_hash TEXT
                );
                """
            )
        self._migrate_legacy_audit_log()

    def _audit_log_has_hash_columns(self) -> bool:
        columns = {
            str(row[1])
            for row in self._conn.execute("PRAGMA table_info(audit_log)").fetchall()
        }
        return "prev_hash" in columns and "entry_hash" in columns

    def _migrate_legacy_audit_log(self) -> None:
        """Add hash columns to a legacy audit_log and chain its rows in place, once."""
        if self._audit_log_has_hash_columns():
            return
        with self._write_transaction():
            columns = {
                str(row[1])
                for row in self._conn.execute("PRAGMA table_info(audit_log)").fetchall()
            }
            if "prev_hash" in columns and "entry_hash" in columns:
                return
            for column in ("prev_hash", "entry_hash"):
                if column not in columns:
                    self._conn.execute(f"ALTER TABLE audit_log ADD COLUMN {column} TEXT")
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY seq ASC"
            ).fetchall()
            legacy = [self._row_to_audit_entry(r) for r in rows]
            chained = _chain_entries(legacy)
            for row, entry in zip(rows, chained):
                self._conn.execute(
                    "UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE seq = ? AND entry_hash IS NULL",
                    (entry.prev_hash, entry.entry_hash, row["seq"]),
                )
            if chained:
                self._record_migration_marker(chained, source="sqlite")

    def _record_migration_marker(
        self, chained_legacy: Sequence[AuditLogEntry], *, source: str
    ) -> AuditLogEntry:
        return self._record_audit(
            actor="system",
            action="migration",
            target_type=_AUDIT_LOG_TARGET_TYPE,
            target_id="audit_log",
            changes={
                "legacy_entries": len(chained_legacy),
                "legacy_head_hash": chained_legacy[-1].entry_hash,
                "source": source,
            },
            reason=_MIGRATION_REASON,
            site_id=None,
        )

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block inside one `BEGIN IMMEDIATE` transaction on the current connection."""
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __enter__(self) -> CurationStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _next_entry_id(self) -> str:
        row = self._conn.execute("SELECT COUNT(*) AS cnt FROM audit_log").fetchone()
        seq = (int(row["cnt"]) if row is not None else 0) + 1
        return f"audit-{seq:04d}-{uuid.uuid4().hex[:8]}"

    def _chain_head_hash(self) -> str:
        row = self._conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return GENESIS_HASH
        head = row["entry_hash"]
        if head is None:
            raise ValueError(
                "audit_log head entry has no entry_hash; refusing to extend an unattested chain"
            )
        return str(head)

    def export_chain_head(self) -> tuple[int, str]:
        """Return `(entry_count, head_hash)` for the whole audit log, to be recorded as an external anchor."""
        row = self._conn.execute("SELECT COUNT(*) AS cnt FROM audit_log").fetchone()
        count = int(row["cnt"]) if row is not None else 0
        return count, self._chain_head_hash()

    def _insert_audit_entry(self, entry: AuditLogEntry) -> None:
        self._conn.execute(
            """
            INSERT INTO audit_log (
                entry_id, timestamp, actor, action, target_type, target_id,
                changes_json, reason, site_id, prev_hash, entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.entry_id,
                entry.timestamp.isoformat(),
                entry.actor,
                entry.action,
                entry.target_type,
                entry.target_id,
                json.dumps(entry.changes),
                entry.reason,
                entry.site_id,
                entry.prev_hash,
                entry.entry_hash,
            ),
        )

    def _infer_site_id(
        self, target_type: str, target_id: str, explicit_site_id: Optional[str] = None
    ) -> Optional[str]:
        if explicit_site_id is not None and explicit_site_id.strip():
            return explicit_site_id.strip()

        patch_row = self._conn.execute(
            "SELECT site_id FROM item_patches WHERE target_type = ? AND target_id = ?",
            (target_type, target_id),
        ).fetchone()
        if patch_row is not None and patch_row["site_id"]:
            return str(patch_row["site_id"])

        if target_type == "NetworkDevice":
            row = self._conn.execute(
                "SELECT site_id FROM custom_devices WHERE device_id = ?",
                (target_id,),
            ).fetchone()
            if row is not None and row["site_id"]:
                return str(row["site_id"])
        elif target_type == "Equipment":
            row = self._conn.execute(
                "SELECT site_id FROM custom_equipment WHERE equipment_id = ?",
                (target_id,),
            ).fetchone()
            if row is not None and row["site_id"]:
                return str(row["site_id"])
        elif target_type == "VLAN":
            row = self._conn.execute(
                "SELECT site_id FROM custom_vlans WHERE vlan_id = ? LIMIT 1",
                (target_id,),
            ).fetchone()
            if row is not None and row["site_id"]:
                return str(row["site_id"])
        elif target_type == "Subnet":
            row = self._conn.execute(
                "SELECT site_id FROM custom_subnets WHERE subnet_id = ? LIMIT 1",
                (target_id,),
            ).fetchone()
            if row is not None and row["site_id"]:
                return str(row["site_id"])
        elif target_type == "Port":
            row = self._conn.execute(
                "SELECT site_id, device_id FROM custom_ports WHERE port_id = ? LIMIT 1",
                (target_id,),
            ).fetchone()
            if row is not None:
                if row["site_id"]:
                    return str(row["site_id"])
                dev_row = self._conn.execute(
                    "SELECT site_id FROM custom_devices WHERE device_id = ?",
                    (row["device_id"],),
                ).fetchone()
                if dev_row is not None and dev_row["site_id"]:
                    return str(dev_row["site_id"])

        return None

    def _record_audit(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        changes: Mapping[str, Any],
        reason: str = "",
        site_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> AuditLogEntry:
        """Append a chained audit row; callers must already hold a `_write_transaction`."""
        unhashed = AuditLogEntry(
            entry_id=self._next_entry_id(),
            timestamp=timestamp or datetime.now(timezone.utc),
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            changes=dict(changes),
            reason=reason,
            site_id=site_id,
            prev_hash=self._chain_head_hash(),
        )
        entry = replace(unhashed, entry_hash=_compute_entry_hash(unhashed))
        self._insert_audit_entry(entry)
        return entry

    def get_patch(
        self, target_type: str, target_id: str
    ) -> Optional[ItemEditPatch]:
        """Return the stored ItemEditPatch for `(target_type, target_id)`, or None."""
        norm_type = _normalize_target_type(target_type, "target_type")
        clean_id = _require_non_empty_str(target_id, "target_id").strip()
        row = self._conn.execute(
            "SELECT patch_json FROM item_patches WHERE target_type = ? AND target_id = ?",
            (norm_type, clean_id),
        ).fetchone()
        if row is None:
            return None
        return ItemEditPatch.from_json(row["patch_json"])

    def upsert_patch(
        self,
        patch: ItemEditPatch | Mapping[str, Any],
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Insert or merge an ItemEditPatch and record an AuditLogEntry."""
        incoming = (
            patch
            if isinstance(patch, ItemEditPatch)
            else ItemEditPatch.from_dict(patch)
        )
        now = incoming.updated_at or datetime.now(timezone.utc)

        with self._write_transaction():
            return self._upsert_patch_locked(incoming, now, actor, reason)

    def _upsert_patch_locked(
        self,
        incoming: ItemEditPatch,
        now: datetime,
        actor: str,
        reason: str,
        *,
        batch_id: Optional[str] = None,
    ) -> AuditLogEntry:
        existing = self.get_patch(incoming.target_type, incoming.target_id)
        resolved_site_id = self._infer_site_id(
            incoming.target_type, incoming.target_id, incoming.site_id
        )

        if existing is not None:
            merged_kwargs: dict[str, Any] = {
                "target_type": incoming.target_type,
                "target_id": incoming.target_id,
                "site_id": resolved_site_id or existing.site_id,
                "updated_at": now,
                "deleted": incoming.deleted,
            }
            for fname in _PATCH_MERGEABLE_FIELDS:
                if fname == "site_id":
                    continue
                inc_val = getattr(incoming, fname)
                merged_kwargs[fname] = (
                    inc_val if inc_val is not None else getattr(existing, fname)
                )
            merged_custom = dict(existing.custom_attributes)
            merged_custom.update(incoming.custom_attributes)
            merged_kwargs["custom_attributes"] = merged_custom
            stored_patch = ItemEditPatch(**merged_kwargs)
        else:
            stored_patch = replace(
                incoming,
                site_id=resolved_site_id,
                updated_at=now,
            )

        changes: dict[str, Any] = {}
        patch_dict = incoming.to_dict()
        for fname in _PATCH_MERGEABLE_FIELDS:
            if patch_dict.get(fname) is not None:
                changes[fname] = patch_dict[fname]
        if incoming.custom_attributes:
            changes["custom_attributes"] = dict(incoming.custom_attributes)
        if incoming.deleted or (existing is not None and existing.deleted != incoming.deleted):
            changes["deleted"] = incoming.deleted
        if batch_id is not None:
            changes["batch_id"] = batch_id

        self._conn.execute(
            """
            INSERT INTO item_patches (
                target_type, target_id, site_id, patch_json, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target_type, target_id) DO UPDATE SET
                site_id = excluded.site_id,
                patch_json = excluded.patch_json,
                updated_at = excluded.updated_at
            """,
            (
                stored_patch.target_type,
                stored_patch.target_id,
                stored_patch.site_id,
                stored_patch.to_json(),
                now.isoformat(),
            ),
        )
        return self._record_audit(
            actor=actor,
            action="UPSERT_PATCH",
            target_type=stored_patch.target_type,
            target_id=stored_patch.target_id,
            changes=changes,
            reason=reason,
            site_id=stored_patch.site_id,
            timestamp=now,
        )

    def add_custom_device(
        self,
        device: NetworkDevice | Mapping[str, Any],
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Persist a custom NetworkDevice and record an AuditLogEntry."""
        dev = (
             NetworkDevice.from_dict(device.to_dict())
            if isinstance(device, NetworkDevice)
            else NetworkDevice.from_dict(device)
        )
        with self._write_transaction():
            existing_patch = self.get_patch("NetworkDevice", dev.device_id)
            self._conn.execute(
                """
                INSERT INTO custom_devices (device_id, site_id, device_json)
                VALUES (?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    site_id = excluded.site_id,
                    device_json = excluded.device_json
                """,
                (dev.device_id, dev.site_id, dev.to_json()),
            )
            for p in dev.ports:
                norm_port = (
                    p
                    if p.device_id == dev.device_id
                    else replace(p, device_id=dev.device_id)
                )
                self._conn.execute(
                    """
                    INSERT INTO custom_ports (device_id, port_id, site_id, port_json)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(device_id, port_id) DO UPDATE SET
                        site_id = excluded.site_id,
                        port_json = excluded.port_json
                    """,
                    (
                        dev.device_id,
                        norm_port.port_id,
                        dev.site_id,
                        norm_port.to_json(),
                    ),
                )
            if existing_patch is not None and existing_patch.deleted:
                undeleted = replace(
                    existing_patch,
                    site_id=existing_patch.site_id or dev.site_id,
                    deleted=False,
                    updated_at=datetime.now(timezone.utc),
                )
                self._conn.execute(
                    """
                    UPDATE item_patches
                    SET site_id = ?, patch_json = ?, updated_at = ?
                    WHERE target_type = 'NetworkDevice' AND target_id = ?
                    """,
                    (
                        undeleted.site_id,
                        undeleted.to_json(),
                        undeleted.updated_at.isoformat() if undeleted.updated_at else "",
                        dev.device_id,
                    ),
                )
            return self._record_audit(
                actor=actor,
                action="ADD_DEVICE",
                target_type="NetworkDevice",
                target_id=dev.device_id,
                changes=dev.to_dict(),
                reason=reason,
                site_id=dev.site_id,
            )

    def add_custom_equipment(
        self,
        equipment: Equipment | Mapping[str, Any],
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Persist a custom Equipment item and record an AuditLogEntry."""
        eq = (
            Equipment.from_dict(equipment.to_dict())
            if isinstance(equipment, Equipment)
            else Equipment.from_dict(equipment)
        )
        with self._write_transaction():
            existing_patch = self.get_patch("Equipment", eq.equipment_id)
            self._conn.execute(
                """
                INSERT INTO custom_equipment (equipment_id, site_id, equipment_json)
                VALUES (?, ?, ?)
                ON CONFLICT(equipment_id) DO UPDATE SET
                    site_id = excluded.site_id,
                    equipment_json = excluded.equipment_json
                """,
                (eq.equipment_id, eq.site_id, eq.to_json()),
            )
            if existing_patch is not None and existing_patch.deleted:
                undeleted = replace(
                    existing_patch,
                    site_id=existing_patch.site_id or eq.site_id,
                    deleted=False,
                    updated_at=datetime.now(timezone.utc),
                )
                self._conn.execute(
                    """
                    UPDATE item_patches
                    SET site_id = ?, patch_json = ?, updated_at = ?
                    WHERE target_type = 'Equipment' AND target_id = ?
                    """,
                    (
                        undeleted.site_id,
                        undeleted.to_json(),
                        undeleted.updated_at.isoformat() if undeleted.updated_at else "",
                        eq.equipment_id,
                    ),
                )
            return self._record_audit(
                actor=actor,
                action="ADD_EQUIPMENT",
                target_type="Equipment",
                target_id=eq.equipment_id,
                changes=eq.to_dict(),
                reason=reason,
                site_id=eq.site_id,
            )

    def add_custom_vlan(
        self,
        vlan: VLAN | Mapping[str, Any],
        subnet: Optional[Subnet | Mapping[str, Any]] = None,
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Persist a custom VLAN and optional associated Subnet, recording an AuditLogEntry."""
        vlan_obj = (
            VLAN.from_dict(vlan.to_dict())
            if isinstance(vlan, VLAN)
            else VLAN.from_dict(vlan)
        )
        subnet_obj: Optional[Subnet] = None
        if subnet is not None:
            subnet_obj = (
                Subnet.from_dict(subnet.to_dict())
                if isinstance(subnet, Subnet)
                else Subnet.from_dict(subnet)
            )

        with self._write_transaction():
            existing_vlan_patch = self.get_patch("VLAN", vlan_obj.vlan_id)
            self._conn.execute(
                """
                INSERT INTO custom_vlans (site_id, vlan_id, vlan_json)
                VALUES (?, ?, ?)
                ON CONFLICT(site_id, vlan_id) DO UPDATE SET
                    vlan_json = excluded.vlan_json
                """,
                (vlan_obj.site_id, vlan_obj.vlan_id, vlan_obj.to_json()),
            )
            if existing_vlan_patch is not None and existing_vlan_patch.deleted:
                undeleted = replace(
                    existing_vlan_patch,
                    site_id=existing_vlan_patch.site_id or vlan_obj.site_id,
                    deleted=False,
                    updated_at=datetime.now(timezone.utc),
                )
                self._conn.execute(
                    """
                    UPDATE item_patches
                    SET site_id = ?, patch_json = ?, updated_at = ?
                    WHERE target_type = 'VLAN' AND target_id = ?
                    """,
                    (
                        undeleted.site_id,
                        undeleted.to_json(),
                        undeleted.updated_at.isoformat() if undeleted.updated_at else "",
                        vlan_obj.vlan_id,
                    ),
                )
            if subnet_obj is not None:
                self._conn.execute(
                    """
                    INSERT INTO custom_subnets (site_id, subnet_id, subnet_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT(site_id, subnet_id) DO UPDATE SET
                        subnet_json = excluded.subnet_json
                    """,
                    (
                        subnet_obj.site_id,
                        subnet_obj.subnet_id,
                        subnet_obj.to_json(),
                    ),
                )

            changes: dict[str, Any] = {"vlan": vlan_obj.to_dict()}
            if subnet_obj is not None:
                changes["subnet"] = subnet_obj.to_dict()

            return self._record_audit(
                actor=actor,
                action="ADD_VLAN",
                target_type="VLAN",
                target_id=vlan_obj.vlan_id,
                changes=changes,
                reason=reason,
                site_id=vlan_obj.site_id,
            )

    def add_or_update_port(
        self,
        device_id: str,
        port: Port | Mapping[str, Any],
        actor: str = "operator",
        reason: str = "",
        site_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Persist a custom or updated Port on `device_id` and record an AuditLogEntry."""
        clean_dev_id = _require_non_empty_str(device_id, "device_id").strip()
        port_obj = (
            Port.from_dict(port.to_dict())
            if isinstance(port, Port)
            else Port.from_dict(port)
        )
        if port_obj.device_id != clean_dev_id:
            port_obj = replace(port_obj, device_id=clean_dev_id)

        explicit_site_id = _normalize_optional_str(site_id, "site_id")

        with self._write_transaction():
            resolved_site_id = (
                explicit_site_id
                or self._infer_site_id("NetworkDevice", clean_dev_id)
                or self._infer_site_id("Port", port_obj.port_id)
            )
            existing_patch = self.get_patch("Port", port_obj.port_id)

            self._conn.execute(
                """
                INSERT INTO custom_ports (device_id, port_id, site_id, port_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(device_id, port_id) DO UPDATE SET
                    site_id = COALESCE(excluded.site_id, custom_ports.site_id),
                    port_json = excluded.port_json
                """,
                (
                    clean_dev_id,
                    port_obj.port_id,
                    resolved_site_id,
                    port_obj.to_json(),
                ),
            )
            dev_row = self._conn.execute(
                "SELECT device_json FROM custom_devices WHERE device_id = ?",
                (clean_dev_id,),
            ).fetchone()
            if dev_row is not None:
                dev = NetworkDevice.from_json(dev_row["device_json"])
                updated_ports: list[Port] = []
                replaced = False
                for existing_p in dev.ports:
                    if existing_p.port_id == port_obj.port_id:
                        updated_ports.append(port_obj)
                        replaced = True
                    else:
                        updated_ports.append(existing_p)
                if not replaced:
                    updated_ports.append(port_obj)
                dev.ports = updated_ports
                self._conn.execute(
                    "UPDATE custom_devices SET device_json = ? WHERE device_id = ?",
                    (dev.to_json(), clean_dev_id),
                )
            if existing_patch is not None and existing_patch.deleted:
                undeleted = replace(
                    existing_patch,
                    site_id=existing_patch.site_id or resolved_site_id,
                    deleted=False,
                    updated_at=datetime.now(timezone.utc),
                )
                self._conn.execute(
                    """
                    UPDATE item_patches
                    SET site_id = ?, patch_json = ?, updated_at = ?
                    WHERE target_type = 'Port' AND target_id = ?
                    """,
                    (
                        undeleted.site_id,
                        undeleted.to_json(),
                        undeleted.updated_at.isoformat() if undeleted.updated_at else "",
                        port_obj.port_id,
                    ),
                )
            return self._record_audit(
                actor=actor,
                action="UPSERT_PORT",
                target_type="Port",
                target_id=port_obj.port_id,
                changes=port_obj.to_dict(),
                reason=reason,
                site_id=resolved_site_id,
            )

    def delete_item(
        self,
        target_type: str,
        target_id: str,
        actor: str = "operator",
        reason: str = "",
        site_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Mark `(target_type, target_id)` as deleted and record an AuditLogEntry."""
        norm_type = _normalize_target_type(target_type, "target_type")
        clean_id = _require_non_empty_str(target_id, "target_id").strip()

        with self._write_transaction():
            return self._delete_item_locked(
                norm_type, clean_id, actor, reason, site_id
            )

    def _delete_item_locked(
        self,
        norm_type: str,
        clean_id: str,
        actor: str,
        reason: str,
        site_id: Optional[str],
        *,
        batch_id: Optional[str] = None,
    ) -> AuditLogEntry:
        resolved_site_id = self._infer_site_id(norm_type, clean_id, site_id)
        existing = self.get_patch(norm_type, clean_id)
        now = datetime.now(timezone.utc)

        if existing is not None:
            deleted_patch = replace(
                existing,
                site_id=resolved_site_id or existing.site_id,
                deleted=True,
                updated_at=now,
            )
        else:
            deleted_patch = ItemEditPatch(
                target_type=norm_type,
                target_id=clean_id,
                site_id=resolved_site_id,
                deleted=True,
                updated_at=now,
            )

        self._conn.execute(
            """
            INSERT INTO item_patches (
                target_type, target_id, site_id, patch_json, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(target_type, target_id) DO UPDATE SET
                site_id = excluded.site_id,
                patch_json = excluded.patch_json,
                updated_at = excluded.updated_at
            """,
            (
                deleted_patch.target_type,
                deleted_patch.target_id,
                deleted_patch.site_id,
                deleted_patch.to_json(),
                now.isoformat(),
            ),
        )

        if norm_type == "NetworkDevice":
            self._conn.execute(
                "DELETE FROM custom_devices WHERE device_id = ?",
                (clean_id,),
            )
            self._conn.execute(
                "DELETE FROM custom_ports WHERE device_id = ?",
                (clean_id,),
            )
        elif norm_type == "Equipment":
            self._conn.execute(
                "DELETE FROM custom_equipment WHERE equipment_id = ?",
                (clean_id,),
            )
        elif norm_type == "VLAN":
            if resolved_site_id is not None:
                self._conn.execute(
                    "DELETE FROM custom_vlans WHERE site_id = ? AND vlan_id = ?",
                    (resolved_site_id, clean_id),
                )
            else:
                self._conn.execute(
                    "DELETE FROM custom_vlans WHERE vlan_id = ?",
                    (clean_id,),
                )
        elif norm_type == "Subnet":
            if resolved_site_id is not None:
                self._conn.execute(
                    "DELETE FROM custom_subnets WHERE site_id = ? AND subnet_id = ?",
                    (resolved_site_id, clean_id),
                )
            else:
                self._conn.execute(
                    "DELETE FROM custom_subnets WHERE subnet_id = ?",
                    (clean_id,),
                )
        elif norm_type == "Port":
            self._conn.execute(
                "DELETE FROM custom_ports WHERE port_id = ?",
                (clean_id,),
            )
            dev_rows = self._conn.execute(
                "SELECT device_id, device_json FROM custom_devices"
            ).fetchall()
            for dev_row in dev_rows:
                dev = NetworkDevice.from_json(dev_row["device_json"])
                filtered_ports = [
                    p for p in dev.ports if p.port_id != clean_id
                ]
                if len(filtered_ports) != len(dev.ports):
                    dev.ports = filtered_ports
                    self._conn.execute(
                        "UPDATE custom_devices SET device_json = ? WHERE device_id = ?",
                        (dev.to_json(), dev.device_id),
                    )

        changes: dict[str, Any] = {"deleted": True}
        if batch_id is not None:
            changes["batch_id"] = batch_id
        return self._record_audit(
            actor=actor,
            action="DELETE_ITEM",
            target_type=norm_type,
            target_id=clean_id,
            changes=changes,
            reason=reason,
            site_id=deleted_patch.site_id,
            timestamp=now,
        )

    def list_patches(self, site_id: Optional[str] = None) -> list[ItemEditPatch]:
        """Return stored ItemEditPatch records, filtered to `site_id` when provided."""
        if site_id is not None:
            clean_site = _require_non_empty_str(site_id, "site_id").strip()
            rows = self._conn.execute(
                """
                SELECT patch_json FROM item_patches
                WHERE site_id = ?
                ORDER BY target_type ASC, target_id ASC
                """,
                (clean_site,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT patch_json FROM item_patches
                ORDER BY target_type ASC, target_id ASC
                """
            ).fetchall()
        return [ItemEditPatch.from_json(r["patch_json"]) for r in rows]

    @staticmethod
    def _row_to_audit_entry(row: sqlite3.Row) -> AuditLogEntry:
        return AuditLogEntry(
            entry_id=row["entry_id"],
            timestamp=normalize_utc_datetime(
                row["timestamp"], field_name="timestamp"
            ),
            actor=row["actor"],
            action=row["action"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            changes=json.loads(row["changes_json"]),
            reason=row["reason"],
            site_id=row["site_id"],
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
        )

    def list_audit_log(
        self, site_id: Optional[str] = None, limit: int = 100
    ) -> list[AuditLogEntry]:
        """Return recorded AuditLogEntry items in chronological order, filtered by `site_id` and bounded by `limit`."""
        _require_non_negative_int(limit, "limit")
        if limit == 0:
            return []

        if site_id is None:
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY seq ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_audit_entry(r) for r in rows]

        clean_site = _require_non_empty_str(site_id, "site_id").strip()
        all_rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY seq ASC"
        ).fetchall()
        matched: list[AuditLogEntry] = []
        for row in all_rows:
            row_site = row["site_id"] or self._infer_site_id(
                row["target_type"], row["target_id"]
            )
            if row_site == clean_site:
                matched.append(self._row_to_audit_entry(row))
                if len(matched) >= limit:
                    break
        return matched

    def _list_custom_devices(
        self, site_id: Optional[str] = None
    ) -> list[NetworkDevice]:
        if site_id is not None:
            rows = self._conn.execute(
                "SELECT device_json FROM custom_devices WHERE site_id = ? ORDER BY device_id ASC",
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT device_json FROM custom_devices ORDER BY device_id ASC"
            ).fetchall()
        return [NetworkDevice.from_json(r["device_json"]) for r in rows]

    def _list_custom_equipment(
        self, site_id: Optional[str] = None
    ) -> list[Equipment]:
        if site_id is not None:
            rows = self._conn.execute(
                "SELECT equipment_json FROM custom_equipment WHERE site_id = ? ORDER BY equipment_id ASC",
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT equipment_json FROM custom_equipment ORDER BY equipment_id ASC"
            ).fetchall()
        return [Equipment.from_json(r["equipment_json"]) for r in rows]

    def _list_custom_vlans(self, site_id: Optional[str] = None) -> list[VLAN]:
        if site_id is not None:
            rows = self._conn.execute(
                "SELECT vlan_json FROM custom_vlans WHERE site_id = ? ORDER BY vlan_id ASC",
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT vlan_json FROM custom_vlans ORDER BY site_id ASC, vlan_id ASC"
            ).fetchall()
        return [VLAN.from_json(r["vlan_json"]) for r in rows]

    def _list_custom_subnets(self, site_id: Optional[str] = None) -> list[Subnet]:
        if site_id is not None:
            rows = self._conn.execute(
                "SELECT subnet_json FROM custom_subnets WHERE site_id = ? ORDER BY subnet_id ASC",
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT subnet_json FROM custom_subnets ORDER BY site_id ASC, subnet_id ASC"
            ).fetchall()
        return [Subnet.from_json(r["subnet_json"]) for r in rows]

    def _list_custom_ports(
        self, site_id: Optional[str] = None
    ) -> list[tuple[str, Optional[str], Port]]:
        if site_id is not None:
            rows = self._conn.execute(
                """
                SELECT device_id, site_id, port_json FROM custom_ports
                WHERE site_id IS NULL OR site_id = ?
                ORDER BY device_id ASC, port_id ASC
                """,
                (site_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT device_id, site_id, port_json FROM custom_ports ORDER BY device_id ASC, port_id ASC"
            ).fetchall()
        return [
            (str(r["device_id"]), r["site_id"], Port.from_json(r["port_json"]))
            for r in rows
        ]

    def _list_all_audit_log(self) -> list[AuditLogEntry]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY seq ASC"
        ).fetchall()
        return [self._row_to_audit_entry(r) for r in rows]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete CurationStore state to a dictionary."""
        return {
            "patches": [p.to_dict() for p in self.list_patches()],
            "custom_devices": [d.to_dict() for d in self._list_custom_devices()],
            "custom_equipment": [e.to_dict() for e in self._list_custom_equipment()],
            "custom_vlans": [v.to_dict() for v in self._list_custom_vlans()],
            "custom_subnets": [s.to_dict() for s in self._list_custom_subnets()],
            "custom_ports": [
                {
                    "device_id": dev_id,
                    "site_id": s_id,
                    "port": port.to_dict(),
                }
                for dev_id, s_id, port in self._list_custom_ports()
            ],
            "audit_log": [a.to_dict() for a in self._list_all_audit_log()],
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        """Serialize the complete CurationStore state to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def export_json(
        self, path: Path | str, *, indent: Optional[int] = 2
    ) -> Path:
        """Write the complete CurationStore state to a JSON file on disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(indent=indent), encoding="utf-8")
        return target

    def _load_state_from_mapping(self, data: Mapping[str, Any]) -> None:
        if not isinstance(data, Mapping):
            raise ValueError("CurationStore state data must be a mapping")

        patches = [
            p if isinstance(p, ItemEditPatch) else ItemEditPatch.from_dict(p)
            for p in data.get("patches", [])
        ]
        devices = [
            d if isinstance(d, NetworkDevice) else NetworkDevice.from_dict(d)
            for d in data.get("custom_devices", [])
        ]
        equipment = [
            e if isinstance(e, Equipment) else Equipment.from_dict(e)
            for e in data.get("custom_equipment", [])
        ]
        vlans = [
            v if isinstance(v, VLAN) else VLAN.from_dict(v)
            for v in data.get("custom_vlans", [])
        ]
        subnets = [
            s if isinstance(s, Subnet) else Subnet.from_dict(s)
            for s in data.get("custom_subnets", [])
        ]
        raw_ports = data.get("custom_ports", [])
        ports: list[tuple[str, Optional[str], Port]] = []
        for item in raw_ports:
            if isinstance(item, Port):
                ports.append((item.device_id, None, item))
            elif isinstance(item, Mapping) and "port" in item:
                p_obj = (
                    item["port"]
                    if isinstance(item["port"], Port)
                    else Port.from_dict(item["port"])
                )
                dev_id = str(item.get("device_id") or p_obj.device_id)
                if p_obj.device_id != dev_id:
                    p_obj = replace(p_obj, device_id=dev_id)
                ports.append((dev_id, item.get("site_id"), p_obj))
            elif isinstance(item, Mapping):
                p_obj = Port.from_dict(item)
                ports.append((p_obj.device_id, item.get("site_id"), p_obj))
            else:
                raise ValueError(f"Invalid custom_ports entry: {item!r}")

        audit_entries = [
            a if isinstance(a, AuditLogEntry) else AuditLogEntry.from_dict(a)
            for a in data.get("audit_log", [])
        ]
        hashed_flags = [
            a.prev_hash is not None and a.entry_hash is not None for a in audit_entries
        ]
        unhashed_flags = [
            a.prev_hash is None and a.entry_hash is None for a in audit_entries
        ]
        if all(hashed_flags):
            expected_prev = GENESIS_HASH
            for idx, entry in enumerate(audit_entries):
                if entry.prev_hash != expected_prev or (
                    _compute_entry_hash(entry) != entry.entry_hash
                ):
                    raise ValueError(
                        f"audit_log hash chain is broken at index {idx}; refusing import"
                    )
                expected_prev = entry.entry_hash
            legacy_import = False
        elif all(unhashed_flags):
            audit_entries = _chain_entries(audit_entries)
            legacy_import = True
        else:
            raise ValueError(
                "audit_log mixes hash-chained and unhashed entries; refusing import"
            )

        with self._write_transaction():
            count_row = self._conn.execute(
                "SELECT COUNT(*) AS cnt FROM audit_log"
            ).fetchone()
            if int(count_row["cnt"]) > 0:
                raise ValueError(
                    "Refusing to import curation state into a store that already has "
                    "audit log entries; the audit log is append-only"
                )
            self._conn.execute("DELETE FROM custom_ports")
            self._conn.execute("DELETE FROM custom_subnets")
            self._conn.execute("DELETE FROM custom_vlans")
            self._conn.execute("DELETE FROM custom_equipment")
            self._conn.execute("DELETE FROM custom_devices")
            self._conn.execute("DELETE FROM item_patches")

            for p in patches:
                updated_ts = (
                    p.updated_at.isoformat()
                    if p.updated_at is not None
                    else datetime.now(timezone.utc).isoformat()
                )
                self._conn.execute(
                    """
                    INSERT INTO item_patches (
                        target_type, target_id, site_id, patch_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        p.target_type,
                        p.target_id,
                        p.site_id,
                        p.to_json(),
                        updated_ts,
                    ),
                )

            for d in devices:
                self._conn.execute(
                    """
                    INSERT INTO custom_devices (device_id, site_id, device_json)
                    VALUES (?, ?, ?)
                    """,
                    (d.device_id, d.site_id, d.to_json()),
                )

            for e in equipment:
                self._conn.execute(
                    """
                    INSERT INTO custom_equipment (equipment_id, site_id, equipment_json)
                    VALUES (?, ?, ?)
                    """,
                    (e.equipment_id, e.site_id, e.to_json()),
                )

            for v in vlans:
                self._conn.execute(
                    """
                    INSERT INTO custom_vlans (site_id, vlan_id, vlan_json)
                    VALUES (?, ?, ?)
                    """,
                    (v.site_id, v.vlan_id, v.to_json()),
                )

            for s in subnets:
                self._conn.execute(
                    """
                    INSERT INTO custom_subnets (site_id, subnet_id, subnet_json)
                    VALUES (?, ?, ?)
                    """,
                    (s.site_id, s.subnet_id, s.to_json()),
                )

            for dev_id, s_id, port_obj in ports:
                self._conn.execute(
                    """
                    INSERT INTO custom_ports (device_id, port_id, site_id, port_json)
                    VALUES (?, ?, ?, ?)
                    """,
                    (dev_id, port_obj.port_id, s_id, port_obj.to_json()),
                )

            for entry in audit_entries:
                self._insert_audit_entry(entry)
            if legacy_import and audit_entries:
                self._record_migration_marker(audit_entries, source="json")

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        db_path: Path | str = ":memory:",
    ) -> CurationStore:
        """Create and populate a CurationStore from a serialized dictionary."""
        store = cls(db_path=db_path)
        store._load_state_from_mapping(data)
        return store

    @classmethod
    def from_json(
        cls,
        raw: str,
        db_path: Path | str = ":memory:",
    ) -> CurationStore:
        """Create and populate a CurationStore from a JSON string."""
        return cls.from_dict(json.loads(raw), db_path=db_path)

    def _import_json_impl(
        target: Any,
        path: Path | str,
        db_path: Path | str = ":memory:",
    ) -> CurationStore:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(target, CurationStore):
            target._load_state_from_mapping(data)
            return target
        return target.from_dict(data, db_path=db_path)

    import_json = _HybridImportMethod(_import_json_impl)


def _validate_anchor(anchor: Any) -> tuple[int, str]:
    if not isinstance(anchor, (tuple, list)) or len(anchor) != 2:
        raise ValueError("anchor must be an (entry_count, head_hash) tuple")
    count, head_hash = anchor
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("anchor entry_count must be a non-negative integer")
    if not isinstance(head_hash, str) or _HASH_PATTERN.fullmatch(head_hash) is None:
        raise ValueError("anchor head_hash must be 64 lowercase hex characters")
    if count == 0 and head_hash != GENESIS_HASH:
        raise ValueError("anchor with entry_count 0 must use GENESIS_HASH")
    return count, head_hash


def verify_audit_chain(
    store: CurationStore, anchor: Optional[tuple[int, str]] = None
) -> AuditChainReport:
    """Walk the audit log in `seq` order and report the first hash-chain break or anchor mismatch."""
    if not isinstance(store, CurationStore):
        raise ValueError("store must be a CurationStore instance")
    anchor_pair = _validate_anchor(anchor) if anchor is not None else None

    rows = store._conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
    entries = [store._row_to_audit_entry(r) for r in rows]
    known_hashes = {e.entry_hash for e in entries if e.entry_hash is not None}

    expected_prev = GENESIS_HASH
    for idx, entry in enumerate(entries):
        if entry.entry_hash is None or _compute_entry_hash(entry) != entry.entry_hash:
            return AuditChainReport(
                ok=False, entries_checked=idx, broken_index=idx, reason="hash_mismatch"
            )
        if entry.prev_hash != expected_prev:
            reason = (
                "prev_link_broken"
                if entry.prev_hash == GENESIS_HASH or entry.prev_hash in known_hashes
                else "gap"
            )
            return AuditChainReport(
                ok=False, entries_checked=idx, broken_index=idx, reason=reason
            )
        expected_prev = entry.entry_hash

    if anchor_pair is not None:
        count, head_hash = anchor_pair
        if count > 0 and (
            len(entries) < count or entries[count - 1].entry_hash != head_hash
        ):
            return AuditChainReport(
                ok=False,
                entries_checked=len(entries),
                broken_index=count - 1,
                reason="anchor_mismatch",
            )

    return AuditChainReport(ok=True, entries_checked=len(entries))


def _format_pin_rationale(
    existing_rationale: Optional[str],
    pinned_cls: ValidationClassification,
    notes: Optional[str],
) -> str:
    pin_clause = f"Pinned to {pinned_cls.value} by operator"
    if notes:
        pin_clause = f"{pin_clause} ({notes})"

    if not existing_rationale or not existing_rationale.strip():
        return pin_clause

    base = existing_rationale.strip()
    if pin_clause in base:
        return base

    marker = "Pinned to "
    if "; Pinned to " in base:
        base = base.split("; Pinned to ", 1)[0].strip()
    elif base.startswith(marker):
        return pin_clause

    return f"{base}; {pin_clause}" if base else pin_clause


def apply_curation_overlay(
    site: Site,
    store: CurationStore,
    results: Optional[Sequence[ValidationResult]] = None,
) -> tuple[Site, list[ValidationResult]]:
    """Non-destructively merge custom inventory records, field patches, deletions, and pinned classifications."""
    if not isinstance(site, Site):
        raise ValueError("site must be a Site instance")
    if not isinstance(store, CurationStore):
        raise ValueError("store must be a CurationStore instance")

    curated_site = Site.from_dict(site.to_dict())
    curated_results: list[ValidationResult] = (
        [
            ValidationResult.from_dict(r.to_dict())
            if isinstance(r, ValidationResult)
            else ValidationResult.from_dict(r)
            for r in results
        ]
        if results is not None
        else []
    )

    all_patches = [
        p
        for p in store.list_patches()
        if p.site_id is None or p.site_id == curated_site.site_id
    ]
    patches_by_key: dict[tuple[str, str], ItemEditPatch] = {
        (p.target_type, p.target_id): p for p in all_patches
    }
    deleted_keys: set[tuple[str, str]] = {
        key for key, p in patches_by_key.items() if p.deleted
    }

    # 1. Merge custom VLANs
    for custom_vlan in store._list_custom_vlans(site_id=curated_site.site_id):
        if ("VLAN", custom_vlan.vlan_id) in deleted_keys:
            continue
        vlan_copy = VLAN.from_dict(custom_vlan.to_dict())
        replaced = False
        for idx, existing_vlan in enumerate(curated_site.vlans):
            if existing_vlan.vlan_id == vlan_copy.vlan_id:
                curated_site.vlans[idx] = vlan_copy
                replaced = True
                break
        if not replaced:
            curated_site.vlans.append(vlan_copy)

    # 2. Merge custom Subnets
    for custom_subnet in store._list_custom_subnets(site_id=curated_site.site_id):
        if ("Subnet", custom_subnet.subnet_id) in deleted_keys:
            continue
        subnet_copy = Subnet.from_dict(custom_subnet.to_dict())
        replaced = False
        for idx, existing_subnet in enumerate(curated_site.subnets):
            if existing_subnet.subnet_id == subnet_copy.subnet_id:
                curated_site.subnets[idx] = subnet_copy
                replaced = True
                break
        if not replaced:
            curated_site.subnets.append(subnet_copy)

    # 3. Merge custom NetworkDevices
    for custom_dev in store._list_custom_devices(site_id=curated_site.site_id):
        if ("NetworkDevice", custom_dev.device_id) in deleted_keys:
            continue
        dev_copy = NetworkDevice.from_dict(custom_dev.to_dict())
        replaced = False
        for idx, existing_dev in enumerate(curated_site.devices):
            if existing_dev.device_id == dev_copy.device_id:
                curated_site.devices[idx] = dev_copy
                replaced = True
                break
        if not replaced:
            curated_site.devices.append(dev_copy)

    # 4. Merge custom/updated Ports into devices in site
    devices_by_id: dict[str, NetworkDevice] = {
        d.device_id: d for d in curated_site.devices
    }
    for dev_id, port_site_id, custom_port in store._list_custom_ports(
        site_id=curated_site.site_id
    ):
        if ("Port", custom_port.port_id) in deleted_keys:
            continue
        target_dev = devices_by_id.get(dev_id)
        if target_dev is None:
            continue
        port_copy = Port.from_dict(custom_port.to_dict())
        if port_copy.device_id != dev_id:
            port_copy = replace(port_copy, device_id=dev_id)
        replaced = False
        for idx, existing_port in enumerate(target_dev.ports):
            if existing_port.port_id == port_copy.port_id:
                target_dev.ports[idx] = port_copy
                replaced = True
                break
        if not replaced:
            target_dev.ports.append(port_copy)

    # 5. Merge custom Equipment
    for custom_eq in store._list_custom_equipment(site_id=curated_site.site_id):
        if ("Equipment", custom_eq.equipment_id) in deleted_keys:
            continue
        eq_copy = Equipment.from_dict(custom_eq.to_dict())
        replaced = False
        for idx, existing_eq in enumerate(curated_site.equipment):
            if existing_eq.equipment_id == eq_copy.equipment_id:
                curated_site.equipment[idx] = eq_copy
                replaced = True
                break
        if not replaced:
            curated_site.equipment.append(eq_copy)

    # 6. Apply deletions to Site collections
    if deleted_keys:
        curated_site.devices = [
            d
            for d in curated_site.devices
            if ("NetworkDevice", d.device_id) not in deleted_keys
        ]
        for dev in curated_site.devices:
            dev.ports = [
                p for p in dev.ports if ("Port", p.port_id) not in deleted_keys
            ]
        curated_site.vlans = [
            v
            for v in curated_site.vlans
            if ("VLAN", v.vlan_id) not in deleted_keys
        ]
        curated_site.subnets = [
            s
            for s in curated_site.subnets
            if ("Subnet", s.subnet_id) not in deleted_keys
        ]
        curated_site.ip_addresses = [
            ip_rec
            for ip_rec in curated_site.ip_addresses
            if ("IPAddress", ip_rec.ip) not in deleted_keys
        ]
        curated_site.equipment = [
            e
            for e in curated_site.equipment
            if ("Equipment", e.equipment_id) not in deleted_keys
        ]

    # 7. Apply field patches to Site items
    for dev in curated_site.devices:
        dev_patch = patches_by_key.get(("NetworkDevice", dev.device_id))
        if dev_patch is not None and not dev_patch.deleted:
            new_hostname = (
                dev_patch.hostname
                if dev_patch.hostname is not None
                else dev_patch.name
            )
            if new_hostname is not None:
                dev.hostname = new_hostname
            new_role = (
                dev_patch.role
                if dev_patch.role is not None
                else (
                    dev_patch.category.value
                    if isinstance(dev_patch.category, EquipmentCategory)
                    else dev_patch.category
                )
            )
            if new_role is not None:
                dev.role = new_role
            if dev_patch.vendor is not None:
                dev.vendor = dev_patch.vendor
            if dev_patch.model is not None:
                dev.model = dev_patch.model
            if dev_patch.room is not None and dev_patch.room not in curated_site.rooms:
                curated_site.rooms.append(dev_patch.room)

        for port in dev.ports:
            port_patch = patches_by_key.get(("Port", port.port_id))
            if port_patch is not None and not port_patch.deleted:
                new_port_name = (
                    port_patch.name
                    if port_patch.name is not None
                    else port_patch.hostname
                )
                if new_port_name is not None:
                    port.name = new_port_name
                if port_patch.vlan_id is not None:
                    port.vlan_id = port_patch.vlan_id

    for vlan in curated_site.vlans:
        vlan_patch = patches_by_key.get(("VLAN", vlan.vlan_id))
        if vlan_patch is not None and not vlan_patch.deleted:
            new_vlan_name = (
                vlan_patch.name
                if vlan_patch.name is not None
                else vlan_patch.hostname
            )
            if new_vlan_name is not None:
                vlan.name = new_vlan_name
            if vlan_patch.subnet_id is not None:
                vlan.subnet_id = vlan_patch.subnet_id

    for subnet in curated_site.subnets:
        subnet_patch = patches_by_key.get(("Subnet", subnet.subnet_id))
        if subnet_patch is not None and not subnet_patch.deleted:
            new_subnet_name = (
                subnet_patch.name
                if subnet_patch.name is not None
                else subnet_patch.hostname
            )
            if new_subnet_name is not None:
                subnet.name = new_subnet_name
            if subnet_patch.vlan_id is not None:
                subnet.vlan_id = subnet_patch.vlan_id

    for ip_rec in curated_site.ip_addresses:
        ip_patch = patches_by_key.get(("IPAddress", ip_rec.ip))
        if ip_patch is not None and not ip_patch.deleted:
            if ip_patch.subnet_id is not None:
                ip_rec.subnet_id = ip_patch.subnet_id

    for eq in curated_site.equipment:
        eq_patch = patches_by_key.get(("Equipment", eq.equipment_id))
        if eq_patch is not None and not eq_patch.deleted:
            new_eq_name = (
                eq_patch.name
                if eq_patch.name is not None
                else eq_patch.hostname
            )
            if new_eq_name is not None:
                eq.name = new_eq_name
            raw_cat = (
                eq_patch.category
                if eq_patch.category is not None
                else eq_patch.role
            )
            if raw_cat is not None:
                eq.category = _coerce_equipment_category(raw_cat, "category")
            if eq_patch.room is not None and eq_patch.room not in curated_site.rooms:
                curated_site.rooms.append(eq_patch.room)

    # 8. Build item name index for ValidationResult updates and synthesis
    site_item_names: dict[tuple[str, str], str] = {}
    for dev in curated_site.devices:
        site_item_names[("NetworkDevice", dev.device_id)] = dev.hostname
        for port in dev.ports:
            site_item_names[("Port", port.port_id)] = port.name
    for vlan in curated_site.vlans:
        site_item_names[("VLAN", vlan.vlan_id)] = vlan.name or vlan.vlan_id
    for subnet in curated_site.subnets:
        site_item_names[("Subnet", subnet.subnet_id)] = (
            subnet.name or subnet.cidr
        )
    for ip_rec in curated_site.ip_addresses:
        site_item_names[("IPAddress", ip_rec.ip)] = ip_rec.ip
    for eq in curated_site.equipment:
        site_item_names[("Equipment", eq.equipment_id)] = eq.name

    # 9. Filter deleted items from results and apply patches / pinned_classification
    updated_results: list[ValidationResult] = []
    seen_result_keys: set[tuple[str, str]] = set()

    for res in curated_results:
        try:
            norm_type = _normalize_target_type(res.item_type, "item_type")
        except ValueError:
            norm_type = res.item_type

        key = (norm_type, res.item_id)
        if key in deleted_keys:
            continue

        seen_result_keys.add(key)
        patch = patches_by_key.get(key)
        if key in site_item_names:
            res.name = site_item_names[key]
        elif patch is not None:
            patched_name = patch.name or patch.hostname
            if patched_name is not None:
                res.name = patched_name

        if patch is not None and not patch.deleted:
            if isinstance(
                patch.pinned_classification, ValidationClassification
            ):
                res.classification = patch.pinned_classification
                res.confidence = 1.0
                res.rationale = _format_pin_rationale(
                    res.rationale, patch.pinned_classification, patch.notes
                )
            elif patch.notes:
                note_clause = f"Operator note: {patch.notes}"
                if not res.rationale:
                    res.rationale = note_clause
                elif note_clause not in res.rationale and patch.notes not in res.rationale:
                    res.rationale = f"{res.rationale}; {note_clause}"

        updated_results.append(res)

    # 10. Synthesize ValidationResult for pinned items in site not yet in results
    for (target_type, target_id), item_name in site_item_names.items():
        if (target_type, target_id) in seen_result_keys:
            continue
        patch = patches_by_key.get((target_type, target_id))
        if (
            patch is not None
            and not patch.deleted
            and isinstance(patch.pinned_classification, ValidationClassification)
        ):
            updated_results.append(
                ValidationResult(
                    item_type=target_type,
                    item_id=target_id,
                    site_id=curated_site.site_id,
                    name=item_name,
                    classification=patch.pinned_classification,
                    confidence=1.0,
                    signals=[],
                    rationale=_format_pin_rationale(
                        None, patch.pinned_classification, patch.notes
                    ),
                    evaluated_at=patch.updated_at,
                )
            )
            seen_result_keys.add((target_type, target_id))

    return curated_site, updated_results


__all__ = [
    "AuditLogEntry",
    "CurationStore",
    "ItemEditPatch",
    "apply_curation_overlay",
]
