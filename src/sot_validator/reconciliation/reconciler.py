"""Reverse discovery and untracked inventory (Shadow IT) reconciler."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import io
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    Site,
    Subnet,
    ValidationSignal,
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.signals.hypervisor import (
    HypervisorInventoryProvider,
    HypervisorVmRecord,
    MultiVCenterInventoryProvider,
    VmPowerState,
    _extract_equipment_vm_hints,
    _format_mac_canonical,
    _instances_match,
    _normalize_ip,
    _normalize_mac,
    _normalize_uuid,
)
from sot_validator.signals.icmp import IcmpProbeResponse
from sot_validator.signals.management import (
    APC_ENTERPRISE_OID_PREFIX,
    EXTREME_ENTERPRISE_OID_PREFIX,
    FixtureManagementTransport,
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_NAME,
    parse_apc_ups_oids,
    parse_extreme_switch_oids,
)

VALID_DISCREPANCY_SOURCES: frozenset[str] = frozenset(
    {"vcenter", "arp", "snmp", "icmp"}
)

DISCREPANCY_CSV_COLUMNS: tuple[str, ...] = (
    "discrepancy_id",
    "discrepancy_type",
    "site_id",
    "observed_identifier",
    "observed_ip",
    "observed_mac",
    "observed_hostname",
    "source",
    "sot_item_id",
    "details",
    "recommended_onboarding_action",
)

ONBOARDING_CSV_COLUMNS: tuple[str, ...] = (
    "record_type",
    "target_table",
    "item_id",
    "site_id",
    "subnet_id",
    "hostname",
    "category_or_role",
    "vendor",
    "model",
    "ip_address",
    "mac_address",
    "hypervisor_id",
    "source",
    "notes",
)


class DiscrepancyType(str, Enum):
    """Supported reverse-discovery discrepancy types."""

    UNTRACKED_VM = "UNTRACKED_VM"
    UNTRACKED_IP = "UNTRACKED_IP"
    UNTRACKED_DEVICE = "UNTRACKED_DEVICE"
    ATTRIBUTE_MISMATCH = "ATTRIBUTE_MISMATCH"


ALL_DISCREPANCY_TYPES: tuple[DiscrepancyType, ...] = (
    DiscrepancyType.UNTRACKED_VM,
    DiscrepancyType.UNTRACKED_IP,
    DiscrepancyType.UNTRACKED_DEVICE,
    DiscrepancyType.ATTRIBUTE_MISMATCH,
)


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    text = str(value).strip()
    return text if text else None


def _resolve_timestamp(value: Optional[datetime | str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = _parse_optional_datetime(value, "generated_at")
    assert parsed is not None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_hostname(hostname: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(hostname)
    if cleaned is None:
        return None
    return cleaned.lower().rstrip(".")


def _short_hostname(hostname: Optional[str]) -> Optional[str]:
    norm = _normalize_hostname(hostname)
    if norm is None:
        return None
    return norm.split(".", 1)[0]


def _hostnames_match(host_a: Optional[str], host_b: Optional[str]) -> bool:
    norm_a = _normalize_hostname(host_a)
    norm_b = _normalize_hostname(host_b)
    if norm_a is None or norm_b is None:
        return False
    if norm_a == norm_b:
        return True
    if norm_a.startswith(norm_b + ".") or norm_b.startswith(norm_a + "."):
        return True
    short_a = _short_hostname(norm_a)
    short_b = _short_hostname(norm_b)
    if ("." not in norm_a or "." not in norm_b) and short_a and short_a == short_b:
        return True
    return False


def _slugify_id(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", raw.strip().lower()).strip("-")
    return cleaned or "item"


def _sql_literal(value: Optional[str]) -> str:
    if value is None:
        return "NULL"
    escaped = str(value).replace("'", "''")
    return f"'{escaped}'"


def _extract_detail_kv(details: Optional[str]) -> dict[str, str]:
    if not details:
        return {}
    result: dict[str, str] = {}
    for match in re.finditer(r"([a-z_]+)=([^,)\s]+)", details):
        key = match.group(1).strip()
        val = match.group(2).strip().strip("'\"")
        if val and val.lower() not in ("none", "n/a", "null"):
            result[key] = val
    return result


def _infer_subnet_id(site_id: str, ip_str: Optional[str], hint: Optional[str] = None) -> str:
    if hint and hint.strip():
        return hint.strip()
    site_num_match = re.search(r"(\d+)$", site_id)
    site_token = site_num_match.group(1).zfill(3) if site_num_match else _slugify_id(site_id)
    if ip_str:
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            if isinstance(addr, ipaddress.IPv4Address):
                third_octet = int(str(addr).split(".")[2])
                return f"sub-{site_token}-{third_octet:03d}"
        except ValueError:
            pass
    return f"sub-{site_token}-001"


@dataclass
class DiscrepancyRecord:
    """Single reverse-discovery discrepancy or attribute mismatch record."""

    discrepancy_id: str
    discrepancy_type: DiscrepancyType
    site_id: str
    observed_identifier: str
    observed_ip: Optional[str] = None
    observed_mac: Optional[str] = None
    observed_hostname: Optional[str] = None
    source: str = "vcenter"
    sot_item_id: Optional[str] = None
    details: Optional[str] = None
    recommended_onboarding_action: Optional[str] = None

    def __post_init__(self) -> None:
        self.discrepancy_id = _require_non_empty_str(
            self.discrepancy_id, "discrepancy_id"
        ).strip()
        if not isinstance(self.discrepancy_type, DiscrepancyType):
            try:
                self.discrepancy_type = DiscrepancyType(self.discrepancy_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid discrepancy_type: {self.discrepancy_type!r}"
                ) from exc
        self.site_id = _require_non_empty_str(self.site_id, "site_id").strip()
        self.observed_identifier = _require_non_empty_str(
            self.observed_identifier, "observed_identifier"
        ).strip()
        self.observed_ip = _clean_optional_str(self.observed_ip)
        self.observed_mac = _format_mac_canonical(self.observed_mac)
        self.observed_hostname = _clean_optional_str(self.observed_hostname)

        raw_source = _require_non_empty_str(self.source, "source").strip().lower()
        if raw_source not in VALID_DISCREPANCY_SOURCES:
            raise ValueError(
                f"Invalid source {self.source!r}; must be one of {sorted(VALID_DISCREPANCY_SOURCES)}"
            )
        self.source = raw_source
        self.sot_item_id = _clean_optional_str(self.sot_item_id)
        self.details = _clean_optional_str(self.details)
        self.recommended_onboarding_action = _clean_optional_str(
            self.recommended_onboarding_action
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "discrepancy_id": self.discrepancy_id,
            "discrepancy_type": self.discrepancy_type.value,
            "site_id": self.site_id,
            "observed_identifier": self.observed_identifier,
            "observed_ip": self.observed_ip,
            "observed_mac": self.observed_mac,
            "observed_hostname": self.observed_hostname,
            "source": self.source,
            "sot_item_id": self.sot_item_id,
            "details": self.details,
            "recommended_onboarding_action": self.recommended_onboarding_action,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DiscrepancyRecord:
        return cls(
            discrepancy_id=data["discrepancy_id"],
            discrepancy_type=DiscrepancyType(data["discrepancy_type"]),
            site_id=data["site_id"],
            observed_identifier=data["observed_identifier"],
            observed_ip=data.get("observed_ip"),
            observed_mac=data.get("observed_mac"),
            observed_hostname=data.get("observed_hostname"),
            source=data.get("source", "vcenter"),
            sot_item_id=data.get("sot_item_id"),
            details=data.get("details"),
            recommended_onboarding_action=data.get("recommended_onboarding_action"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> DiscrepancyRecord:
        return cls.from_dict(json.loads(raw))


@dataclass
class ReconciliationReport:
    """Aggregated reverse-discovery reconciliation report across sites."""

    discrepancies: list[DiscrepancyRecord] = field(default_factory=list)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        self.generated_at = _resolve_timestamp(self.generated_at)
        self.discrepancies = [
            d if isinstance(d, DiscrepancyRecord) else DiscrepancyRecord.from_dict(d)
            for d in (self.discrepancies or [])
        ]

    @property
    def total_discrepancies(self) -> int:
        return len(self.discrepancies)

    @property
    def summary_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {
            dtype.value: 0 for dtype in ALL_DISCREPANCY_TYPES
        }
        for disc in self.discrepancies:
            counts[disc.discrepancy_type.value] = (
                counts.get(disc.discrepancy_type.value, 0) + 1
            )
        return counts

    @property
    def summary_by_site(self) -> dict[str, dict[str, Any]]:
        summary: dict[str, dict[str, Any]] = {}
        for site_id in sorted({d.site_id for d in self.discrepancies}):
            site_items = [d for d in self.discrepancies if d.site_id == site_id]
            by_type = {
                dtype.value: sum(
                    1 for d in site_items if d.discrepancy_type is dtype
                )
                for dtype in ALL_DISCREPANCY_TYPES
            }
            summary[site_id] = {
                "site_id": site_id,
                "total": len(site_items),
                **by_type,
                "by_type": dict(by_type),
            }
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": _format_optional_datetime(self.generated_at),
            "total_discrepancies": self.total_discrepancies,
            "summary_by_type": self.summary_by_type,
            "summary_by_site": self.summary_by_site,
            "discrepancies": [d.to_dict() for d in self.discrepancies],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReconciliationReport:
        raw_discs = data.get("discrepancies", [])
        return cls(
            discrepancies=[
                d if isinstance(d, DiscrepancyRecord) else DiscrepancyRecord.from_dict(d)
                for d in raw_discs
            ],
            generated_at=_resolve_timestamp(data.get("generated_at")),
        )

    def to_json(
        self,
        *,
        indent: Optional[int] = 2,
        output_path: Optional[Path | str] = None,
    ) -> str:
        content = json.dumps(self.to_dict(), indent=indent)
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content

    @classmethod
    def from_json(cls, raw: str | Path) -> ReconciliationReport:
        if isinstance(raw, Path):
            raw_text = raw.read_text(encoding="utf-8")
        else:
            raw_text = raw
        return cls.from_dict(json.loads(raw_text))

    def to_csv(self, *, output_path: Optional[Path | str] = None) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(DISCREPANCY_CSV_COLUMNS)
        for disc in self.discrepancies:
            writer.writerow(
                [
                    disc.discrepancy_id,
                    disc.discrepancy_type.value,
                    disc.site_id,
                    disc.observed_identifier,
                    disc.observed_ip or "",
                    disc.observed_mac or "",
                    disc.observed_hostname or "",
                    disc.source,
                    disc.sot_item_id or "",
                    disc.details or "",
                    disc.recommended_onboarding_action or "",
                ]
            )
        content = buf.getvalue()
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content

    def _build_onboarding_entries(self) -> list[dict[str, Optional[str]]]:
        entries: list[dict[str, Optional[str]]] = []
        timestamp_str = _format_optional_datetime(self.generated_at)

        for idx, disc in enumerate(self.discrepancies, start=1):
            if disc.discrepancy_type is DiscrepancyType.ATTRIBUTE_MISMATCH:
                continue

            kv = _extract_detail_kv(disc.details)
            subnet_id = _infer_subnet_id(
                disc.site_id, disc.observed_ip, kv.get("subnet_id")
            )
            notes = disc.recommended_onboarding_action or disc.details or ""

            if disc.discrepancy_type is DiscrepancyType.UNTRACKED_VM:
                hostname = disc.observed_hostname or disc.observed_identifier
                short_slug = _slugify_id(_short_hostname(hostname) or disc.observed_identifier)
                item_id = kv.get("item_id") or f"eq-{_slugify_id(disc.site_id)}-vm-{short_slug}"
                vcenter_inst = kv.get("vcenter_instance") or "vcenter-default"
                vm_moref = kv.get("vm_moref") or (
                    disc.observed_identifier
                    if disc.observed_identifier.lower().startswith("vm-")
                    else f"vm-{idx:04d}"
                )
                bios_uuid = kv.get("bios_uuid") or (
                    disc.observed_identifier
                    if "-" in disc.observed_identifier
                    and len(disc.observed_identifier) >= 32
                    else None
                )
                hypervisor_id = (
                    f"{vcenter_inst}:{vm_moref}"
                    if vcenter_inst and vm_moref
                    else (bios_uuid or disc.observed_identifier)
                )
                entries.append(
                    {
                        "record_type": DiscrepancyType.UNTRACKED_VM.value,
                        "target_table": "equipment",
                        "item_id": item_id,
                        "site_id": disc.site_id,
                        "subnet_id": subnet_id if disc.observed_ip else "",
                        "hostname": hostname,
                        "category_or_role": "VM",
                        "vendor": kv.get("vendor") or "VMware",
                        "model": kv.get("model") or "Virtual Machine",
                        "ip_address": disc.observed_ip,
                        "mac_address": disc.observed_mac,
                        "hypervisor_id": hypervisor_id,
                        "vcenter_instance": vcenter_inst,
                        "vcenter_bios_uuid": bios_uuid,
                        "vcenter_moref": vm_moref,
                        "source": disc.source,
                        "notes": notes,
                        "last_seen": timestamp_str,
                    }
                )

            elif disc.discrepancy_type is DiscrepancyType.UNTRACKED_DEVICE:
                hostname = disc.observed_hostname or disc.observed_identifier
                short_slug = _slugify_id(_short_hostname(hostname) or disc.observed_identifier)
                details_lower = (disc.details or "").lower()
                if "vendor" in kv:
                    vendor = kv["vendor"].replace("_", " ")
                elif "extreme" in details_lower:
                    vendor = "Extreme Networks"
                elif "apc" in details_lower or "smart-ups" in details_lower:
                    vendor = "APC"
                else:
                    vendor = "Unknown"

                if "model" in kv:
                    model = kv["model"].replace("_", " ")
                elif vendor == "Extreme Networks":
                    model = "ExtremeSwitching"
                elif vendor == "APC":
                    model = "Smart-UPS"
                else:
                    model = "Unknown"

                if "role" in kv:
                    role = kv["role"]
                elif vendor == "APC":
                    role = "ups"
                else:
                    role = "access-switch"

                item_id = kv.get("item_id") or f"dev-{_slugify_id(disc.site_id)}-{short_slug}"
                entries.append(
                    {
                        "record_type": DiscrepancyType.UNTRACKED_DEVICE.value,
                        "target_table": "network_devices",
                        "item_id": item_id,
                        "site_id": disc.site_id,
                        "subnet_id": subnet_id if disc.observed_ip else "",
                        "hostname": hostname,
                        "category_or_role": role,
                        "vendor": vendor,
                        "model": model,
                        "ip_address": disc.observed_ip or disc.observed_identifier,
                        "mac_address": disc.observed_mac,
                        "hypervisor_id": None,
                        "room": kv.get("room") or "MDF-101",
                        "os_version": kv.get("os_version"),
                        "serial_number": kv.get("serial_number"),
                        "source": disc.source,
                        "notes": notes,
                        "last_seen": timestamp_str,
                    }
                )

            elif disc.discrepancy_type is DiscrepancyType.UNTRACKED_IP:
                ip_val = disc.observed_ip or disc.observed_identifier
                ip_slug = _slugify_id(ip_val)
                item_id = kv.get("item_id") or f"ip-{_slugify_id(disc.site_id)}-{ip_slug}"
                target_type = kv.get("target_type") or (
                    "network_device" if disc.source == "snmp" else "equipment"
                )
                target_id = kv.get("target_id") or (
                    f"eq-{_slugify_id(disc.site_id)}-{ip_slug}"
                    if target_type == "equipment"
                    else f"dev-{_slugify_id(disc.site_id)}-{ip_slug}"
                )
                entries.append(
                    {
                        "record_type": DiscrepancyType.UNTRACKED_IP.value,
                        "target_table": "ip_arp_entries",
                        "item_id": item_id,
                        "site_id": disc.site_id,
                        "subnet_id": subnet_id,
                        "hostname": disc.observed_hostname,
                        "category_or_role": target_type,
                        "vendor": None,
                        "model": None,
                        "ip_address": ip_val,
                        "mac_address": disc.observed_mac,
                        "hypervisor_id": None,
                        "assigned_target_type": target_type,
                        "assigned_target_id": target_id,
                        "arp_source_device_id": kv.get("arp_source_device_id"),
                        "source": disc.source,
                        "notes": notes,
                        "last_seen": timestamp_str,
                    }
                )

        return entries

    def generate_onboarding_csv(
        self, *, output_path: Optional[Path | str] = None
    ) -> str:
        """Generate an operator-ready CSV import template for untracked active assets."""
        entries = self._build_onboarding_entries()
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(ONBOARDING_CSV_COLUMNS)

        for entry in entries:
            writer.writerow(
                [
                    entry.get("record_type") or "",
                    entry.get("target_table") or "",
                    entry.get("item_id") or "",
                    entry.get("site_id") or "",
                    entry.get("subnet_id") or "",
                    entry.get("hostname") or "",
                    entry.get("category_or_role") or "",
                    entry.get("vendor") or "",
                    entry.get("model") or "",
                    entry.get("ip_address") or "",
                    entry.get("mac_address") or "",
                    entry.get("hypervisor_id") or "",
                    entry.get("source") or "",
                    entry.get("notes") or "",
                ]
            )

        content = buf.getvalue()
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content

    def generate_onboarding_sql(
        self, *, output_path: Optional[Path | str] = None
    ) -> str:
        """Generate deterministic SQL INSERT INTO statements for untracked active assets."""
        entries = self._build_onboarding_entries()
        statements: list[str] = []

        for entry in entries:
            table = entry.get("target_table")
            if table == "equipment":
                stmt = (
                    "INSERT INTO equipment "
                    "(equipment_id, site_id, hostname, equipment_type, vendor, model, "
                    "primary_ip, mac_address, vcenter_instance, vcenter_bios_uuid, "
                    "vcenter_moref, connected_port_id, last_seen) VALUES ("
                    f"{_sql_literal(entry.get('item_id'))}, "
                    f"{_sql_literal(entry.get('site_id'))}, "
                    f"{_sql_literal(entry.get('hostname'))}, "
                    f"{_sql_literal(entry.get('category_or_role') or 'VM')}, "
                    f"{_sql_literal(entry.get('vendor') or 'VMware')}, "
                    f"{_sql_literal(entry.get('model') or 'Virtual Machine')}, "
                    f"{_sql_literal(entry.get('ip_address'))}, "
                    f"{_sql_literal(entry.get('mac_address'))}, "
                    f"{_sql_literal(entry.get('vcenter_instance'))}, "
                    f"{_sql_literal(entry.get('vcenter_bios_uuid'))}, "
                    f"{_sql_literal(entry.get('vcenter_moref'))}, "
                    "NULL, "
                    f"{_sql_literal(entry.get('last_seen'))}"
                    ");"
                )
                statements.append(stmt)
            elif table == "network_devices":
                stmt = (
                    "INSERT INTO network_devices "
                    "(device_id, site_id, hostname, vendor, model, role, mgmt_ip, "
                    "mac_address, room, os_version, serial_number, last_seen) VALUES ("
                    f"{_sql_literal(entry.get('item_id'))}, "
                    f"{_sql_literal(entry.get('site_id'))}, "
                    f"{_sql_literal(entry.get('hostname'))}, "
                    f"{_sql_literal(entry.get('vendor') or 'Unknown')}, "
                    f"{_sql_literal(entry.get('model') or 'Unknown')}, "
                    f"{_sql_literal(entry.get('category_or_role') or 'access-switch')}, "
                    f"{_sql_literal(entry.get('ip_address') or '0.0.0.0')}, "
                    f"{_sql_literal(entry.get('mac_address') or '00:00:00:00:00:00')}, "
                    f"{_sql_literal(entry.get('room') or 'MDF-101')}, "
                    f"{_sql_literal(entry.get('os_version'))}, "
                    f"{_sql_literal(entry.get('serial_number'))}, "
                    f"{_sql_literal(entry.get('last_seen'))}"
                    ");"
                )
                statements.append(stmt)
            elif table == "ip_arp_entries":
                stmt = (
                    "INSERT INTO ip_arp_entries "
                    "(ip_id, site_id, subnet_id, ip_address, mac_address, "
                    "assigned_target_type, assigned_target_id, arp_last_seen, "
                    "arp_source_device_id) VALUES ("
                    f"{_sql_literal(entry.get('item_id'))}, "
                    f"{_sql_literal(entry.get('site_id'))}, "
                    f"{_sql_literal(entry.get('subnet_id'))}, "
                    f"{_sql_literal(entry.get('ip_address'))}, "
                    f"{_sql_literal(entry.get('mac_address'))}, "
                    f"{_sql_literal(entry.get('assigned_target_type') or 'equipment')}, "
                    f"{_sql_literal(entry.get('assigned_target_id') or 'unassigned')}, "
                    f"{_sql_literal(entry.get('last_seen'))}, "
                    f"{_sql_literal(entry.get('arp_source_device_id'))}"
                    ");"
                )
                statements.append(stmt)

        content = "\n".join(statements) + ("\n" if statements else "")
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content


@dataclass
class _NormalizedArpObservation:
    ip: str
    mac: str
    site_id: Optional[str] = None
    subnet_id: Optional[str] = None
    arp_source_device_id: Optional[str] = None
    connected_port: Optional[str] = None
    hostname: Optional[str] = None


@dataclass
class _NormalizedSnmpObservation:
    ip: str
    sys_name: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    role: Optional[str] = None
    mac_address: Optional[str] = None
    os_version: Optional[str] = None
    serial_number: Optional[str] = None
    site_id: Optional[str] = None
    is_ups: bool = False


class InventoryReconciler:
    """Compares Site snapshots against live discovery feeds to surface untracked assets and drift."""

    def __init__(
        self,
        *,
        vcenter_provider: Optional[
            HypervisorInventoryProvider
            | Sequence[HypervisorVmRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        vms: Optional[Sequence[HypervisorVmRecord | Mapping[str, Any]]] = None,
        arp_entries: Optional[
            Sequence[ArpEntry | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        snmp_targets: Optional[
            Mapping[str, Any]
            | Sequence[Mapping[str, Any]]
            | FixtureManagementTransport
        ] = None,
        icmp_responses: Optional[
            Mapping[str, Any] | Sequence[Any]
        ] = None,
    ) -> None:
        self.vcenter_provider = vcenter_provider
        self.vms = vms
        self.arp_entries = arp_entries
        self.snmp_targets = snmp_targets
        self.icmp_responses = icmp_responses

    @staticmethod
    def _normalize_sites(
        sites: Sequence[Site | Mapping[str, Any]]
        | Mapping[str, Site | Mapping[str, Any]]
        | Site,
    ) -> dict[str, Site]:
        if isinstance(sites, Site):
            return {sites.site_id: sites}
        if isinstance(sites, Mapping):
            if "site_id" in sites and "name" in sites:
                single = Site.from_dict(sites)
                return {single.site_id: single}
            indexed: dict[str, Site] = {}
            for _, raw_site in sites.items():
                site_obj = (
                    raw_site if isinstance(raw_site, Site) else Site.from_dict(raw_site)
                )
                indexed[site_obj.site_id] = site_obj
            return dict(sorted(indexed.items(), key=lambda kv: kv[0]))
        indexed = {}
        for item in sites:
            site_obj = item if isinstance(item, Site) else Site.from_dict(item)
            indexed[site_obj.site_id] = site_obj
        return dict(sorted(indexed.items(), key=lambda kv: kv[0]))

    @staticmethod
    def _build_subnet_index(
        sites_by_id: Mapping[str, Site],
    ) -> list[tuple[str, Subnet, ipaddress.IPv4Network]]:
        subnet_index: list[tuple[str, Subnet, ipaddress.IPv4Network]] = []
        for site_id, site in sites_by_id.items():
            for subnet in site.subnets:
                try:
                    net = ipaddress.ip_network(subnet.cidr.strip(), strict=False)
                except ValueError:
                    continue
                if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 24:
                    subnet_index.append((site_id, subnet, net))
        return subnet_index

    @staticmethod
    def _match_ip_to_allocated_subnet(
        ip_str: Optional[str],
        subnet_index: Sequence[tuple[str, Subnet, ipaddress.IPv4Network]],
        *,
        site_id_filter: Optional[str] = None,
    ) -> Optional[tuple[str, Subnet, str]]:
        cleaned = _normalize_ip(ip_str)
        if not cleaned or "/" in cleaned:
            return None
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            return None
        if not isinstance(addr, ipaddress.IPv4Address):
            return None
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
            return None

        norm_ip = str(addr)
        filter_lower = site_id_filter.strip().lower() if site_id_filter else None
        for site_id, subnet, net in subnet_index:
            if filter_lower and site_id.lower() != filter_lower:
                continue
            if addr in net and addr != net.network_address and addr != net.broadcast_address:
                return site_id, subnet, norm_ip
        return None

    @staticmethod
    def _normalize_vm_records(
        vcenter_provider: Optional[
            HypervisorInventoryProvider
            | Sequence[HypervisorVmRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ],
        vms: Optional[Sequence[HypervisorVmRecord | Mapping[str, Any]]],
    ) -> list[HypervisorVmRecord]:
        records: list[HypervisorVmRecord] = []
        if isinstance(vcenter_provider, HypervisorInventoryProvider):
            records.extend(vcenter_provider.list_vms())
        elif isinstance(vcenter_provider, Mapping):
            provider = MultiVCenterInventoryProvider.from_dict(vcenter_provider)
            records.extend(provider.list_vms())
        elif isinstance(vcenter_provider, Sequence):
            for item in vcenter_provider:
                records.append(
                    item
                    if isinstance(item, HypervisorVmRecord)
                    else HypervisorVmRecord.from_dict(item)
                )

        if vms is not None:
            for item in vms:
                records.append(
                    item
                    if isinstance(item, HypervisorVmRecord)
                    else HypervisorVmRecord.from_dict(item)
                )
        return records

    @classmethod
    def _normalize_arp_observations(
        cls,
        arp_entries: Optional[
            Sequence[ArpEntry | Mapping[str, Any]] | Mapping[str, Any]
        ],
    ) -> list[_NormalizedArpObservation]:
        if arp_entries is None:
            return []

        raw_items: list[tuple[Optional[str], Any]] = []
        if isinstance(arp_entries, Mapping):
            if "ip" in arp_entries or "ip_address" in arp_entries:
                raw_items.append((None, arp_entries))
            else:
                for key, val in arp_entries.items():
                    if isinstance(val, str):
                        raw_items.append(
                            (None, {"ip": str(key), "arp_mac": val})
                        )
                    elif isinstance(val, ArpEntry):
                        raw_items.append((str(key), val))
                    elif isinstance(val, Mapping):
                        item_copy = dict(val)
                        if "ip" not in item_copy and "ip_address" not in item_copy:
                            item_copy["ip"] = str(key)
                            raw_items.append((None, item_copy))
                        else:
                            raw_items.append((str(key), item_copy))
                    elif isinstance(val, Sequence):
                        for entry in val:
                            raw_items.append((str(key), entry))
        else:
            for entry in arp_entries:
                raw_items.append((None, entry))

        observations: list[_NormalizedArpObservation] = []
        for site_hint, item in raw_items:
            if isinstance(item, ArpEntry):
                ip_val = _normalize_ip(item.ip)
                mac_val = _format_mac_canonical(item.arp_mac)
                if not ip_val or not mac_val:
                    continue
                resolved_site = (
                    site_hint
                    if site_hint and not site_hint[0].isdigit()
                    else None
                )
                observations.append(
                    _NormalizedArpObservation(
                        ip=ip_val,
                        mac=mac_val,
                        site_id=resolved_site,
                        subnet_id=_clean_optional_str(item.subnet_id),
                        arp_source_device_id=_clean_optional_str(
                            item.arp_source_device_id
                        ),
                    )
                )
            elif isinstance(item, Mapping):
                ip_val = _normalize_ip(
                    item.get("ip") or item.get("ip_address")
                )
                mac_val = _format_mac_canonical(
                    item.get("arp_mac")
                    or item.get("mac_address")
                    or item.get("mac")
                )
                if not ip_val or not mac_val:
                    continue
                explicit_site = _clean_optional_str(item.get("site_id")) or (
                    site_hint
                    if site_hint and not site_hint[0].isdigit()
                    else None
                )
                observations.append(
                    _NormalizedArpObservation(
                        ip=ip_val,
                        mac=mac_val,
                        site_id=explicit_site,
                        subnet_id=_clean_optional_str(item.get("subnet_id")),
                        arp_source_device_id=_clean_optional_str(
                            item.get("arp_source_device_id")
                            or item.get("device_id")
                        ),
                        connected_port=_clean_optional_str(
                            item.get("connected_port")
                            or item.get("connected_port_id")
                            or item.get("port_id")
                            or item.get("port_name")
                            or item.get("port")
                        ),
                        hostname=_clean_optional_str(item.get("hostname")),
                    )
                )
        return observations

    @classmethod
    def _normalize_snmp_observations(
        cls,
        snmp_targets: Optional[
            Mapping[str, Any]
            | Sequence[Mapping[str, Any]]
            | FixtureManagementTransport
        ],
    ) -> list[_NormalizedSnmpObservation]:
        if snmp_targets is None:
            return []

        raw_entries: list[tuple[Optional[str], Optional[str], Mapping[str, Any]]] = []
        if isinstance(snmp_targets, FixtureManagementTransport):
            for key, entry in snmp_targets._targets_by_id.items():
                raw_entries.append((snmp_targets.site_id, key, entry))
        elif isinstance(snmp_targets, Mapping):
            if "targets" in snmp_targets and isinstance(
                snmp_targets["targets"], Mapping
            ):
                fixture_site = _clean_optional_str(snmp_targets.get("site_id"))
                for key, entry in snmp_targets["targets"].items():
                    if isinstance(entry, Mapping):
                        raw_entries.append((fixture_site, str(key), entry))
            else:
                for key, entry in snmp_targets.items():
                    if isinstance(entry, Mapping):
                        raw_entries.append((None, str(key), entry))
        elif isinstance(snmp_targets, Sequence):
            for entry in snmp_targets:
                if isinstance(entry, Mapping):
                    raw_entries.append((None, None, entry))

        observations: list[_NormalizedSnmpObservation] = []
        for site_hint, key_hint, entry in raw_entries:
            if entry.get("snmp_reachable") is False or entry.get("reachable") is False:
                continue

            raw_oids = entry.get("oids")
            if isinstance(raw_oids, Mapping):
                oids: Mapping[str, Any] = raw_oids
            elif any(str(k).startswith("1.3.6.1.") for k in entry.keys()):
                oids = entry
            else:
                oids = {}

            if (
                entry.get("snmp_reachable") is None
                and entry.get("reachable") is None
                and not oids
                and not entry.get("sys_name")
                and not entry.get("hostname")
                and not entry.get("vendor")
            ):
                continue

            ip_val = _normalize_ip(
                entry.get("ip_address")
                or entry.get("ip")
                or entry.get("mgmt_ip")
                or entry.get("management_ip")
                or (key_hint if key_hint and key_hint[0].isdigit() else None)
            )
            if not ip_val:
                continue

            sys_descr = str(
                oids.get(SNMPV2_MIB_SYS_DESCR, entry.get("sys_descr", ""))
            )
            sys_descr_lower = sys_descr.lower()
            is_extreme = (
                any(
                    str(k).startswith(f"{EXTREME_ENTERPRISE_OID_PREFIX}.")
                    for k in oids
                )
                or "extreme" in sys_descr_lower
                or "extreme" in str(entry.get("vendor", "")).lower()
            )
            is_apc = (
                any(
                    str(k).startswith(f"{APC_ENTERPRISE_OID_PREFIX}.")
                    for k in oids
                )
                or "apc" in sys_descr_lower
                or "smart-ups" in sys_descr_lower
                or "apc" in str(entry.get("vendor", "")).lower()
            )

            parsed_metrics: dict[str, Any] = {}
            if is_extreme and oids:
                parsed_metrics = parse_extreme_switch_oids(oids)
            elif is_apc and oids:
                parsed_metrics = parse_apc_ups_oids(oids)

            sys_name = _clean_optional_str(
                parsed_metrics.get("sys_name")
                or oids.get(SNMPV2_MIB_SYS_NAME)
                or entry.get("sys_name")
                or entry.get("hostname")
                or entry.get("name")
            )
            vendor = _clean_optional_str(
                entry.get("vendor") or parsed_metrics.get("vendor")
            )
            model = _clean_optional_str(
                entry.get("model") or parsed_metrics.get("model")
            )
            if not model and is_extreme:
                model_match = re.search(r"\(([^)]+)\)", sys_descr)
                model = (
                    f"ExtremeSwitching {model_match.group(1)}"
                    if model_match
                    else "ExtremeSwitching"
                )
            elif not model and is_apc:
                model = "Smart-UPS"

            role = _clean_optional_str(
                entry.get("role")
                or entry.get("category")
                or ("ups" if is_apc else ("access-switch" if is_extreme else "network-device"))
            )
            mac_val = _format_mac_canonical(
                entry.get("mac_address") or entry.get("mac")
            )
            os_version = _clean_optional_str(
                entry.get("os_version") or parsed_metrics.get("os_version")
            )
            serial_number = _clean_optional_str(
                entry.get("serial_number") or parsed_metrics.get("serial_number")
            )
            site_id = _clean_optional_str(entry.get("site_id")) or site_hint

            observations.append(
                _NormalizedSnmpObservation(
                    ip=ip_val,
                    sys_name=sys_name,
                    vendor=vendor,
                    model=model,
                    role=role,
                    mac_address=mac_val,
                    os_version=os_version,
                    serial_number=serial_number,
                    site_id=site_id,
                    is_ups=is_apc,
                )
            )
        return observations

    @classmethod
    def _normalize_icmp_reachable_ips(
        cls,
        icmp_responses: Optional[Mapping[str, Any] | Sequence[Any]],
    ) -> list[str]:
        if icmp_responses is None:
            return []

        reachable_ips: list[str] = []

        def _add_ip(raw_ip: Any) -> None:
            norm = _normalize_ip(str(raw_ip) if raw_ip is not None else None)
            if norm and norm not in reachable_ips:
                reachable_ips.append(norm)

        if isinstance(icmp_responses, Mapping):
            if "targets" in icmp_responses and isinstance(
                icmp_responses["targets"], Mapping
            ):
                for entry in icmp_responses["targets"].values():
                    if isinstance(entry, Mapping) and entry.get("icmp_reachable"):
                        _add_ip(entry.get("ip_address") or entry.get("ip"))
            else:
                for key, val in icmp_responses.items():
                    if isinstance(val, bool):
                        if val:
                            _add_ip(key)
                    elif isinstance(val, IcmpProbeResponse):
                        if val.reachable:
                            _add_ip(key)
                    elif isinstance(val, ValidationSignal):
                        if val.status is SignalStatus.ACTIVE:
                            _add_ip(key)
                    elif isinstance(val, Mapping):
                        is_up = val.get(
                            "reachable", val.get("icmp_reachable", True)
                        )
                        if is_up:
                            _add_ip(val.get("ip_address") or val.get("ip") or key)
        elif isinstance(icmp_responses, Sequence) and not isinstance(
            icmp_responses, (str, bytes)
        ):
            for item in icmp_responses:
                if isinstance(item, str):
                    _add_ip(item)
                elif isinstance(item, Mapping):
                    if item.get("reachable", item.get("icmp_reachable", True)):
                        _add_ip(item.get("ip_address") or item.get("ip"))

        return reachable_ips

    @staticmethod
    def _collect_equipment_ips_and_macs(
        equipment: Equipment,
        site: Site,
    ) -> tuple[set[str], set[str]]:
        sot_ips: set[str] = set()
        sot_macs: set[str] = set()

        for raw_ip in equipment.assigned_ips:
            norm_ip = _normalize_ip(raw_ip)
            if norm_ip:
                sot_ips.add(norm_ip)

        for attr in ("mac_address", "mac_addresses"):
            attr_val = getattr(equipment, attr, None)
            if isinstance(attr_val, str):
                norm_m = _normalize_mac(attr_val)
                if norm_m:
                    sot_macs.add(norm_m)
            elif isinstance(attr_val, Iterable):
                for m in attr_val:
                    norm_m = _normalize_mac(str(m))
                    if norm_m:
                        sot_macs.add(norm_m)

        for ip_rec in site.ip_addresses:
            if (
                ip_rec.assigned_object_id == equipment.equipment_id
                or ip_rec.ip in sot_ips
            ):
                norm_ip = _normalize_ip(ip_rec.ip)
                if norm_ip:
                    sot_ips.add(norm_ip)
                for raw_mac in (
                    ip_rec.arp_mac,
                    ip_rec.arp_entry.arp_mac if ip_rec.arp_entry else None,
                ):
                    norm_m = _normalize_mac(raw_mac)
                    if norm_m:
                        sot_macs.add(norm_m)

        for dev in site.devices:
            for port in dev.ports:
                if (
                    port.connected_device_id == equipment.equipment_id
                    and port.connected_mac
                ):
                    norm_m = _normalize_mac(port.connected_mac)
                    if norm_m:
                        sot_macs.add(norm_m)

        return sot_ips, sot_macs

    @classmethod
    def _match_vm_to_equipment(
        cls,
        vm: HypervisorVmRecord,
        site: Site,
    ) -> tuple[Optional[Equipment], Optional[str]]:
        vm_uuids = {
            u
            for u in (
                _normalize_uuid(vm.bios_uuid),
                _normalize_uuid(vm.instance_uuid),
            )
            if u
        }
        vm_moref_lower = vm.vm_moref.lower()
        vm_macs = {
            norm for m in vm.mac_addresses if (norm := _normalize_mac(m)) is not None
        }
        vm_ips = {
            norm for ip in vm.ip_addresses if (norm := _normalize_ip(ip)) is not None
        }

        # Priority 1: BIOS / Instance UUID
        if vm_uuids:
            for eq in site.equipment:
                eq_uuids, _, _, _, _ = _extract_equipment_vm_hints(eq)
                if vm_uuids & set(eq_uuids):
                    return eq, "bios_uuid"

        # Priority 2: (vcenter_instance, vm_moref) or vm_moref
        fallback_moref_match: Optional[Equipment] = None
        for eq in site.equipment:
            _, inst_hint, moref_hint, _, _ = _extract_equipment_vm_hints(eq)
            if moref_hint and moref_hint.lower() == vm_moref_lower:
                if inst_hint is None or _instances_match(
                    inst_hint, vm.vcenter_instance
                ) or _instances_match(inst_hint, vm.vcenter_host):
                    return eq, "vm_moref"
                if fallback_moref_match is None:
                    fallback_moref_match = eq
        if fallback_moref_match is not None:
            return fallback_moref_match, "vm_moref"

        # Priority 3: MAC address or IP address
        ip_fallback_match: Optional[Equipment] = None
        for eq in site.equipment:
            eq_ips, eq_macs = cls._collect_equipment_ips_and_macs(eq, site)
            if vm_macs and (vm_macs & eq_macs):
                return eq, "mac"
            if vm_ips and (vm_ips & eq_ips) and ip_fallback_match is None:
                ip_fallback_match = eq
        if ip_fallback_match is not None:
            return ip_fallback_match, "ip"

        # Priority 4: Normalized hostname
        for eq in site.equipment:
            if _hostnames_match(eq.name, vm.vm_name) or (
                vm.guest_hostname is not None
                and _hostnames_match(eq.name, vm.guest_hostname)
            ):
                return eq, "hostname"

        return None, None

    def reconcile(
        self,
        sites: Sequence[Site | Mapping[str, Any]]
        | Mapping[str, Site | Mapping[str, Any]]
        | Site,
        *,
        vcenter_provider: Optional[
            HypervisorInventoryProvider
            | Sequence[HypervisorVmRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        vms: Optional[Sequence[HypervisorVmRecord | Mapping[str, Any]]] = None,
        arp_entries: Optional[
            Sequence[ArpEntry | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        snmp_targets: Optional[
            Mapping[str, Any]
            | Sequence[Mapping[str, Any]]
            | FixtureManagementTransport
        ] = None,
        icmp_responses: Optional[Mapping[str, Any] | Sequence[Any]] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> ReconciliationReport:
        """Compare Site snapshots against live discovery feeds and return a ReconciliationReport."""
        sites_by_id = self._normalize_sites(sites)
        subnet_index = self._build_subnet_index(sites_by_id)
        report_dt = _resolve_timestamp(generated_at)

        resolved_vc = (
            vcenter_provider
            if vcenter_provider is not None
            else self.vcenter_provider
        )
        resolved_vms = vms if vms is not None else self.vms
        resolved_arp = (
            arp_entries if arp_entries is not None else self.arp_entries
        )
        resolved_snmp = (
            snmp_targets if snmp_targets is not None else self.snmp_targets
        )
        resolved_icmp = (
            icmp_responses
            if icmp_responses is not None
            else self.icmp_responses
        )

        vm_records = self._normalize_vm_records(resolved_vc, resolved_vms)
        arp_observations = self._normalize_arp_observations(resolved_arp)
        snmp_observations = self._normalize_snmp_observations(resolved_snmp)
        icmp_ips = self._normalize_icmp_reachable_ips(resolved_icmp)

        discrepancies: list[DiscrepancyRecord] = []
        seq = 0

        def _next_id(site_id: str, dtype: DiscrepancyType) -> str:
            nonlocal seq
            seq += 1
            return f"disc-{_slugify_id(site_id)}-{dtype.value.lower().replace('_', '-')}-{seq:04d}"

        # Track active IPs discovered across feeds per (site_id, ip)
        # Value: dict with subnet, primary_source, mac, hostname, target_type, target_id, arp_source_device_id
        active_ip_observations: dict[tuple[str, str], dict[str, Any]] = {}

        def _record_active_ip(
            site_id: str,
            subnet: Subnet,
            ip_str: str,
            source: str,
            *,
            mac: Optional[str] = None,
            hostname: Optional[str] = None,
            target_type: Optional[str] = None,
            target_id: Optional[str] = None,
            arp_source_device_id: Optional[str] = None,
        ) -> None:
            key = (site_id, ip_str)
            existing = active_ip_observations.get(key)
            if existing is None:
                active_ip_observations[key] = {
                    "site_id": site_id,
                    "subnet": subnet,
                    "ip": ip_str,
                    "source": source,
                    "mac": _format_mac_canonical(mac),
                    "hostname": hostname,
                    "target_type": target_type,
                    "target_id": target_id,
                    "arp_source_device_id": arp_source_device_id,
                }
            else:
                if not existing.get("mac") and mac:
                    existing["mac"] = _format_mac_canonical(mac)
                if not existing.get("hostname") and hostname:
                    existing["hostname"] = hostname
                if not existing.get("target_type") and target_type:
                    existing["target_type"] = target_type
                if not existing.get("target_id") and target_id:
                    existing["target_id"] = target_id
                if not existing.get("arp_source_device_id") and arp_source_device_id:
                    existing["arp_source_device_id"] = arp_source_device_id

        # -------------------------------------------------------------------
        # 1. Multi-vCenter VM Reconciliation (UNTRACKED_VM & ATTRIBUTE_MISMATCH)
        # -------------------------------------------------------------------
        site_id_lookup = {sid.lower(): sid for sid in sites_by_id}

        for vm in vm_records:
            resolved_site_id: Optional[str] = None
            resolved_subnet: Optional[Subnet] = None
            primary_scoped_ip: Optional[str] = None

            if vm.site_id and vm.site_id.lower() in site_id_lookup:
                resolved_site_id = site_id_lookup[vm.site_id.lower()]

            for vm_ip in vm.ip_addresses:
                match = self._match_ip_to_allocated_subnet(
                    vm_ip,
                    subnet_index,
                    site_id_filter=resolved_site_id,
                )
                if match is not None:
                    resolved_site_id, resolved_subnet, primary_scoped_ip = match
                    break

            if resolved_site_id is None:
                if vm.site_id and vm.site_id.lower().startswith("site-"):
                    # Explicitly tagged for another site not in the current batch
                    continue
                if len(sites_by_id) == 1:
                    resolved_site_id = next(iter(sites_by_id.keys()))
                else:
                    continue

            site = sites_by_id[resolved_site_id]
            matched_eq, _ = self._match_vm_to_equipment(vm, site)

            # Record active VM NIC IPs inside allocated /24 subnets when VM is powered on
            if vm.power_state is VmPowerState.POWERED_ON:
                vm_short_slug = _slugify_id(
                    _short_hostname(vm.guest_hostname or vm.vm_name) or vm.vm_moref
                )
                inferred_eq_id = (
                    matched_eq.equipment_id
                    if matched_eq is not None
                    else f"eq-{_slugify_id(site.site_id)}-vm-{vm_short_slug}"
                )
                for vm_ip in vm.ip_addresses:
                    ip_match = self._match_ip_to_allocated_subnet(
                        vm_ip, subnet_index, site_id_filter=site.site_id
                    )
                    if ip_match is not None:
                        _, sub_obj, norm_vm_ip = ip_match
                        _record_active_ip(
                            site.site_id,
                            sub_obj,
                            norm_vm_ip,
                            "vcenter",
                            mac=vm.mac_addresses[0] if vm.mac_addresses else None,
                            hostname=vm.guest_hostname or vm.vm_name,
                            target_type="equipment",
                            target_id=inferred_eq_id,
                        )

            if matched_eq is None:
                if vm.power_state is not VmPowerState.POWERED_ON:
                    continue
                obs_ip = primary_scoped_ip or (
                    vm.ip_addresses[0] if vm.ip_addresses else None
                )
                obs_mac = vm.mac_addresses[0] if vm.mac_addresses else None
                obs_host = vm.guest_hostname or vm.vm_name
                obs_id = vm.bios_uuid or vm.vm_moref or vm.vm_name
                sub_token = resolved_subnet.subnet_id if resolved_subnet else ""
                short_slug = _slugify_id(_short_hostname(obs_host) or vm.vm_moref)
                suggested_eq_id = f"eq-{_slugify_id(site.site_id)}-vm-{short_slug}"
                discrepancies.append(
                    DiscrepancyRecord(
                        discrepancy_id=_next_id(
                            site.site_id, DiscrepancyType.UNTRACKED_VM
                        ),
                        discrepancy_type=DiscrepancyType.UNTRACKED_VM,
                        site_id=site.site_id,
                        observed_identifier=obs_id,
                        observed_ip=obs_ip,
                        observed_mac=obs_mac,
                        observed_hostname=obs_host,
                        source="vcenter",
                        sot_item_id=None,
                        details=(
                            f"Powered-on VM '{vm.vm_name}' on {vm.vcenter_instance} "
                            f"has no matching Equipment in SoT "
                            f"(item_id={suggested_eq_id}, vcenter_instance={vm.vcenter_instance}, "
                            f"vm_moref={vm.vm_moref}, bios_uuid={vm.bios_uuid or 'none'}, "
                            f"subnet_id={sub_token or 'none'}, "
                            f"guest_os={vm.guest_os_family or 'unknown'})"
                        ),
                        recommended_onboarding_action=(
                            f"Insert VM '{obs_host}' ({obs_ip or 'no-ip'}) as equipment "
                            f"'{suggested_eq_id}' in site {site.site_id}"
                        ),
                    )
                )
            else:
                # Check for ATTRIBUTE_MISMATCH between matched_eq and vm
                mismatch_reasons: list[str] = []

                name_matches_vm = _hostnames_match(matched_eq.name, vm.vm_name)
                name_matches_guest = (
                    _hostnames_match(matched_eq.name, vm.guest_hostname)
                    if vm.guest_hostname is not None
                    else True
                )
                if not name_matches_vm or not name_matches_guest:
                    live_host = vm.guest_hostname or vm.vm_name
                    mismatch_reasons.append(
                        f"hostname mismatch (SoT={matched_eq.name!r} vs vCenter={live_host!r})"
                    )

                sot_ips, sot_macs = self._collect_equipment_ips_and_macs(
                    matched_eq, site
                )
                vm_ips = {
                    norm
                    for ip in vm.ip_addresses
                    if (norm := _normalize_ip(ip)) is not None
                }
                if sot_ips and vm_ips and sot_ips.isdisjoint(vm_ips):
                    mismatch_reasons.append(
                        f"IP mismatch (SoT={sorted(sot_ips)} vs vCenter={sorted(vm_ips)})"
                    )

                vm_macs = {
                    norm
                    for m in vm.mac_addresses
                    if (norm := _normalize_mac(m)) is not None
                }
                if sot_macs and vm_macs and sot_macs.isdisjoint(vm_macs):
                    sot_canon = sorted(
                        _format_mac_canonical(m) or m for m in sot_macs
                    )
                    vm_canon = sorted(
                        _format_mac_canonical(m) or m for m in vm.mac_addresses
                    )
                    mismatch_reasons.append(
                        f"MAC mismatch (SoT={sot_canon} vs vCenter={vm_canon})"
                    )

                if mismatch_reasons:
                    discrepancies.append(
                        DiscrepancyRecord(
                            discrepancy_id=_next_id(
                                site.site_id, DiscrepancyType.ATTRIBUTE_MISMATCH
                            ),
                            discrepancy_type=DiscrepancyType.ATTRIBUTE_MISMATCH,
                            site_id=site.site_id,
                            observed_identifier=vm.bios_uuid or vm.vm_moref or vm.vm_name,
                            observed_ip=vm.ip_addresses[0] if vm.ip_addresses else None,
                            observed_mac=vm.mac_addresses[0] if vm.mac_addresses else None,
                            observed_hostname=vm.guest_hostname or vm.vm_name,
                            source="vcenter",
                            sot_item_id=matched_eq.equipment_id,
                            details=(
                                f"vCenter attribute drift on {matched_eq.equipment_id}: "
                                + "; ".join(mismatch_reasons)
                            ),
                            recommended_onboarding_action=(
                                f"Update SoT equipment '{matched_eq.equipment_id}' attributes "
                                "to match live vCenter inventory"
                            ),
                        )
                    )

        # -------------------------------------------------------------------
        # 2. SNMP / Management Discovery (UNTRACKED_DEVICE & ATTRIBUTE_MISMATCH)
        # -------------------------------------------------------------------
        for snmp_obs in snmp_observations:
            match = self._match_ip_to_allocated_subnet(
                snmp_obs.ip,
                subnet_index,
                site_id_filter=snmp_obs.site_id,
            )
            if match is None:
                continue
            site_id, subnet, norm_ip = match
            site = sites_by_id[site_id]

            # Match against site.devices or site.equipment
            matched_dev: Optional[NetworkDevice] = None
            matched_eq_snmp: Optional[Equipment] = None

            for dev in site.devices:
                if _normalize_ip(dev.management_ip) == norm_ip or (
                    snmp_obs.sys_name
                    and _hostnames_match(dev.hostname, snmp_obs.sys_name)
                ):
                    matched_dev = dev
                    break

            if matched_dev is None:
                for eq in site.equipment:
                    eq_ips = {_normalize_ip(ip) for ip in eq.assigned_ips if _normalize_ip(ip)}
                    if norm_ip in eq_ips or (
                        snmp_obs.sys_name
                        and _hostnames_match(eq.name, snmp_obs.sys_name)
                    ):
                        matched_eq_snmp = eq
                        break

            short_slug = _slugify_id(
                _short_hostname(snmp_obs.sys_name) or norm_ip
            )
            inferred_dev_id = (
                matched_dev.device_id
                if matched_dev is not None
                else (
                    matched_eq_snmp.equipment_id
                    if matched_eq_snmp is not None
                    else f"dev-{_slugify_id(site.site_id)}-{short_slug}"
                )
            )
            _record_active_ip(
                site.site_id,
                subnet,
                norm_ip,
                "snmp",
                mac=snmp_obs.mac_address,
                hostname=snmp_obs.sys_name,
                target_type=(
                    "equipment"
                    if matched_eq_snmp is not None
                    else "network_device"
                ),
                target_id=inferred_dev_id,
            )

            if matched_dev is None and matched_eq_snmp is None:
                vendor_tok = (snmp_obs.vendor or "Unknown").replace(" ", "_")
                model_tok = (snmp_obs.model or "Unknown").replace(" ", "_")
                role_tok = snmp_obs.role or "access-switch"
                discrepancies.append(
                    DiscrepancyRecord(
                        discrepancy_id=_next_id(
                            site.site_id, DiscrepancyType.UNTRACKED_DEVICE
                        ),
                        discrepancy_type=DiscrepancyType.UNTRACKED_DEVICE,
                        site_id=site.site_id,
                        observed_identifier=snmp_obs.sys_name or norm_ip,
                        observed_ip=norm_ip,
                        observed_mac=snmp_obs.mac_address,
                        observed_hostname=snmp_obs.sys_name,
                        source="snmp",
                        sot_item_id=None,
                        details=(
                            f"Untracked SNMP responder at {norm_ip} in subnet {subnet.subnet_id} "
                            f"(item_id={inferred_dev_id}, vendor={vendor_tok}, model={model_tok}, "
                            f"role={role_tok}, subnet_id={subnet.subnet_id}, "
                            f"os_version={snmp_obs.os_version or 'none'}, "
                            f"serial_number={snmp_obs.serial_number or 'none'})"
                        ),
                        recommended_onboarding_action=(
                            f"Onboard SNMP device '{snmp_obs.sys_name or norm_ip}' "
                            f"({snmp_obs.vendor or 'Unknown'}) into SoT for site {site.site_id}"
                        ),
                    )
                )
            else:
                # Check SNMP vs SoT ATTRIBUTE_MISMATCH
                mismatch_reasons = []
                if matched_dev is not None:
                    sot_id = matched_dev.device_id
                    sot_host = matched_dev.hostname
                    sot_ips = (
                        {_normalize_ip(matched_dev.management_ip)}
                        if _normalize_ip(matched_dev.management_ip)
                        else set()
                    )
                    sot_macs = {
                        norm
                        for ip_rec in site.ip_addresses
                        if (
                            ip_rec.assigned_object_id == matched_dev.device_id
                            or _normalize_ip(ip_rec.ip) in sot_ips
                        )
                        for raw_m in (
                            ip_rec.arp_mac,
                            ip_rec.arp_entry.arp_mac if ip_rec.arp_entry else None,
                        )
                        if (norm := _normalize_mac(raw_m)) is not None
                    }
                else:
                    assert matched_eq_snmp is not None
                    sot_id = matched_eq_snmp.equipment_id
                    sot_host = matched_eq_snmp.name
                    sot_ips, sot_macs = self._collect_equipment_ips_and_macs(
                        matched_eq_snmp, site
                    )

                if snmp_obs.sys_name and not _hostnames_match(
                    sot_host, snmp_obs.sys_name
                ):
                    mismatch_reasons.append(
                        f"sysName/hostname mismatch (SoT={sot_host!r} vs SNMP={snmp_obs.sys_name!r})"
                    )
                if sot_ips and norm_ip not in sot_ips:
                    mismatch_reasons.append(
                        f"management IP mismatch (SoT={sorted(sot_ips)} vs SNMP={norm_ip!r})"
                    )
                obs_norm_mac = _normalize_mac(snmp_obs.mac_address)
                if obs_norm_mac and sot_macs and obs_norm_mac not in sot_macs:
                    sot_canon = sorted(
                        _format_mac_canonical(m) or m for m in sot_macs
                    )
                    mismatch_reasons.append(
                        f"MAC mismatch (SoT={sot_canon} vs SNMP={snmp_obs.mac_address!r})"
                    )

                if mismatch_reasons:
                    discrepancies.append(
                        DiscrepancyRecord(
                            discrepancy_id=_next_id(
                                site.site_id, DiscrepancyType.ATTRIBUTE_MISMATCH
                            ),
                            discrepancy_type=DiscrepancyType.ATTRIBUTE_MISMATCH,
                            site_id=site.site_id,
                            observed_identifier=snmp_obs.sys_name or norm_ip,
                            observed_ip=norm_ip,
                            observed_mac=snmp_obs.mac_address,
                            observed_hostname=snmp_obs.sys_name,
                            source="snmp",
                            sot_item_id=sot_id,
                            details=(
                                f"SNMP attribute drift on {sot_id}: "
                                + "; ".join(mismatch_reasons)
                            ),
                            recommended_onboarding_action=(
                                f"Update SoT record '{sot_id}' to match SNMP discovery on {norm_ip}"
                            ),
                        )
                    )

        # -------------------------------------------------------------------
        # 3. ARP Discovery (Record active IPs & ARP vs SoT ATTRIBUTE_MISMATCH)
        # -------------------------------------------------------------------
        for arp_obs in arp_observations:
            match = self._match_ip_to_allocated_subnet(
                arp_obs.ip,
                subnet_index,
                site_id_filter=arp_obs.site_id,
            )
            if match is None:
                continue
            site_id, subnet, norm_ip = match
            site = sites_by_id[site_id]

            # Record for UNTRACKED_IP evaluation (ARP has priority over ICMP/vCenter/SNMP for IP source)
            existing_ip_obs = active_ip_observations.get((site_id, norm_ip))
            if existing_ip_obs is not None:
                existing_ip_obs["source"] = "arp"
                existing_ip_obs["mac"] = arp_obs.mac
                if arp_obs.arp_source_device_id:
                    existing_ip_obs["arp_source_device_id"] = arp_obs.arp_source_device_id
                if arp_obs.hostname and not existing_ip_obs.get("hostname"):
                    existing_ip_obs["hostname"] = arp_obs.hostname
            else:
                _record_active_ip(
                    site.site_id,
                    subnet,
                    norm_ip,
                    "arp",
                    mac=arp_obs.mac,
                    hostname=arp_obs.hostname,
                    arp_source_device_id=arp_obs.arp_source_device_id,
                )

            # Check if IP exists in site.ip_addresses or equipment/devices for ATTRIBUTE_MISMATCH
            matched_ip_rec = next(
                (
                    ip_rec
                    for ip_rec in site.ip_addresses
                    if _normalize_ip(ip_rec.ip) == norm_ip
                ),
                None,
            )
            matched_eq_arp = next(
                (
                    eq
                    for eq in site.equipment
                    if norm_ip
                    in {_normalize_ip(ip) for ip in eq.assigned_ips if _normalize_ip(ip)}
                    or (
                        matched_ip_rec is not None
                        and matched_ip_rec.assigned_object_id == eq.equipment_id
                    )
                ),
                None,
            )

            if matched_ip_rec is not None or matched_eq_arp is not None:
                mismatch_reasons = []
                obs_norm_mac = _normalize_mac(arp_obs.mac)

                recorded_macs: set[str] = set()
                if matched_ip_rec is not None:
                    for raw_m in (
                        matched_ip_rec.arp_mac,
                        matched_ip_rec.arp_entry.arp_mac
                        if matched_ip_rec.arp_entry
                        else None,
                    ):
                        if (norm_m := _normalize_mac(raw_m)) is not None:
                            recorded_macs.add(norm_m)

                if matched_eq_arp is not None:
                    _, eq_macs = self._collect_equipment_ips_and_macs(
                        matched_eq_arp, site
                    )
                    recorded_macs.update(eq_macs)

                if obs_norm_mac and recorded_macs and obs_norm_mac not in recorded_macs:
                    sot_canon = sorted(
                        _format_mac_canonical(m) or m for m in recorded_macs
                    )
                    mismatch_reasons.append(
                        f"ARP MAC mismatch for {norm_ip} (SoT={sot_canon} vs ARP={arp_obs.mac!r})"
                    )

                if (
                    arp_obs.arp_source_device_id
                    and matched_ip_rec is not None
                    and matched_ip_rec.arp_source_device_id
                    and arp_obs.arp_source_device_id.lower()
                    != matched_ip_rec.arp_source_device_id.lower()
                ):
                    mismatch_reasons.append(
                        f"ARP source switch mismatch for {norm_ip} "
                        f"(SoT={matched_ip_rec.arp_source_device_id!r} vs ARP={arp_obs.arp_source_device_id!r})"
                    )

                if arp_obs.connected_port and matched_eq_arp is not None:
                    allowed_port_refs: set[str] = {
                        p.strip().lower()
                        for p in matched_eq_arp.connected_ports
                        if p and p.strip()
                    }
                    for dev in site.devices:
                        for port in dev.ports:
                            if (
                                port.connected_device_id == matched_eq_arp.equipment_id
                                or port.port_id.lower() in allowed_port_refs
                            ):
                                allowed_port_refs.add(port.port_id.lower())
                                allowed_port_refs.add(port.name.lower())
                                allowed_port_refs.add(
                                    f"{dev.device_id}:{port.name}".lower()
                                )
                    if (
                        allowed_port_refs
                        and arp_obs.connected_port.lower() not in allowed_port_refs
                    ):
                        mismatch_reasons.append(
                            f"switch port mapping mismatch for {norm_ip} "
                            f"(SoT={matched_eq_arp.connected_ports} vs ARP={arp_obs.connected_port!r})"
                        )

                if mismatch_reasons:
                    sot_item_id = (
                        (
                            matched_ip_rec.assigned_object_id
                            if matched_ip_rec and matched_ip_rec.assigned_object_id
                            else None
                        )
                        or (
                            matched_eq_arp.equipment_id
                            if matched_eq_arp is not None
                            else None
                        )
                        or (matched_ip_rec.ip if matched_ip_rec is not None else norm_ip)
                    )
                    discrepancies.append(
                        DiscrepancyRecord(
                            discrepancy_id=_next_id(
                                site.site_id, DiscrepancyType.ATTRIBUTE_MISMATCH
                            ),
                            discrepancy_type=DiscrepancyType.ATTRIBUTE_MISMATCH,
                            site_id=site.site_id,
                            observed_identifier=norm_ip,
                            observed_ip=norm_ip,
                            observed_mac=arp_obs.mac,
                            observed_hostname=arp_obs.hostname,
                            source="arp",
                            sot_item_id=sot_item_id,
                            details=(
                                f"ARP attribute drift on {sot_item_id} ({norm_ip}): "
                                + "; ".join(mismatch_reasons)
                            ),
                            recommended_onboarding_action=(
                                f"Update SoT MAC/port assignment for '{sot_item_id}' ({norm_ip})"
                            ),
                        )
                    )

        # -------------------------------------------------------------------
        # 4. Scoped Active ICMP Discovery (Record active IPs)
        # -------------------------------------------------------------------
        for icmp_ip in icmp_ips:
            match = self._match_ip_to_allocated_subnet(icmp_ip, subnet_index)
            if match is None:
                continue
            site_id, subnet, norm_ip = match
            existing_obs = active_ip_observations.get((site_id, norm_ip))
            if existing_obs is None:
                _record_active_ip(site_id, subnet, norm_ip, "icmp")
            elif existing_obs["source"] in ("vcenter", "snmp"):
                # Keep richer MAC/hostname from vCenter/SNMP if present, or preserve source
                pass

        # -------------------------------------------------------------------
        # 5. Evaluate UNTRACKED_IP across all sites' allocated /24 subnets
        # -------------------------------------------------------------------
        for (site_id, norm_ip), obs in sorted(
            active_ip_observations.items(),
            key=lambda kv: (kv[0][0], ipaddress.ip_address(kv[0][1])),
        ):
            site = sites_by_id[site_id]
            recorded_site_ips = {
                norm
                for ip_rec in site.ip_addresses
                if (norm := _normalize_ip(ip_rec.ip)) is not None
            }
            if norm_ip in recorded_site_ips:
                continue

            subnet_obj: Subnet = obs["subnet"]
            src: str = obs["source"]
            mac_val: Optional[str] = obs.get("mac")
            host_val: Optional[str] = obs.get("hostname")
            t_type: str = obs.get("target_type") or (
                "network_device" if src == "snmp" else "equipment"
            )
            ip_slug = _slugify_id(norm_ip)
            t_id: str = obs.get("target_id") or (
                f"dev-{_slugify_id(site_id)}-{ip_slug}"
                if t_type == "network_device"
                else f"eq-{_slugify_id(site_id)}-{ip_slug}"
            )
            arp_dev: Optional[str] = obs.get("arp_source_device_id")
            item_id = f"ip-{_slugify_id(site_id)}-{ip_slug}"

            discrepancies.append(
                DiscrepancyRecord(
                    discrepancy_id=_next_id(site_id, DiscrepancyType.UNTRACKED_IP),
                    discrepancy_type=DiscrepancyType.UNTRACKED_IP,
                    site_id=site_id,
                    observed_identifier=norm_ip,
                    observed_ip=norm_ip,
                    observed_mac=mac_val,
                    observed_hostname=host_val,
                    source=src,
                    sot_item_id=None,
                    details=(
                        f"Active IP {norm_ip} in allocated /24 subnet {subnet_obj.subnet_id} "
                        f"({subnet_obj.cidr}) has no IPAddress record in SoT "
                        f"(item_id={item_id}, subnet_id={subnet_obj.subnet_id}, "
                        f"target_type={t_type}, target_id={t_id}, "
                        f"arp_source_device_id={arp_dev or 'none'})"
                    ),
                    recommended_onboarding_action=(
                        f"Register IP {norm_ip} in subnet {subnet_obj.subnet_id} "
                        f"(ip_arp_entries) for site {site_id}"
                    ),
                )
            )

        return ReconciliationReport(
            discrepancies=discrepancies,
            generated_at=report_dt,
        )


__all__ = [
    "ALL_DISCREPANCY_TYPES",
    "DISCREPANCY_CSV_COLUMNS",
    "DiscrepancyRecord",
    "DiscrepancyType",
    "InventoryReconciler",
    "ONBOARDING_CSV_COLUMNS",
    "ReconciliationReport",
    "VALID_DISCREPANCY_SOURCES",
]
