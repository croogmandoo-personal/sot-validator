"""Snapshot diff engine, scan drift events, and drift alert dispatcher for discovery runs."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional, Union
import urllib.error
import urllib.parse
import urllib.request

from sot_validator.curation.store import CurationStore, ItemEditPatch
from sot_validator.discovery.scanner import DiscoveredHost, _normalize_mac
from sot_validator.models import (
    IPAddress,
    Site,
    ValidationClassification,
    ValidationResult,
    _require_non_empty_str,
)
from sot_validator.signals.base import normalize_utc_datetime

logger = logging.getLogger(__name__)

DriftValue = Optional[Union[str, list[int]]]


class ScanDriftEventType(str, Enum):
    """Categories of drift detected between two discovery snapshots of a site."""

    NEW_HOST_JOINED = "NEW_HOST_JOINED"
    HOST_WENT_OFFLINE = "HOST_WENT_OFFLINE"
    CRITICAL_ASSET_OFFLINE = "CRITICAL_ASSET_OFFLINE"
    MAC_ADDRESS_CHANGED = "MAC_ADDRESS_CHANGED"
    OPEN_PORTS_CHANGED = "OPEN_PORTS_CHANGED"
    NEW_SUBNET_DISCOVERED = "NEW_SUBNET_DISCOVERED"
    CLASSIFICATION_CHANGED = "CLASSIFICATION_CHANGED"


SEVERITY_LEVELS: tuple[str, ...] = ("critical", "warning", "info")

# MAC_ADDRESS_CHANGED escalates to "critical" when the asset is critical.
DEFAULT_DRIFT_SEVERITY: dict[ScanDriftEventType, str] = {
    ScanDriftEventType.NEW_HOST_JOINED: "warning",
    ScanDriftEventType.HOST_WENT_OFFLINE: "warning",
    ScanDriftEventType.CRITICAL_ASSET_OFFLINE: "critical",
    ScanDriftEventType.MAC_ADDRESS_CHANGED: "warning",
    ScanDriftEventType.OPEN_PORTS_CHANGED: "info",
    ScanDriftEventType.NEW_SUBNET_DISCOVERED: "warning",
    ScanDriftEventType.CLASSIFICATION_CHANGED: "info",
}

CRITICAL_ROLES: frozenset[str] = frozenset({"router", "switch", "hypervisor"})

_EVENT_TYPE_ORDER: dict[ScanDriftEventType, int] = {
    member: index for index, member in enumerate(ScanDriftEventType)
}
_SEVERITY_ORDER: dict[str, int] = {
    severity: index for index, severity in enumerate(SEVERITY_LEVELS)
}

LinkedKey = tuple[str, str]


def _coerce_drift_value(value: Any, field_name: str) -> DriftValue:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        for port in value:
            if isinstance(port, bool) or not isinstance(port, int):
                raise ValueError(f"{field_name} list must contain only integers")
        return sorted(value)
    raise ValueError(f"{field_name} must be None, a string, or a list of integers")


def _seed_value(value: DriftValue) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(port) for port in value)
    return value


def _drift_event_id(
    site_id: str,
    event_type: ScanDriftEventType,
    target_id: str,
    ip: Optional[str],
    previous_value: DriftValue,
    current_value: DriftValue,
) -> str:
    seed = "|".join(
        (
            site_id,
            event_type.value,
            target_id,
            ip or "",
            _seed_value(previous_value),
            _seed_value(current_value),
        )
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"drift-{digest}"


@dataclass
class ScanDriftEvent:
    """Single typed, severity-ranked drift observation between two site snapshots."""

    event_id: str
    event_type: ScanDriftEventType
    severity: str
    site_id: str
    target_id: str
    ip: Optional[str]
    previous_value: DriftValue
    current_value: DriftValue
    detected_at: datetime
    summary: str

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, ScanDriftEventType):
            try:
                self.event_type = ScanDriftEventType(self.event_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid event_type: {self.event_type!r}"
                ) from exc
        if not isinstance(self.severity, str) or self.severity not in _SEVERITY_ORDER:
            raise ValueError(
                f"Invalid severity: {self.severity!r}; expected one of {SEVERITY_LEVELS}"
            )
        _require_non_empty_str(self.event_id, "event_id")
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.target_id, "target_id")
        _require_non_empty_str(self.summary, "summary")
        if self.ip is not None and not isinstance(self.ip, str):
            raise ValueError("ip must be a string or None")
        self.previous_value = _coerce_drift_value(self.previous_value, "previous_value")
        self.current_value = _coerce_drift_value(self.current_value, "current_value")
        self.detected_at = normalize_utc_datetime(
            self.detected_at, field_name="detected_at"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity,
            "site_id": self.site_id,
            "target_id": self.target_id,
            "ip": self.ip,
            "previous_value": (
                list(self.previous_value)
                if isinstance(self.previous_value, list)
                else self.previous_value
            ),
            "current_value": (
                list(self.current_value)
                if isinstance(self.current_value, list)
                else self.current_value
            ),
            "detected_at": self.detected_at.isoformat(),
            "summary": self.summary,
        }


def _empty_summary_counts() -> dict[str, Any]:
    return {
        "total": 0,
        "by_type": {member.value: 0 for member in ScanDriftEventType},
        "by_severity": {severity: 0 for severity in SEVERITY_LEVELS},
    }


def _markdown_cell(value: DriftValue) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        text = ", ".join(str(port) for port in value)
    else:
        text = str(value)
    return text.replace("|", "\\|")


@dataclass
class SnapshotDiffReport:
    """Drift report produced by diffing a baseline and current snapshot of one site."""

    site_id: str
    baseline_timestamp: Optional[datetime]
    current_timestamp: datetime
    events: list[ScanDriftEvent] = field(default_factory=list)
    summary_counts: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.site_id, "site_id")
        if self.baseline_timestamp is not None:
            self.baseline_timestamp = normalize_utc_datetime(
                self.baseline_timestamp, field_name="baseline_timestamp"
            )
        self.current_timestamp = normalize_utc_datetime(
            self.current_timestamp, field_name="current_timestamp"
        )
        self.events = list(self.events)
        for event in self.events:
            if not isinstance(event, ScanDriftEvent):
                raise ValueError("events must contain only ScanDriftEvent instances")
        counts = _empty_summary_counts()
        for event in self.events:
            counts["total"] += 1
            counts["by_type"][event.event_type.value] += 1
            counts["by_severity"][event.severity] += 1
        self.summary_counts = counts

    @property
    def highest_severity(self) -> Optional[str]:
        if not self.events:
            return None
        return min(
            (event.severity for event in self.events),
            key=lambda severity: _SEVERITY_ORDER[severity],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "baseline_timestamp": (
                self.baseline_timestamp.isoformat()
                if self.baseline_timestamp is not None
                else None
            ),
            "current_timestamp": self.current_timestamp.isoformat(),
            "summary_counts": {
                "total": self.summary_counts["total"],
                "by_type": dict(self.summary_counts["by_type"]),
                "by_severity": dict(self.summary_counts["by_severity"]),
            },
            "highest_severity": self.highest_severity,
            "events": [event.to_dict() for event in self.events],
        }

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        baseline = (
            self.baseline_timestamp.isoformat()
            if self.baseline_timestamp is not None
            else "unknown"
        )
        lines = [
            f"# Snapshot Drift Report: {self.site_id}",
            "",
            f"- Baseline: {baseline}",
            f"- Current: {self.current_timestamp.isoformat()}",
            "",
            "## Counts",
            "",
            f"- Total: {self.summary_counts['total']}",
        ]
        for severity in SEVERITY_LEVELS:
            lines.append(f"- {severity}: {self.summary_counts['by_severity'][severity]}")
        for member in ScanDriftEventType:
            lines.append(f"- {member.value}: {self.summary_counts['by_type'][member.value]}")
        lines.extend(["", "## Events", ""])
        if not self.events:
            lines.append("No drift detected.")
        else:
            lines.append("| Severity | Type | Target | IP | Previous | Current | Summary |")
            lines.append("|---|---|---|---|---|---|---|")
            for event in self.events:
                cells = (
                    _markdown_cell(event.severity),
                    _markdown_cell(event.event_type.value),
                    _markdown_cell(event.target_id),
                    _markdown_cell(event.ip),
                    _markdown_cell(event.previous_value),
                    _markdown_cell(event.current_value),
                    _markdown_cell(event.summary),
                )
                lines.append("| " + " | ".join(cells) + " |")
        return "\n".join(lines) + "\n"


class _SnapshotIndex:
    """Read-only lookup tables over one Site snapshot (first record wins on duplicates)."""

    def __init__(self, site: Site) -> None:
        self.ips: dict[str, IPAddress] = {}
        for record in site.ip_addresses:
            self.ips.setdefault(record.ip.strip(), record)
        self.devices = {}
        for device in site.devices:
            self.devices.setdefault(device.device_id, device)
        self.equipment = {}
        for item in site.equipment:
            self.equipment.setdefault(item.equipment_id, item)
        self.devices_by_ip: dict[str, list[str]] = {}
        for device in self.devices.values():
            if device.management_ip:
                self.devices_by_ip.setdefault(device.management_ip.strip(), []).append(
                    device.device_id
                )
        self.equipment_by_ip: dict[str, list[str]] = {}
        for item in self.equipment.values():
            for ip in item.assigned_ips:
                if isinstance(ip, str) and ip.strip():
                    ids = self.equipment_by_ip.setdefault(ip.strip(), [])
                    if item.equipment_id not in ids:
                        ids.append(item.equipment_id)

    def mac_for(self, ip: str) -> Optional[str]:
        record = self.ips.get(ip)
        if record is None:
            return None
        raw = record.arp_mac
        if not raw and record.arp_entry is not None:
            raw = record.arp_entry.arp_mac
        return _normalize_mac(raw) if raw else None

    def linked_keys(self, ip: str) -> set[LinkedKey]:
        keys: set[LinkedKey] = {("IPAddress", ip)}
        record = self.ips.get(ip)
        if record is not None and record.assigned_object_type and record.assigned_object_id:
            keys.add((record.assigned_object_type, record.assigned_object_id))
        for device_id in self.devices_by_ip.get(ip, []):
            keys.add(("NetworkDevice", device_id))
        for equipment_id in self.equipment_by_ip.get(ip, []):
            keys.add(("Equipment", equipment_id))
        return keys

    def ips_linked_to(self, key: LinkedKey) -> set[str]:
        linked = {
            ip
            for ip, record in self.ips.items()
            if (record.assigned_object_type, record.assigned_object_id) == key
        }
        if key[0] == "NetworkDevice":
            device = self.devices.get(key[1])
            if device is not None and device.management_ip:
                linked.add(device.management_ip.strip())
        elif key[0] == "Equipment":
            item = self.equipment.get(key[1])
            if item is not None:
                linked.update(
                    ip.strip()
                    for ip in item.assigned_ips
                    if isinstance(ip, str) and ip.strip()
                )
        return linked


def _target_for(record: Optional[IPAddress], ip: str) -> str:
    if record is not None and record.assigned_object_id and record.assigned_object_id.strip():
        return record.assigned_object_id
    return ip


def _collect_patches(curation: Any, site_id: str) -> list[ItemEditPatch]:
    if curation is None:
        return []
    if isinstance(curation, CurationStore):
        raw_patches = curation.list_patches()
    elif isinstance(curation, Iterable) and not isinstance(
        curation, (str, bytes, Mapping)
    ):
        raw_patches = list(curation)
        for patch in raw_patches:
            if not isinstance(patch, ItemEditPatch):
                raise ValueError(
                    "curation iterable must contain only ItemEditPatch instances"
                )
    else:
        raise ValueError(
            "curation must be None, a CurationStore, or an iterable of ItemEditPatch"
        )
    return [
        patch
        for patch in raw_patches
        if not patch.deleted and (patch.site_id is None or patch.site_id == site_id)
    ]


def _collect_port_input(
    value: Any, field_name: str
) -> tuple[Optional[dict[str, list[int]]], dict[str, str]]:
    """Return (ports by IP or None when not given, inferred roles by IP)."""
    if value is None:
        return None, {}
    ports: dict[str, list[int]] = {}
    roles: dict[str, str] = {}
    if isinstance(value, Mapping):
        for ip, raw_ports in value.items():
            if not isinstance(ip, str) or not ip.strip():
                raise ValueError(f"{field_name} keys must be non-empty IP strings")
            if isinstance(raw_ports, (str, bytes)) or not isinstance(raw_ports, Iterable):
                raise ValueError(f"{field_name} values must be iterables of integers")
            port_list = list(raw_ports)
            for port in port_list:
                if isinstance(port, bool) or not isinstance(port, int):
                    raise ValueError(f"{field_name} values must contain only integers")
            ports.setdefault(ip.strip(), sorted(set(port_list)))
        return ports, roles
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for host in value:
            if not isinstance(host, DiscoveredHost):
                raise ValueError(
                    f"{field_name} sequence must contain only DiscoveredHost instances"
                )
            if host.ip not in ports:
                ports[host.ip] = sorted(set(host.open_tcp_ports))
                roles[host.ip] = host.inferred_role
        return ports, roles
    raise ValueError(
        f"{field_name} must be None, a mapping of IP to ports, or a sequence of DiscoveredHost"
    )


def _collect_results(value: Any, field_name: str) -> Optional[list[ValidationResult]]:
    if value is None:
        return None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{field_name} must be None or a sequence of ValidationResult")
    results = list(value)
    for result in results:
        if not isinstance(result, ValidationResult):
            raise ValueError(f"{field_name} must contain only ValidationResult instances")
    return results


def _network_key(cidr: str) -> str:
    raw = cidr.strip()
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        return raw


def _collect_networks(site: Site) -> dict[str, dict[str, Any]]:
    """Map each network key to its first Subnet and first VLAN in the site."""
    networks: dict[str, dict[str, Any]] = {}
    for subnet in site.subnets:
        entry = networks.setdefault(
            _network_key(subnet.cidr), {"subnet": None, "vlan": None}
        )
        if entry["subnet"] is None:
            entry["subnet"] = subnet
    for vlan in site.vlans:
        if vlan.cidr and vlan.cidr.strip():
            key = _network_key(vlan.cidr)
        else:
            key = f"vlan:{vlan.vlan_id}"
        entry = networks.setdefault(key, {"subnet": None, "vlan": None})
        if entry["vlan"] is None:
            entry["vlan"] = vlan
    return networks


def _ip_sort_key(ip: Optional[str]) -> tuple[int, int, int]:
    if ip is None:
        return (1, 0, 0)
    try:
        parsed = ipaddress.ip_address(ip.strip())
    except ValueError:
        return (1, 0, 0)
    return (0, parsed.version, int(parsed))


def _event_sort_key(event: ScanDriftEvent) -> tuple[Any, ...]:
    return (
        _SEVERITY_ORDER[event.severity],
        _EVENT_TYPE_ORDER[event.event_type],
        _ip_sort_key(event.ip),
        event.target_id,
        event.event_id,
    )


def _format_ports(ports: list[int]) -> str:
    return ", ".join(str(port) for port in ports) if ports else "none"


class SnapshotDiffEngine:
    """Deterministic, read-only diff of two Site snapshots into typed drift events.

    Default severities (``DEFAULT_DRIFT_SEVERITY``):

    - ``NEW_HOST_JOINED``: ``warning``
    - ``HOST_WENT_OFFLINE``: ``warning``
    - ``CRITICAL_ASSET_OFFLINE``: ``critical``
    - ``MAC_ADDRESS_CHANGED``: ``warning`` (``critical`` when the asset is critical)
    - ``OPEN_PORTS_CHANGED``: ``info``
    - ``NEW_SUBNET_DISCOVERED``: ``warning``
    - ``CLASSIFICATION_CHANGED``: ``info``

    An asset is critical when curation pins it ``Confirmed Active`` or its role
    (device record, curation patch, or discovered host) is router, switch or
    hypervisor. A critical asset going offline emits ``CRITICAL_ASSET_OFFLINE``
    instead of ``HOST_WENT_OFFLINE``.
    """

    def diff(
        self,
        baseline: Site,
        current: Site,
        *,
        baseline_timestamp: Optional[datetime | str] = None,
        current_timestamp: Optional[datetime | str] = None,
        detected_at: Optional[datetime | str] = None,
        baseline_results: Optional[Sequence[ValidationResult]] = None,
        current_results: Optional[Sequence[ValidationResult]] = None,
        curation: Optional[CurationStore | Iterable[ItemEditPatch]] = None,
        baseline_open_ports: Optional[
            Mapping[str, Iterable[int]] | Sequence[DiscoveredHost]
        ] = None,
        current_open_ports: Optional[
            Mapping[str, Iterable[int]] | Sequence[DiscoveredHost]
        ] = None,
    ) -> SnapshotDiffReport:
        if not isinstance(baseline, Site) or not isinstance(current, Site):
            raise ValueError("baseline and current must be Site instances")
        if baseline.site_id != current.site_id:
            raise ValueError(
                f"site_id mismatch: baseline {baseline.site_id!r} vs current {current.site_id!r}"
            )
        site_id = current.site_id

        resolved_current = (
            normalize_utc_datetime(current_timestamp, field_name="current_timestamp")
            if current_timestamp is not None
            else datetime.now(timezone.utc)
        )
        resolved_detected = (
            normalize_utc_datetime(detected_at, field_name="detected_at")
            if detected_at is not None
            else resolved_current
        )
        resolved_baseline = (
            normalize_utc_datetime(baseline_timestamp, field_name="baseline_timestamp")
            if baseline_timestamp is not None
            else None
        )

        patches = _collect_patches(curation, site_id)
        base_ports, base_roles = _collect_port_input(
            baseline_open_ports, "baseline_open_ports"
        )
        cur_ports, cur_roles = _collect_port_input(
            current_open_ports, "current_open_ports"
        )
        base_results = _collect_results(baseline_results, "baseline_results")
        cur_results = _collect_results(current_results, "current_results")

        base = _SnapshotIndex(baseline)
        cur = _SnapshotIndex(current)

        pinned: set[LinkedKey] = set()
        patch_roles: dict[LinkedKey, list[str]] = {}
        for patch in patches:
            key = (patch.target_type, patch.target_id)
            if patch.pinned_classification == ValidationClassification.CONFIRMED_ACTIVE:
                pinned.add(key)
            if patch.role:
                patch_roles.setdefault(key, []).append(patch.role)

        def critical_reason(keys: set[LinkedKey], ips: set[str]) -> Optional[str]:
            ordered = sorted(keys)
            if any(key in pinned for key in ordered):
                return "pinned Confirmed Active"
            roles: list[Optional[str]] = []
            for key in ordered:
                if key[0] == "NetworkDevice":
                    for index in (base, cur):
                        device = index.devices.get(key[1])
                        if device is not None:
                            roles.append(device.role)
                roles.extend(patch_roles.get(key, []))
            for ip in sorted(ips):
                roles.append(base_roles.get(ip))
                roles.append(cur_roles.get(ip))
            for role in roles:
                if isinstance(role, str) and role.strip().lower() in CRITICAL_ROLES:
                    return f"role {role.strip().lower()}"
            return None

        def ip_critical_reason(ip: str) -> Optional[str]:
            return critical_reason(base.linked_keys(ip) | cur.linked_keys(ip), {ip})

        events: list[ScanDriftEvent] = []

        def emit(
            event_type: ScanDriftEventType,
            severity: str,
            target_id: str,
            ip: Optional[str],
            previous_value: DriftValue,
            current_value: DriftValue,
            summary: str,
        ) -> None:
            events.append(
                ScanDriftEvent(
                    event_id=_drift_event_id(
                        site_id, event_type, target_id, ip, previous_value, current_value
                    ),
                    event_type=event_type,
                    severity=severity,
                    site_id=site_id,
                    target_id=target_id,
                    ip=ip,
                    previous_value=previous_value,
                    current_value=current_value,
                    detected_at=resolved_detected,
                    summary=summary,
                )
            )

        # New hosts.
        for ip, record in cur.ips.items():
            if ip in base.ips:
                continue
            mac = cur.mac_for(ip)
            target = _target_for(record, ip)
            mac_text = f" with MAC {mac}" if mac else ""
            emit(
                ScanDriftEventType.NEW_HOST_JOINED,
                DEFAULT_DRIFT_SEVERITY[ScanDriftEventType.NEW_HOST_JOINED],
                target,
                ip,
                None,
                mac,
                f"New host {target} joined at {ip}{mac_text}.",
            )

        # IP-level offline hosts.
        offline_ips: set[str] = set()
        for ip, record in base.ips.items():
            if ip in cur.ips:
                continue
            offline_ips.add(ip)
            mac = base.mac_for(ip)
            target = _target_for(record, ip)
            mac_text = f", last seen with MAC {mac}" if mac else ""
            reason = ip_critical_reason(ip)
            if reason is not None:
                event_type = ScanDriftEventType.CRITICAL_ASSET_OFFLINE
                summary = (
                    f"Critical asset {target} at {ip} went offline "
                    f"(critical: {reason}){mac_text}."
                )
            else:
                event_type = ScanDriftEventType.HOST_WENT_OFFLINE
                summary = f"Host {target} at {ip} went offline{mac_text}."
            emit(
                event_type,
                DEFAULT_DRIFT_SEVERITY[event_type],
                target,
                ip,
                mac,
                None,
                summary,
            )

        # Record-level offline devices and equipment not covered above.
        missing_records: list[tuple[LinkedKey, str, Optional[str]]] = []
        for device_id, device in base.devices.items():
            if device_id not in cur.devices:
                ip = device.management_ip.strip() if device.management_ip else None
                missing_records.append((("NetworkDevice", device_id), device.hostname, ip))
        for equipment_id, item in base.equipment.items():
            if equipment_id not in cur.equipment:
                first_ip = next(
                    (
                        ip.strip()
                        for ip in item.assigned_ips
                        if isinstance(ip, str) and ip.strip()
                    ),
                    None,
                )
                missing_records.append((("Equipment", equipment_id), item.name, first_ip))
        for key, label, ip in missing_records:
            linked_ips = base.ips_linked_to(key)
            if linked_ips & offline_ips:
                continue
            keys: set[LinkedKey] = {key}
            keys.update(("IPAddress", linked_ip) for linked_ip in linked_ips)
            reason = critical_reason(keys, linked_ips)
            kind = "Device" if key[0] == "NetworkDevice" else "Equipment"
            ip_text = f"at {ip}" if ip else "with no recorded IP"
            if reason is not None:
                event_type = ScanDriftEventType.CRITICAL_ASSET_OFFLINE
                summary = (
                    f"Critical {kind.lower()} {key[1]} ({label}) {ip_text} "
                    f"went offline (critical: {reason})."
                )
            else:
                event_type = ScanDriftEventType.HOST_WENT_OFFLINE
                summary = f"{kind} {key[1]} ({label}) {ip_text} went offline."
            emit(
                event_type,
                DEFAULT_DRIFT_SEVERITY[event_type],
                key[1],
                ip,
                label,
                None,
                summary,
            )

        # MAC changes and open-port changes for hosts present in both snapshots.
        for ip, record in cur.ips.items():
            if ip not in base.ips:
                continue
            target = _target_for(record, ip)
            if target == ip:
                target = _target_for(base.ips[ip], ip)
            old_mac = base.mac_for(ip)
            new_mac = cur.mac_for(ip)
            if old_mac and new_mac and old_mac != new_mac:
                reason = ip_critical_reason(ip)
                if reason is not None:
                    severity = "critical"
                    summary = (
                        f"MAC address of critical asset {target} at {ip} changed "
                        f"from {old_mac} to {new_mac} (critical: {reason})."
                    )
                else:
                    severity = DEFAULT_DRIFT_SEVERITY[
                        ScanDriftEventType.MAC_ADDRESS_CHANGED
                    ]
                    summary = (
                        f"MAC address of {target} at {ip} changed "
                        f"from {old_mac} to {new_mac}."
                    )
                emit(
                    ScanDriftEventType.MAC_ADDRESS_CHANGED,
                    severity,
                    target,
                    ip,
                    old_mac,
                    new_mac,
                    summary,
                )
            if (
                base_ports is not None
                and cur_ports is not None
                and ip in base_ports
                and ip in cur_ports
                and base_ports[ip] != cur_ports[ip]
            ):
                old_ports = list(base_ports[ip])
                new_ports = list(cur_ports[ip])
                emit(
                    ScanDriftEventType.OPEN_PORTS_CHANGED,
                    DEFAULT_DRIFT_SEVERITY[ScanDriftEventType.OPEN_PORTS_CHANGED],
                    target,
                    ip,
                    old_ports,
                    new_ports,
                    f"Open TCP ports on {target} at {ip} changed from "
                    f"[{_format_ports(old_ports)}] to [{_format_ports(new_ports)}].",
                )

        # New subnets / VLANs.
        base_networks = _collect_networks(baseline)
        for key, entry in _collect_networks(current).items():
            if key in base_networks:
                continue
            subnet = entry["subnet"]
            vlan = entry["vlan"]
            gateway = None
            if subnet is not None and subnet.gateway and subnet.gateway.strip():
                gateway = subnet.gateway.strip()
            elif vlan is not None and vlan.gateway and vlan.gateway.strip():
                gateway = vlan.gateway.strip()
            target = subnet.subnet_id if subnet is not None else vlan.vlan_id
            value = vlan.vlan_id if key.startswith("vlan:") else key
            noun = "VLAN" if key.startswith("vlan:") else "subnet"
            gateway_text = f" with gateway {gateway}" if gateway else ""
            emit(
                ScanDriftEventType.NEW_SUBNET_DISCOVERED,
                DEFAULT_DRIFT_SEVERITY[ScanDriftEventType.NEW_SUBNET_DISCOVERED],
                target,
                gateway,
                None,
                value,
                f"New {noun} {target} discovered: {value}{gateway_text}.",
            )

        # Classification changes.
        if base_results is not None and cur_results is not None:
            base_by_key: dict[tuple[str, str], ValidationResult] = {}
            for result in base_results:
                if result.site_id == site_id:
                    base_by_key.setdefault((result.item_type, result.item_id), result)
            seen: set[tuple[str, str]] = set()
            for result in cur_results:
                result_key = (result.item_type, result.item_id)
                if result.site_id != site_id or result_key in seen:
                    continue
                seen.add(result_key)
                previous = base_by_key.get(result_key)
                if previous is None or previous.classification == result.classification:
                    continue
                emit(
                    ScanDriftEventType.CLASSIFICATION_CHANGED,
                    DEFAULT_DRIFT_SEVERITY[ScanDriftEventType.CLASSIFICATION_CHANGED],
                    result.item_id,
                    None,
                    previous.classification.value,
                    result.classification.value,
                    f"Classification of {result.item_type} {result.item_id} "
                    f"({result.name}) changed from {previous.classification.value} "
                    f"to {result.classification.value}.",
                )

        events.sort(key=_event_sort_key)
        return SnapshotDiffReport(
            site_id=site_id,
            baseline_timestamp=resolved_baseline,
            current_timestamp=resolved_current,
            events=events,
        )


DRIFT_TARGET_KINDS: tuple[str, ...] = (
    "json_file",
    "webhook",
    "home_assistant_event",
    "home_assistant_webhook",
)
_URL_TARGET_KINDS: frozenset[str] = frozenset(
    {"webhook", "home_assistant_event", "home_assistant_webhook"}
)
HOME_ASSISTANT_EVENT_TYPE = "sot_validator_drift"

DriftSender = Callable[[str, str, Mapping[str, str], bytes, float], int]


@dataclass
class DriftAlertTarget:
    """Destination for a drift report: JSON file, generic webhook, or Home Assistant."""

    kind: str
    destination: str | os.PathLike[str]
    token: Optional[str] = field(default=None, repr=False)
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or self.kind not in DRIFT_TARGET_KINDS:
            raise ValueError(
                f"Invalid kind: {self.kind!r}; expected one of {DRIFT_TARGET_KINDS}"
            )
        if self.kind == "json_file":
            if not isinstance(self.destination, os.PathLike) and (
                not isinstance(self.destination, str) or not self.destination.strip()
            ):
                raise ValueError("json_file destination must be a non-empty path")
        else:
            if not isinstance(self.destination, str) or not self.destination.strip():
                raise ValueError(f"{self.kind} destination must be a non-empty URL")
            parts = urllib.parse.urlsplit(self.destination.strip())
            if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
                raise ValueError(
                    f"{self.kind} destination must be an http or https URL with a host"
                )
        if self.token is not None and not isinstance(self.token, str):
            raise ValueError("token must be a string or None")
        if self.kind == "home_assistant_event":
            if not self.token or not self.token.strip():
                raise ValueError("home_assistant_event targets require a non-empty token")
        elif self.token is not None:
            raise ValueError(f"{self.kind} targets do not accept a token")
        if self.name is None:
            self.name = self.kind
        else:
            _require_non_empty_str(self.name, "name")


@dataclass
class DriftDispatchResult:
    """Outcome of sending one drift report to one target (secrets redacted)."""

    name: str
    kind: str
    status: str
    http_status: Optional[int]
    destination: str
    detail: Optional[str]


class _RefuseRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that never follows a redirect, so headers are never forwarded."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _default_sender(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout: float,
) -> int:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(_RefuseRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        return status


def _redacted_destination(target: DriftAlertTarget) -> str:
    if target.kind not in _URL_TARGET_KINDS:
        return os.fspath(target.destination)
    parts = urllib.parse.urlsplit(str(target.destination).strip())
    host_port = parts.netloc.rpartition("@")[2]
    return f"{parts.scheme}://{host_port}"


def _redact(text: str, secrets: Iterable[Optional[str]]) -> str:
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


def _drift_payload(report: SnapshotDiffReport) -> dict[str, Any]:
    data = report.to_dict()
    return {
        "source": "sot-validator",
        "event_type": HOME_ASSISTANT_EVENT_TYPE,
        "site_id": data["site_id"],
        "baseline_timestamp": data["baseline_timestamp"],
        "current_timestamp": data["current_timestamp"],
        "highest_severity": data["highest_severity"],
        "event_count": len(data["events"]),
        "summary_counts": data["summary_counts"],
        "events": data["events"],
    }


class DriftAlertDispatcher:
    """Sends a SnapshotDiffReport to JSON file, webhook, and Home Assistant targets."""

    def __init__(
        self,
        targets: Sequence[DriftAlertTarget],
        *,
        sender: Optional[DriftSender] = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        if (
            not isinstance(targets, Sequence)
            or isinstance(targets, (str, bytes))
            or not targets
        ):
            raise ValueError("targets must be a non-empty sequence of DriftAlertTarget")
        for target in targets:
            if not isinstance(target, DriftAlertTarget):
                raise ValueError("targets must contain only DriftAlertTarget instances")
        if sender is not None and not callable(sender):
            raise ValueError("sender must be callable or None")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not timeout_seconds > 0
        ):
            raise ValueError("timeout_seconds must be a number greater than 0")
        self.targets: list[DriftAlertTarget] = list(targets)
        self.sender: DriftSender = sender if sender is not None else _default_sender
        self.timeout_seconds = float(timeout_seconds)

    def __repr__(self) -> str:
        names = ", ".join(f"{t.name}:{t.kind}" for t in self.targets)
        return f"DriftAlertDispatcher(targets=[{names}], timeout_seconds={self.timeout_seconds})"

    def dispatch(self, report: SnapshotDiffReport) -> list[DriftDispatchResult]:
        if not isinstance(report, SnapshotDiffReport):
            raise ValueError("report must be a SnapshotDiffReport instance")
        body = json.dumps(_drift_payload(report)).encode("utf-8")
        return [self._dispatch_one(target, report, body) for target in self.targets]

    def _dispatch_one(
        self, target: DriftAlertTarget, report: SnapshotDiffReport, body: bytes
    ) -> DriftDispatchResult:
        destination = _redacted_destination(target)
        url: Optional[str] = None
        http_status: Optional[int] = None
        try:
            if target.kind == "json_file":
                path = Path(target.destination)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(report.to_json(indent=2), encoding="utf-8")
                detail = None
            else:
                headers = {"Content-Type": "application/json"}
                url = str(target.destination).strip()
                if target.kind == "home_assistant_event":
                    url = f"{url.rstrip('/')}/api/events/{HOME_ASSISTANT_EVENT_TYPE}"
                    headers["Authorization"] = f"Bearer {target.token}"
                status = self.sender("POST", url, headers, body, self.timeout_seconds)
                if isinstance(status, bool) or not isinstance(status, int):
                    raise TypeError("sender must return an integer HTTP status code")
                http_status = status
                detail = None if 200 <= status < 300 else f"HTTP {status}"
        except Exception as exc:  # noqa: BLE001 - one failing target must not stop the rest
            detail = f"{type(exc).__name__}: {exc}"

        if detail is None:
            return DriftDispatchResult(
                name=str(target.name),
                kind=target.kind,
                status="sent",
                http_status=http_status,
                destination=destination,
                detail=None,
            )
        detail = _redact(
            detail,
            (target.token, url, str(target.destination).strip() if url else None),
        )
        logger.warning(
            "Drift alert target %s (%s, %s) failed: %s",
            target.name,
            target.kind,
            destination,
            detail,
        )
        return DriftDispatchResult(
            name=str(target.name),
            kind=target.kind,
            status="failed",
            http_status=http_status,
            destination=destination,
            detail=detail,
        )


__all__ = [
    "DriftAlertDispatcher",
    "DriftAlertTarget",
    "DriftDispatchResult",
    "ScanDriftEvent",
    "ScanDriftEventType",
    "SnapshotDiffEngine",
    "SnapshotDiffReport",
]
