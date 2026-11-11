"""Canonical domain models and validation schemas for sot-validator."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
from typing import Any, Mapping, Optional, TypeVar

T = TypeVar("T")


def _require_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _parse_optional_datetime(
    value: Optional[datetime | str], field_name: str
) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(
                f"{field_name} must be a valid ISO-8601 datetime string"
            ) from exc
    raise ValueError(f"{field_name} must be a datetime instance or ISO-8601 string")


def _format_optional_datetime(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


class EquipmentCategory(str, Enum):
    """Supported categories of network-attached equipment in the SoT."""

    SERVER = "server"
    SAN = "san"
    UPS = "ups"
    VM = "vm"
    OTHER = "other"


class SignalType(str, Enum):
    """Types of passive or active validation signals collected for an inventory item."""

    ARP_RECENCY = "ARP_RECENCY"
    PORT_STATE = "PORT_STATE"
    ICMP_REACHABILITY = "ICMP_REACHABILITY"
    SNMP_API_REACHABILITY = "SNMP_API_REACHABILITY"
    LAST_SEEN_TIMESTAMP = "LAST_SEEN_TIMESTAMP"
    VM_POWER_STATE = "VM_POWER_STATE"
    AD_COMPUTER_ACCOUNT = "AD_COMPUTER_ACCOUNT"
    DNS_DHCP_LEASE = "DNS_DHCP_LEASE"


class SignalStatus(str, Enum):
    """Normalized evaluation status of an individual validation signal."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNREACHABLE = "UNREACHABLE"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ValidationClassification(str, Enum):
    """Final validation classification states for an inventory record."""

    CONFIRMED_ACTIVE = "Confirmed Active"
    STALE_LIKELY_UNUSED = "Stale / Likely Unused"
    UNREACHABLE_NEEDS_REVIEW = "Unreachable / Needs Manual Review"
    INSUFFICIENT_DATA = "Insufficient Data"


@dataclass
class Port:
    """Switch or router port record with mapping and operational status."""

    port_id: str
    device_id: str
    name: str
    admin_status: Optional[str] = None
    oper_status: Optional[str] = None
    poe_status: Optional[str] = None
    connected_device_id: Optional[str] = None
    connected_mac: Optional[str] = None
    vlan_id: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.port_id, "port_id")
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.name, "name")

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "device_id": self.device_id,
            "name": self.name,
            "admin_status": self.admin_status,
            "oper_status": self.oper_status,
            "poe_status": self.poe_status,
            "connected_device_id": self.connected_device_id,
            "connected_mac": self.connected_mac,
            "vlan_id": self.vlan_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Port:
        return cls(
            port_id=data["port_id"],
            device_id=data["device_id"],
            name=data["name"],
            admin_status=data.get("admin_status"),
            oper_status=data.get("oper_status"),
            poe_status=data.get("poe_status"),
            connected_device_id=data.get("connected_device_id"),
            connected_mac=data.get("connected_mac"),
            vlan_id=data.get("vlan_id"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> Port:
        return cls.from_dict(json.loads(raw))


@dataclass
class NetworkDevice:
    """Network device (switch/router) associated with a site."""

    device_id: str
    site_id: str
    hostname: str
    management_ip: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    role: Optional[str] = None
    last_seen: Optional[datetime] = None
    ports: list[Port] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.hostname, "hostname")
        self.last_seen = _parse_optional_datetime(self.last_seen, "last_seen")
        self.ports = [
            p if isinstance(p, Port) else Port.from_dict(p) for p in self.ports
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "site_id": self.site_id,
            "hostname": self.hostname,
            "management_ip": self.management_ip,
            "vendor": self.vendor,
            "model": self.model,
            "role": self.role,
            "last_seen": _format_optional_datetime(self.last_seen),
            "ports": [p.to_dict() for p in self.ports],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NetworkDevice:
        return cls(
            device_id=data["device_id"],
            site_id=data["site_id"],
            hostname=data["hostname"],
            management_ip=data.get("management_ip"),
            vendor=data.get("vendor"),
            model=data.get("model"),
            role=data.get("role"),
            last_seen=_parse_optional_datetime(data.get("last_seen"), "last_seen"),
            ports=[
                p if isinstance(p, Port) else Port.from_dict(p)
                for p in data.get("ports", [])
            ],
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> NetworkDevice:
        return cls.from_dict(json.loads(raw))


@dataclass
class VLAN:
    """Site VLAN record with optional subnet cross-reference."""

    vlan_id: str
    site_id: str
    name: Optional[str] = None
    subnet_id: Optional[str] = None
    cidr: Optional[str] = None
    gateway: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.vlan_id, "vlan_id")
        _require_non_empty_str(self.site_id, "site_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "vlan_id": self.vlan_id,
            "site_id": self.site_id,
            "name": self.name,
            "subnet_id": self.subnet_id,
            "cidr": self.cidr,
            "gateway": self.gateway,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VLAN:
        return cls(
            vlan_id=data["vlan_id"],
            site_id=data["site_id"],
            name=data.get("name"),
            subnet_id=data.get("subnet_id"),
            cidr=data.get("cidr"),
            gateway=data.get("gateway"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> VLAN:
        return cls.from_dict(json.loads(raw))


@dataclass
class Subnet:
    """Site IPv4/IPv6 subnet record."""

    subnet_id: str
    site_id: str
    cidr: str
    vlan_id: Optional[str] = None
    gateway: Optional[str] = None
    name: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.subnet_id, "subnet_id")
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.cidr, "cidr")

    def to_dict(self) -> dict[str, Any]:
        return {
            "subnet_id": self.subnet_id,
            "site_id": self.site_id,
            "cidr": self.cidr,
            "vlan_id": self.vlan_id,
            "gateway": self.gateway,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Subnet:
        return cls(
            subnet_id=data["subnet_id"],
            site_id=data["site_id"],
            cidr=data["cidr"],
            vlan_id=data.get("vlan_id"),
            gateway=data.get("gateway"),
            name=data.get("name"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> Subnet:
        return cls.from_dict(json.loads(raw))


@dataclass
class ArpEntry:
    """ARP discovery record observed for an IP address."""

    ip: str
    arp_mac: str
    arp_last_seen: Optional[datetime] = None
    arp_source_device_id: Optional[str] = None
    subnet_id: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.ip, "ip")
        _require_non_empty_str(self.arp_mac, "arp_mac")
        self.arp_last_seen = _parse_optional_datetime(
            self.arp_last_seen, "arp_last_seen"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "arp_mac": self.arp_mac,
            "arp_last_seen": _format_optional_datetime(self.arp_last_seen),
            "arp_source_device_id": self.arp_source_device_id,
            "subnet_id": self.subnet_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ArpEntry:
        return cls(
            ip=data["ip"],
            arp_mac=data["arp_mac"],
            arp_last_seen=_parse_optional_datetime(
                data.get("arp_last_seen"), "arp_last_seen"
            ),
            arp_source_device_id=data.get("arp_source_device_id"),
            subnet_id=data.get("subnet_id"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ArpEntry:
        return cls.from_dict(json.loads(raw))


@dataclass
class IPAddress:
    """IP address assignment and associated ARP discovery data."""

    ip: str
    subnet_id: str
    assigned_object_type: Optional[str] = None
    assigned_object_id: Optional[str] = None
    arp_mac: Optional[str] = None
    arp_last_seen: Optional[datetime] = None
    arp_source_device_id: Optional[str] = None
    arp_entry: Optional[ArpEntry] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.ip, "ip")
        _require_non_empty_str(self.subnet_id, "subnet_id")
        self.arp_last_seen = _parse_optional_datetime(
            self.arp_last_seen, "arp_last_seen"
        )
        if self.arp_entry is not None and not isinstance(self.arp_entry, ArpEntry):
            self.arp_entry = ArpEntry.from_dict(self.arp_entry)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "subnet_id": self.subnet_id,
            "assigned_object_type": self.assigned_object_type,
            "assigned_object_id": self.assigned_object_id,
            "arp_mac": self.arp_mac,
            "arp_last_seen": _format_optional_datetime(self.arp_last_seen),
            "arp_source_device_id": self.arp_source_device_id,
            "arp_entry": (
                self.arp_entry.to_dict() if self.arp_entry is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IPAddress:
        raw_arp_entry = data.get("arp_entry")
        arp_entry = (
            raw_arp_entry
            if isinstance(raw_arp_entry, ArpEntry) or raw_arp_entry is None
            else ArpEntry.from_dict(raw_arp_entry)
        )
        return cls(
            ip=data["ip"],
            subnet_id=data["subnet_id"],
            assigned_object_type=data.get("assigned_object_type"),
            assigned_object_id=data.get("assigned_object_id"),
            arp_mac=data.get("arp_mac"),
            arp_last_seen=_parse_optional_datetime(
                data.get("arp_last_seen"), "arp_last_seen"
            ),
            arp_source_device_id=data.get("arp_source_device_id"),
            arp_entry=arp_entry,
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> IPAddress:
        return cls.from_dict(json.loads(raw))


@dataclass
class Equipment:
    """Network-attached equipment record (server, SAN, UPS, VM, other)."""

    equipment_id: str
    site_id: str
    name: str
    category: EquipmentCategory = EquipmentCategory.OTHER
    assigned_ips: list[str] = field(default_factory=list)
    connected_ports: list[str] = field(default_factory=list)
    hypervisor_id: Optional[str] = None
    power_state: Optional[str] = None
    last_seen: Optional[datetime] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.equipment_id, "equipment_id")
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.name, "name")
        if not isinstance(self.category, EquipmentCategory):
            try:
                self.category = EquipmentCategory(self.category)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid equipment category: {self.category!r}"
                ) from exc
        self.assigned_ips = list(self.assigned_ips)
        self.connected_ports = list(self.connected_ports)
        self.last_seen = _parse_optional_datetime(self.last_seen, "last_seen")

    def to_dict(self) -> dict[str, Any]:
        return {
            "equipment_id": self.equipment_id,
            "site_id": self.site_id,
            "name": self.name,
            "category": self.category.value,
            "assigned_ips": list(self.assigned_ips),
            "connected_ports": list(self.connected_ports),
            "hypervisor_id": self.hypervisor_id,
            "power_state": self.power_state,
            "last_seen": _format_optional_datetime(self.last_seen),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Equipment:
        return cls(
            equipment_id=data["equipment_id"],
            site_id=data["site_id"],
            name=data["name"],
            category=EquipmentCategory(
                data.get("category", EquipmentCategory.OTHER.value)
            ),
            assigned_ips=list(data.get("assigned_ips", [])),
            connected_ports=list(data.get("connected_ports", [])),
            hypervisor_id=data.get("hypervisor_id"),
            power_state=data.get("power_state"),
            last_seen=_parse_optional_datetime(data.get("last_seen"), "last_seen"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> Equipment:
        return cls.from_dict(json.loads(raw))


@dataclass
class Site:
    """Site hierarchy container holding metadata and child inventory records."""

    site_id: str
    name: str
    address: Optional[str] = None
    contact_info: Optional[str] = None
    rooms: list[str] = field(default_factory=list)
    devices: list[NetworkDevice] = field(default_factory=list)
    vlans: list[VLAN] = field(default_factory=list)
    subnets: list[Subnet] = field(default_factory=list)
    ip_addresses: list[IPAddress] = field(default_factory=list)
    equipment: list[Equipment] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.name, "name")
        self.rooms = list(self.rooms)
        self.devices = [
            d if isinstance(d, NetworkDevice) else NetworkDevice.from_dict(d)
            for d in self.devices
        ]
        self.vlans = [
            v if isinstance(v, VLAN) else VLAN.from_dict(v) for v in self.vlans
        ]
        self.subnets = [
            s if isinstance(s, Subnet) else Subnet.from_dict(s) for s in self.subnets
        ]
        self.ip_addresses = [
            ip if isinstance(ip, IPAddress) else IPAddress.from_dict(ip)
            for ip in self.ip_addresses
        ]
        self.equipment = [
            e if isinstance(e, Equipment) else Equipment.from_dict(e)
            for e in self.equipment
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "name": self.name,
            "address": self.address,
            "contact_info": self.contact_info,
            "rooms": list(self.rooms),
            "devices": [d.to_dict() for d in self.devices],
            "vlans": [v.to_dict() for v in self.vlans],
            "subnets": [s.to_dict() for s in self.subnets],
            "ip_addresses": [ip.to_dict() for ip in self.ip_addresses],
            "equipment": [e.to_dict() for e in self.equipment],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Site:
        return cls(
            site_id=data["site_id"],
            name=data["name"],
            address=data.get("address"),
            contact_info=data.get("contact_info"),
            rooms=list(data.get("rooms", [])),
            devices=[
                d if isinstance(d, NetworkDevice) else NetworkDevice.from_dict(d)
                for d in data.get("devices", [])
            ],
            vlans=[
                v if isinstance(v, VLAN) else VLAN.from_dict(v)
                for v in data.get("vlans", [])
            ],
            subnets=[
                s if isinstance(s, Subnet) else Subnet.from_dict(s)
                for s in data.get("subnets", [])
            ],
            ip_addresses=[
                ip if isinstance(ip, IPAddress) else IPAddress.from_dict(ip)
                for ip in data.get("ip_addresses", [])
            ],
            equipment=[
                e if isinstance(e, Equipment) else Equipment.from_dict(e)
                for e in data.get("equipment", [])
            ],
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> Site:
        return cls.from_dict(json.loads(raw))


@dataclass
class ValidationSignal:
    """Single validation signal observation for an inventory item."""

    signal_type: SignalType
    status: SignalStatus
    observed_at: Optional[datetime] = None
    age_seconds: Optional[float] = None
    details: Optional[str] = None
    source: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.signal_type, SignalType):
            try:
                self.signal_type = SignalType(self.signal_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid signal_type: {self.signal_type!r}"
                ) from exc
        if not isinstance(self.status, SignalStatus):
            try:
                self.status = SignalStatus(self.status)
            except ValueError as exc:
                raise ValueError(f"Invalid status: {self.status!r}") from exc
        self.observed_at = _parse_optional_datetime(self.observed_at, "observed_at")
        if self.age_seconds is not None:
            if isinstance(self.age_seconds, bool) or not isinstance(
                self.age_seconds, (int, float)
            ):
                raise ValueError("age_seconds must be a non-negative number")
            self.age_seconds = float(self.age_seconds)
            if not (self.age_seconds >= 0.0):
                raise ValueError("age_seconds must be non-negative")
        if self.metadata is None:
            self.metadata = {}
        elif isinstance(self.metadata, Mapping):
            self.metadata = dict(self.metadata)
        else:
            raise ValueError("metadata must be a mapping or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_type": self.signal_type.value,
            "status": self.status.value,
            "observed_at": _format_optional_datetime(self.observed_at),
            "age_seconds": self.age_seconds,
            "details": self.details,
            "source": self.source,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidationSignal:
        return cls(
            signal_type=SignalType(data["signal_type"]),
            status=SignalStatus(data["status"]),
            observed_at=_parse_optional_datetime(
                data.get("observed_at"), "observed_at"
            ),
            age_seconds=data.get("age_seconds"),
            details=data.get("details"),
            source=data.get("source"),
            metadata=data.get("metadata") or {},
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ValidationSignal:
        return cls.from_dict(json.loads(raw))


Signal = ValidationSignal


@dataclass
class ValidationResult:
    """Evaluated classification result and supporting signal evidence for an inventory item."""

    item_type: str
    item_id: str
    site_id: str
    name: str
    classification: ValidationClassification
    confidence: float = 0.0
    signals: list[ValidationSignal] = field(default_factory=list)
    rationale: Optional[str] = None
    evaluated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.item_type, "item_type")
        _require_non_empty_str(self.item_id, "item_id")
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.name, "name")
        if not isinstance(self.classification, ValidationClassification):
            try:
                self.classification = ValidationClassification(self.classification)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid classification: {self.classification!r}"
                ) from exc
        if isinstance(self.confidence, bool) or not isinstance(
            self.confidence, (int, float)
        ):
            raise ValueError("confidence must be a number between 0.0 and 1.0")
        self.confidence = float(self.confidence)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")
        self.signals = [
            s if isinstance(s, ValidationSignal) else ValidationSignal.from_dict(s)
            for s in self.signals
        ]
        self.evaluated_at = _parse_optional_datetime(
            self.evaluated_at, "evaluated_at"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_type": self.item_type,
            "item_id": self.item_id,
            "site_id": self.site_id,
            "name": self.name,
            "classification": self.classification.value,
            "confidence": self.confidence,
            "signals": [s.to_dict() for s in self.signals],
            "rationale": self.rationale,
            "evaluated_at": _format_optional_datetime(self.evaluated_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidationResult:
        return cls(
            item_type=data["item_type"],
            item_id=data["item_id"],
            site_id=data["site_id"],
            name=data["name"],
            classification=ValidationClassification(data["classification"]),
            confidence=data.get("confidence", 0.0),
            signals=[
                s if isinstance(s, ValidationSignal) else ValidationSignal.from_dict(s)
                for s in data.get("signals", [])
            ],
            rationale=data.get("rationale"),
            evaluated_at=_parse_optional_datetime(
                data.get("evaluated_at"), "evaluated_at"
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ValidationResult:
        return cls.from_dict(json.loads(raw))


__all__ = [
    "ArpEntry",
    "Equipment",
    "EquipmentCategory",
    "IPAddress",
    "NetworkDevice",
    "Port",
    "Signal",
    "SignalStatus",
    "SignalType",
    "Site",
    "Subnet",
    "VLAN",
    "ValidationClassification",
    "ValidationResult",
    "ValidationSignal",
]
