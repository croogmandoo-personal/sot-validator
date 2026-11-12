"""Read-only cross-VLAN router ARP/neighbor and DHCP lease table collector."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import io
import ipaddress
import json
import re
from typing import Any, Optional

from sot_validator.discovery.scanner import (
    _NEIGH_STATES,
    DEFAULT_GATEWAY_OCTETS,
    DiscoveredHost,
    _infer_host_role,
    _infer_vlan_id_from_subnet,
    _role_to_equipment_category,
)
from sot_validator.models import ArpEntry, EquipmentCategory, NetworkDevice, Site
from sot_validator.signals.management import (
    IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX,
    IP_MIB_NET_TO_PHYSICAL_PHYS_ADDRESS_PREFIX,
)

IP_MIB_NET_TO_MEDIA_NET_ADDRESS_PREFIX = "1.3.6.1.2.1.4.22.1.3"
IP_MIB_NET_TO_MEDIA_TYPE_PREFIX = "1.3.6.1.2.1.4.22.1.4"
IF_MIB_IF_DESCR_PREFIX = "1.3.6.1.2.1.2.2.1.2"
IF_MIB_IF_NAME_PREFIX = "1.3.6.1.2.1.31.1.1.1.1"

_MAC_NULL_TOKENS: frozenset[str] = frozenset(
    {"incomplete", "(incomplete)", "<incomplete>", "failed", "none", "(none)", "-"}
)
_ZERO_MAC = "00:00:00:00:00:00"
_MAC_OCTET_RE = re.compile(r"^[0-9a-f]{1,2}$")
_MAC_GROUP_RE = re.compile(r"^[0-9a-f]{1,4}$")
_HEX12_RE = re.compile(r"^[0-9a-f]{12}$")
_NUMERIC_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
_ISC_TS_RE = re.compile(
    r"^(?:\d\s+)?(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})$"
)
_IFACE_DOT_VLAN_RE = re.compile(r"\.(\d+)$")
_IFACE_NAMED_VLAN_RE = re.compile(r"^(?:vlan|br|vl|v)[._-]?(\d+)$", re.IGNORECASE)
_DIGITS_RE = re.compile(r"(\d+)")
_SNMP_TYPE_PREFIX_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s+")
_SNMP_TYPE_NAMES: dict[int, str] = {1: "OTHER", 2: "INVALID", 3: "DYNAMIC", 4: "STATIC"}
_EXOS_STATIC_TOKENS: frozenset[str] = frozenset(
    {"YES", "NO", "STATIC", "DYNAMIC", "1", "0"}
)
_VOSS_TYPES: frozenset[str] = frozenset(
    {"DYNAMIC", "STATIC", "LOCAL", "INVALID", "OTHER"}
)
_LEASE_NULL_TOKENS: frozenset[str] = frozenset({"", "0", "infinite", "never"})
_ISC_LEASE_START_RE = re.compile(r"^\s*lease\s+\S+\s*\{", re.MULTILINE)
_ISC_LEASE_BLOCK_RE = re.compile(r"lease\s+(\S+)\s*\{(.*?)\}", re.DOTALL)
_ISC_STATEMENT_RE = re.compile(r'\s*((?:[^;"]|"(?:[^"\\]|\\.)*")*);')
_KEA_INFINITE_LFT = 0xFFFFFFFF

_ARP_STATE_RANK: dict[str, int] = {
    "REACHABLE": 2,
    "PERMANENT": 2,
    "DYNAMIC": 2,
    "STATIC": 2,
    "LOCAL": 2,
    "STALE": 1,
    "INCOMPLETE": 0,
    "FAILED": 0,
    "INVALID": 0,
    "NONE": 0,
}

_LEASE_IP_KEYS = ("ip", "ip-address", "ip_address", "address", "ipaddress")
_LEASE_MAC_KEYS = (
    "mac_address",
    "hw-address",
    "hw_address",
    "mac",
    "hardware",
    "hwaddr",
)
_LEASE_HOSTNAME_KEYS = ("hostname", "client-hostname", "client_hostname", "fqdn")
_LEASE_EXPIRY_KEYS = ("lease_expires_at", "expire", "expires_at", "expires", "ends")
_LEASE_SUBNET_KEYS = ("subnet_id", "subnet-id")
_LEASE_CLIENT_ID_KEYS = ("client_id", "client-id")


def _normalize_router_mac(value: Any) -> Optional[str]:
    """Strictly normalize a MAC address to lowercase ``aa:bb:cc:dd:ee:ff`` or None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("mac_address must be a string or None")
    cleaned = value.strip().lower()
    if not cleaned or cleaned in _MAC_NULL_TOKENS:
        return None
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:].strip()

    hex_digits: Optional[str] = None
    if any(sep in cleaned for sep in (":", "-", " ")):
        parts = re.split(r"[:\- ]+", cleaned)
        if len(parts) == 6 and all(_MAC_OCTET_RE.match(p) for p in parts):
            hex_digits = "".join(p.zfill(2) for p in parts)
    elif "." in cleaned:
        groups = cleaned.split(".")
        if len(groups) == 3 and all(_MAC_GROUP_RE.match(g) for g in groups):
            hex_digits = "".join(g.zfill(4) for g in groups)
    elif _HEX12_RE.match(cleaned):
        hex_digits = cleaned

    if hex_digits is None:
        raise ValueError(f"Invalid MAC address: {value!r}")
    mac = ":".join(hex_digits[i : i + 2] for i in range(0, 12, 2))
    return None if mac == _ZERO_MAC else mac


def _canonical_ipv4(value: Any, field_name: str = "ip") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty IPv4 address string")
    return str(ipaddress.IPv4Address(value.strip()))


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _optional_token(value: Any, field_name: str) -> Optional[str]:
    """Normalize an int or string identifier to a stripped string or None."""
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    raise ValueError(f"{field_name} must be a string, integer, or None")


def _optional_name(value: Any, field_name: str) -> Optional[str]:
    """Normalize a hostname/client-id string, treating ``""`` and ``"*"`` as None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    cleaned = value.strip()
    return None if cleaned in ("", "*") else cleaned


def _coerce_datetime(value: Any, field_name: str) -> Optional[datetime]:
    """Parse a datetime, ISO-8601/ISC string, or Unix epoch into an aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a datetime, string, number, or None")
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError(f"{field_name} epoch value out of range: {value!r}") from exc
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a datetime, string, number, or None")

    cleaned = value.strip()
    if not cleaned:
        return None
    if _NUMERIC_RE.match(cleaned):
        return _coerce_datetime(float(cleaned), field_name)
    isc_match = _ISC_TS_RE.match(cleaned)
    if isc_match is not None:
        year, month, day, hour, minute, second = (int(g) for g in isc_match.groups())
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    iso_text = cleaned[:-1] + "+00:00" if cleaned.endswith(("Z", "z")) else cleaned
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid timestamp, got {value!r}") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _parse_lease_expiry(value: Any) -> Optional[datetime]:
    if isinstance(value, str) and value.strip().lower() in _LEASE_NULL_TOKENS:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0:
        return None
    return _coerce_datetime(value, "lease_expires_at")


def _format_dt(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _vlan_from_interface(interface: Optional[str]) -> Optional[str]:
    """Infer a VLAN ID from tagged interface names such as ``eth1.10`` or ``vlan20``."""
    if not interface:
        return None
    name = interface.strip()
    match = _IFACE_DOT_VLAN_RE.search(name) or _IFACE_NAMED_VLAN_RE.match(name)
    if match is None:
        return None
    vid = int(match.group(1))
    return str(vid) if 1 <= vid <= 4094 else None


def _vlan_from_number(token: Optional[str], *, max_vid: int = 4095) -> Optional[str]:
    if token is None:
        return None
    match = _DIGITS_RE.search(token)
    if match is None:
        return None
    vid = int(match.group(1))
    return str(vid) if 1 <= vid <= max_vid else None


def _vlan_from_ip(ip: str) -> str:
    return _infer_vlan_id_from_subnet(f"{ip}/24")


@dataclass
class RouterArpRecord:
    """Normalized ARP/neighbor entry read from a gateway router or L3 switch."""

    ip: str
    mac_address: Optional[str] = None
    interface: Optional[str] = None
    vlan_id: Optional[str] = None
    state: Optional[str] = "REACHABLE"
    router_id: Optional[str] = None
    observed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.ip = _canonical_ipv4(self.ip)
        self.mac_address = _normalize_router_mac(self.mac_address)
        self.interface = _optional_token(self.interface, "interface")
        self.vlan_id = _optional_token(self.vlan_id, "vlan_id")
        if self.state is not None:
            if not isinstance(self.state, str):
                raise ValueError("state must be a string or None")
            cleaned_state = self.state.strip().upper()
            self.state = cleaned_state if cleaned_state else None
        self.router_id = _optional_token(self.router_id, "router_id")
        self.observed_at = _coerce_datetime(self.observed_at, "observed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac_address": self.mac_address,
            "interface": self.interface,
            "vlan_id": self.vlan_id,
            "state": self.state,
            "router_id": self.router_id,
            "observed_at": _format_dt(self.observed_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RouterArpRecord:
        return cls(
            ip=data["ip"],
            mac_address=data.get("mac_address"),
            interface=data.get("interface"),
            vlan_id=data.get("vlan_id"),
            state=data.get("state", "REACHABLE"),
            router_id=data.get("router_id"),
            observed_at=data.get("observed_at"),
        )


@dataclass
class DhcpLeaseRecord:
    """Normalized DHCPv4 lease read from a DHCP server lease table or export."""

    ip: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    lease_expires_at: Optional[datetime] = None
    subnet_id: Optional[str] = None
    client_id: Optional[str] = None

    def __post_init__(self) -> None:
        self.ip = _canonical_ipv4(self.ip)
        self.mac_address = _normalize_router_mac(self.mac_address)
        self.hostname = _optional_name(self.hostname, "hostname")
        self.lease_expires_at = _parse_lease_expiry(self.lease_expires_at)
        self.subnet_id = _optional_token(self.subnet_id, "subnet_id")
        self.client_id = _optional_name(self.client_id, "client_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "lease_expires_at": _format_dt(self.lease_expires_at),
            "subnet_id": self.subnet_id,
            "client_id": self.client_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DhcpLeaseRecord:
        return cls(
            ip=data["ip"],
            mac_address=data.get("mac_address"),
            hostname=data.get("hostname"),
            lease_expires_at=data.get("lease_expires_at"),
            subnet_id=data.get("subnet_id"),
            client_id=data.get("client_id"),
        )


def _snmp_text(value: Any) -> Optional[str]:
    """Strip net-snmp style type prefixes (``Hex-STRING: ``) and quotes from a value."""
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, str):
        return None
    cleaned = _SNMP_TYPE_PREFIX_RE.sub("", value.strip()).strip().strip('"').strip()
    return cleaned if cleaned else None


def _snmp_type_state(value: Any) -> Optional[str]:
    """Map an ``ipNetToMediaType`` value (``3``, ``"dynamic(3)"``) to a state name."""
    if isinstance(value, int) and not isinstance(value, bool):
        return _SNMP_TYPE_NAMES.get(value)
    text = _snmp_text(value)
    if text is None:
        return None
    match = re.search(r"\((\d+)\)", text)
    if match is not None:
        return _SNMP_TYPE_NAMES.get(int(match.group(1)))
    if text.isdigit():
        return _SNMP_TYPE_NAMES.get(int(text))
    upper = text.upper()
    return upper if upper in _SNMP_TYPE_NAMES.values() else None


def _first_value(row: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return None


class RouterTableParsers:
    """Deterministic parsers for gateway ARP/neighbor tables and DHCP lease exports."""

    # ------------------------------------------------------------------ ARP / neighbor

    @staticmethod
    def _parse_ip_neigh_tokens(
        tokens: Sequence[str],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> Optional[RouterArpRecord]:
        if not tokens or not _is_ipv4(tokens[0]):
            return None
        interface: Optional[str] = None
        mac_token: Optional[str] = None
        for idx, tok in enumerate(tokens[:-1]):
            lowered = tok.lower()
            if lowered == "dev" and interface is None:
                interface = tokens[idx + 1]
            elif lowered == "lladdr" and mac_token is None:
                mac_token = tokens[idx + 1]
        last_upper = tokens[-1].upper()
        state = last_upper if last_upper in _NEIGH_STATES else None
        ip = str(ipaddress.IPv4Address(tokens[0]))
        return RouterArpRecord(
            ip=ip,
            mac_address=mac_token,
            interface=interface,
            vlan_id=_vlan_from_interface(interface) or _vlan_from_ip(ip),
            state=state,
            router_id=router_id,
            observed_at=observed_at,
        )

    @staticmethod
    def _parse_exos_tokens(
        tokens: Sequence[str],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> Optional[RouterArpRecord]:
        if len(tokens) >= 2 and _is_ipv4(tokens[0]):
            start = 0
        elif len(tokens) >= 3 and _is_ipv4(tokens[1]):
            start = 1
        else:
            return None
        ip = str(ipaddress.IPv4Address(tokens[start]))
        mac_token = tokens[start + 1] if len(tokens) > start + 1 else None
        # Remaining columns: Age, Static, VLAN name, VID, Port
        rest = list(tokens[start + 2 :])
        static_token = rest[1].upper() if len(rest) > 1 else ""
        vlan_name = rest[2] if len(rest) > 2 else None
        vid_token = rest[3] if len(rest) > 3 and rest[3].isdigit() else None
        port_token = rest[4] if len(rest) > 4 and rest[4] != "-" else None

        mac = _normalize_router_mac(mac_token)
        if static_token in ("YES", "STATIC", "1"):
            state = "STATIC"
        elif mac is None:
            state = "INCOMPLETE"
        else:
            state = "DYNAMIC"
        vlan_id = (
            _vlan_from_number(vid_token)
            or _vlan_from_number(vlan_name)
            or _vlan_from_ip(ip)
        )
        return RouterArpRecord(
            ip=ip,
            mac_address=mac,
            interface=port_token,
            vlan_id=vlan_id,
            state=state,
            router_id=router_id,
            observed_at=observed_at,
        )

    @staticmethod
    def _parse_voss_tokens(
        tokens: Sequence[str],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> Optional[RouterArpRecord]:
        if len(tokens) < 2 or not _is_ipv4(tokens[0]):
            return None
        ip = str(ipaddress.IPv4Address(tokens[0]))
        mac = _normalize_router_mac(tokens[1])
        vlan_token = tokens[2] if len(tokens) > 2 else None
        port_token = tokens[3] if len(tokens) > 3 and tokens[3] != "-" else None
        type_token = tokens[4].upper() if len(tokens) > 4 else None
        state = type_token or ("INCOMPLETE" if mac is None else None)
        vlan_id = (
            _vlan_from_number(vlan_token)
            if vlan_token is not None and vlan_token.isdigit()
            else None
        ) or _vlan_from_interface(port_token) or _vlan_from_ip(ip)
        return RouterArpRecord(
            ip=ip,
            mac_address=mac,
            interface=port_token,
            vlan_id=vlan_id,
            state=state,
            router_id=router_id,
            observed_at=observed_at,
        )

    @staticmethod
    def _iter_lines(raw_output: str) -> Iterator[list[str]]:
        if not isinstance(raw_output, str):
            raise ValueError("raw_output must be a string")
        for raw_line in raw_output.splitlines():
            tokens = raw_line.split()
            if tokens and not tokens[0].startswith(("#", "=", "-")):
                yield tokens

    @classmethod
    def _parse_lines(
        cls,
        raw_output: str,
        line_parser: Any,
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> list[RouterArpRecord]:
        records: list[RouterArpRecord] = []
        for tokens in cls._iter_lines(raw_output):
            try:
                record = line_parser(tokens, router_id, observed_at)
            except ValueError:
                continue
            if record is not None:
                records.append(record)
        return records

    @classmethod
    def parse_ip_neigh(
        cls,
        raw_output: str,
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Parse Linux / UniFi / EdgeOS ``ip -4 neigh show`` output."""
        return cls._parse_lines(
            raw_output, cls._parse_ip_neigh_tokens, router_id, observed_at
        )

    @classmethod
    def parse_extremexos_arp(
        cls,
        raw_output: str,
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Parse ExtremeXOS ``show iparp`` table output (with or without ``VR`` column)."""
        return cls._parse_lines(
            raw_output, cls._parse_exos_tokens, router_id, observed_at
        )

    @classmethod
    def parse_voss_arp(
        cls,
        raw_output: str,
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Parse Extreme VOSS ``show ip arp`` table output."""
        return cls._parse_lines(
            raw_output, cls._parse_voss_tokens, router_id, observed_at
        )

    @classmethod
    def _classify_cli_line(cls, tokens: Sequence[str]) -> Any:
        if len(tokens) < 2:
            return None
        if _is_ipv4(tokens[0]):
            lowered = {t.lower() for t in tokens}
            if "dev" in lowered or "lladdr" in lowered:
                return cls._parse_ip_neigh_tokens
            if (
                len(tokens) >= 4
                and tokens[2].isdigit()
                and tokens[3].upper() in _EXOS_STATIC_TOKENS
            ):
                return cls._parse_exos_tokens
            if len(tokens) >= 5 and tokens[4].upper() in _VOSS_TYPES:
                return cls._parse_voss_tokens
            return None
        if len(tokens) >= 3 and _is_ipv4(tokens[1]):
            return cls._parse_exos_tokens
        return None

    @classmethod
    def parse_cli_arp(
        cls,
        raw_output: str,
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Auto-detect and parse ``ip neigh``, ExtremeXOS and VOSS ARP text output."""
        records: list[RouterArpRecord] = []
        for tokens in cls._iter_lines(raw_output):
            line_parser = cls._classify_cli_line(tokens)
            if line_parser is None:
                continue
            try:
                record = line_parser(tokens, router_id, observed_at)
            except ValueError:
                continue
            if record is not None:
                records.append(record)
        return records

    @staticmethod
    def _split_arp_index(
        suffix: str, *, physical: bool
    ) -> Optional[tuple[str, str]]:
        parts = suffix.split(".")
        if physical and len(parts) == 7 and parts[1:3] == ["1", "4"]:
            parts = [parts[0], *parts[3:]]
        if len(parts) != 5 or not all(p.isdigit() for p in parts):
            return None
        ip = ".".join(parts[1:])
        if not _is_ipv4(ip):
            return None
        return parts[0], str(ipaddress.IPv4Address(ip))

    @classmethod
    def _parse_snmp_oids(
        cls,
        oids: Mapping[str, Any],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> list[RouterArpRecord]:
        entries: dict[tuple[str, str], dict[str, Any]] = {}
        if_names: dict[str, str] = {}
        if_descrs: dict[str, str] = {}
        arp_prefixes = (
            (IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX, "mac", False),
            (IP_MIB_NET_TO_MEDIA_NET_ADDRESS_PREFIX, "net", False),
            (IP_MIB_NET_TO_MEDIA_TYPE_PREFIX, "type", False),
            (IP_MIB_NET_TO_PHYSICAL_PHYS_ADDRESS_PREFIX, "mac", True),
        )

        for raw_oid, raw_value in oids.items():
            oid = str(raw_oid).strip().lstrip(".")
            if oid.startswith("iso."):
                oid = "1." + oid[4:]
            if oid.startswith(IF_MIB_IF_NAME_PREFIX + "."):
                name = _snmp_text(raw_value)
                if name:
                    if_names[oid[len(IF_MIB_IF_NAME_PREFIX) + 1 :]] = name
                continue
            if oid.startswith(IF_MIB_IF_DESCR_PREFIX + "."):
                descr = _snmp_text(raw_value)
                if descr:
                    if_descrs[oid[len(IF_MIB_IF_DESCR_PREFIX) + 1 :]] = descr
                continue
            for prefix, kind, physical in arp_prefixes:
                if not oid.startswith(prefix + "."):
                    continue
                index = cls._split_arp_index(oid[len(prefix) + 1 :], physical=physical)
                if index is None:
                    break
                entry = entries.setdefault(index, {})
                if kind == "mac":
                    entry.setdefault("mac", _snmp_text(raw_value))
                elif kind == "type":
                    entry["type"] = _snmp_type_state(raw_value)
                else:
                    entry.setdefault("mac", None)
                break

        records: list[RouterArpRecord] = []
        for (if_index, ip), entry in sorted(
            entries.items(),
            key=lambda item: (ipaddress.IPv4Address(item[0][1]), int(item[0][0])),
        ):
            interface = if_names.get(if_index) or if_descrs.get(if_index) or if_index
            try:
                mac = _normalize_router_mac(entry.get("mac"))
            except ValueError:
                continue
            state = entry.get("type") or ("REACHABLE" if mac else None)
            records.append(
                RouterArpRecord(
                    ip=ip,
                    mac_address=mac,
                    interface=interface,
                    vlan_id=_vlan_from_interface(interface) or _vlan_from_ip(ip),
                    state=state,
                    router_id=router_id,
                    observed_at=observed_at,
                )
            )
        return records

    @staticmethod
    def _snmp_row_to_record(
        row: Mapping[str, Any],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> RouterArpRecord:
        ip = _snmp_text(_first_value(row, ("ip", "ipNetToMediaNetAddress")))
        if ip is None:
            raise ValueError("SNMP ARP row is missing an IP address")
        ip = _canonical_ipv4(ip)
        mac = _snmp_text(
            _first_value(row, ("mac_address", "mac", "ipNetToMediaPhysAddress"))
        )
        interface = _snmp_text(_first_value(row, ("interface", "if_index", "ifIndex")))
        raw_state = _first_value(row, ("state",))
        if raw_state is not None:
            state: Optional[str] = str(raw_state)
        else:
            state = _snmp_type_state(row.get("ipNetToMediaType"))
        normalized_mac = _normalize_router_mac(mac)
        if state is None and normalized_mac is not None:
            state = "REACHABLE"
        vlan_id = (
            _optional_token(row.get("vlan_id"), "vlan_id")
            or _vlan_from_interface(interface)
            or _vlan_from_ip(ip)
        )
        return RouterArpRecord(
            ip=ip,
            mac_address=normalized_mac,
            interface=interface,
            vlan_id=vlan_id,
            state=state,
            router_id=row.get("router_id") or router_id,
            observed_at=row.get("observed_at") or observed_at,
        )

    @classmethod
    def parse_snmp_arp(
        cls,
        raw_data: str | Mapping[str, Any] | Sequence[Mapping[str, Any]],
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Parse IP-MIB ARP walk data from a JSON string, OID dict, or row dicts."""
        data: Any = raw_data
        if isinstance(raw_data, str):
            if not raw_data.strip():
                return []
            data = json.loads(raw_data)

        if isinstance(data, Mapping):
            oids = data.get("oids")
            return cls._parse_snmp_oids(
                oids if isinstance(oids, Mapping) else data, router_id, observed_at
            )
        if isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
            records: list[RouterArpRecord] = []
            for row in data:
                if not isinstance(row, Mapping):
                    continue
                try:
                    records.append(cls._snmp_row_to_record(row, router_id, observed_at))
                except ValueError:
                    continue
            return records
        raise ValueError("SNMP ARP data must be a JSON string, mapping, or sequence")

    # ------------------------------------------------------------------ DHCP leases

    @staticmethod
    def parse_dnsmasq_leases(
        raw_text: str, *, subnet_id: Optional[str] = None
    ) -> list[DhcpLeaseRecord]:
        """Parse ``dnsmasq.leases`` lines (``<expiry> <mac> <ip> <hostname> <client_id>``)."""
        if not isinstance(raw_text, str):
            raise ValueError("raw_text must be a string")
        leases: list[DhcpLeaseRecord] = []
        for raw_line in raw_text.splitlines():
            tokens = raw_line.split()
            if len(tokens) < 3 or tokens[0].startswith("#") or tokens[0].lower() == "duid":
                continue
            try:
                leases.append(
                    DhcpLeaseRecord(
                        ip=tokens[2],
                        mac_address=tokens[1],
                        hostname=tokens[3] if len(tokens) > 3 else None,
                        lease_expires_at=tokens[0],
                        subnet_id=subnet_id,
                        client_id=tokens[4] if len(tokens) > 4 else None,
                    )
                )
            except ValueError:
                continue
        return leases

    @staticmethod
    def _lease_from_row(
        row: Mapping[str, Any], ip_hint: Optional[str], subnet_id: Optional[str]
    ) -> DhcpLeaseRecord:
        lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
        ip = _first_value(lowered, _LEASE_IP_KEYS) or ip_hint
        mac = _first_value(lowered, _LEASE_MAC_KEYS)
        if isinstance(mac, str) and mac.strip().lower().startswith("ethernet "):
            mac = mac.strip()[len("ethernet ") :]
        expires: Any = _first_value(lowered, _LEASE_EXPIRY_KEYS)
        if expires is None:
            cltt = _first_value(lowered, ("cltt",))
            valid_lft = _first_value(lowered, ("valid-lft", "valid_lft"))
            if cltt is not None and valid_lft is not None:
                lft = int(float(valid_lft))
                expires = None if lft >= _KEA_INFINITE_LFT else int(float(cltt)) + lft
        return DhcpLeaseRecord(
            ip=ip,
            mac_address=mac,
            hostname=_first_value(lowered, _LEASE_HOSTNAME_KEYS),
            lease_expires_at=expires,
            subnet_id=_first_value(lowered, _LEASE_SUBNET_KEYS) or subnet_id,
            client_id=_first_value(lowered, _LEASE_CLIENT_ID_KEYS),
        )

    @classmethod
    def _iter_lease_rows(cls, data: Any) -> Iterator[tuple[Optional[str], Mapping[str, Any]]]:
        if isinstance(data, Mapping):
            lowered_keys = {str(k).strip().lower() for k in data}
            if isinstance(data.get("arguments"), Mapping):
                yield from cls._iter_lease_rows(data["arguments"])
            elif "leases" in data:
                yield from cls._iter_lease_rows(data["leases"])
            elif lowered_keys & set(_LEASE_IP_KEYS):
                yield None, data
            else:
                for key, value in data.items():
                    if isinstance(value, Mapping) and _is_ipv4(str(key).strip()):
                        yield str(key).strip(), value
        elif isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
            for item in data:
                if isinstance(item, Mapping) and (
                    "arguments" in item or "leases" in item
                ):
                    yield from cls._iter_lease_rows(item)
                elif isinstance(item, Mapping):
                    yield None, item

    @classmethod
    def parse_json_dhcp_leases(
        cls,
        raw_data: str | Mapping[str, Any] | Sequence[Mapping[str, Any]],
        *,
        subnet_id: Optional[str] = None,
    ) -> list[DhcpLeaseRecord]:
        """Parse ISC / Kea DHCPv4 JSON lease exports and generic JSON lease lists."""
        data: Any = raw_data
        if isinstance(raw_data, str):
            if not raw_data.strip():
                return []
            data = json.loads(raw_data)
        if not isinstance(data, (Mapping, Sequence)) or isinstance(data, bytes):
            raise ValueError("DHCP lease data must be a JSON string, mapping, or sequence")
        leases: list[DhcpLeaseRecord] = []
        for ip_hint, row in cls._iter_lease_rows(data):
            try:
                leases.append(cls._lease_from_row(row, ip_hint, subnet_id))
            except (ValueError, TypeError):
                continue
        return leases

    @classmethod
    def parse_csv_dhcp_leases(
        cls, raw_csv: str, *, subnet_id: Optional[str] = None
    ) -> list[DhcpLeaseRecord]:
        """Parse CSV DHCP lease exports with (case-insensitive) header columns."""
        if not isinstance(raw_csv, str):
            raise ValueError("raw_csv must be a string")
        lines = [
            line
            for line in raw_csv.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        leases: list[DhcpLeaseRecord] = []
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            cleaned = {
                k: (v.strip() if isinstance(v, str) else v)
                for k, v in row.items()
                if k is not None
            }
            try:
                leases.append(cls._lease_from_row(cleaned, None, subnet_id))
            except (ValueError, TypeError):
                continue
        return leases

    @staticmethod
    def parse_isc_dhcpd_leases(
        raw_text: str, *, subnet_id: Optional[str] = None
    ) -> list[DhcpLeaseRecord]:
        """Parse ISC ``dhcpd.leases`` text blocks (``lease <ip> { ... }``)."""
        if not isinstance(raw_text, str):
            raise ValueError("raw_text must be a string")
        leases: list[DhcpLeaseRecord] = []
        for match in _ISC_LEASE_BLOCK_RE.finditer(raw_text):
            fields: dict[str, Optional[str]] = {}
            for stmt_match in _ISC_STATEMENT_RE.finditer(match.group(2)):
                statement = stmt_match.group(1).strip()
                parts = statement.split(None, 1)
                if len(parts) < 2:
                    continue
                keyword, rest = parts[0].lower(), parts[1].strip()
                if keyword == "ends":
                    fields["ends"] = re.sub(r"^(?:\d\s+|epoch\s+)", "", rest)
                elif keyword == "hardware":
                    fields["mac"] = rest.split()[-1]
                elif keyword == "client-hostname":
                    fields["hostname"] = rest.strip('"')
                elif keyword == "uid":
                    fields["client_id"] = rest.strip('"')
            try:
                leases.append(
                    DhcpLeaseRecord(
                        ip=match.group(1),
                        mac_address=fields.get("mac"),
                        hostname=fields.get("hostname"),
                        lease_expires_at=fields.get("ends"),
                        subnet_id=subnet_id,
                        client_id=fields.get("client_id"),
                    )
                )
            except ValueError:
                continue
        return leases

    @classmethod
    def parse_dhcp_leases(
        cls,
        raw_data: str | Mapping[str, Any] | Sequence[Mapping[str, Any]],
        *,
        subnet_id: Optional[str] = None,
    ) -> list[DhcpLeaseRecord]:
        """Detect the lease format (JSON, ISC, CSV or dnsmasq) and parse it."""
        if not isinstance(raw_data, str):
            return cls.parse_json_dhcp_leases(raw_data, subnet_id=subnet_id)
        text = raw_data.strip()
        if not text:
            return []
        if text[0] in "{[":
            return cls.parse_json_dhcp_leases(text, subnet_id=subnet_id)
        if _ISC_LEASE_START_RE.search(text):
            return cls.parse_isc_dhcpd_leases(text, subnet_id=subnet_id)
        first_line = next(
            (
                line
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ),
            "",
        )
        if "," in first_line:
            return cls.parse_csv_dhcp_leases(text, subnet_id=subnet_id)
        return cls.parse_dnsmasq_leases(text, subnet_id=subnet_id)


def _timestamp_rank(value: Optional[datetime]) -> float:
    return value.timestamp() if value is not None else float("-inf")


def _arp_rank(record: RouterArpRecord) -> tuple[bool, int, float]:
    return (
        record.mac_address is not None,
        _ARP_STATE_RANK.get(record.state or "", 1),
        _timestamp_rank(record.observed_at),
    )


def _lease_rank(lease: DhcpLeaseRecord) -> tuple[bool, float]:
    return lease.hostname is not None, _timestamp_rank(lease.lease_expires_at)


def _ip_slug(ip: str) -> str:
    return ip.strip().replace(".", "-")


def _is_synthetic_equipment_name(name: str, ip: str, equipment_id: str) -> bool:
    lowered = name.strip().lower()
    return (
        lowered == equipment_id.strip().lower()
        or lowered.startswith(("host-", "server-"))
        or re.fullmatch(r"[a-z_]+-" + re.escape(_ip_slug(ip)), lowered) is not None
    )


def _is_synthetic_device_hostname(hostname: str, ip: str) -> bool:
    slug = _ip_slug(ip)
    return hostname.strip().lower() in {f"{p}-{slug}" for p in ("router", "switch", "gw")}


class RouterArpDhcpCollector:
    """Merge router ARP and DHCP lease tables onto discovered hosts and Site snapshots."""

    def __init__(
        self,
        arp_records: Optional[Iterable[RouterArpRecord | Mapping[str, Any]]] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        *,
        observed_at: Optional[datetime | str] = None,
        gateway_octets: Sequence[int] = DEFAULT_GATEWAY_OCTETS,
    ) -> None:
        self.observed_at: Optional[datetime] = _coerce_datetime(observed_at, "observed_at")
        self.gateway_octets: tuple[int, ...] = tuple(gateway_octets)
        if not self.gateway_octets:
            raise ValueError("gateway_octets must not be empty")
        self._arp: dict[str, RouterArpRecord] = {}
        self._leases: dict[str, DhcpLeaseRecord] = {}
        self.add_arp_records(arp_records or ())
        self.add_dhcp_leases(dhcp_leases or ())

    def add_arp_records(
        self, records: Iterable[RouterArpRecord | Mapping[str, Any]]
    ) -> None:
        """Merge ARP records, keeping the best record per IP."""
        for raw in records:
            record = raw if isinstance(raw, RouterArpRecord) else RouterArpRecord.from_dict(raw)
            current = self._arp.get(record.ip)
            if current is None or _arp_rank(record) > _arp_rank(current):
                self._arp[record.ip] = record

    def add_dhcp_leases(
        self, leases: Iterable[DhcpLeaseRecord | Mapping[str, Any]]
    ) -> None:
        """Merge DHCP leases, keeping the best lease per IP."""
        for raw in leases:
            lease = raw if isinstance(raw, DhcpLeaseRecord) else DhcpLeaseRecord.from_dict(raw)
            current = self._leases.get(lease.ip)
            if current is None or _lease_rank(lease) > _lease_rank(current):
                self._leases[lease.ip] = lease

    @property
    def arp_by_ip(self) -> dict[str, RouterArpRecord]:
        """Best ARP record per canonical IPv4 address."""
        return dict(self._arp)

    @property
    def leases_by_ip(self) -> dict[str, DhcpLeaseRecord]:
        """Best DHCP lease per canonical IPv4 address."""
        return dict(self._leases)

    def _merge(
        self,
        arp_records: Optional[Iterable[RouterArpRecord | Mapping[str, Any]]],
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]],
    ) -> None:
        if arp_records is not None:
            self.add_arp_records(arp_records)
        if dhcp_leases is not None:
            self.add_dhcp_leases(dhcp_leases)

    def enrich_hosts(
        self,
        hosts: Sequence[DiscoveredHost | Mapping[str, Any]],
        *,
        arp_records: Optional[Iterable[RouterArpRecord | Mapping[str, Any]]] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        overwrite: bool = False,
    ) -> list[DiscoveredHost]:
        """Backfill MAC, ARP state, hostname and inferred role onto discovered hosts."""
        self._merge(arp_records, dhcp_leases)
        enriched: list[DiscoveredHost] = []
        for raw_host in hosts:
            host = (
                raw_host
                if isinstance(raw_host, DiscoveredHost)
                else DiscoveredHost.from_dict(raw_host)
            )
            arp = self._arp.get(host.ip)
            lease = self._leases.get(host.ip)
            mac_changed = False
            hostname_changed = False

            new_mac = (arp.mac_address if arp is not None else None) or (
                lease.mac_address if lease is not None else None
            )
            if (
                new_mac is not None
                and (host.mac_address is None or overwrite)
                and new_mac != host.mac_address
            ):
                host.mac_address = new_mac
                mac_changed = True

            if host.arp_state is None or overwrite:
                if arp is not None and arp.state is not None:
                    host.arp_state = arp.state
                elif mac_changed and host.arp_state is None:
                    host.arp_state = "REACHABLE"

            new_hostname = lease.hostname if lease is not None else None
            if (
                new_hostname is not None
                and (host.hostname is None or overwrite)
                and new_hostname != host.hostname
            ):
                host.hostname = new_hostname
                hostname_changed = True

            if host.inferred_role == "host" or overwrite or mac_changed or hostname_changed:
                host.inferred_role = _infer_host_role(
                    ip=host.ip,
                    gateway_octets=self.gateway_octets,
                    mac_address=host.mac_address,
                    open_tcp_ports=host.open_tcp_ports,
                    hostname=host.hostname,
                )
            enriched.append(host)
        return enriched

    @staticmethod
    def _primary_device_id(
        site: Site, subnet_cidr: Optional[str], ip: str
    ) -> Optional[str]:
        try:
            net = ipaddress.ip_network(subnet_cidr or f"{ip}/24", strict=False)
        except ValueError:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)

        def _in_net(dev: NetworkDevice) -> bool:
            try:
                return ipaddress.ip_address((dev.management_ip or "").strip()) in net
            except ValueError:
                return False

        infra = [
            d for d in site.devices if (d.role or "").strip().lower() in ("router", "switch")
        ]
        for pool in ([d for d in infra if _in_net(d)], infra):
            for role in ("router", "switch"):
                for dev in pool:
                    if (dev.role or "").strip().lower() == role:
                        return dev.device_id
        return None

    def enrich_site(
        self,
        site: Site,
        *,
        arp_records: Optional[Iterable[RouterArpRecord | Mapping[str, Any]]] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        observed_at: Optional[datetime | str] = None,
        overwrite: bool = False,
    ) -> Site:
        """Backfill ARP, hostname, equipment and port data onto a Site in place."""
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")
        self._merge(arp_records, dhcp_leases)
        fallback_obs = (
            _coerce_datetime(observed_at, "observed_at")
            or self.observed_at
            or datetime.now(timezone.utc)
        )
        eq_by_id = {eq.equipment_id: eq for eq in site.equipment}
        dev_by_id = {dev.device_id: dev for dev in site.devices}
        cidr_by_subnet = {s.subnet_id: s.cidr for s in site.subnets}

        for ip_rec in site.ip_addresses:
            try:
                ip_key = _canonical_ipv4(ip_rec.ip)
            except ValueError:
                continue
            arp = self._arp.get(ip_key)
            lease = self._leases.get(ip_key)
            if arp is None and lease is None:
                continue

            mac = (arp.mac_address if arp is not None else None) or (
                lease.mac_address if lease is not None else None
            )
            hostname = lease.hostname if lease is not None else None
            linked_eq = eq_by_id.get(ip_rec.assigned_object_id or "")
            linked_dev = dev_by_id.get(ip_rec.assigned_object_id or "")
            if linked_eq is not None or linked_dev is not None:
                equipment, device = linked_eq, linked_dev
            else:
                equipment = next(
                    (
                        eq
                        for eq in site.equipment
                        if ip_key in (a.strip() for a in eq.assigned_ips)
                    ),
                    None,
                )
                device = next(
                    (
                        dev
                        for dev in site.devices
                        if (dev.management_ip or "").strip() == ip_key
                    ),
                    None,
                )

            if mac is not None:
                obs_dt = (arp.observed_at if arp is not None else None) or fallback_obs
                source_id = (
                    (arp.router_id if arp is not None else None)
                    or ip_rec.arp_source_device_id
                    or self._primary_device_id(
                        site, cidr_by_subnet.get(ip_rec.subnet_id), ip_key
                    )
                )
                if ip_rec.arp_mac is None or overwrite:
                    ip_rec.arp_mac = mac
                    ip_rec.arp_last_seen = obs_dt
                    ip_rec.arp_source_device_id = source_id
                if ip_rec.arp_entry is None or overwrite:
                    ip_rec.arp_entry = ArpEntry(
                        ip=ip_rec.ip,
                        arp_mac=ip_rec.arp_mac or mac,
                        arp_last_seen=ip_rec.arp_last_seen or obs_dt,
                        arp_source_device_id=ip_rec.arp_source_device_id or source_id,
                        subnet_id=ip_rec.subnet_id,
                    )

            if hostname is not None:
                if ip_rec.assigned_object_id is None or (
                    overwrite and linked_eq is None and linked_dev is None
                ):
                    if equipment is not None:
                        ip_rec.assigned_object_id = equipment.equipment_id
                        if ip_rec.assigned_object_type is None or overwrite:
                            ip_rec.assigned_object_type = "Equipment"
                    elif device is not None:
                        ip_rec.assigned_object_id = device.device_id
                        if ip_rec.assigned_object_type is None or overwrite:
                            ip_rec.assigned_object_type = "NetworkDevice"
                    else:
                        ip_rec.assigned_object_id = hostname
                        if ip_rec.assigned_object_type is None:
                            ip_rec.assigned_object_type = "Equipment"
                if equipment is not None and (
                    overwrite
                    or _is_synthetic_equipment_name(
                        equipment.name, ip_key, equipment.equipment_id
                    )
                ):
                    equipment.name = hostname
                if device is not None and (
                    overwrite
                    or _is_synthetic_device_hostname(
                        device.hostname, device.management_ip or ip_key
                    )
                ):
                    device.hostname = hostname

            if equipment is not None and (mac is not None or hostname is not None):
                category = _role_to_equipment_category(
                    _infer_host_role(
                        ip=ip_key,
                        gateway_octets=self.gateway_octets,
                        mac_address=mac,
                        hostname=hostname,
                    )
                )
                if category is not EquipmentCategory.OTHER and (
                    equipment.category is EquipmentCategory.OTHER or overwrite
                ):
                    equipment.category = category

            if mac is not None:
                target_id = ip_rec.assigned_object_id
                for dev in site.devices:
                    for port in dev.ports:
                        matches = (
                            target_id is not None and port.connected_device_id == target_id
                        ) or (dev is device and port.name == "mgmt0")
                        if matches and (port.connected_mac is None or overwrite):
                            port.connected_mac = mac
                if (
                    device is not None
                    and device.vendor is None
                    and mac.startswith("00:04:96")
                ):
                    device.vendor = "Extreme Networks"

        return site


__all__ = [
    "DhcpLeaseRecord",
    "RouterArpDhcpCollector",
    "RouterArpRecord",
    "RouterTableParsers",
]
