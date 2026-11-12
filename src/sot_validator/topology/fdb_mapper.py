"""Switch Bridge-MIB / FDB MAC-to-port parser, trunk/access inferrer, and Site port auto-mapper."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import ipaddress
import json
import re
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    _require_non_empty_str,
)
from sot_validator.topology.device_types import (
    DevicePortManager,
    normalize_mac_address,
)
from sot_validator.topology.identifier import (
    KNOWN_OUI_VENDORS,
    _TOKEN_SPLIT_PATTERN,
    _extract_oui_prefix,
)

VALID_PORT_MODES: tuple[str, ...] = ("access", "trunk", "uplink", "empty")

_ROUTER_ROLES: frozenset[str] = frozenset(
    {"router", "l3_switch", "firewall", "gateway"}
)
_ROUTER_HOSTNAME_TOKENS: frozenset[str] = frozenset(
    {"router", "gw", "gateway", "rtr", "udm", "edge"}
)
_SWITCH_HOSTNAME_TOKENS: frozenset[str] = frozenset(
    {"sw", "switch", "idf", "mdf", "exos", "voss", "core"}
)
_IGNORED_PORT_TOKENS: frozenset[str] = frozenset(
    {
        "cpu",
        "router",
        "switch",
        "sup-eth1(r)",
        "sup-eth1",
        "vl1",
        "drop",
        "blackhole",
        "self",
        "none",
        "-",
        "m",
        "d",
        "s",
        "p",
        "b",
        "i",
        "l",
        "dynamic",
        "static",
        "permanent",
        "learned",
        "mgmt",
        "self-ip",
    }
)
_MAC_CANDIDATE_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F]{12})$"
)
_PAREN_VLAN_PATTERN = re.compile(r"\((\d{1,4})\)")
_VLAN_SUFFIX_PATTERN = re.compile(r"(?:vlan|vl)[_\-]?(\d{1,4})$", re.IGNORECASE)
_VOSS_PORT_PREFIX_PATTERN = re.compile(r"^port[\-_]?(\d+/\d+(?:/\d+)?)$", re.IGNORECASE)
_QBRIDGE_FDB_OID_PATTERN = re.compile(
    r"^\.?(?:1\.3\.6\.1\.2\.1\.17\.7\.1\.2\.2\.1\.2|dot1qTpFdbPort)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)$"
)
_BRIDGE_FDB_OID_PATTERN = re.compile(
    r"^\.?(?:1\.3\.6\.1\.2\.1\.17\.4\.3\.1\.2|dot1dTpFdbPort)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)$"
)
_HOSTNAME_TRAILING_DIGITS_PATTERN = re.compile(r"\d+$")


def _parse_mac_token(raw: Any) -> Optional[str]:
    """Normalize a token only when it is shaped like a full MAC address (CLI-safe)."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    cleaned = raw.strip()
    if not _MAC_CANDIDATE_PATTERN.match(cleaned):
        return None
    try:
        return normalize_mac_address(cleaned)
    except ValueError:
        return None


def _parse_static_flag(value: Any) -> bool:
    """Parse FDB static/status values (bool, Q-BRIDGE status int, or string)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        # Q-BRIDGE-MIB dot1qTpFdbStatus: 1=other, 2=invalid, 3=learned, 4=self, 5=mgmt
        return value in (4, 5)
    if isinstance(value, str):
        return value.strip().lower() in ("static", "permanent", "mgmt", "4", "5", "true")
    return False


def _normalize_vlan_id(raw: Any) -> Optional[str]:
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return str(raw) if raw > 0 else None
    text = str(raw).strip()
    if not text:
        return None
    m_paren = _PAREN_VLAN_PATTERN.search(text)
    if m_paren:
        val = int(m_paren.group(1))
        return str(val) if val > 0 else None
    m_suffix = _VLAN_SUFFIX_PATTERN.search(text)
    if m_suffix:
        val = int(m_suffix.group(1))
        return str(val) if val > 0 else None
    if text.isdigit():
        val = int(text)
        return str(val) if val > 0 else None
    return text


def _normalize_voss_port_name(raw_port: str) -> str:
    cleaned = raw_port.strip()
    m = _VOSS_PORT_PREFIX_PATTERN.match(cleaned)
    if m:
        return m.group(1)
    return cleaned


def _is_ignored_port_token(token: str) -> bool:
    cleaned = token.strip().lower()
    if not cleaned or cleaned in _IGNORED_PORT_TOKENS:
        return True
    if cleaned.startswith("sup-eth") or cleaned.startswith("cpu"):
        return True
    if re.match(r"^vl(?:an)?\d+$", cleaned):
        return True
    return False


def _looks_like_port_name(token: str) -> bool:
    cleaned = token.strip()
    if not cleaned or _is_ignored_port_token(cleaned):
        return False
    if _parse_mac_token(cleaned) is not None:
        return False
    # Common switch port formats: 1:1, 1/1, Gi1/0/1, Port-1/1, eth1, Po1, lag1, etc.
    if re.match(r"^\d+[:/]\d+(?:[:/]\d+)*$", cleaned):
        return True
    if _VOSS_PORT_PREFIX_PATTERN.match(cleaned):
        return True
    if re.match(
        r"^(?:gi|fa|te|tw|fo|hu|et|eth|ge|xe|po|port-channel|lag|mlt|trk|bridge|br|eno|ens|enp)[a-z0-9\-_/:.]*$",
        cleaned,
        re.IGNORECASE,
    ):
        return True
    return False


def _site_gateway_ips(site: Site) -> set[str]:
    gateway_ips: set[str] = set()
    for v in site.vlans:
        if v.gateway and v.gateway.strip():
            gateway_ips.add(v.gateway.strip())
    for s in site.subnets:
        if s.gateway and s.gateway.strip():
            gateway_ips.add(s.gateway.strip())
    return gateway_ips


def _unlink_port_from_equipment(site: Site, dev: NetworkDevice, port: Port) -> None:
    """Remove references to `port` from every `Equipment.connected_ports` in `site`."""
    refs = {port.port_id, f"{dev.device_id}:{port.name}", f"{dev.hostname}:{port.name}"}
    # A bare port name is only cleared when it identifies this port uniquely in the site
    name_is_unique = not any(
        p.name == port.name
        for d in site.devices
        for p in d.ports
        if p is not port
    )
    if name_is_unique:
        refs.add(port.name)
    for eq in site.equipment:
        if any(ref in refs for ref in eq.connected_ports):
            eq.connected_ports = [ref for ref in eq.connected_ports if ref not in refs]


def _deduplicate_entries(entries: Sequence[FdbEntry]) -> list[FdbEntry]:
    seen: dict[tuple[str, str, str, Optional[str]], FdbEntry] = {}
    ordered_keys: list[tuple[str, str, str, Optional[str]]] = []
    for entry in entries:
        key = (
            entry.device_id,
            entry.port_name,
            entry.mac_address,
            entry.vlan_id,
        )
        if key not in seen:
            seen[key] = entry
            ordered_keys.append(key)
        elif entry.is_static and not seen[key].is_static:
            seen[key] = entry
    return [seen[k] for k in ordered_keys]


@dataclass
class FdbEntry:
    """Normalized switch Forwarding Database (FDB) / Bridge-MIB MAC table entry."""

    device_id: str
    port_name: str
    mac_address: str
    vlan_id: Optional[str] = None
    is_static: bool = False

    def __post_init__(self) -> None:
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")
        self.device_id = self.device_id.strip()
        self.port_name = self.port_name.strip()
        self.mac_address = normalize_mac_address(self.mac_address)
        if self.vlan_id is not None:
            if isinstance(self.vlan_id, bool):
                raise ValueError("vlan_id must be a string, int, or None")
            cleaned_vlan = str(self.vlan_id).strip()
            self.vlan_id = cleaned_vlan if cleaned_vlan else None
        self.is_static = bool(self.is_static)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "port_name": self.port_name,
            "mac_address": self.mac_address,
            "vlan_id": self.vlan_id,
            "is_static": self.is_static,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FdbEntry:
        return cls(
            device_id=data["device_id"],
            port_name=data["port_name"],
            mac_address=data["mac_address"],
            vlan_id=data.get("vlan_id"),
            is_static=_parse_static_flag(data.get("is_static", False)),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> FdbEntry:
        return cls.from_dict(json.loads(raw))


@dataclass
class PortClassificationResult:
    """Inferred port mode (`access`, `trunk`, `uplink`, `empty`) and downstream binding metadata."""

    device_id: str
    port_name: str
    port_mode: str
    learned_mac_count: int = 0
    vlan_ids: list[str] = field(default_factory=list)
    bound_mac: Optional[str] = None
    bound_device_id: Optional[str] = None
    rationale: str = ""

    def __post_init__(self) -> None:
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")
        _require_non_empty_str(self.port_mode, "port_mode")
        self.device_id = self.device_id.strip()
        self.port_name = self.port_name.strip()

        normalized_mode = self.port_mode.strip().lower()
        if normalized_mode not in VALID_PORT_MODES:
            raise ValueError(
                f"Invalid port_mode {self.port_mode!r}; must be one of {VALID_PORT_MODES}"
            )
        self.port_mode = normalized_mode

        if (
            isinstance(self.learned_mac_count, bool)
            or not isinstance(self.learned_mac_count, int)
            or self.learned_mac_count < 0
        ):
            raise ValueError("learned_mac_count must be a non-negative integer")

        dedup_vlans: list[str] = []
        for v in self.vlan_ids or []:
            if v is None or isinstance(v, bool):
                continue
            v_str = str(v).strip()
            if v_str and v_str not in dedup_vlans:
                dedup_vlans.append(v_str)
        self.vlan_ids = dedup_vlans

        if self.bound_mac is not None:
            self.bound_mac = normalize_mac_address(self.bound_mac)

        if self.bound_device_id is not None:
            cleaned_dev = str(self.bound_device_id).strip()
            self.bound_device_id = cleaned_dev if cleaned_dev else None

        self.rationale = str(self.rationale) if self.rationale is not None else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "port_name": self.port_name,
            "port_mode": self.port_mode,
            "learned_mac_count": self.learned_mac_count,
            "vlan_ids": list(self.vlan_ids),
            "bound_mac": self.bound_mac,
            "bound_device_id": self.bound_device_id,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PortClassificationResult:
        return cls(
            device_id=data["device_id"],
            port_name=data["port_name"],
            port_mode=data["port_mode"],
            learned_mac_count=data.get("learned_mac_count", 0),
            vlan_ids=list(data.get("vlan_ids", [])),
            bound_mac=data.get("bound_mac"),
            bound_device_id=data.get("bound_device_id"),
            rationale=data.get("rationale", ""),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> PortClassificationResult:
        return cls.from_dict(json.loads(raw))


class FdbTableParser:
    """Multi-dialect parser for switch CLI FDB outputs and SNMP Q-BRIDGE-MIB / JSON records."""

    def parse_exos(self, text: str, *, device_id: str) -> list[FdbEntry]:
        """Parse ExtremeXOS `show fdb` CLI output into normalized FdbEntry records."""
        _require_non_empty_str(device_id, "device_id")
        if not isinstance(text, str) or not text.strip():
            return []

        entries: list[FdbEntry] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("-", "=", "#", "Mac", "MAC", "Flags", "Total")):
                continue
            tokens = line.split()
            if len(tokens) < 3:
                continue

            norm_mac = _parse_mac_token(tokens[0])
            if norm_mac is None:
                continue

            port_candidate = tokens[-1]
            if _is_ignored_port_token(port_candidate) or not _looks_like_port_name(
                port_candidate
            ):
                continue

            # Extract VLAN ID from second token (or combined VLAN name + `(0010)`)
            vlan_id: Optional[str] = None
            m_paren = _PAREN_VLAN_PATTERN.search(line)
            if m_paren:
                vlan_id = _normalize_vlan_id(m_paren.group(1))
            else:
                vlan_id = _normalize_vlan_id(tokens[1])

            # Inspect middle flag tokens for static ('s', 'sp', 'static', 'permanent')
            middle_tokens = [t.lower() for t in tokens[2:-1]]
            is_static = any(
                t in ("s", "sp", "static", "permanent", "mgmt")
                for t in middle_tokens
            )

            entries.append(
                FdbEntry(
                    device_id=device_id,
                    port_name=port_candidate,
                    mac_address=norm_mac,
                    vlan_id=vlan_id,
                    is_static=is_static,
                )
            )

        return _deduplicate_entries(entries)

    def parse_voss(self, text: str, *, device_id: str) -> list[FdbEntry]:
        """Parse Extreme VOSS `show mac-address-table` / `show vlan mac-address-entry` CLI output."""
        _require_non_empty_str(device_id, "device_id")
        if not isinstance(text, str) or not text.strip():
            return []

        entries: list[FdbEntry] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("-", "=", "#", "Vlan", "VLAN", "Mac", "MAC", "Total")):
                continue
            tokens = line.split()
            if len(tokens) < 3:
                continue

            mac_idx: Optional[int] = None
            norm_mac: Optional[str] = None
            for idx, tok in enumerate(tokens):
                cand = _parse_mac_token(tok)
                if cand is not None:
                    mac_idx = idx
                    norm_mac = cand
                    break

            if norm_mac is None or mac_idx is None:
                continue

            vlan_id: Optional[str] = None
            port_name: Optional[str] = None
            is_static = False

            for idx, tok in enumerate(tokens):
                if idx == mac_idx:
                    continue
                tok_lower = tok.lower()
                if tok_lower in ("static", "permanent", "mgmt"):
                    is_static = True
                    continue
                if tok_lower in ("dynamic", "learned", "age", "aged", "true", "false"):
                    continue

                if (
                    vlan_id is None
                    and (idx < mac_idx or (idx == mac_idx + 1 and tok.isdigit()))
                    and (tok.isdigit() or _VLAN_SUFFIX_PATTERN.match(tok))
                ):
                    vlan_id = _normalize_vlan_id(tok)
                    continue

                if port_name is None and _looks_like_port_name(tok):
                    port_name = _normalize_voss_port_name(tok)

            if port_name is None or _is_ignored_port_token(port_name):
                continue

            entries.append(
                FdbEntry(
                    device_id=device_id,
                    port_name=port_name,
                    mac_address=norm_mac,
                    vlan_id=vlan_id,
                    is_static=is_static,
                )
            )

        return _deduplicate_entries(entries)

    def parse_cisco(self, text: str, *, device_id: str) -> list[FdbEntry]:
        """Parse Cisco IOS / generic `show mac address-table` CLI output."""
        _require_non_empty_str(device_id, "device_id")
        if not isinstance(text, str) or not text.strip():
            return []

        entries: list[FdbEntry] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(
                ("-", "=", "#", "Vlan", "VLAN", "Mac", "MAC", "Total", "All")
            ):
                continue
            tokens = [t for t in line.split() if t not in ("*", "+", "G", "R", "O")]
            if len(tokens) < 3:
                continue

            mac_idx: Optional[int] = None
            norm_mac: Optional[str] = None
            for idx, tok in enumerate(tokens):
                cand = _parse_mac_token(tok)
                if cand is not None:
                    mac_idx = idx
                    norm_mac = cand
                    break

            if norm_mac is None or mac_idx is None:
                continue

            port_candidate = tokens[-1]
            if _is_ignored_port_token(port_candidate) or not _looks_like_port_name(
                port_candidate
            ):
                continue

            vlan_id: Optional[str] = None
            if mac_idx > 0:
                vlan_id = _normalize_vlan_id(tokens[0])

            middle_tokens = [t.lower() for t in tokens[mac_idx + 1 : -1]]
            is_static = any(
                t in ("static", "permanent", "s", "mgmt") for t in middle_tokens
            )

            entries.append(
                FdbEntry(
                    device_id=device_id,
                    port_name=port_candidate,
                    mac_address=norm_mac,
                    vlan_id=vlan_id,
                    is_static=is_static,
                )
            )

        return _deduplicate_entries(entries)

    def parse_cli(
        self,
        text: str,
        *,
        device_id: str,
        dialect: str = "auto",
    ) -> list[FdbEntry]:
        """Parse CLI FDB output across `exos`, `voss`, `cisco`, or `auto` dialects."""
        _require_non_empty_str(device_id, "device_id")
        norm_dialect = (dialect or "auto").strip().lower()
        if norm_dialect not in ("auto", "exos", "voss", "cisco"):
            raise ValueError(
                f"Unsupported FDB CLI dialect {dialect!r}; must be one of ('auto', 'exos', 'voss', 'cisco')"
            )

        if norm_dialect == "exos":
            return self.parse_exos(text, device_id=device_id)
        if norm_dialect == "voss":
            return self.parse_voss(text, device_id=device_id)
        if norm_dialect == "cisco":
            return self.parse_cisco(text, device_id=device_id)

        if not isinstance(text, str) or not text.strip():
            return []

        combined: list[FdbEntry] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            # Check EXOS pattern first (starts with MAC and has paren VLAN or EXOS port N:M)
            tokens = line.split()
            if tokens and _parse_mac_token(tokens[0]) is not None:
                if _PAREN_VLAN_PATTERN.search(line) or (
                    len(tokens) >= 4 and ":" in tokens[-1]
                ):
                    parsed = self.parse_exos(line, device_id=device_id)
                    if parsed:
                        combined.extend(parsed)
                        continue
                parsed_voss = self.parse_voss(line, device_id=device_id)
                if parsed_voss:
                    combined.extend(parsed_voss)
                    continue
                parsed_exos = self.parse_exos(line, device_id=device_id)
                if parsed_exos:
                    combined.extend(parsed_exos)
                    continue

            # Check VOSS vs Cisco
            if any(_VOSS_PORT_PREFIX_PATTERN.match(t) for t in tokens) or any(
                t.lower() in ("learned",) for t in tokens
            ):
                parsed = self.parse_voss(line, device_id=device_id)
                if parsed:
                    combined.extend(parsed)
                    continue

            parsed_cisco = self.parse_cisco(line, device_id=device_id)
            if parsed_cisco:
                combined.extend(parsed_cisco)
                continue

            parsed_voss = self.parse_voss(line, device_id=device_id)
            if parsed_voss:
                combined.extend(parsed_voss)

        return _deduplicate_entries(combined)

    def parse_qbridge_mib(
        self,
        data: str | Sequence[Mapping[str, Any]] | Mapping[str, Any],
        *,
        device_id: Optional[str] = None,
        port_index_map: Optional[Mapping[int | str, str]] = None,
    ) -> list[FdbEntry]:
        """Parse SNMP Q-BRIDGE-MIB / BRIDGE-MIB OID tables or JSON record lists into FdbEntry records."""
        parsed_data: Any = data
        if isinstance(data, str):
            stripped = data.strip()
            if not stripped:
                return []
            parsed_data = json.loads(stripped)

        resolved_port_map: dict[str, str] = {}
        if port_index_map:
            for k, v in port_index_map.items():
                if v is not None and str(v).strip():
                    resolved_port_map[str(k).strip()] = str(v).strip()

        def resolve_port_name(raw_port: Any) -> Optional[str]:
            if raw_port is None or isinstance(raw_port, bool):
                return None
            key = str(raw_port).strip()
            if not key or key == "0":
                return None
            if key in resolved_port_map:
                return resolved_port_map[key]
            return _normalize_voss_port_name(key)

        entries: list[FdbEntry] = []

        if isinstance(parsed_data, Mapping):
            # Wrapper dict with entries/fdb/records list
            record_list: Optional[Sequence[Any]] = None
            for list_key in ("entries", "fdb", "records", "items", "data"):
                if isinstance(parsed_data.get(list_key), Sequence) and not isinstance(
                    parsed_data.get(list_key), (str, bytes)
                ):
                    record_list = parsed_data[list_key]
                    break

            default_dev_id = (
                device_id
                or parsed_data.get("device_id")
                or parsed_data.get("switch_id")
            )

            if record_list is not None:
                return self.parse_qbridge_mib(
                    record_list,
                    device_id=str(default_dev_id) if default_dev_id else None,
                    port_index_map=port_index_map,
                )

            # Single record dict vs OID-keyed mapping
            if any(
                k in parsed_data
                for k in (
                    "mac_address",
                    "mac",
                    "dot1qTpFdbAddress",
                    "dot1dTpFdbAddress",
                )
            ):
                return self.parse_qbridge_mib(
                    [parsed_data],
                    device_id=device_id,
                    port_index_map=port_index_map,
                )

            # OID-keyed mapping: { "<oid>": <bridge_port_or_dict>, ... }
            if not default_dev_id:
                raise ValueError(
                    "device_id is required when parsing OID-keyed Q-BRIDGE-MIB mappings"
                )
            dev_id_str = str(default_dev_id).strip()

            for oid_key, raw_val in parsed_data.items():
                oid_str = str(oid_key).strip()
                vlan_id: Optional[str] = None
                octets: Optional[tuple[int, ...]] = None

                m_q = _QBRIDGE_FDB_OID_PATTERN.match(oid_str)
                if m_q:
                    vlan_id = _normalize_vlan_id(m_q.group(1))
                    octets = tuple(int(m_q.group(i)) for i in range(2, 8))
                else:
                    m_b = _BRIDGE_FDB_OID_PATTERN.match(oid_str)
                    if m_b:
                        octets = tuple(int(m_b.group(i)) for i in range(1, 7))

                if octets is None or any(o < 0 or o > 255 for o in octets):
                    continue

                mac_str = ":".join(f"{o:02x}" for o in octets)
                is_static = False
                if isinstance(raw_val, Mapping):
                    raw_port = (
                        raw_val.get("port_name")
                        or raw_val.get("port")
                        or raw_val.get("bridge_port")
                        or raw_val.get("dot1qTpFdbPort")
                        or raw_val.get("dot1dTpFdbPort")
                    )
                    status_val = raw_val.get("status", raw_val.get("is_static", False))
                    is_static = _parse_static_flag(status_val)
                    if raw_val.get("vlan_id") is not None:
                        vlan_id = _normalize_vlan_id(raw_val.get("vlan_id"))
                else:
                    raw_port = raw_val

                port_name = resolve_port_name(raw_port)
                if not port_name or _is_ignored_port_token(port_name):
                    continue

                entries.append(
                    FdbEntry(
                        device_id=dev_id_str,
                        port_name=port_name,
                        mac_address=mac_str,
                        vlan_id=vlan_id,
                        is_static=is_static,
                    )
                )

            return _deduplicate_entries(entries)

        if isinstance(parsed_data, Sequence) and not isinstance(
            parsed_data, (str, bytes)
        ):
            for item in parsed_data:
                if not isinstance(item, Mapping):
                    continue
                rec_dev_id = (
                    item.get("device_id")
                    or item.get("switch_id")
                    or device_id
                )
                if not rec_dev_id or not str(rec_dev_id).strip():
                    raise ValueError(
                        "Each Q-BRIDGE-MIB record must provide device_id or pass device_id to parse_qbridge_mib"
                    )

                raw_mac = (
                    item.get("mac_address")
                    or item.get("mac")
                    or item.get("dot1qTpFdbAddress")
                    or item.get("dot1dTpFdbAddress")
                )
                if raw_mac is None:
                    continue

                raw_port = (
                    item.get("port_name")
                    or item.get("port")
                    or item.get("interface")
                    or item.get("bridge_port")
                    or item.get("dot1qTpFdbPort")
                    or item.get("dot1dTpFdbPort")
                )
                port_name = resolve_port_name(raw_port)
                if not port_name or _is_ignored_port_token(port_name):
                    continue

                raw_vlan = (
                    item.get("vlan_id")
                    if item.get("vlan_id") is not None
                    else (
                        item.get("vlan")
                        if item.get("vlan") is not None
                        else item.get("fdb_id")
                    )
                )
                vlan_id = _normalize_vlan_id(raw_vlan)

                if "is_static" in item:
                    is_static = _parse_static_flag(item["is_static"])
                else:
                    status_val = item.get(
                        "status",
                        item.get("dot1qTpFdbStatus", item.get("dot1dTpFdbStatus")),
                    )
                    is_static = _parse_static_flag(status_val)

                entries.append(
                    FdbEntry(
                        device_id=str(rec_dev_id).strip(),
                        port_name=port_name,
                        mac_address=normalize_mac_address(str(raw_mac)),
                        vlan_id=vlan_id,
                        is_static=is_static,
                    )
                )

            return _deduplicate_entries(entries)

        raise ValueError("Unsupported Q-BRIDGE-MIB input format")


class SwitchFdbPortMapper:
    """Infers switch port modes (`access`, `trunk`, `uplink`, `empty`) from FDB entries and auto-binds Site ports."""

    def __init__(
        self,
        *,
        max_access_macs: int = 2,
        oui_vendors: Optional[Mapping[str, tuple[str, str]]] = None,
    ) -> None:
        if (
            isinstance(max_access_macs, bool)
            or not isinstance(max_access_macs, int)
            or max_access_macs < 1
        ):
            raise ValueError("max_access_macs must be an integer >= 1")
        self.max_access_macs = max_access_macs
        self.oui_vendors: dict[str, tuple[str, str]] = dict(KNOWN_OUI_VENDORS)
        if oui_vendors:
            for k, v in oui_vendors.items():
                self.oui_vendors[k.strip().lower()] = v

    @staticmethod
    def _classify_network_device_role(
        dev: NetworkDevice, site_gateway_ips: set[str]
    ) -> str:
        role_lower = (dev.role or "").strip().lower()
        mgmt_ip = dev.management_ip.strip() if dev.management_ip else None
        if role_lower in _ROUTER_ROLES or (
            mgmt_ip is not None and mgmt_ip in site_gateway_ips
        ):
            return "router"
        if role_lower == "switch":
            return "switch"
        hostname_lower = (dev.hostname or "").strip().lower()
        # Strip trailing digits so `site01-sw01` yields the `sw` token
        tokens = {
            _HOSTNAME_TRAILING_DIGITS_PATTERN.sub("", t)
            for t in _TOKEN_SPLIT_PATTERN.split(hostname_lower)
            if t
        }
        if not role_lower:
            if tokens & _ROUTER_HOSTNAME_TOKENS or any(
                s in hostname_lower for s in ("router", "gateway", "udm")
            ):
                return "router"
            if tokens & _SWITCH_HOSTNAME_TOKENS or any(
                s in hostname_lower for s in ("switch", "exos", "voss")
            ):
                return "switch"
            # Unroled devices without router/switch hints are treated as end-hosts
            return ""
        return role_lower

    def _infrastructure_device_ids(self, site: Site) -> set[str]:
        site_gateway_ips = _site_gateway_ips(site)
        return {
            d.device_id
            for d in site.devices
            if self._classify_network_device_role(d, site_gateway_ips)
            in ("router", "switch")
        }

    def _build_site_lookup_context(
        self,
        site: Site,
        *,
        arp_entries: Sequence[ArpEntry] = (),
        device_mac_map: Optional[Mapping[str, str]] = None,
    ) -> dict[str, Any]:
        subnet_by_id: dict[str, Subnet] = {s.subnet_id: s for s in site.subnets}
        # Invalid CIDRs in legacy inventory data are skipped rather than failing the mapping
        parsed_subnets: list[tuple[ipaddress._BaseNetwork, Subnet]] = []
        for s in site.subnets:
            try:
                parsed_subnets.append((ipaddress.ip_network(s.cidr, strict=False), s))
            except ValueError:
                continue

        parsed_vlans: list[tuple[ipaddress._BaseNetwork, VLAN]] = []
        for v in site.vlans:
            if v.cidr:
                try:
                    parsed_vlans.append((ipaddress.ip_network(v.cidr, strict=False), v))
                except ValueError:
                    continue

        site_gateway_ips = _site_gateway_ips(site)

        def infer_vlan_for_subnet_id(subnet_id: Optional[str]) -> Optional[str]:
            if not subnet_id:
                return None
            sub = subnet_by_id.get(subnet_id)
            if sub and sub.vlan_id:
                return sub.vlan_id
            for v in site.vlans:
                if v.subnet_id == subnet_id:
                    return v.vlan_id
                if sub and v.cidr and v.cidr == sub.cidr:
                    return v.vlan_id
            return None

        def infer_vlan_for_ip(ip_str: Optional[str]) -> Optional[str]:
            if not ip_str or not ip_str.strip():
                return None
            cleaned = ip_str.strip()
            for ip_rec in site.ip_addresses:
                if ip_rec.ip == cleaned:
                    v_id = infer_vlan_for_subnet_id(ip_rec.subnet_id)
                    if v_id:
                        return v_id
            try:
                ip_obj = ipaddress.ip_address(cleaned)
            except ValueError:
                return None
            for net, sub in parsed_subnets:
                if ip_obj in net:
                    return sub.vlan_id or infer_vlan_for_subnet_id(sub.subnet_id)
            for net, v in parsed_vlans:
                if ip_obj in net:
                    return v.vlan_id
            return None

        dev_by_id: dict[str, NetworkDevice] = {d.device_id: d for d in site.devices}
        dev_role_by_id: dict[str, str] = {
            d.device_id: self._classify_network_device_role(d, site_gateway_ips)
            for d in site.devices
        }
        infra_device_ids: set[str] = {
            d_id
            for d_id, role in dev_role_by_id.items()
            if role in ("router", "switch")
        }

        eq_by_id: dict[str, Equipment] = {e.equipment_id: e for e in site.equipment}

        # Map MAC -> infrastructure device_id (router or switch)
        infra_mac_to_device_id: dict[str, str] = {}
        # Map MAC -> downstream entity id (Equipment.equipment_id or non-infra NetworkDevice.device_id)
        host_mac_to_entity_id: dict[str, str] = {}
        # Map MAC -> set of IPs
        mac_to_ips: dict[str, list[str]] = {}
        # Map MAC -> inferred VLAN ID
        mac_to_vlan_id: dict[str, str] = {}
        # Map IP -> MAC
        ip_to_mac: dict[str, str] = {}

        def record_mac_ip(norm_mac: str, ip_str: str, subnet_id: Optional[str] = None) -> None:
            cleaned_ip = ip_str.strip()
            if not cleaned_ip:
                return
            mac_to_ips.setdefault(norm_mac, [])
            if cleaned_ip not in mac_to_ips[norm_mac]:
                mac_to_ips[norm_mac].append(cleaned_ip)
            ip_to_mac.setdefault(cleaned_ip, norm_mac)
            if norm_mac not in mac_to_vlan_id:
                v_id = infer_vlan_for_subnet_id(subnet_id) or infer_vlan_for_ip(
                    cleaned_ip
                )
                if v_id:
                    mac_to_vlan_id[norm_mac] = v_id

        for entry in arp_entries:
            norm_mac = _parse_mac_token(entry.arp_mac)
            if norm_mac:
                record_mac_ip(norm_mac, entry.ip, entry.subnet_id)

        for ip_rec in site.ip_addresses:
            raw_mac = ip_rec.arp_mac or (
                ip_rec.arp_entry.arp_mac if ip_rec.arp_entry is not None else None
            )
            norm_mac = _parse_mac_token(raw_mac)
            if norm_mac:
                record_mac_ip(norm_mac, ip_rec.ip, ip_rec.subnet_id)
                if ip_rec.assigned_object_id:
                    obj_id = ip_rec.assigned_object_id.strip()
                    if obj_id in infra_device_ids:
                        infra_mac_to_device_id[norm_mac] = obj_id
                    elif obj_id:
                        host_mac_to_entity_id[norm_mac] = obj_id

        # Check explicit device_mac_map (supports {device_id: mac} or {mac: device_id})
        if device_mac_map:
            for k, v in device_mac_map.items():
                norm_k = _parse_mac_token(k)
                norm_v = _parse_mac_token(v)
                if norm_v is not None and k.strip() in dev_by_id:
                    dev_id = k.strip()
                    if dev_id in infra_device_ids:
                        infra_mac_to_device_id[norm_v] = dev_id
                    else:
                        host_mac_to_entity_id[norm_v] = dev_id
                elif norm_k is not None and v.strip() in dev_by_id:
                    dev_id = v.strip()
                    if dev_id in infra_device_ids:
                        infra_mac_to_device_id[norm_k] = dev_id
                    else:
                        host_mac_to_entity_id[norm_k] = dev_id
                elif norm_v is not None and k.strip() in eq_by_id:
                    host_mac_to_entity_id[norm_v] = k.strip()
                elif norm_k is not None and v.strip() in eq_by_id:
                    host_mac_to_entity_id[norm_k] = v.strip()

        # Check NetworkDevice management_ip and router interface ports (e.g. ConsolidatedRouter)
        for dev in site.devices:
            is_infra = dev.device_id in infra_device_ids
            if dev.management_ip and dev.management_ip.strip() in ip_to_mac:
                m = ip_to_mac[dev.management_ip.strip()]
                if is_infra:
                    infra_mac_to_device_id[m] = dev.device_id
                else:
                    host_mac_to_entity_id.setdefault(m, dev.device_id)

            if dev_role_by_id.get(dev.device_id) == "router":
                for port in dev.ports:
                    if port.connected_mac and not port.connected_device_id:
                        norm_p_mac = _parse_mac_token(port.connected_mac)
                        if norm_p_mac:
                            infra_mac_to_device_id[norm_p_mac] = dev.device_id

        # Check Equipment assigned_ips -> MAC
        for eq in site.equipment:
            for ip_str in eq.assigned_ips:
                cleaned_ip = ip_str.strip()
                if cleaned_ip in ip_to_mac:
                    m = ip_to_mac[cleaned_ip]
                    host_mac_to_entity_id[m] = eq.equipment_id

        return {
            "dev_by_id": dev_by_id,
            "dev_role_by_id": dev_role_by_id,
            "infra_device_ids": infra_device_ids,
            "eq_by_id": eq_by_id,
            "infra_mac_to_device_id": infra_mac_to_device_id,
            "host_mac_to_entity_id": host_mac_to_entity_id,
            "mac_to_ips": mac_to_ips,
            "mac_to_vlan_id": mac_to_vlan_id,
        }

    def _is_infrastructure_mac(
        self,
        mac: str,
        *,
        current_device_id: str,
        ctx: Mapping[str, Any],
    ) -> tuple[bool, Optional[str], str]:
        """Return (is_infra, peer_device_id, reason_detail) for a learned MAC address."""
        infra_mac_to_device_id: Mapping[str, str] = ctx["infra_mac_to_device_id"]
        host_mac_to_entity_id: Mapping[str, str] = ctx["host_mac_to_entity_id"]
        dev_role_by_id: Mapping[str, str] = ctx["dev_role_by_id"]

        if mac in infra_mac_to_device_id:
            peer_id = infra_mac_to_device_id[mac]
            if peer_id == current_device_id:
                return False, None, ""
            role = dev_role_by_id.get(peer_id, "infrastructure")
            return True, peer_id, f"known {role} {peer_id} ({mac})"

        # If explicitly assigned to an edge Equipment or non-switch/non-router device, not an uplink
        if mac in host_mac_to_entity_id:
            return False, None, ""

        oui = _extract_oui_prefix(mac)
        if oui and oui in self.oui_vendors:
            vendor, role_hint = self.oui_vendors[oui]
            if role_hint in ("router", "switch"):
                return True, None, f"{vendor} {role_hint} OUI {oui} ({mac})"

        return False, None, ""

    def classify_site_ports(
        self,
        site: Site,
        fdb_entries: Sequence[FdbEntry],
        *,
        arp_entries: Sequence[ArpEntry] = (),
        device_mac_map: Optional[Mapping[str, str]] = None,
        voip_vlan_ids: Sequence[str] = (),
        include_empty_ports: bool = False,
    ) -> list[PortClassificationResult]:
        """Classify switch ports into `access`, `trunk`, `uplink`, or `empty` modes without mutating `site`."""
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")

        ctx = self._build_site_lookup_context(
            site,
            arp_entries=arp_entries,
            device_mac_map=device_mac_map,
        )
        voip_vlan_set: set[str] = {
            str(v).strip() for v in voip_vlan_ids if v is not None and str(v).strip()
        }

        # Group FdbEntry records by (device_id, port_name)
        grouped: dict[tuple[str, str], list[FdbEntry]] = {}
        ordered_port_keys: list[tuple[str, str]] = []

        dev_by_id: Mapping[str, NetworkDevice] = ctx["dev_by_id"]

        for entry in fdb_entries:
            resolved_port_name = entry.port_name
            if entry.device_id in dev_by_id:
                dev = dev_by_id[entry.device_id]
                for p in dev.ports:
                    if p.port_id == entry.port_name or p.name == entry.port_name:
                        resolved_port_name = p.name
                        break
            key = (entry.device_id, resolved_port_name)
            if key not in grouped:
                grouped[key] = []
                ordered_port_keys.append(key)
            grouped[key].append(entry)

        if include_empty_ports:
            for dev in site.devices:
                if ctx["dev_role_by_id"].get(dev.device_id) not in ("switch", "router"):
                    continue
                for p in dev.ports:
                    key = (dev.device_id, p.name)
                    if key not in grouped:
                        grouped[key] = []
                        ordered_port_keys.append(key)

        results: list[PortClassificationResult] = []
        host_mac_to_entity_id: Mapping[str, str] = ctx["host_mac_to_entity_id"]
        mac_to_ips: Mapping[str, list[str]] = ctx["mac_to_ips"]
        mac_to_vlan_id: Mapping[str, str] = ctx["mac_to_vlan_id"]

        for dev_id, port_name in ordered_port_keys:
            port_entries = grouped[(dev_id, port_name)]
            unique_macs: list[str] = []
            unique_vlans: list[str] = []
            mac_vlan_map: dict[str, list[str]] = {}

            for e in port_entries:
                if e.mac_address not in unique_macs:
                    unique_macs.append(e.mac_address)
                mac_vlan_map.setdefault(e.mac_address, [])
                effective_vlan = e.vlan_id or mac_to_vlan_id.get(e.mac_address)
                if effective_vlan:
                    if effective_vlan not in unique_vlans:
                        unique_vlans.append(effective_vlan)
                    if effective_vlan not in mac_vlan_map[e.mac_address]:
                        mac_vlan_map[e.mac_address].append(effective_vlan)

            mac_count = len(unique_macs)

            # 1. Empty port
            if mac_count == 0:
                results.append(
                    PortClassificationResult(
                        device_id=dev_id,
                        port_name=port_name,
                        port_mode="empty",
                        learned_mac_count=0,
                        vlan_ids=[],
                        bound_mac=None,
                        bound_device_id=None,
                        rationale="No MAC addresses learned on port",
                    )
                )
                continue

            # 2. Check for known router/switch infrastructure MACs -> Uplink
            infra_hits: list[tuple[str, Optional[str], str]] = []
            for m in unique_macs:
                is_infra, peer_id, reason_str = self._is_infrastructure_mac(
                    m, current_device_id=dev_id, ctx=ctx
                )
                if is_infra:
                    infra_hits.append((m, peer_id, reason_str))

            if infra_hits:
                peer_ids: list[str] = []
                for _, p_id, _ in infra_hits:
                    if p_id and p_id not in peer_ids:
                        peer_ids.append(p_id)

                bound_peer_id: Optional[str] = (
                    peer_ids[0] if len(peer_ids) == 1 else None
                )
                bound_peer_mac: Optional[str] = (
                    infra_hits[0][0]
                    if mac_count == 1 and len(infra_hits) == 1
                    else None
                )
                reasons_joined = "; ".join(r for _, _, r in infra_hits)
                results.append(
                    PortClassificationResult(
                        device_id=dev_id,
                        port_name=port_name,
                        port_mode="uplink",
                        learned_mac_count=mac_count,
                        vlan_ids=unique_vlans,
                        bound_mac=bound_peer_mac,
                        bound_device_id=bound_peer_id,
                        rationale=f"Uplink port detected via {reasons_joined}",
                    )
                )
                continue

            # 3. Check for Trunk (> max_access_macs or multi-VLAN non-VoIP)
            if mac_count > self.max_access_macs:
                results.append(
                    PortClassificationResult(
                        device_id=dev_id,
                        port_name=port_name,
                        port_mode="trunk",
                        learned_mac_count=mac_count,
                        vlan_ids=unique_vlans,
                        bound_mac=None,
                        bound_device_id=None,
                        rationale=(
                            f"Trunk port: learned {mac_count} MACs "
                            f"(exceeds max_access_macs={self.max_access_macs})"
                        ),
                    )
                )
                continue

            is_voip_dual_vlan = (
                mac_count == 2
                and len(unique_vlans) == 2
                and bool(voip_vlan_set)
                and len(set(unique_vlans) & voip_vlan_set) == 1
            )
            if len(unique_vlans) > 1 and not is_voip_dual_vlan:
                results.append(
                    PortClassificationResult(
                        device_id=dev_id,
                        port_name=port_name,
                        port_mode="trunk",
                        learned_mac_count=mac_count,
                        vlan_ids=unique_vlans,
                        bound_mac=None,
                        bound_device_id=None,
                        rationale=(
                            f"Trunk port: multiple VLANs ({', '.join(unique_vlans)}) learned on port"
                        ),
                    )
                )
                continue

            # 4. Access port (1 <= mac_count <= max_access_macs)
            # Prefer MAC matching a known Equipment or non-infra NetworkDevice
            # If voip_vlan_set is provided, also prefer the MAC on the data VLAN over the voice VLAN
            data_mac_candidates = [
                m
                for m in unique_macs
                if not (
                    voip_vlan_set
                    and mac_vlan_map.get(m)
                    and set(mac_vlan_map[m]).issubset(voip_vlan_set)
                )
            ] or unique_macs
            selected_mac: str = data_mac_candidates[0]
            selected_entity_id: Optional[str] = None

            for m in data_mac_candidates:
                if m in host_mac_to_entity_id:
                    selected_mac = m
                    selected_entity_id = host_mac_to_entity_id[m]
                    break

            if selected_entity_id is None:
                for m in unique_macs:
                    if m in host_mac_to_entity_id:
                        selected_mac = m
                        selected_entity_id = host_mac_to_entity_id[m]
                        break

            if selected_entity_id is None:
                for m in data_mac_candidates:
                    if m in mac_to_ips:
                        selected_mac = m
                        break

            # Order vlan_ids so the data VLAN (if VoIP+PC dual-VLAN) comes first
            ordered_vlans = list(unique_vlans)
            if voip_vlan_set and len(ordered_vlans) > 1:
                ordered_vlans.sort(key=lambda v: (1 if v in voip_vlan_set else 0))

            if mac_count == 1:
                rationale = f"Single-MAC access port bound to {selected_mac}"
            else:
                rationale = (
                    f"Dual-MAC/VoIP+PC access port ({mac_count} MACs <= max_access_macs={self.max_access_macs}) "
                    f"bound to {selected_mac}"
                )

            results.append(
                PortClassificationResult(
                    device_id=dev_id,
                    port_name=port_name,
                    port_mode="access",
                    learned_mac_count=mac_count,
                    vlan_ids=ordered_vlans,
                    bound_mac=selected_mac,
                    bound_device_id=selected_entity_id,
                    rationale=rationale,
                )
            )

        return results

    def map_site_ports(
        self,
        site: Site,
        fdb_entries: Sequence[FdbEntry],
        *,
        arp_entries: Sequence[ArpEntry] = (),
        device_mac_map: Optional[Mapping[str, str]] = None,
        voip_vlan_ids: Sequence[str] = (),
        include_empty_ports: bool = False,
        bind_uplink_devices: bool = True,
    ) -> list[PortClassificationResult]:
        """Classify switch ports and automatically update `Site` switch `Port` and `Equipment` bindings.

        Pass `voip_vlan_ids` for VoIP+PC ports whose phone and PC sit on different VLANs;
        without it those ports are classified as `trunk`.
        """
        results = self.classify_site_ports(
            site,
            fdb_entries,
            arp_entries=arp_entries,
            device_mac_map=device_mac_map,
            voip_vlan_ids=voip_vlan_ids,
            include_empty_ports=include_empty_ports,
        )

        dev_by_id: dict[str, NetworkDevice] = {d.device_id: d for d in site.devices}
        eq_by_id: dict[str, Equipment] = {e.equipment_id: e for e in site.equipment}
        infra_device_ids = self._infrastructure_device_ids(site)

        for res in results:
            dev = dev_by_id.get(res.device_id)
            if dev is None:
                continue

            mgr = DevicePortManager(dev)
            try:
                port = mgr.get_port(res.port_name)
            except KeyError:
                port = mgr.add_port(res.port_name)

            if res.port_mode != "empty":
                # Drop stale Equipment links to this port; access bindings re-add below
                _unlink_port_from_equipment(site, dev, port)

            if res.port_mode == "access":
                port.oper_status = "up"
                port.connected_mac = res.bound_mac
                port.connected_device_id = res.bound_device_id
                if res.vlan_ids:
                    port.vlan_id = res.vlan_ids[0]
                if res.bound_device_id and res.bound_device_id in eq_by_id:
                    eq = eq_by_id[res.bound_device_id]
                    if (
                        port.port_id not in eq.connected_ports
                        and port.name not in eq.connected_ports
                    ):
                        eq.connected_ports.append(port.port_id)

            elif res.port_mode == "trunk":
                port.oper_status = "up"
                # Never bind an end-host (Equipment or non-infra device) or single MAC to a trunk port
                if (
                    port.connected_device_id
                    and port.connected_device_id not in infra_device_ids
                ):
                    port.connected_device_id = None
                port.connected_mac = None

            elif res.port_mode == "uplink":
                port.oper_status = "up"
                # Never bind an end-host (Equipment or non-infra device) to an uplink port
                if (
                    port.connected_device_id
                    and port.connected_device_id not in infra_device_ids
                ):
                    port.connected_device_id = None
                if (
                    bind_uplink_devices
                    and res.bound_device_id
                    and res.bound_device_id in dev_by_id
                ):
                    port.connected_device_id = res.bound_device_id
                    port.connected_mac = res.bound_mac
                else:
                    port.connected_mac = None

        return results

    def classify_device_ports(
        self,
        device: NetworkDevice,
        fdb_entries: Sequence[FdbEntry],
        *,
        site: Optional[Site] = None,
        arp_entries: Sequence[ArpEntry] = (),
        device_mac_map: Optional[Mapping[str, str]] = None,
        voip_vlan_ids: Sequence[str] = (),
        include_empty_ports: bool = False,
    ) -> list[PortClassificationResult]:
        """Classify switch ports for a single `NetworkDevice`."""
        if not isinstance(device, NetworkDevice):
            raise ValueError("device must be a NetworkDevice instance")
        target_site = (
            site
            if site is not None
            else Site(
                site_id=device.site_id,
                name=device.site_id,
                devices=[device],
            )
        )
        filtered_entries = [
            e for e in fdb_entries if e.device_id == device.device_id
        ]
        all_results = self.classify_site_ports(
            target_site,
            filtered_entries,
            arp_entries=arp_entries,
            device_mac_map=device_mac_map,
            voip_vlan_ids=voip_vlan_ids,
            include_empty_ports=include_empty_ports,
        )
        return [r for r in all_results if r.device_id == device.device_id]

    apply_to_site = map_site_ports


__all__ = [
    "FdbEntry",
    "FdbTableParser",
    "PortClassificationResult",
    "SwitchFdbPortMapper",
    "VALID_PORT_MODES",
]
