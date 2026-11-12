"""Proxmox VE (:8006) & Docker/Portainer (:9000) hypervisor and container correlator."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
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
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals.base import (
    SignalCollector,
    resolve_evaluation_time,
)

PROXMOX_MAC_OUI: str = "bc:24:11"

_MAC_COLON_RE = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![0-9a-fA-F])"
)
_MAC_DOT_RE = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}(?![0-9a-fA-F])"
)
_HWADDR_KV_RE = re.compile(
    r"(?:hwaddr|macaddr|mac|virtio|e1000|vmxnet3|rtl8139)=((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})",
    re.IGNORECASE,
)
_IP_KV_RE = re.compile(
    r"(?:^|,|\s)(?:ip|ip6|inet|inet6)=([^,\s]+)",
    re.IGNORECASE,
)
_NON_IP_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "dhcp",
        "dhcp6",
        "manual",
        "auto",
        "none",
        "unknown",
        "n/a",
        "-",
    }
)


def _require_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    text = str(value).strip()
    return text if text else None


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("/", 1)[0])
    except ValueError:
        return False
    return True


def normalize_mac_address(mac: Optional[str]) -> Optional[str]:
    """Normalize a MAC address string (or Proxmox net config string) to lowercase aa:bb:cc:dd:ee:ff."""
    if not isinstance(mac, str):
        return None
    cleaned = mac.strip()
    if not cleaned:
        return None

    kv_match = _HWADDR_KV_RE.search(cleaned)
    if kv_match:
        cleaned = kv_match.group(1)
    else:
        colon_match = _MAC_COLON_RE.search(cleaned)
        if colon_match:
            cleaned = colon_match.group(0)
        else:
            dot_match = _MAC_DOT_RE.search(cleaned)
            if dot_match:
                cleaned = dot_match.group(0)
            elif "." in cleaned or _is_ip_literal(cleaned):
                # Bare-hex fallback must not read IPv4/IPv6 addresses as MACs.
                return None

    hex_only = "".join(ch for ch in cleaned.lower() if ch not in (":", "-", "."))
    if len(hex_only) == 12 and all(c in "0123456789abcdef" for c in hex_only):
        return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))
    return None


def extract_mac_addresses(value: Any) -> list[str]:
    """Extract and deduplicate normalized MAC addresses from strings, lists, or Proxmox config strings."""
    result: list[str] = []

    def _add(raw: Optional[str]) -> None:
        if not raw:
            return
        for match in _MAC_COLON_RE.findall(raw):
            norm = normalize_mac_address(match)
            if norm and norm not in result:
                result.append(norm)
        for match in _MAC_DOT_RE.findall(raw):
            norm = normalize_mac_address(match)
            if norm and norm not in result:
                result.append(norm)
        norm_direct = normalize_mac_address(raw)
        if norm_direct and norm_direct not in result:
            result.append(norm_direct)

    if value is None:
        return result
    if isinstance(value, str):
        _add(value)
        return result
    if isinstance(value, Mapping):
        for k, v in value.items():
            if isinstance(k, str) and (
                k.lower() in ("hwaddr", "mac", "mac_address", "macaddr", "hardware-address", "hardware_address")
                or k.lower().startswith("net")
            ):
                for m in extract_mac_addresses(v):
                    if m not in result:
                        result.append(m)
        return result
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            for m in extract_mac_addresses(item):
                if m not in result:
                    result.append(m)
        return result
    return result


def is_proxmox_mac(mac: Optional[str]) -> bool:
    """Return True when mac normalizes to a valid 12-hex-digit MAC with Proxmox OUI bc:24:11."""
    norm = normalize_mac_address(mac)
    if norm is None:
        return False
    return norm.startswith(PROXMOX_MAC_OUI + ":")


def normalize_ip_address(ip: Optional[str]) -> Optional[str]:
    """Normalize an IPv4/IPv6 address or CIDR string, ignoring loopback and non-IP placeholders."""
    if not isinstance(ip, str):
        return None
    cleaned = ip.strip()
    if not cleaned:
        return None

    kv_match = _IP_KV_RE.search(cleaned)
    if kv_match and "=" in cleaned:
        cleaned = kv_match.group(1).strip()

    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0].strip()

    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0].strip()

    if not cleaned or cleaned.lower() in _NON_IP_PLACEHOLDERS:
        return None

    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return None

    if addr.is_loopback or addr.is_unspecified or addr.is_link_local:
        return None

    return str(addr)


def extract_ip_addresses(value: Any) -> list[str]:
    """Extract and deduplicate normalized IPv4/IPv6 addresses from strings, lists, or config strings."""
    result: list[str] = []

    def _add(raw: Optional[str]) -> None:
        if not raw:
            return
        for match in _IP_KV_RE.findall(raw):
            norm = normalize_ip_address(match)
            if norm and norm not in result:
                result.append(norm)
        for token in re.split(r"[,;\s]+", raw.strip()):
            if not token or "=" in token:
                continue
            norm = normalize_ip_address(token)
            if norm and norm not in result:
                result.append(norm)

    if value is None:
        return result
    if isinstance(value, str):
        _add(value)
        return result
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                continue
            kl = k.lower()
            if kl in (
                "ip",
                "ip6",
                "inet",
                "inet6",
                "ip_address",
                "ip-address",
                "ip_addresses",
                "ip-addresses",
                "ipaddress",
                "ips",
                "primary_ip",
            ) or kl.startswith("net"):
                for ip_str in extract_ip_addresses(v):
                    if ip_str not in result:
                        result.append(ip_str)
        return result
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            for ip_str in extract_ip_addresses(item):
                if ip_str not in result:
                    result.append(ip_str)
        return result
    return result


def normalize_proxmox_guest_type(value: Any) -> str:
    """Normalize a Proxmox guest type to 'qemu' or 'lxc'."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Unsupported Proxmox guest_type: {value!r}")
    token = value.strip().lower()
    if token in ("qemu", "kvm", "vm"):
        return "qemu"
    if token in ("lxc", "ct", "container"):
        return "lxc"
    raise ValueError(f"Unsupported Proxmox guest_type: {value!r}")


def normalize_proxmox_guest_status(value: Any) -> str:
    """Normalize a Proxmox guest runtime status to 'running', 'stopped', or 'paused'."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Unsupported Proxmox guest status: {value!r}")
    token = value.strip().lower()
    if token in ("running", "online", "active", "up", "started", "on", "powered_on", "poweredon"):
        return "running"
    if token in (
        "stopped",
        "offline",
        "down",
        "halted",
        "shutoff",
        "shut_off",
        "exited",
        "off",
        "powered_off",
        "poweredoff",
    ):
        return "stopped"
    if token in ("paused", "suspended", "suspend", "prelaunch"):
        return "paused"
    raise ValueError(f"Unsupported Proxmox guest status: {value!r}")


def normalize_container_state(value: Any) -> str:
    """Normalize a Docker / Portainer container state to 'running', 'exited', or 'paused'."""
    if isinstance(value, Mapping):
        raw_status = value.get("Status") or value.get("status")
        if raw_status is not None:
            return normalize_container_state(raw_status)
        if value.get("Running") is True or value.get("running") is True:
            return "running"
        if value.get("Paused") is True or value.get("paused") is True:
            return "paused"
        return "exited"

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Unsupported container state: {value!r}")
    token = value.strip().lower()
    if token in ("running", "up", "healthy", "active", "restarting", "starting", "online"):
        return "running"
    if token in (
        "exited",
        "stopped",
        "dead",
        "created",
        "removing",
        "down",
        "inactive",
        "offline",
        "halted",
    ):
        return "exited"
    if token in ("paused", "suspended", "suspend"):
        return "paused"
    if token.startswith("up "):
        return "running"
    if token.startswith("exited ") or token.startswith("dead"):
        return "exited"
    raise ValueError(f"Unsupported container state: {value!r}")


def _parse_tags(value: Any) -> list[str]:
    if value is None:
        return []
    tags: list[str] = []
    if isinstance(value, str):
        for part in re.split(r"[;,\s]+", value.strip()):
            cleaned = part.strip()
            if cleaned and cleaned not in tags:
                tags.append(cleaned)
        return tags
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, Mapping)):
        for item in value:
            for sub in _parse_tags(item):
                if sub not in tags:
                    tags.append(sub)
        return tags
    cleaned = _clean_optional_str(value)
    if cleaned:
        tags.append(cleaned)
    return tags


def _coerce_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a positive integer")
    if isinstance(value, int):
        num = value
    elif isinstance(value, str):
        cleaned = value.strip()
        if "/" in cleaned:
            cleaned = cleaned.rsplit("/", 1)[-1].strip()
        if not cleaned.isdigit():
            raise ValueError(f"{field_name} must be a positive integer, got {value!r}")
        num = int(cleaned)
    else:
        raise ValueError(f"{field_name} must be a positive integer, got {value!r}")
    if num <= 0:
        raise ValueError(f"{field_name} must be a positive integer, got {value!r}")
    return num


def _coerce_optional_non_negative_int(value: Any, field_name: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a non-negative integer")
    if isinstance(value, (int, float)):
        num = int(value)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            num = int(float(cleaned))
        except ValueError as exc:
            raise ValueError(f"{field_name} must be a non-negative integer, got {value!r}") from exc
    else:
        raise ValueError(f"{field_name} must be a non-negative integer, got {value!r}")
    if num < 0:
        raise ValueError(f"{field_name} must be a non-negative integer, got {value!r}")
    return num


def _parse_interface_payload(payload: Any) -> tuple[list[str], list[str]]:
    """Extract (ip_addresses, mac_addresses) from Proxmox QEMU agent or LXC interface payloads."""
    ips: list[str] = []
    macs: list[str] = []

    def _add_ip(val: Any) -> None:
        for ip_str in extract_ip_addresses(val):
            if ip_str not in ips:
                ips.append(ip_str)

    def _add_mac(val: Any) -> None:
        for mac_str in extract_mac_addresses(val):
            if mac_str not in macs:
                macs.append(mac_str)

    if payload is None:
        return ips, macs

    if isinstance(payload, str):
        _add_ip(payload)
        _add_mac(payload)
        return ips, macs

    if isinstance(payload, Mapping):
        if "data" in payload:
            sub_ips, sub_macs = _parse_interface_payload(payload["data"])
            for i in sub_ips:
                if i not in ips:
                    ips.append(i)
            for m in sub_macs:
                if m not in macs:
                    macs.append(m)
        if "result" in payload:
            sub_ips, sub_macs = _parse_interface_payload(payload["result"])
            for i in sub_ips:
                if i not in ips:
                    ips.append(i)
            for m in sub_macs:
                if m not in macs:
                    macs.append(m)

        iface_name = _clean_optional_str(payload.get("name"))
        if iface_name and iface_name.lower() == "lo":
            return ips, macs

        for mac_key in ("hardware-address", "hardware_address", "hwaddr", "mac", "mac_address", "macaddr"):
            if mac_key in payload:
                _add_mac(payload[mac_key])

        for ip_key in ("ip-addresses", "ip_addresses", "ip-address", "ip_address", "inet", "inet6", "ip", "ip6", "ips"):
            if ip_key in payload:
                val = payload[ip_key]
                if isinstance(val, Iterable) and not isinstance(val, (str, bytes, bytearray, Mapping)):
                    for entry in val:
                        if isinstance(entry, Mapping):
                            _add_ip(entry.get("ip-address") or entry.get("ip_address") or entry.get("ip") or entry.get("inet"))
                        else:
                            _add_ip(entry)
                else:
                    _add_ip(val)

        for k, v in payload.items():
            if isinstance(k, str) and k.lower().startswith("net"):
                _add_ip(v)
                _add_mac(v)
            elif isinstance(v, (Mapping, list, tuple)) and k not in ("data", "result", "ip-addresses", "ip_addresses"):
                sub_ips, sub_macs = _parse_interface_payload(v)
                for i in sub_ips:
                    if i not in ips:
                        ips.append(i)
                for m in sub_macs:
                    if m not in macs:
                        macs.append(m)

        return ips, macs

    if isinstance(payload, Iterable) and not isinstance(payload, (bytes, bytearray)):
        for item in payload:
            sub_ips, sub_macs = _parse_interface_payload(item)
            for i in sub_ips:
                if i not in ips:
                    ips.append(i)
            for m in sub_macs:
                if m not in macs:
                    macs.append(m)

    return ips, macs


@dataclass
class ProxmoxGuestRecord:
    """Normalized Proxmox VE (:8006) QEMU VM or LXC container record."""

    vmid: int
    name: str
    guest_type: str
    node: str
    host_ip: Optional[str] = None
    status: str = "running"
    ip_addresses: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    uptime_sec: Optional[int] = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.vmid = _coerce_positive_int(self.vmid, "vmid")
        self.guest_type = normalize_proxmox_guest_type(self.guest_type)
        self.name = _require_non_empty_str(self.name, "name")
        self.node = _require_non_empty_str(self.node, "node")
        self.host_ip = normalize_ip_address(self.host_ip) if self.host_ip is not None else None
        self.status = normalize_proxmox_guest_status(self.status)
        self.ip_addresses = extract_ip_addresses(self.ip_addresses)
        self.mac_addresses = extract_mac_addresses(self.mac_addresses)
        self.uptime_sec = _coerce_optional_non_negative_int(self.uptime_sec, "uptime_sec")
        self.tags = _parse_tags(self.tags)

    @property
    def is_running(self) -> bool:
        """Return True if the Proxmox guest is currently running."""
        return self.status == "running"

    @property
    def has_proxmox_mac(self) -> bool:
        """Return True if any guest MAC address matches the Proxmox OUI bc:24:11."""
        return any(is_proxmox_mac(m) for m in self.mac_addresses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vmid": self.vmid,
            "name": self.name,
            "guest_type": self.guest_type,
            "node": self.node,
            "host_ip": self.host_ip,
            "status": self.status,
            "ip_addresses": list(self.ip_addresses),
            "mac_addresses": list(self.mac_addresses),
            "uptime_sec": self.uptime_sec,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        default_node: Optional[str] = None,
        default_host_ip: Optional[str] = None,
    ) -> ProxmoxGuestRecord:
        raw_vmid = data.get("vmid")
        if raw_vmid is None and isinstance(data.get("id"), str) and "/" in data["id"]:
            raw_vmid = data["id"].rsplit("/", 1)[-1]
        if raw_vmid is None:
            raw_vmid = data.get("id")
        vmid = _coerce_positive_int(raw_vmid, "vmid")

        raw_type = data.get("guest_type") or data.get("type")
        if raw_type is None and isinstance(data.get("id"), str) and "/" in data["id"]:
            raw_type = data["id"].split("/", 1)[0]
        guest_type = normalize_proxmox_guest_type(raw_type or "qemu")

        name = _clean_optional_str(
            data.get("name") or data.get("hostname") or data.get("vm_name")
        ) or f"{guest_type}-{vmid}"

        node = (
            _clean_optional_str(data.get("node") or data.get("proxmox_node"))
            or _clean_optional_str(default_node)
            or "pve"
        )

        host_ip = _clean_optional_str(
            data.get("host_ip") or data.get("node_ip") or default_host_ip
        )

        raw_status = data.get("status") or data.get("state") or data.get("power_state") or "running"
        status = normalize_proxmox_guest_status(raw_status)

        ips: list[str] = []
        for key in ("ip_addresses", "ips", "ip", "ip6", "primary_ip", "inet", "inet6"):
            if key in data:
                for ip_str in extract_ip_addresses(data[key]):
                    if ip_str not in ips:
                        ips.append(ip_str)

        macs: list[str] = []
        for key in ("mac_addresses", "macs", "mac", "mac_address", "hwaddr", "macaddr"):
            if key in data:
                for mac_str in extract_mac_addresses(data[key]):
                    if mac_str not in macs:
                        macs.append(mac_str)

        for k, v in data.items():
            if isinstance(k, str) and k.lower().startswith("net"):
                for ip_str in extract_ip_addresses(v):
                    if ip_str not in ips:
                        ips.append(ip_str)
                for mac_str in extract_mac_addresses(v):
                    if mac_str not in macs:
                        macs.append(mac_str)

        for iface_key in ("interfaces", "guest_interfaces", "nics", "network"):
            if iface_key in data:
                iface_ips, iface_macs = _parse_interface_payload(data[iface_key])
                for ip_str in iface_ips:
                    if ip_str not in ips:
                        ips.append(ip_str)
                for mac_str in iface_macs:
                    if mac_str not in macs:
                        macs.append(mac_str)

        raw_uptime = data.get("uptime_sec") if data.get("uptime_sec") is not None else data.get("uptime")

        return cls(
            vmid=vmid,
            name=name,
            guest_type=guest_type,
            node=node,
            host_ip=host_ip,
            status=status,
            ip_addresses=ips,
            mac_addresses=macs,
            uptime_sec=raw_uptime,
            tags=_parse_tags(data.get("tags")),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str, **kwargs: Any) -> ProxmoxGuestRecord:
        return cls.from_dict(json.loads(raw), **kwargs)


def _parse_published_ports(value: Any) -> list[int]:
    ports: set[int] = set()
    if value is None:
        return []
    if isinstance(value, int) and not isinstance(value, bool):
        if 1 <= value <= 65535:
            ports.add(value)
        return sorted(ports)
    if isinstance(value, str):
        for token in re.split(r"[,;\s]+", value.strip()):
            if not token:
                continue
            if "->" in token:
                port_part = token.split("->", 1)[0].rsplit(":", 1)[-1].strip()
            elif "/" in token:
                # Docker "80/tcp" without "->" is exposed but not published.
                continue
            else:
                port_part = token.rsplit(":", 1)[-1].strip()
            if port_part.isdigit():
                p = int(port_part)
                if 1 <= p <= 65535:
                    ports.add(p)
        return sorted(ports)
    if isinstance(value, Mapping):
        # Only host-side bindings count; Docker lists exposed-only ports with just PrivatePort.
        for pub_key in ("PublicPort", "public_port", "HostPort", "host_port"):
            if value.get(pub_key) is not None:
                return _parse_published_ports(value[pub_key])
        if any(k in value for k in ("PrivatePort", "private_port")):
            return []
        # Docker inspect style {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]} or {"80/tcp": None}
        for v in value.values():
            if isinstance(v, (Mapping, list, tuple)):
                for p in _parse_published_ports(v):
                    ports.add(p)
        return sorted(ports)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            for p in _parse_published_ports(item):
                ports.add(p)
        return sorted(ports)
    return sorted(ports)


@dataclass
class ContainerEndpointRecord:
    """Normalized Docker / Portainer (:9000) container endpoint record."""

    container_id: str
    name: str
    image: str
    host_ip: Optional[str] = None
    state: str = "running"
    ip_addresses: list[str] = field(default_factory=list)
    published_ports: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.container_id = _require_non_empty_str(self.container_id, "container_id")
        cleaned_name = _require_non_empty_str(self.name, "name").lstrip("/").strip()
        if not cleaned_name:
            raise ValueError("name must be a non-empty string")
        self.name = cleaned_name
        self.image = _require_non_empty_str(self.image, "image")
        self.host_ip = normalize_ip_address(self.host_ip) if self.host_ip is not None else None
        self.state = normalize_container_state(self.state)
        self.ip_addresses = extract_ip_addresses(self.ip_addresses)
        self.published_ports = _parse_published_ports(self.published_ports)

    @property
    def is_running(self) -> bool:
        """Return True if the container is currently running."""
        return self.state == "running"

    def to_dict(self) -> dict[str, Any]:
        return {
            "container_id": self.container_id,
            "name": self.name,
            "image": self.image,
            "host_ip": self.host_ip,
            "state": self.state,
            "ip_addresses": list(self.ip_addresses),
            "published_ports": list(self.published_ports),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        default_host_ip: Optional[str] = None,
    ) -> ContainerEndpointRecord:
        container_id = _clean_optional_str(
            data.get("container_id") or data.get("Id") or data.get("id") or data.get("ID")
        )
        if not container_id:
            raise ValueError("container_id must be a non-empty string")

        raw_name = data.get("name") or data.get("Name")
        if not raw_name:
            names_list = data.get("Names") or data.get("names")
            if isinstance(names_list, Sequence) and not isinstance(names_list, (str, bytes)) and names_list:
                raw_name = names_list[0]
        name = _clean_optional_str(raw_name) or container_id[:12]
        name = name.lstrip("/").strip() or container_id[:12]

        image = _clean_optional_str(data.get("image") or data.get("Image")) or "unknown"

        host_ip = _clean_optional_str(
            data.get("host_ip") or data.get("HostIP") or data.get("endpoint_ip") or default_host_ip
        )

        raw_state = (
            data.get("state")
            if data.get("state") is not None
            else (
                data.get("State")
                if data.get("State") is not None
                else (data.get("status") or data.get("Status") or "running")
            )
        )
        state = normalize_container_state(raw_state)

        ips: list[str] = []
        for key in ("ip_addresses", "ips", "ip", "ip_address", "IPAddress"):
            if key in data:
                for ip_str in extract_ip_addresses(data[key]):
                    if ip_str not in ips:
                        ips.append(ip_str)

        net_settings = data.get("NetworkSettings") or data.get("network_settings")
        if isinstance(net_settings, Mapping):
            for ip_str in extract_ip_addresses(net_settings.get("IPAddress") or net_settings.get("ip_address")):
                if ip_str not in ips:
                    ips.append(ip_str)
            networks = net_settings.get("Networks") or net_settings.get("networks")
            if isinstance(networks, Mapping):
                for net_obj in networks.values():
                    if isinstance(net_obj, Mapping):
                        for ip_str in extract_ip_addresses(
                            net_obj.get("IPAddress")
                            or net_obj.get("ip_address")
                            or net_obj.get("GlobalIPv6Address")
                        ):
                            if ip_str not in ips:
                                ips.append(ip_str)

        raw_ports = (
            data.get("published_ports")
            if data.get("published_ports") is not None
            else (data.get("Ports") if data.get("Ports") is not None else data.get("ports"))
        )
        ports_list = _parse_published_ports(raw_ports)

        if host_ip is None and isinstance(raw_ports, Sequence) and not isinstance(raw_ports, (str, bytes)):
            for p_entry in raw_ports:
                if isinstance(p_entry, Mapping):
                    candidate_hip = normalize_ip_address(_clean_optional_str(p_entry.get("IP") or p_entry.get("ip")))
                    if candidate_hip:
                        host_ip = candidate_hip
                        break

        return cls(
            container_id=container_id,
            name=name,
            image=image,
            host_ip=host_ip,
            state=state,
            ip_addresses=ips,
            published_ports=ports_list,
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str, **kwargs: Any) -> ContainerEndpointRecord:
        return cls.from_dict(json.loads(raw), **kwargs)


def _names_match(name_a: Optional[str], name_b: Optional[str]) -> bool:
    clean_a = _clean_optional_str(name_a)
    clean_b = _clean_optional_str(name_b)
    if not clean_a or not clean_b:
        return False
    low_a = clean_a.lstrip("/").lower()
    low_b = clean_b.lstrip("/").lower()
    if low_a == low_b:
        return True
    short_a = low_a.split(".", 1)[0]
    short_b = low_b.split(".", 1)[0]
    return bool(short_a and short_a == short_b)


@dataclass
class ProxmoxClusterSnapshot:
    """Point-in-time snapshot of Proxmox VE (:8006) guests and Docker/Portainer (:9000) containers."""

    guests: list[ProxmoxGuestRecord] = field(default_factory=list)
    containers: list[ContainerEndpointRecord] = field(default_factory=list)
    node_ips: dict[str, str] = field(default_factory=dict)
    unreachable_hosts: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.guests = [
            g if isinstance(g, ProxmoxGuestRecord) else ProxmoxGuestRecord.from_dict(g)
            for g in (self.guests or [])
        ]
        self.containers = [
            c if isinstance(c, ContainerEndpointRecord) else ContainerEndpointRecord.from_dict(c)
            for c in (self.containers or [])
        ]
        normalized_node_ips: dict[str, str] = {}
        for k, v in (self.node_ips or {}).items():
            key = _clean_optional_str(k)
            val = normalize_ip_address(_clean_optional_str(v))
            if key and val:
                normalized_node_ips[key.lower()] = val
        self.node_ips = normalized_node_ips

        for g in self.guests:
            if g.host_ip is None and g.node.lower() in self.node_ips:
                g.host_ip = self.node_ips[g.node.lower()]
            elif g.host_ip is not None and g.node.lower() not in self.node_ips:
                self.node_ips[g.node.lower()] = g.host_ip

        self.unreachable_hosts = {
            cleaned
            for h in (self.unreachable_hosts or set())
            if (cleaned := _clean_optional_str(h)) is not None
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "guests": [g.to_dict() for g in self.guests],
            "containers": [c.to_dict() for c in self.containers],
            "node_ips": dict(self.node_ips),
            "unreachable_hosts": sorted(self.unreachable_hosts),
        }

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any] | Sequence[Any],
        *,
        node_ips: Optional[Mapping[str, str]] = None,
        default_host_ip: Optional[str] = None,
    ) -> ProxmoxClusterSnapshot:
        resolved_node_ips: dict[str, str] = {}
        if node_ips:
            for k, v in node_ips.items():
                clean_k = _clean_optional_str(k)
                clean_v = normalize_ip_address(_clean_optional_str(v))
                if clean_k and clean_v:
                    resolved_node_ips[clean_k.lower()] = clean_v

        guests: list[ProxmoxGuestRecord] = []
        containers: list[ContainerEndpointRecord] = []
        unreachable: set[str] = set()

        if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
            for item in data:
                if isinstance(item, ProxmoxGuestRecord):
                    guests.append(item)
                elif isinstance(item, ContainerEndpointRecord):
                    containers.append(item)
                elif isinstance(item, Mapping):
                    cls._ingest_entry(
                        item,
                        guests=guests,
                        containers=containers,
                        node_ips=resolved_node_ips,
                        default_host_ip=default_host_ip,
                    )
            return cls(
                guests=guests,
                containers=containers,
                node_ips=resolved_node_ips,
                unreachable_hosts=unreachable,
            )

        if not isinstance(data, Mapping):
            raise ValueError("ProxmoxClusterSnapshot payload must be a mapping or sequence")

        raw_node_ips = data.get("node_ips") or data.get("nodes_by_ip")
        if isinstance(raw_node_ips, Mapping):
            for k, v in raw_node_ips.items():
                clean_k = _clean_optional_str(k)
                clean_v = normalize_ip_address(_clean_optional_str(v))
                if clean_k and clean_v:
                    resolved_node_ips[clean_k.lower()] = clean_v

        raw_nodes = data.get("nodes")
        if isinstance(raw_nodes, Mapping):
            for k, v in raw_nodes.items():
                clean_k = _clean_optional_str(k)
                if isinstance(v, Mapping):
                    clean_v = normalize_ip_address(_clean_optional_str(v.get("ip") or v.get("host_ip")))
                else:
                    clean_v = normalize_ip_address(_clean_optional_str(v))
                if clean_k and clean_v:
                    resolved_node_ips[clean_k.lower()] = clean_v
        elif isinstance(raw_nodes, Sequence) and not isinstance(raw_nodes, (str, bytes)):
            for n_entry in raw_nodes:
                if isinstance(n_entry, Mapping):
                    n_name = _clean_optional_str(n_entry.get("node") or n_entry.get("name"))
                    n_ip = normalize_ip_address(_clean_optional_str(n_entry.get("ip") or n_entry.get("host_ip")))
                    if n_name and n_ip:
                        resolved_node_ips[n_name.lower()] = n_ip
                    if _clean_optional_str(n_entry.get("status") or "") in ("offline", "unreachable", "down"):
                        if n_name:
                            unreachable.add(n_name)
                        if n_ip:
                            unreachable.add(n_ip)

        raw_unreach = data.get("unreachable_hosts") or data.get("unreachable_nodes")
        if isinstance(raw_unreach, Iterable) and not isinstance(raw_unreach, (str, bytes, Mapping)):
            for u in raw_unreach:
                cu = _clean_optional_str(u)
                if cu:
                    unreachable.add(cu)

        top_host_ip = _clean_optional_str(data.get("host_ip") or default_host_ip)

        raw_resource_lists: list[Sequence[Any]] = []
        for key in ("data", "resources", "guests", "vms"):
            val = data.get(key)
            if isinstance(val, Sequence) and not isinstance(val, (str, bytes, bytearray)):
                raw_resource_lists.append(val)
            elif isinstance(val, Mapping) and isinstance(val.get("data"), Sequence):
                raw_resource_lists.append(val["data"])

        for res_list in raw_resource_lists:
            for item in res_list:
                if isinstance(item, Mapping):
                    r_type = _clean_optional_str(item.get("type"))
                    if r_type and r_type.lower() == "node":
                        n_name = _clean_optional_str(item.get("node") or item.get("name"))
                        n_ip = normalize_ip_address(_clean_optional_str(item.get("ip") or item.get("host_ip")))
                        if n_name and n_ip:
                            resolved_node_ips[n_name.lower()] = n_ip
                        if _clean_optional_str(item.get("status") or "") in ("offline", "unreachable", "down"):
                            if n_name:
                                unreachable.add(n_name)
                            if n_ip:
                                unreachable.add(n_ip)

        for res_list in raw_resource_lists:
            for item in res_list:
                if isinstance(item, ProxmoxGuestRecord):
                    guests.append(item)
                elif isinstance(item, ContainerEndpointRecord):
                    containers.append(item)
                elif isinstance(item, Mapping):
                    cls._ingest_entry(
                        item,
                        guests=guests,
                        containers=containers,
                        node_ips=resolved_node_ips,
                        default_host_ip=top_host_ip,
                    )

        iface_map = data.get("guest_interfaces") or data.get("interfaces") or data.get("vm_interfaces")
        if isinstance(iface_map, Mapping):
            guests_by_vmid: dict[int, list[ProxmoxGuestRecord]] = {}
            for g in guests:
                guests_by_vmid.setdefault(g.vmid, []).append(g)

            for raw_vmid_key, iface_payload in iface_map.items():
                try:
                    vmid_int = _coerce_positive_int(raw_vmid_key, "vmid")
                except ValueError:
                    continue
                iface_ips, iface_macs = _parse_interface_payload(iface_payload)
                for target_g in guests_by_vmid.get(vmid_int, []):
                    for ip_str in iface_ips:
                        if ip_str not in target_g.ip_addresses:
                            target_g.ip_addresses.append(ip_str)
                    for mac_str in iface_macs:
                        if mac_str not in target_g.mac_addresses:
                            target_g.mac_addresses.append(mac_str)

        for c_key in ("containers", "docker_containers", "portainer_containers"):
            c_val = data.get(c_key)
            if isinstance(c_val, Sequence) and not isinstance(c_val, (str, bytes, bytearray)):
                for item in c_val:
                    if isinstance(item, ContainerEndpointRecord):
                        containers.append(item)
                    elif isinstance(item, Mapping):
                        containers.append(
                            ContainerEndpointRecord.from_dict(item, default_host_ip=top_host_ip)
                        )

        endpoints = data.get("endpoints") or data.get("portainer_endpoints")
        if isinstance(endpoints, Sequence) and not isinstance(endpoints, (str, bytes, bytearray)):
            for ep in endpoints:
                if not isinstance(ep, Mapping):
                    continue
                ep_ip = _clean_optional_str(ep.get("host_ip") or ep.get("url") or ep.get("PublicURL") or top_host_ip)
                if ep_ip and "://" in ep_ip:
                    ep_ip = ep_ip.split("://", 1)[-1].split(":", 1)[0].split("/", 1)[0]
                if ep.get("Status") == 2 or str(ep.get("status", "")).lower() in ("down", "unreachable", "offline"):
                    if ep_ip:
                        unreachable.add(ep_ip)
                ep_containers = ep.get("containers") or ep.get("Containers")
                if isinstance(ep_containers, Sequence) and not isinstance(ep_containers, (str, bytes, bytearray)):
                    for c_item in ep_containers:
                        if isinstance(c_item, ContainerEndpointRecord):
                            containers.append(c_item)
                        elif isinstance(c_item, Mapping):
                            containers.append(
                                ContainerEndpointRecord.from_dict(c_item, default_host_ip=ep_ip)
                            )
                for snap in ep.get("Snapshots") or ep.get("snapshots") or []:
                    if isinstance(snap, Mapping):
                        raw_snap = snap.get("DockerSnapshotRaw") or snap.get("docker_snapshot_raw") or snap
                        snap_containers = raw_snap.get("Containers") if isinstance(raw_snap, Mapping) else None
                        if isinstance(snap_containers, Sequence) and not isinstance(snap_containers, (str, bytes, bytearray)):
                            for c_item in snap_containers:
                                if isinstance(c_item, Mapping):
                                    containers.append(
                                        ContainerEndpointRecord.from_dict(c_item, default_host_ip=ep_ip)
                                    )

        return cls(
            guests=guests,
            containers=containers,
            node_ips=resolved_node_ips,
            unreachable_hosts=unreachable,
        )

    @staticmethod
    def _ingest_entry(
        item: Mapping[str, Any],
        *,
        guests: list[ProxmoxGuestRecord],
        containers: list[ContainerEndpointRecord],
        node_ips: dict[str, str],
        default_host_ip: Optional[str],
    ) -> None:
        tpl = item.get("template")
        if tpl is True or tpl == 1 or str(tpl).strip().lower() in ("1", "true", "yes"):
            return

        r_type = _clean_optional_str(item.get("type") or item.get("guest_type"))
        if r_type and r_type.lower() in ("node", "storage", "pool", "sdn"):
            return

        if (
            r_type is None
            and "vmid" not in item
            and ("container_id" in item or "Id" in item or "Names" in item or "Image" in item)
        ):
            containers.append(
                ContainerEndpointRecord.from_dict(item, default_host_ip=default_host_ip)
            )
            return

        if r_type is not None:
            try:
                normalize_proxmox_guest_type(r_type)
            except ValueError:
                return

        if "vmid" not in item and not (isinstance(item.get("id"), str) and "/" in item["id"]):
            return

        node_name = _clean_optional_str(item.get("node"))
        resolved_hip = _clean_optional_str(item.get("host_ip") or item.get("node_ip"))
        if not resolved_hip and node_name and node_name.lower() in node_ips:
            resolved_hip = node_ips[node_name.lower()]
        if not resolved_hip:
            resolved_hip = default_host_ip

        guests.append(
            ProxmoxGuestRecord.from_dict(
                item,
                default_node=node_name,
                default_host_ip=resolved_hip,
            )
        )

    @classmethod
    def from_json(cls, raw_json: str, **kwargs: Any) -> ProxmoxClusterSnapshot:
        return cls.from_dict(json.loads(raw_json), **kwargs)

    @classmethod
    def from_json_file(cls, path: str | Path, **kwargs: Any) -> ProxmoxClusterSnapshot:
        file_path = Path(path)
        return cls.from_json(file_path.read_text(encoding="utf-8"), **kwargs)

    @classmethod
    def from_fetchers(
        cls,
        *,
        proxmox_fetcher: Optional[Callable[[], Any]] = None,
        container_fetcher: Optional[Callable[[], Any]] = None,
        node_ips: Optional[Mapping[str, str]] = None,
        default_host_ip: Optional[str] = None,
    ) -> ProxmoxClusterSnapshot:
        """Build a ProxmoxClusterSnapshot from read-only fetcher callables."""
        guests: list[ProxmoxGuestRecord] = []
        containers: list[ContainerEndpointRecord] = []
        resolved_node_ips: dict[str, str] = {}
        if node_ips:
            for k, v in node_ips.items():
                clean_k = _clean_optional_str(k)
                clean_v = normalize_ip_address(_clean_optional_str(v))
                if clean_k and clean_v:
                    resolved_node_ips[clean_k.lower()] = clean_v
        unreachable: set[str] = set()

        if proxmox_fetcher is not None:
            try:
                pve_raw = proxmox_fetcher()
                if isinstance(pve_raw, str):
                    pve_snap = cls.from_json(
                        pve_raw,
                        node_ips=resolved_node_ips,
                        default_host_ip=default_host_ip,
                    )
                elif isinstance(pve_raw, ProxmoxClusterSnapshot):
                    pve_snap = pve_raw
                else:
                    pve_snap = cls.from_dict(
                        pve_raw,
                        node_ips=resolved_node_ips,
                        default_host_ip=default_host_ip,
                    )
                guests.extend(pve_snap.guests)
                containers.extend(pve_snap.containers)
                resolved_node_ips.update(pve_snap.node_ips)
                unreachable.update(pve_snap.unreachable_hosts)
            except Exception:
                unreachable.add(default_host_ip or "proxmox")

        if container_fetcher is not None:
            try:
                ct_raw = container_fetcher()
                if isinstance(ct_raw, str):
                    ct_parsed = json.loads(ct_raw)
                else:
                    ct_parsed = ct_raw

                if isinstance(ct_parsed, ProxmoxClusterSnapshot):
                    containers.extend(ct_parsed.containers)
                    unreachable.update(ct_parsed.unreachable_hosts)
                elif isinstance(ct_parsed, Sequence) and not isinstance(ct_parsed, (str, bytes, bytearray)):
                    for item in ct_parsed:
                        if isinstance(item, ContainerEndpointRecord):
                            containers.append(item)
                        elif isinstance(item, Mapping):
                            containers.append(
                                ContainerEndpointRecord.from_dict(item, default_host_ip=default_host_ip)
                            )
                elif isinstance(ct_parsed, Mapping):
                    ct_snap = cls.from_dict(
                        ct_parsed,
                        node_ips=resolved_node_ips,
                        default_host_ip=default_host_ip,
                    )
                    containers.extend(ct_snap.containers)
                    guests.extend(ct_snap.guests)
                    unreachable.update(ct_snap.unreachable_hosts)
            except Exception:
                unreachable.add(default_host_ip or "portainer")

        return cls(
            guests=guests,
            containers=containers,
            node_ips=resolved_node_ips,
            unreachable_hosts=unreachable,
        )

    def find_guests(
        self,
        *,
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        name: Optional[str] = None,
        vmid: Optional[int | str] = None,
        host_ip: Optional[str] = None,
    ) -> list[ProxmoxGuestRecord]:
        """Look up Proxmox guests matching all provided filter criteria."""
        norm_ip = normalize_ip_address(ip) if ip is not None else None
        norm_mac = normalize_mac_address(mac) if mac is not None else None
        clean_name = _clean_optional_str(name)
        norm_host_ip = normalize_ip_address(host_ip) if host_ip is not None else None
        target_vmid: Optional[int] = None
        if vmid is not None:
            try:
                target_vmid = _coerce_positive_int(vmid, "vmid")
            except ValueError:
                return []

        matches: list[ProxmoxGuestRecord] = []
        for g in self.guests:
            if target_vmid is not None and g.vmid != target_vmid:
                continue
            if norm_ip is not None and norm_ip not in g.ip_addresses:
                continue
            if norm_mac is not None and norm_mac not in g.mac_addresses:
                continue
            if clean_name is not None and not _names_match(g.name, clean_name):
                continue
            if norm_host_ip is not None and g.host_ip != norm_host_ip:
                continue
            matches.append(g)
        return matches

    def find_containers(
        self,
        *,
        ip: Optional[str] = None,
        name: Optional[str] = None,
        container_id: Optional[str] = None,
        host_ip: Optional[str] = None,
        port: Optional[int] = None,
    ) -> list[ContainerEndpointRecord]:
        """Look up Docker/Portainer containers matching all provided filter criteria."""
        norm_ip = normalize_ip_address(ip) if ip is not None else None
        clean_name = _clean_optional_str(name)
        clean_cid = _clean_optional_str(container_id)
        norm_host_ip = normalize_ip_address(host_ip) if host_ip is not None else None

        matches: list[ContainerEndpointRecord] = []
        for c in self.containers:
            if clean_cid is not None:
                cid_low = clean_cid.lower()
                c_low = c.container_id.lower()
                if not (c_low == cid_low or c_low.startswith(cid_low) or cid_low.startswith(c_low)):
                    continue
            if norm_ip is not None and norm_ip not in c.ip_addresses:
                continue
            if clean_name is not None and not _names_match(c.name, clean_name):
                continue
            if norm_host_ip is not None and c.host_ip != norm_host_ip:
                continue
            if port is not None and port not in c.published_ports:
                continue
            matches.append(c)
        return matches


def _extract_vmid_hint(text: Optional[str]) -> Optional[int]:
    cleaned = _clean_optional_str(text)
    if not cleaned:
        return None
    # Only bare digits or explicit Proxmox prefixes count; generic "vm-<n>" names are VMware-style too.
    # Proxmox VMIDs start at 100, which keeps node names such as "pve-01" from reading as VMIDs.
    if cleaned.isdigit():
        val = int(cleaned)
        return val if val >= 100 else None
    m = re.search(r"(?:^|[-_:/])(?:qemu|lxc|ct|pve)[-_:/]?(\d{3,9})$", cleaned, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def _resolve_parent_hypervisor_id(
    *,
    site: Site,
    host_ip: Optional[str],
    node_name: Optional[str],
    exclude_equipment_id: Optional[str] = None,
) -> Optional[str]:
    norm_hip = normalize_ip_address(host_ip) if host_ip else None
    clean_node = _clean_optional_str(node_name)

    if norm_hip:
        for eq in site.equipment:
            if eq.equipment_id == exclude_equipment_id:
                continue
            if eq.category is EquipmentCategory.VM and eq.hypervisor_id:
                continue
            if norm_hip in [normalize_ip_address(ip) for ip in eq.assigned_ips]:
                return eq.equipment_id
        for dev in site.devices:
            if normalize_ip_address(dev.management_ip) == norm_hip:
                return dev.device_id

    if clean_node:
        for eq in site.equipment:
            if eq.equipment_id == exclude_equipment_id:
                continue
            if eq.equipment_id.lower() == clean_node.lower() or _names_match(eq.name, clean_node):
                return eq.equipment_id
        for dev in site.devices:
            if dev.device_id.lower() == clean_node.lower() or _names_match(dev.hostname, clean_node):
                return dev.device_id

    return clean_node or norm_hip


def _collect_host_ips_in_site(site: Site, snapshot: ProxmoxClusterSnapshot) -> set[str]:
    host_ips: set[str] = set()
    for ip in snapshot.node_ips.values():
        norm = normalize_ip_address(ip)
        if norm:
            host_ips.add(norm)
    for g in snapshot.guests:
        if g.host_ip:
            host_ips.add(g.host_ip)
    for c in snapshot.containers:
        if c.host_ip:
            host_ips.add(c.host_ip)
    return host_ips


class ProxmoxContainerCollector(SignalCollector):
    """Evaluate VM_POWER_STATE validation signals for Proxmox VE guests and Docker/Portainer containers."""

    signal_type = SignalType.VM_POWER_STATE

    def __init__(
        self,
        snapshot: Optional[ProxmoxClusterSnapshot] = None,
        *,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "proxmox_container.vm_power_state",
    ) -> None:
        self.snapshot = snapshot
        self.evaluation_time = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = _require_non_empty_str(source, "source")

    def evaluate(
        self,
        target: Any,
        *,
        snapshot: Optional[ProxmoxClusterSnapshot] = None,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        arp_entries: Optional[Sequence[ArpEntry]] = None,
        ports: Optional[Sequence[Port]] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (self.evaluation_time or resolve_evaluation_time(None))
        )
        active_snapshot = snapshot if snapshot is not None else self.snapshot

        if isinstance(target, ProxmoxGuestRecord):
            return self._evaluate_guest_record(target, eval_dt)

        if isinstance(target, ContainerEndpointRecord):
            return self._evaluate_container_record(target, eval_dt)

        if isinstance(target, (NetworkDevice, Port)):
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=f"Target {type(target).__name__} is physical network infrastructure; Proxmox/container check not applicable",
                source=self.source,
                metadata={"target_type": type(target).__name__},
            )

        if isinstance(target, IPAddress):
            return self._evaluate_ip_target(
                target,
                snapshot=active_snapshot,
                site=site,
                arp_entries=arp_entries,
                ports=ports,
                eval_dt=eval_dt,
            )

        if isinstance(target, Equipment):
            return self._evaluate_equipment_target(
                target,
                snapshot=active_snapshot,
                site=site,
                ip_addresses=ip_addresses,
                arp_entries=arp_entries,
                ports=ports,
                eval_dt=eval_dt,
            )

        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=SignalStatus.NOT_APPLICABLE,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=f"Unsupported target type for Proxmox/container correlation: {type(target).__name__}",
            source=self.source,
            metadata={"target_type": type(target).__name__},
        )

    def _evaluate_guest_record(
        self, guest: ProxmoxGuestRecord, eval_dt: datetime
    ) -> ValidationSignal:
        status = SignalStatus.ACTIVE if guest.is_running else SignalStatus.INACTIVE
        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=status,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=(
                f"Proxmox {guest.guest_type.upper()} {guest.name} (vmid={guest.vmid} on {guest.node}) "
                f"is {guest.status}"
            ),
            source=self.source,
            metadata={
                "correlation_key": "direct_guest",
                "vmid": guest.vmid,
                "guest_type": guest.guest_type,
                "node": guest.node,
                "host_ip": guest.host_ip,
                "status": guest.status,
                "proxmox_mac_detected": guest.has_proxmox_mac,
                "matched_guests": [guest.to_dict()],
                "matched_containers": [],
            },
        )

    def _evaluate_container_record(
        self, container: ContainerEndpointRecord, eval_dt: datetime
    ) -> ValidationSignal:
        status = SignalStatus.ACTIVE if container.is_running else SignalStatus.INACTIVE
        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=status,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=(
                f"Container {container.name} ({container.container_id[:12]}, image={container.image}) "
                f"is {container.state}"
            ),
            source=self.source,
            metadata={
                "correlation_key": "direct_container",
                "container_id": container.container_id,
                "name": container.name,
                "image": container.image,
                "host_ip": container.host_ip,
                "state": container.state,
                "proxmox_mac_detected": False,
                "matched_guests": [],
                "matched_containers": [container.to_dict()],
            },
        )

    def _evaluate_ip_target(
        self,
        ip_rec: IPAddress,
        *,
        snapshot: Optional[ProxmoxClusterSnapshot],
        site: Optional[Site],
        arp_entries: Optional[Sequence[ArpEntry]],
        ports: Optional[Sequence[Port]],
        eval_dt: datetime,
    ) -> ValidationSignal:
        norm_ip = normalize_ip_address(ip_rec.ip)
        candidate_macs: list[str] = []
        for raw_m in (
            ip_rec.arp_mac,
            ip_rec.arp_entry.arp_mac if isinstance(ip_rec.arp_entry, ArpEntry) else None,
        ):
            nm = normalize_mac_address(raw_m)
            if nm and nm not in candidate_macs:
                candidate_macs.append(nm)

        if arp_entries and norm_ip:
            for entry in arp_entries:
                if normalize_ip_address(entry.ip) == norm_ip:
                    nm = normalize_mac_address(entry.arp_mac)
                    if nm and nm not in candidate_macs:
                        candidate_macs.append(nm)

        pve_mac_detected = any(is_proxmox_mac(m) for m in candidate_macs)

        if snapshot is None:
            if pve_mac_detected:
                return ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details=f"IP {ip_rec.ip} has Proxmox MAC OUI ({PROXMOX_MAC_OUI}), but no Proxmox snapshot is available",
                    source=self.source,
                    metadata={
                        "ip": ip_rec.ip,
                        "mac_addresses": candidate_macs,
                        "proxmox_mac_detected": True,
                    },
                )
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=f"No Proxmox/container snapshot configured for IP {ip_rec.ip}",
                source=self.source,
                metadata={"ip": ip_rec.ip, "proxmox_mac_detected": False},
            )

        matched_guests: list[ProxmoxGuestRecord] = []
        matched_containers: list[ContainerEndpointRecord] = []
        correlation_key: Optional[str] = None

        for mac in candidate_macs:
            for g in snapshot.find_guests(mac=mac):
                if g not in matched_guests:
                    matched_guests.append(g)
                    correlation_key = correlation_key or "mac"

        if norm_ip:
            for g in snapshot.find_guests(ip=norm_ip):
                if g not in matched_guests:
                    matched_guests.append(g)
                    correlation_key = correlation_key or "ip"
            for c in snapshot.find_containers(ip=norm_ip):
                if c not in matched_containers:
                    matched_containers.append(c)
                    correlation_key = correlation_key or "ip"

        if matched_guests or matched_containers:
            return self._build_correlated_signal(
                target_label=f"IP {ip_rec.ip}",
                matched_guests=matched_guests,
                matched_containers=matched_containers,
                correlation_key=correlation_key or "ip",
                pve_mac_detected=pve_mac_detected or any(g.has_proxmox_mac for g in matched_guests),
                eval_dt=eval_dt,
            )

        if pve_mac_detected:
            if snapshot.unreachable_hosts or (not snapshot.guests and not snapshot.containers):
                return ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details=(
                        f"IP {ip_rec.ip} has Proxmox OUI MAC ({candidate_macs[0]}), "
                        "but Proxmox host snapshot is unreachable or empty"
                    ),
                    source=self.source,
                    metadata={
                        "ip": ip_rec.ip,
                        "mac_addresses": candidate_macs,
                        "proxmox_mac_detected": True,
                        "unreachable_hosts": sorted(snapshot.unreachable_hosts),
                    },
                )
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.INACTIVE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=(
                    f"IP {ip_rec.ip} has Proxmox OUI MAC ({candidate_macs[0]}), "
                    "but no matching guest exists in Proxmox cluster snapshot"
                ),
                source=self.source,
                metadata={
                    "ip": ip_rec.ip,
                    "mac_addresses": candidate_macs,
                    "proxmox_mac_detected": True,
                },
            )

        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=SignalStatus.NOT_APPLICABLE,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=f"IP {ip_rec.ip} did not match any Proxmox guest or container",
            source=self.source,
            metadata={"ip": ip_rec.ip, "proxmox_mac_detected": False},
        )

    def _evaluate_equipment_target(
        self,
        equipment: Equipment,
        *,
        snapshot: Optional[ProxmoxClusterSnapshot],
        site: Optional[Site],
        ip_addresses: Optional[Sequence[IPAddress]],
        arp_entries: Optional[Sequence[ArpEntry]],
        ports: Optional[Sequence[Port]],
        eval_dt: datetime,
    ) -> ValidationSignal:
        candidate_ips: list[str] = []
        for raw_ip in equipment.assigned_ips:
            norm_ip = normalize_ip_address(raw_ip)
            if norm_ip and norm_ip not in candidate_ips:
                candidate_ips.append(norm_ip)

        candidate_macs: list[str] = []
        for attr in ("mac_address", "mac_addresses"):
            for m in extract_mac_addresses(getattr(equipment, attr, None)):
                if m not in candidate_macs:
                    candidate_macs.append(m)

        all_ips: list[IPAddress] = []
        if ip_addresses:
            all_ips.extend(ip_addresses)
        if site is not None:
            all_ips.extend(site.ip_addresses)

        for ip_rec in all_ips:
            norm_rec_ip = normalize_ip_address(ip_rec.ip)
            if ip_rec.assigned_object_id == equipment.equipment_id or (
                norm_rec_ip and norm_rec_ip in candidate_ips
            ):
                if norm_rec_ip and norm_rec_ip not in candidate_ips:
                    candidate_ips.append(norm_rec_ip)
                for raw_m in (
                    ip_rec.arp_mac,
                    ip_rec.arp_entry.arp_mac if isinstance(ip_rec.arp_entry, ArpEntry) else None,
                ):
                    nm = normalize_mac_address(raw_m)
                    if nm and nm not in candidate_macs:
                        candidate_macs.append(nm)

        if arp_entries:
            for entry in arp_entries:
                if normalize_ip_address(entry.ip) in candidate_ips:
                    nm = normalize_mac_address(entry.arp_mac)
                    if nm and nm not in candidate_macs:
                        candidate_macs.append(nm)

        all_ports: list[Port] = []
        if ports:
            all_ports.extend(ports)
        if site is not None:
            for dev in site.devices:
                all_ports.extend(dev.ports)

        conn_refs = {r.strip() for r in equipment.connected_ports if r and r.strip()}
        for port in all_ports:
            if (
                port.connected_device_id == equipment.equipment_id
                or port.port_id in conn_refs
                or port.name in conn_refs
                or f"{port.device_id}:{port.name}" in conn_refs
            ):
                nm = normalize_mac_address(port.connected_mac)
                if nm and nm not in candidate_macs:
                    candidate_macs.append(nm)

        vmid_hint = (
            _extract_vmid_hint(getattr(equipment, "vmid", None))
            or _extract_vmid_hint(equipment.hypervisor_id)
            or _extract_vmid_hint(equipment.equipment_id)
            or _extract_vmid_hint(equipment.name)
        )
        pve_mac_detected = any(is_proxmox_mac(m) for m in candidate_macs)
        has_vm_hint = bool(
            equipment.category is EquipmentCategory.VM
            or equipment.hypervisor_id
            or vmid_hint is not None
            or pve_mac_detected
        )

        if snapshot is None:
            if has_vm_hint:
                return ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details=f"Equipment {equipment.name} ({equipment.equipment_id}) is a VM/container candidate, but no Proxmox/container snapshot is available",
                    source=self.source,
                    metadata={
                        "equipment_id": equipment.equipment_id,
                        "proxmox_mac_detected": pve_mac_detected,
                    },
                )
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=f"Equipment {equipment.name} ({equipment.equipment_id}) is not a VM/container and no snapshot is configured",
                source=self.source,
                metadata={
                    "equipment_id": equipment.equipment_id,
                    "proxmox_mac_detected": False,
                },
            )

        matched_guests: list[ProxmoxGuestRecord] = []
        matched_containers: list[ContainerEndpointRecord] = []
        correlation_key: Optional[str] = None

        if vmid_hint is not None:
            for g in snapshot.find_guests(vmid=vmid_hint):
                if g not in matched_guests:
                    matched_guests.append(g)
                    correlation_key = correlation_key or "vmid"

        for mac in candidate_macs:
            for g in snapshot.find_guests(mac=mac):
                if g not in matched_guests:
                    matched_guests.append(g)
                    correlation_key = correlation_key or "mac"

        for ip_str in candidate_ips:
            for g in snapshot.find_guests(ip=ip_str):
                if g not in matched_guests:
                    matched_guests.append(g)
                    correlation_key = correlation_key or "ip"
            for c in snapshot.find_containers(ip=ip_str):
                if c not in matched_containers:
                    matched_containers.append(c)
                    correlation_key = correlation_key or "ip"

        if not matched_guests and not matched_containers:
            for g in snapshot.find_guests(name=equipment.name):
                if g not in matched_guests:
                    matched_guests.append(g)
                    correlation_key = correlation_key or "name"
            for c in snapshot.find_containers(name=equipment.name):
                if c not in matched_containers:
                    matched_containers.append(c)
                    correlation_key = correlation_key or "name"
            for c in snapshot.find_containers(container_id=equipment.equipment_id):
                if c not in matched_containers:
                    matched_containers.append(c)
                    correlation_key = correlation_key or "container_id"

        if matched_guests or matched_containers:
            return self._build_correlated_signal(
                target_label=f"Equipment {equipment.name} ({equipment.equipment_id})",
                matched_guests=matched_guests,
                matched_containers=matched_containers,
                correlation_key=correlation_key or "name",
                pve_mac_detected=pve_mac_detected or any(g.has_proxmox_mac for g in matched_guests),
                eval_dt=eval_dt,
            )

        # A generic VM (e.g. VMware) with no match is out of scope for this collector; only
        # Proxmox-specific evidence lets a reachable snapshot confirm the guest is gone.
        hypervisor_ref = (equipment.hypervisor_id or "").lower()
        has_proxmox_evidence = bool(
            pve_mac_detected
            or vmid_hint is not None
            or (
                hypervisor_ref
                and (
                    hypervisor_ref in snapshot.node_ips
                    or hypervisor_ref in snapshot.node_ips.values()
                )
            )
        )

        if has_vm_hint:
            if snapshot.unreachable_hosts or (not snapshot.guests and not snapshot.containers):
                return ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details=(
                        f"Equipment {equipment.name} ({equipment.equipment_id}) has VM/Proxmox hints, "
                        "but Proxmox/container host is unreachable"
                    ),
                    source=self.source,
                    metadata={
                        "equipment_id": equipment.equipment_id,
                        "proxmox_mac_detected": pve_mac_detected,
                        "unreachable_hosts": sorted(snapshot.unreachable_hosts),
                    },
                )
            if has_proxmox_evidence:
                return ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.INACTIVE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details=(
                        f"Equipment {equipment.name} ({equipment.equipment_id}) has Proxmox hints, "
                        "but no matching guest or container was found in snapshot"
                    ),
                    source=self.source,
                    metadata={
                        "equipment_id": equipment.equipment_id,
                        "proxmox_mac_detected": pve_mac_detected,
                    },
                )

        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=SignalStatus.NOT_APPLICABLE,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=f"Equipment {equipment.name} ({equipment.equipment_id}) did not match any Proxmox guest or container",
            source=self.source,
            metadata={
                "equipment_id": equipment.equipment_id,
                "proxmox_mac_detected": pve_mac_detected,
            },
        )

    def _build_correlated_signal(
        self,
        *,
        target_label: str,
        matched_guests: list[ProxmoxGuestRecord],
        matched_containers: list[ContainerEndpointRecord],
        correlation_key: str,
        pve_mac_detected: bool,
        eval_dt: datetime,
    ) -> ValidationSignal:
        any_running = any(g.is_running for g in matched_guests) or any(
            c.is_running for c in matched_containers
        )
        status = SignalStatus.ACTIVE if any_running else SignalStatus.INACTIVE

        summary_parts: list[str] = []
        for g in matched_guests:
            summary_parts.append(
                f"Proxmox {g.guest_type.upper()} {g.name} (vmid={g.vmid}, node={g.node}, status={g.status})"
            )
        for c in matched_containers:
            summary_parts.append(
                f"Container {c.name} (id={c.container_id[:12]}, state={c.state})"
            )

        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=status,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=f"{target_label} correlated via {correlation_key}: {'; '.join(summary_parts)}",
            source=self.source,
            metadata={
                "correlation_key": correlation_key,
                "proxmox_mac_detected": pve_mac_detected,
                "matched_guests": [g.to_dict() for g in matched_guests],
                "matched_containers": [c.to_dict() for c in matched_containers],
            },
        )

    def enrich_site_with_guests(
        self,
        site: Site,
        *,
        snapshot: Optional[ProxmoxClusterSnapshot] = None,
    ) -> Site:
        """Return an enriched Site copy with Proxmox guests and containers linked via hypervisor_id."""
        active_snapshot = snapshot if snapshot is not None else self.snapshot
        cloned_site = Site.from_dict(site.to_dict())
        if active_snapshot is None:
            return cloned_site

        host_ips = _collect_host_ips_in_site(cloned_site, active_snapshot)

        # Map normalized MACs from site.ip_addresses and switch ports to equipment_id
        mac_to_eq_id: dict[str, str] = {}
        mac_to_ip_rec: dict[str, IPAddress] = {}
        for ip_rec in cloned_site.ip_addresses:
            for raw_m in (
                ip_rec.arp_mac,
                ip_rec.arp_entry.arp_mac if isinstance(ip_rec.arp_entry, ArpEntry) else None,
            ):
                nm = normalize_mac_address(raw_m)
                if nm:
                    mac_to_ip_rec[nm] = ip_rec
                    if ip_rec.assigned_object_id:
                        mac_to_eq_id[nm] = ip_rec.assigned_object_id

        for dev in cloned_site.devices:
            for port in dev.ports:
                nm = normalize_mac_address(port.connected_mac)
                if nm and port.connected_device_id:
                    mac_to_eq_id.setdefault(nm, port.connected_device_id)

        # Identify which existing Equipment records represent hypervisor/container hosts themselves
        host_equipment_ids: set[str] = set()
        for eq in cloned_site.equipment:
            eq_ips = {normalize_ip_address(ip) for ip in eq.assigned_ips}
            eq_ips.discard(None)
            if (eq_ips & host_ips) and eq.category is not EquipmentCategory.VM:
                host_equipment_ids.add(eq.equipment_id)
            elif any(_names_match(eq.name, node_name) for node_name in active_snapshot.node_ips):
                host_equipment_ids.add(eq.equipment_id)

        # 1. Enrich or add ProxmoxGuestRecords
        for guest in active_snapshot.guests:
            matched_eq: Optional[Equipment] = None

            # Match by MAC first
            for g_mac in guest.mac_addresses:
                eq_id = mac_to_eq_id.get(g_mac)
                if eq_id and eq_id not in host_equipment_ids:
                    matched_eq = next(
                        (e for e in cloned_site.equipment if e.equipment_id == eq_id),
                        None,
                    )
                    if matched_eq is not None:
                        break

            # Match by guest IP
            if matched_eq is None and guest.ip_addresses:
                for eq in cloned_site.equipment:
                    if eq.equipment_id in host_equipment_ids:
                        continue
                    eq_ips = {normalize_ip_address(ip) for ip in eq.assigned_ips}
                    if any(g_ip in eq_ips for g_ip in guest.ip_addresses):
                        matched_eq = eq
                        break

            # Match by VMID or name, never taking over a record already hosted by another hypervisor
            if matched_eq is None:
                guest_host_refs = {
                    ref.lower()
                    for ref in (
                        guest.node,
                        guest.host_ip,
                        _resolve_parent_hypervisor_id(
                            site=cloned_site, host_ip=guest.host_ip, node_name=guest.node
                        ),
                    )
                    if ref
                }
                for eq in cloned_site.equipment:
                    if eq.equipment_id in host_equipment_ids:
                        continue
                    if eq.hypervisor_id and eq.hypervisor_id.lower() not in guest_host_refs:
                        continue
                    if (
                        _extract_vmid_hint(eq.equipment_id) == guest.vmid
                        or _extract_vmid_hint(eq.name) == guest.vmid
                        or _names_match(eq.name, guest.name)
                    ):
                        matched_eq = eq
                        break

            parent_id = _resolve_parent_hypervisor_id(
                site=cloned_site,
                host_ip=guest.host_ip or active_snapshot.node_ips.get(guest.node.lower()),
                node_name=guest.node,
                exclude_equipment_id=matched_eq.equipment_id if matched_eq else None,
            )

            if matched_eq is not None:
                matched_eq.category = EquipmentCategory.VM
                matched_eq.power_state = guest.status
                if parent_id and parent_id != matched_eq.equipment_id:
                    matched_eq.hypervisor_id = parent_id
                if matched_eq.name in (matched_eq.equipment_id, *(matched_eq.assigned_ips or [])):
                    matched_eq.name = guest.name
                for g_ip in guest.ip_addresses:
                    if g_ip != guest.host_ip and g_ip not in matched_eq.assigned_ips:
                        matched_eq.assigned_ips.append(g_ip)
            else:
                new_eq_id = f"{cloned_site.site_id}-pve-{guest.guest_type}-{guest.vmid}"
                existing_ids = {e.equipment_id for e in cloned_site.equipment}
                if new_eq_id in existing_ids:
                    new_eq_id = f"{new_eq_id}-{guest.node}"
                guest_ips = [ip for ip in guest.ip_addresses if ip != guest.host_ip]
                new_eq = Equipment(
                    equipment_id=new_eq_id,
                    site_id=cloned_site.site_id,
                    name=guest.name,
                    category=EquipmentCategory.VM,
                    assigned_ips=guest_ips,
                    connected_ports=[],
                    hypervisor_id=parent_id,
                    power_state=guest.status,
                )
                cloned_site.equipment.append(new_eq)
                for g_mac in guest.mac_addresses:
                    ip_rec = mac_to_ip_rec.get(g_mac)
                    if ip_rec and not ip_rec.assigned_object_id:
                        ip_rec.assigned_object_type = "equipment"
                        ip_rec.assigned_object_id = new_eq_id

        # 2. Enrich or add ContainerEndpointRecords
        for container in active_snapshot.containers:
            matched_eq = None

            # Match by dedicated non-host container IP or name/id
            non_host_c_ips = [
                ip
                for ip in container.ip_addresses
                if ip != container.host_ip and ip not in host_ips
            ]
            if non_host_c_ips:
                for eq in cloned_site.equipment:
                    if eq.equipment_id in host_equipment_ids:
                        continue
                    eq_ips = {normalize_ip_address(ip) for ip in eq.assigned_ips}
                    if any(c_ip in eq_ips for c_ip in non_host_c_ips):
                        matched_eq = eq
                        break

            if matched_eq is None:
                container_host_refs = {
                    ref.lower()
                    for ref in (
                        container.host_ip,
                        _resolve_parent_hypervisor_id(
                            site=cloned_site, host_ip=container.host_ip, node_name=None
                        ),
                    )
                    if ref
                }
                for eq in cloned_site.equipment:
                    if eq.equipment_id in host_equipment_ids:
                        continue
                    if eq.hypervisor_id and eq.hypervisor_id.lower() not in container_host_refs:
                        continue
                    if (
                        _names_match(eq.name, container.name)
                        or eq.equipment_id.lower() == container.container_id.lower()
                    ):
                        matched_eq = eq
                        break

            parent_id = _resolve_parent_hypervisor_id(
                site=cloned_site,
                host_ip=container.host_ip,
                node_name=None,
                exclude_equipment_id=matched_eq.equipment_id if matched_eq else None,
            )

            if matched_eq is not None:
                matched_eq.category = EquipmentCategory.VM
                matched_eq.power_state = container.state
                if parent_id and parent_id != matched_eq.equipment_id:
                    matched_eq.hypervisor_id = parent_id
                for c_ip in non_host_c_ips:
                    if c_ip not in matched_eq.assigned_ips:
                        matched_eq.assigned_ips.append(c_ip)
            else:
                slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", container.name).strip("-") or container.container_id[:12]
                new_eq_id = f"{cloned_site.site_id}-ct-{slug}"
                existing_ids = {e.equipment_id for e in cloned_site.equipment}
                if new_eq_id in existing_ids:
                    new_eq_id = f"{new_eq_id}-{container.container_id[:8]}"
                new_eq = Equipment(
                    equipment_id=new_eq_id,
                    site_id=cloned_site.site_id,
                    name=container.name,
                    category=EquipmentCategory.VM,
                    assigned_ips=list(non_host_c_ips),
                    connected_ports=[],
                    hypervisor_id=parent_id,
                    power_state=container.state,
                )
                cloned_site.equipment.append(new_eq)

        return cloned_site


ProxmoxContainerCorrelator = ProxmoxContainerCollector


__all__ = [
    "PROXMOX_MAC_OUI",
    "ContainerEndpointRecord",
    "ProxmoxClusterSnapshot",
    "ProxmoxContainerCollector",
    "ProxmoxContainerCorrelator",
    "ProxmoxGuestRecord",
    "extract_ip_addresses",
    "extract_mac_addresses",
    "is_proxmox_mac",
    "normalize_container_state",
    "normalize_ip_address",
    "normalize_mac_address",
    "normalize_proxmox_guest_status",
    "normalize_proxmox_guest_type",
]
