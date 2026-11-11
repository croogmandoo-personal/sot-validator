"""Multi-vCenter VM power state and Guest Tools correlation collector."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping, Sequence
import csv
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
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
    SECONDS_PER_DAY,
    SignalCollector,
    normalize_utc_datetime,
    resolve_evaluation_time,
)

_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_MOREF_PATTERN = re.compile(r"^vm-[0-9a-zA-Z_-]+$", re.IGNORECASE)

_ALLOWED_READONLY_MODES: frozenset[str] = frozenset(
    {
        "readonly",
        "read_only",
        "read-only",
        "ro",
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


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str):
        return None
    cleaned = mac.strip().lower()
    if not cleaned:
        return None
    hex_only = "".join(ch for ch in cleaned if ch not in (":", "-", "."))
    return hex_only or cleaned


def _format_mac_canonical(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str):
        return None
    cleaned = mac.strip().lower()
    if not cleaned:
        return None
    hex_only = "".join(ch for ch in cleaned if ch not in (":", "-", "."))
    if len(hex_only) == 12 and all(c in "0123456789abcdef" for c in hex_only):
        return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))
    return cleaned


def _normalize_ip(ip: Optional[str]) -> Optional[str]:
    if not isinstance(ip, str):
        return None
    cleaned = ip.strip()
    return cleaned if cleaned else None


def _normalize_uuid(value: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(value)
    if cleaned is None:
        return None
    lower = cleaned.lower()
    if lower.startswith("uuid:"):
        lower = lower[5:].strip()
    return lower if lower else None


def _looks_like_uuid(value: Optional[str]) -> bool:
    norm = _normalize_uuid(value)
    if norm is None:
        return False
    return bool(_UUID_PATTERN.match(norm))


def _normalize_instance_key(instance: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(instance)
    if cleaned is None:
        return None
    return cleaned.lower()


def _short_instance_key(instance: Optional[str]) -> Optional[str]:
    norm = _normalize_instance_key(instance)
    if norm is None:
        return None
    return norm.split(".", 1)[0]


def _instances_match(inst_a: Optional[str], inst_b: Optional[str]) -> bool:
    norm_a = _normalize_instance_key(inst_a)
    norm_b = _normalize_instance_key(inst_b)
    if norm_a is None or norm_b is None:
        return False
    if norm_a == norm_b:
        return True
    short_a = _short_instance_key(norm_a)
    short_b = _short_instance_key(norm_b)
    return bool(short_a and short_a == short_b)


def _parse_optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if not cleaned:
            return None
        if cleaned in ("true", "1", "yes", "y", "connected", "up", "on"):
            return True
        if cleaned in ("false", "0", "no", "n", "disconnected", "down", "off"):
            return False
    return None


def _split_str_items(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except ValueError:
                pass
        sep = ";" if ";" in stripped else ","
        return [part.strip() for part in stripped.split(sep) if part.strip()]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        result: list[str] = []
        for item in value:
            result.extend(_split_str_items(item))
        return result
    cleaned = _clean_optional_str(value)
    return [cleaned] if cleaned else []


class VmPowerState(str, Enum):
    """Normalized VMware vCenter virtual machine power state."""

    POWERED_ON = "POWERED_ON"
    POWERED_OFF = "POWERED_OFF"
    SUSPENDED = "SUSPENDED"

    @classmethod
    def from_raw(cls, value: Any) -> VmPowerState:
        """Normalize raw vCenter or RVTools power state string to VmPowerState."""
        if isinstance(value, VmPowerState):
            return value
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Invalid VM power state: {value!r}")
        token = (
            value.strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
        )
        if token in ("poweredon", "powered_on", "on", "running", "active", "up"):
            return cls.POWERED_ON
        if token in ("poweredoff", "powered_off", "off", "halted", "stopped", "down", "shut_off"):
            return cls.POWERED_OFF
        if token in ("suspended", "suspend", "paused"):
            return cls.SUSPENDED
        raise ValueError(f"Unsupported VM power state: {value!r}")


def normalize_vm_power_state(value: Any) -> VmPowerState:
    """Normalize a raw power state string or VmPowerState enum."""
    return VmPowerState.from_raw(value)


class GuestToolsStatus(str, Enum):
    """Normalized VMware Guest Tools operational status."""

    TOOLS_OK = "toolsOk"
    TOOLS_OLD = "toolsOld"
    TOOLS_NOT_RUNNING = "toolsNotRunning"
    TOOLS_NOT_INSTALLED = "toolsNotInstalled"

    @classmethod
    def from_raw(cls, value: Any) -> Optional[GuestToolsStatus]:
        """Normalize raw vCenter or RVTools Guest Tools status string to GuestToolsStatus."""
        if value is None:
            return None
        if isinstance(value, GuestToolsStatus):
            return value
        if not isinstance(value, str):
            raise ValueError(f"Invalid Guest Tools status: {value!r}")
        cleaned = value.strip()
        if not cleaned:
            return None
        token = (
            cleaned.lower()
            .replace("-", "")
            .replace("_", "")
            .replace(" ", "")
        )
        if token in ("toolsok", "guesttoolsrunning", "ok", "running", "current"):
            return cls.TOOLS_OK
        if token in ("toolsold", "guesttoolsoutofdate", "old", "outofdate", "needupgrade"):
            return cls.TOOLS_OLD
        if token in (
            "toolsnotrunning",
            "guesttoolsnotrunning",
            "notrunning",
            "stopped",
            "unmanaged",
        ):
            return cls.TOOLS_NOT_RUNNING
        if token in (
            "toolsnotinstalled",
            "guesttoolsnotinstalled",
            "notinstalled",
            "none",
            "absent",
        ):
            return cls.TOOLS_NOT_INSTALLED
        raise ValueError(f"Unsupported Guest Tools status: {value!r}")


def normalize_guest_tools_status(value: Any) -> Optional[GuestToolsStatus]:
    """Normalize a raw Guest Tools status string or GuestToolsStatus enum."""
    return GuestToolsStatus.from_raw(value)


def _infer_guest_os_family(
    os_family: Optional[str], os_full_name: Optional[str]
) -> Optional[str]:
    fam = _clean_optional_str(os_family)
    if fam:
        lower = fam.lower()
        if "win" in lower:
            return "windows"
        if any(k in lower for k in ("linux", "ubuntu", "rhel", "centos", "debian", "suse", "rocky", "alma")):
            return "linux"
        return lower

    full = _clean_optional_str(os_full_name)
    if full:
        lower_full = full.lower()
        if "windows" in lower_full or "microsoft" in lower_full:
            return "windows"
        if any(
            k in lower_full
            for k in ("linux", "ubuntu", "red hat", "rhel", "centos", "debian", "suse", "rocky", "alma")
        ):
            return "linux"
    return None


@dataclass
class VmNicBinding:
    """Virtual machine guest network adapter binding."""

    mac_address: Optional[str] = None
    ip_addresses: list[str] = field(default_factory=list)
    nic_label: Optional[str] = None
    vlan_id: Optional[int | str] = None
    connected: Optional[bool] = None

    def __post_init__(self) -> None:
        self.mac_address = _format_mac_canonical(self.mac_address)
        ips: list[str] = []
        for raw_ip in _split_str_items(self.ip_addresses):
            norm_ip = _normalize_ip(raw_ip)
            if norm_ip and norm_ip not in ips:
                ips.append(norm_ip)
        self.ip_addresses = ips
        self.nic_label = _clean_optional_str(self.nic_label)
        if isinstance(self.vlan_id, str):
            cleaned_vlan = self.vlan_id.strip()
            if not cleaned_vlan:
                self.vlan_id = None
            elif cleaned_vlan.isdigit():
                self.vlan_id = int(cleaned_vlan)
            else:
                self.vlan_id = cleaned_vlan
        self.connected = _parse_optional_bool(self.connected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nic_label": self.nic_label,
            "mac_address": self.mac_address,
            "ip_addresses": list(self.ip_addresses),
            "vlan_id": self.vlan_id,
            "connected": self.connected,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VmNicBinding:
        raw_ips = data.get("ip_addresses")
        if raw_ips is None:
            raw_ips = data.get("ip_address") or data.get("ip")
        return cls(
            mac_address=data.get("mac_address") or data.get("mac"),
            ip_addresses=_split_str_items(raw_ips),
            nic_label=data.get("nic_label") or data.get("label") or data.get("name"),
            vlan_id=data.get("vlan_id") if data.get("vlan_id") is not None else data.get("vlan"),
            connected=data.get("connected"),
        )


@dataclass
class HypervisorVmRecord:
    """Normalized virtual machine inventory record owned by a vCenter instance."""

    vcenter_instance: str
    vm_moref: str
    vm_name: str
    power_state: VmPowerState
    vcenter_host: Optional[str] = None
    site_id: Optional[str] = None
    bios_uuid: Optional[str] = None
    instance_uuid: Optional[str] = None
    guest_hostname: Optional[str] = None
    guest_os_family: Optional[str] = None
    guest_os_full_name: Optional[str] = None
    guest_tools_status: Optional[GuestToolsStatus] = None
    tools_heartbeat: Optional[str] = None
    icmp_blocked_by_host_firewall: Optional[bool] = None
    nics: list[VmNicBinding] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    last_updated: Optional[datetime] = None
    power_state_changed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.vcenter_instance = _require_non_empty_str(
            self.vcenter_instance, "vcenter_instance"
        )
        self.vm_moref = _require_non_empty_str(self.vm_moref, "vm_moref")
        self.vm_name = _require_non_empty_str(self.vm_name, "vm_name")
        self.power_state = normalize_vm_power_state(self.power_state)
        self.vcenter_host = _clean_optional_str(self.vcenter_host)
        self.site_id = _clean_optional_str(self.site_id)
        self.bios_uuid = _normalize_uuid(self.bios_uuid)
        self.instance_uuid = _normalize_uuid(self.instance_uuid)
        self.guest_hostname = _clean_optional_str(self.guest_hostname)
        self.guest_os_full_name = _clean_optional_str(self.guest_os_full_name)
        self.guest_os_family = _infer_guest_os_family(
            self.guest_os_family, self.guest_os_full_name
        )
        self.guest_tools_status = normalize_guest_tools_status(self.guest_tools_status)
        hb = _clean_optional_str(self.tools_heartbeat)
        self.tools_heartbeat = hb.lower() if hb else None
        self.icmp_blocked_by_host_firewall = _parse_optional_bool(
            self.icmp_blocked_by_host_firewall
        )

        self.nics = [
            nic if isinstance(nic, VmNicBinding) else VmNicBinding.from_dict(nic)
            for nic in (self.nics or [])
        ]

        merged_ips: list[str] = []
        for raw_ip in _split_str_items(self.ip_addresses):
            norm_ip = _normalize_ip(raw_ip)
            if norm_ip and norm_ip not in merged_ips:
                merged_ips.append(norm_ip)
        for nic in self.nics:
            for nic_ip in nic.ip_addresses:
                if nic_ip and nic_ip not in merged_ips:
                    merged_ips.append(nic_ip)
        self.ip_addresses = merged_ips

        merged_macs: list[str] = []
        seen_norm_macs: set[str] = set()
        for raw_mac in _split_str_items(self.mac_addresses):
            norm_mac = _normalize_mac(raw_mac)
            canon_mac = _format_mac_canonical(raw_mac)
            if norm_mac and canon_mac and norm_mac not in seen_norm_macs:
                seen_norm_macs.add(norm_mac)
                merged_macs.append(canon_mac)
        for nic in self.nics:
            if nic.mac_address:
                norm_mac = _normalize_mac(nic.mac_address)
                canon_mac = _format_mac_canonical(nic.mac_address)
                if norm_mac and canon_mac and norm_mac not in seen_norm_macs:
                    seen_norm_macs.add(norm_mac)
                    merged_macs.append(canon_mac)
        self.mac_addresses = merged_macs

        if self.last_updated is not None:
            self.last_updated = normalize_utc_datetime(
                self.last_updated, field_name="last_updated"
            )
        if self.power_state_changed_at is not None:
            self.power_state_changed_at = normalize_utc_datetime(
                self.power_state_changed_at, field_name="power_state_changed_at"
            )

    @property
    def tools_status(self) -> Optional[GuestToolsStatus]:
        """Alias for guest_tools_status matching vCenter snapshot field naming."""
        return self.guest_tools_status

    @property
    def is_windows(self) -> bool:
        """Return True if the VM guest OS family is Windows."""
        return self.guest_os_family == "windows"

    @property
    def has_healthy_tools_heartbeat(self) -> bool:
        """Return True if VMware Guest Tools is running/healthy or heartbeat is green."""
        if self.guest_tools_status in (
            GuestToolsStatus.TOOLS_OK,
            GuestToolsStatus.TOOLS_OLD,
        ):
            return True
        if self.tools_heartbeat == "green":
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "vcenter_instance": self.vcenter_instance,
            "vcenter_host": self.vcenter_host,
            "site_id": self.site_id,
            "vm_moref": self.vm_moref,
            "bios_uuid": self.bios_uuid,
            "instance_uuid": self.instance_uuid,
            "vm_name": self.vm_name,
            "guest_hostname": self.guest_hostname,
            "guest_os_family": self.guest_os_family,
            "guest_os_full_name": self.guest_os_full_name,
            "power_state": self.power_state.value,
            "guest_tools_status": (
                self.guest_tools_status.value
                if self.guest_tools_status is not None
                else None
            ),
            "tools_status": (
                self.guest_tools_status.value
                if self.guest_tools_status is not None
                else None
            ),
            "tools_heartbeat": self.tools_heartbeat,
            "icmp_blocked_by_host_firewall": self.icmp_blocked_by_host_firewall,
            "nics": [nic.to_dict() for nic in self.nics],
            "ip_addresses": list(self.ip_addresses),
            "mac_addresses": list(self.mac_addresses),
            "last_updated": (
                self.last_updated.isoformat()
                if self.last_updated is not None
                else None
            ),
            "power_state_changed_at": (
                self.power_state_changed_at.isoformat()
                if self.power_state_changed_at is not None
                else None
            ),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        default_vcenter_instance: Optional[str] = None,
    ) -> HypervisorVmRecord:
        vcenter_instance = (
            _clean_optional_str(
                data.get("vcenter_instance")
                or data.get("VI SDK Server")
                or data.get("vcenter")
                or data.get("vcenter_server")
            )
            or _clean_optional_str(default_vcenter_instance)
            or _clean_optional_str(data.get("vcenter_host"))
        )
        if not vcenter_instance:
            raise ValueError("vcenter_instance must be a non-empty string")

        vcenter_host = _clean_optional_str(
            data.get("vcenter_host")
            or data.get("VI SDK Server")
            or (
                vcenter_instance
                if "." in vcenter_instance
                else None
            )
        )
        # If vcenter_instance was given as full FQDN and no separate short name, keep as provided;
        # matching handles short-name vs FQDN transparently.

        vm_moref = _clean_optional_str(
            data.get("vm_moref")
            or data.get("vcenter_moref")
            or data.get("moref")
            or data.get("VM ID")
            or data.get("vm_id")
        )
        if not vm_moref:
            raise ValueError("vm_moref must be a non-empty string")

        vm_name = _clean_optional_str(
            data.get("vm_name")
            or data.get("VM")
            or data.get("name")
            or data.get("guest_hostname")
            or data.get("DNS Name")
        )
        if not vm_name:
            raise ValueError("vm_name must be a non-empty string")

        raw_power = (
            data.get("power_state")
            if data.get("power_state") is not None
            else (
                data.get("Powerstate")
                if data.get("Powerstate") is not None
                else data.get("powerstate")
            )
        )
        power_state = normalize_vm_power_state(raw_power)

        bios_uuid = _clean_optional_str(
            data.get("bios_uuid")
            or data.get("vcenter_bios_uuid")
            or data.get("UUID")
            or data.get("VM UUID")
            or data.get("uuid")
        )
        instance_uuid = _clean_optional_str(
            data.get("instance_uuid") or data.get("SMBIOS UUID")
        )

        guest_hostname = _clean_optional_str(
            data.get("guest_hostname")
            or data.get("DNS Name")
            or data.get("hostname")
        )
        guest_os_full_name = _clean_optional_str(
            data.get("guest_os_full_name")
            or data.get("OS according to the configuration file")
            or data.get("OS according to the VMware Tools")
            or data.get("guest_os")
        )
        guest_os_family = _clean_optional_str(data.get("guest_os_family"))

        raw_tools = (
            data.get("guest_tools_status")
            if data.get("guest_tools_status") is not None
            else (
                data.get("tools_status")
                if data.get("tools_status") is not None
                else data.get("Tools")
            )
        )
        guest_tools_status = normalize_guest_tools_status(raw_tools)

        tools_heartbeat = _clean_optional_str(
            data.get("tools_heartbeat")
            or data.get("Heartbeat")
            or data.get("heartbeat")
        )

        icmp_blocked = data.get("icmp_blocked_by_host_firewall")

        raw_nics = data.get("nics") or []
        nics = [
            nic if isinstance(nic, VmNicBinding) else VmNicBinding.from_dict(nic)
            for nic in raw_nics
        ]

        top_ips = _split_str_items(
            data.get("ip_addresses")
            if data.get("ip_addresses") is not None
            else (
                data.get("primary_ip")
                if data.get("primary_ip") is not None
                else data.get("Primary IP Address")
            )
        )
        top_macs = _split_str_items(
            data.get("mac_addresses")
            if data.get("mac_addresses") is not None
            else (
                data.get("mac_address")
                if data.get("mac_address") is not None
                else data.get("Mac Address")
            )
        )

        if not nics and (top_macs or top_ips):
            nics.append(
                VmNicBinding(
                    mac_address=top_macs[0] if top_macs else None,
                    ip_addresses=top_ips,
                    nic_label="Network adapter 1",
                )
            )

        last_updated = _clean_optional_str(
            data.get("last_updated") or data.get("export_timestamp")
        ) or (
            data.get("last_updated")
            if isinstance(data.get("last_updated"), datetime)
            else None
        )
        power_state_changed_at = _clean_optional_str(
            data.get("power_state_changed_at") or data.get("poweroff_timestamp")
        ) or (
            data.get("power_state_changed_at")
            if isinstance(data.get("power_state_changed_at"), datetime)
            else None
        )

        return cls(
            vcenter_instance=vcenter_instance,
            vcenter_host=vcenter_host,
            site_id=_clean_optional_str(data.get("site_id") or data.get("Datacenter")),
            vm_moref=vm_moref,
            bios_uuid=bios_uuid,
            instance_uuid=instance_uuid,
            vm_name=vm_name,
            guest_hostname=guest_hostname,
            guest_os_family=guest_os_family,
            guest_os_full_name=guest_os_full_name,
            power_state=power_state,
            guest_tools_status=guest_tools_status,
            tools_heartbeat=tools_heartbeat,
            icmp_blocked_by_host_firewall=icmp_blocked,
            nics=nics,
            ip_addresses=top_ips,
            mac_addresses=top_macs,
            last_updated=last_updated,
            power_state_changed_at=power_state_changed_at,
        )


def _extract_equipment_vm_hints(
    equipment: Equipment,
    *,
    bios_uuid: Optional[str] = None,
    vcenter_instance: Optional[str] = None,
    vm_moref: Optional[str] = None,
    mac_addresses: Optional[Iterable[str]] = None,
) -> tuple[
    list[str],
    Optional[str],
    Optional[str],
    list[str],
    bool,
]:
    """Extract (uuid_candidates, vcenter_instance_hint, vm_moref_hint, mac_candidates, has_vm_hint)."""
    uuids: list[str] = []

    def _add_uuid(val: Optional[str]) -> None:
        norm = _normalize_uuid(val)
        if norm and norm not in uuids:
            uuids.append(norm)

    if bios_uuid:
        _add_uuid(bios_uuid)

    for attr in ("vcenter_bios_uuid", "bios_uuid", "instance_uuid", "uuid"):
        attr_val = getattr(equipment, attr, None)
        if isinstance(attr_val, str) and attr_val.strip():
            _add_uuid(attr_val)

    inst_hint = _clean_optional_str(vcenter_instance)
    if not inst_hint:
        for attr in ("vcenter_instance", "vcenter_host"):
            attr_val = getattr(equipment, attr, None)
            if isinstance(attr_val, str) and attr_val.strip():
                inst_hint = attr_val.strip()
                break

    moref_hint = _clean_optional_str(vm_moref)
    if not moref_hint:
        for attr in ("vcenter_moref", "vm_moref", "moref"):
            attr_val = getattr(equipment, attr, None)
            if isinstance(attr_val, str) and attr_val.strip():
                moref_hint = attr_val.strip()
                break

    hyp_id = _clean_optional_str(equipment.hypervisor_id)
    if hyp_id:
        if hyp_id.lower().startswith("uuid:") or _looks_like_uuid(hyp_id):
            _add_uuid(hyp_id)
        elif ":" in hyp_id or "/" in hyp_id:
            sep = ":" if ":" in hyp_id else "/"
            left, right = [part.strip() for part in hyp_id.split(sep, 1)]
            if left and not inst_hint:
                inst_hint = left
            if right:
                if _looks_like_uuid(right):
                    _add_uuid(right)
                elif not moref_hint:
                    moref_hint = right
        elif _MOREF_PATTERN.match(hyp_id):
            if not moref_hint:
                moref_hint = hyp_id
        else:
            if not inst_hint:
                inst_hint = hyp_id

    macs: list[str] = []
    if mac_addresses:
        for m in mac_addresses:
            if isinstance(m, str) and m.strip():
                macs.append(m.strip())
    for attr in ("mac_address", "mac_addresses"):
        attr_val = getattr(equipment, attr, None)
        for m in _split_str_items(attr_val):
            if m not in macs:
                macs.append(m)

    has_vm_hint = bool(
        equipment.category is EquipmentCategory.VM
        or uuids
        or inst_hint
        or moref_hint
        or hyp_id
    )
    return uuids, inst_hint, moref_hint, macs, has_vm_hint


class HypervisorInventoryProvider(ABC):
    """Read-only interface for querying and correlating VM inventory across vCenter instances."""

    @abstractmethod
    def list_vms(self) -> Sequence[HypervisorVmRecord]:
        """Return all known virtual machine records across reachable vCenter instances."""
        raise NotImplementedError

    @abstractmethod
    def configured_instances(self) -> set[str]:
        """Return the set of configured vCenter instance identifiers."""
        raise NotImplementedError

    @abstractmethod
    def unreachable_instances(self) -> set[str]:
        """Return the set of unreachable vCenter instance identifiers."""
        raise NotImplementedError

    def is_instance_reachable(self, vcenter_instance: str) -> bool:
        """Return True if the specified vCenter instance is reachable (not in unreachable_instances)."""
        if not vcenter_instance or not vcenter_instance.strip():
            return False
        for unreach in self.unreachable_instances():
            if _instances_match(vcenter_instance, unreach):
                return False
        configured = self.configured_instances()
        if not configured:
            return False
        for conf in configured:
            if _instances_match(vcenter_instance, conf):
                return True
        for vm in self.list_vms():
            if _instances_match(vcenter_instance, vm.vcenter_instance) or _instances_match(
                vcenter_instance, vm.vcenter_host
            ):
                return True
        return False

    def find_by_uuid(self, uuid_value: str) -> list[HypervisorVmRecord]:
        """Look up VM records matching bios_uuid or instance_uuid across all vCenter instances."""
        norm_uuid = _normalize_uuid(uuid_value)
        if not norm_uuid:
            return []
        matches: list[HypervisorVmRecord] = []
        for vm in self.list_vms():
            if vm.bios_uuid == norm_uuid or vm.instance_uuid == norm_uuid:
                matches.append(vm)
        return matches

    def find_by_moref(
        self, vm_moref: str, vcenter_instance: Optional[str] = None
    ) -> list[HypervisorVmRecord]:
        """Look up VM records matching vm_moref (scoped to vcenter_instance when provided)."""
        cleaned_moref = _clean_optional_str(vm_moref)
        if not cleaned_moref:
            return []
        target_moref = cleaned_moref.lower()
        cleaned_inst = _clean_optional_str(vcenter_instance)

        matches: list[HypervisorVmRecord] = []
        for vm in self.list_vms():
            if vm.vm_moref.lower() != target_moref:
                continue
            if cleaned_inst is not None:
                if not (
                    _instances_match(cleaned_inst, vm.vcenter_instance)
                    or _instances_match(cleaned_inst, vm.vcenter_host)
                ):
                    continue
            matches.append(vm)
        return matches

    def find_by_mac_or_ip(
        self,
        *,
        mac_addresses: Optional[Iterable[str]] = None,
        ip_addresses: Optional[Iterable[str]] = None,
        site_id: Optional[str] = None,
    ) -> list[HypervisorVmRecord]:
        """Look up VM records matching normalized NIC MAC addresses and/or IP addresses."""
        target_macs = {
            norm
            for m in (mac_addresses or ())
            if (norm := _normalize_mac(m)) is not None
        }
        target_ips = {
            norm
            for ip in (ip_addresses or ())
            if (norm := _normalize_ip(ip)) is not None
        }
        if not target_macs and not target_ips:
            return []

        cleaned_site = _clean_optional_str(site_id)

        mac_matches: list[HypervisorVmRecord] = []
        ip_matches: list[HypervisorVmRecord] = []

        for vm in self.list_vms():
            if (
                cleaned_site is not None
                and vm.site_id is not None
                and vm.site_id.lower() != cleaned_site.lower()
            ):
                continue

            vm_macs = {
                norm
                for m in vm.mac_addresses
                if (norm := _normalize_mac(m)) is not None
            }
            vm_ips = {
                norm
                for ip in vm.ip_addresses
                if (norm := _normalize_ip(ip)) is not None
            }

            if target_macs and (vm_macs & target_macs):
                mac_matches.append(vm)
            elif target_ips and (vm_ips & target_ips):
                ip_matches.append(vm)

        return mac_matches + ip_matches

    def find_by_hostname(
        self, hostname: str, *, site_id: Optional[str] = None
    ) -> list[HypervisorVmRecord]:
        """Look up VM records matching guest_hostname or vm_name (exact or short-hostname match)."""
        cleaned = _clean_optional_str(hostname)
        if not cleaned:
            return []
        target_lower = cleaned.lower()
        target_short = target_lower.split(".", 1)[0]
        cleaned_site = _clean_optional_str(site_id)

        exact_matches: list[HypervisorVmRecord] = []
        short_matches: list[HypervisorVmRecord] = []

        for vm in self.list_vms():
            site_ok = (
                cleaned_site is None
                or vm.site_id is None
                or vm.site_id.lower() == cleaned_site.lower()
            )
            if not site_ok:
                continue

            vm_name_lower = vm.vm_name.lower()
            guest_lower = vm.guest_hostname.lower() if vm.guest_hostname else None

            if target_lower == vm_name_lower or (
                guest_lower is not None and target_lower == guest_lower
            ):
                exact_matches.append(vm)
                continue

            vm_short = vm_name_lower.split(".", 1)[0]
            guest_short = guest_lower.split(".", 1)[0] if guest_lower else None

            if (
                target_lower.startswith(vm_name_lower + ".")
                or vm_name_lower.startswith(target_lower + ".")
                or (
                    guest_lower is not None
                    and (
                        target_lower.startswith(guest_lower + ".")
                        or guest_lower.startswith(target_lower + ".")
                    )
                )
                or target_short == vm_short
                or (guest_short is not None and target_short == guest_short)
            ):
                short_matches.append(vm)

        return exact_matches if exact_matches else short_matches

    def correlate_vms(
        self,
        equipment: Equipment,
        *,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        arp_entries: Optional[Sequence[ArpEntry]] = None,
        ports: Optional[Sequence[Port]] = None,
        bios_uuid: Optional[str] = None,
        vcenter_instance: Optional[str] = None,
        vm_moref: Optional[str] = None,
        mac_addresses: Optional[Iterable[str]] = None,
    ) -> tuple[list[HypervisorVmRecord], Optional[str]]:
        """Correlate an Equipment record across vCenter instances using the 4-tier priority order:
        1. bios_uuid
        2. (vcenter_instance, vm_moref) / vm_moref
        3. NIC mac_address / ip_addresses
        4. guest_hostname / vm_name
        """
        uuids, inst_hint, moref_hint, explicit_macs, _ = _extract_equipment_vm_hints(
            equipment,
            bios_uuid=bios_uuid,
            vcenter_instance=vcenter_instance,
            vm_moref=vm_moref,
            mac_addresses=mac_addresses,
        )

        # Priority 1: BIOS UUID / Instance UUID
        for candidate_uuid in uuids:
            uuid_matches = self.find_by_uuid(candidate_uuid)
            if uuid_matches:
                return uuid_matches, "bios_uuid"

        # Priority 2: (vcenter_instance, vm_moref) or vm_moref
        if moref_hint:
            moref_matches = self.find_by_moref(moref_hint, vcenter_instance=inst_hint)
            if not moref_matches and inst_hint is not None:
                # If VM was vMotioned across vCenters and kept or updated MoRef, check without instance filter
                # only when no instance-scoped match was found
                moref_matches = self.find_by_moref(moref_hint, vcenter_instance=None)
            if moref_matches:
                return moref_matches, "vm_moref"

        # Priority 3: MAC address + IP addresses
        resolved_ips: list[str] = []
        for ip in equipment.assigned_ips:
            norm_ip = _normalize_ip(ip)
            if norm_ip and norm_ip not in resolved_ips:
                resolved_ips.append(norm_ip)

        resolved_macs: list[str] = list(explicit_macs)

        all_ip_records: list[IPAddress] = []
        if ip_addresses:
            all_ip_records.extend(ip_addresses)
        if site is not None:
            all_ip_records.extend(site.ip_addresses)

        for ip_rec in all_ip_records:
            if (
                ip_rec.assigned_object_id == equipment.equipment_id
                or ip_rec.ip in resolved_ips
            ):
                if ip_rec.ip not in resolved_ips:
                    resolved_ips.append(ip_rec.ip)
                if ip_rec.arp_mac and ip_rec.arp_mac not in resolved_macs:
                    resolved_macs.append(ip_rec.arp_mac)
                if (
                    isinstance(ip_rec.arp_entry, ArpEntry)
                    and ip_rec.arp_entry.arp_mac
                    and ip_rec.arp_entry.arp_mac not in resolved_macs
                ):
                    resolved_macs.append(ip_rec.arp_entry.arp_mac)

        if arp_entries:
            for entry in arp_entries:
                if entry.ip in resolved_ips and entry.arp_mac not in resolved_macs:
                    resolved_macs.append(entry.arp_mac)

        all_ports: list[Port] = []
        if ports:
            all_ports.extend(ports)
        if site is not None:
            for dev in site.devices:
                all_ports.extend(dev.ports)

        connected_refs = {
            ref.strip() for ref in equipment.connected_ports if ref and ref.strip()
        }
        for port in all_ports:
            if (
                port.connected_device_id == equipment.equipment_id
                or port.port_id in connected_refs
                or port.name in connected_refs
                or f"{port.device_id}:{port.name}" in connected_refs
            ):
                # Only use port connected_mac if it's dedicated to this equipment_id
                if (
                    port.connected_device_id == equipment.equipment_id
                    and port.connected_mac
                    and port.connected_mac not in resolved_macs
                ):
                    resolved_macs.append(port.connected_mac)

        site_id = equipment.site_id or (site.site_id if site is not None else None)
        mac_ip_matches = self.find_by_mac_or_ip(
            mac_addresses=resolved_macs,
            ip_addresses=resolved_ips,
            site_id=site_id,
        )
        if mac_ip_matches:
            return mac_ip_matches, "mac_or_ip"

        # Priority 4: Normalized guest_hostname / vm_name
        hostname_matches = self.find_by_hostname(equipment.name, site_id=site_id)
        if hostname_matches:
            return hostname_matches, "hostname"

        return [], None


class MultiVCenterInventoryProvider(HypervisorInventoryProvider):
    """Read-only multi-vCenter inventory aggregator supporting JSON, CSV/RVTools, and adapter callables."""

    def __init__(
        self,
        vms: Iterable[HypervisorVmRecord | Mapping[str, Any]] = (),
        *,
        instances: Optional[Iterable[str | Mapping[str, Any]]] = None,
        unreachable_instances: Optional[Iterable[str]] = None,
        adapters: Optional[
            Mapping[str, Callable[[], Iterable[HypervisorVmRecord | Mapping[str, Any]]]]
        ] = None,
    ) -> None:
        self._vms: list[HypervisorVmRecord] = []
        self._configured_instances: set[str] = set()
        self._instance_hosts: dict[str, str] = {}
        self._unreachable_instances: set[str] = set()
        self._adapter_errors: dict[str, str] = {}

        if instances is not None:
            for inst in instances:
                if isinstance(inst, str):
                    cleaned = _clean_optional_str(inst)
                    if cleaned:
                        self._configured_instances.add(cleaned)
                elif isinstance(inst, Mapping):
                    mode = _clean_optional_str(
                        inst.get("api_mode") or inst.get("mode")
                    )
                    if mode is not None and mode.lower() not in _ALLOWED_READONLY_MODES:
                        raise ValueError(
                            f"vCenter instance api_mode must be read-only, got {mode!r}"
                        )
                    inst_id = _clean_optional_str(
                        inst.get("vcenter_instance")
                        or inst.get("instance")
                        or inst.get("name")
                        or inst.get("vcenter_host")
                    )
                    host = _clean_optional_str(inst.get("vcenter_host") or inst.get("host"))
                    if inst_id:
                        self._configured_instances.add(inst_id)
                        if host:
                            self._instance_hosts[inst_id] = host
                    if inst.get("reachable") is False or (
                        isinstance(inst.get("status"), str)
                        and inst["status"].strip().lower() in ("unreachable", "down", "error", "offline")
                    ):
                        if inst_id:
                            self._unreachable_instances.add(inst_id)
                else:
                    raise ValueError(f"Unsupported instance descriptor: {inst!r}")

        if unreachable_instances is not None:
            for unreach in unreachable_instances:
                cleaned = _clean_optional_str(unreach)
                if cleaned:
                    self._unreachable_instances.add(cleaned)
                    self._configured_instances.add(cleaned)

        for item in vms:
            rec = (
                item
                if isinstance(item, HypervisorVmRecord)
                else HypervisorVmRecord.from_dict(item)
            )
            self._vms.append(rec)
            self._configured_instances.add(rec.vcenter_instance)
            if rec.vcenter_host:
                self._instance_hosts.setdefault(rec.vcenter_instance, rec.vcenter_host)

        if adapters is not None:
            for inst_name, adapter_fn in adapters.items():
                cleaned_inst = _require_non_empty_str(inst_name, "adapter vcenter_instance")
                self._configured_instances.add(cleaned_inst)
                try:
                    adapter_items = adapter_fn()
                    for item in adapter_items:
                        rec = (
                            item
                            if isinstance(item, HypervisorVmRecord)
                            else HypervisorVmRecord.from_dict(
                                item, default_vcenter_instance=cleaned_inst
                            )
                        )
                        self._vms.append(rec)
                        self._configured_instances.add(rec.vcenter_instance)
                        if rec.vcenter_host:
                            self._instance_hosts.setdefault(
                                rec.vcenter_instance, rec.vcenter_host
                            )
                except Exception as exc:
                    self._unreachable_instances.add(cleaned_inst)
                    self._adapter_errors[cleaned_inst] = str(exc)

    def list_vms(self) -> Sequence[HypervisorVmRecord]:
        return tuple(self._vms)

    def configured_instances(self) -> set[str]:
        return set(self._configured_instances)

    def unreachable_instances(self) -> set[str]:
        return set(self._unreachable_instances)

    @property
    def adapter_errors(self) -> dict[str, str]:
        """Return any errors captured while invoking per-instance adapter callables."""
        return dict(self._adapter_errors)

    def is_instance_configured(self, vcenter_instance: str) -> bool:
        """Return True if vcenter_instance matches any configured instance or host."""
        for conf in self._configured_instances:
            if _instances_match(vcenter_instance, conf):
                return True
        for inst_id, host in self._instance_hosts.items():
            if _instances_match(vcenter_instance, host) or _instances_match(
                vcenter_instance, inst_id
            ):
                return True
        return False

    def is_instance_unreachable(self, vcenter_instance: str) -> bool:
        """Return True if vcenter_instance matches any unreachable vCenter instance."""
        for unreach in self._unreachable_instances:
            if _instances_match(vcenter_instance, unreach):
                return True
            host = self._instance_hosts.get(unreach)
            if host and _instances_match(vcenter_instance, host):
                return True
        return False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from a parsed JSON snapshot dictionary."""
        raw_instances = data.get("instances")
        raw_vms = data.get("vms") or []
        raw_unreachable = data.get("unreachable_instances")
        export_ts = _clean_optional_str(data.get("export_timestamp"))

        vms: list[HypervisorVmRecord] = []
        for raw_vm in raw_vms:
            if isinstance(raw_vm, HypervisorVmRecord):
                vms.append(raw_vm)
            elif isinstance(raw_vm, Mapping):
                vm_dict = dict(raw_vm)
                if export_ts and vm_dict.get("last_updated") is None:
                    vm_dict["last_updated"] = export_ts
                vms.append(HypervisorVmRecord.from_dict(vm_dict))
            else:
                raise ValueError(f"Unsupported VM entry in snapshot: {raw_vm!r}")

        return cls(
            vms=vms,
            instances=raw_instances,
            unreachable_instances=raw_unreachable,
        )

    @classmethod
    def from_json(cls, raw_json: str) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from a JSON string."""
        parsed = json.loads(raw_json)
        if isinstance(parsed, list):
            return cls(vms=parsed)
        if not isinstance(parsed, Mapping):
            raise ValueError("vCenter JSON inventory must be an object or array of VMs")
        return cls.from_dict(parsed)

    @classmethod
    def from_json_file(cls, path: str | Path) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from a JSON snapshot file on disk."""
        file_path = Path(path)
        return cls.from_json(file_path.read_text(encoding="utf-8"))

    @classmethod
    def from_csv_rows(
        cls,
        rows: Iterable[Mapping[str, Any]],
        *,
        default_vcenter_instance: Optional[str] = None,
        unreachable_instances: Optional[Iterable[str]] = None,
    ) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from CSV or RVTools dictionary rows."""
        vms = [
            HypervisorVmRecord.from_dict(
                row, default_vcenter_instance=default_vcenter_instance
            )
            for row in rows
        ]
        instances: list[str] = []
        if default_vcenter_instance:
            instances.append(default_vcenter_instance)
        return cls(
            vms=vms,
            instances=instances or None,
            unreachable_instances=unreachable_instances,
        )

    @classmethod
    def from_csv_file(
        cls,
        path: str | Path,
        *,
        default_vcenter_instance: Optional[str] = None,
        unreachable_instances: Optional[Iterable[str]] = None,
    ) -> MultiVCenterInventoryProvider:
        """Construct MultiVCenterInventoryProvider from a CSV / RVTools export file."""
        file_path = Path(path)
        with file_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return cls.from_csv_rows(
                reader,
                default_vcenter_instance=default_vcenter_instance,
                unreachable_instances=unreachable_instances,
            )


class VmPowerStateCollector(SignalCollector):
    """Evaluate VM power state and Guest Tools heartbeat across multiple vCenter instances."""

    signal_type = SignalType.VM_POWER_STATE

    def __init__(
        self,
        provider: Optional[HypervisorInventoryProvider] = None,
        *,
        inactive_threshold_days: Optional[float] = None,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "vcenter.vm_power_state",
    ) -> None:
        if inactive_threshold_days is not None:
            if isinstance(inactive_threshold_days, bool) or not isinstance(
                inactive_threshold_days, (int, float)
            ):
                raise ValueError("inactive_threshold_days must be a non-negative number")
            if float(inactive_threshold_days) < 0.0:
                raise ValueError("inactive_threshold_days must be non-negative")
            self.inactive_threshold_days: Optional[float] = float(
                inactive_threshold_days
            )
        else:
            self.inactive_threshold_days = None

        self.provider = provider
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = source

    def evaluate(
        self,
        target: Any,
        *,
        provider: Optional[HypervisorInventoryProvider] = None,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        arp_entries: Optional[Sequence[ArpEntry]] = None,
        ports: Optional[Sequence[Port]] = None,
        bios_uuid: Optional[str] = None,
        vcenter_instance: Optional[str] = None,
        vm_moref: Optional[str] = None,
        mac_addresses: Optional[Sequence[str]] = None,
        inactive_threshold_days: Optional[float] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate VM power state and Guest Tools correlation for an inventory target."""
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (
                self.evaluation_time
                if self.evaluation_time is not None
                else resolve_evaluation_time(None)
            )
        )

        threshold_days = (
            self.inactive_threshold_days
            if inactive_threshold_days is None
            else float(inactive_threshold_days)
        )
        if threshold_days is not None and threshold_days < 0.0:
            raise ValueError("inactive_threshold_days must be non-negative")

        active_provider = provider if provider is not None else self.provider

        # Direct HypervisorVmRecord evaluation support
        if isinstance(target, HypervisorVmRecord):
            return self._build_signal_for_matched_vms(
                matched_vms=[target],
                correlation_key="direct_vm_record",
                eval_dt=eval_dt,
                threshold_days=threshold_days,
            )

        # Non-Equipment physical network entities (NetworkDevice, Port, etc.)
        if isinstance(target, (NetworkDevice, Port)):
            label = (
                f"NetworkDevice {target.hostname} ({target.device_id})"
                if isinstance(target, NetworkDevice)
                else f"Port {target.device_id}:{target.name} ({target.port_id})"
            )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"{label}: physical network hardware; VM power state is not applicable",
                source=self.source,
            )

        if not isinstance(target, Equipment):
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"Target {type(target).__name__} is not a virtual machine Equipment record",
                source=self.source,
            )

        uuids, inst_hint, moref_hint, _, has_vm_hint = _extract_equipment_vm_hints(
            target,
            bios_uuid=bios_uuid,
            vcenter_instance=vcenter_instance,
            vm_moref=vm_moref,
            mac_addresses=mac_addresses,
        )

        # If provider is missing
        if active_provider is None:
            if has_vm_hint:
                return ValidationSignal(
                    signal_type=self.signal_type,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=None,
                    age_seconds=None,
                    details=(
                        f"Equipment {target.name} ({target.equipment_id}): "
                        "no vCenter inventory provider available to query VM power state"
                    ),
                    source=self.source,
                )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}) "
                    f"[category={target.category.value}]: physical/non-VM equipment"
                ),
                source=self.source,
            )

        matched_vms, correlation_key = active_provider.correlate_vms(
            target,
            site=site,
            ip_addresses=ip_addresses,
            arp_entries=arp_entries,
            ports=ports,
            bios_uuid=bios_uuid,
            vcenter_instance=vcenter_instance,
            vm_moref=vm_moref,
            mac_addresses=mac_addresses,
        )

        # If physical hardware (non-VM category, no VM hints) and not found in vCenter -> NOT_APPLICABLE
        if not matched_vms and not has_vm_hint:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}) "
                    f"[category={target.category.value}]: physical/non-VM equipment "
                    "with no matching vCenter record"
                ),
                source=self.source,
            )

        unreachable_set = active_provider.unreachable_instances()
        configured_set = active_provider.configured_instances()

        # Check if any matched VM is POWERED_ON
        powered_on_vms = [
            vm for vm in matched_vms if vm.power_state is VmPowerState.POWERED_ON
        ]
        if powered_on_vms:
            return self._build_signal_for_matched_vms(
                matched_vms=matched_vms,
                correlation_key=correlation_key or "vcenter",
                eval_dt=eval_dt,
                threshold_days=threshold_days,
            )

        # Check if target's pinned vCenter instance or candidate vCenter instances are unreachable
        target_inst_unreachable = False
        if inst_hint:
            if isinstance(active_provider, MultiVCenterInventoryProvider):
                target_inst_unreachable = active_provider.is_instance_unreachable(
                    inst_hint
                )
            else:
                target_inst_unreachable = any(
                    _instances_match(inst_hint, u) for u in unreachable_set
                )

        if matched_vms:
            # All matched VMs are POWERED_OFF or SUSPENDED.
            # If the target's explicitly associated vCenter is unreachable or another configured
            # vCenter is unreachable (where a migrated active copy could live), check reachability.
            if target_inst_unreachable:
                return ValidationSignal(
                    signal_type=self.signal_type,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=None,
                    age_seconds=None,
                    details=(
                        f"Equipment {target.name} ({target.equipment_id}): "
                        f"target vCenter instance {inst_hint!r} is unreachable "
                        f"(only inactive copy found on reachable vCenter)"
                    ),
                    source=self.source,
                )
            return self._build_signal_for_matched_vms(
                matched_vms=matched_vms,
                correlation_key=correlation_key or "vcenter",
                eval_dt=eval_dt,
                threshold_days=threshold_days,
            )

        # No matched VMs found across reachable vCenter instances
        if target_inst_unreachable:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.UNREACHABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}): "
                    f"vCenter instance {inst_hint!r} is unreachable"
                ),
                source=self.source,
            )

        if unreachable_set:
            unreach_list = ", ".join(sorted(unreachable_set))
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.UNREACHABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}): "
                    f"not found in reachable vCenter instances and vCenter instance(s) "
                    f"[{unreach_list}] are unreachable"
                ),
                source=self.source,
            )

        if not configured_set:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.UNREACHABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"Equipment {target.name} ({target.equipment_id}): "
                    "no configured vCenter instances available"
                ),
                source=self.source,
            )

        # All configured vCenter instances are reachable and the VM is absent from all of them
        checked_instances = ", ".join(sorted(configured_set))
        hint_parts: list[str] = []
        if uuids:
            hint_parts.append(f"bios_uuid={uuids[0]}")
        if inst_hint:
            hint_parts.append(f"vcenter_instance={inst_hint}")
        if moref_hint:
            hint_parts.append(f"vm_moref={moref_hint}")
        hint_summary = f" ({', '.join(hint_parts)})" if hint_parts else ""

        return ValidationSignal(
            signal_type=self.signal_type,
            status=SignalStatus.INACTIVE,
            observed_at=eval_dt,
            age_seconds=None,
            details=(
                f"Equipment {target.name} ({target.equipment_id}){hint_summary}: "
                f"orphaned/missing VM not found in any reachable vCenter instance [{checked_instances}]"
            ),
            source=self.source,
        )

    def _build_signal_for_matched_vms(
        self,
        *,
        matched_vms: Sequence[HypervisorVmRecord],
        correlation_key: str,
        eval_dt: datetime,
        threshold_days: Optional[float],
    ) -> ValidationSignal:
        powered_on = [
            vm for vm in matched_vms if vm.power_state is VmPowerState.POWERED_ON
        ]

        if powered_on:
            # Prefer a POWERED_ON VM with healthy Guest Tools heartbeat and latest timestamp
            chosen = max(
                powered_on,
                key=lambda vm: (
                    1 if vm.has_healthy_tools_heartbeat else 0,
                    vm.last_updated.timestamp() if vm.last_updated is not None else 0.0,
                ),
            )
            obs_at, age_sec = self._resolve_observation_age(chosen, eval_dt)

            tools_str = (
                chosen.guest_tools_status.value
                if chosen.guest_tools_status is not None
                else "unknown"
            )
            hb_str = chosen.tools_heartbeat or "unknown"
            os_str = chosen.guest_os_family or "unknown"

            extra_notes: list[str] = []
            if chosen.has_healthy_tools_heartbeat:
                extra_notes.append(
                    f"Guest Tools heartbeat active ({tools_str}, heartbeat={hb_str}; bonus confidence)"
                )
            else:
                extra_notes.append(
                    f"Guest Tools status={tools_str}, heartbeat={hb_str}"
                )

            if chosen.is_windows:
                if chosen.icmp_blocked_by_host_firewall:
                    extra_notes.append(
                        "Windows VM with host firewall blocking ICMP (vCenter power state + Guest Tools authoritative)"
                    )
                else:
                    extra_notes.append("Windows VM")
            elif chosen.icmp_blocked_by_host_firewall:
                extra_notes.append("host firewall blocks ICMP")

            if len(matched_vms) > 1:
                all_insts = ", ".join(
                    f"{vm.vcenter_instance}:{vm.vm_moref}({vm.power_state.value})"
                    for vm in matched_vms
                )
                extra_notes.append(f"multi-vCenter matches=[{all_insts}]")

            notes_suffix = f"; {'; '.join(extra_notes)}" if extra_notes else ""
            details = (
                f"VM {chosen.vm_name} ({chosen.vm_moref}) on {chosen.vcenter_instance} "
                f"is {chosen.power_state.value} [matched by {correlation_key}, os={os_str}]"
                f"{notes_suffix}"
            )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.ACTIVE,
                observed_at=obs_at,
                age_seconds=age_sec,
                details=details,
                source=self.source,
            )

        # Otherwise all matched VMs are POWERED_OFF or SUSPENDED
        chosen = max(
            matched_vms,
            key=lambda vm: (
                1 if vm.power_state is VmPowerState.SUSPENDED else 0,
                vm.last_updated.timestamp() if vm.last_updated is not None else 0.0,
            ),
        )
        obs_at, age_sec = self._resolve_observation_age(chosen, eval_dt)

        tools_str = (
            chosen.guest_tools_status.value
            if chosen.guest_tools_status is not None
            else "unknown"
        )
        hb_str = chosen.tools_heartbeat or "unknown"
        os_str = chosen.guest_os_family or "unknown"

        inactivity_ref_dt = chosen.power_state_changed_at or chosen.last_updated
        threshold_note = ""
        if threshold_days is not None and inactivity_ref_dt is not None:
            inactivity_seconds = max(0.0, (eval_dt - inactivity_ref_dt).total_seconds())
            inactivity_days = inactivity_seconds / SECONDS_PER_DAY
            if inactivity_days > threshold_days:
                threshold_note = (
                    f"; inactive for {inactivity_days:.2f}d (> threshold {threshold_days:g}d)"
                )
            else:
                threshold_note = (
                    f"; inactive for {inactivity_days:.2f}d (<= threshold {threshold_days:g}d)"
                )

        details = (
            f"VM {chosen.vm_name} ({chosen.vm_moref}) on {chosen.vcenter_instance} "
            f"is {chosen.power_state.value} [matched by {correlation_key}, os={os_str}, "
            f"tools={tools_str}, heartbeat={hb_str}]{threshold_note}"
        )
        return ValidationSignal(
            signal_type=self.signal_type,
            status=SignalStatus.INACTIVE,
            observed_at=obs_at,
            age_seconds=age_sec,
            details=details,
            source=self.source,
        )

    @staticmethod
    def _resolve_observation_age(
        vm: HypervisorVmRecord, eval_dt: datetime
    ) -> tuple[Optional[datetime], Optional[float]]:
        ref_dt = vm.last_updated or vm.power_state_changed_at
        if ref_dt is None:
            return None, None
        obs_utc = normalize_utc_datetime(ref_dt, field_name="last_updated")
        age_seconds = max(0.0, (eval_dt - obs_utc).total_seconds())
        return obs_utc, age_seconds


__all__ = [
    "GuestToolsStatus",
    "HypervisorInventoryProvider",
    "HypervisorVmRecord",
    "MultiVCenterInventoryProvider",
    "VmNicBinding",
    "VmPowerState",
    "VmPowerStateCollector",
    "normalize_guest_tools_status",
    "normalize_vm_power_state",
]
