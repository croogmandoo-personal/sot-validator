"""Read-only Source of Truth (SoT) client interface, guardrails, and fixture adapter."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional, Sequence
from urllib.parse import parse_qs, urlsplit

from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
)

_ALLOWED_HTTP_METHODS = frozenset({"GET", "HEAD"})

_BLOCKED_PATH_PREFIXES = (
    "/actions/port-admin",
    "/actions/poe-toggle",
    "/actions/port-bounce",
    "/actions/vlan-assign",
    "/actions/delete",
    "/api/cmd",
)

_BLOCKED_PATH_SEGMENTS = (
    "port-enable",
    "port-disable",
    "poe-control",
    "poe-toggle",
    "port-admin",
    "delete",
)

_BLOCKED_QUERY_KEYS = ("action", "cmd")

_BLOCKED_QUERY_VALUES = frozenset(
    {
        "enable",
        "disable",
        "toggle",
        "reset",
        "delete",
        "bounce",
        "poe",
        "write",
        "set",
    }
)


class ReadOnlyViolationError(RuntimeError):
    """Raised when an adapter attempts a non-read-only HTTP, URL, or SQL operation."""


def validate_read_only_request(method: str, url: str) -> None:
    """Validate that an HTTP method and URL strictly conform to Phase 1 read-only rules."""
    if not isinstance(method, str) or not method.strip():
        raise ReadOnlyViolationError("HTTP method must be a non-empty string")

    normalized_method = method.strip().upper()
    if normalized_method not in _ALLOWED_HTTP_METHODS:
        raise ReadOnlyViolationError(
            f"HTTP method {normalized_method!r} is forbidden in read-only mode; "
            f"only {sorted(_ALLOWED_HTTP_METHODS)} are allowed"
        )

    parsed = urlsplit(url)
    path_lower = (parsed.path or "/").lower()

    for blocked_prefix in _BLOCKED_PATH_PREFIXES:
        if path_lower == blocked_prefix or path_lower.startswith(blocked_prefix + "/") or (
            blocked_prefix in path_lower
        ):
            raise ReadOnlyViolationError(
                f"URL path {parsed.path!r} matches forbidden mutating endpoint {blocked_prefix!r}"
            )

    segments = [seg for seg in path_lower.split("/") if seg]
    for seg in segments:
        for blocked_seg in _BLOCKED_PATH_SEGMENTS:
            if seg == blocked_seg or blocked_seg in seg:
                raise ReadOnlyViolationError(
                    f"URL path segment {seg!r} in {url!r} is forbidden in read-only mode"
                )

    if parsed.query:
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query_params.items():
            if key.strip().lower() in _BLOCKED_QUERY_KEYS:
                for val in values:
                    val_lower = val.strip().lower()
                    if val_lower in _BLOCKED_QUERY_VALUES:
                        raise ReadOnlyViolationError(
                            f"Query parameter {key}={val!r} in {url!r} is forbidden in read-only mode"
                        )


class SoTClient(ABC):
    """Abstract read-only client for extracting site inventory from the legacy SoT."""

    @abstractmethod
    def list_sites(self) -> list[Site]:
        """Return available Site records sorted by site_id."""

    def list_site_ids(self) -> list[str]:
        """Return sorted list of available site_id identifiers."""
        return [site.site_id for site in self.list_sites()]

    @abstractmethod
    def get_site(self, site_id: str) -> Site:
        """Return a complete Site record with populated child entities. Raises KeyError if unknown."""

    def get_devices(self, site_id: str) -> list[NetworkDevice]:
        """Return network devices for the given site_id."""
        return list(self.get_site(site_id).devices)

    def get_ports(
        self, site_id: str, device_id: Optional[str] = None
    ) -> list[Port]:
        """Return ports for the given site_id, optionally filtered by device_id."""
        ports: list[Port] = []
        for device in self.get_devices(site_id):
            if device_id is not None and device.device_id != device_id:
                continue
            ports.extend(device.ports)
        return ports

    def get_vlans(self, site_id: str) -> list[VLAN]:
        """Return VLANs for the given site_id."""
        return list(self.get_site(site_id).vlans)

    def get_subnets(self, site_id: str) -> list[Subnet]:
        """Return subnets for the given site_id."""
        return list(self.get_site(site_id).subnets)

    def get_ip_addresses(self, site_id: str) -> list[IPAddress]:
        """Return IP addresses (and ARP metadata) for the given site_id."""
        return list(self.get_site(site_id).ip_addresses)

    def get_equipment(self, site_id: str) -> list[Equipment]:
        """Return network-attached equipment for the given site_id."""
        return list(self.get_site(site_id).equipment)


def _build_default_fixture_site(index: int) -> Site:
    """Build a deterministic fixture Site for 1-indexed site number `index` (`10.{index}.0.0/16`)."""
    site_id = f"site-{index:03d}"
    ts_recent = datetime(2026, 2, 10, 12, 0, 0, tzinfo=timezone.utc)
    ts_intermediate = datetime(2026, 1, 25, 12, 0, 0, tzinfo=timezone.utc)
    ts_stale = datetime(2025, 9, 1, 8, 30, 0, tzinfo=timezone.utc)

    sw_id = f"{site_id}-sw-01"
    vlan_mgmt_id = f"{site_id}-vlan-1"
    vlan_srv_id = f"{site_id}-vlan-10"
    vlan_ups_id = f"{site_id}-vlan-20"

    sub_mgmt_id = f"{site_id}-sub-1"
    sub_srv_id = f"{site_id}-sub-10"
    sub_ups_id = f"{site_id}-sub-20"

    eq_vm_win_id = f"{site_id}-vm-win-01"
    eq_ups_id = f"{site_id}-ups-01"
    eq_srv_id = f"{site_id}-srv-01"
    eq_san_id = f"{site_id}-san-01"
    eq_spare_id = f"{site_id}-spare-01"

    p1_id = f"{sw_id}-p1"
    p2_id = f"{sw_id}-p2"
    p3_id = f"{sw_id}-p3"

    vm_mac = f"00:50:56:{index:02x}:10:11"
    ups_mac = f"00:c0:b7:{index:02x}:20:10"
    srv_mac = f"00:1b:21:{index:02x}:10:25"

    ports = [
        Port(
            port_id=p1_id,
            device_id=sw_id,
            name="1:1",
            admin_status="up",
            oper_status="up",
            poe_status="off",
            connected_device_id=eq_vm_win_id,
            connected_mac=vm_mac,
            vlan_id=vlan_srv_id,
        ),
        Port(
            port_id=p2_id,
            device_id=sw_id,
            name="1:2",
            admin_status="up",
            oper_status="up",
            poe_status="delivering",
            connected_device_id=eq_ups_id,
            connected_mac=ups_mac,
            vlan_id=vlan_ups_id,
        ),
        Port(
            port_id=p3_id,
            device_id=sw_id,
            name="1:3",
            admin_status="up",
            oper_status="down",
            poe_status="off",
            connected_device_id=eq_srv_id,
            connected_mac=srv_mac,
            vlan_id=vlan_srv_id,
        ),
    ]

    devices = [
        NetworkDevice(
            device_id=sw_id,
            site_id=site_id,
            hostname=f"ext-sw-{index:03d}-01",
            management_ip=f"10.{index}.1.2",
            vendor="Extreme Networks",
            model="X460-G2-48p-10GE4",
            role="access",
            last_seen=ts_recent,
            ports=ports,
        )
    ]

    vlans = [
        VLAN(
            vlan_id=vlan_mgmt_id,
            site_id=site_id,
            name="Management",
            subnet_id=sub_mgmt_id,
            cidr=f"10.{index}.1.0/24",
            gateway=f"10.{index}.1.1",
        ),
        VLAN(
            vlan_id=vlan_srv_id,
            site_id=site_id,
            name="Servers_VMs",
            subnet_id=sub_srv_id,
            cidr=f"10.{index}.10.0/24",
            gateway=f"10.{index}.10.1",
        ),
        VLAN(
            vlan_id=vlan_ups_id,
            site_id=site_id,
            name="Facilities_UPS",
            subnet_id=sub_ups_id,
            cidr=f"10.{index}.20.0/24",
            gateway=f"10.{index}.20.1",
        ),
    ]

    subnets = [
        Subnet(
            subnet_id=sub_mgmt_id,
            site_id=site_id,
            cidr=f"10.{index}.1.0/24",
            vlan_id=vlan_mgmt_id,
            gateway=f"10.{index}.1.1",
            name="Management /24",
        ),
        Subnet(
            subnet_id=sub_srv_id,
            site_id=site_id,
            cidr=f"10.{index}.10.0/24",
            vlan_id=vlan_srv_id,
            gateway=f"10.{index}.10.1",
            name="Servers & Windows VMs /24",
        ),
        Subnet(
            subnet_id=sub_ups_id,
            site_id=site_id,
            cidr=f"10.{index}.20.0/24",
            vlan_id=vlan_ups_id,
            gateway=f"10.{index}.20.1",
            name="APC UPS Management /24",
        ),
    ]

    vm_ip = f"10.{index}.10.11"
    ups_ip = f"10.{index}.20.10"
    srv_ip = f"10.{index}.10.25"

    vm_arp = ArpEntry(
        ip=vm_ip,
        arp_mac=vm_mac,
        arp_last_seen=ts_recent,
        arp_source_device_id=sw_id,
        subnet_id=sub_srv_id,
    )
    ups_arp = ArpEntry(
        ip=ups_ip,
        arp_mac=ups_mac,
        arp_last_seen=ts_recent,
        arp_source_device_id=sw_id,
        subnet_id=sub_ups_id,
    )

    ip_addresses = [
        IPAddress(
            ip=vm_ip,
            subnet_id=sub_srv_id,
            assigned_object_type="Equipment",
            assigned_object_id=eq_vm_win_id,
            arp_mac=vm_mac,
            arp_last_seen=ts_recent,
            arp_source_device_id=sw_id,
            arp_entry=vm_arp,
        ),
        IPAddress(
            ip=ups_ip,
            subnet_id=sub_ups_id,
            assigned_object_type="Equipment",
            assigned_object_id=eq_ups_id,
            arp_mac=ups_mac,
            arp_last_seen=ts_recent,
            arp_source_device_id=sw_id,
            arp_entry=ups_arp,
        ),
        IPAddress(
            ip=srv_ip,
            subnet_id=sub_srv_id,
            assigned_object_type="Equipment",
            assigned_object_id=eq_srv_id,
            arp_mac=None,
            arp_last_seen=None,
            arp_source_device_id=None,
            arp_entry=None,
        ),
    ]

    equipment = [
        Equipment(
            equipment_id=eq_vm_win_id,
            site_id=site_id,
            name=f"win-srv-{index:03d}-01",
            category=EquipmentCategory.VM,
            assigned_ips=[vm_ip],
            connected_ports=[p1_id],
            hypervisor_id=f"vcenter-{(index - 1) % 2 + 1:02d}.corp.internal",
            power_state="poweredOn",
            last_seen=ts_recent,
        ),
        Equipment(
            equipment_id=eq_ups_id,
            site_id=site_id,
            name=f"apc-ups-{index:03d}-01",
            category=EquipmentCategory.UPS,
            assigned_ips=[ups_ip],
            connected_ports=[p2_id],
            hypervisor_id=None,
            power_state="online",
            last_seen=ts_recent,
        ),
        Equipment(
            equipment_id=eq_srv_id,
            site_id=site_id,
            name=f"legacy-srv-{index:03d}-01",
            category=EquipmentCategory.SERVER,
            assigned_ips=[srv_ip],
            connected_ports=[p3_id],
            hypervisor_id=None,
            power_state="poweredOff",
            last_seen=ts_stale,
        ),
        Equipment(
            equipment_id=eq_san_id,
            site_id=site_id,
            name=f"san-array-{index:03d}-01",
            category=EquipmentCategory.SAN,
            assigned_ips=[f"10.{index}.10.40"],
            connected_ports=[],
            hypervisor_id=None,
            power_state=None,
            last_seen=ts_intermediate,
        ),
        Equipment(
            equipment_id=eq_spare_id,
            site_id=site_id,
            name=f"spare-chassis-{index:03d}-01",
            category=EquipmentCategory.OTHER,
            assigned_ips=[],
            connected_ports=[],
            hypervisor_id=None,
            power_state=None,
            last_seen=None,
        ),
    ]

    return Site(
        site_id=site_id,
        name=f"Site {index:03d} (10.{index}.0.0/16)",
        address=f"{index * 100} Enterprise Way, Suite {index}",
        contact_info=f"site-{index:03d}-ops@example.internal",
        rooms=["MDF-1", "IDF-1"],
        devices=devices,
        vlans=vlans,
        subnets=subnets,
        ip_addresses=ip_addresses,
        equipment=equipment,
    )


class FixtureSoTClient(SoTClient):
    """Deterministic in-memory SoTClient for offline testing and validation."""

    def __init__(
        self,
        sites: Optional[Sequence[Site]] = None,
        *,
        fixture_path: Optional[Path | str] = None,
        num_sites: int = 3,
    ) -> None:
        if sites is not None:
            loaded_sites = [
                s if isinstance(s, Site) else Site.from_dict(s) for s in sites
            ]
        elif fixture_path is not None:
            raw_data: Any = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
            if isinstance(raw_data, dict) and "sites" in raw_data:
                site_items = raw_data["sites"]
            elif isinstance(raw_data, list):
                site_items = raw_data
            elif isinstance(raw_data, dict) and "site_id" in raw_data:
                site_items = [raw_data]
            else:
                raise ValueError(
                    f"Unsupported fixture JSON structure in {fixture_path!s}"
                )
            loaded_sites = [Site.from_dict(item) for item in site_items]
        else:
            if num_sites < 0:
                raise ValueError("num_sites must be non-negative")
            loaded_sites = [
                _build_default_fixture_site(i) for i in range(1, num_sites + 1)
            ]

        self._sites: dict[str, Site] = {
            site.site_id: site for site in sorted(loaded_sites, key=lambda s: s.site_id)
        }

    def list_sites(self) -> list[Site]:
        return [
            Site.from_dict(site.to_dict())
            for _, site in sorted(self._sites.items(), key=lambda kv: kv[0])
        ]

    def get_site(self, site_id: str) -> Site:
        if site_id not in self._sites:
            raise KeyError(f"Unknown site_id: {site_id!r}")
        return Site.from_dict(self._sites[site_id].to_dict())


__all__ = [
    "FixtureSoTClient",
    "ReadOnlyViolationError",
    "SoTClient",
    "validate_read_only_request",
]
