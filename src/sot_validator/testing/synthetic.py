"""Seeded, deterministic synthetic 100-site fleet generator for tests and perf budgets.

Every name is prefixed with ``synth-``, every domain ends in ``.example`` and
every MAC is locally administered (first octet ``02``). Site ``i`` (0-based)
owns ``10.(i+1).0.0/16`` and all emitted addresses fall inside one of that
site's ``/24`` subnets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import math
import random
from typing import Any, Optional

from sot_validator.classifier.engine import ClassificationPolicy
from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Site,
    Subnet,
    VLAN,
)
from sot_validator.signals.directory_dns import DhcpLeaseRecord
from sot_validator.topology.device_types import DeviceTypeCatalog
from sot_validator.topology.fdb_mapper import FdbEntry

DEFAULT_REFERENCE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
NAME_PREFIX = "synth-"
DOMAIN = "synth.example"
SWITCH_TEMPLATE_ID = "extreme-exos-48p"
UPS_TEMPLATE_ID = "apc-smart-ups"
ROUTER_TEMPLATE_ID = "unifi-multi-vlan-router"
SWITCH_PORT_COUNT = 48
# Port 1:48 is reserved for the uplink to the router on every switch
SWITCH_ACCESS_PORTS = SWITCH_PORT_COUNT - 1
UPLINK_PORT_NAME = f"1:{SWITCH_PORT_COUNT}"
# .0 network, .1 gateway, .2 UPS, .3-.9 switch management, .255 broadcast
FIRST_HOST_OCTET = 10
LAST_HOST_OCTET = 254
MAX_HOSTS_PER_SUBNET = LAST_HOST_OCTET - FIRST_HOST_OCTET + 1
UPS_OCTET = 2
FIRST_SWITCH_OCTET = 3
MAX_SITES = 254
MAX_SUBNETS_PER_SITE = 256
VM_SHARE = 0.6
ACTIVE_MAX_OFFSET_SECONDS = 6 * 3600
STALE_EXTRA_MAX_SECONDS = 60 * 86400

def _require_count(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _require_fraction(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number between 0 and 1")
    fraction = float(value)
    if not (0.0 <= fraction <= 1.0):
        raise ValueError(f"{name} must be between 0 and 1")
    return fraction


def _mac(site_octet: int, third: int, fourth: int, nic: int) -> str:
    return f"02:00:{site_octet:02x}:{third:02x}:{fourth:02x}:{nic:02x}"


def _pick(rng: random.Random, population: list[Any], fraction: float) -> list[Any]:
    """Return a seeded, ordered sample of ``round(fraction * len)`` items."""
    count = int(round(fraction * len(population)))
    if count <= 0:
        return []
    indices = sorted(rng.sample(range(len(population)), count))
    return [population[i] for i in indices]


@dataclass
class _Host:
    ip: str
    subnet: Subnet
    mac: str
    host_id: str
    name: str
    category: EquipmentCategory
    seen_at: datetime
    stale: bool = False
    orphan: bool = False
    duplicate: bool = False
    windows: bool = False
    port_id: Optional[str] = None


@dataclass
class SyntheticFleet:
    """Generated fleet: sites plus per-site FDB, ARP and DHCP observations."""

    seed: int
    reference_time: datetime
    sites: list[Site] = field(default_factory=list)
    fdb_entries: dict[str, list[FdbEntry]] = field(default_factory=dict)
    arp_entries: dict[str, list[ArpEntry]] = field(default_factory=dict)
    dhcp_leases: dict[str, list[DhcpLeaseRecord]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "reference_time": self.reference_time.isoformat(),
            "sites": [s.to_dict() for s in self.sites],
            "fdb_entries": {
                k: [e.to_dict() for e in v] for k, v in self.fdb_entries.items()
            },
            "arp_entries": {
                k: [e.to_dict() for e in v] for k, v in self.arp_entries.items()
            },
            "dhcp_leases": {
                k: [e.to_dict() for e in v] for k, v in self.dhcp_leases.items()
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    def drift(self, site: Site, *, change_fraction: float = 0.05) -> Site:
        """Return a drifted copy of ``site`` seeded by this fleet's seed."""
        return drift_site(
            site,
            seed=self.seed,
            reference_time=self.reference_time,
            change_fraction=change_fraction,
        )


def drift_site(
    site: Site,
    *,
    seed: int,
    reference_time: datetime = DEFAULT_REFERENCE_TIME,
    change_fraction: float = 0.05,
) -> Site:
    """Return a new Site with seeded host removals, additions and MAC changes."""
    fraction = _require_fraction(change_fraction, "change_fraction")
    drifted = Site.from_dict(site.to_dict())
    rng = random.Random(f"{NAME_PREFIX}drift:{seed}:{site.site_id}:{fraction!r}")

    equipment_ids = {e.equipment_id for e in drifted.equipment}
    host_records = [
        r
        for r in drifted.ip_addresses
        if r.assigned_object_type == "Equipment"
        and r.assigned_object_id in equipment_ids
    ]
    removed = _pick(rng, host_records, fraction)
    removed_ips = {r.ip for r in removed}
    remaining = [r for r in host_records if r.ip not in removed_ips]
    changed = _pick(rng, remaining, fraction)

    removed_ids = {r.assigned_object_id for r in removed}
    drifted.ip_addresses = [r for r in drifted.ip_addresses if r.ip not in removed_ips]
    drifted.equipment = [
        e for e in drifted.equipment if e.equipment_id not in removed_ids
    ]
    for device in drifted.devices:
        for port in device.ports:
            if port.connected_device_id in removed_ids:
                port.connected_device_id = None
                port.connected_mac = None
                port.oper_status = "down"

    for record in changed:
        octets = [int(o) for o in record.ip.split(".")]
        record.arp_mac = _mac(octets[1], octets[2], octets[3], 0xD1)

    # Added hosts take addresses that were never used in the baseline snapshot
    used_ips = {r.ip for r in site.ip_addresses}
    free: list[tuple[str, str]] = []
    for subnet in drifted.subnets:
        prefix = subnet.cidr.rsplit(".", 1)[0]
        for n in range(FIRST_HOST_OCTET, LAST_HOST_OCTET + 1):
            if f"{prefix}.{n}" not in used_ips:
                free.append((f"{prefix}.{n}", subnet.subnet_id))
    add_count = min(len(removed), len(free))
    picks = sorted(rng.sample(range(len(free)), add_count)) if add_count else []
    for added, pick in enumerate(picks):
        ip, subnet_id = free[pick]
        octets = [int(o) for o in ip.split(".")]
        equipment_id = f"{site.site_id}-new-{added:04d}"
        seen_at = reference_time - timedelta(
            seconds=rng.randint(0, ACTIVE_MAX_OFFSET_SECONDS)
        )
        drifted.equipment.append(
            Equipment(
                equipment_id=equipment_id,
                site_id=site.site_id,
                name=equipment_id,
                category=EquipmentCategory.SERVER,
                assigned_ips=[ip],
                last_seen=seen_at,
            )
        )
        drifted.ip_addresses.append(
            IPAddress(
                ip=ip,
                subnet_id=subnet_id,
                assigned_object_type="Equipment",
                assigned_object_id=equipment_id,
                arp_mac=_mac(octets[1], octets[2], octets[3], 0xA1),
                arp_last_seen=seen_at,
            )
        )
    return drifted


class SyntheticFleetGenerator:
    """Builds realistic, obviously fake `Site` fleets from a single integer seed."""

    def __init__(
        self,
        seed: int,
        sites: int = 100,
        subnets_per_site: int = 10,
        hosts_per_subnet: int = 60,
        *,
        stale_fraction: float = 0.10,
        duplicate_fraction: float = 0.02,
        orphan_fraction: float = 0.03,
        windows_vm_fraction: float = 0.9,
        reference_time: datetime = DEFAULT_REFERENCE_TIME,
    ) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        self.seed = seed
        self.sites = _require_count(sites, "sites", minimum=1, maximum=MAX_SITES)
        self.subnets_per_site = _require_count(
            subnets_per_site,
            "subnets_per_site",
            minimum=1,
            maximum=MAX_SUBNETS_PER_SITE,
        )
        self.hosts_per_subnet = _require_count(
            hosts_per_subnet,
            "hosts_per_subnet",
            minimum=0,
            maximum=MAX_HOSTS_PER_SUBNET,
        )
        self.stale_fraction = _require_fraction(stale_fraction, "stale_fraction")
        self.duplicate_fraction = _require_fraction(
            duplicate_fraction, "duplicate_fraction"
        )
        self.orphan_fraction = _require_fraction(orphan_fraction, "orphan_fraction")
        self.windows_vm_fraction = _require_fraction(
            windows_vm_fraction, "windows_vm_fraction"
        )
        if not isinstance(reference_time, datetime) or reference_time.tzinfo is None:
            raise ValueError("reference_time must be a timezone-aware datetime")
        self.reference_time = reference_time
        self.stale_after_days = ClassificationPolicy().stale_after_days
        self._catalog = DeviceTypeCatalog()

    def drift(self, site: Site, *, change_fraction: float = 0.05) -> Site:
        """Return a new drifted copy of ``site`` for snapshot diffing."""
        return drift_site(
            site,
            seed=self.seed,
            reference_time=self.reference_time,
            change_fraction=change_fraction,
        )

    def generate(self) -> SyntheticFleet:
        fleet = SyntheticFleet(seed=self.seed, reference_time=self.reference_time)
        for index in range(self.sites):
            site, fdb, arp, leases = self._generate_site(index)
            fleet.sites.append(site)
            fleet.fdb_entries[site.site_id] = fdb
            fleet.arp_entries[site.site_id] = arp
            fleet.dhcp_leases[site.site_id] = leases
        return fleet

    def _offset_time(self, rng: random.Random, stale: bool) -> datetime:
        if stale:
            seconds = int(self.stale_after_days * 86400) + rng.randint(
                86400, STALE_EXTRA_MAX_SECONDS
            )
        else:
            seconds = rng.randint(0, ACTIVE_MAX_OFFSET_SECONDS)
        return self.reference_time - timedelta(seconds=seconds)

    def _generate_site(
        self, index: int
    ) -> tuple[Site, list[FdbEntry], list[ArpEntry], list[DhcpLeaseRecord]]:
        rng = random.Random(f"{NAME_PREFIX}fleet:{self.seed}:site:{index}")
        site_octet = index + 1
        tag = f"s{site_octet:03d}"
        site_id = f"{NAME_PREFIX}site-{site_octet:03d}"
        site = Site(
            site_id=site_id,
            name=f"{NAME_PREFIX}site {site_octet:03d}",
            address=f"{site_octet} Synthetic Way, Example City",
            contact_info=f"noc-{tag}@{DOMAIN}",
            rooms=[f"{NAME_PREFIX}{tag}-mdf"],
        )

        thirds = sorted(rng.sample(range(256), self.subnets_per_site))
        for third in thirds:
            vlan_id = str(100 + third)
            subnet_id = f"{site_id}-net-{third:03d}"
            cidr = f"10.{site_octet}.{third}.0/24"
            gateway = f"10.{site_octet}.{third}.1"
            site.subnets.append(
                Subnet(
                    subnet_id=subnet_id,
                    site_id=site_id,
                    cidr=cidr,
                    vlan_id=vlan_id,
                    gateway=gateway,
                    name=f"{NAME_PREFIX}{tag}-vlan{vlan_id}",
                )
            )
            site.vlans.append(
                VLAN(
                    vlan_id=vlan_id,
                    site_id=site_id,
                    name=f"{NAME_PREFIX}{tag}-vlan{vlan_id}",
                    subnet_id=subnet_id,
                    cidr=cidr,
                    gateway=gateway,
                )
            )

        router_id = f"{NAME_PREFIX}{tag}-rtr01"
        router = self._catalog.instantiate_device(
            ROUTER_TEMPLATE_ID,
            device_id=router_id,
            site_id=site_id,
            hostname=router_id,
            management_ip=site.subnets[0].gateway,
            last_seen=self._offset_time(rng, False),
        )
        site.devices.append(router)

        first = site.subnets[0]
        first_third = thirds[0]
        ups_id = f"{NAME_PREFIX}{tag}-ups01"
        ups_ip = f"10.{site_octet}.{first_third}.{UPS_OCTET}"
        ups_mac = _mac(site_octet, first_third, UPS_OCTET, 0)
        ups_seen = self._offset_time(rng, False)
        ups = self._catalog.instantiate_device(
            UPS_TEMPLATE_ID,
            device_id=ups_id,
            site_id=site_id,
            hostname=ups_id,
            management_ip=ups_ip,
            last_seen=ups_seen,
        )

        arp: list[ArpEntry] = []
        fdb: list[FdbEntry] = []
        leases: list[DhcpLeaseRecord] = []
        infra_records: list[IPAddress] = []

        def add_infra_ip(
            ip: str, subnet: Subnet, mac: str, object_id: str, seen_at: datetime
        ) -> None:
            infra_records.append(
                IPAddress(
                    ip=ip,
                    subnet_id=subnet.subnet_id,
                    assigned_object_type="NetworkDevice",
                    assigned_object_id=object_id,
                    arp_mac=mac,
                    arp_last_seen=seen_at,
                    arp_source_device_id=router_id,
                )
            )
            arp.append(
                ArpEntry(
                    ip=ip,
                    arp_mac=mac,
                    arp_last_seen=seen_at,
                    arp_source_device_id=router_id,
                    subnet_id=subnet.subnet_id,
                )
            )

        for subnet, third in zip(site.subnets, thirds):
            add_infra_ip(
                subnet.gateway,
                subnet,
                _mac(site_octet, third, 1, 0),
                router_id,
                router.last_seen,
            )
        add_infra_ip(ups_ip, first, ups_mac, ups_id, ups_seen)

        hosts: list[_Host] = []
        for subnet, third in zip(site.subnets, thirds):
            octets = sorted(
                rng.sample(
                    range(FIRST_HOST_OCTET, LAST_HOST_OCTET + 1), self.hosts_per_subnet
                )
            )
            for octet in octets:
                is_vm = rng.random() < VM_SHARE
                host_id = f"{NAME_PREFIX}{tag}-{third:03d}-{octet:03d}"
                hosts.append(
                    _Host(
                        ip=f"10.{site_octet}.{third}.{octet}",
                        subnet=subnet,
                        mac=_mac(site_octet, third, octet, 1),
                        host_id=host_id,
                        name=host_id,
                        category=(
                            EquipmentCategory.VM if is_vm else EquipmentCategory.SERVER
                        ),
                        seen_at=self.reference_time,
                    )
                )

        for host in _pick(rng, hosts, self.stale_fraction):
            host.stale = True
        for host in _pick(rng, hosts, self.duplicate_fraction):
            host.duplicate = True
        for host in _pick(rng, hosts, self.orphan_fraction):
            host.orphan = True
        vms = [h for h in hosts if h.category is EquipmentCategory.VM]
        for host in _pick(rng, vms, self.windows_vm_fraction):
            host.windows = True
        for host in hosts:
            host.seen_at = self._offset_time(rng, host.stale)
            suffix = host.host_id[len(f"{NAME_PREFIX}{tag}-") :]
            if host.category is EquipmentCategory.VM:
                os_tag = "win" if host.windows else "lnx"
                host.name = f"{NAME_PREFIX}{tag}-{os_tag}-vm-{suffix}"
            else:
                host.name = f"{NAME_PREFIX}{tag}-srv-{suffix}"

        # Wired endpoints per subnet: physical servers, plus the UPS on the first subnet
        switch_seq = 0
        host_records: list[IPAddress] = []
        duplicate_records: list[IPAddress] = []
        for subnet_pos, (subnet, third) in enumerate(zip(site.subnets, thirds)):
            subnet_hosts = [h for h in hosts if h.subnet is subnet]
            wired: list[Any] = [
                h for h in subnet_hosts if h.category is EquipmentCategory.SERVER
            ]
            if subnet_pos == 0:
                wired.insert(0, ups)
            switch_count = max(1, math.ceil(len(wired) / SWITCH_ACCESS_PORTS))
            for k in range(switch_count):
                switch_seq += 1
                switch_id = f"{NAME_PREFIX}{tag}-sw{switch_seq:02d}"
                mgmt_octet = FIRST_SWITCH_OCTET + k
                switch_ip = f"10.{site_octet}.{third}.{mgmt_octet}"
                switch_seen = self._offset_time(rng, False)
                switch = self._catalog.instantiate_device(
                    SWITCH_TEMPLATE_ID,
                    device_id=switch_id,
                    site_id=site_id,
                    hostname=switch_id,
                    management_ip=switch_ip,
                    default_vlan_id=subnet.vlan_id,
                    last_seen=switch_seen,
                )
                site.devices.append(switch)
                add_infra_ip(
                    switch_ip,
                    subnet,
                    _mac(site_octet, third, mgmt_octet, 0),
                    switch_id,
                    switch_seen,
                )
                uplink = switch.ports[SWITCH_PORT_COUNT - 1]
                uplink.oper_status = "up"
                uplink.connected_device_id = router_id
                fdb.append(
                    FdbEntry(
                        device_id=switch_id,
                        port_name=UPLINK_PORT_NAME,
                        mac_address=_mac(site_octet, third, 1, 0),
                        vlan_id=subnet.vlan_id,
                    )
                )
                chunk = wired[k * SWITCH_ACCESS_PORTS : (k + 1) * SWITCH_ACCESS_PORTS]
                for port, endpoint in zip(switch.ports, chunk):
                    if isinstance(endpoint, NetworkDevice):
                        port.oper_status = "up"
                        port.connected_device_id = endpoint.device_id
                        port.connected_mac = ups_mac
                        fdb.append(
                            FdbEntry(
                                device_id=switch_id,
                                port_name=port.name,
                                mac_address=ups_mac,
                                vlan_id=subnet.vlan_id,
                            )
                        )
                        continue
                    port.oper_status = "down" if endpoint.stale else "up"
                    port.connected_mac = endpoint.mac
                    if not endpoint.orphan:
                        port.connected_device_id = endpoint.host_id
                    endpoint.port_id = port.port_id
                    fdb.append(
                        FdbEntry(
                            device_id=switch_id,
                            port_name=port.name,
                            mac_address=endpoint.mac,
                            vlan_id=subnet.vlan_id,
                        )
                    )

            for host in subnet_hosts:
                record = IPAddress(
                    ip=host.ip,
                    subnet_id=subnet.subnet_id,
                    assigned_object_type="Equipment",
                    assigned_object_id=(
                        f"{host.host_id}-missing" if host.orphan else host.host_id
                    ),
                    arp_mac=host.mac,
                    arp_last_seen=host.seen_at,
                    arp_source_device_id=router_id,
                )
                host_records.append(record)
                if host.duplicate:
                    duplicate_records.append(IPAddress.from_dict(record.to_dict()))
                arp.append(
                    ArpEntry(
                        ip=host.ip,
                        arp_mac=host.mac,
                        arp_last_seen=host.seen_at,
                        arp_source_device_id=router_id,
                        subnet_id=subnet.subnet_id,
                    )
                )
                leases.append(
                    DhcpLeaseRecord(
                        ip=host.ip,
                        hostname=f"{host.name}.{DOMAIN}",
                        mac_address=host.mac,
                        subnet_cidr=subnet.cidr,
                        status="expired" if host.stale else "active",
                        lease_expiration=host.seen_at if host.stale else None,
                        observed_at=host.seen_at,
                    )
                )
                if host.orphan:
                    continue
                is_vm = host.category is EquipmentCategory.VM
                if is_vm:
                    power_state = "poweredOff" if host.stale else "poweredOn"
                else:
                    power_state = None
                site.equipment.append(
                    Equipment(
                        equipment_id=host.host_id,
                        site_id=site_id,
                        name=host.name,
                        category=host.category,
                        assigned_ips=[host.ip],
                        connected_ports=[host.port_id] if host.port_id else [],
                        hypervisor_id=(
                            f"{NAME_PREFIX}{tag}-esx{(len(site.equipment) % 4) + 1:02d}"
                            if is_vm
                            else None
                        ),
                        power_state=power_state,
                        last_seen=host.seen_at,
                    )
                )

        site.devices.append(ups)
        site.ip_addresses = infra_records + host_records + duplicate_records
        return site, fdb, arp, leases


__all__ = [
    "DEFAULT_REFERENCE_TIME",
    "SyntheticFleet",
    "SyntheticFleetGenerator",
    "drift_site",
]
