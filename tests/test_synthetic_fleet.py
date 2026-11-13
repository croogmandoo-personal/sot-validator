import ipaddress
import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from sot_validator.classifier.engine import ClassificationPolicy
from sot_validator.discovery.monitor import SnapshotDiffEngine
from sot_validator.models import EquipmentCategory, Site
from sot_validator.signals.directory_dns import DhcpLeaseRecord
from sot_validator.testing import (
    SyntheticFleet,
    SyntheticFleetGenerator,
    run_pipeline,
)

SRC_DIR = Path(__file__).resolve().parents[1] / "src"

ZERO_FRACTIONS = {
    "stale_fraction": 0.0,
    "duplicate_fraction": 0.0,
    "orphan_fraction": 0.0,
}


def _small(seed: int = 7, **kwargs):
    params = {"sites": 3, "subnets_per_site": 3, "hosts_per_subnet": 10}
    params.update(kwargs)
    return SyntheticFleetGenerator(seed, **params).generate()


@pytest.fixture(scope="module")
def fleet() -> SyntheticFleet:
    return _small()


def _site_ips(site: Site, fleet: SyntheticFleet) -> list[str]:
    ips = [r.ip for r in site.ip_addresses]
    ips += [d.management_ip for d in site.devices if d.management_ip]
    ips += [s.gateway for s in site.subnets]
    ips += [v.gateway for v in site.vlans]
    ips += [ip for e in site.equipment for ip in e.assigned_ips]
    ips += [a.ip for a in fleet.arp_entries[site.site_id]]
    ips += [lease.ip for lease in fleet.dhcp_leases[site.site_id]]
    return ips


def _site_macs(site: Site, fleet: SyntheticFleet) -> list[str]:
    macs = [r.arp_mac for r in site.ip_addresses if r.arp_mac]
    macs += [p.connected_mac for d in site.devices for p in d.ports if p.connected_mac]
    macs += [a.arp_mac for a in fleet.arp_entries[site.site_id]]
    macs += [e.mac_address for e in fleet.fdb_entries[site.site_id]]
    macs += [lease.mac_address for lease in fleet.dhcp_leases[site.site_id]]
    return macs


def _host_records(site: Site):
    return [r for r in site.ip_addresses if r.assigned_object_type == "Equipment"]


def test_run_pipeline_produces_output_for_every_stage(fleet):
    timings = run_pipeline(fleet)
    assert timings.result_count > 0
    assert timings.port_classification_count > 0
    assert timings.drift_event_count > 0
    assert timings.html_length > 0
    for seconds in (
        timings.classification_seconds,
        timings.fdb_mapping_seconds,
        timings.snapshot_diff_seconds,
        timings.dashboard_seconds,
    ):
        assert seconds >= 0.0


def test_run_pipeline_does_not_mutate_fleet_sites(fleet):
    before = [s.to_json(indent=2) for s in fleet.sites]
    run_pipeline(fleet)
    assert [s.to_json(indent=2) for s in fleet.sites] == before


def test_same_seed_gives_byte_identical_fleet_and_snapshots():
    first = _small(seed=11)
    second = _small(seed=11)
    assert first.to_json() == second.to_json()
    assert [s.to_json(indent=2) for s in first.sites] == [
        s.to_json(indent=2) for s in second.sites
    ]


def test_different_seed_gives_different_fleet():
    assert _small(seed=11).to_json() != _small(seed=12).to_json()


def test_to_json_is_identical_across_interpreter_runs():
    script = (
        "import hashlib\n"
        "from sot_validator.testing import SyntheticFleetGenerator\n"
        "fleet = SyntheticFleetGenerator(seed=7, sites=2, subnets_per_site=2,"
        " hosts_per_subnet=5).generate()\n"
        "print(hashlib.sha256(fleet.to_json().encode()).hexdigest())\n"
    )
    digests = set()
    for hash_seed in ("1", "2"):
        out = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(SRC_DIR), "PYTHONHASHSEED": hash_seed},
        )
        digests.add(out.stdout.strip())
    assert len(digests) == 1


def test_to_json_covers_sites_and_observations(fleet):
    data = json.loads(fleet.to_json())
    assert [s["site_id"] for s in data["sites"]] == [s.site_id for s in fleet.sites]
    for key in ("fdb_entries", "arp_entries", "dhcp_leases"):
        assert sorted(data[key]) == sorted(s.site_id for s in fleet.sites)
    assert data["reference_time"] == fleet.reference_time.isoformat()


def test_sites_are_ordered_and_own_their_slash16(fleet):
    for index, site in enumerate(fleet.sites):
        site_net = ipaddress.ip_network(f"10.{index + 1}.0.0/16")
        nets = [ipaddress.ip_network(s.cidr) for s in site.subnets]
        assert len(nets) == 3
        assert len(set(nets)) == len(nets)
        for net in nets:
            assert net.prefixlen == 24
            assert net.subnet_of(site_net)
        assert {v.cidr for v in site.vlans} == {s.cidr for s in site.subnets}
        assert all(s.gateway for s in site.subnets)


def test_every_ip_is_inside_site_slash16_and_a_site_slash24(fleet):
    for index, site in enumerate(fleet.sites):
        site_net = ipaddress.ip_network(f"10.{index + 1}.0.0/16")
        nets = [ipaddress.ip_network(s.cidr) for s in site.subnets]
        ips = _site_ips(site, fleet)
        assert ips
        for raw in ips:
            addr = ipaddress.ip_address(raw)
            assert addr in site_net
            assert any(addr in net for net in nets)
        for lease in fleet.dhcp_leases[site.site_id]:
            assert ipaddress.ip_address(lease.ip) in ipaddress.ip_network(
                lease.subnet_cidr
            )


def test_every_mac_is_locally_administered(fleet):
    for site in fleet.sites:
        macs = _site_macs(site, fleet)
        assert macs
        for mac in macs:
            assert mac.startswith("02:")
            assert len(mac.split(":")) == 6


def test_every_name_is_obviously_fake(fleet):
    for site in fleet.sites:
        assert site.site_id.startswith("synth-")
        assert site.name.startswith("synth-")
        for device in site.devices:
            assert device.hostname.startswith("synth-")
        for item in site.equipment:
            assert item.name.startswith("synth-")
        for lease in fleet.dhcp_leases[site.site_id]:
            assert lease.hostname.startswith("synth-")
            assert lease.hostname.endswith(".example")
        assert site.contact_info.endswith(".example")


def test_each_site_has_router_ups_extreme_switches_and_vms(fleet):
    for site in fleet.sites:
        roles = [d.role for d in site.devices]
        assert "router" in roles
        assert "ups" in roles
        ups = [d for d in site.devices if d.role == "ups"]
        assert all(d.vendor == "APC" for d in ups)
        switches = [d for d in site.devices if d.role == "switch"]
        assert switches
        for switch in switches:
            assert switch.vendor == "Extreme Networks"
            assert switch.model == "Summit X460-G2-48p"
            assert len(switch.ports) == 48
            assert [p.name for p in switch.ports] == [f"1:{n}" for n in range(1, 49)]
        vms = [e for e in site.equipment if e.category is EquipmentCategory.VM]
        assert vms
        assert all(vm.power_state for vm in vms)


def test_every_wired_host_gets_an_access_port(fleet):
    for site in fleet.sites:
        wired = [e for e in site.equipment if e.category is EquipmentCategory.SERVER]
        bound = {
            p.connected_device_id
            for d in site.devices
            if d.role == "switch"
            for p in d.ports
            if p.connected_device_id
        }
        for item in wired:
            assert item.equipment_id in bound
            assert len(item.connected_ports) == 1


def test_switch_count_grows_with_wired_hosts():
    fleet = SyntheticFleetGenerator(
        3, sites=1, subnets_per_site=1, hosts_per_subnet=245
    ).generate()
    site = fleet.sites[0]
    wired = [e for e in site.equipment if e.category is EquipmentCategory.SERVER]
    switches = [d for d in site.devices if d.role == "switch"]
    # one port per wired host plus the UPS, with 1:48 kept for the uplink
    assert len(switches) * 47 >= len(wired) + 1


def test_ip_records_carry_arp_data_and_assignments(fleet):
    for site in fleet.sites:
        subnet_ids = {s.subnet_id for s in site.subnets}
        for record in site.ip_addresses:
            assert record.subnet_id in subnet_ids
            assert record.arp_mac
            assert record.arp_last_seen is not None
            assert record.arp_source_device_id
            assert record.assigned_object_type in ("Equipment", "NetworkDevice")
            assert record.assigned_object_id
        assert len(_host_records(site)) >= 3 * 10


def test_fdb_puts_host_macs_on_access_ports_and_router_on_uplink(fleet):
    for site in fleet.sites:
        router = next(d for d in site.devices if d.role == "router")
        router_macs = {
            r.arp_mac for r in site.ip_addresses if r.assigned_object_id == router.device_id
        }
        entries = fleet.fdb_entries[site.site_id]
        uplinks = [e for e in entries if e.port_name == "1:48"]
        assert uplinks
        assert all(e.mac_address in router_macs for e in uplinks)
        host_macs = {r.arp_mac for r in _host_records(site)}
        access = [e for e in entries if e.port_name != "1:48"]
        assert any(e.mac_address in host_macs for e in access)


def test_dhcp_leases_use_directory_dns_type_with_host_slash24(fleet):
    for site in fleet.sites:
        cidrs = {s.cidr for s in site.subnets}
        leases = fleet.dhcp_leases[site.site_id]
        assert leases
        for lease in leases:
            assert isinstance(lease, DhcpLeaseRecord)
            assert lease.subnet_cidr in cidrs


def test_timestamps_are_reference_time_minus_offset(fleet):
    ref = fleet.reference_time
    for site in fleet.sites:
        stamps = [r.arp_last_seen for r in site.ip_addresses]
        stamps += [d.last_seen for d in site.devices]
        stamps += [e.last_seen for e in site.equipment]
        for lease in fleet.dhcp_leases[site.site_id]:
            stamps += [lease.observed_at, lease.lease_expiration]
        for stamp in stamps:
            if stamp is not None:
                assert stamp <= ref


def test_default_reference_time_is_fixed_and_timezone_aware():
    gen = SyntheticFleetGenerator(1, sites=1, subnets_per_site=1, hosts_per_subnet=1)
    assert gen.reference_time == datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    assert gen.reference_time.tzinfo is not None


def test_windows_vm_share_is_within_tolerance():
    fleet = SyntheticFleetGenerator(
        5, sites=2, subnets_per_site=2, hosts_per_subnet=50
    ).generate()
    vms = [
        e
        for s in fleet.sites
        for e in s.equipment
        if e.category is EquipmentCategory.VM
    ]
    share = sum("win" in vm.name.lower() for vm in vms) / len(vms)
    assert 0.85 <= share <= 0.95
    non_windows = [vm for vm in vms if "win" not in vm.name.lower()]
    assert non_windows


def test_zero_fractions_produce_no_stale_duplicate_or_orphan_records():
    fleet = _small(seed=9, **ZERO_FRACTIONS)
    cutoff = fleet.reference_time - timedelta(
        days=ClassificationPolicy().stale_after_days
    )
    for site in fleet.sites:
        ips = [r.ip for r in site.ip_addresses]
        assert len(ips) == len(set(ips))
        macs = [r.arp_mac for r in site.ip_addresses]
        assert len(macs) == len(set(macs))
        known = {d.device_id for d in site.devices} | {
            e.equipment_id for e in site.equipment
        }
        assert all(r.assigned_object_id in known for r in site.ip_addresses)
        sot_macs = set(macs)
        assert all(e.mac_address in sot_macs for e in fleet.fdb_entries[site.site_id])
        assert all(a.arp_mac in sot_macs for a in fleet.arp_entries[site.site_id])
        for record in site.ip_addresses:
            assert record.arp_last_seen > cutoff
        for item in site.equipment:
            assert item.last_seen > cutoff


def test_nonzero_fractions_produce_stale_duplicate_and_orphan_records():
    fleet = _small(
        seed=9, stale_fraction=0.2, duplicate_fraction=0.1, orphan_fraction=0.1
    )
    cutoff = fleet.reference_time - timedelta(
        days=ClassificationPolicy().stale_after_days
    )
    for site in fleet.sites:
        hosts = _host_records(site)
        ips = [r.ip for r in hosts]
        duplicates = len(ips) - len(set(ips))
        known = {e.equipment_id for e in site.equipment}
        orphans = sum(r.assigned_object_id not in known for r in hosts)
        stale = {r.ip for r in hosts if r.arp_last_seen < cutoff}
        assert duplicates == 3
        assert orphans >= 3
        assert len(stale) == 6


def test_drift_returns_new_site_with_seeded_changes(fleet):
    gen = SyntheticFleetGenerator(7, sites=3, subnets_per_site=3, hosts_per_subnet=10)
    site = fleet.sites[0]
    before = site.to_json(indent=2)
    drifted = gen.drift(site, change_fraction=0.2)
    assert drifted is not site
    assert site.to_json(indent=2) == before
    assert drifted.to_json(indent=2) == gen.drift(site, change_fraction=0.2).to_json(
        indent=2
    )
    assert drifted.to_json(indent=2) == fleet.drift(
        site, change_fraction=0.2
    ).to_json(indent=2)
    base_ips = {r.ip for r in site.ip_addresses}
    cur_ips = {r.ip for r in drifted.ip_addresses}
    assert base_ips - cur_ips
    assert cur_ips - base_ips
    for raw in cur_ips:
        assert any(
            ipaddress.ip_address(raw) in ipaddress.ip_network(s.cidr)
            for s in site.subnets
        )
    base_mac = {r.ip: r.arp_mac for r in site.ip_addresses}
    assert any(
        base_mac.get(r.ip) not in (None, r.arp_mac) for r in drifted.ip_addresses
    )
    assert all(r.arp_mac.startswith("02:") for r in drifted.ip_addresses)
    report = SnapshotDiffEngine().diff(
        site,
        drifted,
        current_timestamp=fleet.reference_time,
    )
    assert report.events


@pytest.mark.parametrize(
    "kwargs",
    [
        {"sites": -1},
        {"sites": 0},
        {"sites": 255},
        {"sites": 1.5},
        {"sites": True},
        {"sites": "3"},
        {"subnets_per_site": -1},
        {"subnets_per_site": 257},
        {"hosts_per_subnet": -1},
        {"hosts_per_subnet": 246},
        {"hosts_per_subnet": 2.0},
        {"stale_fraction": -0.1},
        {"stale_fraction": 1.1},
        {"duplicate_fraction": 2},
        {"orphan_fraction": -1},
        {"windows_vm_fraction": 1.5},
        {"stale_fraction": "0.1"},
        {"stale_fraction": float("nan")},
        {"reference_time": datetime(2026, 1, 1)},
        {"reference_time": "2026-01-01T00:00:00+00:00"},
    ],
)
def test_invalid_arguments_raise_value_error(kwargs):
    with pytest.raises(ValueError):
        SyntheticFleetGenerator(1, **kwargs)


@pytest.mark.parametrize("seed", [None, "7", 1.0, True])
def test_invalid_seed_raises_value_error(seed):
    with pytest.raises(ValueError):
        SyntheticFleetGenerator(seed)


def test_largest_valid_hosts_per_subnet_is_accepted():
    fleet = SyntheticFleetGenerator(
        1, sites=1, subnets_per_site=1, hosts_per_subnet=245
    ).generate()
    hosts = _host_records(fleet.sites[0])
    assert len({r.ip for r in hosts}) == 245


def test_drift_rejects_invalid_change_fraction(fleet):
    gen = SyntheticFleetGenerator(7)
    with pytest.raises(ValueError):
        gen.drift(fleet.sites[0], change_fraction=1.5)
