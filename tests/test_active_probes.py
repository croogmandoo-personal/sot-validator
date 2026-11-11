"""Unit tests for scoped active network probe collectors (/24 ICMP & Extreme/APC SNMP checks)."""

from __future__ import annotations

import pathlib
import threading
import time
from typing import Any
import pytest

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
)
from sot_validator.signals import (
    FixtureManagementTransport,
    HttpsProbeResponse,
    IcmpProbeCollector,
    IcmpProbeResponse,
    ManagementProbeCollector,
    ReadOnlyViolationError,
    ScopeViolationError,
    SubnetScopeGuard,
    parse_apc_ups_oids,
    parse_extreme_switch_oids,
)
import sot_validator.signals.management as mgmt_mod

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SNMP_FIXTURE_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "sot_samples" / "snmp" / "extreme_and_apc_walks.json"
)


@pytest.fixture()
def site_042() -> Site:
    """Construct canonical site-042 fixture with allocated /24 subnets and inventory items."""
    return Site(
        site_id="site-042",
        name="SF Regional Distribution Center 42",
        subnets=[
            Subnet(subnet_id="sub-042-001", site_id="site-042", cidr="10.42.1.0/24", vlan_id="1"),
            Subnet(subnet_id="sub-042-010", site_id="site-042", cidr="10.42.10.0/24", vlan_id="10"),
            Subnet(subnet_id="sub-042-020", site_id="site-042", cidr="10.42.20.0/24", vlan_id="20"),
            Subnet(subnet_id="sub-042-030", site_id="site-042", cidr="10.42.30.0/24", vlan_id="30"),
        ],
        devices=[
            NetworkDevice(
                device_id="dev-042-sw01",
                site_id="site-042",
                hostname="sw01.site042.example.internal",
                management_ip="10.42.1.10",
                vendor="Extreme Networks",
                model="ExtremeSwitching X465-48W",
                role="core-switch",
            ),
            NetworkDevice(
                device_id="dev-042-sw-unmanaged",
                site_id="site-042",
                hostname="sw-unmanaged.site042.example.internal",
                management_ip=None,
                vendor="Extreme Networks",
            ),
        ],
        equipment=[
            Equipment(
                equipment_id="eq-042-ups01",
                site_id="site-042",
                name="ups01.site042.example.internal",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.30.10"],
            ),
            Equipment(
                equipment_id="eq-042-san01",
                site_id="site-042",
                name="san01.site042.example.internal",
                category=EquipmentCategory.SAN,
                assigned_ips=["10.42.20.15"],
            ),
            Equipment(
                equipment_id="eq-042-vm-win01",
                site_id="site-042",
                name="win-dc01.site042.example.internal",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.21"],
            ),
            Equipment(
                equipment_id="eq-042-noip",
                site_id="site-042",
                name="spare-chassis.site042.example.internal",
                category=EquipmentCategory.SERVER,
                assigned_ips=[],
            ),
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.1.10",
                subnet_id="sub-042-001",
                assigned_object_type="network_device",
                assigned_object_id="dev-042-sw01",
            ),
            IPAddress(
                ip="10.42.10.21",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-vm-win01",
            ),
            IPAddress(
                ip="10.42.20.15",
                subnet_id="sub-042-020",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-san01",
            ),
            IPAddress(
                ip="10.42.30.10",
                subnet_id="sub-042-030",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-ups01",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# 1. /24 Subnet & Recorded-IP Scoping Guard Tests
# ---------------------------------------------------------------------------


def test_scope_guard_allows_allocated_slash24_ips(site_042: Site) -> None:
    guard = SubnetScopeGuard.from_site(site_042, site_prefix="10.42.0.0/16")

    assert guard.validate_target_ip("10.42.1.10") == "10.42.1.10"
    assert guard.validate_target_ip("10.42.10.21") == "10.42.10.21"
    assert guard.validate_target_ip("10.42.20.15") == "10.42.20.15"
    assert guard.validate_target_ip("10.42.30.10") == "10.42.30.10"
    assert guard.validate_target_ip("10.42.1.250") == "10.42.1.250"
    assert guard.is_ip_in_scope("10.42.1.10") is True

    hosts = guard.expand_scoped_hosts("10.42.1.0/24")
    assert len(hosts) == 254
    assert hosts[0] == "10.42.1.1"
    assert hosts[-1] == "10.42.1.254"


@pytest.mark.parametrize(
    "bad_cidr",
    [
        "10.42.0.0/16",
        "10.0.0.0/8",
        "10.42.0.0/23",
        "10.42.1.0/25",
        "0.0.0.0/0",
    ],
)
def test_scope_guard_rejects_non_slash24_cidr_sweeps(
    site_042: Site, bad_cidr: str
) -> None:
    guard = SubnetScopeGuard.from_site(site_042, site_prefix="10.42.0.0/16")

    with pytest.raises(ScopeViolationError):
        guard.validate_cidr_scope(bad_cidr)

    with pytest.raises(ScopeViolationError):
        guard.expand_scoped_hosts(bad_cidr)

    with pytest.raises(ScopeViolationError):
        SubnetScopeGuard(subnets=[bad_cidr])


@pytest.mark.parametrize(
    "out_of_scope_ip",
    [
        "10.42.99.10",     # Unallocated /24 inside site 10.42.0.0/16
        "10.42.0.10",      # Unallocated /24 inside site 10.42.0.0/16
        "10.99.1.10",      # Different site /16 entirely
        "192.168.1.10",    # Outside 10.42.0.0/16
        "10.42.1.0",       # /24 network address
        "10.42.1.255",     # /24 broadcast address
        "10.42.0.0/16",    # CIDR string passed as host IP
        "127.0.0.1",       # Loopback address
    ],
)
def test_scope_guard_rejects_unallocated_and_invalid_ips(
    site_042: Site, out_of_scope_ip: str
) -> None:
    guard = SubnetScopeGuard.from_site(site_042, site_prefix="10.42.0.0/16")

    assert guard.is_ip_in_scope(out_of_scope_ip) is False
    with pytest.raises(ScopeViolationError):
        guard.validate_target_ip(out_of_scope_ip)


def test_scope_guard_rejects_unallocated_slash24_subnet(site_042: Site) -> None:
    guard = SubnetScopeGuard.from_site(site_042, site_prefix="10.42.0.0/16")

    with pytest.raises(ScopeViolationError, match="not in the site's allocated /24"):
        guard.validate_cidr_scope("10.42.99.0/24")

    with pytest.raises(ScopeViolationError, match="outside site prefix"):
        SubnetScopeGuard(subnets=["10.43.1.0/24"], site_prefix="10.42.0.0/16")


def test_scope_guard_recorded_ips_only_when_no_subnets_defined() -> None:
    guard = SubnetScopeGuard(recorded_ips=["10.42.1.10", "10.42.10.21"])
    assert guard.validate_target_ip("10.42.1.10") == "10.42.1.10"
    assert guard.is_ip_in_scope("10.42.1.99") is False
    with pytest.raises(ScopeViolationError):
        guard.validate_target_ip("10.42.1.99")


# ---------------------------------------------------------------------------
# 2. IcmpProbeCollector Tests
# ---------------------------------------------------------------------------


def test_icmp_collector_statuses_active_unreachable_not_applicable_and_error(
    site_042: Site,
) -> None:
    reachable_ips = {"10.42.1.10", "10.42.30.10"}

    def mock_probe(ip: str, timeout: float) -> IcmpProbeResponse:
        assert timeout == 0.5
        if ip in reachable_ips:
            return IcmpProbeResponse(reachable=True, latency_ms=1.75, detail="echo_reply")
        return IcmpProbeResponse(reachable=False)

    collector = IcmpProbeCollector(
        max_concurrency=8,
        timeout_seconds=0.5,
        retries=1,
        probe_fn=mock_probe,
    )

    # ACTIVE on reachable switch management IP
    sw_sig = collector.collect_for_device(site_042.devices[0], site=site_042)
    assert sw_sig.signal_type is SignalType.ICMP_REACHABILITY
    assert sw_sig.status is SignalStatus.ACTIVE
    assert sw_sig.details is not None
    assert "10.42.1.10" in sw_sig.details
    assert "1.75ms" in sw_sig.details

    # UNREACHABLE on Windows VM dropping ICMP echo
    vm_sig = collector.collect_for_equipment(site_042.equipment[2], site=site_042)
    assert vm_sig.signal_type is SignalType.ICMP_REACHABILITY
    assert vm_sig.status is SignalStatus.UNREACHABLE
    assert vm_sig.details is not None
    assert "after 2 attempt(s)" in vm_sig.details

    # NOT_APPLICABLE on device without management_ip or equipment without assigned_ips
    unmanaged_sig = collector.collect_for_device(site_042.devices[1], site=site_042)
    assert unmanaged_sig.signal_type is SignalType.ICMP_REACHABILITY
    assert unmanaged_sig.status is SignalStatus.NOT_APPLICABLE

    noip_eq_sig = collector.collect_for_equipment(site_042.equipment[3], site=site_042)
    assert noip_eq_sig.signal_type is SignalType.ICMP_REACHABILITY
    assert noip_eq_sig.status is SignalStatus.NOT_APPLICABLE

    # ERROR on out-of-scope IP or /16 CIDR sweep attempt
    out_of_scope_sig = collector.collect_for_ip("10.42.99.50", site=site_042)
    assert out_of_scope_sig.signal_type is SignalType.ICMP_REACHABILITY
    assert out_of_scope_sig.status is SignalStatus.ERROR
    assert out_of_scope_sig.details is not None
    assert "Scope guard rejected" in out_of_scope_sig.details

    with pytest.raises(ScopeViolationError):
        collector.validate_cidr_scope("10.42.0.0/16", site=site_042)


def test_icmp_collector_retries_and_timeout_handling(site_042: Site) -> None:
    attempts_by_ip: dict[str, int] = {}

    def flaky_probe(ip: str, timeout: float) -> bool:
        _ = timeout
        attempts_by_ip[ip] = attempts_by_ip.get(ip, 0) + 1
        if ip == "10.42.1.10":
            # Fails on attempt 1 with TimeoutError, succeeds on attempt 2
            if attempts_by_ip[ip] == 1:
                raise TimeoutError("ICMP request timed out")
            return True
        if ip == "10.42.20.15":
            # Always times out
            raise TimeoutError("ICMP request timed out")
        raise RuntimeError("Raw socket permission error")

    collector = IcmpProbeCollector(
        max_concurrency=4,
        timeout_seconds=0.25,
        retries=2,
        probe_fn=flaky_probe,
    )

    # Succeeds on 2nd attempt and stops without running a 3rd attempt
    sig_ok = collector.collect_for_ip("10.42.1.10", site=site_042)
    assert sig_ok.status is SignalStatus.ACTIVE
    assert attempts_by_ip["10.42.1.10"] == 2
    assert sig_ok.details is not None
    assert "attempt 2/3" in sig_ok.details

    # Exhausts all 3 attempts (1 + retries=2) on TimeoutError -> UNREACHABLE
    sig_timeout = collector.collect_for_ip("10.42.20.15", site=site_042)
    assert sig_timeout.status is SignalStatus.UNREACHABLE
    assert attempts_by_ip["10.42.20.15"] == 3

    # Unexpected non-timeout exception -> ERROR
    sig_err = collector.collect_for_ip("10.42.30.10", site=site_042)
    assert sig_err.status is SignalStatus.ERROR
    assert sig_err.details is not None
    assert "RuntimeError" in sig_err.details


def test_icmp_collector_bounded_concurrency(site_042: Site) -> None:
    max_concurrency = 3
    lock = threading.Lock()
    in_flight = 0
    peak_in_flight = 0

    def slow_probe(ip: str, timeout: float) -> bool:
        nonlocal in_flight, peak_in_flight
        _ = (ip, timeout)
        with lock:
            in_flight += 1
            if in_flight > peak_in_flight:
                peak_in_flight = in_flight
        time.sleep(0.03)
        with lock:
            in_flight -= 1
        return True

    collector = IcmpProbeCollector(
        max_concurrency=max_concurrency,
        timeout_seconds=1.0,
        retries=0,
        probe_fn=slow_probe,
    )

    target_ips = [f"10.42.1.{host}" for host in range(10, 26)]
    results = collector.probe_ips(target_ips, site=site_042)

    assert len(results) == len(target_ips)
    assert all(sig.status is SignalStatus.ACTIVE for sig in results.values())
    assert 1 < peak_in_flight <= max_concurrency


def test_icmp_collector_site_batch_and_fixture_loader(site_042: Site) -> None:
    collector = IcmpProbeCollector.from_fixture_file(SNMP_FIXTURE_PATH)
    site_results = collector.collect_site(site_042)

    assert site_results["dev-042-sw01"].status is SignalStatus.ACTIVE
    assert site_results["eq-042-ups01"].status is SignalStatus.ACTIVE
    assert site_results["dev-042-sw-unmanaged"].status is SignalStatus.NOT_APPLICABLE
    assert site_results["eq-042-noip"].status is SignalStatus.NOT_APPLICABLE
    assert site_results["10.42.1.10"].status is SignalStatus.ACTIVE
    assert site_results["10.42.30.10"].status is SignalStatus.ACTIVE


# ---------------------------------------------------------------------------
# 3. ManagementProbeCollector: Extreme Networks Switch & APC UPS Fixture Tests
# ---------------------------------------------------------------------------


def test_extreme_and_apc_snmp_fixture_evaluation(site_042: Site) -> None:
    collector = ManagementProbeCollector.from_fixture_file(SNMP_FIXTURE_PATH)

    # Evaluate Extreme Networks switch dev-042-sw01 (10.42.1.10)
    sw_device = site_042.devices[0]
    sw_signal = collector.collect_for_device(sw_device, site=site_042)
    assert sw_signal.signal_type is SignalType.SNMP_API_REACHABILITY
    assert sw_signal.status is SignalStatus.ACTIVE
    assert sw_signal.details is not None
    assert "Extreme Networks" in sw_signal.details
    assert "sw01.site042.example.internal" in sw_signal.details
    assert "31.7.1.4" in sw_signal.details
    assert "SIM-EX465-04201" in sw_signal.details
    assert "ports_up=4/5" in sw_signal.details
    assert "ports_down=1" in sw_signal.details
    assert "poe_active_ports=2" in sw_signal.details
    assert "28200" in sw_signal.details
    assert "arp_entries=4" in sw_signal.details

    # Evaluate APC Smart-UPS eq-042-ups01 (10.42.30.10)
    ups_eq = site_042.equipment[0]
    ups_signal = collector.collect_for_equipment(ups_eq, site=site_042)
    assert ups_signal.signal_type is SignalType.SNMP_API_REACHABILITY
    assert ups_signal.status is SignalStatus.ACTIVE
    assert ups_signal.details is not None
    assert "APC UPS" in ups_signal.details
    assert "ups01.site042.example.internal" in ups_signal.details
    assert "Smart-UPS SRT 5000" in ups_signal.details
    assert "online=True" in ups_signal.details
    assert "battery_capacity=100%" in ups_signal.details
    assert "output_load=38%" in ups_signal.details


def test_extreme_and_apc_oid_parsers_directly() -> None:
    transport = FixtureManagementTransport.from_file(SNMP_FIXTURE_PATH)

    sw_oids = transport.query_snmp("10.42.1.10")
    assert sw_oids is not None
    sw_metrics = parse_extreme_switch_oids(sw_oids)
    assert sw_metrics["sys_name"] == "sw01.site042.example.internal"
    assert sw_metrics["os_version"] == "31.7.1.4"
    assert sw_metrics["serial_number"] == "SIM-EX465-04201"
    assert sw_metrics["ports_total"] == 5
    assert sw_metrics["ports_up"] == 4
    assert sw_metrics["ports_down"] == 1
    assert sw_metrics["poe_active_ports"] == 2
    assert sw_metrics["poe_total_mw"] == 28200
    assert sw_metrics["poe_total_watts"] == 28.2
    assert sw_metrics["arp_entries"] == 4

    ups_oids = transport.query_snmp("10.42.30.10")
    assert ups_oids is not None
    ups_metrics = parse_apc_ups_oids(ups_oids)
    assert ups_metrics["sys_name"] == "ups01.site042.example.internal"
    assert ups_metrics["model"] == "Smart-UPS SRT 5000"
    assert ups_metrics["on_line"] is True
    assert ups_metrics["output_status"] == "onLine"
    assert ups_metrics["battery_capacity_pct"] == 100
    assert ups_metrics["output_load_pct"] == 38


# ---------------------------------------------------------------------------
# 4. ManagementProbeCollector: Read-Only Guardrails, HTTPS Fallback, & Concurrency
# ---------------------------------------------------------------------------


def test_management_canonical_oid_constants_exist() -> None:
    assert mgmt_mod.SNMPV2_MIB_SYS_DESCR == "1.3.6.1.2.1.1.1.0"
    assert mgmt_mod.SNMPV2_MIB_SYS_UPTIME == "1.3.6.1.2.1.1.3.0"
    assert mgmt_mod.SNMPV2_MIB_SYS_NAME == "1.3.6.1.2.1.1.5.0"
    assert mgmt_mod.IF_MIB_IF_ADMIN_STATUS_PREFIX == "1.3.6.1.2.1.2.2.1.7"
    assert mgmt_mod.IF_MIB_IF_OPER_STATUS_PREFIX == "1.3.6.1.2.1.2.2.1.8"
    assert mgmt_mod.IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX == "1.3.6.1.2.1.4.22.1.2"
    assert mgmt_mod.EXTREME_ENTERPRISE_OID_PREFIX == "1.3.6.1.4.1.1916"
    assert mgmt_mod.APC_ENTERPRISE_OID_PREFIX == "1.3.6.1.4.1.318"
    assert mgmt_mod.APC_UPS_BASIC_IDENT_MODEL_OID == "1.3.6.1.4.1.318.1.1.1.1.1.1.0"
    assert mgmt_mod.APC_UPS_BASIC_STATE_OUTPUT_STATE_OID == "1.3.6.1.4.1.318.1.1.1.11.1.1.0"
    assert mgmt_mod.APC_UPS_ADV_BATTERY_CAPACITY_OID == "1.3.6.1.4.1.318.1.1.1.2.2.1.0"
    assert mgmt_mod.APC_UPS_ADV_OUTPUT_LOAD_OID == "1.3.6.1.4.1.318.1.1.1.4.2.3.0"


def test_management_collector_enforces_readonly_snmp_and_http(site_042: Site) -> None:
    # Reject SNMP SET operation at initialization
    with pytest.raises(ReadOnlyViolationError):
        ManagementProbeCollector(snmp_operation="SET")

    # Reject non-readonly SNMP mode at initialization
    with pytest.raises(ReadOnlyViolationError):
        ManagementProbeCollector(snmp_mode="readwrite")

    with pytest.raises(ReadOnlyViolationError):
        ManagementProbeCollector(snmp_mode="write")

    # Reject mutating HTTP methods (POST, DELETE, PUT)
    for bad_method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(ReadOnlyViolationError):
            ManagementProbeCollector(http_method=bad_method)

    # Reject SNMP SET or write mode during explicit execute_snmp_query call
    collector = ManagementProbeCollector.from_fixture_file(SNMP_FIXTURE_PATH)
    with pytest.raises(ReadOnlyViolationError):
        collector.execute_snmp_query("10.42.1.10", operation="SET", site=site_042)
    with pytest.raises(ReadOnlyViolationError):
        collector.execute_snmp_query("10.42.1.10", mode="readwrite", site=site_042)

    # Reject fixture with non-readonly snmp_profile
    with pytest.raises(ReadOnlyViolationError):
        FixtureManagementTransport({"snmp_profile": {"mode": "readwrite"}, "targets": {}})


def test_management_collector_https_fallback_and_vm_handling(site_042: Site) -> None:
    # SAN eq-042-san01 (10.42.20.15) has no SNMP response in fixture, but HTTPS responds
    def mock_https_probe(ip: str, timeout: float) -> HttpsProbeResponse:
        assert timeout == 2.0
        if ip == "10.42.20.15":
            return HttpsProbeResponse(
                reachable=True,
                status_code=200,
                port=443,
                detail="NetApp ONTAP System Manager",
            )
        return HttpsProbeResponse(reachable=False)

    collector = ManagementProbeCollector.from_fixture_file(
        SNMP_FIXTURE_PATH,
        https_probe_fn=mock_https_probe,
    )

    site_signals = collector.collect_site(site_042)

    # Switch and UPS active via SNMP
    assert site_signals["dev-042-sw01"].status is SignalStatus.ACTIVE
    assert site_signals["eq-042-ups01"].status is SignalStatus.ACTIVE

    # SAN active via HTTPS management fallback
    san_sig = site_signals["eq-042-san01"]
    assert san_sig.status is SignalStatus.ACTIVE
    assert san_sig.details is not None
    assert "HTTPS management reachable on 10.42.20.15:443" in san_sig.details
    assert "NetApp ONTAP System Manager" in san_sig.details

    # Windows VM without dedicated SNMP/HTTPS responder returns NOT_APPLICABLE
    vm_sig = site_signals["eq-042-vm-win01"]
    assert vm_sig.status is SignalStatus.NOT_APPLICABLE

    # Unmanaged device / equipment without IP returns NOT_APPLICABLE
    assert site_signals["dev-042-sw-unmanaged"].status is SignalStatus.NOT_APPLICABLE
    assert site_signals["eq-042-noip"].status is SignalStatus.NOT_APPLICABLE


def test_management_collector_retries_timeouts_scope_and_concurrency(
    site_042: Site,
) -> None:
    max_concurrency = 2
    lock = threading.Lock()
    active_workers = 0
    max_observed_workers = 0
    attempts: dict[str, int] = {}

    def mock_snmp(ip: str, oids: list[str], timeout: float) -> dict[str, Any] | None:
        nonlocal active_workers, max_observed_workers
        _ = (oids, timeout)
        with lock:
            active_workers += 1
            if active_workers > max_observed_workers:
                max_observed_workers = active_workers
            attempts[ip] = attempts.get(ip, 0) + 1
            current_attempt = attempts[ip]

        time.sleep(0.02)

        with lock:
            active_workers -= 1

        if ip == "10.42.1.10":
            if current_attempt < 2:
                raise TimeoutError("SNMP UDP timeout")
            return {
                mgmt_mod.SNMPV2_MIB_SYS_DESCR: "ExtremeXOS (X465-48W)",
                mgmt_mod.SNMPV2_MIB_SYS_UPTIME: "123456",
                mgmt_mod.SNMPV2_MIB_SYS_NAME: "sw01",
            }
        return None

    collector = ManagementProbeCollector(
        max_concurrency=max_concurrency,
        timeout_seconds=0.5,
        retries=2,
        snmp_probe_fn=mock_snmp,
    )

    # Succeeds on 2nd attempt
    sw_sig = collector.collect_for_device(site_042.devices[0], site=site_042)
    assert sw_sig.status is SignalStatus.ACTIVE
    assert attempts["10.42.1.10"] == 2

    # Unreachable after 3 attempts (1 + retries=2)
    san_sig = collector.collect_for_equipment(site_042.equipment[1], site=site_042)
    assert san_sig.status is SignalStatus.UNREACHABLE
    assert attempts["10.42.20.15"] == 3

    # Out-of-scope IP rejected with ERROR
    bad_dev = NetworkDevice(
        device_id="dev-bad",
        site_id="site-042",
        hostname="bad-sw",
        management_ip="10.42.99.10",
    )
    bad_sig = collector.collect_for_device(bad_dev, site=site_042)
    assert bad_sig.status is SignalStatus.ERROR

    # Run concurrent site collection and verify max_concurrency is respected
    collector.collect_site(site_042)
    assert 1 <= max_observed_workers <= max_concurrency
