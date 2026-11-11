"""Unit tests for Phase 4 live pilot connectors and pre-flight cutover validator."""

from __future__ import annotations

from typing import Any
import pytest

from sot_validator.connectors import (
    APC_UPS_MIB_OIDS,
    EXTREME_SWITCH_MIB_OIDS,
    LLDP_MIB_OIDS,
    LLDP_REM_PORT_ID_PREFIX,
    LLDP_REM_SYS_NAME_PREFIX,
    PETH_PSE_PORT_ADMIN_ENABLE_PREFIX,
    PETH_PSE_PORT_DETECTION_STATUS_PREFIX,
    POWER_ETHERNET_MIB_OIDS,
    AuthenticatedScraperSession,
    ConnectorReadOnlyError,
    PilotCutoverValidator,
    PreFlightCheckResult,
    PreFlightReport,
    RequestTelemetry,
    SnmpWalkConnector,
    VSphereRestConnector,
)
from sot_validator.extraction.client import (
    FixtureSoTClient,
    ReadOnlyViolationError,
)
from sot_validator.extraction.scraper import HtmlScraperSoTClient
from sot_validator.models import (
    NetworkDevice,
    SignalStatus,
    Site,
    Subnet,
)
from sot_validator.signals.hypervisor import VmPowerState
from sot_validator.signals.icmp import ScopeViolationError, SubnetScopeGuard
from sot_validator.signals.management import (
    APC_UPS_ADV_BATTERY_CAPACITY_OID,
    APC_UPS_ADV_OUTPUT_LOAD_OID,
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
    EXTREME_POE_PORT_MEASURED_POWER_PREFIX,
    EXTREME_SYS_SERIAL_NUMBER_OID,
    EXTREME_SYS_VERSION_OID,
    IF_MIB_IF_ADMIN_STATUS_PREFIX,
    IF_MIB_IF_OPER_STATUS_PREFIX,
    IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX,
    ManagementProbeCollector,
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_NAME,
    SNMPV2_MIB_SYS_UPTIME,
)


# ---------------------------------------------------------------------------
# 1. AuthenticatedScraperSession Tests (-k scraper)
# ---------------------------------------------------------------------------


def test_scraper_session_get_head_and_html_scraper_integration() -> None:
    calls: list[tuple[str, str, dict[str, str], float]] = []

    html_pages = {
        "https://sot.internal/sites": """
            <html><body>
              <div data-site-id="site-001" data-site-name="Site 001"></div>
            </body></html>
        """,
        "https://sot.internal/sites/site-001": """
            <html><body>
              <div id="site-overview" data-site-id="site-001" data-site-name="Site 001 (10.1.0.0/16)">
                <span class="site-address">100 Enterprise Way</span>
              </div>
              <table id="subnets-table">
                <thead><tr><th>subnet_id</th><th>vlan_id</th><th>cidr</th><th>gateway</th></tr></thead>
                <tbody>
                  <tr><td>sub-1</td><td>vlan-1</td><td>10.1.1.0/24</td><td>10.1.1.1</td></tr>
                </tbody>
              </table>
            </body></html>
        """,
    }

    def fake_transport(
        method: str, url: str, headers: dict[str, str], timeout: float
    ) -> str:
        calls.append((method, url, headers, timeout))
        return html_pages.get(url, "<html></html>")

    session = AuthenticatedScraperSession(
        base_url="https://sot.internal",
        headers={"X-Custom": "pilot"},
        cookies={"sot_sid": "abc123"},
        session_token="tok-xyz",
        timeout_seconds=5.0,
        transport=fake_transport,
    )

    headers = session.build_request_headers()
    assert headers["X-Custom"] == "pilot"
    assert "sot_sid=abc123" in headers["Cookie"]
    assert headers["Authorization"] == "Bearer tok-xyz"

    assert session.check_health("/sites") is True
    head_resp = session.head("/sites")
    assert "site-001" in head_resp

    # Pass directly as transport into HtmlScraperSoTClient
    scraper_client = HtmlScraperSoTClient(
        base_url="https://sot.internal",
        transport=session,
    )
    site_ids = scraper_client.list_site_ids()
    assert site_ids == ["site-001"]
    site = scraper_client.get_site("site-001")
    assert site.site_id == "site-001"
    assert len(site.subnets) == 1
    assert site.subnets[0].cidr == "10.1.1.0/24"

    assert session.telemetry.total_requests == 4
    assert session.telemetry.successful_requests == 4
    assert session.telemetry.failed_requests == 0
    assert session.telemetry.blocked_mutations == 0
    assert all(m in {"GET", "HEAD"} for m, _, _, _ in calls)


@pytest.mark.parametrize(
    ("bad_method", "bad_url"),
    [
        ("POST", "/sites"),
        ("PUT", "/sites/site-001"),
        ("PATCH", "/sites/site-001"),
        ("DELETE", "/sites/site-001"),
        ("GET", "/actions/port-admin"),
        ("GET", "/actions/poe-toggle/sw-01/1:1"),
        ("GET", "/api/cmd?run=reboot"),
        ("GET", "/sites/site-001/devices/sw-01?action=disable"),
    ],
)
def test_scraper_session_blocks_mutating_methods_and_urls(
    bad_method: str, bad_url: str
) -> None:
    transport_called = False

    def forbidden_transport(method: str, url: str) -> str:
        nonlocal transport_called
        transport_called = True
        return f"{method} {url}"

    session = AuthenticatedScraperSession(
        base_url="https://sot.internal",
        transport=forbidden_transport,
    )

    with pytest.raises(PermissionError) as exc_info:
        session.request(bad_method, bad_url)

    assert isinstance(exc_info.value, ConnectorReadOnlyError)
    assert isinstance(exc_info.value, ReadOnlyViolationError)
    assert transport_called is False
    assert session.telemetry.blocked_mutations == 1
    assert session.telemetry.total_requests == 0


def test_scraper_session_retries_and_backoff_telemetry() -> None:
    attempts = 0
    sleeps: list[float] = []

    def flaky_transport(method: str, url: str, timeout: float) -> str:
        nonlocal attempts
        _ = (method, url, timeout)
        attempts += 1
        if attempts < 3:
            raise TimeoutError("transient timeout")
        return "<html>ok</html>"

    session = AuthenticatedScraperSession(
        base_url="https://sot.internal",
        timeout_seconds=2.5,
        max_retries=2,
        backoff_seconds=0.5,
        transport=flaky_transport,
        sleep_fn=sleeps.append,
    )

    body = session.get("/sites")
    assert body == "<html>ok</html>"
    assert attempts == 3
    assert sleeps == [0.5, 1.0]
    assert session.telemetry.total_requests == 1
    assert session.telemetry.successful_requests == 1
    assert session.telemetry.retried_requests == 2
    assert session.telemetry.failed_requests == 0
    assert len(session.telemetry.latencies_ms) == 1
    telemetry_dict = session.telemetry.to_dict()
    assert telemetry_dict["retried_requests"] == 2
    assert "average_latency_ms" in telemetry_dict


# ---------------------------------------------------------------------------
# 2. VSphereRestConnector Tests (-k vsphere)
# ---------------------------------------------------------------------------


def test_vsphere_connector_multi_instance_caching_and_inventory_provider() -> None:
    clock = [100.0]
    transport_calls: list[tuple[str, str]] = []

    vcenter_payloads: dict[str, dict[str, Any]] = {
        "https://vcenter-01.corp.internal/api/vcenter/vm": {
            "value": [
                {
                    "vm": "vm-101",
                    "name": "win-srv-001-01",
                    "power_state": "POWERED_ON",
                    "guest_os_family": "windows",
                    "guest_tools_status": "toolsOk",
                    "tools_heartbeat": "green",
                    "ip_addresses": ["10.1.10.11"],
                    "mac_addresses": ["00:50:56:01:10:11"],
                }
            ]
        },
        "https://vcenter-02.corp.internal/api/vcenter/vm": {
            "value": [
                {
                    "vm": "vm-202",
                    "name": "win-srv-002-01",
                    "power_state": "POWERED_OFF",
                    "guest_os_family": "windows",
                    "guest_tools_status": "toolsNotRunning",
                    "ip_addresses": ["10.2.10.11"],
                    "mac_addresses": ["00:50:56:02:10:11"],
                }
            ]
        },
        "https://vcenter-01.corp.internal/api/vcenter/host": {
            "value": [
                {
                    "host": "host-11",
                    "name": "esxi-01.corp.internal",
                    "connection_state": "CONNECTED",
                    "power_state": "POWERED_ON",
                }
            ]
        },
    }

    def fake_vsphere_transport(
        method: str, url: str, headers: dict[str, str], timeout: float
    ) -> Any:
        _ = (headers, timeout)
        transport_calls.append((method, url))
        if url not in vcenter_payloads:
            return {"value": []}
        return vcenter_payloads[url]

    connector = VSphereRestConnector(
        instances=[
            {"vcenter_instance": "vcenter-01.corp.internal", "site_id": "site-001"},
            {"vcenter_instance": "vcenter-02.corp.internal", "site_id": "site-002"},
        ],
        auth_token="vc-ro-session",
        cache_ttl_seconds=60.0,
        transport=fake_vsphere_transport,
        clock_fn=lambda: clock[0],
    )

    vms_first = connector.fetch_vms()
    assert len(vms_first) == 2
    assert vms_first[0].vm_moref == "vm-101"
    assert vms_first[0].power_state is VmPowerState.POWERED_ON
    assert vms_first[0].is_windows is True
    assert vms_first[0].site_id == "site-001"
    assert vms_first[1].vm_moref == "vm-202"
    assert vms_first[1].power_state is VmPowerState.POWERED_OFF
    assert connector.telemetry.cache_misses == 2
    assert connector.telemetry.cache_hits == 0
    assert len(transport_calls) == 2

    # Second fetch within TTL serves from cache without calling transport
    clock[0] = 130.0
    vms_cached = connector.fetch_vms()
    assert len(vms_cached) == 2
    assert connector.telemetry.cache_hits == 2
    assert len(transport_calls) == 2

    # Advance past TTL -> re-fetches
    clock[0] = 200.0
    vms_refreshed = connector.fetch_vms("vcenter-01.corp.internal")
    assert len(vms_refreshed) == 1
    assert connector.telemetry.cache_misses == 3
    assert len(transport_calls) == 3

    # Fetch hosts and verify caching
    hosts = connector.fetch_hosts("vcenter-01.corp.internal")
    assert len(hosts) == 1
    assert hosts[0]["host"] == "host-11"
    assert hosts[0]["vcenter_instance"] == "vcenter-01.corp.internal"
    _ = connector.fetch_hosts("vcenter-01.corp.internal")
    assert connector.telemetry.cache_hits == 3

    # Build MultiVCenterInventoryProvider
    provider = connector.to_inventory_provider()
    assert len(provider.list_vms()) == 2
    matched = provider.find_by_moref("vm-101", "vcenter-01.corp.internal")
    assert len(matched) == 1
    assert matched[0].vm_name == "win-srv-001-01"

    connector.invalidate_cache("vcenter-01.corp.internal")
    _ = connector.fetch_vms("vcenter-01.corp.internal")
    assert connector.telemetry.cache_misses == 6


@pytest.mark.parametrize(
    ("bad_method", "bad_path"),
    [
        ("POST", "/api/vcenter/vm"),
        ("DELETE", "/api/vcenter/vm/vm-101"),
        ("PATCH", "/api/vcenter/vm/vm-101"),
        ("PUT", "/api/vcenter/host/host-11"),
        ("GET", "/api/vcenter/vm/vm-101/power/stop"),
        ("GET", "/api/vcenter/vm/vm-101/power/reset"),
        ("GET", "/api/vcenter/vm/vm-101/delete"),
        ("GET", "/api/vcenter/datacenter/delete"),
    ],
)
def test_vsphere_connector_blocks_mutating_verbs_and_paths(
    bad_method: str, bad_path: str
) -> None:
    called = False

    def fake_transport(method: str, url: str) -> Any:
        nonlocal called
        called = True
        return {"method": method, "url": url}

    connector = VSphereRestConnector(
        instances=["vcenter-01.corp.internal"],
        transport=fake_transport,
    )

    with pytest.raises(PermissionError) as exc_info:
        connector.request(bad_method, "vcenter-01.corp.internal", bad_path)

    assert isinstance(exc_info.value, ConnectorReadOnlyError)
    assert called is False
    assert connector.telemetry.blocked_mutations == 1


def test_vsphere_connector_rejects_write_mode_or_role() -> None:
    with pytest.raises(PermissionError):
        VSphereRestConnector(
            instances=["vcenter-01.corp.internal"],
            api_mode="readwrite",
        )

    with pytest.raises(PermissionError):
        VSphereRestConnector(
            instances=[{"vcenter_instance": "vcenter-01.corp.internal", "mode": "admin"}],
        )


# ---------------------------------------------------------------------------
# 3. SnmpWalkConnector Tests (-k snmp)
# ---------------------------------------------------------------------------


def test_snmp_connector_extreme_switch_and_apc_ups_walks_and_collector_integration() -> None:
    site = FixtureSoTClient(num_sites=1).get_site("site-001")
    guard = SubnetScopeGuard.from_site(site)

    extreme_oids = {
        SNMPV2_MIB_SYS_DESCR: "ExtremeXOS version 31.7.1.4 by release-manager",
        SNMPV2_MIB_SYS_UPTIME: "12345678",
        SNMPV2_MIB_SYS_NAME: "ext-sw-001-01",
        EXTREME_SYS_VERSION_OID: "31.7.1.4",
        EXTREME_SYS_SERIAL_NUMBER_OID: "EX-001-SN",
        f"{IF_MIB_IF_ADMIN_STATUS_PREFIX}.1": 1,
        f"{IF_MIB_IF_ADMIN_STATUS_PREFIX}.2": 1,
        f"{IF_MIB_IF_OPER_STATUS_PREFIX}.1": 1,
        f"{IF_MIB_IF_OPER_STATUS_PREFIX}.2": 2,
        f"{EXTREME_POE_PORT_MEASURED_POWER_PREFIX}.1": 15400,
        f"{IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX}.1.10.1.10.11": "00:50:56:01:10:11",
        f"{LLDP_REM_SYS_NAME_PREFIX}.100.1": "core-rtr-001",
        f"{LLDP_REM_PORT_ID_PREFIX}.100.1": "1:48",
        f"{PETH_PSE_PORT_ADMIN_ENABLE_PREFIX}.1.1": 1,
        f"{PETH_PSE_PORT_DETECTION_STATUS_PREFIX}.1.1": 3,
    }

    apc_oids = {
        SNMPV2_MIB_SYS_DESCR: "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6)",
        SNMPV2_MIB_SYS_UPTIME: "9876543",
        SNMPV2_MIB_SYS_NAME: "apc-ups-001-01",
        APC_UPS_BASIC_IDENT_MODEL_OID: "Smart-UPS SRT 5000",
        APC_UPS_BASIC_STATE_OUTPUT_STATE_OID: "00010000",
        APC_UPS_ADV_BATTERY_CAPACITY_OID: 100,
        APC_UPS_ADV_OUTPUT_LOAD_OID: 42,
    }

    def fake_snmp_transport(
        target_ip: str, oids: list[str], operation: str, timeout: float
    ) -> dict[str, Any]:
        _ = (oids, operation, timeout)
        if target_ip == "10.1.1.2":
            return extreme_oids
        if target_ip == "10.1.20.10":
            return apc_oids
        return {}

    snmp = SnmpWalkConnector(
        community="public-ro",
        version="2c",
        scope_guard=guard,
        transport=fake_snmp_transport,
    )

    assert len(LLDP_MIB_OIDS) == 3
    assert len(POWER_ETHERNET_MIB_OIDS) == 2
    assert all(oid in EXTREME_SWITCH_MIB_OIDS for oid in LLDP_MIB_OIDS)
    assert all(oid in EXTREME_SWITCH_MIB_OIDS for oid in POWER_ETHERNET_MIB_OIDS)
    assert len(APC_UPS_MIB_OIDS) > 3

    sw_result = snmp.walk_extreme_switch("10.1.1.2")
    assert sw_result["vendor"] == "Extreme Networks"
    assert sw_result["sys_name"] == "ext-sw-001-01"
    assert sw_result["ports_up"] == 1
    assert sw_result["ports_down"] == 1
    assert sw_result["lldp_neighbor_count"] == 1
    assert sw_result["lldp_neighbors"] == ["core-rtr-001"]
    assert sw_result["peth_admin_enabled_ports"] == 1
    assert sw_result["peth_delivering_ports"] == 1

    ups_result = snmp.walk_apc_ups("10.1.20.10")
    assert ups_result["vendor"] == "APC"
    assert ups_result["model"] == "Smart-UPS SRT 5000"
    assert ups_result["on_line"] is True
    assert ups_result["battery_capacity_pct"] == 100

    # Out-of-scope IP is rejected by SubnetScopeGuard
    with pytest.raises(ScopeViolationError):
        snmp.get("10.99.1.2")

    # Works directly as snmp_probe_fn in ManagementProbeCollector
    collector = ManagementProbeCollector(
        snmp_probe_fn=snmp,
        scope_guard=guard,
    )
    sw_sig = collector.collect_for_device(site.devices[0], site=site)
    assert sw_sig.status is SignalStatus.ACTIVE
    assert "Extreme Networks SNMP GET active on 10.1.1.2" in (sw_sig.details or "")


@pytest.mark.parametrize("bad_op", ["SET", "SNMP-SET", "SETNEXT", "WRITE", "TRAP"])
def test_snmp_connector_rejects_set_and_write_profiles(bad_op: str) -> None:
    transport_called = False

    def forbidden_snmp_transport(target_ip: str, oids: list[str]) -> dict[str, Any]:
        nonlocal transport_called
        transport_called = True
        return {target_ip: oids}

    snmp = SnmpWalkConnector(
        community="public-ro",
        transport=forbidden_snmp_transport,
    )

    with pytest.raises(PermissionError) as exc_info:
        snmp.query("10.1.1.2", operation=bad_op)
    assert isinstance(exc_info.value, ConnectorReadOnlyError)
    assert transport_called is False
    assert snmp.telemetry.blocked_mutations == 1

    with pytest.raises(PermissionError):
        snmp.set("10.1.1.2", {SNMPV2_MIB_SYS_NAME: "mutated"})
    assert snmp.telemetry.blocked_mutations == 2
    assert transport_called is False


@pytest.mark.parametrize(
    ("bad_mode", "bad_community"),
    [
        ("readwrite", "public-ro"),
        ("rw", "public-ro"),
        ("readonly", "private"),
        ("readonly", "write"),
        ("readonly", "rw"),
        ("readonly", "corp-rw"),
    ],
)
def test_snmp_connector_rejects_write_mode_or_community_at_init(
    bad_mode: str, bad_community: str
) -> None:
    with pytest.raises(PermissionError) as exc_info:
        SnmpWalkConnector(mode=bad_mode, community=bad_community)
    assert isinstance(exc_info.value, ConnectorReadOnlyError)


# ---------------------------------------------------------------------------
# 4. PilotCutoverValidator Tests (-k preflight)
# ---------------------------------------------------------------------------


def test_preflight_validator_passes_valid_3_site_pilot_cohort() -> None:
    sot_client = FixtureSoTClient(num_sites=5)

    scraper = AuthenticatedScraperSession(
        base_url="https://sot.internal",
        session_token="pilot-ro-token",
        transport=lambda method, url: "<html><div data-site-id='site-001'></div></html>",
    )

    vsphere = VSphereRestConnector(
        instances=["vcenter-01.corp.internal", "vcenter-02.corp.internal"],
        auth_token="vc-ro-token",
        transport=lambda method, url: {
            "value": [
                {
                    "vm": "vm-101",
                    "name": "win-srv-001-01",
                    "power_state": "POWERED_ON",
                }
            ]
        },
    )

    snmp = SnmpWalkConnector(
        community="public-ro",
        transport=lambda ip, oids: {
            SNMPV2_MIB_SYS_NAME: f"sw-{ip}",
            SNMPV2_MIB_SYS_DESCR: "ExtremeXOS",
            SNMPV2_MIB_SYS_UPTIME: "1000",
        },
    )

    validator = PilotCutoverValidator(
        sot_client=sot_client,
        scraper_session=scraper,
        vsphere_connector=vsphere,
        snmp_connector=snmp,
    )

    report = validator.validate(["site-001", "site-002", "site-003"])
    assert isinstance(report, PreFlightReport)
    assert report.ready is True
    assert report.pilot_site_ids == ["site-001", "site-002", "site-003"]
    assert report.blocking_errors == []
    assert report.warnings == []
    assert all(isinstance(c, PreFlightCheckResult) and c.passed for c in report.checks)

    serialized = report.to_dict()
    assert serialized["ready"] is True
    assert len(serialized["checks"]) >= 4


def test_preflight_validator_rejects_unsegmented_slash16_sweep() -> None:
    sot_client = FixtureSoTClient(num_sites=3)
    validator = PilotCutoverValidator(sot_client=sot_client)

    report = validator.validate(
        ["site-001", "site-002", "site-003"],
        target_subnets_by_site={"site-002": ["10.2.0.0/16"]},
    )

    assert report.ready is False
    assert any("/16" in err for err in report.blocking_errors)
    failed_checks = [c for c in report.checks if not c.passed]
    assert any(
        c.check_name == "subnet_scope_safety" and c.site_id == "site-002"
        for c in failed_checks
    )


def test_preflight_validator_rejects_out_of_subnet_ip_and_mixed_slash16_site() -> None:
    bad_site = Site(
        site_id="site-099",
        name="Site 099",
        subnets=[
            Subnet(subnet_id="s1", site_id="site-099", cidr="10.99.1.0/24"),
            Subnet(subnet_id="s2", site_id="site-099", cidr="10.98.1.0/24"),
        ],
        devices=[
            NetworkDevice(
                device_id="sw-99",
                site_id="site-099",
                hostname="sw-99",
                management_ip="10.77.1.2",
            )
        ],
    )
    validator = PilotCutoverValidator()
    report = validator.validate(["site-099"], sites=[bad_site])

    assert report.ready is False
    assert len(report.warnings) == 1  # 1 site is outside 3-5 recommended cohort size
    assert any("multiple 10.x.0.0/16" in err for err in report.blocking_errors)


def test_preflight_validator_detects_unreachable_endpoints_and_broken_guardrails() -> None:
    sot_client = FixtureSoTClient(num_sites=3)

    # Unreachable scraper + unreachable vCenter
    dead_scraper = AuthenticatedScraperSession(
        base_url="https://sot.internal",
        max_retries=0,
        transport=lambda method, url: (_ for _ in ()).throw(
            ConnectionError("SoT down")
        ),
    )
    dead_vsphere = VSphereRestConnector(
        instances=["vcenter-dead.corp.internal"],
        max_retries=0,
        transport=lambda method, url: (_ for _ in ()).throw(
            TimeoutError("vCenter timeout")
        ),
    )

    validator = PilotCutoverValidator(
        sot_client=sot_client,
        scraper_session=dead_scraper,
        vsphere_connector=dead_vsphere,
    )
    report = validator.validate(["site-001", "site-002", "site-003"])
    assert report.ready is False
    assert any("health check failed" in err for err in report.blocking_errors)
    assert any("vcenter-dead.corp.internal" in err for err in report.blocking_errors)

    # Simulate a tampered connector that fails read-only guardrail check
    class _UnsafeScraper:
        base_url = "https://sot.internal"

        def request(self, method: str, path: str) -> str:
            return f"ALLOWED {method} {path}"

        def check_health(self, path: str = "/sites") -> bool:
            _ = path
            return True

    unsafe_validator = PilotCutoverValidator(
        sot_client=sot_client,
        scraper_session=_UnsafeScraper(),  # type: ignore[arg-type]
    )
    unsafe_report = unsafe_validator.validate(["site-001", "site-002", "site-003"])
    assert unsafe_report.ready is False
    assert any("failed to block mutating request" in err for err in unsafe_report.blocking_errors)
