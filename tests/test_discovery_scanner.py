"""Unit tests for the native /16-to-/24 subnet discovery scanner and Site bootstrapper."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from sot_validator.classifier import ClassificationEngine
from sot_validator.discovery import (
    DiscoveredHost,
    DiscoveryConfig,
    SubnetDiscoveryScanner,
    parse_ip_neigh_output,
)
from sot_validator.models import (
    EquipmentCategory,
    Site,
    ValidationClassification,
)
from sot_validator.signals.icmp import IcmpProbeResponse, SubnetScopeGuard


def test_discovery_config_defaults_and_validation() -> None:
    cfg = DiscoveryConfig(cidr="10.42.0.0/16")
    assert cfg.cidr == "10.42.0.0/16"
    assert cfg.gateway_octets == (1,)
    assert cfg.tcp_ports == (
        22,
        53,
        80,
        443,
        445,
        5000,
        8000,
        8006,
        8080,
        8123,
        8443,
        9000,
    )
    assert cfg.max_concurrency == 128
    assert cfg.ping_timeout_sec == 1.0
    assert cfg.tcp_timeout_sec == 0.35
    assert cfg.max_active_subnets == 32

    # Non-strict host bits in /24 or /16 are normalized to network address
    normalized_cfg = DiscoveryConfig(
        cidr="10.42.1.55/24",
        gateway_octets=[1, 254, 1],
        tcp_ports=[443, 22, 443],
    )
    assert normalized_cfg.cidr == "10.42.1.0/24"
    assert normalized_cfg.gateway_octets == (1, 254)
    assert normalized_cfg.tcp_ports == (443, 22)

    for invalid_cidr in ("", "10.0.0.0/8", "10.42.0.0/20", "10.42.1.0/32", "not-a-cidr"):
        with pytest.raises(ValueError):
            DiscoveryConfig(cidr=invalid_cidr)

    with pytest.raises(ValueError):
        DiscoveryConfig(gateway_octets=())
    with pytest.raises(ValueError):
        DiscoveryConfig(gateway_octets=(0,))
    with pytest.raises(ValueError):
        DiscoveryConfig(gateway_octets=(255,))
    with pytest.raises(ValueError):
        DiscoveryConfig(tcp_ports=(70000,))
    with pytest.raises(ValueError):
        DiscoveryConfig(max_concurrency=0)
    with pytest.raises(ValueError):
        DiscoveryConfig(max_active_subnets=0)
    with pytest.raises(ValueError):
        DiscoveryConfig(ping_timeout_sec=0)
    with pytest.raises(ValueError):
        DiscoveryConfig(tcp_timeout_sec=-1.0)


def test_discovered_host_normalization_and_serialization() -> None:
    host = DiscoveredHost(
        ip="10.42.1.10",
        subnet_cidr="10.42.1.0/24",
        vlan_id=1,  # type: ignore[arg-type]
        icmp_reachable=True,
        rtt_ms=1.25,
        open_tcp_ports=[8006, 22, 8006, 443],
        mac_address="BC-24-11-00-AB-CD",
        arp_state="reachable",
        hostname=" pve-01.local ",
        inferred_role="hypervisor",
    )
    assert host.vlan_id == "1"
    assert host.open_tcp_ports == [22, 443, 8006]
    assert host.mac_address == "bc:24:11:00:ab:cd"
    assert host.arp_state == "REACHABLE"
    assert host.hostname == "pve-01.local"

    serialized = host.to_dict()
    restored = DiscoveredHost.from_dict(serialized)
    assert restored == host


def test_parse_ip_neigh_output() -> None:
    raw = """
    10.42.1.1 dev eth0 lladdr 00:04:96:11:22:33 REACHABLE
    10.42.1.10 dev eth0 lladdr BC-24-11-AA-BB-CC STALE
    10.42.1.25 dev eth0 lladdr 0:c0:b7:1:2:3 DELAY
    10.42.1.99 dev eth0 INCOMPLETE
    10.42.1.100 dev eth0 FAILED
    invalid line here
    fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    """
    parsed = parse_ip_neigh_output(raw)
    assert parsed == {
        "10.42.1.1": ("00:04:96:11:22:33", "REACHABLE"),
        "10.42.1.10": ("bc:24:11:aa:bb:cc", "STALE"),
        "10.42.1.25": ("00:c0:b7:01:02:03", "DELAY"),
        "10.42.1.99": (None, "INCOMPLETE"),
        "10.42.1.100": (None, "FAILED"),
    }
    assert parse_ip_neigh_output("") == {}


def test_stage1_slash16_gateway_discovery_without_full_slash16_sweep() -> None:
    probed_ips: list[str] = []
    active_gateways = {"10.42.1.1", "10.42.10.1"}

    def mock_ping(ip: str, timeout: float) -> tuple[bool, float | None]:
        assert timeout == 1.0
        probed_ips.append(ip)
        if ip in active_gateways:
            return True, 0.8
        return False, None

    scanner = SubnetDiscoveryScanner(
        DiscoveryConfig(cidr="10.42.0.0/16", gateway_octets=(1,)),
        ping_fn=mock_ping,
        arp_table_fn=lambda: {},
    )

    active_subnets = scanner.discover_active_subnets()
    assert active_subnets == ["10.42.1.0/24", "10.42.10.0/24"]
    # Stage 1 probes only the 256 .1 candidate gateways across 10.42.0..255.1
    assert len(probed_ips) == 256
    assert all(ip.endswith(".1") for ip in probed_ips)


def test_direct_slash24_skips_stage1_and_max_active_subnets_cap() -> None:
    stage1_probes: list[str] = []

    scanner_24 = SubnetDiscoveryScanner(
        DiscoveryConfig(cidr="10.42.1.0/24"),
        ping_fn=lambda ip, _t: (stage1_probes.append(ip) or False, None),
        arp_table_fn=lambda: {},
    )
    assert scanner_24.discover_active_subnets() == ["10.42.1.0/24"]
    assert stage1_probes == []

    # Verify max_active_subnets cap on /16 discovery
    responsive_gws = {f"10.42.{idx}.1" for idx in (1, 2, 3, 4, 5)}
    scanner_capped = SubnetDiscoveryScanner(
        DiscoveryConfig(cidr="10.42.0.0/16", max_active_subnets=3, tcp_ports=()),
        ping_fn=lambda ip, _t: (ip in responsive_gws, 1.1 if ip in responsive_gws else None),
        arp_table_fn=lambda: {},
    )
    active = scanner_capped.discover_active_subnets()
    assert active == ["10.42.1.0/24", "10.42.2.0/24", "10.42.3.0/24"]

    swept_hosts = scanner_capped.scan()
    assert [h.ip for h in swept_hosts] == ["10.42.1.1", "10.42.2.1", "10.42.3.1"]

    with pytest.raises(ValueError):
        scanner_capped.sweep_subnet("10.42.0.0/16")


def test_host_sweep_arp_correlation_tcp_probing_and_role_inference() -> None:
    raw_arp = "\n".join(
        [
            "10.42.1.1 dev eth0 lladdr 00:11:22:33:44:01 REACHABLE",
            "10.42.1.2 dev eth0 lladdr 00:04:96:aa:bb:cc REACHABLE",
            "10.42.1.10 dev eth0 lladdr bc:24:11:00:11:22 REACHABLE",
            "10.42.1.20 dev eth0 lladdr 00:c0:b7:11:22:33 STALE",
            "10.42.1.30 dev eth0 lladdr aa:bb:cc:00:00:30 REACHABLE",
            "10.42.1.60 dev eth0 lladdr 44:61:32:10:20:30 REACHABLE",
            "10.42.1.99 dev eth0 INCOMPLETE",
        ]
    )

    icmp_up = {
        "10.42.1.1": 0.45,
        "10.42.1.2": 0.60,
        "10.42.1.10": 0.95,
        "10.42.1.40": 1.20,
        "10.42.1.50": 1.50,
        "10.42.1.70": 2.10,
        "10.42.1.80": 1.80,
    }
    open_ports_by_ip: dict[str, set[int]] = {
        "10.42.1.1": {53, 80, 443},
        "10.42.1.2": {22, 443},
        "10.42.1.10": {22, 8006},
        "10.42.1.30": {445, 5000},  # NAS blocking ICMP but open on SMB/Synology ports
        "10.42.1.40": {53},
        "10.42.1.50": {8123},
        "10.42.1.70": {22, 443},
    }
    rdns_by_ip = {
        "10.42.1.1": "gw-site42.corp.local",
        "10.42.1.2": "sw-core-01.corp.local",
        "10.42.1.10": "pve-node01.corp.local",
        "10.42.1.20": "apc-ups-01.corp.local",
        "10.42.1.30": "synology-nas01.corp.local",
        "10.42.1.40": "dns01.corp.local",
    }

    async def async_ping(ip: str, timeout: float) -> IcmpProbeResponse:
        _ = timeout
        if ip in icmp_up:
            return IcmpProbeResponse(reachable=True, latency_ms=icmp_up[ip])
        return IcmpProbeResponse(reachable=False, latency_ms=None)

    async def async_tcp(ip: str, port: int, timeout: float) -> bool:
        _ = timeout
        return port in open_ports_by_ip.get(ip, set())

    async def async_arp() -> str:
        return raw_arp

    async def async_rdns(ip: str) -> str | None:
        return rdns_by_ip.get(ip)

    scanner = SubnetDiscoveryScanner(
        DiscoveryConfig(cidr="10.42.0.0/16", gateway_octets=(1,)),
        ping_fn=async_ping,
        tcp_probe_fn=async_tcp,
        arp_table_fn=async_arp,
        rdns_fn=async_rdns,
    )

    hosts = scanner.scan()
    by_ip = {h.ip: h for h in hosts}

    assert "10.42.1.99" not in by_ip
    assert set(by_ip) == {
        "10.42.1.1",
        "10.42.1.2",
        "10.42.1.10",
        "10.42.1.20",
        "10.42.1.30",
        "10.42.1.40",
        "10.42.1.50",
        "10.42.1.60",
        "10.42.1.70",
        "10.42.1.80",
    }

    assert by_ip["10.42.1.1"].inferred_role == "router"
    assert by_ip["10.42.1.1"].vlan_id == "1"
    assert by_ip["10.42.1.1"].rtt_ms == pytest.approx(0.45)

    assert by_ip["10.42.1.2"].inferred_role == "switch"
    assert by_ip["10.42.1.2"].mac_address == "00:04:96:aa:bb:cc"

    assert by_ip["10.42.1.10"].inferred_role == "hypervisor"
    assert by_ip["10.42.1.10"].open_tcp_ports == [22, 8006]

    assert by_ip["10.42.1.20"].inferred_role == "ups"
    assert by_ip["10.42.1.20"].icmp_reachable is False
    assert by_ip["10.42.1.20"].arp_state == "STALE"

    assert by_ip["10.42.1.30"].inferred_role == "nas_storage"
    assert by_ip["10.42.1.30"].open_tcp_ports == [445, 5000]

    assert by_ip["10.42.1.40"].inferred_role == "dns_server"
    assert by_ip["10.42.1.50"].inferred_role == "automation_hub"
    assert by_ip["10.42.1.60"].inferred_role == "iot_device"
    assert by_ip["10.42.1.70"].inferred_role == "server"
    assert by_ip["10.42.1.80"].inferred_role == "host"


def test_site_snapshot_generation_and_classification_compatibility() -> None:
    observed_dt = datetime(2026, 11, 12, 1, 0, 0, tzinfo=timezone.utc)
    arp_map = {
        "10.42.1.1": ("00:11:22:33:44:01", "REACHABLE"),
        "10.42.1.2": ("00:04:96:aa:bb:cc", "REACHABLE"),
        "10.42.1.10": ("bc:24:11:00:11:22", "REACHABLE"),
        "10.42.1.20": ("00:c0:b7:11:22:33", "REACHABLE"),
        "10.42.1.30": ("aa:bb:cc:dd:ee:30", "REACHABLE"),
    }
    ping_up = {"10.42.1.1", "10.42.1.2", "10.42.1.10", "10.42.1.20", "10.42.1.30"}
    open_ports = {
        "10.42.1.1": {53, 443},
        "10.42.1.2": {22},
        "10.42.1.10": {22, 8006},
        "10.42.1.30": {445, 5000},
    }

    scanner = SubnetDiscoveryScanner(
        DiscoveryConfig(cidr="10.42.0.0/16", gateway_octets=(1,)),
        ping_fn=lambda ip, _t: (ip in ping_up, 0.9 if ip in ping_up else None),
        tcp_probe_fn=lambda ip, port, _t: port in open_ports.get(ip, set()),
        arp_table_fn=lambda: arp_map,
        rdns_fn=lambda ip: f"host-{ip.split('.')[-1]}.site42.local",
    )

    site = scanner.discover_site(
        site_id="site-42",
        site_name="Site 42 Live Discovery",
        observed_at=observed_dt,
    )

    assert site.site_id == "site-42"
    assert site.name == "Site 42 Live Discovery"
    assert len(site.vlans) == 1
    assert site.vlans[0].vlan_id == "1"
    assert site.vlans[0].cidr == "10.42.1.0/24"
    assert site.vlans[0].gateway == "10.42.1.1"

    assert len(site.subnets) == 1
    assert site.subnets[0].subnet_id == "site-42-sub-1"
    assert site.subnets[0].cidr == "10.42.1.0/24"
    assert site.subnets[0].vlan_id == "1"

    # Gateway router (.1) and Extreme switch (.2) become NetworkDevice records
    dev_by_ip = {d.management_ip: d for d in site.devices}
    assert set(dev_by_ip) == {"10.42.1.1", "10.42.1.2"}
    assert dev_by_ip["10.42.1.1"].role == "router"
    assert dev_by_ip["10.42.1.2"].role == "switch"
    assert dev_by_ip["10.42.1.2"].vendor == "Extreme Networks"

    # Equipment records created for .10 (SERVER), .20 (UPS), .30 (SAN)
    eq_by_ip = {e.assigned_ips[0]: e for e in site.equipment}
    assert set(eq_by_ip) == {"10.42.1.10", "10.42.1.20", "10.42.1.30"}
    assert eq_by_ip["10.42.1.10"].category is EquipmentCategory.SERVER
    assert eq_by_ip["10.42.1.20"].category is EquipmentCategory.UPS
    assert eq_by_ip["10.42.1.30"].category is EquipmentCategory.SAN

    # Gateway/switch ports link local ARP neighbors
    gw_ports_by_eq = {
        p.connected_device_id: p
        for p in dev_by_ip["10.42.1.1"].ports
        if p.connected_device_id is not None
    }
    for eq_ip, eq in eq_by_ip.items():
        assert eq.equipment_id in gw_ports_by_eq
        linked_port = gw_ports_by_eq[eq.equipment_id]
        assert linked_port.connected_mac == arp_map[eq_ip][0]
        assert linked_port.oper_status == "up"
        assert linked_port.admin_status == "up"
        assert linked_port.port_id in eq.connected_ports

    # IPAddress & ArpEntry records populated
    ip_by_addr = {rec.ip: rec for rec in site.ip_addresses}
    assert set(ip_by_addr) == {
        "10.42.1.1",
        "10.42.1.2",
        "10.42.1.10",
        "10.42.1.20",
        "10.42.1.30",
    }
    for ip_str, rec in ip_by_addr.items():
        assert rec.arp_mac == arp_map[ip_str][0]
        assert rec.arp_entry is not None
        assert rec.arp_entry.arp_mac == arp_map[ip_str][0]
        assert rec.arp_entry.arp_last_seen == observed_dt

    # Round-trip serialization via Site.to_dict() / Site.from_dict()
    rehydrated = Site.from_dict(site.to_dict())
    assert rehydrated.to_dict() == site.to_dict()

    # SubnetScopeGuard compatibility
    guard = SubnetScopeGuard.from_site(rehydrated, site_prefix="10.42.0.0/16")
    assert guard.is_ip_in_scope("10.42.1.10") is True
    assert guard.is_ip_in_scope("10.42.99.10") is False

    # ClassificationEngine compatibility
    engine = ClassificationEngine(evaluation_time=observed_dt)
    results = engine.classify_site(rehydrated, evaluation_time=observed_dt)
    assert len(results) == len(rehydrated.devices) + len(rehydrated.equipment) + len(
        rehydrated.ip_addresses
    )
    assert all(
        r.classification is ValidationClassification.CONFIRMED_ACTIVE for r in results
    )


def test_build_site_snapshot_synthesizes_gateway_when_only_hosts_discovered() -> None:
    observed_dt = datetime(2026, 11, 12, 1, 0, 0, tzinfo=timezone.utc)
    scanner = SubnetDiscoveryScanner(DiscoveryConfig(cidr="10.42.0.0/24"))
    hosts = [
        DiscoveredHost(
            ip="10.42.0.50",
            subnet_cidr="10.42.0.0/24",
            vlan_id="1",
            icmp_reachable=True,
            rtt_ms=1.1,
            open_tcp_ports=[22],
            mac_address="aa:bb:cc:dd:ee:50",
            arp_state="REACHABLE",
            inferred_role="server",
        )
    ]
    site = scanner.build_site_snapshot(
        hosts,
        site_id="site-zero",
        site_name="Site Zero",
        observed_at=observed_dt,
    )
    assert len(site.vlans) == 1
    assert site.vlans[0].vlan_id == "1"
    assert len(site.devices) == 1
    assert site.devices[0].management_ip == "10.42.0.1"
    assert site.devices[0].role == "router"
    assert len(site.devices[0].ports) == 1
    assert site.devices[0].ports[0].connected_device_id == site.equipment[0].equipment_id
