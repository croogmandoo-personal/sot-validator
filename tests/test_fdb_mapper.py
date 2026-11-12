"""Unit tests for Switch Bridge-MIB / FDB MAC-to-Port Auto-Mapper and Trunk/Access Inferrer."""

from __future__ import annotations

import json
import pytest

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
from sot_validator.topology import (
    DeviceTypeCatalog,
    FdbEntry,
    FdbTableParser,
    PortClassificationResult,
    SwitchFdbPortMapper,
    TopologyGraphBuilder,
    VALID_PORT_MODES,
)


def _build_sample_site() -> Site:
    catalog = DeviceTypeCatalog()
    router = catalog.instantiate_device(
        "unifi-multi-vlan-router",
        device_id="rtr-01",
        site_id="site-01",
        hostname="site01-router",
        management_ip="10.1.10.1",
        port_count=2,
    )
    router.ports[0].vlan_id = "10"
    router.ports[0].connected_mac = "aa:9c:6c:00:00:01"
    router.ports[1].vlan_id = "20"
    router.ports[1].connected_mac = "aa:9c:6c:00:00:02"

    switch = catalog.instantiate_device(
        "extreme-exos-24p",
        device_id="sw-01",
        site_id="site-01",
        hostname="site01-sw01",
        management_ip="10.1.10.2",
        port_count=6,
    )

    peer_switch = catalog.instantiate_device(
        "extreme-voss-core",
        device_id="sw-core",
        site_id="site-01",
        hostname="site01-core-sw",
        management_ip="10.1.10.3",
        port_count=4,
    )

    vlans = [
        VLAN(
            vlan_id="10",
            site_id="site-01",
            name="Management / Infrastructure",
            subnet_id="sub-10",
            cidr="10.1.10.0/24",
            gateway="10.1.10.1",
        ),
        VLAN(
            vlan_id="20",
            site_id="site-01",
            name="Workstation / Server",
            subnet_id="sub-20",
            cidr="10.1.20.0/24",
            gateway="10.1.20.1",
        ),
        VLAN(
            vlan_id="30",
            site_id="site-01",
            name="VoIP",
            subnet_id="sub-30",
            cidr="10.1.30.0/24",
            gateway="10.1.30.1",
        ),
    ]
    subnets = [
        Subnet(
            subnet_id="sub-10",
            site_id="site-01",
            cidr="10.1.10.0/24",
            vlan_id="10",
            gateway="10.1.10.1",
            name="Management / Infrastructure",
        ),
        Subnet(
            subnet_id="sub-20",
            site_id="site-01",
            cidr="10.1.20.0/24",
            vlan_id="20",
            gateway="10.1.20.1",
            name="Workstation / Server",
        ),
        Subnet(
            subnet_id="sub-30",
            site_id="site-01",
            cidr="10.1.30.0/24",
            vlan_id="30",
            gateway="10.1.30.1",
            name="VoIP",
        ),
    ]
    ip_addresses = [
        IPAddress(
            ip="10.1.10.1",
            subnet_id="sub-10",
            assigned_object_type="device",
            assigned_object_id="rtr-01",
            arp_mac="aa:9c:6c:00:00:01",
        ),
        IPAddress(
            ip="10.1.10.2",
            subnet_id="sub-10",
            assigned_object_type="device",
            assigned_object_id="sw-01",
            arp_mac="00:04:96:11:11:11",
        ),
        IPAddress(
            ip="10.1.10.3",
            subnet_id="sub-10",
            assigned_object_type="device",
            assigned_object_id="sw-core",
            arp_mac="00:04:96:22:22:22",
        ),
        IPAddress(
            ip="10.1.20.10",
            subnet_id="sub-20",
            assigned_object_type="equipment",
            assigned_object_id="eq-srv-01",
            arp_mac="bc:24:11:aa:bb:01",
        ),
        IPAddress(
            ip="10.1.20.11",
            subnet_id="sub-20",
            assigned_object_type="equipment",
            assigned_object_id="eq-pc-01",
            arp_mac="d4:be:d9:11:22:33",
        ),
    ]
    equipment = [
        Equipment(
            equipment_id="eq-srv-01",
            site_id="site-01",
            name="pve-node-01",
            category=EquipmentCategory.SERVER,
            assigned_ips=["10.1.20.10"],
        ),
        Equipment(
            equipment_id="eq-pc-01",
            site_id="site-01",
            name="wkstn-01",
            category=EquipmentCategory.OTHER,
            assigned_ips=["10.1.20.11"],
        ),
    ]

    return Site(
        site_id="site-01",
        name="Site 01",
        devices=[router, switch, peer_switch],
        vlans=vlans,
        subnets=subnets,
        ip_addresses=ip_addresses,
        equipment=equipment,
    )


def test_fdb_entry_and_port_classification_models() -> None:
    assert VALID_PORT_MODES == ("access", "trunk", "uplink", "empty")

    entry = FdbEntry(
        device_id=" sw-01 ",
        port_name=" 1:1 ",
        mac_address="BC-24-11-AA-BB-CC",
        vlan_id=10,  # type: ignore[arg-type]
        is_static=True,
    )
    assert entry.device_id == "sw-01"
    assert entry.port_name == "1:1"
    assert entry.mac_address == "bc:24:11:aa:bb:cc"
    assert entry.vlan_id == "10"
    assert entry.is_static is True

    round_trip = FdbEntry.from_json(entry.to_json())
    assert round_trip == entry

    with pytest.raises(ValueError):
        FdbEntry(device_id="", port_name="1:1", mac_address="bc:24:11:aa:bb:cc")
    with pytest.raises(ValueError):
        FdbEntry(device_id="sw-01", port_name="1:1", mac_address="not-a-mac")

    res = PortClassificationResult(
        device_id="sw-01",
        port_name="1:1",
        port_mode="ACCESS",
        learned_mac_count=1,
        vlan_ids=["20", "20", " "],
        bound_mac="BC24.11AA.BB01",
        bound_device_id="eq-srv-01",
        rationale="Single host",
    )
    assert res.port_mode == "access"
    assert res.vlan_ids == ["20"]
    assert res.bound_mac == "bc:24:11:aa:bb:01"
    assert PortClassificationResult.from_json(res.to_json()) == res

    with pytest.raises(ValueError):
        PortClassificationResult(
            device_id="sw-01",
            port_name="1:1",
            port_mode="invalid_mode",
        )
    with pytest.raises(ValueError):
        PortClassificationResult(
            device_id="sw-01",
            port_name="1:1",
            port_mode="access",
            learned_mac_count=-1,
        )


def test_fdb_table_parser_exos_voss_cisco_and_auto() -> None:
    parser = FdbTableParser()

    exos_text = """
Mac                     Vlan       Age  Flags          Port / Virtual Port List
--------------------------------------------------------------------------------
00:04:96:22:22:22       VLAN_0010(0010) 0001 d m           1:24
bc:24:11:aa:bb:01       Data(0020)      0045 d m           1:1
00:c0:b7:99:88:77       Default(0001)   0000 s m           1:2
aa:bb:cc:dd:ee:ff       VLAN_0010(0010) 0000 d m           CPU
Total: 4 Static: 1
"""
    exos_entries = parser.parse_exos(exos_text, device_id="sw-01")
    assert len(exos_entries) == 3
    assert exos_entries[0] == FdbEntry(
        device_id="sw-01",
        port_name="1:24",
        mac_address="00:04:96:22:22:22",
        vlan_id="10",
        is_static=False,
    )
    assert exos_entries[1] == FdbEntry(
        device_id="sw-01",
        port_name="1:1",
        mac_address="bc:24:11:aa:bb:01",
        vlan_id="20",
        is_static=False,
    )
    assert exos_entries[2] == FdbEntry(
        device_id="sw-01",
        port_name="1:2",
        mac_address="00:c0:b7:99:88:77",
        vlan_id="1",
        is_static=True,
    )

    voss_text = """
================================================================================
                                Vlan Mac Address Entry
================================================================================
VLAN   MAC-ADDRESS        PORT       STATUS
--------------------------------------------------------------------------------
10     00:c0:b7:11:22:33  Port-1/1   dynamic
20     bc:24:11:aa:bb:cc  1/2        static
00:04:96:11:22:33 10 1/48 learned
"""
    voss_entries = parser.parse_voss(voss_text, device_id="sw-core")
    assert len(voss_entries) == 3
    assert voss_entries[0] == FdbEntry(
        device_id="sw-core",
        port_name="1/1",
        mac_address="00:c0:b7:11:22:33",
        vlan_id="10",
        is_static=False,
    )
    assert voss_entries[1] == FdbEntry(
        device_id="sw-core",
        port_name="1/2",
        mac_address="bc:24:11:aa:bb:cc",
        vlan_id="20",
        is_static=True,
    )
    assert voss_entries[2] == FdbEntry(
        device_id="sw-core",
        port_name="1/48",
        mac_address="00:04:96:11:22:33",
        vlan_id="10",
        is_static=False,
    )

    cisco_text = """
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  10    00c0.b7aa.bbcc    DYNAMIC     Gi1/0/1
* 20    bc24.1100.1122    STATIC      Gi0/2
 100    aa:bb:cc:dd:ee:ff dynamic     eth1
"""
    cisco_entries = parser.parse_cisco(cisco_text, device_id="sw-cisco")
    assert len(cisco_entries) == 3
    assert cisco_entries[0] == FdbEntry(
        device_id="sw-cisco",
        port_name="Gi1/0/1",
        mac_address="00:c0:b7:aa:bb:cc",
        vlan_id="10",
        is_static=False,
    )
    assert cisco_entries[1] == FdbEntry(
        device_id="sw-cisco",
        port_name="Gi0/2",
        mac_address="bc:24:11:00:11:22",
        vlan_id="20",
        is_static=True,
    )
    assert cisco_entries[2] == FdbEntry(
        device_id="sw-cisco",
        port_name="eth1",
        mac_address="aa:bb:cc:dd:ee:ff",
        vlan_id="100",
        is_static=False,
    )

    auto_entries = parser.parse_cli(
        exos_text + "\n" + voss_text + "\n" + cisco_text,
        device_id="sw-mixed",
        dialect="auto",
    )
    assert len(auto_entries) == 9


def test_fdb_table_parser_qbridge_mib_json_and_oids() -> None:
    parser = FdbTableParser()

    json_payload = json.dumps(
        {
            "device_id": "sw-01",
            "entries": [
                {
                    "mac_address": "bc:24:11:aa:bb:01",
                    "bridge_port": 1,
                    "vlan_id": 20,
                    "status": "learned",
                },
                {
                    "dot1qTpFdbAddress": "00-C0-B7-11-22-33",
                    "dot1qTpFdbPort": 2,
                    "fdb_id": 10,
                    "dot1qTpFdbStatus": 5,
                },
            ],
        }
    )
    records = parser.parse_qbridge_mib(
        json_payload,
        port_index_map={1: "1:1", 2: "1:2"},
    )
    assert len(records) == 2
    assert records[0] == FdbEntry(
        device_id="sw-01",
        port_name="1:1",
        mac_address="bc:24:11:aa:bb:01",
        vlan_id="20",
        is_static=False,
    )
    assert records[1] == FdbEntry(
        device_id="sw-01",
        port_name="1:2",
        mac_address="00:c0:b7:11:22:33",
        vlan_id="10",
        is_static=True,
    )

    # OID-keyed mapping (dot1qTpFdbPort: 1.3.6.1.2.1.17.7.1.2.2.1.2.<vlan>.<6 mac octets>)
    oid_table = {
        "1.3.6.1.2.1.17.7.1.2.2.1.2.20.188.36.17.170.187.1": 1,
        "1.3.6.1.2.1.17.4.3.1.2.0.192.183.17.34.51": 2,
    }
    oid_entries = parser.parse_qbridge_mib(
        oid_table,
        device_id="sw-01",
        port_index_map={1: "1:1", 2: "1:2"},
    )
    assert len(oid_entries) == 2
    assert oid_entries[0].mac_address == "bc:24:11:aa:bb:01"
    assert oid_entries[0].vlan_id == "20"
    assert oid_entries[0].port_name == "1:1"
    assert oid_entries[1].mac_address == "00:c0:b7:11:22:33"
    assert oid_entries[1].vlan_id is None
    assert oid_entries[1].port_name == "1:2"


def test_mapper_trunk_and_uplink_classification_never_binds_end_host() -> None:
    site = _build_sample_site()
    sw = next(d for d in site.devices if d.device_id == "sw-01")
    # Pre-contaminate trunk/uplink ports with an Equipment ID to verify cleanup
    sw.ports[3].connected_device_id = "eq-srv-01"
    sw.ports[4].connected_device_id = "eq-pc-01"
    sw.ports[5].connected_device_id = "eq-srv-01"

    fdb_entries = [
        # Port 1:4 has 4 learned MACs (> max_access_macs=2) -> trunk
        FdbEntry("sw-01", "1:4", "bc:24:11:aa:bb:01", vlan_id="20"),
        FdbEntry("sw-01", "1:4", "d4:be:d9:11:22:33", vlan_id="20"),
        FdbEntry("sw-01", "1:4", "de:ad:be:ef:00:01", vlan_id="20"),
        FdbEntry("sw-01", "1:4", "de:ad:be:ef:00:02", vlan_id="20"),
        # Port 1:5 has 1 MAC across 2 VLANs -> trunk
        FdbEntry("sw-01", "1:5", "bc:24:11:aa:bb:01", vlan_id="10"),
        FdbEntry("sw-01", "1:5", "bc:24:11:aa:bb:01", vlan_id="20"),
        # Port 1:6 has router MAC + end-host MAC -> uplink (router rtr-01)
        FdbEntry("sw-01", "1:6", "aa:9c:6c:00:00:01", vlan_id="10"),
        FdbEntry("sw-01", "1:6", "bc:24:11:aa:bb:01", vlan_id="20"),
    ]

    mapper = SwitchFdbPortMapper(max_access_macs=2)
    results = mapper.map_site_ports(site, fdb_entries, include_empty_ports=True)
    by_port = {r.port_name: r for r in results if r.device_id == "sw-01"}

    assert by_port["1:4"].port_mode == "trunk"
    assert by_port["1:4"].learned_mac_count == 4
    assert by_port["1:4"].bound_mac is None
    assert by_port["1:4"].bound_device_id is None

    assert by_port["1:5"].port_mode == "trunk"
    assert by_port["1:5"].vlan_ids == ["10", "20"]
    assert by_port["1:5"].bound_mac is None
    assert by_port["1:5"].bound_device_id is None

    assert by_port["1:6"].port_mode == "uplink"
    assert by_port["1:6"].bound_device_id == "rtr-01"
    assert by_port["1:6"].bound_mac is None  # 2 MACs on uplink, so no single MAC bound

    # Verify site switch ports were updated safely without end-host Equipment bindings
    p4 = next(p for p in sw.ports if p.name == "1:4")
    p5 = next(p for p in sw.ports if p.name == "1:5")
    p6 = next(p for p in sw.ports if p.name == "1:6")
    assert p4.oper_status == "up"
    assert p4.connected_device_id is None
    assert p4.connected_mac is None

    assert p5.oper_status == "up"
    assert p5.connected_device_id is None
    assert p5.connected_mac is None

    assert p6.oper_status == "up"
    assert p6.connected_device_id == "rtr-01"
    assert p6.connected_mac is None

    # Empty ports when include_empty_ports=True
    assert by_port["1:1"].port_mode == "empty"
    assert by_port["1:1"].learned_mac_count == 0


def test_mapper_access_voip_and_site_port_auto_binding_with_topology_graph() -> None:
    site = _build_sample_site()
    fdb_entries = [
        # Port 1:1 -> single-MAC access port for eq-srv-01
        FdbEntry("sw-01", "1:1", "bc:24:11:aa:bb:01", vlan_id="20"),
        # Port 1:2 -> VoIP phone + PC workstation (2 MACs <= max_access_macs=2, voice VLAN 30 + data VLAN 20)
        FdbEntry("sw-01", "1:2", "00:08:5d:aa:bb:cc", vlan_id="30"),
        FdbEntry("sw-01", "1:2", "d4:be:d9:11:22:33", vlan_id="20"),
        # Port 1:3 -> single unmapped MAC with ARP entry on subnet sub-20
        FdbEntry("sw-01", "1:3", "de:ad:be:ef:12:34"),
        # Port 1:6 -> single peer switch MAC on uplink to sw-core
        FdbEntry("sw-01", "1:6", "00:04:96:22:22:22", vlan_id="10"),
    ]
    extra_arp = [
        ArpEntry(
            ip="10.1.20.99",
            arp_mac="de:ad:be:ef:12:34",
            subnet_id="sub-20",
        )
    ]

    mapper = SwitchFdbPortMapper(max_access_macs=2)
    results = mapper.map_site_ports(
        site,
        fdb_entries,
        arp_entries=extra_arp,
        voip_vlan_ids=["30"],
    )
    by_port = {r.port_name: r for r in results}

    # 1:1 single-MAC access port
    assert by_port["1:1"].port_mode == "access"
    assert by_port["1:1"].bound_mac == "bc:24:11:aa:bb:01"
    assert by_port["1:1"].bound_device_id == "eq-srv-01"
    assert by_port["1:1"].vlan_ids == ["20"]

    # 1:2 VoIP + PC dual-MAC access port prioritizes known Equipment eq-pc-01 and data VLAN 20
    assert by_port["1:2"].port_mode == "access"
    assert by_port["1:2"].learned_mac_count == 2
    assert by_port["1:2"].bound_mac == "d4:be:d9:11:22:33"
    assert by_port["1:2"].bound_device_id == "eq-pc-01"
    assert by_port["1:2"].vlan_ids == ["20", "30"]

    # 1:3 single MAC correlated via ARP entry -> infers VLAN 20
    assert by_port["1:3"].port_mode == "access"
    assert by_port["1:3"].bound_mac == "de:ad:be:ef:12:34"
    assert by_port["1:3"].vlan_ids == ["20"]

    # 1:6 uplink to sw-core
    assert by_port["1:6"].port_mode == "uplink"
    assert by_port["1:6"].bound_device_id == "sw-core"
    assert by_port["1:6"].bound_mac == "00:04:96:22:22:22"

    sw = next(d for d in site.devices if d.device_id == "sw-01")
    p1 = next(p for p in sw.ports if p.name == "1:1")
    p2 = next(p for p in sw.ports if p.name == "1:2")
    p3 = next(p for p in sw.ports if p.name == "1:3")
    p6 = next(p for p in sw.ports if p.name == "1:6")

    assert p1.oper_status == "up"
    assert p1.connected_mac == "bc:24:11:aa:bb:01"
    assert p1.connected_device_id == "eq-srv-01"
    assert p1.vlan_id == "20"

    assert p2.oper_status == "up"
    assert p2.connected_mac == "d4:be:d9:11:22:33"
    assert p2.connected_device_id == "eq-pc-01"
    assert p2.vlan_id == "20"

    assert p3.oper_status == "up"
    assert p3.connected_mac == "de:ad:be:ef:12:34"
    assert p3.vlan_id == "20"

    assert p6.oper_status == "up"
    assert p6.connected_device_id == "sw-core"
    assert p6.connected_mac == "00:04:96:22:22:22"

    eq_srv = next(e for e in site.equipment if e.equipment_id == "eq-srv-01")
    eq_pc = next(e for e in site.equipment if e.equipment_id == "eq-pc-01")
    assert "sw-01:1:1" in eq_srv.connected_ports
    assert "sw-01:1:2" in eq_pc.connected_ports

    # Verify TopologyGraphBuilder integration
    graph = TopologyGraphBuilder().build(site)
    uplink_edges = [
        e
        for e in graph.edges
        if e.relation == "uplink_to" and e.source_id == "sw-01"
    ]
    assert any(e.target_id == "sw-core" and e.port_name == "1:6" for e in uplink_edges)

    port_edges = [
        e
        for e in graph.edges
        if e.relation == "connected_port" and e.source_id == "sw-01:1:1"
    ]
    assert any(e.target_id == "eq-srv-01" for e in port_edges)


def test_mapper_uplink_oui_signature_and_equipment_override() -> None:
    site = _build_sample_site()
    fdb_entries = [
        # Unknown Extreme Networks switch OUI MAC -> uplink with no peer binding
        FdbEntry("sw-01", "1:3", "00:04:96:ab:cd:ef", vlan_id="10"),
        # Extreme OUI MAC explicitly assigned to Equipment -> not infrastructure, access
        FdbEntry("sw-01", "1:4", "00:04:96:99:99:99", vlan_id="20"),
        # Switch's own management MAC is excluded from uplink detection
        FdbEntry("sw-01", "1:5", "00:04:96:11:11:11", vlan_id="10"),
    ]
    mapper = SwitchFdbPortMapper()
    results = mapper.classify_site_ports(
        site,
        fdb_entries,
        device_mac_map={"eq-srv-01": "00:04:96:99:99:99"},
    )
    by_port = {r.port_name: r for r in results}

    assert by_port["1:3"].port_mode == "uplink"
    assert by_port["1:3"].bound_device_id is None
    assert by_port["1:3"].bound_mac == "00:04:96:ab:cd:ef"
    assert "OUI" in by_port["1:3"].rationale

    assert by_port["1:4"].port_mode == "access"
    assert by_port["1:4"].bound_device_id == "eq-srv-01"

    assert by_port["1:5"].port_mode != "uplink"

    # classify_site_ports never mutates the Site
    sw = next(d for d in site.devices if d.device_id == "sw-01")
    assert all(p.oper_status == "down" for p in sw.ports)


def test_mapper_voip_dual_vlan_requires_voip_vlan_ids_and_same_vlan_is_access() -> None:
    site = _build_sample_site()
    sw = next(d for d in site.devices if d.device_id == "sw-01")
    fdb_entries = [
        FdbEntry("sw-01", "1:2", "00:08:5d:aa:bb:cc", vlan_id="30"),
        FdbEntry("sw-01", "1:2", "d4:be:d9:11:22:33", vlan_id="20"),
        # Both MACs on the same VLAN -> access without voip_vlan_ids
        FdbEntry("sw-01", "1:3", "00:08:5d:aa:bb:dd", vlan_id="20"),
        FdbEntry("sw-01", "1:3", "bc:24:11:aa:bb:01", vlan_id="20"),
    ]
    mapper = SwitchFdbPortMapper()
    by_port = {
        r.port_name: r for r in mapper.classify_device_ports(sw, fdb_entries, site=site)
    }

    assert by_port["1:2"].port_mode == "trunk"
    assert by_port["1:2"].bound_mac is None
    assert by_port["1:2"].bound_device_id is None

    assert by_port["1:3"].port_mode == "access"
    assert by_port["1:3"].bound_mac == "bc:24:11:aa:bb:01"
    assert by_port["1:3"].bound_device_id == "eq-srv-01"

    # max_access_macs=1 turns a dual-MAC port into a trunk
    strict = SwitchFdbPortMapper(max_access_macs=1)
    strict_by_port = {
        r.port_name: r for r in strict.classify_device_ports(sw, fdb_entries, site=site)
    }
    assert strict_by_port["1:3"].port_mode == "trunk"

    # Unknown FDB ports are created on the switch by map_site_ports
    mapper.map_site_ports(
        site,
        [FdbEntry("sw-01", "1:24", "bc:24:11:aa:bb:01", vlan_id="20")],
    )
    new_port = next(p for p in sw.ports if p.name == "1:24")
    assert new_port.oper_status == "up"
    assert new_port.connected_device_id == "eq-srv-01"


def test_mapper_and_parser_argument_validation() -> None:
    with pytest.raises(ValueError):
        SwitchFdbPortMapper(max_access_macs=0)
    with pytest.raises(ValueError):
        SwitchFdbPortMapper(max_access_macs=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        FdbTableParser().parse_cli("", device_id="sw-01", dialect="junos")
    assert SwitchFdbPortMapper.apply_to_site is SwitchFdbPortMapper.map_site_ports

    custom = SwitchFdbPortMapper(oui_vendors={"de:ad:be": ("Lab Switch", "switch")})
    site = _build_sample_site()
    results = custom.classify_site_ports(
        site, [FdbEntry("sw-01", "1:1", "de:ad:be:00:00:01")]
    )
    assert results[0].port_mode == "uplink"


def test_mapper_access_then_trunk_unlinks_equipment_connected_ports() -> None:
    site = _build_sample_site()
    mapper = SwitchFdbPortMapper()
    mapper.map_site_ports(
        site, [FdbEntry("sw-01", "1:1", "bc:24:11:aa:bb:01", vlan_id="20")]
    )
    eq_srv = next(e for e in site.equipment if e.equipment_id == "eq-srv-01")
    assert "sw-01:1:1" in eq_srv.connected_ports

    results = mapper.map_site_ports(
        site,
        [
            FdbEntry("sw-01", "1:1", "bc:24:11:aa:bb:01", vlan_id="20"),
            FdbEntry("sw-01", "1:1", "de:ad:be:ef:00:01", vlan_id="20"),
            FdbEntry("sw-01", "1:1", "de:ad:be:ef:00:02", vlan_id="20"),
        ],
    )
    assert results[0].port_mode == "trunk"
    assert "sw-01:1:1" not in eq_srv.connected_ports
    sw = next(d for d in site.devices if d.device_id == "sw-01")
    p1 = next(p for p in sw.ports if p.name == "1:1")
    assert p1.connected_device_id is None
    assert p1.connected_mac is None

    graph = TopologyGraphBuilder().build(site)
    assert not any(
        e.relation == "connected_port"
        and "eq-srv-01" in (e.source_id, e.target_id)
        and "sw-01:1:1" in (e.source_id, e.target_id)
        for e in graph.edges
    )


def test_mapper_unroled_ups_stays_access_and_unroled_switch_is_uplink() -> None:
    site = _build_sample_site()
    site.devices.append(
        NetworkDevice(
            device_id="ups-01",
            site_id="site-01",
            hostname="site01-ups-a",
            management_ip="10.1.10.50",
        )
    )
    site.devices.append(
        NetworkDevice(
            device_id="sw-02",
            site_id="site-01",
            hostname="site01-sw02",
            management_ip="10.1.10.4",
        )
    )
    site.ip_addresses.append(
        IPAddress(ip="10.1.10.50", subnet_id="sub-10", arp_mac="00:c0:b7:11:22:33")
    )
    site.ip_addresses.append(
        IPAddress(ip="10.1.10.4", subnet_id="sub-10", arp_mac="02:00:00:00:00:04")
    )
    sw = next(d for d in site.devices if d.device_id == "sw-01")
    # A UPS previously bound to a port that is now a trunk must be cleared
    sw.ports[3].connected_device_id = "ups-01"

    mapper = SwitchFdbPortMapper()
    results = mapper.map_site_ports(
        site,
        [
            FdbEntry("sw-01", "1:1", "00:c0:b7:11:22:33", vlan_id="10"),
            FdbEntry("sw-01", "1:2", "02:00:00:00:00:04", vlan_id="10"),
            FdbEntry("sw-01", "1:4", "de:ad:be:ef:00:01", vlan_id="10"),
            FdbEntry("sw-01", "1:4", "de:ad:be:ef:00:01", vlan_id="20"),
        ],
    )
    by_port = {r.port_name: r for r in results}

    assert by_port["1:1"].port_mode == "access"
    assert by_port["1:1"].bound_device_id == "ups-01"

    assert by_port["1:2"].port_mode == "uplink"
    assert by_port["1:2"].bound_device_id == "sw-02"

    assert by_port["1:4"].port_mode == "trunk"
    p4 = next(p for p in sw.ports if p.name == "1:4")
    assert p4.connected_device_id is None


def test_mapper_voip_pc_with_unknown_hosts_binds_data_vlan_mac() -> None:
    site = _build_sample_site()
    results = SwitchFdbPortMapper().classify_site_ports(
        site,
        [
            FdbEntry("sw-01", "1:2", "00:08:5d:aa:bb:cc", vlan_id="30"),
            FdbEntry("sw-01", "1:2", "de:ad:be:ef:00:01", vlan_id="20"),
        ],
        voip_vlan_ids=["30"],
    )
    assert results[0].port_mode == "access"
    assert results[0].bound_mac == "de:ad:be:ef:00:01"
    assert results[0].bound_device_id is None
    assert results[0].vlan_ids == ["20", "30"]


def test_fdb_table_parser_string_static_flags_and_unrelated_oids() -> None:
    parser = FdbTableParser()
    records = parser.parse_qbridge_mib(
        [
            {"mac": "bc:24:11:aa:bb:01", "port": "1:1", "is_static": "false"},
            {"mac": "bc:24:11:aa:bb:02", "port": "1:2", "is_static": "true"},
        ],
        device_id="sw-01",
    )
    assert [r.is_static for r in records] == [False, True]

    assert (
        FdbEntry.from_dict(
            {
                "device_id": "sw-01",
                "port_name": "1:1",
                "mac_address": "bc:24:11:aa:bb:01",
                "is_static": "false",
            }
        ).is_static
        is False
    )

    oid_entries = parser.parse_qbridge_mib(
        {
            "1.3.6.1.2.1.17.4.3.1.2.0.192.183.17.34.51": 2,
            # Unrelated enterprise OID with a six-component numeric tail
            "1.3.6.1.4.1.1916.1.16.4.1.0.192.183.17.34.52": 3,
        },
        device_id="sw-01",
    )
    assert len(oid_entries) == 1
    assert oid_entries[0].mac_address == "00:c0:b7:11:22:33"
