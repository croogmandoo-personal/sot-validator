"""Unit tests for the network topology graph builder (Issue #51)."""

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
    ValidationClassification,
    ValidationResult,
)
from sot_validator.topology import (
    DevicePortManager,
    DeviceTypeCatalog,
    TopologyEdge,
    TopologyGraph,
    TopologyGraphBuilder,
    TopologyNode,
    VALID_EDGE_RELATIONS,
    VALID_NODE_TYPES,
)


def _build_sample_site() -> Site:
    router = NetworkDevice(
        device_id="rtr-site1-01",
        site_id="site-01",
        hostname="udm-gw-01",
        management_ip="10.1.2.1",
        vendor="Ubiquiti",
        model="UniFi Gateway Enterprise",
        role="router",
        ports=[
            Port(
                port_id="rtr-site1-01:eth1",
                device_id="rtr-site1-01",
                name="eth1",
                admin_status="up",
                oper_status="up",
                vlan_id="2",
                connected_device_id="sw-site1-core",
            ),
            Port(
                port_id="rtr-site1-01:eth2",
                device_id="rtr-site1-01",
                name="eth2",
                admin_status="up",
                oper_status="up",
                vlan_id="3",
            ),
        ],
    )

    core_switch = NetworkDevice(
        device_id="sw-site1-core",
        site_id="site-01",
        hostname="exos-core-01",
        management_ip="10.1.2.2",
        vendor="Extreme Networks",
        model="Summit X460-G2-48p",
        role="switch",
        ports=[
            Port(
                port_id="sw-site1-core:1:1",
                device_id="sw-site1-core",
                name="1:1",
                admin_status="up",
                oper_status="up",
                vlan_id="2",
                connected_device_id="rtr-site1-01",
            ),
            Port(
                port_id="sw-site1-core:1:2",
                device_id="sw-site1-core",
                name="1:2",
                admin_status="up",
                oper_status="up",
                poe_status="off",
                vlan_id="2",
                connected_device_id="eq-pve-01",
                connected_mac="BC-24-11-00-11-22",
            ),
            Port(
                port_id="sw-site1-core:1:3",
                device_id="sw-site1-core",
                name="1:3",
                admin_status="up",
                oper_status="up",
                poe_status="delivering",
                vlan_id="3",
                connected_mac="00:c0:b7:aa:bb:cc",
            ),
            Port(
                port_id="sw-site1-core:1:4",
                device_id="sw-site1-core",
                name="1:4",
                admin_status="up",
                oper_status="up",
                vlan_id="2",
            ),
            Port(
                port_id="sw-site1-core:1:48",
                device_id="sw-site1-core",
                name="1:48",
                admin_status="up",
                oper_status="down",
                poe_status="auto",
                vlan_id="2",
            ),
        ],
    )

    idf_switch = NetworkDevice(
        device_id="sw-site1-idf",
        site_id="site-01",
        hostname="exos-idf-01",
        management_ip="10.1.3.2",
        vendor="Extreme Networks",
        model="Summit X440-G2-24p",
        role="switch",
        ports=[
            Port(
                port_id="sw-site1-idf:1:24",
                device_id="sw-site1-idf",
                name="1:24",
                admin_status="up",
                oper_status="up",
                vlan_id="3",
                connected_device_id="sw-site1-core",
            ),
            Port(
                port_id="sw-site1-idf:1:5",
                device_id="sw-site1-idf",
                name="1:5",
                admin_status="up",
                oper_status="up",
                vlan_id="3",
                connected_mac="44:61:32:10:20:30",
            ),
        ],
    )

    vlans = [
        VLAN(
            vlan_id="2",
            site_id="site-01",
            name="Virtualization & Storage",
            subnet_id="sub-site1-v2",
            cidr="10.1.2.0/24",
            gateway="10.1.2.1",
        ),
        VLAN(
            vlan_id="3",
            site_id="site-01",
            name="IoT & Power",
            subnet_id="sub-site1-v3",
            cidr="10.1.3.0/24",
            gateway="10.1.3.1",
        ),
    ]

    subnets = [
        Subnet(
            subnet_id="sub-site1-v2",
            site_id="site-01",
            cidr="10.1.2.0/24",
            vlan_id="2",
            gateway="10.1.2.1",
            name="VLAN 2 Subnet",
        ),
        Subnet(
            subnet_id="sub-site1-v3",
            site_id="site-01",
            cidr="10.1.3.0/24",
            vlan_id="3",
            gateway="10.1.3.1",
            name="VLAN 3 Subnet",
        ),
    ]

    equipment = [
        Equipment(
            equipment_id="eq-pve-01",
            site_id="site-01",
            name="pve-node-01",
            category=EquipmentCategory.SERVER,
            assigned_ips=["10.1.2.10"],
            connected_ports=["sw-site1-core:1:2"],
            power_state="on",
        ),
        Equipment(
            equipment_id="eq-vm-win01",
            site_id="site-01",
            name="win-app-vm01",
            category=EquipmentCategory.VM,
            assigned_ips=["10.1.2.50"],
            hypervisor_id="eq-pve-01",
            power_state="poweredOn",
        ),
        Equipment(
            equipment_id="eq-nas-01",
            site_id="site-01",
            name="synology-nas-01",
            category=EquipmentCategory.SAN,
            assigned_ips=["10.1.2.20"],
            connected_ports=["sw-site1-core:1:4"],
            power_state="on",
        ),
        Equipment(
            equipment_id="eq-ups-01",
            site_id="site-01",
            name="apc-smart-ups-01",
            category=EquipmentCategory.UPS,
            assigned_ips=["10.1.3.15"],
            power_state="online",
        ),
    ]

    ip_addresses = [
        IPAddress(
            ip="10.1.2.1",
            subnet_id="sub-site1-v2",
            assigned_object_type="device",
            assigned_object_id="rtr-site1-01",
            arp_mac="aa:9c:6c:00:00:01",
        ),
        IPAddress(
            ip="10.1.2.2",
            subnet_id="sub-site1-v2",
            assigned_object_type="device",
            assigned_object_id="sw-site1-core",
            arp_mac="00:04:96:00:00:01",
        ),
        IPAddress(
            ip="10.1.2.10",
            subnet_id="sub-site1-v2",
            assigned_object_type="equipment",
            assigned_object_id="eq-pve-01",
            arp_mac="bc:24:11:00:11:22",
        ),
        IPAddress(
            ip="10.1.2.20",
            subnet_id="sub-site1-v2",
            assigned_object_type="equipment",
            assigned_object_id="eq-nas-01",
            arp_mac="00:11:32:aa:bb:cc",
        ),
        IPAddress(
            ip="10.1.2.50",
            subnet_id="sub-site1-v2",
            assigned_object_type="equipment",
            assigned_object_id="eq-vm-win01",
            arp_mac="bc:24:11:00:55:66",
        ),
        IPAddress(
            ip="10.1.3.15",
            subnet_id="sub-site1-v3",
            assigned_object_type="equipment",
            assigned_object_id="eq-ups-01",
            arp_entry=ArpEntry(
                ip="10.1.3.15",
                arp_mac="00:c0:b7:aa:bb:cc",
                subnet_id="sub-site1-v3",
            ),
        ),
        IPAddress(
            ip="10.1.3.99",
            subnet_id="sub-site1-v3",
            arp_mac="44:61:32:10:20:30",
        ),
    ]

    return Site(
        site_id="site-01",
        name="Site 01 Main Campus",
        address="100 Enterprise Way",
        contact_info="netops@example.com",
        rooms=["MDF-1", "IDF-2"],
        devices=[router, core_switch, idf_switch],
        vlans=vlans,
        subnets=subnets,
        ip_addresses=ip_addresses,
        equipment=equipment,
    )


def test_topology_node_validation_and_round_trip() -> None:
    assert VALID_NODE_TYPES == (
        "site",
        "router",
        "switch",
        "vlan",
        "subnet",
        "port",
        "equipment",
        "ip",
    )

    node = TopologyNode(
        node_id="sw-01",
        node_type="SWITCH",
        label="core-sw-01",
        ip="10.1.2.2",
        mac="00-04-96-AA-BB-CC",
        vlan_id="2",
        status="Confirmed Active",
        metadata={"vendor": "Extreme Networks"},
    )
    assert node.node_type == "switch"
    assert node.mac == "00:04:96:aa:bb:cc"

    as_dict = node.to_dict()
    assert TopologyNode.from_dict(as_dict) == node

    as_json = node.to_json(indent=2)
    assert TopologyNode.from_json(as_json) == node

    with pytest.raises(ValueError, match="Invalid node_type"):
        TopologyNode(node_id="n1", node_type="hub", label="bad")

    with pytest.raises(ValueError, match="node_id must be a non-empty string"):
        TopologyNode(node_id="  ", node_type="switch", label="sw")

    with pytest.raises(ValueError, match="label must be a non-empty string"):
        TopologyNode(node_id="n1", node_type="switch", label="")

    with pytest.raises(ValueError, match="metadata must be a mapping"):
        TopologyNode(
            node_id="n1",
            node_type="switch",
            label="sw",
            metadata=["invalid"],  # type: ignore[arg-type]
        )


def test_topology_edge_validation_and_round_trip() -> None:
    assert VALID_EDGE_RELATIONS == (
        "routes_vlan",
        "uplink_to",
        "member_of_vlan",
        "connected_port",
        "assigned_ip",
        "hosts_vm",
    )

    edge = TopologyEdge(
        source_id="sw-01:1:3",
        target_id="eq-ups-01",
        relation="CONNECTED_PORT",
        port_name="1:3",
        vlan_id="3",
        poe_status="delivering",
    )
    assert edge.relation == "connected_port"

    as_dict = edge.to_dict()
    assert TopologyEdge.from_dict(as_dict) == edge

    as_json = edge.to_json()
    assert TopologyEdge.from_json(as_json) == edge

    with pytest.raises(ValueError, match="Invalid edge relation"):
        TopologyEdge(source_id="a", target_id="b", relation="peers_with")

    with pytest.raises(ValueError, match="source_id must be a non-empty string"):
        TopologyEdge(source_id="", target_id="b", relation="uplink_to")

    with pytest.raises(ValueError, match="target_id must be a non-empty string"):
        TopologyEdge(source_id="a", target_id="   ", relation="uplink_to")


def test_topology_graph_builder_constructs_complete_hierarchy() -> None:
    site = _build_sample_site()
    validation_results = [
        ValidationResult(
            item_type="equipment",
            item_id="eq-pve-01",
            site_id="site-01",
            name="pve-node-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
        ),
        ValidationResult(
            item_type="equipment",
            item_id="eq-ups-01",
            site_id="site-01",
            name="apc-smart-ups-01",
            classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
            confidence=0.60,
        ),
        ValidationResult(
            item_type="port",
            item_id="sw-site1-core:1:3",
            site_id="site-01",
            name="exos-core-01:1:3",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.90,
        ),
    ]

    builder = TopologyGraphBuilder()
    graph = builder.build(site, validation_results)

    assert graph.site_id == "site-01"

    # Verify node types and lookup
    site_node = graph.get_node("site-01")
    assert site_node is not None and site_node.node_type == "site"

    router_node = graph.get_node("rtr-site1-01")
    assert router_node is not None
    assert router_node.node_type == "router"
    assert router_node.ip == "10.1.2.1"

    core_sw_node = graph.get_node("sw-site1-core")
    idf_sw_node = graph.get_node("sw-site1-idf")
    assert core_sw_node is not None and core_sw_node.node_type == "switch"
    assert idf_sw_node is not None and idf_sw_node.node_type == "switch"

    vlan2_node = graph.get_node("2")
    vlan3_node = graph.get_node("3")
    assert vlan2_node is not None and vlan2_node.node_type == "vlan"
    assert vlan3_node is not None and vlan3_node.node_type == "vlan"

    sub2_node = graph.get_node("sub-site1-v2")
    sub3_node = graph.get_node("sub-site1-v3")
    assert sub2_node is not None and sub2_node.node_type == "subnet"
    assert sub3_node is not None and sub3_node.node_type == "subnet"

    # Unconnected down port 1:48 should be omitted by default
    assert graph.get_node("sw-site1-core:1:48") is None
    assert graph.get_node("sw-site1-core:1:2") is not None
    assert graph.get_node("sw-site1-core:1:3") is not None

    # Verify ValidationResult status & confidence annotation
    pve_node = graph.get_node("eq-pve-01")
    assert pve_node is not None
    assert pve_node.status == "Confirmed Active"
    assert pve_node.metadata["confidence"] == 0.95
    assert pve_node.mac == "bc:24:11:00:11:22"
    assert pve_node.vlan_id == "2"

    ups_node = graph.get_node("eq-ups-01")
    assert ups_node is not None
    assert ups_node.status == "Unreachable / Needs Manual Review"
    assert ups_node.mac == "00:c0:b7:aa:bb:cc"
    assert ups_node.vlan_id == "3"

    port3_node = graph.get_node("sw-site1-core:1:3")
    assert port3_node is not None
    assert port3_node.status == "Confirmed Active"

    edge_triples = {(e.source_id, e.target_id, e.relation) for e in graph.edges}

    # 1. uplink_to: site -> router, core_switch -> router, idf_switch -> core_switch
    assert ("site-01", "rtr-site1-01", "uplink_to") in edge_triples
    assert ("sw-site1-core", "rtr-site1-01", "uplink_to") in edge_triples
    assert ("sw-site1-idf", "sw-site1-core", "uplink_to") in edge_triples

    # 2. routes_vlan: router -> VLANs, VLANs -> subnets
    assert ("rtr-site1-01", "2", "routes_vlan") in edge_triples
    assert ("rtr-site1-01", "3", "routes_vlan") in edge_triples
    assert ("2", "sub-site1-v2", "routes_vlan") in edge_triples
    assert ("3", "sub-site1-v3", "routes_vlan") in edge_triples

    # 3. connected_port: switch -> port and port -> host (by connected_device_id, connected_ports, and MAC/ARP)
    assert ("sw-site1-core", "sw-site1-core:1:2", "connected_port") in edge_triples
    assert ("sw-site1-core:1:2", "eq-pve-01", "connected_port") in edge_triples
    assert ("sw-site1-core:1:3", "eq-ups-01", "connected_port") in edge_triples
    assert ("sw-site1-core:1:4", "eq-nas-01", "connected_port") in edge_triples
    assert ("sw-site1-idf:1:5", "10.1.3.99", "connected_port") in edge_triples

    poe_edge = next(
        e
        for e in graph.edges
        if e.source_id == "sw-site1-core:1:3"
        and e.target_id == "eq-ups-01"
        and e.relation == "connected_port"
    )
    assert poe_edge.port_name == "1:3"
    assert poe_edge.vlan_id == "3"
    assert poe_edge.poe_status == "delivering"

    # 4. member_of_vlan: VLAN -> equipment, switches, and unassigned IP
    assert ("2", "eq-pve-01", "member_of_vlan") in edge_triples
    assert ("2", "eq-vm-win01", "member_of_vlan") in edge_triples
    assert ("2", "eq-nas-01", "member_of_vlan") in edge_triples
    assert ("3", "eq-ups-01", "member_of_vlan") in edge_triples
    assert ("2", "sw-site1-core", "member_of_vlan") in edge_triples
    assert ("3", "10.1.3.99", "member_of_vlan") in edge_triples

    # 5. assigned_ip: equipment/device -> IP
    assert ("eq-pve-01", "10.1.2.10", "assigned_ip") in edge_triples
    assert ("eq-vm-win01", "10.1.2.50", "assigned_ip") in edge_triples
    assert ("eq-nas-01", "10.1.2.20", "assigned_ip") in edge_triples
    assert ("eq-ups-01", "10.1.3.15", "assigned_ip") in edge_triples
    assert ("rtr-site1-01", "10.1.2.1", "assigned_ip") in edge_triples

    # 6. hosts_vm: hypervisor -> VM
    assert ("eq-pve-01", "eq-vm-win01", "hosts_vm") in edge_triples

    # Verify summary_counts accuracy
    counts = graph.summary_counts
    assert counts["total_nodes"] == len(graph.nodes)
    assert counts["total_edges"] == len(graph.edges)
    assert counts["site"] == 1
    assert counts["router"] == 1
    assert counts["switch"] == 2
    assert counts["vlan"] == 2
    assert counts["subnet"] == 2
    assert counts["equipment"] == 4
    assert counts["ip"] == 7
    assert counts["hosts_vm"] == 1
    assert sum(counts[nt] for nt in VALID_NODE_TYPES) == counts["total_nodes"]
    assert sum(counts[er] for er in VALID_EDGE_RELATIONS) == counts["total_edges"]

    # Verify get_edges_for_node helper
    vm_edges = graph.get_edges_for_node("eq-vm-win01")
    assert any(e.relation == "hosts_vm" and e.source_id == "eq-pve-01" for e in vm_edges)
    assert any(e.relation == "assigned_ip" and e.target_id == "10.1.2.50" for e in vm_edges)


def test_topology_graph_json_and_mermaid_export() -> None:
    site = _build_sample_site()
    graph = TopologyGraphBuilder().build(site)

    raw_json = graph.to_json(indent=2)
    parsed = json.loads(raw_json)
    assert parsed["site_id"] == "site-01"
    restored = TopologyGraph.from_json(raw_json)
    assert restored == graph

    mermaid = graph.to_mermaid()
    lines = mermaid.splitlines()
    assert lines[0] == "flowchart LR"
    assert any('["Site 01 Main Campus"]' in line for line in lines)
    assert any('["udm-gw-01 - 10.1.2.1"]' in line for line in lines)
    assert any("-->|routes_vlan VLAN 2|" in line for line in lines)
    assert any("-->|connected_port 1:3 VLAN 3 PoE:delivering|" in line for line in lines)
    assert any("-->|hosts_vm|" in line for line in lines)

    # Numeric VLAN IDs ("2", "3") must be prefixed so Mermaid IDs never start with a digit
    assert any("n_2[" in line for line in lines)
    assert any("n_3[" in line for line in lines)


def test_include_unconnected_ports_and_template_integration() -> None:
    catalog = DeviceTypeCatalog()
    sw = catalog.instantiate_device(
        "extreme-exos-24p",
        device_id="sw-24p",
        site_id="site-tpl",
        hostname="sw-24p-01",
        management_ip="10.2.1.2",
        default_vlan_id="10",
    )
    mgr = DevicePortManager(sw)
    mgr.bind_mac_to_port(
        "1:1",
        "bc:24:11:aa:bb:01",
        connected_device_id="srv-01",
        vlan_id="10",
    )

    site = Site(
        site_id="site-tpl",
        name="Template Site",
        devices=[sw],
        equipment=[
            Equipment(
                equipment_id="srv-01",
                site_id="site-tpl",
                name="proxmox-01",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.2.1.10"],
            )
        ],
    )

    compact_graph = TopologyGraphBuilder(include_unconnected_ports=False).build(site)
    assert compact_graph.summary_counts["port"] == 1
    assert compact_graph.get_node("sw-24p:1:1") is not None
    assert compact_graph.get_node("sw-24p:1:24") is None

    full_graph = TopologyGraphBuilder(include_unconnected_ports=True).build(site)
    assert full_graph.summary_counts["port"] == 24
    assert full_graph.get_node("sw-24p:1:24") is not None

    # Site with no routers links site -> switch via uplink_to
    assert any(
        e.source_id == "site-tpl"
        and e.target_id == "sw-24p"
        and e.relation == "uplink_to"
        for e in compact_graph.edges
    )
