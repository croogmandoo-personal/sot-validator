"""Tests for Proxmox VE (:8006) & Docker/Portainer (:9000) hypervisor and container correlator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import pytest

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
    Subnet,
    VLAN,
)
from sot_validator.signals import (
    PROXMOX_MAC_OUI,
    ContainerEndpointRecord,
    ProxmoxClusterSnapshot,
    ProxmoxContainerCollector,
    ProxmoxContainerCorrelator,
    ProxmoxGuestRecord,
    is_proxmox_mac,
)
from sot_validator.topology import TopologyGraphBuilder


def test_proxmox_mac_oui_and_exports() -> None:
    assert PROXMOX_MAC_OUI == "bc:24:11"
    assert ProxmoxContainerCorrelator is ProxmoxContainerCollector
    assert is_proxmox_mac("BC:24:11:AA:BB:CC") is True
    assert is_proxmox_mac("bc-24-11-01-02-03") is True
    assert is_proxmox_mac("bc24.11ab.cdef") is True
    assert (
        is_proxmox_mac("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:10:20:30,ip=10.42.10.50/24")
        is True
    )
    assert is_proxmox_mac("00:50:56:aa:bb:cc") is False
    assert is_proxmox_mac(None) is False
    assert is_proxmox_mac("invalid-mac") is False


def test_parse_proxmox_guest_record_qemu_and_lxc() -> None:
    qemu_rec = ProxmoxGuestRecord.from_dict(
        {
            "vmid": "101",
            "name": "win11-ws-01",
            "type": "qemu",
            "node": "pve-01",
            "host_ip": "10.42.10.21",
            "status": "running",
            "uptime": 86400,
            "tags": "prod;windows,homelab",
            "net0": "virtio=BC:24:11:11:22:33,bridge=vmbr0",
            "ip_addresses": ["10.42.10.101/24", "127.0.0.1"],
        }
    )
    assert qemu_rec.vmid == 101
    assert qemu_rec.name == "win11-ws-01"
    assert qemu_rec.guest_type == "qemu"
    assert qemu_rec.node == "pve-01"
    assert qemu_rec.host_ip == "10.42.10.21"
    assert qemu_rec.status == "running"
    assert qemu_rec.is_running is True
    assert qemu_rec.has_proxmox_mac is True
    assert qemu_rec.ip_addresses == ["10.42.10.101"]
    assert qemu_rec.mac_addresses == ["bc:24:11:11:22:33"]
    assert qemu_rec.uptime_sec == 86400
    assert qemu_rec.tags == ["prod", "windows", "homelab"]

    roundtrip = ProxmoxGuestRecord.from_json(qemu_rec.to_json())
    assert roundtrip == qemu_rec

    lxc_rec = ProxmoxGuestRecord.from_dict(
        {
            "id": "lxc/202",
            "node": "pve-02",
            "status": "stopped",
            "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:44:55:66,ip=10.42.10.202/24,ip6=auto",
        },
        default_host_ip="10.42.10.22",
    )
    assert lxc_rec.vmid == 202
    assert lxc_rec.name == "lxc-202"
    assert lxc_rec.guest_type == "lxc"
    assert lxc_rec.host_ip == "10.42.10.22"
    assert lxc_rec.status == "stopped"
    assert lxc_rec.is_running is False
    assert lxc_rec.ip_addresses == ["10.42.10.202"]
    assert lxc_rec.mac_addresses == ["bc:24:11:44:55:66"]

    with pytest.raises(ValueError):
        ProxmoxGuestRecord(vmid=0, name="bad", guest_type="qemu", node="pve-01")

    with pytest.raises(ValueError):
        ProxmoxGuestRecord(vmid=100, name="bad", guest_type="hyperv", node="pve-01")

    with pytest.raises(ValueError):
        ProxmoxGuestRecord(vmid=100, name="bad", guest_type="qemu", node="pve-01", status="crashed")


def test_parse_proxmox_cluster_snapshot_and_interfaces(tmp_path: Path) -> None:
    payload = {
        "data": [
            {"type": "node", "node": "pve-01", "status": "online", "ip": "10.42.10.21"},
            {"type": "node", "node": "pve-02", "status": "online", "ip": "10.42.10.22"},
            {"type": "storage", "storage": "local-lvm", "node": "pve-01"},
            {
                "type": "qemu",
                "vmid": 9000,
                "name": "ubuntu-cloud-template",
                "node": "pve-01",
                "status": "stopped",
                "template": 1,
            },
            {
                "type": "qemu",
                "vmid": 101,
                "name": "k3s-worker-01",
                "node": "pve-01",
                "status": "running",
                "uptime": 12345,
                "tags": "k3s;homelab",
            },
            {
                "type": "lxc",
                "vmid": 102,
                "name": "pihole-dns",
                "node": "pve-02",
                "status": "running",
                "uptime": 54321,
                "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:02,ip=10.42.10.53/24",
            },
            {
                "type": "lxc",
                "vmid": 103,
                "name": "legacy-archive",
                "node": "pve-02",
                "status": "stopped",
                "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:03,ip=10.42.10.54/24",
            },
        ],
        "guest_interfaces": {
            "101": {
                "result": [
                    {
                        "name": "lo",
                        "hardware-address": "00:00:00:00:00:00",
                        "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}],
                    },
                    {
                        "name": "eth0",
                        "hardware-address": "BC:24:11:AA:BB:01",
                        "ip-addresses": [
                            {"ip-address": "10.42.10.51", "ip-address-type": "ipv4"},
                            {"ip-address": "fe80::be24:11ff:feaa:bb01", "ip-address-type": "ipv6"},
                        ],
                    },
                ]
            }
        },
    }

    snap = ProxmoxClusterSnapshot.from_dict(payload)
    assert len(snap.guests) == 3
    assert snap.node_ips == {"pve-01": "10.42.10.21", "pve-02": "10.42.10.22"}

    g101 = snap.find_guests(vmid=101)[0]
    assert g101.name == "k3s-worker-01"
    assert g101.host_ip == "10.42.10.21"
    assert g101.ip_addresses == ["10.42.10.51"]
    assert g101.mac_addresses == ["bc:24:11:aa:bb:01"]
    assert g101.has_proxmox_mac is True

    assert snap.find_guests(ip="10.42.10.53")[0].name == "pihole-dns"
    assert snap.find_guests(mac="BC:24:11:AA:BB:02")[0].vmid == 102
    assert snap.find_guests(name="legacy-archive", host_ip="10.42.10.22")[0].status == "stopped"

    json_file = tmp_path / "proxmox_snapshot.json"
    json_file.write_text(snap.to_json(indent=2), encoding="utf-8")
    loaded = ProxmoxClusterSnapshot.from_json_file(json_file)
    assert len(loaded.guests) == 3
    assert loaded.find_guests(vmid=101)[0].ip_addresses == ["10.42.10.51"]


def test_container_endpoint_record_and_snapshot_parsing() -> None:
    docker_raw = {
        "Id": "9f8e7d6c5b4a3210fedcba9876543210",
        "Names": ["/portainer"],
        "Image": "portainer/portainer-ce:latest",
        "State": "running",
        "Status": "Up 4 days",
        "Ports": [
            {"IP": "0.0.0.0", "PrivatePort": 9000, "PublicPort": 9000, "Type": "tcp"},
            {"IP": "0.0.0.0", "PrivatePort": 9443, "PublicPort": 9443, "Type": "tcp"},
        ],
        "NetworkSettings": {
            "Networks": {
                "bridge": {"IPAddress": "172.17.0.2"},
                "macvlan_lan": {"IPAddress": "10.42.10.60"},
            }
        },
    }
    rec = ContainerEndpointRecord.from_dict(docker_raw, default_host_ip="10.42.10.21")
    assert rec.container_id == "9f8e7d6c5b4a3210fedcba9876543210"
    assert rec.name == "portainer"
    assert rec.image == "portainer/portainer-ce:latest"
    assert rec.host_ip == "10.42.10.21"
    assert rec.state == "running"
    assert rec.is_running is True
    assert rec.ip_addresses == ["172.17.0.2", "10.42.10.60"]
    assert rec.published_ports == [9000, 9443]

    roundtrip = ContainerEndpointRecord.from_json(rec.to_json())
    assert roundtrip == rec

    exited_rec = ContainerEndpointRecord.from_dict(
        {
            "id": "abc123def456",
            "name": "watchtower",
            "image": "containrrr/watchtower:latest",
            "state": "exited",
            "host_ip": "10.42.10.22",
            "published_ports": [],
        }
    )
    assert exited_rec.is_running is False
    assert exited_rec.state == "exited"

    snap = ProxmoxClusterSnapshot.from_fetchers(
        proxmox_fetcher=lambda: {"data": []},
        container_fetcher=lambda: [docker_raw, exited_rec.to_dict()],
        default_host_ip="10.42.10.21",
    )
    assert len(snap.containers) == 2
    assert snap.find_containers(name="portainer")[0].published_ports == [9000, 9443]
    assert snap.find_containers(ip="10.42.10.60")[0].name == "portainer"
    assert snap.find_containers(container_id="9f8e7d6c5b4a")[0].name == "portainer"
    assert snap.find_containers(port=9000, host_ip="10.42.10.21")[0].name == "portainer"
    assert snap.find_containers(name="watchtower")[0].state == "exited"

    # Verify fetcher failure resilience records unreachable_hosts
    def _failing_fetcher() -> None:
        raise RuntimeError("API 8006 timeout")

    unreach_snap = ProxmoxClusterSnapshot.from_fetchers(
        proxmox_fetcher=_failing_fetcher,
        default_host_ip="10.42.10.21",
    )
    assert "10.42.10.21" in unreach_snap.unreachable_hosts


def test_evaluate_vm_power_state_signals() -> None:
    snap = ProxmoxClusterSnapshot.from_dict(
        {
            "node_ips": {"pve-01": "10.42.10.21", "pve-02": "10.42.10.22"},
            "guests": [
                {
                    "vmid": 101,
                    "name": "home-assistant",
                    "guest_type": "qemu",
                    "node": "pve-01",
                    "status": "running",
                    "ip_addresses": ["10.42.10.51"],
                    "mac_addresses": ["bc:24:11:10:00:51"],
                },
                {
                    "vmid": 102,
                    "name": "test-lab-lxc",
                    "guest_type": "lxc",
                    "node": "pve-02",
                    "status": "stopped",
                    "ip_addresses": ["10.42.10.52"],
                    "mac_addresses": ["bc:24:11:10:00:52"],
                },
            ],
            "containers": [
                {
                    "container_id": "c11111111111",
                    "name": "traefik",
                    "image": "traefik:v3.0",
                    "host_ip": "10.42.10.21",
                    "state": "running",
                    "ip_addresses": ["10.42.10.61"],
                    "published_ports": [80, 443],
                },
                {
                    "container_id": "c22222222222",
                    "name": "old-redis",
                    "image": "redis:7",
                    "host_ip": "10.42.10.22",
                    "state": "exited",
                    "ip_addresses": ["10.42.10.62"],
                    "published_ports": [6379],
                },
            ],
        }
    )

    eval_time = datetime(2026, 3, 28, 12, 0, 0, tzinfo=timezone.utc)
    collector = ProxmoxContainerCollector(snapshot=snap, evaluation_time=eval_time)

    # Direct guest evaluation
    sig_direct_guest = collector.evaluate(snap.guests[0])
    assert sig_direct_guest.signal_type is SignalType.VM_POWER_STATE
    assert sig_direct_guest.status is SignalStatus.ACTIVE
    assert sig_direct_guest.metadata["proxmox_mac_detected"] is True

    sig_direct_stopped = collector.evaluate(snap.guests[1])
    assert sig_direct_stopped.status is SignalStatus.INACTIVE

    # Direct container evaluation
    sig_direct_ct = collector.evaluate(snap.containers[0])
    assert sig_direct_ct.status is SignalStatus.ACTIVE
    assert sig_direct_ct.metadata["name"] == "traefik"

    sig_direct_ct_exited = collector.evaluate(snap.containers[1])
    assert sig_direct_ct_exited.status is SignalStatus.INACTIVE

    # Equipment correlated by MAC (from ARP entry)
    eq_by_mac = Equipment(
        equipment_id="eq-ha",
        site_id="site-42",
        name="unknown-host-51",
        category=EquipmentCategory.SERVER,
        assigned_ips=["10.42.10.199"],
    )
    arp_entries = [ArpEntry(ip="10.42.10.199", arp_mac="BC:24:11:10:00:51")]
    sig_mac = collector.evaluate(eq_by_mac, arp_entries=arp_entries)
    assert sig_mac.status is SignalStatus.ACTIVE
    assert sig_mac.metadata["correlation_key"] == "mac"
    assert sig_mac.metadata["proxmox_mac_detected"] is True

    # Equipment correlated by IP to stopped LXC
    eq_stopped = Equipment(
        equipment_id="eq-lxc-102",
        site_id="site-42",
        name="test-lab-lxc",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.52"],
    )
    sig_stopped = collector.evaluate(eq_stopped)
    assert sig_stopped.status is SignalStatus.INACTIVE

    # Equipment correlated by container name
    eq_ct = Equipment(
        equipment_id="eq-traefik",
        site_id="site-42",
        name="traefik",
        category=EquipmentCategory.VM,
    )
    sig_ct = collector.evaluate(eq_ct)
    assert sig_ct.status is SignalStatus.ACTIVE
    assert sig_ct.metadata["correlation_key"] == "name"

    # IPAddress target with Proxmox MAC matched
    ip_active = IPAddress(ip="10.42.10.51", subnet_id="sub-10", arp_mac="bc:24:11:10:00:51")
    sig_ip_active = collector.evaluate(ip_active)
    assert sig_ip_active.status is SignalStatus.ACTIVE

    # IPAddress target with Proxmox MAC when snapshot is missing -> UNREACHABLE
    empty_collector = ProxmoxContainerCollector(snapshot=None, evaluation_time=eval_time)
    ip_orphan_pve = IPAddress(ip="10.42.10.99", subnet_id="sub-10", arp_mac="bc:24:11:99:99:99")
    sig_orphan_unreach = empty_collector.evaluate(ip_orphan_pve)
    assert sig_orphan_unreach.status is SignalStatus.UNREACHABLE

    # NetworkDevice target -> NOT_APPLICABLE
    sw = NetworkDevice(device_id="sw-01", site_id="site-42", hostname="sw-42-01")
    assert collector.evaluate(sw).status is SignalStatus.NOT_APPLICABLE


def test_parse_snapshot_lxc_interfaces_and_portainer_endpoint_containers() -> None:
    snap = ProxmoxClusterSnapshot.from_dict(
        {
            "resources": [
                {"type": "lxc", "vmid": 110, "name": "nginx-proxy", "node": "pve-02", "status": "running"},
                {"type": "qemu", "vmid": 111, "name": "tpl", "node": "pve-02", "template": True},
                {"type": "pool", "poolid": "lab"},
                {"type": "sdn", "sdn": "zone1"},
            ],
            "interfaces": {
                110: [
                    {"name": "lo", "hwaddr": "00:00:00:00:00:00", "inet": "127.0.0.1/8"},
                    {"name": "eth0", "hwaddr": "BC:24:11:CC:00:10", "inet": "10.42.10.70/24"},
                ]
            },
            "node_ips": {"PVE-02": "10.42.10.22"},
            "portainer_endpoints": [
                {
                    "Id": 1,
                    "url": "tcp://10.42.10.22:2375",
                    "Status": 1,
                    "Snapshots": [
                        {
                            "DockerSnapshotRaw": {
                                "Containers": [
                                    {
                                        "Id": "deadbeef0001",
                                        "Names": ["/grafana"],
                                        "Image": "grafana/grafana",
                                        "State": "running",
                                        "Ports": [{"PrivatePort": 3000, "PublicPort": 3000}],
                                    }
                                ]
                            }
                        }
                    ],
                }
            ],
        }
    )
    assert [g.vmid for g in snap.guests] == [110]
    lxc = snap.guests[0]
    assert lxc.host_ip == "10.42.10.22"
    assert lxc.ip_addresses == ["10.42.10.70"]
    assert lxc.mac_addresses == ["bc:24:11:cc:00:10"]
    assert snap.find_containers(port=3000, host_ip="10.42.10.22")[0].name == "grafana"


def test_evaluate_vmid_correlation_and_proxmox_oui_without_guest() -> None:
    snap = ProxmoxClusterSnapshot.from_dict(
        {
            "data": [
                {"type": "lxc", "vmid": 110, "name": "nginx-proxy", "node": "pve-02", "status": "running"},
            ],
            "node_ips": {"pve-02": "10.42.10.22"},
        }
    )
    collector = ProxmoxContainerCollector(snapshot=snap)

    eq_vmid = Equipment(
        equipment_id="lxc-110",
        site_id="site-42",
        name="edge-box",
        category=EquipmentCategory.VM,
    )
    sig_vmid = collector.evaluate(eq_vmid)
    assert sig_vmid.status is SignalStatus.ACTIVE
    assert sig_vmid.metadata["correlation_key"] == "vmid"

    # Reachable snapshot confirms no guest holds the bc:24:11 MAC -> INACTIVE
    eq_orphan = Equipment(
        equipment_id="eq-mystery",
        site_id="site-42",
        name="mystery",
        assigned_ips=["10.42.10.88"],
    )
    sig_orphan = collector.evaluate(
        eq_orphan, arp_entries=[ArpEntry(ip="10.42.10.88", arp_mac="bc:24:11:ff:ff:ff")]
    )
    assert sig_orphan.status is SignalStatus.INACTIVE
    assert sig_orphan.metadata["proxmox_mac_detected"] is True

    assert collector.evaluate(IPAddress(ip="10.42.10.5", subnet_id="sub-10")).status is SignalStatus.NOT_APPLICABLE
    assert collector.evaluate(Port(port_id="p1", device_id="sw-01", name="1:1")).status is SignalStatus.NOT_APPLICABLE


def test_enrich_site_with_guests_and_topology_hosts_vm_edges() -> None:
    site = Site(
        site_id="site-42",
        name="Site 42 Homelab",
        vlans=[VLAN(vlan_id="10", site_id="site-42", name="Servers", cidr="10.42.10.0/24")],
        subnets=[
            Subnet(
                subnet_id="sub-42-10",
                site_id="site-42",
                cidr="10.42.10.0/24",
                vlan_id="10",
                gateway="10.42.10.1",
            )
        ],
        devices=[
            NetworkDevice(
                device_id="sw-42-01",
                site_id="site-42",
                hostname="sw-42-01",
                management_ip="10.42.10.2",
                role="switch",
                ports=[
                    Port(
                        port_id="p1",
                        device_id="sw-42-01",
                        name="1/1",
                        oper_status="up",
                        connected_device_id="eq-pve-01",
                        vlan_id="10",
                    ),
                    Port(
                        port_id="p2",
                        device_id="sw-42-01",
                        name="1/2",
                        oper_status="up",
                        connected_device_id="eq-pve-02",
                        vlan_id="10",
                    ),
                ],
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.10.21",
                subnet_id="sub-42-10",
                assigned_object_type="equipment",
                assigned_object_id="eq-pve-01",
            ),
            IPAddress(
                ip="10.42.10.22",
                subnet_id="sub-42-10",
                assigned_object_type="equipment",
                assigned_object_id="eq-pve-02",
            ),
            IPAddress(
                ip="10.42.10.51",
                subnet_id="sub-42-10",
                assigned_object_type="equipment",
                assigned_object_id="eq-discovered-51",
                arp_mac="bc:24:11:aa:bb:51",
            ),
        ],
        equipment=[
            Equipment(
                equipment_id="eq-pve-01",
                site_id="site-42",
                name="pve-01",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.10.21"],
                connected_ports=["p1"],
            ),
            Equipment(
                equipment_id="eq-pve-02",
                site_id="site-42",
                name="pve-02",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.10.22"],
                connected_ports=["p2"],
            ),
            Equipment(
                equipment_id="eq-discovered-51",
                site_id="site-42",
                name="10.42.10.51",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.10.51"],
            ),
        ],
    )

    snapshot = ProxmoxClusterSnapshot.from_dict(
        {
            "node_ips": {"pve-01": "10.42.10.21", "pve-02": "10.42.10.22"},
            "guests": [
                {
                    "vmid": 101,
                    "name": "qemu-app-01",
                    "guest_type": "qemu",
                    "node": "pve-01",
                    "host_ip": "10.42.10.21",
                    "status": "running",
                    "ip_addresses": ["10.42.10.51"],
                    "mac_addresses": ["bc:24:11:aa:bb:51"],
                },
                {
                    "vmid": 102,
                    "name": "lxc-dns-01",
                    "guest_type": "lxc",
                    "node": "pve-02",
                    "host_ip": "10.42.10.22",
                    "status": "running",
                    "ip_addresses": ["10.42.10.52"],
                    "mac_addresses": ["bc:24:11:aa:bb:52"],
                },
            ],
            "containers": [
                {
                    "container_id": "deadbeef12345678",
                    "name": "portainer",
                    "image": "portainer/portainer-ce:latest",
                    "host_ip": "10.42.10.21",
                    "state": "running",
                    "ip_addresses": ["172.17.0.2"],
                    "published_ports": [9000],
                }
            ],
        }
    )

    collector = ProxmoxContainerCollector(snapshot=snapshot)
    enriched_site = collector.enrich_site_with_guests(site)

    # Original site must not be mutated destructively
    assert len(site.equipment) == 3
    assert len(enriched_site.equipment) == 5

    eq_by_id = {eq.equipment_id: eq for eq in enriched_site.equipment}
    # Host records remain SERVER without self-hypervisor_id
    assert eq_by_id["eq-pve-01"].category is EquipmentCategory.SERVER
    assert eq_by_id["eq-pve-01"].hypervisor_id is None
    assert eq_by_id["eq-pve-02"].category is EquipmentCategory.SERVER
    assert eq_by_id["eq-pve-02"].hypervisor_id is None

    # Existing discovered equipment 10.42.10.51 enriched into VM hosted on eq-pve-01
    vm_51 = eq_by_id["eq-discovered-51"]
    assert vm_51.category is EquipmentCategory.VM
    assert vm_51.name == "qemu-app-01"
    assert vm_51.hypervisor_id == "eq-pve-01"
    assert vm_51.power_state == "running"

    # New LXC guest added and linked to eq-pve-02
    lxc_102 = eq_by_id["site-42-pve-lxc-102"]
    assert lxc_102.category is EquipmentCategory.VM
    assert lxc_102.hypervisor_id == "eq-pve-02"
    assert lxc_102.assigned_ips == ["10.42.10.52"]
    assert lxc_102.power_state == "running"

    # New container added and linked to eq-pve-01
    ct_portainer = eq_by_id["site-42-ct-portainer"]
    assert ct_portainer.category is EquipmentCategory.VM
    assert ct_portainer.hypervisor_id == "eq-pve-01"
    assert ct_portainer.power_state == "running"

    # Build topology graph and verify hosts_vm edges
    graph = TopologyGraphBuilder().build(enriched_site)
    hosts_vm_edges = [
        (edge.source_id, edge.target_id)
        for edge in graph.edges
        if edge.relation == "hosts_vm"
    ]
    assert ("eq-pve-01", "eq-discovered-51") in hosts_vm_edges
    assert ("eq-pve-02", "site-42-pve-lxc-102") in hosts_vm_edges
    assert ("eq-pve-01", "site-42-ct-portainer") in hosts_vm_edges
