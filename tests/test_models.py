"""Unit tests for canonical domain models and validation schemas."""

from __future__ import annotations

from datetime import datetime, timezone
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
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)


def test_enum_exact_values() -> None:
    assert [c.value for c in EquipmentCategory] == [
        "server",
        "san",
        "ups",
        "vm",
        "other",
    ]
    assert {s.name: s.value for s in SignalType} == {
        "ARP_RECENCY": "ARP_RECENCY",
        "PORT_STATE": "PORT_STATE",
        "ICMP_REACHABILITY": "ICMP_REACHABILITY",
        "SNMP_API_REACHABILITY": "SNMP_API_REACHABILITY",
        "LAST_SEEN_TIMESTAMP": "LAST_SEEN_TIMESTAMP",
        "VM_POWER_STATE": "VM_POWER_STATE",
        "AD_COMPUTER_ACCOUNT": "AD_COMPUTER_ACCOUNT",
        "DNS_DHCP_LEASE": "DNS_DHCP_LEASE",
    }
    assert {s.name: s.value for s in SignalStatus} == {
        "ACTIVE": "ACTIVE",
        "INACTIVE": "INACTIVE",
        "UNREACHABLE": "UNREACHABLE",
        "ERROR": "ERROR",
        "NOT_APPLICABLE": "NOT_APPLICABLE",
    }
    assert [c.value for c in ValidationClassification] == [
        "Confirmed Active",
        "Stale / Likely Unused",
        "Unreachable / Needs Manual Review",
        "Insufficient Data",
    ]


def test_model_construction_and_defaults() -> None:
    port = Port(port_id="P1", device_id="D1", name="1/1")
    assert port.admin_status is None
    assert port.oper_status is None
    assert port.poe_status is None
    assert port.connected_device_id is None
    assert port.connected_mac is None
    assert port.vlan_id is None

    dev = NetworkDevice(device_id="D1", site_id="S1", hostname="sw01")
    assert dev.management_ip is None
    assert dev.vendor is None
    assert dev.model is None
    assert dev.role is None
    assert dev.last_seen is None
    assert dev.ports == []

    vlan = VLAN(vlan_id="V10", site_id="S1")
    assert vlan.name is None
    assert vlan.subnet_id is None
    assert vlan.cidr is None
    assert vlan.gateway is None

    subnet = Subnet(subnet_id="SUB10", site_id="S1", cidr="10.1.10.0/24")
    assert subnet.vlan_id is None
    assert subnet.gateway is None
    assert subnet.name is None

    arp = ArpEntry(ip="10.1.10.50", arp_mac="00:11:22:33:44:55")
    assert arp.arp_last_seen is None
    assert arp.arp_source_device_id is None
    assert arp.subnet_id is None

    ip_rec = IPAddress(ip="10.1.10.50", subnet_id="SUB10")
    assert ip_rec.assigned_object_type is None
    assert ip_rec.assigned_object_id is None
    assert ip_rec.arp_mac is None
    assert ip_rec.arp_last_seen is None
    assert ip_rec.arp_source_device_id is None
    assert ip_rec.arp_entry is None

    eq = Equipment(equipment_id="E1", site_id="S1", name="srv01")
    assert eq.category is EquipmentCategory.OTHER
    assert eq.assigned_ips == []
    assert eq.connected_ports == []
    assert eq.hypervisor_id is None
    assert eq.power_state is None
    assert eq.last_seen is None

    eq_vm = Equipment(equipment_id="E2", site_id="S1", name="vm01", category="vm")
    assert eq_vm.category is EquipmentCategory.VM

    site = Site(site_id="S1", name="Site 1")
    assert site.address is None
    assert site.contact_info is None
    assert site.rooms == []
    assert site.devices == []
    assert site.vlans == []
    assert site.subnets == []
    assert site.ip_addresses == []
    assert site.equipment == []

    sig = ValidationSignal(signal_type="ARP_RECENCY", status="ACTIVE")
    assert sig.signal_type is SignalType.ARP_RECENCY
    assert sig.status is SignalStatus.ACTIVE
    assert sig.observed_at is None
    assert sig.age_seconds is None
    assert sig.details is None
    assert sig.source is None

    res = ValidationResult(
        item_type="Equipment",
        item_id="E1",
        site_id="S1",
        name="srv01",
        classification="Confirmed Active",
    )
    assert res.classification is ValidationClassification.CONFIRMED_ACTIVE
    assert res.confidence == 0.0
    assert res.signals == []
    assert res.rationale is None
    assert res.evaluated_at is None


@pytest.mark.parametrize("bad_str", ["", "   ", "\t\n"])
def test_required_identifier_validation(bad_str: str) -> None:
    with pytest.raises(ValueError, match="port_id"):
        Port(port_id=bad_str, device_id="D1", name="ge-0/0/1")
    with pytest.raises(ValueError, match="device_id"):
        Port(port_id="P1", device_id=bad_str, name="ge-0/0/1")
    with pytest.raises(ValueError, match="name"):
        Port(port_id="P1", device_id="D1", name=bad_str)

    with pytest.raises(ValueError, match="device_id"):
        NetworkDevice(device_id=bad_str, site_id="S1", hostname="sw1")
    with pytest.raises(ValueError, match="site_id"):
        NetworkDevice(device_id="D1", site_id=bad_str, hostname="sw1")
    with pytest.raises(ValueError, match="hostname"):
        NetworkDevice(device_id="D1", site_id="S1", hostname=bad_str)

    with pytest.raises(ValueError, match="vlan_id"):
        VLAN(vlan_id=bad_str, site_id="S1")
    with pytest.raises(ValueError, match="site_id"):
        VLAN(vlan_id="V1", site_id=bad_str)

    with pytest.raises(ValueError, match="subnet_id"):
        Subnet(subnet_id=bad_str, site_id="S1", cidr="10.0.0.0/24")
    with pytest.raises(ValueError, match="site_id"):
        Subnet(subnet_id="SUB1", site_id=bad_str, cidr="10.0.0.0/24")
    with pytest.raises(ValueError, match="cidr"):
        Subnet(subnet_id="SUB1", site_id="S1", cidr=bad_str)

    with pytest.raises(ValueError, match="ip"):
        ArpEntry(ip=bad_str, arp_mac="00:11:22:33:44:55")
    with pytest.raises(ValueError, match="arp_mac"):
        ArpEntry(ip="10.0.0.1", arp_mac=bad_str)

    with pytest.raises(ValueError, match="ip"):
        IPAddress(ip=bad_str, subnet_id="SUB1")
    with pytest.raises(ValueError, match="subnet_id"):
        IPAddress(ip="10.0.0.1", subnet_id=bad_str)

    with pytest.raises(ValueError, match="equipment_id"):
        Equipment(equipment_id=bad_str, site_id="S1", name="eq1")
    with pytest.raises(ValueError, match="site_id"):
        Equipment(equipment_id="E1", site_id=bad_str, name="eq1")
    with pytest.raises(ValueError, match="name"):
        Equipment(equipment_id="E1", site_id="S1", name=bad_str)

    with pytest.raises(ValueError, match="site_id"):
        Site(site_id=bad_str, name="HQ")
    with pytest.raises(ValueError, match="name"):
        Site(site_id="S1", name=bad_str)

    with pytest.raises(ValueError, match="item_type"):
        ValidationResult(
            item_type=bad_str,
            item_id="E1",
            site_id="S1",
            name="eq1",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
        )
    with pytest.raises(ValueError, match="item_id"):
        ValidationResult(
            item_type="Equipment",
            item_id=bad_str,
            site_id="S1",
            name="eq1",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
        )
    with pytest.raises(ValueError, match="site_id"):
        ValidationResult(
            item_type="Equipment",
            item_id="E1",
            site_id=bad_str,
            name="eq1",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
        )
    with pytest.raises(ValueError, match="name"):
        ValidationResult(
            item_type="Equipment",
            item_id="E1",
            site_id="S1",
            name=bad_str,
            classification=ValidationClassification.CONFIRMED_ACTIVE,
        )


def test_enum_and_numeric_bounds_validation() -> None:
    with pytest.raises(ValueError, match="Invalid equipment category"):
        Equipment(equipment_id="E1", site_id="S1", name="eq1", category="printer")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Invalid signal_type"):
        ValidationSignal(signal_type="BAD_SIGNAL", status=SignalStatus.ACTIVE)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Invalid status"):
        ValidationSignal(signal_type=SignalType.PORT_STATE, status="BAD_STATUS")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="age_seconds"):
        ValidationSignal(
            signal_type=SignalType.PORT_STATE,
            status=SignalStatus.ACTIVE,
            age_seconds=-0.1,
        )

    with pytest.raises(ValueError, match="Invalid classification"):
        ValidationResult(
            item_type="Equipment",
            item_id="E1",
            site_id="S1",
            name="eq1",
            classification="Unknown Status",  # type: ignore[arg-type]
        )

    for bad_conf in (-0.01, 1.01, 1.5, -5.0):
        with pytest.raises(ValueError, match="confidence"):
            ValidationResult(
                item_type="Equipment",
                item_id="E1",
                site_id="S1",
                name="eq1",
                classification=ValidationClassification.CONFIRMED_ACTIVE,
                confidence=bad_conf,
            )


def test_individual_and_hierarchical_roundtrip_serialization() -> None:
    ts = datetime(2026, 2, 10, 14, 30, 0, tzinfo=timezone.utc)

    port = Port(
        port_id="P1",
        device_id="D1",
        name="1:1",
        admin_status="up",
        oper_status="up",
        poe_status="delivering",
        connected_device_id="E1",
        connected_mac="00:0c:29:aa:bb:cc",
        vlan_id="V10",
    )
    assert Port.from_dict(port.to_dict()) == port
    assert Port.from_json(port.to_json()) == port

    device = NetworkDevice(
        device_id="D1",
        site_id="S1",
        hostname="ext-sw-01",
        management_ip="10.10.1.2",
        vendor="Extreme Networks",
        model="X460-G2",
        role="access",
        last_seen=ts,
        ports=[port],
    )
    assert NetworkDevice.from_dict(device.to_dict()) == device
    assert NetworkDevice.from_json(device.to_json()) == device

    vlan = VLAN(
        vlan_id="V10",
        site_id="S1",
        name="Servers",
        subnet_id="SUB10",
        cidr="10.10.10.0/24",
        gateway="10.10.10.1",
    )
    assert VLAN.from_dict(vlan.to_dict()) == vlan
    assert VLAN.from_json(vlan.to_json()) == vlan

    subnet = Subnet(
        subnet_id="SUB10",
        site_id="S1",
        cidr="10.10.10.0/24",
        vlan_id="V10",
        gateway="10.10.10.1",
        name="Servers Subnet",
    )
    assert Subnet.from_dict(subnet.to_dict()) == subnet
    assert Subnet.from_json(subnet.to_json()) == subnet

    arp = ArpEntry(
        ip="10.10.10.25",
        arp_mac="00:0c:29:aa:bb:cc",
        arp_last_seen=ts,
        arp_source_device_id="D1",
        subnet_id="SUB10",
    )
    assert ArpEntry.from_dict(arp.to_dict()) == arp
    assert ArpEntry.from_json(arp.to_json()) == arp

    ip_address = IPAddress(
        ip="10.10.10.25",
        subnet_id="SUB10",
        assigned_object_type="Equipment",
        assigned_object_id="E1",
        arp_mac="00:0c:29:aa:bb:cc",
        arp_last_seen=ts,
        arp_source_device_id="D1",
        arp_entry=arp,
    )
    assert IPAddress.from_dict(ip_address.to_dict()) == ip_address
    assert IPAddress.from_json(ip_address.to_json()) == ip_address

    equipment = Equipment(
        equipment_id="E1",
        site_id="S1",
        name="win-app-01",
        category=EquipmentCategory.VM,
        assigned_ips=["10.10.10.25"],
        connected_ports=["P1"],
        hypervisor_id="vc01.corp.local",
        power_state="poweredOn",
        last_seen=ts,
    )
    assert Equipment.from_dict(equipment.to_dict()) == equipment
    assert Equipment.from_json(equipment.to_json()) == equipment

    site = Site(
        site_id="S1",
        name="Regional Office 1",
        address="100 Main St",
        contact_info="netops@example.com",
        rooms=["MDF-1", "IDF-2"],
        devices=[device],
        vlans=[vlan],
        subnets=[subnet],
        ip_addresses=[ip_address],
        equipment=[equipment],
    )
    site_dict = site.to_dict()
    assert site_dict["devices"][0]["last_seen"] == ts.isoformat()
    assert site_dict["equipment"][0]["category"] == "vm"
    assert Site.from_dict(site_dict) == site
    assert Site.from_json(site.to_json(indent=2)) == site

    signal = ValidationSignal(
        signal_type=SignalType.VM_POWER_STATE,
        status=SignalStatus.ACTIVE,
        observed_at=ts,
        age_seconds=45.5,
        details="poweredOn with guest tools running",
        source="vc01.corp.local",
    )
    assert ValidationSignal.from_dict(signal.to_dict()) == signal
    assert ValidationSignal.from_json(signal.to_json()) == signal

    result = ValidationResult(
        item_type="Equipment",
        item_id="E1",
        site_id="S1",
        name="win-app-01",
        classification=ValidationClassification.CONFIRMED_ACTIVE,
        confidence=0.95,
        signals=[signal],
        rationale="VM is powered on in vCenter and has recent ARP entry",
        evaluated_at=ts,
    )
    result_dict = result.to_dict()
    assert result_dict["classification"] == "Confirmed Active"
    assert result_dict["signals"][0]["signal_type"] == "VM_POWER_STATE"
    assert ValidationResult.from_dict(result_dict) == result
    assert ValidationResult.from_json(result.to_json(indent=2)) == result
