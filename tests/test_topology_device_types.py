"""Unit tests for sot_validator.topology (device_types and identifier)."""

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
    Subnet,
)
from sot_validator.topology import (
    BUILTIN_DEVICE_TEMPLATES,
    ConsolidatedRouter,
    DevicePortManager,
    DeviceTypeCatalog,
    DeviceTypeTemplate,
    HostIdentification,
    KNOWN_OUI_VENDORS,
    KNOWN_SCAN_TCP_PORTS,
    NetworkRoleIdentifier,
    PortSpec,
    VALID_DEVICE_ROLES,
    VALID_HOST_ROLES,
    normalize_mac_address,
)


class TestPortSpecAndDeviceTypeTemplate:
    def test_port_spec_validation_and_roundtrip(self) -> None:
        spec = PortSpec(
            name="1:1",
            admin_status="up",
            oper_status="down",
            poe_status="auto",
            vlan_id="10",
        )
        as_dict = spec.to_dict()
        restored = PortSpec.from_dict(as_dict)
        assert restored == spec

        with pytest.raises(ValueError, match="name"):
            PortSpec(name="   ")

    def test_device_type_template_validation_and_roundtrip(self) -> None:
        tpl = DeviceTypeTemplate(
            template_id="custom-fw-1",
            vendor="Palo Alto",
            model="PA-440",
            role="FIREWALL",
            default_port_count=8,
            port_naming_pattern="ethernet1/{n}",
            supports_poe=False,
            supports_vlans=True,
            default_vlan_id="100",
        )
        assert tpl.role == "firewall"
        specs = tpl.build_port_specs()
        assert len(specs) == 8
        assert specs[0].name == "ethernet1/1"
        assert specs[7].name == "ethernet1/8"
        assert specs[0].vlan_id == "100"

        restored = DeviceTypeTemplate.from_dict(tpl.to_dict())
        assert restored == tpl

    def test_device_type_template_with_explicit_default_ports(self) -> None:
        tpl = DeviceTypeTemplate(
            template_id="custom-router",
            vendor="Cisco",
            model="ISR-4331",
            role="router",
            default_vlan_id="1",
            default_ports=[
                PortSpec(name="Gi0/0/0", vlan_id="10"),
                PortSpec(name="Gi0/0/1"),
            ],
        )
        specs = tpl.build_port_specs()
        assert [s.name for s in specs] == ["Gi0/0/0", "Gi0/0/1"]
        assert specs[0].vlan_id == "10"
        assert specs[1].vlan_id == "1"

        override_specs = tpl.build_port_specs(port_count=3, default_vlan_id="20")
        assert [s.name for s in override_specs] == ["1", "2", "3"]
        assert all(s.vlan_id == "20" for s in override_specs)

    def test_device_type_template_invalid_inputs(self) -> None:
        with pytest.raises(ValueError, match="Invalid device role"):
            DeviceTypeTemplate(
                template_id="bad-role",
                vendor="Vendor",
                model="Model",
                role="printer",
            )
        with pytest.raises(ValueError, match="default_port_count"):
            DeviceTypeTemplate(
                template_id="neg-ports",
                vendor="Vendor",
                model="Model",
                role="switch",
                default_port_count=-1,
            )
        with pytest.raises(ValueError, match="port_naming_pattern"):
            DeviceTypeTemplate(
                template_id="bad-pattern",
                vendor="Vendor",
                model="Model",
                role="switch",
                default_port_count=4,
                port_naming_pattern="eth-fixed",
            )


class TestDeviceTypeCatalog:
    def test_builtin_templates_present(self) -> None:
        assert len(BUILTIN_DEVICE_TEMPLATES) == 7
        catalog = DeviceTypeCatalog()
        expected_ids = {
            "extreme-exos-48p",
            "extreme-exos-24p",
            "extreme-voss-core",
            "unifi-multi-vlan-router",
            "proxmox-ve-host",
            "apc-smart-ups",
            "generic-smb-nas",
        }
        registered_ids = {t.template_id for t in catalog.list_templates()}
        assert registered_ids == expected_ids

        switches = catalog.list_templates(role="switch")
        assert {t.template_id for t in switches} == {
            "extreme-exos-48p",
            "extreme-exos-24p",
        }

    def test_register_custom_template_and_overwrite(self) -> None:
        catalog = DeviceTypeCatalog()
        custom = DeviceTypeTemplate(
            template_id="custom-switch-12p",
            vendor="Extreme Networks",
            model="X435-12P",
            role="switch",
            default_port_count=12,
            port_naming_pattern="1:{n}",
            supports_poe=True,
            supports_vlans=True,
        )
        catalog.register(custom)
        assert catalog.get("CUSTOM-SWITCH-12P") == custom

        with pytest.raises(ValueError, match="already registered"):
            catalog.register(custom, overwrite=False)

        updated = DeviceTypeTemplate(
            template_id="custom-switch-12p",
            vendor="Extreme Networks",
            model="X435-12P-v2",
            role="switch",
            default_port_count=12,
            port_naming_pattern="1:{n}",
        )
        catalog.register(updated, overwrite=True)
        assert catalog.get("custom-switch-12p").model == "X435-12P-v2"

        with pytest.raises(KeyError):
            catalog.get("non-existent-template")

    def test_instantiate_device_across_all_builtins(self) -> None:
        catalog = DeviceTypeCatalog()
        now = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)

        exos48 = catalog.instantiate_device(
            "extreme-exos-48p",
            device_id="sw-idf-1",
            site_id="site-01",
            hostname="sw-idf-01",
            management_ip="10.1.1.2",
            last_seen=now,
        )
        assert exos48.vendor == "Extreme Networks"
        assert exos48.model == "Summit X460-G2-48p"
        assert exos48.role == "switch"
        assert len(exos48.ports) == 48
        assert exos48.ports[0].port_id == "sw-idf-1:1:1"
        assert exos48.ports[0].name == "1:1"
        assert exos48.ports[0].poe_status == "auto"
        assert exos48.ports[0].vlan_id == "1"
        assert exos48.ports[47].name == "1:48"

        voss = catalog.instantiate_device(
            "extreme-voss-core",
            device_id="sw-core-1",
            site_id="site-01",
            hostname="sw-core-01",
            port_count=12,
            default_vlan_id="10",
        )
        assert len(voss.ports) == 12
        assert voss.ports[0].name == "1/1"
        assert voss.ports[11].name == "1/12"
        assert voss.ports[0].poe_status is None
        assert voss.ports[0].vlan_id == "10"

        pve = catalog.instantiate_device(
            "proxmox-ve-host",
            device_id="pve-1",
            site_id="site-01",
            hostname="pve-01",
        )
        assert [p.name for p in pve.ports] == ["vmbr1", "vmbr2", "vmbr3", "vmbr4"]

        ups = catalog.instantiate_device(
            "apc-smart-ups",
            device_id="ups-1",
            site_id="site-01",
            hostname="ups-01",
        )
        assert [p.name for p in ups.ports] == ["mgmt1"]


class TestDevicePortManager:
    def test_add_single_port_and_duplicate_handling(self) -> None:
        device = NetworkDevice(
            device_id="sw-1", site_id="site-1", hostname="sw-01"
        )
        mgr = DevicePortManager(device)

        p1 = mgr.add_port("1:1", vlan_id="10", poe_status="delivering")
        assert p1.port_id == "sw-1:1:1"
        assert p1.vlan_id == "10"
        assert mgr.get_port("1:1") is p1
        assert mgr.get_port("sw-1:1:1") is p1

        with pytest.raises(ValueError, match="already exists"):
            mgr.add_port("1:1", overwrite=False)

        p1_replaced = mgr.add_port("1:1", vlan_id="20", overwrite=True)
        assert len(device.ports) == 1
        assert p1_replaced.vlan_id == "20"

    def test_add_port_range_patterns(self) -> None:
        device = NetworkDevice(
            device_id="sw-1", site_id="site-1", hostname="sw-01"
        )
        mgr = DevicePortManager(device)

        exos_ports = mgr.add_port_range("1:1..1:48", vlan_id="1", poe_status="auto")
        assert len(exos_ports) == 48
        assert exos_ports[0].name == "1:1"
        assert exos_ports[-1].name == "1:48"

        gi_ports = mgr.add_port_range("gi0/1..gi0/24", vlan_id="100")
        assert len(gi_ports) == 24
        assert gi_ports[0].name == "gi0/1"
        assert gi_ports[-1].name == "gi0/24"

        numeric_ports = mgr.add_port_range("1..8", naming_pattern="eth{n}")
        assert [p.name for p in numeric_ports] == [f"eth{i}" for i in range(1, 9)]

        explicit_ports = mgr.add_port_range(
            start=1, end=4, naming_pattern="2/{n}", vlan_id="50"
        )
        assert [p.name for p in explicit_ports] == ["2/1", "2/2", "2/3", "2/4"]

        with pytest.raises(ValueError):
            mgr.add_port_range("1:24..1:1")
        with pytest.raises(ValueError):
            mgr.add_port_range("1:1..2:24")
        with pytest.raises(ValueError):
            mgr.add_port_range("invalid_range")

    def test_update_port_and_bind_mac(self) -> None:
        device = NetworkDevice(
            device_id="sw-1", site_id="site-1", hostname="sw-01"
        )
        mgr = DevicePortManager(device)
        mgr.add_port_range("1:1..1:4")

        updated = mgr.update_port(
            "1:2",
            admin_status="down",
            oper_status="down",
            vlan_id="99",
            connected_mac="AA-BB-CC-DD-EE-FF",
        )
        assert updated.admin_status == "down"
        assert updated.vlan_id == "99"
        assert updated.connected_mac == "aa:bb:cc:dd:ee:ff"

        bound = mgr.bind_mac_to_port(
            "1:1",
            "00c0.b711.2233",
            connected_device_id="ups-01",
            vlan_id="30",
        )
        assert bound.connected_mac == "00:c0:b7:11:22:33"
        assert bound.connected_device_id == "ups-01"
        assert bound.vlan_id == "30"
        assert bound.oper_status == "up"

        with pytest.raises(ValueError, match="Unsupported port attribute"):
            mgr.update_port("1:1", bogus_field="x")

        with pytest.raises(KeyError):
            mgr.get_port("1:99")

        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac_address("not-a-mac")

    def test_bind_discovered_hosts_correlates_arp_ip_equipment_and_subnet(self) -> None:
        device = NetworkDevice(
            device_id="sw-1", site_id="site-1", hostname="sw-01"
        )
        mgr = DevicePortManager(device)
        mgr.add_port_range("1:1..1:4")

        subnets = [
            Subnet(
                subnet_id="sub-20",
                site_id="site-1",
                cidr="10.1.20.0/24",
                vlan_id="20",
            ),
            Subnet(
                subnet_id="sub-30",
                site_id="site-1",
                cidr="10.1.30.0/24",
                vlan_id="30",
            ),
        ]
        arp_entries = [
            ArpEntry(
                ip="10.1.20.10",
                arp_mac="bc:24:11:00:11:22",
                subnet_id="sub-20",
            ),
            ArpEntry(
                ip="10.1.30.50",
                arp_mac="00:c0:b7:aa:bb:cc",
                subnet_id="sub-30",
            ),
        ]
        ip_addresses = [
            IPAddress(
                ip="10.1.20.10",
                subnet_id="sub-20",
                assigned_object_type="equipment",
                assigned_object_id="eq-pve-1",
                arp_mac="bc:24:11:00:11:22",
            ),
            IPAddress(
                ip="10.1.30.50",
                subnet_id="sub-30",
                assigned_object_type="equipment",
                assigned_object_id="eq-ups-1",
                arp_mac="00:c0:b7:aa:bb:cc",
            ),
        ]
        equipment = [
            Equipment(
                equipment_id="eq-pve-1",
                site_id="site-1",
                name="pve-node-01",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.1.20.10"],
            ),
            Equipment(
                equipment_id="eq-ups-1",
                site_id="site-1",
                name="apc-ups-01",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.1.30.50"],
            ),
        ]

        bound_ports = mgr.bind_discovered_hosts(
            {
                "1:1": "BC-24-11-00-11-22",
                "1:2": "00c0.b7aa.bbcc",
            },
            arp_entries=arp_entries,
            ip_addresses=ip_addresses,
            equipment=equipment,
            subnets=subnets,
        )

        assert len(bound_ports) == 2
        p1 = mgr.get_port("1:1")
        assert p1.connected_mac == "bc:24:11:00:11:22"
        assert p1.connected_device_id == "eq-pve-1"
        assert p1.vlan_id == "20"
        assert p1.oper_status == "up"
        assert "sw-1:1:1" in equipment[0].connected_ports

        p2 = mgr.get_port("1:2")
        assert p2.connected_mac == "00:c0:b7:aa:bb:cc"
        assert p2.connected_device_id == "eq-ups-1"
        assert p2.vlan_id == "30"
        assert "sw-1:1:2" in equipment[1].connected_ports


class TestNetworkRoleIdentifier:
    def test_exported_constants(self) -> None:
        assert VALID_DEVICE_ROLES == (
            "router",
            "switch",
            "l3_switch",
            "firewall",
            "hypervisor",
            "ups",
            "nas",
        )
        assert VALID_HOST_ROLES == (
            "router",
            "switch",
            "hypervisor",
            "dns_server",
            "nas_storage",
            "automation_hub",
            "iot_device",
            "workstation_server",
        )
        assert set(KNOWN_SCAN_TCP_PORTS) == {
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
            9090,
        }
        for oui in ("bc:24:11", "00:04:96", "00:c0:b7", "aa:9c:6c", "44:61:32"):
            assert oui in KNOWN_OUI_VENDORS

    def test_identify_all_eight_host_roles(self) -> None:
        ident = NetworkRoleIdentifier()

        # 1. Router
        r_host = ident.identify_host(
            "10.10.1.1",
            mac="aa:9c:6c:11:22:33",
            hostname="udm-gw-01",
            open_ports=[53, 80, 443],
        )
        assert r_host.role == "router"
        assert r_host.is_gateway_ip is True
        assert r_host.inferred_vlan_id == "1"
        assert r_host.subnet_cidr == "10.10.1.0/24"
        assert r_host.suggested_template_id == "unifi-multi-vlan-router"

        # 2. Switch (EXOS & VOSS)
        sw_exos = ident.identify_host(
            "10.10.1.2",
            mac="00:04:96:aa:bb:cc",
            hostname="idf-sw-01",
            open_ports=[22, 80],
        )
        assert sw_exos.role == "switch"
        assert sw_exos.suggested_template_id == "extreme-exos-48p"

        sw_voss = ident.identify_host(
            "10.10.1.3",
            hostname="voss-core-sw-01",
            open_ports=[22],
        )
        assert sw_voss.role == "switch"
        assert sw_voss.suggested_template_id == "extreme-voss-core"

        # 3. Hypervisor
        hv_host = ident.identify_host(
            "10.10.20.10",
            mac="bc:24:11:12:34:56",
            hostname="pve-01",
            open_ports=[22, 8006],
        )
        assert hv_host.role == "hypervisor"
        assert hv_host.inferred_vlan_id == "20"
        assert hv_host.suggested_template_id == "proxmox-ve-host"

        # 4. Automation Hub
        ha_host = ident.identify_host(
            "10.10.30.15",
            hostname="homeassistant",
            open_ports=[8123],
        )
        assert ha_host.role == "automation_hub"

        # 5. NAS / Storage
        nas_host = ident.identify_host(
            "10.10.40.20",
            hostname="synology-nas-01",
            open_ports=[80, 445, 5000],
        )
        assert nas_host.role == "nas_storage"
        assert nas_host.suggested_template_id == "generic-smb-nas"

        # 6. DNS Server
        dns_host = ident.identify_host(
            "10.10.1.53",
            hostname="pihole-dns",
            open_ports=[53, 80],
        )
        assert dns_host.role == "dns_server"

        # 7. IoT / UPS
        ecobee = ident.identify_host(
            "10.10.50.100",
            mac="44:61:32:01:02:03",
            hostname="ecobee-thermostat",
        )
        assert ecobee.role == "iot_device"
        assert ecobee.suggested_template_id is None

        apc_ups = ident.identify_host(
            "10.10.50.101",
            mac="00:c0:b7:01:02:03",
            hostname="apc-ups-idf1",
            open_ports=[80, 443],
        )
        assert apc_ups.role == "iot_device"
        assert apc_ups.suggested_template_id == "apc-smart-ups"

        # 8. Workstation / Server
        ws_host = ident.identify_host(
            "10.10.60.25",
            hostname="app-srv-01",
            open_ports=[22, 443, 8080, 9090],
        )
        assert ws_host.role == "workstation_server"
        assert HostIdentification.from_dict(ws_host.to_dict()) == ws_host

    def test_multi_vlan_router_consolidation_and_vlan_inference(self) -> None:
        ident = NetworkRoleIdentifier()
        observations = [
            {
                "ip": "192.168.1.1",
                "mac": "aa:9c:6c:01:02:01",
                "hostname": "unifi-gw",
                "open_ports": [53, 80, 443],
            },
            {
                "ip": "192.168.20.1",
                "mac": "aa:9c:6c:01:02:02",
                "open_ports": [53, 80, 443],
            },
            {
                "ip": "192.168.30.1",
                "mac": "aa:9c:6c:01:02:03",
                "open_ports": [53, 80, 443],
            },
            {
                "ip": "192.168.20.10",
                "mac": "bc:24:11:aa:bb:cc",
                "hostname": "pve-node1",
                "open_ports": [22, 8006],
            },
            {
                "ip": "192.168.30.15",
                "mac": "44:61:32:11:22:33",
                "hostname": "ecobee-living",
                "open_ports": [],
            },
            {
                "ip": "192.168.30.16",
                "hostname": "homeassistant",
                "open_ports": [8123],
            },
        ]

        identifications = ident.identify_hosts(observations)
        assert len(identifications) == 6

        routers = ident.consolidate_multi_vlan_routers(identifications)
        assert len(routers) == 1
        router = routers[0]
        assert router.primary_ip == "192.168.1.1"
        assert router.gateway_ips == [
            "192.168.1.1",
            "192.168.20.1",
            "192.168.30.1",
        ]
        assert router.vlan_ids == ["1", "20", "30"]
        assert router.subnet_cidrs == [
            "192.168.1.0/24",
            "192.168.20.0/24",
            "192.168.30.0/24",
        ]
        assert ConsolidatedRouter.from_dict(router.to_dict()) == router

        router_dev = router.to_network_device(site_id="site-hq")
        assert router_dev.role == "router"
        assert router_dev.management_ip == "192.168.1.1"
        assert len(router_dev.ports) == 3
        assert [p.vlan_id for p in router_dev.ports] == ["1", "20", "30"]

        vlans, subnets = ident.infer_vlans_and_subnets(
            identifications, site_id="site-hq"
        )
        assert len(vlans) == 3
        assert len(subnets) == 3

        vlan_by_id = {v.vlan_id: v for v in vlans}
        assert vlan_by_id["1"].gateway == "192.168.1.1"
        assert vlan_by_id["1"].name == "Management / Infrastructure"
        assert vlan_by_id["20"].gateway == "192.168.20.1"
        assert vlan_by_id["20"].name == "Hypervisor / Virtualization"
        assert vlan_by_id["30"].gateway == "192.168.30.1"
        assert vlan_by_id["30"].name == "IoT / Automation"
