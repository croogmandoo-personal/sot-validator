"""Unit and integration tests for Phase 5 Validated Golden Inventory Exporter (NetBox / Nautobot)."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import re

import pytest

from sot_validator.migration import (
    CSV_COLUMNS_BY_ENTITY,
    ENTITY_COLLECTION_KEYS,
    GoldenInventoryFilter,
    ModernSoTExporter,
    slugify,
)
from sot_validator.models import (
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
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    DiscrepancyType,
    ReconciliationReport,
)


def _build_sample_site() -> Site:
    ts = datetime(2026, 2, 10, 12, 0, 0, tzinfo=timezone.utc)
    return Site(
        site_id="site-042",
        name="SF Campus 042",
        address="100 Market St, San Francisco, CA",
        contact_info="Jordan Rivera | netops-site042@example.internal | +1-650-555-0142",
        rooms=["MDF-101", "IDF-202"],
        devices=[
            NetworkDevice(
                device_id="dev-042-sw-01",
                site_id="site-042",
                hostname="ext-sw-042-01",
                management_ip="10.42.1.2",
                vendor="Extreme Networks",
                model="X460-G2-48p-10GE4",
                role="Access Switch",
                last_seen=ts,
                ports=[
                    Port(
                        port_id="port-042-1-1",
                        device_id="dev-042-sw-01",
                        name="1:1",
                        admin_status="up",
                        oper_status="up",
                        poe_status="off",
                        connected_device_id="eq-042-vm-win-01",
                        connected_mac="00:50:56:2a:10:11",
                        vlan_id="110",
                    ),
                    Port(
                        port_id="port-042-1-2",
                        device_id="dev-042-sw-01",
                        name="1:2",
                        admin_status="up",
                        oper_status="up",
                        poe_status="delivering",
                        connected_device_id="eq-042-ups-01",
                        connected_mac="00:c0:b7:2a:20:10",
                        vlan_id="120",
                    ),
                    Port(
                        port_id="port-042-1-3",
                        device_id="dev-042-sw-01",
                        name="1:3",
                        admin_status="down",
                        oper_status="down",
                        poe_status="off",
                        connected_device_id="eq-042-srv-stale",
                        connected_mac="00:1b:21:2a:10:99",
                        vlan_id="110",
                    ),
                ],
            ),
            NetworkDevice(
                device_id="dev-042-sw-stale",
                site_id="site-042",
                hostname="ext-sw-042-old",
                management_ip="10.42.1.99",
                vendor="Extreme Networks",
                model="Summit X440",
                role="Access Switch",
                last_seen=ts,
                ports=[
                    Port(
                        port_id="port-042-old-1",
                        device_id="dev-042-sw-stale",
                        name="1:1",
                        admin_status="down",
                        oper_status="down",
                        poe_status="off",
                        vlan_id="110",
                    )
                ],
            ),
        ],
        vlans=[
            VLAN(
                vlan_id="101",
                site_id="site-042",
                name="Management",
                subnet_id="sub-042-001",
                cidr="10.42.1.0/24",
                gateway="10.42.1.1",
            ),
            VLAN(
                vlan_id="110",
                site_id="site-042",
                name="Servers_VMs",
                subnet_id="sub-042-010",
                cidr="10.42.10.0/24",
                gateway="10.42.10.1",
            ),
            VLAN(
                vlan_id="120",
                site_id="site-042",
                name="Facilities_UPS",
                subnet_id="sub-042-020",
                cidr="10.42.20.0/24",
                gateway="10.42.20.1",
            ),
        ],
        subnets=[
            Subnet(
                subnet_id="sub-042-001",
                site_id="site-042",
                cidr="10.42.1.0/24",
                vlan_id="101",
                gateway="10.42.1.1",
                name="Management /24",
            ),
            Subnet(
                subnet_id="sub-042-010",
                site_id="site-042",
                cidr="10.42.10.0/24",
                vlan_id="110",
                gateway="10.42.10.1",
                name="Servers & Windows VMs /24",
            ),
            Subnet(
                subnet_id="sub-042-020",
                site_id="site-042",
                cidr="10.42.20.0/24",
                vlan_id="120",
                gateway="10.42.20.1",
                name="APC UPS /24",
            ),
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.1.2",
                subnet_id="sub-042-001",
                assigned_object_type="network_device",
                assigned_object_id="dev-042-sw-01",
                arp_mac="00:04:96:2a:01:02",
            ),
            IPAddress(
                ip="10.42.1.99",
                subnet_id="sub-042-001",
                assigned_object_type="network_device",
                assigned_object_id="dev-042-sw-stale",
                arp_mac="00:04:96:2a:01:99",
            ),
            IPAddress(
                ip="10.42.10.11",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-vm-win-01",
                arp_mac="00:50:56:2a:10:11",
            ),
            IPAddress(
                ip="10.42.10.12",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-vm-lin-01",
                arp_mac="00:50:56:2a:10:12",
            ),
            IPAddress(
                ip="10.42.20.10",
                subnet_id="sub-042-020",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-ups-01",
                arp_mac="00:c0:b7:2a:20:10",
            ),
            IPAddress(
                ip="10.42.10.99",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-srv-stale",
                arp_mac="00:1b:21:2a:10:99",
            ),
        ],
        equipment=[
            Equipment(
                equipment_id="eq-042-vm-win-01",
                site_id="site-042",
                name="win-sql-042-01",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.11"],
                connected_ports=["port-042-1-1"],
                hypervisor_id="vc-west-01:vm-1011",
                power_state="poweredOn",
                last_seen=ts,
            ),
            Equipment(
                equipment_id="eq-042-vm-lin-01",
                site_id="site-042",
                name="ubuntu-app-042-01",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.12"],
                connected_ports=[],
                hypervisor_id="vc-west-01:vm-1012",
                power_state="poweredOn",
                last_seen=ts,
            ),
            Equipment(
                equipment_id="eq-042-ups-01",
                site_id="site-042",
                name="apc-ups-042-01",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.20.10"],
                connected_ports=["port-042-1-2"],
                power_state="online",
                last_seen=ts,
            ),
            Equipment(
                equipment_id="eq-042-srv-01",
                site_id="site-042",
                name="dell-srv-042-01",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.10.25"],
                connected_ports=[],
                power_state="on",
                last_seen=ts,
            ),
            Equipment(
                equipment_id="eq-042-srv-stale",
                site_id="site-042",
                name="old-srv-042-99",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.10.99"],
                connected_ports=["port-042-1-3"],
                power_state="off",
                last_seen=ts,
            ),
        ],
    )


def _build_sample_validation_results() -> list[ValidationResult]:
    return [
        ValidationResult(
            item_type="NetworkDevice",
            item_id="dev-042-sw-01",
            site_id="site-042",
            name="ext-sw-042-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
        ),
        ValidationResult(
            item_type="NetworkDevice",
            item_id="dev-042-sw-stale",
            site_id="site-042",
            name="ext-sw-042-old",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.90,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-042-vm-win-01",
            site_id="site-042",
            name="win-sql-042-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.98,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-042-vm-lin-01",
            site_id="site-042",
            name="ubuntu-app-042-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.96,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-042-ups-01",
            site_id="site-042",
            name="apc-ups-042-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.92,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-042-srv-01",
            site_id="site-042",
            name="dell-srv-042-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.88,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-042-srv-stale",
            site_id="site-042",
            name="old-srv-042-99",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.91,
        ),
        ValidationResult(
            item_type="IPAddress",
            item_id="10.42.1.2",
            site_id="site-042",
            name="10.42.1.2",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
        ),
        ValidationResult(
            item_type="IPAddress",
            item_id="10.42.10.99",
            site_id="site-042",
            name="10.42.10.99",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.91,
        ),
    ]


def _build_sample_reconciliation_report() -> ReconciliationReport:
    return ReconciliationReport(
        discrepancies=[
            DiscrepancyRecord(
                discrepancy_id="disc-042-vm-01",
                discrepancy_type=DiscrepancyType.UNTRACKED_VM,
                site_id="site-042",
                observed_identifier="vm-2044",
                observed_ip="10.42.10.44",
                observed_mac="00:50:56:2a:10:44",
                observed_hostname="win-iis-042-44.corp.internal",
                source="vcenter",
                details="vcenter_instance=vc-west-02 vm_moref=vm-2044 power_state=poweredOn",
            ),
            DiscrepancyRecord(
                discrepancy_id="disc-042-dev-sw",
                discrepancy_type=DiscrepancyType.UNTRACKED_DEVICE,
                site_id="site-042",
                observed_identifier="10.42.1.5",
                observed_ip="10.42.1.5",
                observed_mac="00:04:96:2a:01:05",
                observed_hostname="ext-sw-042-02",
                source="snmp",
                details="vendor=Extreme_Networks model=X460-G2 role=access-switch",
            ),
            DiscrepancyRecord(
                discrepancy_id="disc-042-dev-ups",
                discrepancy_type=DiscrepancyType.UNTRACKED_DEVICE,
                site_id="site-042",
                observed_identifier="10.42.20.15",
                observed_ip="10.42.20.15",
                observed_mac="00:c0:b7:2a:20:15",
                observed_hostname="apc-ups-042-02",
                source="snmp",
                details="APC Smart-UPS 3000 RM role=ups",
            ),
            DiscrepancyRecord(
                discrepancy_id="disc-042-ip-01",
                discrepancy_type=DiscrepancyType.UNTRACKED_IP,
                site_id="site-042",
                observed_identifier="10.42.10.77",
                observed_ip="10.42.10.77",
                observed_mac="00:11:22:33:44:77",
                observed_hostname="printer-042-01",
                source="arp",
                details="subnet_id=sub-042-010 arp_source_device_id=dev-042-sw-01",
            ),
            DiscrepancyRecord(
                discrepancy_id="disc-042-mismatch-01",
                discrepancy_type=DiscrepancyType.ATTRIBUTE_MISMATCH,
                site_id="site-042",
                observed_identifier="eq-042-vm-win-01",
                observed_ip="10.42.10.11",
                observed_hostname="win-sql-042-01-renamed",
                source="vcenter",
                sot_item_id="eq-042-vm-win-01",
                details="hostname mismatch",
            ),
        ],
        generated_at=datetime(2026, 2, 10, 15, 0, 0, tzinfo=timezone.utc),
    )


def test_slugify_deterministic_and_url_safe() -> None:
    assert slugify("Site_042 / SF Campus #1") == "site-042-sf-campus-1"
    assert slugify("10.42.10.11/24") == "10-42-10-11-24"
    assert slugify("   ---   ") == "item"


def test_filter_excludes_stale_by_default_and_supports_override() -> None:
    site = _build_sample_site()
    results = _build_sample_validation_results()

    default_filter = GoldenInventoryFilter(include_stale=False, merge_untracked=False)
    filtered = default_filter.filter_site(site, validation_results=results)

    # Stale switch, stale server, and stale IP must be excluded
    assert [d.device_id for d in filtered.devices] == ["dev-042-sw-01"]
    retained_eq_ids = {e.equipment_id for e in filtered.equipment}
    assert "eq-042-srv-stale" not in retained_eq_ids
    assert "eq-042-vm-win-01" in retained_eq_ids
    assert "eq-042-ups-01" in retained_eq_ids

    retained_ips = {ip.ip for ip in filtered.ip_addresses}
    assert "10.42.10.99" not in retained_ips
    assert "10.42.1.99" not in retained_ips
    assert "10.42.1.2" in retained_ips
    assert "10.42.10.11" in retained_ips

    # Port 1:3 on dev-042-sw-01 connected to excluded eq-042-srv-stale has connected_device_id cleared
    port_1_3 = next(p for p in filtered.devices[0].ports if p.name == "1:3")
    assert port_1_3.connected_device_id is None
    # Original site object was not mutated
    orig_port_1_3 = next(p for p in site.devices[0].ports if p.name == "1:3")
    assert orig_port_1_3.connected_device_id == "eq-042-srv-stale"

    # With include_stale=True, stale records are retained and marked decommissioning / deprecated
    stale_exporter = ModernSoTExporter(
        sites=[site],
        validation_results=results,
        include_stale=True,
        merge_untracked=False,
        target_platform="netbox",
    )
    bundle = stale_exporter.to_dict()
    devices_by_name = {d["name"]: d for d in bundle["devices"]}
    assert devices_by_name["ext-sw-042-old"]["status"] == "decommissioning"
    assert devices_by_name["old-srv-042-99"]["status"] == "decommissioning"
    assert devices_by_name["ext-sw-042-01"]["status"] == "active"

    ips_by_addr = {ip["address"]: ip for ip in bundle["ip_addresses"]}
    assert ips_by_addr["10.42.10.99/24"]["status"] == "deprecated"
    assert ips_by_addr["10.42.1.99/24"]["status"] == "deprecated"
    assert ips_by_addr["10.42.1.2/24"]["status"] == "active"


def test_filter_excludes_unreachable_and_insufficient_data_when_disabled() -> None:
    site = _build_sample_site()
    results = _build_sample_validation_results()
    # Mark dell-srv-042-01 as UNREACHABLE and ubuntu-app-042-01 as INSUFFICIENT_DATA
    updated_results = []
    for r in results:
        if r.item_id == "eq-042-srv-01":
            updated_results.append(
                ValidationResult(
                    item_type=r.item_type,
                    item_id=r.item_id,
                    site_id=r.site_id,
                    name=r.name,
                    classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                    confidence=0.5,
                )
            )
        elif r.item_id == "eq-042-vm-lin-01":
            updated_results.append(
                ValidationResult(
                    item_type=r.item_type,
                    item_id=r.item_id,
                    site_id=r.site_id,
                    name=r.name,
                    classification=ValidationClassification.INSUFFICIENT_DATA,
                    confidence=0.2,
                )
            )
        else:
            updated_results.append(r)

    strict_filter = GoldenInventoryFilter(
        include_stale=False,
        include_unreachable=False,
        include_insufficient_data=False,
        merge_untracked=False,
    )
    filtered = strict_filter.filter_site(site, validation_results=updated_results)
    eq_ids = {e.equipment_id for e in filtered.equipment}
    assert "eq-042-srv-01" not in eq_ids
    assert "eq-042-vm-lin-01" not in eq_ids
    assert "eq-042-vm-win-01" in eq_ids


def test_merges_untracked_assets_and_respects_approved_discrepancy_ids() -> None:
    site = _build_sample_site()
    results = _build_sample_validation_results()
    recon = _build_sample_reconciliation_report()

    # Merge all untracked assets (ignoring ATTRIBUTE_MISMATCH)
    inv_filter = GoldenInventoryFilter(include_stale=False, merge_untracked=True)
    filtered = inv_filter.filter_site(
        site,
        validation_results=results,
        reconciliation_report=recon,
    )

    dev_names = {d.hostname for d in filtered.devices}
    assert "ext-sw-042-02" in dev_names
    assert "apc-ups-042-02" in dev_names

    eq_names = {e.name for e in filtered.equipment}
    assert "win-iis-042-44.corp.internal" in eq_names
    assert "win-sql-042-01-renamed" not in eq_names

    ips = {ip.ip for ip in filtered.ip_addresses}
    assert "10.42.10.44" in ips
    assert "10.42.1.5" in ips
    assert "10.42.20.15" in ips
    assert "10.42.10.77" in ips

    # Now filter with explicit approved_discrepancy_ids subset
    selective_filter = GoldenInventoryFilter(
        include_stale=False,
        merge_untracked=True,
        approved_discrepancy_ids=["disc-042-vm-01", "disc-042-dev-ups"],
    )
    selective_site = selective_filter.filter_site(
        site,
        validation_results=results,
        reconciliation_report=recon,
    )
    sel_dev_names = {d.hostname for d in selective_site.devices}
    assert "apc-ups-042-02" in sel_dev_names
    assert "ext-sw-042-02" not in sel_dev_names

    sel_eq_names = {e.name for e in selective_site.equipment}
    assert "win-iis-042-44.corp.internal" in sel_eq_names

    sel_ips = {ip.ip for ip in selective_site.ip_addresses}
    assert "10.42.10.44" in sel_ips
    assert "10.42.20.15" in sel_ips
    assert "10.42.10.77" not in sel_ips


def test_exporter_schema_mapping_netbox_and_nautobot() -> None:
    site = _build_sample_site()
    results = _build_sample_validation_results()
    recon = _build_sample_reconciliation_report()
    fixed_ts = datetime(2026, 2, 11, 0, 0, 0, tzinfo=timezone.utc)

    for platform in ("netbox", "nautobot"):
        exporter = ModernSoTExporter(
            sites=[site],
            validation_results={"results": [r.to_dict() for r in results]},
            reconciliation_report=recon,
            target_platform=platform,
            generated_at=fixed_ts,
        )
        bundle = exporter.to_dict()

        assert bundle["target_platform"] == platform
        assert bundle["generated_at"] == "2026-02-11T00:00:00+00:00"

        for key in ENTITY_COLLECTION_KEYS:
            assert key in bundle
            assert bundle["summary"][key] == len(bundle[key])
            assert len(bundle[key]) > 0
            for record in bundle[key]:
                assert isinstance(record.get("slug"), str)
                assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", record["slug"])
                assert isinstance(record.get("custom_fields"), dict)
                legacy_id = record["custom_fields"].get("legacy_sot_id")
                assert isinstance(legacy_id, str) and len(legacy_id.strip()) > 0

        # Verify site record
        site_rec = bundle["sites"][0]
        assert site_rec["name"] == "SF Campus 042"
        assert site_rec["slug"] == "site-042"
        assert site_rec["contact_name"] == "Jordan Rivera"
        assert site_rec["contact_email"] == "netops-site042@example.internal"
        assert site_rec["custom_fields"]["legacy_sot_id"] == "site-042"

        # Verify VLANs and /24 prefixes
        vids = [v["vid"] for v in bundle["vlans"]]
        assert vids == [101, 110, 120]
        cidrs = [p["prefix"] for p in bundle["prefixes"]]
        assert cidrs == ["10.42.1.0/24", "10.42.10.0/24", "10.42.20.0/24"]

        # Verify devices (Extreme switches, APC UPS, physical Dell server; no VMs or stale items)
        devices_by_name = {d["name"]: d for d in bundle["devices"]}
        assert "ext-sw-042-01" in devices_by_name
        assert devices_by_name["ext-sw-042-01"]["manufacturer"] == "Extreme Networks"
        assert "ext-sw-042-02" in devices_by_name
        assert "apc-ups-042-01" in devices_by_name
        assert devices_by_name["apc-ups-042-01"]["manufacturer"] == "APC"
        assert devices_by_name["apc-ups-042-01"]["role"] == "ups"
        assert "apc-ups-042-02" in devices_by_name
        assert devices_by_name["apc-ups-042-02"]["manufacturer"] == "APC"
        assert "dell-srv-042-01" in devices_by_name
        assert devices_by_name["dell-srv-042-01"]["role"] == "server"
        assert "ext-sw-042-old" not in devices_by_name
        assert "old-srv-042-99" not in devices_by_name
        assert "win-sql-042-01" not in devices_by_name

        # Verify interfaces on retained switch
        ifaces_by_name = {i["name"]: i for i in bundle["interfaces"]}
        assert ifaces_by_name["1:1"]["enabled"] is True
        assert ifaces_by_name["1:1"]["poe_mode"] == "disabled"
        assert ifaces_by_name["1:1"]["description"] == "Connected to eq-042-vm-win-01"
        assert ifaces_by_name["1:1"]["untagged_vlan"] == 110
        assert ifaces_by_name["1:2"]["poe_mode"] == "pse"
        # Port 1:3 was connected to stale excluded server -> description cleared
        assert ifaces_by_name["1:3"]["enabled"] is False
        assert ifaces_by_name["1:3"]["description"] == ""

        # Verify VMs (Windows and Linux OS family inference + cluster extraction)
        vms_by_name = {vm["name"]: vm for vm in bundle["virtual_machines"]}
        assert set(vms_by_name.keys()) == {
            "win-sql-042-01",
            "ubuntu-app-042-01",
            "win-iis-042-44.corp.internal",
        }
        assert vms_by_name["win-sql-042-01"]["cluster"] == "vc-west-01"
        assert vms_by_name["win-sql-042-01"]["custom_fields"]["os_family"] == "windows"
        assert vms_by_name["ubuntu-app-042-01"]["custom_fields"]["os_family"] == "linux"
        assert (
            vms_by_name["win-iis-042-44.corp.internal"]["cluster"] == "vc-west-02"
        )

    with pytest.raises(ValueError, match="target_platform"):
        ModernSoTExporter(sites=[site], target_platform="invalid-platform")


def test_export_json_and_csv_bundle_parity(tmp_path: Path) -> None:
    site = _build_sample_site()
    results = _build_sample_validation_results()
    recon = _build_sample_reconciliation_report()

    exporter = ModernSoTExporter(
        sites=[site],
        validation_results=results,
        reconciliation_report=recon,
        target_platform="netbox",
        generated_at="2026-02-11T00:00:00+00:00",
    )

    json_file = tmp_path / "export" / "golden_bundle.json"
    raw_json = exporter.export_json(output_path=json_file)
    assert json_file.is_file()
    parsed_json = json.loads(raw_json)
    assert json.loads(json_file.read_text(encoding="utf-8")) == parsed_json

    csv_dir = tmp_path / "csv_bundle"
    written_csvs = exporter.export_csv_bundle(csv_dir)
    assert set(written_csvs.keys()) == set(ENTITY_COLLECTION_KEYS)

    for entity_key in ENTITY_COLLECTION_KEYS:
        csv_path = written_csvs[entity_key]
        assert csv_path.is_file()
        assert csv_path.name == f"{entity_key}.csv"

        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            assert tuple(reader.fieldnames or ()) == CSV_COLUMNS_BY_ENTITY[entity_key]
            rows = list(reader)

        json_records = parsed_json[entity_key]
        assert len(rows) == len(json_records)
        for row, json_rec in zip(rows, json_records):
            assert row["slug"] == json_rec["slug"]
            assert row["legacy_sot_id"] == json_rec["custom_fields"]["legacy_sot_id"]
            if entity_key == "virtual_machines":
                assert row["os_family"] == json_rec["custom_fields"]["os_family"]
