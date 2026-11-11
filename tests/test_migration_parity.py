"""Unit tests for Phase 5 Legacy-to-Modern SoT Dual-Run Parity Checker and Migration Readiness Scorecard."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from sot_validator.migration import (
    CutoverRecommendation,
    DualRunParityChecker,
    GoldenInventoryFilter,
    MigrationParityReport,
    ModernSoTExporter,
    ParityDiscrepancy,
    ParityDiscrepancyType,
    SiteMigrationReadinessScorecard,
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


def _build_site(site_id: str = "site-042", name: str = "SF Campus 042") -> Site:
    ts = datetime(2026, 2, 10, 12, 0, 0, tzinfo=timezone.utc)
    octet = "42" if "042" in site_id else "43"
    return Site(
        site_id=site_id,
        name=name,
        address="100 Market St, San Francisco, CA",
        contact_info="Jordan Rivera | netops@example.internal | +1-650-555-0142",
        rooms=["MDF-101"],
        devices=[
            NetworkDevice(
                device_id=f"dev-{octet}-sw-01",
                site_id=site_id,
                hostname=f"ext-sw-{octet}-01",
                management_ip=f"10.{octet}.1.2",
                vendor="Extreme Networks",
                model="X460-G2-48p-10GE4",
                role="Access Switch",
                last_seen=ts,
                ports=[
                    Port(
                        port_id=f"port-{octet}-1-1",
                        device_id=f"dev-{octet}-sw-01",
                        name="1:1",
                        admin_status="up",
                        oper_status="up",
                        poe_status="off",
                        connected_device_id=f"eq-{octet}-vm-win-01",
                        connected_mac="00:50:56:2a:10:11",
                        vlan_id="110",
                    ),
                    Port(
                        port_id=f"port-{octet}-1-2",
                        device_id=f"dev-{octet}-sw-01",
                        name="1:2",
                        admin_status="up",
                        oper_status="up",
                        poe_status="delivering",
                        connected_device_id=f"eq-{octet}-ups-01",
                        connected_mac="00:c0:b7:2a:20:10",
                        vlan_id="120",
                    ),
                ],
            ),
            NetworkDevice(
                device_id=f"dev-{octet}-sw-stale",
                site_id=site_id,
                hostname=f"ext-sw-{octet}-old",
                management_ip=f"10.{octet}.1.99",
                vendor="Extreme Networks",
                model="Summit X440",
                role="Access Switch",
                last_seen=ts,
                ports=[],
            ),
        ],
        vlans=[
            VLAN(
                vlan_id="101",
                site_id=site_id,
                name="Management",
                subnet_id=f"sub-{octet}-001",
                cidr=f"10.{octet}.1.0/24",
                gateway=f"10.{octet}.1.1",
            ),
            VLAN(
                vlan_id="110",
                site_id=site_id,
                name="Servers_VMs",
                subnet_id=f"sub-{octet}-010",
                cidr=f"10.{octet}.10.0/24",
                gateway=f"10.{octet}.10.1",
            ),
            VLAN(
                vlan_id="120",
                site_id=site_id,
                name="Facilities_UPS",
                subnet_id=f"sub-{octet}-020",
                cidr=f"10.{octet}.20.0/24",
                gateway=f"10.{octet}.20.1",
            ),
        ],
        subnets=[
            Subnet(
                subnet_id=f"sub-{octet}-001",
                site_id=site_id,
                cidr=f"10.{octet}.1.0/24",
                vlan_id="101",
                gateway=f"10.{octet}.1.1",
                name="Management /24",
            ),
            Subnet(
                subnet_id=f"sub-{octet}-010",
                site_id=site_id,
                cidr=f"10.{octet}.10.0/24",
                vlan_id="110",
                gateway=f"10.{octet}.10.1",
                name="Servers & Windows VMs /24",
            ),
            Subnet(
                subnet_id=f"sub-{octet}-020",
                site_id=site_id,
                cidr=f"10.{octet}.20.0/24",
                vlan_id="120",
                gateway=f"10.{octet}.20.1",
                name="APC UPS /24",
            ),
        ],
        ip_addresses=[
            IPAddress(
                ip=f"10.{octet}.1.2",
                subnet_id=f"sub-{octet}-001",
                assigned_object_type="network_device",
                assigned_object_id=f"dev-{octet}-sw-01",
                arp_mac="00:04:96:2a:01:02",
            ),
            IPAddress(
                ip=f"10.{octet}.1.99",
                subnet_id=f"sub-{octet}-001",
                assigned_object_type="network_device",
                assigned_object_id=f"dev-{octet}-sw-stale",
                arp_mac="00:04:96:2a:01:99",
            ),
            IPAddress(
                ip=f"10.{octet}.10.11",
                subnet_id=f"sub-{octet}-010",
                assigned_object_type="equipment",
                assigned_object_id=f"eq-{octet}-vm-win-01",
                arp_mac="00:50:56:2a:10:11",
            ),
            IPAddress(
                ip=f"10.{octet}.20.10",
                subnet_id=f"sub-{octet}-020",
                assigned_object_type="equipment",
                assigned_object_id=f"eq-{octet}-ups-01",
                arp_mac="00:c0:b7:2a:20:10",
            ),
            IPAddress(
                ip=f"10.{octet}.10.99",
                subnet_id=f"sub-{octet}-010",
                assigned_object_type="equipment",
                assigned_object_id=f"eq-{octet}-srv-stale",
                arp_mac="00:1b:21:2a:10:99",
            ),
        ],
        equipment=[
            Equipment(
                equipment_id=f"eq-{octet}-vm-win-01",
                site_id=site_id,
                name=f"win-sql-{octet}-01",
                category=EquipmentCategory.VM,
                assigned_ips=[f"10.{octet}.10.11"],
                connected_ports=[f"port-{octet}-1-1"],
                hypervisor_id="vc-west-01:vm-1011",
                power_state="poweredOn",
                last_seen=ts,
            ),
            Equipment(
                equipment_id=f"eq-{octet}-ups-01",
                site_id=site_id,
                name=f"apc-ups-{octet}-01",
                category=EquipmentCategory.UPS,
                assigned_ips=[f"10.{octet}.20.10"],
                connected_ports=[f"port-{octet}-1-2"],
                power_state="online",
                last_seen=ts,
            ),
            Equipment(
                equipment_id=f"eq-{octet}-srv-stale",
                site_id=site_id,
                name=f"old-srv-{octet}-99",
                category=EquipmentCategory.SERVER,
                assigned_ips=[f"10.{octet}.10.99"],
                connected_ports=[],
                power_state="off",
                last_seen=ts,
            ),
        ],
    )


def _build_validation_results(site_id: str = "site-042") -> list[ValidationResult]:
    octet = "42" if "042" in site_id else "43"
    return [
        ValidationResult(
            item_type="NetworkDevice",
            item_id=f"dev-{octet}-sw-01",
            site_id=site_id,
            name=f"ext-sw-{octet}-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
        ),
        ValidationResult(
            item_type="NetworkDevice",
            item_id=f"dev-{octet}-sw-stale",
            site_id=site_id,
            name=f"ext-sw-{octet}-old",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.91,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id=f"eq-{octet}-vm-win-01",
            site_id=site_id,
            name=f"win-sql-{octet}-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.98,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id=f"eq-{octet}-ups-01",
            site_id=site_id,
            name=f"apc-ups-{octet}-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.94,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id=f"eq-{octet}-srv-stale",
            site_id=site_id,
            name=f"old-srv-{octet}-99",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.90,
        ),
    ]


def test_full_parity_produces_100_score_and_ready_for_cutover() -> None:
    site = _build_site()
    results = _build_validation_results()
    exporter = ModernSoTExporter(sites=[site], validation_results=results)
    modern_bundle = exporter.to_dict()

    # Evaluate using pre-built golden bundle + modern bundle
    checker = DualRunParityChecker(
        golden_bundle=exporter.to_dict(),
        modern_bundle=modern_bundle,
        validation_results=results,
    )
    scorecard = checker.evaluate_site("site-042")

    assert scorecard.site_id == "site-042"
    assert scorecard.site_name == "SF Campus 042"
    assert scorecard.parity_match_percentage == 100.0
    assert scorecard.readiness_score == 100.0
    assert scorecard.recommendation is CutoverRecommendation.READY_FOR_CUTOVER
    assert scorecard.is_ready_for_cutover is True
    assert scorecard.discrepancies == []
    assert scorecard.unwaived_discrepancies == []
    assert scorecard.blocking_reasons == []
    assert scorecard.expected_golden_items > 0
    assert scorecard.matched_modern_items == scorecard.expected_golden_items
    assert scorecard.confirmed_active_count == 3
    assert scorecard.stale_count == 2
    assert scorecard.unreachable_count == 0
    assert scorecard.insufficient_data_count == 0
    assert scorecard.unresolved_untracked_count == 0

    # Evaluate directly from raw Site + ValidationResult inputs
    raw_checker = DualRunParityChecker(
        sites=[site],
        validation_results=results,
        modern_bundle=modern_bundle,
    )
    raw_scorecard = raw_checker.evaluate_site()
    assert raw_scorecard.readiness_score == 100.0
    assert raw_scorecard.recommendation is CutoverRecommendation.READY_FOR_CUTOVER


def test_detects_missing_in_modern_sot_for_devices_vms_and_ips() -> None:
    site = _build_site()
    results = _build_validation_results()
    exporter = ModernSoTExporter(sites=[site], validation_results=results)
    golden_bundle = exporter.to_dict()
    modern_bundle = copy.deepcopy(golden_bundle)

    # Remove APC UPS from devices, Windows VM from virtual_machines, and 10.42.20.10/24 from ip_addresses
    modern_bundle["devices"] = [
        d for d in modern_bundle["devices"] if d["name"] != "apc-ups-42-01"
    ]
    modern_bundle["virtual_machines"] = [
        vm
        for vm in modern_bundle["virtual_machines"]
        if vm["name"] != "win-sql-42-01"
    ]
    modern_bundle["ip_addresses"] = [
        ip
        for ip in modern_bundle["ip_addresses"]
        if ip["address"] != "10.42.20.10/24"
    ]

    checker = DualRunParityChecker()
    scorecard = checker.evaluate_site(
        golden_bundle=golden_bundle,
        modern_bundle=modern_bundle,
        validation_results=results,
    )

    assert scorecard.recommendation is CutoverRecommendation.NEEDS_REMEDIATION
    assert scorecard.is_ready_for_cutover is False
    assert scorecard.parity_match_percentage < 100.0
    assert scorecard.readiness_score < 100.0
    assert (
        scorecard.summary_by_discrepancy_type[
            ParityDiscrepancyType.MISSING_IN_MODERN_SOT.value
        ]
        == 3
    )

    missing_items = {
        (d.entity_type, d.item_identifier)
        for d in scorecard.discrepancies
        if d.discrepancy_type is ParityDiscrepancyType.MISSING_IN_MODERN_SOT
    }
    assert ("devices", "apc-ups-42-01") in missing_items
    assert ("virtual_machines", "win-sql-42-01") in missing_items
    assert ("ip_addresses", "10.42.20.10/24") in missing_items


def test_detects_stale_leaked_to_modern_sot_and_blocks_cutover() -> None:
    site = _build_site()
    results = _build_validation_results()
    golden_exporter = ModernSoTExporter(
        sites=[site], validation_results=results, include_stale=False
    )
    # Build a leaky bundle that includes stale items
    leaky_exporter = ModernSoTExporter(
        sites=[site], validation_results=results, include_stale=True
    )
    leaky_bundle = leaky_exporter.to_dict()
    # Even if a leaked stale item was imported with status="active" in NetBox,
    # DualRunParityChecker must still catch it via validation_results / stale_item_ids!
    for dev in leaky_bundle["devices"]:
        if dev["name"] == "ext-sw-42-old":
            dev["status"] = "active"

    checker = DualRunParityChecker(
        sites=[site],
        validation_results=results,
        golden_bundle=golden_exporter.to_dict(),
        modern_bundle=leaky_bundle,
    )
    scorecard = checker.evaluate_site("site-042")

    assert scorecard.recommendation is CutoverRecommendation.BLOCKED
    assert scorecard.is_ready_for_cutover is False
    assert scorecard.readiness_score < 85.0
    leaked_discs = [
        d
        for d in scorecard.discrepancies
        if d.discrepancy_type is ParityDiscrepancyType.STALE_LEAKED_TO_MODERN_SOT
    ]
    assert len(leaked_discs) == 4
    leaked_identifiers = {d.item_identifier for d in leaked_discs}
    assert "ext-sw-42-old" in leaked_identifiers
    assert "old-srv-42-99" in leaked_identifiers
    assert "10.42.1.99/24" in leaked_identifiers
    assert "10.42.10.99/24" in leaked_identifiers
    assert any("stale" in reason.lower() for reason in scorecard.blocking_reasons)


def test_detects_attribute_mismatches_across_ip_vlan_hostname_and_role() -> None:
    site = _build_site()
    results = _build_validation_results()
    golden_bundle = ModernSoTExporter(
        sites=[site], validation_results=results
    ).to_dict()
    modern_bundle = copy.deepcopy(golden_bundle)

    # 1. Hostname & Role mismatch on Extreme switch
    for dev in modern_bundle["devices"]:
        if dev["custom_fields"]["legacy_sot_id"] == "dev-42-sw-01":
            dev["name"] = "ext-sw-42-01-renamed"
            dev["role"] = "core-router"

    # 2. VLAN ID mismatch on VLAN 110 (Servers_VMs)
    for vlan in modern_bundle["vlans"]:
        if vlan["name"] == "Servers_VMs":
            vlan["vid"] = 210

    # 3. IP assignment mismatch on Windows VM IP (10.42.10.11/24 -> 10.42.10.250/24)
    for ip_rec in modern_bundle["ip_addresses"]:
        if ip_rec["custom_fields"]["legacy_sot_id"] == "site-042:ip:10.42.10.11":
            ip_rec["address"] = "10.42.10.250/24"

    checker = DualRunParityChecker(
        golden_bundle=golden_bundle,
        modern_bundle=modern_bundle,
        validation_results=results,
    )
    scorecard = checker.evaluate_site("site-042")

    assert scorecard.recommendation is CutoverRecommendation.NEEDS_REMEDIATION
    mismatches = [
        d
        for d in scorecard.discrepancies
        if d.discrepancy_type is ParityDiscrepancyType.ATTRIBUTE_MISMATCH
    ]
    assert len(mismatches) == 4

    by_attr = {d.attribute_name: d for d in mismatches}
    assert set(by_attr.keys()) == {"hostname", "role", "vlan", "ip_address"}

    assert by_attr["hostname"].expected_value == "ext-sw-42-01"
    assert by_attr["hostname"].actual_value == "ext-sw-42-01-renamed"
    assert by_attr["role"].expected_value == "access-switch"
    assert by_attr["role"].actual_value == "core-router"
    assert by_attr["vlan"].expected_value == 110
    assert by_attr["vlan"].actual_value == 210
    assert by_attr["ip_address"].expected_value == "10.42.10.11/24"
    assert by_attr["ip_address"].actual_value == "10.42.10.250/24"


def test_readiness_degradation_from_unreachable_insufficient_data_and_untracked_assets() -> None:
    site = _build_site()
    results = _build_validation_results()
    # Add an UNREACHABLE_NEEDS_REVIEW and an INSUFFICIENT_DATA validation result
    results_with_issues = list(results) + [
        ValidationResult(
            item_type="Equipment",
            item_id="eq-42-san-01",
            site_id="site-042",
            name="netapp-san-42-01",
            classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
            confidence=0.45,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-42-pdu-01",
            site_id="site-042",
            name="apc-pdu-42-01",
            classification=ValidationClassification.INSUFFICIENT_DATA,
            confidence=0.20,
        ),
    ]
    # Add an unmerged untracked VM in ReconciliationReport
    recon = ReconciliationReport(
        discrepancies=[
            DiscrepancyRecord(
                discrepancy_id="disc-042-untracked-vm",
                discrepancy_type=DiscrepancyType.UNTRACKED_VM,
                site_id="site-042",
                observed_identifier="vm-9999",
                observed_ip="10.42.10.88",
                observed_hostname="shadow-win-vm-88",
                source="vcenter",
            )
        ]
    )

    # Export without merging untracked VM
    exporter = ModernSoTExporter(
        sites=[site],
        validation_results=results_with_issues,
        merge_untracked=False,
    )
    bundle = exporter.to_dict()

    checker = DualRunParityChecker(
        golden_bundle=bundle,
        modern_bundle=bundle,
        validation_results=results_with_issues,
        reconciliation_report=recon,
    )
    scorecard = checker.evaluate_site("site-042")

    # Parity on exported golden items is 100%, but unreachable, insufficient data, and untracked VM degrade readiness
    assert scorecard.parity_match_percentage == 100.0
    assert scorecard.unreachable_count == 1
    assert scorecard.insufficient_data_count == 1
    assert scorecard.unresolved_untracked_count == 1
    assert scorecard.readiness_score < 90.0
    assert scorecard.recommendation is CutoverRecommendation.NEEDS_REMEDIATION
    assert len(scorecard.blocking_reasons) == 3


def test_discrepancy_waivers_promote_site_to_ready_for_cutover() -> None:
    site = _build_site()
    results = _build_validation_results()
    golden_bundle = ModernSoTExporter(
        sites=[site], validation_results=results
    ).to_dict()
    modern_bundle = copy.deepcopy(golden_bundle)

    # Introduce a role mismatch on ext-sw-42-01 and remove apc-ups-42-01
    for dev in modern_bundle["devices"]:
        if dev["name"] == "ext-sw-42-01":
            dev["role"] = "distribution-switch"
    modern_bundle["devices"] = [
        d for d in modern_bundle["devices"] if d["name"] != "apc-ups-42-01"
    ]

    checker = DualRunParityChecker(
        golden_bundle=golden_bundle,
        modern_bundle=modern_bundle,
        validation_results=results,
    )
    unwaived_card = checker.evaluate_site("site-042")
    assert unwaived_card.recommendation is CutoverRecommendation.NEEDS_REMEDIATION
    assert len(unwaived_card.unwaived_discrepancies) == 2

    # Waive both items by identifier / legacy_sot_id
    waived_card = checker.evaluate_site(
        "site-042",
        waived_discrepancy_ids=["ext-sw-42-01", "eq-42-ups-01"],
    )
    assert waived_card.waived_discrepancy_count == 2
    assert waived_card.unwaived_discrepancies == []
    assert waived_card.parity_match_percentage == 100.0
    assert waived_card.readiness_score == 100.0
    assert waived_card.recommendation is CutoverRecommendation.READY_FOR_CUTOVER
    assert waived_card.is_ready_for_cutover is True


def test_multi_site_report_and_serialization_round_trip(tmp_path: Path) -> None:
    site_42 = _build_site("site-042", "SF Campus 042")
    site_43 = _build_site("site-043", "Oakland DC 043")
    results_42 = _build_validation_results("site-042")
    results_43 = _build_validation_results("site-043")
    all_results = results_42 + results_43

    golden_exporter = ModernSoTExporter(
        sites=[site_42, site_43],
        validation_results=all_results,
    )
    golden_bundle = golden_exporter.to_dict()
    modern_bundle = copy.deepcopy(golden_bundle)

    # Keep site-042 at 100% parity (READY_FOR_CUTOVER), and leak a stale switch into site-043 (BLOCKED)
    modern_bundle["devices"].append(
        {
            "name": "ext-sw-43-old",
            "slug": "ext-sw-43-old",
            "manufacturer": "Extreme Networks",
            "role": "access-switch",
            "device_type": "Summit X440",
            "site": "site-043",
            "status": "decommissioning",
            "custom_fields": {"legacy_sot_id": "dev-43-sw-stale"},
        }
    )

    checker = DualRunParityChecker(
        sites=[site_42, site_43],
        validation_results=all_results,
        golden_bundle=golden_bundle,
        modern_bundle=modern_bundle,
        evaluated_at="2026-02-12T00:00:00+00:00",
    )
    report = checker.check_parity()

    assert isinstance(report, MigrationParityReport)
    assert report.total_sites == 2
    assert report.ready_for_cutover_count == 1
    assert report.needs_remediation_count == 0
    assert report.blocked_count == 1
    assert report.total_discrepancies == 1
    assert report.summary_by_type == {
        "MISSING_IN_MODERN_SOT": 0,
        "STALE_LEAKED_TO_MODERN_SOT": 1,
        "ATTRIBUTE_MISMATCH": 0,
    }
    assert report.summary_by_recommendation == {
        "READY_FOR_CUTOVER": 1,
        "NEEDS_REMEDIATION": 0,
        "BLOCKED": 1,
    }

    card_42 = report.get_scorecard("site-042")
    card_43 = report.get_scorecard("site-043")
    assert card_42 is not None and card_42.is_ready_for_cutover is True
    assert card_43 is not None and card_43.recommendation is CutoverRecommendation.BLOCKED

    # Test JSON & dict round-trips for ParityDiscrepancy, SiteMigrationReadinessScorecard, and MigrationParityReport
    disc = card_43.discrepancies[0]
    assert ParityDiscrepancy.from_json(disc.to_json()) == disc
    assert SiteMigrationReadinessScorecard.from_json(card_43.to_json()) == card_43

    json_path = tmp_path / "parity_report.json"
    raw_json = report.to_json(output_path=json_path)
    assert json_path.is_file()
    restored = MigrationParityReport.from_json(raw_json)
    assert restored.to_dict() == report.to_dict()
