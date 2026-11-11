"""Unit tests for Phase 3 Reverse Discovery & Untracked Inventory Reconciler."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sqlite3
import pytest

from sot_validator.extraction import SqlExportSoTClient
from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
)
from sot_validator.reconciliation import (
    DISCREPANCY_CSV_COLUMNS,
    ONBOARDING_CSV_COLUMNS,
    DiscrepancyRecord,
    DiscrepancyType,
    InventoryReconciler,
    ReconciliationReport,
)
from sot_validator.signals.hypervisor import (
    HypervisorVmRecord,
    MultiVCenterInventoryProvider,
    VmPowerState,
)
from sot_validator.signals.icmp import IcmpProbeResponse
from sot_validator.signals.management import (
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
    EXTREME_SYS_SERIAL_NUMBER_OID,
    EXTREME_SYS_VERSION_OID,
    FixtureManagementTransport,
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_NAME,
    SNMPV2_MIB_SYS_UPTIME,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "sot_samples"
SQL_SEED_PATH = FIXTURES_DIR / "sql" / "sot_schema_and_seed.sql"
VCENTER_FIXTURE_PATH = FIXTURES_DIR / "vcenter" / "vcenter_inventory.json"
SNMP_FIXTURE_PATH = FIXTURES_DIR / "snmp" / "extreme_and_apc_walks.json"
FIXED_TIME = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)


def _build_base_site() -> Site:
    return Site(
        site_id="site-042",
        name="SF Regional Distribution Center 42",
        subnets=[
            Subnet(
                subnet_id="sub-042-001",
                site_id="site-042",
                cidr="10.42.1.0/24",
                vlan_id="1",
                gateway="10.42.1.1",
                name="MGMT-NET",
            ),
            Subnet(
                subnet_id="sub-042-010",
                site_id="site-042",
                cidr="10.42.10.0/24",
                vlan_id="10",
                gateway="10.42.10.1",
                name="SERVER-PROD",
            ),
            Subnet(
                subnet_id="sub-042-030",
                site_id="site-042",
                cidr="10.42.30.0/24",
                vlan_id="30",
                gateway="10.42.30.1",
                name="FACILITY-UPS",
            ),
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
                ports=[
                    Port(
                        port_id="port-042-sw01-1",
                        device_id="dev-042-sw01",
                        name="1:1",
                        admin_status="up",
                        oper_status="up",
                        connected_device_id="eq-042-esx01",
                        connected_mac="00:50:56:60:42:01",
                    ),
                    Port(
                        port_id="port-042-sw01-3",
                        device_id="dev-042-sw01",
                        name="1:3",
                        admin_status="up",
                        oper_status="up",
                        connected_device_id="eq-042-ups01",
                        connected_mac="00:c0:b7:42:30:01",
                    ),
                ],
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.1.10",
                subnet_id="sub-042-001",
                assigned_object_type="network_device",
                assigned_object_id="dev-042-sw01",
                arp_mac="00:04:96:9a:bc:01",
                arp_source_device_id="dev-042-sw01",
            ),
            IPAddress(
                ip="10.42.10.21",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-vm-win01",
                arp_mac="00:50:56:9a:42:11",
                arp_source_device_id="dev-042-sw01",
            ),
            IPAddress(
                ip="10.42.30.10",
                subnet_id="sub-042-030",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-ups01",
                arp_mac="00:c0:b7:42:30:01",
                arp_source_device_id="dev-042-sw01",
            ),
        ],
        equipment=[
            Equipment(
                equipment_id="eq-042-vm-win01",
                site_id="site-042",
                name="win-dc01.site042.example.internal",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.21"],
                connected_ports=["port-042-sw01-1"],
                hypervisor_id="421a0042-0001-4000-8000-0050569a4211",
                power_state="poweredOn",
            ),
            Equipment(
                equipment_id="eq-042-ups01",
                site_id="site-042",
                name="ups01.site042.example.internal",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.30.10"],
                connected_ports=["port-042-sw01-3"],
            ),
        ],
    )


def test_discrepancy_record_validation_and_serialization() -> None:
    record = DiscrepancyRecord(
        discrepancy_id="disc-001",
        discrepancy_type="UNTRACKED_VM",  # type: ignore[arg-type]
        site_id="site-042",
        observed_identifier="vm-10999",
        observed_ip="10.42.10.50",
        observed_mac="00-50-56-9A-42-50",
        observed_hostname="win-shadow01.site042.example.internal",
        source="VCENTER",
        details="Untracked Windows VM",
        recommended_onboarding_action="Insert into equipment",
    )
    assert record.discrepancy_type is DiscrepancyType.UNTRACKED_VM
    assert record.observed_mac == "00:50:56:9a:42:50"
    assert record.source == "vcenter"
    assert record.sot_item_id is None

    round_trip = DiscrepancyRecord.from_json(record.to_json(indent=2))
    assert round_trip == record

    with pytest.raises(ValueError, match="discrepancy_id"):
        DiscrepancyRecord(
            discrepancy_id="  ",
            discrepancy_type=DiscrepancyType.UNTRACKED_IP,
            site_id="site-042",
            observed_identifier="10.42.10.50",
        )

    with pytest.raises(ValueError, match="Invalid discrepancy_type"):
        DiscrepancyRecord(
            discrepancy_id="disc-bad",
            discrepancy_type="UNKNOWN_TYPE",  # type: ignore[arg-type]
            site_id="site-042",
            observed_identifier="10.42.10.50",
        )

    with pytest.raises(ValueError, match="Invalid source"):
        DiscrepancyRecord(
            discrepancy_id="disc-bad-src",
            discrepancy_type=DiscrepancyType.UNTRACKED_IP,
            site_id="site-042",
            observed_identifier="10.42.10.50",
            source="netflow",
        )


def test_reconcile_untracked_vm_detection_and_powered_off_filtering() -> None:
    site = _build_base_site()
    provider = MultiVCenterInventoryProvider(
        vms=[
            # Already tracked in site.equipment (matches by BIOS UUID)
            HypervisorVmRecord(
                vcenter_instance="vcenter-prod-01",
                vm_moref="vm-10421",
                vm_name="win-dc01.site042",
                guest_hostname="win-dc01.site042.example.internal",
                bios_uuid="421a0042-0001-4000-8000-0050569a4211",
                power_state=VmPowerState.POWERED_ON,
                guest_os_family="windows",
                ip_addresses=["10.42.10.21"],
                mac_addresses=["00:50:56:9a:42:11"],
                site_id="site-042",
            ),
            # Powered-off untracked VM -> must NOT trigger UNTRACKED_VM
            HypervisorVmRecord(
                vcenter_instance="vcenter-prod-01",
                vm_moref="vm-10499",
                vm_name="win-decomm01.site042",
                guest_hostname="win-decomm01.site042.example.internal",
                bios_uuid="421a0042-0099-4000-8000-0050569a4299",
                power_state=VmPowerState.POWERED_OFF,
                guest_os_family="windows",
                ip_addresses=["10.42.10.99"],
                mac_addresses=["00:50:56:9a:42:99"],
                site_id="site-042",
            ),
            # Powered-on untracked Windows VM -> MUST trigger UNTRACKED_VM
            HypervisorVmRecord(
                vcenter_instance="vcenter-prod-02",
                vm_moref="vm-20421",
                vm_name="win-app01.site042",
                guest_hostname="win-app01.site042.example.internal",
                bios_uuid="421a0042-0006-4000-8000-0050569a4216",
                power_state=VmPowerState.POWERED_ON,
                guest_os_family="windows",
                ip_addresses=["10.42.10.26"],
                mac_addresses=["00:50:56:9a:42:16"],
                site_id="site-042",
            ),
            # Powered-on untracked Linux VM -> MUST trigger UNTRACKED_VM
            HypervisorVmRecord(
                vcenter_instance="vcenter-prod-02",
                vm_moref="vm-20425",
                vm_name="lnx-syslog01.site042",
                guest_hostname="lnx-syslog01.site042.example.internal",
                bios_uuid="421a0042-0010-4000-8000-0050569a4220",
                power_state=VmPowerState.POWERED_ON,
                guest_os_family="linux",
                ip_addresses=["10.42.10.30"],
                mac_addresses=["00:50:56:9a:42:20"],
                site_id="site-042",
            ),
        ]
    )

    reconciler = InventoryReconciler()
    report = reconciler.reconcile(
        site, vcenter_provider=provider, generated_at=FIXED_TIME
    )

    untracked_vms = [
        d
        for d in report.discrepancies
        if d.discrepancy_type is DiscrepancyType.UNTRACKED_VM
    ]
    assert len(untracked_vms) == 2
    hostnames = {d.observed_hostname for d in untracked_vms}
    assert hostnames == {
        "win-app01.site042.example.internal",
        "lnx-syslog01.site042.example.internal",
    }
    for d in untracked_vms:
        assert d.source == "vcenter"
        assert d.sot_item_id is None
        assert d.site_id == "site-042"


def _load_seed_sql_without_pragma() -> str:
    raw = SQL_SEED_PATH.read_text(encoding="utf-8")
    return "\n".join(
        line
        for line in raw.splitlines()
        if not line.strip().upper().startswith("PRAGMA")
    )


def test_reconcile_untracked_vm_with_seed_fixtures() -> None:
    sot_client = SqlExportSoTClient.from_sql_dump(_load_seed_sql_without_pragma())
    sites = sot_client.list_sites()
    vc_provider = MultiVCenterInventoryProvider.from_json_file(VCENTER_FIXTURE_PATH)

    report = InventoryReconciler().reconcile(
        sites, vcenter_provider=vc_provider, generated_at=FIXED_TIME
    )
    untracked_vms = [
        d
        for d in report.discrepancies
        if d.discrepancy_type is DiscrepancyType.UNTRACKED_VM
    ]
    # vcenter_inventory.json has 10 VMs: 1 tracked poweredOn (win-dc01), 1 tracked poweredOff (win-print02),
    # and 8 untracked poweredOn VMs (7 Windows + 1 Linux).
    assert len(untracked_vms) == 8
    assert report.summary_by_type[DiscrepancyType.UNTRACKED_VM.value] == 8
    assert report.summary_by_type[DiscrepancyType.ATTRIBUTE_MISMATCH.value] == 0


def test_reconcile_untracked_ip_and_slash24_scoping() -> None:
    site = _build_base_site()
    reconciler = InventoryReconciler()

    report = reconciler.reconcile(
        site,
        arp_entries=[
            # Tracked IP with matching MAC -> not untracked
            ArpEntry(
                ip="10.42.10.21",
                arp_mac="00:50:56:9a:42:11",
                arp_source_device_id="dev-042-sw01",
            ),
            # Untracked active ARP IP inside allocated /24 (10.42.10.0/24)
            ArpEntry(
                ip="10.42.10.75",
                arp_mac="00:50:56:9a:42:75",
                arp_source_device_id="dev-042-sw01",
            ),
            # Out-of-scope ARP IP in unallocated /24 block (10.42.99.0/24) -> ignored
            ArpEntry(
                ip="10.42.99.50",
                arp_mac="00:50:56:9a:99:50",
            ),
        ],
        icmp_responses={
            # Tracked IP
            "10.42.1.10": IcmpProbeResponse(reachable=True, latency_ms=1.1),
            # Untracked reachable ICMP IP in allocated /24 (10.42.1.0/24)
            "10.42.1.88": IcmpProbeResponse(reachable=True, latency_ms=2.4),
            # Unreachable ICMP IP in allocated /24 -> ignored
            "10.42.1.89": IcmpProbeResponse(reachable=False),
            # Reachable ICMP IP outside allocated /24 subnets -> ignored
            "10.42.88.10": IcmpProbeResponse(reachable=True, latency_ms=1.5),
            "192.168.1.50": True,
        },
        generated_at=FIXED_TIME,
    )

    untracked_ips = [
        d
        for d in report.discrepancies
        if d.discrepancy_type is DiscrepancyType.UNTRACKED_IP
    ]
    assert len(untracked_ips) == 2
    by_ip = {d.observed_ip: d for d in untracked_ips}
    assert set(by_ip.keys()) == {"10.42.1.88", "10.42.10.75"}
    assert by_ip["10.42.10.75"].source == "arp"
    assert by_ip["10.42.10.75"].observed_mac == "00:50:56:9a:42:75"
    assert by_ip["10.42.1.88"].source == "icmp"
    assert by_ip["10.42.1.88"].sot_item_id is None


def test_reconcile_untracked_device_extreme_switch_and_apc_ups() -> None:
    site = _build_base_site()
    reconciler = InventoryReconciler()

    snmp_targets = {
        # Tracked Extreme switch -> should NOT be flagged as untracked
        "dev-042-sw01": {
            "ip_address": "10.42.1.10",
            "snmp_reachable": True,
            "oids": {
                SNMPV2_MIB_SYS_DESCR: "ExtremeXOS (X465-48W) version 31.7.1.4",
                SNMPV2_MIB_SYS_UPTIME: "419284500",
                SNMPV2_MIB_SYS_NAME: "sw01.site042.example.internal",
                EXTREME_SYS_VERSION_OID: "31.7.1.4",
                EXTREME_SYS_SERIAL_NUMBER_OID: "SIM-EX465-04201",
            },
        },
        # Untracked Extreme Networks access switch in 10.42.1.0/24
        "untracked-sw03": {
            "ip_address": "10.42.1.15",
            "mac_address": "00-04-96-9A-BC-03",
            "snmp_reachable": True,
            "oids": {
                SNMPV2_MIB_SYS_DESCR: "ExtremeXOS (X440-G2-48p) version 31.7.1.4",
                SNMPV2_MIB_SYS_UPTIME: "12345600",
                SNMPV2_MIB_SYS_NAME: "sw03-shadow.site042.example.internal",
                EXTREME_SYS_VERSION_OID: "31.7.1.4",
                EXTREME_SYS_SERIAL_NUMBER_OID: "SIM-EX440-04203",
            },
        },
        # Untracked APC Smart-UPS in 10.42.30.0/24
        "untracked-ups02": {
            "ip_address": "10.42.30.25",
            "mac_address": "00:C0:B7:42:30:25",
            "snmp_reachable": True,
            "oids": {
                SNMPV2_MIB_SYS_DESCR: "APC Web/SNMP Management Card",
                SNMPV2_MIB_SYS_UPTIME: "9876500",
                SNMPV2_MIB_SYS_NAME: "ups02-idf.site042.example.internal",
                APC_UPS_BASIC_IDENT_MODEL_OID: "Smart-UPS SRT 3000VA",
                APC_UPS_BASIC_STATE_OUTPUT_STATE_OID: "00010000",
            },
        },
        # Unreachable SNMP target -> ignored
        "offline-dev": {
            "ip_address": "10.42.1.16",
            "snmp_reachable": False,
        },
        # Out-of-scope SNMP target outside allocated /24 subnets -> ignored
        "out-of-scope-dev": {
            "ip_address": "10.42.77.10",
            "snmp_reachable": True,
            "oids": {
                SNMPV2_MIB_SYS_NAME: "rogue-sw.site042.example.internal",
            },
        },
    }

    report = reconciler.reconcile(
        site, snmp_targets=snmp_targets, generated_at=FIXED_TIME
    )
    untracked_devs = [
        d
        for d in report.discrepancies
        if d.discrepancy_type is DiscrepancyType.UNTRACKED_DEVICE
    ]
    assert len(untracked_devs) == 2
    by_ip = {d.observed_ip: d for d in untracked_devs}
    assert set(by_ip.keys()) == {"10.42.1.15", "10.42.30.25"}

    sw_disc = by_ip["10.42.1.15"]
    assert sw_disc.source == "snmp"
    assert sw_disc.observed_hostname == "sw03-shadow.site042.example.internal"
    assert sw_disc.observed_mac == "00:04:96:9a:bc:03"
    assert "Extreme" in (sw_disc.details or "")

    ups_disc = by_ip["10.42.30.25"]
    assert ups_disc.source == "snmp"
    assert ups_disc.observed_hostname == "ups02-idf.site042.example.internal"
    assert ups_disc.observed_mac == "00:c0:b7:42:30:25"
    assert "APC" in (ups_disc.details or "")


def test_reconcile_attribute_mismatch_across_vcenter_arp_and_snmp() -> None:
    site = _build_base_site()
    reconciler = InventoryReconciler()

    # 1. vCenter VM matched by BIOS UUID, but hostname, IP, and MAC have drifted
    drifted_vm = HypervisorVmRecord(
        vcenter_instance="vcenter-prod-01",
        vm_moref="vm-10421",
        vm_name="win-dc01-renamed.site042",
        guest_hostname="win-dc01-renamed.site042.example.internal",
        bios_uuid="421a0042-0001-4000-8000-0050569a4211",
        power_state=VmPowerState.POWERED_ON,
        guest_os_family="windows",
        ip_addresses=["10.42.10.210"],
        mac_addresses=["00:50:56:9a:ff:ff"],
        site_id="site-042",
    )

    # 2. ARP entry for tracked UPS IP 10.42.30.10 with drifted MAC and port mapping
    drifted_arp = [
        {
            "ip": "10.42.30.10",
            "arp_mac": "00:c0:b7:99:99:99",
            "arp_source_device_id": "dev-042-sw02",
            "connected_port": "port-042-sw02-9",
        }
    ]

    # 3. SNMP target for tracked switch 10.42.1.10 with drifted sysName and MAC
    drifted_snmp = [
        {
            "ip_address": "10.42.1.10",
            "sys_name": "sw01-replaced.site042.example.internal",
            "mac_address": "00:04:96:ff:ff:ff",
            "vendor": "Extreme Networks",
            "snmp_reachable": True,
        }
    ]

    report = reconciler.reconcile(
        site,
        vms=[drifted_vm],
        arp_entries=drifted_arp,
        snmp_targets=drifted_snmp,
        generated_at=FIXED_TIME,
    )

    mismatches = [
        d
        for d in report.discrepancies
        if d.discrepancy_type is DiscrepancyType.ATTRIBUTE_MISMATCH
    ]
    assert len(mismatches) == 3

    by_source = {d.source: d for d in mismatches}
    assert set(by_source.keys()) == {"vcenter", "arp", "snmp"}

    vc_m = by_source["vcenter"]
    assert vc_m.sot_item_id == "eq-042-vm-win01"
    assert "hostname mismatch" in (vc_m.details or "")
    assert "IP mismatch" in (vc_m.details or "")
    assert "MAC mismatch" in (vc_m.details or "")

    arp_m = by_source["arp"]
    assert arp_m.sot_item_id == "eq-042-ups01"
    assert "MAC mismatch" in (arp_m.details or "")
    assert "switch port mapping mismatch" in (arp_m.details or "")

    snmp_m = by_source["snmp"]
    assert snmp_m.sot_item_id == "dev-042-sw01"
    assert "sysName/hostname mismatch" in (snmp_m.details or "")
    assert "MAC mismatch" in (snmp_m.details or "")


def test_report_serialization_and_onboarding_csv_sql_generation(
    tmp_path: Path,
) -> None:
    seed_sql_no_pragma = _load_seed_sql_without_pragma()
    sot_client = SqlExportSoTClient.from_sql_dump(seed_sql_no_pragma)
    site = sot_client.get_site("site-042")

    reconciler = InventoryReconciler()
    report = reconciler.reconcile(
        site,
        vms=[
            HypervisorVmRecord(
                vcenter_instance="vcenter-prod-02",
                vm_moref="vm-20421",
                vm_name="win-app01.site042",
                guest_hostname="win-app01.site042.example.internal",
                bios_uuid="421a0042-0006-4000-8000-0050569a4216",
                power_state=VmPowerState.POWERED_ON,
                guest_os_family="windows",
                ip_addresses=["10.42.10.26"],
                mac_addresses=["00:50:56:9a:42:16"],
                site_id="site-042",
            )
        ],
        snmp_targets=[
            {
                "ip_address": "10.42.1.15",
                "sys_name": "sw03.site042.example.internal",
                "vendor": "Extreme Networks",
                "model": "ExtremeSwitching X440-G2",
                "role": "access-switch",
                "mac_address": "00:04:96:9a:bc:03",
                "os_version": "EXOS 31.7.1.4",
                "serial_number": "SIM-EX440-04203",
                "snmp_reachable": True,
            }
        ],
        arp_entries=[
            ArpEntry(
                ip="10.42.20.88",
                arp_mac="00:a0:98:42:20:88",
                arp_source_device_id="dev-042-sw01",
            ),
            # Also include an attribute mismatch to verify it is excluded from onboarding templates
            ArpEntry(
                ip="10.42.10.21",
                arp_mac="00:50:56:9a:ff:99",
                arp_source_device_id="dev-042-sw01",
            ),
        ],
        generated_at=FIXED_TIME,
    )

    assert report.total_discrepancies == 6
    assert report.summary_by_type == {
        "UNTRACKED_VM": 1,
        "UNTRACKED_DEVICE": 1,
        "UNTRACKED_IP": 3,
        "ATTRIBUTE_MISMATCH": 1,
    }
    assert report.summary_by_site["site-042"]["total"] == 6
    assert report.summary_by_site["site-042"]["UNTRACKED_VM"] == 1
    assert report.summary_by_site["site-042"]["UNTRACKED_DEVICE"] == 1
    assert report.summary_by_site["site-042"]["UNTRACKED_IP"] == 3
    assert report.summary_by_site["site-042"]["ATTRIBUTE_MISMATCH"] == 1

    # 1. JSON serialization & round-trip
    json_path = tmp_path / "reconciliation_report.json"
    raw_json = report.to_json(output_path=json_path)
    assert json_path.is_file()
    restored = ReconciliationReport.from_json(raw_json)
    assert restored.total_discrepancies == report.total_discrepancies
    assert restored.summary_by_type == report.summary_by_type
    assert restored.discrepancies == report.discrepancies

    # 2. Discrepancy CSV serialization
    csv_path = tmp_path / "reconciliation_report.csv"
    raw_csv = report.to_csv(output_path=csv_path)
    assert csv_path.is_file()
    csv_rows = list(csv.DictReader(io.StringIO(raw_csv)))
    assert len(csv_rows) == 6
    assert tuple(csv_rows[0].keys()) == DISCREPANCY_CSV_COLUMNS

    # 3. Onboarding CSV template generation
    onboard_csv_path = tmp_path / "onboarding.csv"
    onboard_csv = report.generate_onboarding_csv(output_path=onboard_csv_path)
    assert onboard_csv_path.is_file()
    onboard_rows = list(csv.DictReader(io.StringIO(onboard_csv)))
    # 5 untracked records (1 VM, 1 Device, 3 IPs); ATTRIBUTE_MISMATCH is excluded
    assert len(onboard_rows) == 5
    assert tuple(onboard_rows[0].keys()) == ONBOARDING_CSV_COLUMNS
    tables_in_csv = {r["target_table"] for r in onboard_rows}
    assert tables_in_csv == {"equipment", "network_devices", "ip_arp_entries"}

    # 4. Onboarding SQL template generation & SQLite + SqlExportSoTClient verification
    onboard_sql_path = tmp_path / "onboarding.sql"
    onboard_sql = report.generate_onboarding_sql(output_path=onboard_sql_path)
    assert onboard_sql_path.is_file()
    assert "INSERT INTO equipment" in onboard_sql
    assert "INSERT INTO network_devices" in onboard_sql
    assert "INSERT INTO ip_arp_entries" in onboard_sql

    # Verify generated SQL executes cleanly against the strict SQLite schema (with foreign keys enabled)
    seed_sql = SQL_SEED_PATH.read_text(encoding="utf-8")
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(seed_sql)
        conn.executescript(onboard_sql)
    finally:
        conn.close()

    # Verify SqlExportSoTClient can ingest combined SQL and that re-running reconciliation
    # on the untracked assets shows 0 untracked items!
    combined_sql = seed_sql_no_pragma + "\n" + onboard_sql
    updated_site = SqlExportSoTClient.from_sql_dump(combined_sql).get_site("site-042")
    followup_report = reconciler.reconcile(
        updated_site,
        vms=[
            HypervisorVmRecord(
                vcenter_instance="vcenter-prod-02",
                vm_moref="vm-20421",
                vm_name="win-app01.site042",
                guest_hostname="win-app01.site042.example.internal",
                bios_uuid="421a0042-0006-4000-8000-0050569a4216",
                power_state=VmPowerState.POWERED_ON,
                guest_os_family="windows",
                ip_addresses=["10.42.10.26"],
                mac_addresses=["00:50:56:9a:42:16"],
                site_id="site-042",
            )
        ],
        snmp_targets=[
            {
                "ip_address": "10.42.1.15",
                "sys_name": "sw03.site042.example.internal",
                "vendor": "Extreme Networks",
                "model": "ExtremeSwitching X440-G2",
                "role": "access-switch",
                "mac_address": "00:04:96:9a:bc:03",
                "snmp_reachable": True,
            }
        ],
        arp_entries=[
            ArpEntry(
                ip="10.42.20.88",
                arp_mac="00:a0:98:42:20:88",
                arp_source_device_id="dev-042-sw01",
            )
        ],
        generated_at=FIXED_TIME,
    )
    assert followup_report.total_discrepancies == 0


def test_onboarding_sql_escapes_single_quotes_and_supports_fixture_transport() -> None:
    site = _build_base_site()
    transport = FixtureManagementTransport.from_file(SNMP_FIXTURE_PATH)
    # Fixture targets dev-042-sw01 and eq-042-ups01 are both tracked in _build_base_site()
    report_clean = InventoryReconciler().reconcile(
        site, snmp_targets=transport, generated_at=FIXED_TIME
    )
    assert report_clean.total_discrepancies == 0

    # Test single-quote escaping in SQL generation
    manual_report = ReconciliationReport(
        discrepancies=[
            DiscrepancyRecord(
                discrepancy_id="disc-quote-01",
                discrepancy_type=DiscrepancyType.UNTRACKED_VM,
                site_id="site-042",
                observed_identifier="vm-9001",
                observed_ip="10.42.10.199",
                observed_mac="00:50:56:9a:42:c7",
                observed_hostname="o'reilly-vm.site042.example.internal",
                source="vcenter",
            )
        ],
        generated_at=FIXED_TIME,
    )
    sql_text = manual_report.generate_onboarding_sql()
    assert "'o''reilly-vm.site042.example.internal'" in sql_text
