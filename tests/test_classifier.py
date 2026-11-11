"""Unit and integration tests for ClassificationPolicy and ClassificationEngine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from sot_validator import (
    ArpEntry,
    ClassificationEngine,
    ClassificationPolicy,
    Equipment,
    EquipmentCategory,
    GuestToolsStatus,
    HypervisorVmRecord,
    IPAddress,
    IcmpProbeCollector,
    ManagementProbeCollector,
    MultiVCenterInventoryProvider,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
    VmPowerState,
    VmPowerStateCollector,
)
from sot_validator.classifier import (
    ClassificationEngine as ClassifierEngineExport,
    ClassificationPolicy as ClassifierPolicyExport,
    DEFAULT_SIGNAL_WEIGHTS,
)
from sot_validator.extraction import SqlExportSoTClient
from sot_validator.signals import IcmpProbeResponse, SECONDS_PER_DAY

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "sot_samples"
CSV_DIR = FIXTURES_DIR / "csv"
SQL_FILE = FIXTURES_DIR / "sql" / "sot_schema_and_seed.sql"
VCENTER_JSON = FIXTURES_DIR / "vcenter" / "vcenter_inventory.json"
SNMP_JSON = FIXTURES_DIR / "snmp" / "extreme_and_apc_walks.json"

FIXED_EVAL_TIME = datetime(2026, 11, 11, 8, 10, 0, tzinfo=timezone.utc)


def test_package_exports() -> None:
    assert ClassifierEngineExport is ClassificationEngine
    assert ClassifierPolicyExport is ClassificationPolicy
    assert set(DEFAULT_SIGNAL_WEIGHTS.keys()) == set(SignalType)


def test_classification_policy_defaults_and_validation() -> None:
    default_policy = ClassificationPolicy()
    assert default_policy.active_within_days == 7.0
    assert default_policy.stale_after_days == 30.0
    assert default_policy.windows_vm_ignore_icmp_unreachable is True
    assert default_policy.active_threshold_seconds == pytest.approx(7.0 * SECONDS_PER_DAY)
    assert default_policy.stale_threshold_seconds == pytest.approx(30.0 * SECONDS_PER_DAY)

    custom_policy = ClassificationPolicy(
        active_within_days=14,
        stale_after_days=60,
        windows_vm_ignore_icmp_unreachable=False,
        signal_weights={SignalType.VM_POWER_STATE: 0.5, "ARP_RECENCY": 0.4},  # type: ignore[dict-item]
    )
    assert custom_policy.active_within_days == 14.0
    assert custom_policy.stale_after_days == 60.0
    assert custom_policy.windows_vm_ignore_icmp_unreachable is False
    assert custom_policy.weight_for(SignalType.VM_POWER_STATE) == 0.5
    assert custom_policy.weight_for(SignalType.ARP_RECENCY) == 0.4

    with pytest.raises(ValueError, match="non-negative"):
        ClassificationPolicy(active_within_days=-1.0, stale_after_days=30.0)

    with pytest.raises(ValueError, match="non-negative"):
        ClassificationPolicy(active_within_days=7.0, stale_after_days=-5.0)

    with pytest.raises(ValueError, match="must not exceed"):
        ClassificationPolicy(active_within_days=45.0, stale_after_days=30.0)

    with pytest.raises(ValueError, match="non-negative number"):
        ClassificationPolicy(active_within_days=True, stale_after_days=30.0)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="non-negative number"):
        ClassificationPolicy(active_within_days=7.0, stale_after_days="30")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="boolean"):
        ClassificationPolicy(windows_vm_ignore_icmp_unreachable="yes")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="non-negative"):
        ClassificationPolicy(signal_weights={SignalType.ICMP_REACHABILITY: -0.1})

    with pytest.raises(ValueError, match="non-negative number"):
        ClassificationPolicy(signal_weights={SignalType.ICMP_REACHABILITY: True})  # type: ignore[dict-item]


def test_policy_threshold_overrides_shift_classifications() -> None:
    # A signal observed 12 days ago:
    # - With default policy (active<=7d, stale>30d): intermediate window -> Unreachable / Needs Manual Review
    # - With extended active policy (active<=14d, stale>30d): active -> Confirmed Active
    # - With aggressive stale policy (active<=3d, stale>10d): stale -> Stale / Likely Unused
    age_12d = 12.0 * SECONDS_PER_DAY
    obs_12d = FIXED_EVAL_TIME - timedelta(days=12)

    signals = [
        ValidationSignal(
            signal_type=SignalType.ARP_RECENCY,
            status=SignalStatus.INACTIVE,
            observed_at=obs_12d,
            age_seconds=age_12d,
            details="ARP observed 12 days ago",
        ),
        ValidationSignal(
            signal_type=SignalType.LAST_SEEN_TIMESTAMP,
            status=SignalStatus.INACTIVE,
            observed_at=obs_12d,
            age_seconds=age_12d,
            details="last_seen 12 days ago",
        ),
    ]

    default_engine = ClassificationEngine(evaluation_time=FIXED_EVAL_TIME)
    res_default = default_engine.classify_signals(
        signals,
        item_type="Equipment",
        item_id="eq-12d",
        site_id="site-042",
        name="srv-12d",
    )
    assert (
        res_default.classification
        is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
    )
    assert 0.20 <= res_default.confidence <= 0.75

    active_14d_engine = ClassificationEngine(
        policy=ClassificationPolicy(active_within_days=14.0, stale_after_days=30.0),
        evaluation_time=FIXED_EVAL_TIME,
    )
    res_active = active_14d_engine.classify_signals(
        signals,
        item_type="Equipment",
        item_id="eq-12d",
        site_id="site-042",
        name="srv-12d",
    )
    assert res_active.classification is ValidationClassification.CONFIRMED_ACTIVE
    assert res_active.confidence >= 0.80

    stale_10d_engine = ClassificationEngine(
        policy=ClassificationPolicy(active_within_days=3.0, stale_after_days=10.0),
        evaluation_time=FIXED_EVAL_TIME,
    )
    res_stale = stale_10d_engine.classify_signals(
        signals,
        item_type="Equipment",
        item_id="eq-12d",
        site_id="site-042",
        name="srv-12d",
    )
    assert res_stale.classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert res_stale.confidence >= 0.65


def test_windows_vm_powered_on_or_active_arp_overrides_icmp_unreachable() -> None:
    provider = MultiVCenterInventoryProvider.from_json_file(VCENTER_JSON)
    icmp_collector = IcmpProbeCollector(
        probe_fn=lambda ip, timeout: IcmpProbeResponse(
            reachable=False, detail="windows_defender_firewall_drop"
        )
    )
    mgmt_collector = ManagementProbeCollector()
    engine = ClassificationEngine(
        hypervisor_provider=provider,
        icmp_collector=icmp_collector,
        management_collector=mgmt_collector,
        evaluation_time=FIXED_EVAL_TIME,
    )

    # Case 1: Windows VM poweredOn with Guest Tools OK + recent ARP + ICMP UNREACHABLE
    eq_win_dc = Equipment(
        equipment_id="eq-042-vm-win01",
        site_id="site-042",
        name="win-dc01.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.21"],
        hypervisor_id="vcenter-prod-01.example.internal",
        last_seen="2026-11-11T07:58:00Z",
    )
    site = Site(
        site_id="site-042",
        name="Site 42",
        subnets=[
            Subnet(
                subnet_id="sub-042-010",
                site_id="site-042",
                cidr="10.42.10.0/24",
                vlan_id="10",
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.10.21",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-vm-win01",
                arp_mac="00:50:56:9a:42:11",
                arp_last_seen="2026-11-11T07:58:00Z",
            )
        ],
        equipment=[eq_win_dc],
    )

    result = engine.classify_equipment(eq_win_dc, site=site)
    assert isinstance(result, ValidationResult)
    assert result.classification is ValidationClassification.CONFIRMED_ACTIVE
    assert result.confidence >= 0.85
    assert result.rationale is not None and len(result.rationale) > 0
    assert "VM_POWER_STATE=ACTIVE" in result.rationale
    assert "ARP_RECENCY=ACTIVE" in result.rationale

    by_type = {s.signal_type: s.status for s in result.signals}
    assert by_type[SignalType.VM_POWER_STATE] is SignalStatus.ACTIVE
    assert by_type[SignalType.ARP_RECENCY] is SignalStatus.ACTIVE
    assert by_type[SignalType.ICMP_REACHABILITY] is SignalStatus.UNREACHABLE

    # Case 2: Windows VM with VM_POWER_STATE == ACTIVE alone + ICMP_REACHABILITY == UNREACHABLE
    res_vm_only = engine.classify_signals(
        [
            ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.ACTIVE,
                observed_at=FIXED_EVAL_TIME - timedelta(minutes=5),
                age_seconds=300.0,
                details="VM win-sql01 (vm-10424) on vcenter-prod-01 is POWERED_ON [os=windows]; Guest Tools heartbeat active (toolsOk, heartbeat=green; bonus confidence)",
            ),
            ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.UNREACHABLE,
                observed_at=FIXED_EVAL_TIME,
                age_seconds=0.0,
                details="ICMP unreachable (blocked by Windows Firewall)",
            ),
        ],
        item_type="Equipment",
        item_id="eq-042-vm-win04",
        site_id="site-042",
        name="win-sql01.site042.example.internal",
    )
    assert res_vm_only.classification is ValidationClassification.CONFIRMED_ACTIVE
    assert res_vm_only.confidence >= 0.85
    assert res_vm_only.rationale is not None
    assert "Windows VM rule" in res_vm_only.rationale

    # Case 3: Windows VM with ARP_RECENCY == ACTIVE + ICMP_REACHABILITY == UNREACHABLE
    res_arp_only = engine.classify_signals(
        [
            ValidationSignal(
                signal_type=SignalType.ARP_RECENCY,
                status=SignalStatus.ACTIVE,
                observed_at=FIXED_EVAL_TIME - timedelta(hours=2),
                age_seconds=7200.0,
                details="ARP for IP 10.42.10.25 is active",
            ),
            ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.UNREACHABLE,
                observed_at=FIXED_EVAL_TIME,
                age_seconds=0.0,
                details="ICMP timeout",
            ),
        ],
        item_type="Equipment",
        item_id="eq-042-vm-win05",
        site_id="site-042",
        name="win-wms01.site042.example.internal",
    )
    assert res_arp_only.classification is ValidationClassification.CONFIRMED_ACTIVE
    assert res_arp_only.confidence >= 0.85
    assert res_arp_only.rationale is not None

    # Case 4: vMotioned Windows VM across vCenters (poweredOff on vc01, poweredOn on vc02)
    old_vm = HypervisorVmRecord(
        vcenter_instance="vcenter-prod-01",
        vm_moref="vm-10900",
        bios_uuid="421a0042-0090-4000-8000-0050569a4290",
        vm_name="win-migrated01",
        guest_hostname="win-migrated01.site042.example.internal",
        guest_os_family="windows",
        power_state=VmPowerState.POWERED_OFF,
        guest_tools_status=GuestToolsStatus.TOOLS_NOT_RUNNING,
        tools_heartbeat="gray",
        last_updated="2026-11-01T00:00:00Z",
    )
    new_vm = HypervisorVmRecord(
        vcenter_instance="vcenter-prod-02",
        vm_moref="vm-20900",
        bios_uuid="421a0042-0090-4000-8000-0050569a4290",
        vm_name="win-migrated01",
        guest_hostname="win-migrated01.site042.example.internal",
        guest_os_family="windows",
        power_state=VmPowerState.POWERED_ON,
        guest_tools_status=GuestToolsStatus.TOOLS_OK,
        tools_heartbeat="green",
        icmp_blocked_by_host_firewall=True,
        last_updated="2026-11-11T08:05:00Z",
    )
    vmotion_engine = ClassificationEngine(
        hypervisor_provider=MultiVCenterInventoryProvider(vms=[old_vm, new_vm]),
        icmp_collector=icmp_collector,
        evaluation_time=FIXED_EVAL_TIME,
    )
    eq_migrated = Equipment(
        equipment_id="eq-042-vm-mig01",
        site_id="site-042",
        name="win-migrated01.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.90"],
        hypervisor_id="421a0042-0090-4000-8000-0050569a4290",
    )
    res_migrated = vmotion_engine.classify_equipment(eq_migrated, site=site)
    assert res_migrated.classification is ValidationClassification.CONFIRMED_ACTIVE
    assert res_migrated.confidence >= 0.85


def test_stale_likely_unused_classifications_across_entity_types() -> None:
    provider = MultiVCenterInventoryProvider.from_json_file(VCENTER_JSON)
    icmp_collector = IcmpProbeCollector(
        probe_fn=lambda ip, timeout: IcmpProbeResponse(reachable=False)
    )
    mgmt_collector = ManagementProbeCollector()
    engine = ClassificationEngine(
        hypervisor_provider=provider,
        icmp_collector=icmp_collector,
        management_collector=mgmt_collector,
        evaluation_time=FIXED_EVAL_TIME,
    )

    site = Site(
        site_id="site-042",
        name="Site 42",
        subnets=[
            Subnet(subnet_id="sub-042-001", site_id="site-042", cidr="10.42.1.0/24"),
            Subnet(subnet_id="sub-042-010", site_id="site-042", cidr="10.42.10.0/24"),
            Subnet(subnet_id="sub-042-030", site_id="site-042", cidr="10.42.30.0/24"),
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.1.11",
                subnet_id="sub-042-001",
                assigned_object_type="network_device",
                assigned_object_id="dev-042-sw02",
                arp_mac="00:04:96:9a:bc:02",
                arp_last_seen="2026-08-01T12:00:00Z",
            ),
            IPAddress(
                ip="10.42.10.99",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-srv-legacy01",
                arp_mac="00:1b:21:42:10:99",
                arp_last_seen="2026-06-15T17:59:00Z",
            ),
            IPAddress(
                ip="10.42.10.22",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-vm-win02",
                arp_mac="00:50:56:9a:42:12",
                arp_last_seen="2026-07-10T04:15:00Z",
            ),
            IPAddress(
                ip="10.42.30.99",
                subnet_id="sub-042-030",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-ups-old",
                arp_mac="00:c0:b7:42:30:99",
                arp_last_seen="2026-05-01T00:00:00Z",
            ),
        ],
    )

    # 1. Stale Extreme Networks switch (dev-042-sw02)
    stale_sw = NetworkDevice(
        device_id="dev-042-sw02",
        site_id="site-042",
        hostname="sw02.site042.example.internal",
        management_ip="10.42.1.11",
        vendor="Extreme Networks",
        last_seen="2026-08-01T12:00:00Z",
        ports=[
            Port(
                port_id="port-sw02-1",
                device_id="dev-042-sw02",
                name="1:1",
                admin_status="up",
                oper_status="down",
            )
        ],
    )
    res_sw = engine.classify_device(stale_sw, site=site)
    assert res_sw.classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert res_sw.item_type == "NetworkDevice"
    assert res_sw.confidence >= 0.75
    assert res_sw.rationale is not None and "Stale / Likely Unused" in res_sw.rationale

    # 2. Stale /24 IPAddress
    res_ip = engine.classify_ip(site.ip_addresses[1], site=site)
    assert res_ip.classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert res_ip.item_type == "IPAddress"
    assert res_ip.site_id == "site-042"
    assert res_ip.confidence >= 0.65

    # 3. Stale physical server (port down, ARP > 140d old, ICMP/SNMP unreachable)
    stale_srv = Equipment(
        equipment_id="eq-042-srv-legacy01",
        site_id="site-042",
        name="srv-legacy01.site042.example.internal",
        category=EquipmentCategory.SERVER,
        assigned_ips=["10.42.10.99"],
        connected_ports=["port-sw02-1"],
        last_seen="2026-06-15T18:00:00Z",
    )
    res_srv = engine.classify_equipment(
        stale_srv, site=site, ports=stale_sw.ports
    )
    assert res_srv.classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert res_srv.confidence >= 0.80

    # 4. Stale APC UPS unit
    stale_ups = Equipment(
        equipment_id="eq-042-ups-old",
        site_id="site-042",
        name="ups-old.site042.example.internal",
        category=EquipmentCategory.UPS,
        assigned_ips=["10.42.30.99"],
        last_seen="2026-05-01T00:00:00Z",
    )
    res_ups = engine.classify_equipment(stale_ups, site=site)
    assert res_ups.classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert res_ups.confidence >= 0.70

    # 5. Powered-off Windows VM (even when shared ESXi host uplink port is UP)
    shared_trunk_port = Port(
        port_id="port-042-sw01-1",
        device_id="dev-042-sw01",
        name="1:1",
        admin_status="up",
        oper_status="up",
        connected_device_id="eq-042-esx01",
        connected_mac="00:50:56:60:42:01",
    )
    stale_vm = Equipment(
        equipment_id="eq-042-vm-win02",
        site_id="site-042",
        name="win-print02.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.22"],
        connected_ports=["port-042-sw01-1"],
        hypervisor_id="vcenter-prod-01.example.internal",
        last_seen="2026-07-10T04:15:00Z",
    )
    res_vm = engine.classify_equipment(
        stale_vm, site=site, ports=[shared_trunk_port]
    )
    assert res_vm.classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert res_vm.confidence >= 0.80

    # 6. Orphaned VM missing across all reachable vCenters
    orphan_vm = Equipment(
        equipment_id="eq-042-vm-orphan",
        site_id="site-042",
        name="win-orphan99.site042.example.internal",
        category=EquipmentCategory.VM,
        hypervisor_id="421a0042-9999-4000-8000-0050569a9999",
        last_seen="2026-04-01T00:00:00Z",
    )
    res_orphan = engine.classify_equipment(orphan_vm, site=site)
    assert res_orphan.classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert res_orphan.confidence >= 0.75


def test_unreachable_conflict_and_error_classifications() -> None:
    engine = ClassificationEngine(evaluation_time=FIXED_EVAL_TIME)

    # 1. Conflict: Switch port link UP + PoE delivering power while ICMP/SNMP UNREACHABLE and ARP stale
    res_poe_conflict = engine.classify_signals(
        [
            ValidationSignal(
                signal_type=SignalType.PORT_STATE,
                status=SignalStatus.ACTIVE,
                observed_at=FIXED_EVAL_TIME,
                details="Port dev-042-sw01:1:5 -> ACTIVE (link UP and PoE delivering power)",
            ),
            ValidationSignal(
                signal_type=SignalType.ARP_RECENCY,
                status=SignalStatus.INACTIVE,
                observed_at=FIXED_EVAL_TIME - timedelta(days=52),
                age_seconds=52 * SECONDS_PER_DAY,
                details="ARP is stale (52d > 30d)",
            ),
            ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.UNREACHABLE,
                observed_at=FIXED_EVAL_TIME,
                age_seconds=0.0,
                details="ICMP timeout",
            ),
            ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.UNREACHABLE,
                observed_at=FIXED_EVAL_TIME,
                age_seconds=0.0,
                details="SNMP timeout",
            ),
        ],
        item_type="Equipment",
        item_id="eq-042-nas-sec01",
        site_id="site-042",
        name="nas-sec01.site042.example.internal",
    )
    assert (
        res_poe_conflict.classification
        is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
    )
    assert 0.20 <= res_poe_conflict.confidence <= 0.75
    assert res_poe_conflict.rationale is not None
    assert "conflicting signals" in res_poe_conflict.rationale.lower()

    # 2. Unreachable vCenter hypervisor for a VM while probes fail
    res_vc_unreachable = engine.classify_signals(
        [
            ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.UNREACHABLE,
                details="vCenter instance 'vcenter-prod-02' is unreachable",
            ),
            ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.UNREACHABLE,
                details="ICMP timeout",
            ),
        ],
        item_type="Equipment",
        item_id="eq-042-vm-win06",
        site_id="site-042",
        name="win-app01.site042.example.internal",
    )
    assert (
        res_vc_unreachable.classification
        is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
    )
    assert 0.20 <= res_vc_unreachable.confidence <= 0.75
    assert res_vc_unreachable.rationale is not None
    assert "vcenter" in res_vc_unreachable.rationale.lower()

    # 3. Probe / signal evaluation ERROR without an ACTIVE signal
    res_error = engine.classify_signals(
        [
            ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.ERROR,
                details="Scope guard rejected IP",
            ),
            ValidationSignal(
                signal_type=SignalType.ARP_RECENCY,
                status=SignalStatus.NOT_APPLICABLE,
                details="No ARP entry",
            ),
        ],
        item_type="Equipment",
        item_id="eq-err01",
        site_id="site-042",
        name="srv-err01",
    )
    assert (
        res_error.classification
        is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
    )
    assert 0.20 <= res_error.confidence <= 0.75
    assert res_error.rationale is not None
    assert "error" in res_error.rationale.lower()

    # 4. Point-in-time probe UNREACHABLE with no historical ARP/port/last-seen evidence
    res_probe_only = engine.classify_signals(
        [
            ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.UNREACHABLE,
                details="ICMP timeout",
            ),
            ValidationSignal(
                signal_type=SignalType.ARP_RECENCY,
                status=SignalStatus.NOT_APPLICABLE,
                details="No ARP timestamp",
            ),
        ],
        item_type="IPAddress",
        item_id="10.42.10.200",
        site_id="site-042",
        name="10.42.10.200",
    )
    assert (
        res_probe_only.classification
        is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
    )


def test_insufficient_data_classification() -> None:
    engine = ClassificationEngine(evaluation_time=FIXED_EVAL_TIME)

    # 1. Untracked Equipment with no IPs, no ports, no VM hints, no last_seen
    untracked_eq = Equipment(
        equipment_id="eq-042-untracked01",
        site_id="site-042",
        name="spare-appliance-closetb",
        category=EquipmentCategory.SERVER,
    )
    res_eq = engine.classify_equipment(untracked_eq)
    assert res_eq.classification is ValidationClassification.INSUFFICIENT_DATA
    assert res_eq.confidence == 0.0
    assert res_eq.rationale is not None and "Insufficient Data" in res_eq.rationale

    # 2. Unmanaged NetworkDevice with no management_ip, no ports, no last_seen
    untracked_dev = NetworkDevice(
        device_id="dev-042-spare",
        site_id="site-042",
        hostname="spare-switch-closetb",
    )
    res_dev = engine.classify_device(untracked_dev)
    assert res_dev.classification is ValidationClassification.INSUFFICIENT_DATA
    assert res_dev.confidence == 0.0

    # 3. IPAddress with no ARP timestamp and no active probe collectors configured
    ip_no_arp = IPAddress(ip="10.42.10.250", subnet_id="sub-042-010")
    res_ip = engine.classify_ip(ip_no_arp)
    assert res_ip.classification is ValidationClassification.INSUFFICIENT_DATA
    assert res_ip.confidence == 0.0
    assert res_ip.site_id == "sub-042-010"

    # 4. Empty signal list and all-NOT_APPLICABLE signal list
    res_empty = engine.classify_signals(
        [], item_type="Equipment", item_id="eq-empty", site_id="site-042"
    )
    assert res_empty.classification is ValidationClassification.INSUFFICIENT_DATA
    assert res_empty.confidence == 0.0

    res_na = engine.classify_signals(
        [
            ValidationSignal(
                signal_type=SignalType.ARP_RECENCY,
                status=SignalStatus.NOT_APPLICABLE,
            ),
            ValidationSignal(
                signal_type=SignalType.PORT_STATE,
                status=SignalStatus.NOT_APPLICABLE,
            ),
        ],
        item_type="Equipment",
        item_id="eq-na",
        site_id="site-042",
    )
    assert res_na.classification is ValidationClassification.INSUFFICIENT_DATA
    assert res_na.confidence == 0.0


def test_site_042_end_to_end_fixture_classification() -> None:
    sot_client = SqlExportSoTClient.from_csv_dir(CSV_DIR)
    site_042 = sot_client.get_site("site-042")

    vcenter_provider = MultiVCenterInventoryProvider.from_json_file(VCENTER_JSON)
    icmp_collector = IcmpProbeCollector.from_fixture_file(SNMP_JSON)
    mgmt_collector = ManagementProbeCollector.from_fixture_file(SNMP_JSON)

    engine = ClassificationEngine(
        hypervisor_provider=vcenter_provider,
        icmp_collector=icmp_collector,
        management_collector=mgmt_collector,
        evaluation_time=FIXED_EVAL_TIME,
    )

    results = engine.classify_site(site_042, include_ip_addresses=True)
    by_id = {r.item_id: r for r in results}

    expected_classifications = {
        "dev-042-sw01": ValidationClassification.CONFIRMED_ACTIVE,
        "dev-042-sw02": ValidationClassification.STALE_LIKELY_UNUSED,
        "eq-042-esx01": ValidationClassification.CONFIRMED_ACTIVE,
        "eq-042-vm-win01": ValidationClassification.CONFIRMED_ACTIVE,
        "eq-042-vm-win02": ValidationClassification.STALE_LIKELY_UNUSED,
        "eq-042-srv-legacy01": ValidationClassification.STALE_LIKELY_UNUSED,
        "eq-042-san01": ValidationClassification.CONFIRMED_ACTIVE,
        "eq-042-nas-sec01": ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
        "eq-042-ups01": ValidationClassification.CONFIRMED_ACTIVE,
        "eq-042-untracked01": ValidationClassification.INSUFFICIENT_DATA,
    }

    for item_id, expected_class in expected_classifications.items():
        assert item_id in by_id, f"Missing classification result for {item_id}"
        res = by_id[item_id]
        assert res.classification is expected_class, (
            f"Expected {item_id} to be {expected_class.value}, got "
            f"{res.classification.value} (rationale: {res.rationale})"
        )
        assert res.site_id == "site-042"
        assert res.evaluated_at == FIXED_EVAL_TIME
        assert res.rationale is not None and len(res.rationale) > 0

    assert by_id["eq-042-vm-win01"].confidence >= 0.85
    assert by_id["eq-042-ups01"].confidence >= 0.90
    assert by_id["dev-042-sw01"].confidence >= 0.90
    assert by_id["eq-042-untracked01"].confidence == 0.0
    assert 0.20 <= by_id["eq-042-nas-sec01"].confidence <= 0.75
    assert by_id["eq-042-vm-win02"].confidence >= 0.80
    assert by_id["eq-042-srv-legacy01"].confidence >= 0.80

    # Verify SQL seed ingestion produces identical classifications
    sql_text = "\n".join(
        line
        for line in SQL_FILE.read_text(encoding="utf-8").splitlines()
        if not line.strip().upper().startswith("PRAGMA")
    )
    sql_site_042 = SqlExportSoTClient.from_sql_dump(sql_text).get_site("site-042")
    sql_results = {
        r.item_id: r.classification
        for r in engine.classify_site(sql_site_042, include_ip_addresses=False)
    }
    assert sql_results == expected_classifications

    # Verify ValidationResult JSON/dict round-trip serialization
    for res in results:
        restored = ValidationResult.from_json(res.to_json())
        assert restored.item_id == res.item_id
        assert restored.classification is res.classification
        assert restored.confidence == pytest.approx(res.confidence)
