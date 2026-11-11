"""Unit tests for multi-vCenter VM correlation and VmPowerStateCollector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from sot_validator import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    GuestToolsStatus,
    HypervisorInventoryProvider,
    HypervisorVmRecord,
    IPAddress,
    MultiVCenterInventoryProvider,
    NetworkDevice,
    Port,
    SignalCollector,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
    VmNicBinding,
    VmPowerState,
    VmPowerStateCollector,
)
from sot_validator.signals import (
    SECONDS_PER_DAY,
    normalize_guest_tools_status,
    normalize_vm_power_state,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "sot_samples"
    / "vcenter"
    / "vcenter_inventory.json"
)

FIXED_EVAL_TIME = datetime(2026, 11, 11, 8, 10, 0, tzinfo=timezone.utc)


def test_exports_and_enum_normalization() -> None:
    assert issubclass(MultiVCenterInventoryProvider, HypervisorInventoryProvider)
    assert issubclass(VmPowerStateCollector, SignalCollector)

    assert normalize_vm_power_state("poweredOn") is VmPowerState.POWERED_ON
    assert normalize_vm_power_state("POWERED_ON") is VmPowerState.POWERED_ON
    assert normalize_vm_power_state("powered_on") is VmPowerState.POWERED_ON
    assert normalize_vm_power_state("on") is VmPowerState.POWERED_ON
    assert normalize_vm_power_state("poweredOff") is VmPowerState.POWERED_OFF
    assert normalize_vm_power_state("POWERED_OFF") is VmPowerState.POWERED_OFF
    assert normalize_vm_power_state("powered_off") is VmPowerState.POWERED_OFF
    assert normalize_vm_power_state("off") is VmPowerState.POWERED_OFF
    assert normalize_vm_power_state("suspended") is VmPowerState.SUSPENDED
    assert normalize_vm_power_state("SUSPENDED") is VmPowerState.SUSPENDED

    with pytest.raises(ValueError, match="Unsupported VM power state"):
        normalize_vm_power_state("migrating")

    assert normalize_guest_tools_status("toolsOk") is GuestToolsStatus.TOOLS_OK
    assert normalize_guest_tools_status("toolsOld") is GuestToolsStatus.TOOLS_OLD
    assert (
        normalize_guest_tools_status("toolsNotRunning")
        is GuestToolsStatus.TOOLS_NOT_RUNNING
    )
    assert (
        normalize_guest_tools_status("toolsNotInstalled")
        is GuestToolsStatus.TOOLS_NOT_INSTALLED
    )
    assert normalize_guest_tools_status(None) is None
    assert normalize_guest_tools_status("") is None


def test_load_vcenter_fixture_and_lookup_methods() -> None:
    provider = MultiVCenterInventoryProvider.from_json_file(FIXTURE_PATH)
    vms = provider.list_vms()

    # 10 VMs across 2 vCenter instances (9 Windows, 1 Linux)
    assert len(vms) == 10
    assert provider.configured_instances() == {"vcenter-prod-01", "vcenter-prod-02"}
    assert provider.unreachable_instances() == set()
    assert provider.is_instance_reachable("vcenter-prod-01")
    assert provider.is_instance_reachable("vcenter-prod-01.example.internal")
    assert provider.is_instance_reachable("vcenter-prod-02")

    windows_vms = [vm for vm in vms if vm.is_windows]
    linux_vms = [vm for vm in vms if vm.guest_os_family == "linux"]
    assert len(windows_vms) == 9
    assert len(linux_vms) == 1

    # 1. Lookup by BIOS UUID (case-insensitive)
    uuid_matches = provider.find_by_uuid("421A0042-0001-4000-8000-0050569A4211")
    assert len(uuid_matches) == 1
    assert uuid_matches[0].vm_name == "win-dc01.site042"
    assert uuid_matches[0].vcenter_instance == "vcenter-prod-01"
    assert uuid_matches[0].power_state is VmPowerState.POWERED_ON

    # 2. Lookup by (vcenter_instance, vm_moref) including FQDN vcenter_host
    moref_matches = provider.find_by_moref(
        "vm-20421", vcenter_instance="vcenter-prod-02.example.internal"
    )
    assert len(moref_matches) == 1
    assert moref_matches[0].vm_name == "win-app01.site042"

    # Lookup by vm_moref with wrong vCenter instance returns empty
    assert (
        provider.find_by_moref("vm-20421", vcenter_instance="vcenter-prod-01") == []
    )

    # 3. Lookup by MAC or IP address (handling separator/case normalization)
    mac_matches = provider.find_by_mac_or_ip(mac_addresses=["00-50-56-9A-42-16"])
    assert len(mac_matches) == 1
    assert mac_matches[0].vm_moref == "vm-20421"

    ip_matches = provider.find_by_mac_or_ip(ip_addresses=["10.42.10.30"])
    assert len(ip_matches) == 1
    assert ip_matches[0].vm_name == "lnx-syslog01.site042"

    # 4. Lookup by guest_hostname or vm_name (FQDN and short hostname)
    host_matches = provider.find_by_hostname("win-sql01.site042.example.internal")
    assert len(host_matches) == 1
    assert host_matches[0].vm_moref == "vm-10424"

    short_matches = provider.find_by_hostname("win-sql01", site_id="site-042")
    assert len(short_matches) == 1
    assert short_matches[0].vm_moref == "vm-10424"


def test_correlation_priority_order_uuid_moref_mac_ip_hostname() -> None:
    provider = MultiVCenterInventoryProvider.from_json_file(FIXTURE_PATH)

    # Priority 1: BIOS UUID beats conflicting MoRef, IP, and hostname
    eq_uuid_first = Equipment(
        equipment_id="eq-042-vm-win01",
        site_id="site-042",
        name="win-rds01.site042.example.internal",  # belongs to vm-20422
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.28"],  # belongs to vm-20423
        hypervisor_id="421a0042-0001-4000-8000-0050569a4211",  # belongs to vm-10421
    )
    matched, method = provider.correlate_vms(
        eq_uuid_first,
        vcenter_instance="vcenter-prod-02",
        vm_moref="vm-20421",
    )
    assert method == "bios_uuid"
    assert len(matched) == 1
    assert matched[0].vm_moref == "vm-10421"

    # Priority 2: (vcenter_instance, vm_moref) beats conflicting IP and hostname
    eq_moref_second = Equipment(
        equipment_id="eq-042-vm-win06",
        site_id="site-042",
        name="win-dc01.site042.example.internal",  # belongs to vm-10421
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.21"],  # belongs to vm-10421
        hypervisor_id="vcenter-prod-02:vm-20421",
    )
    matched, method = provider.correlate_vms(eq_moref_second)
    assert method == "vm_moref"
    assert len(matched) == 1
    assert matched[0].vm_moref == "vm-20421"
    assert matched[0].vcenter_instance == "vcenter-prod-02"

    # Priority 3: MAC/IP beats conflicting hostname when UUID and MoRef don't match
    eq_mac_ip_third = Equipment(
        equipment_id="eq-042-vm-win07",
        site_id="site-042",
        name="stale-dns-alias.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.27"],  # belongs to vm-20422 (win-rds01)
    )
    matched, method = provider.correlate_vms(eq_mac_ip_third)
    assert method == "mac_or_ip"
    assert len(matched) == 1
    assert matched[0].vm_moref == "vm-20422"

    # Priority 4: Hostname fallback when UUID, MoRef, and IP are absent/changed
    eq_hostname_fourth = Equipment(
        equipment_id="eq-042-vm-win09",
        site_id="site-042",
        name="win-wsus01.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.250"],  # outdated IP in SoT
    )
    matched, method = provider.correlate_vms(eq_hostname_fourth)
    assert method == "hostname"
    assert len(matched) == 1
    assert matched[0].vm_moref == "vm-20424"


def test_windows_powered_on_vm_with_icmp_blocked_and_guest_tools_ok() -> None:
    provider = MultiVCenterInventoryProvider.from_json_file(FIXTURE_PATH)
    collector = VmPowerStateCollector(
        provider=provider,
        evaluation_time=FIXED_EVAL_TIME,
    )

    # Windows VM win-dc01 on vcenter-prod-01: poweredOn, toolsOk, green heartbeat, ICMP blocked
    eq_win_dc = Equipment(
        equipment_id="eq-042-vm-win01",
        site_id="site-042",
        name="win-dc01.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.21"],
        hypervisor_id="vcenter-prod-01.example.internal",
    )

    sig = collector.evaluate(
        eq_win_dc,
        bios_uuid="421a0042-0001-4000-8000-0050569a4211",
        vm_moref="vm-10421",
    )
    assert isinstance(sig, ValidationSignal)
    assert sig.signal_type is SignalType.VM_POWER_STATE
    assert sig.status is SignalStatus.ACTIVE
    assert sig.observed_at == datetime(2026, 11, 11, 8, 4, 30, tzinfo=timezone.utc)
    assert sig.age_seconds == pytest.approx(330.0)
    assert sig.details is not None
    assert "vcenter-prod-01" in sig.details
    assert "POWERED_ON" in sig.details
    assert "windows" in sig.details.lower()
    assert "toolsOk" in sig.details
    assert "green" in sig.details
    assert "bonus confidence" in sig.details
    assert "firewall" in sig.details.lower()

    # Windows VM on second vCenter instance (vcenter-prod-02) correlated via IP/ARP
    eq_win_app = Equipment(
        equipment_id="eq-042-vm-win06",
        site_id="site-042",
        name="win-app01.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.26"],
    )
    sig_app = collector.evaluate(eq_win_app)
    assert sig_app.status is SignalStatus.ACTIVE
    assert sig_app.details is not None
    assert "vcenter-prod-02" in sig_app.details
    assert "vm-20421" in sig_app.details
    assert "mac_or_ip" in sig_app.details


def test_multi_vcenter_vmotion_migration_prefers_powered_on_instance() -> None:
    # Simulate a VM migrated from vcenter-prod-01 (left poweredOff) to vcenter-prod-02 (poweredOn)
    old_copy = HypervisorVmRecord(
        vcenter_instance="vcenter-prod-01",
        vm_moref="vm-10999",
        bios_uuid="421a0042-0099-4000-8000-0050569a4299",
        vm_name="win-erp01.site042",
        guest_hostname="win-erp01.site042.example.internal",
        guest_os_family="windows",
        power_state=VmPowerState.POWERED_OFF,
        guest_tools_status=GuestToolsStatus.TOOLS_NOT_RUNNING,
        tools_heartbeat="gray",
        last_updated="2026-11-01T00:00:00Z",
    )
    active_copy = HypervisorVmRecord(
        vcenter_instance="vcenter-prod-02",
        vm_moref="vm-20999",
        bios_uuid="421a0042-0099-4000-8000-0050569a4299",
        vm_name="win-erp01.site042",
        guest_hostname="win-erp01.site042.example.internal",
        guest_os_family="windows",
        power_state=VmPowerState.POWERED_ON,
        guest_tools_status=GuestToolsStatus.TOOLS_OK,
        tools_heartbeat="green",
        icmp_blocked_by_host_firewall=True,
        last_updated="2026-11-11T08:05:00Z",
    )
    provider = MultiVCenterInventoryProvider(vms=[old_copy, active_copy])
    collector = VmPowerStateCollector(provider=provider, evaluation_time=FIXED_EVAL_TIME)

    eq = Equipment(
        equipment_id="eq-042-vm-erp01",
        site_id="site-042",
        name="win-erp01.site042.example.internal",
        category=EquipmentCategory.VM,
        # SoT still points to vcenter-prod-01, but UUID correlates across both vCenters
        hypervisor_id="421a0042-0099-4000-8000-0050569a4299",
    )
    sig = collector.evaluate(eq)
    assert sig.status is SignalStatus.ACTIVE
    assert sig.details is not None
    assert "vcenter-prod-02" in sig.details
    assert "multi-vCenter matches" in sig.details


def test_powered_off_suspended_and_orphaned_vms_emit_inactive() -> None:
    provider = MultiVCenterInventoryProvider.from_json_file(FIXTURE_PATH)
    collector = VmPowerStateCollector(
        provider=provider,
        inactive_threshold_days=30.0,
        evaluation_time=FIXED_EVAL_TIME,
    )

    # 1. Powered-off VM from fixture (win-print02 on vcenter-prod-01)
    eq_off = Equipment(
        equipment_id="eq-042-vm-win02",
        site_id="site-042",
        name="win-print02.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.22"],
        hypervisor_id="421a0042-0002-4000-8000-0050569a4212",
    )
    sig_off = collector.evaluate(eq_off)
    assert sig_off.signal_type is SignalType.VM_POWER_STATE
    assert sig_off.status is SignalStatus.INACTIVE
    assert sig_off.details is not None
    assert "POWERED_OFF" in sig_off.details
    assert "toolsNotRunning" in sig_off.details

    # 2. Suspended VM powered off/suspended beyond threshold (45 days > 30 days)
    suspended_vm = HypervisorVmRecord(
        vcenter_instance="vcenter-prod-02",
        vm_moref="vm-20888",
        bios_uuid="421a0042-0088-4000-8000-0050569a4288",
        vm_name="win-legacy-test01",
        guest_hostname="win-legacy-test01.site042.example.internal",
        guest_os_family="windows",
        power_state="suspended",
        guest_tools_status="toolsNotRunning",
        tools_heartbeat="gray",
        last_updated=FIXED_EVAL_TIME - timedelta(days=1),
        power_state_changed_at=FIXED_EVAL_TIME - timedelta(days=45),
    )
    custom_provider = MultiVCenterInventoryProvider(
        vms=[*provider.list_vms(), suspended_vm]
    )
    eq_susp = Equipment(
        equipment_id="eq-042-vm-susp01",
        site_id="site-042",
        name="win-legacy-test01.site042.example.internal",
        category=EquipmentCategory.VM,
        hypervisor_id="vcenter-prod-02:vm-20888",
    )
    sig_susp = collector.evaluate(eq_susp, provider=custom_provider)
    assert sig_susp.status is SignalStatus.INACTIVE
    assert sig_susp.details is not None
    assert "SUSPENDED" in sig_susp.details
    assert "> threshold 30d" in sig_susp.details

    # 3. Orphaned / decommissioned VM in SoT missing from all reachable vCenter instances
    eq_orphan = Equipment(
        equipment_id="eq-042-vm-orphan99",
        site_id="site-042",
        name="win-decomm99.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.199"],
        hypervisor_id="421a0042-9999-4000-8000-0050569a9999",
    )
    sig_orphan = collector.evaluate(eq_orphan)
    assert sig_orphan.status is SignalStatus.INACTIVE
    assert sig_orphan.details is not None
    assert "orphaned/missing" in sig_orphan.details
    assert "vcenter-prod-01" in sig_orphan.details
    assert "vcenter-prod-02" in sig_orphan.details


def test_unreachable_vcenter_instance_emits_unreachable() -> None:
    fixture_provider = MultiVCenterInventoryProvider.from_json_file(FIXTURE_PATH)
    vcenter1_vms = [
        vm
        for vm in fixture_provider.list_vms()
        if vm.vcenter_instance == "vcenter-prod-01"
    ]

    # Case 1: Adapter for vcenter-prod-02 fails with connection timeout
    def _failing_vcenter2_adapter() -> list[HypervisorVmRecord]:
        raise TimeoutError("Connection to vcenter-prod-02.example.internal timed out")

    partial_provider = MultiVCenterInventoryProvider(
        vms=vcenter1_vms,
        adapters={"vcenter-prod-02": _failing_vcenter2_adapter},
    )
    assert "vcenter-prod-02" in partial_provider.unreachable_instances()
    assert not partial_provider.is_instance_reachable("vcenter-prod-02")
    assert partial_provider.is_instance_reachable("vcenter-prod-01")
    assert "timed out" in partial_provider.adapter_errors["vcenter-prod-02"]

    collector = VmPowerStateCollector(
        provider=partial_provider,
        evaluation_time=FIXED_EVAL_TIME,
    )

    # A VM on reachable vcenter-prod-01 still resolves as ACTIVE
    eq_on_vc1 = Equipment(
        equipment_id="eq-042-vm-win01",
        site_id="site-042",
        name="win-dc01.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.21"],
    )
    assert collector.evaluate(eq_on_vc1).status is SignalStatus.ACTIVE

    # A VM pinned to unreachable vcenter-prod-02 resolves as UNREACHABLE (not INACTIVE)
    eq_on_vc2 = Equipment(
        equipment_id="eq-042-vm-win06",
        site_id="site-042",
        name="win-app01.site042.example.internal",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.26"],
        hypervisor_id="vcenter-prod-02.example.internal",
    )
    sig_vc2 = collector.evaluate(eq_on_vc2)
    assert sig_vc2.status is SignalStatus.UNREACHABLE
    assert sig_vc2.details is not None
    assert "vcenter-prod-02" in sig_vc2.details
    assert "unreachable" in sig_vc2.details.lower()

    # An unpinned VM not found in vcenter-prod-01 while vcenter-prod-02 is unreachable -> UNREACHABLE
    eq_unpinned = Equipment(
        equipment_id="eq-042-vm-unknown",
        site_id="site-042",
        name="win-rds01.site042.example.internal",
        category=EquipmentCategory.VM,
    )
    sig_unpinned = collector.evaluate(eq_unpinned)
    assert sig_unpinned.status is SignalStatus.UNREACHABLE

    # Case 2: No provider supplied at all for a VM -> UNREACHABLE
    collector_no_provider = VmPowerStateCollector(evaluation_time=FIXED_EVAL_TIME)
    sig_no_prov = collector_no_provider.evaluate(eq_on_vc1)
    assert sig_no_prov.status is SignalStatus.UNREACHABLE


def test_physical_hardware_emits_not_applicable() -> None:
    provider = MultiVCenterInventoryProvider.from_json_file(FIXTURE_PATH)
    collector = VmPowerStateCollector(
        provider=provider,
        evaluation_time=FIXED_EVAL_TIME,
    )

    # Physical Dell ESXi Server
    eq_server = Equipment(
        equipment_id="eq-042-esx01",
        site_id="site-042",
        name="esx01.site042.example.internal",
        category=EquipmentCategory.SERVER,
        assigned_ips=["10.42.1.20"],
        connected_ports=["port-042-sw01-1"],
    )
    sig_srv = collector.evaluate(eq_server)
    assert sig_srv.signal_type is SignalType.VM_POWER_STATE
    assert sig_srv.status is SignalStatus.NOT_APPLICABLE
    assert sig_srv.details is not None
    assert "physical" in sig_srv.details.lower()

    # Physical NetApp SAN
    eq_san = Equipment(
        equipment_id="eq-042-san01",
        site_id="site-042",
        name="san01.site042.example.internal",
        category=EquipmentCategory.SAN,
        assigned_ips=["10.42.20.15"],
    )
    assert collector.evaluate(eq_san).status is SignalStatus.NOT_APPLICABLE

    # Physical APC UPS
    eq_ups = Equipment(
        equipment_id="eq-042-ups01",
        site_id="site-042",
        name="ups01.site042.example.internal",
        category=EquipmentCategory.UPS,
        assigned_ips=["10.42.30.10"],
    )
    assert collector.evaluate(eq_ups).status is SignalStatus.NOT_APPLICABLE

    # Physical NetworkDevice and Port
    dev = NetworkDevice(
        device_id="dev-042-sw01",
        site_id="site-042",
        hostname="sw01.site042.example.internal",
        management_ip="10.42.1.10",
    )
    port = Port(
        port_id="port-042-sw01-1",
        device_id="dev-042-sw01",
        name="1:1",
    )
    assert collector.evaluate(dev).status is SignalStatus.NOT_APPLICABLE
    assert collector.evaluate(port).status is SignalStatus.NOT_APPLICABLE


def test_csv_rvtools_ingestion_and_readonly_guardrail(tmp_path: Path) -> None:
    csv_file = tmp_path / "rvtools_vinfo.csv"
    csv_file.write_text(
        "VI SDK Server,VM ID,UUID,VM,DNS Name,Powerstate,Tools,Heartbeat,OS according to the configuration file,Primary IP Address,Mac Address,Datacenter\n"
        "vcenter-prod-01,vm-501,421a0042-0501-4000-8000-0050569a0501,win-iis01,win-iis01.site042.example.internal,poweredOn,toolsOk,green,Microsoft Windows Server 2022 (64-bit),10.42.10.51,00:50:56:9a:05:01,site-042\n"
        "vcenter-prod-02,vm-502,421a0042-0502-4000-8000-0050569a0502,win-iis02,win-iis02.site042.example.internal,poweredOff,toolsNotRunning,gray,Microsoft Windows Server 2019 (64-bit),10.42.10.52,00:50:56:9a:05:02,site-042\n",
        encoding="utf-8",
    )

    provider = MultiVCenterInventoryProvider.from_csv_file(csv_file)
    assert len(provider.list_vms()) == 2
    assert provider.configured_instances() == {"vcenter-prod-01", "vcenter-prod-02"}

    vm1 = provider.find_by_uuid("421a0042-0501-4000-8000-0050569a0501")[0]
    assert vm1.is_windows
    assert vm1.power_state is VmPowerState.POWERED_ON
    assert vm1.guest_tools_status is GuestToolsStatus.TOOLS_OK
    assert vm1.ip_addresses == ["10.42.10.51"]
    assert vm1.mac_addresses == ["00:50:56:9a:05:01"]

    # Round-trip serialization
    restored = HypervisorVmRecord.from_dict(vm1.to_dict())
    assert restored.bios_uuid == vm1.bios_uuid
    assert restored.power_state is VmPowerState.POWERED_ON
    assert restored.guest_tools_status is GuestToolsStatus.TOOLS_OK

    # Read-only guardrail: reject non-readonly vCenter instance configuration
    with pytest.raises(ValueError, match="read-only"):
        MultiVCenterInventoryProvider(
            instances=[
                {
                    "vcenter_instance": "vcenter-prod-01",
                    "api_mode": "readwrite",
                }
            ]
        )


def test_site_and_arp_context_mac_correlation() -> None:
    provider = MultiVCenterInventoryProvider.from_json_file(FIXTURE_PATH)
    collector = VmPowerStateCollector(
        provider=provider,
        evaluation_time=FIXED_EVAL_TIME,
    )

    # Equipment has neither UUID, MoRef, nor matching hostname, and assigned_ips is empty,
    # but Site IPAddress record maps equipment_id -> arp_mac 00:50:56:9a:42:18 (vm-20423)
    eq = Equipment(
        equipment_id="eq-042-vm-win08",
        site_id="site-042",
        name="custom-av-appliance",
        category=EquipmentCategory.VM,
    )
    site = Site(
        site_id="site-042",
        name="Site 42",
        ip_addresses=[
            IPAddress(
                ip="10.42.10.28",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-vm-win08",
                arp_mac="00:50:56:9a:42:18",
                arp_entry=ArpEntry(
                    ip="10.42.10.28",
                    arp_mac="00:50:56:9a:42:18",
                ),
            )
        ],
    )

    sig = collector.evaluate(eq, site=site)
    assert sig.status is SignalStatus.ACTIVE
    assert sig.details is not None
    assert "vm-20423" in sig.details
    assert "vcenter-prod-02" in sig.details
    assert "mac_or_ip" in sig.details
