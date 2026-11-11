"""Unit tests for Phase 4 LLDP Uplink Guard and Staged Extreme Switch Port & PoE Reclamation Planner."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest

from sot_validator.extraction import SqlExportSoTClient
from sot_validator.history import HistoryStore, ItemStreakSummary
from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.remediation import (
    DEFAULT_BLOCKED_LLDP_CAPABILITIES,
    DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS,
    BlockedPortRecord,
    ExtremeCliDialect,
    ExtremePortReclamationPlanner,
    LldpGuardDecision,
    LldpNeighborRecord,
    LldpUplinkGuard,
    PortReclamationCandidate,
    PortReclamationPlan,
    ReadOnlyViolationError,
)
from sot_validator.remediation.port_reclamation import (
    ExtremeCliDialect as DirectExtremeCliDialect,
    ExtremePortReclamationPlanner as DirectExtremePortReclamationPlanner,
    LldpUplinkGuard as DirectLldpUplinkGuard,
)
from sot_validator.signals.management import (
    EXTREME_POE_PORT_MEASURED_POWER_PREFIX,
    EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX,
    IF_MIB_IF_ALIAS_PREFIX,
)


def _make_access_port(
    port_id: str = "port-042-sw01-4",
    device_id: str = "dev-042-sw01",
    name: str = "1:4",
    *,
    admin_status: str | None = "up",
    oper_status: str | None = "down",
    poe_status: str | None = "disabled",
    connected_device_id: str | None = "eq-042-srv-legacy01",
    connected_mac: str | None = "00:1b:21:42:10:99",
    vlan_id: str | None = "10",
) -> Port:
    return Port(
        port_id=port_id,
        device_id=device_id,
        name=name,
        admin_status=admin_status,
        oper_status=oper_status,
        poe_status=poe_status,
        connected_device_id=connected_device_id,
        connected_mac=connected_mac,
        vlan_id=vlan_id,
    )


def _make_streak(
    item_id: str,
    *,
    item_type: str = "port",
    site_id: str = "site-042",
    name: str | None = None,
    classification: ValidationClassification = ValidationClassification.STALE_LIKELY_UNUSED,
    consecutive_stale_runs: int = 4,
    stale_duration_days: float = 45.0,
) -> ItemStreakSummary:
    t0 = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
    return ItemStreakSummary(
        site_id=site_id,
        item_type=item_type,
        item_id=item_id,
        name=name or item_id,
        current_classification=classification,
        current_confidence=0.92,
        consecutive_stale_runs=consecutive_stale_runs,
        total_runs_seen=max(consecutive_stale_runs, 1),
        first_seen_at=t0 - timedelta(days=max(stale_duration_days, 1.0)),
        first_stale_at=t0 - timedelta(days=stale_duration_days),
        stale_duration_days=stale_duration_days,
    )


def test_exports_and_dialect_coercion() -> None:
    assert ExtremeCliDialect is DirectExtremeCliDialect
    assert ExtremePortReclamationPlanner is DirectExtremePortReclamationPlanner
    assert LldpUplinkGuard is DirectLldpUplinkGuard
    assert DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS == (
        "uplink",
        "trunk",
        "core",
        "wan",
        "wap",
        "ap-",
        "ups",
        "apc",
        "vcenter",
        "esxi",
    )
    assert "bridge" in DEFAULT_BLOCKED_LLDP_CAPABILITIES
    assert "router" in DEFAULT_BLOCKED_LLDP_CAPABILITIES
    assert "wlan" in DEFAULT_BLOCKED_LLDP_CAPABILITIES

    assert ExtremeCliDialect("exos") is ExtremeCliDialect.EXOS
    assert ExtremeCliDialect("EXTREME_XOS") is ExtremeCliDialect.EXOS
    assert ExtremeCliDialect("extremexos") is ExtremeCliDialect.EXOS
    assert ExtremeCliDialect("voss") is ExtremeCliDialect.VOSS
    assert ExtremeCliDialect("Extreme-VOSS") is ExtremeCliDialect.VOSS
    with pytest.raises(ValueError, match="ExtremeCliDialect"):
        ExtremeCliDialect("cisco_ios")


def test_lldp_neighbor_record_coercion_and_serialization() -> None:
    # Bitmask 0x14 = 0x04 (bridge) | 0x10 (router)
    rec = LldpNeighborRecord(
        port_id="port-042-sw01-1",
        port_name="1:1",
        lldpRemSysName="sw-core-01.site042.internal",
        lldpRemSysCapEnabled="0x14",
        neighbor_role="core-switch",
        lldpRemSysDesc="ExtremeXOS version 31.7",
        remote_port="1:48",
    )
    assert rec.lldp_rem_sys_name == "sw-core-01.site042.internal"
    assert rec.lldpRemSysName == "sw-core-01.site042.internal"
    assert rec.lldp_rem_sys_cap_enabled == ("bridge", "router")
    assert rec.lldpRemSysCapEnabled == ("bridge", "router")
    assert rec.neighbor_device_role == "core-switch"
    assert rec.lldp_rem_sys_desc == "ExtremeXOS version 31.7"
    assert rec.neighbor_port_id == "1:48"

    with pytest.raises(FrozenInstanceError):
        rec.port_name = "1:2"  # type: ignore[misc]

    round_tripped = LldpNeighborRecord.from_json(rec.to_json())
    assert round_tripped == rec


def test_lldp_uplink_guard_blocks_bridge_router_and_wap_neighbors() -> None:
    guard = LldpUplinkGuard()
    stale_port = _make_access_port()

    # 1. Switch / Bridge capability
    sw_neighbor = LldpNeighborRecord(
        port_id=stale_port.port_id,
        lldp_rem_sys_name="idf-sw02.site042.internal",
        lldp_rem_sys_cap_enabled=("bridge",),
    )
    dec_sw = guard.evaluate_port(stale_port, lldp_neighbors=[sw_neighbor])
    assert dec_sw.blocked is True
    assert dec_sw.block_reason is not None and len(dec_sw.block_reason) > 0
    assert "lldp_neighbor" in dec_sw.matched_rules

    # 2. Router capability via bitmask (0x10 = router)
    rtr_neighbor = LldpNeighborRecord(
        port_name="1:4",
        lldpRemSysName="wan-gw01",
        lldpRemSysCapEnabled=0x10,
    )
    dec_rtr = guard.evaluate_port(stale_port, lldp_neighbors=rtr_neighbor)
    assert dec_rtr.blocked is True
    assert "lldp_neighbor" in dec_rtr.matched_rules

    # 3. Wireless AP capability / role
    wap_neighbor = {
        "port_id": stale_port.port_id,
        "lldpRemSysName": "ap-floor2-east",
        "lldpRemSysCapEnabled": "wlan-ap",
        "neighbor_device_role": "wap",
    }
    dec_wap = guard.evaluate_port(stale_port, lldp_neighbors=wap_neighbor)
    assert dec_wap.blocked is True
    assert "lldp_neighbor" in dec_wap.matched_rules

    # 4. Connected to a NetworkDevice in site.devices
    peer_switch = NetworkDevice(
        device_id="dev-042-sw02",
        site_id="site-042",
        hostname="sw02.site042.example.internal",
        vendor="Extreme Networks",
        role="access-switch",
    )
    site = Site(
        site_id="site-042",
        name="Site 042",
        devices=[peer_switch],
    )
    uplink_port = _make_access_port(connected_device_id="dev-042-sw02")
    dec_peer = guard.evaluate_port(uplink_port, site=site)
    assert dec_peer.blocked is True
    assert "lldp_neighbor" in dec_peer.matched_rules


@pytest.mark.parametrize(
    "keyword,description_text",
    [
        ("uplink", "MDF Uplink to Core Switch"),
        ("trunk", "802.1Q Trunk to IDF-2"),
        ("core", "Link to Core Router"),
        ("wan", "Primary WAN Handoff Circuit"),
        ("wap", "Ceiling WAP Conference Room"),
        ("ap-", "ExtremeWireless AP-305C"),
        ("ups", "Rack UPS Management Card"),
        ("apc", "APC Smart-UPS NMC3 MDF-101"),
        ("vcenter", "VMware vCenter Management Appliance"),
        ("esxi", "Uplink to ESXi Host esx01"),
    ],
)
def test_lldp_uplink_guard_blocks_all_critical_keywords(
    keyword: str, description_text: str
) -> None:
    guard = LldpUplinkGuard()
    port = _make_access_port(connected_device_id="eq-generic-01")
    decision = guard.evaluate_port(port, description=description_text)
    assert decision.blocked is True
    assert decision.block_reason is not None
    assert keyword in decision.block_reason.lower()
    assert "critical_keyword" in decision.matched_rules


def test_lldp_uplink_guard_blocks_ups_equipment_category() -> None:
    guard = LldpUplinkGuard()
    ups_eq = Equipment(
        equipment_id="eq-power-unit-01",
        site_id="site-042",
        name="battery-backup-rack01",
        category=EquipmentCategory.UPS,
        connected_ports=["port-042-sw01-4"],
    )
    port = _make_access_port(connected_device_id="eq-power-unit-01")
    decision = guard.evaluate_port(port, mapped_equipment=ups_eq)
    assert decision.blocked is True
    assert "critical_keyword" in decision.matched_rules
    assert "UPS" in (decision.block_reason or "")


def test_lldp_uplink_guard_blocks_multi_vlan_trunks() -> None:
    guard = LldpUplinkGuard()
    port = _make_access_port()

    # Explicit is_trunk=True
    dec_trunk_flag = guard.evaluate_port(port, is_trunk=True)
    assert dec_trunk_flag.blocked is True
    assert "tagged_trunk" in dec_trunk_flag.matched_rules

    # Tagged VLAN list
    dec_tagged_list = guard.evaluate_port(port, tagged_vlans=[10, 20, 30])
    assert dec_tagged_list.blocked is True
    assert "tagged_trunk" in dec_tagged_list.matched_rules

    # Multi-VLAN string in port.vlan_id
    multi_vlan_port = _make_access_port(vlan_id="10,20")
    dec_multi_vlan = guard.evaluate_port(multi_vlan_port)
    assert dec_multi_vlan.blocked is True
    assert "tagged_trunk" in dec_multi_vlan.matched_rules

    # VLAN range in port.vlan_id
    range_vlan_port = _make_access_port(vlan_id="10-20")
    dec_range_vlan = guard.evaluate_port(range_vlan_port)
    assert dec_range_vlan.blocked is True
    assert "tagged_trunk" in dec_range_vlan.matched_rules


def test_lldp_uplink_guard_blocks_oper_up_and_recent_arp_allows_stale_access() -> None:
    guard = LldpUplinkGuard(arp_active_within_days=30.0)
    eval_dt = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)

    # 1. oper_status == "up"
    up_port = _make_access_port(oper_status="up")
    dec_up = guard.evaluate_port(up_port, evaluation_time=eval_dt)
    assert dec_up.blocked is True
    assert "oper_up_or_active_arp" in dec_up.matched_rules

    # 2. Recent ARP entry within 30 days
    stale_port = _make_access_port(oper_status="down")
    recent_ip = IPAddress(
        ip="10.42.10.99",
        subnet_id="sub-042-10",
        assigned_object_id="eq-042-srv-legacy01",
        arp_mac="00:1b:21:42:10:99",
        arp_last_seen=eval_dt - timedelta(days=5),
    )
    dec_recent_arp = guard.evaluate_port(
        stale_port,
        ip_addresses=[recent_ip],
        evaluation_time=eval_dt,
    )
    assert dec_recent_arp.blocked is True
    assert "oper_up_or_active_arp" in dec_recent_arp.matched_rules

    # 3. Active MAC table hit
    dec_active_mac = guard.evaluate_port(
        stale_port,
        active_macs=["00-1B-21-42-10-99"],
        evaluation_time=eval_dt,
    )
    assert dec_active_mac.blocked is True
    assert "oper_up_or_active_arp" in dec_active_mac.matched_rules

    # 4. Safe stale access port (ARP last seen 150 days ago, oper_status="down")
    old_ip = IPAddress(
        ip="10.42.10.99",
        subnet_id="sub-042-10",
        assigned_object_id="eq-042-srv-legacy01",
        arp_mac="00:1b:21:42:10:99",
        arp_last_seen=eval_dt - timedelta(days=150),
    )
    dec_safe = guard.evaluate_port(
        stale_port,
        description="Decommissioned App Server srv-legacy01",
        ip_addresses=[old_ip],
        evaluation_time=eval_dt,
    )
    assert dec_safe.blocked is False
    assert dec_safe.block_reason is None
    assert dec_safe.block_reasons == ()
    assert dec_safe.matched_rules == ()


def test_planner_streak_filtering_poe_aggregation_and_exos_voss_scripts() -> None:
    eval_dt = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
    sw01 = NetworkDevice(
        device_id="dev-042-sw01",
        site_id="site-042",
        hostname="sw01.site042.example.internal",
        vendor="Extreme Networks",
        model="ExtremeSwitching X465-48W",
        role="core-switch",
        ports=[
            # Port 1:1 - ESXi Uplink (UP + critical keyword -> blocked)
            Port(
                port_id="port-042-sw01-1",
                device_id="dev-042-sw01",
                name="1:1",
                admin_status="up",
                oper_status="up",
                poe_status="disabled",
                connected_device_id="eq-042-esx01",
                vlan_id="10,20",
            ),
            # Port 1:3 - APC UPS port (even if down, blocked by UPS equipment & keyword)
            Port(
                port_id="port-042-sw01-3",
                device_id="dev-042-sw01",
                name="1:3",
                admin_status="up",
                oper_status="down",
                poe_status="delivering 12.4W",
                connected_device_id="eq-042-ups01",
                vlan_id="30",
            ),
            # Port 1:4 - Eligible stale access port #1 (4 runs, 45 days, 6.5W PoE)
            Port(
                port_id="port-042-sw01-4",
                device_id="dev-042-sw01",
                name="1:4",
                admin_status="up",
                oper_status="down",
                poe_status="searching 6.5W",
                connected_device_id="eq-042-srv-legacy01",
                vlan_id="10",
            ),
            # Port 1:6 - Eligible stale access port #2 (5 runs, 60 days, 4.2W via SNMP OID)
            Port(
                port_id="port-042-sw01-6",
                device_id="dev-042-sw01",
                name="1:6",
                admin_status="up",
                oper_status="down",
                poe_status="searching",
                connected_device_id="eq-042-prn-old01",
                vlan_id="10",
            ),
            # Port 1:7 - Below streak threshold (only 2 runs, 14 days -> blocked)
            Port(
                port_id="port-042-sw01-7",
                device_id="dev-042-sw01",
                name="1:7",
                admin_status="up",
                oper_status="down",
                poe_status="disabled",
                connected_device_id="eq-042-pc-temp01",
                vlan_id="10",
            ),
            # Port 1:8 - Already administratively down (blocked)
            Port(
                port_id="port-042-sw01-8",
                device_id="dev-042-sw01",
                name="1:8",
                admin_status="down",
                oper_status="down",
                poe_status="disabled",
                vlan_id="10",
            ),
        ],
    )
    site = Site(
        site_id="site-042",
        name="Site 042",
        devices=[sw01],
        equipment=[
            Equipment(
                equipment_id="eq-042-ups01",
                site_id="site-042",
                name="ups01.site042.example.internal",
                category=EquipmentCategory.UPS,
                connected_ports=["port-042-sw01-3"],
            ),
            Equipment(
                equipment_id="eq-042-srv-legacy01",
                site_id="site-042",
                name="srv-legacy01.site042.example.internal",
                category=EquipmentCategory.SERVER,
                connected_ports=["port-042-sw01-4"],
            ),
        ],
    )

    streaks = [
        _make_streak(
            "port-042-sw01-1",
            consecutive_stale_runs=5,
            stale_duration_days=60.0,
        ),
        _make_streak(
            "port-042-sw01-3",
            consecutive_stale_runs=5,
            stale_duration_days=60.0,
        ),
        _make_streak(
            "port-042-sw01-4",
            consecutive_stale_runs=4,
            stale_duration_days=45.0,
        ),
        _make_streak(
            "port-042-sw01-6",
            consecutive_stale_runs=5,
            stale_duration_days=60.0,
        ),
        _make_streak(
            "port-042-sw01-7",
            consecutive_stale_runs=2,
            stale_duration_days=14.0,
        ),
        _make_streak(
            "port-042-sw01-8",
            consecutive_stale_runs=6,
            stale_duration_days=90.0,
        ),
    ]

    snmp_oids = {
        "dev-042-sw01": {
            f"{IF_MIB_IF_ALIAS_PREFIX}.1001": "Uplink to ESXi Host esx01 (VM Trunk)",
            f"{IF_MIB_IF_ALIAS_PREFIX}.1003": "APC Smart-UPS NMC3 MDF-101",
            f"{IF_MIB_IF_ALIAS_PREFIX}.1004": "Decommissioned App Server srv-legacy01",
            f"{IF_MIB_IF_ALIAS_PREFIX}.1006": "Retired Floor Printer prn-old01",
            f"{EXTREME_POE_PORT_MEASURED_POWER_PREFIX}.1.1006": 4200,
            f"{EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX}.1.1006": 15400,
        }
    }

    planner = ExtremePortReclamationPlanner(
        min_inactive_runs=3,
        min_inactive_days=30.0,
        dialect=ExtremeCliDialect.EXOS,
    )
    plan = planner.plan(
        sites=[site],
        streaks=streaks,
        snmp_oids_by_device=snmp_oids,
        evaluation_time=eval_dt,
    )

    assert plan.dry_run is True
    assert [c.port_id for c in plan.candidates] == [
        "port-042-sw01-4",
        "port-042-sw01-6",
    ]
    assert plan.eligible_ports == plan.candidates
    assert plan.estimated_poe_watts_saved == pytest.approx(10.7)

    cand_4, cand_6 = plan.candidates
    assert cand_4.estimated_poe_watts_saved == pytest.approx(6.5)
    assert cand_4.poe_restore_limit_mw == 30000
    assert cand_4.exos_disable_commands == (
        "configure inline-power operator-limit 0 ports 1:4",
        "disable ports 1:4",
    )
    assert cand_4.exos_rollback_command == (
        "enable ports 1:4; configure inline-power operator-limit 30000 ports 1:4"
    )

    assert cand_6.estimated_poe_watts_saved == pytest.approx(4.2)
    assert cand_6.poe_restore_limit_mw == 15400
    assert cand_6.voss_disable_commands == (
        "interface GigabitEthernet 1:6",
        "poe-shutdown",
        "shutdown",
        "exit",
    )
    assert cand_6.voss_rollback_command == (
        "interface GigabitEthernet 1:6; no poe-shutdown; no shutdown; exit"
    )

    # Verify ExtremeXOS forward and rollback scripts
    assert "configure inline-power operator-limit 0 ports 1:4" in plan.exos_script
    assert "disable ports 1:4" in plan.exos_script
    assert "configure inline-power operator-limit 0 ports 1:6" in plan.exos_script
    assert "disable ports 1:6" in plan.exos_script

    assert "enable ports 1:4" in plan.exos_rollback_script
    assert (
        "configure inline-power operator-limit 30000 ports 1:4"
        in plan.exos_rollback_script
    )
    assert (
        "configure inline-power operator-limit 15400 ports 1:6"
        in plan.exos_rollback_script
    )

    # Verify VOSS forward and rollback scripts
    voss_fwd = plan.format_cli_script("voss")
    voss_rb = plan.format_rollback_script(ExtremeCliDialect.VOSS)
    assert "interface GigabitEthernet 1:4" in voss_fwd
    assert "poe-shutdown" in voss_fwd
    assert "shutdown" in voss_fwd
    assert "exit" in voss_fwd

    assert "interface GigabitEthernet 1:4" in voss_rb
    assert "no poe-shutdown" in voss_rb
    assert "no shutdown" in voss_rb
    assert "exit" in voss_rb

    # Verify blocked ports and their audit reasons
    blocked_by_id = {b.port_id: b for b in plan.blocked_ports}
    assert set(blocked_by_id.keys()) == {
        "port-042-sw01-1",
        "port-042-sw01-3",
        "port-042-sw01-7",
        "port-042-sw01-8",
    }
    assert "critical_keyword" in blocked_by_id["port-042-sw01-1"].matched_rules
    assert "tagged_trunk" in blocked_by_id["port-042-sw01-1"].matched_rules
    assert (
        "oper_up_or_active_arp"
        in blocked_by_id["port-042-sw01-1"].matched_rules
    )
    assert "critical_keyword" in blocked_by_id["port-042-sw01-3"].matched_rules
    assert (
        "below_inactivity_threshold"
        in blocked_by_id["port-042-sw01-7"].matched_rules
    )
    assert (
        "admin_already_disabled"
        in blocked_by_id["port-042-sw01-8"].matched_rules
    )

    # Verify immutability and serialization round-trip
    with pytest.raises(FrozenInstanceError):
        plan.estimated_poe_watts_saved = 0.0  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        cand_4.port_name = "1:99"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        blocked_by_id["port-042-sw01-1"].blocked = False  # type: ignore[misc]

    reloaded_plan = PortReclamationPlan.from_json(plan.to_json(indent=2))
    assert reloaded_plan == plan

    with pytest.raises(ReadOnlyViolationError):
        PortReclamationPlan(dry_run=False)


def test_planner_integration_with_csv_fixtures_and_history_store() -> None:
    fixtures_root = (
        Path(__file__).resolve().parent / "fixtures" / "sot_samples"
    )
    client = SqlExportSoTClient.from_csv_dir(fixtures_root / "csv")
    site = client.get_site("site-042")
    snmp_walk = json.loads(
        (fixtures_root / "snmp" / "extreme_and_apc_walks.json").read_text(
            encoding="utf-8"
        )
    )

    store = HistoryStore(":memory:")
    t0 = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
    for idx, days_offset in enumerate((0, 15, 35, 50), start=1):
        store.record_run(
            [
                ValidationResult(
                    item_type="equipment",
                    item_id="eq-042-srv-legacy01",
                    site_id="site-042",
                    name="srv-legacy01.site042.example.internal",
                    classification=ValidationClassification.STALE_LIKELY_UNUSED,
                    confidence=0.95,
                )
            ],
            run_id=f"run-{idx}",
            recorded_at=t0 + timedelta(days=days_offset),
        )

    planner = ExtremePortReclamationPlanner(
        min_inactive_runs=3,
        min_inactive_days=30.0,
    )
    plan = planner.plan(
        sites=[site],
        history_store=store,
        snmp_oids_by_device=snmp_walk,
        evaluation_time=datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc),
    )

    # Only port-042-sw01-4 (1:4, decommissioned server) is eligible;
    # ports 1:1 (ESXi uplink), 1:2 (SAN UP), 1:3 (APC UPS), 1:5 (NAS UP) are blocked.
    assert [c.port_id for c in plan.candidates] == ["port-042-sw01-4"]
    assert plan.candidates[0].port_name == "1:4"
    assert plan.candidates[0].inactive_runs == 4
    assert plan.candidates[0].inactive_days == pytest.approx(50.0)
    assert len(plan.blocked_ports) == 4
    store.close()
