"""Unit tests for APC UPS PowerNet-MIB battery, runtime, and environmental health evaluator."""

from __future__ import annotations

from datetime import datetime, timezone
import pathlib

import pytest

from sot_validator.connectors.live import SnmpWalkConnector
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    NetworkDevice,
    SignalStatus,
    SignalType,
    Site,
)
from sot_validator.signals import (
    APC_UPS_ADV_BATTERY_CAPACITY_OID,
    APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID,
    APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID,
    APC_UPS_ADV_BATTERY_TEMPERATURE_OID,
    APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID,
    APC_UPS_ADV_OUTPUT_LOAD_OID,
    APC_UPS_BASIC_BATTERY_STATUS_OID,
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_OUTPUT_STATUS_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
    APC_UPS_HEALTH_OIDS,
    ApcUpsHealthEvaluator,
    EquipmentType,
    FixtureManagementTransport,
    UpsAdvisoryCode,
    UpsFleetHealthReport,
    UpsHealthRecord,
    UpsHealthStatus,
    parse_powernet_telemetry,
)

FIXTURE_PATH = (
    pathlib.Path(__file__).resolve().parent
    / "fixtures"
    / "sot_samples"
    / "snmp"
    / "extreme_and_apc_walks.json"
)


def _make_ups(
    equipment_id: str = "eq-042-ups01",
    site_id: str = "site-042",
    name: str = "ups01.site042.example.internal",
    ip: str = "10.42.30.10",
) -> Equipment:
    return Equipment(
        equipment_id=equipment_id,
        site_id=site_id,
        name=name,
        category=EquipmentCategory.UPS,
        assigned_ips=[ip] if ip else [],
    )


def test_healthy_ups_evaluation_numeric_oids() -> None:
    """Healthy APC UPS telemetry evaluates to HEALTHY with zero advisories."""
    ups = _make_ups()
    telemetry = {
        APC_UPS_BASIC_IDENT_MODEL_OID: "Smart-UPS SRT 5000",
        APC_UPS_BASIC_BATTERY_STATUS_OID: 2,  # batteryNormal
        APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID: 1,  # noBatteryNeedsReplacing
        APC_UPS_ADV_BATTERY_CAPACITY_OID: 100,
        APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID: 48,  # 48 minutes
        APC_UPS_ADV_BATTERY_TEMPERATURE_OID: 27,  # 27 C
        APC_UPS_ADV_OUTPUT_LOAD_OID: 38,  # 38%
        APC_UPS_BASIC_OUTPUT_STATUS_OID: 2,  # onLine
        APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID: 1,  # noTransfer
    }

    evaluator = ApcUpsHealthEvaluator(evaluation_time="2026-11-11T12:00:00Z")
    record = evaluator.evaluate_unit(ups, telemetry)

    assert record.status is UpsHealthStatus.HEALTHY
    assert record.health_status is UpsHealthStatus.HEALTHY
    assert record.reachable is True
    assert record.ups_id == "eq-042-ups01"
    assert record.hostname == "ups01.site042.example.internal"
    assert record.model == "Smart-UPS SRT 5000"
    assert record.battery_status == "batteryNormal"
    assert record.battery_status_code == 2
    assert record.battery_replace_indicator == 1
    assert record.needs_battery_replacement is False
    assert record.battery_needs_replacing is False
    assert record.battery_capacity_pct == 100.0
    assert record.runtime_remaining_minutes == 48.0
    assert record.runtime_minutes == 48.0
    assert record.temperature_celsius == 27.0
    assert record.battery_temperature_celsius == 27.0
    assert record.output_load_pct == 38.0
    assert record.load_pct == 38.0
    assert record.output_status == "onLine"
    assert record.on_battery is False
    assert record.input_line_fail_cause == "noTransfer"
    assert record.is_low_runtime is False
    assert record.is_high_temperature is False
    assert record.is_high_load is False
    assert record.advisories == []
    assert record.signal is not None
    assert record.signal.signal_type is SignalType.SNMP_API_REACHABILITY
    assert record.signal.status is SignalStatus.ACTIVE
    assert record.signal.metadata["health_status"] == "HEALTHY"


def test_battery_replacement_needed_and_battery_fault() -> None:
    """upsAdvBatteryReplaceIndicator=2 and upsBasicBatteryStatus=4 trigger CRITICAL status."""
    ups = _make_ups()
    evaluator = ApcUpsHealthEvaluator()

    # Case 1: upsAdvBatteryReplaceIndicator = 2
    replace_telemetry = {
        APC_UPS_BASIC_BATTERY_STATUS_OID: 2,
        APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID: 2,
        APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID: 35,
        APC_UPS_ADV_BATTERY_TEMPERATURE_OID: 29,
        APC_UPS_ADV_OUTPUT_LOAD_OID: 42,
        APC_UPS_BASIC_OUTPUT_STATUS_OID: 2,
    }
    rec_replace = evaluator.evaluate_unit(ups, replace_telemetry)
    assert rec_replace.status is UpsHealthStatus.CRITICAL
    assert rec_replace.needs_battery_replacement is True
    assert rec_replace.replace_battery is True
    assert UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED.value in rec_replace.advisories

    # Case 2: upsBasicBatteryStatus = 4 (batteryInFaultCondition)
    fault_telemetry = {
        APC_UPS_BASIC_BATTERY_STATUS_OID: 4,
        APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID: 1,
        APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID: 30,
        APC_UPS_ADV_BATTERY_TEMPERATURE_OID: 28,
        APC_UPS_ADV_OUTPUT_LOAD_OID: 35,
    }
    rec_fault = evaluator.evaluate_unit(ups, fault_telemetry)
    assert rec_fault.status is UpsHealthStatus.CRITICAL
    assert rec_fault.battery_status == "batteryInFaultCondition"
    assert UpsAdvisoryCode.BATTERY_FAULT.value in rec_fault.advisories

    # Case 3: upsBasicBatteryStatus = 3 (batteryLow)
    low_batt_telemetry = {
        "upsBasicBatteryStatus": "batteryLow",
        "upsAdvBatteryReplaceIndicator": "noBatteryNeedsReplacing",
        "upsAdvBatteryRunTimeRemaining": 20,
    }
    rec_low = evaluator.evaluate_unit(ups, low_batt_telemetry)
    assert rec_low.status is UpsHealthStatus.WARNING
    assert UpsAdvisoryCode.BATTERY_LOW.value in rec_low.advisories


def test_runtime_temp_load_and_symbolic_mib_thresholds() -> None:
    """Low runtime, high temperature, and high load thresholds work with numeric and symbolic keys."""
    ups = _make_ups()
    evaluator = ApcUpsHealthEvaluator(
        min_runtime_minutes=15.0,
        critical_runtime_minutes=5.0,
        max_temp_celsius=40.0,
        critical_temp_celsius=50.0,
        max_load_pct=80.0,
        critical_load_pct=95.0,
    )

    # Warning thresholds via symbolic PowerNet-MIB names
    warn_telemetry = {
        "PowerNet-MIB::upsBasicBatteryStatus.0": "batteryNormal",
        "PowerNet-MIB::upsAdvBatteryReplaceIndicator.0": 1,
        "upsAdvBatteryRunTimeRemaining": 10.0,  # < 15 min
        "upsAdvBatteryTemperature": 44.5,  # > 40 C
        "upsAdvOutputLoad": 85.0,  # > 80%
        "upsBasicOutputStatus": "onBattery",
        "upsAdvInputLineFailCause": "blackout",
    }
    rec_warn = evaluator.evaluate_unit(ups, warn_telemetry)
    assert rec_warn.status is UpsHealthStatus.WARNING
    assert rec_warn.is_low_runtime is True
    assert rec_warn.low_runtime is True
    assert rec_warn.is_high_temperature is True
    assert rec_warn.high_temperature is True
    assert rec_warn.thermal_alert is True
    assert rec_warn.is_high_load is True
    assert rec_warn.high_load is True
    assert rec_warn.overload_risk is True
    assert rec_warn.on_battery is True
    assert UpsAdvisoryCode.LOW_RUNTIME_WARNING.value in rec_warn.advisories
    assert UpsAdvisoryCode.HIGH_TEMP_WARNING.value in rec_warn.advisories
    assert UpsAdvisoryCode.HIGH_LOAD_WARNING.value in rec_warn.advisories
    assert UpsAdvisoryCode.ON_BATTERY_ALERT.value in rec_warn.advisories
    assert UpsAdvisoryCode.INPUT_LINE_FAIL.value in rec_warn.advisories

    # Critical thresholds via numeric OIDs and TimeTicks conversion (18000 ticks = 3 minutes)
    crit_telemetry = {
        APC_UPS_BASIC_BATTERY_STATUS_OID: 2,
        APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID: 1,
        APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID: 18000,  # 18000 / 6000 = 3.0 min (< 5.0)
        APC_UPS_ADV_BATTERY_TEMPERATURE_OID: 53,  # > 50 C
        APC_UPS_ADV_OUTPUT_LOAD_OID: 97,  # > 95%
    }
    rec_crit = evaluator.evaluate_unit(ups, crit_telemetry)
    assert rec_crit.status is UpsHealthStatus.CRITICAL
    assert rec_crit.runtime_remaining_minutes == 3.0
    assert UpsAdvisoryCode.CRITICAL_RUNTIME.value in rec_crit.advisories
    assert UpsAdvisoryCode.HIGH_TEMP_CRITICAL.value in rec_crit.advisories
    assert UpsAdvisoryCode.OVERLOAD_CRITICAL.value in rec_crit.advisories


def test_symbolic_and_duration_string_parsing() -> None:
    """parse_powernet_telemetry normalizes duration strings, TimeTicks, and state flags."""
    parsed_hms = parse_powernet_telemetry(
        {
            "upsAdvBatteryRunTimeRemaining": "0:12:30.00",
            "upsBasicStateOutputState": (
                "0110000000000000000000000000000000000000000000000000000000000000"
            ),
        }
    )
    assert parsed_hms["runtime_remaining_minutes"] == 12.5
    assert parsed_hms["needs_battery_replacement"] is True
    assert parsed_hms["on_battery"] is True
    assert parsed_hms["output_status"] == "onBattery"

    parsed_sec = parse_powernet_telemetry({"upsAdvBatteryRunTimeRemaining": "720s"})
    assert parsed_sec["runtime_remaining_minutes"] == 12.0


def test_unreachable_ups_unit() -> None:
    """Missing telemetry or snmp_reachable=False yields UpsHealthStatus.UNREACHABLE."""
    ups = _make_ups(equipment_id="eq-042-ups99", ip="10.42.30.99")
    evaluator = ApcUpsHealthEvaluator()

    rec_none = evaluator.evaluate_unit(ups, None)
    assert rec_none.status is UpsHealthStatus.UNREACHABLE
    assert rec_none.reachable is False
    assert rec_none.advisories == [UpsAdvisoryCode.UNREACHABLE.value]
    assert rec_none.signal is not None
    assert rec_none.signal.status is SignalStatus.UNREACHABLE

    rec_false = evaluator.evaluate_unit(ups, {"snmp_reachable": False})
    assert rec_false.status is UpsHealthStatus.UNREACHABLE
    assert rec_false.reachable is False


def test_fleet_and_site_aggregation_filters_non_ups_equipment() -> None:
    """evaluate_fleet and evaluate_site aggregate UPS health across sites and skip non-UPS items."""
    assert EquipmentType.UPS is EquipmentCategory.UPS

    site_42 = Site(
        site_id="site-042",
        name="Site 042",
        devices=[
            NetworkDevice(
                device_id="dev-042-sw01",
                site_id="site-042",
                hostname="sw01.site042",
                management_ip="10.42.1.10",
                vendor="Extreme Networks",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-042-ups01",
                site_id="site-042",
                name="ups01.site042",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.30.10"],
            ),
            Equipment(
                equipment_id="eq-042-ups02",
                site_id="site-042",
                name="ups02.site042",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.30.11"],
            ),
            Equipment(
                equipment_id="eq-042-vm01",
                site_id="site-042",
                name="winvm01.site042",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.21"],
            ),
            Equipment(
                equipment_id="eq-042-san01",
                site_id="site-042",
                name="san01.site042",
                category=EquipmentCategory.SAN,
                assigned_ips=["10.42.20.15"],
            ),
        ],
    )

    site_43 = Site(
        site_id="site-043",
        name="Site 043",
        equipment=[
            Equipment(
                equipment_id="eq-043-ups01",
                site_id="site-043",
                name="ups01.site043",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.43.30.10"],
            ),
            Equipment(
                equipment_id="eq-043-ups02",
                site_id="site-043",
                name="ups02.site043",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.43.30.11"],
            ),
        ],
    )

    telemetry_map = {
        "eq-042-ups01": {
            APC_UPS_BASIC_BATTERY_STATUS_OID: 2,
            APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID: 1,
            APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID: 45,
            APC_UPS_ADV_BATTERY_TEMPERATURE_OID: 26,
            APC_UPS_ADV_OUTPUT_LOAD_OID: 38,
            APC_UPS_BASIC_OUTPUT_STATUS_OID: 2,
        },
        "eq-042-ups02": {
            APC_UPS_BASIC_BATTERY_STATUS_OID: 2,
            APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID: 2,  # Needs replacement
            APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID: 11,  # Low runtime
            APC_UPS_ADV_BATTERY_TEMPERATURE_OID: 29,
            APC_UPS_ADV_OUTPUT_LOAD_OID: 50,
            APC_UPS_BASIC_OUTPUT_STATUS_OID: 2,
        },
        "eq-043-ups01": {
            APC_UPS_BASIC_BATTERY_STATUS_OID: 2,
            APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID: 1,
            APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID: 28,
            APC_UPS_ADV_BATTERY_TEMPERATURE_OID: 43,  # High temp
            APC_UPS_ADV_OUTPUT_LOAD_OID: 84,  # High load
            APC_UPS_BASIC_OUTPUT_STATUS_OID: 3,  # onBattery
        },
        # eq-043-ups02 is unreachable (omitted)
    }

    evaluator = ApcUpsHealthEvaluator(
        telemetry_by_target=telemetry_map,
        evaluation_time=datetime(2026, 11, 11, 15, 0, tzinfo=timezone.utc),
    )

    site_report = evaluator.evaluate_site(site_42)
    assert site_report.total_units == 2
    assert site_report.healthy_count == 1
    assert site_report.critical_count == 1
    assert len(site_report.battery_replacement_units) == 1
    assert site_report.battery_replacement_units[0].equipment_id == "eq-042-ups02"

    fleet_report = evaluator.evaluate_fleet([site_42, site_43])
    assert isinstance(fleet_report, UpsFleetHealthReport)
    assert fleet_report.total_units == 4
    assert fleet_report.total_ups_count == 4
    assert fleet_report.healthy_count == 1
    assert fleet_report.warning_count == 1
    assert fleet_report.critical_count == 1
    assert fleet_report.unreachable_count == 1
    assert fleet_report.battery_replacement_count == 1
    assert fleet_report.low_runtime_count == 1
    assert fleet_report.thermal_alert_count == 1
    assert fleet_report.high_load_count == 1
    assert fleet_report.on_battery_count == 1
    assert set(fleet_report.by_site.keys()) == {"site-042", "site-043"}
    assert fleet_report.by_site["site-042"]["total_units"] == 2
    assert fleet_report.by_site["site-043"]["unreachable_count"] == 1

    # Round-trip JSON serialization
    restored = UpsFleetHealthReport.from_json(fleet_report.to_json(indent=2))
    assert restored.total_units == 4
    assert restored.critical_count == 1
    assert restored.battery_replacement_count == 1


def test_fixture_file_and_snmp_walk_connector_integration() -> None:
    """ApcUpsHealthEvaluator works with extreme_and_apc_walks.json and SnmpWalkConnector."""
    evaluator = ApcUpsHealthEvaluator.from_fixture_file(FIXTURE_PATH)
    fleet_report = evaluator.evaluate_fleet()
    # extreme_and_apc_walks.json has 1 switch (dev-042-sw01) and 1 APC UPS (eq-042-ups01)
    assert fleet_report.total_units == 1
    ups_rec = fleet_report.records[0]
    assert ups_rec.equipment_id == "eq-042-ups01"
    assert ups_rec.status is UpsHealthStatus.HEALTHY
    assert ups_rec.battery_capacity_pct == 100.0
    assert ups_rec.output_load_pct == 38.0
    assert ups_rec.output_status == "onLine"

    # Also test with SnmpWalkConnector transport
    transport = FixtureManagementTransport.from_file(FIXTURE_PATH)
    connector = SnmpWalkConnector(
        transport=lambda ip, oids=APC_UPS_HEALTH_OIDS: transport.query_snmp(ip)
    )
    conn_evaluator = ApcUpsHealthEvaluator(snmp_connector=connector)
    ups_eq = _make_ups(equipment_id="eq-042-ups01", ip="10.42.30.10")
    signal = conn_evaluator.evaluate(ups_eq)
    assert signal.status is SignalStatus.ACTIVE
    assert signal.metadata["health_status"] == "HEALTHY"


def test_evaluator_parameter_validation() -> None:
    """ApcUpsHealthEvaluator rejects invalid threshold arguments."""
    with pytest.raises(ValueError, match="min_runtime_minutes"):
        ApcUpsHealthEvaluator(min_runtime_minutes=0)
    with pytest.raises(ValueError, match="critical_runtime_minutes"):
        ApcUpsHealthEvaluator(min_runtime_minutes=15, critical_runtime_minutes=20)
    with pytest.raises(ValueError, match="max_temp_celsius"):
        ApcUpsHealthEvaluator(max_temp_celsius=-5)
    with pytest.raises(ValueError, match="critical_temp_celsius"):
        ApcUpsHealthEvaluator(max_temp_celsius=40, critical_temp_celsius=35)
    with pytest.raises(ValueError, match="max_load_pct"):
        ApcUpsHealthEvaluator(max_load_pct=110)
    with pytest.raises(ValueError, match="critical_load_pct"):
        ApcUpsHealthEvaluator(max_load_pct=80, critical_load_pct=70)
