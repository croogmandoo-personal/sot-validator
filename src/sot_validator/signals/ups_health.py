"""APC UPS battery, runtime, load, and environmental health evaluator (PowerNet-MIB)."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import inspect
import json
import pathlib
import re
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals.base import (
    SignalCollector,
    normalize_utc_datetime,
    resolve_evaluation_time,
)
from sot_validator.signals.management import (
    APC_ENTERPRISE_OID_PREFIX,
    APC_UPS_ADV_BATTERY_CAPACITY_OID,
    APC_UPS_ADV_OUTPUT_LOAD_OID,
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
    SNMPV2_MIB_OIDS,
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_NAME,
    SNMPV2_MIB_SYS_UPTIME,
    validate_readonly_snmp_request,
)

# Convenience alias so callers referencing EquipmentType.UPS or EquipmentCategory.UPS both work.
EquipmentType = EquipmentCategory

# ---------------------------------------------------------------------------
# Canonical APC PowerNet-MIB (1.3.6.1.4.1.318) OID Constants
# ---------------------------------------------------------------------------

APC_UPS_BASIC_BATTERY_STATUS_OID = "1.3.6.1.4.1.318.1.1.1.2.1.1.0"
APC_UPS_ADV_BATTERY_TEMPERATURE_OID = "1.3.6.1.4.1.318.1.1.1.2.2.2.0"
APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID = "1.3.6.1.4.1.318.1.1.1.2.2.3.0"
APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID = "1.3.6.1.4.1.318.1.1.1.2.2.4.0"
APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID = "1.3.6.1.4.1.318.1.1.1.3.2.5.0"
APC_UPS_BASIC_OUTPUT_STATUS_OID = "1.3.6.1.4.1.318.1.1.1.4.1.1.0"

APC_UPS_HEALTH_OIDS: tuple[str, ...] = (
    *SNMPV2_MIB_OIDS,
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_BATTERY_STATUS_OID,
    APC_UPS_ADV_BATTERY_CAPACITY_OID,
    APC_UPS_ADV_BATTERY_TEMPERATURE_OID,
    APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID,
    APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID,
    APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID,
    APC_UPS_BASIC_OUTPUT_STATUS_OID,
    APC_UPS_ADV_OUTPUT_LOAD_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
)

_BATTERY_STATUS_CODE_TO_NAME: dict[int, str] = {
    1: "unknown",
    2: "batteryNormal",
    3: "batteryLow",
    4: "batteryInFaultCondition",
}

_BATTERY_STATUS_NAME_TO_CODE: dict[str, int] = {
    "unknown": 1,
    "batterynormal": 2,
    "normal": 2,
    "ok": 2,
    "batterylow": 3,
    "low": 3,
    "batteryinfaultcondition": 4,
    "fault": 4,
    "batteryfault": 4,
}

_REPLACE_INDICATOR_CODE_TO_NAME: dict[int, str] = {
    1: "noBatteryNeedsReplacing",
    2: "batteryNeedsReplacing",
}

_REPLACE_INDICATOR_NAME_TO_CODE: dict[str, int] = {
    "nobatteryneedsreplacing": 1,
    "no": 1,
    "false": 1,
    "normal": 1,
    "ok": 1,
    "batteryneedsreplacing": 2,
    "replace": 2,
    "needsreplacement": 2,
    "yes": 2,
    "true": 2,
}

_INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME: dict[int, str] = {
    1: "noTransfer",
    2: "highLineVoltage",
    3: "brownout",
    4: "blackout",
    5: "smallMomentarySag",
    6: "deepMomentarySag",
    7: "smallMomentarySpike",
    8: "largeMomentarySpike",
    9: "selfTest",
    10: "rateOfVoltageChange",
}

_INPUT_LINE_FAIL_CAUSE_NAME_TO_CODE: dict[str, int] = {
    name.lower(): code for code, name in _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME.items()
}

_OUTPUT_STATUS_CODE_TO_NAME: dict[int, str] = {
    1: "unknown",
    2: "onLine",
    3: "onBattery",
    4: "onSmartBoost",
    5: "timedSleeping",
    6: "softwareBypass",
    7: "off",
    8: "rebooting",
    9: "switchedBypass",
    10: "hardwareFailureBypass",
    11: "sleepingUntilPowerReturn",
    12: "onSmartTrim",
}

_OUTPUT_STATUS_NAME_TO_CANONICAL: dict[str, str] = {
    **{name.lower(): name for name in _OUTPUT_STATUS_CODE_TO_NAME.values()},
    "online": "onLine",
    "on_line": "onLine",
    "onbattery": "onBattery",
    "on_battery": "onBattery",
    "onsmartboost": "onSmartBoost",
    "onsmarttrim": "onSmartTrim",
    "offline": "offLine",
    "off_line": "offLine",
}


class UpsHealthStatus(str, Enum):
    """Overall health classification for an APC UPS unit."""

    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    UNREACHABLE = "UNREACHABLE"


class UpsAdvisoryCode(str, Enum):
    """Standardized maintenance and environmental advisory codes for APC UPS units."""

    BATTERY_REPLACEMENT_NEEDED = "BATTERY_REPLACEMENT_NEEDED"
    BATTERY_FAULT = "BATTERY_FAULT"
    BATTERY_LOW = "BATTERY_LOW"
    LOW_RUNTIME_WARNING = "LOW_RUNTIME_WARNING"
    CRITICAL_RUNTIME = "CRITICAL_RUNTIME"
    HIGH_TEMP_WARNING = "HIGH_TEMP_WARNING"
    HIGH_TEMP_CRITICAL = "HIGH_TEMP_CRITICAL"
    HIGH_LOAD_WARNING = "HIGH_LOAD_WARNING"
    OVERLOAD_CRITICAL = "OVERLOAD_CRITICAL"
    ON_BATTERY_ALERT = "ON_BATTERY_ALERT"
    INPUT_LINE_FAIL = "INPUT_LINE_FAIL"
    UNREACHABLE = "UNREACHABLE"


def _normalize_lookup_key(key: str) -> str:
    cleaned = str(key).strip().lstrip(".")
    if "::" in cleaned:
        cleaned = cleaned.split("::", 1)[1].strip()
    return cleaned


def _build_lookup_map(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten payload (including nested 'oids' and 'metrics' dicts) into normalized key lookups."""
    flat: dict[str, Any] = {}
    for nested_key in ("metrics", "oids"):
        nested = payload.get(nested_key)
        if isinstance(nested, Mapping):
            for k, v in nested.items():
                flat[str(k)] = v
    for k, v in payload.items():
        if k not in ("metrics", "oids"):
            flat[str(k)] = v

    lookup: dict[str, Any] = {}
    for raw_k, val in flat.items():
        if val is None:
            continue
        lookup[raw_k] = val
        norm_k = _normalize_lookup_key(raw_k)
        lookup[norm_k] = val
        lookup[norm_k.lower()] = val
        if norm_k.endswith(".0"):
            without_zero = norm_k[:-2]
            lookup.setdefault(without_zero, val)
            lookup.setdefault(without_zero.lower(), val)
        else:
            with_zero = f"{norm_k}.0"
            lookup.setdefault(with_zero, val)
            lookup.setdefault(with_zero.lower(), val)
    return lookup


def _lookup_first(
    lookup: Mapping[str, Any],
    candidates: Sequence[str],
) -> tuple[Optional[str], Any]:
    for candidate in candidates:
        if candidate in lookup:
            return candidate, lookup[candidate]
        lower_cand = candidate.lower()
        if lower_cand in lookup:
            return candidate, lookup[lower_cand]
    return None, None


def _parse_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        cleaned = re.sub(r"\s*(%|c|°c|degc|celsius)$", "", cleaned, flags=re.IGNORECASE).strip()
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def _parse_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        # Handle SNMP enum syntax like "batteryNeedsReplacing(2)"
        match = re.search(r"\((-?\d+)\)\s*$", cleaned)
        if match:
            return int(match.group(1))
        try:
            return int(float(cleaned))
        except ValueError:
            return None
    return None


def _parse_runtime_minutes(raw_value: Any, matched_key: Optional[str]) -> Optional[float]:
    if raw_value is None or isinstance(raw_value, bool):
        return None

    is_snmp_oid_or_mib = False
    if matched_key is not None:
        key_lower = matched_key.lower()
        if (
            "1.3.6.1.4.1.318" in key_lower
            or "upsadvbatteryruntime" in key_lower
            or "timeticks" in key_lower
        ):
            is_snmp_oid_or_mib = True

    if isinstance(raw_value, (int, float)):
        val = float(raw_value)
        if is_snmp_oid_or_mib and val >= 6000.0:
            return round(val / 6000.0, 4)
        return val

    if isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return None

        # Check for SNMP TimeTicks string format: "(72000) 0:12:00.00"
        ticks_match = re.match(r"^\((\d+)\)", text)
        if ticks_match:
            ticks = float(ticks_match.group(1))
            return round(ticks / 6000.0, 4)

        # Check for HH:MM:SS(.cc) or D days, HH:MM:SS
        hms_match = re.search(
            r"(?:(\d+)\s*d(?:ays?)?[,\s]+)?(\d+):(\d{1,2}):(\d{1,2}(?:\.\d+)?)",
            text,
            flags=re.IGNORECASE,
        )
        if hms_match:
            days = float(hms_match.group(1) or 0.0)
            hours = float(hms_match.group(2))
            minutes = float(hms_match.group(3))
            seconds = float(hms_match.group(4))
            return round(days * 1440.0 + hours * 60.0 + minutes + seconds / 60.0, 4)

        # Check for explicit unit suffixes ("12m", "12 min", "720s", "2h")
        unit_match = re.match(
            r"^([+-]?\d+(?:\.\d+)?)\s*(h|hr|hrs|hours?|m|min|mins|minutes?|s|sec|secs|seconds?|ticks|timeticks)$",
            text,
            flags=re.IGNORECASE,
        )
        if unit_match:
            amount = float(unit_match.group(1))
            unit = unit_match.group(2).lower()
            if unit.startswith("h"):
                return round(amount * 60.0, 4)
            if unit.startswith("s"):
                return round(amount / 60.0, 4)
            if unit.startswith("t"):
                return round(amount / 6000.0, 4)
            return amount

        try:
            numeric_val = float(text)
            if is_snmp_oid_or_mib and numeric_val >= 6000.0:
                return round(numeric_val / 6000.0, 4)
            return numeric_val
        except ValueError:
            return None

    return None


def parse_powernet_telemetry(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Parse APC PowerNet-MIB numeric OIDs, symbolic MIB keys, or snake_case telemetry into normalized fields."""
    if not isinstance(payload, Mapping):
        raise TypeError(f"payload must be a Mapping, got {type(payload).__name__}")

    lookup = _build_lookup_map(payload)

    # System & Model identity
    _, raw_sys_name = _lookup_first(
        lookup,
        (
            SNMPV2_MIB_SYS_NAME,
            "sysName",
            "sys_name",
            "hostname",
            "name",
        ),
    )
    _, raw_sys_descr = _lookup_first(
        lookup,
        (
            SNMPV2_MIB_SYS_DESCR,
            "sysDescr",
            "sys_descr",
        ),
    )
    _, raw_sys_uptime = _lookup_first(
        lookup,
        (
            SNMPV2_MIB_SYS_UPTIME,
            "sysUpTime",
            "sys_uptime",
        ),
    )
    _, raw_model = _lookup_first(
        lookup,
        (
            APC_UPS_BASIC_IDENT_MODEL_OID,
            "upsBasicIdentModel",
            "model",
        ),
    )

    # Battery Status (upsBasicBatteryStatus)
    _, raw_batt_status = _lookup_first(
        lookup,
        (
            APC_UPS_BASIC_BATTERY_STATUS_OID,
            "upsBasicBatteryStatus",
            "battery_status_code",
            "battery_status",
        ),
    )
    battery_status_code: Optional[int] = None
    battery_status: Optional[str] = None
    if raw_batt_status is not None:
        parsed_code = _parse_int(raw_batt_status)
        if parsed_code in _BATTERY_STATUS_CODE_TO_NAME:
            battery_status_code = parsed_code
            battery_status = _BATTERY_STATUS_CODE_TO_NAME[parsed_code]
        elif isinstance(raw_batt_status, str):
            clean_str = re.sub(r"\(\d+\)$", "", raw_batt_status.strip()).strip()
            mapped_code = _BATTERY_STATUS_NAME_TO_CODE.get(clean_str.lower().replace("_", ""))
            if mapped_code is not None:
                battery_status_code = mapped_code
                battery_status = _BATTERY_STATUS_CODE_TO_NAME[mapped_code]
            elif clean_str:
                battery_status = clean_str

    # Battery Replace Indicator (upsAdvBatteryReplaceIndicator)
    _, raw_replace = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID,
            "upsAdvBatteryReplaceIndicator",
            "battery_replace_indicator",
            "needs_battery_replacement",
            "battery_needs_replacing",
            "replace_battery",
        ),
    )
    battery_replace_indicator: Optional[int] = None
    needs_battery_replacement: bool = False
    if raw_replace is not None:
        if isinstance(raw_replace, bool):
            needs_battery_replacement = raw_replace
            battery_replace_indicator = 2 if raw_replace else 1
        else:
            parsed_ind = _parse_int(raw_replace)
            if parsed_ind is not None:
                battery_replace_indicator = parsed_ind
                needs_battery_replacement = parsed_ind == 2
            elif isinstance(raw_replace, str):
                clean_rep = re.sub(r"\(\d+\)$", "", raw_replace.strip()).strip().lower()
                mapped_ind = _REPLACE_INDICATOR_NAME_TO_CODE.get(
                    clean_rep.replace("_", "")
                )
                if mapped_ind is not None:
                    battery_replace_indicator = mapped_ind
                    needs_battery_replacement = mapped_ind == 2

    # Battery Capacity (upsAdvBatteryCapacity)
    _, raw_capacity = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_BATTERY_CAPACITY_OID,
            "upsAdvBatteryCapacity",
            "battery_capacity_pct",
            "battery_capacity",
        ),
    )
    battery_capacity_pct = _parse_float(raw_capacity)

    # Battery Temperature (upsAdvBatteryTemperature)
    _, raw_temp = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_BATTERY_TEMPERATURE_OID,
            "upsAdvBatteryTemperature",
            "temperature_celsius",
            "battery_temperature_celsius",
            "temp_celsius",
            "temperature",
        ),
    )
    temperature_celsius = _parse_float(raw_temp)

    # Runtime Remaining (upsAdvBatteryRunTimeRemaining)
    runtime_key, raw_runtime = _lookup_first(
        lookup,
        (
            "runtime_remaining_minutes",
            "runtime_minutes",
            APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID,
            "upsAdvBatteryRunTimeRemaining",
            "runtime_remaining",
        ),
    )
    runtime_remaining_minutes = _parse_runtime_minutes(raw_runtime, runtime_key)

    # Output Load (upsAdvOutputLoad)
    _, raw_load = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_OUTPUT_LOAD_OID,
            "upsAdvOutputLoad",
            "output_load_pct",
            "load_pct",
            "output_load",
        ),
    )
    output_load_pct = _parse_float(raw_load)

    # Input Line Fail Cause (upsAdvInputLineFailCause)
    _, raw_fail_cause = _lookup_first(
        lookup,
        (
            APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID,
            "upsAdvInputLineFailCause",
            "input_line_fail_cause_code",
            "input_line_fail_cause",
        ),
    )
    input_line_fail_cause_code: Optional[int] = None
    input_line_fail_cause: Optional[str] = None
    if raw_fail_cause is not None:
        parsed_cause = _parse_int(raw_fail_cause)
        if parsed_cause in _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME:
            input_line_fail_cause_code = parsed_cause
            input_line_fail_cause = _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME[parsed_cause]
        elif isinstance(raw_fail_cause, str):
            clean_cause = re.sub(r"\(\d+\)$", "", raw_fail_cause.strip()).strip()
            mapped_cause = _INPUT_LINE_FAIL_CAUSE_NAME_TO_CODE.get(
                clean_cause.lower().replace("_", "")
            )
            if mapped_cause is not None:
                input_line_fail_cause_code = mapped_cause
                input_line_fail_cause = _INPUT_LINE_FAIL_CAUSE_CODE_TO_NAME[mapped_cause]
            elif clean_cause:
                input_line_fail_cause = clean_cause

    # Output Status & 64-bit State Flags (upsBasicOutputStatus / upsBasicStateOutputState)
    _, raw_output_status = _lookup_first(
        lookup,
        (
            APC_UPS_BASIC_OUTPUT_STATUS_OID,
            "upsBasicOutputStatus",
            "output_status",
        ),
    )
    _, raw_state_flags = _lookup_first(
        lookup,
        (
            APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
            "upsBasicStateOutputState",
            "output_state_flags",
        ),
    )
    output_state_flags = (
        str(raw_state_flags).strip() if raw_state_flags is not None else ""
    )

    output_status_code: Optional[int] = None
    output_status: Optional[str] = None
    if raw_output_status is not None:
        parsed_out = _parse_int(raw_output_status)
        if parsed_out in _OUTPUT_STATUS_CODE_TO_NAME:
            output_status_code = parsed_out
            output_status = _OUTPUT_STATUS_CODE_TO_NAME[parsed_out]
        elif isinstance(raw_output_status, str):
            clean_out = re.sub(r"\(\d+\)$", "", raw_output_status.strip()).strip()
            canonical_out = _OUTPUT_STATUS_NAME_TO_CANONICAL.get(clean_out.lower())
            output_status = canonical_out if canonical_out is not None else clean_out

    if output_status is None and len(output_state_flags) >= 4:
        if output_state_flags[2] == "1":
            output_status = "onBattery"
            output_status_code = 3
        elif output_state_flags[3] == "1":
            output_status = "onLine"
            output_status_code = 2
        else:
            output_status = "offLine"

    if battery_replace_indicator is None and len(output_state_flags) >= 2:
        if output_state_flags[1] == "1":
            battery_replace_indicator = 2
            needs_battery_replacement = True

    _, raw_on_battery = _lookup_first(lookup, ("on_battery",))
    if isinstance(raw_on_battery, bool):
        on_battery = raw_on_battery
    else:
        on_battery = bool(
            output_status == "onBattery"
            or output_status_code == 3
            or (len(output_state_flags) >= 3 and output_state_flags[2] == "1")
        )

    if on_battery and output_status is None:
        output_status = "onBattery"

    return {
        "vendor": str(payload.get("vendor") or "APC"),
        "sys_name": str(raw_sys_name) if raw_sys_name is not None else None,
        "sys_descr": str(raw_sys_descr) if raw_sys_descr is not None else None,
        "sys_uptime": str(raw_sys_uptime) if raw_sys_uptime is not None else None,
        "model": str(raw_model).strip() if raw_model is not None and str(raw_model).strip() else None,
        "battery_status": battery_status,
        "battery_status_code": battery_status_code,
        "battery_replace_indicator": battery_replace_indicator,
        "needs_battery_replacement": needs_battery_replacement,
        "battery_capacity_pct": battery_capacity_pct,
        "runtime_remaining_minutes": runtime_remaining_minutes,
        "temperature_celsius": temperature_celsius,
        "output_load_pct": output_load_pct,
        "output_status": output_status,
        "output_status_code": output_status_code,
        "output_state_flags": output_state_flags or None,
        "on_battery": on_battery,
        "input_line_fail_cause": input_line_fail_cause,
        "input_line_fail_cause_code": input_line_fail_cause_code,
    }


@dataclass
class UpsHealthRecord:
    """Evaluated battery, runtime, thermal, and load health record for a single APC UPS unit."""

    equipment_id: str
    site_id: str
    name: str
    status: UpsHealthStatus
    ip_address: Optional[str] = None
    vendor: str = "APC"
    model: Optional[str] = None
    reachable: bool = True
    battery_status: Optional[str] = None
    battery_status_code: Optional[int] = None
    battery_replace_indicator: Optional[int] = None
    needs_battery_replacement: bool = False
    battery_capacity_pct: Optional[float] = None
    runtime_remaining_minutes: Optional[float] = None
    temperature_celsius: Optional[float] = None
    output_load_pct: Optional[float] = None
    output_status: Optional[str] = None
    on_battery: bool = False
    input_line_fail_cause: Optional[str] = None
    input_line_fail_cause_code: Optional[int] = None
    is_low_runtime: bool = False
    is_high_temperature: bool = False
    is_high_load: bool = False
    advisories: list[str] = field(default_factory=list)
    details: Optional[str] = None
    signal: Optional[ValidationSignal] = None
    evaluated_at: Optional[datetime] = None
    raw_oids: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.equipment_id, str) or not self.equipment_id.strip():
            raise ValueError("equipment_id must be a non-empty string")
        if not isinstance(self.site_id, str) or not self.site_id.strip():
            raise ValueError("site_id must be a non-empty string")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if not isinstance(self.status, UpsHealthStatus):
            self.status = UpsHealthStatus(str(self.status).upper())
        if self.evaluated_at is not None and not isinstance(self.evaluated_at, datetime):
            self.evaluated_at = normalize_utc_datetime(
                self.evaluated_at, field_name="evaluated_at"
            )
        if self.signal is not None and not isinstance(self.signal, ValidationSignal):
            if isinstance(self.signal, Mapping):
                self.signal = ValidationSignal.from_dict(self.signal)
        self.advisories = [
            adv.value if isinstance(adv, UpsAdvisoryCode) else str(adv)
            for adv in self.advisories
        ]
        self.raw_oids = dict(self.raw_oids) if self.raw_oids else {}

    @property
    def ups_id(self) -> str:
        return self.equipment_id

    @property
    def device_id(self) -> str:
        return self.equipment_id

    @property
    def hostname(self) -> str:
        return self.name

    @property
    def health_status(self) -> UpsHealthStatus:
        return self.status

    @property
    def battery_needs_replacing(self) -> bool:
        return self.needs_battery_replacement

    @property
    def replace_battery(self) -> bool:
        return self.needs_battery_replacement

    @property
    def runtime_minutes(self) -> Optional[float]:
        return self.runtime_remaining_minutes

    @property
    def battery_temperature_celsius(self) -> Optional[float]:
        return self.temperature_celsius

    @property
    def temp_celsius(self) -> Optional[float]:
        return self.temperature_celsius

    @property
    def load_pct(self) -> Optional[float]:
        return self.output_load_pct

    @property
    def low_runtime(self) -> bool:
        return self.is_low_runtime

    @property
    def high_temperature(self) -> bool:
        return self.is_high_temperature

    @property
    def thermal_alert(self) -> bool:
        return self.is_high_temperature

    @property
    def high_load(self) -> bool:
        return self.is_high_load

    @property
    def overload_risk(self) -> bool:
        return self.is_high_load

    def to_dict(self) -> dict[str, Any]:
        return {
            "equipment_id": self.equipment_id,
            "site_id": self.site_id,
            "name": self.name,
            "status": self.status.value,
            "ip_address": self.ip_address,
            "vendor": self.vendor,
            "model": self.model,
            "reachable": self.reachable,
            "battery_status": self.battery_status,
            "battery_status_code": self.battery_status_code,
            "battery_replace_indicator": self.battery_replace_indicator,
            "needs_battery_replacement": self.needs_battery_replacement,
            "battery_capacity_pct": self.battery_capacity_pct,
            "runtime_remaining_minutes": self.runtime_remaining_minutes,
            "temperature_celsius": self.temperature_celsius,
            "output_load_pct": self.output_load_pct,
            "output_status": self.output_status,
            "on_battery": self.on_battery,
            "input_line_fail_cause": self.input_line_fail_cause,
            "input_line_fail_cause_code": self.input_line_fail_cause_code,
            "is_low_runtime": self.is_low_runtime,
            "is_high_temperature": self.is_high_temperature,
            "is_high_load": self.is_high_load,
            "advisories": list(self.advisories),
            "details": self.details,
            "signal": self.signal.to_dict() if self.signal is not None else None,
            "evaluated_at": (
                self.evaluated_at.isoformat() if self.evaluated_at is not None else None
            ),
            "raw_oids": dict(self.raw_oids),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UpsHealthRecord:
        raw_signal = data.get("signal")
        signal = (
            raw_signal
            if isinstance(raw_signal, ValidationSignal) or raw_signal is None
            else ValidationSignal.from_dict(raw_signal)
        )
        raw_eval = data.get("evaluated_at")
        evaluated_at = (
            normalize_utc_datetime(raw_eval, field_name="evaluated_at")
            if raw_eval is not None
            else None
        )
        return cls(
            equipment_id=str(data["equipment_id"]),
            site_id=str(data["site_id"]),
            name=str(data["name"]),
            status=UpsHealthStatus(str(data["status"])),
            ip_address=data.get("ip_address"),
            vendor=str(data.get("vendor", "APC")),
            model=data.get("model"),
            reachable=bool(data.get("reachable", True)),
            battery_status=data.get("battery_status"),
            battery_status_code=data.get("battery_status_code"),
            battery_replace_indicator=data.get("battery_replace_indicator"),
            needs_battery_replacement=bool(data.get("needs_battery_replacement", False)),
            battery_capacity_pct=data.get("battery_capacity_pct"),
            runtime_remaining_minutes=data.get("runtime_remaining_minutes"),
            temperature_celsius=data.get("temperature_celsius"),
            output_load_pct=data.get("output_load_pct"),
            output_status=data.get("output_status"),
            on_battery=bool(data.get("on_battery", False)),
            input_line_fail_cause=data.get("input_line_fail_cause"),
            input_line_fail_cause_code=data.get("input_line_fail_cause_code"),
            is_low_runtime=bool(data.get("is_low_runtime", False)),
            is_high_temperature=bool(data.get("is_high_temperature", False)),
            is_high_load=bool(data.get("is_high_load", False)),
            advisories=list(data.get("advisories", [])),
            details=data.get("details"),
            signal=signal,
            evaluated_at=evaluated_at,
            raw_oids=dict(data.get("raw_oids") or {}),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> UpsHealthRecord:
        return cls.from_dict(json.loads(raw))


@dataclass
class UpsFleetHealthReport:
    """Fleet-wide and per-site aggregated APC UPS health telemetry report."""

    records: list[UpsHealthRecord] = field(default_factory=list)
    total_units: int = 0
    healthy_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    unreachable_count: int = 0
    battery_replacement_units: list[UpsHealthRecord] = field(default_factory=list)
    low_runtime_units: list[UpsHealthRecord] = field(default_factory=list)
    thermal_alert_units: list[UpsHealthRecord] = field(default_factory=list)
    high_load_units: list[UpsHealthRecord] = field(default_factory=list)
    on_battery_units: list[UpsHealthRecord] = field(default_factory=list)
    by_site: dict[str, dict[str, Any]] = field(default_factory=dict)
    evaluated_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.records = [
            r if isinstance(r, UpsHealthRecord) else UpsHealthRecord.from_dict(r)
            for r in self.records
        ]
        if self.evaluated_at is not None and not isinstance(self.evaluated_at, datetime):
            self.evaluated_at = normalize_utc_datetime(
                self.evaluated_at, field_name="evaluated_at"
            )

        if self.records:
            self.total_units = len(self.records)
            self.healthy_count = sum(
                1 for r in self.records if r.status is UpsHealthStatus.HEALTHY
            )
            self.warning_count = sum(
                1 for r in self.records if r.status is UpsHealthStatus.WARNING
            )
            self.critical_count = sum(
                1 for r in self.records if r.status is UpsHealthStatus.CRITICAL
            )
            self.unreachable_count = sum(
                1 for r in self.records if r.status is UpsHealthStatus.UNREACHABLE
            )
            if not self.battery_replacement_units:
                self.battery_replacement_units = [
                    r
                    for r in self.records
                    if r.needs_battery_replacement
                    or UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED.value in r.advisories
                ]
            if not self.low_runtime_units:
                self.low_runtime_units = [
                    r
                    for r in self.records
                    if r.is_low_runtime
                    or UpsAdvisoryCode.LOW_RUNTIME_WARNING.value in r.advisories
                    or UpsAdvisoryCode.CRITICAL_RUNTIME.value in r.advisories
                ]
            if not self.thermal_alert_units:
                self.thermal_alert_units = [
                    r
                    for r in self.records
                    if r.is_high_temperature
                    or UpsAdvisoryCode.HIGH_TEMP_WARNING.value in r.advisories
                    or UpsAdvisoryCode.HIGH_TEMP_CRITICAL.value in r.advisories
                ]
            if not self.high_load_units:
                self.high_load_units = [
                    r
                    for r in self.records
                    if r.is_high_load
                    or UpsAdvisoryCode.HIGH_LOAD_WARNING.value in r.advisories
                    or UpsAdvisoryCode.OVERLOAD_CRITICAL.value in r.advisories
                ]
            if not self.on_battery_units:
                self.on_battery_units = [
                    r
                    for r in self.records
                    if r.on_battery
                    or UpsAdvisoryCode.ON_BATTERY_ALERT.value in r.advisories
                ]
            if not self.by_site:
                site_map: dict[str, list[UpsHealthRecord]] = {}
                for rec in self.records:
                    site_map.setdefault(rec.site_id, []).append(rec)
                self.by_site = {
                    site_id: {
                        "site_id": site_id,
                        "total_units": len(site_recs),
                        "healthy_count": sum(
                            1
                            for r in site_recs
                            if r.status is UpsHealthStatus.HEALTHY
                        ),
                        "warning_count": sum(
                            1
                            for r in site_recs
                            if r.status is UpsHealthStatus.WARNING
                        ),
                        "critical_count": sum(
                            1
                            for r in site_recs
                            if r.status is UpsHealthStatus.CRITICAL
                        ),
                        "unreachable_count": sum(
                            1
                            for r in site_recs
                            if r.status is UpsHealthStatus.UNREACHABLE
                        ),
                        "battery_replacement_count": sum(
                            1 for r in site_recs if r.needs_battery_replacement
                        ),
                        "low_runtime_count": sum(
                            1 for r in site_recs if r.is_low_runtime
                        ),
                        "thermal_alert_count": sum(
                            1 for r in site_recs if r.is_high_temperature
                        ),
                        "high_load_count": sum(
                            1 for r in site_recs if r.is_high_load
                        ),
                        "on_battery_count": sum(
                            1 for r in site_recs if r.on_battery
                        ),
                        "equipment_ids": [r.equipment_id for r in site_recs],
                    }
                    for site_id, site_recs in site_map.items()
                }

    @property
    def units(self) -> list[UpsHealthRecord]:
        return self.records

    @property
    def results(self) -> list[UpsHealthRecord]:
        return self.records

    @property
    def total_ups_count(self) -> int:
        return self.total_units

    @property
    def healthy_units(self) -> list[UpsHealthRecord]:
        return [r for r in self.records if r.status is UpsHealthStatus.HEALTHY]

    @property
    def warning_units(self) -> list[UpsHealthRecord]:
        return [r for r in self.records if r.status is UpsHealthStatus.WARNING]

    @property
    def critical_units(self) -> list[UpsHealthRecord]:
        return [r for r in self.records if r.status is UpsHealthStatus.CRITICAL]

    @property
    def unreachable_units(self) -> list[UpsHealthRecord]:
        return [r for r in self.records if r.status is UpsHealthStatus.UNREACHABLE]

    @property
    def units_needing_battery_replacement(self) -> list[UpsHealthRecord]:
        return self.battery_replacement_units

    @property
    def battery_replacement_count(self) -> int:
        return len(self.battery_replacement_units)

    @property
    def low_runtime_count(self) -> int:
        return len(self.low_runtime_units)

    @property
    def thermal_alerts(self) -> list[UpsHealthRecord]:
        return self.thermal_alert_units

    @property
    def high_temperature_units(self) -> list[UpsHealthRecord]:
        return self.thermal_alert_units

    @property
    def high_temp_units(self) -> list[UpsHealthRecord]:
        return self.thermal_alert_units

    @property
    def thermal_alert_count(self) -> int:
        return len(self.thermal_alert_units)

    @property
    def high_temp_count(self) -> int:
        return len(self.thermal_alert_units)

    @property
    def overload_units(self) -> list[UpsHealthRecord]:
        return self.high_load_units

    @property
    def high_load_count(self) -> int:
        return len(self.high_load_units)

    @property
    def overload_count(self) -> int:
        return len(self.high_load_units)

    @property
    def on_battery_count(self) -> int:
        return len(self.on_battery_units)

    @property
    def site_summaries(self) -> dict[str, dict[str, Any]]:
        return self.by_site

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [r.to_dict() for r in self.records],
            "total_units": self.total_units,
            "healthy_count": self.healthy_count,
            "warning_count": self.warning_count,
            "critical_count": self.critical_count,
            "unreachable_count": self.unreachable_count,
            "battery_replacement_units": [
                r.to_dict() for r in self.battery_replacement_units
            ],
            "low_runtime_units": [r.to_dict() for r in self.low_runtime_units],
            "thermal_alert_units": [r.to_dict() for r in self.thermal_alert_units],
            "high_load_units": [r.to_dict() for r in self.high_load_units],
            "on_battery_units": [r.to_dict() for r in self.on_battery_units],
            "by_site": dict(self.by_site),
            "evaluated_at": (
                self.evaluated_at.isoformat() if self.evaluated_at is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> UpsFleetHealthReport:
        records = [
            r if isinstance(r, UpsHealthRecord) else UpsHealthRecord.from_dict(r)
            for r in data.get("records", [])
        ]
        raw_eval = data.get("evaluated_at")
        evaluated_at = (
            normalize_utc_datetime(raw_eval, field_name="evaluated_at")
            if raw_eval is not None
            else None
        )
        return cls(
            records=records,
            evaluated_at=evaluated_at,
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> UpsFleetHealthReport:
        return cls.from_dict(json.loads(raw))


def _has_powernet_keys(telemetry: Optional[Mapping[str, Any]]) -> bool:
    if not isinstance(telemetry, Mapping):
        return False
    oids = telemetry.get("oids")
    search_space: list[str] = [str(k) for k in telemetry.keys()]
    if isinstance(oids, Mapping):
        search_space.extend(str(k) for k in oids.keys())
    ent_prefix = str(telemetry.get("enterprise_oid_prefix") or "")
    if ent_prefix.startswith(APC_ENTERPRISE_OID_PREFIX):
        return True
    for k in search_space:
        norm = _normalize_lookup_key(k)
        if norm.startswith(APC_ENTERPRISE_OID_PREFIX):
            return True
        lower_k = norm.lower()
        if lower_k.startswith(("upsbasic", "upsadv")):
            return True
    sys_descr = str(
        telemetry.get(SNMPV2_MIB_SYS_DESCR)
        or (oids.get(SNMPV2_MIB_SYS_DESCR) if isinstance(oids, Mapping) else "")
        or telemetry.get("sysDescr")
        or telemetry.get("sys_descr")
        or ""
    ).lower()
    if any(token in sys_descr for token in ("apc", "smart-ups", "symmetra", "powernet")):
        return True
    return False


class ApcUpsHealthEvaluator(SignalCollector):
    """APC UPS battery, runtime, load, and environmental health evaluator (PowerNet-MIB)."""

    signal_type: SignalType = SignalType.SNMP_API_REACHABILITY

    def __init__(
        self,
        min_runtime_minutes: float = 15.0,
        critical_runtime_minutes: Optional[float] = 5.0,
        max_temp_celsius: float = 40.0,
        critical_temp_celsius: Optional[float] = 50.0,
        max_load_pct: float = 80.0,
        critical_load_pct: Optional[float] = 95.0,
        *,
        telemetry_by_target: Optional[Mapping[str, Any]] = None,
        telemetry: Optional[Mapping[str, Any]] = None,
        fixtures: Optional[Mapping[str, Any]] = None,
        snmp_connector: Optional[Any] = None,
        transport: Optional[Any] = None,
        snmp_probe_fn: Optional[Callable[..., Optional[Mapping[str, Any]]]] = None,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "apc_ups_health",
    ) -> None:
        if (
            isinstance(min_runtime_minutes, bool)
            or not isinstance(min_runtime_minutes, (int, float))
            or min_runtime_minutes <= 0
        ):
            raise ValueError("min_runtime_minutes must be a number > 0")
        self.min_runtime_minutes: float = float(min_runtime_minutes)

        if critical_runtime_minutes is not None:
            if (
                isinstance(critical_runtime_minutes, bool)
                or not isinstance(critical_runtime_minutes, (int, float))
                or critical_runtime_minutes < 0
                or critical_runtime_minutes > self.min_runtime_minutes
            ):
                raise ValueError(
                    "critical_runtime_minutes must be >= 0 and <= min_runtime_minutes"
                )
            self.critical_runtime_minutes: Optional[float] = float(
                critical_runtime_minutes
            )
        else:
            self.critical_runtime_minutes = None

        if (
            isinstance(max_temp_celsius, bool)
            or not isinstance(max_temp_celsius, (int, float))
            or max_temp_celsius <= 0
        ):
            raise ValueError("max_temp_celsius must be a number > 0")
        self.max_temp_celsius: float = float(max_temp_celsius)

        if critical_temp_celsius is not None:
            if (
                isinstance(critical_temp_celsius, bool)
                or not isinstance(critical_temp_celsius, (int, float))
                or critical_temp_celsius < self.max_temp_celsius
            ):
                raise ValueError(
                    "critical_temp_celsius must be >= max_temp_celsius"
                )
            self.critical_temp_celsius: Optional[float] = float(critical_temp_celsius)
        else:
            self.critical_temp_celsius = None

        if (
            isinstance(max_load_pct, bool)
            or not isinstance(max_load_pct, (int, float))
            or not (0 < max_load_pct <= 100)
        ):
            raise ValueError("max_load_pct must be between 0 (exclusive) and 100")
        self.max_load_pct: float = float(max_load_pct)

        if critical_load_pct is not None:
            if (
                isinstance(critical_load_pct, bool)
                or not isinstance(critical_load_pct, (int, float))
                or critical_load_pct < self.max_load_pct
                or critical_load_pct > 100
            ):
                raise ValueError(
                    "critical_load_pct must be >= max_load_pct and <= 100"
                )
            self.critical_load_pct: Optional[float] = float(critical_load_pct)
        else:
            self.critical_load_pct = None

        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source: str = source
        self.snmp_connector: Optional[Any] = (
            snmp_connector if snmp_connector is not None else transport
        )
        self.snmp_probe_fn: Optional[Callable[..., Optional[Mapping[str, Any]]]] = (
            snmp_probe_fn
        )

        raw_telemetry = (
            telemetry_by_target
            if telemetry_by_target is not None
            else (telemetry if telemetry is not None else fixtures)
        )
        self._telemetry_by_key: dict[str, Mapping[str, Any]] = {}
        self._raw_targets: dict[str, Mapping[str, Any]] = {}
        self._default_site_id: Optional[str] = None
        if isinstance(raw_telemetry, Mapping):
            self._ingest_telemetry_mapping(raw_telemetry)

    def _ingest_telemetry_mapping(self, mapping: Mapping[str, Any]) -> None:
        if "site_id" in mapping and isinstance(mapping.get("site_id"), str):
            self._default_site_id = str(mapping["site_id"])

        targets_dict = (
            mapping["targets"]
            if "targets" in mapping and isinstance(mapping["targets"], Mapping)
            else mapping
        )
        for key, entry in targets_dict.items():
            if not isinstance(entry, Mapping):
                continue
            key_str = str(key).strip()
            self._raw_targets[key_str] = entry
            self._telemetry_by_key[key_str] = entry
            self._telemetry_by_key[key_str.lower()] = entry
            for alias_field in ("target_id", "equipment_id", "hostname", "name", "ip_address", "ip"):
                alias_val = entry.get(alias_field)
                if isinstance(alias_val, str) and alias_val.strip():
                    clean_alias = alias_val.strip()
                    self._telemetry_by_key[clean_alias] = entry
                    self._telemetry_by_key[clean_alias.lower()] = entry

    @classmethod
    def from_fixture_file(
        cls,
        fixture_path: str | pathlib.Path,
        **kwargs: Any,
    ) -> ApcUpsHealthEvaluator:
        """Create an ApcUpsHealthEvaluator loaded from an SNMP discovery fixture JSON file."""
        raw = json.loads(pathlib.Path(fixture_path).read_text(encoding="utf-8"))
        return cls(telemetry_by_target=raw, **kwargs)

    @staticmethod
    def is_apc_ups(
        item: Any,
        telemetry: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Return True if `item` or `telemetry` represents an APC UPS unit."""
        if isinstance(item, Equipment):
            if item.category is EquipmentCategory.UPS:
                return True
            name_lower = item.name.lower()
            if any(tok in name_lower for tok in ("apc", "smart-ups", "symmetra", "ups")):
                return True
            return _has_powernet_keys(telemetry)

        if isinstance(item, Mapping):
            cat = item.get("category") or item.get("equipment_type") or item.get("type")
            if isinstance(cat, EquipmentCategory) and cat is EquipmentCategory.UPS:
                return True
            if isinstance(cat, str) and cat.strip().lower() == "ups":
                return True
            for field_name in ("vendor", "model", "name", "hostname"):
                val = item.get(field_name)
                if isinstance(val, str) and any(
                    tok in val.lower() for tok in ("apc", "smart-ups", "symmetra")
                ):
                    return True
            if _has_powernet_keys(item):
                return True

        return _has_powernet_keys(telemetry)

    def _extract_equipment_identity(
        self,
        equipment: Any,
        telemetry: Optional[Mapping[str, Any]] = None,
        site_id: Optional[str] = None,
    ) -> tuple[str, str, str, list[str], Optional[str], Optional[str]]:
        """Return (equipment_id, resolved_site_id, name, ips, vendor, model)."""
        ips: list[str] = []
        vendor: Optional[str] = None
        model: Optional[str] = None

        if isinstance(equipment, Equipment):
            eq_id = equipment.equipment_id
            resolved_site = site_id or equipment.site_id or self._default_site_id or "site-unknown"
            name = equipment.name
            ips = [ip.strip() for ip in equipment.assigned_ips if ip and ip.strip()]
        elif isinstance(equipment, Mapping):
            eq_id = str(
                equipment.get("equipment_id")
                or equipment.get("target_id")
                or equipment.get("ups_id")
                or equipment.get("device_id")
                or equipment.get("id")
                or equipment.get("hostname")
                or equipment.get("name")
                or "ups-unknown"
            )
            resolved_site = str(
                site_id
                or equipment.get("site_id")
                or self._default_site_id
                or "site-unknown"
            )
            name = str(
                equipment.get("name")
                or equipment.get("hostname")
                or eq_id
            )
            raw_ips = equipment.get("assigned_ips")
            if isinstance(raw_ips, Sequence) and not isinstance(raw_ips, (str, bytes)):
                ips.extend(str(ip).strip() for ip in raw_ips if ip and str(ip).strip())
            for single_ip_key in ("ip_address", "ip", "management_ip"):
                single_ip = equipment.get(single_ip_key)
                if isinstance(single_ip, str) and single_ip.strip():
                    if single_ip.strip() not in ips:
                        ips.append(single_ip.strip())
            if isinstance(equipment.get("vendor"), str):
                vendor = equipment["vendor"]
            if isinstance(equipment.get("model"), str):
                model = equipment["model"]
        elif isinstance(equipment, str):
            eq_id = equipment.strip()
            resolved_site = site_id or self._default_site_id or "site-unknown"
            name = eq_id
        else:
            raise TypeError(
                f"Unsupported equipment target type: {type(equipment).__name__}"
            )

        if isinstance(telemetry, Mapping):
            if not ips:
                for ip_key in ("ip_address", "ip"):
                    t_ip = telemetry.get(ip_key)
                    if isinstance(t_ip, str) and t_ip.strip():
                        ips.append(t_ip.strip())
            if vendor is None and isinstance(telemetry.get("vendor"), str):
                vendor = telemetry["vendor"]
            if model is None and isinstance(telemetry.get("model"), str):
                model = telemetry["model"]
            if name == eq_id and isinstance(telemetry.get("hostname"), str):
                name = telemetry["hostname"]

        return eq_id, resolved_site, name, ips, vendor, model

    def _resolve_telemetry(
        self,
        equipment_id: str,
        name: str,
        ips: Sequence[str],
        explicit_telemetry: Optional[Mapping[str, Any]],
        equipment_obj: Any,
    ) -> Optional[Mapping[str, Any]]:
        if explicit_telemetry is not None:
            return explicit_telemetry

        if isinstance(equipment_obj, Mapping) and (
            "oids" in equipment_obj
            or "metrics" in equipment_obj
            or _has_powernet_keys(equipment_obj)
            or "snmp_reachable" in equipment_obj
            or "reachable" in equipment_obj
        ):
            return equipment_obj

        lookup_candidates = [equipment_id, name, *ips]
        for cand in lookup_candidates:
            if not cand:
                continue
            matched = self._telemetry_by_key.get(cand) or self._telemetry_by_key.get(
                cand.lower()
            )
            if matched is not None:
                return matched

        if self.snmp_probe_fn is not None:
            validate_readonly_snmp_request(operation="GET", mode="readonly")
            targets_to_try = list(ips) if ips else [equipment_id]
            for target in targets_to_try:
                sig = inspect.signature(self.snmp_probe_fn)
                pos_params = [
                    p
                    for p in sig.parameters.values()
                    if p.kind
                    in (
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                ]
                has_varargs = any(
                    p.kind == inspect.Parameter.VAR_POSITIONAL
                    for p in sig.parameters.values()
                )
                if len(pos_params) >= 2 or has_varargs:
                    res = self.snmp_probe_fn(target, list(APC_UPS_HEALTH_OIDS))
                else:
                    res = self.snmp_probe_fn(target)
                if res:
                    return res

        if self.snmp_connector is not None:
            targets_to_try = list(ips) if ips else [equipment_id]
            for target in targets_to_try:
                if hasattr(self.snmp_connector, "query_snmp"):
                    res = self.snmp_connector.query_snmp(target, operation="GET")
                    if res:
                        return res
                elif hasattr(self.snmp_connector, "walk_apc_ups"):
                    res = self.snmp_connector.walk_apc_ups(target)
                    if res:
                        return res
                elif hasattr(self.snmp_connector, "get"):
                    res = self.snmp_connector.get(target, APC_UPS_HEALTH_OIDS)
                    if res:
                        return res
                elif hasattr(self.snmp_connector, "query"):
                    res = self.snmp_connector.query(
                        target, APC_UPS_HEALTH_OIDS, operation="GET"
                    )
                    if res:
                        return res
                elif callable(self.snmp_connector):
                    res = self.snmp_connector(target, APC_UPS_HEALTH_OIDS)
                    if res:
                        return res

        return None

    def evaluate_unit(
        self,
        equipment: Any,
        telemetry: Optional[Mapping[str, Any]] = None,
        *,
        site_id: Optional[str] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> UpsHealthRecord:
        """Evaluate APC PowerNet-MIB health telemetry for a single UPS unit."""
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (self.evaluation_time or resolve_evaluation_time(None))
        )

        eq_id, resolved_site_id, name, ips, eq_vendor, eq_model = (
            self._extract_equipment_identity(equipment, telemetry, site_id=site_id)
        )
        resolved_telemetry = self._resolve_telemetry(
            eq_id, name, ips, telemetry, equipment
        )
        # Update ips/vendor/model if resolved_telemetry provided additional metadata
        if isinstance(resolved_telemetry, Mapping):
            if not ips:
                for ip_key in ("ip_address", "ip"):
                    t_ip = resolved_telemetry.get(ip_key)
                    if isinstance(t_ip, str) and t_ip.strip():
                        ips.append(t_ip.strip())
            if eq_vendor is None and isinstance(resolved_telemetry.get("vendor"), str):
                eq_vendor = resolved_telemetry["vendor"]
            if eq_model is None and isinstance(resolved_telemetry.get("model"), str):
                eq_model = resolved_telemetry["model"]
            if name == eq_id and isinstance(resolved_telemetry.get("hostname"), str):
                name = resolved_telemetry["hostname"]

        primary_ip = ips[0] if ips else None

        # Check reachability
        explicit_unreachable = False
        if resolved_telemetry is not None:
            if resolved_telemetry.get("snmp_reachable") is False or (
                resolved_telemetry.get("reachable") is False
            ):
                explicit_unreachable = True
            elif (
                "oids" in resolved_telemetry
                and isinstance(resolved_telemetry["oids"], Mapping)
                and not resolved_telemetry["oids"]
            ):
                explicit_unreachable = True

        if resolved_telemetry is None or not resolved_telemetry or explicit_unreachable:
            advisories = [UpsAdvisoryCode.UNREACHABLE.value]
            details = (
                f"APC UPS {eq_id} ({name}) at {primary_ip or 'no-ip'} is unreachable via SNMP"
            )
            signal = ValidationSignal(
                signal_type=SignalType.SNMP_API_REACHABILITY,
                status=SignalStatus.UNREACHABLE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=details,
                source=self.source,
                metadata={
                    "equipment_id": eq_id,
                    "site_id": resolved_site_id,
                    "health_status": UpsHealthStatus.UNREACHABLE.value,
                    "advisories": list(advisories),
                    "needs_battery_replacement": False,
                    "runtime_remaining_minutes": None,
                    "temperature_celsius": None,
                    "output_load_pct": None,
                    "battery_status": None,
                    "output_status": None,
                    "input_line_fail_cause": None,
                },
            )
            return UpsHealthRecord(
                equipment_id=eq_id,
                site_id=resolved_site_id,
                name=name,
                status=UpsHealthStatus.UNREACHABLE,
                ip_address=primary_ip,
                vendor=eq_vendor or "APC",
                model=eq_model,
                reachable=False,
                advisories=advisories,
                details=details,
                signal=signal,
                evaluated_at=eval_dt,
                raw_oids={},
            )

        parsed = parse_powernet_telemetry(resolved_telemetry)
        raw_oids_dict = (
            dict(resolved_telemetry["oids"])
            if isinstance(resolved_telemetry.get("oids"), Mapping)
            else dict(resolved_telemetry)
        )

        vendor = eq_vendor or parsed.get("vendor") or "APC"
        model = parsed.get("model") or eq_model
        battery_status = parsed.get("battery_status")
        battery_status_code = parsed.get("battery_status_code")
        battery_replace_indicator = parsed.get("battery_replace_indicator")
        needs_battery_replacement = bool(parsed.get("needs_battery_replacement", False))
        battery_capacity_pct = parsed.get("battery_capacity_pct")
        runtime_remaining_minutes = parsed.get("runtime_remaining_minutes")
        temperature_celsius = parsed.get("temperature_celsius")
        output_load_pct = parsed.get("output_load_pct")
        output_status = parsed.get("output_status")
        on_battery = bool(parsed.get("on_battery", False))
        input_line_fail_cause = parsed.get("input_line_fail_cause")
        input_line_fail_cause_code = parsed.get("input_line_fail_cause_code")

        advisories: list[str] = []
        severity_rank = 0  # 0=HEALTHY, 1=WARNING, 2=CRITICAL
        is_low_runtime = False
        is_high_temperature = False
        is_high_load = False

        def _escalate(rank: int) -> None:
            nonlocal severity_rank
            if rank > severity_rank:
                severity_rank = rank

        def _add_advisory(code: UpsAdvisoryCode) -> None:
            if code.value not in advisories:
                advisories.append(code.value)

        # 1. Battery replacement indicator
        if needs_battery_replacement or battery_replace_indicator == 2:
            needs_battery_replacement = True
            _add_advisory(UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED)
            _escalate(2)

        # 2. Battery status (1=unknown, 2=batteryNormal, 3=batteryLow, 4=batteryInFaultCondition)
        if battery_status_code == 4 or battery_status == "batteryInFaultCondition":
            _add_advisory(UpsAdvisoryCode.BATTERY_FAULT)
            _escalate(2)
        elif battery_status_code == 3 or battery_status == "batteryLow":
            _add_advisory(UpsAdvisoryCode.BATTERY_LOW)
            if on_battery:
                _escalate(2)
            else:
                _escalate(1)

        # 3. Runtime remaining
        if runtime_remaining_minutes is not None:
            if runtime_remaining_minutes < self.min_runtime_minutes:
                is_low_runtime = True
                _add_advisory(UpsAdvisoryCode.LOW_RUNTIME_WARNING)
                _escalate(1)
            if (
                self.critical_runtime_minutes is not None
                and runtime_remaining_minutes < self.critical_runtime_minutes
            ):
                is_low_runtime = True
                _add_advisory(UpsAdvisoryCode.CRITICAL_RUNTIME)
                _escalate(2)

        # 4. Temperature
        if temperature_celsius is not None:
            if temperature_celsius > self.max_temp_celsius:
                is_high_temperature = True
                _add_advisory(UpsAdvisoryCode.HIGH_TEMP_WARNING)
                _escalate(1)
            if (
                self.critical_temp_celsius is not None
                and temperature_celsius > self.critical_temp_celsius
            ):
                is_high_temperature = True
                _add_advisory(UpsAdvisoryCode.HIGH_TEMP_CRITICAL)
                _escalate(2)

        # 5. Output load
        if output_load_pct is not None:
            if output_load_pct > self.max_load_pct:
                is_high_load = True
                _add_advisory(UpsAdvisoryCode.HIGH_LOAD_WARNING)
                _escalate(1)
            if (
                self.critical_load_pct is not None
                and output_load_pct > self.critical_load_pct
            ):
                is_high_load = True
                _add_advisory(UpsAdvisoryCode.OVERLOAD_CRITICAL)
                _escalate(2)

        # 6. Output status & input line fail cause
        if on_battery:
            _add_advisory(UpsAdvisoryCode.ON_BATTERY_ALERT)
            _escalate(1)

        if (
            input_line_fail_cause is not None
            and input_line_fail_cause not in ("noTransfer", "selfTest")
            and (on_battery or output_status not in ("onLine", None))
        ):
            _add_advisory(UpsAdvisoryCode.INPUT_LINE_FAIL)
            _escalate(1)

        if severity_rank >= 2:
            status = UpsHealthStatus.CRITICAL
        elif severity_rank == 1:
            status = UpsHealthStatus.WARNING
        else:
            status = UpsHealthStatus.HEALTHY

        advisory_str = ", ".join(advisories) if advisories else "none"
        details = (
            f"APC UPS {eq_id} ({name}) status={status.value} "
            f"(model={model or 'unknown'}, output={output_status or 'unknown'}, "
            f"battery_status={battery_status or 'unknown'}, "
            f"replace_battery={needs_battery_replacement}, "
            f"runtime_min={runtime_remaining_minutes}, "
            f"temp_c={temperature_celsius}, "
            f"load_pct={output_load_pct}, "
            f"advisories=[{advisory_str}])"
        )

        signal = ValidationSignal(
            signal_type=SignalType.SNMP_API_REACHABILITY,
            status=SignalStatus.ACTIVE,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=details,
            source=self.source,
            metadata={
                "equipment_id": eq_id,
                "site_id": resolved_site_id,
                "health_status": status.value,
                "advisories": list(advisories),
                "needs_battery_replacement": needs_battery_replacement,
                "runtime_remaining_minutes": runtime_remaining_minutes,
                "temperature_celsius": temperature_celsius,
                "output_load_pct": output_load_pct,
                "battery_capacity_pct": battery_capacity_pct,
                "battery_status": battery_status,
                "output_status": output_status,
                "on_battery": on_battery,
                "input_line_fail_cause": input_line_fail_cause,
            },
        )

        return UpsHealthRecord(
            equipment_id=eq_id,
            site_id=resolved_site_id,
            name=name,
            status=status,
            ip_address=primary_ip,
            vendor=vendor,
            model=model,
            reachable=True,
            battery_status=battery_status,
            battery_status_code=battery_status_code,
            battery_replace_indicator=battery_replace_indicator,
            needs_battery_replacement=needs_battery_replacement,
            battery_capacity_pct=battery_capacity_pct,
            runtime_remaining_minutes=runtime_remaining_minutes,
            temperature_celsius=temperature_celsius,
            output_load_pct=output_load_pct,
            output_status=output_status,
            on_battery=on_battery,
            input_line_fail_cause=input_line_fail_cause,
            input_line_fail_cause_code=input_line_fail_cause_code,
            is_low_runtime=is_low_runtime,
            is_high_temperature=is_high_temperature,
            is_high_load=is_high_load,
            advisories=advisories,
            details=details,
            signal=signal,
            evaluated_at=eval_dt,
            raw_oids=raw_oids_dict,
        )

    evaluate_equipment = evaluate_unit
    evaluate_ups = evaluate_unit

    def evaluate(self, target: Any, **kwargs: Any) -> ValidationSignal:
        """Evaluate the validation signal for an APC UPS inventory target."""
        record = self.evaluate_unit(target, **kwargs)
        assert record.signal is not None
        return record.signal

    def evaluate_site(
        self,
        site: Site | Sequence[Any] | Mapping[str, Any],
        telemetry_by_target: Optional[Mapping[str, Any]] = None,
        *,
        evaluation_time: Optional[datetime | str] = None,
    ) -> UpsFleetHealthReport:
        """Evaluate all APC UPS units in a Site and return an aggregated UpsFleetHealthReport."""
        return self.evaluate_fleet(
            site,
            telemetry_by_target=telemetry_by_target,
            evaluation_time=evaluation_time,
        )

    def evaluate_fleet(
        self,
        sites_or_units: Any = None,
        telemetry_by_target: Optional[Mapping[str, Any]] = None,
        *,
        evaluation_time: Optional[datetime | str] = None,
    ) -> UpsFleetHealthReport:
        """Evaluate APC UPS units across one or more Sites or equipment collections."""
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (self.evaluation_time or resolve_evaluation_time(None))
        )

        extra_lookup: dict[str, Mapping[str, Any]] = {}
        if isinstance(telemetry_by_target, Mapping):
            targets_sub = (
                telemetry_by_target["targets"]
                if "targets" in telemetry_by_target
                and isinstance(telemetry_by_target["targets"], Mapping)
                else telemetry_by_target
            )
            for k, v in targets_sub.items():
                if isinstance(v, Mapping):
                    extra_lookup[str(k)] = v
                    extra_lookup[str(k).lower()] = v
                    for alias_field in (
                        "target_id",
                        "equipment_id",
                        "hostname",
                        "name",
                        "ip_address",
                        "ip",
                    ):
                        alias_val = v.get(alias_field)
                        if isinstance(alias_val, str) and alias_val.strip():
                            extra_lookup[alias_val.strip()] = v
                            extra_lookup[alias_val.strip().lower()] = v

        def _find_telemetry_for_item(item: Any) -> Optional[Mapping[str, Any]]:
            eq_id, _, name, ips, _, _ = self._extract_equipment_identity(item)
            for cand in (eq_id, name, *ips):
                if not cand:
                    continue
                if cand in extra_lookup:
                    return extra_lookup[cand]
                if cand.lower() in extra_lookup:
                    return extra_lookup[cand.lower()]
                if cand in self._telemetry_by_key:
                    return self._telemetry_by_key[cand]
                if cand.lower() in self._telemetry_by_key:
                    return self._telemetry_by_key[cand.lower()]
            return None

        records: list[UpsHealthRecord] = []

        def _process_candidate(item: Any, default_site_id: Optional[str] = None) -> None:
            t_data = _find_telemetry_for_item(item)
            if not self.is_apc_ups(item, t_data):
                return
            rec = self.evaluate_unit(
                item,
                telemetry=t_data,
                site_id=default_site_id,
                evaluation_time=eval_dt,
            )
            records.append(rec)

        if sites_or_units is None:
            # Evaluate all APC UPS targets loaded in self._raw_targets
            for target_id, entry in self._raw_targets.items():
                if self.is_apc_ups(entry, entry):
                    target_dict = dict(entry)
                    target_dict.setdefault("equipment_id", target_id)
                    records.append(
                        self.evaluate_unit(
                            target_dict,
                            telemetry=entry,
                            site_id=self._default_site_id,
                            evaluation_time=eval_dt,
                        )
                    )
        elif isinstance(sites_or_units, Site):
            for eq in sites_or_units.equipment:
                _process_candidate(eq, default_site_id=sites_or_units.site_id)
        elif isinstance(sites_or_units, Equipment):
            _process_candidate(sites_or_units)
        elif isinstance(sites_or_units, Mapping):
            if "equipment" in sites_or_units and isinstance(
                sites_or_units["equipment"], Iterable
            ):
                s_id = str(sites_or_units.get("site_id") or "site-unknown")
                for eq in sites_or_units["equipment"]:
                    _process_candidate(eq, default_site_id=s_id)
            elif "targets" in sites_or_units and isinstance(
                sites_or_units["targets"], Mapping
            ):
                s_id = str(sites_or_units.get("site_id") or self._default_site_id or "site-unknown")
                for target_id, entry in sites_or_units["targets"].items():
                    if isinstance(entry, Mapping) and self.is_apc_ups(entry, entry):
                        target_dict = dict(entry)
                        target_dict.setdefault("equipment_id", str(target_id))
                        records.append(
                            self.evaluate_unit(
                                target_dict,
                                telemetry=entry,
                                site_id=s_id,
                                evaluation_time=eval_dt,
                            )
                        )
            else:
                # Mapping of target_id -> telemetry or single equipment dict
                if any(
                    k in sites_or_units
                    for k in ("equipment_id", "target_id", "category", "equipment_type")
                ):
                    _process_candidate(sites_or_units)
                else:
                    for target_id, entry in sites_or_units.items():
                        if isinstance(entry, Mapping):
                            target_dict = dict(entry)
                            target_dict.setdefault("equipment_id", str(target_id))
                            if self.is_apc_ups(target_dict, entry):
                                records.append(
                                    self.evaluate_unit(
                                        target_dict,
                                        telemetry=entry,
                                        evaluation_time=eval_dt,
                                    )
                                )
        elif isinstance(sites_or_units, Iterable):
            for elem in sites_or_units:
                if isinstance(elem, Site):
                    for eq in elem.equipment:
                        _process_candidate(eq, default_site_id=elem.site_id)
                elif isinstance(elem, Mapping) and "equipment" in elem:
                    s_id = str(elem.get("site_id") or "site-unknown")
                    for eq in elem["equipment"]:
                        _process_candidate(eq, default_site_id=s_id)
                else:
                    _process_candidate(elem)
        else:
            raise TypeError(
                f"Unsupported sites_or_units argument: {type(sites_or_units).__name__}"
            )

        return UpsFleetHealthReport(records=records, evaluated_at=eval_dt)


__all__ = [
    "APC_ENTERPRISE_OID_PREFIX",
    "APC_UPS_ADV_BATTERY_CAPACITY_OID",
    "APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID",
    "APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID",
    "APC_UPS_ADV_BATTERY_TEMPERATURE_OID",
    "APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID",
    "APC_UPS_ADV_OUTPUT_LOAD_OID",
    "APC_UPS_BASIC_BATTERY_STATUS_OID",
    "APC_UPS_BASIC_IDENT_MODEL_OID",
    "APC_UPS_BASIC_OUTPUT_STATUS_OID",
    "APC_UPS_BASIC_STATE_OUTPUT_STATE_OID",
    "APC_UPS_HEALTH_OIDS",
    "ApcUpsHealthEvaluator",
    "EquipmentType",
    "UpsAdvisoryCode",
    "UpsFleetHealthReport",
    "UpsHealthRecord",
    "UpsHealthStatus",
    "parse_powernet_telemetry",
]
