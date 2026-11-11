"""Phase 4 LLDP Uplink Guard and Staged Extreme Switch Port & PoE Reclamation Planner."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import re
from typing import Any, Optional
import uuid

from sot_validator.history.ledger import HistoryStore, ItemStreakSummary
from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    ValidationClassification,
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.remediation.sink import (
    _enforce_dry_run_only,
    _resolve_plan_timestamp,
)
from sot_validator.signals.arp import _normalize_mac
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    normalize_utc_datetime,
    resolve_evaluation_time,
)
from sot_validator.signals.management import (
    EXTREME_POE_PORT_MEASURED_POWER_PREFIX,
    EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX,
    IF_MIB_IF_ALIAS_PREFIX,
)
from sot_validator.signals.port_state import (
    _ADMIN_DISABLED_VALUES,
    _OPER_ACTIVE_VALUES,
    _WATTAGE_PATTERN,
)

DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS: tuple[str, ...] = (
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

DEFAULT_BLOCKED_LLDP_CAPABILITIES: tuple[str, ...] = (
    "bridge",
    "switch",
    "router",
    "wlan",
    "wlan-ap",
    "access-point",
    "ap",
    "repeater",
)

_LLDP_INFRASTRUCTURE_ROLES_AND_KEYWORDS: tuple[str, ...] = (
    "switch",
    "bridge",
    "router",
    "core",
    "distribution",
    "wan",
    "firewall",
    "wap",
    "ap-",
    "access-point",
    "wlan",
    "ups",
    "apc",
    "uplink",
    "trunk",
    "vcenter",
    "esxi",
    "extremexos",
    "voss",
)

_IEEE_8021AB_CAPABILITY_BITS: tuple[tuple[int, str], ...] = (
    (0x01, "other"),
    (0x02, "repeater"),
    (0x04, "bridge"),
    (0x08, "wlan"),
    (0x10, "router"),
    (0x20, "telephone"),
    (0x40, "docsis"),
    (0x80, "station"),
)

_MILLIWATT_PATTERN = re.compile(r"(\d+(?:\.\d+)?)\s*mw\b", re.IGNORECASE)
_VLAN_RANGE_PATTERN = re.compile(r"^\d+\s*-\s*\d+$")
_PORT_TRAILING_DIGITS_PATTERN = re.compile(r"(\d+)$")
_SLOT_PORT_PATTERN = re.compile(r"^(\d+)[:/](\d+)$")


class ExtremeCliDialect(str, Enum):
    """Supported Extreme Networks switch CLI dialects for staged port reclamation."""

    EXOS = "exos"
    VOSS = "voss"

    @classmethod
    def _missing_(cls, value: object) -> Optional[ExtremeCliDialect]:
        if isinstance(value, str):
            cleaned = value.strip().lower().replace("-", "_")
            if cleaned in ("exos", "extreme_xos", "extremexos", "xos"):
                return cls.EXOS
            if cleaned in ("voss", "extreme_voss", "extremevoss", "fabric_engine"):
                return cls.VOSS
        return None


def _coerce_cli_dialect(
    value: ExtremeCliDialect | str, field_name: str = "dialect"
) -> ExtremeCliDialect:
    if isinstance(value, ExtremeCliDialect):
        return value
    if isinstance(value, str):
        try:
            return ExtremeCliDialect(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    text = str(value).strip()
    return text if text else None


def _normalize_str_tuple(values: Optional[Iterable[Any]]) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        stripped = values.strip()
        return (stripped,) if stripped else ()
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        cleaned = _clean_optional_str(item)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return tuple(result)


def _preserve_str_tuple(values: Optional[Iterable[Any]]) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        stripped = values.strip()
        return (stripped,) if stripped else ()
    return tuple(
        cleaned
        for item in values
        if (cleaned := _clean_optional_str(item)) is not None
    )


def _decode_lldp_capabilities(raw: Any) -> tuple[str, ...]:
    """Normalize LLDP/CDP capabilities from sequences, delimited strings, or IEEE 802.1AB bitmasks."""
    if raw is None or isinstance(raw, bool):
        return ()

    if isinstance(raw, int):
        if raw <= 0:
            return ()
        decoded = [
            name for bit, name in _IEEE_8021AB_CAPABILITY_BITS if (raw & bit) != 0
        ]
        return tuple(decoded)

    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return ()
        # Check hex or integer bitmask string
        if stripped.lower().startswith("0x") or stripped.isdigit():
            try:
                mask = int(stripped, 0)
                if mask > 0:
                    decoded = [
                        name
                        for bit, name in _IEEE_8021AB_CAPABILITY_BITS
                        if (mask & bit) != 0
                    ]
                    if decoded:
                        return tuple(decoded)
            except ValueError:
                pass

        normalized_text = re.sub(
            r"\bwlan\s+access\s+point\b",
            "wlan-ap",
            stripped,
            flags=re.IGNORECASE,
        )
        normalized_text = re.sub(
            r"\baccess\s+point\b",
            "access-point",
            normalized_text,
            flags=re.IGNORECASE,
        )
        if any(sep in normalized_text for sep in (",", ";", "|", "/")):
            parts = re.split(r"[,;|/]+", normalized_text)
        else:
            parts = normalized_text.split()
        result: list[str] = []
        seen: set[str] = set()
        for part in parts:
            token = part.strip().lower()
            if token and token not in seen:
                seen.add(token)
                result.append(token)
        return tuple(result)

    if isinstance(raw, Iterable):
        result = []
        seen = set()
        for item in raw:
            for sub in _decode_lldp_capabilities(item):
                if sub not in seen:
                    seen.add(sub)
                    result.append(sub)
        return tuple(result)

    return ()


@dataclass(frozen=True)
class LldpNeighborRecord:
    """Normalized LLDP or CDP neighbor discovery record associated with a switch port."""

    port_id: Optional[str] = None
    port_name: Optional[str] = None
    lldp_rem_sys_name: Optional[str] = None
    lldp_rem_sys_cap_enabled: tuple[str, ...] = ()
    neighbor_device_role: Optional[str] = None
    lldp_rem_sys_desc: Optional[str] = None
    neighbor_port_id: Optional[str] = None
    protocol: str = "lldp"

    def __init__(
        self,
        port_id: Optional[str] = None,
        port_name: Optional[str] = None,
        lldp_rem_sys_name: Optional[str] = None,
        lldp_rem_sys_cap_enabled: Any = (),
        neighbor_device_role: Optional[str] = None,
        lldp_rem_sys_desc: Optional[str] = None,
        neighbor_port_id: Optional[str] = None,
        protocol: str = "lldp",
        *,
        lldpRemSysName: Optional[str] = None,
        lldpRemSysCapEnabled: Any = None,
        lldpRemSysDesc: Optional[str] = None,
        sys_name: Optional[str] = None,
        neighbor_name: Optional[str] = None,
        device_id: Optional[str] = None,
        chassis_id: Optional[str] = None,
        capabilities: Any = None,
        sys_capabilities: Any = None,
        neighbor_role: Optional[str] = None,
        device_role: Optional[str] = None,
        role: Optional[str] = None,
        sys_descr: Optional[str] = None,
        platform: Optional[str] = None,
        local_port: Optional[str] = None,
        remote_port: Optional[str] = None,
    ) -> None:
        resolved_port_id = _clean_optional_str(port_id)
        resolved_port_name = _clean_optional_str(port_name or local_port)
        resolved_sys_name = _clean_optional_str(
            lldp_rem_sys_name
            or lldpRemSysName
            or sys_name
            or neighbor_name
            or device_id
            or chassis_id
        )
        raw_caps = (
            lldp_rem_sys_cap_enabled
            if lldp_rem_sys_cap_enabled not in ((), None)
            else (
                lldpRemSysCapEnabled
                if lldpRemSysCapEnabled is not None
                else (
                    capabilities
                    if capabilities is not None
                    else sys_capabilities
                )
            )
        )
        resolved_caps = _decode_lldp_capabilities(raw_caps)
        resolved_role = _clean_optional_str(
            neighbor_device_role or neighbor_role or device_role or role
        )
        resolved_desc = _clean_optional_str(
            lldp_rem_sys_desc or lldpRemSysDesc or sys_descr or platform
        )
        resolved_neighbor_port = _clean_optional_str(
            neighbor_port_id or remote_port
        )
        resolved_protocol = (_clean_optional_str(protocol) or "lldp").lower()

        object.__setattr__(self, "port_id", resolved_port_id)
        object.__setattr__(self, "port_name", resolved_port_name)
        object.__setattr__(self, "lldp_rem_sys_name", resolved_sys_name)
        object.__setattr__(self, "lldp_rem_sys_cap_enabled", resolved_caps)
        object.__setattr__(self, "neighbor_device_role", resolved_role)
        object.__setattr__(self, "lldp_rem_sys_desc", resolved_desc)
        object.__setattr__(self, "neighbor_port_id", resolved_neighbor_port)
        object.__setattr__(self, "protocol", resolved_protocol)

    @property
    def lldpRemSysName(self) -> Optional[str]:
        """MIB-style alias for lldp_rem_sys_name."""
        return self.lldp_rem_sys_name

    @property
    def lldpRemSysCapEnabled(self) -> tuple[str, ...]:
        """MIB-style alias for lldp_rem_sys_cap_enabled."""
        return self.lldp_rem_sys_cap_enabled

    @property
    def lldpRemSysDesc(self) -> Optional[str]:
        """MIB-style alias for lldp_rem_sys_desc."""
        return self.lldp_rem_sys_desc

    @property
    def sys_name(self) -> Optional[str]:
        """Alias for lldp_rem_sys_name."""
        return self.lldp_rem_sys_name

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Alias for lldp_rem_sys_cap_enabled."""
        return self.lldp_rem_sys_cap_enabled

    @property
    def role(self) -> Optional[str]:
        """Alias for neighbor_device_role."""
        return self.neighbor_device_role

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "port_name": self.port_name,
            "lldp_rem_sys_name": self.lldp_rem_sys_name,
            "lldp_rem_sys_cap_enabled": list(self.lldp_rem_sys_cap_enabled),
            "neighbor_device_role": self.neighbor_device_role,
            "lldp_rem_sys_desc": self.lldp_rem_sys_desc,
            "neighbor_port_id": self.neighbor_port_id,
            "protocol": self.protocol,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LldpNeighborRecord:
        if isinstance(data, cls):
            return data
        return cls(
            port_id=data.get("port_id"),
            port_name=data.get("port_name") or data.get("local_port") or data.get("port"),
            lldp_rem_sys_name=(
                data.get("lldp_rem_sys_name")
                or data.get("lldpRemSysName")
                or data.get("sys_name")
                or data.get("neighbor_name")
                or data.get("device_id")
                or data.get("chassis_id")
            ),
            lldp_rem_sys_cap_enabled=(
                data.get("lldp_rem_sys_cap_enabled")
                if "lldp_rem_sys_cap_enabled" in data
                else (
                    data.get("lldpRemSysCapEnabled")
                    if "lldpRemSysCapEnabled" in data
                    else (
                        data.get("capabilities")
                        if "capabilities" in data
                        else data.get("sys_capabilities")
                    )
                )
            ),
            neighbor_device_role=(
                data.get("neighbor_device_role")
                or data.get("neighbor_role")
                or data.get("device_role")
                or data.get("role")
            ),
            lldp_rem_sys_desc=(
                data.get("lldp_rem_sys_desc")
                or data.get("lldpRemSysDesc")
                or data.get("sys_descr")
                or data.get("platform")
            ),
            neighbor_port_id=(
                data.get("neighbor_port_id")
                or data.get("lldp_rem_port_id")
                or data.get("lldpRemPortId")
                or data.get("remote_port")
            ),
            protocol=data.get("protocol", "lldp"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> LldpNeighborRecord:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class LldpGuardDecision:
    """Safety evaluation result from LldpUplinkGuard for a candidate switch port."""

    port_id: str
    device_id: str
    port_name: str
    blocked: bool
    block_reason: Optional[str] = None
    block_reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_non_empty_str(self.port_id, "port_id")
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")
        object.__setattr__(self, "blocked", bool(self.blocked))

        reasons = _normalize_str_tuple(self.block_reasons)
        rules = _normalize_str_tuple(self.matched_rules)
        primary_reason = _clean_optional_str(self.block_reason)

        if self.blocked:
            if primary_reason is None and reasons:
                primary_reason = "; ".join(reasons)
            if primary_reason is None:
                raise ValueError(
                    "block_reason must be a non-empty string when blocked=True"
                )
            if not reasons:
                reasons = (primary_reason,)
        else:
            primary_reason = None
            reasons = ()
            rules = ()

        object.__setattr__(self, "block_reason", primary_reason)
        object.__setattr__(self, "block_reasons", reasons)
        object.__setattr__(self, "matched_rules", rules)

    @property
    def reason(self) -> Optional[str]:
        """Alias for block_reason."""
        return self.block_reason

    @property
    def allowed(self) -> bool:
        """Return True when the port passed all uplink guard checks."""
        return not self.blocked

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "device_id": self.device_id,
            "port_name": self.port_name,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "block_reasons": list(self.block_reasons),
            "matched_rules": list(self.matched_rules),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LldpGuardDecision:
        if isinstance(data, cls):
            return data
        return cls(
            port_id=data["port_id"],
            device_id=data["device_id"],
            port_name=data.get("port_name") or data.get("name", ""),
            blocked=bool(data["blocked"]),
            block_reason=data.get("block_reason"),
            block_reasons=tuple(data.get("block_reasons", ())),
            matched_rules=tuple(data.get("matched_rules", ())),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> LldpGuardDecision:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class BlockedPortRecord:
    """Audit record for a switch port blocked from reclamation by LldpUplinkGuard or streak policy."""

    port_id: str
    device_id: str
    port_name: str
    site_id: Optional[str] = None
    device_hostname: Optional[str] = None
    blocked: bool = True
    block_reason: str = ""
    block_reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
    admin_status: Optional[str] = None
    oper_status: Optional[str] = None
    poe_status: Optional[str] = None
    vlan_id: Optional[str] = None
    description: Optional[str] = None
    connected_device_id: Optional[str] = None
    inactive_runs: int = 0
    inactive_days: float = 0.0

    def __post_init__(self) -> None:
        _require_non_empty_str(self.port_id, "port_id")
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")
        object.__setattr__(self, "blocked", bool(self.blocked))

        reasons = _normalize_str_tuple(self.block_reasons)
        rules = _normalize_str_tuple(self.matched_rules)
        primary_reason = _clean_optional_str(self.block_reason) or ""

        if not primary_reason and reasons:
            primary_reason = "; ".join(reasons)
        if self.blocked and not primary_reason:
            raise ValueError(
                "block_reason must be a non-empty string when blocked=True"
            )
        if primary_reason and not reasons:
            reasons = (primary_reason,)

        if isinstance(self.inactive_runs, bool) or not isinstance(
            self.inactive_runs, int
        ) or self.inactive_runs < 0:
            raise ValueError("inactive_runs must be a non-negative integer")
        if isinstance(self.inactive_days, bool) or not isinstance(
            self.inactive_days, (int, float)
        ) or float(self.inactive_days) < 0.0:
            raise ValueError("inactive_days must be a non-negative number")

        object.__setattr__(self, "block_reason", primary_reason)
        object.__setattr__(self, "block_reasons", reasons)
        object.__setattr__(self, "matched_rules", rules)
        object.__setattr__(self, "inactive_days", float(self.inactive_days))

    @property
    def name(self) -> str:
        """Alias for port_name."""
        return self.port_name

    @property
    def reason(self) -> str:
        """Alias for block_reason."""
        return self.block_reason

    @property
    def consecutive_stale_runs(self) -> int:
        """Alias for inactive_runs."""
        return self.inactive_runs

    @property
    def stale_duration_days(self) -> float:
        """Alias for inactive_days."""
        return self.inactive_days

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "device_id": self.device_id,
            "port_name": self.port_name,
            "site_id": self.site_id,
            "device_hostname": self.device_hostname,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "block_reasons": list(self.block_reasons),
            "matched_rules": list(self.matched_rules),
            "admin_status": self.admin_status,
            "oper_status": self.oper_status,
            "poe_status": self.poe_status,
            "vlan_id": self.vlan_id,
            "description": self.description,
            "connected_device_id": self.connected_device_id,
            "inactive_runs": self.inactive_runs,
            "inactive_days": self.inactive_days,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BlockedPortRecord:
        if isinstance(data, cls):
            return data
        return cls(
            port_id=data["port_id"],
            device_id=data["device_id"],
            port_name=data.get("port_name") or data.get("name", ""),
            site_id=data.get("site_id"),
            device_hostname=data.get("device_hostname"),
            blocked=bool(data.get("blocked", True)),
            block_reason=data.get("block_reason") or data.get("reason") or "",
            block_reasons=tuple(data.get("block_reasons", ())),
            matched_rules=tuple(data.get("matched_rules", ())),
            admin_status=data.get("admin_status"),
            oper_status=data.get("oper_status"),
            poe_status=data.get("poe_status"),
            vlan_id=data.get("vlan_id"),
            description=data.get("description"),
            connected_device_id=data.get("connected_device_id"),
            inactive_runs=int(
                data.get(
                    "inactive_runs", data.get("consecutive_stale_runs", 0)
                )
            ),
            inactive_days=float(
                data.get("inactive_days", data.get("stale_duration_days", 0.0))
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> BlockedPortRecord:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class PortReclamationCandidate:
    """Eligible stale Extreme Networks access port with staged CLI disable and rollback commands."""

    port_id: str
    device_id: str
    port_name: str
    site_id: Optional[str] = None
    device_hostname: Optional[str] = None
    admin_status: Optional[str] = "up"
    oper_status: Optional[str] = "down"
    poe_status: Optional[str] = None
    vlan_id: Optional[str] = None
    description: Optional[str] = None
    connected_device_id: Optional[str] = None
    inactive_runs: int = 0
    inactive_days: float = 0.0
    estimated_poe_watts_saved: float = 0.0
    poe_restore_limit_mw: int = 30000
    dialect: ExtremeCliDialect = ExtremeCliDialect.EXOS
    exos_disable_commands: tuple[str, ...] = ()
    exos_rollback_commands: tuple[str, ...] = ()
    exos_rollback_command: str = ""
    voss_disable_commands: tuple[str, ...] = ()
    voss_rollback_commands: tuple[str, ...] = ()
    voss_rollback_command: str = ""

    def __post_init__(self) -> None:
        _require_non_empty_str(self.port_id, "port_id")
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")

        if isinstance(self.inactive_runs, bool) or not isinstance(
            self.inactive_runs, int
        ) or self.inactive_runs < 0:
            raise ValueError("inactive_runs must be a non-negative integer")
        if isinstance(self.inactive_days, bool) or not isinstance(
            self.inactive_days, (int, float)
        ) or float(self.inactive_days) < 0.0:
            raise ValueError("inactive_days must be a non-negative number")
        if isinstance(self.estimated_poe_watts_saved, bool) or not isinstance(
            self.estimated_poe_watts_saved, (int, float)
        ) or float(self.estimated_poe_watts_saved) < 0.0:
            raise ValueError(
                "estimated_poe_watts_saved must be a non-negative number"
            )
        if isinstance(self.poe_restore_limit_mw, bool) or not isinstance(
            self.poe_restore_limit_mw, int
        ) or self.poe_restore_limit_mw < 0:
            raise ValueError(
                "poe_restore_limit_mw must be a non-negative integer"
            )

        coerced_dialect = _coerce_cli_dialect(self.dialect, "dialect")
        object.__setattr__(self, "dialect", coerced_dialect)
        object.__setattr__(self, "inactive_days", float(self.inactive_days))
        object.__setattr__(
            self,
            "estimated_poe_watts_saved",
            round(float(self.estimated_poe_watts_saved), 2),
        )

        pname = self.port_name.strip()
        limit_mw = self.poe_restore_limit_mw

        exos_fwd = _preserve_str_tuple(self.exos_disable_commands) or (
            f"configure inline-power operator-limit 0 ports {pname}",
            f"disable ports {pname}",
        )
        exos_rb = _preserve_str_tuple(self.exos_rollback_commands) or (
            f"configure inline-power operator-limit {limit_mw} ports {pname}",
            f"enable ports {pname}",
        )
        exos_rb_one = _clean_optional_str(self.exos_rollback_command) or (
            f"enable ports {pname}; configure inline-power operator-limit {limit_mw} ports {pname}"
        )

        voss_fwd = _preserve_str_tuple(self.voss_disable_commands) or (
            f"interface GigabitEthernet {pname}",
            "poe-shutdown",
            "shutdown",
            "exit",
        )
        voss_rb = _preserve_str_tuple(self.voss_rollback_commands) or (
            f"interface GigabitEthernet {pname}",
            "no poe-shutdown",
            "no shutdown",
            "exit",
        )
        voss_rb_one = _clean_optional_str(self.voss_rollback_command) or (
            f"interface GigabitEthernet {pname}; no poe-shutdown; no shutdown; exit"
        )

        object.__setattr__(self, "exos_disable_commands", exos_fwd)
        object.__setattr__(self, "exos_rollback_commands", exos_rb)
        object.__setattr__(self, "exos_rollback_command", exos_rb_one)
        object.__setattr__(self, "voss_disable_commands", voss_fwd)
        object.__setattr__(self, "voss_rollback_commands", voss_rb)
        object.__setattr__(self, "voss_rollback_command", voss_rb_one)

    @property
    def name(self) -> str:
        """Alias for port_name."""
        return self.port_name

    @property
    def consecutive_stale_runs(self) -> int:
        """Alias for inactive_runs."""
        return self.inactive_runs

    @property
    def stale_duration_days(self) -> float:
        """Alias for inactive_days."""
        return self.inactive_days

    @property
    def forward_commands(self) -> tuple[str, ...]:
        """Return staged forward disable commands for the active CLI dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_disable_commands
        return self.exos_disable_commands

    @property
    def disable_commands(self) -> tuple[str, ...]:
        """Alias for forward_commands."""
        return self.forward_commands

    @property
    def rollback_commands(self) -> tuple[str, ...]:
        """Return staged rollback commands for the active CLI dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_rollback_commands
        return self.exos_rollback_commands

    @property
    def rollback_command(self) -> str:
        """Return 1-command rollback string for the active CLI dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_rollback_command
        return self.exos_rollback_command

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "device_id": self.device_id,
            "port_name": self.port_name,
            "site_id": self.site_id,
            "device_hostname": self.device_hostname,
            "admin_status": self.admin_status,
            "oper_status": self.oper_status,
            "poe_status": self.poe_status,
            "vlan_id": self.vlan_id,
            "description": self.description,
            "connected_device_id": self.connected_device_id,
            "inactive_runs": self.inactive_runs,
            "inactive_days": self.inactive_days,
            "estimated_poe_watts_saved": self.estimated_poe_watts_saved,
            "poe_restore_limit_mw": self.poe_restore_limit_mw,
            "dialect": self.dialect.value,
            "exos_disable_commands": list(self.exos_disable_commands),
            "exos_rollback_commands": list(self.exos_rollback_commands),
            "exos_rollback_command": self.exos_rollback_command,
            "voss_disable_commands": list(self.voss_disable_commands),
            "voss_rollback_commands": list(self.voss_rollback_commands),
            "voss_rollback_command": self.voss_rollback_command,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PortReclamationCandidate:
        if isinstance(data, cls):
            return data
        return cls(
            port_id=data["port_id"],
            device_id=data["device_id"],
            port_name=data.get("port_name") or data.get("name", ""),
            site_id=data.get("site_id"),
            device_hostname=data.get("device_hostname"),
            admin_status=data.get("admin_status", "up"),
            oper_status=data.get("oper_status", "down"),
            poe_status=data.get("poe_status"),
            vlan_id=data.get("vlan_id"),
            description=data.get("description"),
            connected_device_id=data.get("connected_device_id"),
            inactive_runs=int(
                data.get(
                    "inactive_runs", data.get("consecutive_stale_runs", 0)
                )
            ),
            inactive_days=float(
                data.get("inactive_days", data.get("stale_duration_days", 0.0))
            ),
            estimated_poe_watts_saved=float(
                data.get("estimated_poe_watts_saved", 0.0)
            ),
            poe_restore_limit_mw=int(data.get("poe_restore_limit_mw", 30000)),
            dialect=_coerce_cli_dialect(
                data.get("dialect", ExtremeCliDialect.EXOS)
            ),
            exos_disable_commands=tuple(data.get("exos_disable_commands", ())),
            exos_rollback_commands=tuple(
                data.get("exos_rollback_commands", ())
            ),
            exos_rollback_command=data.get("exos_rollback_command", ""),
            voss_disable_commands=tuple(data.get("voss_disable_commands", ())),
            voss_rollback_commands=tuple(
                data.get("voss_rollback_commands", ())
            ),
            voss_rollback_command=data.get("voss_rollback_command", ""),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> PortReclamationCandidate:
        return cls.from_dict(json.loads(raw))


def _render_staged_cli_script(
    candidates: Sequence[PortReclamationCandidate],
    *,
    dialect: ExtremeCliDialect,
    rollback: bool,
    estimated_poe_watts_saved: float,
) -> str:
    mode_label = "ROLLBACK" if rollback else "STAGED PORT & POE RECLAMATION"
    lines: list[str] = [
        f"# Extreme Networks ({dialect.value.upper()}) {mode_label} SCRIPT (DRY-RUN)",
        f"# Eligible ports: {len(candidates)} | Estimated PoE savings: {estimated_poe_watts_saved:.2f}W",
    ]
    if not candidates:
        lines.append("# No eligible ports for reclamation.")
        return "\n".join(lines) + "\n"

    for candidate in candidates:
        host_Part = (
            f" ({candidate.device_hostname})"
            if candidate.device_hostname
            else ""
        )
        lines.append(
            f"# Device: {candidate.device_id}{host_Part} | Port: {candidate.port_name} ({candidate.port_id}) "
            f"| Inactive: {candidate.inactive_runs} runs ({candidate.inactive_days:.1f}d) "
            f"| PoE saved: {candidate.estimated_poe_watts_saved:.2f}W"
        )
        if dialect is ExtremeCliDialect.EXOS:
            if rollback:
                lines.append(
                    f"# 1-command rollback: {candidate.exos_rollback_command}"
                )
                lines.extend(candidate.exos_rollback_commands)
            else:
                lines.extend(candidate.exos_disable_commands)
        else:
            if rollback:
                lines.append(
                    f"# 1-command rollback: {candidate.voss_rollback_command}"
                )
                lines.extend(candidate.voss_rollback_commands)
            else:
                lines.extend(candidate.voss_disable_commands)

    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class PortReclamationPlan:
    """Staged dry-run Extreme switch port and PoE reclamation plan with rollback scripts."""

    candidates: tuple[PortReclamationCandidate, ...] = ()
    blocked_ports: tuple[BlockedPortRecord, ...] = ()
    estimated_poe_watts_saved: float = 0.0
    min_inactive_runs: int = 3
    min_inactive_days: float = 30.0
    dialect: ExtremeCliDialect = ExtremeCliDialect.EXOS
    exos_commands: tuple[str, ...] = ()
    exos_rollback_commands: tuple[str, ...] = ()
    voss_commands: tuple[str, ...] = ()
    voss_rollback_commands: tuple[str, ...] = ()
    exos_script: str = ""
    exos_rollback_script: str = ""
    voss_script: str = ""
    voss_rollback_script: str = ""
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    plan_id: str = field(
        default_factory=lambda: f"port-plan-{uuid.uuid4().hex[:12]}"
    )
    dry_run: bool = True

    def __post_init__(self) -> None:
        _enforce_dry_run_only(self.dry_run, "PortReclamationPlan")
        _require_non_empty_str(self.plan_id, "plan_id")

        if isinstance(self.min_inactive_runs, bool) or not isinstance(
            self.min_inactive_runs, int
        ) or self.min_inactive_runs < 1:
            raise ValueError("min_inactive_runs must be an integer >= 1")
        if isinstance(self.min_inactive_days, bool) or not isinstance(
            self.min_inactive_days, (int, float)
        ) or float(self.min_inactive_days) < 0.0:
            raise ValueError("min_inactive_days must be a non-negative number")

        coerced_dialect = _coerce_cli_dialect(self.dialect, "dialect")
        resolved_generated_at = _resolve_plan_timestamp(self.generated_at)

        normalized_candidates = tuple(
            c
            if isinstance(c, PortReclamationCandidate)
            else PortReclamationCandidate.from_dict(c)
            for c in (self.candidates or ())
        )
        normalized_blocked = tuple(
            b
            if isinstance(b, BlockedPortRecord)
            else BlockedPortRecord.from_dict(b)
            for b in (self.blocked_ports or ())
        )

        computed_poe = round(
            sum(c.estimated_poe_watts_saved for c in normalized_candidates), 2
        )
        if (
            self.estimated_poe_watts_saved == 0.0
            and computed_poe > 0.0
        ):
            resolved_poe = computed_poe
        else:
            resolved_poe = round(float(self.estimated_poe_watts_saved), 2)
        if resolved_poe < 0.0:
            raise ValueError(
                "estimated_poe_watts_saved must be a non-negative number"
            )

        exos_cmds = _preserve_str_tuple(self.exos_commands) or tuple(
            cmd
            for c in normalized_candidates
            for cmd in c.exos_disable_commands
        )
        exos_rb_cmds = _preserve_str_tuple(self.exos_rollback_commands) or tuple(
            cmd
            for c in normalized_candidates
            for cmd in c.exos_rollback_commands
        )
        voss_cmds = _preserve_str_tuple(self.voss_commands) or tuple(
            cmd
            for c in normalized_candidates
            for cmd in c.voss_disable_commands
        )
        voss_rb_cmds = _preserve_str_tuple(self.voss_rollback_commands) or tuple(
            cmd
            for c in normalized_candidates
            for cmd in c.voss_rollback_commands
        )

        exos_scr = self.exos_script or _render_staged_cli_script(
            normalized_candidates,
            dialect=ExtremeCliDialect.EXOS,
            rollback=False,
            estimated_poe_watts_saved=resolved_poe,
        )
        exos_rb_scr = self.exos_rollback_script or _render_staged_cli_script(
            normalized_candidates,
            dialect=ExtremeCliDialect.EXOS,
            rollback=True,
            estimated_poe_watts_saved=resolved_poe,
        )
        voss_scr = self.voss_script or _render_staged_cli_script(
            normalized_candidates,
            dialect=ExtremeCliDialect.VOSS,
            rollback=False,
            estimated_poe_watts_saved=resolved_poe,
        )
        voss_rb_scr = self.voss_rollback_script or _render_staged_cli_script(
            normalized_candidates,
            dialect=ExtremeCliDialect.VOSS,
            rollback=True,
            estimated_poe_watts_saved=resolved_poe,
        )

        object.__setattr__(self, "candidates", normalized_candidates)
        object.__setattr__(self, "blocked_ports", normalized_blocked)
        object.__setattr__(self, "estimated_poe_watts_saved", resolved_poe)
        object.__setattr__(
            self, "min_inactive_days", float(self.min_inactive_days)
        )
        object.__setattr__(self, "dialect", coerced_dialect)
        object.__setattr__(self, "exos_commands", exos_cmds)
        object.__setattr__(self, "exos_rollback_commands", exos_rb_cmds)
        object.__setattr__(self, "voss_commands", voss_cmds)
        object.__setattr__(self, "voss_rollback_commands", voss_rb_cmds)
        object.__setattr__(self, "exos_script", exos_scr)
        object.__setattr__(self, "exos_rollback_script", exos_rb_scr)
        object.__setattr__(self, "voss_script", voss_scr)
        object.__setattr__(self, "voss_rollback_script", voss_rb_scr)
        object.__setattr__(self, "generated_at", resolved_generated_at)

    @property
    def eligible_ports(self) -> tuple[PortReclamationCandidate, ...]:
        """Alias for candidates."""
        return self.candidates

    @property
    def forward_commands(self) -> tuple[str, ...]:
        """Return staged forward CLI commands for the plan's active dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_commands
        return self.exos_commands

    @property
    def rollback_commands(self) -> tuple[str, ...]:
        """Return staged rollback CLI commands for the plan's active dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_rollback_commands
        return self.exos_rollback_commands

    @property
    def forward_script(self) -> str:
        """Return staged forward CLI script for the plan's active dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_script
        return self.exos_script

    @property
    def rollback_script(self) -> str:
        """Return staged rollback CLI script for the plan's active dialect."""
        if self.dialect is ExtremeCliDialect.VOSS:
            return self.voss_rollback_script
        return self.exos_rollback_script

    def format_cli_script(
        self, dialect: ExtremeCliDialect | str = ExtremeCliDialect.EXOS
    ) -> str:
        """Return the staged forward CLI script for the requested Extreme CLI dialect."""
        target = _coerce_cli_dialect(dialect, "dialect")
        return (
            self.voss_script
            if target is ExtremeCliDialect.VOSS
            else self.exos_script
        )

    def format_rollback_script(
        self, dialect: ExtremeCliDialect | str = ExtremeCliDialect.EXOS
    ) -> str:
        """Return the staged rollback CLI script for the requested Extreme CLI dialect."""
        target = _coerce_cli_dialect(dialect, "dialect")
        return (
            self.voss_rollback_script
            if target is ExtremeCliDialect.VOSS
            else self.exos_rollback_script
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "generated_at": _format_optional_datetime(self.generated_at),
            "dry_run": self.dry_run,
            "dialect": self.dialect.value,
            "min_inactive_runs": self.min_inactive_runs,
            "min_inactive_days": self.min_inactive_days,
            "estimated_poe_watts_saved": self.estimated_poe_watts_saved,
            "candidates": [c.to_dict() for c in self.candidates],
            "blocked_ports": [b.to_dict() for b in self.blocked_ports],
            "exos_commands": list(self.exos_commands),
            "exos_rollback_commands": list(self.exos_rollback_commands),
            "voss_commands": list(self.voss_commands),
            "voss_rollback_commands": list(self.voss_rollback_commands),
            "exos_script": self.exos_script,
            "exos_rollback_script": self.exos_rollback_script,
            "voss_script": self.voss_script,
            "voss_rollback_script": self.voss_rollback_script,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PortReclamationPlan:
        if isinstance(data, cls):
            return data
        raw_candidates = data.get(
            "candidates", data.get("eligible_ports", ())
        )
        return cls(
            plan_id=data.get(
                "plan_id", f"port-plan-{uuid.uuid4().hex[:12]}"
            ),
            generated_at=_resolve_plan_timestamp(data.get("generated_at")),
            dry_run=data.get("dry_run", True),
            dialect=_coerce_cli_dialect(
                data.get("dialect", ExtremeCliDialect.EXOS)
            ),
            min_inactive_runs=int(data.get("min_inactive_runs", 3)),
            min_inactive_days=float(data.get("min_inactive_days", 30.0)),
            estimated_poe_watts_saved=float(
                data.get("estimated_poe_watts_saved", 0.0)
            ),
            candidates=tuple(
                PortReclamationCandidate.from_dict(c) for c in raw_candidates
            ),
            blocked_ports=tuple(
                BlockedPortRecord.from_dict(b)
                for b in data.get("blocked_ports", ())
            ),
            exos_commands=tuple(data.get("exos_commands", ())),
            exos_rollback_commands=tuple(
                data.get("exos_rollback_commands", ())
            ),
            voss_commands=tuple(data.get("voss_commands", ())),
            voss_rollback_commands=tuple(
                data.get("voss_rollback_commands", ())
            ),
            exos_script=data.get("exos_script", ""),
            exos_rollback_script=data.get("exos_rollback_script", ""),
            voss_script=data.get("voss_script", ""),
            voss_rollback_script=data.get("voss_rollback_script", ""),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> PortReclamationPlan:
        return cls.from_dict(json.loads(raw))


def _coerce_port_and_extras(
    raw_port: Port | Mapping[str, Any],
    default_device_id: Optional[str] = None,
) -> tuple[Port, dict[str, Any]]:
    """Coerce a Port or mapping into a canonical Port and a dictionary of extra metadata."""
    extras: dict[str, Any] = {}
    if isinstance(raw_port, Port):
        for attr in (
            "description",
            "tagged_vlans",
            "is_trunk",
            "vlan_mode",
            "lldp_neighbors",
            "lldp_neighbor",
            "poe_power_w",
            "poe_watts",
            "poe_power_mw",
            "poe_restore_limit_mw",
            "poe_limit_mw",
            "if_index",
            "inactive_runs",
            "consecutive_stale_runs",
            "inactive_days",
            "stale_duration_days",
            "site_id",
            "device_hostname",
            "has_recent_arp_activity",
            "has_recent_mac_activity",
        ):
            if hasattr(raw_port, attr):
                extras[attr] = getattr(raw_port, attr)
        return raw_port, extras

    if isinstance(raw_port, Mapping):
        extras = dict(raw_port)
        port_id = _clean_optional_str(
            raw_port.get("port_id") or raw_port.get("id")
        )
        device_id = _clean_optional_str(
            raw_port.get("device_id") or default_device_id or "unknown-device"
        )
        name = _clean_optional_str(
            raw_port.get("name") or raw_port.get("port_name") or port_id
        )
        if not port_id and device_id and name:
            port_id = f"{device_id}:{name}"
        if not port_id or not device_id or not name:
            raise ValueError(
                "Port mapping must include port_id, device_id, and name/port_name"
            )
        port = Port(
            port_id=port_id,
            device_id=device_id,
            name=name,
            admin_status=_clean_optional_str(raw_port.get("admin_status")),
            oper_status=_clean_optional_str(raw_port.get("oper_status")),
            poe_status=_clean_optional_str(raw_port.get("poe_status")),
            connected_device_id=_clean_optional_str(
                raw_port.get("connected_device_id")
                or raw_port.get("connected_equipment_id")
            ),
            connected_mac=_clean_optional_str(raw_port.get("connected_mac")),
            vlan_id=_clean_optional_str(raw_port.get("vlan_id")),
        )
        return port, extras

    raise ValueError(f"Unsupported port representation: {raw_port!r}")


def _port_matches_identifier(port: Port, identifier: str) -> bool:
    cleaned = identifier.strip()
    if not cleaned:
        return False
    return cleaned in (
        port.port_id,
        port.name,
        f"{port.device_id}:{port.name}",
        f"{port.device_id}:{port.port_id}",
    )


class LldpUplinkGuard:
    """Safety guard blocking reclamation of uplinks, trunks, WAPs, UPSs, and active ports."""

    def __init__(
        self,
        *,
        critical_keywords: Iterable[str] = DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS,
        blocked_capabilities: Iterable[str] = DEFAULT_BLOCKED_LLDP_CAPABILITIES,
        arp_active_within_days: float = 30.0,
    ) -> None:
        if isinstance(arp_active_within_days, bool) or not isinstance(
            arp_active_within_days, (int, float)
        ) or float(arp_active_within_days) < 0.0:
            raise ValueError(
                "arp_active_within_days must be a non-negative number"
            )
        self.critical_keywords: tuple[str, ...] = tuple(
            kw.strip().lower()
            for kw in critical_keywords
            if isinstance(kw, str) and kw.strip()
        )
        self.blocked_capabilities: tuple[str, ...] = tuple(
            cap.strip().lower()
            for cap in blocked_capabilities
            if isinstance(cap, str) and cap.strip()
        )
        self.arp_active_within_days: float = float(arp_active_within_days)

    def evaluate_port(
        self,
        port: Port | Mapping[str, Any],
        *,
        device: Optional[NetworkDevice | Mapping[str, Any]] = None,
        site: Optional[Site | Mapping[str, Any]] = None,
        description: Optional[str] = None,
        tagged_vlans: Optional[Iterable[str | int]] = None,
        is_trunk: Optional[bool] = None,
        vlan_mode: Optional[str] = None,
        lldp_neighbors: Optional[
            LldpNeighborRecord
            | Mapping[str, Any]
            | Sequence[LldpNeighborRecord | Mapping[str, Any]]
        ] = None,
        mapped_equipment: Optional[
            Equipment
            | NetworkDevice
            | Mapping[str, Any]
            | Sequence[Equipment | NetworkDevice | Mapping[str, Any]]
        ] = None,
        ip_addresses: Optional[Sequence[IPAddress | Mapping[str, Any]]] = None,
        arp_entries: Optional[Sequence[ArpEntry | Mapping[str, Any]]] = None,
        has_recent_arp_activity: Optional[bool] = None,
        has_recent_mac_activity: Optional[bool] = None,
        active_macs: Optional[Iterable[str]] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> LldpGuardDecision:
        """Evaluate whether `port` must be blocked from switch port/PoE reclamation."""
        resolved_site: Optional[Site] = None
        if site is not None:
            resolved_site = (
                site if isinstance(site, Site) else Site.from_dict(site)
            )

        resolved_device: Optional[NetworkDevice] = None
        if device is not None:
            resolved_device = (
                device
                if isinstance(device, NetworkDevice)
                else NetworkDevice.from_dict(device)
            )

        port_obj, extras = _coerce_port_and_extras(
            port,
            default_device_id=(
                resolved_device.device_id
                if resolved_device is not None
                else None
            ),
        )

        reasons: list[str] = []
        rules: list[str] = []

        def _add_block(rule_name: str, reason_text: str) -> None:
            if rule_name not in rules:
                rules.append(rule_name)
            if reason_text not in reasons:
                reasons.append(reason_text)

        # Resolve connected peer NetworkDevices and Equipment
        connected_devices, connected_equipment = self._resolve_connected_peers(
            port=port_obj,
            device=resolved_device,
            site=resolved_site,
            mapped_equipment=mapped_equipment,
        )

        # 1. Active LLDP / CDP neighbor check ("lldp_neighbor")
        matched_neighbors = self._resolve_port_lldp_neighbors(
            port=port_obj,
            extras=extras,
            lldp_neighbors=lldp_neighbors,
        )
        for neighbor in matched_neighbors:
            cap_hits = self._match_blocked_capabilities(
                neighbor.lldp_rem_sys_cap_enabled
            )
            role_or_name_hits = self._match_neighbor_infrastructure_indicators(
                neighbor
            )
            if cap_hits or role_or_name_hits:
                neighbor_label = (
                    neighbor.lldp_rem_sys_name
                    or neighbor.neighbor_device_role
                    or "unknown-neighbor"
                )
                detail_parts: list[str] = []
                if cap_hits:
                    detail_parts.append(
                        f"capabilities={','.join(cap_hits)}"
                    )
                if role_or_name_hits:
                    detail_parts.append(
                        f"indicators={','.join(role_or_name_hits)}"
                    )
                detail_str = ", ".join(detail_parts)
                _add_block(
                    "lldp_neighbor",
                    f"LLDP/CDP neighbor {neighbor_label!r} on port {port_obj.name} ({detail_str})",
                )

        for peer_dev in connected_devices:
            _add_block(
                "lldp_neighbor",
                f"Port {port_obj.name} is connected to network device {peer_dev.hostname!r} ({peer_dev.device_id})",
            )

        # 2. Critical infrastructure keywords or UPS category ("critical_keyword")
        resolved_description = _clean_optional_str(
            description
            if description is not None
            else extras.get("description")
        )
        text_sources: list[tuple[str, str]] = []
        if resolved_description:
            text_sources.append(("port description", resolved_description))
        if port_obj.name:
            text_sources.append(("port name", port_obj.name))
        if port_obj.connected_device_id:
            text_sources.append(
                ("connected_device_id", port_obj.connected_device_id)
            )
        for neighbor in matched_neighbors:
            if neighbor.lldp_rem_sys_name:
                text_sources.append(
                    ("LLDP neighbor sys_name", neighbor.lldp_rem_sys_name)
                )
            if neighbor.neighbor_device_role:
                text_sources.append(
                    ("LLDP neighbor role", neighbor.neighbor_device_role)
                )
            if neighbor.lldp_rem_sys_desc:
                text_sources.append(
                    ("LLDP neighbor description", neighbor.lldp_rem_sys_desc)
                )

        for eq in connected_equipment:
            if eq.category is EquipmentCategory.UPS:
                _add_block(
                    "critical_keyword",
                    f"Mapped equipment {eq.name!r} ({eq.equipment_id}) is critical category UPS",
                )
            for label, val in (
                ("equipment name", eq.name),
                ("equipment_id", eq.equipment_id),
                ("equipment category", eq.category.value),
            ):
                if val:
                    text_sources.append((label, val))

        for peer_dev in connected_devices:
            for label, val in (
                ("peer device hostname", peer_dev.hostname),
                ("peer device_id", peer_dev.device_id),
                ("peer device vendor", peer_dev.vendor),
                ("peer device model", peer_dev.model),
                ("peer device role", peer_dev.role),
            ):
                if val:
                    text_sources.append((label, val))

        # Also inspect raw mapping fields if mapped_equipment had custom dicts
        for raw_peer in self._iter_raw_mappings(mapped_equipment):
            for key in (
                "name",
                "hostname",
                "equipment_id",
                "device_id",
                "vendor",
                "model",
                "role",
                "category",
                "description",
            ):
                val = _clean_optional_str(raw_peer.get(key))
                if val:
                    text_sources.append((f"mapped {key}", val))

        matched_keywords: list[tuple[str, str, str]] = []
        for source_label, text in text_sources:
            lowered = text.lower()
            for kw in self.critical_keywords:
                if self._keyword_matches_text(kw, lowered):
                    matched_keywords.append((kw, source_label, text))

        if matched_keywords:
            kw, source_label, text = matched_keywords[0]
            unique_kws = list(dict.fromkeys(m[0] for m in matched_keywords))
            _add_block(
                "critical_keyword",
                f"Critical infrastructure keyword {kw!r} (matched {unique_kws}) in {source_label} {text!r}",
            )

        # 3. Multi-VLAN tagged trunk check ("tagged_trunk")
        trunk_reason = self._check_tagged_trunk(
            port=port_obj,
            extras=extras,
            tagged_vlans=tagged_vlans,
            is_trunk=is_trunk,
            vlan_mode=vlan_mode,
        )
        if trunk_reason is not None:
            _add_block("tagged_trunk", trunk_reason)

        # 4. Operational link UP or recent ARP/MAC activity ("oper_up_or_active_arp")
        oper_norm = (
            port_obj.oper_status.strip().lower()
            if isinstance(port_obj.oper_status, str)
            and port_obj.oper_status.strip()
            else None
        )
        if oper_norm is not None and oper_norm in _OPER_ACTIVE_VALUES:
            _add_block(
                "oper_up_or_active_arp",
                f"Port {port_obj.name} operational status is active (oper_status={port_obj.oper_status!r})",
            )

        arp_reason = self._check_recent_arp_or_mac_activity(
            port=port_obj,
            extras=extras,
            site=resolved_site,
            connected_equipment=connected_equipment,
            ip_addresses=ip_addresses,
            arp_entries=arp_entries,
            has_recent_arp_activity=has_recent_arp_activity,
            has_recent_mac_activity=has_recent_mac_activity,
            active_macs=active_macs,
            evaluation_time=evaluation_time,
        )
        if arp_reason is not None:
            _add_block("oper_up_or_active_arp", arp_reason)

        is_blocked = len(reasons) > 0
        return LldpGuardDecision(
            port_id=port_obj.port_id,
            device_id=port_obj.device_id,
            port_name=port_obj.name,
            blocked=is_blocked,
            block_reason="; ".join(reasons) if is_blocked else None,
            block_reasons=tuple(reasons),
            matched_rules=tuple(rules),
        )

    inspect_port = evaluate_port
    __call__ = evaluate_port

    @staticmethod
    def _keyword_matches_text(keyword: str, lowered_text: str) -> bool:
        """Check whether `keyword` matches `lowered_text` without spurious short-word substring hits."""
        if not keyword or not lowered_text:
            return False
        if keyword in ("wan", "wap", "ups", "apc"):
            pattern = rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z])"
            return re.search(pattern, lowered_text) is not None
        return keyword in lowered_text

    def _match_blocked_capabilities(
        self, capabilities: Sequence[str]
    ) -> list[str]:
        hits: list[str] = []
        for raw_cap in capabilities:
            lowered = raw_cap.strip().lower()
            if not lowered:
                continue
            tokens = [
                t for t in re.split(r"[^a-z0-9]+", lowered) if t
            ]
            for blocked in self.blocked_capabilities:
                if blocked == lowered or blocked in tokens:
                    if blocked not in hits:
                        hits.append(blocked)
                elif len(blocked) >= 4 and blocked in lowered:
                    if blocked not in hits:
                        hits.append(blocked)
        return hits

    def _match_neighbor_infrastructure_indicators(
        self, neighbor: LldpNeighborRecord
    ) -> list[str]:
        hits: list[str] = []
        for field_val in (
            neighbor.neighbor_device_role,
            neighbor.lldp_rem_sys_name,
            neighbor.lldp_rem_sys_desc,
        ):
            if not field_val:
                continue
            lowered = field_val.lower()
            for kw in _LLDP_INFRASTRUCTURE_ROLES_AND_KEYWORDS:
                if self._keyword_matches_text(kw, lowered) and kw not in hits:
                    hits.append(kw)
            for kw in self.critical_keywords:
                if self._keyword_matches_text(kw, lowered) and kw not in hits:
                    hits.append(kw)
            # Also check standalone "ap", "sw", "rtr", "fw" tokens in role or sys_name
            tokens = [t for t in re.split(r"[^a-z0-9]+", lowered) if t]
            for short_tok in ("ap", "sw", "rtr", "fw"):
                if short_tok in tokens and short_tok not in hits:
                    hits.append(short_tok)
        return hits

    @staticmethod
    def _resolve_port_lldp_neighbors(
        *,
        port: Port,
        extras: Mapping[str, Any],
        lldp_neighbors: Optional[Any],
    ) -> list[LldpNeighborRecord]:
        raw_sources: list[Any] = []
        if lldp_neighbors is not None:
            raw_sources.append(lldp_neighbors)
        for key in ("lldp_neighbors", "lldp_neighbor"):
            if key in extras and extras[key] is not None:
                raw_sources.append(extras[key])
        if any(
            k in extras and extras[k] is not None
            for k in (
                "lldp_rem_sys_name",
                "lldpRemSysName",
                "lldp_rem_sys_cap_enabled",
                "lldpRemSysCapEnabled",
                "neighbor_device_role",
            )
        ):
            raw_sources.append(extras)

        matched: list[LldpNeighborRecord] = []
        for source in raw_sources:
            if isinstance(source, LldpNeighborRecord):
                if (
                    source.port_id is None
                    and source.port_name is None
                ) or (
                    (
                        source.port_id is not None
                        and _port_matches_identifier(port, source.port_id)
                    )
                    or (
                        source.port_name is not None
                        and _port_matches_identifier(port, source.port_name)
                    )
                ):
                    matched.append(source)
            elif isinstance(source, Mapping):
                # Check if it's a single neighbor dict vs a port->neighbor lookup mapping
                if any(
                    k in source
                    for k in (
                        "lldp_rem_sys_name",
                        "lldpRemSysName",
                        "sys_name",
                        "neighbor_name",
                        "lldp_rem_sys_cap_enabled",
                        "lldpRemSysCapEnabled",
                        "capabilities",
                        "sys_capabilities",
                        "neighbor_device_role",
                        "neighbor_role",
                        "lldp_rem_sys_desc",
                        "lldpRemSysDesc",
                    )
                ):
                    rec = LldpNeighborRecord.from_dict(source)
                    if (
                        rec.port_id is None
                        and rec.port_name is None
                    ) or (
                        (
                            rec.port_id is not None
                            and _port_matches_identifier(port, rec.port_id)
                        )
                        or (
                            rec.port_name is not None
                            and _port_matches_identifier(port, rec.port_name)
                        )
                    ):
                        matched.append(rec)
                else:
                    for key, val in source.items():
                        if _port_matches_identifier(port, str(key)):
                            matched.extend(
                                LldpUplinkGuard._coerce_neighbor_list(val)
                            )
            elif isinstance(source, Sequence) and not isinstance(
                source, (str, bytes)
            ):
                for item in source:
                    rec = (
                        item
                        if isinstance(item, LldpNeighborRecord)
                        else LldpNeighborRecord.from_dict(item)
                    )
                    if (
                        rec.port_id is None
                        and rec.port_name is None
                    ) or (
                        (
                            rec.port_id is not None
                            and _port_matches_identifier(port, rec.port_id)
                        )
                        or (
                            rec.port_name is not None
                            and _port_matches_identifier(port, rec.port_name)
                        )
                    ):
                        matched.append(rec)

        return matched

    @staticmethod
    def _coerce_neighbor_list(val: Any) -> list[LldpNeighborRecord]:
        if val is None:
            return []
        if isinstance(val, LldpNeighborRecord):
            return [val]
        if isinstance(val, Mapping):
            return [LldpNeighborRecord.from_dict(val)]
        if isinstance(val, Sequence) and not isinstance(val, (str, bytes)):
            return [
                item
                if isinstance(item, LldpNeighborRecord)
                else LldpNeighborRecord.from_dict(item)
                for item in val
            ]
        return []

    @staticmethod
    def _iter_raw_mappings(
        mapped_equipment: Optional[Any],
    ) -> list[Mapping[str, Any]]:
        if mapped_equipment is None:
            return []
        if isinstance(mapped_equipment, Mapping):
            return [mapped_equipment]
        if isinstance(mapped_equipment, Sequence) and not isinstance(
            mapped_equipment, (str, bytes)
        ):
            return [
                item for item in mapped_equipment if isinstance(item, Mapping)
            ]
        return []

    @staticmethod
    def _resolve_connected_peers(
        *,
        port: Port,
        device: Optional[NetworkDevice],
        site: Optional[Site],
        mapped_equipment: Optional[Any],
    ) -> tuple[list[NetworkDevice], list[Equipment]]:
        connected_devices: list[NetworkDevice] = []
        connected_equipment: list[Equipment] = []
        seen_dev_ids: set[str] = set()
        seen_eq_ids: set[str] = set()

        def _add_dev(dev: NetworkDevice) -> None:
            if dev.device_id not in seen_dev_ids:
                seen_dev_ids.add(dev.device_id)
                connected_devices.append(dev)

        def _add_eq(eq: Equipment) -> None:
            if eq.equipment_id not in seen_eq_ids:
                seen_eq_ids.add(eq.equipment_id)
                connected_equipment.append(eq)

        # If `device` was passed and is a peer device (not the local switch owning `port`)
        if device is not None and device.device_id != port.device_id:
            _add_dev(device)

        if site is not None:
            if port.connected_device_id:
                for dev in site.devices:
                    if dev.device_id != port.device_id and (
                        dev.device_id == port.connected_device_id
                        or dev.hostname == port.connected_device_id
                    ):
                        _add_dev(dev)
            for eq in site.equipment:
                connected_refs = {
                    ref.strip()
                    for ref in eq.connected_ports
                    if ref and ref.strip()
                }
                if (
                    (
                        port.connected_device_id is not None
                        and (
                            eq.equipment_id == port.connected_device_id
                            or eq.name == port.connected_device_id
                        )
                    )
                    or port.port_id in connected_refs
                    or port.name in connected_refs
                    or f"{port.device_id}:{port.name}" in connected_refs
                    or f"{port.device_id}:{port.port_id}" in connected_refs
                ):
                    _add_eq(eq)

        items: list[Any] = []
        if mapped_equipment is not None:
            if isinstance(
                mapped_equipment, (Equipment, NetworkDevice, Mapping)
            ):
                items.append(mapped_equipment)
            elif isinstance(mapped_equipment, Sequence) and not isinstance(
                mapped_equipment, (str, bytes)
            ):
                items.extend(mapped_equipment)

        for item in items:
            if isinstance(item, Equipment):
                _add_eq(item)
            elif isinstance(item, NetworkDevice):
                if item.device_id != port.device_id:
                    _add_dev(item)
            elif isinstance(item, Mapping):
                if "equipment_id" in item:
                    try:
                        _add_eq(Equipment.from_dict(item))
                    except (KeyError, ValueError):
                        pass
                elif "device_id" in item and "hostname" in item:
                    try:
                        dev_obj = NetworkDevice.from_dict(item)
                        if dev_obj.device_id != port.device_id:
                            _add_dev(dev_obj)
                    except (KeyError, ValueError):
                        pass

        return connected_devices, connected_equipment

    @staticmethod
    def _check_tagged_trunk(
        *,
        port: Port,
        extras: Mapping[str, Any],
        tagged_vlans: Optional[Iterable[str | int]],
        is_trunk: Optional[bool],
        vlan_mode: Optional[str],
    ) -> Optional[str]:
        resolved_is_trunk = (
            is_trunk if is_trunk is not None else extras.get("is_trunk")
        )
        if resolved_is_trunk is True:
            return f"Port {port.name} is explicitly marked as a trunk port (is_trunk=True)"

        resolved_vlan_mode = _clean_optional_str(
            vlan_mode if vlan_mode is not None else extras.get("vlan_mode")
        )
        if resolved_vlan_mode and resolved_vlan_mode.lower() in (
            "trunk",
            "tagged",
            "802.1q",
            "dot1q",
        ):
            return f"Port {port.name} has trunk/tagged VLAN mode (vlan_mode={resolved_vlan_mode!r})"

        raw_tagged = (
            tagged_vlans
            if tagged_vlans is not None
            else extras.get("tagged_vlans")
        )
        if raw_tagged is not None:
            if isinstance(raw_tagged, (str, int)):
                tagged_list = [
                    p.strip()
                    for p in re.split(r"[,;|/\s]+", str(raw_tagged))
                    if p.strip()
                ]
            else:
                tagged_list = [
                    str(v).strip() for v in raw_tagged if str(v).strip()
                ]
            if tagged_list:
                return (
                    f"Port {port.name} carries tagged VLANs ({','.join(tagged_list)})"
                )

        if port.vlan_id:
            vlan_raw = port.vlan_id.strip()
            vlan_lower = vlan_raw.lower()
            if any(
                tok in vlan_lower for tok in ("trunk", "tagged", "all", "tag")
            ):
                return f"Port {port.name} vlan_id indicates trunk/tagged state ({vlan_raw!r})"
            if any(sep in vlan_raw for sep in (",", ";", "|", "/")):
                parts = [
                    p.strip()
                    for p in re.split(r"[,;|/]+", vlan_raw)
                    if p.strip()
                ]
                if len(parts) >= 2:
                    return f"Port {port.name} vlan_id contains multiple VLANs ({vlan_raw!r})"
            if _VLAN_RANGE_PATTERN.match(vlan_raw):
                return f"Port {port.name} vlan_id specifies a VLAN range ({vlan_raw!r})"

        return None

    def _check_recent_arp_or_mac_activity(
        self,
        *,
        port: Port,
        extras: Mapping[str, Any],
        site: Optional[Site],
        connected_equipment: Sequence[Equipment],
        ip_addresses: Optional[Sequence[IPAddress | Mapping[str, Any]]],
        arp_entries: Optional[Sequence[ArpEntry | Mapping[str, Any]]],
        has_recent_arp_activity: Optional[bool],
        has_recent_mac_activity: Optional[bool],
        active_macs: Optional[Iterable[str]],
        evaluation_time: Optional[datetime | str],
    ) -> Optional[str]:
        explicit_arp = (
            has_recent_arp_activity
            if has_recent_arp_activity is not None
            else extras.get("has_recent_arp_activity")
        )
        explicit_mac = (
            has_recent_mac_activity
            if has_recent_mac_activity is not None
            else extras.get("has_recent_mac_activity")
        )
        if explicit_arp is True or explicit_mac is True:
            return f"Port {port.name} has recent ARP/MAC activity flagged"

        port_mac_norm = _normalize_mac(port.connected_mac)
        if active_macs is not None and port_mac_norm is not None:
            norm_active = {
                m for m in (_normalize_mac(raw) for raw in active_macs) if m
            }
            if port_mac_norm in norm_active:
                return f"Port {port.name} MAC {port.connected_mac!r} is present in active MAC table"

        eval_dt = resolve_evaluation_time(evaluation_time)

        # Collect candidate IPAddresses and ArpEntries from site and explicit arguments
        candidate_ips: list[IPAddress] = []
        if site is not None:
            candidate_ips.extend(site.ip_addresses)
        if ip_addresses is not None:
            for item in ip_addresses:
                candidate_ips.append(
                    item
                    if isinstance(item, IPAddress)
                    else IPAddress.from_dict(item)
                )

        explicit_arp_entries: list[ArpEntry] = []
        if arp_entries is not None:
            for item in arp_entries:
                explicit_arp_entries.append(
                    item
                    if isinstance(item, ArpEntry)
                    else ArpEntry.from_dict(item)
                )

        eq_ids = {eq.equipment_id for eq in connected_equipment}
        if port.connected_device_id:
            eq_ids.add(port.connected_device_id)
        eq_assigned_ips = {
            ip.strip()
            for eq in connected_equipment
            for ip in eq.assigned_ips
            if ip and ip.strip()
        }

        for ip_obj in candidate_ips:
            ip_mac_norm = _normalize_mac(ip_obj.arp_mac)
            matches_port = (
                (port_mac_norm is not None and ip_mac_norm == port_mac_norm)
                or (
                    ip_obj.assigned_object_id is not None
                    and ip_obj.assigned_object_id in eq_ids
                )
                or (ip_obj.ip in eq_assigned_ips)
            )
            if not matches_port or ip_obj.arp_last_seen is None:
                continue
            seen_dt = normalize_utc_datetime(
                ip_obj.arp_last_seen, field_name="arp_last_seen"
            )
            age_days = max(
                0.0, (eval_dt - seen_dt).total_seconds() / SECONDS_PER_DAY
            )
            if age_days <= self.arp_active_within_days:
                return (
                    f"Port {port.name} has recent ARP entry for IP {ip_obj.ip} "
                    f"(age={age_days:.1f}d <= {self.arp_active_within_days:.1f}d)"
                )

        for arp_obj in explicit_arp_entries:
            arp_mac_norm = _normalize_mac(arp_obj.mac)
            if port_mac_norm is not None and arp_mac_norm == port_mac_norm:
                if arp_obj.last_seen is None:
                    return (
                        f"Port {port.name} MAC {port.connected_mac!r} has live ARP entry for IP {arp_obj.ip}"
                    )
                seen_dt = normalize_utc_datetime(
                    arp_obj.last_seen, field_name="last_seen"
                )
                age_days = max(
                    0.0, (eval_dt - seen_dt).total_seconds() / SECONDS_PER_DAY
                )
                if age_days <= self.arp_active_within_days:
                    return (
                        f"Port {port.name} has recent ARP entry for IP {arp_obj.ip} "
                        f"(age={age_days:.1f}d <= {self.arp_active_within_days:.1f}d)"
                    )

        return None


class ExtremePortReclamationPlanner:
    """Staged Extreme Networks switch port and PoE reclamation planner with LLDP uplink guard."""

    def __init__(
        self,
        *,
        min_inactive_runs: int = 3,
        min_inactive_days: float = 30.0,
        uplink_guard: Optional[LldpUplinkGuard] = None,
        dialect: ExtremeCliDialect | str = ExtremeCliDialect.EXOS,
        default_searching_poe_watts: float = 0.0,
        default_poe_restore_limit_mw: int = 30000,
    ) -> None:
        if isinstance(min_inactive_runs, bool) or not isinstance(
            min_inactive_runs, int
        ) or min_inactive_runs < 1:
            raise ValueError("min_inactive_runs must be an integer >= 1")
        if isinstance(min_inactive_days, bool) or not isinstance(
            min_inactive_days, (int, float)
        ) or float(min_inactive_days) < 0.0:
            raise ValueError("min_inactive_days must be a non-negative number")
        if isinstance(default_searching_poe_watts, bool) or not isinstance(
            default_searching_poe_watts, (int, float)
        ) or float(default_searching_poe_watts) < 0.0:
            raise ValueError(
                "default_searching_poe_watts must be a non-negative number"
            )
        if isinstance(default_poe_restore_limit_mw, bool) or not isinstance(
            default_poe_restore_limit_mw, int
        ) or default_poe_restore_limit_mw < 0:
            raise ValueError(
                "default_poe_restore_limit_mw must be a non-negative integer"
            )

        self.min_inactive_runs: int = min_inactive_runs
        self.min_inactive_days: float = float(min_inactive_days)
        self.uplink_guard: LldpUplinkGuard = (
            uplink_guard
            if uplink_guard is not None
            else LldpUplinkGuard(arp_active_within_days=float(min_inactive_days))
        )
        self.dialect: ExtremeCliDialect = _coerce_cli_dialect(dialect, "dialect")
        self.default_searching_poe_watts: float = float(
            default_searching_poe_watts
        )
        self.default_poe_restore_limit_mw: int = default_poe_restore_limit_mw

    def plan(
        self,
        *,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        ports: Optional[Sequence[Port | Mapping[str, Any]]] = None,
        devices: Optional[Sequence[NetworkDevice | Mapping[str, Any]]] = None,
        streaks: Optional[
            Sequence[ItemStreakSummary | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        history_store: Optional[HistoryStore] = None,
        lldp_neighbors: Optional[
            Mapping[str, Any]
            | Sequence[LldpNeighborRecord | Mapping[str, Any]]
        ] = None,
        port_descriptions: Optional[Mapping[str, str]] = None,
        tagged_vlans_by_port: Optional[
            Mapping[str, Iterable[str | int]]
        ] = None,
        trunk_ports: Optional[Iterable[str]] = None,
        poe_watts_by_port: Optional[Mapping[str, float]] = None,
        poe_limit_mw_by_port: Optional[Mapping[str, int]] = None,
        snmp_oids_by_device: Optional[Mapping[str, Any]] = None,
        ip_addresses: Optional[Sequence[IPAddress | Mapping[str, Any]]] = None,
        arp_entries: Optional[Sequence[ArpEntry | Mapping[str, Any]]] = None,
        active_macs: Optional[Iterable[str]] = None,
        evaluation_time: Optional[datetime | str] = None,
        dialect: Optional[ExtremeCliDialect | str] = None,
        min_inactive_runs: Optional[int] = None,
        min_inactive_days: Optional[float] = None,
    ) -> PortReclamationPlan:
        """Evaluate candidate switch ports and generate a staged PortReclamationPlan."""
        effective_runs = (
            min_inactive_runs
            if min_inactive_runs is not None
            else self.min_inactive_runs
        )
        effective_days = (
            float(min_inactive_days)
            if min_inactive_days is not None
            else self.min_inactive_days
        )
        effective_dialect = (
            _coerce_cli_dialect(dialect, "dialect")
            if dialect is not None
            else self.dialect
        )
        if isinstance(effective_runs, bool) or not isinstance(
            effective_runs, int
        ) or effective_runs < 1:
            raise ValueError("min_inactive_runs must be an integer >= 1")
        if isinstance(effective_days, bool) or not isinstance(
            effective_days, (int, float)
        ) or effective_days < 0.0:
            raise ValueError("min_inactive_days must be a non-negative number")

        eval_dt = resolve_evaluation_time(evaluation_time)
        resolved_sites = self._normalize_sites(sites)
        site_by_id = {s.site_id: s for s in resolved_sites}

        port_entries = self._collect_candidate_ports(
            sites=resolved_sites,
            devices=devices,
            ports=ports,
        )
        streak_lookup = self._build_streak_lookup(
            streaks=streaks,
            history_store=history_store,
        )
        trunk_port_set = {
            p.strip() for p in (trunk_ports or ()) if isinstance(p, str) and p.strip()
        }

        candidates: list[PortReclamationCandidate] = []
        blocked_ports: list[BlockedPortRecord] = []

        for port_obj, extras, parent_dev, parent_site in port_entries:
            site_id = (
                parent_site.site_id
                if parent_site is not None
                else (
                    parent_dev.site_id
                    if parent_dev is not None
                    else _clean_optional_str(extras.get("site_id"))
                )
            )
            if parent_site is None and site_id is not None:
                parent_site = site_by_id.get(site_id)

            device_hostname = (
                parent_dev.hostname
                if parent_dev is not None
                else _clean_optional_str(extras.get("device_hostname"))
            )
            device_oids = self._resolve_device_oids(
                device_id=port_obj.device_id,
                snmp_oids_by_device=snmp_oids_by_device,
            )

            resolved_desc = self._lookup_by_port(
                port_obj, port_descriptions
            ) or _clean_optional_str(extras.get("description"))
            if resolved_desc is None and device_oids:
                alias_val = self._lookup_snmp_oid_for_port(
                    port=port_obj,
                    extras=extras,
                    oids=device_oids,
                    oid_prefix=IF_MIB_IF_ALIAS_PREFIX,
                )
                if alias_val is not None:
                    resolved_desc = _clean_optional_str(alias_val)

            resolved_tagged_vlans = self._lookup_by_port(
                port_obj, tagged_vlans_by_port
            )
            resolved_is_trunk: Optional[bool] = extras.get("is_trunk")
            if any(
                _port_matches_identifier(port_obj, tp) for tp in trunk_port_set
            ):
                resolved_is_trunk = True

            guard_decision = self.uplink_guard.evaluate_port(
                port_obj,
                device=parent_dev,
                site=parent_site,
                description=resolved_desc,
                tagged_vlans=resolved_tagged_vlans,
                is_trunk=resolved_is_trunk,
                vlan_mode=extras.get("vlan_mode"),
                lldp_neighbors=(
                    lldp_neighbors
                    if lldp_neighbors is not None
                    else (
                        extras.get("lldp_neighbors")
                        or extras.get("lldp_neighbor")
                    )
                ),
                ip_addresses=ip_addresses,
                arp_entries=arp_entries,
                has_recent_arp_activity=extras.get("has_recent_arp_activity"),
                has_recent_mac_activity=extras.get("has_recent_mac_activity"),
                active_macs=active_macs,
                evaluation_time=eval_dt,
            )

            inactive_runs, inactive_days, streak_cls = self._resolve_port_streak(
                port=port_obj,
                extras=extras,
                site=parent_site,
                streak_lookup=streak_lookup,
            )

            block_reasons = list(guard_decision.block_reasons)
            matched_rules = list(guard_decision.matched_rules)

            # Check if already administratively disabled
            admin_norm = (
                port_obj.admin_status.strip().lower()
                if isinstance(port_obj.admin_status, str)
                and port_obj.admin_status.strip()
                else None
            )
            if admin_norm is not None and admin_norm in _ADMIN_DISABLED_VALUES:
                matched_rules.append("admin_already_disabled")
                block_reasons.append(
                    f"Port {port_obj.name} is already administratively disabled (admin_status={port_obj.admin_status!r})"
                )

            # Check historical inactivity streak thresholds
            if (
                streak_cls is not None
                and streak_cls is not ValidationClassification.STALE_LIKELY_UNUSED
            ):
                matched_rules.append("below_inactivity_threshold")
                block_reasons.append(
                    f"Port {port_obj.name} classification is {streak_cls.value!r} (requires {ValidationClassification.STALE_LIKELY_UNUSED.value!r})"
                )
            elif (
                inactive_runs < effective_runs
                or inactive_days < effective_days
            ):
                matched_rules.append("below_inactivity_threshold")
                block_reasons.append(
                    f"Port {port_obj.name} inactivity streak ({inactive_runs} runs, {inactive_days:.1f} days) "
                    f"is below threshold (min_inactive_runs={effective_runs}, min_inactive_days={effective_days:.1f})"
                )

            if block_reasons:
                blocked_ports.append(
                    BlockedPortRecord(
                        port_id=port_obj.port_id,
                        device_id=port_obj.device_id,
                        port_name=port_obj.name,
                        site_id=site_id,
                        device_hostname=device_hostname,
                        blocked=True,
                        block_reason="; ".join(block_reasons),
                        block_reasons=tuple(block_reasons),
                        matched_rules=tuple(matched_rules),
                        admin_status=port_obj.admin_status,
                        oper_status=port_obj.oper_status,
                        poe_status=port_obj.poe_status,
                        vlan_id=port_obj.vlan_id,
                        description=resolved_desc,
                        connected_device_id=port_obj.connected_device_id,
                        inactive_runs=inactive_runs,
                        inactive_days=inactive_days,
                    )
                )
                continue

            poe_watts = self._resolve_poe_watts(
                port=port_obj,
                extras=extras,
                poe_watts_by_port=poe_watts_by_port,
                device_oids=device_oids,
            )
            poe_limit_mw = self._resolve_poe_restore_limit_mw(
                port=port_obj,
                extras=extras,
                poe_limit_mw_by_port=poe_limit_mw_by_port,
                device_oids=device_oids,
            )

            candidates.append(
                PortReclamationCandidate(
                    port_id=port_obj.port_id,
                    device_id=port_obj.device_id,
                    port_name=port_obj.name,
                    site_id=site_id,
                    device_hostname=device_hostname,
                    admin_status=port_obj.admin_status,
                    oper_status=port_obj.oper_status,
                    poe_status=port_obj.poe_status,
                    vlan_id=port_obj.vlan_id,
                    description=resolved_desc,
                    connected_device_id=port_obj.connected_device_id,
                    inactive_runs=inactive_runs,
                    inactive_days=inactive_days,
                    estimated_poe_watts_saved=poe_watts,
                    poe_restore_limit_mw=poe_limit_mw,
                    dialect=effective_dialect,
                )
            )

        total_poe_saved = round(
            sum(c.estimated_poe_watts_saved for c in candidates), 2
        )

        return PortReclamationPlan(
            candidates=tuple(candidates),
            blocked_ports=tuple(blocked_ports),
            estimated_poe_watts_saved=total_poe_saved,
            min_inactive_runs=effective_runs,
            min_inactive_days=effective_days,
            dialect=effective_dialect,
            generated_at=eval_dt,
            dry_run=True,
        )

    evaluate = plan

    @staticmethod
    def _normalize_sites(
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ],
    ) -> list[Site]:
        if sites is None:
            return []
        if isinstance(sites, Site):
            return [sites]
        if isinstance(sites, Mapping):
            if "site_id" in sites and "name" in sites:
                return [Site.from_dict(sites)]
            return [
                v if isinstance(v, Site) else Site.from_dict(v)
                for v in sites.values()
            ]
        if isinstance(sites, Sequence):
            return [
                s if isinstance(s, Site) else Site.from_dict(s) for s in sites
            ]
        return []

    @staticmethod
    def _is_extreme_switch(device: Optional[NetworkDevice]) -> bool:
        if device is None or not device.vendor or not device.vendor.strip():
            return True
        lowered = device.vendor.strip().lower()
        return any(tok in lowered for tok in ("extreme", "exos", "voss"))

    def _collect_candidate_ports(
        self,
        *,
        sites: Sequence[Site],
        devices: Optional[Sequence[NetworkDevice | Mapping[str, Any]]],
        ports: Optional[Sequence[Port | Mapping[str, Any]]],
    ) -> list[
        tuple[
            Port,
            dict[str, Any],
            Optional[NetworkDevice],
            Optional[Site],
        ]
    ]:
        collected: list[
            tuple[
                Port,
                dict[str, Any],
                Optional[NetworkDevice],
                Optional[Site],
            ]
        ] = []
        seen_keys: set[tuple[str, str]] = set()
        dev_by_id: dict[str, tuple[NetworkDevice, Optional[Site]]] = {}

        for site in sites:
            for dev in site.devices:
                dev_by_id[dev.device_id] = (dev, site)

        normalized_devices: list[NetworkDevice] = []
        if devices is not None:
            for raw_dev in devices:
                dev_obj = (
                    raw_dev
                    if isinstance(raw_dev, NetworkDevice)
                    else NetworkDevice.from_dict(raw_dev)
                )
                normalized_devices.append(dev_obj)
                if dev_obj.device_id not in dev_by_id:
                    dev_by_id[dev_obj.device_id] = (dev_obj, None)

        def _add_port(
            raw_port: Port | Mapping[str, Any],
            parent_dev: Optional[NetworkDevice],
            parent_site: Optional[Site],
        ) -> None:
            if not self._is_extreme_switch(parent_dev):
                return
            port_obj, extras = _coerce_port_and_extras(
                raw_port,
                default_device_id=(
                    parent_dev.device_id if parent_dev is not None else None
                ),
            )
            if parent_dev is None and port_obj.device_id in dev_by_id:
                parent_dev, inferred_site = dev_by_id[port_obj.device_id]
                if parent_site is None:
                    parent_site = inferred_site
                if not self._is_extreme_switch(parent_dev):
                    return
            key = (port_obj.device_id, port_obj.port_id)
            if key not in seen_keys:
                seen_keys.add(key)
                collected.append((port_obj, extras, parent_dev, parent_site))

        if ports is not None:
            for raw_port in ports:
                _add_port(raw_port, None, None)

        for dev_obj in normalized_devices:
            _, parent_site = dev_by_id.get(dev_obj.device_id, (dev_obj, None))
            for port_obj in dev_obj.ports:
                _add_port(port_obj, dev_obj, parent_site)

        for site in sites:
            for dev_obj in site.devices:
                for port_obj in dev_obj.ports:
                    _add_port(port_obj, dev_obj, site)

        return collected

    @staticmethod
    def _build_streak_lookup(
        *,
        streaks: Optional[
            Sequence[ItemStreakSummary | Mapping[str, Any]] | Mapping[str, Any]
        ],
        history_store: Optional[HistoryStore],
    ) -> dict[str, tuple[int, float, Optional[ValidationClassification]]]:
        lookup: dict[
            str, tuple[int, float, Optional[ValidationClassification]]
        ] = {}

        def _register_entry(
            key: str,
            runs: int,
            days: float,
            cls_val: Optional[ValidationClassification],
        ) -> None:
            cleaned = key.strip()
            if cleaned:
                lookup[cleaned] = (runs, days, cls_val)

        def _ingest_item(key_hint: Optional[str], item: Any) -> None:
            if isinstance(item, ItemStreakSummary):
                entry = (
                    item.consecutive_stale_runs,
                    item.stale_duration_days,
                    item.current_classification,
                )
                _register_entry(item.item_id, *entry)
                _register_entry(f"{item.item_type}:{item.item_id}", *entry)
                if item.name:
                    _register_entry(item.name, *entry)
                if key_hint:
                    _register_entry(key_hint, *entry)
            elif isinstance(item, Mapping):
                runs = int(
                    item.get(
                        "consecutive_stale_runs",
                        item.get("inactive_runs", 0),
                    )
                )
                days = float(
                    item.get(
                        "stale_duration_days",
                        item.get("inactive_days", 0.0),
                    )
                )
                raw_cls = item.get(
                    "current_classification", item.get("classification")
                )
                cls_val: Optional[ValidationClassification] = None
                if raw_cls is not None:
                    cls_val = (
                        raw_cls
                        if isinstance(raw_cls, ValidationClassification)
                        else ValidationClassification(raw_cls)
                    )
                item_id = _clean_optional_str(
                    item.get("item_id") or item.get("port_id") or key_hint
                )
                if item_id:
                    _register_entry(item_id, runs, days, cls_val)
                name = _clean_optional_str(
                    item.get("name") or item.get("port_name")
                )
                if name:
                    _register_entry(name, runs, days, cls_val)
                if key_hint:
                    _register_entry(key_hint, runs, days, cls_val)
            elif (
                isinstance(item, tuple)
                and len(item) >= 2
                and key_hint is not None
            ):
                _register_entry(key_hint, int(item[0]), float(item[1]), None)

        if history_store is not None:
            for streak in history_store.list_streaks():
                _ingest_item(streak.item_id, streak)

        if streaks is not None:
            if isinstance(streaks, Mapping):
                for k, v in streaks.items():
                    key_str = (
                        f"{k[0]}:{k[1]}"
                        if isinstance(k, tuple) and len(k) == 2
                        else str(k)
                    )
                    _ingest_item(key_str, v)
                    if isinstance(k, tuple) and len(k) == 2:
                        _ingest_item(str(k[1]), v)
            elif isinstance(streaks, Sequence):
                for item in streaks:
                    _ingest_item(None, item)

        return lookup

    @staticmethod
    def _resolve_port_streak(
        *,
        port: Port,
        extras: Mapping[str, Any],
        site: Optional[Site],
        streak_lookup: Mapping[
            str, tuple[int, float, Optional[ValidationClassification]]
        ],
    ) -> tuple[int, float, Optional[ValidationClassification]]:
        raw_runs = extras.get(
            "inactive_runs", extras.get("consecutive_stale_runs")
        )
        raw_days = extras.get(
            "inactive_days", extras.get("stale_duration_days")
        )
        if raw_runs is not None or raw_days is not None:
            return (
                int(raw_runs or 0),
                float(raw_days or 0.0),
                None,
            )

        candidate_keys: list[str] = [
            port.port_id,
            f"port:{port.port_id}",
            f"{port.device_id}:{port.name}",
            f"{port.device_id}:{port.port_id}",
            port.name,
        ]
        if port.connected_device_id:
            candidate_keys.append(port.connected_device_id)
            candidate_keys.append(f"equipment:{port.connected_device_id}")

        if site is not None:
            for eq in site.equipment:
                if (
                    port.port_id in eq.connected_ports
                    or port.name in eq.connected_ports
                    or f"{port.device_id}:{port.name}" in eq.connected_ports
                ):
                    candidate_keys.append(eq.equipment_id)
                    candidate_keys.append(f"equipment:{eq.equipment_id}")

        for key in candidate_keys:
            if key in streak_lookup:
                return streak_lookup[key]

        return (0, 0.0, None)

    @staticmethod
    def _lookup_by_port(
        port: Port, mapping: Optional[Mapping[str, Any]]
    ) -> Any:
        if not mapping:
            return None
        for key in (
            port.port_id,
            f"{port.device_id}:{port.name}",
            f"{port.device_id}:{port.port_id}",
            port.name,
        ):
            if key in mapping:
                return mapping[key]
        return None

    @staticmethod
    def _resolve_device_oids(
        *,
        device_id: str,
        snmp_oids_by_device: Optional[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        if not snmp_oids_by_device:
            return {}
        if "targets" in snmp_oids_by_device and isinstance(
            snmp_oids_by_device["targets"], Mapping
        ):
            target = snmp_oids_by_device["targets"].get(device_id)
            if isinstance(target, Mapping):
                oids = target.get("oids", target)
                if isinstance(oids, Mapping):
                    return oids
        if device_id in snmp_oids_by_device:
            dev_entry = snmp_oids_by_device[device_id]
            if isinstance(dev_entry, Mapping):
                if "oids" in dev_entry and isinstance(
                    dev_entry["oids"], Mapping
                ):
                    return dev_entry["oids"]
                return dev_entry
        # Support flat OID dictionary passed directly
        if any(str(k).startswith("1.3.6.1.") for k in snmp_oids_by_device):
            return snmp_oids_by_device
        return {}

    @staticmethod
    def _lookup_snmp_oid_for_port(
        *,
        port: Port,
        extras: Mapping[str, Any],
        oids: Mapping[str, Any],
        oid_prefix: str,
    ) -> Any:
        if not oids:
            return None

        candidate_indices: list[str] = []
        if_index = extras.get("if_index")
        if if_index is not None:
            candidate_indices.append(str(if_index).strip())

        slot_port_match = _SLOT_PORT_PATTERN.match(port.name.strip())
        if slot_port_match:
            slot_num = int(slot_port_match.group(1))
            port_num = int(slot_port_match.group(2))
            if_idx = slot_num * 1000 + port_num
            candidate_indices.extend(
                [
                    f"{slot_num}.{if_idx}",
                    str(if_idx),
                    f"{slot_num}.{port_num}",
                    str(port_num),
                ]
            )
        else:
            trailing = _PORT_TRAILING_DIGITS_PATTERN.search(port.name.strip())
            if trailing:
                p_num = int(trailing.group(1))
                candidate_indices.extend(
                    [
                        f"1.{1000 + p_num}",
                        str(1000 + p_num),
                        f"1.{p_num}",
                        str(p_num),
                    ]
                )

        id_trailing = _PORT_TRAILING_DIGITS_PATTERN.search(port.port_id.strip())
        if id_trailing:
            p_num = int(id_trailing.group(1))
            for idx in (
                f"1.{1000 + p_num}",
                str(1000 + p_num),
                f"1.{p_num}",
                str(p_num),
            ):
                if idx not in candidate_indices:
                    candidate_indices.append(idx)

        for suffix in candidate_indices:
            full_oid = f"{oid_prefix}.{suffix}"
            if full_oid in oids:
                return oids[full_oid]

        return None

    def _resolve_poe_watts(
        self,
        *,
        port: Port,
        extras: Mapping[str, Any],
        poe_watts_by_port: Optional[Mapping[str, float]],
        device_oids: Mapping[str, Any],
    ) -> float:
        explicit_watts = self._lookup_by_port(port, poe_watts_by_port)
        if explicit_watts is not None:
            return round(max(0.0, float(explicit_watts)), 2)

        for key in (
            "poe_power_w",
            "poe_watts",
            "estimated_poe_watts_saved",
            "poe_draw_watts",
        ):
            val = extras.get(key)
            if val is not None and str(val).strip() != "":
                try:
                    return round(max(0.0, float(val)), 2)
                except ValueError:
                    pass

        mw_val = extras.get("poe_power_mw")
        if mw_val is not None and str(mw_val).strip() != "":
            try:
                return round(max(0.0, float(mw_val) / 1000.0), 2)
            except ValueError:
                pass

        if device_oids:
            oid_mw = self._lookup_snmp_oid_for_port(
                port=port,
                extras=extras,
                oids=device_oids,
                oid_prefix=EXTREME_POE_PORT_MEASURED_POWER_PREFIX,
            )
            if oid_mw is not None:
                try:
                    watts = float(oid_mw) / 1000.0
                    if watts > 0.0:
                        return round(watts, 2)
                except (TypeError, ValueError):
                    pass

        if port.poe_status:
            poe_text = port.poe_status.strip()
            mw_match = _MILLIWATT_PATTERN.search(poe_text)
            if mw_match is not None:
                return round(float(mw_match.group(1)) / 1000.0, 2)
            watt_match = _WATTAGE_PATTERN.search(poe_text)
            if watt_match is not None:
                return round(float(watt_match.group(1)), 2)
            poe_norm = poe_text.lower()
            if poe_norm in (
                "searching",
                "enabled",
                "on",
                "auto",
                "standby",
                "delivering",
            ):
                return round(self.default_searching_poe_watts, 2)

        return 0.0

    def _resolve_poe_restore_limit_mw(
        self,
        *,
        port: Port,
        extras: Mapping[str, Any],
        poe_limit_mw_by_port: Optional[Mapping[str, int]],
        device_oids: Mapping[str, Any],
    ) -> int:
        explicit_limit = self._lookup_by_port(port, poe_limit_mw_by_port)
        if explicit_limit is not None:
            return max(0, int(explicit_limit))

        for key in (
            "poe_restore_limit_mw",
            "poe_operator_limit_mw",
            "poe_limit_mw",
        ):
            val = extras.get(key)
            if val is not None and str(val).strip() != "":
                try:
                    limit_int = int(float(val))
                    if limit_int > 0:
                        return limit_int
                except ValueError:
                    pass

        if device_oids:
            oid_limit = self._lookup_snmp_oid_for_port(
                port=port,
                extras=extras,
                oids=device_oids,
                oid_prefix=EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX,
            )
            if oid_limit is not None:
                try:
                    limit_int = int(float(oid_limit))
                    if limit_int > 0:
                        return limit_int
                except (TypeError, ValueError):
                    pass

        return self.default_poe_restore_limit_mw


__all__ = [
    "BlockedPortRecord",
    "DEFAULT_BLOCKED_LLDP_CAPABILITIES",
    "DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS",
    "ExtremeCliDialect",
    "ExtremePortReclamationPlanner",
    "LldpGuardDecision",
    "LldpNeighborRecord",
    "LldpUplinkGuard",
    "PortReclamationCandidate",
    "PortReclamationPlan",
]
