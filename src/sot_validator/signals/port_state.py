"""Passive validation signal evaluator for switch port link, admin, and PoE state."""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any, Iterable, Optional, Sequence

from sot_validator.models import (
    Equipment,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals.base import SignalCollector, resolve_evaluation_time

_ADMIN_DISABLED_VALUES: frozenset[str] = frozenset(
    {
        "down",
        "disabled",
        "disable",
        "admin_down",
        "admindown",
        "admin-down",
        "shutdown",
        "shut",
        "false",
        "0",
        "off",
    }
)

_OPER_ACTIVE_VALUES: frozenset[str] = frozenset(
    {
        "up",
        "active",
        "connected",
        "connect",
        "1",
        "true",
        "ok",
        "forwarding",
    }
)

_OPER_INACTIVE_VALUES: frozenset[str] = frozenset(
    {
        "down",
        "inactive",
        "disconnected",
        "notconnect",
        "notconnected",
        "not-connected",
        "not_connected",
        "dormant",
        "lowerlayerdown",
        "lower_layer_down",
        "0",
        "false",
        "err-disabled",
        "errdisabled",
        "disabled",
    }
)

_POE_ACTIVE_KEYWORDS: frozenset[str] = frozenset(
    {
        "delivering",
        "delivering power",
        "active",
        "powering",
        "drawing",
        "on",
    }
)

_POE_INACTIVE_KEYWORDS: frozenset[str] = frozenset(
    {
        "off",
        "disabled",
        "inactive",
        "searching",
        "fault",
        "denied",
        "none",
        "0",
        "false",
    }
)

_WATTAGE_PATTERN = re.compile(r"(\d+(?:\.\d+)?)\s*(?:w|watts?)\b", re.IGNORECASE)


def _normalize_token(value: Optional[str]) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    return cleaned if cleaned else None


def _evaluate_poe_state(poe_status: Optional[str]) -> Optional[bool]:
    """Return True if PoE is actively delivering power, False if explicitly inactive, None if unknown."""
    norm = _normalize_token(poe_status)
    if norm is None:
        return None

    watt_match = _WATTAGE_PATTERN.search(norm)
    if watt_match is not None:
        watts = float(watt_match.group(1))
        return watts > 0.0

    if norm in _POE_ACTIVE_KEYWORDS or any(
        kw in norm for kw in ("delivering", "powering", "drawing")
    ):
        return True

    if norm in _POE_INACTIVE_KEYWORDS:
        return False

    return None


def evaluate_single_port(port: Port) -> tuple[SignalStatus, str]:
    """Evaluate a single switch port's operational, administrative, and PoE state."""
    admin_norm = _normalize_token(port.admin_status)
    oper_norm = _normalize_token(port.oper_status)
    poe_norm = _normalize_token(port.poe_status)

    port_label = f"{port.device_id}:{port.name} ({port.port_id})"
    state_summary = (
        f"admin={port.admin_status!r}, oper={port.oper_status!r}, poe={port.poe_status!r}"
    )

    if admin_norm is None and oper_norm is None and poe_norm is None:
        return (
            SignalStatus.NOT_APPLICABLE,
            f"Port {port_label} [{state_summary}] -> {SignalStatus.NOT_APPLICABLE.value} (no state recorded)",
        )

    is_admin_disabled = admin_norm in _ADMIN_DISABLED_VALUES if admin_norm else False
    is_oper_active = oper_norm in _OPER_ACTIVE_VALUES if oper_norm else False
    is_oper_inactive = oper_norm in _OPER_INACTIVE_VALUES if oper_norm else False
    poe_active = _evaluate_poe_state(port.poe_status)

    if is_admin_disabled:
        return (
            SignalStatus.INACTIVE,
            f"Port {port_label} [{state_summary}] -> {SignalStatus.INACTIVE.value} (administratively disabled)",
        )

    if is_oper_active or poe_active is True:
        reasons: list[str] = []
        if is_oper_active:
            reasons.append("link UP")
        if poe_active is True:
            reasons.append("PoE delivering power")
        reason_str = " and ".join(reasons)
        return (
            SignalStatus.ACTIVE,
            f"Port {port_label} [{state_summary}] -> {SignalStatus.ACTIVE.value} ({reason_str})",
        )

    if is_oper_inactive or poe_active is False:
        return (
            SignalStatus.INACTIVE,
            f"Port {port_label} [{state_summary}] -> {SignalStatus.INACTIVE.value} (link down / no PoE draw)",
        )

    return (
        SignalStatus.NOT_APPLICABLE,
        f"Port {port_label} [{state_summary}] -> {SignalStatus.NOT_APPLICABLE.value} (indeterminate port state)",
    )


class PortStateSignalEvaluator(SignalCollector):
    """Evaluate switch port operational, administrative, and PoE state for inventory targets."""

    signal_type = SignalType.PORT_STATE

    def __init__(
        self,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "sot.port_state",
    ) -> None:
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = source

    def evaluate(
        self,
        target: Any,
        *,
        site: Optional[Site] = None,
        ports: Optional[Sequence[Port]] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate port state across single or redundant multi-port mappings."""
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else self.evaluation_time
        )

        resolved_ports = self._resolve_ports(target=target, site=site, ports=ports)

        if not resolved_ports:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=eval_dt,
                age_seconds=None,
                details="No mapped switch ports found for target",
                source=self.source,
            )

        statuses: list[SignalStatus] = []
        details_list: list[str] = []

        for port in resolved_ports:
            port_status, port_detail = evaluate_single_port(port)
            statuses.append(port_status)
            details_list.append(port_detail)

        if any(s is SignalStatus.ACTIVE for s in statuses):
            overall_status = SignalStatus.ACTIVE
        elif any(s is SignalStatus.INACTIVE for s in statuses):
            overall_status = SignalStatus.INACTIVE
        else:
            overall_status = SignalStatus.NOT_APPLICABLE

        return ValidationSignal(
            signal_type=self.signal_type,
            status=overall_status,
            observed_at=eval_dt,
            age_seconds=None,
            details="; ".join(details_list),
            source=self.source,
        )

    def _resolve_ports(
        self,
        *,
        target: Any,
        site: Optional[Site],
        ports: Optional[Sequence[Port]],
    ) -> list[Port]:
        if isinstance(target, Port):
            return [target]

        if isinstance(target, Equipment):
            return self._resolve_equipment_ports(
                equipment=target, site=site, ports=ports
            )

        if isinstance(target, NetworkDevice):
            return self._resolve_device_ports(device=target, site=site, ports=ports)

        if isinstance(target, Iterable) and not isinstance(target, (str, bytes, dict)):
            collected: list[Port] = []
            for item in target:
                if isinstance(item, Port):
                    collected.append(item)
                else:
                    collected.extend(
                        self._resolve_ports(target=item, site=site, ports=ports)
                    )
            return collected

        return []

    @staticmethod
    def _available_ports(
        site: Optional[Site], ports: Optional[Sequence[Port]]
    ) -> list[Port]:
        available: list[Port] = []
        seen: set[tuple[str, str, str]] = set()

        def _add(port: Port) -> None:
            key = (port.device_id, port.port_id, port.name)
            if key not in seen:
                seen.add(key)
                available.append(port)

        if ports:
            for port in ports:
                _add(port)
        if site is not None:
            for dev in site.devices:
                for port in dev.ports:
                    _add(port)
        return available

    def _resolve_equipment_ports(
        self,
        *,
        equipment: Equipment,
        site: Optional[Site],
        ports: Optional[Sequence[Port]],
    ) -> list[Port]:
        connected_refs = {
            ref.strip() for ref in equipment.connected_ports if ref and ref.strip()
        }
        matched: list[Port] = []
        for port in self._available_ports(site, ports):
            if (
                port.port_id in connected_refs
                or port.name in connected_refs
                or f"{port.device_id}:{port.name}" in connected_refs
                or f"{port.device_id}:{port.port_id}" in connected_refs
                or port.connected_device_id == equipment.equipment_id
            ):
                matched.append(port)
        return matched

    def _resolve_device_ports(
        self,
        *,
        device: NetworkDevice,
        site: Optional[Site],
        ports: Optional[Sequence[Port]],
    ) -> list[Port]:
        matched: list[Port] = []
        seen: set[tuple[str, str, str]] = set()

        def _add(port: Port) -> None:
            key = (port.device_id, port.port_id, port.name)
            if key not in seen:
                seen.add(key)
                matched.append(port)

        for port in device.ports:
            _add(port)

        for port in self._available_ports(site, ports):
            if (
                port.device_id == device.device_id
                or port.connected_device_id == device.device_id
            ):
                _add(port)

        return matched


__all__ = ["PortStateSignalEvaluator", "evaluate_single_port"]
