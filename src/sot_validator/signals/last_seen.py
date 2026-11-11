"""Passive validation signal evaluator for SoT last-seen timestamps."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    IPAddress,
    NetworkDevice,
    SignalStatus,
    SignalType,
    ValidationSignal,
)
from sot_validator.signals.base import (
    SignalCollector,
    evaluate_timestamp_recency,
    normalize_utc_datetime,
    resolve_evaluation_time,
    validate_recency_thresholds,
)


class LastSeenSignalEvaluator(SignalCollector):
    """Evaluate last_seen timestamp recency on NetworkDevice, Equipment, and IP records."""

    signal_type = SignalType.LAST_SEEN_TIMESTAMP

    def __init__(
        self,
        active_within_days: float = 7.0,
        stale_after_days: float = 30.0,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "sot.last_seen",
    ) -> None:
        self.active_within_days, self.stale_after_days = validate_recency_thresholds(
            active_within_days, stale_after_days
        )
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
        evaluation_time: Optional[datetime | str] = None,
        active_within_days: Optional[float] = None,
        stale_after_days: Optional[float] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate the last_seen timestamp on an inventory record."""
        active_days = (
            self.active_within_days
            if active_within_days is None
            else active_within_days
        )
        stale_days = (
            self.stale_after_days if stale_after_days is None else stale_after_days
        )
        active_days, stale_days = validate_recency_thresholds(active_days, stale_days)

        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (
                self.evaluation_time
                if self.evaluation_time is not None
                else resolve_evaluation_time(None)
            )
        )

        has_field, raw_ts, target_label = self._extract_raw_timestamp(target)

        if not has_field:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.ERROR,
                observed_at=None,
                age_seconds=None,
                details=f"Unsupported target for last_seen evaluation: {target_label}",
                source=self.source,
            )

        if raw_ts is None or (isinstance(raw_ts, str) and not raw_ts.strip()):
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"{target_label}: no last_seen timestamp recorded",
                source=self.source,
            )

        try:
            obs_dt = normalize_utc_datetime(raw_ts, field_name="last_seen")
        except ValueError as exc:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.ERROR,
                observed_at=None,
                age_seconds=None,
                details=f"{target_label}: invalid last_seen timestamp ({exc})",
                source=self.source,
            )

        status, obs_utc, age_seconds, summary = evaluate_timestamp_recency(
            observed_at=obs_dt,
            evaluation_time=eval_dt,
            active_within_days=active_days,
            stale_after_days=stale_days,
            label=f"last_seen for {target_label}",
        )

        return ValidationSignal(
            signal_type=self.signal_type,
            status=status,
            observed_at=obs_utc,
            age_seconds=age_seconds,
            details=summary,
            source=self.source,
        )

    @staticmethod
    def _extract_raw_timestamp(target: Any) -> tuple[bool, Any, str]:
        if target is None:
            return True, None, "target"

        if isinstance(target, NetworkDevice):
            return True, target.last_seen, f"NetworkDevice {target.hostname} ({target.device_id})"

        if isinstance(target, Equipment):
            return True, target.last_seen, f"Equipment {target.name} ({target.equipment_id})"

        if isinstance(target, IPAddress):
            raw = getattr(target, "last_seen", None)
            if raw is None:
                raw = target.arp_last_seen
            if raw is None and isinstance(target.arp_entry, ArpEntry):
                raw = target.arp_entry.arp_last_seen
            return True, raw, f"IPAddress {target.ip}"

        if isinstance(target, ArpEntry):
            raw = getattr(target, "last_seen", None)
            if raw is None:
                raw = target.arp_last_seen
            return True, raw, f"ArpEntry {target.ip}"

        if isinstance(target, Mapping):
            if "last_seen" in target:
                return True, target["last_seen"], "mapping"
            if "arp_last_seen" in target:
                return True, target["arp_last_seen"], "mapping"
            return True, None, "mapping"

        if isinstance(target, (datetime, str)):
            return True, target, "timestamp"

        if hasattr(target, "last_seen"):
            return True, getattr(target, "last_seen"), type(target).__name__

        if hasattr(target, "arp_last_seen"):
            return True, getattr(target, "arp_last_seen"), type(target).__name__

        return False, None, type(target).__name__


__all__ = ["LastSeenSignalEvaluator"]
