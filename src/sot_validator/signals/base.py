"""Base signal collector interface and shared timestamp/recency evaluation utilities."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from sot_validator.models import SignalStatus, SignalType, ValidationSignal

SECONDS_PER_DAY: float = 86400.0


def normalize_utc_datetime(
    value: datetime | str, field_name: str = "timestamp"
) -> datetime:
    """Normalize a datetime object or ISO-8601 string to a timezone-aware UTC datetime.

    Naive datetimes and naive ISO-8601 strings are assumed to represent UTC.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError(f"{field_name} must not be an empty string")
        if raw.endswith(("Z", "z")):
            raw = raw[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError(
                f"{field_name} must be a valid ISO-8601 datetime string: {value!r}"
            ) from exc
    else:
        raise ValueError(
            f"{field_name} must be a datetime instance or ISO-8601 string, got {type(value).__name__}"
        )

    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def resolve_evaluation_time(
    evaluation_time: Optional[datetime | str] = None,
) -> datetime:
    """Resolve an optional evaluation_time to a timezone-aware UTC datetime."""
    if evaluation_time is None:
        return datetime.now(timezone.utc)
    return normalize_utc_datetime(evaluation_time, field_name="evaluation_time")


def validate_recency_thresholds(
    active_within_days: float, stale_after_days: float
) -> tuple[float, float]:
    """Validate and normalize active_within_days and stale_after_days thresholds."""
    if isinstance(active_within_days, bool) or not isinstance(
        active_within_days, (int, float)
    ):
        raise ValueError("active_within_days must be a non-negative number")
    if isinstance(stale_after_days, bool) or not isinstance(
        stale_after_days, (int, float)
    ):
        raise ValueError("stale_after_days must be a non-negative number")

    active_days = float(active_within_days)
    stale_days = float(stale_after_days)

    if active_days < 0.0:
        raise ValueError("active_within_days must be non-negative")
    if stale_days < 0.0:
        raise ValueError("stale_after_days must be non-negative")
    if active_days > stale_days:
        raise ValueError("active_within_days must not exceed stale_after_days")

    return active_days, stale_days


def evaluate_timestamp_recency(
    observed_at: datetime,
    evaluation_time: datetime,
    active_within_days: float = 7.0,
    stale_after_days: float = 30.0,
    label: str = "Timestamp",
) -> tuple[SignalStatus, datetime, float, str]:
    """Evaluate a timestamp's recency against active and stale thresholds.

    Returns (status, normalized_observed_at, age_seconds, summary_detail).
    """
    active_days, stale_days = validate_recency_thresholds(
        active_within_days, stale_after_days
    )
    obs_utc = normalize_utc_datetime(observed_at, field_name="observed_at")
    eval_utc = resolve_evaluation_time(evaluation_time)

    age_seconds = max(0.0, (eval_utc - obs_utc).total_seconds())
    age_days = age_seconds / SECONDS_PER_DAY
    active_threshold_seconds = active_days * SECONDS_PER_DAY
    stale_threshold_seconds = stale_days * SECONDS_PER_DAY

    if age_seconds <= active_threshold_seconds:
        status = SignalStatus.ACTIVE
        detail = (
            f"{label} is active: observed at {obs_utc.isoformat()} "
            f"(age {age_days:.2f}d <= active threshold {active_days:g}d)"
        )
    elif age_seconds <= stale_threshold_seconds:
        status = SignalStatus.INACTIVE
        detail = (
            f"{label} is in intermediate aging window: observed at {obs_utc.isoformat()} "
            f"(age {age_days:.2f}d > active threshold {active_days:g}d, "
            f"<= stale threshold {stale_days:g}d)"
        )
    else:
        status = SignalStatus.INACTIVE
        detail = (
            f"{label} is stale: observed at {obs_utc.isoformat()} "
            f"(age {age_days:.2f}d > stale threshold {stale_days:g}d)"
        )

    return status, obs_utc, age_seconds, detail


class SignalCollector(ABC):
    """Abstract base interface for validation signal collectors and evaluators."""

    signal_type: SignalType

    @abstractmethod
    def evaluate(self, target: Any, **kwargs: Any) -> ValidationSignal:
        """Evaluate the validation signal for a given inventory target."""
        raise NotImplementedError


__all__ = [
    "SECONDS_PER_DAY",
    "SignalCollector",
    "evaluate_timestamp_recency",
    "normalize_utc_datetime",
    "resolve_evaluation_time",
    "validate_recency_thresholds",
]
