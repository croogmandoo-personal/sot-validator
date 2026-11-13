"""History retention policy and prune report for the validation run ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from sot_validator.models import _format_optional_datetime


def _require_optional_positive_int(value: Any, field_name: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be None or a positive integer")
    return value


@dataclass(frozen=True)
class RetentionPolicy:
    """Age and per-site run-count limits; a run is prunable when either limit marks it."""

    max_age_days: Optional[int] = None
    max_runs_per_site: Optional[int] = None

    def __post_init__(self) -> None:
        _require_optional_positive_int(self.max_age_days, "max_age_days")
        _require_optional_positive_int(self.max_runs_per_site, "max_runs_per_site")

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_age_days": self.max_age_days,
            "max_runs_per_site": self.max_runs_per_site,
        }


@dataclass
class PruneReport:
    """Runs and drift rows selected (dry run) or deleted by ``HistoryStore.prune_runs``."""

    dry_run: bool
    policy: RetentionPolicy
    now: datetime
    age_cutoff: Optional[datetime]
    run_ids: list[str] = field(default_factory=list)
    run_count: int = 0
    drift_event_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "policy": self.policy.to_dict(),
            "now": self.now.isoformat(),
            "age_cutoff": _format_optional_datetime(self.age_cutoff),
            "run_ids": list(self.run_ids),
            "run_count": self.run_count,
            "drift_event_count": self.drift_event_count,
        }


__all__ = ["PruneReport", "RetentionPolicy"]
