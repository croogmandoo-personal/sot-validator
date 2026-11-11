"""Phase 2 dry-run remediation action sink and plan generator (strictly read-only)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.extraction.client import ReadOnlyViolationError
from sot_validator.models import (
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)


def _enforce_dry_run_only(dry_run: Any, context: str) -> bool:
    if dry_run is not True:
        raise ReadOnlyViolationError(
            f"{context} strictly enforces dry_run=True in Phase 1; "
            f"live write-back or mutating actions (dry_run={dry_run!r}) are prohibited"
        )
    return True


def _resolve_plan_timestamp(value: Optional[datetime | str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = _parse_optional_datetime(value, "generated_at")
    assert parsed is not None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class RemediationActionType(str, Enum):
    """Supported Phase 2 dry-run remediation action types."""

    MARK_STALE_CANDIDATE = "MARK_STALE_CANDIDATE"
    FLAG_FOR_REVIEW = "FLAG_FOR_REVIEW"


@dataclass
class ProposedRemediationAction:
    """Single dry-run proposed remediation action derived from a ValidationResult."""

    action_type: RemediationActionType
    site_id: str
    item_type: str
    item_id: str
    name: str
    classification: ValidationClassification
    confidence: float
    rationale: Optional[str] = None
    proposed_at: Optional[datetime] = None
    dry_run: bool = True

    def __post_init__(self) -> None:
        self.dry_run = _enforce_dry_run_only(self.dry_run, "ProposedRemediationAction")
        if not isinstance(self.action_type, RemediationActionType):
            try:
                self.action_type = RemediationActionType(self.action_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid action_type: {self.action_type!r}"
                ) from exc
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.item_type, "item_type")
        _require_non_empty_str(self.item_id, "item_id")
        _require_non_empty_str(self.name, "name")
        if not isinstance(self.classification, ValidationClassification):
            try:
                self.classification = ValidationClassification(self.classification)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid classification: {self.classification!r}"
                ) from exc
        if isinstance(self.confidence, bool) or not isinstance(
            self.confidence, (int, float)
        ):
            raise ValueError("confidence must be a number between 0.0 and 1.0")
        self.confidence = float(self.confidence)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")
        self.proposed_at = _parse_optional_datetime(self.proposed_at, "proposed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type.value,
            "site_id": self.site_id,
            "item_type": self.item_type,
            "item_id": self.item_id,
            "name": self.name,
            "classification": self.classification.value,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "proposed_at": _format_optional_datetime(self.proposed_at),
            "dry_run": self.dry_run,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProposedRemediationAction:
        dry_run_val = data.get("dry_run", True)
        _enforce_dry_run_only(dry_run_val, "ProposedRemediationAction")
        return cls(
            action_type=RemediationActionType(data["action_type"]),
            site_id=data["site_id"],
            item_type=data["item_type"],
            item_id=data["item_id"],
            name=data["name"],
            classification=ValidationClassification(data["classification"]),
            confidence=data.get("confidence", 0.0),
            rationale=data.get("rationale"),
            proposed_at=_parse_optional_datetime(
                data.get("proposed_at"), "proposed_at"
            ),
            dry_run=dry_run_val,
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ProposedRemediationAction:
        return cls.from_dict(json.loads(raw))


@dataclass
class DryRunActionPlan:
    """Read-only Phase 2 remediation action plan summarizing proposed dry-run actions."""

    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    dry_run: bool = True
    total_evaluated: int = 0
    actions: list[ProposedRemediationAction] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.dry_run = _enforce_dry_run_only(self.dry_run, "DryRunActionPlan")
        self.generated_at = _resolve_plan_timestamp(self.generated_at)
        if isinstance(self.total_evaluated, bool) or not isinstance(
            self.total_evaluated, int
        ) or self.total_evaluated < 0:
            raise ValueError("total_evaluated must be a non-negative integer")
        self.actions = [
            a
            if isinstance(a, ProposedRemediationAction)
            else ProposedRemediationAction.from_dict(a)
            for a in self.actions
        ]

    @property
    def summary_by_action(self) -> dict[str, int]:
        counts: dict[str, int] = {
            RemediationActionType.MARK_STALE_CANDIDATE.value: 0,
            RemediationActionType.FLAG_FOR_REVIEW.value: 0,
        }
        for action in self.actions:
            counts[action.action_type.value] = (
                counts.get(action.action_type.value, 0) + 1
            )
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": _format_optional_datetime(self.generated_at),
            "dry_run": self.dry_run,
            "total_evaluated": self.total_evaluated,
            "total_actions": len(self.actions),
            "summary_by_action": self.summary_by_action,
            "actions": [a.to_dict() for a in self.actions],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DryRunActionPlan:
        dry_run_val = data.get("dry_run", True)
        _enforce_dry_run_only(dry_run_val, "DryRunActionPlan")
        raw_actions = data.get("actions", [])
        actions = [
            a
            if isinstance(a, ProposedRemediationAction)
            else ProposedRemediationAction.from_dict(a)
            for a in raw_actions
        ]
        total_eval = data.get("total_evaluated")
        if total_eval is None:
            total_eval = len(actions)
        return cls(
            generated_at=_resolve_plan_timestamp(data.get("generated_at")),
            dry_run=dry_run_val,
            total_evaluated=int(total_eval),
            actions=actions,
        )

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> DryRunActionPlan:
        return cls.from_dict(json.loads(raw))


class RemediationActionSink(ABC):
    """Abstract Phase 2 hook for consuming ValidationResult records into a dry-run action plan."""

    @abstractmethod
    def process_results(
        self, results: Sequence[ValidationResult]
    ) -> DryRunActionPlan:
        """Process evaluated ValidationResult records and return a DryRunActionPlan."""


class DryRunActionPlanGenerator(RemediationActionSink):
    """Read-only Phase 2 action plan generator mapping Stale and Review items to dry-run actions."""

    def __init__(
        self,
        *,
        dry_run: bool = True,
        generated_at: Optional[datetime | str] = None,
    ) -> None:
        self.dry_run = _enforce_dry_run_only(dry_run, "DryRunActionPlanGenerator")
        self.generated_at: Optional[datetime] = (
            _resolve_plan_timestamp(generated_at)
            if generated_at is not None
            else None
        )

    def generate_plan(
        self,
        results: Sequence[ValidationResult],
        *,
        generated_at: Optional[datetime | str] = None,
    ) -> DryRunActionPlan:
        """Build a DryRunActionPlan from a sequence of ValidationResult items."""
        _enforce_dry_run_only(self.dry_run, "DryRunActionPlanGenerator")
        plan_dt = _resolve_plan_timestamp(
            generated_at if generated_at is not None else self.generated_at
        )
        actions: list[ProposedRemediationAction] = []

        for raw_res in results:
            res = (
                raw_res
                if isinstance(raw_res, ValidationResult)
                else ValidationResult.from_dict(raw_res)
            )
            if res.classification is ValidationClassification.STALE_LIKELY_UNUSED:
                action_type = RemediationActionType.MARK_STALE_CANDIDATE
            elif (
                res.classification
                is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
            ):
                action_type = RemediationActionType.FLAG_FOR_REVIEW
            else:
                continue

            proposed_dt = res.evaluated_at if res.evaluated_at is not None else plan_dt
            actions.append(
                ProposedRemediationAction(
                    action_type=action_type,
                    site_id=res.site_id,
                    item_type=res.item_type,
                    item_id=res.item_id,
                    name=res.name,
                    classification=res.classification,
                    confidence=res.confidence,
                    rationale=res.rationale,
                    proposed_at=proposed_dt,
                    dry_run=True,
                )
            )

        return DryRunActionPlan(
            generated_at=plan_dt,
            dry_run=True,
            total_evaluated=len(results),
            actions=actions,
        )

    def process_results(
        self,
        results: Sequence[ValidationResult],
        *,
        generated_at: Optional[datetime | str] = None,
    ) -> DryRunActionPlan:
        """Process ValidationResult records into a DryRunActionPlan (RemediationActionSink interface)."""
        return self.generate_plan(results, generated_at=generated_at)

    def write_plan(
        self,
        results_or_plan: Sequence[ValidationResult] | DryRunActionPlan,
        output_path: Path | str,
        *,
        generated_at: Optional[datetime | str] = None,
    ) -> Path:
        """Serialize a DryRunActionPlan (or generate one from results) to `output_path`."""
        _enforce_dry_run_only(self.dry_run, "DryRunActionPlanGenerator")
        if isinstance(results_or_plan, DryRunActionPlan):
            plan = results_or_plan
            _enforce_dry_run_only(plan.dry_run, "DryRunActionPlan")
        else:
            plan = self.generate_plan(results_or_plan, generated_at=generated_at)

        target_path = Path(output_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(plan.to_json(indent=2), encoding="utf-8")
        return target_path


__all__ = [
    "DryRunActionPlan",
    "DryRunActionPlanGenerator",
    "ProposedRemediationAction",
    "ReadOnlyViolationError",
    "RemediationActionSink",
    "RemediationActionType",
]
