"""Phase 2 stale quarantine graduation policy engine and SHA-256 signed approval manifests."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import io
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, ClassVar, Optional
import uuid

from sot_validator.history.ledger import HistoryStore, ItemStreakSummary
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalType,
    Site,
    Subnet,
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.remediation.sink import (
    ProposedRemediationAction,
    RemediationActionType,
    _enforce_dry_run_only,
    _resolve_plan_timestamp,
)


class ApprovalStatus(str, Enum):
    """Operator review and approval states for quarantine manifest entries."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXEMPT = "EXEMPT"
    EXEMPT_PROTECTED = "EXEMPT"


class RemediationOperation(str, Enum):
    """Target Phase 2 remediation operations for quarantined inventory records."""

    FLAG_STALE_IN_SOT = "FLAG_STALE_IN_SOT"
    RECLAIM_STALE_IP = "RECLAIM_STALE_IP"
    DECOMMISSION_VM_RECORD = "DECOMMISSION_VM_RECORD"
    PROPOSE_PORT_SHUTDOWN = "PROPOSE_PORT_SHUTDOWN"
    EXEMPT_PROTECTED = "EXEMPT_PROTECTED"


class QuarantineGraduationStatus(str, Enum):
    """Quarantine policy evaluation outcome for a stale inventory candidate."""

    ELIGIBLE = "ELIGIBLE"
    EXEMPT_PROTECTED = "EXEMPT_PROTECTED"
    BELOW_THRESHOLD = "BELOW_THRESHOLD"


def _coerce_approval_status(
    value: ApprovalStatus | str, field_name: str = "approval_status"
) -> ApprovalStatus:
    if isinstance(value, ApprovalStatus):
        return value
    if isinstance(value, str):
        cleaned = value.strip().upper()
        if cleaned == "EXEMPT_PROTECTED":
            return ApprovalStatus.EXEMPT
        try:
            return ApprovalStatus(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_remediation_operation(
    value: RemediationOperation | str, field_name: str = "target_operation"
) -> RemediationOperation:
    if isinstance(value, RemediationOperation):
        return value
    if isinstance(value, str):
        cleaned = value.strip().upper()
        try:
            return RemediationOperation(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_graduation_status(
    value: QuarantineGraduationStatus | str,
    field_name: str = "graduation_status",
) -> QuarantineGraduationStatus:
    if isinstance(value, QuarantineGraduationStatus):
        return value
    if isinstance(value, str):
        cleaned = value.strip().upper()
        if cleaned == "EXEMPT":
            return QuarantineGraduationStatus.EXEMPT_PROTECTED
        try:
            return QuarantineGraduationStatus(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _normalize_string_tuple(
    values: Optional[Iterable[Any]],
    field_name: str,
    *,
    lowercase: bool = False,
) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field_name} must be an iterable of strings, not a single string")
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if isinstance(raw, Enum):
            raw_str = str(raw.value)
        elif isinstance(raw, str):
            raw_str = raw
        else:
            raise ValueError(f"{field_name} entries must be strings")
        cleaned = raw_str.strip()
        if not cleaned:
            raise ValueError(f"{field_name} entries must be non-empty strings")
        if lowercase:
            cleaned = cleaned.lower()
        if cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return tuple(result)


def _normalize_subnets_tuple(
    values: Optional[Iterable[Any]],
    field_name: str = "protected_subnets",
) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field_name} must be an iterable of CIDR strings")
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"{field_name} entries must be non-empty CIDR strings")
        try:
            net = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(
                f"Invalid subnet CIDR in {field_name}: {raw!r}"
            ) from exc
        cidr_str = str(net)
        if cidr_str not in seen:
            seen.add(cidr_str)
            result.append(cidr_str)
    return tuple(result)


def _canonical_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _word_tokens(value: str) -> set[str]:
    return {tok for tok in re.split(r"[^a-z0-9]+", value.lower()) if tok}


def _default_operation_for_item(
    item_type: str,
    *,
    category: Optional[EquipmentCategory | str] = None,
    is_vm: bool = False,
) -> RemediationOperation:
    norm_type = _canonical_token(item_type)
    if norm_type in ("ipaddress", "ip"):
        return RemediationOperation.RECLAIM_STALE_IP
    if norm_type == "port":
        return RemediationOperation.PROPOSE_PORT_SHUTDOWN
    if is_vm or norm_type in ("vm", "virtualmachine"):
        return RemediationOperation.DECOMMISSION_VM_RECORD
    if category is not None:
        cat_val = category.value if isinstance(category, Enum) else str(category)
        if _canonical_token(cat_val) in ("vm", "virtualmachine"):
            return RemediationOperation.DECOMMISSION_VM_RECORD
    return RemediationOperation.FLAG_STALE_IN_SOT


@dataclass(init=False)
class QuarantinePolicy:
    """Configurable rules governing when a Stale / Likely Unused item graduates to cleanup eligibility."""

    min_consecutive_stale_runs: int = 3
    min_stale_days: float = 30.0
    min_confidence: float = 0.85
    protected_item_ids: tuple[str, ...] = ()
    protected_categories: tuple[str, ...] = ()
    protected_subnets: tuple[str, ...] = ()
    protected_vendors: tuple[str, ...] = ()
    allow_protected_override: bool = False

    def __init__(
        self,
        min_consecutive_stale_runs: int = 3,
        min_stale_days: float = 30.0,
        min_confidence: float = 0.85,
        protected_item_ids: Iterable[str] = (),
        protected_categories: Iterable[str | Enum] = (),
        protected_subnets: Iterable[str] = (),
        protected_Subnets: Optional[Iterable[str]] = None,
        protected_vendors: Iterable[str] = (),
        allow_protected_override: bool = False,
    ) -> None:
        if (
            isinstance(min_consecutive_stale_runs, bool)
            or not isinstance(min_consecutive_stale_runs, int)
            or min_consecutive_stale_runs < 1
        ):
            raise ValueError(
                "min_consecutive_stale_runs must be an integer >= 1"
            )
        self.min_consecutive_stale_runs = min_consecutive_stale_runs

        if isinstance(min_stale_days, bool) or not isinstance(
            min_stale_days, (int, float)
        ):
            raise ValueError("min_stale_days must be a non-negative number")
        self.min_stale_days = float(min_stale_days)
        if self.min_stale_days < 0.0:
            raise ValueError("min_stale_days must be non-negative")

        if isinstance(min_confidence, bool) or not isinstance(
            min_confidence, (int, float)
        ):
            raise ValueError("min_confidence must be a number between 0.0 and 1.0")
        self.min_confidence = float(min_confidence)
        if not (0.0 <= self.min_confidence <= 1.0):
            raise ValueError("min_confidence must be between 0.0 and 1.0")

        self.protected_item_ids = _normalize_string_tuple(
            protected_item_ids, "protected_item_ids", lowercase=False
        )
        self.protected_categories = _normalize_string_tuple(
            protected_categories, "protected_categories", lowercase=True
        )

        combined_subnets: list[str] = []
        if protected_subnets:
            if isinstance(protected_subnets, (str, bytes)):
                raise ValueError("protected_subnets must be an iterable of CIDR strings")
            combined_subnets.extend(protected_subnets)
        if protected_Subnets is not None:
            if isinstance(protected_Subnets, (str, bytes)):
                raise ValueError("protected_Subnets must be an iterable of CIDR strings")
            combined_subnets.extend(protected_Subnets)
        self.protected_subnets = _normalize_subnets_tuple(
            combined_subnets, "protected_subnets"
        )

        self.protected_vendors = _normalize_string_tuple(
            protected_vendors, "protected_vendors", lowercase=True
        )
        if not isinstance(allow_protected_override, bool):
            raise ValueError("allow_protected_override must be a boolean")
        self.allow_protected_override = allow_protected_override

    @property
    def protected_Subnets(self) -> tuple[str, ...]:
        """Alias for protected_subnets matching Issue #21 casing."""
        return self.protected_subnets

    @protected_Subnets.setter
    def protected_Subnets(self, value: Iterable[str]) -> None:
        self.protected_subnets = _normalize_subnets_tuple(
            value, "protected_Subnets"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_consecutive_stale_runs": self.min_consecutive_stale_runs,
            "min_stale_days": self.min_stale_days,
            "min_confidence": self.min_confidence,
            "protected_item_ids": list(self.protected_item_ids),
            "protected_categories": list(self.protected_categories),
            "protected_subnets": list(self.protected_subnets),
            "protected_vendors": list(self.protected_vendors),
            "allow_protected_override": self.allow_protected_override,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> QuarantinePolicy:
        return cls(
            min_consecutive_stale_runs=int(
                data.get("min_consecutive_stale_runs", 3)
            ),
            min_stale_days=float(data.get("min_stale_days", 30.0)),
            min_confidence=float(data.get("min_confidence", 0.85)),
            protected_item_ids=data.get("protected_item_ids", ()),
            protected_categories=data.get("protected_categories", ()),
            protected_subnets=data.get("protected_subnets", ()),
            protected_Subnets=data.get("protected_Subnets"),
            protected_vendors=data.get("protected_vendors", ()),
            allow_protected_override=bool(
                data.get("allow_protected_override", False)
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> QuarantinePolicy:
        return cls.from_dict(json.loads(raw))


@dataclass(init=False)
class QuarantineManifestEntry:
    """Single item entry in a RemediationApprovalManifest linking action, streak, and review state."""

    FLAG_STALE_IN_SOT: ClassVar[RemediationOperation] = (
        RemediationOperation.FLAG_STALE_IN_SOT
    )
    RECLAIM_STALE_IP: ClassVar[RemediationOperation] = (
        RemediationOperation.RECLAIM_STALE_IP
    )
    DECOMMISSION_VM_RECORD: ClassVar[RemediationOperation] = (
        RemediationOperation.DECOMMISSION_VM_RECORD
    )
    PROPOSE_PORT_SHUTDOWN: ClassVar[RemediationOperation] = (
        RemediationOperation.PROPOSE_PORT_SHUTDOWN
    )
    EXEMPT_PROTECTED: ClassVar[RemediationOperation] = (
        RemediationOperation.EXEMPT_PROTECTED
    )

    action: ProposedRemediationAction
    site_id: str
    item_type: str
    item_id: str
    name: str
    classification: ValidationClassification
    confidence: float
    consecutive_stale_runs: int
    stale_duration_days: float
    target_operation: RemediationOperation
    graduation_status: QuarantineGraduationStatus = (
        QuarantineGraduationStatus.ELIGIBLE
    )
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    reviewed_by: Optional[str] = None
    review_note: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    exemption_reason: Optional[str] = None
    rationale: Optional[str] = None
    proposed_at: Optional[datetime] = None
    dry_run: bool = True
    streak: Optional[ItemStreakSummary] = field(default=None, repr=False, compare=False)

    def __init__(
        self,
        action: Optional[ProposedRemediationAction | Mapping[str, Any]] = None,
        *,
        streak: Optional[ItemStreakSummary | Mapping[str, Any]] = None,
        site_id: Optional[str] = None,
        item_type: Optional[str] = None,
        item_id: Optional[str] = None,
        name: Optional[str] = None,
        classification: Optional[ValidationClassification | str] = None,
        confidence: Optional[float] = None,
        consecutive_stale_runs: Optional[int] = None,
        stale_duration_days: Optional[float] = None,
        target_operation: Optional[RemediationOperation | str] = None,
        operation: Optional[RemediationOperation | str] = None,
        graduation_status: Optional[QuarantineGraduationStatus | str] = None,
        approval_status: ApprovalStatus | str = ApprovalStatus.PENDING,
        reviewed_by: Optional[str] = None,
        review_note: Optional[str] = None,
        reviewed_at: Optional[datetime | str] = None,
        exemption_reason: Optional[str] = None,
        rationale: Optional[str] = None,
        proposed_at: Optional[datetime | str] = None,
        dry_run: bool = True,
    ) -> None:
        self.dry_run = _enforce_dry_run_only(dry_run, "QuarantineManifestEntry")

        resolved_streak: Optional[ItemStreakSummary] = None
        if streak is not None:
            resolved_streak = (
                streak
                if isinstance(streak, ItemStreakSummary)
                else ItemStreakSummary.from_dict(streak)
            )
        self.streak = resolved_streak

        resolved_action: Optional[ProposedRemediationAction] = None
        if action is not None:
            resolved_action = (
                action
                if isinstance(action, ProposedRemediationAction)
                else ProposedRemediationAction.from_dict(action)
            )

        res_site_id = (
            site_id
            or (resolved_action.site_id if resolved_action is not None else None)
            or (resolved_streak.site_id if resolved_streak is not None else None)
        )
        res_item_type = (
            item_type
            or (resolved_action.item_type if resolved_action is not None else None)
            or (resolved_streak.item_type if resolved_streak is not None else None)
        )
        res_item_id = (
            item_id
            or (resolved_action.item_id if resolved_action is not None else None)
            or (resolved_streak.item_id if resolved_streak is not None else None)
        )
        res_name = (
            name
            or (resolved_action.name if resolved_action is not None else None)
            or (resolved_streak.name if resolved_streak is not None else None)
            or res_item_id
        )
        res_cls_raw = (
            classification
            if classification is not None
            else (
                resolved_action.classification
                if resolved_action is not None
                else (
                    resolved_streak.current_classification
                    if resolved_streak is not None
                    else ValidationClassification.STALE_LIKELY_UNUSED
                )
            )
        )
        res_conf_raw = (
            confidence
            if confidence is not None
            else (
                resolved_action.confidence
                if resolved_action is not None
                else (
                    resolved_streak.current_confidence
                    if resolved_streak is not None
                    else 0.0
                )
            )
        )
        res_runs_raw = (
            consecutive_stale_runs
            if consecutive_stale_runs is not None
            else (
                resolved_streak.consecutive_stale_runs
                if resolved_streak is not None
                else 0
            )
        )
        res_days_raw = (
            stale_duration_days
            if stale_duration_days is not None
            else (
                resolved_streak.stale_duration_days
                if resolved_streak is not None
                else 0.0
            )
        )
        res_rationale = (
            rationale
            if rationale is not None
            else (resolved_action.rationale if resolved_action is not None else None)
        )
        res_proposed_at = (
            _parse_optional_datetime(proposed_at, "proposed_at")
            if proposed_at is not None
            else (
                resolved_action.proposed_at if resolved_action is not None else None
            )
        )

        self.site_id = _require_non_empty_str(res_site_id, "site_id")
        self.item_type = _require_non_empty_str(res_item_type, "item_type")
        self.item_id = _require_non_empty_str(res_item_id, "item_id")
        self.name = _require_non_empty_str(res_name, "name")

        if isinstance(res_cls_raw, ValidationClassification):
            self.classification = res_cls_raw
        else:
            try:
                self.classification = ValidationClassification(res_cls_raw)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid classification: {res_cls_raw!r}"
                ) from exc

        if isinstance(res_conf_raw, bool) or not isinstance(
            res_conf_raw, (int, float)
        ):
            raise ValueError("confidence must be a number between 0.0 and 1.0")
        self.confidence = float(res_conf_raw)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")

        if (
            isinstance(res_runs_raw, bool)
            or not isinstance(res_runs_raw, int)
            or res_runs_raw < 0
        ):
            raise ValueError(
                "consecutive_stale_runs must be a non-negative integer"
            )
        self.consecutive_stale_runs = res_runs_raw

        if isinstance(res_days_raw, bool) or not isinstance(
            res_days_raw, (int, float)
        ):
            raise ValueError("stale_duration_days must be a non-negative number")
        self.stale_duration_days = float(res_days_raw)
        if self.stale_duration_days < 0.0:
            raise ValueError("stale_duration_days must be non-negative")

        op_raw = target_operation if target_operation is not None else operation
        if op_raw is not None:
            self.target_operation = _coerce_remediation_operation(
                op_raw, "target_operation"
            )
        else:
            self.target_operation = _default_operation_for_item(self.item_type)

        self.approval_status = _coerce_approval_status(
            approval_status, "approval_status"
        )

        if graduation_status is not None:
            self.graduation_status = _coerce_graduation_status(
                graduation_status, "graduation_status"
            )
        elif (
            self.approval_status is ApprovalStatus.EXEMPT
            or self.target_operation is RemediationOperation.EXEMPT_PROTECTED
            or exemption_reason is not None
        ):
            self.graduation_status = QuarantineGraduationStatus.EXEMPT_PROTECTED
        else:
            self.graduation_status = QuarantineGraduationStatus.ELIGIBLE

        if reviewed_by is not None:
            self.reviewed_by = _require_non_empty_str(
                reviewed_by, "reviewed_by"
            ).strip()
        else:
            self.reviewed_by = None

        self.review_note = review_note
        self.reviewed_at = _parse_optional_datetime(reviewed_at, "reviewed_at")
        self.exemption_reason = exemption_reason
        self.rationale = res_rationale
        self.proposed_at = res_proposed_at

        if resolved_action is None:
            action_type = (
                RemediationActionType.MARK_STALE_CANDIDATE
                if self.classification
                is ValidationClassification.STALE_LIKELY_UNUSED
                else RemediationActionType.FLAG_FOR_REVIEW
            )
            resolved_action = ProposedRemediationAction(
                action_type=action_type,
                site_id=self.site_id,
                item_type=self.item_type,
                item_id=self.item_id,
                name=self.name,
                classification=self.classification,
                confidence=self.confidence,
                rationale=self.rationale,
                proposed_at=self.proposed_at,
                dry_run=True,
            )
        self.action = resolved_action
        self._initial_action_snapshot = (
            self.action.site_id,
            self.action.item_type,
            self.action.item_id,
            self.action.name,
            self.action.classification,
            self.action.confidence,
            self.action.dry_run,
        )

    @property
    def operation(self) -> RemediationOperation:
        """Alias for target_operation."""
        return self.target_operation

    @operation.setter
    def operation(self, value: RemediationOperation | str) -> None:
        self.target_operation = _coerce_remediation_operation(value, "operation")

    def canonical_payload(self) -> dict[str, Any]:
        """Return deterministic dictionary of entry fields covered by the SHA-256 manifest digest."""
        init_snap = getattr(self, "_initial_action_snapshot", None)
        site_id = self.site_id
        item_type = self.item_type
        item_id = self.item_id
        name = self.name
        classification = self.classification
        confidence = self.confidence
        dry_run = self.dry_run

        if init_snap is not None and hasattr(self, "action") and self.action is not None:
            if self.action.site_id != init_snap[0] and site_id == init_snap[0]:
                site_id = self.action.site_id
            if self.action.item_type != init_snap[1] and item_type == init_snap[1]:
                item_type = self.action.item_type
            if self.action.item_id != init_snap[2] and item_id == init_snap[2]:
                item_id = self.action.item_id
            if self.action.name != init_snap[3] and name == init_snap[3]:
                name = self.action.name
            if self.action.classification != init_snap[4] and classification == init_snap[4]:
                classification = self.action.classification
            if self.action.confidence != init_snap[5] and confidence == init_snap[5]:
                confidence = self.action.confidence
            if self.action.dry_run != init_snap[6] and dry_run == init_snap[6]:
                dry_run = self.action.dry_run

        cls_val = (
            classification.value
            if isinstance(classification, Enum)
            else str(classification)
        )
        op_val = (
            self.target_operation.value
            if isinstance(self.target_operation, Enum)
            else str(self.target_operation)
        )
        grad_val = (
            self.graduation_status.value
            if isinstance(self.graduation_status, Enum)
            else str(self.graduation_status)
        )
        app_val = (
            self.approval_status.value
            if isinstance(self.approval_status, Enum)
            else str(self.approval_status)
        )

        return {
            "site_id": str(site_id),
            "item_type": str(item_type),
            "item_id": str(item_id),
            "name": str(name),
            "classification": cls_val,
            "confidence": round(float(confidence), 6),
            "consecutive_stale_runs": int(self.consecutive_stale_runs),
            "stale_duration_days": round(float(self.stale_duration_days), 6),
            "target_operation": op_val,
            "graduation_status": grad_val,
            "approval_status": app_val,
            "reviewed_by": self.reviewed_by,
            "review_note": self.review_note,
            "exemption_reason": self.exemption_reason,
            "dry_run": bool(dry_run),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.canonical_payload()
        payload.update(
            {
                "reviewed_at": _format_optional_datetime(self.reviewed_at),
                "rationale": self.rationale,
                "proposed_at": _format_optional_datetime(self.proposed_at),
                "action": self.action.to_dict(),
            }
        )
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> QuarantineManifestEntry:
        raw_action = data.get("action")
        action_obj = (
            raw_action
            if isinstance(raw_action, ProposedRemediationAction) or raw_action is None
            else ProposedRemediationAction.from_dict(raw_action)
        )
        raw_streak = data.get("streak")
        streak_obj = (
            raw_streak
            if isinstance(raw_streak, ItemStreakSummary) or raw_streak is None
            else ItemStreakSummary.from_dict(raw_streak)
        )
        return cls(
            action=action_obj,
            streak=streak_obj,
            site_id=data.get("site_id"),
            item_type=data.get("item_type"),
            item_id=data.get("item_id"),
            name=data.get("name"),
            classification=data.get("classification"),
            confidence=(
                float(data["confidence"])
                if data.get("confidence") is not None
                else None
            ),
            consecutive_stale_runs=(
                int(data["consecutive_stale_runs"])
                if data.get("consecutive_stale_runs") is not None
                else None
            ),
            stale_duration_days=(
                float(data["stale_duration_days"])
                if data.get("stale_duration_days") is not None
                else None
            ),
            target_operation=data.get("target_operation") or data.get("operation"),
            graduation_status=data.get("graduation_status"),
            approval_status=data.get("approval_status", ApprovalStatus.PENDING),
            reviewed_by=data.get("reviewed_by") or None,
            review_note=data.get("review_note") or None,
            reviewed_at=data.get("reviewed_at") or None,
            exemption_reason=data.get("exemption_reason") or None,
            rationale=data.get("rationale") or None,
            proposed_at=data.get("proposed_at") or None,
            dry_run=data.get("dry_run", True),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> QuarantineManifestEntry:
        return cls.from_dict(json.loads(raw))


class _HybridManifestMethod:
    """Descriptor allowing import_json / import_csv to be called on class or instance."""

    def __init__(self, func: Any) -> None:
        self._func = func

    def __get__(self, instance: Any, owner: Any = None) -> Any:
        target = owner if instance is None else instance

        def _bound(*args: Any, **kwargs: Any) -> RemediationApprovalManifest:
            return self._func(target, *args, **kwargs)

        return _bound


_CSV_FIELDNAMES: tuple[str, ...] = (
    "site_id",
    "item_type",
    "item_id",
    "name",
    "classification",
    "confidence",
    "consecutive_stale_runs",
    "stale_duration_days",
    "target_operation",
    "graduation_status",
    "approval_status",
    "reviewed_by",
    "review_note",
    "reviewed_at",
    "exemption_reason",
    "rationale",
    "proposed_at",
    "dry_run",
)


@dataclass
class RemediationApprovalManifest:
    """Operator-reviewable Phase 2 quarantine manifest with SHA-256 integrity verification."""

    entries: list[QuarantineManifestEntry] = field(default_factory=list)
    policy: QuarantinePolicy = field(default_factory=QuarantinePolicy)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    manifest_id: str = field(
        default_factory=lambda: f"manifest-{uuid.uuid4().hex[:12]}"
    )
    dry_run: bool = True
    manifest_sha256: str = ""

    def __post_init__(self) -> None:
        self.dry_run = _enforce_dry_run_only(
            self.dry_run, "RemediationApprovalManifest"
        )
        if not isinstance(self.policy, QuarantinePolicy):
            if isinstance(self.policy, Mapping):
                self.policy = QuarantinePolicy.from_dict(self.policy)
            else:
                raise ValueError("policy must be a QuarantinePolicy instance")
        self.generated_at = _resolve_plan_timestamp(self.generated_at)
        _require_non_empty_str(self.manifest_id, "manifest_id")
        self.entries = [
            e
            if isinstance(e, QuarantineManifestEntry)
            else QuarantineManifestEntry.from_dict(e)
            for e in self.entries
        ]
        if not self.manifest_sha256:
            self.manifest_sha256 = self.compute_digest()

    @property
    def eligible_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries that graduated as ELIGIBLE for remediation."""
        return [
            e
            for e in self.entries
            if e.graduation_status is QuarantineGraduationStatus.ELIGIBLE
        ]

    @property
    def exempt_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries marked EXEMPT_PROTECTED / EXEMPT."""
        return [
            e
            for e in self.entries
            if e.graduation_status is QuarantineGraduationStatus.EXEMPT_PROTECTED
            or e.approval_status is ApprovalStatus.EXEMPT
        ]

    @property
    def approved_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries with ApprovalStatus.APPROVED."""
        return [
            e
            for e in self.entries
            if e.approval_status is ApprovalStatus.APPROVED
        ]

    @property
    def pending_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries with ApprovalStatus.PENDING."""
        return [
            e
            for e in self.entries
            if e.approval_status is ApprovalStatus.PENDING
        ]

    @property
    def rejected_entries(self) -> list[QuarantineManifestEntry]:
        """Return entries with ApprovalStatus.REJECTED."""
        return [
            e
            for e in self.entries
            if e.approval_status is ApprovalStatus.REJECTED
        ]

    @property
    def summary_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {
            ApprovalStatus.PENDING.value: 0,
            ApprovalStatus.APPROVED.value: 0,
            ApprovalStatus.REJECTED.value: 0,
            ApprovalStatus.EXEMPT.value: 0,
        }
        for entry in self.entries:
            status_val = (
                entry.approval_status.value
                if isinstance(entry.approval_status, Enum)
                else str(entry.approval_status)
            )
            counts[status_val] = counts.get(status_val, 0) + 1
        return counts

    @property
    def summary_by_operation(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries:
            op_val = (
                entry.target_operation.value
                if isinstance(entry.target_operation, Enum)
                else str(entry.target_operation)
            )
            counts[op_val] = counts.get(op_val, 0) + 1
        return counts

    def canonical_entries_payload(self) -> list[dict[str, Any]]:
        """Return deterministically sorted canonical entry payloads for hashing."""
        payloads = [entry.canonical_payload() for entry in self.entries]
        payloads.sort(
            key=lambda p: (
                p["site_id"],
                p["item_type"],
                p["item_id"],
                p["target_operation"],
                p["approval_status"],
            )
        )
        return payloads

    def compute_digest(self) -> str:
        """Compute deterministic SHA-256 hex digest over canonical JSON of manifest entries."""
        serialized = json.dumps(
            self.canonical_entries_payload(),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def update_digest(self) -> str:
        """Recompute and update manifest_sha256 in place."""
        self.manifest_sha256 = self.compute_digest()
        return self.manifest_sha256

    def recompute_digest(self) -> str:
        """Alias for update_digest()."""
        return self.update_digest()

    def verify_digest(self) -> bool:
        """Return True iff manifest_sha256 matches the freshly computed canonical SHA-256 digest."""
        if not isinstance(self.manifest_sha256, str) or not self.manifest_sha256:
            return False
        try:
            expected = self.compute_digest()
        except Exception:
            return False
        return hmac.compare_digest(self.manifest_sha256, expected)

    def get_entry(
        self, item_id: str, *, item_type: Optional[str] = None
    ) -> Optional[QuarantineManifestEntry]:
        """Find a manifest entry by item_id (and optional item_type)."""
        for entry in self.entries:
            if entry.item_id == item_id and (
                item_type is None or entry.item_type == item_type
            ):
                return entry
        return None

    def approve_all(
        self, reviewer: str, note: Optional[str] = None
    ) -> RemediationApprovalManifest:
        """Approve all non-exempt entries, record reviewer metadata, and recompute digest."""
        clean_reviewer = _require_non_empty_str(reviewer, "reviewer").strip()
        now = datetime.now(timezone.utc)
        for entry in self.entries:
            if (
                entry.approval_status is ApprovalStatus.EXEMPT
                or entry.graduation_status
                is QuarantineGraduationStatus.EXEMPT_PROTECTED
            ):
                entry.approval_status = ApprovalStatus.EXEMPT
                continue
            entry.approval_status = ApprovalStatus.APPROVED
            entry.reviewed_by = clean_reviewer
            if note is not None:
                entry.review_note = note
            entry.reviewed_at = now
        self.update_digest()
        return self

    def set_entry_decision(
        self,
        item_id: str,
        status: ApprovalStatus | str,
        reviewer: Optional[str] = None,
        note: Optional[str] = None,
        *,
        item_type: Optional[str] = None,
        allow_exempt_override: bool = False,
    ) -> QuarantineManifestEntry:
        """Set approval decision for a specific entry and recompute manifest_sha256."""
        target_status = _coerce_approval_status(status, "status")
        clean_reviewer = (
            _require_non_empty_str(reviewer, "reviewer").strip()
            if reviewer is not None
            else None
        )

        entry = self.get_entry(item_id, item_type=item_type)
        if entry is None:
            raise KeyError(
                f"Manifest entry for item_id={item_id!r} not found in manifest"
            )

        is_exempt = (
            entry.graduation_status
            is QuarantineGraduationStatus.EXEMPT_PROTECTED
            or entry.approval_status is ApprovalStatus.EXEMPT
        )
        if is_exempt and target_status is ApprovalStatus.APPROVED:
            if not (allow_exempt_override or self.policy.allow_protected_override):
                raise ValueError(
                    f"Cannot approve EXEMPT_PROTECTED item {item_id!r} without explicit override"
                )
            entry.graduation_status = QuarantineGraduationStatus.ELIGIBLE
            if entry.target_operation is RemediationOperation.EXEMPT_PROTECTED:
                entry.target_operation = _default_operation_for_item(
                    entry.item_type
                )

        entry.approval_status = target_status
        if clean_reviewer is not None:
            entry.reviewed_by = clean_reviewer
        if note is not None:
            entry.review_note = note
        entry.reviewed_at = datetime.now(timezone.utc)
        self.update_digest()
        return entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "generated_at": _format_optional_datetime(self.generated_at),
            "dry_run": self.dry_run,
            "manifest_sha256": self.manifest_sha256,
            "policy": self.policy.to_dict(),
            "total_entries": len(self.entries),
            "summary_by_status": self.summary_by_status,
            "summary_by_operation": self.summary_by_operation,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RemediationApprovalManifest:
        dry_run_val = data.get("dry_run", True)
        _enforce_dry_run_only(dry_run_val, "RemediationApprovalManifest")
        raw_policy = data.get("policy")
        policy = (
            raw_policy
            if isinstance(raw_policy, QuarantinePolicy)
            else (
                QuarantinePolicy.from_dict(raw_policy)
                if isinstance(raw_policy, Mapping)
                else QuarantinePolicy()
            )
        )
        entries = [
            e
            if isinstance(e, QuarantineManifestEntry)
            else QuarantineManifestEntry.from_dict(e)
            for e in data.get("entries", [])
        ]
        manifest_id = data.get("manifest_id") or f"manifest-{uuid.uuid4().hex[:12]}"
        stored_digest = data.get("manifest_sha256")
        instance = cls(
            entries=entries,
            policy=policy,
            generated_at=_resolve_plan_timestamp(data.get("generated_at")),
            manifest_id=manifest_id,
            dry_run=dry_run_val,
            manifest_sha256=stored_digest if stored_digest is not None else "",
        )
        if stored_digest is not None:
            instance.manifest_sha256 = str(stored_digest)
        return instance

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> RemediationApprovalManifest:
        return cls.from_dict(json.loads(raw))

    def export_json(self, path: Optional[Path | str] = None) -> str:
        """Serialize manifest to JSON string and optionally write to path."""
        payload = self.to_json(indent=2)
        if path is not None:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(payload, encoding="utf-8")
        return payload

    def _import_json_impl(
        target: Any, path_or_raw: Path | str
    ) -> RemediationApprovalManifest:
        if isinstance(path_or_raw, Path):
            raw_text = path_or_raw.read_text(encoding="utf-8")
        elif isinstance(path_or_raw, str):
            stripped = path_or_raw.lstrip()
            if stripped.startswith("{"):
                raw_text = path_or_raw
            else:
                raw_text = Path(path_or_raw).read_text(encoding="utf-8")
        else:
            raise ValueError("path_or_raw must be a Path or JSON string")

        loaded = RemediationApprovalManifest.from_json(raw_text)
        if isinstance(target, RemediationApprovalManifest):
            target.entries = loaded.entries
            target.policy = loaded.policy
            target.generated_at = loaded.generated_at
            target.manifest_id = loaded.manifest_id
            target.dry_run = loaded.dry_run
            target.manifest_sha256 = loaded.manifest_sha256
        return loaded

    import_json = _HybridManifestMethod(_import_json_impl)

    def export_csv(self, path: Optional[Path | str] = None) -> str:
        """Export manifest entries to CSV format and optionally write to path."""
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=list(_CSV_FIELDNAMES), lineterminator="\n"
        )
        writer.writeheader()
        for entry in self.entries:
            writer.writerow(
                {
                    "site_id": entry.site_id,
                    "item_type": entry.item_type,
                    "item_id": entry.item_id,
                    "name": entry.name,
                    "classification": entry.classification.value,
                    "confidence": entry.confidence,
                    "consecutive_stale_runs": entry.consecutive_stale_runs,
                    "stale_duration_days": entry.stale_duration_days,
                    "target_operation": entry.target_operation.value,
                    "graduation_status": entry.graduation_status.value,
                    "approval_status": entry.approval_status.value,
                    "reviewed_by": entry.reviewed_by or "",
                    "review_note": entry.review_note or "",
                    "reviewed_at": _format_optional_datetime(entry.reviewed_at) or "",
                    "exemption_reason": entry.exemption_reason or "",
                    "rationale": entry.rationale or "",
                    "proposed_at": _format_optional_datetime(entry.proposed_at) or "",
                    "dry_run": str(entry.dry_run),
                }
            )
        csv_text = buf.getvalue()
        if path is not None:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(csv_text, encoding="utf-8")
        return csv_text

    def _import_csv_impl(
        target: Any,
        path_or_raw: Path | str,
        *,
        policy: Optional[QuarantinePolicy] = None,
        manifest_sha256: Optional[str] = None,
    ) -> RemediationApprovalManifest:
        if isinstance(path_or_raw, Path):
            raw_csv = path_or_raw.read_text(encoding="utf-8")
        elif isinstance(path_or_raw, str):
            first_line = path_or_raw.splitlines()[0] if path_or_raw else ""
            if "\n" in path_or_raw or "\r" in path_or_raw or "," in first_line:
                raw_csv = path_or_raw
            else:
                raw_csv = Path(path_or_raw).read_text(encoding="utf-8")
        else:
            raise ValueError("path_or_raw must be a Path or CSV string")

        reader = csv.DictReader(io.StringIO(raw_csv))
        entries: list[QuarantineManifestEntry] = []
        for row in reader:
            raw_dry = (row.get("dry_run") or "True").strip().lower()
            dry_run_val = raw_dry in ("true", "1", "yes")
            entries.append(
                QuarantineManifestEntry(
                    site_id=row["site_id"],
                    item_type=row["item_type"],
                    item_id=row["item_id"],
                    name=row.get("name") or row["item_id"],
                    classification=row.get(
                        "classification",
                        ValidationClassification.STALE_LIKELY_UNUSED.value,
                    ),
                    confidence=float(row.get("confidence") or 0.0),
                    consecutive_stale_runs=int(
                        row.get("consecutive_stale_runs") or 0
                    ),
                    stale_duration_days=float(
                        row.get("stale_duration_days") or 0.0
                    ),
                    target_operation=row.get("target_operation")
                    or row.get("operation"),
                    graduation_status=row.get("graduation_status") or None,
                    approval_status=row.get(
                        "approval_status", ApprovalStatus.PENDING.value
                    ),
                    reviewed_by=row.get("reviewed_by") or None,
                    review_note=row.get("review_note") or None,
                    reviewed_at=row.get("reviewed_at") or None,
                    exemption_reason=row.get("exemption_reason") or None,
                    rationale=row.get("rationale") or None,
                    proposed_at=row.get("proposed_at") or None,
                    dry_run=dry_run_val,
                )
            )

        resolved_policy = policy
        if resolved_policy is None:
            if isinstance(target, RemediationApprovalManifest):
                resolved_policy = target.policy
            else:
                resolved_policy = QuarantinePolicy()

        loaded = RemediationApprovalManifest(
            entries=entries,
            policy=resolved_policy,
            manifest_sha256=manifest_sha256 if manifest_sha256 is not None else "",
        )
        if manifest_sha256 is not None:
            loaded.manifest_sha256 = manifest_sha256
        if isinstance(target, RemediationApprovalManifest):
            target.entries = loaded.entries
            target.policy = loaded.policy
            target.manifest_sha256 = loaded.manifest_sha256
        return loaded

    import_csv = _HybridManifestMethod(_import_csv_impl)


@dataclass
class _SiteInventoryIndex:
    """Internal lookup index over Site objects for category, role, vendor, and IP/subnet checks."""

    equipment_by_site_id: dict[tuple[str, str], Equipment] = field(
        default_factory=dict
    )
    equipment_by_id: dict[str, Equipment] = field(default_factory=dict)
    devices_by_site_id: dict[tuple[str, str], NetworkDevice] = field(
        default_factory=dict
    )
    devices_by_id: dict[str, NetworkDevice] = field(default_factory=dict)
    ports_by_site_id: dict[tuple[str, str], Port] = field(default_factory=dict)
    ports_by_id: dict[str, Port] = field(default_factory=dict)
    ips_by_site_ip: dict[tuple[str, str], IPAddress] = field(
        default_factory=dict
    )
    ips_by_ip: dict[str, IPAddress] = field(default_factory=dict)
    ips_by_assigned_obj: dict[str, list[str]] = field(default_factory=dict)
    subnets_by_site_id: dict[tuple[str, str], Subnet] = field(
        default_factory=dict
    )
    subnets_by_id: dict[str, Subnet] = field(default_factory=dict)

    @classmethod
    def from_sites(
        cls,
        sites: Optional[Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]],
    ) -> _SiteInventoryIndex:
        idx = cls()
        if sites is None:
            return idx

        if isinstance(sites, Site):
            site_list = [sites]
        elif isinstance(sites, Mapping):
            if "site_id" in sites and "name" in sites:
                site_list = [Site.from_dict(sites)]
            else:
                site_list = [
                    v if isinstance(v, Site) else Site.from_dict(v)
                    for v in sites.values()
                ]
        else:
            site_list = [
                s if isinstance(s, Site) else Site.from_dict(s) for s in sites
            ]

        for site in site_list:
            for eq in site.equipment:
                idx.equipment_by_site_id[(site.site_id, eq.equipment_id)] = eq
                idx.equipment_by_id[eq.equipment_id] = eq
            for dev in site.devices:
                idx.devices_by_site_id[(site.site_id, dev.device_id)] = dev
                idx.devices_by_id[dev.device_id] = dev
                for port in dev.ports:
                    idx.ports_by_site_id[(site.site_id, port.port_id)] = port
                    idx.ports_by_id[port.port_id] = port
            for sub in site.subnets:
                idx.subnets_by_site_id[(site.site_id, sub.subnet_id)] = sub
                idx.subnets_by_id[sub.subnet_id] = sub
            for ip_rec in site.ip_addresses:
                idx.ips_by_site_ip[(site.site_id, ip_rec.ip)] = ip_rec
                idx.ips_by_ip[ip_rec.ip] = ip_rec
                if ip_rec.assigned_object_id:
                    bucket = idx.ips_by_assigned_obj.setdefault(
                        ip_rec.assigned_object_id, []
                    )
                    if ip_rec.ip not in bucket:
                        bucket.append(ip_rec.ip)

        return idx


def _try_parse_ip_addr(
    value: Optional[str],
) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0].strip()
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        return None


class QuarantineEngine:
    """Evaluates ValidationResult items alongside HistoryStore streaks against QuarantinePolicy."""

    FLAG_STALE_IN_SOT: ClassVar[RemediationOperation] = (
        RemediationOperation.FLAG_STALE_IN_SOT
    )
    RECLAIM_STALE_IP: ClassVar[RemediationOperation] = (
        RemediationOperation.RECLAIM_STALE_IP
    )
    DECOMMISSION_VM_RECORD: ClassVar[RemediationOperation] = (
        RemediationOperation.DECOMMISSION_VM_RECORD
    )
    PROPOSE_PORT_SHUTDOWN: ClassVar[RemediationOperation] = (
        RemediationOperation.PROPOSE_PORT_SHUTDOWN
    )
    EXEMPT_PROTECTED: ClassVar[RemediationOperation] = (
        RemediationOperation.EXEMPT_PROTECTED
    )

    def __init__(self, policy: Optional[QuarantinePolicy] = None) -> None:
        if policy is None:
            self.policy = QuarantinePolicy()
        elif isinstance(policy, QuarantinePolicy):
            self.policy = policy
        elif isinstance(policy, Mapping):
            self.policy = QuarantinePolicy.from_dict(policy)
        else:
            raise ValueError("policy must be a QuarantinePolicy instance or None")

    def map_target_operation(
        self,
        res: ValidationResult,
        site_index: Optional[_SiteInventoryIndex] = None,
    ) -> RemediationOperation:
        """Map an inventory item to its default Phase 2 RemediationOperation."""
        norm_type = _canonical_token(res.item_type)
        if norm_type in ("ipaddress", "ip"):
            return RemediationOperation.RECLAIM_STALE_IP
        if norm_type == "port":
            return RemediationOperation.PROPOSE_PORT_SHUTDOWN
        if norm_type in ("vm", "virtualmachine"):
            return RemediationOperation.DECOMMISSION_VM_RECORD

        if site_index is not None:
            eq = site_index.equipment_by_site_id.get(
                (res.site_id, res.item_id)
            ) or site_index.equipment_by_id.get(res.item_id)
            if eq is not None and eq.category is EquipmentCategory.VM:
                return RemediationOperation.DECOMMISSION_VM_RECORD

        has_vm_signal = any(
            s.signal_type is SignalType.VM_POWER_STATE for s in res.signals
        )
        if has_vm_signal:
            return RemediationOperation.DECOMMISSION_VM_RECORD

        if norm_type == "equipment":
            tokens = _word_tokens(res.item_id) | _word_tokens(res.name)
            if "vm" in tokens:
                return RemediationOperation.DECOMMISSION_VM_RECORD

        return RemediationOperation.FLAG_STALE_IN_SOT

    def check_protection(
        self,
        res: ValidationResult,
        site_index: Optional[_SiteInventoryIndex] = None,
    ) -> Optional[str]:
        """Return an exemption reason string if `res` matches a policy protection allowlist, else None."""
        # 1. Protected item IDs
        if self.policy.protected_item_ids:
            protected_ids_exact = set(self.policy.protected_item_ids)
            protected_ids_lower = {pid.lower() for pid in self.policy.protected_item_ids}
            composite_key = f"{res.item_type}:{res.item_id}"
            if (
                res.item_id in protected_ids_exact
                or res.item_id.lower() in protected_ids_lower
                or composite_key in protected_ids_exact
                or composite_key.lower() in protected_ids_lower
            ):
                return f"Protected item_id {res.item_id!r} in policy allowlist"

        # 2. Protected categories / roles / vendors
        if self.policy.protected_categories or self.policy.protected_vendors:
            item_categories: set[str] = set()
            item_vendors: set[str] = set()

            item_categories.add(res.item_type.lower())
            item_categories.add(_canonical_token(res.item_type))
            if _canonical_token(res.item_type) == "networkdevice":
                item_categories.update({"network_device", "networkdevice", "switch"})

            eq_found = False
            dev_found = False
            if site_index is not None:
                eq = site_index.equipment_by_site_id.get(
                    (res.site_id, res.item_id)
                ) or site_index.equipment_by_id.get(res.item_id)
                if eq is not None:
                    eq_found = True
                    item_categories.add(eq.category.value.lower())
                    item_categories.add(_canonical_token(eq.category.value))

                dev = site_index.devices_by_site_id.get(
                    (res.site_id, res.item_id)
                ) or site_index.devices_by_id.get(res.item_id)
                if dev is not None:
                    dev_found = True
                    if dev.role:
                        role_clean = dev.role.strip().lower()
                        role_canon = _canonical_token(role_clean)
                        item_categories.add(role_clean)
                        item_categories.add(role_canon)
                        if role_canon in ("core", "coreswitch"):
                            item_categories.update(
                                {"core", "core_switch", "coreswitch"}
                            )
                    if dev.vendor:
                        vendor_clean = dev.vendor.strip().lower()
                        vendor_canon = _canonical_token(vendor_clean)
                        item_vendors.add(vendor_clean)
                        item_vendors.add(vendor_canon)
                        item_categories.add(vendor_clean)
                        item_categories.add(vendor_canon)
                        for tok in _word_tokens(vendor_clean):
                            item_vendors.add(tok)
                            item_categories.add(tok)

            if not eq_found and not dev_found:
                name_id_tokens = _word_tokens(res.item_id) | _word_tokens(res.name)
                if "ups" in name_id_tokens or "apc" in name_id_tokens:
                    item_categories.add("ups")
                if "apc" in name_id_tokens:
                    item_vendors.add("apc")
                if "extreme" in name_id_tokens:
                    item_vendors.add("extreme")
                    item_categories.add("extreme")
                if "core" in name_id_tokens:
                    item_categories.update({"core", "core_switch", "coreswitch"})

            for prot_cat in self.policy.protected_categories:
                prot_canon = _canonical_token(prot_cat)
                if prot_cat.lower() in item_categories or prot_canon in item_categories:
                    return f"Protected category {prot_cat!r} in policy allowlist"

            for prot_vendor in self.policy.protected_vendors:
                prot_canon = _canonical_token(prot_vendor)
                if prot_vendor.lower() in item_vendors or prot_canon in item_vendors:
                    return f"Protected vendor {prot_vendor!r} in policy allowlist"

        # 3. Protected subnets
        if self.policy.protected_subnets:
            networks = [
                ipaddress.ip_network(cidr, strict=False)
                for cidr in self.policy.protected_subnets
            ]
            candidate_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

            for raw_candidate in (res.item_id, res.name):
                parsed = _try_parse_ip_addr(raw_candidate)
                if parsed is not None and parsed not in candidate_ips:
                    candidate_ips.append(parsed)

            if site_index is not None:
                eq = site_index.equipment_by_site_id.get(
                    (res.site_id, res.item_id)
                ) or site_index.equipment_by_id.get(res.item_id)
                if eq is not None:
                    for raw_ip in eq.assigned_ips:
                        parsed = _try_parse_ip_addr(raw_ip)
                        if parsed is not None and parsed not in candidate_ips:
                            candidate_ips.append(parsed)

                dev = site_index.devices_by_site_id.get(
                    (res.site_id, res.item_id)
                ) or site_index.devices_by_id.get(res.item_id)
                if dev is not None and dev.management_ip:
                    parsed = _try_parse_ip_addr(dev.management_ip)
                    if parsed is not None and parsed not in candidate_ips:
                        candidate_ips.append(parsed)

                for linked_ip in site_index.ips_by_assigned_obj.get(
                    res.item_id, ()
                ):
                    parsed = _try_parse_ip_addr(linked_ip)
                    if parsed is not None and parsed not in candidate_ips:
                        candidate_ips.append(parsed)

                ip_rec = site_index.ips_by_site_ip.get(
                    (res.site_id, res.item_id)
                ) or site_index.ips_by_ip.get(res.item_id)
                if ip_rec is not None:
                    parsed = _try_parse_ip_addr(ip_rec.ip)
                    if parsed is not None and parsed not in candidate_ips:
                        candidate_ips.append(parsed)

            for ip_addr in candidate_ips:
                for net in networks:
                    if ip_addr.version == net.version and ip_addr in net:
                        return (
                            f"Item IP {str(ip_addr)!r} falls within protected subnet {str(net)!r}"
                        )

        return None

    @staticmethod
    def _resolve_streak_lookup(
        history: Optional[
            HistoryStore
            | Sequence[ItemStreakSummary | Mapping[str, Any]]
            | Mapping[Any, ItemStreakSummary | Mapping[str, Any]]
        ],
    ) -> tuple[
        Optional[HistoryStore],
        dict[tuple[str, str, str], ItemStreakSummary],
        dict[tuple[str, str], ItemStreakSummary],
        dict[str, ItemStreakSummary],
        list[ItemStreakSummary],
    ]:
        by_site_type_id: dict[tuple[str, str, str], ItemStreakSummary] = {}
        by_type_id: dict[tuple[str, str], ItemStreakSummary] = {}
        by_id: dict[str, ItemStreakSummary] = {}
        all_streaks: list[ItemStreakSummary] = []

        if history is None:
            return None, by_site_type_id, by_type_id, by_id, all_streaks

        if isinstance(history, HistoryStore):
            for st in history.list_streaks():
                by_site_type_id[(st.site_id, st.item_type, st.item_id)] = st
                by_type_id[(st.item_type, st.item_id)] = st
                by_id[st.item_id] = st
                all_streaks.append(st)
            return history, by_site_type_id, by_type_id, by_id, all_streaks

        if isinstance(history, Mapping):
            raw_items = list(history.values())
        else:
            raw_items = list(history)

        for raw in raw_items:
            st = (
                raw
                if isinstance(raw, ItemStreakSummary)
                else ItemStreakSummary.from_dict(raw)
            )
            by_site_type_id[(st.site_id, st.item_type, st.item_id)] = st
            by_type_id[(st.item_type, st.item_id)] = st
            by_id[st.item_id] = st
            all_streaks.append(st)

        return None, by_site_type_id, by_type_id, by_id, all_streaks

    def evaluate(
        self,
        results: Optional[
            Sequence[ValidationResult | ItemStreakSummary | Mapping[str, Any]]
            | HistoryStore
        ] = None,
        history: Optional[
            HistoryStore
            | Sequence[ItemStreakSummary | Mapping[str, Any]]
            | Mapping[Any, ItemStreakSummary | Mapping[str, Any]]
        ] = None,
        *,
        streaks: Optional[
            HistoryStore
            | Sequence[ItemStreakSummary | Mapping[str, Any]]
            | Mapping[Any, ItemStreakSummary | Mapping[str, Any]]
        ] = None,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        override_protected: bool = False,
        generated_at: Optional[datetime | str] = None,
        manifest_id: Optional[str] = None,
        include_below_threshold: bool = False,
    ) -> RemediationApprovalManifest:
        """Evaluate ValidationResult items and streak history against QuarantinePolicy."""
        effective_history = history if history is not None else streaks
        if isinstance(results, HistoryStore) and effective_history is None:
            effective_history = results
            results = None

        _, by_site_type_id, by_type_id, by_id, all_streaks = (
            self._resolve_streak_lookup(effective_history)
        )
        site_index = _SiteInventoryIndex.from_sites(sites)
        manifest_dt = _resolve_plan_timestamp(generated_at)

        candidates: list[tuple[ValidationResult, Optional[ItemStreakSummary]]] = []

        if results is not None:
            for raw_item in results:
                if isinstance(raw_item, ItemStreakSummary):
                    st = raw_item
                    res = ValidationResult(
                        item_type=st.item_type,
                        item_id=st.item_id,
                        site_id=st.site_id,
                        name=st.name,
                        classification=st.current_classification,
                        confidence=st.current_confidence,
                        evaluated_at=st.first_seen_at,
                    )
                    candidates.append((res, st))
                elif isinstance(raw_item, ValidationResult):
                    res = raw_item
                    st = (
                        by_site_type_id.get(
                            (res.site_id, res.item_type, res.item_id)
                        )
                        or by_type_id.get((res.item_type, res.item_id))
                        or by_id.get(res.item_id)
                    )
                    candidates.append((res, st))
                elif isinstance(raw_item, Mapping):
                    if "consecutive_stale_runs" in raw_item and "current_classification" in raw_item:
                        st = ItemStreakSummary.from_dict(raw_item)
                        res = ValidationResult(
                            item_type=st.item_type,
                            item_id=st.item_id,
                            site_id=st.site_id,
                            name=st.name,
                            classification=st.current_classification,
                            confidence=st.current_confidence,
                            evaluated_at=st.first_seen_at,
                        )
                        candidates.append((res, st))
                    else:
                        res = ValidationResult.from_dict(raw_item)
                        st = (
                            by_site_type_id.get(
                                (res.site_id, res.item_type, res.item_id)
                            )
                            or by_type_id.get((res.item_type, res.item_id))
                            or by_id.get(res.item_id)
                        )
                        candidates.append((res, st))
                else:
                    raise ValueError(f"Unsupported result item: {raw_item!r}")
        else:
            for st in all_streaks:
                res = ValidationResult(
                    item_type=st.item_type,
                    item_id=st.item_id,
                    site_id=st.site_id,
                    name=st.name,
                    classification=st.current_classification,
                    confidence=st.current_confidence,
                    evaluated_at=st.first_seen_at,
                )
                candidates.append((res, st))

        effective_override = bool(
            override_protected or self.policy.allow_protected_override
        )
        entries: list[QuarantineManifestEntry] = []

        for res, streak in candidates:
            if res.classification is not ValidationClassification.STALE_LIKELY_UNUSED:
                continue

            consecutive_runs = (
                streak.consecutive_stale_runs if streak is not None else 1
            )
            stale_days = (
                streak.stale_duration_days if streak is not None else 0.0
            )
            confidence = res.confidence

            target_op = self.map_target_operation(res, site_index=site_index)
            protection_reason = self.check_protection(res, site_index=site_index)

            proposed_dt = (
                res.evaluated_at if res.evaluated_at is not None else manifest_dt
            )
            action = ProposedRemediationAction(
                action_type=RemediationActionType.MARK_STALE_CANDIDATE,
                site_id=res.site_id,
                item_type=res.item_type,
                item_id=res.item_id,
                name=res.name,
                classification=res.classification,
                confidence=confidence,
                rationale=res.rationale,
                proposed_at=proposed_dt,
                dry_run=True,
            )

            if protection_reason is not None and not effective_override:
                entries.append(
                    QuarantineManifestEntry(
                        action=action,
                        streak=streak,
                        site_id=res.site_id,
                        item_type=res.item_type,
                        item_id=res.item_id,
                        name=res.name,
                        classification=res.classification,
                        confidence=confidence,
                        consecutive_stale_runs=consecutive_runs,
                        stale_duration_days=stale_days,
                        target_operation=target_op,
                        graduation_status=QuarantineGraduationStatus.EXEMPT_PROTECTED,
                        approval_status=ApprovalStatus.EXEMPT,
                        exemption_reason=protection_reason,
                        rationale=res.rationale,
                        proposed_at=proposed_dt,
                        dry_run=True,
                    )
                )
                continue

            meets_thresholds = (
                consecutive_runs >= self.policy.min_consecutive_stale_runs
                and stale_days >= self.policy.min_stale_days
                and confidence >= self.policy.min_confidence
            )
            if meets_thresholds:
                entries.append(
                    QuarantineManifestEntry(
                        action=action,
                        streak=streak,
                        site_id=res.site_id,
                        item_type=res.item_type,
                        item_id=res.item_id,
                        name=res.name,
                        classification=res.classification,
                        confidence=confidence,
                        consecutive_stale_runs=consecutive_runs,
                        stale_duration_days=stale_days,
                        target_operation=target_op,
                        graduation_status=QuarantineGraduationStatus.ELIGIBLE,
                        approval_status=ApprovalStatus.PENDING,
                        exemption_reason=None,
                        rationale=res.rationale,
                        proposed_at=proposed_dt,
                        dry_run=True,
                    )
                )
            elif include_below_threshold:
                entries.append(
                    QuarantineManifestEntry(
                        action=action,
                        streak=streak,
                        site_id=res.site_id,
                        item_type=res.item_type,
                        item_id=res.item_id,
                        name=res.name,
                        classification=res.classification,
                        confidence=confidence,
                        consecutive_stale_runs=consecutive_runs,
                        stale_duration_days=stale_days,
                        target_operation=target_op,
                        graduation_status=QuarantineGraduationStatus.BELOW_THRESHOLD,
                        approval_status=ApprovalStatus.REJECTED,
                        exemption_reason=None,
                        rationale=res.rationale,
                        proposed_at=proposed_dt,
                        dry_run=True,
                    )
                )

        entries.sort(key=lambda e: (e.site_id, e.item_type, e.item_id))
        resolved_manifest_id = (
            manifest_id
            if manifest_id is not None
            else f"manifest-{uuid.uuid4().hex[:12]}"
        )
        return RemediationApprovalManifest(
            entries=entries,
            policy=self.policy,
            generated_at=manifest_dt,
            manifest_id=resolved_manifest_id,
            dry_run=True,
        )

    def build_manifest(
        self,
        results: Optional[
            Sequence[ValidationResult | ItemStreakSummary | Mapping[str, Any]]
            | HistoryStore
        ] = None,
        history: Optional[
            HistoryStore
            | Sequence[ItemStreakSummary | Mapping[str, Any]]
            | Mapping[Any, ItemStreakSummary | Mapping[str, Any]]
        ] = None,
        **kwargs: Any,
    ) -> RemediationApprovalManifest:
        """Alias for evaluate()."""
        return self.evaluate(results, history, **kwargs)


__all__ = [
    "ApprovalStatus",
    "QuarantineEngine",
    "QuarantineGraduationStatus",
    "QuarantineManifestEntry",
    "QuarantinePolicy",
    "RemediationApprovalManifest",
    "RemediationOperation",
]
