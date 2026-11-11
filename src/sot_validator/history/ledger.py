"""Multi-run validation history ledger, stale streak tracker, and drift analyzer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import json
from pathlib import Path
import sqlite3
from typing import Any, ClassVar, Optional
import uuid

from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.signals.base import SECONDS_PER_DAY, normalize_utc_datetime

ALL_CLASSIFICATION_VALUES: tuple[str, ...] = (
    ValidationClassification.CONFIRMED_ACTIVE.value,
    ValidationClassification.STALE_LIKELY_UNUSED.value,
    ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value,
    ValidationClassification.INSUFFICIENT_DATA.value,
)


class DriftTransitionType(str, Enum):
    """Classification transition types tracked across consecutive validation runs."""

    NEWLY_STALE = "NEWLY_STALE"
    NEWLY_UNREACHABLE = "NEWLY_UNREACHABLE"
    RESURRECTED = "RESURRECTED"
    RECOVERED = "RECOVERED"


_DRIFT_TRANSITION_MAP: dict[
    tuple[ValidationClassification, ValidationClassification], DriftTransitionType
] = {
    (
        ValidationClassification.CONFIRMED_ACTIVE,
        ValidationClassification.STALE_LIKELY_UNUSED,
    ): DriftTransitionType.NEWLY_STALE,
    (
        ValidationClassification.CONFIRMED_ACTIVE,
        ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
    ): DriftTransitionType.NEWLY_UNREACHABLE,
    (
        ValidationClassification.STALE_LIKELY_UNUSED,
        ValidationClassification.CONFIRMED_ACTIVE,
    ): DriftTransitionType.RESURRECTED,
    (
        ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
        ValidationClassification.CONFIRMED_ACTIVE,
    ): DriftTransitionType.RECOVERED,
}


def _normalize_optional_utc_datetime(
    value: Optional[datetime | str], field_name: str
) -> Optional[datetime]:
    if value is None:
        return None
    return normalize_utc_datetime(value, field_name=field_name)


def _require_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _require_confidence(value: Any, field_name: str = "confidence") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a number between 0.0 and 1.0")
    score = float(value)
    if not (0.0 <= score <= 1.0):
        raise ValueError(f"{field_name} must be between 0.0 and 1.0")
    return score


def _coerce_classification(
    value: ValidationClassification | str, field_name: str = "classification"
) -> ValidationClassification:
    if isinstance(value, ValidationClassification):
        return value
    try:
        return ValidationClassification(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {value!r}") from exc


def _coerce_transition_type(
    value: DriftTransitionType | str, field_name: str = "transition_type"
) -> DriftTransitionType:
    if isinstance(value, DriftTransitionType):
        return value
    try:
        return DriftTransitionType(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {value!r}") from exc


@dataclass
class ValidationRunRecord:
    """Metadata summary for a recorded validation run."""

    run_id: str
    recorded_at: datetime
    site_ids: list[str] = field(default_factory=list)
    total_items: int = 0
    classification_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.run_id, "run_id")
        self.recorded_at = normalize_utc_datetime(
            self.recorded_at, field_name="recorded_at"
        )
        if isinstance(self.site_ids, (str, bytes)) or not isinstance(
            self.site_ids, Sequence
        ):
            raise ValueError("site_ids must be a sequence of site ID strings")
        normalized_sites: set[str] = set()
        for raw_site in self.site_ids:
            _require_non_empty_str(raw_site, "site_id")
            normalized_sites.add(raw_site.strip())
        self.site_ids = sorted(normalized_sites)

        self.total_items = _require_non_negative_int(
            self.total_items, "total_items"
        )
        if not isinstance(self.classification_counts, Mapping):
            raise ValueError("classification_counts must be a mapping")

        normalized_counts: dict[str, int] = {
            cls_val: 0 for cls_val in ALL_CLASSIFICATION_VALUES
        }
        for raw_key, raw_count in self.classification_counts.items():
            cls_enum = _coerce_classification(raw_key, "classification_counts key")
            count_val = _require_non_negative_int(
                raw_count, f"classification_counts[{cls_enum.value!r}]"
            )
            normalized_counts[cls_enum.value] = count_val
        self.classification_counts = normalized_counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "recorded_at": _format_optional_datetime(self.recorded_at),
            "site_ids": list(self.site_ids),
            "total_items": self.total_items,
            "classification_counts": dict(self.classification_counts),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidationRunRecord:
        return cls(
            run_id=data["run_id"],
            recorded_at=normalize_utc_datetime(
                data["recorded_at"], field_name="recorded_at"
            ),
            site_ids=list(data.get("site_ids", [])),
            total_items=int(data.get("total_items", 0)),
            classification_counts=dict(data.get("classification_counts", {})),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ValidationRunRecord:
        return cls.from_dict(json.loads(raw))


@dataclass
class ItemStreakSummary:
    """Per-item multi-run historical validation state and stale streak counters."""

    site_id: str
    item_type: str
    item_id: str
    name: str
    current_classification: ValidationClassification
    current_confidence: float
    consecutive_stale_runs: int
    total_runs_seen: int
    first_seen_at: datetime
    first_stale_at: Optional[datetime] = None
    last_confirmed_active_at: Optional[datetime] = None
    stale_duration_days: float = 0.0
    previous_classification: Optional[ValidationClassification] = None
    transition_type: Optional[DriftTransitionType] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.item_type, "item_type")
        _require_non_empty_str(self.item_id, "item_id")
        _require_non_empty_str(self.name, "name")
        self.current_classification = _coerce_classification(
            self.current_classification, "current_classification"
        )
        self.current_confidence = _require_confidence(
            self.current_confidence, "current_confidence"
        )
        self.consecutive_stale_runs = _require_non_negative_int(
            self.consecutive_stale_runs, "consecutive_stale_runs"
        )
        self.total_runs_seen = _require_non_negative_int(
            self.total_runs_seen, "total_runs_seen"
        )
        self.first_seen_at = normalize_utc_datetime(
            self.first_seen_at, field_name="first_seen_at"
        )
        self.first_stale_at = _normalize_optional_utc_datetime(
            self.first_stale_at, "first_stale_at"
        )
        self.last_confirmed_active_at = _normalize_optional_utc_datetime(
            self.last_confirmed_active_at, "last_confirmed_active_at"
        )
        if isinstance(self.stale_duration_days, bool) or not isinstance(
            self.stale_duration_days, (int, float)
        ):
            raise ValueError("stale_duration_days must be a non-negative number")
        self.stale_duration_days = float(self.stale_duration_days)
        if self.stale_duration_days < 0.0:
            raise ValueError("stale_duration_days must be non-negative")

        if self.previous_classification is not None:
            self.previous_classification = _coerce_classification(
                self.previous_classification, "previous_classification"
            )
        if self.transition_type is not None:
            self.transition_type = _coerce_transition_type(
                self.transition_type, "transition_type"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "item_type": self.item_type,
            "item_id": self.item_id,
            "name": self.name,
            "current_classification": self.current_classification.value,
            "current_confidence": self.current_confidence,
            "consecutive_stale_runs": self.consecutive_stale_runs,
            "total_runs_seen": self.total_runs_seen,
            "first_seen_at": _format_optional_datetime(self.first_seen_at),
            "first_stale_at": _format_optional_datetime(self.first_stale_at),
            "last_confirmed_active_at": _format_optional_datetime(
                self.last_confirmed_active_at
            ),
            "stale_duration_days": self.stale_duration_days,
            "previous_classification": (
                self.previous_classification.value
                if self.previous_classification is not None
                else None
            ),
            "transition_type": (
                self.transition_type.value
                if self.transition_type is not None
                else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ItemStreakSummary:
        prev_cls = data.get("previous_classification")
        trans_type = data.get("transition_type")
        return cls(
            site_id=data["site_id"],
            item_type=data["item_type"],
            item_id=data["item_id"],
            name=data["name"],
            current_classification=_coerce_classification(
                data["current_classification"], "current_classification"
            ),
            current_confidence=data.get("current_confidence", 0.0),
            consecutive_stale_runs=int(data.get("consecutive_stale_runs", 0)),
            total_runs_seen=int(data.get("total_runs_seen", 0)),
            first_seen_at=normalize_utc_datetime(
                data["first_seen_at"], field_name="first_seen_at"
            ),
            first_stale_at=_normalize_optional_utc_datetime(
                data.get("first_stale_at"), "first_stale_at"
            ),
            last_confirmed_active_at=_normalize_optional_utc_datetime(
                data.get("last_confirmed_active_at"), "last_confirmed_active_at"
            ),
            stale_duration_days=float(data.get("stale_duration_days", 0.0)),
            previous_classification=(
                _coerce_classification(prev_cls, "previous_classification")
                if prev_cls is not None
                else None
            ),
            transition_type=(
                _coerce_transition_type(trans_type, "transition_type")
                if trans_type is not None
                else None
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ItemStreakSummary:
        return cls.from_dict(json.loads(raw))


@dataclass
class DriftEvent:
    """Classification transition event observed for an item between consecutive runs."""

    NEWLY_STALE: ClassVar[DriftTransitionType] = DriftTransitionType.NEWLY_STALE
    NEWLY_UNREACHABLE: ClassVar[DriftTransitionType] = (
        DriftTransitionType.NEWLY_UNREACHABLE
    )
    RESURRECTED: ClassVar[DriftTransitionType] = DriftTransitionType.RESURRECTED
    RECOVERED: ClassVar[DriftTransitionType] = DriftTransitionType.RECOVERED

    run_id: str
    recorded_at: datetime
    site_id: str
    item_type: str
    item_id: str
    name: str
    previous_classification: ValidationClassification
    new_classification: ValidationClassification
    transition_type: DriftTransitionType
    confidence: float = 0.0

    def __post_init__(self) -> None:
        _require_non_empty_str(self.run_id, "run_id")
        self.recorded_at = normalize_utc_datetime(
            self.recorded_at, field_name="recorded_at"
        )
        _require_non_empty_str(self.site_id, "site_id")
        _require_non_empty_str(self.item_type, "item_type")
        _require_non_empty_str(self.item_id, "item_id")
        _require_non_empty_str(self.name, "name")
        self.previous_classification = _coerce_classification(
            self.previous_classification, "previous_classification"
        )
        self.new_classification = _coerce_classification(
            self.new_classification, "new_classification"
        )
        self.transition_type = _coerce_transition_type(
            self.transition_type, "transition_type"
        )
        self.confidence = _require_confidence(self.confidence, "confidence")

    @property
    def current_classification(self) -> ValidationClassification:
        """Alias for new_classification."""
        return self.new_classification

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "recorded_at": _format_optional_datetime(self.recorded_at),
            "site_id": self.site_id,
            "item_type": self.item_type,
            "item_id": self.item_id,
            "name": self.name,
            "previous_classification": self.previous_classification.value,
            "new_classification": self.new_classification.value,
            "transition_type": self.transition_type.value,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DriftEvent:
        raw_new_cls = (
            data["new_classification"]
            if "new_classification" in data
            else data["current_classification"]
        )
        return cls(
            run_id=data["run_id"],
            recorded_at=normalize_utc_datetime(
                data["recorded_at"], field_name="recorded_at"
            ),
            site_id=data["site_id"],
            item_type=data["item_type"],
            item_id=data["item_id"],
            name=data["name"],
            previous_classification=_coerce_classification(
                data["previous_classification"], "previous_classification"
            ),
            new_classification=_coerce_classification(
                raw_new_cls, "new_classification"
            ),
            transition_type=_coerce_transition_type(
                data["transition_type"], "transition_type"
            ),
            confidence=data.get("confidence", 0.0),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> DriftEvent:
        return cls.from_dict(json.loads(raw))


@dataclass
class SubnetUtilizationSummary:
    """Per-site /24 subnet IP assignment, active usage, and stale reclaimable summary."""

    subnet_id: str
    cidr: str
    total_assigned_ips: int
    confirmed_active_ips: int
    stale_reclaimable_ips: int
    active_utilization_pct: float
    site_id: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.subnet_id, "subnet_id")
        _require_non_empty_str(self.cidr, "cidr")
        self.total_assigned_ips = _require_non_negative_int(
            self.total_assigned_ips, "total_assigned_ips"
        )
        self.confirmed_active_ips = _require_non_negative_int(
            self.confirmed_active_ips, "confirmed_active_ips"
        )
        self.stale_reclaimable_ips = _require_non_negative_int(
            self.stale_reclaimable_ips, "stale_reclaimable_ips"
        )
        if isinstance(self.active_utilization_pct, bool) or not isinstance(
            self.active_utilization_pct, (int, float)
        ):
            raise ValueError(
                "active_utilization_pct must be a number between 0.0 and 100.0"
            )
        self.active_utilization_pct = float(self.active_utilization_pct)
        if not (0.0 <= self.active_utilization_pct <= 100.0):
            raise ValueError(
                "active_utilization_pct must be between 0.0 and 100.0"
            )
        if self.site_id is not None:
            _require_non_empty_str(self.site_id, "site_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "subnet_id": self.subnet_id,
            "site_id": self.site_id,
            "cidr": self.cidr,
            "total_assigned_ips": self.total_assigned_ips,
            "confirmed_active_ips": self.confirmed_active_ips,
            "stale_reclaimable_ips": self.stale_reclaimable_ips,
            "active_utilization_pct": self.active_utilization_pct,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SubnetUtilizationSummary:
        return cls(
            subnet_id=data["subnet_id"],
            cidr=data["cidr"],
            total_assigned_ips=int(data["total_assigned_ips"]),
            confirmed_active_ips=int(data["confirmed_active_ips"]),
            stale_reclaimable_ips=int(data["stale_reclaimable_ips"]),
            active_utilization_pct=float(data["active_utilization_pct"]),
            site_id=data.get("site_id"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> SubnetUtilizationSummary:
        return cls.from_dict(json.loads(raw))


class _HybridImportMethod:
    """Descriptor allowing import_json to be invoked on either HistoryStore class or instance."""

    def __init__(self, func: Any) -> None:
        self._func = func

    def __get__(self, instance: Any, owner: Any = None) -> Any:
        target = owner if instance is None else instance

        def _bound(*args: Any, **kwargs: Any) -> HistoryStore:
            return self._func(target, *args, **kwargs)

        return _bound


def _coerce_sites(
    sites: Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
) -> list[Site]:
    if isinstance(sites, Site):
        return [sites]
    if isinstance(sites, Mapping):
        if "site_id" in sites and "name" in sites:
            return [Site.from_dict(sites)]
        return [
            v if isinstance(v, Site) else Site.from_dict(v)
            for v in sites.values()
        ]
    return [s if isinstance(s, Site) else Site.from_dict(s) for s in sites]


def _try_parse_ipv4(ip_str: Optional[str]) -> Optional[ipaddress.IPv4Address]:
    if not ip_str or not isinstance(ip_str, str) or not ip_str.strip():
        return None
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    return addr if isinstance(addr, ipaddress.IPv4Address) else None


def _try_parse_slash24_ipv4(
    cidr_str: Optional[str],
) -> Optional[ipaddress.IPv4Network]:
    if not cidr_str or not isinstance(cidr_str, str) or not cidr_str.strip():
        return None
    try:
        net = ipaddress.ip_network(cidr_str.strip(), strict=False)
    except ValueError:
        return None
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 24:
        return net
    return None


class HistoryStore:
    """SQLite-backed multi-run validation history ledger, streak tracker, and drift analyzer."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        if isinstance(db_path, Path):
            self.db_path: Path | str = db_path
            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn_target = str(db_path)
        elif isinstance(db_path, str):
            raw = db_path.strip()
            if not raw:
                raise ValueError("db_path must not be an empty string")
            if raw == ":memory:":
                self.db_path = ":memory:"
                conn_target = ":memory:"
            else:
                path_obj = Path(raw)
                path_obj.parent.mkdir(parents=True, exist_ok=True)
                self.db_path = path_obj
                conn_target = str(path_obj)
        else:
            raise ValueError("db_path must be a Path or string")

        self._conn = sqlite3.connect(conn_target)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS validation_runs (
                    run_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL UNIQUE,
                    recorded_at TEXT NOT NULL,
                    site_ids_json TEXT NOT NULL,
                    total_items INTEGER NOT NULL,
                    classification_counts_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS item_streaks (
                    item_type TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    current_classification TEXT NOT NULL,
                    current_confidence REAL NOT NULL,
                    consecutive_stale_runs INTEGER NOT NULL,
                    total_runs_seen INTEGER NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    first_stale_at TEXT,
                    last_confirmed_active_at TEXT,
                    stale_duration_days REAL NOT NULL,
                    previous_classification TEXT,
                    transition_type TEXT,
                    PRIMARY KEY (item_type, item_id)
                );

                CREATE TABLE IF NOT EXISTS drift_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    item_type TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    previous_classification TEXT NOT NULL,
                    new_classification TEXT NOT NULL,
                    transition_type TEXT NOT NULL,
                    confidence REAL NOT NULL
                );
                """
            )

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __enter__(self) -> HistoryStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _next_generated_run_id(self) -> str:
        row = self._conn.execute(
            "SELECT COUNT(*) AS cnt FROM validation_runs"
        ).fetchone()
        seq = (int(row["cnt"]) if row is not None else 0) + 1
        return f"run-{seq:04d}-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _row_to_run_record(row: sqlite3.Row) -> ValidationRunRecord:
        return ValidationRunRecord(
            run_id=row["run_id"],
            recorded_at=normalize_utc_datetime(
                row["recorded_at"], field_name="recorded_at"
            ),
            site_ids=json.loads(row["site_ids_json"]),
            total_items=int(row["total_items"]),
            classification_counts=json.loads(row["classification_counts_json"]),
        )

    @staticmethod
    def _row_to_streak(row: sqlite3.Row) -> ItemStreakSummary:
        return ItemStreakSummary(
            site_id=row["site_id"],
            item_type=row["item_type"],
            item_id=row["item_id"],
            name=row["name"],
            current_classification=ValidationClassification(
                row["current_classification"]
            ),
            current_confidence=float(row["current_confidence"]),
            consecutive_stale_runs=int(row["consecutive_stale_runs"]),
            total_runs_seen=int(row["total_runs_seen"]),
            first_seen_at=normalize_utc_datetime(
                row["first_seen_at"], field_name="first_seen_at"
            ),
            first_stale_at=_normalize_optional_utc_datetime(
                row["first_stale_at"], "first_stale_at"
            ),
            last_confirmed_active_at=_normalize_optional_utc_datetime(
                row["last_confirmed_active_at"], "last_confirmed_active_at"
            ),
            stale_duration_days=float(row["stale_duration_days"]),
            previous_classification=(
                ValidationClassification(row["previous_classification"])
                if row["previous_classification"] is not None
                else None
            ),
            transition_type=(
                DriftTransitionType(row["transition_type"])
                if row["transition_type"] is not None
                else None
            ),
        )

    @staticmethod
    def _row_to_drift_event(row: sqlite3.Row) -> DriftEvent:
        return DriftEvent(
            run_id=row["run_id"],
            recorded_at=normalize_utc_datetime(
                row["recorded_at"], field_name="recorded_at"
            ),
            site_id=row["site_id"],
            item_type=row["item_type"],
            item_id=row["item_id"],
            name=row["name"],
            previous_classification=ValidationClassification(
                row["previous_classification"]
            ),
            new_classification=ValidationClassification(
                row["new_classification"]
            ),
            transition_type=DriftTransitionType(row["transition_type"]),
            confidence=float(row["confidence"]),
        )

    def record_run(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        run_id: Optional[str] = None,
        recorded_at: Optional[datetime | str] = None,
    ) -> ValidationRunRecord:
        """Persist a validation run, update per-item stale streaks, and record drift events."""
        resolved_run_id = (
            _require_non_empty_str(run_id, "run_id").strip()
            if run_id is not None
            else self._next_generated_run_id()
        )
        existing_run = self._conn.execute(
            "SELECT 1 FROM validation_runs WHERE run_id = ?",
            (resolved_run_id,),
        ).fetchone()
        if existing_run is not None:
            raise ValueError(
                f"Validation run {resolved_run_id!r} already exists in HistoryStore"
            )

        run_dt = (
            normalize_utc_datetime(recorded_at, field_name="recorded_at")
            if recorded_at is not None
            else datetime.now(timezone.utc)
        )

        normalized_results: list[ValidationResult] = [
            r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
            for r in results
        ]

        counts: dict[str, int] = {
            cls_val: 0 for cls_val in ALL_CLASSIFICATION_VALUES
        }
        site_ids: set[str] = set()

        for res in normalized_results:
            counts[res.classification.value] = (
                counts.get(res.classification.value, 0) + 1
            )
            site_ids.add(res.site_id)

        run_record = ValidationRunRecord(
            run_id=resolved_run_id,
            recorded_at=run_dt,
            site_ids=sorted(site_ids),
            total_items=len(normalized_results),
            classification_counts=counts,
        )

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO validation_runs (
                    run_id, recorded_at, site_ids_json, total_items, classification_counts_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run_record.run_id,
                    run_record.recorded_at.isoformat(),
                    json.dumps(run_record.site_ids),
                    run_record.total_items,
                    json.dumps(run_record.classification_counts),
                ),
            )

            for res in normalized_results:
                prior_row = self._conn.execute(
                    """
                    SELECT * FROM item_streaks
                    WHERE item_type = ? AND item_id = ?
                    """,
                    (res.item_type, res.item_id),
                ).fetchone()

                prior = (
                    self._row_to_streak(prior_row)
                    if prior_row is not None
                    else None
                )

                first_seen_at = (
                    prior.first_seen_at if prior is not None else run_dt
                )
                total_runs_seen = (
                    prior.total_runs_seen + 1 if prior is not None else 1
                )
                previous_classification = (
                    prior.current_classification if prior is not None else None
                )
                last_confirmed_active_at = (
                    prior.last_confirmed_active_at if prior is not None else None
                )

                if (
                    res.classification
                    is ValidationClassification.STALE_LIKELY_UNUSED
                ):
                    consecutive_stale = (
                        prior.consecutive_stale_runs + 1
                        if prior is not None
                        else 1
                    )
                    first_stale_at = (
                        prior.first_stale_at
                        if (prior is not None and prior.first_stale_at is not None)
                        else run_dt
                    )
                    stale_duration_days = round(
                        max(
                            0.0,
                            (run_dt - first_stale_at).total_seconds()
                            / SECONDS_PER_DAY,
                        ),
                        4,
                    )
                elif (
                    res.classification
                    is ValidationClassification.CONFIRMED_ACTIVE
                ):
                    consecutive_stale = 0
                    first_stale_at = None
                    stale_duration_days = 0.0
                    last_confirmed_active_at = run_dt
                else:
                    consecutive_stale = 0
                    first_stale_at = None
                    stale_duration_days = 0.0

                transition_type: Optional[DriftTransitionType] = None
                if previous_classification is not None:
                    transition_type = _DRIFT_TRANSITION_MAP.get(
                        (previous_classification, res.classification)
                    )

                updated_streak = ItemStreakSummary(
                    site_id=res.site_id,
                    item_type=res.item_type,
                    item_id=res.item_id,
                    name=res.name,
                    current_classification=res.classification,
                    current_confidence=res.confidence,
                    consecutive_stale_runs=consecutive_stale,
                    total_runs_seen=total_runs_seen,
                    first_seen_at=first_seen_at,
                    first_stale_at=first_stale_at,
                    last_confirmed_active_at=last_confirmed_active_at,
                    stale_duration_days=stale_duration_days,
                    previous_classification=previous_classification,
                    transition_type=transition_type,
                )

                self._conn.execute(
                    """
                    INSERT INTO item_streaks (
                        item_type, item_id, site_id, name,
                        current_classification, current_confidence,
                        consecutive_stale_runs, total_runs_seen,
                        first_seen_at, first_stale_at, last_confirmed_active_at,
                        stale_duration_days, previous_classification, transition_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(item_type, item_id) DO UPDATE SET
                        site_id = excluded.site_id,
                        name = excluded.name,
                        current_classification = excluded.current_classification,
                        current_confidence = excluded.current_confidence,
                        consecutive_stale_runs = excluded.consecutive_stale_runs,
                        total_runs_seen = excluded.total_runs_seen,
                        first_seen_at = excluded.first_seen_at,
                        first_stale_at = excluded.first_stale_at,
                        last_confirmed_active_at = excluded.last_confirmed_active_at,
                        stale_duration_days = excluded.stale_duration_days,
                        previous_classification = excluded.previous_classification,
                        transition_type = excluded.transition_type
                    """,
                    (
                        updated_streak.item_type,
                        updated_streak.item_id,
                        updated_streak.site_id,
                        updated_streak.name,
                        updated_streak.current_classification.value,
                        updated_streak.current_confidence,
                        updated_streak.consecutive_stale_runs,
                        updated_streak.total_runs_seen,
                        updated_streak.first_seen_at.isoformat(),
                        _format_optional_datetime(updated_streak.first_stale_at),
                        _format_optional_datetime(
                            updated_streak.last_confirmed_active_at
                        ),
                        updated_streak.stale_duration_days,
                        (
                            updated_streak.previous_classification.value
                            if updated_streak.previous_classification is not None
                            else None
                        ),
                        (
                            updated_streak.transition_type.value
                            if updated_streak.transition_type is not None
                            else None
                        ),
                    ),
                )

                if (
                    transition_type is not None
                    and previous_classification is not None
                ):
                    drift_event = DriftEvent(
                        run_id=run_record.run_id,
                        recorded_at=run_dt,
                        site_id=res.site_id,
                        item_type=res.item_type,
                        item_id=res.item_id,
                        name=res.name,
                        previous_classification=previous_classification,
                        new_classification=res.classification,
                        transition_type=transition_type,
                        confidence=res.confidence,
                    )
                    self._conn.execute(
                        """
                        INSERT INTO drift_events (
                            run_id, recorded_at, site_id, item_type, item_id, name,
                            previous_classification, new_classification,
                            transition_type, confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            drift_event.run_id,
                            drift_event.recorded_at.isoformat(),
                            drift_event.site_id,
                            drift_event.item_type,
                            drift_event.item_id,
                            drift_event.name,
                            drift_event.previous_classification.value,
                            drift_event.new_classification.value,
                            drift_event.transition_type.value,
                            drift_event.confidence,
                        ),
                    )

        return run_record

    def get_run(self, run_id: str) -> Optional[ValidationRunRecord]:
        """Return the ValidationRunRecord for `run_id`, or None if not found."""
        row = self._conn.execute(
            "SELECT * FROM validation_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_run_record(row)

    def list_runs(self) -> list[ValidationRunRecord]:
        """Return all recorded ValidationRunRecord entries ordered by recording sequence."""
        rows = self._conn.execute(
            "SELECT * FROM validation_runs ORDER BY run_seq ASC"
        ).fetchall()
        return [self._row_to_run_record(r) for r in rows]

    def get_item_streak(
        self,
        item_type: str,
        item_id: str,
        site_id: Optional[str] = None,
    ) -> Optional[ItemStreakSummary]:
        """Return the current ItemStreakSummary for `(item_type, item_id)` or None."""
        if site_id is not None:
            row = self._conn.execute(
                """
                SELECT * FROM item_streaks
                WHERE item_type = ? AND item_id = ? AND site_id = ?
                """,
                (item_type, item_id, site_id),
            ).fetchone()
        else:
            row = self._conn.execute(
                """
                SELECT * FROM item_streaks
                WHERE item_type = ? AND item_id = ?
                """,
                (item_type, item_id),
            ).fetchone()

        if row is None:
            return None
        return self._row_to_streak(row)

    def list_streaks(
        self,
        site_id: Optional[str] = None,
        min_consecutive_stale: int = 0,
        item_type: Optional[str] = None,
        classification: Optional[ValidationClassification | str] = None,
    ) -> list[ItemStreakSummary]:
        """Return tracked ItemStreakSummary records matching the given filters."""
        _require_non_negative_int(min_consecutive_stale, "min_consecutive_stale")

        clauses: list[str] = ["consecutive_stale_runs >= ?"]
        params: list[Any] = [min_consecutive_stale]

        if site_id is not None:
            clauses.append("site_id = ?")
            params.append(site_id)
        if item_type is not None:
            clauses.append("item_type = ?")
            params.append(item_type)
        if classification is not None:
            cls_enum = _coerce_classification(classification, "classification")
            clauses.append("current_classification = ?")
            params.append(cls_enum.value)

        where_sql = " AND ".join(clauses)
        rows = self._conn.execute(
            f"""
            SELECT * FROM item_streaks
            WHERE {where_sql}
            ORDER BY site_id ASC, item_type ASC, item_id ASC
            """,
            params,
        ).fetchall()
        return [self._row_to_streak(r) for r in rows]

    def detect_drift(
        self,
        run_id: Optional[str] = None,
        site_id: Optional[str] = None,
        transition_type: Optional[DriftTransitionType | str] = None,
    ) -> list[DriftEvent]:
        """Return DriftEvent records for `run_id` (or the latest recorded run when `run_id` is None)."""
        if run_id is None:
            latest_row = self._conn.execute(
                "SELECT run_id FROM validation_runs ORDER BY run_seq DESC LIMIT 1"
            ).fetchone()
            if latest_row is None:
                return []
            target_run_id = str(latest_row["run_id"])
        else:
            run_row = self._conn.execute(
                "SELECT run_id FROM validation_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run_row is None:
                raise KeyError(
                    f"Validation run {run_id!r} not found in HistoryStore"
                )
            target_run_id = run_id

        clauses: list[str] = ["run_id = ?"]
        params: list[Any] = [target_run_id]

        if site_id is not None:
            clauses.append("site_id = ?")
            params.append(site_id)
        if transition_type is not None:
            trans_enum = _coerce_transition_type(
                transition_type, "transition_type"
            )
            clauses.append("transition_type = ?")
            params.append(trans_enum.value)

        where_sql = " AND ".join(clauses)
        rows = self._conn.execute(
            f"""
            SELECT * FROM drift_events
            WHERE {where_sql}
            ORDER BY event_id ASC
            """,
            params,
        ).fetchall()
        return [self._row_to_drift_event(r) for r in rows]

    @staticmethod
    def compute_subnet_utilization(
        sites: Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any],
        results: Sequence[ValidationResult | Mapping[str, Any]],
    ) -> list[SubnetUtilizationSummary]:
        """Compute per-site /24 subnet IP assignment, active usage, and reclaimable stale IP metrics."""
        site_list = _coerce_sites(sites)
        result_list: list[ValidationResult] = [
            r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
            for r in results
        ]

        ip_results_by_site: dict[tuple[str, str], ValidationResult] = {}
        ip_results_global: dict[str, ValidationResult] = {}
        obj_results_by_site: dict[tuple[str, str], ValidationResult] = {}
        obj_results_global: dict[str, ValidationResult] = {}

        for res in result_list:
            if res.item_type == "IPAddress":
                parsed_ip = _try_parse_ipv4(res.item_id)
                norm_ip = str(parsed_ip) if parsed_ip is not None else res.item_id.strip()
                ip_results_by_site[(res.site_id, norm_ip)] = res
                ip_results_global[norm_ip] = res
            else:
                obj_results_by_site[(res.site_id, res.item_id)] = res
                obj_results_global[res.item_id] = res

        summaries: list[SubnetUtilizationSummary] = []

        for site in site_list:
            ip_to_assigned_obj_ids: dict[str, list[str]] = {}

            def _link_ip_obj(ip_val: str, obj_id: Optional[str]) -> None:
                if not obj_id or not obj_id.strip():
                    return
                clean_obj = obj_id.strip()
                bucket = ip_to_assigned_obj_ids.setdefault(ip_val, [])
                if clean_obj not in bucket:
                    bucket.append(clean_obj)

            for ip_rec in site.ip_addresses:
                parsed = _try_parse_ipv4(ip_rec.ip)
                if parsed is not None:
                    _link_ip_obj(str(parsed), ip_rec.assigned_object_id)

            for eq in site.equipment:
                for raw_ip in eq.assigned_ips:
                    parsed = _try_parse_ipv4(raw_ip)
                    if parsed is not None:
                        _link_ip_obj(str(parsed), eq.equipment_id)

            for dev in site.devices:
                parsed = _try_parse_ipv4(dev.management_ip)
                if parsed is not None:
                    _link_ip_obj(str(parsed), dev.device_id)

            for subnet in site.subnets:
                net = _try_parse_slash24_ipv4(subnet.cidr)
                if net is None:
                    continue

                assigned_ips: set[str] = set()
                for ip_rec in site.ip_addresses:
                    parsed = _try_parse_ipv4(ip_rec.ip)
                    if parsed is not None and (
                        ip_rec.subnet_id == subnet.subnet_id or parsed in net
                    ):
                        assigned_ips.add(str(parsed))

                for eq in site.equipment:
                    for raw_ip in eq.assigned_ips:
                        parsed = _try_parse_ipv4(raw_ip)
                        if parsed is not None and parsed in net:
                            assigned_ips.add(str(parsed))

                for dev in site.devices:
                    parsed = _try_parse_ipv4(dev.management_ip)
                    if parsed is not None and parsed in net:
                        assigned_ips.add(str(parsed))

                confirmed_active_count = 0
                stale_reclaimable_count = 0

                for ip_str in sorted(assigned_ips):
                    direct_res = ip_results_by_site.get(
                        (site.site_id, ip_str)
                    ) or ip_results_global.get(ip_str)

                    linked_res: Optional[ValidationResult] = None
                    for obj_id in ip_to_assigned_obj_ids.get(ip_str, ()):
                        candidate = obj_results_by_site.get(
                            (site.site_id, obj_id)
                        ) or obj_results_global.get(obj_id)
                        if candidate is not None:
                            linked_res = candidate
                            if candidate.classification in (
                                ValidationClassification.CONFIRMED_ACTIVE,
                                ValidationClassification.STALE_LIKELY_UNUSED,
                            ):
                                break

                    effective_cls: Optional[ValidationClassification] = None
                    if direct_res is not None and direct_res.classification in (
                        ValidationClassification.CONFIRMED_ACTIVE,
                        ValidationClassification.STALE_LIKELY_UNUSED,
                    ):
                        effective_cls = direct_res.classification
                    elif linked_res is not None and linked_res.classification in (
                        ValidationClassification.CONFIRMED_ACTIVE,
                        ValidationClassification.STALE_LIKELY_UNUSED,
                    ):
                        effective_cls = linked_res.classification
                    elif direct_res is not None:
                        effective_cls = direct_res.classification
                    elif linked_res is not None:
                        effective_cls = linked_res.classification

                    if (
                        effective_cls
                        is ValidationClassification.CONFIRMED_ACTIVE
                    ):
                        confirmed_active_count += 1
                    elif (
                        effective_cls
                        is ValidationClassification.STALE_LIKELY_UNUSED
                    ):
                        stale_reclaimable_count += 1

                total_assigned = len(assigned_ips)
                utilization_pct = (
                    round((confirmed_active_count / total_assigned) * 100.0, 2)
                    if total_assigned > 0
                    else 0.0
                )

                summaries.append(
                    SubnetUtilizationSummary(
                        subnet_id=subnet.subnet_id,
                        site_id=site.site_id,
                        cidr=subnet.cidr,
                        total_assigned_ips=total_assigned,
                        confirmed_active_ips=confirmed_active_count,
                        stale_reclaimable_ips=stale_reclaimable_count,
                        active_utilization_pct=utilization_pct,
                    )
                )

        return summaries

    def _list_all_drift_events(self) -> list[DriftEvent]:
        rows = self._conn.execute(
            "SELECT * FROM drift_events ORDER BY event_id ASC"
        ).fetchall()
        return [self._row_to_drift_event(r) for r in rows]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete history ledger state to a dictionary."""
        return {
            "runs": [r.to_dict() for r in self.list_runs()],
            "streaks": [s.to_dict() for s in self.list_streaks()],
            "drift_events": [e.to_dict() for e in self._list_all_drift_events()],
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        """Serialize the complete history ledger state to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def export_json(
        self, path: Path | str, *, indent: Optional[int] = 2
    ) -> Path:
        """Write the complete history ledger state to a JSON file on disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(indent=indent), encoding="utf-8")
        return target

    def _load_state_from_mapping(self, data: Mapping[str, Any]) -> None:
        if not isinstance(data, Mapping):
            raise ValueError("HistoryStore state data must be a mapping")

        runs = [
            r
            if isinstance(r, ValidationRunRecord)
            else ValidationRunRecord.from_dict(r)
            for r in data.get("runs", [])
        ]
        streaks = [
            s
            if isinstance(s, ItemStreakSummary)
            else ItemStreakSummary.from_dict(s)
            for s in data.get("streaks", [])
        ]
        drift_events = [
            e if isinstance(e, DriftEvent) else DriftEvent.from_dict(e)
            for e in data.get("drift_events", [])
        ]

        with self._conn:
            self._conn.execute("DELETE FROM drift_events")
            self._conn.execute("DELETE FROM item_streaks")
            self._conn.execute("DELETE FROM validation_runs")

            for run in runs:
                self._conn.execute(
                    """
                    INSERT INTO validation_runs (
                        run_id, recorded_at, site_ids_json, total_items, classification_counts_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        run.run_id,
                        run.recorded_at.isoformat(),
                        json.dumps(run.site_ids),
                        run.total_items,
                        json.dumps(run.classification_counts),
                    ),
                )

            for streak in streaks:
                self._conn.execute(
                    """
                    INSERT INTO item_streaks (
                        item_type, item_id, site_id, name,
                        current_classification, current_confidence,
                        consecutive_stale_runs, total_runs_seen,
                        first_seen_at, first_stale_at, last_confirmed_active_at,
                        stale_duration_days, previous_classification, transition_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        streak.item_type,
                        streak.item_id,
                        streak.site_id,
                        streak.name,
                        streak.current_classification.value,
                        streak.current_confidence,
                        streak.consecutive_stale_runs,
                        streak.total_runs_seen,
                        streak.first_seen_at.isoformat(),
                        _format_optional_datetime(streak.first_stale_at),
                        _format_optional_datetime(
                            streak.last_confirmed_active_at
                        ),
                        streak.stale_duration_days,
                        (
                            streak.previous_classification.value
                            if streak.previous_classification is not None
                            else None
                        ),
                        (
                            streak.transition_type.value
                            if streak.transition_type is not None
                            else None
                        ),
                    ),
                )

            for event in drift_events:
                self._conn.execute(
                    """
                    INSERT INTO drift_events (
                        run_id, recorded_at, site_id, item_type, item_id, name,
                        previous_classification, new_classification,
                        transition_type, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.run_id,
                        event.recorded_at.isoformat(),
                        event.site_id,
                        event.item_type,
                        event.item_id,
                        event.name,
                        event.previous_classification.value,
                        event.new_classification.value,
                        event.transition_type.value,
                        event.confidence,
                    ),
                )

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        db_path: Path | str = ":memory:",
    ) -> HistoryStore:
        """Create and populate a HistoryStore from a serialized state dictionary."""
        store = cls(db_path=db_path)
        store._load_state_from_mapping(data)
        return store

    @classmethod
    def from_json(
        cls,
        raw: str,
        db_path: Path | str = ":memory:",
    ) -> HistoryStore:
        """Create and populate a HistoryStore from a JSON string."""
        return cls.from_dict(json.loads(raw), db_path=db_path)

    def _import_json_impl(
        target: Any,
        path: Path | str,
        db_path: Path | str = ":memory:",
    ) -> HistoryStore:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(target, HistoryStore):
            target._load_state_from_mapping(data)
            return target
        return target.from_dict(data, db_path=db_path)

    import_json = _HybridImportMethod(_import_json_impl)


__all__ = [
    "DriftEvent",
    "DriftTransitionType",
    "HistoryStore",
    "ItemStreakSummary",
    "SubnetUtilizationSummary",
    "ValidationRunRecord",
]
