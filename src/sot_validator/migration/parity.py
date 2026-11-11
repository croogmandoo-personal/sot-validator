"""Dual-Run Parity Checker and Site Migration Readiness Scorecard for NetBox and Nautobot."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.migration.exporter import (
    ENTITY_COLLECTION_KEYS,
    GoldenInventoryFilter,
    ModernSoTExporter,
    _normalize_discrepancies,
    _normalize_sites_input,
    _normalize_validation_results,
    _parse_vlan_vid,
    _resolve_timestamp,
    _strip_ip_mask,
    slugify,
)
from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    DiscrepancyType,
    ReconciliationReport,
)


PARITY_ENTITY_COLLECTIONS: tuple[str, ...] = (
    "devices",
    "virtual_machines",
    "ip_addresses",
    "vlans",
    "prefixes",
    "interfaces",
)

_STALE_MODERN_STATUSES: frozenset[str] = frozenset(
    {"decommissioning", "deprecated", "quarantined", "stale", "retired", "offline"}
)

_UNTRACKED_DISCREPANCY_TYPES: frozenset[DiscrepancyType] = frozenset(
    {
        DiscrepancyType.UNTRACKED_VM,
        DiscrepancyType.UNTRACKED_DEVICE,
        DiscrepancyType.UNTRACKED_IP,
    }
)


class ParityDiscrepancyType(str, Enum):
    """Discrepancy categories surfaced during legacy-to-modern SoT dual-run comparison."""

    MISSING_IN_MODERN_SOT = "MISSING_IN_MODERN_SOT"
    STALE_LEAKED_TO_MODERN_SOT = "STALE_LEAKED_TO_MODERN_SOT"
    ATTRIBUTE_MISMATCH = "ATTRIBUTE_MISMATCH"


ALL_PARITY_DISCREPANCY_TYPES: tuple[ParityDiscrepancyType, ...] = (
    ParityDiscrepancyType.MISSING_IN_MODERN_SOT,
    ParityDiscrepancyType.STALE_LEAKED_TO_MODERN_SOT,
    ParityDiscrepancyType.ATTRIBUTE_MISMATCH,
)


class CutoverRecommendation(str, Enum):
    """Per-site migration cutover recommendation state."""

    READY_FOR_CUTOVER = "READY_FOR_CUTOVER"
    NEEDS_REMEDIATION = "NEEDS_REMEDIATION"
    BLOCKED = "BLOCKED"


ALL_CUTOVER_RECOMMENDATIONS: tuple[CutoverRecommendation, ...] = (
    CutoverRecommendation.READY_FOR_CUTOVER,
    CutoverRecommendation.NEEDS_REMEDIATION,
    CutoverRecommendation.BLOCKED,
)


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _clamp_percentage(value: float | int) -> float:
    return round(max(0.0, min(100.0, float(value))), 2)


def _extract_legacy_id(record: Mapping[str, Any]) -> str:
    custom_fields = record.get("custom_fields")
    if isinstance(custom_fields, Mapping):
        raw = custom_fields.get("legacy_sot_id")
        if raw is not None and str(raw).strip():
            return str(raw).strip()
    raw_top = record.get("legacy_sot_id")
    if raw_top is not None and str(raw_top).strip():
        return str(raw_top).strip()
    return ""


def _extract_explicit_ip(record: Mapping[str, Any]) -> Optional[str]:
    for key in ("primary_ip", "primary_ip4", "management_ip", "ip_address", "ip"):
        val = _clean_optional_str(record.get(key))
        if val:
            return val
    custom_fields = record.get("custom_fields")
    if isinstance(custom_fields, Mapping):
        for key in ("primary_ip", "management_ip", "ip_address"):
            val = _clean_optional_str(custom_fields.get(key))
            if val:
                return val
    return None


def _extract_record_identifier(entity_type: str, record: Mapping[str, Any]) -> str:
    legacy_id = _extract_legacy_id(record)
    if entity_type in ("devices", "virtual_machines", "sites"):
        name = _clean_optional_str(record.get("name") or record.get("hostname"))
        if name:
            return name
    elif entity_type == "ip_addresses":
        addr = _clean_optional_str(record.get("address") or record.get("ip"))
        if addr:
            return addr
    elif entity_type == "vlans":
        name = _clean_optional_str(record.get("name"))
        vid = (
            record.get("vid")
            if record.get("vid") is not None
            else record.get("vlan_id")
        )
        if name:
            return name
        if vid is not None:
            return str(vid)
    elif entity_type == "prefixes":
        prefix = _clean_optional_str(record.get("prefix") or record.get("cidr"))
        if prefix:
            return prefix
    elif entity_type == "interfaces":
        name = _clean_optional_str(record.get("name"))
        dev = _clean_optional_str(record.get("device"))
        if dev and name:
            return f"{dev}:{name}"
        if name:
            return name

    if legacy_id:
        return legacy_id
    slug_val = _clean_optional_str(record.get("slug"))
    if slug_val:
        return slug_val
    return "unknown"


def _record_candidate_tokens(
    entity_type: str, record: Mapping[str, Any]
) -> set[str]:
    tokens: set[str] = set()
    legacy_id = _extract_legacy_id(record)
    if legacy_id:
        tokens.add(legacy_id)
        tokens.add(legacy_id.lower())
        tokens.add(slugify(legacy_id))
        if ":ip:" in legacy_id:
            ip_part = legacy_id.split(":ip:", 1)[1].strip()
            if ip_part:
                tokens.add(ip_part)

    for key in ("name", "hostname", "slug", "address", "ip", "prefix", "cidr"):
        val = _clean_optional_str(record.get(key))
        if val:
            tokens.add(val)
            tokens.add(val.lower())
            tokens.add(slugify(val))
            if key in ("address", "ip"):
                clean_ip = _strip_ip_mask(val)
                if clean_ip:
                    tokens.add(clean_ip)

    if entity_type == "vlans":
        vid = _parse_vlan_vid(
            record.get("vid")
            if record.get("vid") is not None
            else record.get("vlan_id"),
            fallback=None,
        )
        if vid is not None:
            tokens.add(str(vid))

    if entity_type == "interfaces":
        dev = _clean_optional_str(record.get("device"))
        name = _clean_optional_str(record.get("name"))
        if dev and name:
            tokens.add(f"{dev}:{name}")
            tokens.add(f"{dev.lower()}:{name.lower()}")

    return tokens


@dataclass
class ParityDiscrepancy:
    """Single dual-run parity discrepancy between Golden Inventory and Modern SoT."""

    discrepancy_id: str
    discrepancy_type: ParityDiscrepancyType
    site_id: str
    entity_type: str
    item_identifier: str
    attribute_name: Optional[str] = None
    expected_value: Optional[Any] = None
    actual_value: Optional[Any] = None
    waived: bool = False
    details: Optional[str] = None

    def __post_init__(self) -> None:
        self.discrepancy_id = _require_non_empty_str(
            self.discrepancy_id, "discrepancy_id"
        ).strip()
        if not isinstance(self.discrepancy_type, ParityDiscrepancyType):
            try:
                self.discrepancy_type = ParityDiscrepancyType(self.discrepancy_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid discrepancy_type: {self.discrepancy_type!r}"
                ) from exc
        self.site_id = _require_non_empty_str(self.site_id, "site_id").strip()
        self.entity_type = _require_non_empty_str(
            self.entity_type, "entity_type"
        ).strip()
        self.item_identifier = _require_non_empty_str(
            self.item_identifier, "item_identifier"
        ).strip()
        self.attribute_name = _clean_optional_str(self.attribute_name)
        self.waived = bool(self.waived)
        self.details = _clean_optional_str(self.details)

    def to_dict(self) -> dict[str, Any]:
        return {
            "discrepancy_id": self.discrepancy_id,
            "discrepancy_type": self.discrepancy_type.value,
            "site_id": self.site_id,
            "entity_type": self.entity_type,
            "item_identifier": self.item_identifier,
            "attribute_name": self.attribute_name,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "waived": self.waived,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ParityDiscrepancy:
        return cls(
            discrepancy_id=data["discrepancy_id"],
            discrepancy_type=ParityDiscrepancyType(data["discrepancy_type"]),
            site_id=data["site_id"],
            entity_type=data["entity_type"],
            item_identifier=data["item_identifier"],
            attribute_name=data.get("attribute_name"),
            expected_value=data.get("expected_value"),
            actual_value=data.get("actual_value"),
            waived=bool(data.get("waived", False)),
            details=data.get("details"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ParityDiscrepancy:
        return cls.from_dict(json.loads(raw))


@dataclass
class SiteMigrationReadinessScorecard:
    """Per-site dual-run parity evaluation and migration readiness scorecard."""

    site_id: str
    site_name: str = ""
    readiness_score: float = 0.0
    recommendation: CutoverRecommendation = CutoverRecommendation.BLOCKED
    parity_match_percentage: float = 0.0
    confirmed_active_count: int = 0
    stale_count: int = 0
    unreachable_count: int = 0
    insufficient_data_count: int = 0
    unresolved_untracked_count: int = 0
    expected_golden_items: int = 0
    matched_modern_items: int = 0
    discrepancies: list[ParityDiscrepancy] = field(default_factory=list)
    waived_discrepancy_count: int = 0
    blocking_reasons: list[str] = field(default_factory=list)
    evaluated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        self.site_id = _require_non_empty_str(self.site_id, "site_id").strip()
        self.site_name = str(self.site_name or "").strip() or self.site_id
        self.readiness_score = _clamp_percentage(self.readiness_score)
        if not isinstance(self.recommendation, CutoverRecommendation):
            try:
                self.recommendation = CutoverRecommendation(self.recommendation)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid recommendation: {self.recommendation!r}"
                ) from exc
        self.parity_match_percentage = _clamp_percentage(self.parity_match_percentage)
        self.confirmed_active_count = max(0, int(self.confirmed_active_count))
        self.stale_count = max(0, int(self.stale_count))
        self.unreachable_count = max(0, int(self.unreachable_count))
        self.insufficient_data_count = max(0, int(self.insufficient_data_count))
        self.unresolved_untracked_count = max(0, int(self.unresolved_untracked_count))
        self.expected_golden_items = max(0, int(self.expected_golden_items))
        self.matched_modern_items = max(0, int(self.matched_modern_items))
        self.discrepancies = [
            d if isinstance(d, ParityDiscrepancy) else ParityDiscrepancy.from_dict(d)
            for d in (self.discrepancies or [])
        ]
        computed_waived = sum(1 for d in self.discrepancies if d.waived)
        self.waived_discrepancy_count = (
            computed_waived
            if self.waived_discrepancy_count == 0 and computed_waived > 0
            else max(0, int(self.waived_discrepancy_count))
        )
        self.blocking_reasons = [
            str(r).strip() for r in (self.blocking_reasons or []) if str(r).strip()
        ]
        self.evaluated_at = _resolve_timestamp(self.evaluated_at)

    @property
    def unwaived_discrepancies(self) -> list[ParityDiscrepancy]:
        return [d for d in self.discrepancies if not d.waived]

    @property
    def is_ready_for_cutover(self) -> bool:
        return self.recommendation is CutoverRecommendation.READY_FOR_CUTOVER

    @property
    def summary_by_discrepancy_type(self) -> dict[str, int]:
        counts: dict[str, int] = {
            dtype.value: 0 for dtype in ALL_PARITY_DISCREPANCY_TYPES
        }
        for disc in self.discrepancies:
            counts[disc.discrepancy_type.value] = (
                counts.get(disc.discrepancy_type.value, 0) + 1
            )
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "site_name": self.site_name,
            "readiness_score": self.readiness_score,
            "recommendation": self.recommendation.value,
            "is_ready_for_cutover": self.is_ready_for_cutover,
            "parity_match_percentage": self.parity_match_percentage,
            "confirmed_active_count": self.confirmed_active_count,
            "stale_count": self.stale_count,
            "unreachable_count": self.unreachable_count,
            "insufficient_data_count": self.insufficient_data_count,
            "unresolved_untracked_count": self.unresolved_untracked_count,
            "expected_golden_items": self.expected_golden_items,
            "matched_modern_items": self.matched_modern_items,
            "waived_discrepancy_count": self.waived_discrepancy_count,
            "unwaived_discrepancy_count": len(self.unwaived_discrepancies),
            "summary_by_discrepancy_type": self.summary_by_discrepancy_type,
            "blocking_reasons": list(self.blocking_reasons),
            "discrepancies": [d.to_dict() for d in self.discrepancies],
            "evaluated_at": _format_optional_datetime(self.evaluated_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SiteMigrationReadinessScorecard:
        return cls(
            site_id=data["site_id"],
            site_name=data.get("site_name", ""),
            readiness_score=float(data.get("readiness_score", 0.0)),
            recommendation=CutoverRecommendation(
                data.get("recommendation", CutoverRecommendation.BLOCKED.value)
            ),
            parity_match_percentage=float(data.get("parity_match_percentage", 0.0)),
            confirmed_active_count=int(data.get("confirmed_active_count", 0)),
            stale_count=int(data.get("stale_count", 0)),
            unreachable_count=int(data.get("unreachable_count", 0)),
            insufficient_data_count=int(data.get("insufficient_data_count", 0)),
            unresolved_untracked_count=int(data.get("unresolved_untracked_count", 0)),
            expected_golden_items=int(data.get("expected_golden_items", 0)),
            matched_modern_items=int(data.get("matched_modern_items", 0)),
            discrepancies=[
                d if isinstance(d, ParityDiscrepancy) else ParityDiscrepancy.from_dict(d)
                for d in data.get("discrepancies", [])
            ],
            waived_discrepancy_count=int(data.get("waived_discrepancy_count", 0)),
            blocking_reasons=list(data.get("blocking_reasons", [])),
            evaluated_at=_resolve_timestamp(data.get("evaluated_at")),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> SiteMigrationReadinessScorecard:
        return cls.from_dict(json.loads(raw))


@dataclass
class MigrationParityReport:
    """Multi-site migration readiness and dual-run parity report."""

    scorecards: list[SiteMigrationReadinessScorecard] = field(default_factory=list)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        self.generated_at = _resolve_timestamp(self.generated_at)
        self.scorecards = [
            s
            if isinstance(s, SiteMigrationReadinessScorecard)
            else SiteMigrationReadinessScorecard.from_dict(s)
            for s in (self.scorecards or [])
        ]

    @property
    def total_sites(self) -> int:
        return len(self.scorecards)

    @property
    def ready_for_cutover_count(self) -> int:
        return sum(
            1
            for s in self.scorecards
            if s.recommendation is CutoverRecommendation.READY_FOR_CUTOVER
        )

    @property
    def needs_remediation_count(self) -> int:
        return sum(
            1
            for s in self.scorecards
            if s.recommendation is CutoverRecommendation.NEEDS_REMEDIATION
        )

    @property
    def blocked_count(self) -> int:
        return sum(
            1
            for s in self.scorecards
            if s.recommendation is CutoverRecommendation.BLOCKED
        )

    @property
    def average_readiness_score(self) -> float:
        if not self.scorecards:
            return 0.0
        return round(
            sum(s.readiness_score for s in self.scorecards) / len(self.scorecards),
            2,
        )

    @property
    def overall_parity_percentage(self) -> float:
        if not self.scorecards:
            return 0.0
        return round(
            sum(s.parity_match_percentage for s in self.scorecards)
            / len(self.scorecards),
            2,
        )

    @property
    def discrepancies(self) -> list[ParityDiscrepancy]:
        return [d for s in self.scorecards for d in s.discrepancies]

    @property
    def total_discrepancies(self) -> int:
        return sum(len(s.discrepancies) for s in self.scorecards)

    @property
    def summary_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {
            dtype.value: 0 for dtype in ALL_PARITY_DISCREPANCY_TYPES
        }
        for scorecard in self.scorecards:
            for disc in scorecard.discrepancies:
                counts[disc.discrepancy_type.value] = (
                    counts.get(disc.discrepancy_type.value, 0) + 1
                )
        return counts

    @property
    def summary_by_recommendation(self) -> dict[str, int]:
        counts: dict[str, int] = {
            rec.value: 0 for rec in ALL_CUTOVER_RECOMMENDATIONS
        }
        for scorecard in self.scorecards:
            counts[scorecard.recommendation.value] = (
                counts.get(scorecard.recommendation.value, 0) + 1
            )
        return counts

    def get_scorecard(
        self, site_id: str
    ) -> Optional[SiteMigrationReadinessScorecard]:
        target_slug = slugify(site_id)
        for scorecard in self.scorecards:
            if scorecard.site_id == site_id or slugify(scorecard.site_id) == target_slug:
                return scorecard
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": _format_optional_datetime(self.generated_at),
            "total_sites": self.total_sites,
            "ready_for_cutover_count": self.ready_for_cutover_count,
            "needs_remediation_count": self.needs_remediation_count,
            "blocked_count": self.blocked_count,
            "average_readiness_score": self.average_readiness_score,
            "overall_parity_percentage": self.overall_parity_percentage,
            "total_discrepancies": self.total_discrepancies,
            "summary_by_type": self.summary_by_type,
            "summary_by_recommendation": self.summary_by_recommendation,
            "scorecards": [s.to_dict() for s in self.scorecards],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MigrationParityReport:
        return cls(
            scorecards=[
                s
                if isinstance(s, SiteMigrationReadinessScorecard)
                else SiteMigrationReadinessScorecard.from_dict(s)
                for s in data.get("scorecards", [])
            ],
            generated_at=_resolve_timestamp(data.get("generated_at")),
        )

    def to_json(
        self,
        *,
        indent: Optional[int] = 2,
        output_path: Optional[Path | str] = None,
    ) -> str:
        content = json.dumps(self.to_dict(), indent=indent)
        if output_path is not None:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return content

    @classmethod
    def from_json(cls, raw: str) -> MigrationParityReport:
        return cls.from_dict(json.loads(raw))


class DualRunParityChecker:
    """Compares validated Golden Inventory against target NetBox/Nautobot state and computes readiness scorecards."""

    def __init__(
        self,
        golden_bundle: Optional[Mapping[str, Any] | ModernSoTExporter] = None,
        modern_bundle: Optional[
            Mapping[str, Any]
            | ModernSoTExporter
            | Sequence[Site | Mapping[str, Any]]
            | Site
        ] = None,
        *,
        target_bundle: Optional[
            Mapping[str, Any]
            | ModernSoTExporter
            | Sequence[Site | Mapping[str, Any]]
            | Site
        ] = None,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        stale_item_ids: Optional[Iterable[str]] = None,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
        unresolved_untracked_discrepancies: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        waived_discrepancy_ids: Optional[Iterable[str]] = None,
        waive_all_parity_discrepancies: bool = False,
        merge_untracked: bool = True,
        target_platform: str = "netbox",
        ready_score_threshold: float = 95.0,
        blocked_parity_threshold: float = 50.0,
        blocked_score_threshold: float = 50.0,
        evaluated_at: Optional[datetime | str] = None,
    ) -> None:
        self._golden_bundle = golden_bundle
        self._modern_bundle = (
            modern_bundle if modern_bundle is not None else target_bundle
        )
        self._sites = sites
        self._validation_results = validation_results
        self._reconciliation_report = reconciliation_report
        self._stale_item_ids: set[str] = (
            {str(x).strip() for x in stale_item_ids if str(x).strip()}
            if stale_item_ids is not None
            else set()
        )
        self._approved_discrepancy_ids: Optional[set[str]] = (
            {str(x).strip() for x in approved_discrepancy_ids if str(x).strip()}
            if approved_discrepancy_ids is not None
            else None
        )
        self._unresolved_untracked_discrepancies = unresolved_untracked_discrepancies
        self._waived_discrepancy_ids: set[str] = (
            {str(x).strip() for x in waived_discrepancy_ids if str(x).strip()}
            if waived_discrepancy_ids is not None
            else set()
        )
        self.waive_all_parity_discrepancies = bool(waive_all_parity_discrepancies)
        self.merge_untracked = bool(merge_untracked)
        self.target_platform = target_platform
        self.ready_score_threshold = float(ready_score_threshold)
        self.blocked_parity_threshold = float(blocked_parity_threshold)
        self.blocked_score_threshold = float(blocked_score_threshold)
        self._evaluated_at = evaluated_at

    @staticmethod
    def _is_bundle_mapping(obj: Any) -> bool:
        if isinstance(obj, ModernSoTExporter):
            return True
        if not isinstance(obj, Mapping):
            return False
        if "site_id" in obj and "name" in obj and "devices" in obj:
            # This is a serialized Site dict, not a ModernSoTExporter bundle
            devices_val = obj.get("devices")
            if isinstance(devices_val, Sequence) and devices_val:
                first_dev = devices_val[0]
                if isinstance(first_dev, Mapping) and "device_id" in first_dev:
                    return False
            if "subnets" in obj or "equipment" in obj:
                return False
        return any(k in obj for k in ENTITY_COLLECTION_KEYS) or "target_platform" in obj

    def _coerce_to_bundle(
        self,
        source: Any,
        *,
        validation_results: Optional[list[ValidationResult]] = None,
        reconciliation_report: Optional[list[DiscrepancyRecord]] = None,
        approved_discrepancy_ids: Optional[set[str]] = None,
        merge_untracked: bool = True,
        filter_for_golden: bool = False,
    ) -> dict[str, list[dict[str, Any]]]:
        if source is None:
            return {k: [] for k in ENTITY_COLLECTION_KEYS}
        if isinstance(source, ModernSoTExporter):
            raw_bundle = source.to_dict()
            return {
                k: [dict(item) for item in raw_bundle.get(k, [])]
                for k in ENTITY_COLLECTION_KEYS
            }
        if isinstance(source, Mapping) and self._is_bundle_mapping(source):
            return {
                k: [dict(item) for item in source.get(k, [])]
                for k in ENTITY_COLLECTION_KEYS
            }

        sites_list = _normalize_sites_input(source)
        if filter_for_golden:
            exporter = ModernSoTExporter(
                sites=sites_list,
                validation_results=validation_results,
                reconciliation_report=reconciliation_report,
                merge_untracked=merge_untracked,
                approved_discrepancy_ids=approved_discrepancy_ids,
                target_platform=self.target_platform,
            )
        else:
            inv_filter = GoldenInventoryFilter(
                include_stale=True,
                include_unreachable=True,
                include_insufficient_data=True,
                merge_untracked=False,
            )
            exporter = ModernSoTExporter(
                sites=sites_list,
                inventory_filter=inv_filter,
                target_platform=self.target_platform,
            )
        raw_bundle = exporter.to_dict()
        return {
            k: [dict(item) for item in raw_bundle.get(k, [])]
            for k in ENTITY_COLLECTION_KEYS
        }

    @staticmethod
    def _expand_waived_tokens(raw_ids: Iterable[str]) -> set[str]:
        tokens: set[str] = set()
        for item in raw_ids:
            text = str(item).strip()
            if not text:
                continue
            tokens.add(text)
            tokens.add(text.lower())
            tokens.add(slugify(text))
            clean_ip = _strip_ip_mask(text)
            if clean_ip:
                tokens.add(clean_ip)
        return tokens

    @staticmethod
    def _collect_stale_tokens(
        site_id: str,
        raw_sites: Sequence[Site],
        validation_results: Sequence[ValidationResult],
        explicit_stale_ids: Iterable[str],
        golden_bundle_records: Mapping[str, Sequence[Mapping[str, Any]]],
    ) -> set[str]:
        site_slug = slugify(site_id)
        tokens: set[str] = set()

        def _add_token(val: Optional[str]) -> None:
            if not val:
                return
            cleaned = str(val).strip()
            if not cleaned:
                return
            tokens.add(cleaned)
            tokens.add(cleaned.lower())
            tokens.add(slugify(cleaned))
            clean_ip = _strip_ip_mask(cleaned)
            if clean_ip and clean_ip[0].isdigit():
                tokens.add(clean_ip)
                tokens.add(f"{site_id}:ip:{clean_ip}")
                tokens.add(f"{site_slug}:ip:{clean_ip}")

        for s_id in explicit_stale_ids:
            _add_token(s_id)

        for res in validation_results:
            if res.site_id not in (site_id, site_slug, "unknown", "*"):
                continue
            if res.classification is ValidationClassification.STALE_LIKELY_UNUSED:
                _add_token(res.item_id)
                _add_token(res.name)

        for site in raw_sites:
            if site.site_id != site_id and slugify(site.site_id) != site_slug:
                continue
            for dev in site.devices:
                if (
                    dev.device_id in tokens
                    or dev.hostname.lower() in tokens
                    or slugify(dev.hostname) in tokens
                ):
                    _add_token(dev.device_id)
                    _add_token(dev.hostname)
                    _add_token(dev.management_ip)
            for eq in site.equipment:
                if (
                    eq.equipment_id in tokens
                    or eq.name.lower() in tokens
                    or slugify(eq.name) in tokens
                ):
                    _add_token(eq.equipment_id)
                    _add_token(eq.name)
                    for raw_ip in eq.assigned_ips:
                        _add_token(raw_ip)
            for ip_rec in site.ip_addresses:
                clean_ip = _strip_ip_mask(ip_rec.ip)
                if (
                    ip_rec.ip in tokens
                    or clean_ip in tokens
                    or (
                        ip_rec.assigned_object_id
                        and ip_rec.assigned_object_id in tokens
                    )
                ):
                    _add_token(ip_rec.ip)

        for entity_type in PARITY_ENTITY_COLLECTIONS:
            for rec in golden_bundle_records.get(entity_type, ()):
                status_lower = str(rec.get("status") or "").strip().lower()
                if status_lower in _STALE_MODERN_STATUSES:
                    for tok in _record_candidate_tokens(entity_type, rec):
                        _add_token(tok)

        return tokens

    @staticmethod
    def _filter_bundle_for_site(
        bundle: Mapping[str, Sequence[Mapping[str, Any]]],
        site_id: str,
        *,
        single_site_context: bool = False,
        raw_site: Optional[Site] = None,
    ) -> dict[str, list[dict[str, Any]]]:
        site_slug = slugify(site_id)
        site_device_names: set[str] = set()
        if raw_site is not None:
            for dev in raw_site.devices:
                site_device_names.add(dev.hostname.lower())
                site_device_names.add(slugify(dev.hostname))
            for eq in raw_site.equipment:
                site_device_names.add(eq.name.lower())
                site_device_names.add(slugify(eq.name))

        scoped: dict[str, list[dict[str, Any]]] = {
            k: [] for k in ENTITY_COLLECTION_KEYS
        }

        for s_rec in bundle.get("sites", ()):
            rec_slug = slugify(
                _clean_optional_str(s_rec.get("slug"))
                or _extract_legacy_id(s_rec)
                or _clean_optional_str(s_rec.get("name"))
                or ""
            )
            legacy_id = _extract_legacy_id(s_rec)
            if (
                rec_slug == site_slug
                or legacy_id == site_id
                or single_site_context
            ):
                scoped["sites"].append(dict(s_rec))

        for entity_type in (
            "devices",
            "virtual_machines",
            "ip_addresses",
            "vlans",
            "prefixes",
        ):
            for rec in bundle.get(entity_type, ()):
                rec_site = _clean_optional_str(rec.get("site"))
                legacy_id = _extract_legacy_id(rec)
                if rec_site:
                    if rec_site == site_id or slugify(rec_site) == site_slug:
                        scoped[entity_type].append(dict(rec))
                        if entity_type == "devices":
                            d_name = _clean_optional_str(
                                rec.get("name") or rec.get("hostname")
                            )
                            if d_name:
                                site_device_names.add(d_name.lower())
                                site_device_names.add(slugify(d_name))
                elif legacy_id.startswith(f"{site_id}:") or legacy_id.startswith(
                    f"{site_slug}:"
                ):
                    scoped[entity_type].append(dict(rec))
                elif single_site_context:
                    scoped[entity_type].append(dict(rec))
                    if entity_type == "devices":
                        d_name = _clean_optional_str(
                            rec.get("name") or rec.get("hostname")
                        )
                        if d_name:
                            site_device_names.add(d_name.lower())
                            site_device_names.add(slugify(d_name))

        for rec in bundle.get("interfaces", ()):
            rec_site = _clean_optional_str(rec.get("site"))
            dev_name = _clean_optional_str(rec.get("device"))
            if rec_site:
                if rec_site == site_id or slugify(rec_site) == site_slug:
                    scoped["interfaces"].append(dict(rec))
            elif dev_name and (
                dev_name.lower() in site_device_names
                or slugify(dev_name) in site_device_names
            ):
                scoped["interfaces"].append(dict(rec))
            elif single_site_context:
                scoped["interfaces"].append(dict(rec))

        return scoped

    @staticmethod
    def _records_match_exact(
        entity_type: str,
        g_rec: Mapping[str, Any],
        m_rec: Mapping[str, Any],
    ) -> bool:
        g_legacy = _extract_legacy_id(g_rec)
        m_legacy = _extract_legacy_id(m_rec)
        if g_legacy and m_legacy and g_legacy == m_legacy:
            return True

        g_slug = _clean_optional_str(g_rec.get("slug"))
        m_slug = _clean_optional_str(m_rec.get("slug"))
        if g_slug and m_slug and slugify(g_slug) == slugify(m_slug):
            return True

        if entity_type in ("devices", "virtual_machines"):
            g_name = _clean_optional_str(g_rec.get("name") or g_rec.get("hostname"))
            m_name = _clean_optional_str(m_rec.get("name") or m_rec.get("hostname"))
            if g_name and m_name and g_name.lower() == m_name.lower():
                return True

        elif entity_type == "ip_addresses":
            g_addr = _strip_ip_mask(
                _clean_optional_str(g_rec.get("address") or g_rec.get("ip"))
            )
            m_addr = _strip_ip_mask(
                _clean_optional_str(m_rec.get("address") or m_rec.get("ip"))
            )
            if g_addr and m_addr and g_addr == m_addr:
                return True

        elif entity_type == "vlans":
            g_vid = _parse_vlan_vid(
                g_rec.get("vid")
                if g_rec.get("vid") is not None
                else g_rec.get("vlan_id"),
                fallback=None,
            )
            m_vid = _parse_vlan_vid(
                m_rec.get("vid")
                if m_rec.get("vid") is not None
                else m_rec.get("vlan_id"),
                fallback=None,
            )
            if g_vid is not None and m_vid is not None and g_vid == m_vid:
                return True

        elif entity_type == "prefixes":
            g_pfx = _clean_optional_str(g_rec.get("prefix") or g_rec.get("cidr"))
            m_pfx = _clean_optional_str(m_rec.get("prefix") or m_rec.get("cidr"))
            if g_pfx and m_pfx and g_pfx == m_pfx:
                return True

        elif entity_type == "interfaces":
            g_dev = (_clean_optional_str(g_rec.get("device")) or "").lower()
            m_dev = (_clean_optional_str(m_rec.get("device")) or "").lower()
            g_name = (_clean_optional_str(g_rec.get("name")) or "").lower()
            m_name = (_clean_optional_str(m_rec.get("name")) or "").lower()
            if g_name and m_name and g_name == m_name:
                if not g_dev or not m_dev or g_dev == m_dev:
                    return True

        return False

    @staticmethod
    def _records_match_fallback(
        entity_type: str,
        g_rec: Mapping[str, Any],
        m_rec: Mapping[str, Any],
    ) -> bool:
        if entity_type == "ip_addresses":
            g_obj = _clean_optional_str(
                g_rec.get("assigned_object") or g_rec.get("dns_name")
            )
            m_obj = _clean_optional_str(
                m_rec.get("assigned_object") or m_rec.get("dns_name")
            )
            if g_obj and m_obj and g_obj.lower() == m_obj.lower():
                return True

        elif entity_type == "vlans":
            g_name = _clean_optional_str(g_rec.get("name"))
            m_name = _clean_optional_str(m_rec.get("name"))
            if g_name and m_name and g_name.lower() == m_name.lower():
                return True

        elif entity_type == "prefixes":
            g_desc = _clean_optional_str(g_rec.get("description"))
            m_desc = _clean_optional_str(m_rec.get("description"))
            if g_desc and m_desc and g_desc.lower() == m_desc.lower():
                return True

        return False

    @staticmethod
    def _compare_matched_records(
        site_id: str,
        entity_type: str,
        g_rec: Mapping[str, Any],
        m_rec: Mapping[str, Any],
        *,
        golden_ip_by_host: Mapping[str, str],
    ) -> list[ParityDiscrepancy]:
        mismatches: list[ParityDiscrepancy] = []
        item_id = _extract_record_identifier(entity_type, g_rec)

        def _add_mismatch(
            attr: str,
            expected: Any,
            actual: Any,
            details: str,
        ) -> None:
            disc_id = (
                f"parity-{slugify(site_id)}-mismatch-"
                f"{slugify(entity_type)}-{slugify(item_id)}-{slugify(attr)}"
            )
            mismatches.append(
                ParityDiscrepancy(
                    discrepancy_id=disc_id,
                    discrepancy_type=ParityDiscrepancyType.ATTRIBUTE_MISMATCH,
                    site_id=site_id,
                    entity_type=entity_type,
                    item_identifier=item_id,
                    attribute_name=attr,
                    expected_value=expected,
                    actual_value=actual,
                    details=details,
                )
            )

        if entity_type in ("devices", "virtual_machines"):
            g_name = _clean_optional_str(g_rec.get("name") or g_rec.get("hostname"))
            m_name = _clean_optional_str(m_rec.get("name") or m_rec.get("hostname"))
            if g_name and m_name and g_name != m_name:
                _add_mismatch(
                    "hostname",
                    g_name,
                    m_name,
                    f"{entity_type} hostname mismatch for '{item_id}': expected '{g_name}', got '{m_name}'",
                )

            g_role = _clean_optional_str(g_rec.get("role"))
            m_role = _clean_optional_str(m_rec.get("role"))
            if g_role and m_role and slugify(g_role) != slugify(m_role):
                _add_mismatch(
                    "role",
                    g_role,
                    m_role,
                    f"{entity_type} role mismatch for '{item_id}': expected '{g_role}', got '{m_role}'",
                )

            g_ip = _extract_explicit_ip(g_rec) or (
                golden_ip_by_host.get(g_name.lower()) if g_name else None
            )
            m_ip = _extract_explicit_ip(m_rec)
            if g_ip and m_ip and _strip_ip_mask(g_ip) != _strip_ip_mask(m_ip):
                _add_mismatch(
                    "ip_address",
                    g_ip,
                    m_ip,
                    f"{entity_type} IP assignment mismatch for '{item_id}': expected '{g_ip}', got '{m_ip}'",
                )

            if (
                "vlan" in g_rec
                or "vid" in g_rec
                or "vlan" in m_rec
                or "vid" in m_rec
            ):
                g_vlan = _parse_vlan_vid(
                    g_rec.get("vlan")
                    if g_rec.get("vlan") is not None
                    else g_rec.get("vid"),
                    fallback=None,
                )
                m_vlan = _parse_vlan_vid(
                    m_rec.get("vlan")
                    if m_rec.get("vlan") is not None
                    else m_rec.get("vid"),
                    fallback=None,
                )
                if g_vlan is not None and m_vlan is not None and g_vlan != m_vlan:
                    _add_mismatch(
                        "vlan",
                        g_vlan,
                        m_vlan,
                        f"{entity_type} VLAN mismatch for '{item_id}': expected {g_vlan}, got {m_vlan}",
                    )

        elif entity_type == "ip_addresses":
            g_addr = _clean_optional_str(g_rec.get("address") or g_rec.get("ip"))
            m_addr = _clean_optional_str(m_rec.get("address") or m_rec.get("ip"))
            if g_addr and m_addr:
                if _strip_ip_mask(g_addr) != _strip_ip_mask(m_addr) or (
                    "/" in g_addr and "/" in m_addr and g_addr != m_addr
                ):
                    _add_mismatch(
                        "ip_address",
                        g_addr,
                        m_addr,
                        f"IP address mismatch for '{item_id}': expected '{g_addr}', got '{m_addr}'",
                    )

            g_dns = _clean_optional_str(g_rec.get("dns_name"))
            m_dns = _clean_optional_str(m_rec.get("dns_name"))
            g_obj = _clean_optional_str(g_rec.get("assigned_object"))
            m_obj = _clean_optional_str(m_rec.get("assigned_object"))

            dns_diff = bool(g_dns and m_dns and g_dns != m_dns)
            obj_diff = bool(g_obj and m_obj and g_obj != m_obj)

            if dns_diff and not obj_diff:
                _add_mismatch(
                    "hostname",
                    g_dns,
                    m_dns,
                    f"IP DNS hostname mismatch for '{item_id}': expected '{g_dns}', got '{m_dns}'",
                )
            elif obj_diff and not dns_diff:
                _add_mismatch(
                    "ip_address",
                    g_obj,
                    m_obj,
                    f"IP assigned_object mismatch for '{item_id}': expected '{g_obj}', got '{m_obj}'",
                )
            elif dns_diff and obj_diff:
                _add_mismatch(
                    "hostname",
                    g_dns,
                    m_dns,
                    f"IP hostname/assignment mismatch for '{item_id}': expected '{g_dns}', got '{m_dns}'",
                )

            if (
                "vlan" in g_rec
                or "vid" in g_rec
                or "vlan" in m_rec
                or "vid" in m_rec
            ):
                g_vlan = _parse_vlan_vid(
                    g_rec.get("vlan")
                    if g_rec.get("vlan") is not None
                    else g_rec.get("vid"),
                    fallback=None,
                )
                m_vlan = _parse_vlan_vid(
                    m_rec.get("vlan")
                    if m_rec.get("vlan") is not None
                    else m_rec.get("vid"),
                    fallback=None,
                )
                if g_vlan is not None and m_vlan is not None and g_vlan != m_vlan:
                    _add_mismatch(
                        "vlan",
                        g_vlan,
                        m_vlan,
                        f"IP VLAN mismatch for '{item_id}': expected {g_vlan}, got {m_vlan}",
                    )

        elif entity_type == "vlans":
            g_vid = _parse_vlan_vid(
                g_rec.get("vid")
                if g_rec.get("vid") is not None
                else g_rec.get("vlan_id"),
                fallback=None,
            )
            m_vid = _parse_vlan_vid(
                m_rec.get("vid")
                if m_rec.get("vid") is not None
                else m_rec.get("vlan_id"),
                fallback=None,
            )
            if g_vid is not None and m_vid is not None and g_vid != m_vid:
                _add_mismatch(
                    "vlan",
                    g_vid,
                    m_vid,
                    f"VLAN ID mismatch for '{item_id}': expected {g_vid}, got {m_vid}",
                )

            g_name = _clean_optional_str(g_rec.get("name"))
            m_name = _clean_optional_str(m_rec.get("name"))
            if g_name and m_name and g_name != m_name:
                _add_mismatch(
                    "hostname",
                    g_name,
                    m_name,
                    f"VLAN name mismatch for '{item_id}': expected '{g_name}', got '{m_name}'",
                )

        elif entity_type == "prefixes":
            g_vlan = _parse_vlan_vid(g_rec.get("vlan"), fallback=None)
            m_vlan = _parse_vlan_vid(m_rec.get("vlan"), fallback=None)
            if g_vlan != m_vlan and (g_vlan is not None or m_vlan is not None):
                _add_mismatch(
                    "vlan",
                    g_vlan,
                    m_vlan,
                    f"Prefix VLAN mismatch for '{item_id}': expected {g_vlan}, got {m_vlan}",
                )

        elif entity_type == "interfaces":
            g_vlan = _parse_vlan_vid(
                g_rec.get("untagged_vlan")
                if "untagged_vlan" in g_rec
                else g_rec.get("vlan"),
                fallback=None,
            )
            m_vlan = _parse_vlan_vid(
                m_rec.get("untagged_vlan")
                if "untagged_vlan" in m_rec
                else m_rec.get("vlan"),
                fallback=None,
            )
            if g_vlan != m_vlan and (g_vlan is not None or m_vlan is not None):
                _add_mismatch(
                    "vlan",
                    g_vlan,
                    m_vlan,
                    f"Interface untagged VLAN mismatch for '{item_id}': expected {g_vlan}, got {m_vlan}",
                )

        return mismatches

    @staticmethod
    def _is_untracked_resolved_in_bundle(
        disc: DiscrepancyRecord,
        modern_site_bundle: Mapping[str, Sequence[Mapping[str, Any]]],
    ) -> bool:
        all_modern_tokens: set[str] = set()
        for entity_type in ("devices", "virtual_machines", "ip_addresses"):
            for rec in modern_site_bundle.get(entity_type, ()):
                status_lower = str(rec.get("status") or "").strip().lower()
                if status_lower in _STALE_MODERN_STATUSES:
                    continue
                all_modern_tokens.update(_record_candidate_tokens(entity_type, rec))

        candidates: set[str] = set()
        if disc.observed_hostname:
            candidates.add(disc.observed_hostname)
            candidates.add(disc.observed_hostname.lower())
            candidates.add(slugify(disc.observed_hostname))
        if disc.observed_ip:
            clean_ip = _strip_ip_mask(disc.observed_ip)
            if clean_ip:
                candidates.add(clean_ip)
        if disc.observed_identifier:
            candidates.add(disc.observed_identifier)
            candidates.add(disc.observed_identifier.lower())
            candidates.add(slugify(disc.observed_identifier))
            clean_obs_ip = _strip_ip_mask(disc.observed_identifier)
            if clean_obs_ip and clean_obs_ip[0].isdigit():
                candidates.add(clean_obs_ip)

        return bool(candidates & all_modern_tokens)

    def evaluate_site(
        self,
        site_or_golden: Optional[Any] = None,
        modern_bundle: Optional[Any] = None,
        *,
        site_id: Optional[str] = None,
        site: Optional[Site | Mapping[str, Any]] = None,
        golden_bundle: Optional[Mapping[str, Any] | ModernSoTExporter] = None,
        target_bundle: Optional[Any] = None,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        stale_item_ids: Optional[Iterable[str]] = None,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
        unresolved_untracked_discrepancies: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        waived_discrepancy_ids: Optional[Iterable[str]] = None,
        waive_all_parity_discrepancies: Optional[bool] = None,
        merge_untracked: Optional[bool] = None,
        evaluated_at: Optional[datetime | str] = None,
    ) -> SiteMigrationReadinessScorecard:
        """Evaluate dual-run parity and readiness scorecard for a single site."""
        if site_or_golden is not None:
            if isinstance(site_or_golden, str):
                site_id = site_id or site_or_golden
            elif isinstance(site_or_golden, Site) or (
                isinstance(site_or_golden, Mapping)
                and not self._is_bundle_mapping(site_or_golden)
            ):
                site = site if site is not None else site_or_golden
            elif self._is_bundle_mapping(site_or_golden):
                golden_bundle = (
                    golden_bundle if golden_bundle is not None else site_or_golden
                )

        eff_modern_input = (
            modern_bundle
            if modern_bundle is not None
            else (
                target_bundle
                if target_bundle is not None
                else self._modern_bundle
            )
        )
        eff_golden_input = (
            golden_bundle if golden_bundle is not None else self._golden_bundle
        )
        eff_sites_input = (
            site
            if site is not None
            else (sites if sites is not None else self._sites)
        )
        if eff_sites_input is None and isinstance(eff_golden_input, ModernSoTExporter):
            eff_sites_input = eff_golden_input._raw_sites

        eff_val_input = (
            validation_results
            if validation_results is not None
            else self._validation_results
        )
        if eff_val_input is None and isinstance(eff_golden_input, ModernSoTExporter):
            eff_val_input = eff_golden_input._validation_results

        eff_recon_input = (
            reconciliation_report
            if reconciliation_report is not None
            else self._reconciliation_report
        )
        if eff_recon_input is None and isinstance(eff_golden_input, ModernSoTExporter):
            eff_recon_input = eff_golden_input._discrepancies

        norm_sites = _normalize_sites_input(eff_sites_input)
        norm_results = _normalize_validation_results(eff_val_input)
        norm_recon = _normalize_discrepancies(eff_recon_input)
        norm_unresolved_untracked = _normalize_discrepancies(
            unresolved_untracked_discrepancies
            if unresolved_untracked_discrepancies is not None
            else self._unresolved_untracked_discrepancies
        )

        eff_approved: Optional[set[str]] = (
            {str(x).strip() for x in approved_discrepancy_ids if str(x).strip()}
            if approved_discrepancy_ids is not None
            else self._approved_discrepancy_ids
        )
        eff_merge_untracked = (
            bool(merge_untracked)
            if merge_untracked is not None
            else self.merge_untracked
        )

        if eff_golden_input is not None:
            full_golden_bundle = self._coerce_to_bundle(eff_golden_input)
        else:
            full_golden_bundle = self._coerce_to_bundle(
                norm_sites,
                validation_results=norm_results,
                reconciliation_report=norm_recon,
                approved_discrepancy_ids=eff_approved,
                merge_untracked=eff_merge_untracked,
                filter_for_golden=True,
            )

        full_modern_bundle = self._coerce_to_bundle(eff_modern_input)

        # Resolve target site_id and site_name
        resolved_site_id = site_id
        resolved_site_name = ""
        raw_site_obj: Optional[Site] = None

        if resolved_site_id is None:
            if norm_sites:
                resolved_site_id = norm_sites[0].site_id
                resolved_site_name = norm_sites[0].name
                raw_site_obj = norm_sites[0]
            elif full_golden_bundle.get("sites"):
                first_s = full_golden_bundle["sites"][0]
                resolved_site_id = (
                    _extract_legacy_id(first_s)
                    or _clean_optional_str(first_s.get("slug"))
                    or _clean_optional_str(first_s.get("name"))
                    or "site-001"
                )
                resolved_site_name = (
                    _clean_optional_str(first_s.get("name")) or resolved_site_id
                )
            elif full_modern_bundle.get("sites"):
                first_s = full_modern_bundle["sites"][0]
                resolved_site_id = (
                    _extract_legacy_id(first_s)
                    or _clean_optional_str(first_s.get("slug"))
                    or _clean_optional_str(first_s.get("name"))
                    or "site-001"
                )
                resolved_site_name = (
                    _clean_optional_str(first_s.get("name")) or resolved_site_id
                )
            else:
                resolved_site_id = "site-001"

        target_slug = slugify(resolved_site_id)
        for s_obj in norm_sites:
            if s_obj.site_id == resolved_site_id or slugify(s_obj.site_id) == target_slug:
                raw_site_obj = s_obj
                resolved_site_id = s_obj.site_id
                resolved_site_name = s_obj.name
                break

        if not resolved_site_name:
            for s_rec in full_golden_bundle.get("sites", []) + full_modern_bundle.get(
                "sites", []
            ):
                s_leg = _extract_legacy_id(s_rec)
                s_slg = _clean_optional_str(s_rec.get("slug"))
                if s_leg == resolved_site_id or (s_slg and slugify(s_slg) == target_slug):
                    resolved_site_name = (
                        _clean_optional_str(s_rec.get("name")) or resolved_site_id
                    )
                    if s_leg:
                        resolved_site_id = s_leg
                    break
        if not resolved_site_name:
            resolved_site_name = resolved_site_id

        total_known_sites = max(
            len(norm_sites),
            len(full_golden_bundle.get("sites", [])),
            len(full_modern_bundle.get("sites", [])),
        )
        single_site_context = total_known_sites <= 1

        golden_site_bundle = self._filter_bundle_for_site(
            full_golden_bundle,
            resolved_site_id,
            single_site_context=single_site_context,
            raw_site=raw_site_obj,
        )
        modern_site_bundle = self._filter_bundle_for_site(
            full_modern_bundle,
            resolved_site_id,
            single_site_context=single_site_context,
            raw_site=raw_site_obj,
        )

        combined_stale_ids = set(self._stale_item_ids)
        if stale_item_ids is not None:
            combined_stale_ids.update(
                str(x).strip() for x in stale_item_ids if str(x).strip()
            )

        stale_tokens = self._collect_stale_tokens(
            resolved_site_id,
            norm_sites,
            norm_results,
            combined_stale_ids,
            golden_site_bundle,
        )

        # Separate active golden items from any stale items in golden_site_bundle
        active_golden_by_entity: dict[str, list[dict[str, Any]]] = {}
        active_golden_tokens_by_entity: dict[str, set[str]] = {}
        for entity_type in PARITY_ENTITY_COLLECTIONS:
            active_list: list[dict[str, Any]] = []
            entity_tokens: set[str] = set()
            for rec in golden_site_bundle.get(entity_type, ()):
                status_lower = str(rec.get("status") or "").strip().lower()
                rec_tokens = _record_candidate_tokens(entity_type, rec)
                if status_lower in _STALE_MODERN_STATUSES or (rec_tokens & stale_tokens):
                    stale_tokens.update(rec_tokens)
                    continue
                active_list.append(rec)
                entity_tokens.update(rec_tokens)
            active_golden_by_entity[entity_type] = active_list
            active_golden_tokens_by_entity[entity_type] = entity_tokens

        # Build host -> golden IP lookup for device/VM IP comparison
        golden_ip_by_host: dict[str, str] = {}
        for ip_rec in active_golden_by_entity.get("ip_addresses", ()):
            addr = _clean_optional_str(ip_rec.get("address") or ip_rec.get("ip"))
            if not addr:
                continue
            for host_key in ("assigned_object", "dns_name"):
                host_val = _clean_optional_str(ip_rec.get(host_key))
                if host_val:
                    golden_ip_by_host.setdefault(host_val.lower(), addr)

        discrepancies: list[ParityDiscrepancy] = []
        leaked_modern_indices: dict[str, set[int]] = {
            et: set() for et in PARITY_ENTITY_COLLECTIONS
        }

        # 1. Detect STALE_LEAKED_TO_MODERN_SOT
        for entity_type in PARITY_ENTITY_COLLECTIONS:
            for m_idx, m_rec in enumerate(modern_site_bundle.get(entity_type, ())):
                status_lower = str(m_rec.get("status") or "").strip().lower()
                m_tokens = _record_candidate_tokens(entity_type, m_rec)

                if entity_type == "interfaces":
                    # Only flag interfaces as leaked stale if explicitly in stale_item_ids or carrying stale status
                    is_leaked = status_lower in _STALE_MODERN_STATUSES or bool(
                        m_tokens
                        & {t.lower() for t in combined_stale_ids}
                    )
                else:
                    is_active_golden = any(
                        self._records_match_exact(entity_type, g_rec, m_rec)
                        for g_rec in active_golden_by_entity[entity_type]
                    )
                    is_leaked = status_lower in _STALE_MODERN_STATUSES or (
                        bool(m_tokens & stale_tokens) and not is_active_golden
                    )

                if is_leaked:
                    leaked_modern_indices[entity_type].add(m_idx)
                    item_id = _extract_record_identifier(entity_type, m_rec)
                    legacy_id = _extract_legacy_id(m_rec)
                    disc_id = (
                        f"parity-{slugify(resolved_site_id)}-stale-leaked-"
                        f"{slugify(entity_type)}-{slugify(item_id)}"
                    )
                    discrepancies.append(
                        ParityDiscrepancy(
                            discrepancy_id=disc_id,
                            discrepancy_type=ParityDiscrepancyType.STALE_LEAKED_TO_MODERN_SOT,
                            site_id=resolved_site_id,
                            entity_type=entity_type,
                            item_identifier=item_id,
                            expected_value="absent",
                            actual_value=status_lower or "present",
                            details=(
                                f"Stale/quarantined {entity_type} record '{item_id}'"
                                + (f" (legacy_sot_id={legacy_id})" if legacy_id else "")
                                + " leaked into target Modern SoT bundle"
                            ),
                        )
                    )

        # 2. Match active golden items against modern items & detect MISSING_IN_MODERN_SOT and ATTRIBUTE_MISMATCH
        golden_item_discrepancies: dict[tuple[str, int], list[ParityDiscrepancy]] = {}
        for entity_type in PARITY_ENTITY_COLLECTIONS:
            g_list = active_golden_by_entity[entity_type]
            m_list = modern_site_bundle.get(entity_type, [])
            matched_g_to_m: dict[int, int] = {}
            used_m_indices: set[int] = set(leaked_modern_indices[entity_type])

            # Pass 1: exact identity match
            for g_idx, g_rec in enumerate(g_list):
                for m_idx, m_rec in enumerate(m_list):
                    if m_idx in used_m_indices:
                        continue
                    if self._records_match_exact(entity_type, g_rec, m_rec):
                        matched_g_to_m[g_idx] = m_idx
                        used_m_indices.add(m_idx)
                        break

            # Pass 2: fallback natural-attribute match for unmatched items
            for g_idx, g_rec in enumerate(g_list):
                if g_idx in matched_g_to_m:
                    continue
                for m_idx, m_rec in enumerate(m_list):
                    if m_idx in used_m_indices:
                        continue
                    if self._records_match_fallback(entity_type, g_rec, m_rec):
                        matched_g_to_m[g_idx] = m_idx
                        used_m_indices.add(m_idx)
                        break

            for g_idx, g_rec in enumerate(g_list):
                item_discs: list[ParityDiscrepancy] = []
                if g_idx not in matched_g_to_m:
                    item_id = _extract_record_identifier(entity_type, g_rec)
                    legacy_id = _extract_legacy_id(g_rec)
                    disc_id = (
                        f"parity-{slugify(resolved_site_id)}-missing-"
                        f"{slugify(entity_type)}-{slugify(item_id)}"
                    )
                    missing_disc = ParityDiscrepancy(
                        discrepancy_id=disc_id,
                        discrepancy_type=ParityDiscrepancyType.MISSING_IN_MODERN_SOT,
                        site_id=resolved_site_id,
                        entity_type=entity_type,
                        item_identifier=item_id,
                        expected_value=item_id,
                        actual_value=None,
                        details=(
                            f"Active golden {entity_type} record '{item_id}'"
                            + (f" (legacy_sot_id={legacy_id})" if legacy_id else "")
                            + " is missing from target Modern SoT bundle"
                        ),
                    )
                    item_discs.append(missing_disc)
                    discrepancies.append(missing_disc)
                else:
                    m_rec = m_list[matched_g_to_m[g_idx]]
                    attr_mismatches = self._compare_matched_records(
                        resolved_site_id,
                        entity_type,
                        g_rec,
                        m_rec,
                        golden_ip_by_host=golden_ip_by_host,
                    )
                    item_discs.extend(attr_mismatches)
                    discrepancies.extend(attr_mismatches)

                golden_item_discrepancies[(entity_type, g_idx)] = item_discs

        # 3. Apply waivers to discrepancies
        eff_waive_all = (
            bool(waive_all_parity_discrepancies)
            if waive_all_parity_discrepancies is not None
            else self.waive_all_parity_discrepancies
        )
        combined_waived_raw = set(self._waived_discrepancy_ids)
        if waived_discrepancy_ids is not None:
            combined_waived_raw.update(
                str(x).strip() for x in waived_discrepancy_ids if str(x).strip()
            )
        waived_tokens = self._expand_waived_tokens(combined_waived_raw)

        # Build lookup from item_identifier to record tokens for waiver matching
        record_tokens_by_item: dict[tuple[str, str], set[str]] = {}
        for entity_type in PARITY_ENTITY_COLLECTIONS:
            for rec in active_golden_by_entity[entity_type] + modern_site_bundle.get(
                entity_type, []
            ):
                iid = _extract_record_identifier(entity_type, rec)
                record_tokens_by_item.setdefault((entity_type, iid), set()).update(
                    _record_candidate_tokens(entity_type, rec)
                )

        for disc in discrepancies:
            if eff_waive_all:
                disc.waived = True
                continue
            candidate_waiver_keys = {
                disc.discrepancy_id,
                disc.discrepancy_id.lower(),
                disc.item_identifier,
                disc.item_identifier.lower(),
                slugify(disc.item_identifier),
                _strip_ip_mask(disc.item_identifier),
                f"{disc.entity_type}:{disc.item_identifier}",
                f"{disc.entity_type}:{disc.item_identifier}".lower(),
            }
            candidate_waiver_keys.update(
                record_tokens_by_item.get((disc.entity_type, disc.item_identifier), set())
            )
            if candidate_waiver_keys & waived_tokens:
                disc.waived = True

        # 4. Compute validation classification counts for this site
        site_val_results = [
            r
            for r in norm_results
            if r.site_id in (resolved_site_id, target_slug, "unknown", "*")
        ]
        confirmed_active_count = sum(
            1
            for r in site_val_results
            if r.classification is ValidationClassification.CONFIRMED_ACTIVE
        )
        stale_count = sum(
            1
            for r in site_val_results
            if r.classification is ValidationClassification.STALE_LIKELY_UNUSED
        )
        unreachable_count = sum(
            1
            for r in site_val_results
            if r.classification is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
        )
        insufficient_data_count = sum(
            1
            for r in site_val_results
            if r.classification is ValidationClassification.INSUFFICIENT_DATA
        )

        if not site_val_results:
            confirmed_active_count = (
                len(active_golden_by_entity["devices"])
                + len(active_golden_by_entity["virtual_machines"])
                + len(active_golden_by_entity["ip_addresses"])
            )

        # 5. Compute unresolved untracked Shadow IT count for this site
        unresolved_untracked_ids: set[str] = set()
        for u_disc in norm_unresolved_untracked:
            if (
                u_disc.site_id not in (resolved_site_id, target_slug)
                and not single_site_context
            ):
                continue
            if u_disc.discrepancy_type not in _UNTRACKED_DISCREPANCY_TYPES:
                continue
            u_tokens = {
                u_disc.discrepancy_id,
                u_disc.discrepancy_id.lower(),
                u_disc.observed_identifier,
                u_disc.observed_identifier.lower(),
            }
            if u_disc.observed_ip:
                u_tokens.add(_strip_ip_mask(u_disc.observed_ip))
            if u_disc.observed_hostname:
                u_tokens.add(u_disc.observed_hostname.lower())
            if eff_waive_all or (u_tokens & waived_tokens):
                continue
            unresolved_untracked_ids.add(u_disc.discrepancy_id)

        for r_disc in norm_recon:
            if (
                r_disc.site_id not in (resolved_site_id, target_slug)
                and not single_site_context
            ):
                continue
            if r_disc.discrepancy_type not in _UNTRACKED_DISCREPANCY_TYPES:
                continue
            r_tokens = {
                r_disc.discrepancy_id,
                r_disc.discrepancy_id.lower(),
                r_disc.observed_identifier,
                r_disc.observed_identifier.lower(),
            }
            if r_disc.observed_ip:
                r_tokens.add(_strip_ip_mask(r_disc.observed_ip))
            if r_disc.observed_hostname:
                r_tokens.add(r_disc.observed_hostname.lower())

            if eff_waive_all or (r_tokens & waived_tokens):
                continue
            if eff_approved is not None and (r_tokens & eff_approved):
                if self._is_untracked_resolved_in_bundle(r_disc, modern_site_bundle):
                    continue
            if not self._is_untracked_resolved_in_bundle(r_disc, modern_site_bundle):
                unresolved_untracked_ids.add(r_disc.discrepancy_id)

        unresolved_untracked_count = len(unresolved_untracked_ids)

        # 6. Compute parity_match_percentage, readiness_score, and CutoverRecommendation
        expected_golden_items = sum(
            len(active_golden_by_entity[et]) for et in PARITY_ENTITY_COLLECTIONS
        )
        unwaived_missing_or_mismatched = sum(
            1
            for item_discs in golden_item_discrepancies.values()
            if any(not d.waived for d in item_discs)
        )
        unwaived_leaked = sum(
            1
            for d in discrepancies
            if not d.waived
            and d.discrepancy_type
            is ParityDiscrepancyType.STALE_LEAKED_TO_MODERN_SOT
        )
        unwaived_missing = sum(
            1
            for d in discrepancies
            if not d.waived
            and d.discrepancy_type is ParityDiscrepancyType.MISSING_IN_MODERN_SOT
        )
        unwaived_mismatched = sum(
            1
            for d in discrepancies
            if not d.waived
            and d.discrepancy_type is ParityDiscrepancyType.ATTRIBUTE_MISMATCH
        )
        waived_discrepancy_count = sum(1 for d in discrepancies if d.waived)

        matched_modern_items = max(
            0, expected_golden_items - unwaived_missing_or_mismatched
        )

        if expected_golden_items > 0:
            parity_match_percentage = _clamp_percentage(
                ((matched_modern_items - unwaived_leaked) / expected_golden_items)
                * 100.0
            )
        else:
            parity_match_percentage = 100.0 if unwaived_leaked == 0 else 0.0

        non_stale_validated = (
            confirmed_active_count + unreachable_count + insufficient_data_count
        )
        validation_ratio = (
            confirmed_active_count / non_stale_validated
            if non_stale_validated > 0
            else 1.0
        )
        validation_penalty = max(
            (1.0 - validation_ratio) * 40.0,
            5.0 * (unreachable_count + insufficient_data_count),
        )
        untracked_penalty = 5.0 * unresolved_untracked_count
        leaked_penalty = 15.0 * unwaived_leaked

        if expected_golden_items > 0 and matched_modern_items == 0:
            raw_readiness = 0.0
        else:
            raw_readiness = (
                parity_match_percentage
                - validation_penalty
                - untracked_penalty
                - leaked_penalty
            )
        readiness_score = _clamp_percentage(raw_readiness)

        blocking_reasons: list[str] = []
        if unwaived_leaked > 0:
            blocking_reasons.append(
                f"{unwaived_leaked} stale/quarantined item(s) leaked into Modern SoT"
            )
        if unwaived_missing > 0:
            blocking_reasons.append(
                f"{unwaived_missing} active golden item(s) missing in Modern SoT"
            )
        if unwaived_mismatched > 0:
            blocking_reasons.append(
                f"{unwaived_mismatched} attribute mismatch discrepancy(ies) detected"
            )
        if unreachable_count > 0:
            blocking_reasons.append(
                f"{unreachable_count} item(s) classified as Unreachable / Needs Manual Review"
            )
        if insufficient_data_count > 0:
            blocking_reasons.append(
                f"{insufficient_data_count} item(s) classified as Insufficient Data"
            )
        if unresolved_untracked_count > 0:
            blocking_reasons.append(
                f"{unresolved_untracked_count} unresolved untracked Shadow IT asset(s)"
            )
        if expected_golden_items > 0 and matched_modern_items == 0:
            blocking_reasons.append(
                "Zero golden inventory items matched in Modern SoT"
            )

        if (
            unwaived_leaked > 0
            or parity_match_percentage < self.blocked_parity_threshold
            or readiness_score < self.blocked_score_threshold
            or (expected_golden_items > 0 and matched_modern_items == 0)
        ):
            recommendation = CutoverRecommendation.BLOCKED
        elif (
            parity_match_percentage == 100.0
            and len([d for d in discrepancies if not d.waived]) == 0
            and unreachable_count == 0
            and insufficient_data_count == 0
            and unresolved_untracked_count == 0
            and readiness_score >= self.ready_score_threshold
        ):
            recommendation = CutoverRecommendation.READY_FOR_CUTOVER
            blocking_reasons = []
        else:
            recommendation = CutoverRecommendation.NEEDS_REMEDIATION

        resolved_ts = _resolve_timestamp(
            evaluated_at if evaluated_at is not None else self._evaluated_at
        )

        return SiteMigrationReadinessScorecard(
            site_id=resolved_site_id,
            site_name=resolved_site_name,
            readiness_score=readiness_score,
            recommendation=recommendation,
            parity_match_percentage=parity_match_percentage,
            confirmed_active_count=confirmed_active_count,
            stale_count=stale_count,
            unreachable_count=unreachable_count,
            insufficient_data_count=insufficient_data_count,
            unresolved_untracked_count=unresolved_untracked_count,
            expected_golden_items=expected_golden_items,
            matched_modern_items=matched_modern_items,
            discrepancies=discrepancies,
            waived_discrepancy_count=waived_discrepancy_count,
            blocking_reasons=blocking_reasons,
            evaluated_at=resolved_ts,
        )

    def evaluate_sites(
        self,
        golden_or_sites: Optional[Any] = None,
        modern_bundle: Optional[Any] = None,
        *,
        golden_bundle: Optional[Mapping[str, Any] | ModernSoTExporter] = None,
        target_bundle: Optional[Any] = None,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        stale_item_ids: Optional[Iterable[str]] = None,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
        unresolved_untracked_discrepancies: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        waived_discrepancy_ids: Optional[Iterable[str]] = None,
        waive_all_parity_discrepancies: Optional[bool] = None,
        merge_untracked: Optional[bool] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> MigrationParityReport:
        """Evaluate dual-run parity across all sites and return a MigrationParityReport."""
        if golden_or_sites is not None:
            if self._is_bundle_mapping(golden_or_sites):
                golden_bundle = (
                    golden_bundle if golden_bundle is not None else golden_or_sites
                )
            else:
                sites = sites if sites is not None else golden_or_sites

        eff_golden = (
            golden_bundle if golden_bundle is not None else self._golden_bundle
        )
        eff_modern = (
            modern_bundle
            if modern_bundle is not None
            else (
                target_bundle
                if target_bundle is not None
                else self._modern_bundle
            )
        )
        eff_sites = sites if sites is not None else self._sites
        if eff_sites is None and isinstance(eff_golden, ModernSoTExporter):
            eff_sites = eff_golden._raw_sites

        norm_sites = _normalize_sites_input(eff_sites)
        site_ids_ordered: list[str] = []
        seen_slugs: set[str] = set()

        for s_obj in sorted(norm_sites, key=lambda s: slugify(s.site_id)):
            s_slug = slugify(s_obj.site_id)
            if s_slug not in seen_slugs:
                seen_slugs.add(s_slug)
                site_ids_ordered.append(s_obj.site_id)

        if not site_ids_ordered and eff_golden is not None:
            coerced_golden = self._coerce_to_bundle(eff_golden)
            for s_rec in coerced_golden.get("sites", ()):
                sid = (
                    _extract_legacy_id(s_rec)
                    or _clean_optional_str(s_rec.get("slug"))
                    or _clean_optional_str(s_rec.get("name"))
                )
                if sid:
                    s_slug = slugify(sid)
                    if s_slug not in seen_slugs:
                        seen_slugs.add(s_slug)
                        site_ids_ordered.append(sid)

        if not site_ids_ordered and eff_modern is not None:
            coerced_modern = self._coerce_to_bundle(eff_modern)
            for s_rec in coerced_modern.get("sites", ()):
                sid = (
                    _extract_legacy_id(s_rec)
                    or _clean_optional_str(s_rec.get("slug"))
                    or _clean_optional_str(s_rec.get("name"))
                )
                if sid:
                    s_slug = slugify(sid)
                    if s_slug not in seen_slugs:
                        seen_slugs.add(s_slug)
                        site_ids_ordered.append(sid)

        resolved_ts = _resolve_timestamp(
            generated_at if generated_at is not None else self._evaluated_at
        )

        scorecards = [
            self.evaluate_site(
                site_id=sid,
                golden_bundle=eff_golden,
                modern_bundle=eff_modern,
                sites=eff_sites,
                validation_results=validation_results,
                reconciliation_report=reconciliation_report,
                stale_item_ids=stale_item_ids,
                approved_discrepancy_ids=approved_discrepancy_ids,
                unresolved_untracked_discrepancies=unresolved_untracked_discrepancies,
                waived_discrepancy_ids=waived_discrepancy_ids,
                waive_all_parity_discrepancies=waive_all_parity_discrepancies,
                merge_untracked=merge_untracked,
                evaluated_at=resolved_ts,
            )
            for sid in site_ids_ordered
        ]

        return MigrationParityReport(
            scorecards=scorecards,
            generated_at=resolved_ts,
        )

    def evaluate(
        self,
        golden_or_sites: Optional[Any] = None,
        modern_bundle: Optional[Any] = None,
        **kwargs: Any,
    ) -> MigrationParityReport:
        """Alias for evaluate_sites returning a MigrationParityReport."""
        return self.evaluate_sites(golden_or_sites, modern_bundle, **kwargs)

    def check_parity(
        self,
        golden_or_sites: Optional[Any] = None,
        modern_bundle: Optional[Any] = None,
        **kwargs: Any,
    ) -> MigrationParityReport:
        """Alias for evaluate_sites returning a MigrationParityReport."""
        return self.evaluate_sites(golden_or_sites, modern_bundle, **kwargs)
