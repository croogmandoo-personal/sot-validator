"""Fleet-wide site health scorecard, trend, and Markdown / self-contained HTML report.

Each site gets a health score from 0 to 100 built from up to five dimensions, in
``FLEET_DIMENSIONS`` order: ``records``, ``quality``, ``certificates``, ``firmware``
and ``drift``. A dimension is *present* for a site when the caller supplied its
input (even with zero findings) and *missing* otherwise.

Default weights and penalties (``FleetScoreWeights``)::

    records=0.40  quality=0.20  certificates=0.15  firmware=0.15  drift=0.10
    stale_penalty=1.0  unreachable_penalty=0.5  insufficient_penalty=0.25
    quality_error_penalty=1.0  quality_warning_penalty=0.25
    cert_error_points=25.0  cert_warning_points=10.0  cert_info_points=2.0
    drift_penalty=1.0

Let ``N`` be the sum of the four record counts when ``records`` is present. The
denominator ``D`` is ``N``, or 1 when ``records`` is missing or ``N == 0``.

Sub-scores of the present dimensions:

* records: ``100 * (1 - (stale*stale_penalty + unreachable*unreachable_penalty
  + insufficient*insufficient_penalty) / max(N, 1))``; 100 when ``N == 0``.
  ``Confirmed Active`` records carry no penalty.
* quality: ``100 * (1 - (errors*quality_error_penalty
  + warnings*quality_warning_penalty) / D)``. ``info`` findings are ignored.
* certificates: ``100 - (error*cert_error_points + warning*cert_warning_points
  + info*cert_info_points)``. These are absolute points per finding because
  certificate findings only exist for problem endpoints (no endpoint count).
* firmware: ``100 * (1 - noncompliant / devices)``; 100 when ``devices == 0``.
  Every status other than ``compliant`` (including ``unknown_platform`` and
  ``unparsed``) is non-compliant.
* drift: ``100 * (1 - drift_events*drift_penalty / D)``. Every ``DriftEvent``
  counts, whatever its ``transition_type``.

Each sub-score is clamped to [0, 100]. ``dimension_scores`` stores each clamped
sub-score rounded with ``round(x, 1)``; the health score uses the clamped,
unrounded sub-scores::

    health_score = round(clamp(sum(w_d * sub_d) / sum(w_d), 0, 100), 1)

where both sums run over the present dimensions only, so the weights of missing
dimensions drop out and the remaining weights are renormalised. A present
dimension with zero findings scores 100; a missing dimension is left out, never
counted as 0. When no dimension is present, or the present weights add up to 0,
``health_score`` is ``None`` ("no data").

Worked example: records 8 active / 2 stale (80), 1 quality error over D=10 (90),
1 certificate error (75), 1 of 4 firmware devices non-compliant (75) and 1 drift
event over D=10 (90) give ``0.4*80 + 0.2*90 + 0.15*75 + 0.15*75 + 0.1*90 = 81.5``.

Trend: the previous score is supplied by the caller (the history ledger stores no
per-site scores). With ``delta = round(health_score - previous_score, 1)``:

* ``new`` when ``previous_score`` or ``health_score`` is ``None``;
* ``stable`` when ``abs(delta) <= TREND_STABLE_THRESHOLD`` (5.0);
* ``improving`` when ``delta > 5``;
* ``degrading`` when ``delta < -5``.

Drift events come from ``HistoryStore.detect_drift`` (read-only, passed in by the
caller); nothing is read from or written to the ledger here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime
import html
import math
from typing import TYPE_CHECKING, Any, Optional

from sot_validator.models import ValidationClassification
from sot_validator.reporting.generators import _escape_md_cell

if TYPE_CHECKING:
    from sot_validator.history.ledger import DriftEvent
    from sot_validator.lifecycle.certificates import CertificateFinding
    from sot_validator.lifecycle.firmware import FirmwareFinding
    from sot_validator.models import ValidationResult
    from sot_validator.quality.checks import QualityFinding

FLEET_DIMENSIONS: tuple[str, ...] = (
    "records",
    "quality",
    "certificates",
    "firmware",
    "drift",
)

TREND_IMPROVING = "improving"
TREND_STABLE = "stable"
TREND_DEGRADING = "degrading"
TREND_NEW = "new"
TREND_VALUES: tuple[str, ...] = (
    TREND_IMPROVING,
    TREND_STABLE,
    TREND_DEGRADING,
    TREND_NEW,
)
TREND_STABLE_THRESHOLD = 5.0

CERT_SEVERITIES: tuple[str, ...] = ("error", "warning", "info")
# Equals sot_validator.lifecycle.firmware.STATUS_COMPLIANT (not imported: import cycle).
_FIRMWARE_COMPLIANT = "compliant"

_RECORD_KEYS: tuple[str, ...] = tuple(c.value for c in ValidationClassification)
_STALE = ValidationClassification.STALE_LIKELY_UNUSED.value
_UNREACHABLE = ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value
_INSUFFICIENT = ValidationClassification.INSUFFICIENT_DATA.value

NO_DATA = "no data"
DEFAULT_FLEET_TITLE = "Fleet Site Health Scorecard"
TOP_N = 10


def _require_count(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
    return value


def _require_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number, got {value!r}")
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"{name} must be finite, got {value!r}")
    return value


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


@dataclass
class FleetScoreWeights:
    """Dimension weights and per-dimension penalties for the fleet health score."""

    records: float = 0.40
    quality: float = 0.20
    certificates: float = 0.15
    firmware: float = 0.15
    drift: float = 0.10
    stale_penalty: float = 1.0
    unreachable_penalty: float = 0.5
    insufficient_penalty: float = 0.25
    quality_error_penalty: float = 1.0
    quality_warning_penalty: float = 0.25
    cert_error_points: float = 25.0
    cert_warning_points: float = 10.0
    cert_info_points: float = 2.0
    drift_penalty: float = 1.0

    def __post_init__(self) -> None:
        for f in fields(self):
            value = _require_number(getattr(self, f.name), f.name)
            if value < 0:
                raise ValueError(f"{f.name} must not be negative, got {value!r}")
        if all(getattr(self, dim) == 0 for dim in FLEET_DIMENSIONS):
            raise ValueError("at least one dimension weight must be greater than 0")

    def weight(self, dimension: str) -> float:
        return getattr(self, dimension)


@dataclass
class SiteScorecard:
    """Health score, per-dimension counts and trend for one site."""

    site_id: str
    record_counts: dict[str, int] = field(
        default_factory=lambda: {key: 0 for key in _RECORD_KEYS}
    )
    quality_errors: int = 0
    quality_warnings: int = 0
    cert_findings: dict[str, int] = field(
        default_factory=lambda: {key: 0 for key in CERT_SEVERITIES}
    )
    firmware_noncompliant: int = 0
    firmware_devices: int = 0
    drift_events: int = 0
    inputs_present: list[str] = field(default_factory=list)
    dimension_scores: dict[str, float] = field(default_factory=dict)
    health_score: Optional[float] = None
    previous_score: Optional[float] = None
    trend: str = TREND_NEW

    def has(self, dimension: str) -> bool:
        return dimension in self.inputs_present

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "record_counts": dict(self.record_counts),
            "quality_errors": self.quality_errors,
            "quality_warnings": self.quality_warnings,
            "cert_findings": dict(self.cert_findings),
            "firmware_noncompliant": self.firmware_noncompliant,
            "firmware_devices": self.firmware_devices,
            "drift_events": self.drift_events,
            "inputs_present": list(self.inputs_present),
            "dimension_scores": dict(self.dimension_scores),
            "health_score": self.health_score,
            "previous_score": self.previous_score,
            "trend": self.trend,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SiteScorecard:
        trend = data.get("trend", TREND_NEW)
        if trend not in TREND_VALUES:
            raise ValueError(f"trend must be one of {TREND_VALUES}, got {trend!r}")
        health = data.get("health_score")
        if health is not None:
            _require_number(health, "health_score")
            if not 0 <= health <= 100:
                raise ValueError(f"health_score must be between 0 and 100, got {health!r}")
        record_counts = {key: 0 for key in _RECORD_KEYS}
        record_counts.update(data.get("record_counts") or {})
        cert_findings = {key: 0 for key in CERT_SEVERITIES}
        cert_findings.update(data.get("cert_findings") or {})
        return cls(
            site_id=data["site_id"],
            record_counts=record_counts,
            quality_errors=data.get("quality_errors", 0),
            quality_warnings=data.get("quality_warnings", 0),
            cert_findings=cert_findings,
            firmware_noncompliant=data.get("firmware_noncompliant", 0),
            firmware_devices=data.get("firmware_devices", 0),
            drift_events=data.get("drift_events", 0),
            inputs_present=list(data.get("inputs_present") or []),
            dimension_scores=dict(data.get("dimension_scores") or {}),
            health_score=health,
            previous_score=data.get("previous_score"),
            trend=trend,
        )


def _trend(health_score: Optional[float], previous_score: Optional[float]) -> str:
    if health_score is None or previous_score is None:
        return TREND_NEW
    delta = round(health_score - previous_score, 1)
    if abs(delta) <= TREND_STABLE_THRESHOLD:
        return TREND_STABLE
    return TREND_IMPROVING if delta > 0 else TREND_DEGRADING


class FleetScorer:
    """Score sites from plain counts (`score_site`) or typed findings (`score_fleet`)."""

    def __init__(self, weights: Optional[FleetScoreWeights] = None) -> None:
        self.weights = weights if weights is not None else FleetScoreWeights()

    def score_site(
        self,
        site_id: str,
        *,
        record_counts: Optional[Mapping[Any, int]] = None,
        quality_errors: Optional[int] = None,
        quality_warnings: Optional[int] = None,
        cert_findings: Optional[Mapping[str, int]] = None,
        firmware_devices: Optional[int] = None,
        firmware_noncompliant: Optional[int] = None,
        drift_events: Optional[int] = None,
        previous_score: Optional[float] = None,
    ) -> SiteScorecard:
        if not isinstance(site_id, str) or not site_id:
            raise ValueError(f"site_id must be a non-empty string, got {site_id!r}")
        if previous_score is not None:
            _require_number(previous_score, "previous_score")
        w = self.weights
        card = SiteScorecard(site_id=site_id, previous_score=previous_score)
        present: list[str] = []
        subs: dict[str, float] = {}

        total_records = 0
        if record_counts is not None:
            if not isinstance(record_counts, Mapping):
                raise ValueError("record_counts must be a mapping")
            for key, value in record_counts.items():
                try:
                    cls_value = ValidationClassification(key).value
                except ValueError as exc:
                    raise ValueError(f"unknown record classification: {key!r}") from exc
                card.record_counts[cls_value] += _require_count(
                    value, f"record_counts[{cls_value!r}]"
                )
            total_records = sum(card.record_counts.values())
            if total_records == 0:
                subs["records"] = 100.0
            else:
                penalty = (
                    card.record_counts[_STALE] * w.stale_penalty
                    + card.record_counts[_UNREACHABLE] * w.unreachable_penalty
                    + card.record_counts[_INSUFFICIENT] * w.insufficient_penalty
                )
                subs["records"] = 100.0 * (1 - penalty / total_records)
            present.append("records")
        denominator = total_records if total_records > 0 else 1

        if quality_errors is not None or quality_warnings is not None:
            card.quality_errors = _require_count(
                0 if quality_errors is None else quality_errors, "quality_errors"
            )
            card.quality_warnings = _require_count(
                0 if quality_warnings is None else quality_warnings, "quality_warnings"
            )
            penalty = (
                card.quality_errors * w.quality_error_penalty
                + card.quality_warnings * w.quality_warning_penalty
            )
            subs["quality"] = 100.0 * (1 - penalty / denominator)
            present.append("quality")

        if cert_findings is not None:
            if not isinstance(cert_findings, Mapping):
                raise ValueError("cert_findings must be a mapping")
            for key, value in cert_findings.items():
                if key not in CERT_SEVERITIES:
                    raise ValueError(f"unknown certificate severity: {key!r}")
                card.cert_findings[key] += _require_count(value, f"cert_findings[{key!r}]")
            subs["certificates"] = 100.0 - (
                card.cert_findings["error"] * w.cert_error_points
                + card.cert_findings["warning"] * w.cert_warning_points
                + card.cert_findings["info"] * w.cert_info_points
            )
            present.append("certificates")

        if (firmware_devices is None) != (firmware_noncompliant is None):
            raise ValueError(
                "firmware_devices and firmware_noncompliant must be given together"
            )
        if firmware_devices is not None:
            card.firmware_devices = _require_count(firmware_devices, "firmware_devices")
            card.firmware_noncompliant = _require_count(
                firmware_noncompliant, "firmware_noncompliant"
            )
            if card.firmware_noncompliant > card.firmware_devices:
                raise ValueError("firmware_noncompliant must not exceed firmware_devices")
            if card.firmware_devices == 0:
                subs["firmware"] = 100.0
            else:
                subs["firmware"] = 100.0 * (
                    1 - card.firmware_noncompliant / card.firmware_devices
                )
            present.append("firmware")

        if drift_events is not None:
            card.drift_events = _require_count(drift_events, "drift_events")
            subs["drift"] = 100.0 * (1 - card.drift_events * w.drift_penalty / denominator)
            present.append("drift")

        subs = {dim: _clamp(value) for dim, value in subs.items()}
        card.inputs_present = present
        card.dimension_scores = {dim: round(subs[dim], 1) for dim in present}
        weight_total = sum(w.weight(dim) for dim in present)
        if present and weight_total > 0:
            weighted = sum(w.weight(dim) * subs[dim] for dim in present)
            card.health_score = round(_clamp(weighted / weight_total), 1)
        card.trend = _trend(card.health_score, previous_score)
        return card

    def score_fleet(
        self,
        *,
        results: Optional[Iterable[ValidationResult]] = None,
        quality_findings: Optional[Iterable[QualityFinding]] = None,
        certificate_findings: Optional[Iterable[CertificateFinding]] = None,
        firmware_findings: Optional[Iterable[FirmwareFinding]] = None,
        drift_events: Optional[Iterable[DriftEvent]] = None,
        previous: Optional[Mapping[str, Optional[float]] | Iterable[SiteScorecard]] = None,
        site_ids: Optional[Iterable[str]] = None,
    ) -> list[SiteScorecard]:
        """Score every site seen in `site_ids` or any finding input (not `previous`)."""
        sites: set[str] = set(site_ids or ())
        records: dict[str, dict[str, int]] = {}
        quality: dict[str, list[int]] = {}
        certs: dict[str, dict[str, int]] = {}
        firmware: dict[str, list[int]] = {}
        drift: dict[str, int] = {}

        if results is not None:
            for result in results:
                counts = records.setdefault(result.site_id, {})
                key = ValidationClassification(result.classification).value
                counts[key] = counts.get(key, 0) + 1
        if quality_findings is not None:
            for finding in quality_findings:
                pair = quality.setdefault(finding.site_id, [0, 0])
                if finding.severity == "error":
                    pair[0] += 1
                elif finding.severity == "warning":
                    pair[1] += 1
        if certificate_findings is not None:
            for finding in certificate_findings:
                counts = certs.setdefault(finding.site_id, {})
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        if firmware_findings is not None:
            for finding in firmware_findings:
                pair = firmware.setdefault(finding.site_id, [0, 0])
                pair[0] += 1
                if finding.status != _FIRMWARE_COMPLIANT:
                    pair[1] += 1
        if drift_events is not None:
            for event in drift_events:
                drift[event.site_id] = drift.get(event.site_id, 0) + 1

        for mapping in (records, quality, certs, firmware, drift):
            sites.update(mapping)

        previous_scores: dict[str, Optional[float]] = {}
        if isinstance(previous, Mapping):
            previous_scores = dict(previous)
        elif previous is not None:
            for prev_card in previous:
                previous_scores[prev_card.site_id] = prev_card.health_score

        cards: list[SiteScorecard] = []
        for site_id in sorted(sites):
            quality_pair = quality.get(site_id, [0, 0]) if quality_findings is not None else None
            firmware_pair = (
                firmware.get(site_id, [0, 0]) if firmware_findings is not None else None
            )
            cards.append(
                self.score_site(
                    site_id,
                    record_counts=records.get(site_id, {}) if results is not None else None,
                    quality_errors=quality_pair[0] if quality_pair is not None else None,
                    quality_warnings=quality_pair[1] if quality_pair is not None else None,
                    cert_findings=(
                        certs.get(site_id, {}) if certificate_findings is not None else None
                    ),
                    firmware_devices=firmware_pair[0] if firmware_pair is not None else None,
                    firmware_noncompliant=(
                        firmware_pair[1] if firmware_pair is not None else None
                    ),
                    drift_events=drift.get(site_id, 0) if drift_events is not None else None,
                    previous_score=previous_scores.get(site_id),
                )
            )
        return cards


# ---------------------------------------------------------------------------
# Shared report model
# ---------------------------------------------------------------------------


def _card_sort_key(card: SiteScorecard) -> tuple[Any, ...]:
    score = card.health_score
    return (
        score is None,
        score if score is not None else 0.0,
        card.site_id,
        repr(card.to_dict()),
    )


def _ordered(scorecards: Iterable[SiteScorecard]) -> list[SiteScorecard]:
    return sorted(scorecards, key=_card_sort_key)


def _fmt_score(value: Optional[float]) -> str:
    return NO_DATA if value is None else f"{float(value):.1f}"


def _fmt_timestamp(generated_at: Optional[datetime | str]) -> Optional[str]:
    if generated_at is None:
        return None
    if isinstance(generated_at, datetime):
        return generated_at.isoformat()
    return str(generated_at)


def _cert_text(card: SiteScorecard) -> str:
    if not card.has("certificates"):
        return NO_DATA
    c = card.cert_findings
    return f"{c['error']}/{c['warning']}/{c['info']}"


def _firmware_text(card: SiteScorecard) -> str:
    if not card.has("firmware"):
        return NO_DATA
    return f"{card.firmware_noncompliant}/{card.firmware_devices}"


def _count_text(card: SiteScorecard, dimension: str, value: int) -> str:
    return str(value) if card.has(dimension) else NO_DATA


def _table_cells(card: SiteScorecard) -> list[tuple[str, str]]:
    """Return (display text, sort value) for each site-table column after Site."""
    def _score_sort(value: Optional[float]) -> str:
        return "" if value is None else repr(float(value))

    cells: list[tuple[str, str]] = [
        (_fmt_score(card.health_score), _score_sort(card.health_score)),
        (_fmt_score(card.previous_score), _score_sort(card.previous_score)),
        (card.trend, card.trend),
    ]
    stale = card.record_counts[_STALE]
    cells.append((_count_text(card, "records", stale), str(stale) if card.has("records") else ""))
    cells.append(
        (
            _count_text(card, "quality", card.quality_errors),
            str(card.quality_errors) if card.has("quality") else "",
        )
    )
    c = card.cert_findings
    cells.append(
        (_cert_text(card), f"{c['error']} {c['warning']} {c['info']}" if card.has("certificates") else "")
    )
    cells.append(
        (
            _firmware_text(card),
            f"{card.firmware_noncompliant} {card.firmware_devices}" if card.has("firmware") else "",
        )
    )
    cells.append(
        (_count_text(card, "drift", card.drift_events), str(card.drift_events) if card.has("drift") else "")
    )
    return cells


TABLE_HEADERS: tuple[str, ...] = (
    "Site",
    "Health score",
    "Previous",
    "Trend",
    "Stale",
    "Quality errors",
    "Certificate findings (error/warning/info)",
    "Firmware non-compliant",
    "Drift",
)

# (title, dimension) for the top-10 risk lists, in FLEET_DIMENSIONS order.
_TOP_LISTS: tuple[tuple[str, str], ...] = (
    ("Stale records", "records"),
    ("Quality errors", "quality"),
    ("Certificate findings", "certificates"),
    ("Firmware non-compliance", "firmware"),
    ("Drift", "drift"),
)


def _top_metric(card: SiteScorecard, dimension: str) -> tuple[int, ...]:
    if dimension == "records":
        return (card.record_counts[_STALE],)
    if dimension == "quality":
        return (card.quality_errors,)
    if dimension == "certificates":
        c = card.cert_findings
        return (c["error"], c["warning"], c["info"])
    if dimension == "firmware":
        return (card.firmware_noncompliant,)
    return (card.drift_events,)


def _top_display(card: SiteScorecard, dimension: str) -> str:
    if dimension == "certificates":
        return _cert_text(card)
    if dimension == "firmware":
        return _firmware_text(card)
    return str(_top_metric(card, dimension)[0])


def _top_list(cards: list[SiteScorecard], dimension: str) -> list[SiteScorecard]:
    eligible = [
        card for card in cards if card.has(dimension) and any(_top_metric(card, dimension))
    ]
    eligible.sort(
        key=lambda card: (
            tuple(-v for v in _top_metric(card, dimension)),
            card.site_id,
            repr(card.to_dict()),
        )
    )
    return eligible[:TOP_N]


def _fleet_totals(cards: list[SiteScorecard]) -> list[tuple[str, str]]:
    """Return ordered (label, value) pairs for the fleet totals header."""
    scored = [card.health_score for card in cards if card.health_score is not None]
    mean = round(sum(scored) / len(scored), 1) if scored else None
    totals: list[tuple[str, str]] = [
        ("Sites", str(len(cards))),
        ("Sites with a score", str(len(scored))),
        ("Mean health score", _fmt_score(mean)),
    ]
    for trend in TREND_VALUES:
        totals.append(
            (f"Trend: {trend}", str(sum(1 for card in cards if card.trend == trend)))
        )

    def _present(dimension: str) -> list[SiteScorecard]:
        return [card for card in cards if card.has(dimension)]

    record_cards = _present("records")
    for key in _RECORD_KEYS:
        totals.append(
            (
                f"Records: {key}",
                str(sum(c.record_counts[key] for c in record_cards)) if record_cards else NO_DATA,
            )
        )
    quality_cards = _present("quality")
    totals.append(
        ("Quality errors", str(sum(c.quality_errors for c in quality_cards)) if quality_cards else NO_DATA)
    )
    totals.append(
        (
            "Quality warnings",
            str(sum(c.quality_warnings for c in quality_cards)) if quality_cards else NO_DATA,
        )
    )
    cert_cards = _present("certificates")
    for severity in CERT_SEVERITIES:
        totals.append(
            (
                f"Certificate findings: {severity}",
                str(sum(c.cert_findings[severity] for c in cert_cards)) if cert_cards else NO_DATA,
            )
        )
    firmware_cards = _present("firmware")
    totals.append(
        (
            "Firmware non-compliant / devices",
            (
                f"{sum(c.firmware_noncompliant for c in firmware_cards)}"
                f"/{sum(c.firmware_devices for c in firmware_cards)}"
            )
            if firmware_cards
            else NO_DATA,
        )
    )
    drift_cards = _present("drift")
    totals.append(
        ("Drift events", str(sum(c.drift_events for c in drift_cards)) if drift_cards else NO_DATA)
    )
    return totals


def _dimension_detail(card: SiteScorecard, dimension: str) -> str:
    if not card.has(dimension):
        return NO_DATA
    if dimension == "records":
        counts = ", ".join(f"{key} {card.record_counts[key]}" for key in _RECORD_KEYS)
    elif dimension == "quality":
        counts = f"errors {card.quality_errors}, warnings {card.quality_warnings}"
    elif dimension == "certificates":
        counts = ", ".join(f"{sev} {card.cert_findings[sev]}" for sev in CERT_SEVERITIES)
    elif dimension == "firmware":
        counts = f"non-compliant {card.firmware_noncompliant} of {card.firmware_devices} devices"
    else:
        counts = f"events {card.drift_events}"
    return f"{counts}; sub-score {_fmt_score(card.dimension_scores.get(dimension))}"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_row(cells: Iterable[Any]) -> str:
    return "| " + " | ".join(_escape_md_cell(cell) for cell in cells) + " |"


def render_fleet_markdown(
    scorecards: Iterable[SiteScorecard],
    generated_at: Optional[datetime | str] = None,
    title: str = DEFAULT_FLEET_TITLE,
) -> str:
    """Render the fleet scorecard as deterministic Markdown."""
    cards = _ordered(scorecards)
    lines: list[str] = [f"# {_escape_md_cell(title)}", ""]
    timestamp = _fmt_timestamp(generated_at)
    if timestamp is not None:
        lines += [f"Generated at: {_escape_md_cell(timestamp)}", ""]

    lines += ["## Fleet totals", "", _md_row(("Metric", "Value")), _md_row(("---", "---"))]
    lines += [_md_row(pair) for pair in _fleet_totals(cards)]
    lines.append("")

    lines += ["## Site table", "", _md_row(TABLE_HEADERS), _md_row(["---"] * len(TABLE_HEADERS))]
    for card in cards:
        lines.append(_md_row([card.site_id] + [text for text, _ in _table_cells(card)]))
    lines.append("")

    lines += ["## Top 10 per risk dimension", ""]
    for list_title, dimension in _TOP_LISTS:
        lines += [f"### Top 10: {list_title}", ""]
        top = _top_list(cards, dimension)
        if not top:
            lines += ["None", ""]
            continue
        lines += [_md_row(("Rank", "Site", list_title)), _md_row(("---", "---", "---"))]
        for rank, card in enumerate(top, start=1):
            lines.append(_md_row((rank, card.site_id, _top_display(card, dimension))))
        lines.append("")

    lines += ["## Per-site drill-down", ""]
    for index, card in enumerate(cards, start=1):
        lines += [f"### {index}. {_escape_md_cell(card.site_id)}", ""]
        lines.append(f"- Health score: {_fmt_score(card.health_score)}")
        lines.append(f"- Previous score: {_fmt_score(card.previous_score)}")
        lines.append(f"- Trend: {_escape_md_cell(card.trend)}")
        for dimension in FLEET_DIMENSIONS:
            lines.append(f"- {dimension}: {_escape_md_cell(_dimension_detail(card, dimension))}")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    """Escape any value for safe inclusion in HTML text or quoted attributes."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


_FLEET_STYLE = """
    :root {
      --bg: #f8fafc;
      --surface: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #475569;
      --active-bg: #dcfce7;
      --active-fg: #166534;
      --stale-bg: #fee2e2;
      --stale-fg: #991b1b;
      --unreach-bg: #fef3c7;
      --unreach-fg: #92400e;
      --insuff-bg: #e2e8f0;
      --insuff-fg: #334155;
      --accent: #2563eb;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    header {
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 2px solid var(--border);
    }
    header h1 { margin: 0 0 8px 0; font-size: 1.75rem; }
    h2 { font-size: 1.25rem; margin: 28px 0 12px 0; }
    h3 { font-size: 1.05rem; margin: 16px 0 8px 0; }
    .header-meta { color: var(--muted); font-size: 0.9rem; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 28px;
    }
    .kpi-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }
    .kpi-label {
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 6px;
    }
    .kpi-value { font-size: 1.5rem; font-weight: 700; overflow-wrap: anywhere; }
    .table-wrap {
      overflow-x: auto;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 16px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }
    th { background: var(--bg); color: var(--muted); font-weight: 600; }
    th button {
      font: inherit;
      color: inherit;
      background: none;
      border: 0;
      padding: 0;
      cursor: pointer;
      text-align: left;
    }
    th button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    th[aria-sort="ascending"] button::after { content: " \\25B2"; }
    th[aria-sort="descending"] button::after { content: " \\25BC"; }
    td a { color: var(--accent); overflow-wrap: anywhere; }
    .no-data { color: var(--muted); font-style: italic; }
    .trend { display: inline-block; padding: 1px 8px; border-radius: 999px; font-weight: 600; }
    .trend-improving { background: var(--active-bg); color: var(--active-fg); }
    .trend-stable { background: var(--insuff-bg); color: var(--insuff-fg); }
    .trend-degrading { background: var(--stale-bg); color: var(--stale-fg); }
    .trend-new { background: var(--unreach-bg); color: var(--unreach-fg); }
    .site-block {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 12px;
    }
    .site-block h3 { overflow-wrap: anywhere; }
    .site-block dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 0; }
    .site-block dt { font-weight: 600; color: var(--muted); }
    .site-block dd { margin: 0; overflow-wrap: anywhere; }
    @media (max-width: 600px) {
      body { padding: 12px; }
      header h1 { font-size: 1.4rem; }
      .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
      .kpi-card { padding: 10px; }
      .kpi-value { font-size: 1.2rem; }
      th, td { white-space: nowrap; }
    }
"""

_FLEET_SCRIPT = """
    (function () {
      var table = document.getElementById("fleet-site-table");
      if (!table) { return; }
      var tbody = table.querySelector("tbody");
      var headers = Array.prototype.slice.call(table.querySelectorAll("thead th"));

      function parse(raw) {
        var parts = raw.split(" ");
        var nums = [];
        for (var i = 0; i < parts.length; i++) {
          var n = Number(parts[i]);
          if (parts[i] === "" || !isFinite(n)) { return null; }
          nums.push(n);
        }
        return nums;
      }

      function compareValues(a, b) {
        var na = parse(a);
        var nb = parse(b);
        if (na && nb) {
          for (var i = 0; i < Math.max(na.length, nb.length); i++) {
            var x = i < na.length ? na[i] : 0;
            var y = i < nb.length ? nb[i] : 0;
            if (x !== y) { return x < y ? -1 : 1; }
          }
          return 0;
        }
        return a < b ? -1 : (a > b ? 1 : 0);
      }

      function sortBy(col, direction) {
        var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
        rows.sort(function (ra, rb) {
          var a = ra.children[col].getAttribute("data-sort-value") || "";
          var b = rb.children[col].getAttribute("data-sort-value") || "";
          if (a === "" && b !== "") { return 1; }
          if (b === "" && a !== "") { return -1; }
          var result = a === "" ? 0 : compareValues(a, b) * direction;
          if (result === 0) {
            result = Number(ra.getAttribute("data-index")) - Number(rb.getAttribute("data-index"));
          }
          return result;
        });
        for (var i = 0; i < rows.length; i++) { tbody.appendChild(rows[i]); }
      }

      headers.forEach(function (th, col) {
        var button = th.querySelector("button");
        if (!button) { return; }
        button.addEventListener("click", function () {
          var next = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
          headers.forEach(function (other) { other.removeAttribute("aria-sort"); });
          th.setAttribute("aria-sort", next);
          sortBy(col, next === "ascending" ? 1 : -1);
        });
      });
    })();
"""


def _html_value(text: str) -> str:
    if text == NO_DATA:
        return f'<span class="no-data">{NO_DATA}</span>'
    return _esc(text)


def render_fleet_html(
    scorecards: Iterable[SiteScorecard],
    generated_at: Optional[datetime | str] = None,
    title: str = DEFAULT_FLEET_TITLE,
) -> str:
    """Render the fleet scorecard as a single self-contained HTML document."""
    cards = _ordered(scorecards)
    out: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '  <meta charset="utf-8">',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
        f"  <title>{_esc(title)}</title>",
        "  <style>" + _FLEET_STYLE + "  </style>",
        "</head>",
        "<body>",
        "  <header>",
        f"    <h1>{_esc(title)}</h1>",
    ]
    timestamp = _fmt_timestamp(generated_at)
    if timestamp is not None:
        out.append(f'    <div class="header-meta">Generated at: {_esc(timestamp)}</div>')
    out.append("  </header>")

    out += ['  <section aria-labelledby="fleet-totals">', '    <h2 id="fleet-totals">Fleet totals</h2>']
    out.append('    <div class="kpi-grid">')
    for label, value in _fleet_totals(cards):
        out.append(
            f'      <div class="kpi-card"><div class="kpi-label">{_esc(label)}</div>'
            f'<div class="kpi-value">{_html_value(value)}</div></div>'
        )
    out += ["    </div>", "  </section>"]

    out += ['  <section aria-labelledby="fleet-sites">', '    <h2 id="fleet-sites">Site table</h2>']
    out.append('    <div class="table-wrap">')
    out.append('      <table id="fleet-site-table">')
    out.append("        <thead><tr>")
    for header in TABLE_HEADERS:
        sort_attr = ' aria-sort="ascending"' if header == "Health score" else ""
        out.append(
            f'          <th scope="col"{sort_attr}><button type="button">{_esc(header)}</button></th>'
        )
    out.append("        </tr></thead>")
    out.append("        <tbody>")
    for index, card in enumerate(cards, start=1):
        cells = [
            f'<td data-sort-value="{_esc(card.site_id)}">'
            f'<a href="#site-{index}">{_esc(card.site_id)}</a></td>'
        ]
        for col, (text, sort_value) in enumerate(_table_cells(card)):
            if col == 2:
                body = f'<span class="trend trend-{_esc(text)}">{_esc(text)}</span>'
            else:
                body = _html_value(text)
            cells.append(f'<td data-sort-value="{_esc(sort_value)}">{body}</td>')
        out.append(f'          <tr data-index="{index}">' + "".join(cells) + "</tr>")
    out += ["        </tbody>", "      </table>", "    </div>", "  </section>"]

    out += [
        '  <section aria-labelledby="fleet-top">',
        '    <h2 id="fleet-top">Top 10 per risk dimension</h2>',
    ]
    for list_title, dimension in _TOP_LISTS:
        out.append(f"    <h3>Top 10: {_esc(list_title)}</h3>")
        top = _top_list(cards, dimension)
        if not top:
            out.append("    <p>None</p>")
            continue
        out.append("    <ol>")
        for card in top:
            out.append(
                f"      <li>{_esc(card.site_id)}: {_esc(_top_display(card, dimension))}</li>"
            )
        out.append("    </ol>")
    out.append("  </section>")

    out += [
        '  <section aria-labelledby="fleet-drill">',
        '    <h2 id="fleet-drill">Per-site drill-down</h2>',
    ]
    for index, card in enumerate(cards, start=1):
        out.append(f'    <div class="site-block" id="site-{index}">')
        out.append(f"      <h3>{index}. {_esc(card.site_id)}</h3>")
        out.append("      <dl>")
        rows = [
            ("Health score", _fmt_score(card.health_score)),
            ("Previous score", _fmt_score(card.previous_score)),
            ("Trend", card.trend),
        ] + [(dimension, _dimension_detail(card, dimension)) for dimension in FLEET_DIMENSIONS]
        for label, value in rows:
            out.append(f"        <dt>{_esc(label)}</dt><dd>{_html_value(value)}</dd>")
        out += ["      </dl>", "    </div>"]
    out.append("  </section>")

    out += ["  <script>" + _FLEET_SCRIPT + "  </script>", "</body>", "</html>"]
    return "\n".join(out) + "\n"
