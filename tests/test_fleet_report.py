"""Tests for the fleet-wide site health scorecard and trend report."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import random
import re
import subprocess
import sys

import pytest

from sot_validator.history import HistoryStore
from sot_validator.lifecycle.certificates import CertificateFinding
from sot_validator.lifecycle.firmware import FirmwareFinding
from sot_validator.models import ValidationClassification, ValidationResult
from sot_validator.quality.checks import QualityFinding
from sot_validator.reporting import (
    FLEET_DIMENSIONS,
    TREND_DEGRADING,
    TREND_IMPROVING,
    TREND_NEW,
    TREND_STABLE,
    TREND_STABLE_THRESHOLD,
    FleetScorer,
    FleetScoreWeights,
    SiteScorecard,
    render_fleet_html,
    render_fleet_markdown,
)

ACTIVE = ValidationClassification.CONFIRMED_ACTIVE.value
STALE = ValidationClassification.STALE_LIKELY_UNUSED.value
UNREACHABLE = ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value
INSUFFICIENT = ValidationClassification.INSUFFICIENT_DATA.value
HOSTILE = 'evil<script>alert(1)</script>"|\nx'
SRC = Path(__file__).resolve().parents[1] / "src"


def _full_card(site_id: str = "s1", **overrides):
    kwargs = dict(
        record_counts={ACTIVE: 8, STALE: 2},
        quality_errors=1,
        quality_warnings=0,
        cert_findings={"error": 1},
        firmware_devices=4,
        firmware_noncompliant=1,
        drift_events=1,
    )
    kwargs.update(overrides)
    return FleetScorer().score_site(site_id, **kwargs)


def _result(site_id: str, item_id: str, classification: str) -> ValidationResult:
    return ValidationResult(
        item_type="IPAddress",
        item_id=item_id,
        site_id=site_id,
        name=item_id,
        classification=ValidationClassification(classification),
    )


def _quality(site_id: str, finding_id: str, severity: str) -> QualityFinding:
    return QualityFinding(
        finding_id=finding_id,
        site_id=site_id,
        rule="duplicate_ip",
        severity=severity,
        record_type="IPAddress",
        record_ids=[finding_id],
        message="m",
    )


def _cert(site_id: str, port: int, severity: str) -> CertificateFinding:
    return CertificateFinding(
        site_id=site_id,
        ip="10.1.1.1",
        port=port,
        subject_cn=None,
        issuer=None,
        not_after=None,
        days_remaining=None,
        issues=["expired"],
        severity=severity,
    )


def _firmware(site_id: str, device: str, status: str) -> FirmwareFinding:
    return FirmwareFinding(
        site_id=site_id,
        device=device,
        ip=None,
        sys_descr=None,
        vendor=None,
        platform=None,
        os_family=None,
        version=None,
        status=status,
        conditions=[],
    )


def _script_body(doc: str) -> str:
    return doc.split("<script>", 1)[1].split("</script>", 1)[0]


def _md_section(doc: str, heading: str) -> str:
    return doc.split(heading, 1)[1].split("\n### ", 1)[0].split("\n## ", 1)[0]


# --- constants and score maths -------------------------------------------------


def test_constants():
    assert FLEET_DIMENSIONS == ("records", "quality", "certificates", "firmware", "drift")
    assert TREND_STABLE_THRESHOLD == 5.0
    assert (TREND_IMPROVING, TREND_STABLE, TREND_DEGRADING, TREND_NEW) == (
        "improving",
        "stable",
        "degrading",
        "new",
    )


def test_all_five_dimensions_exact_score():
    card = _full_card()
    assert card.dimension_scores == {
        "records": 80.0,
        "quality": 90.0,
        "certificates": 75.0,
        "firmware": 75.0,
        "drift": 90.0,
    }
    expected = 0.4 * 80 + 0.2 * 90 + 0.15 * 75 + 0.15 * 75 + 0.1 * 90
    assert expected == pytest.approx(81.5)
    assert card.health_score == 81.5
    assert card.inputs_present == list(FLEET_DIMENSIONS)
    assert card.record_counts == {ACTIVE: 8, STALE: 2, UNREACHABLE: 0, INSUFFICIENT: 0}
    assert list(card.record_counts) == [c.value for c in ValidationClassification]
    assert card.cert_findings == {"error": 1, "warning": 0, "info": 0}


def test_records_penalties_and_clamping():
    card = FleetScorer().score_site(
        "s",
        record_counts={
            ValidationClassification.CONFIRMED_ACTIVE: 4,
            UNREACHABLE: 4,
            INSUFFICIENT: 4,
        },
        quality_errors=50,
        cert_findings={"error": 3, "warning": 2, "info": 5},
    )
    # records: 100 * (1 - (4*0.5 + 4*0.25) / 12) = 75.0
    assert card.dimension_scores["records"] == 75.0
    # quality: 100 * (1 - 50/12) clamps to 0; certificates: 100 - 75 - 20 - 10 clamps to 0.
    assert card.dimension_scores["quality"] == 0.0
    assert card.dimension_scores["certificates"] == 0.0
    expected = (0.4 * 75 + 0.2 * 0 + 0.15 * 0) / (0.4 + 0.2 + 0.15)
    assert card.health_score == round(expected, 1) == 40.0


def test_denominator_is_one_without_records():
    card = FleetScorer().score_site("s", quality_warnings=2, drift_events=0)
    assert card.dimension_scores == {"quality": 50.0, "drift": 100.0}
    assert card.quality_errors == 0
    assert card.health_score == round((0.2 * 50 + 0.1 * 100) / 0.3, 1)


def test_renormalisation_matches_zero_certificate_weight():
    kwargs = dict(
        record_counts={ACTIVE: 7, STALE: 3},
        quality_errors=0,
        quality_warnings=2,
        firmware_devices=5,
        firmware_noncompliant=2,
        drift_events=2,
    )
    missing = FleetScorer().score_site("s", **kwargs)
    zero_weight = FleetScorer(FleetScoreWeights(certificates=0)).score_site(
        "s", cert_findings={"error": 2}, **kwargs
    )
    assert "certificates" not in missing.inputs_present
    assert missing.health_score == zero_weight.health_score
    assert missing.health_score is not None


def test_present_with_zero_findings_scores_100():
    card = FleetScorer().score_site(
        "s",
        record_counts={},
        quality_errors=0,
        cert_findings={},
        firmware_devices=0,
        firmware_noncompliant=0,
        drift_events=0,
    )
    assert card.dimension_scores == {dim: 100.0 for dim in FLEET_DIMENSIONS}
    assert card.health_score == 100.0


def test_records_only_and_no_inputs():
    card = FleetScorer().score_site("s2", record_counts={ACTIVE: 10})
    assert card.health_score == 100.0
    assert card.inputs_present == ["records"]
    empty = FleetScorer().score_site("s3", previous_score=50.0)
    assert empty.health_score is None
    assert empty.trend == TREND_NEW
    assert empty.inputs_present == []
    assert empty.dimension_scores == {}
    assert empty.previous_score == 50.0


def test_present_dimensions_with_zero_weight_score_none():
    weights = FleetScoreWeights(records=0, quality=1)
    card = FleetScorer(weights).score_site("s", record_counts={STALE: 1})
    assert card.health_score is None
    assert card.dimension_scores == {"records": 0.0}
    assert card.trend == TREND_NEW


# --- validation -------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"records": -1},
        {"quality": "x"},
        {"drift": True},
        {"stale_penalty": float("nan")},
        {"cert_info_points": float("inf")},
        {"records": 0, "quality": 0, "certificates": 0, "firmware": 0, "drift": 0},
    ],
)
def test_weights_validation(kwargs):
    with pytest.raises(ValueError):
        FleetScoreWeights(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"firmware_devices": 1},
        {"firmware_noncompliant": 0},
        {"firmware_devices": 1, "firmware_noncompliant": 2},
        {"record_counts": {"Bogus": 1}},
        {"record_counts": {ACTIVE: -1}},
        {"record_counts": {ACTIVE: True}},
        {"record_counts": {ACTIVE: 1.0}},
        {"record_counts": {ACTIVE: "1"}},
        {"cert_findings": {"critical": 1}},
        {"cert_findings": {"error": -2}},
        {"quality_errors": -1},
        {"quality_warnings": False},
        {"drift_events": 1.5},
        {"previous_score": "70"},
        {"previous_score": float("nan")},
    ],
)
def test_score_site_validation(kwargs):
    with pytest.raises(ValueError):
        FleetScorer().score_site("s", **kwargs)


# --- trend ------------------------------------------------------------------


def _card_with_score(score: float, previous: float | None) -> SiteScorecard:
    # Records only: health equals the records sub-score, 100 * (1 - stale / N).
    stale = round((100 - score) * 10)
    card = FleetScorer().score_site(
        "s", record_counts={ACTIVE: 1000 - stale, STALE: stale}, previous_score=previous
    )
    assert card.health_score == score
    return card


@pytest.mark.parametrize(
    ("current", "previous", "expected"),
    [
        (75.0, 70.0, TREND_STABLE),
        (65.0, 70.0, TREND_STABLE),
        (75.1, 70.0, TREND_IMPROVING),
        (64.9, 70.0, TREND_DEGRADING),
        (75.1, 70.1, TREND_STABLE),
        (70.0, 70.0, TREND_STABLE),
        (70.0, None, TREND_NEW),
    ],
)
def test_trend_boundaries(current, previous, expected):
    assert _card_with_score(current, previous).trend == expected


def test_trend_float_drift_case():
    # 3.3 - 8.3 is -5.000000000000001 in floats; the rounded delta keeps it stable.
    assert 3.3 - 8.3 < -5.0
    assert _card_with_score(3.3, 8.3).trend == TREND_STABLE
    assert _card_with_score(75.1, 70.1).trend == TREND_STABLE


# --- score_fleet ------------------------------------------------------------


def _fleet_inputs():
    results = [
        _result("a", "a1", ACTIVE),
        _result("a", "a2", STALE),
        _result("a", "a3", UNREACHABLE),
        _result("b", "b1", INSUFFICIENT),
        _result("b", "b2", ACTIVE),
    ]
    quality = [
        _quality("a", "q1", "error"),
        _quality("a", "q2", "warning"),
        _quality("a", "q3", "info"),
        _quality("c", "q4", "info"),
    ]
    certs = [_cert("a", 443, "error"), _cert("b", 443, "warning"), _cert("b", 8443, "info")]
    firmware = [
        _firmware("a", "sw1", "compliant"),
        _firmware("a", "sw2", "unknown_platform"),
        _firmware("a", "sw3", "unparsed"),
        _firmware("b", "sw4", "below_minimum"),
    ]
    return results, quality, certs, firmware


def test_score_fleet_matches_score_site():
    results, quality, certs, firmware = _fleet_inputs()
    cards = FleetScorer().score_fleet(
        results=results,
        quality_findings=quality,
        certificate_findings=certs,
        firmware_findings=firmware,
        previous={"a": 50.0, "z": 10.0},
        site_ids=["d"],
    )
    assert [card.site_id for card in cards] == ["a", "b", "c", "d"]
    scorer = FleetScorer()
    expected = [
        scorer.score_site(
            "a",
            record_counts={ACTIVE: 1, STALE: 1, UNREACHABLE: 1},
            quality_errors=1,
            quality_warnings=1,
            cert_findings={"error": 1},
            firmware_devices=3,
            firmware_noncompliant=2,
            previous_score=50.0,
        ),
        scorer.score_site(
            "b",
            record_counts={INSUFFICIENT: 1, ACTIVE: 1},
            quality_errors=0,
            quality_warnings=0,
            cert_findings={"warning": 1, "info": 1},
            firmware_devices=1,
            firmware_noncompliant=1,
        ),
        scorer.score_site(
            "c",
            record_counts={},
            quality_errors=0,
            quality_warnings=0,
            cert_findings={},
            firmware_devices=0,
            firmware_noncompliant=0,
        ),
        scorer.score_site(
            "d",
            record_counts={},
            quality_errors=0,
            quality_warnings=0,
            cert_findings={},
            firmware_devices=0,
            firmware_noncompliant=0,
        ),
    ]
    assert cards == expected
    assert cards[0].firmware_noncompliant == 2
    assert cards[2].quality_errors == 0 and cards[2].quality_warnings == 0
    assert all("drift" not in card.inputs_present for card in cards)


def test_score_fleet_none_vs_empty_inputs():
    results, *_ = _fleet_inputs()
    cards = FleetScorer().score_fleet(results=results, quality_findings=[])
    assert all(card.inputs_present == ["records", "quality"] for card in cards)
    assert FleetScorer().score_fleet() == []
    only_ids = FleetScorer().score_fleet(site_ids=["x"])
    assert only_ids[0].health_score is None


def test_score_fleet_previous_from_scorecards():
    results, *_ = _fleet_inputs()
    prior = FleetScorer().score_fleet(results=results)
    again = FleetScorer().score_fleet(results=results, previous=prior)
    assert [card.previous_score for card in again] == [card.health_score for card in prior]
    assert all(card.trend == TREND_STABLE for card in again)


def test_score_fleet_shuffled_inputs_identical():
    results, quality, certs, firmware = _fleet_inputs()
    baseline = FleetScorer().score_fleet(
        results=results,
        quality_findings=quality,
        certificate_findings=certs,
        firmware_findings=firmware,
        site_ids=["d", "a"],
    )
    rng = random.Random(7)
    for _ in range(5):
        shuffled = [list(x) for x in (results, quality, certs, firmware)]
        for seq in shuffled:
            rng.shuffle(seq)
        cards = FleetScorer().score_fleet(
            results=shuffled[0],
            quality_findings=shuffled[1],
            certificate_findings=shuffled[2],
            firmware_findings=shuffled[3],
            site_ids=["a", "d"],
        )
        assert cards == baseline
        assert render_fleet_markdown(cards) == render_fleet_markdown(baseline)
        assert render_fleet_html(cards) == render_fleet_html(baseline)


def test_drift_counts_from_history_store():
    store = HistoryStore(":memory:")
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record_run(
        [_result("a", "a1", ACTIVE), _result("a", "a2", ACTIVE), _result("b", "b1", STALE)],
        run_id="r1",
        recorded_at=t0,
    )
    second = [_result("a", "a1", STALE), _result("a", "a2", UNREACHABLE), _result("b", "b1", ACTIVE)]
    store.record_run(second, run_id="r2", recorded_at=t0 + timedelta(days=1))
    events = store.detect_drift()
    assert len(events) == 3
    cards = FleetScorer().score_fleet(results=second, drift_events=events)
    by_site = {card.site_id: card for card in cards}
    assert by_site["a"].drift_events == 2
    # b's RECOVERED transition still counts as drift.
    assert by_site["b"].drift_events == 1
    # a: D = 2 records, drift sub-score = 100 * (1 - 2/2) = 0.
    assert by_site["a"].dimension_scores["drift"] == 0.0
    assert by_site["b"].dimension_scores["drift"] == 0.0


# --- to_dict / from_dict ----------------------------------------------------


def test_to_dict_round_trip():
    for card in (
        _full_card(previous_score=60.0),
        FleetScorer().score_site("empty"),
        FleetScorer().score_site("q", quality_warnings=1),
    ):
        assert SiteScorecard.from_dict(card.to_dict()) == card


def test_from_dict_validation():
    data = _full_card().to_dict()
    with pytest.raises(ValueError):
        SiteScorecard.from_dict({**data, "trend": "sideways"})
    with pytest.raises(ValueError):
        SiteScorecard.from_dict({**data, "health_score": 100.1})
    with pytest.raises(ValueError):
        SiteScorecard.from_dict({**data, "health_score": -0.1})


# --- rendering --------------------------------------------------------------


def _twelve_sites() -> list[SiteScorecard]:
    scorer = FleetScorer()
    cards = [
        scorer.score_site(f"site-{i:02d}", record_counts={ACTIVE: 100 - i, STALE: i})
        for i in range(1, 13)
    ]
    # Two sites tie on score; site_id breaks the tie.
    cards.append(scorer.score_site("tie-b", record_counts={ACTIVE: 99, STALE: 1}))
    cards.append(scorer.score_site("tie-a", record_counts={ACTIVE: 99, STALE: 1}))
    cards.append(scorer.score_site("zz-none"))
    cards.append(scorer.score_site("aa-none"))
    return cards


def _md_table_sites(doc: str) -> list[str]:
    section = doc.split("## Site table", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("| ")][1:]
    return [row.split(" | ")[0][2:] for row in rows if not row.startswith("| ---")]


def test_site_table_order_and_ties():
    md = render_fleet_markdown(_twelve_sites())
    expected = [f"site-{i:02d}" for i in range(12, 1, -1)] + [
        "site-01",
        "tie-a",
        "tie-b",
        "aa-none",
        "zz-none",
    ]
    # site-01, tie-a and tie-b all score 99.0 and are ordered by site_id.
    assert _md_table_sites(md) == expected
    html_doc = render_fleet_html(_twelve_sites())
    tbody = html_doc.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    html_sites = re.findall(r'<a href="#site-(\d+)">([^<]+)</a>', tbody)
    assert [name for _, name in html_sites] == expected
    assert [int(idx) for idx, _ in html_sites] == list(range(1, len(expected) + 1))
    for idx in range(1, len(expected) + 1):
        assert f'id="site-{idx}"' in html_doc


def test_top_ten_truncation():
    cards = _twelve_sites()
    md = render_fleet_markdown(cards)
    stale_md = _md_section(md, "### Top 10: Stale records")
    md_rows = [line for line in stale_md.splitlines() if line.startswith("| ") and "---" not in line]
    md_sites = [row.split(" | ")[1] for row in md_rows[1:]]
    assert md_sites == [f"site-{i:02d}" for i in range(12, 2, -1)]

    html_doc = render_fleet_html(cards)
    stale_html = html_doc.split("<h3>Top 10: Stale records</h3>", 1)[1].split("</ol>", 1)[0]
    html_sites = re.findall(r"<li>([^:<]+):", stale_html)
    assert html_sites == [f"site-{i:02d}" for i in range(12, 2, -1)]

    # Empty lists show "None".
    assert "None" in _md_section(md, "### Top 10: Quality errors")
    assert "<h3>Top 10: Drift</h3>\n    <p>None</p>" in html_doc


def test_top_list_tie_break_and_certificate_tuple():
    scorer = FleetScorer()
    cards = [
        scorer.score_site("b", cert_findings={"error": 1, "warning": 0}),
        scorer.score_site("a", cert_findings={"error": 1, "warning": 0}),
        scorer.score_site("c", cert_findings={"warning": 5}),
        scorer.score_site("d", cert_findings={"error": 1, "info": 1}),
        scorer.score_site("e", cert_findings={}),
    ]
    section = _md_section(render_fleet_markdown(cards), "### Top 10: Certificate findings")
    rows = [line for line in section.splitlines() if line.startswith("| ") and "---" not in line]
    assert [row.split(" | ")[1] for row in rows[1:]] == ["d", "a", "b", "c"]


def test_rendering_is_order_independent():
    cards = _twelve_sites() + [_full_card("full", previous_score=90.0)]
    md = render_fleet_markdown(cards, generated_at="2026-11-13T00:00:00Z")
    doc = render_fleet_html(cards, generated_at="2026-11-13T00:00:00Z")
    rng = random.Random(3)
    for _ in range(5):
        shuffled = list(cards)
        rng.shuffle(shuffled)
        assert render_fleet_markdown(shuffled, generated_at="2026-11-13T00:00:00Z") == md
        assert render_fleet_html(shuffled, generated_at="2026-11-13T00:00:00Z") == doc


def test_generated_at_optional():
    cards = [_full_card()]
    assert "Generated at" not in render_fleet_markdown(cards)
    assert "Generated at" not in render_fleet_html(cards)
    stamp = datetime(2026, 11, 13, tzinfo=timezone.utc)
    assert "2026-11-13T00:00:00+00:00" in render_fleet_markdown(cards, generated_at=stamp)
    assert "2026-11-13T00:00:00+00:00" in render_fleet_html(cards, generated_at=stamp)


def test_fleet_totals_header():
    cards = [_full_card("a"), FleetScorer().score_site("b", record_counts={ACTIVE: 2}), FleetScorer().score_site("c")]
    md = render_fleet_markdown(cards)
    totals = md.split("## Fleet totals", 1)[1].split("## Site table", 1)[0]
    assert "| Sites | 3 |" in totals
    assert "| Sites with a score | 2 |" in totals
    assert "| Mean health score | 90.8 |" in totals  # (81.5 + 100) / 2 = 90.75
    assert "| Trend: new | 3 |" in totals
    assert "| Records: Confirmed Active | 10 |" in totals
    assert "| Records: Stale / Likely Unused | 2 |" in totals
    assert "| Firmware non-compliant / devices | 1/4 |" in totals
    assert "| Drift events | 1 |" in totals
    empty_md = render_fleet_markdown([FleetScorer().score_site("c")])
    assert "| Mean health score | no data |" in empty_md
    assert "| Drift events | no data |" in empty_md


def test_missing_dimension_shows_no_data():
    card = FleetScorer().score_site(
        "nocert", record_counts={ACTIVE: 1}, quality_errors=0, firmware_devices=1, firmware_noncompliant=0, drift_events=0
    )
    md = render_fleet_markdown([card])
    row = next(line for line in md.splitlines() if line.startswith("| nocert"))
    cells = row.split(" | ")
    assert cells[6] == "no data"
    assert cells[4] == "0"
    assert "- certificates: no data" in md
    assert "- quality: errors 0, warnings 0; sub-score 100.0" in md
    doc = render_fleet_html([card])
    tbody = doc.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert '<td data-sort-value=""><span class="no-data">no data</span></td>' in tbody
    assert '<dt>certificates</dt><dd><span class="no-data">no data</span></dd>' in doc
    assert '<dt>Previous score</dt><dd><span class="no-data">no data</span></dd>' in doc


def test_html_is_self_contained():
    cards = _twelve_sites() + [_full_card("full", previous_score=10.0), FleetScorer().score_site(HOSTILE)]
    doc = render_fleet_html(cards)
    assert doc.startswith("<!DOCTYPE html>")
    assert '<meta charset="utf-8">' in doc
    assert '<meta name="viewport"' in doc
    assert doc.count("<style>") == 1 and doc.count("<script") == 1
    for pattern in (r"https?://", r"<link", r"src=", r"@import", r"url\(", r"<img", r"//", r"@font-face"):
        assert not re.search(pattern, doc), pattern
    for value in ("--bg: #f8fafc", "--accent: #2563eb", "--stale-fg: #991b1b", '"Segoe UI", Roboto'):
        assert value in doc
    assert ".kpi-card" in doc and "header {" in doc
    assert doc.count('<th scope="col"') == 9
    assert doc.count('<button type="button">') == 9
    assert 'aria-sort="ascending"><button type="button">Health score</button>' in doc
    tbody = doc.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
    assert tbody.count("<td") == tbody.count("<td data-sort-value=")


def test_hostile_site_id_is_escaped():
    card = FleetScorer().score_site(HOSTILE, record_counts={STALE: 1}, cert_findings={"error": 1})
    doc = render_fleet_html([card, _full_card()])
    assert "<script>alert(1)" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc
    assert "&quot;" in doc
    assert "evil" not in _script_body(doc)
    assert 'href="#site-' in doc and "evil" not in re.findall(r'id="([^"]*)"', doc).__str__()

    md = render_fleet_markdown([card, _full_card()])
    evil_rows = [line for line in md.splitlines() if line.startswith("|") and "evil" in line]
    assert len(evil_rows) >= 3  # site table plus the stale and certificate top lists
    for line in evil_rows:
        assert "\\|" in line
        assert line.endswith(" |")
    assert all("\n" not in line for line in evil_rows)
    assert "\nx" not in md
    heading = next(line for line in md.splitlines() if line.startswith("### ") and "evil" in line)
    assert "\\|" in heading


def test_hostile_title_and_timestamp_escaped():
    doc = render_fleet_html([], generated_at="<b>t</b>", title="<i>T</i>")
    assert "<i>T</i>" not in doc and "&lt;i&gt;T&lt;/i&gt;" in doc
    assert "<b>t</b>" not in doc
    md = render_fleet_markdown([], title="a\nb|c")
    assert md.splitlines()[0] == "# a b\\|c"


# --- import cycle -----------------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [
        "import sot_validator.lifecycle; import sot_validator.reporting",
        "import sot_validator.quality; import sot_validator.reporting.fleet",
    ],
)
def test_fresh_interpreter_imports(code):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    completed = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr
