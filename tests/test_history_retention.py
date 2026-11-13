"""Tests for HistoryStore.prune_runs, RetentionPolicy and PruneReport."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sqlite3
import uuid

import pytest

from sot_validator.history import (
    HISTORY_SCHEMA_VERSION,
    HistoryStore,
    PruneReport,
    RetentionPolicy,
)
from sot_validator.history import ledger
from sot_validator.models import ValidationClassification, ValidationResult

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
NOW = T0 + timedelta(days=100)
ACTIVE = ValidationClassification.CONFIRMED_ACTIVE
STALE = ValidationClassification.STALE_LIKELY_UNUSED


def _results(
    sites: tuple[str, ...], classification: ValidationClassification
) -> list[ValidationResult]:
    return [
        ValidationResult(
            item_type="IPAddress",
            item_id=f"{site_id}-ip-{index}",
            site_id=site_id,
            name=f"{site_id}-ip-{index}",
            classification=classification,
            confidence=0.9,
            rationale="test",
        )
        for site_id in sites
        for index in range(2)
    ]


def _record(
    store: HistoryStore,
    run_id: str | None,
    day: float,
    sites: tuple[str, ...] = ("site-a",),
    classification: ValidationClassification = ACTIVE,
) -> str:
    return store.record_run(
        _results(sites, classification),
        run_id=run_id,
        recorded_at=T0 + timedelta(days=day),
    ).run_id


def _alternating(store: HistoryStore, run_ids: list[str], sites=("site-a",)) -> None:
    """Record runs ten days apart, flipping ACTIVE/STALE so every later run writes drift rows."""
    for index, run_id in enumerate(run_ids):
        _record(store, run_id, float(index * 10), sites, ACTIVE if index % 2 == 0 else STALE)


def _run_ids(store: HistoryStore) -> list[str]:
    return [run.run_id for run in store.list_runs()]


def _count(store: HistoryStore, table: str) -> int:
    return int(store._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- policy and report ------------------------------------------------------------------


@pytest.mark.parametrize("value", [True, False, 0, -1, 1.5, 2.0, "30", "0"])
@pytest.mark.parametrize("key", ["max_age_days", "max_runs_per_site"])
def test_retention_policy_rejects_bad_values(key, value):
    with pytest.raises(ValueError):
        RetentionPolicy(**{key: value})


def test_retention_policy_accepts_none_and_positive_ints():
    assert RetentionPolicy() == RetentionPolicy(None, None)
    policy = RetentionPolicy(max_age_days=1, max_runs_per_site=52)
    assert (policy.max_age_days, policy.max_runs_per_site) == (1, 52)


def test_prune_report_to_dict_keys_and_iso_datetimes():
    store = HistoryStore()
    _alternating(store, ["r1", "r2", "r3"])
    report = store.prune_runs(RetentionPolicy(max_age_days=85), now=NOW)
    assert isinstance(report, PruneReport)
    data = report.to_dict()
    assert list(data) == [
        "dry_run", "policy", "now", "age_cutoff", "run_ids", "run_count", "drift_event_count"
    ]
    assert data["policy"] == {"max_age_days": 85, "max_runs_per_site": None}
    assert data["now"] == NOW.isoformat()
    assert data["age_cutoff"] == (NOW - timedelta(days=85)).isoformat()
    assert data["dry_run"] is True
    assert data["run_ids"] == ["r1", "r2"]
    assert data["run_count"] == 2
    assert data["drift_event_count"] == 2

    no_age = store.prune_runs(RetentionPolicy(max_runs_per_site=5), now=NOW).to_dict()
    assert no_age["age_cutoff"] is None


def test_now_accepts_iso_string_and_defaults_to_current_time():
    store = HistoryStore()
    _alternating(store, ["r1", "r2"])
    report = store.prune_runs(RetentionPolicy(max_age_days=1), now="2026-04-11T00:00:00Z")
    assert report.now == NOW
    before = datetime.now(timezone.utc)
    report = store.prune_runs(RetentionPolicy(max_age_days=1))
    assert before <= report.now <= datetime.now(timezone.utc)
    assert report.now.tzinfo is not None


def test_policy_must_be_retention_policy():
    with pytest.raises(ValueError):
        HistoryStore().prune_runs({"max_age_days": 1})  # type: ignore[arg-type]


# --- selection rules --------------------------------------------------------------------


def test_age_only_pruning_is_strict():
    store = HistoryStore()
    for run_id, day in [("r1", 0), ("r2", 10), ("r3", 70), ("r4", 71), ("r5", 95)]:
        _record(store, run_id, day)
    # Cutoff is day 70: r3 is exactly max_age_days old and is kept.
    report = store.prune_runs(RetentionPolicy(max_age_days=30), now=NOW, dry_run=False)
    assert report.run_ids == ["r1", "r2"]
    assert report.run_count == 2
    assert report.age_cutoff == T0 + timedelta(days=70)
    assert _run_ids(store) == ["r3", "r4", "r5"]


def test_count_only_pruning_per_site_multi_site_and_empty_runs():
    store = HistoryStore()
    _record(store, "m1", 0, ("site-a", "site-b"))
    _record(store, "a1", 1, ("site-a",))
    _record(store, "e1", 2, ())
    _record(store, "a2", 3, ("site-a",))
    _record(store, "b1", 4, ("site-b",))
    _record(store, "a3", 5, ("site-a",))

    # site-a protects a3, a2; site-b protects b1, m1. m1 survives because site-b
    # still protects it, even though site-a does not. e1 has no sites.
    report = store.prune_runs(RetentionPolicy(max_runs_per_site=2), now=NOW)
    assert report.run_ids == ["a1"]

    # With one run per site, m1 is unprotected for both of its sites.
    report = store.prune_runs(RetentionPolicy(max_runs_per_site=1), now=NOW, dry_run=False)
    assert report.run_ids == ["m1", "a1", "a2"]
    assert _run_ids(store) == ["e1", "b1", "a3"]


def test_count_rule_ignores_recorded_at_order():
    store = HistoryStore()
    # Backfilled run: recorded later in run_seq but with an older timestamp.
    _record(store, "new-seq-1", 50)
    _record(store, "new-seq-2", 5)
    _record(store, "new-seq-3", 60)
    report = store.prune_runs(RetentionPolicy(max_runs_per_site=2), now=NOW)
    assert report.run_ids == ["new-seq-1"]


def test_both_limits_prune_the_union():
    store = HistoryStore()
    _record(store, "old-b", 0, ("site-b",))
    _record(store, "a1", 80, ("site-a",))
    _record(store, "a2", 81, ("site-a",))
    _record(store, "a3", 82, ("site-a",))
    _record(store, "b2", 90, ("site-b",))
    policy = RetentionPolicy(max_age_days=30, max_runs_per_site=2)
    # old-b is marked only by age; a1 only by count.
    assert store.prune_runs(RetentionPolicy(max_age_days=30), now=NOW).run_ids == ["old-b"]
    assert store.prune_runs(RetentionPolicy(max_runs_per_site=2), now=NOW).run_ids == ["a1"]
    report = store.prune_runs(policy, now=NOW, dry_run=False)
    assert report.run_ids == ["old-b", "a1"]
    assert _run_ids(store) == ["a2", "a3", "b2"]


def test_neither_limit_prunes_nothing():
    store = HistoryStore()
    _alternating(store, ["r1", "r2", "r3"])
    report = store.prune_runs(RetentionPolicy(), now=NOW + timedelta(days=10_000), dry_run=False)
    assert report.run_ids == []
    assert report.run_count == 0
    assert report.drift_event_count == 0
    assert report.age_cutoff is None
    assert _run_ids(store) == ["r1", "r2", "r3"]


def test_newest_run_is_kept_even_when_every_rule_marks_it():
    store = HistoryStore()
    _alternating(store, ["r1", "r2", "r3"])
    far_future = NOW + timedelta(days=5000)
    report = store.prune_runs(RetentionPolicy(max_age_days=1), now=far_future, dry_run=False)
    assert report.run_ids == ["r1", "r2"]
    assert _run_ids(store) == ["r3"]

    # A single remaining run is never pruned, and the newest run without sites too.
    assert store.prune_runs(RetentionPolicy(max_age_days=1), now=far_future).run_ids == []
    _record(store, "empty", 1, ())
    report = store.prune_runs(
        RetentionPolicy(max_age_days=1, max_runs_per_site=1), now=far_future, dry_run=False
    )
    assert report.run_ids == ["r3"]
    assert _run_ids(store) == ["empty"]


# --- dry run ----------------------------------------------------------------------------


def test_dry_run_leaves_file_byte_for_byte_unchanged(tmp_path):
    db_path = tmp_path / "history.db"
    with HistoryStore(db_path) as store:
        _alternating(store, ["r1", "r2", "r3", "r4"])
    before = _sha256(db_path)

    store = HistoryStore(db_path)
    statements: list[str] = []
    store._conn.set_trace_callback(statements.append)
    report = store.prune_runs(RetentionPolicy(max_age_days=70, max_runs_per_site=1), now=NOW)
    assert store._conn.in_transaction is False
    store._conn.set_trace_callback(None)
    store.close()

    assert report.dry_run is True
    assert report.run_ids == ["r1", "r2", "r3"]
    assert report.drift_event_count == 4
    assert statements and all(s.lstrip().upper().startswith("SELECT") for s in statements)
    assert _sha256(db_path) == before
    with HistoryStore(db_path) as store:
        assert _run_ids(store) == ["r1", "r2", "r3", "r4"]


def test_dry_run_is_the_default_and_matches_apply():
    store = HistoryStore()
    _alternating(store, ["r1", "r2", "r3", "r4"])
    policy = RetentionPolicy(max_runs_per_site=2)
    dry = store.prune_runs(policy, now=NOW)
    assert dry.dry_run is True
    assert _count(store, "validation_runs") == 4
    applied = store.prune_runs(policy, now=NOW, dry_run=False)
    assert applied.dry_run is False
    assert (applied.run_ids, applied.drift_event_count) == (dry.run_ids, dry.drift_event_count)


# --- deletion ---------------------------------------------------------------------------


def test_drift_rows_removed_only_for_pruned_runs():
    store = HistoryStore()
    _alternating(store, ["r1", "r2", "r3", "r4"])
    survivors_before = [e.to_dict() for e in store._list_all_drift_events() if e.run_id in {"r3", "r4"}]
    assert len(survivors_before) == 4

    report = store.prune_runs(RetentionPolicy(max_runs_per_site=2), now=NOW, dry_run=False)
    assert report.run_ids == ["r1", "r2"]
    # r1 had no previous classification and wrote no drift; r2 wrote two rows.
    assert report.drift_event_count == 2
    assert [e.to_dict() for e in store._list_all_drift_events()] == survivors_before
    assert [e.run_id for e in store.detect_drift()] == ["r4", "r4"]


def test_orphaned_drift_rows_are_left_alone():
    store = HistoryStore()
    _alternating(store, ["r1", "r2", "r3"])
    store._conn.execute(
        "UPDATE drift_events SET run_id = 'gone' WHERE run_id = 'r2'"
    )
    store._conn.commit()
    report = store.prune_runs(RetentionPolicy(max_runs_per_site=1), now=NOW, dry_run=False)
    assert report.run_ids == ["r1", "r2"]
    assert report.drift_event_count == 0
    assert {e.run_id for e in store._list_all_drift_events()} == {"gone", "r3"}


def test_streaks_identical_after_real_prune_and_never_touched():
    store = HistoryStore()
    _alternating(store, ["r1", "r2", "r3", "r4", "r5"], sites=("site-a", "site-b"))
    before = [s.to_dict() for s in store.list_streaks()]
    raw_before = store._conn.execute("SELECT * FROM item_streaks ORDER BY item_id").fetchall()

    statements: list[str] = []
    store._conn.set_trace_callback(statements.append)
    report = store.prune_runs(RetentionPolicy(max_runs_per_site=1), now=NOW, dry_run=False)
    store._conn.set_trace_callback(None)

    assert report.run_count == 4
    assert not any("item_streaks" in s for s in statements)
    assert statements[0] == "BEGIN IMMEDIATE"
    assert statements[-1] == "COMMIT"
    assert [s.to_dict() for s in store.list_streaks()] == before
    raw_after = store._conn.execute("SELECT * FROM item_streaks ORDER BY item_id").fetchall()
    assert [tuple(r) for r in raw_after] == [tuple(r) for r in raw_before]


def test_streaks_continue_after_prune_exactly_as_without_it():
    pruned, control = HistoryStore(), HistoryStore()
    for store in (pruned, control):
        for index, cls in enumerate([ACTIVE, STALE, STALE, STALE]):
            _record(store, f"r{index}", index * 10, ("site-a",), cls)
    pruned.prune_runs(RetentionPolicy(max_runs_per_site=1), now=NOW, dry_run=False)
    assert _run_ids(pruned) == ["r3"]

    for store in (pruned, control):
        _record(store, "r-next", 50, ("site-a",), STALE)
    after = [s.to_dict() for s in pruned.list_streaks()]
    assert after == [s.to_dict() for s in control.list_streaks()]
    streak = pruned.get_item_streak("IPAddress", "site-a-ip-0")
    assert streak.consecutive_stale_runs == 4
    assert streak.total_runs_seen == 5
    assert streak.first_seen_at == T0
    assert streak.first_stale_at == T0 + timedelta(days=10)
    assert streak.last_confirmed_active_at == T0


def test_rollback_on_failure_leaves_every_table_unchanged(tmp_path):
    db_path = tmp_path / "history.db"
    store = HistoryStore(db_path)
    _alternating(store, ["r1", "r2", "r3", "r4"])
    store._conn.execute(
        """
        CREATE TRIGGER block_run_delete BEFORE DELETE ON validation_runs
        BEGIN SELECT RAISE(ABORT, 'blocked by test'); END
        """
    )
    store._conn.commit()
    counts = {t: _count(store, t) for t in ("validation_runs", "drift_events", "item_streaks")}

    with pytest.raises(sqlite3.IntegrityError, match="blocked by test"):
        store.prune_runs(RetentionPolicy(max_runs_per_site=1), now=NOW, dry_run=False)

    assert store._conn.in_transaction is False
    assert {t: _count(store, t) for t in counts} == counts
    store.close()
    with HistoryStore(db_path) as reopened:
        assert _count(reopened, "drift_events") == counts["drift_events"]
        assert _run_ids(reopened) == ["r1", "r2", "r3", "r4"]


def test_prune_needs_no_schema_change():
    assert HISTORY_SCHEMA_VERSION == 1
    assert len(ledger._MIGRATIONS) == 1


# --- generated run IDs ------------------------------------------------------------------


def test_generated_run_ids_never_collide_after_prune():
    store = HistoryStore()
    for day in range(5):
        _record(store, None, day)
    store.prune_runs(RetentionPolicy(max_runs_per_site=2), now=NOW, dry_run=False)
    survivors = _run_ids(store)
    assert len(survivors) == 2

    for day in range(5, 10):
        _record(store, None, day)
    all_ids = _run_ids(store)
    assert len(all_ids) == len(set(all_ids)) == 7
    assert all_ids[:2] == survivors
    sequences = [int(run_id.split("-")[1]) for run_id in all_ids]
    assert sequences == sorted(sequences)
    assert sequences[2:] == [6, 7, 8, 9, 10]
    assert all(len(run_id.split("-")[2]) == 8 for run_id in all_ids)


def test_generated_run_id_regenerates_on_collision(monkeypatch):
    store = HistoryStore()
    _record(store, "run-0002-aaaaaaaa", 0)
    suffixes = iter(["aaaaaaaa" + "0" * 24, "bbbbbbbb" + "0" * 24])
    monkeypatch.setattr(ledger.uuid, "uuid4", lambda: uuid.UUID(next(suffixes)))
    assert _record(store, None, 1) == "run-0002-bbbbbbbb"


def test_generated_sequence_survives_pruning_the_newest_seq_rows(tmp_path):
    db_path = tmp_path / "history.db"
    with HistoryStore(db_path) as store:
        for day in range(4):
            _record(store, None, day)
        store._conn.execute("DELETE FROM validation_runs WHERE run_seq > 1")
        store._conn.commit()
    with HistoryStore(db_path) as store:
        # sqlite_sequence still remembers run_seq 4 even though MAX(run_seq) is 1.
        assert _record(store, None, 5).startswith("run-0005-")
