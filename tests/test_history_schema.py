"""Tests for HistoryStore schema versioning via PRAGMA user_version and ordered migrations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

import pytest

from sot_validator.history import (
    HISTORY_SCHEMA_VERSION,
    HistorySchemaVersionError,
    HistoryStore,
)
from sot_validator.history import ledger
from sot_validator.models import ValidationClassification, ValidationResult

_TABLES = {"validation_runs", "item_streaks", "drift_events"}

# Today's (v1) DDL, written out independently of ledger.py to model an
# operator database created before schema versioning existed.
_UNVERSIONED_V1_DDL = """
CREATE TABLE validation_runs (
    run_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL,
    site_ids_json TEXT NOT NULL,
    total_items INTEGER NOT NULL,
    classification_counts_json TEXT NOT NULL
);

CREATE TABLE item_streaks (
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

CREATE TABLE drift_events (
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


def _make_result(
    item_id: str,
    classification: ValidationClassification,
) -> ValidationResult:
    return ValidationResult(
        item_type="Equipment",
        item_id=item_id,
        site_id="site-010",
        name=item_id,
        classification=classification,
        confidence=0.9,
        rationale=f"{classification.value} for {item_id}",
    )


def _user_version(db_file: Path) -> int:
    conn = sqlite3.connect(str(db_file))
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {str(r[0]) for r in rows}


def _file_tables(db_file: Path) -> set[str]:
    conn = sqlite3.connect(str(db_file))
    try:
        return _table_names(conn)
    finally:
        conn.close()


def _dump_rows(db_file: Path) -> dict[str, list[tuple]]:
    conn = sqlite3.connect(str(db_file))
    try:
        return {
            table: conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            for table in sorted(_TABLES)
        }
    finally:
        conn.close()


def _make_v1_database(db_file: Path) -> None:
    with HistoryStore(db_file):
        pass
    assert _user_version(db_file) == 1


def test_schema_version_constant_matches_migrations() -> None:
    assert HISTORY_SCHEMA_VERSION == 1
    assert HISTORY_SCHEMA_VERSION == len(ledger._MIGRATIONS)
    assert issubclass(HistorySchemaVersionError, RuntimeError)


def test_fresh_file_database_reaches_current_version(tmp_path: Path) -> None:
    db_file = tmp_path / "nested" / "history.sqlite"
    with HistoryStore(db_file):
        pass
    assert _user_version(db_file) == HISTORY_SCHEMA_VERSION == 1
    assert _TABLES <= _file_tables(db_file)


def test_fresh_file_database_from_string_path(tmp_path: Path) -> None:
    db_file = tmp_path / "history.sqlite"
    with HistoryStore(str(db_file)):
        pass
    assert _user_version(db_file) == 1
    assert _TABLES <= _file_tables(db_file)


def test_fresh_memory_database_reaches_current_version() -> None:
    with HistoryStore(":memory:") as store:
        conn = store._conn
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 1
        assert _TABLES <= _table_names(conn)


def test_unversioned_v1_database_is_stamped_and_keeps_rows(tmp_path: Path) -> None:
    db_file = tmp_path / "legacy.sqlite"
    conn = sqlite3.connect(str(db_file))
    conn.executescript(_UNVERSIONED_V1_DDL)
    conn.execute(
        "INSERT INTO validation_runs (run_id, recorded_at, site_ids_json, total_items, "
        "classification_counts_json) VALUES (?, ?, ?, ?, ?)",
        (
            "legacy-run",
            "2026-01-01T00:00:00Z",
            '["site-010"]',
            1,
            '{"Stale / Likely Unused": 1}',
        ),
    )
    conn.execute(
        "INSERT INTO item_streaks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "Equipment",
            "eq-legacy",
            "site-010",
            "eq-legacy",
            "Stale / Likely Unused",
            0.8,
            3,
            4,
            "2025-12-01T00:00:00Z",
            "2025-12-10T00:00:00Z",
            "2025-12-05T00:00:00Z",
            22.0,
            "Confirmed Active",
            "NEWLY_STALE",
        ),
    )
    conn.execute(
        "INSERT INTO drift_events (run_id, recorded_at, site_id, item_type, item_id, name, "
        "previous_classification, new_classification, transition_type, confidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "legacy-run",
            "2026-01-01T00:00:00Z",
            "site-010",
            "Equipment",
            "eq-legacy",
            "eq-legacy",
            "Confirmed Active",
            "Stale / Likely Unused",
            "NEWLY_STALE",
            0.8,
        ),
    )
    conn.commit()
    assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == 0
    conn.close()

    before = _dump_rows(db_file)
    assert all(len(rows) == 1 for rows in before.values())

    with HistoryStore(db_file) as store:
        assert store.get_run("legacy-run") is not None
        streak = store.get_item_streak("Equipment", "eq-legacy")
        assert streak is not None
        assert streak.consecutive_stale_runs == 3
        assert len(store.detect_drift("legacy-run")) == 1

    assert _user_version(db_file) == 1
    assert _dump_rows(db_file) == before


def test_reopening_versioned_database_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "history.sqlite"
    t1 = datetime(2026, 3, 1, tzinfo=timezone.utc)
    with HistoryStore(db_file) as store:
        store.record_run(
            [_make_result("eq-1", ValidationClassification.CONFIRMED_ACTIVE)],
            run_id="run-a",
            recorded_at=t1,
        )
        store.record_run(
            [_make_result("eq-1", ValidationClassification.STALE_LIKELY_UNUSED)],
            run_id="run-b",
            recorded_at=t1 + timedelta(days=7),
        )
        runs_before = store.list_runs()
        streaks_before = store.list_streaks()
        drift_before = store.detect_drift("run-b")
    assert len(drift_before) == 1
    rows_before = _dump_rows(db_file)

    calls: list[int] = []

    def tracking_migration(conn: sqlite3.Connection) -> None:
        calls.append(1)
        ledger._migration_1_create_base_tables(conn)

    monkeypatch.setattr(ledger, "_MIGRATIONS", [tracking_migration])

    with HistoryStore(db_file) as store:
        assert store.list_runs() == runs_before
        assert store.list_streaks() == streaks_before
        assert store.detect_drift("run-b") == drift_before

    assert calls == []
    assert _user_version(db_file) == 1
    assert _dump_rows(db_file) == rows_before


def test_newer_database_is_refused_without_writes(tmp_path: Path) -> None:
    db_file = tmp_path / "future.sqlite"
    conn = sqlite3.connect(str(db_file))
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    before = db_file.read_bytes()

    with pytest.raises(HistorySchemaVersionError) as excinfo:
        HistoryStore(db_file)

    message = str(excinfo.value)
    assert "99" in message
    assert "(1)" in message
    assert db_file.read_bytes() == before
    assert _user_version(db_file) == 99
    assert "validation_runs" not in _file_tables(db_file)


def test_newer_database_refusal_closes_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "future.sqlite"
    conn = sqlite3.connect(str(db_file))
    conn.execute("PRAGMA user_version = 5")
    conn.close()

    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        c = real_connect(*args, **kwargs)
        opened.append(c)
        return c

    monkeypatch.setattr(ledger.sqlite3, "connect", recording_connect)
    with pytest.raises(
        HistorySchemaVersionError,
        match=r"schema version 5 is newer than the highest version this code supports \(1\)",
    ):
        HistoryStore(db_file)

    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute("SELECT 1")


def test_failing_migration_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "history.sqlite"
    _make_v1_database(db_file)

    class MigrationBoom(Exception):
        pass

    def failing_migration(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE half_done (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO half_done (id) VALUES (1)")
        raise MigrationBoom("migration 2 failed")

    monkeypatch.setattr(
        ledger, "_MIGRATIONS", [*ledger._MIGRATIONS, failing_migration]
    )

    with pytest.raises(MigrationBoom, match="migration 2 failed"):
        HistoryStore(db_file)

    assert _user_version(db_file) == 1
    tables = _file_tables(db_file)
    assert "half_done" not in tables
    assert _TABLES <= tables


def test_failing_later_migration_keeps_earlier_committed_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "history.sqlite"
    _make_v1_database(db_file)

    def good_migration(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE step_two (id INTEGER PRIMARY KEY)")

    def bad_migration(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE step_three (id INTEGER PRIMARY KEY)")
        raise ValueError("step three failed")

    monkeypatch.setattr(
        ledger,
        "_MIGRATIONS",
        [*ledger._MIGRATIONS, good_migration, bad_migration],
    )

    with pytest.raises(ValueError, match="step three failed"):
        HistoryStore(db_file)

    assert _user_version(db_file) == 2
    tables = _file_tables(db_file)
    assert "step_two" in tables
    assert "step_three" not in tables


def test_migrations_run_in_order_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "history.sqlite"
    _make_v1_database(db_file)

    calls: list[tuple[str, int]] = []

    def migration_2(conn: sqlite3.Connection) -> None:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        calls.append(("m2", version))

    def migration_3(conn: sqlite3.Connection) -> None:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        calls.append(("m3", version))

    monkeypatch.setattr(
        ledger, "_MIGRATIONS", [*ledger._MIGRATIONS, migration_2, migration_3]
    )

    with HistoryStore(db_file):
        pass
    assert calls == [("m2", 1), ("m3", 2)]
    assert _user_version(db_file) == 3

    with HistoryStore(db_file):
        pass
    assert calls == [("m2", 1), ("m3", 2)]
    assert _user_version(db_file) == 3
