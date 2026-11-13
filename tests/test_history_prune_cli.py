"""CLI tests for `sot-validator history-prune`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from sot_validator.cli import main
from sot_validator.history import HistoryStore
from sot_validator.models import ValidationClassification, ValidationResult

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
NOW = "2026-04-11T00:00:00Z"

SITE = """
[[sites]]
site_id = "SITE-001"
name = "HQ"
block = "10.1.0.0/16"
active_subnets = ["10.1.10.0/24"]
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _config(tmp_path: Path, retention: str = "[retention]\nmax_age_days = 30\n") -> Path:
    path = tmp_path / "fleet.toml"
    path.write_text(retention + SITE, encoding="utf-8")
    return path


def _history_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "history.db"
    with HistoryStore(db_path) as store:
        for index, day in enumerate([0, 10, 20, 80, 95]):
            classification = (
                ValidationClassification.CONFIRMED_ACTIVE
                if index % 2 == 0
                else ValidationClassification.STALE_LIKELY_UNUSED
            )
            store.record_run(
                [
                    ValidationResult(
                        item_type="IPAddress",
                        item_id="ip-1",
                        site_id="SITE-001",
                        name="ip-1",
                        classification=classification,
                        confidence=0.9,
                        rationale="test",
                    )
                ],
                run_id=f"r{index + 1}",
                recorded_at=T0 + timedelta(days=day),
            )
    return db_path


def _prune(capsys, *args: str) -> tuple[int, str, str]:
    rc = main(["history-prune", *args])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _assert_single_error_line(err: str) -> None:
    lines = err.strip().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("error: ")
    assert "Traceback" not in err


def test_dry_run_prints_report_and_leaves_file_unchanged(tmp_path, capsys):
    db_path = _history_db(tmp_path)
    config = _config(tmp_path)
    before = _sha256(db_path)

    rc, out, err = _prune(capsys, "--config", str(config), "--db-path", str(db_path), "--now", NOW)

    assert rc == 0
    assert err == ""
    report = json.loads(out)
    assert report["dry_run"] is True
    assert report["run_ids"] == ["r1", "r2", "r3"]
    assert report["run_count"] == 3
    assert report["drift_event_count"] == 2
    assert report["policy"] == {"max_age_days": 30, "max_runs_per_site": None}
    assert report["now"] == "2026-04-11T00:00:00+00:00"
    assert report["age_cutoff"] == "2026-03-12T00:00:00+00:00"
    assert _sha256(db_path) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fleet.toml", "history.db"]


def test_apply_deletes_the_reported_runs(tmp_path, capsys):
    db_path = _history_db(tmp_path)
    config = _config(tmp_path, "[retention]\nmax_age_days = 30\nmax_runs_per_site = 4\n")
    base = ["--config", str(config), "--db-path", str(db_path), "--now", NOW]

    rc, out, _ = _prune(capsys, *base)
    assert rc == 0
    dry = json.loads(out)
    rc, out, err = _prune(capsys, *base, "--apply")
    assert rc == 0
    assert err == ""
    applied = json.loads(out)

    assert applied["dry_run"] is False
    assert applied["run_ids"] == dry["run_ids"] == ["r1", "r2", "r3"]
    assert applied["drift_event_count"] == dry["drift_event_count"]

    summary_path = tmp_path / "out" / "summary.json"
    assert main(["history", "--db-path", str(db_path), "--drift-output", str(summary_path)]) == 0
    listed = json.loads(summary_path.read_text(encoding="utf-8"))
    assert [run["run_id"] for run in listed["runs"]] == ["r4", "r5"]

    rc, out, _ = _prune(capsys, *base, "--apply")
    assert rc == 0
    assert json.loads(out)["run_ids"] == []


def test_config_without_retention_prunes_nothing(tmp_path, capsys):
    db_path = _history_db(tmp_path)
    config = _config(tmp_path, "")
    rc, out, _ = _prune(capsys, "--config", str(config), "--db-path", str(db_path), "--apply")
    assert rc == 0
    report = json.loads(out)
    assert report["run_ids"] == []
    assert report["policy"] == {"max_age_days": None, "max_runs_per_site": None}


@pytest.mark.parametrize(
    "retention",
    [
        "[retention]\nmax_age_days = true\n",
        "[retention]\nkeep = 1\n",
        "retention = 3\n",
        "[retention]\nmax_runs_per_site = 0\n",
    ],
)
def test_bad_config_exits_2(tmp_path, capsys, retention):
    db_path = _history_db(tmp_path)
    before = _sha256(db_path)
    config = _config(tmp_path, retention)
    rc, out, err = _prune(capsys, "--config", str(config), "--db-path", str(db_path), "--apply")
    assert rc == 2
    assert out == ""
    _assert_single_error_line(err)
    assert "[retention]" in err or "[root] retention" in err
    assert _sha256(db_path) == before


def test_missing_config_file_exits_2(tmp_path, capsys):
    db_path = _history_db(tmp_path)
    rc, _, err = _prune(capsys, "--config", str(tmp_path / "nope.toml"), "--db-path", str(db_path))
    assert rc == 2
    _assert_single_error_line(err)


def test_json_db_path_exits_2_without_touching_files(tmp_path, capsys):
    config = _config(tmp_path)
    json_path = tmp_path / "h.json"
    rc, out, err = _prune(capsys, "--config", str(config), "--db-path", str(json_path), "--apply")
    assert rc == 2
    assert out == ""
    _assert_single_error_line(err)
    assert "JSON history files are not supported" in err
    assert not json_path.exists()

    json_path.write_text('{"runs": [], "streaks": [], "drift_events": []}', encoding="utf-8")
    before = _sha256(json_path)
    rc, _, err = _prune(capsys, "--config", str(config), "--db-path", str(json_path), "--apply")
    assert rc == 2
    _assert_single_error_line(err)
    assert _sha256(json_path) == before


def test_missing_db_path_exits_2_and_is_not_created(tmp_path, capsys):
    config = _config(tmp_path)
    missing = tmp_path / "sub" / "missing.db"
    rc, out, err = _prune(capsys, "--config", str(config), "--db-path", str(missing), "--apply")
    assert rc == 2
    assert out == ""
    _assert_single_error_line(err)
    assert "does not exist" in err
    assert not missing.exists()
    assert not missing.parent.exists()


def test_newer_schema_version_exits_2(tmp_path, capsys):
    db_path = _history_db(tmp_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA user_version = 99")
    conn.close()
    before = _sha256(db_path)
    rc, _, err = _prune(capsys, "--config", str(_config(tmp_path)), "--db-path", str(db_path), "--apply")
    assert rc == 2
    _assert_single_error_line(err)
    assert "schema version 99" in err
    assert _sha256(db_path) == before


def test_non_sqlite_file_and_bad_now_exit_2(tmp_path, capsys):
    config = _config(tmp_path)
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database" * 100)
    before = _sha256(junk)
    rc, _, err = _prune(capsys, "--config", str(config), "--db-path", str(junk), "--apply")
    assert rc == 2
    _assert_single_error_line(err)
    assert _sha256(junk) == before

    db_path = _history_db(tmp_path)
    before = _sha256(db_path)
    rc, _, err = _prune(capsys, "--config", str(config), "--db-path", str(db_path), "--now", "yesterday", "--apply")
    assert rc == 2
    _assert_single_error_line(err)
    assert _sha256(db_path) == before
