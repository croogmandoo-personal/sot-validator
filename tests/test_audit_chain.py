"""Tests for the SHA-256 hash-chained, append-only curation audit log."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import threading

import pytest

from sot_validator.curation import (
    AuditChainReport,
    AuditLogEntry,
    CurationStore,
    GENESIS_HASH,
    ItemEditPatch,
    verify_audit_chain,
)
from sot_validator.models import NetworkDevice, Site
from sot_validator.workbench.server import WorkbenchState

STORE_PY = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "curation" / "store.py"

LEGACY_AUDIT_DDL = """
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    changes_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    site_id TEXT
);
"""


def _expected_hash(entry: AuditLogEntry) -> str:
    payload = entry.to_dict()
    payload.pop("entry_hash")
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(entry.prev_hash.encode("ascii") + canonical).hexdigest()


def _device(device_id: str = "dev-01", site_id: str = "site-1") -> NetworkDevice:
    return NetworkDevice(
        device_id=device_id,
        site_id=site_id,
        hostname=f"{device_id}.local",
        management_ip="10.1.1.2",
    )


def _populated_store(path: Path, n_patches: int = 3) -> CurationStore:
    store = CurationStore(path)
    store.add_custom_device(_device(), actor="alice", reason="new switch")
    for i in range(n_patches):
        store.upsert_patch(
            ItemEditPatch(
                target_type="NetworkDevice",
                target_id="dev-01",
                notes=f"note {i} — ünïcode",
            ),
            actor="bob",
        )
    store.delete_item("Equipment", "eq-9", actor="carol", site_id="site-1")
    return store


def _raw(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def _build_legacy_db(path: Path, n_rows: int) -> list[str]:
    conn = sqlite3.connect(str(path))
    conn.executescript(LEGACY_AUDIT_DDL)
    entry_ids = []
    for i in range(n_rows):
        entry_id = f"audit-{i + 1:04d}-legacy{i}"
        entry_ids.append(entry_id)
        conn.execute(
            """
            INSERT INTO audit_log (
                entry_id, timestamp, actor, action, target_type, target_id,
                changes_json, reason, site_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_id,
                f"2024-01-0{i + 1}T10:00:00+00:00",
                f"actor-{i}",
                "UPSERT_PATCH",
                "NetworkDevice",
                f"dev-{i}",
                json.dumps({"notes": f"legacy {i}"}),
                "",
                None,
            ),
        )
    conn.commit()
    conn.close()
    return entry_ids


def _legacy_json_state(n_entries: int = 2) -> dict:
    return {
        "patches": [],
        "custom_devices": [],
        "custom_equipment": [],
        "custom_vlans": [],
        "custom_subnets": [],
        "custom_ports": [],
        "audit_log": [
            {
                "entry_id": f"audit-{i + 1:04d}-json{i}",
                "timestamp": f"2024-02-0{i + 1}T08:30:00+00:00",
                "actor": "legacy",
                "action": "ADD_DEVICE",
                "target_type": "NetworkDevice",
                "target_id": f"dev-{i}",
                "changes": {"hostname": f"h{i}"},
                "reason": "",
                "site_id": "site-1",
            }
            for i in range(n_entries)
        ],
    }


class TestAppendAndVerify:
    def test_chain_links_and_hashes(self, tmp_path: Path) -> None:
        store = _populated_store(tmp_path / "c.db")
        entries = store.list_audit_log(limit=1000)
        assert len(entries) == 5
        assert entries[0].prev_hash == GENESIS_HASH
        for prev, cur in zip(entries, entries[1:]):
            assert cur.prev_hash == prev.entry_hash
        for entry in entries:
            assert entry.entry_hash == _expected_hash(entry)

        report = verify_audit_chain(store)
        assert report == AuditChainReport(
            ok=True, entries_checked=5, broken_index=None, reason=None
        )
        assert store.export_chain_head() == (5, entries[-1].entry_hash)

    def test_returned_entry_matches_stored_row(self, tmp_path: Path) -> None:
        store = CurationStore(tmp_path / "c.db")
        returned = store.add_custom_device(_device())
        assert returned.prev_hash == GENESIS_HASH
        assert returned.entry_hash == _expected_hash(returned)
        assert store.list_audit_log() == [returned]

    def test_fresh_store_head_is_genesis(self, tmp_path: Path) -> None:
        assert CurationStore(tmp_path / "e.db").export_chain_head() == (0, "0" * 64)
        assert CurationStore().export_chain_head() == (0, GENESIS_HASH)
        assert verify_audit_chain(CurationStore()) == AuditChainReport(
            ok=True, entries_checked=0
        )

    def test_failed_write_rolls_back(self, tmp_path: Path) -> None:
        store = _populated_store(tmp_path / "c.db")
        before = store.to_dict()
        with pytest.raises(RuntimeError):
            with store._write_transaction():
                store._record_audit(
                    actor="x", action="A", target_type="Port", target_id="p", changes={}
                )
                raise RuntimeError("boom")
        assert store.to_dict() == before
        assert verify_audit_chain(store).ok


class TestTamperDetection:
    def test_modified_middle_field(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        with _raw(path) as conn:
            conn.execute("UPDATE audit_log SET reason='x' WHERE seq=2")
        report = verify_audit_chain(store)
        assert (report.ok, report.reason, report.broken_index) == (
            False,
            "hash_mismatch",
            1,
        )
        assert report.entries_checked == 1

    def test_modified_changes_json(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        with _raw(path) as conn:
            conn.execute(
                "UPDATE audit_log SET changes_json = ? WHERE seq=3",
                (json.dumps({"notes": "forged"}),),
            )
        report = verify_audit_chain(store)
        assert (report.reason, report.broken_index) == ("hash_mismatch", 2)

    def test_nulled_hash_is_mismatch(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        with _raw(path) as conn:
            conn.execute("UPDATE audit_log SET entry_hash = NULL WHERE seq=4")
        report = verify_audit_chain(store)
        assert (report.reason, report.broken_index) == ("hash_mismatch", 3)

    def test_deleted_middle_row_is_gap(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        with _raw(path) as conn:
            conn.execute("DELETE FROM audit_log WHERE seq=3")
        report = verify_audit_chain(store)
        assert (report.ok, report.reason, report.broken_index) == (False, "gap", 2)

    def test_deleted_first_row_is_gap(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        with _raw(path) as conn:
            conn.execute("DELETE FROM audit_log WHERE seq=1")
        report = verify_audit_chain(store)
        assert (report.ok, report.reason, report.broken_index) == (False, "gap", 0)

    def test_swapped_rows_is_prev_link_broken(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        with _raw(path) as conn:
            conn.execute("UPDATE audit_log SET seq=-1 WHERE seq=2")
            conn.execute("UPDATE audit_log SET seq=2 WHERE seq=3")
            conn.execute("UPDATE audit_log SET seq=3 WHERE seq=-1")
        report = verify_audit_chain(store)
        assert (report.ok, report.reason, report.broken_index) == (
            False,
            "prev_link_broken",
            1,
        )

    def test_swapped_first_rows_is_prev_link_broken(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        with _raw(path) as conn:
            conn.execute("UPDATE audit_log SET seq=-1 WHERE seq=1")
            conn.execute("UPDATE audit_log SET seq=1 WHERE seq=2")
            conn.execute("UPDATE audit_log SET seq=2 WHERE seq=-1")
        report = verify_audit_chain(store)
        assert (report.reason, report.broken_index) == ("prev_link_broken", 0)


class TestAnchor:
    def _forge_last_reason(self, path: Path) -> None:
        conn = _raw(path)
        row = conn.execute(
            "SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        forged = AuditLogEntry.from_dict(
            {
                **CurationStore._row_to_audit_entry(row).to_dict(),
                "reason": "forged",
                "entry_hash": None,
            }
        )
        conn.execute(
            "UPDATE audit_log SET reason = ?, entry_hash = ? WHERE seq = ?",
            ("forged", _expected_hash(forged), row["seq"]),
        )
        conn.commit()
        conn.close()

    def test_forged_head_detected_only_with_anchor(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        anchor = store.export_chain_head()
        self._forge_last_reason(path)
        assert verify_audit_chain(store).ok is True
        report = verify_audit_chain(store, anchor=anchor)
        assert (report.ok, report.reason, report.broken_index) == (
            False,
            "anchor_mismatch",
            anchor[0] - 1,
        )

    def test_truncated_log_fails_anchor(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = _populated_store(path)
        anchor = store.export_chain_head()
        with _raw(path) as conn:
            conn.execute("DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log)")
        assert verify_audit_chain(store).ok is True
        report = verify_audit_chain(store, anchor=anchor)
        assert (report.ok, report.reason, report.broken_index) == (
            False,
            "anchor_mismatch",
            anchor[0] - 1,
        )

    def test_growth_after_anchor_passes(self, tmp_path: Path) -> None:
        store = _populated_store(tmp_path / "c.db")
        anchor = store.export_chain_head()
        store.add_custom_device(_device("dev-02"))
        report = verify_audit_chain(store, anchor=anchor)
        assert report.ok is True
        assert report.entries_checked == anchor[0] + 1
        assert verify_audit_chain(store, anchor=(0, GENESIS_HASH)).ok is True

    @pytest.mark.parametrize(
        "anchor",
        [
            (-1, GENESIS_HASH),
            (True, GENESIS_HASH),
            ("1", GENESIS_HASH),
            (1, "abc"),
            (1, "A" * 64),
            (1, GENESIS_HASH + "\n"),
            (0, "f" * 64),
            (1,),
            "0" * 64,
        ],
    )
    def test_malformed_anchor_raises(self, anchor: object) -> None:
        with pytest.raises(ValueError):
            verify_audit_chain(CurationStore(), anchor=anchor)  # type: ignore[arg-type]


class TestLegacySqliteMigration:
    def test_migrates_in_place_with_marker(self, tmp_path: Path) -> None:
        path = tmp_path / "legacy.db"
        entry_ids = _build_legacy_db(path, 3)
        store = CurationStore(path)

        columns = {
            r[1] for r in store._conn.execute("PRAGMA table_info(audit_log)").fetchall()
        }
        assert {"prev_hash", "entry_hash"} <= columns

        entries = store.list_audit_log(limit=100)
        assert len(entries) == 4
        assert [e.entry_id for e in entries[:3]] == entry_ids
        assert [e.actor for e in entries[:3]] == ["actor-0", "actor-1", "actor-2"]
        assert all(e.action == "UPSERT_PATCH" for e in entries[:3])
        marker = entries[3]
        assert marker.action == "migration"
        assert marker.actor == "system"
        assert marker.target_type == "AuditLog"
        assert marker.target_id == "audit_log"
        assert marker.site_id is None
        assert marker.changes == {
            "legacy_entries": 3,
            "legacy_head_hash": entries[2].entry_hash,
            "source": "sqlite",
        }
        assert "not attested" in marker.reason

        report = verify_audit_chain(store)
        assert (report.ok, report.entries_checked) == (True, 4)
        head = store.export_chain_head()
        store.close()

        reopened = CurationStore(path)
        assert reopened.export_chain_head() == head
        assert [e.action for e in reopened.list_audit_log()].count("migration") == 1
        reopened.add_custom_device(_device())
        assert verify_audit_chain(reopened).entries_checked == 5

    def test_empty_legacy_log_gets_columns_but_no_marker(self, tmp_path: Path) -> None:
        path = tmp_path / "legacy-empty.db"
        _build_legacy_db(path, 0)
        store = CurationStore(path)
        columns = {
            r[1] for r in store._conn.execute("PRAGMA table_info(audit_log)").fetchall()
        }
        assert {"prev_hash", "entry_hash"} <= columns
        assert store.export_chain_head() == (0, GENESIS_HASH)
        assert store.list_audit_log() == []

    def test_legacy_seq_gaps_are_not_breaks(self, tmp_path: Path) -> None:
        path = tmp_path / "legacy-gaps.db"
        _build_legacy_db(path, 4)
        with _raw(path) as conn:
            conn.execute("DELETE FROM audit_log WHERE seq=2")
        store = CurationStore(path)
        report = verify_audit_chain(store)
        assert (report.ok, report.entries_checked) == (True, 4)


class TestJsonImport:
    def test_legacy_json_is_chained_with_marker(self) -> None:
        store = CurationStore.from_dict(_legacy_json_state(2))
        entries = store.list_audit_log()
        assert [e.entry_id for e in entries[:2]] == ["audit-0001-json0", "audit-0002-json1"]
        marker = entries[2]
        assert marker.action == "migration"
        assert marker.changes["source"] == "json"
        assert marker.changes["legacy_entries"] == 2
        assert marker.changes["legacy_head_hash"] == entries[1].entry_hash
        assert verify_audit_chain(store) == AuditChainReport(ok=True, entries_checked=3)

    def test_empty_legacy_json_adds_no_marker(self) -> None:
        store = CurationStore.from_dict(_legacy_json_state(0))
        assert store.export_chain_head() == (0, GENESIS_HASH)

    def test_edited_hashed_export_is_rejected(self, tmp_path: Path) -> None:
        exported = _populated_store(tmp_path / "c.db").to_dict()
        exported["audit_log"][1]["reason"] = "edited after export"
        target = CurationStore()
        with pytest.raises(ValueError):
            target._load_state_from_mapping(exported)
        assert target.to_dict()["audit_log"] == []
        assert target.to_dict()["custom_devices"] == []

    def test_dropped_entry_in_hashed_export_is_rejected(self, tmp_path: Path) -> None:
        exported = _populated_store(tmp_path / "c.db").to_dict()
        del exported["audit_log"][2]
        with pytest.raises(ValueError):
            CurationStore.from_dict(exported)

    def test_mixed_hashed_and_unhashed_is_rejected(self, tmp_path: Path) -> None:
        exported = _populated_store(tmp_path / "c.db").to_dict()
        exported["audit_log"].append(_legacy_json_state(1)["audit_log"][0])
        with pytest.raises(ValueError):
            CurationStore.from_dict(exported)

    def test_half_hashed_entry_is_rejected(self, tmp_path: Path) -> None:
        exported = _populated_store(tmp_path / "c.db").to_dict()
        exported["audit_log"][0]["entry_hash"] = None
        with pytest.raises(ValueError):
            CurationStore.from_dict(exported)

    def test_round_trip_is_exact(self, tmp_path: Path) -> None:
        store = _populated_store(tmp_path / "c.db")
        out = store.export_json(tmp_path / "export.json")
        imported = CurationStore.import_json(out)
        assert imported.to_dict() == store.to_dict()
        assert all(e["entry_hash"] for e in imported.to_dict()["audit_log"])
        assert "migration" not in [e.action for e in imported.list_audit_log()]
        assert verify_audit_chain(imported).ok is True
        assert imported.export_chain_head() == store.export_chain_head()

    def test_import_into_non_empty_store_is_refused(self, tmp_path: Path) -> None:
        store = _populated_store(tmp_path / "c.db")
        out = store.export_json(tmp_path / "export.json")
        target = CurationStore(tmp_path / "target.db")
        target.upsert_patch(ItemEditPatch(target_type="Port", target_id="p-1", notes="n"))
        before = target.to_dict()

        with pytest.raises(ValueError):
            target.import_json(out)
        assert target.to_dict() == before
        with pytest.raises(ValueError):
            target._load_state_from_mapping(_legacy_json_state(2))
        assert target.to_dict() == before
        with pytest.raises(ValueError):
            target._load_state_from_mapping(_legacy_json_state(0))
        assert target.to_dict() == before
        assert verify_audit_chain(target).ok is True


class TestConcurrency:
    def test_two_writers_share_one_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "shared.db"
        stores = [
            CurationStore(path),
            CurationStore(path),
        ]
        for s in stores:
            s._conn.close()
            s._conn = sqlite3.connect(str(path), check_same_thread=False)
            s._conn.row_factory = sqlite3.Row
        per_writer = 25
        errors: list[BaseException] = []
        barrier = threading.Barrier(2)

        def worker(idx: int) -> None:
            try:
                barrier.wait()
                for i in range(per_writer):
                    stores[idx].upsert_patch(
                        ItemEditPatch(
                            target_type="NetworkDevice",
                            target_id=f"dev-{idx}-{i}",
                            notes=f"writer {idx}",
                        ),
                        actor=f"writer-{idx}",
                    )
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []

        fresh = CurationStore(path)
        entries = fresh.list_audit_log(limit=1000)
        assert len(entries) == 2 * per_writer
        assert len({e.entry_id for e in entries}) == 2 * per_writer
        assert verify_audit_chain(fresh) == AuditChainReport(
            ok=True, entries_checked=2 * per_writer
        )


class TestNoBackfillRewrite:
    def test_site_backfill_no_longer_rewrites_rows(self, tmp_path: Path) -> None:
        path = tmp_path / "c.db"
        store = CurationStore(path)
        first = store.upsert_patch(
            ItemEditPatch(target_type="NetworkDevice", target_id="dev-x", notes="a")
        )
        assert first.site_id is None
        store.upsert_patch(
            ItemEditPatch(
                target_type="NetworkDevice", target_id="dev-x", site_id="site-9"
            )
        )
        with _raw(path) as conn:
            row = conn.execute("SELECT * FROM audit_log WHERE seq=1").fetchone()
        assert row["site_id"] is None
        assert row["entry_hash"] == first.entry_hash
        assert verify_audit_chain(store).ok is True
        assert [e.entry_id for e in store.list_audit_log(site_id="site-9")] == [
            e.entry_id for e in store.list_audit_log()
        ]
        assert len(store.list_audit_log(site_id="site-9")) == 2

    def test_only_migration_updates_audit_rows(self) -> None:
        lines = [
            line
            for line in STORE_PY.read_text(encoding="utf-8").splitlines()
            if "UPDATE audit_log" in line or "DELETE FROM audit_log" in line
        ]
        assert len(lines) == 1
        assert "SET prev_hash = ?, entry_hash = ?" in lines[0]
        assert "entry_hash IS NULL" in lines[0]


class TestMarkerAndFieldValidation:
    def test_marker_entry_constructs(self) -> None:
        entry = AuditLogEntry(
            action="migration",
            target_type="AuditLog",
            target_id="audit_log",
            actor="system",
        )
        assert entry.target_type == "AuditLog"

    def test_patch_cannot_target_audit_log(self) -> None:
        with pytest.raises(ValueError):
            ItemEditPatch(target_type="AuditLog", target_id="x")

    @pytest.mark.parametrize(
        "bad", ["abc", "A" * 64, "g" * 64, "0" * 63, "0" * 64 + "\n", 123, b"0" * 64]
    )
    def test_bad_hash_values_rejected(self, bad: object) -> None:
        with pytest.raises(ValueError):
            AuditLogEntry(
                action="X", target_type="Port", target_id="p", entry_hash=bad  # type: ignore[arg-type]
            )
        with pytest.raises(ValueError):
            AuditLogEntry(
                action="X", target_type="Port", target_id="p", prev_hash=bad  # type: ignore[arg-type]
            )

    def test_hash_fields_round_trip_dict_and_json(self) -> None:
        entry = AuditLogEntry(
            action="X",
            target_type="Port",
            target_id="p",
            prev_hash=GENESIS_HASH,
            entry_hash="a" * 64,
        )
        assert entry.to_dict()["prev_hash"] == GENESIS_HASH
        assert AuditLogEntry.from_json(entry.to_json()) == entry
        legacy = entry.to_dict()
        del legacy["prev_hash"], legacy["entry_hash"]
        rebuilt = AuditLogEntry.from_dict(legacy)
        assert rebuilt.prev_hash is None and rebuilt.entry_hash is None


class TestWorkbenchConnectionSwap:
    def test_in_memory_store_survives_workbench_swap(self) -> None:
        store = CurationStore()
        store.add_custom_device(_device())
        store.delete_item("Port", "p-1")
        head = store.export_chain_head()
        site = Site(site_id="site-1", name="Site 1")
        state = WorkbenchState(site, store=store)
        assert state.store.export_chain_head() == head
        assert verify_audit_chain(state.store).ok is True
        state.store.upsert_patch(ItemEditPatch(target_type="Port", target_id="p-2"))
        assert verify_audit_chain(state.store).entries_checked == 3
