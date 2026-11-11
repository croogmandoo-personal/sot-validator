"""Unit tests for Phase 2 gated SoT remediation executor, SQL generator, and rollback journal."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any
import pytest

from sot_validator.extraction import SnapshotStore, SqlExportSoTClient
from sot_validator.models import Site, ValidationClassification
from sot_validator.remediation import (
    ApprovalStatus,
    ManifestVerificationError,
    QuarantineGraduationStatus,
    QuarantineManifestEntry,
    QuarantinePolicy,
    RemediationApprovalManifest,
    RemediationExecutionError,
    RemediationExecutionResult,
    RemediationExecutor,
    RemediationOperation,
    RollbackJournal,
    RollbackJournalEntry,
    RollbackPlan,
    SqlRemediationScriptGenerator,
    SqlRemediationScripts,
)

SQL_SEED_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "sot_samples"
    / "sql"
    / "sot_schema_and_seed.sql"
)


def _create_seeded_sqlite_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    sql_script = SQL_SEED_PATH.read_text(encoding="utf-8")
    conn.executescript(sql_script)
    return conn


def _dump_all_tables(
    conn: sqlite3.Connection,
) -> dict[str, tuple[tuple[str, ...], list[dict[str, Any]]]]:
    """Capture complete schema column names and row dictionaries for every table in conn."""
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    table_names = [row[0] for row in cursor.fetchall()]
    snapshot: dict[str, tuple[tuple[str, ...], list[dict[str, Any]]]] = {}
    for table in table_names:
        col_cursor = conn.execute(f'PRAGMA table_info("{table}")')
        columns = tuple(row[1] for row in col_cursor.fetchall())
        pk_col = columns[0]
        row_cursor = conn.execute(
            f'SELECT * FROM "{table}" ORDER BY "{pk_col}"'
        )
        rows = [dict(zip(columns, r)) for r in row_cursor.fetchall()]
        snapshot[table] = (columns, rows)
    return snapshot


def _make_manifest_entry(
    item_type: str,
    item_id: str,
    *,
    site_id: str = "site-042",
    name: str | None = None,
    target_operation: RemediationOperation | None = None,
    approval_status: ApprovalStatus = ApprovalStatus.PENDING,
    graduation_status: QuarantineGraduationStatus = QuarantineGraduationStatus.ELIGIBLE,
    reviewed_by: str | None = None,
    review_note: str | None = None,
) -> QuarantineManifestEntry:
    return QuarantineManifestEntry(
        site_id=site_id,
        item_type=item_type,
        item_id=item_id,
        name=name or item_id,
        classification=ValidationClassification.STALE_LIKELY_UNUSED,
        confidence=0.95,
        consecutive_stale_runs=4,
        stale_duration_days=45.0,
        target_operation=target_operation,
        graduation_status=graduation_status,
        approval_status=approval_status,
        reviewed_by=reviewed_by,
        review_note=review_note,
    )


def _make_approved_seed_manifest() -> RemediationApprovalManifest:
    manifest = RemediationApprovalManifest(
        manifest_id="manifest-seed-042",
        policy=QuarantinePolicy(),
        generated_at=datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc),
        entries=[
            _make_manifest_entry(
                "Equipment",
                "eq-042-srv-legacy01",
                name="srv-legacy01.site042.example.internal",
                target_operation=RemediationOperation.FLAG_STALE_IN_SOT,
            ),
            _make_manifest_entry(
                "Equipment",
                "eq-042-vm-win02",
                name="win-print02.site042.example.internal",
                target_operation=RemediationOperation.DECOMMISSION_VM_RECORD,
            ),
            _make_manifest_entry(
                "NetworkDevice",
                "dev-042-sw02",
                name="sw02.site042.example.internal",
                target_operation=RemediationOperation.FLAG_STALE_IN_SOT,
            ),
            _make_manifest_entry(
                "IPAddress",
                "10.42.10.99",
                name="10.42.10.99",
                target_operation=RemediationOperation.RECLAIM_STALE_IP,
            ),
            _make_manifest_entry(
                "Port",
                "port-042-sw01-4",
                name="1:4",
                target_operation=RemediationOperation.PROPOSE_PORT_SHUTDOWN,
            ),
            _make_manifest_entry(
                "Equipment",
                "eq-042-ups01",
                name="ups01.site042.example.internal",
                target_operation=RemediationOperation.EXEMPT_PROTECTED,
                approval_status=ApprovalStatus.EXEMPT,
                graduation_status=QuarantineGraduationStatus.EXEMPT_PROTECTED,
            ),
        ],
    )
    manifest.approve_all(
        reviewer="netops-lead",
        note="Approved stale items for site-042 cleanup",
    )
    return manifest


def test_executor_rejects_tampered_manifest(tmp_path: Path) -> None:
    executor = RemediationExecutor(
        dry_run=True,
        journal=tmp_path / "remediation_journal.jsonl",
    )
    generator = SqlRemediationScriptGenerator()

    # 1. Tamper with an entry's approval_status without updating manifest_sha256
    manifest_status_tampered = _make_approved_seed_manifest()
    manifest_status_tampered.entries[0].approval_status = ApprovalStatus.PENDING
    assert manifest_status_tampered.verify_digest() is False

    with pytest.raises(ManifestVerificationError, match="SHA-256"):
        executor.execute(manifest_status_tampered)

    with pytest.raises(ManifestVerificationError, match="SHA-256"):
        generator.generate(manifest_status_tampered)

    # 2. Tamper with item_id after signing
    manifest_id_tampered = _make_approved_seed_manifest()
    manifest_id_tampered.entries[0].item_id = "eq-042-esx01"
    assert manifest_id_tampered.verify_digest() is False

    with pytest.raises(ManifestVerificationError, match="SHA-256"):
        executor.execute(
            manifest_id_tampered, dry_run=False, confirm_write=True
        )

    # 3. Tamper with manifest_sha256 directly
    manifest_bad_sig = _make_approved_seed_manifest()
    manifest_bad_sig.manifest_sha256 = "0" * 64
    with pytest.raises(ManifestVerificationError):
        executor.execute(manifest_bad_sig)

    # 4. Empty manifest_sha256
    manifest_empty_sig = _make_approved_seed_manifest()
    manifest_empty_sig.manifest_sha256 = ""
    with pytest.raises(ManifestVerificationError):
        executor.execute(manifest_empty_sig)

    # 5. Non-manifest object
    with pytest.raises(ManifestVerificationError):
        executor.execute({"not": "a_manifest"})  # type: ignore[arg-type]


def test_executor_rejects_unapproved_manifests_and_entries(
    tmp_path: Path,
) -> None:
    executor = RemediationExecutor(
        dry_run=True,
        journal=tmp_path / "remediation_journal.jsonl",
    )
    generator = SqlRemediationScriptGenerator()

    # 1. Manifest with only PENDING and EXEMPT entries (zero APPROVED entries)
    pending_manifest = RemediationApprovalManifest(
        entries=[
            _make_manifest_entry(
                "Equipment",
                "eq-042-srv-legacy01",
                approval_status=ApprovalStatus.PENDING,
            ),
            _make_manifest_entry(
                "Equipment",
                "eq-042-ups01",
                approval_status=ApprovalStatus.EXEMPT,
                graduation_status=QuarantineGraduationStatus.EXEMPT_PROTECTED,
                target_operation=RemediationOperation.EXEMPT_PROTECTED,
            ),
        ]
    )
    assert pending_manifest.verify_digest() is True

    with pytest.raises(RemediationExecutionError, match="no APPROVED entries"):
        executor.execute(pending_manifest)

    with pytest.raises(RemediationExecutionError, match="no APPROVED entries"):
        generator.generate(pending_manifest)

    # 2. Manifest with only REJECTED entries
    rejected_manifest = RemediationApprovalManifest(
        entries=[
            _make_manifest_entry(
                "Equipment",
                "eq-042-srv-legacy01",
                approval_status=ApprovalStatus.REJECTED,
                reviewed_by="secops",
            )
        ]
    )
    with pytest.raises(RemediationExecutionError, match="no APPROVED entries"):
        executor.execute(rejected_manifest, dry_run=False, confirm_write=True)

    # 3. Partially approved manifest rejected when strict_approval=True
    mixed_manifest = RemediationApprovalManifest(
        entries=[
            _make_manifest_entry(
                "Equipment",
                "eq-042-srv-legacy01",
                approval_status=ApprovalStatus.APPROVED,
                reviewed_by="netops",
            ),
            _make_manifest_entry(
                "Equipment",
                "eq-042-vm-win02",
                approval_status=ApprovalStatus.PENDING,
            ),
        ]
    )
    with pytest.raises(RemediationExecutionError, match="unapproved entries"):
        executor.execute(mixed_manifest, strict_approval=True)

    # Without strict_approval, only the APPROVED entry is executed and PENDING is skipped
    partial_res = executor.execute(mixed_manifest, strict_approval=False)
    assert len(partial_res.executed_entries) == 1
    assert partial_res.executed_entries[0].item_id == "eq-042-srv-legacy01"
    assert len(partial_res.skipped_entries) == 1
    assert partial_res.skipped_entries[0].item_id == "eq-042-vm-win02"

    # 4. execute_entry rejects PENDING, REJECTED, and EXEMPT entries
    for bad_status in (
        ApprovalStatus.PENDING,
        ApprovalStatus.REJECTED,
        ApprovalStatus.EXEMPT,
    ):
        unapproved_entry = _make_manifest_entry(
            "Equipment",
            "eq-042-srv-legacy01",
            approval_status=bad_status,
        )
        with pytest.raises(
            RemediationExecutionError, match="ApprovalStatus.APPROVED"
        ):
            executor.execute_entry(unapproved_entry)


def test_executor_enforces_dry_run_default_and_confirm_write_gate(
    tmp_path: Path,
) -> None:
    journal_file = tmp_path / "remediation_journal.jsonl"
    conn = _create_seeded_sqlite_conn()
    initial_db_state = _dump_all_tables(conn)
    manifest = _make_approved_seed_manifest()

    # 1. Default executor has dry_run=True and confirm_write=False
    default_executor = RemediationExecutor(journal=journal_file)
    assert default_executor.dry_run is True
    assert default_executor.confirm_write is False

    # Executing with default dry_run=True performs no writes to DB or journal
    dry_result = default_executor.execute(
        manifest,
        sqlite_conn=conn,
        execution_id="exec-dry-001",
    )
    assert dry_result.dry_run is True
    assert dry_result.applied_count == 5
    assert dry_result.skipped_count == 1
    assert not journal_file.exists()
    assert _dump_all_tables(conn) == initial_db_state

    # 2. Constructor rejects dry_run=False without confirm_write=True
    with pytest.raises(RemediationExecutionError, match="confirm_write=True"):
        RemediationExecutor(dry_run=False)

    with pytest.raises(RemediationExecutionError, match="confirm_write=True"):
        RemediationExecutor(dry_run=False, confirm_write=False)

    # 3. execute() rejects dry_run=False without confirm_write=True
    with pytest.raises(RemediationExecutionError, match="confirm_write=True"):
        default_executor.execute(manifest, dry_run=False)

    with pytest.raises(RemediationExecutionError, match="confirm_write=True"):
        default_executor.execute(manifest, dry_run=False, confirm_write=False)

    # Database and journal remain untouched after rejected write attempts
    assert not journal_file.exists()
    assert _dump_all_tables(conn) == initial_db_state
    conn.close()


def test_rollback_journal_append_only_jsonl_and_rollback_plan(
    tmp_path: Path,
) -> None:
    journal_file = tmp_path / "logs" / "remediation_journal.jsonl"
    journal = RollbackJournal(journal_file)
    conn = _create_seeded_sqlite_conn()

    executor = RemediationExecutor(
        dry_run=False,
        confirm_write=True,
        journal=journal,
    )

    # First execution: 1 equipment item
    manifest_1 = RemediationApprovalManifest(
        manifest_id="manifest-run-1",
        entries=[
            _make_manifest_entry(
                "Equipment",
                "eq-042-srv-legacy01",
                name="srv-legacy01.site042.example.internal",
                approval_status=ApprovalStatus.APPROVED,
                reviewed_by="alice",
            )
        ],
    )
    t1 = datetime(2026, 11, 11, 14, 0, tzinfo=timezone.utc)
    res_1 = executor.execute(
        manifest_1,
        sqlite_conn=conn,
        execution_id="exec-run-001",
        executed_at=t1,
    )
    assert res_1.dry_run is False
    assert journal_file.exists()

    # Second execution: 1 IP and 1 network device
    manifest_2 = RemediationApprovalManifest(
        manifest_id="manifest-run-2",
        entries=[
            _make_manifest_entry(
                "IPAddress",
                "ip-042-006",
                name="10.42.10.99",
                target_operation=RemediationOperation.RECLAIM_STALE_IP,
                approval_status=ApprovalStatus.APPROVED,
                reviewed_by="bob",
            ),
            _make_manifest_entry(
                "NetworkDevice",
                "dev-042-sw02",
                name="sw02.site042.example.internal",
                target_operation=RemediationOperation.FLAG_STALE_IN_SOT,
                approval_status=ApprovalStatus.APPROVED,
                reviewed_by="bob",
            ),
        ],
    )
    t2 = datetime(2026, 11, 11, 15, 0, tzinfo=timezone.utc)
    res_2 = executor.execute(
        manifest_2,
        sqlite_conn=conn,
        execution_id="exec-run-002",
        executed_at=t2,
    )
    assert res_2.dry_run is False

    # Verify raw JSONL file has 3 lines (append-only; run 1 was not overwritten by run 2)
    raw_lines = [
        line
        for line in journal_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(raw_lines) == 3

    for raw_line in raw_lines:
        parsed = json.loads(raw_line)
        for required_key in (
            "execution_id",
            "executed_at",
            "reviewer",
            "item_type",
            "item_id",
            "site_id",
            "operation",
            "pre_change_snapshot",
            "post_change_state",
            "rollback_sql",
        ):
            assert required_key in parsed

    all_entries = journal.read_entries()
    assert len(all_entries) == 3
    run1_entries = journal.read_entries(execution_id="exec-run-001")
    run2_entries = journal.read_entries(execution_id="exec-run-002")
    assert len(run1_entries) == 1
    assert len(run2_entries) == 2

    assert run1_entries[0].reviewer == "alice"
    assert run1_entries[0].executed_at == t1
    assert (
        run1_entries[0].pre_change_snapshot["hostname"]
        == "srv-legacy01.site042.example.internal"
    )
    assert run1_entries[0].post_change_state["status"] == "QUARANTINED_STALE"

    # Generate rollback plan for exec-run-002
    plan_2 = journal.generate_rollback_plan("exec-run-002")
    assert isinstance(plan_2, RollbackPlan)
    assert isinstance(plan_2, str)
    assert plan_2.execution_id == "exec-run-002"
    assert len(plan_2.entries) == 2
    assert plan_2.startswith("BEGIN TRANSACTION;\n")
    assert plan_2.strip().endswith("COMMIT;")

    # Unknown execution_id raises RemediationExecutionError
    with pytest.raises(RemediationExecutionError, match="No rollback journal"):
        journal.generate_rollback_plan("exec-does-not-exist")

    conn.close()


def test_sqlite_remediate_and_rollback_lossless_round_trip(
    tmp_path: Path,
) -> None:
    conn = _create_seeded_sqlite_conn()
    baseline_snapshot = _dump_all_tables(conn)

    manifest = _make_approved_seed_manifest()
    journal = RollbackJournal(tmp_path / "remediation_journal.jsonl")
    sql_dir = tmp_path / "sql_out"

    executor = RemediationExecutor(
        dry_run=False,
        confirm_write=True,
        journal=journal,
    )

    result = executor.execute(
        manifest,
        sqlite_conn=conn,
        sql_output_dir=sql_dir,
        execution_id="exec-seed-042",
    )

    assert isinstance(result, RemediationExecutionResult)
    assert result.execution_id == "exec-seed-042"
    assert result.dry_run is False
    assert result.remediate_sql_path == sql_dir / "remediate.sql"
    assert result.rollback_sql_path == sql_dir / "rollback.sql"
    assert result.remediate_sql_path.exists()
    assert result.rollback_sql_path.exists()

    # Verify forward SQL transaction wrapper
    assert result.remediate_sql.startswith("BEGIN TRANSACTION;\n")
    assert result.remediate_sql.strip().endswith("COMMIT;")
    assert result.rollback_sql.startswith("BEGIN TRANSACTION;\n")
    assert result.rollback_sql.strip().endswith("COMMIT;")

    # Verify post-remediation database state:
    # 1. Stale equipment items marked QUARANTINED_STALE; active/exempt items remain ACTIVE
    eq_rows = {
        row["equipment_id"]: dict(row)
        for row in conn.execute("SELECT * FROM equipment").fetchall()
    }
    assert eq_rows["eq-042-srv-legacy01"]["status"] == "QUARANTINED_STALE"
    assert eq_rows["eq-042-vm-win02"]["status"] == "QUARANTINED_STALE"
    assert eq_rows["eq-042-esx01"]["status"] == "ACTIVE"
    assert eq_rows["eq-042-vm-win01"]["status"] == "ACTIVE"
    assert eq_rows["eq-042-ups01"]["status"] == "ACTIVE"

    # 2. Stale network device marked QUARANTINED_STALE; core switch remains ACTIVE
    dev_rows = {
        row["device_id"]: dict(row)
        for row in conn.execute("SELECT * FROM network_devices").fetchall()
    }
    assert dev_rows["dev-042-sw02"]["status"] == "QUARANTINED_STALE"
    assert dev_rows["dev-042-sw01"]["status"] == "ACTIVE"

    # 3. Reclaimed IP marked AVAILABLE_RECLAIMED and unassigned; other IPs remain ACTIVE
    ip_rows = {
        row["ip_address"]: dict(row)
        for row in conn.execute("SELECT * FROM ip_arp_entries").fetchall()
    }
    assert ip_rows["10.42.10.99"]["status"] == "AVAILABLE_RECLAIMED"
    assert ip_rows["10.42.10.99"]["assigned_target_type"] == "unassigned"
    assert ip_rows["10.42.10.99"]["assigned_target_id"] == ""
    assert ip_rows["10.42.1.10"]["status"] == "ACTIVE"
    assert ip_rows["10.42.1.10"]["assigned_target_id"] == "dev-042-sw01"

    # 4. Shutdown port has admin_status='down' and status='QUARANTINED_STALE'
    port_rows = {
        row["port_id"]: dict(row)
        for row in conn.execute("SELECT * FROM ports").fetchall()
    }
    assert port_rows["port-042-sw01-4"]["admin_status"] == "down"
    assert port_rows["port-042-sw01-4"]["status"] == "QUARANTINED_STALE"
    assert port_rows["port-042-sw01-1"]["admin_status"] == "up"
    assert port_rows["port-042-sw01-1"]["status"] == "ACTIVE"

    # Now execute rollback via executor.rollback(execution_id, sqlite_conn=conn)
    rollback_plan = executor.rollback("exec-seed-042", sqlite_conn=conn)
    assert isinstance(rollback_plan, RollbackPlan)
    assert rollback_plan.execution_id == "exec-seed-042"

    # Verify 100% lossless round-trip across all tables, columns, and rows!
    restored_snapshot = _dump_all_tables(conn)
    assert restored_snapshot == baseline_snapshot

    conn.close()


def test_sql_script_generator_from_site_snapshots_and_snapshot_store_rollback(
    tmp_path: Path,
) -> None:
    # Load Site snapshot from the CSV seed fixture using SqlExportSoTClient
    csv_seed_dir = SQL_SEED_PATH.parent.parent / "csv"
    client = SqlExportSoTClient.from_csv_dir(csv_seed_dir)
    sites: list[Site] = client.list_sites()
    assert len(sites) == 1
    baseline_site_dict = sites[0].to_dict()

    # Save Site into SnapshotStore
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_site(sites[0])

    # Generate SQL scripts using Site snapshots (without passing sqlite_conn to generator)
    manifest = _make_approved_seed_manifest()
    generator = SqlRemediationScriptGenerator()
    scripts: SqlRemediationScripts = generator.generate(
        manifest,
        sites=sites,
        execution_id="exec-from-sites",
    )
    remediate_sql, rollback_sql = scripts
    assert "UPDATE equipment SET status = 'QUARANTINED_STALE'" in remediate_sql
    assert (
        "UPDATE ip_arp_entries SET status = 'AVAILABLE_RECLAIMED'"
        in remediate_sql
    )
    assert "UPDATE network_devices SET status = 'QUARANTINED_STALE'" in remediate_sql
    assert (
        "UPDATE ports SET admin_status = 'down', status = 'QUARANTINED_STALE'"
        in remediate_sql
    )

    # Execute generated remediate_sql and rollback_sql directly against SQLite seed DB
    conn = _create_seeded_sqlite_conn()
    baseline_db = _dump_all_tables(conn)
    conn.executescript(remediate_sql)
    assert _dump_all_tables(conn) != baseline_db
    conn.executescript(rollback_sql)
    assert _dump_all_tables(conn) == baseline_db
    conn.close()

    # Also verify SnapshotStore update and rollback via RemediationExecutor
    executor = RemediationExecutor(
        dry_run=False,
        confirm_write=True,
        journal=tmp_path / "remediation_journal.jsonl",
    )
    exec_res = executor.execute(
        manifest,
        snapshot_store=store,
        execution_id="exec-store-042",
    )
    assert exec_res.dry_run is False
    modified_site = store.load_site("site-042")
    assert modified_site.to_dict() != baseline_site_dict

    executor.rollback("exec-store-042", snapshot_store=store)
    restored_site = store.load_site("site-042")
    assert restored_site.to_dict() == baseline_site_dict
