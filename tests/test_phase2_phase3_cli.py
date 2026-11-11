"""End-to-end unit and integration tests for the Interactive HTML5 Operations Dashboard and Phase 2/3 CLI subcommands."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import sot_validator
from sot_validator import (
    ALL_DISCREPANCY_TYPES,
    DISCREPANCY_CSV_COLUMNS,
    ONBOARDING_CSV_COLUMNS,
    VALID_DISCREPANCY_SOURCES,
    AlertEvent,
    AlertSeverity,
    AlertSink,
    AlertType,
    ApprovalStatus,
    CampaignConfig,
    CampaignOrchestrator,
    CampaignRunSummary,
    CircuitBreakerTrippedError,
    DiscrepancyRecord,
    DiscrepancyType,
    DriftEvent,
    DriftTransitionType,
    HistoryStore,
    HtmlDashboardGenerator,
    InMemoryAlertSink,
    InventoryReconciler,
    ItemStreakSummary,
    JsonFileAlertSink,
    ManifestVerificationError,
    QuarantineEngine,
    QuarantineGraduationStatus,
    QuarantineManifestEntry,
    QuarantinePolicy,
    ReconciliationReport,
    RemediationApprovalManifest,
    RemediationExecutionError,
    RemediationExecutionResult,
    RemediationExecutor,
    RemediationOperation,
    RollbackJournal,
    RollbackJournalEntry,
    RollbackPlan,
    SiteWaveResult,
    SiteWaveStatus,
    SqlRemediationScriptGenerator,
    SqlRemediationScripts,
    SubnetUtilizationSummary,
    ValidationClassification,
    ValidationResult,
    ValidationRunRecord,
    ValidationSignal,
    WebhookPayloadFormatter,
    generate_all_reports,
    generate_html_dashboard,
)
from sot_validator.cli import main
from sot_validator.extraction import FixtureSoTClient
from sot_validator.models import SignalStatus, SignalType


def test_html_dashboard_generator_sections_airgapped_and_xss_escaping(
    tmp_path: Path,
) -> None:
    sites = FixtureSoTClient(num_sites=1).list_sites()
    eval_dt = datetime(2026, 2, 12, 12, 0, 0, tzinfo=timezone.utc)

    xss_payload = '<script>alert("xss")</script><img src=x onerror=alert(1)>'
    results = [
        ValidationResult(
            item_type="Equipment",
            item_id="site-001-vm-win-01",
            site_id="site-001",
            name=f"win-srv-001-01 {xss_payload}",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
            signals=[
                ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.ACTIVE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details=f"poweredOn; toolsOk {xss_payload}",
                    source="vcenter",
                )
            ],
            rationale=f"Active Windows VM {xss_payload}",
            evaluated_at=eval_dt,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="site-001-srv-01",
            site_id="site-001",
            name="legacy-srv-001-01",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.90,
            signals=[
                ValidationSignal(
                    signal_type=SignalType.PORT_STATE,
                    status=SignalStatus.INACTIVE,
                    observed_at=eval_dt,
                    age_seconds=7776000.0,
                    details="Port down > 90d",
                    source="sot.port",
                )
            ],
            rationale="Stale server candidate.",
            evaluated_at=eval_dt,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="site-001-san-01",
            site_id="site-001",
            name="san-array-001-01",
            classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
            confidence=0.55,
            signals=[],
            rationale="Unreachable SAN array.",
            evaluated_at=eval_dt,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="site-001-spare-01",
            site_id="site-001",
            name="spare-chassis-001-01",
            classification=ValidationClassification.INSUFFICIENT_DATA,
            confidence=0.0,
            signals=[],
            rationale="No signals available.",
            evaluated_at=eval_dt,
        ),
    ]

    manifest = RemediationApprovalManifest(
        manifest_id="manifest-test-001",
        generated_at=eval_dt,
        entries=[
            QuarantineManifestEntry(
                site_id="site-001",
                item_type="Equipment",
                item_id="site-001-srv-01",
                name="legacy-srv-001-01",
                classification=ValidationClassification.STALE_LIKELY_UNUSED,
                confidence=0.90,
                consecutive_stale_runs=4,
                stale_duration_days=45.0,
                target_operation=RemediationOperation.FLAG_STALE_IN_SOT,
                graduation_status=QuarantineGraduationStatus.ELIGIBLE,
                approval_status=ApprovalStatus.APPROVED,
                reviewed_by="secops-reviewer",
                review_note=f"Approved after streak review {xss_payload}",
            )
        ],
    )

    reconciliation = ReconciliationReport(
        generated_at=eval_dt,
        discrepancies=[
            DiscrepancyRecord(
                discrepancy_id="disc-site-001-untracked-vm-0001",
                discrepancy_type=DiscrepancyType.UNTRACKED_VM,
                site_id="site-001",
                observed_identifier="vm-9999",
                observed_ip="10.1.10.250",
                observed_mac="00:50:56:aa:bb:cc",
                observed_hostname=f"shadow-vm-01 {xss_payload}",
                source="vcenter",
                details=f"Untracked VM {xss_payload}",
                recommended_onboarding_action="Insert into SoT equipment table",
            )
        ],
    )

    out_path = tmp_path / "validation_dashboard.html"
    gen = HtmlDashboardGenerator()
    written = gen.write(
        results,
        out_path,
        sites=sites,
        approval_manifest=manifest,
        reconciliation_report=reconciliation,
        generated_at=eval_dt,
        title=f"Ops Dashboard {xss_payload}",
    )
    assert written == out_path
    assert out_path.exists()

    html_text = out_path.read_text(encoding="utf-8")
    assert html_text.startswith("<!DOCTYPE html>")

    # Verify zero external HTTP/HTTPS CDN dependencies in script/link/style or anywhere
    assert not re.search(r"https?://", html_text, flags=re.IGNORECASE)
    assert "<script src=" not in html_text.lower()
    assert "<link " not in html_text.lower()

    # Verify XSS payload is strictly HTML-escaped and never appears raw
    assert xss_payload not in html_text
    assert '<script>alert("xss")</script>' not in html_text
    assert "<img src=x onerror=alert(1)>" not in html_text
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html_text

    # Verify KPI summary cards
    for kpi_label in (
        "Total Evaluated",
        "Confirmed Active",
        "Stale / Likely Unused",
        "Unreachable / Needs Manual Review",
        "Insufficient Data",
        "Quarantine Eligible",
        "Untracked Discrepancies",
    ):
        assert kpi_label in html_text
    assert 'data-kpi="total-evaluated">4<' in html_text
    assert 'data-kpi="quarantine-eligible">1<' in html_text
    assert 'data-kpi="untracked-discrepancies">1<' in html_text

    # Verify /24 subnet utilization table and interactive controls
    assert "subnet-utilization-table" in html_text
    assert "10.1.10.0/24" in html_text
    assert 'id="filter-classification"' in html_text
    assert 'id="filter-site"' in html_text
    assert 'id="filter-type"' in html_text
    assert 'id="filter-search"' in html_text

    # Verify Phase 2 Quarantine & Remediation queue section
    assert "manifest-test-001" in html_text
    assert manifest.manifest_sha256 in html_text
    assert "FLAG_STALE_IN_SOT" in html_text
    assert "APPROVED" in html_text

    # Verify Phase 3 Reverse Discovery section
    for dtype in ALL_DISCREPANCY_TYPES:
        assert dtype.value in html_text
    assert "disc-site-001-untracked-vm-0001" in html_text
    assert "10.1.10.250" in html_text

    # Verify generate_all_reports backward compatibility when include_html_dashboard=False
    default_paths = generate_all_reports(
        results, tmp_path / "default_reports", sites=sites, generated_at=eval_dt
    )
    assert set(default_paths.keys()) == {
        "json",
        "csv",
        "markdown",
        "remediation_plan",
    }

    # Verify generate_all_reports includes html_dashboard when include_html_dashboard=True
    with_html_paths = generate_all_reports(
        results,
        tmp_path / "html_reports",
        sites=sites,
        generated_at=eval_dt,
        include_html_dashboard=True,
        approval_manifest=manifest,
        reconciliation_report=reconciliation,
    )
    assert set(with_html_paths.keys()) == {
        "json",
        "csv",
        "markdown",
        "remediation_plan",
        "html_dashboard",
    }
    assert with_html_paths["html_dashboard"].exists()


def test_cli_run_and_report_with_html_dashboard(tmp_path: Path) -> None:
    run_dir = tmp_path / "run_html"
    rc = main(
        [
            "run",
            "--fixtures",
            "--num-sites",
            "2",
            "--html-dashboard",
            "--output-dir",
            str(run_dir),
        ]
    )
    assert rc == 0
    dashboard_file = run_dir / "validation_dashboard.html"
    assert dashboard_file.exists()
    assert "<!DOCTYPE html>" in dashboard_file.read_text(encoding="utf-8")

    # Test `report --input-dir <dir> --html-dashboard` with custom --html-output
    report_out = tmp_path / "report_html"
    custom_html = tmp_path / "custom" / "dashboard_report.html"
    rc_report = main(
        [
            "report",
            "--input-dir",
            str(run_dir),
            "--output-dir",
            str(report_out),
            "--html-dashboard",
            "--html-output",
            str(custom_html),
        ]
    )
    assert rc_report == 0
    assert (report_out / "validation_dashboard.html").exists()
    assert custom_html.exists()


def test_cli_history_quarantine_and_remediate_end_to_end_workflow(
    tmp_path: Path,
) -> None:
    snap_dir = tmp_path / "snapshots"
    val_dir = tmp_path / "val_out"
    db_path = tmp_path / "history.db"

    assert (
        main(
            [
                "extract",
                "--fixtures",
                "--num-sites",
                "1",
                "--snapshot-dir",
                str(snap_dir),
            ]
        )
        == 0
    )

    run_timestamps = [
        ("run-001", "2026-01-01T12:00:00Z"),
        ("run-002", "2026-01-20T12:00:00Z"),
        ("run-003", "2026-02-12T12:00:00Z"),
    ]
    for run_id, ts in run_timestamps:
        assert (
            main(
                [
                    "validate",
                    "--snapshot-dir",
                    str(snap_dir),
                    "--output-dir",
                    str(val_dir),
                    "--evaluation-time",
                    ts,
                ]
            )
            == 0
        )
        assert (
            main(
                [
                    "history",
                    "--db-path",
                    str(db_path),
                    "--record",
                    str(val_dir / "validation_results.json"),
                    "--run-id",
                    run_id,
                    "--recorded-at",
                    ts,
                    "--output-dir",
                    str(val_dir),
                    "--export-json",
                    str(tmp_path / "history_export.json"),
                ]
            )
            == 0
        )

    history_summary = json.loads(
        (val_dir / "history_summary.json").read_text(encoding="utf-8")
    )
    assert history_summary["total_runs"] == 3
    assert any(
        s["consecutive_stale_runs"] == 3 and s["stale_duration_days"] >= 40.0
        for s in history_summary["streaks"]
    )
    assert (tmp_path / "history_export.json").exists()

    # Step 2: Run `quarantine` CLI to build and approve manifest
    manifest_path = tmp_path / "approval_manifest.json"
    manifest_csv_path = tmp_path / "approval_manifest.csv"
    assert (
        main(
            [
                "quarantine",
                "--results-file",
                str(val_dir / "validation_results.json"),
                "--db-path",
                str(db_path),
                "--snapshot-dir",
                str(snap_dir),
                "--min-consecutive-stale-runs",
                "3",
                "--min-stale-days",
                "30",
                "--min-confidence",
                "0.75",
                "--protected-categories",
                "ups",
                "--approve-all",
                "--reviewer",
                "netops-lead",
                "--review-note",
                "Approved stale batch for cleanup",
                "--output",
                str(manifest_path),
                "--csv-out",
                str(manifest_csv_path),
            ]
        )
        == 0
    )
    assert manifest_path.exists()
    assert manifest_csv_path.exists()

    loaded_manifest = RemediationApprovalManifest.import_json(manifest_path)
    assert loaded_manifest.verify_digest() is True
    assert len(loaded_manifest.approved_entries) >= 1

    # Step 3: Run `remediate` in default dry-run mode (no --confirm-write)
    dry_rem_dir = tmp_path / "remediate_dry"
    assert (
        main(
            [
                "remediate",
                "--manifest",
                str(manifest_path),
                "--snapshot-dir",
                str(snap_dir),
                "--output-dir",
                str(dry_rem_dir),
            ]
        )
        == 0
    )
    assert (dry_rem_dir / "remediate.sql").exists()
    assert (dry_rem_dir / "rollback.sql").exists()
    assert (dry_rem_dir / "remediation_result.json").exists()
    dry_res = json.loads(
        (dry_rem_dir / "remediation_result.json").read_text(encoding="utf-8")
    )
    assert dry_res["dry_run"] is True
    assert not (dry_rem_dir / "remediation_journal.jsonl").exists()

    # Step 4: Run `remediate` in gated write mode (--confirm-write)
    write_rem_dir = tmp_path / "remediate_write"
    assert (
        main(
            [
                "remediate",
                "--execute-approved-plan",
                str(manifest_path),
                "--snapshot-dir",
                str(snap_dir),
                "--output-dir",
                str(write_rem_dir),
                "--execution-id",
                "exec-cli-001",
                "--confirm-write",
            ]
        )
        == 0
    )
    assert (write_rem_dir / "remediate.sql").exists()
    assert (write_rem_dir / "rollback.sql").exists()
    assert (write_rem_dir / "remediation_journal.jsonl").exists()
    write_res = json.loads(
        (write_rem_dir / "remediation_result.json").read_text(encoding="utf-8")
    )
    assert write_res["dry_run"] is False
    assert write_res["applied_count"] >= 1

    journal = RollbackJournal(write_rem_dir / "remediation_journal.jsonl")
    j_entries = journal.read_entries(execution_id="exec-cli-001")
    assert len(j_entries) == write_res["applied_count"]

    # Step 5: Rollback via `--rollback-execution-id`
    rb_dir = tmp_path / "remediate_rollback"
    assert (
        main(
            [
                "remediate",
                "--journal-path",
                str(write_rem_dir / "remediation_journal.jsonl"),
                "--snapshot-dir",
                str(snap_dir),
                "--output-dir",
                str(rb_dir),
                "--rollback-execution-id",
                "exec-cli-001",
                "--confirm-write",
            ]
        )
        == 0
    )
    assert (rb_dir / "rollback.sql").exists()
    assert "BEGIN TRANSACTION;" in (rb_dir / "rollback.sql").read_text(
        encoding="utf-8"
    )


def test_cli_reconcile_and_campaign_end_to_end_workflow(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    samples_dir = repo_root / "tests" / "fixtures" / "sot_samples"

    # 1. Reconcile CLI with discovery fixtures + extra untracked VM/SNMP/ARP items
    vc_data = json.loads(
        (samples_dir / "vcenter" / "vcenter_inventory.json").read_text(
            encoding="utf-8"
        )
    )
    vc_data["vms"].append(
        {
            "vcenter_instance": "vcenter-prod-01",
            "vcenter_host": "vcenter-prod-01.example.internal",
            "site_id": "site-042",
            "vm_moref": "vm-9999",
            "bios_uuid": "42000042-0000-0000-0000-000000009999",
            "vm_name": "untracked-win-vm-042",
            "guest_hostname": "untracked-win-vm-042.example.internal",
            "guest_os_family": "windows",
            "guest_os_full_name": "Microsoft Windows Server 2019 (64-bit)",
            "power_state": "poweredOn",
            "tools_status": "toolsOk",
            "tools_heartbeat": "green",
            "nics": [
                {
                    "nic_label": "Network adapter 1",
                    "mac_address": "00:50:56:99:99:99",
                    "ip_addresses": ["10.42.10.250"],
                    "vlan_id": 10,
                    "connected": True,
                }
            ],
            "last_updated": "2026-11-11T08:05:00Z",
        }
    )
    vc_file = tmp_path / "vcenter_with_untracked.json"
    vc_file.write_text(json.dumps(vc_data, indent=2), encoding="utf-8")

    rec_out = tmp_path / "reconcile_out"
    assert (
        main(
            [
                "reconcile",
                "--csv-dir",
                str(samples_dir / "csv"),
                "--vcenter-json",
                str(vc_file),
                "--snmp-fixture",
                str(samples_dir / "snmp" / "extreme_and_apc_walks.json"),
                "--output-dir",
                str(rec_out),
            ]
        )
        == 0
    )

    for expected_file in (
        "reconciliation_report.json",
        "reconciliation_discrepancies.csv",
        "onboarding_template.csv",
        "onboarding_import.sql",
    ):
        assert (rec_out / expected_file).exists(), f"Missing {expected_file}"

    rec_report = json.loads(
        (rec_out / "reconciliation_report.json").read_text(encoding="utf-8")
    )
    assert rec_report["total_discrepancies"] >= 1
    assert rec_report["summary_by_type"]["UNTRACKED_VM"] >= 1
    assert "INSERT INTO" in (rec_out / "onboarding_import.sql").read_text(
        encoding="utf-8"
    )

    # 2. Campaign CLI across multi-site cohorts
    camp_out = tmp_path / "campaign_out"
    camp_history_db = tmp_path / "campaign_history.db"
    assert (
        main(
            [
                "campaign",
                "--fixtures",
                "--num-sites",
                "4",
                "--cohort-size",
                "2",
                "--campaign-id",
                "camp-2026-q1",
                "--high-stale-ratio-threshold",
                "0.10",
                "--webhook-format",
                "slack",
                "--history-db",
                str(camp_history_db),
                "--html-dashboard",
                "--output-dir",
                str(camp_out),
            ]
        )
        == 0
    )

    assert (camp_out / "campaign_summary.json").exists()
    assert (camp_out / "campaign_alerts.json").exists()
    assert (camp_out / "campaign_webhook_payload.json").exists()
    assert (camp_out / "validation_dashboard.html").exists()

    camp_summary = json.loads(
        (camp_out / "campaign_summary.json").read_text(encoding="utf-8")
    )
    assert camp_summary["campaign_id"] == "camp-2026-q1"
    assert camp_summary["total_sites_scheduled"] == 4
    assert camp_summary["total_waves_executed"] == 2
    assert len(camp_summary["committed_site_ids"]) == 4

    with HistoryStore(camp_history_db) as hstore:
        runs = hstore.list_runs()
        assert len(runs) == 1
        assert runs[0].run_id == "camp-2026-q1"


def test_top_level_package_exports_and_readme_documentation() -> None:
    expected_symbols = [
        "HtmlDashboardGenerator",
        "generate_html_dashboard",
        "HistoryStore",
        "ValidationRunRecord",
        "ItemStreakSummary",
        "DriftEvent",
        "DriftTransitionType",
        "SubnetUtilizationSummary",
        "QuarantinePolicy",
        "QuarantineEngine",
        "QuarantineManifestEntry",
        "QuarantineGraduationStatus",
        "ApprovalStatus",
        "RemediationOperation",
        "RemediationApprovalManifest",
        "RemediationExecutor",
        "RemediationExecutionResult",
        "SqlRemediationScriptGenerator",
        "SqlRemediationScripts",
        "RollbackJournal",
        "RollbackJournalEntry",
        "RollbackPlan",
        "RemediationExecutionError",
        "ManifestVerificationError",
        "InventoryReconciler",
        "ReconciliationReport",
        "DiscrepancyRecord",
        "DiscrepancyType",
        "ALL_DISCREPANCY_TYPES",
        "DISCREPANCY_CSV_COLUMNS",
        "ONBOARDING_CSV_COLUMNS",
        "VALID_DISCREPANCY_SOURCES",
        "CampaignConfig",
        "CampaignOrchestrator",
        "CampaignRunSummary",
        "SiteWaveResult",
        "SiteWaveStatus",
        "CircuitBreakerTrippedError",
        "AlertEvent",
        "AlertSeverity",
        "AlertType",
        "AlertSink",
        "InMemoryAlertSink",
        "JsonFileAlertSink",
        "WebhookPayloadFormatter",
    ]
    for sym in expected_symbols:
        assert hasattr(sot_validator, sym), f"Missing {sym} on sot_validator"
        assert sym in sot_validator.__all__, f"{sym} missing from __all__"

    repo_root = Path(__file__).resolve().parents[1]
    readme_text = (repo_root / "README.md").read_text(encoding="utf-8")
    for token in (
        "history",
        "quarantine",
        "remediate",
        "reconcile",
        "campaign",
        "--html-dashboard",
    ):
        assert token in readme_text, f"Expected {token!r} in README.md"

    # Suppress unused import warnings by verifying imported references
    assert HtmlDashboardGenerator is not None
    assert generate_html_dashboard is not None
    assert DriftTransitionType.NEWLY_STALE is not None
    assert DriftEvent is not None
    assert ValidationRunRecord is not None
    assert ItemStreakSummary is not None
    assert SubnetUtilizationSummary is not None
    assert QuarantinePolicy is not None
    assert QuarantineEngine is not None
    assert RemediationExecutor is not None
    assert RemediationExecutionResult is not None
    assert SqlRemediationScriptGenerator is not None
    assert SqlRemediationScripts is not None
    assert RollbackJournalEntry is not None
    assert RollbackPlan is not None
    assert RemediationExecutionError is not None
    assert ManifestVerificationError is not None
    assert InventoryReconciler is not None
    assert DISCREPANCY_CSV_COLUMNS is not None
    assert ONBOARDING_CSV_COLUMNS is not None
    assert VALID_DISCREPANCY_SOURCES is not None
    assert CampaignConfig is not None
    assert CampaignOrchestrator is not None
    assert CampaignRunSummary is not None
    assert SiteWaveResult is not None
    assert SiteWaveStatus is not None
    assert CircuitBreakerTrippedError is not None
    assert AlertEvent is not None
    assert AlertSeverity is not None
    assert AlertType is not None
    assert AlertSink is not None
    assert InMemoryAlertSink is not None
    assert JsonFileAlertSink is not None
    assert WebhookPayloadFormatter is not None
