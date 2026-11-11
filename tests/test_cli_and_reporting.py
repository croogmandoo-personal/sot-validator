"""Unit and integration tests for Stage 4: Phase 2 dry-run remediation, multi-format reporting, and CLI runner."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

from sot_validator.cli import main
from sot_validator.extraction import FixtureSoTClient, ReadOnlyViolationError
from sot_validator.models import (
    EquipmentCategory,
    SignalStatus,
    SignalType,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)
from sot_validator.remediation import (
    DryRunActionPlan,
    DryRunActionPlanGenerator,
    ProposedRemediationAction,
    RemediationActionSink,
    RemediationActionType,
)
from sot_validator.reporting import (
    CSV_REPORT_COLUMNS,
    CsvReportGenerator,
    JsonReportGenerator,
    MarkdownReportGenerator,
    generate_all_reports,
    generate_csv_report,
    generate_json_report,
    generate_markdown_summary,
)


def _sample_validation_results() -> list[ValidationResult]:
    eval_dt = datetime(2026, 2, 12, 12, 0, 0, tzinfo=timezone.utc)
    return [
        ValidationResult(
            item_type="Equipment",
            item_id="site-001-vm-win-01",
            site_id="site-001",
            name="win-srv-001-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
            signals=[
                ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.ACTIVE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details="poweredOn; toolsOk",
                    source="vcenter",
                )
            ],
            rationale="Confirmed Active via vCenter power state and Guest Tools.",
            evaluated_at=eval_dt,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="site-001-srv-01",
            site_id="site-001",
            name="legacy-srv-001-01",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.82,
            signals=[
                ValidationSignal(
                    signal_type=SignalType.PORT_STATE,
                    status=SignalStatus.INACTIVE,
                    observed_at=eval_dt,
                    age_seconds=7776000.0,
                    details="Switch port down for 90 days",
                    source="sot.port",
                )
            ],
            rationale="Stale / Likely Unused: port down and last_seen > 30d.",
            evaluated_at=eval_dt,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="site-001-san-01",
            site_id="site-001",
            name="san-array-001-01",
            classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
            confidence=0.55,
            signals=[
                ValidationSignal(
                    signal_type=SignalType.LAST_SEEN_TIMESTAMP,
                    status=SignalStatus.INACTIVE,
                    observed_at=datetime(2026, 1, 25, 12, 0, 0, tzinfo=timezone.utc),
                    age_seconds=1555200.0,
                    details="Intermediate aging window (18 days)",
                    source="sot.last_seen",
                )
            ],
            rationale="Unreachable / Needs Manual Review: intermediate aging window.",
            evaluated_at=eval_dt,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="site-001-spare-01",
            site_id="site-001",
            name="spare-chassis-001-01",
            classification=ValidationClassification.INSUFFICIENT_DATA,
            confidence=0.0,
            signals=[
                ValidationSignal(
                    signal_type=SignalType.ARP_RECENCY,
                    status=SignalStatus.NOT_APPLICABLE,
                    details="No correlated IP or ARP records",
                    source="sot.arp",
                )
            ],
            rationale="Insufficient Data: no actionable identifiers.",
            evaluated_at=eval_dt,
        ),
    ]


def test_remediation_dry_run_action_plan_and_read_only_enforcement(
    tmp_path: Path,
) -> None:
    results = _sample_validation_results()
    gen = DryRunActionPlanGenerator(generated_at="2026-02-12T12:00:00Z")
    assert isinstance(gen, RemediationActionSink)

    plan = gen.process_results(results)
    assert plan.dry_run is True
    assert plan.total_evaluated == 4
    assert len(plan.actions) == 2
    assert plan.summary_by_action == {
        RemediationActionType.MARK_STALE_CANDIDATE.value: 1,
        RemediationActionType.FLAG_FOR_REVIEW.value: 1,
    }

    stale_action = next(
        a
        for a in plan.actions
        if a.action_type is RemediationActionType.MARK_STALE_CANDIDATE
    )
    assert stale_action.item_id == "site-001-srv-01"
    assert (
        stale_action.classification
        is ValidationClassification.STALE_LIKELY_UNUSED
    )
    assert stale_action.dry_run is True

    review_action = next(
        a
        for a in plan.actions
        if a.action_type is RemediationActionType.FLAG_FOR_REVIEW
    )
    assert review_action.item_id == "site-001-san-01"
    assert (
        review_action.classification
        is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
    )
    assert review_action.dry_run is True

    # Verify JSON round-trip and file persistence
    plan_path = tmp_path / "remediation_action_plan.json"
    written_path = gen.write_plan(plan, plan_path)
    assert written_path == plan_path
    loaded_plan = DryRunActionPlan.from_json(
        plan_path.read_text(encoding="utf-8")
    )
    assert loaded_plan.to_dict() == plan.to_dict()

    # ReadOnlyViolationError must be raised if dry_run=False is attempted anywhere
    with pytest.raises(ReadOnlyViolationError):
        DryRunActionPlanGenerator(dry_run=False)

    with pytest.raises(ReadOnlyViolationError):
        ProposedRemediationAction(
            action_type=RemediationActionType.MARK_STALE_CANDIDATE,
            site_id="site-001",
            item_type="Equipment",
            item_id="site-001-srv-01",
            name="legacy-srv-001-01",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.8,
            dry_run=False,
        )

    with pytest.raises(ReadOnlyViolationError):
        DryRunActionPlan(dry_run=False)

    bad_dict = plan.to_dict()
    bad_dict["dry_run"] = False
    with pytest.raises(ReadOnlyViolationError):
        DryRunActionPlan.from_dict(bad_dict)


def test_multi_format_report_generators(tmp_path: Path) -> None:
    sites = FixtureSoTClient(num_sites=1).list_sites()
    results = _sample_validation_results()

    out_dir = tmp_path / "reports"
    paths = generate_all_reports(
        results,
        out_dir,
        sites=sites,
        generated_at="2026-02-12T12:00:00Z",
    )

    assert set(paths.keys()) == {"json", "csv", "markdown", "remediation_plan"}
    for report_file in paths.values():
        assert report_file.exists()
        assert report_file.stat().st_size > 0

    # 1. JSON report verification
    json_payload = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert json_payload["total_items"] == 4
    for cls_enum in ValidationClassification:
        assert cls_enum.value in json_payload["summary"]["by_classification"]
        assert cls_enum.value in json_payload["by_classification"]
        assert (
            json_payload["summary"]["by_classification"][cls_enum.value]["count"]
            == 1
        )
        assert (
            json_payload["summary"]["by_classification"][cls_enum.value][
                "percentage"
            ]
            == 25.0
        )

    assert "site-001" in json_payload["summary"]["by_site"]
    assert (
        json_payload["summary"]["by_site"]["site-001"]["site_name"]
        == "Site 001 (10.1.0.0/16)"
    )
    for cat in EquipmentCategory:
        assert cat.value in json_payload["summary"]["by_equipment_category"]

    for item in json_payload["results"]:
        assert "signals" in item and len(item["signals"]) >= 1
        assert "confidence" in item
        assert "rationale" in item
        assert "classification" in item

    # 2. CSV report verification
    csv_text = paths["csv"].read_text(encoding="utf-8")
    csv_lines = csv_text.strip().splitlines()
    assert (
        csv_lines[0]
        == "site_id,site_name,item_type,item_id,name,ip_addresses,classification,confidence,rationale,evaluated_at"
    )
    reader = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(reader) == 4
    assert reader[0]["site_name"] == "Site 001 (10.1.0.0/16)"
    assert reader[0]["ip_addresses"] == "10.1.10.11"

    # 3. Markdown report verification
    md_text = paths["markdown"].read_text(encoding="utf-8")
    for cls_enum in ValidationClassification:
        assert cls_enum.value in md_text
    assert "Breakdown by Site" in md_text
    assert "Breakdown by Equipment Category" in md_text
    assert "Highlighted Items" in md_text
    assert "legacy-srv-001-01" in md_text
    assert "san-array-001-01" in md_text
    assert "MARK_STALE_CANDIDATE" in md_text
    assert "FLAG_FOR_REVIEW" in md_text

    # Verify generator wrapper classes
    assert JsonReportGenerator().generate(results, sites=sites)["total_items"] == 4
    assert CsvReportGenerator().generate(results, sites=sites).startswith(
        ",".join(CSV_REPORT_COLUMNS)
    )
    assert "Inventory Validation Summary Report" in MarkdownReportGenerator().generate(
        results, sites=sites
    )


def test_cli_end_to_end_run_and_step_by_step_subcommands(tmp_path: Path) -> None:
    # Step 1: End-to-end `run --fixtures`
    run_out_dir = tmp_path / "run_out"
    rc = main(["run", "--fixtures", "--output-dir", str(run_out_dir)])
    assert rc == 0

    for fname in (
        "validation_report.json",
        "validation_report.csv",
        "validation_summary.md",
        "remediation_action_plan.json",
    ):
        fpath = run_out_dir / fname
        assert fpath.exists(), f"Missing {fname}"
        assert fpath.stat().st_size > 0

    run_json = json.loads(
        (run_out_dir / "validation_report.json").read_text(encoding="utf-8")
    )
    for cls_enum in ValidationClassification:
        assert (
            run_json["summary"]["by_classification"][cls_enum.value]["count"] > 0
        ), f"Expected non-zero count for {cls_enum.value}"
        assert len(run_json["by_classification"][cls_enum.value]) > 0

    # Step 2: Step-by-step `extract` -> `validate` -> `report`
    step_snap_dir = tmp_path / "step_snapshots"
    step_out_dir = tmp_path / "step_out"

    assert (
        main(
            [
                "extract",
                "--fixtures",
                "--all-sites",
                "--batch-size",
                "2",
                "--snapshot-dir",
                str(step_snap_dir),
            ]
        )
        == 0
    )
    assert (step_snap_dir / "sites" / "site-001.json").exists()
    assert (step_snap_dir / "batches" / "batch_0000.json").exists()

    assert (
        main(
            [
                "validate",
                "--snapshot-dir",
                str(step_snap_dir),
                "--output-dir",
                str(step_out_dir),
            ]
        )
        == 0
    )
    assert (step_out_dir / "validation_results.json").exists()
    assert (step_out_dir / "remediation_action_plan.json").exists()

    assert (
        main(
            [
                "report",
                "--input-dir",
                str(step_out_dir),
                "--snapshot-dir",
                str(step_snap_dir),
                "--output-dir",
                str(step_out_dir),
            ]
        )
        == 0
    )

    step_json = json.loads(
        (step_out_dir / "validation_report.json").read_text(encoding="utf-8")
    )
    assert step_json == run_json
    assert (step_out_dir / "validation_report.csv").read_text(encoding="utf-8") == (
        run_out_dir / "validation_report.csv"
    ).read_text(encoding="utf-8")
    assert (step_out_dir / "validation_summary.md").read_text(encoding="utf-8") == (
        run_out_dir / "validation_summary.md"
    ).read_text(encoding="utf-8")
    assert json.loads(
        (step_out_dir / "remediation_action_plan.json").read_text(encoding="utf-8")
    ) == json.loads(
        (run_out_dir / "remediation_action_plan.json").read_text(encoding="utf-8")
    )


def test_cli_subprocess_and_discovery_fixtures(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    src_path = str(repo_root / "src")
    env["PYTHONPATH"] = (
        f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
        if "PYTHONPATH" in env
        else src_path
    )

    sub_out = tmp_path / "subprocess_run"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sot_validator",
            "run",
            "--fixtures",
            "--site-ids",
            "site-001,site-002",
            "--output-dir",
            str(sub_out),
        ],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    report_json = json.loads(
        (sub_out / "validation_report.json").read_text(encoding="utf-8")
    )
    assert set(report_json["summary"]["by_site"].keys()) == {
        "site-001",
        "site-002",
    }

    # Test with discovery sample fixtures (CSV + vCenter JSON + SNMP walk fixture)
    samples_dir = repo_root / "tests" / "fixtures" / "sot_samples"
    sample_out = tmp_path / "sample_site_042"
    rc = main(
        [
            "run",
            "--csv-dir",
            str(samples_dir / "csv"),
            "--vcenter-json",
            str(samples_dir / "vcenter" / "vcenter_inventory.json"),
            "--snmp-fixture",
            str(samples_dir / "snmp" / "extreme_and_apc_walks.json"),
            "--evaluation-time",
            "2026-11-11T08:10:00Z",
            "--output-dir",
            str(sample_out),
        ]
    )
    assert rc == 0
    sample_report = json.loads(
        (sample_out / "validation_report.json").read_text(encoding="utf-8")
    )
    assert "site-042" in sample_report["summary"]["by_site"]
    for cls_enum in ValidationClassification:
        assert (
            sample_report["summary"]["by_classification"][cls_enum.value]["count"]
            >= 1
        )
