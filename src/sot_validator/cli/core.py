"""Core pipeline subcommands (`extract`, `validate`, `report`, `run`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.cli._common import (
    _add_source_arguments,
    _add_validation_arguments,
    _evaluate_sites,
    _extract_sites,
    _has_source_flags,
    _load_validation_results_with_timestamp,
    _write_validation_results_file,
)
from sot_validator.extraction import SnapshotStore
from sot_validator.itsm import JsonFileItsmSink
from sot_validator.models import Site
from sot_validator.reconciliation import ReconciliationReport
from sot_validator.remediation import (
    DryRunActionPlan,
    DryRunActionPlanGenerator,
    PortReclamationPlan,
    RemediationApprovalManifest,
)
from sot_validator.reporting import generate_all_reports
from sot_validator.signals.ups_health import UpsFleetHealthReport


def cmd_extract(args: argparse.Namespace) -> int:
    snapshot_dir = Path(args.snapshot_dir or "./snapshots")
    _extract_sites(args, snapshot_dir, default_to_fixtures=True)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    has_source = _has_source_flags(args)
    if args.output_dir is not None:
        output_dir = Path(args.output_dir)
    elif args.snapshot_dir is not None:
        output_dir = Path(args.snapshot_dir)
    else:
        output_dir = Path("./output")

    if args.snapshot_dir is not None:
        snapshot_dir = Path(args.snapshot_dir)
    elif (output_dir / "sites").exists() or has_source:
        snapshot_dir = output_dir
    else:
        snapshot_dir = Path("./snapshots")

    sites = _extract_sites(args, snapshot_dir, default_to_fixtures=False)
    if not sites and has_source:
        sites = _extract_sites(args, snapshot_dir, default_to_fixtures=True)

    results, eval_time = _evaluate_sites(args, sites)
    _write_validation_results_file(results, output_dir, generated_at=eval_time)

    plan_gen = DryRunActionPlanGenerator(generated_at=eval_time)
    plan_gen.write_plan(results, output_dir / "remediation_action_plan.json")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    input_dir = Path(args.input_dir) if args.input_dir is not None else None
    snapshot_dir = (
        Path(args.snapshot_dir)
        if args.snapshot_dir is not None
        else (input_dir if input_dir is not None else Path("./snapshots"))
    )
    output_dir = (
        Path(args.output_dir)
        if args.output_dir is not None
        else (input_dir if input_dir is not None else snapshot_dir)
    )

    if args.results_file is not None:
        results_file = Path(args.results_file)
    elif input_dir is not None and (input_dir / "validation_results.json").exists():
        results_file = input_dir / "validation_results.json"
    elif (output_dir / "validation_results.json").exists():
        results_file = output_dir / "validation_results.json"
    elif (snapshot_dir / "validation_results.json").exists():
        results_file = snapshot_dir / "validation_results.json"
    else:
        raise FileNotFoundError(
            "Could not locate validation_results.json; pass --results-file or --input-dir"
        )

    results, file_eval_time = _load_validation_results_with_timestamp(
        results_file
    )

    sites: list[Site] = []
    for candidate_dir in (
        snapshot_dir,
        input_dir,
        output_dir,
        input_dir / "snapshots" if input_dir is not None else None,
        output_dir / "snapshots",
    ):
        if candidate_dir is not None and (candidate_dir / "sites").exists():
            sites = SnapshotStore(candidate_dir).load_all_sites()
            if sites:
                break

    action_plan: Optional[DryRunActionPlan] = None
    for candidate_dir in (output_dir, input_dir, snapshot_dir):
        if candidate_dir is not None:
            plan_file = candidate_dir / "remediation_action_plan.json"
            if plan_file.exists():
                action_plan = DryRunActionPlan.from_json(
                    plan_file.read_text(encoding="utf-8")
                )
                break

    approval_manifest: Optional[RemediationApprovalManifest] = None
    manifest_file_arg = getattr(args, "manifest_file", None)
    if manifest_file_arg is not None:
        approval_manifest = RemediationApprovalManifest.import_json(
            Path(manifest_file_arg)
        )
    else:
        for candidate_dir in (output_dir, input_dir, snapshot_dir):
            if candidate_dir is not None:
                m_path = candidate_dir / "approval_manifest.json"
                if m_path.exists():
                    approval_manifest = RemediationApprovalManifest.import_json(
                        m_path
                    )
                    break

    reconciliation_report: Optional[ReconciliationReport] = None
    reconciliation_file_arg = getattr(args, "reconciliation_file", None)
    if reconciliation_file_arg is not None:
        reconciliation_report = ReconciliationReport.from_json(
            Path(reconciliation_file_arg)
        )
    else:
        for candidate_dir in (output_dir, input_dir, snapshot_dir):
            if candidate_dir is not None:
                r_path = candidate_dir / "reconciliation_report.json"
                if r_path.exists():
                    reconciliation_report = ReconciliationReport.from_json(
                        r_path
                    )
                    break

    port_plan: Optional[PortReclamationPlan] = None
    port_plan_arg = getattr(args, "port_plan_file", None)
    if port_plan_arg is not None:
        port_plan = PortReclamationPlan.from_json(
            Path(port_plan_arg).read_text(encoding="utf-8")
        )
    else:
        for candidate_dir in (output_dir, input_dir, snapshot_dir):
            if candidate_dir is not None:
                p_path = candidate_dir / "port_reclamation_plan.json"
                if p_path.exists():
                    port_plan = PortReclamationPlan.from_json(
                        p_path.read_text(encoding="utf-8")
                    )
                    break

    parity_data: Optional[Any] = None
    parity_file_arg = getattr(args, "parity_file", None)
    if parity_file_arg is not None:
        parity_data = json.loads(
            Path(parity_file_arg).read_text(encoding="utf-8")
        )
    else:
        for candidate_dir in (output_dir, input_dir, snapshot_dir):
            if candidate_dir is not None:
                for par_filename in (
                    "migration_parity_report.json",
                    "parity_report.json",
                ):
                    par_path = candidate_dir / par_filename
                    if par_path.exists():
                        parity_data = json.loads(
                            par_path.read_text(encoding="utf-8")
                        )
                        break
                if parity_data is not None:
                    break

    ups_report: Optional[UpsFleetHealthReport] = None
    ups_file_arg = getattr(args, "ups_health_file", None)
    if ups_file_arg is not None:
        ups_report = UpsFleetHealthReport.from_json(
            Path(ups_file_arg).read_text(encoding="utf-8")
        )
    else:
        for candidate_dir in (output_dir, input_dir, snapshot_dir):
            if candidate_dir is not None:
                u_path = candidate_dir / "ups_health_report.json"
                if u_path.exists():
                    ups_report = UpsFleetHealthReport.from_json(
                        u_path.read_text(encoding="utf-8")
                    )
                    break

    itsm_tickets: Optional[Any] = None
    itsm_file_arg = getattr(args, "itsm_tickets_file", None)
    if itsm_file_arg is not None:
        itsm_tickets = JsonFileItsmSink(Path(itsm_file_arg)).tickets
    else:
        for candidate_dir in (output_dir, input_dir, snapshot_dir):
            if candidate_dir is not None:
                for t_filename in ("itsm_tickets.json", "itsm_ticket.json"):
                    t_path = candidate_dir / t_filename
                    if t_path.exists():
                        itsm_tickets = JsonFileItsmSink(t_path).tickets
                        break
                if itsm_tickets is not None:
                    break

    eval_time = getattr(args, "evaluation_time", None) or file_eval_time
    want_html = bool(
        getattr(args, "html_dashboard", False)
        or getattr(args, "html_output", None) is not None
    )

    paths = generate_all_reports(
        results,
        output_dir,
        sites=sites if sites else None,
        action_plan=action_plan,
        generated_at=eval_time,
        include_html_dashboard=want_html,
        approval_manifest=approval_manifest,
        reconciliation_report=reconciliation_report,
        port_reclamation_plan=port_plan,
        migration_parity_report=parity_data,
        ups_health_report=ups_report,
        itsm_tickets=itsm_tickets,
    )

    html_output_arg = getattr(args, "html_output", None)
    if html_output_arg is not None:
        custom_html_path = Path(html_output_arg)
        if custom_html_path.resolve() != paths["html_dashboard"].resolve():
            custom_html_path.parent.mkdir(parents=True, exist_ok=True)
            custom_html_path.write_text(
                paths["html_dashboard"].read_text(encoding="utf-8"),
                encoding="utf-8",
            )

    return 0


def cmd_run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
    snapshot_dir = (
        Path(args.snapshot_dir)
        if args.snapshot_dir is not None
        else output_dir / "snapshots"
    )

    has_source = _has_source_flags(args)
    store = SnapshotStore(snapshot_dir)
    default_fixtures = not has_source and not store.load_all_sites()

    sites = _extract_sites(
        args, snapshot_dir, default_to_fixtures=default_fixtures
    )
    results, eval_time = _evaluate_sites(args, sites)

    _write_validation_results_file(results, output_dir, generated_at=eval_time)
    plan = DryRunActionPlanGenerator(generated_at=eval_time).generate_plan(
        results, generated_at=eval_time
    )

    want_html = bool(
        getattr(args, "html_dashboard", False)
        or getattr(args, "html_output", None) is not None
    )
    paths = generate_all_reports(
        results,
        output_dir,
        sites=sites,
        action_plan=plan,
        generated_at=eval_time,
        include_html_dashboard=want_html,
    )

    html_output_arg = getattr(args, "html_output", None)
    if html_output_arg is not None:
        custom_html_path = Path(html_output_arg)
        if custom_html_path.resolve() != paths["html_dashboard"].resolve():
            custom_html_path.parent.mkdir(parents=True, exist_ok=True)
            custom_html_path.write_text(
                paths["html_dashboard"].read_text(encoding="utf-8"),
                encoding="utf-8",
            )

    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `extract`, `validate`, `report`, `run` subcommands."""
    # 1. extract
    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract read-only site inventory batches into local snapshots.",
    )
    extract_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=Path("./snapshots"),
        help="Directory to store extracted site and batch snapshots (default: ./snapshots).",
    )
    _add_source_arguments(extract_parser)
    extract_parser.set_defaults(func=cmd_extract)

    # 2. validate
    validate_parser = subparsers.add_parser(
        "validate",
        help="Evaluate passive, hypervisor, directory/DNS, and scoped active signals against site snapshots.",
    )
    validate_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing extracted site snapshots.",
    )
    validate_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to write validation_results.json and remediation_action_plan.json.",
    )
    _add_source_arguments(validate_parser)
    _add_validation_arguments(validate_parser)
    validate_parser.set_defaults(func=cmd_validate)

    # 3. report
    report_parser = subparsers.add_parser(
        "report",
        help="Generate JSON, CSV, Markdown, and optional interactive HTML validation reports.",
    )
    report_parser.add_argument(
        "--results-file",
        type=Path,
        default=None,
        help="Path to validation_results.json.",
    )
    report_parser.add_argument(
        "--input-dir",
        type=Path,
        default=None,
        help="Directory containing validation_results.json (and optional snapshots).",
    )
    report_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing site snapshots for metadata enrichment.",
    )
    report_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to write validation_report.json, validation_report.csv, validation_summary.md, and remediation_action_plan.json.",
    )
    report_parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Optional timestamp override for report generation.",
    )
    report_parser.add_argument(
        "--html-dashboard",
        action="store_true",
        default=False,
        help="Generate self-contained interactive HTML5 dashboard (validation_dashboard.html).",
    )
    report_parser.add_argument(
        "--html-output",
        type=Path,
        default=None,
        help="Optional custom output path for the HTML5 dashboard.",
    )
    report_parser.add_argument(
        "--manifest-file",
        "--manifest",
        dest="manifest_file",
        type=Path,
        default=None,
        help="Optional Phase 2 RemediationApprovalManifest JSON file to embed in the HTML dashboard.",
    )
    report_parser.add_argument(
        "--reconciliation-file",
        type=Path,
        default=None,
        help="Optional Phase 3 ReconciliationReport JSON file to embed in the HTML dashboard.",
    )
    report_parser.add_argument(
        "--port-plan-file",
        "--port-plan",
        dest="port_plan_file",
        type=Path,
        default=None,
        help="Optional Phase 4 PortReclamationPlan JSON file to embed in the HTML dashboard.",
    )
    report_parser.add_argument(
        "--parity-file",
        "--parity-report",
        dest="parity_file",
        type=Path,
        default=None,
        help="Optional Phase 5 MigrationParityReport JSON file to embed in the HTML dashboard.",
    )
    report_parser.add_argument(
        "--ups-health-file",
        "--ups-report",
        dest="ups_health_file",
        type=Path,
        default=None,
        help="Optional Phase 6 UpsFleetHealthReport JSON file to embed in the HTML dashboard.",
    )
    report_parser.add_argument(
        "--itsm-tickets-file",
        type=Path,
        default=None,
        help="Optional Phase 6 ITSM tickets JSON file to embed in the HTML dashboard.",
    )
    report_parser.set_defaults(func=cmd_report)

    # 4. run
    run_parser = subparsers.add_parser(
        "run",
        help="Execute end-to-end extraction, signal validation, multi-format reporting, and Phase 2 dry-run plan generation.",
    )
    run_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory for extracted site snapshots (defaults to <output-dir>/snapshots).",
    )
    run_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./output"),
        help="Directory to write all validation reports and dry-run action plan (default: ./output).",
    )
    run_parser.add_argument(
        "--html-dashboard",
        action="store_true",
        default=False,
        help="Also generate self-contained interactive HTML5 dashboard (validation_dashboard.html).",
    )
    run_parser.add_argument(
        "--html-output",
        type=Path,
        default=None,
        help="Optional custom output path for the HTML5 dashboard.",
    )
    _add_source_arguments(run_parser)
    _add_validation_arguments(run_parser)
    run_parser.set_defaults(func=cmd_run)
