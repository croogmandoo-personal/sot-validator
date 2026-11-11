"""Batch CLI runner for sot-validator (`extract`, `validate`, `report`, `run`)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Optional

from sot_validator.classifier.engine import (
    ClassificationEngine,
    ClassificationPolicy,
)
from sot_validator.extraction import (
    BatchExtractor,
    FixtureSoTClient,
    HtmlScraperSoTClient,
    SnapshotStore,
    SoTClient,
    SqlExportSoTClient,
)
from sot_validator.models import Site, ValidationResult
from sot_validator.remediation.sink import (
    DryRunActionPlan,
    DryRunActionPlanGenerator,
)
from sot_validator.reporting.generators import generate_all_reports
from sot_validator.signals.hypervisor import MultiVCenterInventoryProvider
from sot_validator.signals.icmp import IcmpProbeCollector
from sot_validator.signals.management import ManagementProbeCollector

DEFAULT_FIXTURE_EVALUATION_TIME = "2026-02-12T12:00:00Z"
DEFAULT_DISCOVERY_SAMPLE_EVALUATION_TIME = "2026-11-11T08:10:00Z"


def _parse_site_ids(raw_values: Optional[Sequence[str]]) -> Optional[list[str]]:
    if not raw_values:
        return None
    parsed: list[str] = []
    for raw in raw_values:
        for part in str(raw).split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in parsed:
                parsed.append(cleaned)
    return parsed if parsed else None


def _has_source_flags(args: argparse.Namespace) -> bool:
    return any(
        bool(getattr(args, attr, None))
        for attr in (
            "fixtures",
            "fixture_path",
            "sql_dump",
            "csv_dir",
            "json_export",
            "scrape_url",
        )
    )


def _build_sot_client(
    args: argparse.Namespace, *, default_to_fixtures: bool = False
) -> Optional[SoTClient]:
    if getattr(args, "sql_dump", None) is not None:
        return SqlExportSoTClient.from_sql_dump(args.sql_dump)
    if getattr(args, "csv_dir", None) is not None:
        return SqlExportSoTClient.from_csv_dir(args.csv_dir)
    if getattr(args, "json_export", None) is not None:
        return SqlExportSoTClient.from_json(args.json_export)
    if getattr(args, "scrape_url", None) is not None:
        return HtmlScraperSoTClient(args.scrape_url)
    if getattr(args, "fixture_path", None) is not None:
        return FixtureSoTClient(fixture_path=args.fixture_path)
    if getattr(args, "fixtures", False) or default_to_fixtures:
        num_sites = getattr(args, "num_sites", 3)
        return FixtureSoTClient(num_sites=num_sites)
    return None


def _infer_evaluation_time(
    args: argparse.Namespace, sites: Sequence[Site]
) -> Optional[str]:
    explicit = getattr(args, "evaluation_time", None)
    if explicit:
        return str(explicit)

    if getattr(args, "fixtures", False) or getattr(args, "fixture_path", None):
        return DEFAULT_FIXTURE_EVALUATION_TIME

    fixture_anchor = datetime(2026, 2, 10, 12, 0, 0, tzinfo=timezone.utc)
    for site in sites:
        for dev in site.devices:
            if dev.last_seen == fixture_anchor:
                return DEFAULT_FIXTURE_EVALUATION_TIME
        if site.site_id == "site-042":
            return DEFAULT_DISCOVERY_SAMPLE_EVALUATION_TIME

    return None


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--site-ids",
        nargs="+",
        action="extend",
        default=None,
        help="Target site IDs (comma-separated or space-separated, e.g. site-001,site-002).",
    )
    parser.add_argument(
        "--all-sites",
        action="store_true",
        default=False,
        help="Process all available sites.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Number of sites per extraction batch (default: 10).",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="Polite delay in seconds between per-site requests (default: 0.0).",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        default=False,
        help="Disable checkpoint resume and re-extract all target sites.",
    )
    parser.add_argument(
        "--fixtures",
        action="store_true",
        default=False,
        help="Use deterministic built-in FixtureSoTClient inventory.",
    )
    parser.add_argument(
        "--num-sites",
        type=int,
        default=3,
        help="Number of fixture sites to generate when --fixtures is set (default: 3).",
    )
    parser.add_argument(
        "--fixture-path",
        type=Path,
        default=None,
        help="Path to a JSON fixture file for FixtureSoTClient.",
    )
    parser.add_argument(
        "--sql-dump",
        type=Path,
        default=None,
        help="Path to a read-only SQL dump file (.sql).",
    )
    parser.add_argument(
        "--csv-dir",
        type=Path,
        default=None,
        help="Path to a directory containing SoT CSV export tables.",
    )
    parser.add_argument(
        "--json-export",
        type=Path,
        default=None,
        help="Path to a JSON export file of SoT tables or sites.",
    )
    parser.add_argument(
        "--scrape-url",
        type=str,
        default=None,
        help="Base URL for read-only GET HTML scraping of the legacy SoT.",
    )


def _add_validation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--vcenter-json",
        type=Path,
        default=None,
        help="Path to a multi-vCenter inventory JSON snapshot.",
    )
    parser.add_argument(
        "--snmp-fixture",
        type=Path,
        default=None,
        help="Path to a read-only SNMP/ICMP discovery fixture JSON file.",
    )
    parser.add_argument(
        "--active-within-days",
        type=float,
        default=7.0,
        help="Threshold in days within which signals are considered active (default: 7.0).",
    )
    parser.add_argument(
        "--stale-after-days",
        type=float,
        default=30.0,
        help="Threshold in days beyond which inactive signals are considered stale (default: 30.0).",
    )
    parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Reference ISO-8601 UTC timestamp for signal recency evaluation.",
    )
    parser.add_argument(
        "--include-ips",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include IPAddress records in site validation results (default: True).",
    )


def _extract_sites(
    args: argparse.Namespace,
    snapshot_dir: Path,
    *,
    default_to_fixtures: bool = False,
) -> list[Site]:
    store = SnapshotStore(snapshot_dir)
    client = _build_sot_client(args, default_to_fixtures=default_to_fixtures)
    site_ids = (
        None
        if getattr(args, "all_sites", False)
        else _parse_site_ids(getattr(args, "site_ids", None))
    )

    if client is not None:
        extractor = BatchExtractor(
            client,
            snapshot_store=store,
            sites_per_batch=getattr(args, "batch_size", 10),
            request_delay_seconds=getattr(args, "rate_limit", 0.0),
        )
        return extractor.extract_all(
            site_ids=site_ids,
            resume=not getattr(args, "no_resume", False),
        )

    all_saved = store.load_all_sites()
    if site_ids is not None:
        wanted = set(site_ids)
        return [s for s in all_saved if s.site_id in wanted]
    return all_saved


def _evaluate_sites(
    args: argparse.Namespace,
    sites: Sequence[Site],
) -> tuple[list[ValidationResult], Optional[str]]:
    eval_time = _infer_evaluation_time(args, sites)
    policy = ClassificationPolicy(
        active_within_days=getattr(args, "active_within_days", 7.0),
        stale_after_days=getattr(args, "stale_after_days", 30.0),
    )

    hypervisor_provider: Optional[MultiVCenterInventoryProvider] = None
    if getattr(args, "vcenter_json", None) is not None:
        hypervisor_provider = MultiVCenterInventoryProvider.from_json_file(
            args.vcenter_json
        )

    icmp_collector: Optional[IcmpProbeCollector] = None
    management_collector: Optional[ManagementProbeCollector] = None
    if getattr(args, "snmp_fixture", None) is not None:
        icmp_collector = IcmpProbeCollector.from_fixture_file(args.snmp_fixture)
        management_collector = ManagementProbeCollector.from_fixture_file(
            args.snmp_fixture
        )

    engine = ClassificationEngine(
        policy=policy,
        icmp_collector=icmp_collector,
        management_collector=management_collector,
        hypervisor_provider=hypervisor_provider,
        evaluation_time=eval_time,
    )

    include_ips = getattr(args, "include_ips", True)
    results: list[ValidationResult] = []
    for site in sites:
        results.extend(
            engine.classify_site(
                site,
                evaluation_time=eval_time,
                include_ip_addresses=include_ips,
            )
        )
    return results, eval_time


def _write_validation_results_file(
    results: Sequence[ValidationResult],
    output_dir: Path,
    *,
    generated_at: Optional[str] = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    results_path = output_dir / "validation_results.json"
    ts_str = generated_at or datetime.now(timezone.utc).isoformat()
    payload = {
        "generated_at": ts_str,
        "total_results": len(results),
        "results": [r.to_dict() for r in results],
    }
    results_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return results_path


def _load_validation_results_file(results_path: Path) -> list[ValidationResult]:
    raw_data: Any = json.loads(results_path.read_text(encoding="utf-8"))
    if isinstance(raw_data, dict):
        items = raw_data.get("results", [])
    elif isinstance(raw_data, list):
        items = raw_data
    else:
        raise ValueError(
            f"Unsupported validation results format in {results_path}"
        )
    return [
        item if isinstance(item, ValidationResult) else ValidationResult.from_dict(item)
        for item in items
    ]


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

    results = _load_validation_results_file(results_file)

    sites: list[Site] = []
    for candidate_dir in (snapshot_dir, input_dir, output_dir):
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

    eval_time = getattr(args, "evaluation_time", None)
    if eval_time is None and results and results[0].evaluated_at is not None:
        eval_time = results[0].evaluated_at.isoformat()

    generate_all_reports(
        results,
        output_dir,
        sites=sites if sites else None,
        action_plan=action_plan,
        generated_at=eval_time,
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
    generate_all_reports(
        results,
        output_dir,
        sites=sites,
        action_plan=plan,
        generated_at=eval_time,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argparse CLI parser for `sot-validator`."""
    parser = argparse.ArgumentParser(
        prog="sot-validator",
        description="Read-only batch inventory validation system for legacy Network Source of Truth.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

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
        help="Evaluate passive, hypervisor, and scoped active signals against site snapshots.",
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
        help="Generate JSON, CSV, and Markdown validation reports from evaluated results.",
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
    _add_source_arguments(run_parser)
    _add_validation_arguments(run_parser)
    run_parser.set_defaults(func=cmd_run)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entrypoint returning an exit code (0 on success)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args))


if __name__ == "__main__":
    sys.exit(main())
