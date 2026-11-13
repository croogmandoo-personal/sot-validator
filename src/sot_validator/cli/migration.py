"""NetBox / Nautobot export and dual-run parity subcommands (`export-modern-sot`, `parity-check`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.cli._common import (
    _add_source_arguments,
    _has_source_flags,
    _infer_evaluation_time,
    _load_validation_results_with_timestamp,
    _parse_str_list,
    _resolve_sites_for_command,
)
from sot_validator.migration import (
    DualRunParityChecker,
    GoldenInventoryFilter,
    ModernSoTExporter,
)
from sot_validator.models import Site, ValidationResult
from sot_validator.reconciliation import ReconciliationReport


def cmd_export_modern_sot(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    sites = _resolve_sites_for_command(
        args, output_dir, default_to_fixtures=True
    )

    results: Optional[list[ValidationResult]] = None
    file_eval_time: Optional[str] = None
    if args.results_file is not None:
        results, file_eval_time = _load_validation_results_with_timestamp(
            Path(args.results_file)
        )
    elif (output_dir / "validation_results.json").exists():
        results, file_eval_time = _load_validation_results_with_timestamp(
            output_dir / "validation_results.json"
        )

    recon_report: Optional[ReconciliationReport] = None
    if args.reconciliation_file is not None:
        recon_report = ReconciliationReport.from_json(
            Path(args.reconciliation_file)
        )
    elif (output_dir / "reconciliation_report.json").exists():
        recon_report = ReconciliationReport.from_json(
            output_dir / "reconciliation_report.json"
        )

    approved_ids = _parse_str_list(args.approved_discrepancy_ids)
    eval_time = (
        args.generated_at
        or file_eval_time
        or _infer_evaluation_time(args, sites)
    )

    inv_filter = GoldenInventoryFilter(
        include_stale=bool(args.include_stale),
        merge_untracked=bool(args.merge_untracked),
        approved_discrepancy_ids=approved_ids if approved_ids else None,
    )
    exporter = ModernSoTExporter(
        sites=sites,
        validation_results=results,
        reconciliation_report=recon_report,
        target_platform=args.target_platform,
        inventory_filter=inv_filter,
        generated_at=eval_time,
    )

    default_json_out = output_dir / "modern_sot_bundle.json"
    platform_json_out = output_dir / f"{args.target_platform}_golden_bundle.json"
    json_content = exporter.export_json(output_path=default_json_out)
    platform_json_out.write_text(json_content, encoding="utf-8")

    if args.json_out is not None:
        custom_json = Path(args.json_out)
        custom_json.parent.mkdir(parents=True, exist_ok=True)
        custom_json.write_text(json_content, encoding="utf-8")

    default_csv_dir = output_dir / "csv_bundle"
    exporter.export_csv_bundle(default_csv_dir)
    platform_csv_dir = output_dir / f"{args.target_platform}_csv_bundle"
    exporter.export_csv_bundle(platform_csv_dir)

    if args.csv_bundle_dir is not None:
        exporter.export_csv_bundle(Path(args.csv_bundle_dir))

    return 0


def cmd_parity_check(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    golden_bundle: Optional[Any] = None
    if args.golden_bundle is not None:
        golden_bundle = json.loads(
            Path(args.golden_bundle).read_text(encoding="utf-8")
        )

    sites: Optional[list[Site]] = None
    if golden_bundle is None or _has_source_flags(args) or args.snapshot_dir is not None:
        sites = _resolve_sites_for_command(
            args, output_dir, default_to_fixtures=(golden_bundle is None)
        )

    results: Optional[list[ValidationResult]] = None
    file_eval_time: Optional[str] = None
    if args.results_file is not None:
        results, file_eval_time = _load_validation_results_with_timestamp(
            Path(args.results_file)
        )
    elif (output_dir / "validation_results.json").exists():
        results, file_eval_time = _load_validation_results_with_timestamp(
            output_dir / "validation_results.json"
        )

    recon_report: Optional[ReconciliationReport] = None
    if args.reconciliation_file is not None:
        recon_report = ReconciliationReport.from_json(
            Path(args.reconciliation_file)
        )
    elif (output_dir / "reconciliation_report.json").exists():
        recon_report = ReconciliationReport.from_json(
            output_dir / "reconciliation_report.json"
        )

    modern_bundle: Any
    if args.modern_bundle is not None:
        modern_bundle = json.loads(
            Path(args.modern_bundle).read_text(encoding="utf-8")
        )
    elif golden_bundle is not None:
        modern_bundle = golden_bundle
    else:
        modern_bundle = ModernSoTExporter(
            sites=sites,
            validation_results=results,
            reconciliation_report=recon_report,
            target_platform=args.target_platform,
        ).to_dict()

    waived_ids = _parse_str_list(args.waive_discrepancies)
    stale_ids = _parse_str_list(args.stale_item_ids)
    eval_time = (
        args.evaluated_at
        or file_eval_time
        or (sites and _infer_evaluation_time(args, sites))
    )

    validator = DualRunParityChecker(
        golden_bundle=golden_bundle,
        modern_bundle=modern_bundle,
        sites=sites,
        validation_results=results,
        reconciliation_report=recon_report,
        stale_item_ids=stale_ids if stale_ids else None,
        waived_discrepancy_ids=waived_ids if waived_ids else None,
        waive_all_parity_discrepancies=bool(args.waive_all),
        target_platform=args.target_platform,
        evaluated_at=eval_time,
    )
    report = validator.evaluate_sites()
    report_json = report.to_json(indent=2)

    (output_dir / "migration_parity_report.json").write_text(
        report_json, encoding="utf-8"
    )
    (output_dir / "parity_report.json").write_text(
        report_json, encoding="utf-8"
    )

    if args.output_file is not None:
        out_file = Path(args.output_file)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(report_json, encoding="utf-8")
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `export-modern-sot`, `parity-check` subcommands."""
    # 12. export-modern-sot (Phase 5)
    export_sot_parser = subparsers.add_parser(
        "export-modern-sot",
        aliases=["migrate-export"],
        help="Export golden validated inventory into normalized NetBox or Nautobot JSON and CSV bundles.",
    )
    export_sot_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing extracted site snapshots.",
    )
    export_sot_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Directory to write NetBox/Nautobot JSON and CSV bundles (default: ./reports).",
    )
    export_sot_parser.add_argument(
        "--target-platform",
        choices=["netbox", "nautobot"],
        default="netbox",
        help="Target modern SoT platform schema (default: netbox).",
    )
    export_sot_parser.add_argument(
        "--results-file",
        type=Path,
        default=None,
        help="Path to validation_results.json used to filter out stale records.",
    )
    export_sot_parser.add_argument(
        "--reconciliation-file",
        type=Path,
        default=None,
        help="Optional Phase 3 reconciliation_report.json to merge approved untracked assets.",
    )
    export_sot_parser.add_argument(
        "--include-stale",
        action="store_true",
        default=False,
        help="Include stale items tagged as decommissioning/deprecated instead of excluding them.",
    )
    export_sot_parser.add_argument(
        "--merge-untracked",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Merge untracked Shadow IT assets from reconciliation report (default: True).",
    )
    export_sot_parser.add_argument(
        "--approved-discrepancy-ids",
        nargs="*",
        action="extend",
        default=None,
        help="Optional list of approved discrepancy IDs to merge.",
    )
    export_sot_parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional explicit output path for the JSON export bundle.",
    )
    export_sot_parser.add_argument(
        "--csv-dir-out",
        "--csv-bundle-dir",
        dest="csv_bundle_dir",
        type=Path,
        default=None,
        help="Optional explicit directory for the per-entity CSV import bundle.",
    )
    export_sot_parser.add_argument(
        "--evaluation-time",
        "--generated-at",
        dest="generated_at",
        type=str,
        default=None,
        help="Optional ISO-8601 timestamp for export bundle metadata.",
    )
    _add_source_arguments(export_sot_parser)
    export_sot_parser.set_defaults(func=cmd_export_modern_sot)

    # 13. parity-check (Phase 5)
    parity_parser = subparsers.add_parser(
        "parity-check",
        aliases=["migration-parity"],
        help="Evaluate dual-run parity and per-site migration readiness scorecards between legacy and modern SoT.",
    )
    parity_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing extracted site snapshots.",
    )
    parity_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Directory to write migration_parity_report.json (default: ./reports).",
    )
    parity_parser.add_argument(
        "--output",
        "--output-file",
        dest="output_file",
        type=Path,
        default=None,
        help="Optional explicit output path for migration_parity_report.json.",
    )
    parity_parser.add_argument(
        "--golden-bundle",
        type=Path,
        default=None,
        help="Optional path to expected golden ModernSoTExporter JSON bundle.",
    )
    parity_parser.add_argument(
        "--modern-bundle",
        type=Path,
        default=None,
        help="Optional path to target NetBox/Nautobot JSON bundle under test.",
    )
    parity_parser.add_argument(
        "--target-platform",
        choices=["netbox", "nautobot"],
        default="netbox",
        help="Target modern SoT platform schema (default: netbox).",
    )
    parity_parser.add_argument(
        "--results-file",
        type=Path,
        default=None,
        help="Optional path to validation_results.json.",
    )
    parity_parser.add_argument(
        "--reconciliation-file",
        type=Path,
        default=None,
        help="Optional path to reconciliation_report.json.",
    )
    parity_parser.add_argument(
        "--stale-item-ids",
        nargs="*",
        action="extend",
        default=None,
        help="Optional explicit stale item IDs that must not leak into Modern SoT.",
    )
    parity_parser.add_argument(
        "--waived-discrepancy-ids",
        "--waive-discrepancies",
        dest="waive_discrepancies",
        nargs="*",
        action="extend",
        default=None,
        help="Optional discrepancy IDs or item identifiers to waive during readiness scoring.",
    )
    parity_parser.add_argument(
        "--waive-all",
        action="store_true",
        default=False,
        help="Waive all parity discrepancies.",
    )
    parity_parser.add_argument(
        "--evaluation-time",
        "--evaluated-at",
        dest="evaluated_at",
        type=str,
        default=None,
        help="Optional ISO-8601 timestamp for scorecard evaluation.",
    )
    _add_source_arguments(parity_parser)
    parity_parser.set_defaults(func=cmd_parity_check)
