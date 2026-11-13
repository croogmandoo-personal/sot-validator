"""APC UPS fleet health subcommand (`ups-health`)."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.cli._common import (
    _add_source_arguments,
    _has_source_flags,
    _infer_evaluation_time,
    _resolve_sites_for_command,
)
from sot_validator.models import Site
from sot_validator.signals.ups_health import ApcUpsHealthEvaluator


def cmd_ups_health(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    has_site_source = _has_source_flags(args) or args.snapshot_dir is not None
    sites: Optional[list[Site]] = None
    if has_site_source or args.snmp_fixture is None:
        sites = _resolve_sites_for_command(
            args, output_dir, default_to_fixtures=True
        )

    telemetry_data: Optional[Mapping[str, Any]] = None
    if args.snmp_fixture is not None:
        telemetry_data = json.loads(
            Path(args.snmp_fixture).read_text(encoding="utf-8")
        )

    eval_time = args.evaluation_time or (
        sites and _infer_evaluation_time(args, sites)
    )
    evaluator = ApcUpsHealthEvaluator(
        min_runtime_minutes=args.min_runtime_minutes,
        critical_runtime_minutes=args.critical_runtime_minutes,
        max_temp_celsius=args.max_temp_celsius,
        critical_temp_celsius=args.critical_temp_celsius,
        max_load_pct=args.max_load_pct,
        critical_load_pct=args.critical_load_pct,
        telemetry_by_target=telemetry_data,
        evaluation_time=eval_time,
    )
    fleet_report = evaluator.evaluate_fleet(
        sites if sites else None, evaluation_time=eval_time
    )
    report_json = fleet_report.to_json(indent=2)

    default_out = output_dir / "ups_health_report.json"
    default_out.write_text(report_json, encoding="utf-8")

    if args.output_file is not None:
        out_file = Path(args.output_file)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(report_json, encoding="utf-8")
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `ups-health` subcommand."""
    # 14. ups-health (Phase 6)
    ups_parser = subparsers.add_parser(
        "ups-health",
        help="Evaluate APC UPS PowerNet-MIB battery replacement, runtime, load, and thermal health across sites.",
    )
    ups_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing extracted site snapshots.",
    )
    ups_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Directory to write ups_health_report.json (default: ./reports).",
    )
    ups_parser.add_argument(
        "--output",
        "--output-file",
        dest="output_file",
        type=Path,
        default=None,
        help="Optional explicit output path for ups_health_report.json.",
    )
    ups_parser.add_argument(
        "--snmp-fixture",
        type=Path,
        default=None,
        help="Path to SNMP PowerNet-MIB discovery fixture JSON file.",
    )
    ups_parser.add_argument(
        "--min-runtime-minutes",
        type=float,
        default=15.0,
        help="Minimum battery runtime remaining in minutes before warning (default: 15.0).",
    )
    ups_parser.add_argument(
        "--critical-runtime-minutes",
        type=float,
        default=5.0,
        help="Critical battery runtime remaining in minutes (default: 5.0).",
    )
    ups_parser.add_argument(
        "--max-temp-celsius",
        type=float,
        default=40.0,
        help="Maximum battery temperature in Celsius before thermal warning (default: 40.0).",
    )
    ups_parser.add_argument(
        "--critical-temp-celsius",
        type=float,
        default=50.0,
        help="Critical battery temperature in Celsius (default: 50.0).",
    )
    ups_parser.add_argument(
        "--max-load-pct",
        type=float,
        default=80.0,
        help="Maximum output load percentage before overload warning (default: 80.0).",
    )
    ups_parser.add_argument(
        "--critical-load-pct",
        type=float,
        default=95.0,
        help="Critical output load percentage (default: 95.0).",
    )
    ups_parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Optional reference ISO-8601 UTC timestamp.",
    )
    _add_source_arguments(ups_parser)
    ups_parser.set_defaults(func=cmd_ups_health)
