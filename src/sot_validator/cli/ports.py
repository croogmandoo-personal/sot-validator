"""Extreme switch port / PoE reclamation subcommand (`reclaim-ports`)."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.cli._common import (
    _add_source_arguments,
    _infer_evaluation_time,
    _open_history_store,
    _resolve_sites_for_command,
)
from sot_validator.history import HistoryStore, ItemStreakSummary
from sot_validator.models import ValidationClassification
from sot_validator.remediation import ExtremeCliDialect, ExtremePortReclamationPlanner


def cmd_reclaim_ports(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    sites = _resolve_sites_for_command(
        args, output_dir, default_to_fixtures=True
    )

    store: Optional[HistoryStore] = None
    if args.db_path is not None:
        store, _ = _open_history_store(Path(args.db_path))
    elif Path("./history.db").exists():
        store, _ = _open_history_store(Path("./history.db"))

    explicit_streaks: Optional[list[ItemStreakSummary]] = None
    if args.streaks_json is not None:
        raw_streaks = json.loads(
            Path(args.streaks_json).read_text(encoding="utf-8")
        )
        if isinstance(raw_streaks, Mapping):
            streak_items = raw_streaks.get("streaks", [])
        elif isinstance(raw_streaks, list):
            streak_items = raw_streaks
        else:
            streak_items = []
        explicit_streaks = [
            s
            if isinstance(s, ItemStreakSummary)
            else ItemStreakSummary.from_dict(s)
            for s in streak_items
        ]

    lldp_data: Optional[Any] = None
    if args.lldp_json is not None:
        lldp_data = json.loads(Path(args.lldp_json).read_text(encoding="utf-8"))

    snmp_data: Optional[Any] = None
    if args.snmp_fixture is not None:
        snmp_data = json.loads(
            Path(args.snmp_fixture).read_text(encoding="utf-8")
        )

    eval_time = args.evaluation_time or _infer_evaluation_time(args, sites)
    try:
        if (
            explicit_streaks is None
            and store is None
            and args.min_inactive_runs == 1
        ):
            synth_dt = (
                datetime.fromisoformat(eval_time.replace("Z", "+00:00"))
                if eval_time
                else datetime.now(timezone.utc)
            )
            explicit_streaks = []
            for site in sites:
                for dev in site.devices:
                    for port in dev.ports:
                        oper_str = (port.oper_status or "").strip().lower()
                        if oper_str in ("down", "notpresent", "lowerlayerdown", "dormant", "2"):
                            explicit_streaks.append(
                                ItemStreakSummary(
                                    site_id=site.site_id,
                                    item_type="Port",
                                    item_id=port.port_id,
                                    name=port.name,
                                    current_classification=ValidationClassification.STALE_LIKELY_UNUSED,
                                    current_confidence=0.95,
                                    consecutive_stale_runs=1,
                                    total_runs_seen=1,
                                    first_seen_at=synth_dt,
                                    first_stale_at=synth_dt,
                                    stale_duration_days=max(0.0, float(args.min_inactive_days)),
                                )
                            )

        dialect = ExtremeCliDialect(args.dialect)
        planner = ExtremePortReclamationPlanner(
            min_inactive_runs=args.min_inactive_runs,
            min_inactive_days=args.min_inactive_days,
            dialect=dialect,
        )
        plan = planner.plan(
            sites=sites,
            streaks=explicit_streaks,
            history_store=store,
            lldp_neighbors=lldp_data,
            snmp_oids_by_device=snmp_data,
            evaluation_time=eval_time,
        )
    finally:
        if store is not None:
            store.close()

    plan_json = plan.to_json(indent=2)
    default_plan_path = output_dir / "port_reclamation_plan.json"
    default_plan_path.write_text(plan_json, encoding="utf-8")

    if args.output_file is not None:
        custom_plan_path = Path(args.output_file)
        custom_plan_path.parent.mkdir(parents=True, exist_ok=True)
        custom_plan_path.write_text(plan_json, encoding="utf-8")

    # Write both dialect-specific and canonical CLI script filenames
    primary_disable = (
        plan.exos_script
        if dialect is ExtremeCliDialect.EXOS
        else plan.voss_script
    )
    primary_rollback = (
        plan.exos_rollback_script
        if dialect is ExtremeCliDialect.EXOS
        else plan.voss_rollback_script
    )
    (output_dir / "port_reclamation_disable.cli").write_text(
        primary_disable, encoding="utf-8"
    )
    (output_dir / "port_reclamation_rollback.cli").write_text(
        primary_rollback, encoding="utf-8"
    )
    (output_dir / "reclaim_ports_exos.xsf").write_text(
        plan.exos_script, encoding="utf-8"
    )
    (output_dir / "rollback_ports_exos.xsf").write_text(
        plan.exos_rollback_script, encoding="utf-8"
    )
    (output_dir / "reclaim_ports_voss.cli").write_text(
        plan.voss_script, encoding="utf-8"
    )
    (output_dir / "rollback_ports_voss.cli").write_text(
        plan.voss_rollback_script, encoding="utf-8"
    )
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `reclaim-ports` subcommand."""
    # 11. reclaim-ports (Phase 4)
    reclaim_ports_parser = subparsers.add_parser(
        "reclaim-ports",
        help="Generate staged dry-run Extreme Networks switch port & PoE reclamation plans with LLDP Uplink Guard.",
    )
    reclaim_ports_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing extracted site snapshots.",
    )
    reclaim_ports_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Directory to write port_reclamation_plan.json and EXOS/VOSS CLI scripts (default: ./reports).",
    )
    reclaim_ports_parser.add_argument(
        "--output",
        "--output-file",
        dest="output_file",
        type=Path,
        default=None,
        help="Optional custom path for port_reclamation_plan.json.",
    )
    reclaim_ports_parser.add_argument(
        "--db-path",
        "--history-db",
        dest="db_path",
        type=Path,
        default=None,
        help="Optional HistoryStore SQLite DB or JSON file for port inactivity streaks.",
    )
    reclaim_ports_parser.add_argument(
        "--streaks-json",
        type=Path,
        default=None,
        help="Optional JSON file containing streak summaries or history_summary.json.",
    )
    reclaim_ports_parser.add_argument(
        "--lldp-json",
        type=Path,
        default=None,
        help="Optional JSON file containing LLDP/CDP neighbor observations.",
    )
    reclaim_ports_parser.add_argument(
        "--snmp-fixture",
        type=Path,
        default=None,
        help="Optional SNMP discovery fixture JSON file.",
    )
    reclaim_ports_parser.add_argument(
        "--dialect",
        choices=["exos", "voss"],
        default="exos",
        help="Primary Extreme CLI dialect for script generation (default: exos).",
    )
    reclaim_ports_parser.add_argument(
        "--min-inactive-runs",
        type=int,
        default=3,
        help="Minimum consecutive inactive runs required for port reclamation (default: 3).",
    )
    reclaim_ports_parser.add_argument(
        "--min-inactive-days",
        type=float,
        default=30.0,
        help="Minimum inactive duration in days required for port reclamation (default: 30.0).",
    )
    reclaim_ports_parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Optional reference ISO-8601 UTC timestamp.",
    )
    _add_source_arguments(reclaim_ports_parser)
    reclaim_ports_parser.set_defaults(func=cmd_reclaim_ports)
