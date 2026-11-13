"""Validation history and quarantine subcommands (`history`, `history-prune`, `quarantine`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Optional

from sot_validator.cli._common import (
    _load_validation_results_with_timestamp,
    _open_history_store,
    _parse_str_list,
)
from sot_validator.config import ConfigError, load_config
from sot_validator.extraction import SnapshotStore
from sot_validator.history import (
    HistorySchemaVersionError,
    HistoryStore,
    RetentionPolicy,
)
from sot_validator.models import Site, ValidationResult
from sot_validator.remediation import (
    ApprovalStatus,
    QuarantineEngine,
    QuarantinePolicy,
    RemediationApprovalManifest,
)


def cmd_history(args: argparse.Namespace) -> int:
    db_path = Path(args.db_path or "./history.db")
    import_json_path = (
        Path(args.import_json) if getattr(args, "import_json", None) else None
    )
    store, is_json_backed = _open_history_store(
        db_path, import_json_path=import_json_path
    )

    try:
        recorded_run = None
        if args.results_file is not None:
            results, file_ts = _load_validation_results_with_timestamp(
                Path(args.results_file)
            )
            effective_recorded_at = args.recorded_at or file_ts
            recorded_run = store.record_run(
                results,
                run_id=args.run_id,
                recorded_at=effective_recorded_at,
            )

        if is_json_backed and recorded_run is not None:
            store.export_json(db_path)

        runs = store.list_runs()
        streaks = store.list_streaks(
            site_id=args.site_id,
            min_consecutive_stale=args.min_consecutive_stale,
        )
        drift_run_id = (
            recorded_run.run_id
            if recorded_run is not None
            else args.run_id
        )
        drift_events = store.detect_drift(
            run_id=drift_run_id,
            site_id=args.site_id,
        )

        summary_payload: dict[str, Any] = {
            "recorded_run": (
                recorded_run.to_dict() if recorded_run is not None else None
            ),
            "total_runs": len(runs),
            "total_streaks": len(streaks),
            "total_drift_events": len(drift_events),
            "runs": [r.to_dict() for r in runs],
            "streaks": [s.to_dict() for s in streaks],
            "drift_events": [e.to_dict() for e in drift_events],
        }

        if args.export_json is not None:
            store.export_json(Path(args.export_json))

        if args.drift_output is not None:
            drift_target = Path(args.drift_output)
            drift_target.parent.mkdir(parents=True, exist_ok=True)
            drift_target.write_text(
                json.dumps(summary_payload, indent=2), encoding="utf-8"
            )

        if args.output_dir is not None:
            out_dir = Path(args.output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "history_summary.json").write_text(
                json.dumps(summary_payload, indent=2), encoding="utf-8"
            )
            (out_dir / "drift_report.json").write_text(
                json.dumps(
                    {
                        "run_id": drift_run_id
                        or (runs[-1].run_id if runs else None),
                        "total_drift_events": len(drift_events),
                        "drift_events": [e.to_dict() for e in drift_events],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
    finally:
        store.close()

    return 0


def _prune_error(message: str) -> int:
    print(f"error: {' '.join(message.split())}", file=sys.stderr)
    return 2


def cmd_history_prune(args: argparse.Namespace) -> int:
    db_path = Path(args.db_path)
    if db_path.suffix.lower() == ".json":
        return _prune_error(
            f"--db-path {db_path}: JSON history files are not supported by history-prune; "
            "use a SQLite history database"
        )
    if not db_path.is_file():
        return _prune_error(f"--db-path {db_path}: history database does not exist")
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        return _prune_error(str(exc))
    policy = RetentionPolicy(
        max_age_days=config.retention.max_age_days,
        max_runs_per_site=config.retention.max_runs_per_site,
    )

    try:
        store = HistoryStore(db_path)
    except (HistorySchemaVersionError, sqlite3.DatabaseError) as exc:
        return _prune_error(f"--db-path {db_path}: {exc}")
    try:
        report = store.prune_runs(policy, now=args.now, dry_run=not args.apply)
    except ValueError as exc:
        return _prune_error(str(exc))
    finally:
        store.close()

    print(json.dumps(report.to_dict(), indent=2))
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    if args.manifest_in is not None:
        in_path = Path(args.manifest_in)
        if in_path.suffix.lower() == ".csv":
            manifest = RemediationApprovalManifest.import_csv(in_path)
        else:
            manifest = RemediationApprovalManifest.import_json(in_path)
        if args.allow_protected_override:
            manifest.policy.allow_protected_override = True
    else:
        policy = QuarantinePolicy(
            min_consecutive_stale_runs=args.min_consecutive_stale_runs,
            min_stale_days=args.min_stale_days,
            min_confidence=args.min_confidence,
            protected_item_ids=_parse_str_list(args.protected_item_ids),
            protected_categories=_parse_str_list(args.protected_categories),
            protected_subnets=_parse_str_list(args.protected_subnets),
            protected_vendors=_parse_str_list(args.protected_vendors),
            allow_protected_override=bool(args.allow_protected_override),
        )

        results: Optional[list[ValidationResult]] = None
        inferred_ts: Optional[str] = None
        if args.results_file is not None:
            results, inferred_ts = _load_validation_results_with_timestamp(
                Path(args.results_file)
            )

        store: Optional[HistoryStore] = None
        if args.db_path is not None:
            store, _ = _open_history_store(Path(args.db_path))
        elif Path("./history.db").exists():
            store, _ = _open_history_store(Path("./history.db"))

        sites: Optional[list[Site]] = None
        if args.snapshot_dir is not None:
            snap_dir = Path(args.snapshot_dir)
            if (snap_dir / "sites").exists():
                sites = SnapshotStore(snap_dir).load_all_sites()
            elif (snap_dir / "snapshots" / "sites").exists():
                sites = SnapshotStore(snap_dir / "snapshots").load_all_sites()

        try:
            engine = QuarantineEngine(policy)
            manifest = engine.evaluate(
                results=results,
                history=store,
                sites=sites if sites else None,
                override_protected=bool(args.allow_protected_override),
                generated_at=args.generated_at or inferred_ts,
                manifest_id=args.manifest_id,
                include_below_threshold=bool(args.include_below_threshold),
            )
        finally:
            if store is not None:
                store.close()

    if args.approve_all:
        manifest.approve_all(reviewer=args.reviewer, note=args.review_note)

    for item_id in _parse_str_list(args.approve_items):
        manifest.set_entry_decision(
            item_id,
            ApprovalStatus.APPROVED,
            reviewer=args.reviewer,
            note=args.review_note,
            allow_exempt_override=bool(args.allow_protected_override),
        )

    for item_id in _parse_str_list(args.reject_items):
        manifest.set_entry_decision(
            item_id,
            ApprovalStatus.REJECTED,
            reviewer=args.reviewer,
            note=args.review_note,
        )

    manifest.update_digest()
    manifest.export_json(Path(args.output))
    if args.csv_out is not None:
        manifest.export_csv(Path(args.csv_out))

    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `history`, `history-prune`, `quarantine` subcommands."""
    # 5. history
    history_parser = subparsers.add_parser(
        "history",
        help="Record validation runs in HistoryStore, query stale streaks, and analyze state-transition drift.",
    )
    history_parser.add_argument(
        "--db-path",
        type=Path,
        default=Path("./history.db"),
        help="Path to SQLite HistoryStore database or exported JSON file (default: ./history.db).",
    )
    history_parser.add_argument(
        "--import-json",
        type=Path,
        default=None,
        help="Optional HistoryStore JSON state file to import before processing.",
    )
    history_parser.add_argument(
        "--record",
        "--results-file",
        dest="results_file",
        type=Path,
        default=None,
        help="Path to validation_results.json to record as a new validation run.",
    )
    history_parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Optional explicit run ID when recording a run or querying drift.",
    )
    history_parser.add_argument(
        "--recorded-at",
        type=str,
        default=None,
        help="Optional ISO-8601 UTC timestamp when recording a validation run.",
    )
    history_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Optional site ID filter for streaks and drift events.",
    )
    history_parser.add_argument(
        "--min-consecutive-stale",
        type=int,
        default=0,
        help="Minimum consecutive stale runs filter when listing item streaks (default: 0).",
    )
    history_parser.add_argument(
        "--export-json",
        type=Path,
        default=None,
        help="Optional path to export full HistoryStore state as JSON.",
    )
    history_parser.add_argument(
        "--drift-output",
        "--output-file",
        dest="drift_output",
        type=Path,
        default=None,
        help="Optional file path to write JSON summary of runs, streaks, and drift events.",
    )
    history_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional directory to write history_summary.json and drift_report.json.",
    )
    history_parser.set_defaults(func=cmd_history)

    # 5b. history-prune
    prune_parser = subparsers.add_parser(
        "history-prune",
        help="Prune old validation runs and their drift rows from a SQLite HistoryStore using the fleet [retention] policy.",
        description=(
            "Prune validation runs, and the drift rows they produced, that fall outside the "
            "[retention] limits in the fleet TOML. The default is a dry run that only reports "
            "what would be deleted; only --apply deletes. The newest run is always kept and "
            "item_streaks is never touched. JSON history files are not supported; --db-path "
            "must be an existing SQLite database."
        ),
    )
    prune_parser.add_argument(
        "--db-path",
        type=Path,
        default=Path("./history.db"),
        help="Path to an existing SQLite HistoryStore database (default: ./history.db). JSON history files are not supported.",
    )
    prune_parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Fleet TOML configuration file whose [retention] table sets max_age_days and max_runs_per_site.",
    )
    prune_parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete the selected runs and drift rows. Without it the command is a dry run that writes nothing.",
    )
    prune_parser.add_argument(
        "--now",
        type=str,
        default=None,
        help="Optional ISO-8601 UTC timestamp to evaluate the age limit against (default: current time).",
    )
    prune_parser.set_defaults(func=cmd_history_prune)

    # 6. quarantine
    quarantine_parser = subparsers.add_parser(
        "quarantine",
        help="Evaluate stale streaks against QuarantinePolicy and generate/approve SHA-256 signed manifests.",
    )
    quarantine_parser.add_argument(
        "--results-file",
        type=Path,
        default=None,
        help="Path to validation_results.json.",
    )
    quarantine_parser.add_argument(
        "--db-path",
        "--history-db",
        dest="db_path",
        type=Path,
        default=None,
        help="Path to HistoryStore SQLite DB or exported JSON file.",
    )
    quarantine_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Optional directory containing site snapshots for protection checks.",
    )
    quarantine_parser.add_argument(
        "--manifest-in",
        type=Path,
        default=None,
        help="Optional existing manifest JSON/CSV file to load and modify/approve.",
    )
    quarantine_parser.add_argument(
        "--output",
        "--manifest-out",
        dest="output",
        type=Path,
        default=Path("./output/approval_manifest.json"),
        help="Output path for the RemediationApprovalManifest JSON (default: ./output/approval_manifest.json).",
    )
    quarantine_parser.add_argument(
        "--csv-out",
        type=Path,
        default=None,
        help="Optional path to also export the manifest as CSV.",
    )
    quarantine_parser.add_argument(
        "--min-consecutive-stale-runs",
        type=int,
        default=3,
        help="Minimum consecutive stale runs required for quarantine graduation (default: 3).",
    )
    quarantine_parser.add_argument(
        "--min-stale-days",
        type=float,
        default=30.0,
        help="Minimum stale duration in days required for quarantine graduation (default: 30.0).",
    )
    quarantine_parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.85,
        help="Minimum classification confidence required for quarantine graduation (default: 0.85).",
    )
    quarantine_parser.add_argument(
        "--protected-item-ids",
        nargs="*",
        action="extend",
        default=None,
        help="Protected item IDs exempt from remediation.",
    )
    quarantine_parser.add_argument(
        "--protected-categories",
        nargs="*",
        action="extend",
        default=None,
        help="Protected equipment/device categories exempt from remediation.",
    )
    quarantine_parser.add_argument(
        "--protected-subnets",
        nargs="*",
        action="extend",
        default=None,
        help="Protected subnet CIDRs exempt from remediation.",
    )
    quarantine_parser.add_argument(
        "--protected-vendors",
        nargs="*",
        action="extend",
        default=None,
        help="Protected vendor names exempt from remediation.",
    )
    quarantine_parser.add_argument(
        "--allow-protected-override",
        action="store_true",
        default=False,
        help="Allow overriding protected item exemptions.",
    )
    quarantine_parser.add_argument(
        "--include-below-threshold",
        action="store_true",
        default=False,
        help="Include BELOW_THRESHOLD stale items in the generated manifest.",
    )
    quarantine_parser.add_argument(
        "--approve-all",
        action="store_true",
        default=False,
        help="Approve all eligible entries in the manifest.",
    )
    quarantine_parser.add_argument(
        "--approve-items",
        nargs="*",
        action="extend",
        default=None,
        help="Specific item IDs to set to APPROVED.",
    )
    quarantine_parser.add_argument(
        "--reject-items",
        nargs="*",
        action="extend",
        default=None,
        help="Specific item IDs to set to REJECTED.",
    )
    quarantine_parser.add_argument(
        "--reviewer",
        type=str,
        default="cli-operator",
        help="Reviewer identifier recorded on approval decisions (default: cli-operator).",
    )
    quarantine_parser.add_argument(
        "--review-note",
        type=str,
        default=None,
        help="Optional review note recorded on approval decisions.",
    )
    quarantine_parser.add_argument(
        "--manifest-id",
        type=str,
        default=None,
        help="Optional explicit manifest ID.",
    )
    quarantine_parser.add_argument(
        "--evaluation-time",
        "--generated-at",
        dest="generated_at",
        type=str,
        default=None,
        help="Optional ISO-8601 timestamp for manifest generation.",
    )
    quarantine_parser.set_defaults(func=cmd_quarantine)
