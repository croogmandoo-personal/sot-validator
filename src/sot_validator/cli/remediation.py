"""Gated remediation and reverse-discovery reconciliation subcommands (`remediate`, `reconcile`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
from typing import Any, Optional

from sot_validator.cli._common import (
    _add_source_arguments,
    _infer_evaluation_time,
    _resolve_sites_for_command,
)
from sot_validator.extraction import SnapshotStore
from sot_validator.itsm import ItsmTicketRequest, JsonFileItsmSink
from sot_validator.reconciliation import InventoryReconciler
from sot_validator.remediation import (
    RemediationApprovalManifest,
    RemediationExecutor,
    RollbackJournal,
)
from sot_validator.signals.hypervisor import MultiVCenterInventoryProvider


def cmd_remediate(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
    output_dir.mkdir(parents=True, exist_ok=True)

    journal_path = (
        Path(args.journal_path)
        if args.journal_path is not None
        else output_dir / RollbackJournal.DEFAULT_FILENAME
    )

    snapshot_store: Optional[SnapshotStore] = None
    if args.snapshot_dir is not None:
        snap_dir = Path(args.snapshot_dir)
        if (snap_dir / "snapshots" / "sites").exists() and not (
            snap_dir / "sites"
        ).exists():
            snapshot_store = SnapshotStore(snap_dir / "snapshots")
        else:
            snapshot_store = SnapshotStore(snap_dir)

    confirm_write = bool(args.confirm_write)
    itsm_sink: Optional[JsonFileItsmSink] = None
    itsm_sink_file = getattr(args, "itsm_tickets_file", None) or getattr(
        args, "itsm_sink_file", None
    )
    if itsm_sink_file is not None:
        itsm_sink = JsonFileItsmSink(Path(itsm_sink_file))

    itsm_ticket_obj: Optional[ItsmTicketRequest] = None
    if getattr(args, "itsm_ticket_file", None) is not None:
        raw_tkt = json.loads(
            Path(args.itsm_ticket_file).read_text(encoding="utf-8")
        )
        if isinstance(raw_tkt, list) and raw_tkt:
            itsm_ticket_obj = ItsmTicketRequest.from_dict(raw_tkt[0])
        elif isinstance(raw_tkt, dict):
            itsm_ticket_obj = ItsmTicketRequest.from_dict(raw_tkt)

    itsm_ticket_id = getattr(args, "itsm_ticket_id", None)
    if itsm_ticket_id is None and itsm_sink is not None and len(itsm_sink.tickets) == 1:
        itsm_ticket_id = itsm_sink.tickets[0].ticket_id

    require_itsm = bool(
        getattr(args, "require_itsm_approval", False)
        or itsm_ticket_id is not None
        or itsm_sink is not None
        or itsm_ticket_obj is not None
    )
    allow_scheduled = bool(getattr(args, "itsm_allow_scheduled", False))

    executor = RemediationExecutor(
        dry_run=not confirm_write,
        confirm_write=confirm_write,
        journal_path=journal_path,
        strict_approval=bool(args.strict_approval),
        require_itsm_approval=require_itsm,
        itsm_sink=itsm_sink,
        itsm_ticket_id=itsm_ticket_id,
        itsm_ticket=itsm_ticket_obj,
        allow_scheduled_ticket=allow_scheduled,
    )

    sqlite_conn: Optional[sqlite3.Connection] = None
    if args.sqlite_db is not None and Path(args.sqlite_db).exists():
        sqlite_conn = sqlite3.connect(str(args.sqlite_db))

    try:
        if args.rollback_execution_id is not None:
            if confirm_write:
                plan = executor.rollback(
                    args.rollback_execution_id,
                    sqlite_conn=sqlite_conn,
                    snapshot_store=snapshot_store,
                )
            else:
                plan = executor.generate_rollback_plan(
                    args.rollback_execution_id
                )

            rollback_sql_path = output_dir / "rollback.sql"
            rollback_sql_path.write_text(plan.rollback_sql, encoding="utf-8")
            (output_dir / "rollback_result.json").write_text(
                json.dumps(plan.to_dict(), indent=2), encoding="utf-8"
            )
            return 0

        if args.manifest is None:
            raise ValueError(
                "Must supply --manifest / --execute-approved-plan or --rollback-execution-id"
            )

        manifest = RemediationApprovalManifest.import_json(Path(args.manifest))
        result = executor.execute(
            manifest,
            sqlite_conn=sqlite_conn,
            snapshot_store=snapshot_store,
            sql_output_dir=output_dir,
            dry_run=not confirm_write,
            confirm_write=confirm_write,
            strict_approval=bool(args.strict_approval),
            execution_id=args.execution_id,
            reviewer=args.reviewer,
            require_itsm_approval=require_itsm,
            itsm_sink=itsm_sink,
            itsm_ticket_id=itsm_ticket_id,
            itsm_ticket=itsm_ticket_obj,
            allow_scheduled_ticket=allow_scheduled,
        )

        remediate_sql_path = output_dir / "remediate.sql"
        rollback_sql_path = output_dir / "rollback.sql"
        if not remediate_sql_path.exists():
            remediate_sql_path.write_text(result.remediate_sql, encoding="utf-8")
            result.remediate_sql_path = remediate_sql_path
        if not rollback_sql_path.exists():
            rollback_sql_path.write_text(result.rollback_sql, encoding="utf-8")
            result.rollback_sql_path = rollback_sql_path

        (output_dir / "remediation_result.json").write_text(
            result.to_json(indent=2), encoding="utf-8"
        )
    finally:
        if sqlite_conn is not None:
            sqlite_conn.close()

    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
    output_dir.mkdir(parents=True, exist_ok=True)
    sites = _resolve_sites_for_command(
        args, output_dir, default_to_fixtures=True
    )

    vcenter_provider: Optional[MultiVCenterInventoryProvider] = None
    if args.vcenter_json is not None:
        vcenter_provider = MultiVCenterInventoryProvider.from_json_file(
            Path(args.vcenter_json)
        )

    snmp_targets: Optional[Any] = None
    if args.snmp_fixture is not None:
        snmp_targets = json.loads(
            Path(args.snmp_fixture).read_text(encoding="utf-8")
        )

    arp_entries: Optional[Any] = None
    if args.arp_json is not None:
        arp_entries = json.loads(
            Path(args.arp_json).read_text(encoding="utf-8")
        )
    elif isinstance(snmp_targets, dict) and "arp_entries" in snmp_targets:
        arp_entries = snmp_targets["arp_entries"]

    icmp_responses: Optional[Any] = None
    if args.icmp_json is not None:
        icmp_responses = json.loads(
            Path(args.icmp_json).read_text(encoding="utf-8")
        )
    elif snmp_targets is not None:
        icmp_responses = snmp_targets

    eval_time = args.generated_at or _infer_evaluation_time(args, sites)
    reconciler = InventoryReconciler(
        vcenter_provider=vcenter_provider,
        arp_entries=arp_entries,
        snmp_targets=snmp_targets,
        icmp_responses=icmp_responses,
    )
    report = reconciler.reconcile(sites, generated_at=eval_time)

    report.to_json(output_path=output_dir / "reconciliation_report.json")
    report.to_csv(output_path=output_dir / "reconciliation_discrepancies.csv")
    report.generate_onboarding_csv(
        output_path=output_dir / "onboarding_template.csv"
    )
    report.generate_onboarding_sql(
        output_path=output_dir / "onboarding_import.sql"
    )
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `remediate`, `reconcile` subcommands."""
    # 7. remediate
    remediate_parser = subparsers.add_parser(
        "remediate",
        help="Execute a SHA-256-verified RemediationApprovalManifest or generate/apply rollback plans.",
    )
    remediate_parser.add_argument(
        "--manifest",
        "--execute-approved-plan",
        dest="manifest",
        type=Path,
        default=None,
        help="Path to the operator-approved RemediationApprovalManifest JSON file.",
    )
    remediate_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./output"),
        help="Directory to write remediate.sql, rollback.sql, remediation_journal.jsonl, and remediation_result.json.",
    )
    remediate_parser.add_argument(
        "--journal-path",
        type=Path,
        default=None,
        help="Explicit path to remediation_journal.jsonl (defaults to <output-dir>/remediation_journal.jsonl).",
    )
    remediate_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Optional directory containing SnapshotStore sites.",
    )
    remediate_parser.add_argument(
        "--sqlite-db",
        type=Path,
        default=None,
        help="Optional SQLite database path to execute SQL against when --confirm-write is passed.",
    )
    remediate_parser.add_argument(
        "--confirm-write",
        action="store_true",
        default=False,
        help="Explicitly confirm write execution (dry_run=False, confirm_write=True). Defaults to dry-run.",
    )
    remediate_parser.add_argument(
        "--strict-approval",
        action="store_true",
        default=False,
        help="Fail if any non-exempt entry in the manifest is not APPROVED.",
    )
    remediate_parser.add_argument(
        "--execution-id",
        type=str,
        default=None,
        help="Optional explicit execution ID.",
    )
    remediate_parser.add_argument(
        "--reviewer",
        type=str,
        default=None,
        help="Optional reviewer override.",
    )
    remediate_parser.add_argument(
        "--rollback-execution-id",
        type=str,
        default=None,
        help="Generate (and if --confirm-write, apply) a RollbackPlan from the journal for the given execution_id.",
    )
    remediate_parser.add_argument(
        "--require-itsm-approval",
        action="store_true",
        default=False,
        help="Require an APPROVED ITSM change ticket with matching SHA-256 digest before executing.",
    )
    remediate_parser.add_argument(
        "--itsm-ticket-id",
        type=str,
        default=None,
        help="Change ticket ID to verify in the ITSM governance sink.",
    )
    remediate_parser.add_argument(
        "--itsm-tickets-file",
        "--itsm-sink-file",
        dest="itsm_tickets_file",
        type=Path,
        default=None,
        help="Path to a JsonFileItsmSink file containing ITSM change tickets.",
    )
    remediate_parser.add_argument(
        "--itsm-ticket-file",
        type=Path,
        default=None,
        help="Path to an individual ItsmTicketRequest JSON file.",
    )
    remediate_parser.add_argument(
        "--itsm-allow-scheduled",
        action="store_true",
        default=False,
        help="Allow SCHEDULED ITSM change tickets in addition to APPROVED tickets.",
    )
    remediate_parser.set_defaults(func=cmd_remediate)

    # 8. reconcile
    reconcile_parser = subparsers.add_parser(
        "reconcile",
        help="Reconcile live vCenter, SNMP, ARP, and ICMP discovery feeds against SoT snapshots to surface untracked assets.",
    )
    reconcile_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing extracted site snapshots.",
    )
    reconcile_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./output"),
        help="Directory to write reconciliation_report.json, reconciliation_discrepancies.csv, onboarding_template.csv, and onboarding_import.sql.",
    )
    reconcile_parser.add_argument(
        "--vcenter-json",
        type=Path,
        default=None,
        help="Path to multi-vCenter inventory JSON.",
    )
    reconcile_parser.add_argument(
        "--snmp-fixture",
        type=Path,
        default=None,
        help="Path to SNMP/ICMP discovery fixture JSON.",
    )
    reconcile_parser.add_argument(
        "--arp-json",
        type=Path,
        default=None,
        help="Optional path to live ARP observations JSON.",
    )
    reconcile_parser.add_argument(
        "--icmp-json",
        type=Path,
        default=None,
        help="Optional path to live ICMP observations JSON.",
    )
    reconcile_parser.add_argument(
        "--evaluation-time",
        "--generated-at",
        dest="generated_at",
        type=str,
        default=None,
        help="Optional ISO-8601 timestamp for the reconciliation report.",
    )
    _add_source_arguments(reconcile_parser)
    reconcile_parser.set_defaults(func=cmd_reconcile)
