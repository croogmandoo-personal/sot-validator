"""Unified CLI runner for sot-validator (`extract`, `validate`, `report`, `run`, `history`, `quarantine`, `remediate`, `reconcile`, `campaign`, `reclaim-ports`, `export-modern-sot`, `parity-check`, `ups-health`, `itsm`)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Optional

from sot_validator.campaign import (
    CampaignConfig,
    CampaignOrchestrator,
    JsonFileAlertSink,
    WebhookPayloadFormatter,
)
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
from sot_validator.history import HistoryStore
from sot_validator.itsm import (
    InMemoryItsmSink,
    ItsmGateVerifier,
    ItsmProvider,
    ItsmTicketPayloadBuilder,
    ItsmTicketRequest,
    ItsmWebhookSerializer,
    ItsmWorkflowType,
    JsonFileItsmSink,
    TicketApprovalStatus,
    WebhookItsmSink,
)
from sot_validator.migration import (
    GoldenInventoryFilter,
    ModernSoTExporter,
    ModernSoTParityValidator,
)
from sot_validator.models import Site, ValidationResult
from sot_validator.reconciliation import (
    InventoryReconciler,
    ReconciliationReport,
)
from sot_validator.remediation import (
    ApprovalStatus,
    DryRunActionPlan,
    DryRunActionPlanGenerator,
    ExtremeCliDialect,
    ExtremePortReclamationPlanner,
    PortReclamationPlan,
    QuarantineEngine,
    QuarantinePolicy,
    RemediationApprovalManifest,
    RemediationExecutor,
    RollbackJournal,
)
from sot_validator.reporting import (
    DEFAULT_DASHBOARD_FILENAME,
    generate_all_reports,
    generate_html_dashboard,
)
from sot_validator.signals.hypervisor import MultiVCenterInventoryProvider
from sot_validator.signals.icmp import IcmpProbeCollector
from sot_validator.signals.management import ManagementProbeCollector
from sot_validator.signals.ups_health import (
    ApcUpsHealthEvaluator,
    UpsFleetHealthReport,
)

DEFAULT_FIXTURE_EVALUATION_TIME = "2026-02-12T12:00:00Z"
DEFAULT_DISCOVERY_SAMPLE_EVALUATION_TIME = "2026-11-11T08:10:00Z"


def _parse_str_list(raw_values: Optional[Sequence[str]]) -> list[str]:
    if not raw_values:
        return []
    parsed: list[str] = []
    for raw in raw_values:
        for part in str(raw).split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in parsed:
                parsed.append(cleaned)
    return parsed


def _parse_site_ids(raw_values: Optional[Sequence[str]]) -> Optional[list[str]]:
    parsed = _parse_str_list(raw_values)
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


def _resolve_sites_for_command(
    args: argparse.Namespace,
    output_dir: Path,
    *,
    default_to_fixtures: bool = True,
) -> list[Site]:
    has_source = _has_source_flags(args)
    raw_snap = getattr(args, "snapshot_dir", None)
    if raw_snap is not None:
        snap_path = Path(raw_snap)
        if (snap_path / "snapshots" / "sites").exists() and not (
            snap_path / "sites"
        ).exists():
            snapshot_dir = snap_path / "snapshots"
        else:
            snapshot_dir = snap_path
    elif (output_dir / "sites").exists():
        snapshot_dir = output_dir
    elif (output_dir / "snapshots" / "sites").exists():
        snapshot_dir = output_dir / "snapshots"
    elif (Path("./snapshots") / "sites").exists() and not has_source:
        snapshot_dir = Path("./snapshots")
    else:
        snapshot_dir = output_dir / "snapshots"

    store = SnapshotStore(snapshot_dir)
    use_fixtures = (
        default_to_fixtures and not has_source and not store.load_all_sites()
    )
    return _extract_sites(args, snapshot_dir, default_to_fixtures=use_fixtures)


def _build_classification_engine(
    args: argparse.Namespace,
    sites: Sequence[Site],
) -> tuple[ClassificationEngine, Optional[str]]:
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
    return engine, eval_time


def _evaluate_sites(
    args: argparse.Namespace,
    sites: Sequence[Site],
) -> tuple[list[ValidationResult], Optional[str]]:
    engine, eval_time = _build_classification_engine(args, sites)
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


def _load_validation_results_with_timestamp(
    results_path: Path,
) -> tuple[list[ValidationResult], Optional[str]]:
    raw_data: Any = json.loads(results_path.read_text(encoding="utf-8"))
    generated_at: Optional[str] = None
    if isinstance(raw_data, dict):
        items = raw_data.get("results", [])
        if isinstance(raw_data.get("generated_at"), str):
            generated_at = raw_data["generated_at"]
    elif isinstance(raw_data, list):
        items = raw_data
    else:
        raise ValueError(
            f"Unsupported validation results format in {results_path}"
        )
    results = [
        item if isinstance(item, ValidationResult) else ValidationResult.from_dict(item)
        for item in items
    ]
    if generated_at is None and results and results[0].evaluated_at is not None:
        generated_at = results[0].evaluated_at.isoformat()
    return results, generated_at


def _load_validation_results_file(results_path: Path) -> list[ValidationResult]:
    results, _ = _load_validation_results_with_timestamp(results_path)
    return results


def _open_history_store(
    db_path: Path,
    *,
    import_json_path: Optional[Path] = None,
) -> tuple[HistoryStore, bool]:
    """Open a HistoryStore from SQLite or JSON file; returns (store, is_json_backed)."""
    if db_path.suffix.lower() == ".json":
        store = HistoryStore(":memory:")
        if db_path.exists():
            store.import_json(db_path)
        if import_json_path is not None and import_json_path.exists():
            store.import_json(import_json_path)
        return store, True

    store = HistoryStore(db_path)
    if import_json_path is not None and import_json_path.exists():
        store.import_json(import_json_path)
    return store, False


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
                par_path = candidate_dir / "parity_report.json"
                if par_path.exists():
                    parity_data = json.loads(
                        par_path.read_text(encoding="utf-8")
                    )
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
                t_path = candidate_dir / "itsm_tickets.json"
                if t_path.exists():
                    itsm_tickets = JsonFileItsmSink(t_path).tickets
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
        parity_report=parity_data,
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
    if getattr(args, "itsm_sink_file", None) is not None:
        itsm_sink = JsonFileItsmSink(Path(args.itsm_sink_file))

    itsm_ticket_obj: Optional[ItsmTicketRequest] = None
    if getattr(args, "itsm_ticket_file", None) is not None:
        raw_tkt = json.loads(
            Path(args.itsm_ticket_file).read_text(encoding="utf-8")
        )
        if isinstance(raw_tkt, list) and raw_tkt:
            itsm_ticket_obj = ItsmTicketRequest.from_dict(raw_tkt[0])
        elif isinstance(raw_tkt, dict):
            itsm_ticket_obj = ItsmTicketRequest.from_dict(raw_tkt)

    require_itsm = bool(
        getattr(args, "require_itsm_approval", False)
        or getattr(args, "itsm_ticket_id", None) is not None
        or itsm_ticket_obj is not None
    )

    executor = RemediationExecutor(
        dry_run=not confirm_write,
        confirm_write=confirm_write,
        journal_path=journal_path,
        strict_approval=bool(args.strict_approval),
        require_itsm_approval=require_itsm,
        itsm_sink=itsm_sink,
        itsm_ticket_id=getattr(args, "itsm_ticket_id", None),
        itsm_ticket=itsm_ticket_obj,
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
            itsm_ticket_id=getattr(args, "itsm_ticket_id", None),
            itsm_ticket=itsm_ticket_obj,
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


def cmd_campaign(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
    output_dir.mkdir(parents=True, exist_ok=True)
    sites = _resolve_sites_for_command(
        args, output_dir, default_to_fixtures=True
    )

    engine, eval_time = _build_classification_engine(args, sites)

    alerts_file = (
        Path(args.alerts_file)
        if args.alerts_file is not None
        else output_dir / "campaign_alerts.json"
    )
    if alerts_file.exists():
        alerts_file.unlink()
    alert_sink = JsonFileAlertSink(alerts_file)

    config = CampaignConfig(
        cohort_size=args.cohort_size,
        max_unreachable_ratio_per_site=args.max_unreachable_ratio,
        max_consecutive_aborted_sites=args.max_consecutive_aborted_sites,
        high_stale_ratio_threshold=args.high_stale_ratio_threshold,
        include_ip_addresses=getattr(args, "include_ips", True),
    )

    orchestrator = CampaignOrchestrator(
        config=config,
        engine=engine,
        alert_sinks=[alert_sink],
        evaluation_time=eval_time,
    )
    summary = orchestrator.run(
        sites,
        campaign_id=args.campaign_id,
        evaluation_time=eval_time,
    )

    (output_dir / "campaign_summary.json").write_text(
        summary.to_json(indent=2), encoding="utf-8"
    )
    if not alerts_file.exists():
        alerts_file.parent.mkdir(parents=True, exist_ok=True)
        alerts_file.write_text(
            json.dumps([a.to_dict() for a in summary.alerts], indent=2),
            encoding="utf-8",
        )

    if args.webhook_format is not None:
        if summary.alerts:
            webhook_payload = WebhookPayloadFormatter.format_payload(
                summary.alerts, target=args.webhook_format
            )
        else:
            webhook_payload = {
                "target": args.webhook_format,
                "alert_count": 0,
                "alerts": [],
            }
        (output_dir / "campaign_webhook_payload.json").write_text(
            json.dumps(webhook_payload, indent=2),
            encoding="utf-8",
        )

    if args.history_db is not None and summary.committed_validation_results:
        with HistoryStore(Path(args.history_db)) as hstore:
            hstore.record_run(
                summary.committed_validation_results,
                run_id=args.campaign_id,
                recorded_at=eval_time,
            )

    if getattr(args, "html_dashboard", False):
        dashboard_results = (
            summary.committed_validation_results
            if summary.committed_validation_results
            else [r for sr in summary.site_results for r in sr.results]
        )
        generate_html_dashboard(
            dashboard_results,
            sites=sites,
            output_path=output_dir / DEFAULT_DASHBOARD_FILENAME,
            generated_at=eval_time,
        )

    return 0


def cmd_reclaim_ports(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
    output_dir.mkdir(parents=True, exist_ok=True)
    sites = _resolve_sites_for_command(
        args, output_dir, default_to_fixtures=True
    )

    store: Optional[HistoryStore] = None
    if args.db_path is not None:
        store, _ = _open_history_store(Path(args.db_path))
    elif Path("./history.db").exists():
        store, _ = _open_history_store(Path("./history.db"))

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
        planner = ExtremePortReclamationPlanner(
            min_inactive_runs=args.min_inactive_runs,
            min_inactive_days=args.min_inactive_days,
            dialect=ExtremeCliDialect(args.dialect),
        )
        plan = planner.plan(
            sites=sites,
            history_store=store,
            lldp_neighbors=lldp_data,
            snmp_oids_by_device=snmp_data,
            evaluation_time=eval_time,
        )
    finally:
        if store is not None:
            store.close()

    plan_path = (
        Path(args.output_file)
        if args.output_file is not None
        else output_dir / "port_reclamation_plan.json"
    )
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(plan.to_json(indent=2), encoding="utf-8")

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


def cmd_export_modern_sot(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
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

    json_out = (
        Path(args.json_out)
        if args.json_out is not None
        else output_dir / f"{args.target_platform}_golden_bundle.json"
    )
    exporter.export_json(output_path=json_out)

    csv_bundle_dir = (
        Path(args.csv_bundle_dir)
        if args.csv_bundle_dir is not None
        else output_dir / f"{args.target_platform}_csv_bundle"
    )
    exporter.export_csv_bundle(csv_bundle_dir)
    return 0


def cmd_parity_check(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
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
        ).to_dict()

    waived_ids = _parse_str_list(args.waive_discrepancies)
    stale_ids = _parse_str_list(args.stale_item_ids)
    eval_time = (
        args.evaluated_at
        or file_eval_time
        or (sites and _infer_evaluation_time(args, sites))
    )

    validator = ModernSoTParityValidator(
        golden_bundle=golden_bundle,
        modern_bundle=modern_bundle,
        sites=sites,
        validation_results=results,
        reconciliation_report=recon_report,
        stale_item_ids=stale_ids if stale_ids else None,
        waived_discrepancy_ids=waived_ids if waived_ids else None,
        waive_all_parity_discrepancies=bool(args.waive_all),
        evaluated_at=eval_time,
    )
    report = validator.evaluate_sites()

    out_file = (
        Path(args.output_file)
        if args.output_file is not None
        else output_dir / "parity_report.json"
    )
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(report.to_json(indent=2), encoding="utf-8")
    return 0


def cmd_ups_health(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
    output_dir.mkdir(parents=True, exist_ok=True)
    sites = _resolve_sites_for_command(
        args, output_dir, default_to_fixtures=True
    )

    telemetry_data: Optional[Mapping[str, Any]] = None
    if args.snmp_fixture is not None:
        telemetry_data = json.loads(
            Path(args.snmp_fixture).read_text(encoding="utf-8")
        )

    eval_time = args.evaluation_time or _infer_evaluation_time(args, sites)
    evaluator = ApcUpsHealthEvaluator(
        min_runtime_minutes=args.min_runtime_minutes,
        max_temp_celsius=args.max_temp_celsius,
        max_load_pct=args.max_load_pct,
        telemetry_by_target=telemetry_data,
        evaluation_time=eval_time,
    )
    fleet_report = evaluator.evaluate_fleet(sites, evaluation_time=eval_time)

    out_file = (
        Path(args.output_file)
        if args.output_file is not None
        else output_dir / "ups_health_report.json"
    )
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(fleet_report.to_json(indent=2), encoding="utf-8")
    return 0


def cmd_itsm(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./output")
    output_dir.mkdir(parents=True, exist_ok=True)

    sink_file = (
        Path(args.sink_file)
        if args.sink_file is not None
        else output_dir / "itsm_tickets.json"
    )
    sink = JsonFileItsmSink(sink_file)

    if args.approve_ticket_id is not None:
        sink.approve_ticket(
            args.approve_ticket_id,
            approved_by=args.approved_by,
            approved_at=args.evaluation_time,
        )

    if args.reject_ticket_id is not None:
        sink.reject_ticket(
            args.reject_ticket_id,
            approved_by=args.approved_by,
            approved_at=args.evaluation_time,
        )

    builder = ItsmTicketPayloadBuilder(
        default_project_key=args.project_key,
        evaluation_time=args.evaluation_time,
    )

    generated_tickets: list[ItsmTicketRequest] = []
    initial_status = TicketApprovalStatus(args.approval_status)

    if args.manifest_file is not None:
        manifest = RemediationApprovalManifest.import_json(
            Path(args.manifest_file)
        )
        tkt = builder.build_quarantine_ticket(
            manifest,
            ticket_id=args.ticket_id,
            approval_status=initial_status,
            approved_by=args.approved_by if initial_status is TicketApprovalStatus.APPROVED else None,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    if args.port_plan_file is not None:
        port_plan = PortReclamationPlan.from_json(
            Path(args.port_plan_file).read_text(encoding="utf-8")
        )
        tkt = builder.build_port_reclamation_ticket(
            port_plan,
            ticket_id=args.ticket_id if not generated_tickets else None,
            approval_status=initial_status,
            approved_by=args.approved_by if initial_status is TicketApprovalStatus.APPROVED else None,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    if args.reconciliation_file is not None:
        recon = ReconciliationReport.from_json(Path(args.reconciliation_file))
        tkt = builder.build_onboarding_ticket(
            recon,
            ticket_id=args.ticket_id if not generated_tickets else None,
            approval_status=initial_status,
            approved_by=args.approved_by if initial_status is TicketApprovalStatus.APPROVED else None,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    if args.ups_health_file is not None:
        ups_rep = UpsFleetHealthReport.from_json(
            Path(args.ups_health_file).read_text(encoding="utf-8")
        )
        tkt = builder.build_ups_incident_ticket(
            ups_rep,
            ticket_id=args.ticket_id if not generated_tickets else None,
            approval_status=initial_status,
            approved_by=args.approved_by if initial_status is TicketApprovalStatus.APPROVED else None,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    provider = ItsmProvider(args.provider)
    active_tickets = generated_tickets if generated_tickets else sink.tickets
    if active_tickets:
        formatted_payloads = [
            ItsmWebhookSerializer.format_payload(
                t, provider=provider, project_key=args.project_key
            )
            for t in active_tickets
        ]
        payload_out = (
            Path(args.payload_out)
            if args.payload_out is not None
            else output_dir / f"itsm_{provider.value}_payloads.json"
        )
        payload_out.parent.mkdir(parents=True, exist_ok=True)
        payload_out.write_text(
            json.dumps(
                formatted_payloads[0]
                if len(formatted_payloads) == 1
                else formatted_payloads,
                indent=2,
            ),
            encoding="utf-8",
        )

    if args.verify_ticket_id is not None:
        verifier = ItsmGateVerifier(sink=sink, raise_on_failure=True)
        manifest_to_verify = (
            RemediationApprovalManifest.import_json(Path(args.manifest_file))
            if args.manifest_file is not None
            else None
        )
        plan_to_verify = (
            PortReclamationPlan.from_json(
                Path(args.port_plan_file).read_text(encoding="utf-8")
            )
            if args.port_plan_file is not None
            else None
        )
        verify_res = verifier.verify_change_ticket_approved(
            args.verify_ticket_id,
            expected_sha256=args.expected_sha256,
            manifest=manifest_to_verify,
            plan=plan_to_verify,
        )
        (output_dir / "itsm_verification_result.json").write_text(
            json.dumps(verify_res.to_dict(), indent=2), encoding="utf-8"
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
        type=Path,
        default=None,
        help="Optional Phase 4 PortReclamationPlan JSON file to embed in the HTML dashboard.",
    )
    report_parser.add_argument(
        "--parity-file",
        type=Path,
        default=None,
        help="Optional Phase 5 ParityValidationReport JSON file to embed in the HTML dashboard.",
    )
    report_parser.add_argument(
        "--ups-health-file",
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
        "--itsm-sink-file",
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

    # 9. campaign
    campaign_parser = subparsers.add_parser(
        "campaign",
        help="Execute rolling multi-site validation waves with outage circuit breakers and alert sinks.",
    )
    campaign_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing or storing site snapshots.",
    )
    campaign_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./output"),
        help="Directory to write campaign_summary.json and campaign_alerts.json (default: ./output).",
    )
    campaign_parser.add_argument(
        "--campaign-id",
        type=str,
        default="campaign-run",
        help="Campaign identifier (default: campaign-run).",
    )
    campaign_parser.add_argument(
        "--cohort-size",
        type=int,
        default=5,
        help="Number of sites per campaign wave (default: 5).",
    )
    campaign_parser.add_argument(
        "--max-unreachable-ratio",
        type=float,
        default=0.50,
        help="Per-site unreachable ratio threshold to quarantine site as suspected outage (default: 0.50).",
    )
    campaign_parser.add_argument(
        "--max-consecutive-aborted-sites",
        type=int,
        default=2,
        help="Consecutive outage-quarantined sites required to trip campaign circuit breaker (default: 2).",
    )
    campaign_parser.add_argument(
        "--high-stale-ratio-threshold",
        type=float,
        default=0.40,
        help="Per-site stale ratio threshold to emit warning alert (default: 0.40).",
    )
    campaign_parser.add_argument(
        "--alerts-file",
        type=Path,
        default=None,
        help="Path for JsonFileAlertSink output (defaults to <output-dir>/campaign_alerts.json).",
    )
    campaign_parser.add_argument(
        "--webhook-format",
        choices=["generic", "slack", "teams"],
        default=None,
        help="Optional webhook format to write <output-dir>/campaign_webhook_payload.json.",
    )
    campaign_parser.add_argument(
        "--history-db",
        type=Path,
        default=None,
        help="Optional HistoryStore SQLite DB to record committed validation results.",
    )
    campaign_parser.add_argument(
        "--html-dashboard",
        action="store_true",
        default=False,
        help="Generate validation_dashboard.html in --output-dir.",
    )
    _add_source_arguments(campaign_parser)
    _add_validation_arguments(campaign_parser)
    campaign_parser.set_defaults(func=cmd_campaign)

    # 10. reclaim-ports (Phase 4)
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
        default=Path("./output"),
        help="Directory to write port_reclamation_plan.json and EXOS/VOSS CLI scripts (default: ./output).",
    )
    reclaim_ports_parser.add_argument(
        "--output-file",
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

    # 11. export-modern-sot (Phase 5)
    export_sot_parser = subparsers.add_parser(
        "export-modern-sot",
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
        default=Path("./output"),
        help="Directory to write NetBox/Nautobot JSON and CSV bundles (default: ./output).",
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
        "--csv-bundle-dir",
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

    # 12. parity-check (Phase 5)
    parity_parser = subparsers.add_parser(
        "parity-check",
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
        default=Path("./output"),
        help="Directory to write parity_report.json (default: ./output).",
    )
    parity_parser.add_argument(
        "--output-file",
        type=Path,
        default=None,
        help="Optional explicit output path for parity_report.json.",
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
        "--waive-discrepancies",
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

    # 13. ups-health (Phase 6)
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
        default=Path("./output"),
        help="Directory to write ups_health_report.json (default: ./output).",
    )
    ups_parser.add_argument(
        "--output-file",
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
        "--max-temp-celsius",
        type=float,
        default=40.0,
        help="Maximum battery temperature in Celsius before thermal alert (default: 40.0).",
    )
    ups_parser.add_argument(
        "--max-load-pct",
        type=float,
        default=80.0,
        help="Maximum output load percentage before overload warning (default: 80.0).",
    )
    ups_parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Optional reference ISO-8601 UTC timestamp.",
    )
    _add_source_arguments(ups_parser)
    ups_parser.set_defaults(func=cmd_ups_health)

    # 14. itsm (Phase 6)
    itsm_parser = subparsers.add_parser(
        "itsm",
        help="Generate, approve, serialize, and verify ServiceNow/Jira/Webhook ITSM change tickets.",
    )
    itsm_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./output"),
        help="Directory to write ITSM ticket sink and provider payload files (default: ./output).",
    )
    itsm_parser.add_argument(
        "--sink-file",
        type=Path,
        default=None,
        help="Path to JsonFileItsmSink file (defaults to <output-dir>/itsm_tickets.json).",
    )
    itsm_parser.add_argument(
        "--manifest-file",
        type=Path,
        default=None,
        help="Optional Phase 2 RemediationApprovalManifest JSON file to generate a quarantine change ticket.",
    )
    itsm_parser.add_argument(
        "--port-plan-file",
        type=Path,
        default=None,
        help="Optional Phase 4 PortReclamationPlan JSON file to generate a port reclamation change ticket.",
    )
    itsm_parser.add_argument(
        "--reconciliation-file",
        type=Path,
        default=None,
        help="Optional Phase 3 ReconciliationReport JSON file to generate a Shadow IT onboarding task.",
    )
    itsm_parser.add_argument(
        "--ups-health-file",
        type=Path,
        default=None,
        help="Optional Phase 6 UpsFleetHealthReport JSON file to generate an APC UPS hardware incident ticket.",
    )
    itsm_parser.add_argument(
        "--ticket-id",
        type=str,
        default=None,
        help="Optional explicit ticket ID when generating a ticket.",
    )
    itsm_parser.add_argument(
        "--provider",
        choices=["servicenow", "jira", "webhook"],
        default="servicenow",
        help="Target ITSM provider payload format (default: servicenow).",
    )
    itsm_parser.add_argument(
        "--project-key",
        type=str,
        default="NETOPS",
        help="Jira project key when formatting Jira payloads (default: NETOPS).",
    )
    itsm_parser.add_argument(
        "--approval-status",
        choices=["PENDING", "APPROVED", "SCHEDULED", "REJECTED", "CANCELLED"],
        default="PENDING",
        help="Initial approval status for newly generated tickets (default: PENDING).",
    )
    itsm_parser.add_argument(
        "--approve-ticket-id",
        type=str,
        default=None,
        help="Ticket ID in sink to transition to APPROVED.",
    )
    itsm_parser.add_argument(
        "--reject-ticket-id",
        type=str,
        default=None,
        help="Ticket ID in sink to transition to REJECTED.",
    )
    itsm_parser.add_argument(
        "--approved-by",
        type=str,
        default="cab-approver",
        help="Approver identifier recorded when approving/rejecting tickets (default: cab-approver).",
    )
    itsm_parser.add_argument(
        "--verify-ticket-id",
        type=str,
        default=None,
        help="Ticket ID to verify via ItsmGateVerifier (exits non-zero if unapproved or SHA-256 mismatches).",
    )
    itsm_parser.add_argument(
        "--expected-sha256",
        type=str,
        default=None,
        help="Optional explicit expected SHA-256 digest when verifying a ticket.",
    )
    itsm_parser.add_argument(
        "--payload-out",
        type=Path,
        default=None,
        help="Optional explicit file path for formatted provider payload JSON.",
    )
    itsm_parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Optional ISO-8601 UTC timestamp.",
    )
    itsm_parser.set_defaults(func=cmd_itsm)

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
