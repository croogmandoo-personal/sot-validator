"""Unified CLI runner for sot-validator (`extract`, `validate`, `report`, `run`, `history`, `quarantine`, `remediate`, `reconcile`, `campaign`, `preflight`, `reclaim-ports`, `export-modern-sot`, `parity-check`, `ups-health`, `itsm`, `discover`, `serve`, `curate`, `topology`, `fingerprint`, `map-ports`, `diff-scans`)."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sqlite3
import sys
import threading
from typing import Any, Optional
from urllib.request import urlopen

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
from sot_validator.connectors import (
    PilotCutoverValidator,
    SnmpWalkConnector,
    VSphereRestConnector,
)
from sot_validator.curation import (
    CurationStore,
    ItemEditPatch,
    apply_curation_overlay,
)
from sot_validator.discovery import (
    DEFAULT_GATEWAY_OCTETS,
    DEFAULT_TCP_PORTS,
    DiscoveredHost,
    DiscoveryConfig,
    DriftAlertDispatcher,
    DriftAlertTarget,
    RawServiceBanner,
    RouterArpDhcpCollector,
    RouterArpRecord,
    RouterTableParsers,
    ServiceBannerFingerprinter,
    SnapshotDiffEngine,
    SubnetDiscoveryScanner,
)
from sot_validator.extraction import (
    BatchExtractor,
    FixtureSoTClient,
    HtmlScraperSoTClient,
    SnapshotStore,
    SoTClient,
    SqlExportSoTClient,
)
from sot_validator.history import HistoryStore, ItemStreakSummary
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
)
from sot_validator.migration import (
    DualRunParityChecker,
    GoldenInventoryFilter,
    ModernSoTExporter,
)
from sot_validator.models import (
    EquipmentCategory,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
)
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
from sot_validator.signals.directory_dns import (
    ActiveDirectoryCollector,
    DnsDhcpLeaseCollector,
)
from sot_validator.signals.hypervisor import MultiVCenterInventoryProvider
from sot_validator.signals.icmp import IcmpProbeCollector
from sot_validator.signals.management import ManagementProbeCollector
from sot_validator.signals.proxmox_containers import ProxmoxClusterSnapshot
from sot_validator.signals.ups_health import (
    ApcUpsHealthEvaluator,
    UpsFleetHealthReport,
)
from sot_validator.topology import (
    DevicePortManager,
    DeviceTypeCatalog,
    FdbEntry,
    FdbTableParser,
    NetworkRoleIdentifier,
    SwitchFdbPortMapper,
    TopologyGraphBuilder,
)
from sot_validator.workbench import (
    WorkbenchState,
    create_workbench_server,
    render_workbench_html,
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
            "sqlite_path",
            "csv_dir",
            "json_export",
            "scrape_url",
        )
    )


def _build_sot_client(
    args: argparse.Namespace, *, default_to_fixtures: bool = False
) -> Optional[SoTClient]:
    if getattr(args, "sqlite_path", None) is not None:
        return SqlExportSoTClient.from_sqlite(args.sqlite_path)
    if getattr(args, "sql_dump", None) is not None:
        sql_path = Path(args.sql_dump)
        if sql_path.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            return SqlExportSoTClient.from_sqlite(sql_path)
        return SqlExportSoTClient.from_sql_dump(sql_path)
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
        "--sqlite-path",
        type=Path,
        default=None,
        help="Path to a read-only SQLite database export.",
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
        "--ad-json",
        type=Path,
        default=None,
        help="Path to an Active Directory computer account export JSON file.",
    )
    parser.add_argument(
        "--dns-json",
        type=Path,
        default=None,
        help="Path to a DNS forward/reverse (A/PTR) records JSON file.",
    )
    parser.add_argument(
        "--dhcp-json",
        type=Path,
        default=None,
        help="Path to a /24-scoped DHCP lease export JSON file.",
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


def _load_ad_collector(
    ad_json_path: Optional[Path],
    *,
    active_within_days: float,
    stale_after_days: float,
    evaluation_time: Optional[str],
) -> Optional[ActiveDirectoryCollector]:
    if ad_json_path is None:
        return None
    raw = json.loads(Path(ad_json_path).read_text(encoding="utf-8"))
    if isinstance(raw, Mapping):
        records = (
            raw.get("computers")
            or raw.get("records")
            or raw.get("accounts")
            or []
        )
    elif isinstance(raw, list):
        records = raw
    else:
        records = []
    return ActiveDirectoryCollector(
        records=records,
        active_within_days=active_within_days,
        stale_after_days=stale_after_days,
        evaluation_time=evaluation_time,
    )


def _load_dns_dhcp_collector(
    dns_json_path: Optional[Path],
    dhcp_json_path: Optional[Path],
    *,
    evaluation_time: Optional[str],
) -> Optional[DnsDhcpLeaseCollector]:
    if dns_json_path is None and dhcp_json_path is None:
        return None

    dns_records: Optional[Any] = None
    a_records: Optional[Any] = None
    ptr_records: Optional[Any] = None
    if dns_json_path is not None:
        raw_dns = json.loads(Path(dns_json_path).read_text(encoding="utf-8"))
        if isinstance(raw_dns, Mapping):
            if "a_records" in raw_dns or "ptr_records" in raw_dns or "forward_records" in raw_dns or "reverse_records" in raw_dns:
                a_records = raw_dns.get("a_records") or raw_dns.get("forward_records")
                ptr_records = raw_dns.get("ptr_records") or raw_dns.get("reverse_records")
                dns_records = raw_dns.get("dns_records") or raw_dns.get("records")
            else:
                dns_records = (
                    raw_dns.get("records")
                    or raw_dns.get("dns_records")
                    or []
                )
        elif isinstance(raw_dns, list):
            dns_records = raw_dns

    dhcp_leases: Optional[Any] = None
    if dhcp_json_path is not None:
        raw_dhcp = json.loads(Path(dhcp_json_path).read_text(encoding="utf-8"))
        if isinstance(raw_dhcp, Mapping):
            dhcp_leases = (
                raw_dhcp.get("leases")
                or raw_dhcp.get("dhcp_leases")
                or raw_dhcp.get("records")
                or []
            )
        elif isinstance(raw_dhcp, list):
            dhcp_leases = raw_dhcp

    return DnsDhcpLeaseCollector(
        dns_records=dns_records,
        a_records=a_records,
        ptr_records=ptr_records,
        dhcp_leases=dhcp_leases,
        evaluation_time=evaluation_time,
    )


def _build_classification_engine(
    args: argparse.Namespace,
    sites: Sequence[Site],
) -> tuple[ClassificationEngine, Optional[str]]:
    eval_time = _infer_evaluation_time(args, sites)
    active_days = float(getattr(args, "active_within_days", 7.0))
    stale_days = float(getattr(args, "stale_after_days", 30.0))
    policy = ClassificationPolicy(
        active_within_days=active_days,
        stale_after_days=stale_days,
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

    ad_collector = _load_ad_collector(
        getattr(args, "ad_json", None),
        active_within_days=active_days,
        stale_after_days=stale_days,
        evaluation_time=eval_time,
    )
    dns_dhcp_collector = _load_dns_dhcp_collector(
        getattr(args, "dns_json", None),
        getattr(args, "dhcp_json", None),
        evaluation_time=eval_time,
    )

    engine = ClassificationEngine(
        policy=policy,
        icmp_collector=icmp_collector,
        management_collector=management_collector,
        hypervisor_provider=hypervisor_provider,
        ad_collector=ad_collector,
        dns_dhcp_collector=dns_dhcp_collector,
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


def cmd_preflight(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    sites = _resolve_sites_for_command(
        args, output_dir, default_to_fixtures=True
    )
    pilot_site_ids = _parse_str_list(args.pilot_sites)
    if not pilot_site_ids:
        pilot_site_ids = [s.site_id for s in sites]

    target_subnets: Optional[dict[str, list[str]]] = None
    if args.target_subnets_json is not None:
        raw_sub = json.loads(
            Path(args.target_subnets_json).read_text(encoding="utf-8")
        )
        if isinstance(raw_sub, Mapping):
            target_subnets = {
                str(k): [str(c) for c in v]
                for k, v in raw_sub.items()
                if isinstance(v, Sequence) and not isinstance(v, (str, bytes))
            }

    vsphere_conn: Optional[VSphereRestConnector] = None
    if args.vcenter_json is not None:
        raw_vc = json.loads(
            Path(args.vcenter_json).read_text(encoding="utf-8")
        )
        vsphere_conn = VSphereRestConnector(fixture_data=raw_vc)

    snmp_conn: Optional[SnmpWalkConnector] = None
    if args.snmp_fixture is not None:
        raw_snmp = json.loads(
            Path(args.snmp_fixture).read_text(encoding="utf-8")
        )
        snmp_conn = SnmpWalkConnector(fixture_data=raw_snmp)

    sot_client = _build_sot_client(args, default_to_fixtures=False)
    validator = PilotCutoverValidator(
        sot_client=sot_client,
        vsphere_connector=vsphere_conn,
        snmp_connector=snmp_conn,
        recommended_min_sites=args.recommended_min_sites,
        recommended_max_sites=args.recommended_max_sites,
    )
    report = validator.validate(
        pilot_site_ids=pilot_site_ids,
        sites=sites,
        target_subnets_by_site=target_subnets,
    )

    payload_text = json.dumps(report.to_dict(), indent=2)
    report_path = output_dir / "preflight_report.json"
    report_path.write_text(payload_text, encoding="utf-8")

    if args.output is not None:
        custom_out = Path(args.output)
        custom_out.parent.mkdir(parents=True, exist_ok=True)
        custom_out.write_text(payload_text, encoding="utf-8")

    if getattr(args, "strict", False) and not report.ready:
        return 1
    return 0


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


def cmd_itsm(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir or "./reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    sink_file = (
        Path(args.sink_file)
        if args.sink_file is not None
        else output_dir / "itsm_tickets.json"
    )
    sink = JsonFileItsmSink(sink_file)

    eval_ts = args.approved_at or args.evaluation_time

    if args.approve_ticket_id is not None:
        sink.approve_ticket(
            args.approve_ticket_id,
            approved_by=args.approved_by,
            approved_at=eval_ts,
        )

    if args.reject_ticket_id is not None:
        sink.reject_ticket(
            args.reject_ticket_id,
            approved_by=args.approved_by,
            approved_at=eval_ts,
        )

    builder_kwargs: dict[str, Any] = {
        "default_project_key": args.project_key,
        "evaluation_time": args.evaluation_time,
    }
    if args.cmdb_ci:
        builder_kwargs["default_cmdb_ci"] = args.cmdb_ci
    builder = ItsmTicketPayloadBuilder(**builder_kwargs)

    generated_tickets: list[ItsmTicketRequest] = []
    initial_status = TicketApprovalStatus(args.approval_status)
    approved_by_arg = (
        args.approved_by
        if initial_status is TicketApprovalStatus.APPROVED
        else None
    )

    manifest_obj: Optional[RemediationApprovalManifest] = None
    port_plan_obj: Optional[PortReclamationPlan] = None
    recon_obj: Optional[ReconciliationReport] = None
    ups_obj: Optional[UpsFleetHealthReport] = None
    generic_artifact_obj: Optional[Any] = None

    if args.manifest_file is not None:
        manifest_obj = RemediationApprovalManifest.import_json(
            Path(args.manifest_file)
        )
        tkt = builder.build_quarantine_ticket(
            manifest_obj,
            ticket_id=args.ticket_id,
            site_id=args.site_id,
            cmdb_ci=args.cmdb_ci,
            approval_status=initial_status,
            approved_by=approved_by_arg,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    if args.port_plan_file is not None:
        port_plan_obj = PortReclamationPlan.from_json(
            Path(args.port_plan_file).read_text(encoding="utf-8")
        )
        tkt = builder.build_port_reclamation_ticket(
            port_plan_obj,
            ticket_id=args.ticket_id if not generated_tickets else None,
            cmdb_ci=args.cmdb_ci,
            approval_status=initial_status,
            approved_by=approved_by_arg,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    if args.reconciliation_file is not None:
        recon_obj = ReconciliationReport.from_json(
            Path(args.reconciliation_file)
        )
        tkt = builder.build_onboarding_ticket(
            recon_obj,
            ticket_id=args.ticket_id if not generated_tickets else None,
            site_id=args.site_id,
            cmdb_ci=args.cmdb_ci,
            approval_status=initial_status,
            approved_by=approved_by_arg,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    if args.ups_health_file is not None:
        ups_obj = UpsFleetHealthReport.from_json(
            Path(args.ups_health_file).read_text(encoding="utf-8")
        )
        tkt = builder.build_ups_incident_ticket(
            ups_obj,
            ticket_id=args.ticket_id if not generated_tickets else None,
            site_id=args.site_id,
            cmdb_ci=args.cmdb_ci,
            approval_status=initial_status,
            approved_by=approved_by_arg,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    if args.artifact_file is not None:
        generic_artifact_obj = json.loads(
            Path(args.artifact_file).read_text(encoding="utf-8")
        )
        wtype = (
            ItsmWorkflowType(args.workflow_type)
            if args.workflow_type is not None
            else None
        )
        tkt = builder.build_ticket(
            generic_artifact_obj,
            workflow_type=wtype,
            ticket_id=args.ticket_id if not generated_tickets else None,
            site_id=args.site_id,
            cmdb_ci=args.cmdb_ci,
            approval_status=initial_status,
            approved_by=approved_by_arg,
        )
        sink.submit_ticket(tkt)
        generated_tickets.append(tkt)

    provider = ItsmProvider(args.provider)
    active_tickets = generated_tickets if generated_tickets else sink.tickets
    if active_tickets:
        first_ticket_json = active_tickets[-1].to_json(indent=2)
        (output_dir / "itsm_ticket.json").write_text(
            first_ticket_json, encoding="utf-8"
        )
        if args.output is not None:
            custom_out = Path(args.output)
            custom_out.parent.mkdir(parents=True, exist_ok=True)
            custom_out.write_text(first_ticket_json, encoding="utf-8")

        formatted_payloads = [
            ItsmWebhookSerializer.format_payload(
                t, provider=provider, project_key=args.project_key
            )
            for t in active_tickets
        ]
        payload_data = (
            formatted_payloads[0]
            if len(formatted_payloads) == 1
            else formatted_payloads
        )
        payload_text = json.dumps(payload_data, indent=2)

        (output_dir / f"itsm_payload_{provider.value}.json").write_text(
            payload_text, encoding="utf-8"
        )
        (output_dir / f"itsm_{provider.value}_payloads.json").write_text(
            payload_text, encoding="utf-8"
        )
        if args.payload_out is not None:
            p_out = Path(args.payload_out)
            p_out.parent.mkdir(parents=True, exist_ok=True)
            p_out.write_text(payload_text, encoding="utf-8")

    if args.verify_ticket_id is not None:
        verifier = ItsmGateVerifier(
            sink=sink,
            allow_scheduled=bool(args.allow_scheduled),
            raise_on_failure=True,
        )
        verify_res = verifier.require_change_ticket_approved(
            args.verify_ticket_id,
            expected_sha256=args.expected_sha256,
            manifest=manifest_obj,
            plan=port_plan_obj,
            artifact=generic_artifact_obj or recon_obj or ups_obj,
            allow_scheduled=bool(args.allow_scheduled),
        )
        (output_dir / "itsm_verification_result.json").write_text(
            json.dumps(verify_res.to_dict(), indent=2), encoding="utf-8"
        )

    return 0


def _parse_int_list(raw_values: Optional[Sequence[Any]]) -> list[int]:
    if not raw_values:
        return []
    parsed: list[int] = []
    for raw in raw_values:
        for part in str(raw).split(","):
            cleaned = part.strip()
            if cleaned:
                val = int(cleaned)
                if val not in parsed:
                    parsed.append(val)
    return parsed


def _load_single_site_snapshot(
    snapshot_path: Optional[Path],
    args: argparse.Namespace,
    *,
    default_to_fixtures: bool = True,
) -> Site:
    """Load a single Site from a JSON snapshot file, a SnapshotStore directory, or source/fixture flags."""
    wanted_ids = _parse_site_ids(getattr(args, "site_ids", None))
    explicit_site_id = getattr(args, "site_id", None)
    if explicit_site_id and not wanted_ids:
        wanted_ids = [str(explicit_site_id).strip()]

    if snapshot_path is not None:
        snap = Path(snapshot_path)
        if snap.is_dir():
            store_dir = (
                snap / "snapshots"
                if (snap / "snapshots" / "sites").exists()
                and not (snap / "sites").exists()
                else snap
            )
            sites = SnapshotStore(store_dir).load_all_sites()
            if not sites:
                raise ValueError(f"No site snapshots found in directory {snap}")
            if wanted_ids:
                for s in sites:
                    if s.site_id in wanted_ids:
                        return s
            return sites[0]

        raw = json.loads(snap.read_text(encoding="utf-8"))
        if isinstance(raw, Mapping):
            if "site" in raw and isinstance(raw["site"], Mapping):
                return Site.from_dict(raw["site"])
            if "sites" in raw and isinstance(raw["sites"], Sequence):
                sites = [
                    s if isinstance(s, Site) else Site.from_dict(s)
                    for s in raw["sites"]
                ]
                if not sites:
                    raise ValueError(f"Empty sites list in {snap}")
                if wanted_ids:
                    for s in sites:
                        if s.site_id in wanted_ids:
                            return s
                return sites[0]
            return Site.from_dict(raw)
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
            sites = [
                s if isinstance(s, Site) else Site.from_dict(s) for s in raw
            ]
            if not sites:
                raise ValueError(f"Empty sites list in {snap}")
            if wanted_ids:
                for s in sites:
                    if s.site_id in wanted_ids:
                        return s
            return sites[0]
        raise ValueError(f"Unsupported site snapshot format in {snap}")

    fallback_dir = Path(getattr(args, "output_dir", None) or "./output")
    sites = _resolve_sites_for_command(
        args, fallback_dir, default_to_fixtures=default_to_fixtures
    )
    if not sites:
        sites = FixtureSoTClient(num_sites=1).extract_all()
    if wanted_ids:
        for s in sites:
            if s.site_id in wanted_ids:
                return s
    return sites[0]


def _open_curation_store(
    curation_db: Optional[Path | str],
    *,
    import_json_path: Optional[Path] = None,
) -> tuple[CurationStore, Optional[Path]]:
    """Open a CurationStore from SQLite path, JSON state path, or :memory:."""
    json_export_target: Optional[Path] = None
    if curation_db is None or str(curation_db).strip() in ("", ":memory:"):
        store = CurationStore(":memory:")
    else:
        db_path = Path(curation_db)
        if db_path.suffix.lower() == ".json":
            store = CurationStore(":memory:")
            if db_path.exists():
                store.import_json(db_path)
            json_export_target = db_path
        else:
            store = CurationStore(db_path)

    if import_json_path is not None and Path(import_json_path).exists():
        store.import_json(Path(import_json_path))

    return store, json_export_target


def _load_json_object_list(path: Path, *, key: str) -> list[Mapping[str, Any]]:
    """Load a JSON list of objects from a bare list or a ``{"<key>": [...]}`` envelope."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, Mapping):
        items: Any = raw.get(key, [])
    elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        items = raw
    else:
        raise ValueError(f"Unsupported {key} JSON in {path}")

    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise ValueError(f"Expected a list of objects for {key!r} in {path}")
    objects: list[Mapping[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError(f"Expected JSON objects in {key!r} from {path}")
        objects.append(item)
    return objects


def _build_fixture_discovery_callbacks(
    cidr: str,
) -> tuple[Any, Any, Any, Any]:
    """Construct deterministic offline discovery callbacks for `--fixtures` runs."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    octets = str(net.network_address).split(".")
    if net.prefixlen == 24:
        subnet_prefixes = [f"{octets[0]}.{octets[1]}.{octets[2]}"]
    else:
        subnet_prefixes = [
            f"{octets[0]}.{octets[1]}.1",
            f"{octets[0]}.{octets[1]}.10",
        ]

    ping_rtt: dict[str, float] = {}
    open_ports: dict[str, set[int]] = {}
    arp_map: dict[str, tuple[str, str]] = {}
    rdns_map: dict[str, str] = {}

    for idx, pfx in enumerate(subnet_prefixes, start=1):
        gw_ip = f"{pfx}.1"
        sw_ip = f"{pfx}.2"
        hv_ip = f"{pfx}.10"
        ups_ip = f"{pfx}.20"
        nas_ip = f"{pfx}.30"

        ping_rtt[gw_ip] = 0.5
        ping_rtt[sw_ip] = 0.7
        ping_rtt[hv_ip] = 0.9
        ping_rtt[ups_ip] = 1.2
        ping_rtt[nas_ip] = 1.1

        open_ports[gw_ip] = {53, 80, 443}
        open_ports[sw_ip] = {22, 443}
        open_ports[hv_ip] = {22, 8006}
        open_ports[ups_ip] = {80, 443}
        open_ports[nas_ip] = {445, 5000}

        arp_map[gw_ip] = (f"aa:9c:6c:00:0{idx}:01", "REACHABLE")
        arp_map[sw_ip] = (f"00:04:96:00:0{idx}:02", "REACHABLE")
        arp_map[hv_ip] = (f"bc:24:11:00:0{idx}:10", "REACHABLE")
        arp_map[ups_ip] = (f"00:c0:b7:00:0{idx}:20", "REACHABLE")
        arp_map[nas_ip] = (f"00:11:32:00:0{idx}:30", "REACHABLE")

        rdns_map[gw_ip] = f"gw-vlan{pfx.split('.')[-1]}.local"
        rdns_map[sw_ip] = f"sw-core-{idx:02d}.local"
        rdns_map[hv_ip] = f"pve-node-{idx:02d}.local"
        rdns_map[ups_ip] = f"apc-ups-{idx:02d}.local"
        rdns_map[nas_ip] = f"synology-nas-{idx:02d}.local"

    def _ping_fn(ip: str, _timeout: float = 1.0) -> tuple[bool, Optional[float]]:
        if ip in ping_rtt:
            return True, ping_rtt[ip]
        return False, None

    def _tcp_fn(ip: str, port: int, _timeout: float = 0.35) -> bool:
        return int(port) in open_ports.get(ip, set())

    def _arp_fn() -> dict[str, tuple[str, str]]:
        return dict(arp_map)

    def _rdns_fn(ip: str) -> Optional[str]:
        return rdns_map.get(ip)

    return _ping_fn, _tcp_fn, _arp_fn, _rdns_fn


def _load_mock_discovery_config(
    mock_config_path: Path,
) -> tuple[Optional[list[DiscoveredHost]], Optional[list[str]], Any, Any, Any, Any]:
    """Load mock discovery hosts or callback tables from a JSON file."""
    raw = json.loads(Path(mock_config_path).read_text(encoding="utf-8"))
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        hosts = [
            h if isinstance(h, DiscoveredHost) else DiscoveredHost.from_dict(h)
            for h in raw
        ]
        return hosts, None, None, None, None, None

    if not isinstance(raw, Mapping):
        raise ValueError(f"Unsupported mock discovery config in {mock_config_path}")

    explicit_hosts: Optional[list[DiscoveredHost]] = None
    if "hosts" in raw and isinstance(raw["hosts"], Sequence):
        explicit_hosts = [
            h if isinstance(h, DiscoveredHost) else DiscoveredHost.from_dict(h)
            for h in raw["hosts"]
        ]

    explicit_subnets: Optional[list[str]] = None
    if "active_subnets" in raw and isinstance(raw["active_subnets"], Sequence):
        explicit_subnets = [str(s) for s in raw["active_subnets"]]

    raw_ping = (
        raw.get("ping")
        if "ping" in raw
        else raw.get("icmp", raw.get("reachable_ips"))
    )
    ping_map: dict[str, tuple[bool, Optional[float]]] = {}
    if isinstance(raw_ping, Mapping):
        for ip_k, val in raw_ping.items():
            ip_str = str(ip_k).strip()
            if isinstance(val, bool):
                ping_map[ip_str] = (val, 1.0 if val else None)
            elif isinstance(val, (int, float)):
                reachable = float(val) >= 0.0
                ping_map[ip_str] = (reachable, float(val) if reachable else None)
            elif isinstance(val, Sequence) and not isinstance(val, (str, bytes)):
                seq = list(val)
                reachable = bool(seq[0]) if seq else False
                rtt = float(seq[1]) if len(seq) > 1 and seq[1] is not None and reachable else None
                ping_map[ip_str] = (reachable, rtt)
            elif isinstance(val, Mapping):
                reachable = bool(val.get("reachable", True))
                raw_rtt = val.get("rtt_ms", val.get("latency_ms", 1.0))
                ping_map[ip_str] = (
                    reachable,
                    float(raw_rtt) if raw_rtt is not None and reachable else None,
                )
    elif isinstance(raw_ping, Sequence) and not isinstance(raw_ping, (str, bytes)):
        for ip_k in raw_ping:
            ping_map[str(ip_k).strip()] = (True, 1.0)

    raw_tcp = (
        raw.get("tcp_ports")
        if "tcp_ports" in raw
        else raw.get("open_ports", raw.get("open_ports_by_ip"))
    )
    tcp_map: dict[str, set[int]] = {}
    if isinstance(raw_tcp, Mapping):
        for ip_k, ports_val in raw_tcp.items():
            if isinstance(ports_val, Sequence) and not isinstance(
                ports_val, (str, bytes)
            ):
                tcp_map[str(ip_k).strip()] = {int(p) for p in ports_val}

    raw_arp = raw.get("arp_table", raw.get("arp"))
    raw_rdns = raw.get("rdns", raw.get("hostnames", raw.get("rdns_by_ip")))
    rdns_map: dict[str, str] = {}
    if isinstance(raw_rdns, Mapping):
        for ip_k, host_val in raw_rdns.items():
            if host_val:
                rdns_map[str(ip_k).strip()] = str(host_val).strip()

    def _ping_fn(ip: str, _timeout: float = 1.0) -> tuple[bool, Optional[float]]:
        return ping_map.get(ip, (False, None))

    def _tcp_fn(ip: str, port: int, _timeout: float = 0.35) -> bool:
        return int(port) in tcp_map.get(ip, set())

    def _arp_fn() -> Any:
        return raw_arp if raw_arp is not None else {}

    def _rdns_fn(ip: str) -> Optional[str]:
        return rdns_map.get(ip)

    return explicit_hosts, explicit_subnets, _ping_fn, _tcp_fn, _arp_fn, _rdns_fn


def _enrich_discovered_site_with_identifier(
    site: Site,
    hosts: Sequence[DiscoveredHost],
    identifier: NetworkRoleIdentifier,
    catalog: DeviceTypeCatalog,
) -> Site:
    """Enrich a discovered Site snapshot with NetworkRoleIdentifier metadata and VLAN/subnet names."""
    if not hosts:
        return site

    observations = [
        {
            "ip": h.ip,
            "mac": h.mac_address,
            "hostname": h.hostname,
            "open_ports": list(h.open_tcp_ports),
            "subnet_cidr": h.subnet_cidr,
            "vlan_id": h.vlan_id,
        }
        for h in hosts
    ]
    identifications = identifier.identify_hosts(observations)
    ident_by_ip = {ident.ip: ident for ident in identifications}
    consolidated_routers = identifier.consolidate_multi_vlan_routers(
        identifications
    )
    router_by_ip = {
        gw_ip: rtr
        for rtr in consolidated_routers
        for gw_ip in rtr.gateway_ips
    }

    inferred_vlans, inferred_subnets = identifier.infer_vlans_and_subnets(
        identifications, site_id=site.site_id
    )
    inferred_vlan_by_cidr = {v.cidr: v for v in inferred_vlans if v.cidr}
    inferred_sub_by_cidr = {s.cidr: s for s in inferred_subnets if s.cidr}

    for vlan in site.vlans:
        if vlan.cidr and vlan.cidr in inferred_vlan_by_cidr:
            inf_v = inferred_vlan_by_cidr[vlan.cidr]
            if inf_v.name and (
                not vlan.name or vlan.name == f"VLAN {vlan.vlan_id}"
            ):
                vlan.name = inf_v.name

    for sub in site.subnets:
        if sub.cidr and sub.cidr in inferred_sub_by_cidr:
            inf_s = inferred_sub_by_cidr[sub.cidr]
            if inf_s.name and (
                not sub.name or sub.name == f"Subnet {sub.cidr}"
            ):
                sub.name = inf_s.name

    for dev in site.devices:
        if dev.management_ip and dev.management_ip in ident_by_ip:
            ident = ident_by_ip[dev.management_ip]
            if ident.vendor and not dev.vendor:
                dev.vendor = ident.vendor
            rtr = router_by_ip.get(dev.management_ip)
            tpl_id = (
                rtr.suggested_template_id
                if rtr is not None and rtr.suggested_template_id
                else ident.suggested_template_id
            )
            if tpl_id and not dev.model:
                try:
                    tpl = catalog.get(tpl_id)
                    dev.model = tpl.model
                    if not dev.vendor:
                        dev.vendor = tpl.vendor
                except KeyError:
                    pass

    return site


def cmd_discover(args: argparse.Namespace) -> int:
    gw_octets = (
        tuple(_parse_int_list(args.gateway_octets))
        if getattr(args, "gateway_octets", None)
        else DEFAULT_GATEWAY_OCTETS
    )
    tcp_ports = (
        tuple(_parse_int_list(args.tcp_ports))
        if getattr(args, "tcp_ports", None)
        else DEFAULT_TCP_PORTS
    )

    config = DiscoveryConfig(
        cidr=args.cidr,
        gateway_octets=gw_octets,
        tcp_ports=tcp_ports,
        max_concurrency=args.max_concurrency,
        ping_timeout_sec=args.ping_timeout,
        tcp_timeout_sec=args.tcp_timeout,
        max_active_subnets=args.max_active_subnets,
    )

    explicit_hosts: Optional[list[DiscoveredHost]] = None
    explicit_subnets: Optional[list[str]] = None
    ping_fn = None
    tcp_fn = None
    arp_fn = None
    rdns_fn = None

    if getattr(args, "mock_config", None) is not None:
        (
            explicit_hosts,
            explicit_subnets,
            ping_fn,
            tcp_fn,
            arp_fn,
            rdns_fn,
        ) = _load_mock_discovery_config(Path(args.mock_config))
    elif getattr(args, "fixtures", False):
        ping_fn, tcp_fn, arp_fn, rdns_fn = _build_fixture_discovery_callbacks(
            config.cidr
        )

    scanner = SubnetDiscoveryScanner(
        config,
        ping_fn=ping_fn,
        tcp_probe_fn=tcp_fn,
        arp_table_fn=arp_fn,
        rdns_fn=rdns_fn,
    )

    if explicit_hosts is not None:
        hosts = list(explicit_hosts)
        active_subnets = explicit_subnets
    else:
        active_subnets = scanner.discover_active_subnets()
        hosts = []
        for sub_cidr in active_subnets[: config.max_active_subnets]:
            hosts.extend(scanner.sweep_subnet(sub_cidr))

    arp_records: Optional[list[RouterArpRecord]] = None
    if getattr(args, "router_arp", None) is not None:
        arp_path = Path(args.router_arp)
        arp_text = arp_path.read_text(encoding="utf-8")
        try:
            json.loads(arp_text)
        except json.JSONDecodeError:
            arp_records = RouterTableParsers.parse_cli_arp(arp_text)
        else:
            arp_records = [
                RouterArpRecord.from_dict(item)
                for item in _load_json_object_list(arp_path, key="arp_records")
            ]

    dhcp_leases = None
    if getattr(args, "dhcp_leases", None) is not None:
        dhcp_leases = RouterTableParsers.parse_dhcp_leases(
            Path(args.dhcp_leases).read_text(encoding="utf-8")
        )

    if arp_records is not None or dhcp_leases is not None:
        hosts = RouterArpDhcpCollector(
            arp_records=arp_records, dhcp_leases=dhcp_leases
        ).enrich_hosts(hosts)

    if getattr(args, "proxmox_snapshot", None) is not None:
        proxmox = ProxmoxClusterSnapshot.from_json_file(
            Path(args.proxmox_snapshot)
        )
        for host in hosts:
            guests = proxmox.find_guests(ip=host.ip)
            if not guests and host.mac_address:
                guests = proxmox.find_guests(mac=host.mac_address)
            running_guests = [guest for guest in guests if guest.is_running]
            if len(running_guests) == 1:
                guest = running_guests[0]
                if host.hostname is None:
                    host.hostname = guest.name
                # Several guest NICs give no single MAC to copy onto the host
                if host.mac_address is None and len(guest.mac_addresses) == 1:
                    host.mac_address = guest.mac_addresses[0]
                continue
            if guests:
                continue
            running_containers = [
                container
                for container in proxmox.find_containers(ip=host.ip)
                if container.is_running
            ]
            if len(running_containers) == 1 and host.hostname is None:
                host.hostname = running_containers[0].name

    identifier = NetworkRoleIdentifier()
    catalog = DeviceTypeCatalog()
    if hosts:
        identifications = identifier.identify_hosts(
            [
                {
                    "ip": h.ip,
                    "mac": h.mac_address,
                    "hostname": h.hostname,
                    "open_ports": list(h.open_tcp_ports),
                    "subnet_cidr": h.subnet_cidr,
                    "vlan_id": h.vlan_id,
                }
                for h in hosts
            ]
        )
        ident_by_ip = {i.ip: i for i in identifications}
        for h in hosts:
            ident = ident_by_ip.get(h.ip)
            if ident is not None and h.inferred_role in ("host", "workstation_server"):
                if ident.role == "workstation_server":
                    h.inferred_role = "server" if h.open_tcp_ports else "host"
                else:
                    h.inferred_role = ident.role

    observed_at = getattr(args, "evaluation_time", None) or datetime.now(
        timezone.utc
    )
    site = scanner.build_site_snapshot(
        hosts,
        active_subnets=active_subnets,
        site_id=args.site_id,
        site_name=args.site_name,
        observed_at=observed_at,
    )
    site = _enrich_discovered_site_with_identifier(
        site, hosts, identifier, catalog
    )

    output_dir: Optional[Path] = (
        Path(args.output_dir)
        if getattr(args, "output_dir", None) is not None
        else None
    )
    output_file: Optional[Path] = (
        Path(args.output)
        if getattr(args, "output", None) is not None
        else (output_dir / "discovered_site.json" if output_dir is not None else None)
    )

    site_json = site.to_json(indent=2)
    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(site_json, encoding="utf-8")

    if getattr(args, "snapshot_dir", None) is not None:
        SnapshotStore(Path(args.snapshot_dir)).save_site(site)
    elif output_dir is not None:
        SnapshotStore(output_dir / "snapshots").save_site(site)

    want_html = bool(
        getattr(args, "html_dashboard", False)
        or getattr(args, "html_output", None) is not None
    )
    want_validate_or_report = bool(
        getattr(args, "validate", False)
        or getattr(args, "report", False)
        or want_html
        or output_dir is not None
    )

    if want_validate_or_report:
        eval_ts_str = (
            observed_at.isoformat()
            if isinstance(observed_at, datetime)
            else str(observed_at)
        )
        engine = ClassificationEngine(evaluation_time=eval_ts_str)
        results = engine.classify_site(site, evaluation_time=eval_ts_str)
        report_dir = (
            output_dir
            or (output_file.parent if output_file is not None else None)
            or (
                Path(args.html_output).parent
                if getattr(args, "html_output", None) is not None
                else Path("./output")
            )
        )
        report_dir.mkdir(parents=True, exist_ok=True)
        _write_validation_results_file(
            results, report_dir, generated_at=eval_ts_str
        )
        plan = DryRunActionPlanGenerator(generated_at=eval_ts_str).generate_plan(
            results, generated_at=eval_ts_str
        )
        if getattr(args, "report", False) or output_dir is not None or want_html:
            paths = generate_all_reports(
                results,
                report_dir,
                sites=[site],
                action_plan=plan,
                generated_at=eval_ts_str,
                include_html_dashboard=want_html,
            )
            if getattr(args, "html_output", None) is not None:
                custom_html = Path(args.html_output)
                if custom_html.resolve() != paths["html_dashboard"].resolve():
                    custom_html.parent.mkdir(parents=True, exist_ok=True)
                    custom_html.write_text(
                        paths["html_dashboard"].read_text(encoding="utf-8"),
                        encoding="utf-8",
                    )

    if output_file is None and output_dir is None and not want_validate_or_report:
        print(site_json)

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    site = _load_single_site_snapshot(
        getattr(args, "snapshot", None), args, default_to_fixtures=True
    )
    store, json_export_target = _open_curation_store(
        getattr(args, "curation_db", None)
    )

    initial_results: Optional[list[ValidationResult]] = None
    if getattr(args, "results_file", None) is not None:
        initial_results = _load_validation_results_file(Path(args.results_file))

    try:
        state = WorkbenchState(
            site=site,
            store=store,
            initial_results=initial_results,
        )
        server = create_workbench_server(
            state, host=args.host, port=int(args.port)
        )
        try:
            if getattr(args, "check", False):
                _ = render_workbench_html(state)
                _ = state.get_state_payload()
                return 0

            if getattr(args, "once", False):
                bound_host, bound_port = server.server_address[:2]
                connect_host = (
                    "127.0.0.1"
                    if bound_host in ("0.0.0.0", "::", "")
                    else str(bound_host)
                )
                probe_url = f"http://{connect_host}:{bound_port}/api/health"

                def _self_probe() -> None:
                    try:
                        with urlopen(probe_url, timeout=3.0) as resp:
                            resp.read()
                    except Exception:
                        pass

                probe_thread = threading.Thread(target=_self_probe, daemon=True)
                probe_thread.start()
                server.handle_request()
                probe_thread.join(timeout=2.0)
                return 0

            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            return 0
        finally:
            server.server_close()
            if json_export_target is not None:
                store.export_json(json_export_target)
    finally:
        store.close()


def cmd_curate(args: argparse.Namespace) -> int:
    store, json_export_target = _open_curation_store(
        getattr(args, "curation_db", Path("./curation.db")),
        import_json_path=getattr(args, "import_json", None),
    )

    try:
        site: Optional[Site] = None
        if getattr(args, "snapshot", None) is not None:
            site = _load_single_site_snapshot(
                Path(args.snapshot), args, default_to_fixtures=False
            )

        resolved_site_id = getattr(args, "site_id", None) or (
            site.site_id if site is not None else None
        )
        actor = getattr(args, "actor", None) or "cli-operator"
        reason = getattr(args, "reason", None) or ""

        # 1. Item patch or delete
        has_target_type = bool(getattr(args, "target_type", None))
        has_target_id = bool(getattr(args, "target_id", None))
        if has_target_type != has_target_id:
            raise ValueError(
                "Both --target-type and --target-id must be provided together"
            )
        if has_target_type and has_target_id:
            if getattr(args, "delete", False):
                store.delete_item(
                    args.target_type,
                    args.target_id,
                    actor=actor,
                    reason=reason,
                    site_id=resolved_site_id,
                )
            else:
                patch = ItemEditPatch(
                    target_type=args.target_type,
                    target_id=args.target_id,
                    site_id=resolved_site_id,
                    name=getattr(args, "name", None),
                    hostname=getattr(args, "hostname", None),
                    category=getattr(args, "category", None),
                    role=getattr(args, "role", None),
                    vendor=getattr(args, "vendor", None),
                    model=getattr(args, "model", None),
                    vlan_id=getattr(args, "vlan_id", None),
                    subnet_id=getattr(args, "subnet_id", None),
                    room=getattr(args, "room", None),
                    notes=getattr(args, "notes", None),
                    pinned_classification=getattr(
                        args, "pin_classification", None
                    ),
                )
                store.upsert_patch(patch, actor=actor, reason=reason)

        # 2. Add device from template or custom specification
        add_device_val = getattr(args, "add_device", None)
        if add_device_val is not None and add_device_val is not False:
            dev_site_id = resolved_site_id or "site-001"
            raw_arg_str = (
                str(add_device_val).strip()
                if isinstance(add_device_val, str) and add_device_val.strip()
                else None
            )
            hostname = (
                getattr(args, "hostname", None)
                or getattr(args, "name", None)
                or raw_arg_str
                or getattr(args, "device_id", None)
                or "custom-device"
            )
            raw_dev_id = getattr(args, "device_id", None) or raw_arg_str
            if raw_dev_id:
                device_id = str(raw_dev_id).strip()
            else:
                slug = "".join(
                    ch if ch.isalnum() else "-" for ch in hostname.lower()
                ).strip("-")
                device_id = f"dev-{slug}" if not slug.startswith("dev-") else slug

            catalog = DeviceTypeCatalog()
            template_id = getattr(args, "template_id", None)
            if template_id:
                device = catalog.instantiate_device(
                    template_id,
                    device_id=device_id,
                    site_id=dev_site_id,
                    hostname=hostname,
                    management_ip=getattr(args, "management_ip", None),
                    port_count=getattr(args, "port_count", None),
                    default_vlan_id=getattr(args, "vlan_id", None),
                )
                if getattr(args, "vendor", None):
                    device.vendor = args.vendor
                if getattr(args, "model", None):
                    device.model = args.model
                if getattr(args, "role", None):
                    device.role = args.role
            else:
                device = NetworkDevice(
                    device_id=device_id,
                    site_id=dev_site_id,
                    hostname=hostname,
                    management_ip=getattr(args, "management_ip", None),
                    vendor=getattr(args, "vendor", None),
                    model=getattr(args, "model", None),
                    role=getattr(args, "role", None) or "switch",
                    ports=[],
                )
                if getattr(args, "port_count", None):
                    DevicePortManager(device).add_port_range(
                        start=1,
                        end=int(args.port_count),
                        naming_pattern="1:{n}",
                        vlan_id=getattr(args, "vlan_id", None),
                        overwrite=True,
                    )

            store.add_custom_device(device, actor=actor, reason=reason)
        elif (
            getattr(args, "template_id", None)
            and getattr(args, "device_id", None)
            and not getattr(args, "add_port", None)
            and not getattr(args, "port_range", None)
        ):
            dev_site_id = resolved_site_id or "site-001"
            device_id = str(args.device_id).strip()
            hostname = (
                getattr(args, "hostname", None)
                or getattr(args, "name", None)
                or device_id
            )
            device = DeviceTypeCatalog().instantiate_device(
                args.template_id,
                device_id=device_id,
                site_id=dev_site_id,
                hostname=hostname,
                management_ip=getattr(args, "management_ip", None),
                port_count=getattr(args, "port_count", None),
                default_vlan_id=getattr(args, "vlan_id", None),
            )
            store.add_custom_device(device, actor=actor, reason=reason)

        # 3. Add or update ports on a device
        port_dev_id = getattr(args, "device_id", None) or (
            str(add_device_val).strip()
            if isinstance(add_device_val, str) and add_device_val.strip()
            else None
        )
        if port_dev_id and (
            getattr(args, "add_port", None) is not None
            or getattr(args, "port_range", None) is not None
        ):
            target_dev: Optional[NetworkDevice] = None
            for custom_d in store._list_custom_devices():
                if custom_d.device_id == port_dev_id:
                    target_dev = custom_d
                    break
            if target_dev is None and site is not None:
                for site_d in site.devices:
                    if site_d.device_id == port_dev_id:
                        target_dev = NetworkDevice.from_dict(site_d.to_dict())
                        break
            if target_dev is None:
                target_dev = NetworkDevice(
                    device_id=port_dev_id,
                    site_id=resolved_site_id or "site-001",
                    hostname=port_dev_id,
                    ports=[],
                )

            mgr = DevicePortManager(target_dev)
            touched_ports: list[Port] = []
            admin_st = getattr(args, "admin_status", None) or "up"
            oper_st = getattr(args, "oper_status", None) or (
                "up"
                if getattr(args, "connected_device_id", None)
                or getattr(args, "connected_mac", None)
                else "down"
            )

            if getattr(args, "add_port", None) is not None:
                p_obj = mgr.add_port(
                    args.add_port,
                    admin_status=admin_st,
                    oper_status=oper_st,
                    poe_status=getattr(args, "poe_status", None),
                    vlan_id=getattr(args, "vlan_id", None),
                    connected_device_id=getattr(
                        args, "connected_device_id", None
                    ),
                    connected_mac=getattr(args, "connected_mac", None),
                    overwrite=True,
                )
                touched_ports.append(p_obj)

            if getattr(args, "port_range", None) is not None:
                range_ports = mgr.add_port_range(
                    args.port_range,
                    admin_status=admin_st,
                    oper_status=oper_st,
                    poe_status=getattr(args, "poe_status", None),
                    vlan_id=getattr(args, "vlan_id", None),
                    overwrite=True,
                )
                for p_obj in range_ports:
                    if getattr(args, "connected_device_id", None) is not None:
                        p_obj.connected_device_id = args.connected_device_id
                    if getattr(args, "connected_mac", None) is not None:
                        p_obj.connected_mac = args.connected_mac
                touched_ports.extend(range_ports)

            for p_obj in touched_ports:
                store.add_or_update_port(
                    port_dev_id,
                    p_obj,
                    actor=actor,
                    reason=reason,
                    site_id=resolved_site_id or target_dev.site_id,
                )

        # 4. Add custom VLAN if requested
        if getattr(args, "add_vlan", None) is not None:
            v_site_id = resolved_site_id or "site-001"
            vlan_id_str = str(args.add_vlan).strip()
            vlan_name = getattr(args, "name", None) or f"VLAN {vlan_id_str}"
            cidr_val = getattr(args, "cidr", None)
            gw_val = getattr(args, "gateway", None)
            sub_id = getattr(args, "subnet_id", None) or (
                f"{v_site_id}-subnet-{vlan_id_str}" if cidr_val else None
            )
            vlan_obj = VLAN(
                vlan_id=vlan_id_str,
                site_id=v_site_id,
                name=vlan_name,
                subnet_id=sub_id,
                cidr=cidr_val,
                gateway=gw_val,
            )
            sub_obj = (
                Subnet(
                    subnet_id=sub_id,
                    site_id=v_site_id,
                    cidr=cidr_val,
                    vlan_id=vlan_id_str,
                    gateway=gw_val,
                    name=vlan_name,
                )
                if cidr_val and sub_id
                else None
            )
            store.add_custom_vlan(
                vlan_obj, subnet=sub_obj, actor=actor, reason=reason
            )

        if json_export_target is not None:
            store.export_json(json_export_target)

        if getattr(args, "export_json", None) is not None:
            store.export_json(Path(args.export_json))

        if site is not None and getattr(args, "output", None) is not None:
            curated_site, _ = apply_curation_overlay(site, store)
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(curated_site.to_json(indent=2), encoding="utf-8")

        if getattr(args, "list_audit", False):
            entries = store.list_audit_log(
                site_id=getattr(args, "site_id", None),
                limit=int(getattr(args, "limit", 100)),
            )
            audit_json = json.dumps(
                [e.to_dict() for e in entries], indent=2
            )
            print(audit_json)
            if getattr(args, "output", None) is not None and site is None:
                out_path = Path(args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(audit_json, encoding="utf-8")

    finally:
        store.close()

    return 0


def cmd_topology(args: argparse.Namespace) -> int:
    site = _load_single_site_snapshot(
        getattr(args, "snapshot", None), args, default_to_fixtures=True
    )
    results: Optional[list[ValidationResult]] = None
    if getattr(args, "results_file", None) is not None:
        results = _load_validation_results_file(Path(args.results_file))

    if getattr(args, "curation_db", None) is not None:
        store, _ = _open_curation_store(args.curation_db)
        try:
            site, curated_results = apply_curation_overlay(site, store, results)
            if results is not None or curated_results:
                results = curated_results
        finally:
            store.close()

    builder = TopologyGraphBuilder(
        include_unconnected_ports=bool(
            getattr(args, "include_unconnected_ports", False)
        )
    )
    graph = builder.build(site, results)

    output_dir: Optional[Path] = (
        Path(args.output_dir)
        if getattr(args, "output_dir", None) is not None
        else None
    )
    output_json: Optional[Path] = (
        Path(args.output_json)
        if getattr(args, "output_json", None) is not None
        else (
            output_dir / "topology_graph.json"
            if output_dir is not None
            else None
        )
    )
    output_mermaid: Optional[Path] = (
        Path(args.output_mermaid)
        if getattr(args, "output_mermaid", None) is not None
        else (
            output_dir / "topology_graph.mmd"
            if output_dir is not None
            else None
        )
    )

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(graph.to_json(indent=2), encoding="utf-8")

    if output_mermaid is not None:
        output_mermaid.parent.mkdir(parents=True, exist_ok=True)
        output_mermaid.write_text(graph.to_mermaid(), encoding="utf-8")

    if output_json is None and output_mermaid is None:
        print(graph.to_json(indent=2))

    return 0


def _markdown_cell(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("|", "\\|")


def _render_fingerprint_markdown(report: Mapping[str, Any]) -> str:
    """Render a ServiceBannerFingerprinter enrichment report as Markdown tables."""
    lines = [
        f"# Service Fingerprint Report: {report['site_id']}",
        "",
        f"- Banners: {report['banner_count']}",
        f"- Fingerprints: {len(report['fingerprints'])}",
        f"- Enriched Devices: {len(report['enriched_devices'])}",
        f"- Enriched Equipment: {len(report['enriched_equipment'])}",
        "",
        "## Fingerprints",
        "",
        "| IP | Vendor | Model | OS Family | Hostname | Role | Template | Confidence | Signatures |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for fp in report["fingerprints"]:
        cells = (
            _markdown_cell(fp["ip"]),
            _markdown_cell(fp["vendor"]),
            _markdown_cell(fp["model"]),
            _markdown_cell(fp["os_family"]),
            _markdown_cell(fp["discovered_hostname"]),
            _markdown_cell(fp["inferred_role"]),
            _markdown_cell(fp["recommended_template_id"]),
            f"{float(fp['confidence']):.2f}",
            _markdown_cell(", ".join(fp["matched_signatures"])),
        )
        lines.append("| " + " | ".join(cells) + " |")

    lines.extend(["", "## Enriched Devices", ""])
    if report["enriched_devices"]:
        lines.append("| Device | Hostname | Vendor | Model |")
        lines.append("|---|---|---|---|")
        for dev in report["enriched_devices"]:
            cells = (
                _markdown_cell(dev["device_id"]),
                _markdown_cell(dev["hostname"]),
                _markdown_cell(dev["vendor"]),
                _markdown_cell(dev["model"]),
            )
            lines.append("| " + " | ".join(cells) + " |")
    else:
        lines.append("None.")

    lines.extend(["", "## Enriched Equipment", ""])
    if report["enriched_equipment"]:
        lines.append("| Equipment | Name |")
        lines.append("|---|---|")
        for eq in report["enriched_equipment"]:
            cells = (_markdown_cell(eq["equipment_id"]), _markdown_cell(eq["name"]))
            lines.append("| " + " | ".join(cells) + " |")
    else:
        lines.append("None.")

    return "\n".join(lines) + "\n"


def cmd_fingerprint(args: argparse.Namespace) -> int:
    site = _load_single_site_snapshot(
        getattr(args, "snapshot", None), args, default_to_fixtures=True
    )
    banners = [
        RawServiceBanner.from_dict(item)
        for item in _load_json_object_list(Path(args.banners), key="banners")
    ]
    enriched, fingerprints = ServiceBannerFingerprinter().enrich_site(
        site, banners
    )

    original_devices = {d.device_id: d for d in site.devices}
    enriched_devices: list[dict[str, Any]] = []
    for device in enriched.devices:
        before = original_devices.get(device.device_id)
        if before is None:
            continue
        if (before.hostname, before.vendor, before.model) != (
            device.hostname,
            device.vendor,
            device.model,
        ):
            enriched_devices.append(
                {
                    "device_id": device.device_id,
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "model": device.model,
                }
            )
    enriched_devices.sort(key=lambda item: item["device_id"])

    original_equipment = {e.equipment_id: e for e in site.equipment}
    enriched_equipment: list[dict[str, Any]] = []
    for equipment in enriched.equipment:
        before = original_equipment.get(equipment.equipment_id)
        if before is None or before.name == equipment.name:
            continue
        enriched_equipment.append(
            {"equipment_id": equipment.equipment_id, "name": equipment.name}
        )
    enriched_equipment.sort(key=lambda item: item["equipment_id"])

    report = {
        "site_id": site.site_id,
        "banner_count": len(banners),
        "fingerprints": [fp.to_dict() for fp in fingerprints],
        "enriched_devices": enriched_devices,
        "enriched_equipment": enriched_equipment,
    }

    output_path: Optional[Path] = (
        Path(args.output) if getattr(args, "output", None) is not None else None
    )
    if output_path is None:
        print(json.dumps(report, indent=2))
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.suffix.lower() in (".md", ".markdown"):
        output_path.write_text(
            _render_fingerprint_markdown(report), encoding="utf-8"
        )
    else:
        output_path.write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
    return 0


def cmd_map_ports(args: argparse.Namespace) -> int:
    site = _load_single_site_snapshot(
        getattr(args, "snapshot", None), args, default_to_fixtures=True
    )
    fdb_path = Path(args.fdb_file)
    if fdb_path.suffix.lower() == ".json":
        entries = [
            FdbEntry.from_dict(item)
            for item in _load_json_object_list(fdb_path, key="entries")
        ]
    else:
        device_id = getattr(args, "device_id", None)
        if not device_id:
            raise ValueError(
                "--device-id is required when --fdb-file is switch CLI text"
            )
        entries = FdbTableParser().parse_cli(
            fdb_path.read_text(encoding="utf-8"), device_id=device_id
        )

    store: Optional[CurationStore] = None
    json_export_target: Optional[Path] = None
    if getattr(args, "curation_db", None) is not None:
        store, json_export_target = _open_curation_store(args.curation_db)

    try:
        if store is not None:
            site, _ = apply_curation_overlay(site, store)

        results = SwitchFdbPortMapper().map_site_ports(site, entries)

        if store is not None:
            devices_by_id = {d.device_id: d for d in site.devices}
            for device_id, port_name in sorted(
                {(res.device_id, res.port_name) for res in results}
            ):
                device = devices_by_id.get(device_id)
                if device is None:
                    continue
                port = DevicePortManager(device).get_port(port_name)
                store.add_or_update_port(
                    device_id,
                    port,
                    actor="sot-validator map-ports",
                    reason="FDB port mapping",
                    site_id=site.site_id,
                )
    finally:
        if store is not None:
            if json_export_target is not None:
                store.export_json(json_export_target)
            store.close()

    report = {
        "site_id": site.site_id,
        "port_count": len(results),
        "ports": [res.to_dict() for res in results],
        "site": site.to_dict(),
    }

    output_path: Optional[Path] = (
        Path(args.output) if getattr(args, "output", None) is not None else None
    )
    if output_path is None:
        print(json.dumps(report, indent=2))
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


def cmd_diff_scans(args: argparse.Namespace) -> int:
    baseline = _load_single_site_snapshot(Path(args.baseline), args)
    current = _load_single_site_snapshot(Path(args.current), args)

    store: Optional[CurationStore] = None
    if getattr(args, "curation_db", None) is not None:
        store, _ = _open_curation_store(args.curation_db)
    try:
        report = SnapshotDiffEngine().diff(baseline, current, curation=store)
    finally:
        if store is not None:
            store.close()

    output_json: Optional[Path] = (
        Path(args.output_json)
        if getattr(args, "output_json", None) is not None
        else None
    )
    output_md: Optional[Path] = (
        Path(args.output_md)
        if getattr(args, "output_md", None) is not None
        else None
    )

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(report.to_json(indent=2), encoding="utf-8")

    if output_md is not None:
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(report.to_markdown(), encoding="utf-8")

    if output_json is None and output_md is None:
        print(report.to_json(indent=2))

    if getattr(args, "alert_file", None) is None:
        return 0

    targets = [
        DriftAlertTarget(
            kind=item.get("kind"),
            destination=item.get("destination"),
            token=item.get("token"),
            name=item.get("name"),
        )
        for item in _load_json_object_list(
            Path(args.alert_file), key="targets"
        )
    ]
    results = DriftAlertDispatcher(targets).dispatch(report)
    if any(result.status == "failed" for result in results):
        return 1
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

    # 10. preflight (Phase 4)
    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Run pre-flight cutover readiness checks verifying /24 scoping, read-only guardrails, and endpoint credentials.",
    )
    preflight_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Directory containing extracted site snapshots.",
    )
    preflight_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Directory to write preflight_report.json (default: ./reports).",
    )
    preflight_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional explicit output file path for preflight_report.json.",
    )
    preflight_parser.add_argument(
        "--pilot-sites",
        nargs="+",
        action="extend",
        default=None,
        help="Pilot site IDs (comma-separated or space-separated; defaults to all loaded sites).",
    )
    preflight_parser.add_argument(
        "--target-subnets-json",
        type=Path,
        default=None,
        help="Optional JSON file mapping site_id -> [cidr, ...].",
    )
    preflight_parser.add_argument(
        "--vcenter-json",
        type=Path,
        default=None,
        help="Optional vCenter inventory fixture JSON file.",
    )
    preflight_parser.add_argument(
        "--snmp-fixture",
        type=Path,
        default=None,
        help="Optional SNMP discovery fixture JSON file.",
    )
    preflight_parser.add_argument(
        "--recommended-min-sites",
        type=int,
        default=3,
        help="Recommended minimum number of pilot sites (default: 3).",
    )
    preflight_parser.add_argument(
        "--recommended-max-sites",
        type=int,
        default=5,
        help="Recommended maximum number of pilot sites (default: 5).",
    )
    preflight_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Return non-zero exit code (1) if report.ready is False.",
    )
    _add_source_arguments(preflight_parser)
    preflight_parser.set_defaults(func=cmd_preflight)

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

    # 15. itsm (Phase 6)
    itsm_parser = subparsers.add_parser(
        "itsm",
        aliases=["itsm-sync"],
        help="Generate, approve, serialize, and verify ServiceNow/Jira/Webhook ITSM change tickets.",
    )
    itsm_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Directory to write ITSM ticket sink and provider payload files (default: ./reports).",
    )
    itsm_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional explicit file path for the generated or updated ticket JSON.",
    )
    itsm_parser.add_argument(
        "--tickets-file",
        "--sink-file",
        dest="sink_file",
        type=Path,
        default=None,
        help="Path to JsonFileItsmSink file (defaults to <output-dir>/itsm_tickets.json).",
    )
    itsm_parser.add_argument(
        "--manifest",
        "--manifest-file",
        dest="manifest_file",
        type=Path,
        default=None,
        help="Optional Phase 2 RemediationApprovalManifest JSON file to generate a quarantine change ticket.",
    )
    itsm_parser.add_argument(
        "--port-plan",
        "--port-plan-file",
        dest="port_plan_file",
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
        "--ups-report",
        "--ups-health-file",
        dest="ups_health_file",
        type=Path,
        default=None,
        help="Optional Phase 6 UpsFleetHealthReport JSON file to generate an APC UPS hardware incident ticket.",
    )
    itsm_parser.add_argument(
        "--artifact",
        dest="artifact_file",
        type=Path,
        default=None,
        help="Optional generic artifact JSON file for ticket generation or verification.",
    )
    itsm_parser.add_argument(
        "--workflow-type",
        choices=[
            "QUARANTINE_DECOMMISSION",
            "PORT_RECLAMATION",
            "SHADOW_IT_ONBOARDING",
            "UPS_HARDWARE_INCIDENT",
        ],
        default=None,
        help="Optional explicit workflow type when using --artifact.",
    )
    itsm_parser.add_argument(
        "--ticket-id",
        type=str,
        default=None,
        help="Optional explicit ticket ID when generating a ticket.",
    )
    itsm_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Optional site ID override for ticket metadata.",
    )
    itsm_parser.add_argument(
        "--cmdb-ci",
        type=str,
        default=None,
        help="Optional CMDB Configuration Item override.",
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
        "--approve-ticket",
        "--approve-ticket-id",
        dest="approve_ticket_id",
        type=str,
        default=None,
        help="Ticket ID in sink to transition to APPROVED.",
    )
    itsm_parser.add_argument(
        "--reject-ticket",
        "--reject-ticket-id",
        dest="reject_ticket_id",
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
        "--approved-at",
        type=str,
        default=None,
        help="Optional ISO-8601 UTC timestamp for approval/rejection.",
    )
    itsm_parser.add_argument(
        "--verify-ticket",
        "--verify-ticket-id",
        dest="verify_ticket_id",
        type=str,
        default=None,
        help="Ticket ID to verify via ItsmGateVerifier (exits non-zero if unapproved or SHA-256 mismatches).",
    )
    itsm_parser.add_argument(
        "--allow-scheduled",
        action="store_true",
        default=False,
        help="Allow SCHEDULED status when verifying a ticket via --verify-ticket.",
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

    # 16. discover (Phase 7)
    discover_parser = subparsers.add_parser(
        "discover",
        help="Run two-stage /16-to-/24 subnet discovery and bootstrap a canonical Site snapshot.",
    )
    discover_parser.add_argument(
        "--cidr",
        type=str,
        default="10.42.0.0/16",
        help="Target IPv4 /16 or /24 CIDR block to discover (default: 10.42.0.0/16).",
    )
    discover_parser.add_argument(
        "--site-id",
        type=str,
        default="site-discovered",
        help="Identifier for the generated Site snapshot (default: site-discovered).",
    )
    discover_parser.add_argument(
        "--site-name",
        type=str,
        default="Discovered Site",
        help="Human-readable name for the generated Site snapshot (default: Discovered Site).",
    )
    discover_parser.add_argument(
        "--output",
        "--output-file",
        dest="output",
        type=Path,
        default=None,
        help="Optional output file path for the discovered Site JSON snapshot.",
    )
    discover_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional directory to write discovered_site.json, validation_results.json, and reports.",
    )
    discover_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Optional SnapshotStore directory to persist the discovered Site.",
    )
    discover_parser.add_argument(
        "--gateway-octets",
        nargs="+",
        action="extend",
        default=None,
        help="Gateway host fourth octets to probe during /16 Stage 1 discovery (default: 1).",
    )
    discover_parser.add_argument(
        "--tcp-ports",
        nargs="+",
        action="extend",
        default=None,
        help="TCP ports to probe on discovered hosts.",
    )
    discover_parser.add_argument(
        "--max-concurrency",
        type=int,
        default=128,
        help="Maximum concurrent async network probes (default: 128).",
    )
    discover_parser.add_argument(
        "--max-active-subnets",
        type=int,
        default=32,
        help="Maximum active /24 subnets to sweep within a /16 (default: 32).",
    )
    discover_parser.add_argument(
        "--ping-timeout",
        type=float,
        default=1.0,
        help="ICMP ping timeout in seconds (default: 1.0).",
    )
    discover_parser.add_argument(
        "--tcp-timeout",
        type=float,
        default=0.35,
        help="TCP connect probe timeout in seconds (default: 0.35).",
    )
    discover_parser.add_argument(
        "--mock-config",
        "--fixture-config",
        "--discovery-fixture",
        dest="mock_config",
        type=Path,
        default=None,
        help="Optional JSON file providing mock ping/TCP/ARP/rDNS callbacks or pre-discovered hosts.",
    )
    discover_parser.add_argument(
        "--fixtures",
        action="store_true",
        default=False,
        help="Use deterministic offline discovery callbacks without live network traffic.",
    )
    discover_parser.add_argument(
        "--router-arp",
        type=Path,
        default=None,
        help="Optional router ARP table file (JSON records or ExtremeXOS/VOSS/ip-neigh CLI text) to enrich discovered hosts.",
    )
    discover_parser.add_argument(
        "--dhcp-leases",
        type=Path,
        default=None,
        help="Optional DHCP lease export file (JSON, ISC, CSV, or dnsmasq) to enrich discovered hosts.",
    )
    discover_parser.add_argument(
        "--proxmox-snapshot",
        type=Path,
        default=None,
        help="Optional Proxmox/Portainer snapshot JSON used to fill missing guest hostnames and MACs.",
    )
    discover_parser.add_argument(
        "--evaluation-time",
        "--observed-at",
        dest="evaluation_time",
        type=str,
        default=None,
        help="Optional ISO-8601 UTC timestamp for discovery observation and classification.",
    )
    discover_parser.add_argument(
        "--validate",
        action="store_true",
        default=False,
        help="Also run ClassificationEngine on the discovered Site snapshot.",
    )
    discover_parser.add_argument(
        "--report",
        action="store_true",
        default=False,
        help="Also generate JSON, CSV, and Markdown validation reports.",
    )
    discover_parser.add_argument(
        "--html-dashboard",
        action="store_true",
        default=False,
        help="Also generate self-contained interactive HTML5 validation dashboard.",
    )
    discover_parser.add_argument(
        "--html-output",
        type=Path,
        default=None,
        help="Optional custom output path for the HTML5 validation dashboard.",
    )
    discover_parser.set_defaults(func=cmd_discover)

    # 17. serve (Phase 8)
    serve_parser = subparsers.add_parser(
        "serve",
        help="Launch the interactive Web Workbench HTTP server and REST API.",
    )
    serve_parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Bind address for the Workbench HTTP server (default: 127.0.0.1).",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=5100,
        help="TCP port for the Workbench HTTP server (default: 5100).",
    )
    serve_parser.add_argument(
        "--snapshot",
        "--snapshot-file",
        dest="snapshot",
        type=Path,
        default=None,
        help="Path to a Site JSON snapshot file or SnapshotStore directory.",
    )
    serve_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Optional SnapshotStore directory when --snapshot is not specified.",
    )
    serve_parser.add_argument(
        "--curation-db",
        "--db-path",
        dest="curation_db",
        type=Path,
        default=None,
        help="Path to SQLite CurationStore database or JSON file (defaults to in-memory).",
    )
    serve_parser.add_argument(
        "--results-file",
        type=Path,
        default=None,
        help="Optional validation_results.json file to seed initial classification results.",
    )
    serve_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Optional site ID to select when loading from a multi-site snapshot.",
    )
    serve_parser.add_argument(
        "--once",
        action="store_true",
        default=False,
        help="Handle a single verification HTTP request and exit cleanly.",
    )
    serve_parser.add_argument(
        "--check",
        action="store_true",
        default=False,
        help="Verify server binding and UI rendering, then exit immediately with code 0.",
    )
    _add_source_arguments(serve_parser)
    serve_parser.set_defaults(func=cmd_serve)

    # 18. curate (Phase 8/9)
    curate_parser = subparsers.add_parser(
        "curate",
        help="Apply operator inventory patches, instantiate template devices, manage switch ports, and inspect audit logs.",
    )
    curate_parser.add_argument(
        "--curation-db",
        "--db-path",
        dest="curation_db",
        type=Path,
        default=Path("./curation.db"),
        help="Path to SQLite CurationStore database or JSON state file (default: ./curation.db).",
    )
    curate_parser.add_argument(
        "--snapshot",
        "--snapshot-file",
        dest="snapshot",
        type=Path,
        default=None,
        help="Optional Site JSON snapshot file to apply curation overlay against.",
    )
    curate_parser.add_argument(
        "--output",
        "--output-snapshot",
        dest="output",
        type=Path,
        default=None,
        help="Optional output path for the curated Site JSON snapshot (or audit log JSON).",
    )
    curate_parser.add_argument(
        "--export-json",
        type=Path,
        default=None,
        help="Optional path to export the full CurationStore state as JSON.",
    )
    curate_parser.add_argument(
        "--import-json",
        type=Path,
        default=None,
        help="Optional path to import CurationStore state from JSON before applying operations.",
    )
    curate_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Optional site ID context for patches, custom devices, and audit log filtering.",
    )
    curate_parser.add_argument(
        "--actor",
        type=str,
        default="cli-operator",
        help="Operator identifier recorded in the audit log (default: cli-operator).",
    )
    curate_parser.add_argument(
        "--reason",
        type=str,
        default="",
        help="Audit reason for the curation change.",
    )
    curate_parser.add_argument(
        "--target-type",
        type=str,
        default=None,
        help="Target entity type to patch or delete (NetworkDevice, Port, VLAN, Subnet, IPAddress, Equipment).",
    )
    curate_parser.add_argument(
        "--target-id",
        type=str,
        default=None,
        help="Target entity identifier to patch or delete.",
    )
    curate_parser.add_argument(
        "--name",
        type=str,
        default=None,
        help="Updated name for patched item, custom device, or VLAN.",
    )
    curate_parser.add_argument(
        "--hostname",
        type=str,
        default=None,
        help="Updated hostname for patched item or custom device.",
    )
    curate_parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Updated EquipmentCategory (server, vm, ups, san, other).",
    )
    curate_parser.add_argument(
        "--role",
        type=str,
        default=None,
        help="Updated device or host role (e.g. router, switch, l3_switch, hypervisor, ups, nas).",
    )
    curate_parser.add_argument(
        "--vendor",
        type=str,
        default=None,
        help="Updated hardware/software vendor name.",
    )
    curate_parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Updated hardware/software model name.",
    )
    curate_parser.add_argument(
        "--vlan-id",
        type=str,
        default=None,
        help="VLAN ID to assign to patched item, custom device, or port(s).",
    )
    curate_parser.add_argument(
        "--subnet-id",
        type=str,
        default=None,
        help="Subnet ID to assign to patched item or custom VLAN.",
    )
    curate_parser.add_argument(
        "--room",
        type=str,
        default=None,
        help="Room/rack location to assign to patched item.",
    )
    curate_parser.add_argument(
        "--notes",
        type=str,
        default=None,
        help="Operator notes to attach to patched item.",
    )
    curate_parser.add_argument(
        "--pin-classification",
        "--pinned-classification",
        dest="pin_classification",
        type=str,
        default=None,
        help="Pin ValidationClassification on the target item (e.g. 'Confirmed Active').",
    )
    curate_parser.add_argument(
        "--delete",
        action="store_true",
        default=False,
        help="Mark the specified (--target-type, --target-id) item as deleted.",
    )
    curate_parser.add_argument(
        "--add-device",
        nargs="?",
        const=True,
        default=None,
        help="Add a custom NetworkDevice (optionally passing hostname or device_id).",
    )
    curate_parser.add_argument(
        "--template-id",
        "--template",
        dest="template_id",
        type=str,
        default=None,
        help="DeviceTypeCatalog template ID (e.g. extreme-exos-48p, unifi-multi-vlan-router).",
    )
    curate_parser.add_argument(
        "--device-id",
        type=str,
        default=None,
        help="Device ID for --add-device or port curation (--add-port / --port-range).",
    )
    curate_parser.add_argument(
        "--management-ip",
        type=str,
        default=None,
        help="Management IPv4 address for --add-device.",
    )
    curate_parser.add_argument(
        "--port-count",
        type=int,
        default=None,
        help="Override port count when instantiating a device.",
    )
    curate_parser.add_argument(
        "--add-port",
        type=str,
        default=None,
        help="Add or update a single port by name on --device-id (e.g. '1:1' or 'eth1').",
    )
    curate_parser.add_argument(
        "--port-range",
        type=str,
        default=None,
        help="Add or update a range of ports on --device-id (e.g. '1:1-1:24' or 'eth1..eth8').",
    )
    curate_parser.add_argument(
        "--poe-status",
        type=str,
        default=None,
        help="PoE status for added/updated port(s) (e.g. delivering, auto, off).",
    )
    curate_parser.add_argument(
        "--admin-status",
        type=str,
        default=None,
        help="Administrative status for added/updated port(s) (default: up).",
    )
    curate_parser.add_argument(
        "--oper-status",
        type=str,
        default=None,
        help="Operational status for added/updated port(s).",
    )
    curate_parser.add_argument(
        "--connected-device-id",
        type=str,
        default=None,
        help="Connected downstream device or equipment ID for added/updated port(s).",
    )
    curate_parser.add_argument(
        "--connected-mac",
        type=str,
        default=None,
        help="Connected MAC address for added/updated port(s).",
    )
    curate_parser.add_argument(
        "--add-vlan",
        type=str,
        default=None,
        help="Add or update a custom VLAN with the specified VLAN ID.",
    )
    curate_parser.add_argument(
        "--cidr",
        type=str,
        default=None,
        help="Subnet CIDR when adding a custom VLAN with --add-vlan.",
    )
    curate_parser.add_argument(
        "--gateway",
        type=str,
        default=None,
        help="Gateway IP when adding a custom VLAN with --add-vlan.",
    )
    curate_parser.add_argument(
        "--list-audit",
        action="store_true",
        default=False,
        help="Print the CurationStore audit log as JSON to stdout.",
    )
    curate_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum audit log entries to return with --list-audit (default: 100).",
    )
    curate_parser.set_defaults(func=cmd_curate)

    # 19. topology (Phase 9)
    topology_parser = subparsers.add_parser(
        "topology",
        help="Build a site network TopologyGraph (with optional curation overlay) and export JSON and Mermaid diagrams.",
    )
    topology_parser.add_argument(
        "--snapshot",
        "--snapshot-file",
        dest="snapshot",
        type=Path,
        default=None,
        help="Path to a Site JSON snapshot file or SnapshotStore directory.",
    )
    topology_parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Optional SnapshotStore directory when --snapshot is not specified.",
    )
    topology_parser.add_argument(
        "--curation-db",
        "--db-path",
        dest="curation_db",
        type=Path,
        default=None,
        help="Optional CurationStore SQLite DB or JSON state file to overlay before graph construction.",
    )
    topology_parser.add_argument(
        "--results-file",
        type=Path,
        default=None,
        help="Optional validation_results.json file to enrich topology nodes with classifications.",
    )
    topology_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Optional site ID to select when loading from a multi-site snapshot.",
    )
    topology_parser.add_argument(
        "--include-unconnected-ports",
        action="store_true",
        default=False,
        help="Include down/unconnected switch ports as nodes in the topology graph.",
    )
    topology_parser.add_argument(
        "--output-json",
        "--output",
        dest="output_json",
        type=Path,
        default=None,
        help="Output file path for the serialized TopologyGraph JSON.",
    )
    topology_parser.add_argument(
        "--output-mermaid",
        type=Path,
        default=None,
        help="Output file path for the Mermaid flowchart LR diagram (.mmd).",
    )
    topology_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional output directory to write topology_graph.json and topology_graph.mmd.",
    )
    _add_source_arguments(topology_parser)
    topology_parser.set_defaults(func=cmd_topology)

    # 20. fingerprint (Phase 10)
    fingerprint_parser = subparsers.add_parser(
        "fingerprint",
        help="Fingerprint vendor/model/OS from collected SSH/HTTP/TLS/SNMP banners and enrich a site snapshot (no network I/O).",
    )
    fingerprint_parser.add_argument(
        "--snapshot",
        "--snapshot-file",
        dest="snapshot",
        type=Path,
        default=None,
        help="Path to a Site JSON snapshot file or SnapshotStore directory.",
    )
    fingerprint_parser.add_argument(
        "--banners",
        type=Path,
        required=True,
        help='JSON file with a list of RawServiceBanner objects or {"banners": [...]}.',
    )
    fingerprint_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output report path (.md/.markdown writes Markdown, anything else JSON). Prints JSON to stdout when omitted.",
    )
    fingerprint_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Optional site ID to select when loading from a multi-site snapshot.",
    )
    _add_source_arguments(fingerprint_parser)
    fingerprint_parser.set_defaults(func=cmd_fingerprint)

    # 21. map-ports (Phase 11)
    map_ports_parser = subparsers.add_parser(
        "map-ports",
        help="Map switch FDB / MAC tables to ports, infer access/trunk/uplink modes, and bind downstream MACs.",
    )
    map_ports_parser.add_argument(
        "--snapshot",
        "--snapshot-file",
        dest="snapshot",
        type=Path,
        default=None,
        help="Path to a Site JSON snapshot file or SnapshotStore directory.",
    )
    map_ports_parser.add_argument(
        "--fdb-file",
        type=Path,
        required=True,
        help='FDB input: .json list of FdbEntry objects or {"entries": [...]}, otherwise EXOS/VOSS/Cisco CLI text.',
    )
    map_ports_parser.add_argument(
        "--device-id",
        type=str,
        default=None,
        help="Switch device ID for CLI-text FDB files (required unless --fdb-file is JSON).",
    )
    map_ports_parser.add_argument(
        "--curation-db",
        "--db-path",
        dest="curation_db",
        type=Path,
        default=None,
        help="Optional CurationStore SQLite DB or JSON state file to overlay and save mapped ports into.",
    )
    map_ports_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path for the port mapping report JSON (with updated site). Prints to stdout when omitted.",
    )
    map_ports_parser.add_argument(
        "--site-id",
        type=str,
        default=None,
        help="Optional site ID to select when loading from a multi-site snapshot.",
    )
    _add_source_arguments(map_ports_parser)
    map_ports_parser.set_defaults(func=cmd_map_ports)

    # 22. diff-scans (Phase 12)
    diff_scans_parser = subparsers.add_parser(
        "diff-scans",
        help="Diff two discovery site snapshots and optionally dispatch drift alerts.",
    )
    diff_scans_parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Baseline Site JSON snapshot file or SnapshotStore directory.",
    )
    diff_scans_parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Current Site JSON snapshot file or SnapshotStore directory.",
    )
    diff_scans_parser.add_argument(
        "--curation-db",
        "--db-path",
        dest="curation_db",
        type=Path,
        default=None,
        help="Optional CurationStore SQLite DB or JSON state file used to suppress curated drift.",
    )
    diff_scans_parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Output path for the drift report JSON.",
    )
    diff_scans_parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Output path for the drift report Markdown.",
    )
    diff_scans_parser.add_argument(
        "--alert-file",
        type=Path,
        default=None,
        help='JSON list of alert targets or {"targets": [...]} ({"kind", "destination", "token"?, "name"?}).',
    )
    diff_scans_parser.set_defaults(func=cmd_diff_scans)

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
