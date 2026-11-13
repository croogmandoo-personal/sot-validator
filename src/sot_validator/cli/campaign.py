"""Multi-site campaign and pilot pre-flight subcommands (`campaign`, `preflight`)."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Optional

from sot_validator.campaign import (
    CampaignConfig,
    CampaignOrchestrator,
    JsonFileAlertSink,
    WebhookPayloadFormatter,
)
from sot_validator.cli._common import (
    _add_source_arguments,
    _add_validation_arguments,
    _build_classification_engine,
    _build_sot_client,
    _parse_str_list,
    _resolve_sites_for_command,
)
from sot_validator.connectors import (
    PilotCutoverValidator,
    SnmpWalkConnector,
    VSphereRestConnector,
)
from sot_validator.history import HistoryStore
from sot_validator.reporting import DEFAULT_DASHBOARD_FILENAME, generate_html_dashboard


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


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `campaign`, `preflight` subcommands."""
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
