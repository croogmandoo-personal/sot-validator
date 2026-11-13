"""ServiceNow / Jira change-ticket governance subcommand (`itsm`)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.itsm import (
    ItsmGateVerifier,
    ItsmProvider,
    ItsmTicketPayloadBuilder,
    ItsmTicketRequest,
    ItsmWebhookSerializer,
    ItsmWorkflowType,
    JsonFileItsmSink,
    TicketApprovalStatus,
)
from sot_validator.reconciliation import ReconciliationReport
from sot_validator.remediation import PortReclamationPlan, RemediationApprovalManifest
from sot_validator.signals.ups_health import UpsFleetHealthReport


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


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `itsm` subcommand."""
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
