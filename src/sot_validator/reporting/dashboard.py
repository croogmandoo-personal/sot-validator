"""Interactive self-contained HTML5 operations dashboard generator (`validation_dashboard.html`)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
import html
from pathlib import Path
from typing import Any, Optional

from sot_validator.history.ledger import (
    HistoryStore,
    ItemStreakSummary,
    SubnetUtilizationSummary,
)
from sot_validator.itsm.tickets import (
    InMemoryItsmSink,
    ItsmTicketRequest,
    TicketApprovalStatus,
)
from sot_validator.migration.parity import (
    CutoverRecommendation,
    ParityValidationReport,
    SiteMigrationReadinessScorecard,
)
from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.reconciliation.reconciler import (
    ALL_DISCREPANCY_TYPES,
    ReconciliationReport,
)
from sot_validator.remediation.port_reclamation import (
    PortReclamationPlan,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineEngine,
    QuarantineGraduationStatus,
    QuarantinePolicy,
    RemediationApprovalManifest,
    RemediationOperation,
)
from sot_validator.remediation.sink import (
    DryRunActionPlan,
    RemediationActionType,
)
from sot_validator.reporting.generators import (
    ALL_CLASSIFICATIONS,
    _index_sites,
    _resolve_report_timestamp,
    generate_json_report,
)
from sot_validator.signals.ups_health import (
    UpsFleetHealthReport,
    UpsHealthRecord,
    UpsHealthStatus,
)

DEFAULT_DASHBOARD_FILENAME = "validation_dashboard.html"
DEFAULT_DASHBOARD_TITLE = "SoT Inventory Validation & Operations Dashboard"


def _esc(value: Any) -> str:
    """Escape any value for safe inclusion in HTML text or quoted attributes."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _classification_badge_class(classification: str) -> str:
    if classification == ValidationClassification.CONFIRMED_ACTIVE.value:
        return "badge-active"
    if classification == ValidationClassification.STALE_LIKELY_UNUSED.value:
        return "badge-stale"
    if classification == ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value:
        return "badge-unreachable"
    return "badge-insufficient"


def _approval_badge_class(status: str) -> str:
    upper = status.upper()
    if upper in (
        ApprovalStatus.APPROVED.value,
        TicketApprovalStatus.APPROVED.value,
        TicketApprovalStatus.IMPLEMENTED.value,
    ):
        return "badge-active"
    if upper in (
        ApprovalStatus.PENDING.value,
        TicketApprovalStatus.PENDING.value,
        TicketApprovalStatus.SCHEDULED.value,
    ):
        return "badge-unreachable"
    if upper in (
        ApprovalStatus.REJECTED.value,
        TicketApprovalStatus.REJECTED.value,
        TicketApprovalStatus.CANCELLED.value,
    ):
        return "badge-stale"
    return "badge-insufficient"


def _ups_status_badge_class(status: str) -> str:
    upper = status.upper()
    if upper == UpsHealthStatus.HEALTHY.value:
        return "badge-active"
    if upper == UpsHealthStatus.WARNING.value:
        return "badge-unreachable"
    if upper == UpsHealthStatus.CRITICAL.value:
        return "badge-stale"
    return "badge-insufficient"


def _cutover_badge_class(recommendation: str) -> str:
    upper = recommendation.upper()
    if upper == CutoverRecommendation.READY_FOR_CUTOVER.value:
        return "badge-active"
    if upper == CutoverRecommendation.NEEDS_REMEDIATION.value:
        return "badge-unreachable"
    return "badge-stale"


def _coerce_manifest(
    raw_manifest: Optional[RemediationApprovalManifest | Mapping[str, Any]],
) -> Optional[RemediationApprovalManifest]:
    if raw_manifest is None:
        return None
    if isinstance(raw_manifest, RemediationApprovalManifest):
        return raw_manifest
    if isinstance(raw_manifest, Mapping):
        return RemediationApprovalManifest.from_dict(raw_manifest)
    raise ValueError(f"Unsupported approval_manifest type: {type(raw_manifest)!r}")


def _coerce_streaks(
    raw_streaks: Optional[
        Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore
    ],
) -> Optional[list[ItemStreakSummary]]:
    if raw_streaks is None:
        return None
    if isinstance(raw_streaks, HistoryStore):
        return raw_streaks.list_streaks()
    if isinstance(raw_streaks, Sequence):
        return [
            s if isinstance(s, ItemStreakSummary) else ItemStreakSummary.from_dict(s)
            for s in raw_streaks
        ]
    raise ValueError(f"Unsupported streaks type: {type(raw_streaks)!r}")


def _coerce_reconciliation(
    raw_reconciliation: Optional[ReconciliationReport | Mapping[str, Any]],
) -> Optional[ReconciliationReport]:
    if raw_reconciliation is None:
        return None
    if isinstance(raw_reconciliation, ReconciliationReport):
        return raw_reconciliation
    if isinstance(raw_reconciliation, Mapping):
        return ReconciliationReport.from_dict(raw_reconciliation)
    raise ValueError(
        f"Unsupported reconciliation_report type: {type(raw_reconciliation)!r}"
    )


def _coerce_subnet_utilization(
    raw_subnets: Optional[Sequence[SubnetUtilizationSummary | Mapping[str, Any]]],
    sites_by_id: Mapping[str, Site],
    results: Sequence[ValidationResult | Mapping[str, Any]],
) -> list[SubnetUtilizationSummary]:
    if raw_subnets is not None:
        return [
            s
            if isinstance(s, SubnetUtilizationSummary)
            else SubnetUtilizationSummary.from_dict(s)
            for s in raw_subnets
        ]
    if sites_by_id:
        return HistoryStore.compute_subnet_utilization(
            list(sites_by_id.values()), results
        )
    return []


def _coerce_port_reclamation_plan(
    raw_plan: Optional[PortReclamationPlan | Mapping[str, Any]],
) -> Optional[PortReclamationPlan]:
    if raw_plan is None:
        return None
    if isinstance(raw_plan, PortReclamationPlan):
        return raw_plan
    if isinstance(raw_plan, Mapping):
        return PortReclamationPlan.from_dict(raw_plan)
    raise ValueError(
        f"Unsupported port_reclamation_plan type: {type(raw_plan)!r}"
    )


def _coerce_parity_report(
    raw_parity: Optional[
        ParityValidationReport
        | SiteMigrationReadinessScorecard
        | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
        | Mapping[str, Any]
    ],
) -> Optional[ParityValidationReport]:
    if raw_parity is None:
        return None
    if isinstance(raw_parity, ParityValidationReport):
        return raw_parity
    if isinstance(raw_parity, SiteMigrationReadinessScorecard):
        return ParityValidationReport(
            scorecards=[raw_parity], evaluated_at=raw_parity.evaluated_at
        )
    if isinstance(raw_parity, Mapping):
        if "scorecards" in raw_parity or "sites" in raw_parity:
            return ParityValidationReport.from_dict(raw_parity)
        if "site_id" in raw_parity and (
            "readiness_score" in raw_parity or "recommendation" in raw_parity
        ):
            sc = SiteMigrationReadinessScorecard.from_dict(raw_parity)
            return ParityValidationReport(
                scorecards=[sc], evaluated_at=sc.evaluated_at
            )
    if isinstance(raw_parity, Sequence) and not isinstance(
        raw_parity, (str, bytes)
    ):
        cards = [
            c
            if isinstance(c, SiteMigrationReadinessScorecard)
            else SiteMigrationReadinessScorecard.from_dict(c)
            for c in raw_parity
        ]
        return ParityValidationReport(scorecards=cards)
    raise ValueError(f"Unsupported parity_report type: {type(raw_parity)!r}")


def _coerce_ups_health_report(
    raw_ups: Optional[
        UpsFleetHealthReport
        | UpsHealthRecord
        | Sequence[UpsHealthRecord | Mapping[str, Any]]
        | Mapping[str, Any]
    ],
) -> Optional[UpsFleetHealthReport]:
    if raw_ups is None:
        return None
    if isinstance(raw_ups, UpsFleetHealthReport):
        return raw_ups
    if isinstance(raw_ups, UpsHealthRecord):
        return UpsFleetHealthReport(
            records=[raw_ups], evaluated_at=raw_ups.evaluated_at
        )
    if isinstance(raw_ups, Mapping):
        if "records" in raw_ups:
            return UpsFleetHealthReport.from_dict(raw_ups)
        if "equipment_id" in raw_ups and "status" in raw_ups:
            rec = UpsHealthRecord.from_dict(raw_ups)
            return UpsFleetHealthReport(records=[rec], evaluated_at=rec.evaluated_at)
    if isinstance(raw_ups, Sequence) and not isinstance(raw_ups, (str, bytes)):
        recs = [
            r if isinstance(r, UpsHealthRecord) else UpsHealthRecord.from_dict(r)
            for r in raw_ups
        ]
        return UpsFleetHealthReport(records=recs)
    raise ValueError(f"Unsupported ups_health_report type: {type(raw_ups)!r}")


def _coerce_itsm_tickets(
    raw_tickets: Optional[
        Sequence[ItsmTicketRequest | Mapping[str, Any]]
        | Mapping[str, Any]
        | ItsmTicketRequest
        | InMemoryItsmSink
    ],
) -> list[ItsmTicketRequest]:
    if raw_tickets is None:
        return []
    if isinstance(raw_tickets, InMemoryItsmSink):
        return list(raw_tickets.tickets)
    if isinstance(raw_tickets, ItsmTicketRequest):
        return [raw_tickets]
    if isinstance(raw_tickets, Mapping):
        if "ticket_id" in raw_tickets:
            return [ItsmTicketRequest.from_dict(raw_tickets)]
        if "tickets" in raw_tickets and isinstance(raw_tickets["tickets"], Sequence):
            return [
                t
                if isinstance(t, ItsmTicketRequest)
                else ItsmTicketRequest.from_dict(t)
                for t in raw_tickets["tickets"]
            ]
        return [
            v
            if isinstance(v, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict({**v, "ticket_id": v.get("ticket_id", k)})
            for k, v in raw_tickets.items()
            if isinstance(v, (ItsmTicketRequest, Mapping))
        ]
    if isinstance(raw_tickets, Sequence) and not isinstance(
        raw_tickets, (str, bytes)
    ):
        return [
            t if isinstance(t, ItsmTicketRequest) else ItsmTicketRequest.from_dict(t)
            for t in raw_tickets
        ]
    raise ValueError(f"Unsupported itsm_tickets type: {type(raw_tickets)!r}")


def generate_html_dashboard(
    results: Sequence[ValidationResult | Mapping[str, Any]],
    *,
    sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
    action_plan: Optional[DryRunActionPlan] = None,
    approval_manifest: Optional[
        RemediationApprovalManifest | Mapping[str, Any]
    ] = None,
    manifest: Optional[RemediationApprovalManifest | Mapping[str, Any]] = None,
    streaks: Optional[
        Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore
    ] = None,
    reconciliation_report: Optional[
        ReconciliationReport | Mapping[str, Any]
    ] = None,
    reconciliation: Optional[ReconciliationReport | Mapping[str, Any]] = None,
    subnet_utilization: Optional[
        Sequence[SubnetUtilizationSummary | Mapping[str, Any]]
    ] = None,
    port_reclamation_plan: Optional[
        PortReclamationPlan | Mapping[str, Any]
    ] = None,
    port_plan: Optional[PortReclamationPlan | Mapping[str, Any]] = None,
    parity_report: Optional[
        ParityValidationReport
        | SiteMigrationReadinessScorecard
        | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    migration_scorecards: Optional[
        ParityValidationReport
        | SiteMigrationReadinessScorecard
        | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    ups_health_report: Optional[
        UpsFleetHealthReport
        | UpsHealthRecord
        | Sequence[UpsHealthRecord | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    ups_report: Optional[
        UpsFleetHealthReport
        | UpsHealthRecord
        | Sequence[UpsHealthRecord | Mapping[str, Any]]
        | Mapping[str, Any]
    ] = None,
    itsm_tickets: Optional[
        Sequence[ItsmTicketRequest | Mapping[str, Any]]
        | Mapping[str, Any]
        | ItsmTicketRequest
        | InMemoryItsmSink
    ] = None,
    tickets: Optional[
        Sequence[ItsmTicketRequest | Mapping[str, Any]]
        | Mapping[str, Any]
        | ItsmTicketRequest
        | InMemoryItsmSink
    ] = None,
    output_path: Optional[Path | str] = None,
    generated_at: Optional[datetime | str] = None,
    title: str = DEFAULT_DASHBOARD_TITLE,
) -> str:
    """Generate a self-contained, zero-dependency HTML5 operations dashboard."""
    report_dt = _resolve_report_timestamp(generated_at)
    sites_by_id = _index_sites(sites)

    json_report = generate_json_report(
        results,
        sites=sites_by_id if sites_by_id else None,
        action_plan=action_plan,
        output_path=None,
        generated_at=report_dt,
    )

    resolved_manifest = _coerce_manifest(
        approval_manifest if approval_manifest is not None else manifest
    )
    resolved_streaks = _coerce_streaks(streaks)
    resolved_reconciliation = _coerce_reconciliation(
        reconciliation_report
        if reconciliation_report is not None
        else reconciliation
    )
    resolved_subnets = _coerce_subnet_utilization(
        subnet_utilization, sites_by_id, results
    )
    resolved_port_plan = _coerce_port_reclamation_plan(
        port_reclamation_plan
        if port_reclamation_plan is not None
        else port_plan
    )
    resolved_parity = _coerce_parity_report(
        parity_report if parity_report is not None else migration_scorecards
    )
    resolved_ups = _coerce_ups_health_report(
        ups_health_report if ups_health_report is not None else ups_report
    )
    resolved_tickets = _coerce_itsm_tickets(
        itsm_tickets if itsm_tickets is not None else tickets
    )

    # Compute KPI counts
    total_items = int(json_report["total_items"])
    by_cls = json_report["summary"]["by_classification"]
    active_count = int(
        by_cls[ValidationClassification.CONFIRMED_ACTIVE.value]["count"]
    )
    stale_count = int(
        by_cls[ValidationClassification.STALE_LIKELY_UNUSED.value]["count"]
    )
    unreachable_count = int(
        by_cls[ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value]["count"]
    )
    insufficient_count = int(
        by_cls[ValidationClassification.INSUFFICIENT_DATA.value]["count"]
    )

    derived_manifest_from_streaks: Optional[RemediationApprovalManifest] = None
    if resolved_manifest is None and resolved_streaks is not None:
        engine = QuarantineEngine(QuarantinePolicy())
        eval_source: Sequence[Any] = (
            results if results else resolved_streaks
        )
        derived_manifest_from_streaks = engine.evaluate(
            eval_source,
            history=resolved_streaks,
            sites=list(sites_by_id.values()) if sites_by_id else None,
            generated_at=report_dt,
            include_below_threshold=True,
        )

    if resolved_manifest is not None:
        quarantine_eligible_count = len(resolved_manifest.eligible_entries)
    elif derived_manifest_from_streaks is not None:
        quarantine_eligible_count = len(
            derived_manifest_from_streaks.eligible_entries
        )
    elif action_plan is not None:
        quarantine_eligible_count = int(
            action_plan.summary_by_action.get(
                RemediationActionType.MARK_STALE_CANDIDATE.value, 0
            )
        )
    else:
        rem_summary = json_report.get("remediation_plan", {}).get(
            "summary_by_action", {}
        )
        quarantine_eligible_count = int(
            rem_summary.get(
                RemediationActionType.MARK_STALE_CANDIDATE.value, 0
            )
        )

    untracked_discrepancies_count = (
        resolved_reconciliation.total_discrepancies
        if resolved_reconciliation is not None
        else 0
    )

    reclaimable_ports_count = (
        len(resolved_port_plan.candidates)
        if resolved_port_plan is not None
        else 0
    )
    poe_watts_saved = (
        float(resolved_port_plan.estimated_poe_watts_saved)
        if resolved_port_plan is not None
        else 0.0
    )
    ready_cutover_sites_count = (
        resolved_parity.ready_for_cutover_count
        if resolved_parity is not None
        else 0
    )
    ups_alerts_count = (
        resolved_ups.critical_count
        + resolved_ups.warning_count
        + resolved_ups.unreachable_count
        if resolved_ups is not None
        else 0
    )
    itsm_tickets_count = len(resolved_tickets)

    enriched_results: list[dict[str, Any]] = json_report["results"]
    by_site_summary: dict[str, dict[str, Any]] = json_report["summary"][
        "by_site"
    ]

    # Collect filter dropdown options
    all_site_ids = sorted(
        set(by_site_summary.keys())
        | {str(item["site_id"]) for item in enriched_results}
    )
    all_item_types = sorted(
        {str(item["item_type"]) for item in enriched_results}
    )

    # 1. Build Site Summary Rows
    site_rows_html: list[str] = []
    if by_site_summary:
        for sid, sdata in by_site_summary.items():
            site_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(sid)}</code></td>"
                f"<td>{_esc(sdata.get('site_name', sid))}</td>"
                f"<td class=\"num\">{int(sdata.get('total', 0))}</td>"
                f"<td class=\"num\">{int(sdata.get(ValidationClassification.CONFIRMED_ACTIVE.value, 0))}</td>"
                f"<td class=\"num\">{int(sdata.get(ValidationClassification.STALE_LIKELY_UNUSED.value, 0))}</td>"
                f"<td class=\"num\">{int(sdata.get(ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value, 0))}</td>"
                f"<td class=\"num\">{int(sdata.get(ValidationClassification.INSUFFICIENT_DATA.value, 0))}</td>"
                "</tr>"
            )
    else:
        site_rows_html.append(
            '<tr><td colspan="7" class="empty-cell">No site summary records available.</td></tr>'
        )

    # 2. Build /24 Subnet Utilization Rows
    subnet_rows_html: list[str] = []
    if resolved_subnets:
        for sub in resolved_subnets:
            pct = max(0.0, min(100.0, float(sub.active_utilization_pct)))
            subnet_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(sub.subnet_id)}</code></td>"
                f"<td><code>{_esc(sub.site_id or '-')}</code></td>"
                f"<td><code>{_esc(sub.cidr)}</code></td>"
                f"<td class=\"num\">{int(sub.total_assigned_ips)}</td>"
                f"<td class=\"num\">{int(sub.confirmed_active_ips)}</td>"
                f"<td class=\"num\">{int(sub.stale_reclaimable_ips)}</td>"
                "<td>"
                '<div class="utilization-cell">'
                f'<span class="utilization-label">{pct:.2f}%</span>'
                '<div class="progress-bar">'
                f'<div class="progress-fill" style="width: {pct:.2f}%;"></div>'
                "</div>"
                "</div>"
                "</td>"
                "</tr>"
            )
    else:
        subnet_rows_html.append(
            '<tr><td colspan="7" class="empty-cell">No /24 subnet utilization data available.</td></tr>'
        )

    # 3. Build Interactive Inventory Classification Table Rows
    inventory_rows_html: list[str] = []
    if enriched_results:
        for item in enriched_results:
            sid = str(item.get("site_id") or "")
            sname = str(item.get("site_name") or sid)
            itype = str(item.get("item_type") or "")
            iid = str(item.get("item_id") or "")
            iname = str(item.get("name") or "")
            icat = str(item.get("category") or "-")
            ips_list = item.get("ip_addresses") or []
            ips_str = ", ".join(str(ip) for ip in ips_list) if ips_list else "-"
            cls_str = str(item.get("classification") or "")
            conf_val = float(item.get("confidence") or 0.0)
            rationale_str = str(item.get("rationale") or "")
            signals_list = item.get("signals") or []

            search_blob = " ".join(
                [sid, sname, itype, iid, iname, icat, ips_str, cls_str, rationale_str]
            ).lower()

            sig_items_html: list[str] = []
            for sig in signals_list:
                stype = _esc(sig.get("signal_type", ""))
                sstatus = _esc(sig.get("status", ""))
                ssource = _esc(sig.get("source") or "n/a")
                sage = (
                    f"{float(sig['age_seconds']):.1f}s"
                    if sig.get("age_seconds") is not None
                    else "n/a"
                )
                sdetails = _esc(sig.get("details") or "")
                sig_items_html.append(
                    "<li>"
                    f"<strong>{stype}</strong> [{sstatus}] "
                    f"(source: <code>{ssource}</code>, age: <code>{_esc(sage)}</code>)"
                    + (f" &mdash; {sdetails}" if sdetails else "")
                    + "</li>"
                )
            if sig_items_html:
                signals_html = (
                    f"<details><summary>{len(sig_items_html)} signal(s)</summary>"
                    f'<ul class="signal-list">{"".join(sig_items_html)}</ul>'
                    "</details>"
                )
            else:
                signals_html = '<span class="muted">No signals</span>'

            badge_cls = _classification_badge_class(cls_str)
            inventory_rows_html.append(
                '<tr class="inventory-row" '
                f'data-classification="{_esc(cls_str)}" '
                f'data-site-id="{_esc(sid)}" '
                f'data-item-type="{_esc(itype)}" '
                f'data-search="{_esc(search_blob)}">'
                f"<td><code>{_esc(sid)}</code></td>"
                f"<td>{_esc(sname)}</td>"
                f"<td>{_esc(itype)}</td>"
                f"<td><code>{_esc(iid)}</code></td>"
                f"<td>{_esc(iname)}</td>"
                f"<td>{_esc(icat)}</td>"
                f"<td><code>{_esc(ips_str)}</code></td>"
                f'<td><span class="badge {badge_cls}">{_esc(cls_str)}</span></td>'
                f'<td class="num">{conf_val:.2f}</td>'
                f"<td>{_esc(rationale_str)}</td>"
                f"<td>{signals_html}</td>"
                "</tr>"
            )
    else:
        inventory_rows_html.append(
            '<tr><td colspan="11" class="empty-cell">No inventory validation results available.</td></tr>'
        )

    # 4. Build Phase 2 Quarantine & Remediation Queue Section
    active_manifest = resolved_manifest or derived_manifest_from_streaks
    manifest_meta_html = ""
    quarantine_rows_html: list[str] = []

    if resolved_manifest is not None:
        digest_valid = resolved_manifest.verify_digest()
        digest_badge = (
            '<span class="badge badge-active">SHA-256 VERIFIED</span>'
            if digest_valid
            else '<span class="badge badge-stale">DIGEST MISMATCH</span>'
        )
        manifest_meta_html = (
            '<div class="section-meta">'
            f"<span><strong>Manifest ID:</strong> <code>{_esc(resolved_manifest.manifest_id)}</code></span> "
            f"<span><strong>SHA-256 Digest:</strong> <code>{_esc(resolved_manifest.manifest_sha256)}</code></span> "
            f"{digest_badge}"
            "</div>"
        )

    if active_manifest is not None and active_manifest.entries:
        for entry in active_manifest.entries:
            op_val = (
                entry.target_operation.value
                if isinstance(entry.target_operation, RemediationOperation)
                else str(entry.target_operation)
            )
            grad_val = (
                entry.graduation_status.value
                if isinstance(entry.graduation_status, QuarantineGraduationStatus)
                else str(entry.graduation_status)
            )
            app_val = (
                entry.approval_status.value
                if isinstance(entry.approval_status, ApprovalStatus)
                else str(entry.approval_status)
            )
            app_badge = _approval_badge_class(app_val)
            quarantine_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(entry.item_id)}</code></td>"
                f"<td><code>{_esc(entry.site_id)}</code></td>"
                f"<td>{_esc(entry.item_type)}</td>"
                f"<td>{_esc(entry.name)}</td>"
                f'<td class="num">{int(entry.consecutive_stale_runs)}</td>'
                f'<td class="num">{float(entry.stale_duration_days):.1f}</td>'
                f"<td><code>{_esc(op_val)}</code></td>"
                f"<td><code>{_esc(grad_val)}</code></td>"
                f'<td><span class="badge {app_badge}">{_esc(app_val)}</span></td>'
                f"<td>{_esc(entry.exemption_reason or entry.review_note or entry.rationale or '-')}</td>"
                "</tr>"
            )
    elif action_plan is not None and action_plan.actions:
        for act in action_plan.actions:
            quarantine_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(act.item_id)}</code></td>"
                f"<td><code>{_esc(act.site_id)}</code></td>"
                f"<td>{_esc(act.item_type)}</td>"
                f"<td>{_esc(act.name)}</td>"
                '<td class="num">1</td>'
                '<td class="num">0.0</td>'
                f"<td><code>{_esc(act.action_type.value)}</code></td>"
                "<td><code>DRY_RUN_CANDIDATE</code></td>"
                '<td><span class="badge badge-unreachable">PENDING</span></td>'
                f"<td>{_esc(act.rationale or '-')}</td>"
                "</tr>"
            )
    else:
        quarantine_rows_html.append(
            '<tr><td colspan="10" class="empty-cell">No quarantine or remediation queue entries present.</td></tr>'
        )

    # 5. Build Phase 3 Reverse Discovery / Untracked Assets Section
    disc_by_type_html: list[str] = []
    disc_rows_html: list[str] = []
    if resolved_reconciliation is not None:
        by_type = resolved_reconciliation.summary_by_type
        for dtype in ALL_DISCREPANCY_TYPES:
            cnt = int(by_type.get(dtype.value, 0))
            disc_by_type_html.append(
                '<div class="mini-stat">'
                f'<span class="mini-stat-label"><code>{_esc(dtype.value)}</code></span>'
                f'<span class="mini-stat-value">{cnt}</span>'
                "</div>"
            )
        if resolved_reconciliation.discrepancies:
            for disc in resolved_reconciliation.discrepancies:
                disc_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(disc.discrepancy_id)}</code></td>"
                    f"<td><code>{_esc(disc.discrepancy_type.value)}</code></td>"
                    f"<td><code>{_esc(disc.site_id)}</code></td>"
                    f"<td><code>{_esc(disc.observed_identifier)}</code></td>"
                    f"<td><code>{_esc(disc.observed_ip or '-')}</code></td>"
                    f"<td><code>{_esc(disc.observed_mac or '-')}</code></td>"
                    f"<td>{_esc(disc.observed_hostname or '-')}</td>"
                    f"<td><code>{_esc(disc.source)}</code></td>"
                    f"<td><code>{_esc(disc.sot_item_id or '-')}</code></td>"
                    f"<td>{_esc(disc.details or '-')}</td>"
                    f"<td>{_esc(disc.recommended_onboarding_action or '-')}</td>"
                    "</tr>"
                )
        else:
            disc_rows_html.append(
                '<tr><td colspan="11" class="empty-cell">No untracked assets or attribute discrepancies detected.</td></tr>'
            )
    else:
        for dtype in ALL_DISCREPANCY_TYPES:
            disc_by_type_html.append(
                '<div class="mini-stat">'
                f'<span class="mini-stat-label"><code>{_esc(dtype.value)}</code></span>'
                '<span class="mini-stat-value">0</span>'
                "</div>"
            )
        disc_rows_html.append(
            '<tr><td colspan="11" class="empty-cell">No Phase 3 reverse discovery reconciliation report provided.</td></tr>'
        )

    # 6. Build Phase 4 Extreme Networks Switch Port & PoE Reclamation Section
    port_plan_meta_html = ""
    port_candidates_rows_html: list[str] = []
    port_blocked_rows_html: list[str] = []
    if resolved_port_plan is not None:
        port_plan_meta_html = (
            '<div class="section-meta">'
            f"<span><strong>Plan ID:</strong> <code>{_esc(resolved_port_plan.plan_id)}</code></span> "
            f"<span><strong>CLI Dialect:</strong> <code>{_esc(resolved_port_plan.dialect.value.upper())}</code></span> "
            f"<span><strong>Eligible Ports:</strong> <code>{len(resolved_port_plan.candidates)}</code></span> "
            f"<span><strong>LLDP Guard Protected:</strong> <code>{len(resolved_port_plan.blocked_ports)}</code></span> "
            f"<span><strong>Estimated PoE Savings:</strong> <code>{resolved_port_plan.estimated_poe_watts_saved:.2f}W</code></span> "
            '<span class="badge badge-active">DRY-RUN STAGED</span>'
            "</div>"
        )
        if resolved_port_plan.candidates:
            for cand in resolved_port_plan.candidates:
                exos_cmds_str = " ; ".join(cand.exos_disable_commands)
                voss_cmds_str = " ; ".join(cand.voss_disable_commands)
                port_candidates_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(cand.site_id or '-')}</code></td>"
                    f"<td><code>{_esc(cand.device_id)}</code></td>"
                    f"<td><code>{_esc(cand.port_name)}</code></td>"
                    f'<td class="num">{cand.inactive_runs}</td>'
                    f'<td class="num">{cand.inactive_days:.1f}</td>'
                    f'<td class="num">{cand.estimated_poe_watts_saved:.2f}W</td>'
                    f"<td><code>{_esc(exos_cmds_str)}</code></td>"
                    f"<td><code>{_esc(voss_cmds_str)}</code></td>"
                    f"<td><code>{_esc(cand.exos_rollback_command)}</code></td>"
                    "</tr>"
                )
        else:
            port_candidates_rows_html.append(
                '<tr><td colspan="9" class="empty-cell">No eligible switch ports for reclamation.</td></tr>'
            )

        if resolved_port_plan.blocked_ports:
            for bport in resolved_port_plan.blocked_ports:
                rules_str = ", ".join(bport.matched_rules) or "-"
                port_blocked_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(bport.site_id or '-')}</code></td>"
                    f"<td><code>{_esc(bport.device_id)}</code></td>"
                    f"<td><code>{_esc(bport.port_name)}</code></td>"
                    f"<td><code>{_esc(bport.port_id)}</code></td>"
                    f'<td><span class="badge badge-stale">PROTECTED</span></td>'
                    f"<td><code>{_esc(rules_str)}</code></td>"
                    f"<td>{_esc(bport.block_reason)}</td>"
                    "</tr>"
                )
        else:
            port_blocked_rows_html.append(
                '<tr><td colspan="7" class="empty-cell">No LLDP Uplink Guard blocked ports recorded.</td></tr>'
            )
    else:
        port_candidates_rows_html.append(
            '<tr><td colspan="9" class="empty-cell">No Phase 4 Extreme port reclamation plan provided.</td></tr>'
        )
        port_blocked_rows_html.append(
            '<tr><td colspan="7" class="empty-cell">No Phase 4 LLDP Uplink Guard audit records provided.</td></tr>'
        )

    # 7. Build Phase 5 Modern SoT Dual-Run Parity & Migration Readiness Scorecards Section
    parity_meta_html = ""
    parity_scorecard_rows_html: list[str] = []
    if resolved_parity is not None:
        overall_rec_badge = _cutover_badge_class(
            resolved_parity.overall_recommendation.value
        )
        parity_meta_html = (
            '<div class="section-meta">'
            f"<span><strong>Total Sites Evaluated:</strong> <code>{resolved_parity.total_sites}</code></span> "
            f"<span><strong>Ready for Cutover:</strong> <code>{resolved_parity.ready_for_cutover_count}</code></span> "
            f"<span><strong>Needs Remediation:</strong> <code>{resolved_parity.needs_remediation_count}</code></span> "
            f"<span><strong>Blocked:</strong> <code>{resolved_parity.blocked_count}</code></span> "
            f"<span><strong>Overall Readiness Score:</strong> <code>{resolved_parity.overall_readiness_score:.2f}%</code></span> "
            f'<span class="badge {overall_rec_badge}">{_esc(resolved_parity.overall_recommendation.value)}</span>'
            "</div>"
        )
        if resolved_parity.scorecards:
            for sc in resolved_parity.scorecards:
                rec_badge = _cutover_badge_class(sc.recommendation.value)
                blockers_str = (
                    "; ".join(sc.blocking_reasons)
                    if sc.blocking_reasons
                    else "None (100% Parity Verified)"
                )
                parity_scorecard_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(sc.site_id)}</code></td>"
                    f"<td>{_esc(sc.site_name)}</td>"
                    f'<td class="num"><strong>{sc.readiness_score:.2f}%</strong></td>'
                    f'<td class="num">{sc.parity_match_percentage:.2f}%</td>'
                    f'<td><span class="badge {rec_badge}">{_esc(sc.recommendation.value)}</span></td>'
                    f'<td class="num">{sc.matched_modern_items}/{sc.expected_golden_items}</td>'
                    f'<td class="num">{len(sc.unwaived_discrepancies)} (waived: {sc.waived_discrepancy_count})</td>'
                    f'<td class="num">{sc.unresolved_untracked_count}</td>'
                    f"<td>{_esc(blockers_str)}</td>"
                    "</tr>"
                )
        else:
            parity_scorecard_rows_html.append(
                '<tr><td colspan="9" class="empty-cell">No site migration readiness scorecards available.</td></tr>'
            )
    else:
        parity_scorecard_rows_html.append(
            '<tr><td colspan="9" class="empty-cell">No Phase 5 Modern SoT parity report provided.</td></tr>'
        )

    # 8. Build Phase 6 APC UPS Fleet Health & Environmental Telemetry Section
    ups_meta_html = ""
    ups_rows_html: list[str] = []
    if resolved_ups is not None:
        ups_meta_html = (
            '<div class="section-meta">'
            f"<span><strong>Total UPS Units:</strong> <code>{resolved_ups.total_units}</code></span> "
            f"<span><strong>Healthy:</strong> <code>{resolved_ups.healthy_count}</code></span> "
            f"<span><strong>Warning:</strong> <code>{resolved_ups.warning_count}</code></span> "
            f"<span><strong>Critical:</strong> <code>{resolved_ups.critical_count}</code></span> "
            f"<span><strong>Unreachable:</strong> <code>{resolved_ups.unreachable_count}</code></span> "
            f"<span><strong>Battery Replacement Needed:</strong> <code>{len(resolved_ups.battery_replacement_units)}</code></span>"
            "</div>"
        )
        if resolved_ups.records:
            for urec in resolved_ups.records:
                ubadge = _ups_status_badge_class(urec.status.value)
                adv_str = ", ".join(urec.advisories) if urec.advisories else "NONE"
                runtime_str = (
                    f"{urec.runtime_remaining_minutes:.1f} min"
                    if urec.runtime_remaining_minutes is not None
                    else "-"
                )
                temp_str = (
                    f"{urec.temperature_celsius:.1f} C"
                    if urec.temperature_celsius is not None
                    else "-"
                )
                load_str = (
                    f"{urec.output_load_pct:.1f}%"
                    if urec.output_load_pct is not None
                    else "-"
                )
                ups_rows_html.append(
                    "<tr>"
                    f"<td><code>{_esc(urec.site_id)}</code></td>"
                    f"<td><code>{_esc(urec.equipment_id)}</code></td>"
                    f"<td>{_esc(urec.name)}</td>"
                    f"<td><code>{_esc(urec.ip_address or '-')}</code></td>"
                    f"<td>{_esc(urec.model or 'APC Smart-UPS')}</td>"
                    f'<td><span class="badge {ubadge}">{_esc(urec.status.value)}</span></td>'
                    f"<td><code>{_esc(urec.battery_status or '-')}</code></td>"
                    f"<td><code>{'YES' if urec.needs_battery_replacement else 'NO'}</code></td>"
                    f'<td class="num">{_esc(runtime_str)}</td>'
                    f'<td class="num">{_esc(temp_str)}</td>'
                    f'<td class="num">{_esc(load_str)}</td>'
                    f"<td><code>{_esc(adv_str)}</code></td>"
                    "</tr>"
                )
        else:
            ups_rows_html.append(
                '<tr><td colspan="12" class="empty-cell">No APC UPS health records evaluated.</td></tr>'
            )
    else:
        ups_rows_html.append(
            '<tr><td colspan="12" class="empty-cell">No Phase 6 APC UPS fleet health telemetry report provided.</td></tr>'
        )

    # 9. Build Phase 6 ITSM Change-Ticket & Approval Governance Queue Section
    itsm_rows_html: list[str] = []
    if resolved_tickets:
        for tkt in resolved_tickets:
            tbadge = _approval_badge_class(tkt.approval_status.value)
            sites_str = ", ".join(tkt.site_ids) if tkt.site_ids else "-"
            itsm_rows_html.append(
                "<tr>"
                f"<td><code>{_esc(tkt.ticket_id)}</code></td>"
                f"<td><code>{_esc(tkt.workflow_type.value)}</code></td>"
                f"<td>{_esc(tkt.title)}</td>"
                f"<td><code>{_esc(tkt.risk)}</code> / <code>{_esc(tkt.priority)}</code></td>"
                f"<td><code>{_esc(sites_str)}</code></td>"
                f"<td><code>{_esc(tkt.artifact_id or '-')}</code></td>"
                f"<td><code>{_esc(tkt.artifact_sha256 or '-')}</code></td>"
                f'<td><span class="badge {tbadge}">{_esc(tkt.approval_status.value)}</span></td>'
                f"<td>{_esc(tkt.approved_by or '-')}</td>"
                "</tr>"
            )
    else:
        itsm_rows_html.append(
            '<tr><td colspan="9" class="empty-cell">No Phase 6 ITSM change tickets or incident payloads queued.</td></tr>'
        )

    cls_options_html = "".join(
        f'<option value="{_esc(c.value)}">{_esc(c.value)}</option>'
        for c in ALL_CLASSIFICATIONS
    )
    site_options_html = "".join(
        f'<option value="{_esc(sid)}">{_esc(sid)}</option>'
        for sid in all_site_ids
    )
    type_options_html = "".join(
        f'<option value="{_esc(t)}">{_esc(t)}</option>'
        for t in all_item_types
    )

    gen_at_str = _esc(json_report["generated_at"])
    safe_title = _esc(title)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{safe_title}</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #475569;
      --active-bg: #dcfce7;
      --active-fg: #166534;
      --stale-bg: #fee2e2;
      --stale-fg: #991b1b;
      --unreach-bg: #fef3c7;
      --unreach-fg: #92400e;
      --insuff-bg: #e2e8f0;
      --insuff-fg: #334155;
      --accent: #2563eb;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    header {{
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 2px solid var(--border);
    }}
    header h1 {{
      margin: 0 0 8px 0;
      font-size: 1.75rem;
    }}
    .header-meta {{
      color: var(--muted);
      font-size: 0.9rem;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 28px;
    }}
    .kpi-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }}
    .kpi-label {{
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 6px;
    }}
    .kpi-value {{
      font-size: 1.8rem;
      font-weight: 700;
    }}
    section {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 24px;
    }}
    section h2 {{
      margin-top: 0;
      font-size: 1.25rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
    }}
    section h3 {{
      font-size: 1.05rem;
      margin: 16px 0 8px 0;
    }}
    .section-meta {{
      margin-bottom: 12px;
      font-size: 0.9rem;
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      align-items: center;
    }}
    .filter-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
      align-items: center;
    }}
    .filter-bar label {{
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--muted);
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .filter-bar select, .filter-bar input {{
      padding: 6px 10px;
      border: 1px solid var(--border);
      border-radius: 4px;
      font-size: 0.9rem;
      min-width: 170px;
    }}
    .table-wrap {{
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }}
    th, td {{
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{
      background: #f1f5f9;
      font-weight: 600;
      white-space: nowrap;
    }}
    td.num, th.num {{
      text-align: right;
    }}
    .empty-cell {{
      text-align: center;
      color: var(--muted);
      font-style: italic;
      padding: 20px;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      white-space: nowrap;
    }}
    .badge-active {{ background: var(--active-bg); color: var(--active-fg); }}
    .badge-stale {{ background: var(--stale-bg); color: var(--stale-fg); }}
    .badge-unreachable {{ background: var(--unreach-bg); color: var(--unreach-fg); }}
    .badge-insufficient {{ background: var(--insuff-bg); color: var(--insuff-fg); }}
    .utilization-cell {{
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 150px;
    }}
    .utilization-label {{
      min-width: 56px;
      text-align: right;
      font-variant-numeric: tabular-nums;
    }}
    .progress-bar {{
      flex: 1;
      height: 8px;
      background: var(--border);
      border-radius: 4px;
      overflow: hidden;
    }}
    .progress-fill {{
      height: 100%;
      background: var(--accent);
    }}
    .signal-list {{
      margin: 6px 0 0 0;
      padding-left: 18px;
      font-size: 0.8rem;
    }}
    .mini-stats {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
    }}
    .mini-stat {{
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      display: flex;
      gap: 10px;
      align-items: center;
      background: #f8fafc;
    }}
    .mini-stat-value {{
      font-weight: 700;
      font-size: 1.05rem;
    }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
<body>
  <header>
    <h1>{safe_title}</h1>
    <div class="header-meta">
      Generated At: <code>{gen_at_str}</code> | Mode: <code>Read-Only / Gated Operations</code>
    </div>
  </header>

  <div class="kpi-grid" id="kpi-summary">
    <div class="kpi-card">
      <div class="kpi-label">Total Evaluated</div>
      <div class="kpi-value" data-kpi="total-evaluated">{total_items}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Confirmed Active</div>
      <div class="kpi-value" data-kpi="confirmed-active">{active_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Stale / Likely Unused</div>
      <div class="kpi-value" data-kpi="stale-likely-unused">{stale_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Unreachable / Needs Manual Review</div>
      <div class="kpi-value" data-kpi="unreachable-needs-review">{unreachable_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Insufficient Data</div>
      <div class="kpi-value" data-kpi="insufficient-data">{insufficient_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Quarantine Eligible</div>
      <div class="kpi-value" data-kpi="quarantine-eligible">{quarantine_eligible_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Untracked Discrepancies</div>
      <div class="kpi-value" data-kpi="untracked-discrepancies">{untracked_discrepancies_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Reclaimable Switch Ports</div>
      <div class="kpi-value" data-kpi="reclaimable-ports">{reclaimable_ports_count} ({poe_watts_saved:.1f}W)</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Sites Ready for Cutover</div>
      <div class="kpi-value" data-kpi="sites-ready-for-cutover">{ready_cutover_sites_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">APC UPS Health Alerts</div>
      <div class="kpi-value" data-kpi="ups-health-alerts">{ups_alerts_count}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">ITSM Change Tickets</div>
      <div class="kpi-value" data-kpi="itsm-tickets">{itsm_tickets_count}</div>
    </div>
  </div>

  <section id="site-subnet-health">
    <h2>1. Per-Site &amp; /24 Subnet Utilization Health</h2>
    <h3>Site Classification Breakdown</h3>
    <div class="table-wrap">
      <table id="site-summary-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Site Name</th>
            <th class="num">Total</th>
            <th class="num">Confirmed Active</th>
            <th class="num">Stale / Likely Unused</th>
            <th class="num">Unreachable / Needs Manual Review</th>
            <th class="num">Insufficient Data</th>
          </tr>
        </thead>
        <tbody>
          {"".join(site_rows_html)}
        </tbody>
      </table>
    </div>

    <h3>/24 Subnet IP Utilization</h3>
    <div class="table-wrap">
      <table id="subnet-utilization-table">
        <thead>
          <tr>
            <th>Subnet ID</th>
            <th>Site ID</th>
            <th>CIDR</th>
            <th class="num">Total Assigned IPs</th>
            <th class="num">Confirmed Active IPs</th>
            <th class="num">Stale Reclaimable IPs</th>
            <th>Active Utilization</th>
          </tr>
        </thead>
        <tbody>
          {"".join(subnet_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="inventory-classification-section">
    <h2>2. Interactive Inventory Classification &amp; Signal Evidence Table</h2>
    <div class="filter-bar">
      <label>
        Classification
        <select id="filter-classification">
          <option value="">All Classifications</option>
          {cls_options_html}
        </select>
      </label>
      <label>
        Site ID
        <select id="filter-site">
          <option value="">All Sites</option>
          {site_options_html}
        </select>
      </label>
      <label>
        Item Type
        <select id="filter-type">
          <option value="">All Item Types</option>
          {type_options_html}
        </select>
      </label>
      <label>
        Search (ID / Name / IP / Rationale)
        <input type="search" id="filter-search" placeholder="Filter items...">
      </label>
      <div class="header-meta">
        Showing <strong id="visible-row-count">{len(enriched_results)}</strong> of {len(enriched_results)} items
      </div>
    </div>
    <div class="table-wrap">
      <table id="inventory-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Site Name</th>
            <th>Item Type</th>
            <th>Item ID</th>
            <th>Name</th>
            <th>Category</th>
            <th>IP Addresses</th>
            <th>Classification</th>
            <th class="num">Confidence</th>
            <th>Rationale</th>
            <th>Signals Evidence Trail</th>
          </tr>
        </thead>
        <tbody>
          {"".join(inventory_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="quarantine-remediation-section">
    <h2>3. Phase 2 Quarantine &amp; Remediation Queue</h2>
    {manifest_meta_html}
    <div class="table-wrap">
      <table id="quarantine-table">
        <thead>
          <tr>
            <th>Item ID</th>
            <th>Site ID</th>
            <th>Item Type</th>
            <th>Name</th>
            <th class="num">Consecutive Stale Runs</th>
            <th class="num">Stale Duration (Days)</th>
            <th>Target Operation</th>
            <th>Graduation Status</th>
            <th>Approval Status</th>
            <th>Notes / Exemption Reason</th>
          </tr>
        </thead>
        <tbody>
          {"".join(quarantine_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="reverse-discovery-section">
    <h2>4. Phase 3 Reverse Discovery &amp; Untracked Assets</h2>
    <div class="mini-stats">
      {"".join(disc_by_type_html)}
    </div>
    <div class="table-wrap">
      <table id="discrepancies-table">
        <thead>
          <tr>
            <th>Discrepancy ID</th>
            <th>Discrepancy Type</th>
            <th>Site ID</th>
            <th>Observed Identifier</th>
            <th>Observed IP</th>
            <th>Observed MAC</th>
            <th>Observed Hostname</th>
            <th>Source</th>
            <th>SoT Item ID</th>
            <th>Details</th>
            <th>Recommended Onboarding Action</th>
          </tr>
        </thead>
        <tbody>
          {"".join(disc_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="port-reclamation-section">
    <h2>5. Phase 4 Extreme Networks Switch Port &amp; PoE Reclamation</h2>
    {port_plan_meta_html}
    <h3>Eligible Stale Access Ports (Staged ExtremeXOS / VOSS Commands)</h3>
    <div class="table-wrap">
      <table id="port-reclamation-candidates-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Switch Device ID</th>
            <th>Port Name</th>
            <th class="num">Inactive Runs</th>
            <th class="num">Inactive Days</th>
            <th class="num">PoE Saved</th>
            <th>ExtremeXOS Disable Commands</th>
            <th>Extreme VOSS Disable Commands</th>
            <th>1-Command Rollback</th>
          </tr>
        </thead>
        <tbody>
          {"".join(port_candidates_rows_html)}
        </tbody>
      </table>
    </div>

    <h3>LLDP Uplink Guard Protected Ports Audit</h3>
    <div class="table-wrap">
      <table id="port-reclamation-blocked-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Switch Device ID</th>
            <th>Port Name</th>
            <th>Port ID</th>
            <th>Guard Status</th>
            <th>Matched Safety Rules</th>
            <th>Protection Reason</th>
          </tr>
        </thead>
        <tbody>
          {"".join(port_blocked_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="modern-sot-parity-section">
    <h2>6. Phase 5 Modern SoT Dual-Run Parity &amp; Migration Readiness Scorecards</h2>
    {parity_meta_html}
    <div class="table-wrap">
      <table id="parity-scorecards-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Site Name</th>
            <th class="num">Readiness Score</th>
            <th class="num">Parity Match</th>
            <th>Cutover Recommendation</th>
            <th class="num">Matched / Expected</th>
            <th class="num">Parity Discrepancies</th>
            <th class="num">Unresolved Shadow IT</th>
            <th>Blocking Reasons</th>
          </tr>
        </thead>
        <tbody>
          {"".join(parity_scorecard_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="ups-health-section">
    <h2>7. Phase 6 APC UPS Fleet Health &amp; Environmental Telemetry</h2>
    {ups_meta_html}
    <div class="table-wrap">
      <table id="ups-health-table">
        <thead>
          <tr>
            <th>Site ID</th>
            <th>Equipment ID</th>
            <th>UPS Hostname</th>
            <th>IP Address</th>
            <th>Model</th>
            <th>Health Status</th>
            <th>Battery Status</th>
            <th>Replace Battery</th>
            <th class="num">Runtime Remaining</th>
            <th class="num">Temp</th>
            <th class="num">Output Load</th>
            <th>Active Advisories</th>
          </tr>
        </thead>
        <tbody>
          {"".join(ups_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <section id="itsm-governance-section">
    <h2>8. Phase 6 ITSM Change-Ticket &amp; Approval Governance Queue</h2>
    <div class="table-wrap">
      <table id="itsm-tickets-table">
        <thead>
          <tr>
            <th>Ticket ID</th>
            <th>Workflow Type</th>
            <th>Title / Short Description</th>
            <th>Risk / Priority</th>
            <th>Sites</th>
            <th>Artifact ID</th>
            <th>Artifact SHA-256 Digest</th>
            <th>Approval Status</th>
            <th>Approved By</th>
          </tr>
        </thead>
        <tbody>
          {"".join(itsm_rows_html)}
        </tbody>
      </table>
    </div>
  </section>

  <script>
    (function () {{
      var clsSelect = document.getElementById("filter-classification");
      var siteSelect = document.getElementById("filter-site");
      var typeSelect = document.getElementById("filter-type");
      var searchInput = document.getElementById("filter-search");
      var countEl = document.getElementById("visible-row-count");
      var rows = Array.prototype.slice.call(
        document.querySelectorAll("#inventory-table tbody tr.inventory-row")
      );

      function applyFilters() {{
        var clsVal = clsSelect ? clsSelect.value : "";
        var siteVal = siteSelect ? siteSelect.value : "";
        var typeVal = typeSelect ? typeSelect.value : "";
        var query = searchInput ? searchInput.value.trim().toLowerCase() : "";
        var visible = 0;

        for (var i = 0; i < rows.length; i++) {{
          var row = rows[i];
          var rowCls = row.getAttribute("data-classification") || "";
          var rowSite = row.getAttribute("data-site-id") || "";
          var rowType = row.getAttribute("data-item-type") || "";
          var rowSearch = row.getAttribute("data-search") || "";

          var match =
            (!clsVal || rowCls === clsVal) &&
            (!siteVal || rowSite === siteVal) &&
            (!typeVal || rowType === typeVal) &&
            (!query || rowSearch.indexOf(query) !== -1);

          row.style.display = match ? "" : "none";
          if (match) {{
            visible += 1;
          }}
        }}

        if (countEl) {{
          countEl.textContent = String(visible);
        }}
      }}

      if (clsSelect) clsSelect.addEventListener("change", applyFilters);
      if (siteSelect) siteSelect.addEventListener("change", applyFilters);
      if (typeSelect) typeSelect.addEventListener("change", applyFilters);
      if (searchInput) searchInput.addEventListener("input", applyFilters);
    }})();
  </script>
</body>
</html>
"""

    if output_path is not None:
        target = Path(output_path)
        if target.exists() and target.is_dir():
            target = target / DEFAULT_DASHBOARD_FILENAME
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(html_doc, encoding="utf-8")

    return html_doc


class HtmlDashboardGenerator:
    """Object-oriented wrapper for generating self-contained HTML5 operations dashboards."""

    DEFAULT_FILENAME = DEFAULT_DASHBOARD_FILENAME

    def generate(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        action_plan: Optional[DryRunActionPlan] = None,
        approval_manifest: Optional[
            RemediationApprovalManifest | Mapping[str, Any]
        ] = None,
        manifest: Optional[
            RemediationApprovalManifest | Mapping[str, Any]
        ] = None,
        streaks: Optional[
            Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport | Mapping[str, Any]
        ] = None,
        reconciliation: Optional[
            ReconciliationReport | Mapping[str, Any]
        ] = None,
        subnet_utilization: Optional[
            Sequence[SubnetUtilizationSummary | Mapping[str, Any]]
        ] = None,
        port_reclamation_plan: Optional[
            PortReclamationPlan | Mapping[str, Any]
        ] = None,
        port_plan: Optional[PortReclamationPlan | Mapping[str, Any]] = None,
        parity_report: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        migration_scorecards: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        ups_health_report: Optional[
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        ups_report: Optional[
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        itsm_tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, Any]
            | ItsmTicketRequest
            | InMemoryItsmSink
        ] = None,
        tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, Any]
            | ItsmTicketRequest
            | InMemoryItsmSink
        ] = None,
        output_path: Optional[Path | str] = None,
        generated_at: Optional[datetime | str] = None,
        title: str = DEFAULT_DASHBOARD_TITLE,
    ) -> str:
        return generate_html_dashboard(
            results,
            sites=sites,
            action_plan=action_plan,
            approval_manifest=approval_manifest,
            manifest=manifest,
            streaks=streaks,
            reconciliation_report=reconciliation_report,
            reconciliation=reconciliation,
            subnet_utilization=subnet_utilization,
            port_reclamation_plan=port_reclamation_plan,
            port_plan=port_plan,
            parity_report=parity_report,
            migration_scorecards=migration_scorecards,
            ups_health_report=ups_health_report,
            ups_report=ups_report,
            itsm_tickets=itsm_tickets,
            tickets=tickets,
            output_path=output_path,
            generated_at=generated_at,
            title=title,
        )

    def write(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        output_path: Path | str = DEFAULT_DASHBOARD_FILENAME,
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        action_plan: Optional[DryRunActionPlan] = None,
        approval_manifest: Optional[
            RemediationApprovalManifest | Mapping[str, Any]
        ] = None,
        manifest: Optional[
            RemediationApprovalManifest | Mapping[str, Any]
        ] = None,
        streaks: Optional[
            Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport | Mapping[str, Any]
        ] = None,
        reconciliation: Optional[
            ReconciliationReport | Mapping[str, Any]
        ] = None,
        subnet_utilization: Optional[
            Sequence[SubnetUtilizationSummary | Mapping[str, Any]]
        ] = None,
        port_reclamation_plan: Optional[
            PortReclamationPlan | Mapping[str, Any]
        ] = None,
        port_plan: Optional[PortReclamationPlan | Mapping[str, Any]] = None,
        parity_report: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        migration_scorecards: Optional[
            ParityValidationReport
            | SiteMigrationReadinessScorecard
            | Sequence[SiteMigrationReadinessScorecard | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        ups_health_report: Optional[
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        ups_report: Optional[
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        itsm_tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, Any]
            | ItsmTicketRequest
            | InMemoryItsmSink
        ] = None,
        tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, Any]
            | ItsmTicketRequest
            | InMemoryItsmSink
        ] = None,
        generated_at: Optional[datetime | str] = None,
        title: str = DEFAULT_DASHBOARD_TITLE,
    ) -> Path:
        target = Path(output_path)
        if target.exists() and target.is_dir():
            target = target / DEFAULT_DASHBOARD_FILENAME
        generate_html_dashboard(
            results,
            sites=sites,
            action_plan=action_plan,
            approval_manifest=approval_manifest,
            manifest=manifest,
            streaks=streaks,
            reconciliation_report=reconciliation_report,
            reconciliation=reconciliation,
            subnet_utilization=subnet_utilization,
            port_reclamation_plan=port_reclamation_plan,
            port_plan=port_plan,
            parity_report=parity_report,
            migration_scorecards=migration_scorecards,
            ups_health_report=ups_health_report,
            ups_report=ups_report,
            itsm_tickets=itsm_tickets,
            tickets=tickets,
            output_path=target,
            generated_at=generated_at,
            title=title,
        )
        return target


__all__ = [
    "DEFAULT_DASHBOARD_FILENAME",
    "DEFAULT_DASHBOARD_TITLE",
    "HtmlDashboardGenerator",
    "generate_html_dashboard",
]
