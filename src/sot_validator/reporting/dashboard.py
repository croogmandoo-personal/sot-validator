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
from sot_validator.models import (
    Site,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.reconciliation.reconciler import (
    ALL_DISCREPANCY_TYPES,
    DiscrepancyRecord,
    ReconciliationReport,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineEngine,
    QuarantineGraduationStatus,
    QuarantineManifestEntry,
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
    if upper == ApprovalStatus.APPROVED.value:
        return "badge-active"
    if upper == ApprovalStatus.PENDING.value:
        return "badge-unreachable"
    if upper == ApprovalStatus.REJECTED.value:
        return "badge-stale"
    return "badge-insufficient"


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
    raw_streaks: Optional[Sequence[ItemStreakSummary | Mapping[str, Any]] | HistoryStore],
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
