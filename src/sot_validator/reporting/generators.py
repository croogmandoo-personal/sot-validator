"""Multi-format validation report generators (JSON, CSV, Markdown) and combined report writer."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import csv
from datetime import datetime, timezone
import io
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    NetworkDevice,
    Site,
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _parse_optional_datetime,
)
from sot_validator.remediation.sink import (
    DryRunActionPlan,
    DryRunActionPlanGenerator,
    RemediationActionType,
)

CSV_REPORT_COLUMNS: tuple[str, ...] = (
    "site_id",
    "site_name",
    "item_type",
    "item_id",
    "name",
    "ip_addresses",
    "classification",
    "confidence",
    "rationale",
    "evaluated_at",
)

ALL_CLASSIFICATIONS: tuple[ValidationClassification, ...] = (
    ValidationClassification.CONFIRMED_ACTIVE,
    ValidationClassification.STALE_LIKELY_UNUSED,
    ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
    ValidationClassification.INSUFFICIENT_DATA,
)

ALL_EQUIPMENT_CATEGORIES: tuple[EquipmentCategory, ...] = (
    EquipmentCategory.SERVER,
    EquipmentCategory.SAN,
    EquipmentCategory.UPS,
    EquipmentCategory.VM,
    EquipmentCategory.OTHER,
)


def _resolve_report_timestamp(value: Optional[datetime | str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = _parse_optional_datetime(value, "generated_at")
    assert parsed is not None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _index_sites(
    sites: Optional[Sequence[Site] | Mapping[str, Site]]
) -> dict[str, Site]:
    if sites is None:
        return {}
    if isinstance(sites, Mapping):
        return {
            str(k): (v if isinstance(v, Site) else Site.from_dict(v))
            for k, v in sites.items()
        }
    indexed: dict[str, Site] = {}
    for item in sites:
        site = item if isinstance(item, Site) else Site.from_dict(item)
        indexed[site.site_id] = site
    return indexed


def _normalize_results_and_metadata(
    results: Sequence[ValidationResult | Mapping[str, Any]],
    sites_by_id: Mapping[str, Site],
) -> list[dict[str, Any]]:
    device_by_key: dict[tuple[str, str], NetworkDevice] = {}
    equipment_by_key: dict[tuple[str, str], Equipment] = {}
    assigned_ips_by_obj: dict[tuple[str, str], list[str]] = {}

    for site_id, site in sites_by_id.items():
        for dev in site.devices:
            device_by_key[(site_id, dev.device_id)] = dev
        for eq in site.equipment:
            equipment_by_key[(site_id, eq.equipment_id)] = eq
        for ip_rec in site.ip_addresses:
            if ip_rec.assigned_object_id and ip_rec.ip:
                obj_ips = assigned_ips_by_obj.setdefault(
                    (site_id, ip_rec.assigned_object_id), []
                )
                if ip_rec.ip not in obj_ips:
                    obj_ips.append(ip_rec.ip)

    enriched_rows: list[dict[str, Any]] = []
    for raw in results:
        extra_site_name: Optional[str] = None
        extra_category: Optional[str] = None
        extra_ips: Optional[list[str]] = None

        if isinstance(raw, ValidationResult):
            res = raw
        elif isinstance(raw, Mapping):
            res = ValidationResult.from_dict(raw)
            if isinstance(raw.get("site_name"), str) and raw["site_name"].strip():
                extra_site_name = raw["site_name"].strip()
            if isinstance(raw.get("category"), str) and raw["category"].strip():
                extra_category = raw["category"].strip().lower()
            raw_ips = raw.get("ip_addresses")
            if isinstance(raw_ips, list):
                extra_ips = [str(ip).strip() for ip in raw_ips if str(ip).strip()]
            elif isinstance(raw_ips, str) and raw_ips.strip():
                extra_ips = [
                    part.strip() for part in raw_ips.split(";") if part.strip()
                ]
        else:
            raise ValueError(f"Unsupported result item: {raw!r}")

        site = sites_by_id.get(res.site_id)
        site_name = (
            site.name
            if site is not None
            else (extra_site_name if extra_site_name else res.site_id)
        )

        ips: list[str] = []
        category: Optional[str] = extra_category

        if res.item_type == "Equipment":
            eq = equipment_by_key.get((res.site_id, res.item_id))
            if eq is not None:
                category = eq.category.value
                for ip_str in eq.assigned_ips:
                    if ip_str and ip_str not in ips:
                        ips.append(ip_str)
            for ip_str in assigned_ips_by_obj.get((res.site_id, res.item_id), ()):
                if ip_str not in ips:
                    ips.append(ip_str)
            if not ips and extra_ips:
                ips = list(extra_ips)
            if category is None:
                category = EquipmentCategory.OTHER.value
        elif res.item_type == "NetworkDevice":
            dev = device_by_key.get((res.site_id, res.item_id))
            if dev is not None and dev.management_ip:
                ips.append(dev.management_ip)
            for ip_str in assigned_ips_by_obj.get((res.site_id, res.item_id), ()):
                if ip_str not in ips:
                    ips.append(ip_str)
            if not ips and extra_ips:
                ips = list(extra_ips)
        elif res.item_type == "IPAddress":
            if extra_ips:
                ips = list(extra_ips)
            elif res.item_id:
                ips = [res.item_id]
        else:
            if extra_ips:
                ips = list(extra_ips)

        base_dict = res.to_dict()
        enriched: dict[str, Any] = {
            "item_type": base_dict["item_type"],
            "item_id": base_dict["item_id"],
            "site_id": base_dict["site_id"],
            "site_name": site_name,
            "name": base_dict["name"],
            "category": category,
            "ip_addresses": ips,
            "classification": base_dict["classification"],
            "confidence": base_dict["confidence"],
            "signals": base_dict["signals"],
            "rationale": base_dict["rationale"],
            "evaluated_at": base_dict["evaluated_at"],
        }
        enriched_rows.append(enriched)

    return enriched_rows


def _escape_md_cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r\n", " ").replace("\n", " ").strip()
    return text.replace("|", "\\|")


def generate_json_report(
    results: Sequence[ValidationResult | Mapping[str, Any]],
    *,
    sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
    action_plan: Optional[DryRunActionPlan] = None,
    output_path: Optional[Path | str] = None,
    generated_at: Optional[datetime | str] = None,
) -> dict[str, Any]:
    """Generate a structured JSON validation report dictionary and optionally write it to disk."""
    report_dt = _resolve_report_timestamp(generated_at)
    sites_by_id = _index_sites(sites)
    enriched_results = _normalize_results_and_metadata(results, sites_by_id)
    total_items = len(enriched_results)

    validation_objs = [
        r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
        for r in results
    ]
    resolved_plan = (
        action_plan
        if action_plan is not None
        else DryRunActionPlanGenerator(generated_at=report_dt).generate_plan(
            validation_objs
        )
    )

    by_classification_items: dict[str, list[dict[str, Any]]] = {
        cls_enum.value: [] for cls_enum in ALL_CLASSIFICATIONS
    }
    for item in enriched_results:
        cls_key = item["classification"]
        by_classification_items.setdefault(cls_key, []).append(item)

    summary_by_classification: dict[str, dict[str, int | float]] = {}
    for cls_enum in ALL_CLASSIFICATIONS:
        cls_val = cls_enum.value
        count = len(by_classification_items.get(cls_val, []))
        pct = round((count / total_items) * 100.0, 2) if total_items > 0 else 0.0
        summary_by_classification[cls_val] = {
            "count": count,
            "percentage": pct,
        }

    # Build per-site breakdown preserving all known sites as well as sites seen in results
    all_site_ids = sorted(
        set(sites_by_id.keys()) | {item["site_id"] for item in enriched_results}
    )
    summary_by_site: dict[str, dict[str, Any]] = {}
    for sid in all_site_ids:
        site_obj = sites_by_id.get(sid)
        sname = site_obj.name if site_obj is not None else sid
        site_items = [item for item in enriched_results if item["site_id"] == sid]
        if site_items and site_obj is None:
            sname = site_items[0].get("site_name") or sid
        cls_counts = {
            cls_enum.value: sum(
                1
                for item in site_items
                if item["classification"] == cls_enum.value
            )
            for cls_enum in ALL_CLASSIFICATIONS
        }
        summary_by_site[sid] = {
            "site_id": sid,
            "site_name": sname,
            "total": len(site_items),
            **cls_counts,
            "by_classification": dict(cls_counts),
        }

    # Build per-equipment-category breakdown
    summary_by_category: dict[str, dict[str, Any]] = {}
    for cat_enum in ALL_EQUIPMENT_CATEGORIES:
        cat_val = cat_enum.value
        cat_items = [
            item
            for item in enriched_results
            if item["item_type"] == "Equipment" and item.get("category") == cat_val
        ]
        cls_counts = {
            cls_enum.value: sum(
                1
                for item in cat_items
                if item["classification"] == cls_enum.value
            )
            for cls_enum in ALL_CLASSIFICATIONS
        }
        summary_by_category[cat_val] = {
            "category": cat_val,
            "total": len(cat_items),
            **cls_counts,
            "by_classification": dict(cls_counts),
        }

    payload: dict[str, Any] = {
        "generated_at": _format_optional_datetime(report_dt),
        "total_items": total_items,
        "summary": {
            "by_classification": summary_by_classification,
            "by_site": summary_by_site,
            "by_equipment_category": summary_by_category,
        },
        "by_classification": by_classification_items,
        "results": enriched_results,
        "remediation_plan": resolved_plan.to_dict(),
    }

    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return payload


def generate_csv_report(
    results: Sequence[ValidationResult | Mapping[str, Any]],
    *,
    sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
    output_path: Optional[Path | str] = None,
) -> str:
    """Generate a flattened CSV validation report and optionally write it to disk."""
    sites_by_id = _index_sites(sites)
    enriched_results = _normalize_results_and_metadata(results, sites_by_id)

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_REPORT_COLUMNS)

    for item in enriched_results:
        ip_str = ";".join(item.get("ip_addresses") or [])
        writer.writerow(
            [
                item["site_id"],
                item["site_name"],
                item["item_type"],
                item["item_id"],
                item["name"],
                ip_str,
                item["classification"],
                item["confidence"],
                item["rationale"] or "",
                item["evaluated_at"] or "",
            ]
        )

    csv_content = buf.getvalue()
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(csv_content, encoding="utf-8")

    return csv_content


def generate_markdown_summary(
    results: Sequence[ValidationResult | Mapping[str, Any]],
    *,
    sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
    action_plan: Optional[DryRunActionPlan] = None,
    output_path: Optional[Path | str] = None,
    generated_at: Optional[datetime | str] = None,
) -> str:
    """Generate a human-readable Markdown validation summary report and optionally write it to disk."""
    report_data = generate_json_report(
        results,
        sites=sites,
        action_plan=action_plan,
        output_path=None,
        generated_at=generated_at,
    )

    gen_at_str = report_data["generated_at"]
    total_items = report_data["total_items"]
    by_cls_summary = report_data["summary"]["by_classification"]
    by_site_summary = report_data["summary"]["by_site"]
    by_cat_summary = report_data["summary"]["by_equipment_category"]
    enriched_results = report_data["results"]
    rem_plan = report_data["remediation_plan"]

    lines: list[str] = [
        "# Inventory Validation Summary Report",
        "",
        f"- **Generated At**: `{gen_at_str}`",
        f"- **Total Evaluated Items**: `{total_items}`",
        "- **Mode**: `Read-Only / Dry-Run`",
        "",
        "## 1. Overall Classification Summary",
        "",
        "| Classification | Count | Percentage |",
        "| :--- | ---: | ---: |",
    ]

    for cls_enum in ALL_CLASSIFICATIONS:
        cls_val = cls_enum.value
        entry = by_cls_summary[cls_val]
        lines.append(
            f"| {cls_val} | {entry['count']} | {entry['percentage']:.2f}% |"
        )

    lines.extend(
        [
            "",
            "## 2. Breakdown by Site",
            "",
            "| Site ID | Site Name | Total | Confirmed Active | Stale / Likely Unused | Unreachable / Needs Manual Review | Insufficient Data |",
            "| :--- | :--- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )

    if by_site_summary:
        for sid, sdata in by_site_summary.items():
            lines.append(
                f"| {_escape_md_cell(sid)} "
                f"| {_escape_md_cell(sdata['site_name'])} "
                f"| {sdata['total']} "
                f"| {sdata[ValidationClassification.CONFIRMED_ACTIVE.value]} "
                f"| {sdata[ValidationClassification.STALE_LIKELY_UNUSED.value]} "
                f"| {sdata[ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value]} "
                f"| {sdata[ValidationClassification.INSUFFICIENT_DATA.value]} |"
            )
    else:
        lines.append("| *(none)* | *(none)* | 0 | 0 | 0 | 0 | 0 |")

    lines.extend(
        [
            "",
            "## 3. Breakdown by Equipment Category",
            "",
            "| Category | Total | Confirmed Active | Stale / Likely Unused | Unreachable / Needs Manual Review | Insufficient Data |",
            "| :--- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )

    for cat_enum in ALL_EQUIPMENT_CATEGORIES:
        cat_val = cat_enum.value
        cdata = by_cat_summary[cat_val]
        lines.append(
            f"| {cat_val} "
            f"| {cdata['total']} "
            f"| {cdata[ValidationClassification.CONFIRMED_ACTIVE.value]} "
            f"| {cdata[ValidationClassification.STALE_LIKELY_UNUSED.value]} "
            f"| {cdata[ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value]} "
            f"| {cdata[ValidationClassification.INSUFFICIENT_DATA.value]} |"
        )

    lines.extend(
        [
            "",
            "## 4. Highlighted Items: Stale / Likely Unused & Unreachable / Needs Manual Review",
            "",
            "| Site ID | Item Type | Item ID | Name | IP Addresses | Classification | Confidence | Rationale |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | ---: | :--- |",
        ]
    )

    highlighted = [
        item
        for item in enriched_results
        if item["classification"]
        in (
            ValidationClassification.STALE_LIKELY_UNUSED.value,
            ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value,
        )
    ]

    if highlighted:
        for item in highlighted:
            ip_str = ";".join(item.get("ip_addresses") or [])
            lines.append(
                f"| {_escape_md_cell(item['site_id'])} "
                f"| {_escape_md_cell(item['item_type'])} "
                f"| {_escape_md_cell(item['item_id'])} "
                f"| {_escape_md_cell(item['name'])} "
                f"| {_escape_md_cell(ip_str)} "
                f"| {_escape_md_cell(item['classification'])} "
                f"| {item['confidence']:.2f} "
                f"| {_escape_md_cell(item.get('rationale') or '')} |"
            )
    else:
        lines.append(
            "| *(none)* | - | - | - | - | - | - | No stale or manual-review items found. |"
        )

    action_counts = rem_plan.get("summary_by_action", {})
    stale_actions = action_counts.get(
        RemediationActionType.MARK_STALE_CANDIDATE.value, 0
    )
    review_actions = action_counts.get(
        RemediationActionType.FLAG_FOR_REVIEW.value, 0
    )

    lines.extend(
        [
            "",
            "## 5. Phase 2 Dry-Run Remediation Action Plan Summary",
            "",
            f"- **Dry-Run Enforced**: `{rem_plan.get('dry_run', True)}`",
            f"- **Total Proposed Actions**: `{rem_plan.get('total_actions', 0)}`",
            f"- **`{RemediationActionType.MARK_STALE_CANDIDATE.value}`**: `{stale_actions}`",
            f"- **`{RemediationActionType.FLAG_FOR_REVIEW.value}`**: `{review_actions}`",
            "",
        ]
    )

    md_content = "\n".join(lines)
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(md_content, encoding="utf-8")

    return md_content


class JsonReportGenerator:
    """Object-oriented wrapper for generating JSON validation reports."""

    def generate(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        action_plan: Optional[DryRunActionPlan] = None,
        output_path: Optional[Path | str] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> dict[str, Any]:
        return generate_json_report(
            results,
            sites=sites,
            action_plan=action_plan,
            output_path=output_path,
            generated_at=generated_at,
        )

    def write(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        output_path: Path | str,
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        action_plan: Optional[DryRunActionPlan] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> Path:
        target = Path(output_path)
        generate_json_report(
            results,
            sites=sites,
            action_plan=action_plan,
            output_path=target,
            generated_at=generated_at,
        )
        return target


class CsvReportGenerator:
    """Object-oriented wrapper for generating CSV validation reports."""

    def generate(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        output_path: Optional[Path | str] = None,
    ) -> str:
        return generate_csv_report(
            results,
            sites=sites,
            output_path=output_path,
        )

    def write(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        output_path: Path | str,
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
    ) -> Path:
        target = Path(output_path)
        generate_csv_report(results, sites=sites, output_path=target)
        return target


class MarkdownReportGenerator:
    """Object-oriented wrapper for generating Markdown summary reports."""

    def generate(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        action_plan: Optional[DryRunActionPlan] = None,
        output_path: Optional[Path | str] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> str:
        return generate_markdown_summary(
            results,
            sites=sites,
            action_plan=action_plan,
            output_path=output_path,
            generated_at=generated_at,
        )

    def write(
        self,
        results: Sequence[ValidationResult | Mapping[str, Any]],
        output_path: Path | str,
        *,
        sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
        action_plan: Optional[DryRunActionPlan] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> Path:
        target = Path(output_path)
        generate_markdown_summary(
            results,
            sites=sites,
            action_plan=action_plan,
            output_path=target,
            generated_at=generated_at,
        )
        return target


def generate_all_reports(
    results: Sequence[ValidationResult | Mapping[str, Any]],
    output_dir: Path | str,
    *,
    sites: Optional[Sequence[Site] | Mapping[str, Site]] = None,
    action_plan: Optional[DryRunActionPlan] = None,
    generated_at: Optional[datetime | str] = None,
) -> dict[str, Path]:
    """Write JSON, CSV, Markdown, and Phase 2 dry-run remediation plan files to `output_dir`."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_dt = _resolve_report_timestamp(generated_at)

    validation_objs = [
        r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
        for r in results
    ]
    plan_generator = DryRunActionPlanGenerator(generated_at=report_dt)
    resolved_plan = (
        action_plan
        if action_plan is not None
        else plan_generator.generate_plan(validation_objs, generated_at=report_dt)
    )

    json_path = out_dir / "validation_report.json"
    csv_path = out_dir / "validation_report.csv"
    md_path = out_dir / "validation_summary.md"
    plan_path = out_dir / "remediation_action_plan.json"

    generate_json_report(
        results,
        sites=sites,
        action_plan=resolved_plan,
        output_path=json_path,
        generated_at=report_dt,
    )
    generate_csv_report(
        results,
        sites=sites,
        output_path=csv_path,
    )
    generate_markdown_summary(
        results,
        sites=sites,
        action_plan=resolved_plan,
        output_path=md_path,
        generated_at=report_dt,
    )
    plan_generator.write_plan(resolved_plan, plan_path)

    return {
        "json": json_path,
        "csv": csv_path,
        "markdown": md_path,
        "remediation_plan": plan_path,
    }


__all__ = [
    "ALL_CLASSIFICATIONS",
    "ALL_EQUIPMENT_CATEGORIES",
    "CSV_REPORT_COLUMNS",
    "CsvReportGenerator",
    "JsonReportGenerator",
    "MarkdownReportGenerator",
    "generate_all_reports",
    "generate_csv_report",
    "generate_json_report",
    "generate_markdown_summary",
]
