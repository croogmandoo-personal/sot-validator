"""Topology, fingerprint, FDB port-mapping and scan-drift subcommands (`topology`, `fingerprint`, `map-ports`, `diff-scans`)."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.cli._common import (
    _add_source_arguments,
    _load_json_object_list,
    _load_single_site_snapshot,
    _load_validation_results_file,
    _open_curation_store,
)
from sot_validator.curation import CurationStore, apply_curation_overlay
from sot_validator.discovery import (
    DriftAlertDispatcher,
    DriftAlertTarget,
    RawServiceBanner,
    ServiceBannerFingerprinter,
    SnapshotDiffEngine,
)
from sot_validator.models import ValidationResult
from sot_validator.topology import (
    DevicePortManager,
    FdbEntry,
    FdbTableParser,
    SwitchFdbPortMapper,
    TopologyGraphBuilder,
)


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


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `topology`, `fingerprint`, `map-ports`, `diff-scans` subcommands."""
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
