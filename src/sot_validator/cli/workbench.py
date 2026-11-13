"""Web Workbench server and operator curation subcommands (`serve`, `curate`)."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys
import threading
from typing import Any, Optional
from urllib.request import urlopen

from sot_validator.cli._common import (
    _add_source_arguments,
    _load_single_site_snapshot,
    _load_validation_results_file,
    _open_curation_store,
)
from sot_validator.curation import ItemEditPatch, apply_curation_overlay
from sot_validator.models import (
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationResult,
)
from sot_validator.topology import DevicePortManager, DeviceTypeCatalog
from sot_validator.workbench import (
    WorkbenchSecurityConfig,
    WorkbenchState,
    create_workbench_server,
    render_workbench_html,
)


def _workbench_url(server_address: Sequence[Any]) -> str:
    bound_host, bound_port = server_address[:2]
    host = "127.0.0.1" if bound_host in ("0.0.0.0", "::", "") else str(bound_host)
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{bound_port}/"


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        security = WorkbenchSecurityConfig(
            token=getattr(args, "token", None),
            allow_remote=bool(getattr(args, "allow_remote", False)),
        )
    except ValueError as exc:
        print(f"error: --token rejected: {exc}", file=sys.stderr)
        return 2

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
        try:
            server = create_workbench_server(
                state, host=args.host, port=int(args.port), security=security
            )
        except ValueError:
            # The only ValueError here is the non-loopback bind refusal.
            print(
                f"error: refusing to bind the workbench to non-loopback host "
                f"{args.host!r}; pass --allow-remote to expose it on the network",
                file=sys.stderr,
            )
            return 2
        except (OSError, OverflowError) as exc:
            print(
                f"error: cannot bind the workbench to {args.host}:{args.port}: "
                f"{getattr(exc, 'strerror', None) or exc}",
                file=sys.stderr,
            )
            return 2
        try:
            if getattr(args, "check", False):
                _ = render_workbench_html(state)
                _ = state.get_state_payload()
                return 0

            print(
                f"Workbench listening; open {_workbench_url(server.server_address)}"
                f"#token={security.token}",
                flush=True,
            )

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


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `serve`, `curate` subcommands."""
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
        "--token",
        type=str,
        default=None,
        help="Bearer token for workbench writes (default: a fresh random token per start).",
    )
    serve_parser.add_argument(
        "--allow-remote",
        action="store_true",
        default=False,
        help="Allow binding --host to a non-loopback address (writes still need the token).",
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
