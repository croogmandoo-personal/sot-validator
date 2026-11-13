"""Live subnet discovery subcommand (`discover`)."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.classifier.engine import ClassificationEngine
from sot_validator.cli._common import (
    _json_object_list,
    _parse_int_list,
    _write_validation_results_file,
)
from sot_validator.discovery import (
    DEFAULT_GATEWAY_OCTETS,
    DEFAULT_TCP_PORTS,
    DiscoveredHost,
    DiscoveryConfig,
    RouterArpDhcpCollector,
    RouterArpRecord,
    RouterTableParsers,
    SubnetDiscoveryScanner,
)
from sot_validator.extraction import SnapshotStore
from sot_validator.models import Site
from sot_validator.remediation import DryRunActionPlanGenerator
from sot_validator.reporting import generate_all_reports
from sot_validator.signals.proxmox_containers import ProxmoxClusterSnapshot
from sot_validator.topology import DeviceTypeCatalog, NetworkRoleIdentifier


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
            arp_raw = json.loads(arp_text)
        except json.JSONDecodeError:
            arp_records = RouterTableParsers.parse_cli_arp(arp_text)
        else:
            arp_records = [
                RouterArpRecord.from_dict(item)
                for item in _json_object_list(
                    arp_raw, key="arp_records", path=arp_path
                )
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


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `discover` subcommand."""
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
