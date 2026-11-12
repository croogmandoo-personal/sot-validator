"""End-to-end CLI and integration tests for Phases 7-9 (`discover`, `serve`, `curate`, `topology`, and package exports)."""

from __future__ import annotations

import json
from pathlib import Path

import sot_validator
from sot_validator.cli import main
from sot_validator.curation import CurationStore
from sot_validator.models import (
    EquipmentCategory,
    Site,
    ValidationClassification,
)
from sot_validator.topology import TopologyGraph


def test_top_level_package_reexports_phases_7_to_9() -> None:
    expected_symbols = (
        "AuditLogEntry",
        "CurationStore",
        "ItemEditPatch",
        "VALID_TARGET_TYPES",
        "apply_curation_overlay",
        "DEFAULT_GATEWAY_OCTETS",
        "DEFAULT_TCP_PORTS",
        "DiscoveredHost",
        "DiscoveryConfig",
        "SubnetDiscoveryScanner",
        "parse_ip_neigh_output",
        "BUILTIN_DEVICE_TEMPLATES",
        "ConsolidatedRouter",
        "DevicePortManager",
        "DeviceTypeCatalog",
        "DeviceTypeTemplate",
        "HostIdentification",
        "KNOWN_OUI_VENDORS",
        "KNOWN_SCAN_TCP_PORTS",
        "NetworkRoleIdentifier",
        "PortSpec",
        "TopologyEdge",
        "TopologyGraph",
        "TopologyGraphBuilder",
        "TopologyNode",
        "VALID_DEVICE_ROLES",
        "VALID_EDGE_RELATIONS",
        "VALID_HOST_ROLES",
        "VALID_NODE_TYPES",
        "normalize_mac_address",
        "DEFAULT_WORKBENCH_TITLE",
        "WorkbenchNotFoundError",
        "WorkbenchRequestHandler",
        "WorkbenchServer",
        "WorkbenchState",
        "create_workbench_server",
        "render_workbench_html",
    )
    for sym in expected_symbols:
        assert hasattr(sot_validator, sym), f"Missing export {sym} in sot_validator"
        assert sym in sot_validator.__all__, f"{sym} not in sot_validator.__all__"


def test_cli_discover_curate_topology_serve_and_report_pipeline(
    tmp_path: Path,
) -> None:
    mock_config_path = tmp_path / "mock_discovery.json"
    mock_config_payload = {
        "ping": {
            "10.42.1.1": 0.45,
            "10.42.1.2": 0.65,
            "10.42.1.10": 0.90,
            "10.42.1.20": 1.15,
            "10.42.1.30": 1.05,
            "10.42.10.1": 0.50,
            "10.42.10.50": 1.40,
        },
        "tcp_ports": {
            "10.42.1.1": [53, 80, 443],
            "10.42.1.2": [22, 443],
            "10.42.1.10": [22, 8006],
            "10.42.1.20": [80, 443],
            "10.42.1.30": [445, 5000],
            "10.42.10.1": [53, 80, 443],
            "10.42.10.50": [8123],
        },
        "arp_table": {
            "10.42.1.1": ["aa:9c:6c:00:01:01", "REACHABLE"],
            "10.42.1.2": ["00:04:96:aa:bb:cc", "REACHABLE"],
            "10.42.1.10": ["bc:24:11:00:11:22", "REACHABLE"],
            "10.42.1.20": ["00:c0:b7:11:22:33", "REACHABLE"],
            "10.42.1.30": ["00:11:32:aa:bb:30", "REACHABLE"],
            "10.42.10.1": ["aa:9c:6c:00:10:01", "REACHABLE"],
            "10.42.10.50": ["44:61:32:10:20:50", "REACHABLE"],
        },
        "rdns": {
            "10.42.1.1": "unifi-gw-01.site42.local",
            "10.42.1.2": "sw-exos-01.site42.local",
            "10.42.1.10": "pve-hv-01.site42.local",
            "10.42.1.20": "apc-ups-01.site42.local",
            "10.42.1.30": "synology-nas-01.site42.local",
            "10.42.10.1": "unifi-gw-10.site42.local",
            "10.42.10.50": "homeassistant.site42.local",
        },
    }
    mock_config_path.write_text(
        json.dumps(mock_config_payload, indent=2), encoding="utf-8"
    )

    discovered_site_path = tmp_path / "discovered_site.json"
    discover_out_dir = tmp_path / "discover_out"

    # 1. Run `discover` CLI with --mock-config, --validate, --report, --html-dashboard
    rc = main(
        [
            "discover",
            "--cidr",
            "10.42.0.0/16",
            "--site-id",
            "site-042",
            "--site-name",
            "Site 42 Live Lab",
            "--mock-config",
            str(mock_config_path),
            "--evaluation-time",
            "2026-11-12T00:00:00Z",
            "--output",
            str(discovered_site_path),
            "--output-dir",
            str(discover_out_dir),
            "--validate",
            "--report",
            "--html-dashboard",
        ]
    )
    assert rc == 0
    assert discovered_site_path.exists()
    assert (discover_out_dir / "validation_results.json").exists()
    assert (discover_out_dir / "validation_report.json").exists()
    assert (discover_out_dir / "validation_dashboard.html").exists()

    discovered_site = Site.from_json(
        discovered_site_path.read_text(encoding="utf-8")
    )
    assert discovered_site.site_id == "site-042"
    assert len(discovered_site.vlans) == 2
    assert {v.vlan_id for v in discovered_site.vlans} == {"1", "10"}

    # 2. Run `curate` CLI: patch an equipment item, add a template switch device, add ports, and export curated site
    curation_db_path = tmp_path / "curation.db"
    curated_site_path = tmp_path / "curated_site.json"
    curation_export_json = tmp_path / "curation_export.json"

    target_eq_id = "site-042-eq-10-42-1-20"
    rc = main(
        [
            "curate",
            "--curation-db",
            str(curation_db_path),
            "--snapshot",
            str(discovered_site_path),
            "--target-type",
            "Equipment",
            "--target-id",
            target_eq_id,
            "--name",
            "APC Smart-UPS MDF-A",
            "--category",
            "ups",
            "--room",
            "MDF-A",
            "--notes",
            "Verified battery bank",
            "--pin-classification",
            "Confirmed Active",
            "--actor",
            "netops-admin",
            "--reason",
            "Physical rack audit",
        ]
    )
    assert rc == 0

    # Add an Extreme 24-port switch via template
    rc = main(
        [
            "curate",
            "--curation-db",
            str(curation_db_path),
            "--site-id",
            "site-042",
            "--add-device",
            "--template-id",
            "extreme-exos-24p",
            "--device-id",
            "dev-sw-idf2",
            "--hostname",
            "sw-idf2-01.site42.local",
            "--management-ip",
            "10.42.1.3",
            "--vlan-id",
            "1",
            "--actor",
            "netops-admin",
            "--reason",
            "Added IDF-2 access switch",
        ]
    )
    assert rc == 0

    # Update port 1:1 on dev-sw-idf2 to connect to the APC UPS and export curated site
    rc = main(
        [
            "curate",
            "--curation-db",
            str(curation_db_path),
            "--snapshot",
            str(discovered_site_path),
            "--device-id",
            "dev-sw-idf2",
            "--add-port",
            "1:1",
            "--vlan-id",
            "1",
            "--poe-status",
            "delivering",
            "--connected-device-id",
            target_eq_id,
            "--connected-mac",
            "00:c0:b7:11:22:33",
            "--output",
            str(curated_site_path),
            "--export-json",
            str(curation_export_json),
            "--list-audit",
        ]
    )
    assert rc == 0
    assert curated_site_path.exists()
    assert curation_export_json.exists()

    curated_site = Site.from_json(curated_site_path.read_text(encoding="utf-8"))
    curated_eq = next(
        e for e in curated_site.equipment if e.equipment_id == target_eq_id
    )
    assert curated_eq.name == "APC Smart-UPS MDF-A"
    assert curated_eq.category is EquipmentCategory.UPS
    assert "MDF-A" in curated_site.rooms

    idf_switch = next(
        d for d in curated_site.devices if d.device_id == "dev-sw-idf2"
    )
    assert idf_switch.vendor == "Extreme Networks"
    assert len(idf_switch.ports) == 24
    port_1_1 = next(p for p in idf_switch.ports if p.name == "1:1")
    assert port_1_1.connected_device_id == target_eq_id
    assert port_1_1.poe_status == "delivering"

    with CurationStore(curation_db_path) as store_check:
        audit_entries = store_check.list_audit_log(site_id="site-042")
        assert len(audit_entries) == 3

    # 3. Run `topology` CLI with --snapshot, --curation-db, --results-file, --output-json, --output-mermaid
    topology_json_path = tmp_path / "topology_graph.json"
    topology_mmd_path = tmp_path / "topology_graph.mmd"
    rc = main(
        [
            "topology",
            "--snapshot",
            str(discovered_site_path),
            "--curation-db",
            str(curation_db_path),
            "--results-file",
            str(discover_out_dir / "validation_results.json"),
            "--output-json",
            str(topology_json_path),
            "--output-mermaid",
            str(topology_mmd_path),
        ]
    )
    assert rc == 0
    assert topology_json_path.exists()
    assert topology_mmd_path.exists()

    graph = TopologyGraph.from_json(
        topology_json_path.read_text(encoding="utf-8")
    )
    assert graph.site_id == "site-042"
    assert graph.summary_counts["router"] >= 1
    assert graph.summary_counts["switch"] >= 2
    assert graph.summary_counts["vlan"] == 2
    assert graph.get_node("dev-sw-idf2") is not None
    ups_node = graph.get_node(target_eq_id)
    assert ups_node is not None
    assert ups_node.label == "APC Smart-UPS MDF-A"
    assert ups_node.status == ValidationClassification.CONFIRMED_ACTIVE.value

    mmd_text = topology_mmd_path.read_text(encoding="utf-8")
    assert mmd_text.startswith("flowchart LR")
    assert "APC Smart-UPS MDF-A" in mmd_text

    # 4. Run `serve` CLI with --once and --check on an ephemeral port
    rc_check = main(
        [
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--snapshot",
            str(curated_site_path),
            "--curation-db",
            str(curation_db_path),
            "--check",
        ]
    )
    assert rc_check == 0

    rc_once = main(
        [
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--snapshot",
            str(curated_site_path),
            "--curation-db",
            str(curation_db_path),
            "--once",
        ]
    )
    assert rc_once == 0


def test_cli_discover_with_fixtures_flag_offline(tmp_path: Path) -> None:
    out_file = tmp_path / "fixture_discovered.json"
    rc = main(
        [
            "discover",
            "--cidr",
            "10.99.1.0/24",
            "--site-id",
            "site-099",
            "--fixtures",
            "--output",
            str(out_file),
        ]
    )
    assert rc == 0
    assert out_file.exists()
    site = Site.from_json(out_file.read_text(encoding="utf-8"))
    assert site.site_id == "site-099"
    assert len(site.devices) >= 1
    assert len(site.equipment) >= 1
