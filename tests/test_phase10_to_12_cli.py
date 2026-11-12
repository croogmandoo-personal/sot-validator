"""End-to-end CLI tests for Phases 10-12 (`fingerprint`, `map-ports`, `diff-scans`, `discover` enrichment, and package exports)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import sot_validator
from sot_validator.cli import main
from sot_validator.curation import CurationStore
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
)
from sot_validator.signals import ProxmoxClusterSnapshot, ProxmoxGuestRecord

SWITCH_MAC = "00:04:96:aa:bb:cc"
SERVER_MAC = "bc:24:11:aa:bb:01"
PHONE_MAC = "00:c0:b7:99:88:77"


def _build_site(*, with_server: bool = True) -> Site:
    switch = NetworkDevice(
        device_id="sw-01",
        site_id="site-042",
        hostname="switch-10-42-1-2",
        management_ip="10.42.1.2",
        vendor="",
        model="",
        ports=[
            Port(port_id="sw-01:1:1", device_id="sw-01", name="1:1"),
            Port(port_id="sw-01:1:2", device_id="sw-01", name="1:2"),
        ],
    )
    ip_addresses = [
        IPAddress(
            ip="10.42.1.2",
            subnet_id="sub-1",
            assigned_object_type="device",
            assigned_object_id="sw-01",
            arp_mac=SWITCH_MAC,
        )
    ]
    equipment: list[Equipment] = []
    if with_server:
        ip_addresses.append(
            IPAddress(
                ip="10.42.1.10",
                subnet_id="sub-1",
                assigned_object_type="equipment",
                assigned_object_id="eq-srv-01",
                arp_mac=SERVER_MAC,
            )
        )
        equipment.append(
            Equipment(
                equipment_id="eq-srv-01",
                site_id="site-042",
                name="pve-node-01",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.1.10"],
            )
        )
    return Site(
        site_id="site-042",
        name="Site 42",
        devices=[switch],
        subnets=[
            Subnet(
                subnet_id="sub-1",
                site_id="site-042",
                cidr="10.42.1.0/24",
                vlan_id="1",
                gateway="10.42.1.1",
            )
        ],
        ip_addresses=ip_addresses,
        equipment=equipment,
    )


def _write_site(path: Path, site: Site) -> Path:
    path.write_text(site.to_json(indent=2), encoding="utf-8")
    return path


def test_package_exports_phases_10_to_12() -> None:
    expected_symbols = (
        "DeviceFingerprint",
        "DriftAlertDispatcher",
        "DriftAlertTarget",
        "DriftDispatchResult",
        "HTTP_BANNER_PORTS",
        "RawServiceBanner",
        "RouterArpDhcpCollector",
        "RouterArpRecord",
        "RouterTableParsers",
        "SSH_BANNER_PORTS",
        "ScanDriftEvent",
        "ScanDriftEventType",
        "ServiceBannerFingerprinter",
        "SnapshotDiffEngine",
        "SnapshotDiffReport",
        "TLS_BANNER_PORTS",
        "FdbEntry",
        "FdbTableParser",
        "PortClassificationResult",
        "SwitchFdbPortMapper",
        "VALID_PORT_MODES",
        "PROXMOX_MAC_OUI",
        "ContainerEndpointRecord",
        "ProxmoxClusterSnapshot",
        "ProxmoxContainerCollector",
        "ProxmoxContainerCorrelator",
        "ProxmoxGuestRecord",
        "is_proxmox_mac",
    )
    for sym in expected_symbols:
        assert hasattr(sot_validator, sym), f"Missing export {sym} in sot_validator"
        assert sym in sot_validator.__all__, f"{sym} not in sot_validator.__all__"

    assert sot_validator.__all__ == sorted(sot_validator.__all__)
    assert len(sot_validator.__all__) == len(set(sot_validator.__all__))

    from sot_validator.signals import DhcpLeaseRecord as SignalsDhcpLeaseRecord

    assert sot_validator.DhcpLeaseRecord is SignalsDhcpLeaseRecord


def test_fingerprint_cli_writes_json_and_markdown_reports(tmp_path: Path) -> None:
    snapshot = _write_site(tmp_path / "site.json", _build_site(with_server=False))
    banners_path = tmp_path / "banners.json"
    banners_path.write_text(
        json.dumps(
            [
                {
                    "ip": "10.42.1.2",
                    "ssh_banner": "ExtremeXOS version 31.2",
                    "snmp_sys_descr": "ExtremeXOS (X460-48t) version 31.2",
                }
            ]
        ),
        encoding="utf-8",
    )

    json_out = tmp_path / "out" / "fingerprint.json"
    rc = main(
        [
            "fingerprint",
            "--snapshot",
            str(snapshot),
            "--banners",
            str(banners_path),
            "--output",
            str(json_out),
        ]
    )
    assert rc == 0
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert report["site_id"] == "site-042"
    assert report["banner_count"] == 1
    assert len(report["fingerprints"]) == 1
    assert report["fingerprints"][0]["vendor"] == "Extreme Networks"
    assert report["fingerprints"][0]["model"] == "X460-48t"
    enriched = {d["device_id"]: d for d in report["enriched_devices"]}
    assert enriched["sw-01"]["vendor"] == "Extreme Networks"
    assert enriched["sw-01"]["model"] == "X460-48t"
    assert report["enriched_equipment"] == []

    # The `{"banners": [...]}` envelope and a Markdown output both work
    banners_path.write_text(
        json.dumps({"banners": json.loads(banners_path.read_text("utf-8"))}),
        encoding="utf-8",
    )
    md_out = tmp_path / "report.md"
    rc = main(
        [
            "fingerprint",
            "--snapshot",
            str(snapshot),
            "--banners",
            str(banners_path),
            "--output",
            str(md_out),
        ]
    )
    assert rc == 0
    markdown = md_out.read_text(encoding="utf-8")
    assert markdown.startswith("# Service Fingerprint Report:")
    assert "Extreme Networks" in markdown
    assert "| IP | Vendor | Model | OS Family | Hostname | Role | Template | Confidence | Signatures |" in markdown
    assert "## Enriched Devices" in markdown
    assert "## Enriched Equipment\n\nNone." in markdown


def test_fingerprint_cli_prints_json_without_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snapshot = _write_site(tmp_path / "site.json", _build_site(with_server=False))
    banners_path = tmp_path / "banners.json"
    banners_path.write_text(json.dumps({"banners": []}), encoding="utf-8")

    rc = main(
        ["fingerprint", "--snapshot", str(snapshot), "--banners", str(banners_path)]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["banner_count"] == 0
    assert report["fingerprints"] == []
    assert report["enriched_devices"] == []


EXOS_FDB_TEXT = f"""
Mac                     Vlan       Age  Flags          Port / Virtual Port List
--------------------------------------------------------------------------------
{SERVER_MAC}       Data(0001)      0045 d m           1:1
{PHONE_MAC}       Default(0001)   0000 d m           1:2
Total: 2 Static: 0
"""


def test_map_ports_cli_binds_ports_and_saves_curation(tmp_path: Path) -> None:
    snapshot = _write_site(tmp_path / "site.json", _build_site())
    fdb_path = tmp_path / "show_fdb.txt"
    fdb_path.write_text(EXOS_FDB_TEXT, encoding="utf-8")
    curation_db = tmp_path / "curation.db"
    out_path = tmp_path / "out" / "ports.json"

    rc = main(
        [
            "map-ports",
            "--snapshot",
            str(snapshot),
            "--fdb-file",
            str(fdb_path),
            "--device-id",
            "sw-01",
            "--curation-db",
            str(curation_db),
            "--output",
            str(out_path),
        ]
    )
    assert rc == 0
    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["site_id"] == "site-042"
    assert report["port_count"] == len(report["ports"])
    by_port = {p["port_name"]: p for p in report["ports"]}
    assert by_port["1:1"]["port_mode"] == "access"
    assert by_port["1:1"]["bound_mac"] == SERVER_MAC

    site = Site.from_dict(report["site"])
    switch = next(d for d in site.devices if d.device_id == "sw-01")
    port = next(p for p in switch.ports if p.name == "1:1")
    assert port.connected_mac == SERVER_MAC

    store = CurationStore(curation_db)
    try:
        audit = store.list_audit_log(site_id="site-042")
    finally:
        store.close()
    assert len(audit) >= 1


def test_map_ports_accepts_json_fdb_entries(tmp_path: Path) -> None:
    snapshot = _write_site(tmp_path / "site.json", _build_site())
    fdb_path = tmp_path / "fdb.json"
    fdb_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "device_id": "sw-01",
                        "port_name": "1:1",
                        "mac_address": SERVER_MAC,
                        "vlan_id": "1",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    out_path = tmp_path / "ports.json"

    rc = main(
        [
            "map-ports",
            "--snapshot",
            str(snapshot),
            "--fdb-file",
            str(fdb_path),
            "--output",
            str(out_path),
        ]
    )
    assert rc == 0
    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert [p["port_name"] for p in report["ports"]] == ["1:1"]
    assert report["ports"][0]["bound_mac"] == SERVER_MAC


def test_map_ports_requires_device_id_for_cli_text(tmp_path: Path) -> None:
    snapshot = _write_site(tmp_path / "site.json", _build_site())
    fdb_path = tmp_path / "show_fdb.txt"
    fdb_path.write_text(EXOS_FDB_TEXT, encoding="utf-8")

    with pytest.raises(ValueError, match="--device-id"):
        main(["map-ports", "--snapshot", str(snapshot), "--fdb-file", str(fdb_path)])


def test_map_ports_exports_json_curation_state(tmp_path: Path) -> None:
    snapshot = _write_site(tmp_path / "site.json", _build_site())
    fdb_path = tmp_path / "show_fdb.txt"
    fdb_path.write_text(EXOS_FDB_TEXT, encoding="utf-8")
    curation_json = tmp_path / "curation_state.json"

    rc = main(
        [
            "map-ports",
            "--snapshot",
            str(snapshot),
            "--fdb-file",
            str(fdb_path),
            "--device-id",
            "sw-01",
            "--curation-db",
            str(curation_json),
            "--output",
            str(tmp_path / "ports.json"),
        ]
    )
    assert rc == 0
    assert curation_json.exists()
    store = CurationStore(":memory:")
    try:
        store.import_json(curation_json)
        assert len(store.list_audit_log(site_id="site-042")) >= 1
    finally:
        store.close()


def _diff_snapshots(tmp_path: Path) -> tuple[Path, Path]:
    baseline = _write_site(tmp_path / "baseline.json", _build_site(with_server=False))
    current = _write_site(tmp_path / "current.json", _build_site(with_server=True))
    return baseline, current


def test_diff_scans_cli_writes_reports_and_dispatches_alerts(tmp_path: Path) -> None:
    baseline, current = _diff_snapshots(tmp_path)
    json_out = tmp_path / "out" / "drift.json"
    md_out = tmp_path / "out" / "drift.md"
    alert_out = tmp_path / "alerts" / "drift_alert.json"
    alert_file = tmp_path / "alerts.json"
    alert_file.write_text(
        json.dumps(
            {
                "targets": [
                    {"kind": "json_file", "destination": str(alert_out), "name": "local"}
                ]
            }
        ),
        encoding="utf-8",
    )

    rc = main(
        [
            "diff-scans",
            "--baseline",
            str(baseline),
            "--current",
            str(current),
            "--output-json",
            str(json_out),
            "--output-md",
            str(md_out),
            "--alert-file",
            str(alert_file),
        ]
    )
    assert rc == 0
    report = json.loads(json_out.read_text(encoding="utf-8"))
    assert "NEW_HOST_JOINED" in report["summary_counts"]["by_type"]
    assert report["summary_counts"]["by_type"]["NEW_HOST_JOINED"] >= 1
    assert md_out.read_text(encoding="utf-8").startswith("# Snapshot Drift Report:")
    assert json.loads(alert_out.read_text(encoding="utf-8")) == report


def test_diff_scans_exits_nonzero_when_alert_target_fails(tmp_path: Path) -> None:
    baseline, current = _diff_snapshots(tmp_path)
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("regular file", encoding="utf-8")
    alert_file = tmp_path / "alerts.json"
    alert_file.write_text(
        json.dumps(
            [{"kind": "json_file", "destination": str(blocker / "alert.json")}]
        ),
        encoding="utf-8",
    )
    json_out = tmp_path / "drift.json"

    rc = main(
        [
            "diff-scans",
            "--baseline",
            str(baseline),
            "--current",
            str(current),
            "--output-json",
            str(json_out),
            "--alert-file",
            str(alert_file),
        ]
    )
    assert rc == 1
    assert json_out.exists()
    by_type = json.loads(json_out.read_text("utf-8"))["summary_counts"]["by_type"]
    assert by_type["NEW_HOST_JOINED"] >= 1


def test_diff_scans_prints_empty_report_for_identical_snapshots(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snapshot = _write_site(tmp_path / "site.json", _build_site())
    rc = main(
        ["diff-scans", "--baseline", str(snapshot), "--current", str(snapshot)]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary_counts"]["total"] == 0


def test_diff_scans_rejects_mismatched_site_ids(tmp_path: Path) -> None:
    baseline = _write_site(tmp_path / "baseline.json", _build_site())
    other = _build_site()
    other.site_id = "site-099"
    current = _write_site(tmp_path / "current.json", other)

    with pytest.raises(ValueError):
        main(["diff-scans", "--baseline", str(baseline), "--current", str(current)])


def test_discover_enriches_hosts_from_router_dhcp_and_proxmox(tmp_path: Path) -> None:
    mock_config = tmp_path / "mock.json"
    mock_config.write_text(
        json.dumps(
            {
                "ping": {
                    "10.42.1.1": 0.4,
                    "10.42.1.50": 0.8,
                    "10.42.1.60": 0.9,
                    "10.42.1.70": 1.0,
                },
                "tcp_ports": {
                    "10.42.1.1": [53, 80, 443],
                    "10.42.1.50": [3389],
                    "10.42.1.60": [22],
                    "10.42.1.70": [22],
                },
            }
        ),
        encoding="utf-8",
    )
    router_arp = tmp_path / "router_arp.json"
    router_arp.write_text(
        json.dumps(
            {
                "arp_records": [
                    {"ip": "10.42.1.50", "mac_address": "d4:be:d9:11:22:33"},
                    {"ip": "10.42.1.60", "mac_address": "00:15:5d:00:00:60"},
                ]
            }
        ),
        encoding="utf-8",
    )
    dhcp_leases = tmp_path / "leases.csv"
    dhcp_leases.write_text(
        "ip,mac_address,hostname\n10.42.1.50,d4:be:d9:11:22:33,accounting-pc-07\n",
        encoding="utf-8",
    )
    proxmox_path = tmp_path / "proxmox.json"
    proxmox_path.write_text(
        ProxmoxClusterSnapshot(
            guests=[
                ProxmoxGuestRecord(
                    vmid=101,
                    name="docker-host-01",
                    guest_type="qemu",
                    node="pve-01",
                    status="running",
                    ip_addresses=["10.42.1.70"],
                    mac_addresses=["bc:24:11:00:00:70"],
                )
            ]
        ).to_json(indent=2),
        encoding="utf-8",
    )
    out_path = tmp_path / "discovered.json"

    rc = main(
        [
            "discover",
            "--cidr",
            "10.42.0.0/16",
            "--site-id",
            "site-042",
            "--mock-config",
            str(mock_config),
            "--router-arp",
            str(router_arp),
            "--dhcp-leases",
            str(dhcp_leases),
            "--proxmox-snapshot",
            str(proxmox_path),
            "--evaluation-time",
            "2026-11-12T00:00:00Z",
            "--output",
            str(out_path),
        ]
    )
    assert rc == 0
    site = Site.from_dict(json.loads(out_path.read_text(encoding="utf-8")))
    eq_by_ip = {ip: eq for eq in site.equipment for ip in eq.assigned_ips}
    ip_by_addr = {ip.ip: ip for ip in site.ip_addresses}

    # DHCP hostname for the leased IP
    assert eq_by_ip["10.42.1.50"].name == "accounting-pc-07"
    # ARP-derived MAC on the matching equipment's IP / ArpEntry
    ip_60 = ip_by_addr["10.42.1.60"]
    assert ip_60.assigned_object_id == eq_by_ip["10.42.1.60"].equipment_id
    assert ip_60.arp_mac == "00:15:5d:00:00:60"
    assert ip_60.arp_entry is not None
    assert ip_60.arp_entry.arp_mac == "00:15:5d:00:00:60"
    # Proxmox guest name and MAC for the guest IP
    assert eq_by_ip["10.42.1.70"].name == "docker-host-01"
    assert ip_by_addr["10.42.1.70"].arp_mac == "bc:24:11:00:00:70"


def test_discover_proxmox_enrichment_only_fills_unambiguous_running_matches(
    tmp_path: Path,
) -> None:
    def _host(ip: str, **extra: object) -> dict[str, object]:
        return {
            "ip": ip,
            "subnet_cidr": "10.42.1.0/24",
            "vlan_id": "1",
            "icmp_reachable": True,
            "open_tcp_ports": [22],
            **extra,
        }

    mock_config = tmp_path / "mock.json"
    mock_config.write_text(
        json.dumps(
            {
                "active_subnets": ["10.42.1.0/24"],
                "hosts": [
                    _host("10.42.1.80", hostname="keep-me", inferred_role="server"),
                    _host("10.42.1.81"),
                    _host("10.42.1.82"),
                    _host("10.42.1.83"),
                    _host("10.42.1.84"),
                ],
            }
        ),
        encoding="utf-8",
    )
    # Router CLI text (not JSON) supplies the MAC used for the MAC-only guest match
    router_arp = tmp_path / "router_arp.txt"
    router_arp.write_text(
        "10.42.1.83 dev eth0 lladdr bc:24:11:00:00:83 REACHABLE\n",
        encoding="utf-8",
    )
    proxmox_path = tmp_path / "proxmox.json"
    proxmox_path.write_text(
        ProxmoxClusterSnapshot.from_dict(
            {
                "guests": [
                    {"vmid": 180, "name": "pve-guest-80", "guest_type": "qemu", "node": "pve-01", "ip_addresses": ["10.42.1.80"]},
                    {"vmid": 181, "name": "stopped-81", "guest_type": "qemu", "node": "pve-01", "status": "stopped", "ip_addresses": ["10.42.1.81"]},
                    {"vmid": 182, "name": "dup-a", "guest_type": "qemu", "node": "pve-01", "ip_addresses": ["10.42.1.82"]},
                    {"vmid": 183, "name": "dup-b", "guest_type": "lxc", "node": "pve-02", "ip_addresses": ["10.42.1.82"]},
                    {"vmid": 184, "name": "mac-only-83", "guest_type": "qemu", "node": "pve-01", "mac_addresses": ["bc:24:11:00:00:83"]},
                ],
                "containers": [
                    {"container_id": "abc123", "name": "portainer-84", "image": "portainer/portainer-ce", "ip_addresses": ["10.42.1.84"]},
                ],
            }
        ).to_json(indent=2),
        encoding="utf-8",
    )
    out_path = tmp_path / "discovered.json"

    rc = main(
        [
            "discover",
            "--cidr",
            "10.42.0.0/16",
            "--site-id",
            "site-042",
            "--mock-config",
            str(mock_config),
            "--router-arp",
            str(router_arp),
            "--proxmox-snapshot",
            str(proxmox_path),
            "--evaluation-time",
            "2026-11-12T00:00:00Z",
            "--output",
            str(out_path),
        ]
    )
    assert rc == 0
    site = Site.from_dict(json.loads(out_path.read_text(encoding="utf-8")))
    names = {ip: eq.name for eq in site.equipment for ip in eq.assigned_ips}
    site_text = out_path.read_text(encoding="utf-8")

    assert names["10.42.1.80"] == "keep-me"
    assert "stopped-81" not in site_text
    assert "dup-a" not in site_text and "dup-b" not in site_text
    assert names["10.42.1.83"] == "mac-only-83"
    assert names["10.42.1.84"] == "portainer-84"
