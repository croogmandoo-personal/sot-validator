"""Fixture integrity and schema consistency tests for Issue #1 discovery deliverables."""

from __future__ import annotations

import csv
from html.parser import HTMLParser
import ipaddress
import json
import pathlib
import sqlite3
import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DISCOVERY_DOC = REPO_ROOT / "docs" / "DISCOVERY.md"
SAMPLES_DIR = REPO_ROOT / "tests" / "fixtures" / "sot_samples"
SQL_SEED_FILE = SAMPLES_DIR / "sql" / "sot_schema_and_seed.sql"
CSV_DIR = SAMPLES_DIR / "csv"
HTML_DIR = SAMPLES_DIR / "html"
VCENTER_JSON = SAMPLES_DIR / "vcenter" / "vcenter_inventory.json"
SNMP_JSON = SAMPLES_DIR / "snmp" / "extreme_and_apc_walks.json"

TABLE_PRIMARY_KEYS = {
    "sites": "site_id",
    "network_devices": "device_id",
    "ports": "port_id",
    "vlans_subnets": "subnet_id",
    "ip_arp_entries": "ip_id",
    "equipment": "equipment_id",
}


class _DOMInspector(HTMLParser):
    """Lightweight stdlib HTML parser collecting element IDs, classes, data-* attributes, and forms."""

    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.table_ids: set[str] = set()
        self.rows_by_class: dict[str, list[dict[str, str]]] = {}
        self.forms: list[dict[str, str]] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k: (v or "") for k, v in attrs}
        elem_id = attr_map.get("id")
        if elem_id:
            self.ids.add(elem_id)
            if tag == "table":
                self.table_ids.add(elem_id)

        if tag == "tr" and "class" in attr_map:
            for cls in attr_map["class"].split():
                self.rows_by_class.setdefault(cls, []).append(attr_map)

        if tag == "form":
            self.forms.append(attr_map)

        if tag == "a" and "href" in attr_map:
            self.links.append(attr_map["href"])


@pytest.fixture()
def seeded_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(SQL_SEED_FILE.read_text(encoding="utf-8"))
    return conn


def test_discovery_doc_contains_required_specifications() -> None:
    assert DISCOVERY_DOC.is_file(), "docs/DISCOVERY.md must exist"
    content = DISCOVERY_DOC.read_text(encoding="utf-8")

    required_tokens = [
        # URL patterns & HTML DOM selectors
        "/sites/{site_id}",
        "/sites/{site_id}/devices/{device_id}",
        "/sites/{site_id}/subnets",
        "/sites/{site_id}/equipment",
        "#site-overview",
        ".room-list",
        "table#subnets-table",
        "table#ip-arp-table",
        "table#equipment-table",
        "table#ports-table",
        "#device-detail",
        # Mutating blocklist
        "/actions/port-admin",
        "/actions/poe-toggle",
        "/actions/port-bounce",
        "/actions/vlan-assign",
        "/actions/delete",
        "/api/cmd/*",
        # SQL/CSV tables
        "sites",
        "network_devices",
        "ports",
        "vlans_subnets",
        "ip_arp_entries",
        "equipment",
        # Multi-vCenter fields
        "vcenter_instance",
        "vm_moref",
        "bios_uuid",
        "power_state",
        "tools_status",
        "tools_heartbeat",
        "guest_os_family",
        # Standard + Extreme + APC SNMP OIDs
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.2.1.1.5.0",
        "1.3.6.1.2.1.2.2.1.7",
        "1.3.6.1.2.1.2.2.1.8",
        "1.3.6.1.2.1.2.2.1.9",
        "1.3.6.1.2.1.31.1.1.1.18",
        "1.3.6.1.2.1.4.22.1.2",
        "1.3.6.1.2.1.4.35.1.4",
        "1.3.6.1.4.1.1916",
        "1.3.6.1.4.1.318",
        "1.3.6.1.4.1.318.1.1.1.1.1.1.0",
        "1.3.6.1.4.1.318.1.1.1.11.1.1.0",
        "1.3.6.1.4.1.318.1.1.1.2.2.1.0",
        "1.3.6.1.4.1.318.1.1.1.4.2.3.0",
    ]
    for token in required_tokens:
        assert token in content, f"Missing required specification token in docs/DISCOVERY.md: {token}"


def test_sql_seed_populates_all_canonical_tables(seeded_db: sqlite3.Connection) -> None:
    tables = {
        row["name"]
        for row in seeded_db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert set(TABLE_PRIMARY_KEYS.keys()) <= tables

    for table in TABLE_PRIMARY_KEYS:
        count = seeded_db.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
        assert count > 0, f"Expected table {table} to be populated"

    fk_errors = seeded_db.execute("PRAGMA foreign_key_check;").fetchall()
    assert fk_errors == []


def test_csv_exports_match_sql_seed_tables(seeded_db: sqlite3.Connection) -> None:
    for table, pk_col in TABLE_PRIMARY_KEYS.items():
        csv_path = CSV_DIR / f"{table}.csv"
        assert csv_path.is_file(), f"Missing CSV fixture: {csv_path}"

        with csv_path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            csv_rows = list(reader)
            csv_columns = reader.fieldnames or []

        sql_rows = [dict(r) for r in seeded_db.execute(f"SELECT * FROM {table}")]
        assert len(csv_rows) == len(sql_rows), f"Row count mismatch for {table}"
        assert csv_columns == list(sql_rows[0].keys()), f"Column mismatch for {table}"

        csv_pks = [r[pk_col] for r in csv_rows]
        sql_pks = [str(r[pk_col]) for r in sql_rows]
        assert csv_pks == sql_pks, f"Primary key mismatch in {table}"


def test_html_fixtures_match_dom_selectors_and_blocklist(seeded_db: sqlite3.Connection) -> None:
    overview_path = HTML_DIR / "site_042_overview.html"
    device_path = HTML_DIR / "site_042_device_sw01.html"
    assert overview_path.is_file()
    assert device_path.is_file()

    overview_dom = _DOMInspector()
    overview_dom.feed(overview_path.read_text(encoding="utf-8"))

    assert "site-overview" in overview_dom.ids
    assert {"subnets-table", "ip-arp-table", "equipment-table"} <= overview_dom.table_ids
    assert overview_dom.forms == [], "Site overview HTML should not require form submissions"

    sql_subnet_ids = [
        r["subnet_id"]
        for r in seeded_db.execute("SELECT subnet_id FROM vlans_subnets ORDER BY rowid")
    ]
    html_subnet_ids = [
        r["data-subnet-id"] for r in overview_dom.rows_by_class.get("subnet-row", [])
    ]
    assert html_subnet_ids == sql_subnet_ids

    sql_ip_ids = [
        r["ip_id"] for r in seeded_db.execute("SELECT ip_id FROM ip_arp_entries ORDER BY rowid")
    ]
    html_ip_ids = [r["data-ip-id"] for r in overview_dom.rows_by_class.get("ip-arp-row", [])]
    assert html_ip_ids == sql_ip_ids

    sql_eq_ids = [
        r["equipment_id"]
        for r in seeded_db.execute("SELECT equipment_id FROM equipment ORDER BY rowid")
    ]
    html_eq_ids = [
        r["data-equipment-id"] for r in overview_dom.rows_by_class.get("equipment-row", [])
    ]
    assert html_eq_ids == sql_eq_ids

    device_dom = _DOMInspector()
    device_dom.feed(device_path.read_text(encoding="utf-8"))

    assert "device-detail" in device_dom.ids
    assert "ports-table" in device_dom.table_ids

    sql_port_ids = [
        r["port_id"] for r in seeded_db.execute("SELECT port_id FROM ports ORDER BY rowid")
    ]
    html_port_ids = [r["data-port-id"] for r in device_dom.rows_by_class.get("port-row", [])]
    assert html_port_ids == sql_port_ids

    # Verify mutating POST forms exist in device HTML for negative-testing the scraper blocklist
    form_methods = {f.get("method", "").upper() for f in device_dom.forms}
    form_actions = {f.get("action", "") for f in device_dom.forms}
    assert form_methods == {"POST"}
    assert "/actions/port-admin" in form_actions
    assert "/actions/poe-toggle" in form_actions


def test_subnet_scoping_and_ip_containment(seeded_db: sqlite3.Connection) -> None:
    sites = {
        r["site_id"]: ipaddress.ip_network(r["site_prefix"], strict=True)
        for r in seeded_db.execute("SELECT site_id, site_prefix FROM sites")
    }
    for site_net in sites.values():
        assert site_net.prefixlen == 16

    subnets: dict[str, ipaddress.IPv4Network] = {}
    for row in seeded_db.execute("SELECT subnet_id, site_id, cidr, gateway_ip FROM vlans_subnets"):
        subnet_net = ipaddress.ip_network(row["cidr"], strict=True)
        assert isinstance(subnet_net, ipaddress.IPv4Network)
        assert subnet_net.prefixlen == 24, f"Subnet {row['subnet_id']} must be a /24 block"
        parent_net = sites[row["site_id"]]
        assert subnet_net.subnet_of(parent_net), (
            f"Subnet {subnet_net} must fall within parent site {parent_net}"
        )
        gw_ip = ipaddress.ip_address(row["gateway_ip"])
        assert gw_ip in subnet_net
        subnets[row["subnet_id"]] = subnet_net

    for row in seeded_db.execute("SELECT ip_id, subnet_id, ip_address FROM ip_arp_entries"):
        ip_obj = ipaddress.ip_address(row["ip_address"])
        subnet_net = subnets[row["subnet_id"]]
        assert ip_obj in subnet_net, f"IP {ip_obj} ({row['ip_id']}) not in /24 {subnet_net}"


def test_vcenter_and_snmp_json_fixtures(seeded_db: sqlite3.Connection) -> None:
    assert VCENTER_JSON.is_file()
    vcenter_data = json.loads(VCENTER_JSON.read_text(encoding="utf-8"))

    instances = {inst["vcenter_instance"] for inst in vcenter_data["instances"]}
    assert {"vcenter-prod-01", "vcenter-prod-02"} <= instances

    vms = vcenter_data["vms"]
    assert len(vms) >= 2
    required_vm_fields = {
        "vcenter_instance",
        "vm_moref",
        "bios_uuid",
        "vm_name",
        "guest_hostname",
        "guest_os_family",
        "power_state",
        "tools_status",
        "tools_heartbeat",
        "nics",
        "last_updated",
    }
    windows_count = 0
    vm_by_uuid = {}
    for vm in vms:
        assert required_vm_fields <= set(vm.keys())
        if vm["guest_os_family"] == "windows":
            windows_count += 1
        vm_by_uuid[vm["bios_uuid"]] = vm

    # Verify ~90% Windows VM footprint in fixture
    windows_ratio = windows_count / len(vms)
    assert 0.85 <= windows_ratio <= 0.95

    # Verify VM records in SoT equipment table correlate cleanly with vCenter fixture
    for row in seeded_db.execute(
        "SELECT equipment_id, vcenter_bios_uuid, vcenter_moref FROM equipment WHERE equipment_type='VM'"
    ):
        assert row["vcenter_bios_uuid"] in vm_by_uuid
        assert vm_by_uuid[row["vcenter_bios_uuid"]]["vm_moref"] == row["vcenter_moref"]

    assert SNMP_JSON.is_file()
    snmp_data = json.loads(SNMP_JSON.read_text(encoding="utf-8"))
    assert snmp_data["snmp_profile"]["mode"] == "readonly"
    targets = snmp_data["targets"]
    assert "dev-042-sw01" in targets
    assert "eq-042-ups01" in targets

    sw_oids = targets["dev-042-sw01"]["oids"]
    assert "1.3.6.1.2.1.1.1.0" in sw_oids
    assert "1.3.6.1.2.1.1.3.0" in sw_oids
    assert any(k.startswith("1.3.6.1.4.1.1916.") for k in sw_oids)
    assert any(k.startswith("1.3.6.1.2.1.2.2.1.8.") for k in sw_oids)

    ups_oids = targets["eq-042-ups01"]["oids"]
    assert "1.3.6.1.4.1.318.1.1.1.1.1.1.0" in ups_oids
    assert "1.3.6.1.4.1.318.1.1.1.11.1.1.0" in ups_oids
    assert "1.3.6.1.4.1.318.1.1.1.2.2.1.0" in ups_oids
    assert "1.3.6.1.4.1.318.1.1.1.4.2.3.0" in ups_oids
