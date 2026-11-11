"""Unit and integration tests for the read-only SoT batch extraction engine and snapshot store."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from sot_validator.extraction import (
    BatchExtractor,
    FixtureSoTClient,
    HtmlScraperSoTClient,
    ReadOnlyViolationError,
    SnapshotStore,
    SoTClient,
    SqlExportSoTClient,
    validate_read_only_request,
)
from sot_validator.models import EquipmentCategory, Site


def test_fixture_sot_client_generates_multi_site_hierarchies(tmp_path: Path) -> None:
    client = FixtureSoTClient(num_sites=3)
    assert isinstance(client, SoTClient)
    assert client.list_site_ids() == ["site-001", "site-002", "site-003"]

    sites = client.list_sites()
    assert len(sites) == 3

    s1 = client.get_site("site-001")
    assert s1.site_id == "site-001"
    assert "10.1.0.0/16" in s1.name
    assert s1.rooms == ["MDF-1", "IDF-1"]

    # Extreme Networks switch with ports
    assert len(s1.devices) == 1
    sw = s1.devices[0]
    assert sw.vendor == "Extreme Networks"
    assert sw.management_ip == "10.1.1.2"
    assert len(sw.ports) == 3
    assert len(client.get_ports("site-001", device_id=sw.device_id)) == 3
    assert client.get_ports("site-001", device_id="non-existent") == []

    # Subnets are /24 inside 10.1.0.0/16
    assert len(client.get_subnets("site-001")) == 3
    assert len(client.get_vlans("site-001")) == 3
    for sub in s1.subnets:
        assert sub.cidr.startswith("10.1.")
        assert sub.cidr.endswith("/24")

    # Equipment includes APC UPS and Windows VM
    eq_list = client.get_equipment("site-001")
    categories = {eq.category for eq in eq_list}
    assert EquipmentCategory.UPS in categories
    assert EquipmentCategory.VM in categories
    vm = next(eq for eq in eq_list if eq.category == EquipmentCategory.VM)
    assert vm.power_state == "poweredOn"
    assert vm.hypervisor_id is not None

    # IP addresses include ARP entries
    ips = client.get_ip_addresses("site-001")
    assert len(ips) == 3
    assert any(
        ip.arp_entry is not None and ip.arp_entry.arp_mac == ip.arp_mac for ip in ips
    )

    with pytest.raises(KeyError):
        client.get_site("site-999")

    # Round-trip via JSON fixture file
    fixture_file = tmp_path / "fixture_sites.json"
    fixture_file.write_text(
        json.dumps({"sites": [s.to_dict() for s in sites]}, indent=2),
        encoding="utf-8",
    )
    loaded_client = FixtureSoTClient(fixture_path=fixture_file)
    assert loaded_client.list_sites() == sites


def test_sql_dump_ingestion_and_normalization(tmp_path: Path) -> None:
    sql_dump = """
    -- Legacy SoT read-only SQL dump
    CREATE TABLE sites (
        site_id TEXT PRIMARY KEY,
        name TEXT,
        address TEXT,
        contact_name TEXT,
        contact_email TEXT,
        contact_phone TEXT,
        rooms TEXT
    );
    INSERT INTO sites VALUES (
        'site-010',
        'Denver Regional',
        '500 Mountain Rd',
        'Jane Admin',
        'jadmin@corp.internal',
        '555-0110',
        'MDF-A;IDF-B'
    );

    CREATE TABLE network_devices (
        device_id TEXT PRIMARY KEY,
        site_id TEXT,
        hostname TEXT,
        mgmt_ip TEXT,
        vendor TEXT,
        model TEXT,
        role TEXT,
        last_seen TEXT
    );
    INSERT INTO network_devices VALUES (
        'dev-sw-10',
        'site-010',
        'den-ext-sw01',
        '10.10.1.2',
        'Extreme Networks',
        'X460-G2',
        'access',
        '2026-02-10T12:00:00+00:00'
    );

    CREATE TABLE ports (
        port_id TEXT PRIMARY KEY,
        device_id TEXT,
        port_name TEXT,
        admin_status TEXT,
        oper_status TEXT,
        poe_status TEXT,
        connected_equipment_id TEXT,
        connected_mac TEXT,
        vlan_id INTEGER
    );
    INSERT INTO ports VALUES (
        'port-10-1',
        'dev-sw-10',
        '1:1',
        'up',
        'up',
        'delivering',
        'eq-ups-10',
        '00:c0:b7:10:20:01',
        20
    );

    CREATE TABLE vlans_subnets (
        subnet_id TEXT PRIMARY KEY,
        site_id TEXT,
        vlan_id TEXT,
        vlan_name TEXT,
        cidr TEXT,
        gateway_ip TEXT,
        description TEXT
    );
    INSERT INTO vlans_subnets VALUES (
        'sub-10-20',
        'site-010',
        '20',
        'UPS_Mgmt',
        '10.10.20.0/24',
        '10.10.20.1',
        'APC UPS Subnet'
    );

    CREATE TABLE ip_arp_entries (
        ip_address TEXT PRIMARY KEY,
        subnet_id TEXT,
        site_id TEXT,
        assigned_target_type TEXT,
        assigned_target_id TEXT,
        mac_address TEXT,
        arp_last_seen TEXT,
        arp_source_device_id TEXT
    );
    INSERT INTO ip_arp_entries VALUES (
        '10.10.20.15',
        'sub-10-20',
        'site-010',
        'Equipment',
        'eq-ups-10',
        '00:c0:b7:10:20:01',
        '2026-02-10T11:55:00+00:00',
        'dev-sw-10'
    );

    CREATE TABLE equipment (
        equipment_id TEXT PRIMARY KEY,
        site_id TEXT,
        hostname TEXT,
        equipment_type TEXT,
        primary_ip TEXT,
        connected_port_id TEXT,
        vcenter_instance TEXT,
        power_state TEXT,
        last_seen TEXT
    );
    INSERT INTO equipment VALUES (
        'eq-ups-10',
        'site-010',
        'den-apc-ups01',
        'UPS',
        '10.10.20.15',
        'port-10-1',
        NULL,
        'online',
        '2026-02-10T12:00:00+00:00'
    );
    INSERT INTO equipment VALUES (
        'eq-vm-10',
        'site-010',
        'den-win-sql01',
        'VM',
        '10.10.20.50',
        NULL,
        'vc-west.corp.internal',
        'poweredOn',
        '2026-02-10T12:00:00+00:00'
    );
    """
    sql_path = tmp_path / "export.sql"
    sql_path.write_text(sql_dump, encoding="utf-8")

    client = SqlExportSoTClient.from_sql_dump(sql_path)
    site = client.get_site("site-010")
    assert site.name == "Denver Regional"
    assert site.contact_info == "Jane Admin | jadmin@corp.internal | 555-0110"
    assert site.rooms == ["MDF-A", "IDF-B"]

    assert len(site.devices) == 1
    dev = site.devices[0]
    assert dev.hostname == "den-ext-sw01"
    assert dev.management_ip == "10.10.1.2"
    assert dev.vendor == "Extreme Networks"
    assert len(dev.ports) == 1
    assert dev.ports[0].name == "1:1"
    assert dev.ports[0].connected_device_id == "eq-ups-10"
    assert dev.ports[0].vlan_id == "20"

    assert len(site.vlans) == 1
    assert site.vlans[0].name == "UPS_Mgmt"
    assert len(site.subnets) == 1
    assert site.subnets[0].cidr == "10.10.20.0/24"
    assert site.subnets[0].gateway == "10.10.20.1"

    assert len(site.ip_addresses) == 1
    ip_rec = site.ip_addresses[0]
    assert ip_rec.ip == "10.10.20.15"
    assert ip_rec.arp_entry is not None
    assert ip_rec.arp_entry.arp_mac == "00:c0:b7:10:20:01"

    assert len(site.equipment) == 2
    ups = next(e for e in site.equipment if e.equipment_id == "eq-ups-10")
    assert ups.category == EquipmentCategory.UPS
    assert ups.assigned_ips == ["10.10.20.15"]
    assert ups.connected_ports == ["port-10-1"]

    vm = next(e for e in site.equipment if e.equipment_id == "eq-vm-10")
    assert vm.category == EquipmentCategory.VM
    assert vm.hypervisor_id == "vc-west.corp.internal"
    assert vm.power_state == "poweredOn"


def test_sql_dump_rejects_destructive_sql() -> None:
    for bad_sql in [
        "DROP TABLE sites;",
        "DELETE FROM ports WHERE port_id = 'p1';",
        "UPDATE ports SET admin_status = 'down';",
        "ALTER TABLE sites ADD COLUMN flag TEXT;",
        "TRUNCATE TABLE ip_arp_entries;",
    ]:
        with pytest.raises(ReadOnlyViolationError):
            SqlExportSoTClient.from_sql_dump(bad_sql)


def test_csv_and_json_exports_ingestion(tmp_path: Path) -> None:
    csv_dir = tmp_path / "csv_export"
    csv_dir.mkdir()

    (csv_dir / "sites.csv").write_text(
        "site_id,name,address,contact_info,rooms\n"
        "site-020,Austin Branch,200 Congress Ave,ops@austin.internal,MDF-1;IDF-2\n",
        encoding="utf-8",
    )
    (csv_dir / "network_devices.csv").write_text(
        "device_id,site_id,hostname,management_ip,vendor,model,role,last_seen\n"
        "sw-20,site-020,aus-ext-sw01,10.20.1.2,Extreme Networks,X440-G2,access,2026-02-10T10:00:00+00:00\n",
        encoding="utf-8",
    )
    (csv_dir / "ports.csv").write_text(
        "port_id,device_id,name,admin_status,oper_status,poe_status,connected_device_id,connected_mac,vlan_id\n"
        "p-20-1,sw-20,1:1,up,up,off,vm-20-1,00:50:56:20:00:01,10\n",
        encoding="utf-8",
    )
    (csv_dir / "vlans_subnets.csv").write_text(
        "subnet_id,site_id,vlan_id,vlan_name,cidr,gateway\n"
        "sub-20-10,site-020,10,VMs,10.20.10.0/24,10.20.10.1\n",
        encoding="utf-8",
    )
    (csv_dir / "ip_arp_entries.csv").write_text(
        "ip,subnet_id,assigned_object_type,assigned_object_id,arp_mac,arp_last_seen,arp_source_device_id\n"
        "10.20.10.11,sub-20-10,Equipment,vm-20-1,00:50:56:20:00:01,2026-02-10T10:00:00+00:00,sw-20\n",
        encoding="utf-8",
    )
    (csv_dir / "equipment.csv").write_text(
        "equipment_id,site_id,name,category,assigned_ips,connected_ports,hypervisor_id,power_state,last_seen\n"
        "vm-20-1,site-020,aus-win-app01,VM,10.20.10.11,p-20-1,vc01.corp.internal,poweredOn,2026-02-10T10:00:00+00:00\n",
        encoding="utf-8",
    )

    csv_client = SqlExportSoTClient.from_csv_dir(csv_dir)
    site_from_csv = csv_client.get_site("site-020")
    assert site_from_csv.name == "Austin Branch"
    assert site_from_csv.devices[0].ports[0].connected_device_id == "vm-20-1"
    assert site_from_csv.ip_addresses[0].arp_entry is not None
    assert site_from_csv.equipment[0].category == EquipmentCategory.VM

    # Verify JSON table export produces identical canonical Site
    json_export_path = tmp_path / "export.json"
    json_payload = {
        "sites": [
            {
                "site_id": "site-020",
                "name": "Austin Branch",
                "address": "200 Congress Ave",
                "contact_info": "ops@austin.internal",
                "rooms": ["MDF-1", "IDF-2"],
            }
        ],
        "network_devices": [
            {
                "device_id": "sw-20",
                "site_id": "site-020",
                "hostname": "aus-ext-sw01",
                "management_ip": "10.20.1.2",
                "vendor": "Extreme Networks",
                "model": "X440-G2",
                "role": "access",
                "last_seen": "2026-02-10T10:00:00+00:00",
            }
        ],
        "ports": [
            {
                "port_id": "p-20-1",
                "device_id": "sw-20",
                "name": "1:1",
                "admin_status": "up",
                "oper_status": "up",
                "poe_status": "off",
                "connected_device_id": "vm-20-1",
                "connected_mac": "00:50:56:20:00:01",
                "vlan_id": "10",
            }
        ],
        "vlans_subnets": [
            {
                "subnet_id": "sub-20-10",
                "site_id": "site-020",
                "vlan_id": "10",
                "vlan_name": "VMs",
                "cidr": "10.20.10.0/24",
                "gateway": "10.20.10.1",
            }
        ],
        "ip_arp_entries": [
            {
                "ip": "10.20.10.11",
                "subnet_id": "sub-20-10",
                "assigned_object_type": "Equipment",
                "assigned_object_id": "vm-20-1",
                "arp_mac": "00:50:56:20:00:01",
                "arp_last_seen": "2026-02-10T10:00:00+00:00",
                "arp_source_device_id": "sw-20",
            }
        ],
        "equipment": [
            {
                "equipment_id": "vm-20-1",
                "site_id": "site-020",
                "name": "aus-win-app01",
                "category": "vm",
                "assigned_ips": ["10.20.10.11"],
                "connected_ports": ["p-20-1"],
                "hypervisor_id": "vc01.corp.internal",
                "power_state": "poweredOn",
                "last_seen": "2026-02-10T10:00:00+00:00",
            }
        ],
    }
    json_export_path.write_text(json.dumps(json_payload), encoding="utf-8")
    json_client = SqlExportSoTClient.from_json(json_export_path)
    assert json_client.get_site("site-020") == site_from_csv


def test_html_scraper_parses_hierarchy_and_ignores_mutating_forms() -> None:
    pages = {
        "https://sot.internal/sites": """
        <html>
          <body>
            <table id="sites-index">
              <tbody>
                <tr class="site-row" data-site-id="site-001" data-site-name="HQ Site">
                  <td><a href="/sites/site-001">HQ Site</a></td>
                </tr>
              </tbody>
            </table>
          </body>
        </html>
        """,
        "https://sot.internal/sites/site-001": """
        <html>
          <body>
            <div id="site-overview" data-site-id="site-001" data-site-name="HQ Site">
              <p class="site-address">100 Corporate Blvd</p>
              <p class="site-contact">netops@corp.internal</p>
              <ul class="room-list">
                <li class="room-item">MDF-1</li>
                <li class="room-item">IDF-2</li>
              </ul>
            </div>

            <table id="devices-table">
              <tbody>
                <tr data-device-id="sw-001">
                  <td><a href="/sites/site-001/devices/sw-001">ext-sw-001</a></td>
                </tr>
              </tbody>
            </table>

            <table id="subnets-table">
              <thead>
                <tr><th>VLAN ID</th><th>VLAN Name</th><th>Subnet ID</th><th>CIDR</th><th>Gateway</th></tr>
              </thead>
              <tbody>
                <tr data-vlan-id="10" data-vlan-name="Servers" data-subnet-id="sub-10" data-cidr="10.1.10.0/24" data-gateway="10.1.10.1">
                  <td class="col-vlan-id">10</td>
                  <td class="col-vlan-name">Servers</td>
                  <td class="col-subnet-id">sub-10</td>
                  <td class="col-cidr">10.1.10.0/24</td>
                  <td class="col-gateway">10.1.10.1</td>
                </tr>
              </tbody>
            </table>

            <table id="ip-arp-table">
              <tbody>
                <tr data-ip="10.1.10.11" data-subnet-id="sub-10" data-assigned-object-type="Equipment" data-assigned-object-id="vm-001" data-arp-mac="00:50:56:01:10:11" data-arp-last-seen="2026-02-10T12:00:00+00:00" data-arp-source-device-id="sw-001">
                  <td class="col-ip">10.1.10.11</td>
                  <td class="col-subnet-id">sub-10</td>
                </tr>
              </tbody>
            </table>

            <table id="equipment-table">
              <tbody>
                <tr data-equipment-id="vm-001" data-name="win-dc-01" data-category="VM" data-assigned-ips="10.1.10.11" data-connected-ports="p-001" data-hypervisor-id="vc01.corp.internal" data-power-state="poweredOn" data-last-seen="2026-02-10T12:00:00+00:00">
                  <td class="col-name">win-dc-01</td>
                </tr>
                <tr data-equipment-id="ups-001" data-name="apc-ups-01" data-category="UPS" data-assigned-ips="10.1.20.10" data-connected-ports="p-002" data-power-state="online">
                  <td class="col-name">apc-ups-01</td>
                </tr>
              </tbody>
            </table>
          </body>
        </html>
        """,
        "https://sot.internal/sites/site-001/devices/sw-001": """
        <html>
          <body>
            <div id="device-detail"
                 data-device-id="sw-001"
                 data-site-id="site-001"
                 data-hostname="ext-sw-001"
                 data-vendor="Extreme Networks"
                 data-model="X460-G2"
                 data-role="access"
                 data-mgmt-ip="10.1.1.2"
                 data-last-seen="2026-02-10T12:00:00+00:00">
            </div>
            <table id="ports-table">
              <tbody>
                <tr class="port-row"
                    data-port-id="p-001"
                    data-port-name="1:1"
                    data-admin-status="up"
                    data-oper-status="up"
                    data-poe-status="off"
                    data-connected-device-id="vm-001"
                    data-connected-mac="00:50:56:01:10:11"
                    data-vlan-id="10">
                  <td class="col-port-name">1:1</td>
                  <td class="col-ops-actions">
                    <form method="POST" action="/actions/port-admin">
                      <input type="hidden" name="port_id" value="p-001" />
                      <button type="submit" name="action" value="disable">Disable Port</button>
                    </form>
                    <form method="POST" action="/actions/poe-toggle">
                      <button type="submit" name="action" value="off">PoE Off</button>
                    </form>
                  </td>
                </tr>
              </tbody>
            </table>
          </body>
        </html>
        """,
    }

    called_requests: list[tuple[str, str]] = []

    def fake_transport(method: str, url: str) -> str:
        called_requests.append((method, url))
        if url not in pages:
            raise KeyError(f"Page not found: {url}")
        return pages[url]

    scraper = HtmlScraperSoTClient("https://sot.internal", transport=fake_transport)
    sites = scraper.list_sites()
    assert len(sites) == 1

    site = sites[0]
    assert site.site_id == "site-001"
    assert site.name == "HQ Site"
    assert site.address == "100 Corporate Blvd"
    assert site.contact_info == "netops@corp.internal"
    assert site.rooms == ["MDF-1", "IDF-2"]

    assert len(site.devices) == 1
    dev = site.devices[0]
    assert dev.device_id == "sw-001"
    assert dev.vendor == "Extreme Networks"
    assert dev.management_ip == "10.1.1.2"
    assert len(dev.ports) == 1
    assert dev.ports[0].port_id == "p-001"
    assert dev.ports[0].oper_status == "up"
    assert dev.ports[0].connected_device_id == "vm-001"

    assert len(site.vlans) == 1
    assert len(site.subnets) == 1
    assert site.subnets[0].cidr == "10.1.10.0/24"
    assert len(site.ip_addresses) == 1
    assert site.ip_addresses[0].arp_entry is not None
    assert len(site.equipment) == 2

    # Ensure only GET requests were issued and no form action URLs were ever requested
    assert all(method == "GET" for method, _ in called_requests)
    assert all("/actions/" not in url for _, url in called_requests)


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("POST", "https://sot.internal/sites"),
        ("PUT", "https://sot.internal/sites/site-001"),
        ("DELETE", "https://sot.internal/sites/site-001"),
        ("PATCH", "https://sot.internal/sites/site-001"),
        ("GET", "https://sot.internal/actions/port-admin"),
        ("GET", "https://sot.internal/actions/poe-toggle"),
        ("GET", "https://sot.internal/actions/port-bounce"),
        ("GET", "https://sot.internal/actions/delete"),
        ("GET", "https://sot.internal/api/cmd/run"),
        ("GET", "https://sot.internal/sites/site-001/ports/p1?action=disable"),
        ("GET", "https://sot.internal/sites/site-001/ports/p1?cmd=poe"),
    ],
)
def test_read_only_guardrail_blocks_mutating_requests_without_calling_transport(
    method: str, url: str
) -> None:
    transport_called = False

    def forbidden_transport(m: str, u: str) -> str:
        nonlocal transport_called
        transport_called = True
        return "<html></html>"

    scraper = HtmlScraperSoTClient("https://sot.internal", transport=forbidden_transport)
    with pytest.raises(ReadOnlyViolationError):
        scraper.request(method, url)
    assert not transport_called

    with pytest.raises(ReadOnlyViolationError):
        validate_read_only_request(method, url)


def test_batch_extractor_snapshots_resume_and_retry(tmp_path: Path) -> None:
    calls: list[str] = []
    transient_failures_remaining = {"site-002": 2}

    class FlakyCountingClient(FixtureSoTClient):
        def get_site(self, site_id: str) -> Site:
            calls.append(site_id)
            if transient_failures_remaining.get(site_id, 0) > 0:
                transient_failures_remaining[site_id] -= 1
                raise ConnectionError(f"Transient connection reset for {site_id}")
            return super().get_site(site_id)

    sleep_delays: list[float] = []
    client = FlakyCountingClient(num_sites=4)
    store = SnapshotStore(tmp_path / "snapshots")

    extractor = BatchExtractor(
        client,
        snapshot_store=store,
        sites_per_batch=2,
        request_delay_seconds=0.1,
        max_retries=3,
        backoff_seconds=0.05,
        sleep_fn=sleep_delays.append,
    )

    # Extract only the first batch (sites 1 and 2)
    batch_iter = extractor.iter_batches()
    first_batch = next(batch_iter)
    assert [s.site_id for s in first_batch] == ["site-001", "site-002"]
    assert store.completed_site_ids() == {"site-001", "site-002"}
    assert store.is_completed("site-001")
    assert store.is_completed("site-002")
    assert not store.is_completed("site-003")

    # site-002 failed twice before succeeding on 3rd try; polite delay + 2 backoff sleeps
    assert calls == ["site-001", "site-002", "site-002", "site-002"]
    assert sleep_delays == [0.1, 0.05, 0.1]

    # Resume extraction: site-001 and site-002 must not be re-fetched from the client
    calls.clear()
    all_sites = extractor.extract_all(resume=True)
    assert [s.site_id for s in all_sites] == [
        "site-001",
        "site-002",
        "site-003",
        "site-004",
    ]
    assert calls == ["site-003", "site-004"]
    assert len(store.load_all_sites()) == 4
