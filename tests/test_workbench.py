"""Unit and HTTP integration tests for sot_validator.workbench."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
import json
import threading
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from sot_validator.curation.store import CurationStore, ItemEditPatch
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)
from sot_validator.workbench import (
    WorkbenchRequestHandler,
    WorkbenchServer,
    WorkbenchState,
    create_workbench_server,
    render_workbench_html,
)


def _sample_site() -> Site:
    now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    return Site(
        site_id="site-001",
        name="SF HQ Campus",
        address="100 Market St, San Francisco, CA",
        contact_info="netops@example.com",
        rooms=["MDF-1", "IDF-2"],
        devices=[
            NetworkDevice(
                device_id="dev-core-01",
                site_id="site-001",
                hostname="sw-core-01",
                management_ip="10.1.1.2",
                vendor="Extreme Networks",
                model="Summit X460-G2-48p",
                role="switch",
                last_seen=now,
                ports=[
                    Port(
                        port_id="dev-core-01:1:1",
                        device_id="dev-core-01",
                        name="1:1",
                        admin_status="up",
                        oper_status="up",
                        poe_status="delivering",
                        connected_device_id="eq-win-01",
                        connected_mac="00:11:22:33:44:55",
                        vlan_id="10",
                    ),
                    Port(
                        port_id="dev-core-01:1:2",
                        device_id="dev-core-01",
                        name="1:2",
                        admin_status="up",
                        oper_status="down",
                        poe_status="auto",
                        vlan_id="10",
                    ),
                ],
            )
        ],
        vlans=[
            VLAN(
                vlan_id="10",
                site_id="site-001",
                name="Servers",
                subnet_id="sub-10",
                cidr="10.1.10.0/24",
                gateway="10.1.10.1",
            )
        ],
        subnets=[
            Subnet(
                subnet_id="sub-10",
                site_id="site-001",
                cidr="10.1.10.0/24",
                vlan_id="10",
                gateway="10.1.10.1",
                name="Servers",
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.1.10.50",
                subnet_id="sub-10",
                assigned_object_type="Equipment",
                assigned_object_id="eq-win-01",
                arp_mac="00:11:22:33:44:55",
                arp_last_seen=now,
                arp_source_device_id="dev-core-01",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-win-01",
                site_id="site-001",
                name="win-app-01",
                category=EquipmentCategory.VM,
                assigned_ips=["10.1.10.50"],
                connected_ports=["dev-core-01:1:1"],
                power_state="poweredOn",
                last_seen=now,
            ),
            Equipment(
                equipment_id="eq- mystery-01".replace(" ", ""),
                site_id="site-001",
                name="unknown-box-99",
                category=EquipmentCategory.OTHER,
            ),
        ],
    )


@pytest.fixture()
def workbench_state() -> WorkbenchState:
    return WorkbenchState(_sample_site())


@pytest.fixture()
def live_workbench(
    workbench_state: WorkbenchState,
) -> Iterator[tuple[str, WorkbenchServer, WorkbenchState]]:
    server = create_workbench_server(workbench_state, host="127.0.0.1", port=0)
    host, port = server.server_address[:2]
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base_url, server, workbench_state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def _http_get_json(url: str) -> tuple[int, dict[str, Any]]:
    req = Request(url, method="GET")
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


def _http_post_json(
    url: str, payload: Any, *, raw_body: bytes | None = None
) -> tuple[int, dict[str, Any]]:
    data = raw_body if raw_body is not None else json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


def test_workbench_state_init_and_payload(workbench_state: WorkbenchState) -> None:
    payload = workbench_state.get_state_payload()
    assert payload["site"]["site_id"] == "site-001"
    assert len(payload["site"]["devices"]) == 1
    assert len(payload["site"]["equipment"]) == 2
    assert len(payload["results"]) == 4  # 1 device + 2 equipment + 1 IP
    assert len(payload["templates"]) >= 7

    summary = payload["summary"]
    assert summary["total_devices"] == 1
    assert summary["total_ports"] == 2
    assert summary["active_ports"] == 1
    assert summary["poe_ports"] == 2
    assert summary["total_vlans"] == 1
    assert summary["total_subnets"] == 1
    assert summary["total_ips"] == 1
    assert summary["total_equipment"] == 2
    assert sum(summary["classification_counts"].values()) == 4

    vlan_summaries = payload["vlan_subnet_summary"]
    assert len(vlan_summaries) == 1
    assert vlan_summaries[0]["vlan_id"] == "10"
    assert vlan_summaries[0]["cidr"] == "10.1.10.0/24"
    assert vlan_summaries[0]["ip_count"] == 1
    assert vlan_summaries[0]["device_port_count"] == 2
    assert vlan_summaries[0]["equipment_count"] == 1


def test_workbench_state_preserves_initial_results_when_supplied() -> None:
    site = _sample_site()
    custom_signal = ValidationSignal(
        signal_type=SignalType.SNMP_API_REACHABILITY,
        status=SignalStatus.ACTIVE,
        details="APC SNMP PowerNet-MIB healthy",
    )
    initial_res = ValidationResult(
        item_type="Equipment",
        item_id="eq-mystery-01",
        site_id="site-001",
        name="unknown-box-99",
        classification=ValidationClassification.CONFIRMED_ACTIVE,
        confidence=0.92,
        signals=[custom_signal],
        rationale="Active via SNMP",
    )
    state = WorkbenchState(site, initial_results=[initial_res])
    mystery_res = next(
        r for r in state.results if r.item_id == "eq-mystery-01"
    )
    assert mystery_res.classification == ValidationClassification.CONFIRMED_ACTIVE


def test_api_health_and_state(
    live_workbench: tuple[str, WorkbenchServer, WorkbenchState],
) -> None:
    base_url, _, _ = live_workbench
    status_health, health_data = _http_get_json(f"{base_url}/api/health")
    assert status_health == 200
    assert health_data == {"status": "ok"}

    status_state, state_data = _http_get_json(f"{base_url}/api/state")
    assert status_state == 200
    assert state_data["site"]["site_id"] == "site-001"
    assert len(state_data["templates"]) >= 7
    assert isinstance(state_data["results"], list)
    assert isinstance(state_data["vlan_subnet_summary"], list)
    assert isinstance(state_data["audit_log"], list)


def test_api_items_patch_rename_category_notes_pin_and_delete(
    live_workbench: tuple[str, WorkbenchServer, WorkbenchState],
) -> None:
    base_url, _, state = live_workbench

    # Patch equipment: rename, change category to UPS, set room, VLAN, notes, and pin classification
    status, data = _http_post_json(
        f"{base_url}/api/items/patch",
        {
            "target_type": "Equipment",
            "target_id": "eq-mystery-01",
            "name": "apc-ups-idf2-01",
            "category": "ups",
            "room": "IDF-2",
            "vlan_id": "10",
            "notes": "Verified APC Smart-UPS in IDF-2 rack",
            "pinned_classification": "Confirmed Active",
            "actor": "netadmin",
            "reason": "Physical walkthrough verification",
        },
    )
    assert status == 200
    assert data["status"] == "ok"
    assert data["audit_entry"]["action"] == "UPSERT_PATCH"
    assert data["audit_entry"]["actor"] == "netadmin"
    assert data["audit_entry"]["target_id"] == "eq-mystery-01"

    eq_list = data["state"]["site"]["equipment"]
    patched_eq = next(e for e in eq_list if e["equipment_id"] == "eq-mystery-01")
    assert patched_eq["name"] == "apc-ups-idf2-01"
    assert patched_eq["category"] == "ups"

    res_list = data["state"]["results"]
    patched_res = next(r for r in res_list if r["item_id"] == "eq-mystery-01")
    assert patched_res["name"] == "apc-ups-idf2-01"
    assert patched_res["classification"] == "Confirmed Active"
    assert patched_res["confidence"] == 1.0
    assert "Verified APC Smart-UPS in IDF-2 rack" in (patched_res["rationale"] or "")

    # Also test direct ItemEditPatch instance on WorkbenchState.apply_item_patch
    direct_entry = state.apply_item_patch(
        ItemEditPatch(
            target_type="NetworkDevice",
            target_id="dev-core-01",
            hostname="sw-core-mdf1",
            role="l3_switch",
            room="MDF-1",
        ),
        actor="architect",
        reason="Promoted to L3 core switch",
    )
    assert direct_entry.target_id == "dev-core-01"
    assert state.site.devices[0].hostname == "sw-core-mdf1"
    assert state.site.devices[0].role == "l3_switch"

    # Delete item via POST /api/items/patch with deleted=True
    del_status, del_data = _http_post_json(
        f"{base_url}/api/items/patch",
        {
            "target_type": "Equipment",
            "target_id": "eq-mystery-01",
            "deleted": True,
            "actor": "netadmin",
            "reason": "Decommissioned unit",
        },
    )
    assert del_status == 200
    assert del_data["audit_entry"]["action"] == "DELETE_ITEM"
    remaining_ids = [
        e["equipment_id"] for e in del_data["state"]["site"]["equipment"]
    ]
    assert "eq-mystery-01" not in remaining_ids


def test_api_create_device_from_template_and_custom(
    live_workbench: tuple[str, WorkbenchServer, WorkbenchState],
) -> None:
    base_url, _, state = live_workbench

    # Instantiate a 24-port Extreme switch from template (auto device_id from hostname)
    status, data = _http_post_json(
        f"{base_url}/api/devices",
        {
            "hostname": "sw-idf2-access-01",
            "template_id": "extreme-exos-24p",
            "management_ip": "10.1.10.12",
            "default_vlan_id": "10",
            "actor": "netops",
            "reason": "Added IDF-2 access switch",
        },
    )
    assert status in (200, 201)
    assert data["status"] == "ok"
    created_dev = data["device"]
    assert created_dev["device_id"] == "dev-sw-idf2-access-01"
    assert created_dev["hostname"] == "sw-idf2-access-01"
    assert created_dev["vendor"] == "Extreme Networks"
    assert created_dev["role"] == "switch"
    assert len(created_dev["ports"]) == 24
    assert created_dev["ports"][0]["name"] == "1:1"
    assert created_dev["ports"][0]["vlan_id"] == "10"
    assert created_dev["ports"][0]["poe_status"] == "auto"

    # Instantiate a multi-VLAN router from template with custom port count
    r_status, r_data = _http_post_json(
        f"{base_url}/api/devices",
        {
            "device_id": "dev-rtr-edge-01",
            "hostname": "rtr-edge-01",
            "template_id": "unifi-multi-vlan-router",
            "management_ip": "10.1.10.1",
            "port_count": 4,
            "reason": "Added edge router",
        },
    )
    assert r_status in (200, 201)
    assert r_data["device"]["role"] == "router"
    assert len(r_data["device"]["ports"]) == 4
    assert r_data["device"]["ports"][0]["name"] == "eth1"

    # Verify persistence in CurationStore and /api/state
    custom_devs = state.store._list_custom_devices(site_id="site-001")
    assert any(d.device_id == "dev-sw-idf2-access-01" for d in custom_devs)
    assert any(d.device_id == "dev-rtr-edge-01" for d in custom_devs)


def test_api_upsert_device_ports_single_and_range(
    live_workbench: tuple[str, WorkbenchServer, WorkbenchState],
) -> None:
    base_url, _, _ = live_workbench

    # 1. Single port update on dev-core-01
    status_single, data_single = _http_post_json(
        f"{base_url}/api/devices/ports",
        {
            "device_id": "dev-core-01",
            "name": "1:2",
            "admin_status": "up",
            "oper_status": "up",
            "poe_status": "delivering",
            "vlan_id": "10",
            "connected_mac": "AA-BB-CC-DD-EE-FF",
            "connected_device_id": "eq-mystery-01",
            "actor": "netops",
            "reason": "Patched port 1:2 to eq-mystery-01",
        },
    )
    assert status_single == 200
    assert data_single["status"] == "ok"
    assert len(data_single["ports"]) == 1
    p_1_2 = data_single["ports"][0]
    assert p_1_2["port_id"] == "dev-core-01:1:2"
    assert p_1_2["oper_status"] == "up"
    assert p_1_2["poe_status"] == "delivering"
    assert p_1_2["connected_mac"] == "aa:bb:cc:dd:ee:ff"
    assert p_1_2["connected_device_id"] == "eq-mystery-01"

    # Because eq-mystery-01 now has an active switch port connected to it,
    # re-classification should promote eq-mystery-01 from Insufficient Data to Confirmed Active!
    mystery_res = next(
        r
        for r in data_single["state"]["results"]
        if r["item_id"] == "eq-mystery-01"
    )
    assert mystery_res["classification"] == "Confirmed Active"

    # 2. Range port provisioning (1:3..1:6)
    status_range, data_range = _http_post_json(
        f"{base_url}/api/devices/ports",
        {
            "device_id": "dev-core-01",
            "range_spec": "1:3..1:6",
            "admin_status": "up",
            "oper_status": "down",
            "poe_status": "auto",
            "vlan_id": "10",
            "reason": "Provisioned ports 1:3..1:6",
        },
    )
    assert status_range == 200
    assert len(data_range["ports"]) == 4
    assert [p["name"] for p in data_range["ports"]] == ["1:3", "1:4", "1:5", "1:6"]
    assert len(data_range["audit_entries"]) == 4

    core_dev = next(
        d
        for d in data_range["state"]["site"]["devices"]
        if d["device_id"] == "dev-core-01"
    )
    assert len(core_dev["ports"]) == 6


def test_api_vlans_and_audit_log(
    live_workbench: tuple[str, WorkbenchServer, WorkbenchState],
) -> None:
    base_url, _, _ = live_workbench

    status_vlan, data_vlan = _http_post_json(
        f"{base_url}/api/vlans",
        {
            "vlan_id": "20",
            "name": "Voice_VoIP",
            "subnet_id": "sub-20",
            "cidr": "10.1.20.0/24",
            "gateway": "10.1.20.1",
            "actor": "netops",
            "reason": "Created VoIP VLAN 20 and /24 subnet",
        },
    )
    assert status_vlan in (200, 201)
    assert data_vlan["status"] == "ok"
    assert data_vlan["vlan"]["vlan_id"] == "20"
    assert data_vlan["vlan"]["name"] == "Voice_VoIP"
    assert data_vlan["subnet"] is not None
    assert data_vlan["subnet"]["cidr"] == "10.1.20.0/24"
    assert data_vlan["subnet"]["gateway"] == "10.1.20.1"

    vlan_ids = [v["vlan_id"] for v in data_vlan["state"]["site"]["vlans"]]
    assert "20" in vlan_ids
    subnet_cidrs = [s["cidr"] for s in data_vlan["state"]["site"]["subnets"]]
    assert "10.1.20.0/24" in subnet_cidrs

    # Verify GET /api/audit-log returns the recorded entry
    status_audit, data_audit = _http_get_json(f"{base_url}/api/audit-log?limit=20")
    assert status_audit == 200
    entries = data_audit["audit_log"]
    assert len(entries) >= 1
    last_entry = entries[-1]
    assert last_entry["action"] == "ADD_VLAN"
    assert last_entry["target_type"] == "VLAN"
    assert last_entry["target_id"] == "20"
    assert last_entry["actor"] == "netops"


def test_ui_html_rendering_and_xss_escaping(
    live_workbench: tuple[str, WorkbenchServer, WorkbenchState],
) -> None:
    base_url, _, state = live_workbench

    # Inject a tricky XSS payload into notes to verify HTML and script escaping
    state.apply_item_patch(
        {
            "target_type": "Equipment",
            "target_id": "eq-win-01",
            "notes": '</script><script>alert("xss")</script>',
        }
    )

    req = Request(f"{base_url}/", method="GET")
    with urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        content_type = resp.headers.get("Content-Type", "")
        assert "text/html" in content_type
        html_body = resp.read().decode("utf-8")

    assert "<!DOCTYPE html>" in html_body
    # Required UI sections and DOM hooks
    assert 'id="tab-inventory"' in html_body
    assert 'id="inventory-table"' in html_body
    assert 'id="item-edit-modal"' in html_body
    assert 'id="item-edit-form"' in html_body
    assert 'id="tab-devices-ports"' in html_body
    assert 'id="create-device-form"' in html_body
    assert 'id="port-manager-form"' in html_body
    assert 'id="tab-vlans"' in html_body
    assert 'id="vlan-form"' in html_body
    assert 'id="tab-audit-log"' in html_body
    assert 'id="audit-log-table"' in html_body

    # Built-in templates present in UI
    assert "extreme-exos-48p" in html_body
    assert "unifi-multi-vlan-router" in html_body
    assert "proxmox-ve-host" in html_body

    # API routes wired in JS
    assert "/api/items/patch" in html_body
    assert "/api/devices" in html_body
    assert "/api/devices/ports" in html_body
    assert "/api/vlans" in html_body

    # Verify XSS payload is escaped and raw <script>alert("xss")</script> is not present
    assert '<script>alert("xss")</script>' not in html_body


def test_http_error_handling_bad_request_and_not_found(
    live_workbench: tuple[str, WorkbenchServer, WorkbenchState],
) -> None:
    base_url, _, _ = live_workbench

    # Unknown GET route -> 404
    status_404, data_404 = _http_get_json(f"{base_url}/api/does-not-exist")
    assert status_404 == 404
    assert data_404["status"] == "error"

    # Unknown POST route -> 404
    status_post_404, data_post_404 = _http_post_json(
        f"{base_url}/api/unknown", {"hello": "world"}
    )
    assert status_post_404 == 404
    assert data_post_404["status"] == "error"

    # Malformed JSON -> 400
    status_bad_json, data_bad_json = _http_post_json(
        f"{base_url}/api/items/patch", None, raw_body=b"{not valid json"
    )
    assert status_bad_json == 400
    assert data_bad_json["status"] == "error"

    # Invalid target_type in patch -> 400
    status_bad_patch, data_bad_patch = _http_post_json(
        f"{base_url}/api/items/patch",
        {"target_type": "InvalidType", "target_id": "x"},
    )
    assert status_bad_patch == 400
    assert data_bad_patch["status"] == "error"

    # Missing device in /api/devices/ports -> 404 (or 400)
    status_missing_dev, data_missing_dev = _http_post_json(
        f"{base_url}/api/devices/ports",
        {"device_id": "non-existent-device", "name": "1:1"},
    )
    assert status_missing_dev in (400, 404)
    assert data_missing_dev["status"] == "error"
