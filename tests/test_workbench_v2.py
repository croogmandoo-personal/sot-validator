"""HTTP and HTML tests for the workbench topology map and switch faceplate."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import html
import json
import re
import threading
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.topology.device_types import DeviceTypeCatalog
from sot_validator.topology.graph import TopologyGraphBuilder
from sot_validator.workbench import WorkbenchState, create_workbench_server, render_workbench_html


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
                equipment_id="eq-mystery-01",
                site_id="site-001",
                name="unknown-box-99",
                category=EquipmentCategory.OTHER,
            ),
        ],
    )


@contextmanager
def _live(state: WorkbenchState) -> Any:
    server = create_workbench_server(state, host="127.0.0.1", port=0)
    host, port = server.server_address[:2]
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base_url, server, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def _http_get_json(url: str) -> tuple[int, dict[str, Any], str]:
    req = Request(url, method="GET")
    try:
        with urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return resp.status, body, resp.headers.get("Content-Type", "")
    except HTTPError as err:
        body = json.loads(err.read().decode("utf-8"))
        return err.code, body, err.headers.get("Content-Type", "")


def _http_post_json(url: str, payload: Any) -> tuple[int, dict[str, Any]]:
    req = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


def _http_get_text(url: str) -> tuple[int, str, str]:
    req = Request(url, method="GET")
    with urlopen(req, timeout=5) as resp:
        return resp.status, resp.headers.get("Content-Type", ""), resp.read().decode("utf-8")


def _element_by_id(page: str, tag: str, element_id: str) -> str:
    pattern = re.compile(
        rf'<{tag}\b[^>]*\bid="{re.escape(element_id)}"[^>]*>',
        re.IGNORECASE,
    )
    match = pattern.search(page)
    assert match is not None, element_id
    token = re.compile(rf"</?{tag}\b[^>]*>", re.IGNORECASE)
    depth = 0
    for tok in token.finditer(page, match.start()):
        snippet = tok.group(0)
        if snippet.startswith("</"):
            depth -= 1
            if depth == 0:
                return page[match.start() : tok.end()]
        elif snippet.endswith("/>"):
            if depth == 0:
                return page[match.start() : tok.end()]
        else:
            depth += 1
    raise AssertionError(f"unclosed {tag}#{element_id}")


def _faceplate_ports(face_html: str) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    for match in re.finditer(
        r'<button type="button" class="([^"]*)" data-port-id="([^"]*)" '
        r'data-port-name="([^"]*)"[^>]*>(.*?)</button>',
        face_html,
        re.DOTALL,
    ):
        badge = re.search(
            r'class="faceplate-poe-badge">([^<]*)</span>',
            match.group(4),
        )
        ports.append(
            {
                "classes": match.group(1).split(),
                "port_id": html.unescape(match.group(2)),
                "name": html.unescape(match.group(3)),
                "badge": html.unescape(badge.group(1)) if badge else None,
            }
        )
    return ports


def _fill_class(classes: list[str]) -> str:
    fills = [
        name
        for name in classes
        if name in {"faceplate-stale", "faceplate-uplink", "faceplate-up", "faceplate-down"}
    ]
    assert len(fills) == 1, classes
    return fills[0]


def _topo_nodes(svg: str) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    for match in re.finditer(
        r'<g class="topo-node" data-node-id="([^"]*)" data-node-type="([^"]*)"[^>]*>'
        r".*?<text[^>]*>([^<]*)</text>",
        svg,
        re.DOTALL,
    ):
        found.append(tuple(html.unescape(part) for part in match.groups()))  # type: ignore[misc]
    return found


def _expected_topology(state: WorkbenchState) -> dict[str, Any]:
    graph = TopologyGraphBuilder().build(state.site, state.results)
    payload = graph.to_dict()
    payload["mermaid"] = graph.to_mermaid()
    return payload


def _site_with(*devices: NetworkDevice, equipment: list[Equipment] | None = None) -> Site:
    return Site(
        site_id="site-lab",
        name="Faceplate Lab",
        devices=list(devices),
        equipment=list(equipment or []),
    )


def test_get_api_topology_matches_builder_and_does_not_mutate() -> None:
    state = WorkbenchState(_sample_site())
    before_site = state.site.to_dict()
    before_audit = len(state.store.list_audit_log(site_id=state.site.site_id, limit=1000))
    expected = _expected_topology(state)
    with _live(state) as (base_url, server, live_state):
        status, payload, _content_type = _http_get_json(f"{base_url}/api/topology")
    assert status == 200
    assert payload == expected
    assert "total_nodes" in payload["summary_counts"]
    assert "total_edges" in payload["summary_counts"]
    assert payload["summary_counts"]["total_nodes"] == len(payload["nodes"])
    assert payload["summary_counts"]["total_edges"] == len(payload["edges"])
    assert live_state.site.to_dict() == before_site
    assert (
        len(live_state.store.list_audit_log(site_id=live_state.site.site_id, limit=1000))
        == before_audit
    )


def test_topology_reflects_hostname_patch_and_json_content_type() -> None:
    state = WorkbenchState(_sample_site())
    state.apply_item_patch(
        {
            "target_type": "NetworkDevice",
            "target_id": "dev-core-01",
            "hostname": "sw-renamed-01",
        }
    )
    with _live(state) as (base_url, server, _live_state):
        status, payload, content_type = _http_get_json(f"{base_url}/api/topology")
    assert status == 200
    assert "application/json" in content_type
    device_node = next(node for node in payload["nodes"] if node["node_id"] == "dev-core-01")
    assert device_node["label"] == "sw-renamed-01"
    assert "sw-renamed-01" in payload["mermaid"]
    assert payload == _expected_topology(state)


def test_topology_tab_renders_every_node_and_edge() -> None:
    state = WorkbenchState(_sample_site())
    graph_payload = _expected_topology(state)
    with _live(state) as (base_url, server, _live_state):
        status, _content_type, page = _http_get_text(f"{base_url}/")
    assert status == 200
    assert 'data-tab="tab-topology"' in page
    assert 'id="tab-topology" class="tab-panel"' in page
    assert 'id="tab-topology" class="tab-panel active"' not in page
    panel = _element_by_id(page, "section", "tab-topology")
    assert 'id="topology-svg"' in panel
    assert 'id="topology-mermaid"' in panel
    svg = _element_by_id(panel, "svg", "topology-svg")
    nodes = _topo_nodes(svg)
    assert nodes == [
        (node["node_id"], node["node_type"], node["label"]) for node in graph_payload["nodes"]
    ]
    relations = [
        html.unescape(value)
        for value in re.findall(r'class="topo-edge" data-relation="([^"]*)"', svg)
    ]
    assert relations == [edge["relation"] for edge in graph_payload["edges"]]
    pre = re.search(r'<pre id="topology-mermaid">(.*?)</pre>', panel, re.DOTALL)
    assert pre is not None
    assert "flowchart LR" in pre.group(1)
    assert html.unescape(pre.group(1)) == graph_payload["mermaid"]


def test_topology_labels_are_escaped_and_page_has_no_external_script() -> None:
    state = WorkbenchState(_sample_site())
    hostile = "</text><script>alert(1)</script>"
    state.apply_item_patch(
        {
            "target_type": "NetworkDevice",
            "target_id": "dev-core-01",
            "hostname": hostile,
        }
    )
    page = render_workbench_html(state)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    svg = _element_by_id(page, "svg", "topology-svg")
    pre = re.search(r'<pre id="topology-mermaid">(.*?)</pre>', page, re.DOTALL)
    assert pre is not None
    assert "&lt;script&gt;" in svg
    assert "&lt;script&gt;" in pre.group(1)
    assert html.unescape(pre.group(1)).find(hostile) != -1
    assert "fetch('/api/topology')" in page
    assert "<script src" not in page


def test_topology_script_wires_existing_editors_and_highlight() -> None:
    page = render_workbench_html(WorkbenchState(_sample_site()))
    script = page.split("function escapeHtml", 1)[1]
    for snippet in (
        "openEditModal('NetworkDevice'",
        "openEditModal('Equipment'",
        "openEditModal('IPAddress'",
        "switchTab('tab-devices-ports')",
        "switchTab('tab-vlans')",
        "pm-port-name",
        "pm-range-spec",
        "vlan-id-input",
        "topo-selected",
        "nodeType === 'site' || nodeType === 'subnet'",
        "ev.key !== 'Enter'",
        "ev.key !== ' '",
        "scrollIntoView",
        "Topology map could not be refreshed.",
        "faceplate-selected",
        'role="button"',
        'tabindex="0"',
    ):
        assert snippet in script
    assert re.search(r"\.topo-node\.topo-selected\s*\{[^}]*outline\s*:", page)
    assert page.count('id="port-manager-form"') == 1


def test_sample_faceplate_shows_link_and_poe_for_core_switch() -> None:
    state = WorkbenchState(_sample_site())
    with _live(state) as (base_url, server, _live_state):
        _status, _content_type, page = _http_get_text(f"{base_url}/")
    devices_tab = _element_by_id(page, "section", "tab-devices-ports")
    assert 'id="device-port-grids"' in devices_tab
    assert 'id="port-manager-form"' in devices_tab
    face = _element_by_id(devices_tab, "div", "switch-faceplate")
    assert 'data-rows="2"' in face
    assert 'data-device-id="dev-core-01"' in face
    assert 'data-faceplate-columns="1"' in face
    ports = _faceplate_ports(face)
    assert [port["name"] for port in ports] == ["1:1", "1:2"]
    up = ports[0]
    down = ports[1]
    assert _fill_class(up["classes"]) == "faceplate-up"
    assert up["badge"] == "delivering"
    assert _fill_class(down["classes"]) == "faceplate-down"
    assert down["badge"] == "auto"
    assert 'aria-label="1:1, Up, PoE delivering"' in face
    assert 'title="1:1, Up, PoE delivering"' in face
    assert 'aria-label="1:2, Down, PoE auto"' in face
    assert 'minmax(5rem, max-content)' in face
    assert '<strong id="faceplate-hostname">sw-core-01</strong>' in devices_tab
    legend = re.search(r'<p class="faceplate-legend">(.*?)</p>', devices_tab)
    assert legend is not None
    for word in ("Up", "Down", "Uplink", "Stale", "PoE"):
        assert word in legend.group(1)


def test_faceplate_stale_wins_over_uplink_and_link_state() -> None:
    state = WorkbenchState(_sample_site())
    state.apply_item_patch(
        {
            "target_type": "Equipment",
            "target_id": "eq-win-01",
            "pinned_classification": ValidationClassification.STALE_LIKELY_UNUSED.value,
        }
    )
    pinned = next(result for result in state.results if result.item_id == "eq-win-01")
    assert pinned.classification == ValidationClassification.STALE_LIKELY_UNUSED
    page = render_workbench_html(state)
    ports = _faceplate_ports(_element_by_id(page, "div", "switch-faceplate"))
    first = next(port for port in ports if port["name"] == "1:1")
    assert _fill_class(first["classes"]) == "faceplate-stale"
    assert "faceplate-up" not in first["classes"]

    uplink_only = NetworkDevice(
        device_id="dev-sw",
        site_id="site-lab",
        hostname="sw-edge",
        role="switch",
        vendor="Acme",
        model="Plain",
        ports=[
            Port(
                port_id="dev-sw:Uplink1",
                device_id="dev-sw",
                name="Uplink1",
                admin_status="up",
                oper_status="up",
                poe_status=None,
            )
        ],
    )
    uplink_page = render_workbench_html(WorkbenchState(_site_with(uplink_only)))
    uplink_port = _faceplate_ports(_element_by_id(uplink_page, "div", "switch-faceplate"))[0]
    assert _fill_class(uplink_port["classes"]) == "faceplate-uplink"
    assert "faceplate-up" not in uplink_port["classes"]

    stale_eq = Equipment(
        equipment_id="eq-stale",
        site_id="site-lab",
        name="stale-phone",
        category=EquipmentCategory.OTHER,
        connected_ports=["dev-sw:Uplink1"],
    )
    stale_switch = NetworkDevice(
        device_id="dev-sw",
        site_id="site-lab",
        hostname="sw-edge",
        role="switch",
        vendor="Acme",
        model="Plain",
        ports=[
            Port(
                port_id="dev-sw:Uplink1",
                device_id="dev-sw",
                name="Uplink1",
                admin_status="up",
                oper_status="up",
                poe_status="off",
                connected_device_id="eq-stale",
            )
        ],
    )
    stale_state = WorkbenchState(_site_with(stale_switch, equipment=[stale_eq]))
    stale_state.apply_item_patch(
        {
            "target_type": "Equipment",
            "target_id": "eq-stale",
            "pinned_classification": "Stale / Likely Unused",
        }
    )
    stale_page = render_workbench_html(stale_state)
    stale_port = _faceplate_ports(_element_by_id(stale_page, "div", "switch-faceplate"))[0]
    assert _fill_class(stale_port["classes"]) == "faceplate-stale"
    assert stale_port["badge"] is None

    router = NetworkDevice(
        device_id="dev-rtr",
        site_id="site-lab",
        hostname="edge-gw",
        role="router",
        vendor="Ubiquiti",
        model="UniFi Gateway",
    )
    access = NetworkDevice(
        device_id="dev-sw",
        site_id="site-lab",
        hostname="sw-access",
        role="switch",
        vendor="Acme",
        model="Plain",
        ports=[
            Port(
                port_id="dev-sw:1:48",
                device_id="dev-sw",
                name="1:48",
                admin_status="up",
                oper_status="up",
                poe_status="off",
                connected_device_id="dev-rtr",
            )
        ],
    )
    link_state = WorkbenchState(_site_with(access, router))
    graph = TopologyGraphBuilder().build(link_state.site, link_state.results)
    assert any(
        edge.relation == "uplink_to" and edge.port_name == "1:48"
        for edge in graph.edges
    )
    link_page = render_workbench_html(link_state)
    link_port = _faceplate_ports(_element_by_id(link_page, "div", "switch-faceplate"))[0]
    assert link_port["name"] == "1:48"
    assert _fill_class(link_port["classes"]) == "faceplate-uplink"
    assert "faceplate-up" not in link_port["classes"]
    assert link_port["badge"] is None


def test_faceplate_columns_follow_live_ports_and_extreme_templates() -> None:
    catalog = DeviceTypeCatalog()

    def _render_device(device: NetworkDevice) -> str:
        return render_workbench_html(WorkbenchState(_site_with(device)))

    page_24 = _render_device(
        catalog.instantiate_device(
            "extreme-exos-24p",
            device_id="dev-24",
            site_id="site-lab",
            hostname="sw-24",
        )
    )
    face_24 = _element_by_id(page_24, "div", "switch-faceplate")
    assert 'data-faceplate-columns="12"' in face_24
    assert 'data-template-ports="24"' in face_24
    assert len(_faceplate_ports(face_24)) == 24

    page_48 = _render_device(
        catalog.instantiate_device(
            "extreme-exos-48p",
            device_id="dev-48",
            site_id="site-lab",
            hostname="sw-48",
        )
    )
    face_48 = _element_by_id(page_48, "div", "switch-faceplate")
    assert 'data-faceplate-columns="24"' in face_48
    assert 'data-template-ports="48"' in face_48
    assert len(_faceplate_ports(face_48)) == 48

    page_voss = _render_device(
        catalog.instantiate_device(
            "extreme-voss-core",
            device_id="dev-voss",
            site_id="site-lab",
            hostname="sw-voss",
        )
    )
    face_voss = _element_by_id(page_voss, "div", "switch-faceplate")
    assert 'data-faceplate-columns="24"' in face_voss
    assert 'data-template-ports="48"' in face_voss
    assert len(_faceplate_ports(face_voss)) == 48

    plain = NetworkDevice(
        device_id="dev-plain",
        site_id="site-lab",
        hostname="plain-sw",
        role="switch",
        vendor="Acme",
        model="Widget",
        ports=[
            Port(port_id=f"dev-plain:{name}", device_id="dev-plain", name=name, oper_status="down")
            for name in ("a", "b", "c")
        ],
    )
    face_plain = _element_by_id(_render_device(plain), "div", "switch-faceplate")
    assert 'data-faceplate-columns="2"' in face_plain
    assert "data-template-ports" not in face_plain
    assert len(_faceplate_ports(face_plain)) == 3

    short = catalog.instantiate_device(
        "extreme-exos-48p",
        device_id="dev-short",
        site_id="site-lab",
        hostname="sw-short",
        port_count=2,
    )
    face_short = _element_by_id(_render_device(short), "div", "switch-faceplate")
    assert 'data-template-ports="48"' in face_short
    assert 'data-faceplate-columns="1"' in face_short
    assert len(_faceplate_ports(face_short)) == 2

    folded = NetworkDevice(
        device_id="dev-fold",
        site_id="site-lab",
        hostname="sw-fold",
        role="switch",
        vendor="EXTREME NETWORKS",
        model="summit x440-g2-24p",
        ports=[
            Port(port_id="dev-fold:1:1", device_id="dev-fold", name="1:1", oper_status="down"),
            Port(port_id="dev-fold:1:2", device_id="dev-fold", name="1:2", oper_status="down"),
        ],
    )
    face_folded = _element_by_id(_render_device(folded), "div", "switch-faceplate")
    assert 'data-template-ports="24"' in face_folded
    assert len(_faceplate_ports(face_folded)) == 2

    empty = NetworkDevice(
        device_id="dev-empty",
        site_id="site-lab",
        hostname="sw-empty",
        role="switch",
        vendor="Acme",
        model="Bare",
        ports=[],
    )
    face_empty = _element_by_id(_render_device(empty), "div", "switch-faceplate")
    assert "No ports provisioned" in face_empty
    assert _faceplate_ports(face_empty) == []


def test_faceplate_colors_and_blocked_scan_routes() -> None:
    state = WorkbenchState(_sample_site())
    page = render_workbench_html(state)
    for selector, color in (
        (".faceplate-up", "#10b981"),
        (".faceplate-down", "#64748b"),
        (".faceplate-uplink", "#4f46e5"),
        (".faceplate-stale", "#e11d48"),
        (".faceplate-poe-badge", "#f59e0b"),
    ):
        assert re.search(
            rf"{re.escape(selector)}\s*\{{[^}}]*{re.escape(color)}",
            page,
        ), selector
    for path in ("/api/discover", "/api/ports/auto-map", "/api/diff"):
        assert path not in page

    with _live(state) as (base_url, server, _live_state):
        discover_status, discover_body = _http_post_json(f"{base_url}/api/discover", {})
        automap_status, automap_body = _http_post_json(
            f"{base_url}/api/ports/auto-map", {}
        )
        diff_status, diff_body, _content_type = _http_get_json(f"{base_url}/api/diff")
    assert discover_status == 404 and discover_body["status"] == "error"
    assert automap_status == 404 and automap_body["status"] == "error"
    assert diff_status == 404 and diff_body["status"] == "error"


def test_stale_result_name_marks_matching_port() -> None:
    device = NetworkDevice(
        device_id="dev-sw",
        site_id="site-lab",
        hostname="sw-edge",
        role="switch",
        vendor="Acme",
        model="Plain",
        ports=[
            Port(
                port_id="dev-sw:1:3",
                device_id="dev-sw",
                name="1:3",
                oper_status="up",
            )
        ],
    )
    state = WorkbenchState(_site_with(device))
    state.results.append(
        ValidationResult(
            item_type="Port",
            item_id="not-the-port",
            site_id="site-lab",
            name="sw-edge:1:3",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.4,
        )
    )
    page = render_workbench_html(state)
    port = _faceplate_ports(_element_by_id(page, "div", "switch-faceplate"))[0]
    assert _fill_class(port["classes"]) == "faceplate-stale"


def _box_edge(src: tuple[int, int], dst: tuple[int, int]) -> tuple[int, int, int, int]:
    """Mirror the page's edge endpoints: the stroke stops on the node box."""
    node_w, node_h = 200, 56
    sx, sy = src
    dx, dy = dst
    sy_mid, dy_mid = sy + node_h // 2, dy + node_h // 2
    sx_mid, dx_mid = sx + node_w // 2, dx + node_w // 2
    if sx + node_w <= dx:
        return (sx + node_w, sy_mid, dx, dy_mid)
    if dx + node_w <= sx:
        return (sx, sy_mid, dx + node_w, dy_mid)
    if sy + node_h <= dy:
        return (sx_mid, sy + node_h, dx_mid, dy)
    if dy + node_h <= sy:
        return (sx_mid, sy, dx_mid, dy + node_h)
    return (sx_mid, sy_mid, dx_mid, dy_mid)


def test_map_and_faceplate_stay_readable() -> None:
    page = render_workbench_html(WorkbenchState(_sample_site()))
    svg = _element_by_id(page, "svg", "topology-svg")
    width = re.search(r'\bwidth="(\d+)"', svg)
    height = re.search(r'\bheight="(\d+)"', svg)
    assert width is not None and height is not None
    assert f'style="width:{width.group(1)}px;height:{height.group(1)}px"' in svg
    assert 'role="button"' in svg
    assert 'tabindex="0"' in svg
    assert 'class="topo-node-box"' in svg
    assert 'height="56"' in svg
    node_id, node_type, label = _topo_nodes(svg)[0]
    access = html.escape(f"{node_type} {label}", quote=True)
    assert f'aria-label="{access}"' in svg
    positions = {
        html.unescape(match.group(1)): (int(match.group(2)), int(match.group(3)))
        for match in re.finditer(
            r'data-node-id="([^"]*)"[^>]*transform="translate\((\d+),(\d+)\)"',
            svg,
        )
    }
    assert node_id in positions
    for edge in _expected_topology(WorkbenchState(_sample_site()))["edges"]:
        x1, y1, x2, y2 = _box_edge(positions[edge["source_id"]], positions[edge["target_id"]])
        assert f'x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"' in svg
    panel = _element_by_id(page, "section", "tab-topology")
    assert "Mermaid source" in panel
    assert 'class="topology-scroll"' in panel
    svg_rule = re.search(r"#topology-svg\s*\{([^}]*)\}", page)
    assert svg_rule is not None
    assert "width: 100%" not in svg_rule.group(1)
    scroll_rule = re.search(r"\.topology-scroll\s*\{([^}]*)\}", page)
    assert scroll_rule is not None and "overflow-x: auto" in scroll_rule.group(1)
    face_rule = re.search(r"#switch-faceplate\s*\{([^}]*)\}", page)
    assert face_rule is not None and "overflow-x: auto" in face_rule.group(1)
    tabs_rule = re.search(r"\.tabs\s*\{([^}]*)\}", page)
    assert tabs_rule is not None and "flex-wrap: wrap" in tabs_rule.group(1)
    up_rule = re.search(r"\.faceplate-up\s*\{([^}]*)\}", page)
    assert up_rule is not None
    assert "#10b981" in up_rule.group(1)
    assert "#0f172a" in up_rule.group(1)
    port_rule = re.search(r"\.faceplate-port\s*\{([^}]*)\}", page)
    assert port_rule is not None
    assert "flex-direction: column" in port_rule.group(1)
    assert "min-width: 5rem" in port_rule.group(1)
    edge_rule = re.search(r"\.topo-edge\s*\{([^}]*)\}", page)
    assert edge_rule is not None and "var(--insufficient)" in edge_rule.group(1)
    selected_rule = re.search(r"\.topo-node\.topo-selected\s*\{([^}]*)\}", page)
    assert selected_rule is not None
    assert "outline" in selected_rule.group(1)
    assert "var(--accent)" in selected_rule.group(1)
