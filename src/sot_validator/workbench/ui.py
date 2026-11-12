"""Self-contained interactive single-page HTML5/CSS/JS Workbench UI generator."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import html
import json
import math
from typing import TYPE_CHECKING, Any, Optional

from sot_validator.models import EquipmentCategory, ValidationClassification
from sot_validator.topology.device_types import VALID_DEVICE_ROLES
from sot_validator.topology.graph import TopologyGraph, TopologyGraphBuilder

if TYPE_CHECKING:
    from sot_validator.workbench.server import WorkbenchState

DEFAULT_WORKBENCH_TITLE = "SoT Interactive Network & Inventory Workbench"


def _esc(value: Any) -> str:
    """Escape any value for safe inclusion in HTML text or quoted attributes."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _safe_json_for_script(payload: Any) -> str:
    """Serialize payload to JSON and escape closing script tags and HTML special sequences."""
    raw = json.dumps(payload)
    return (
        raw.replace("</", "<\\/")
        .replace("<!--", "<\\!--")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _badge_class(classification: str) -> str:
    if classification == ValidationClassification.CONFIRMED_ACTIVE.value:
        return "badge-active"
    if classification == ValidationClassification.STALE_LIKELY_UNUSED.value:
        return "badge-stale"
    if classification == ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value:
        return "badge-unreachable"
    return "badge-insufficient"


_STALE_CLASSIFICATION = ValidationClassification.STALE_LIKELY_UNUSED.value
_INACTIVE_POE = frozenset({"", "off", "disabled", "none"})
_TOPO_COLUMN_ORDER: tuple[str, ...] = (
    "site",
    "router",
    "switch",
    "vlan",
    "subnet",
    "port",
    "equipment",
    "ip",
)
_TOPO_COL_WIDTH = 180
_TOPO_ROW_HEIGHT = 56
_TOPO_PAD_X = 24
_TOPO_PAD_Y = 36
# Case-insensitive vendor + model for the three Extreme faceplate templates.
_FACEPLATE_TEMPLATES: tuple[tuple[str, str, str], ...] = (
    ("extreme networks", "summit x440-g2-24p", "24"),
    ("extreme networks", "summit x460-g2-48p", "48"),
    ("extreme networks", "vsp 7400-48y", "48"),
)


def _template_ports_attr(vendor: Any, model: Any) -> Optional[str]:
    """Return 24 or 48 when vendor and model match an Extreme faceplate template."""
    vendor_l = str(vendor or "").strip().lower()
    model_l = str(model or "").strip().lower()
    for known_vendor, known_model, ports in _FACEPLATE_TEMPLATES:
        if vendor_l == known_vendor and model_l == known_model:
            return ports
    return None


def _faceplate_columns(port_count: int) -> int:
    if port_count == 24:
        return 12
    if port_count == 48:
        return 24
    if port_count <= 0:
        return 0
    return math.ceil(port_count / 2)


def _poe_badge_text(poe_status: Any) -> Optional[str]:
    if poe_status is None:
        return None
    text = str(poe_status).strip()
    if text.lower() in _INACTIVE_POE:
        return None
    return text


def _device_node_ids(graph: TopologyGraph, device_id: str) -> set[str]:
    candidates = {device_id, f"router:{device_id}", f"switch:{device_id}"}
    found = {
        node.node_id
        for node in graph.nodes
        if node.node_type in ("router", "switch") and node.node_id in candidates
    }
    return found or ({device_id} if device_id else set())


def _port_is_stale(
    device: Mapping[str, Any],
    port: Mapping[str, Any],
    results: Sequence[Mapping[str, Any]],
    equipment: Sequence[Mapping[str, Any]],
) -> bool:
    hostname = str(device.get("hostname") or "")
    device_id = str(device.get("device_id") or "")
    port_id = str(port.get("port_id") or "")
    port_name = str(port.get("name") or "")
    connected = str(port.get("connected_device_id") or "")
    name_key = f"{hostname}:{port_name}"
    refs = {
        ref
        for ref in (
            port_id,
            f"{device_id}:{port_name}",
            f"{hostname}:{port_name}",
            port_name,
        )
        if ref
    }
    touching_equipment: set[str] = set()
    for eq in equipment:
        connected_ports = eq.get("connected_ports") or []
        if any(ref in connected_ports for ref in refs):
            eq_id = eq.get("equipment_id")
            if eq_id:
                touching_equipment.add(str(eq_id))
    for res in results:
        if res.get("classification") != _STALE_CLASSIFICATION:
            continue
        item_id = str(res.get("item_id") or "")
        if item_id == port_id:
            return True
        if res.get("name") == name_key:
            return True
        if connected and item_id == connected:
            return True
        if item_id in touching_equipment:
            return True
    return False


def _port_is_uplink(
    device: Mapping[str, Any],
    port: Mapping[str, Any],
    graph: TopologyGraph,
) -> bool:
    port_name = str(port.get("name") or "")
    lowered = port_name.lower()
    if "trunk" in lowered or "uplink" in lowered:
        return True
    node_ids = _device_node_ids(graph, str(device.get("device_id") or ""))
    for edge in graph.edges:
        if edge.relation != "uplink_to" or edge.port_name != port_name:
            continue
        if edge.source_id in node_ids or edge.target_id in node_ids:
            return True
    return False


def _faceplate_fill_class(
    device: Mapping[str, Any],
    port: Mapping[str, Any],
    results: Sequence[Mapping[str, Any]],
    equipment: Sequence[Mapping[str, Any]],
    graph: TopologyGraph,
) -> str:
    if _port_is_stale(device, port, results, equipment):
        return "faceplate-stale"
    if _port_is_uplink(device, port, graph):
        return "faceplate-uplink"
    if str(port.get("oper_status") or "").strip().lower() == "up":
        return "faceplate-up"
    return "faceplate-down"


def _render_switch_faceplate(
    site_dict: Mapping[str, Any],
    results: Sequence[Mapping[str, Any]],
    graph: TopologyGraph,
    device_id: Optional[str] = None,
) -> str:
    """Render the two-row switch faceplate for the selected device."""
    devices = list(site_dict.get("devices") or [])
    device: Optional[Mapping[str, Any]] = None
    if device_id:
        device = next((d for d in devices if d.get("device_id") == device_id), None)
    if device is None and devices:
        device = devices[0]
    if device is None:
        return (
            '<div id="switch-faceplate" data-device-id="" data-rows="2" '
            'data-faceplate-columns="0"><em>No ports provisioned</em></div>'
        )

    ports = list(device.get("ports") or [])
    columns = _faceplate_columns(len(ports))
    template_ports = _template_ports_attr(device.get("vendor"), device.get("model"))
    template_attr = (
        f' data-template-ports="{_esc(template_ports)}"' if template_ports else ""
    )
    style_attr = ""
    if columns > 0:
        style_attr = (
            f' style="grid-template-columns: repeat({columns}, minmax(0, 1fr));"'
        )
    equipment = list(site_dict.get("equipment") or [])
    if not ports:
        body = "<em>No ports provisioned</em>"
    else:
        cells: list[str] = []
        for port in ports:
            fill = _faceplate_fill_class(device, port, results, equipment, graph)
            poe = _poe_badge_text(port.get("poe_status"))
            badge = (
                f'<span class="faceplate-poe-badge">{_esc(poe)}</span>' if poe else ""
            )
            cells.append(
                f'<button type="button" class="faceplate-port {fill}" '
                f'data-port-id="{_esc(port.get("port_id"))}" '
                f'data-port-name="{_esc(port.get("name"))}">'
                f"{_esc(port.get('name'))}{badge}</button>"
            )
        body = "".join(cells)
    return (
        f'<div id="switch-faceplate" data-device-id="{_esc(device.get("device_id"))}" '
        f'data-rows="2" data-faceplate-columns="{columns}"{template_attr}{style_attr}>'
        f"{body}</div>"
    )


def _topology_layout(
    graph: TopologyGraph,
) -> tuple[dict[str, tuple[int, int]], int, int]:
    columns: dict[str, list[str]] = {node_type: [] for node_type in _TOPO_COLUMN_ORDER}
    for node in graph.nodes:
        columns.setdefault(node.node_type, []).append(node.node_id)
    positions: dict[str, tuple[int, int]] = {}
    max_rows = 1
    for col_index, node_type in enumerate(_TOPO_COLUMN_ORDER):
        column_ids = columns.get(node_type, [])
        max_rows = max(max_rows, len(column_ids))
        for row_index, node_id in enumerate(column_ids):
            positions[node_id] = (
                _TOPO_PAD_X + col_index * _TOPO_COL_WIDTH,
                _TOPO_PAD_Y + row_index * _TOPO_ROW_HEIGHT,
            )
    width = _TOPO_PAD_X * 2 + len(_TOPO_COLUMN_ORDER) * _TOPO_COL_WIDTH
    height = _TOPO_PAD_Y + max_rows * _TOPO_ROW_HEIGHT + 16
    return positions, width, height


def _render_topology_svg(graph: TopologyGraph) -> str:
    """Render one inline SVG group per node and one line per edge."""
    positions, width, height = _topology_layout(graph)
    lines: list[str] = []
    for edge in graph.edges:
        src = positions.get(edge.source_id, (0, 0))
        dst = positions.get(edge.target_id, (0, 0))
        lines.append(
            f'<line class="topo-edge" data-relation="{_esc(edge.relation)}" '
            f'x1="{src[0]}" y1="{src[1]}" x2="{dst[0]}" y2="{dst[1]}" />'
        )
    groups: list[str] = []
    for node in graph.nodes:
        x, y = positions.get(node.node_id, (0, 0))
        groups.append(
            f'<g class="topo-node" data-node-id="{_esc(node.node_id)}" '
            f'data-node-type="{_esc(node.node_type)}" '
            f'transform="translate({x},{y})">'
            f"<text>{_esc(node.label)}</text></g>"
        )
    return (
        f'<svg id="topology-svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}">'
        f'{"".join(lines)}{"".join(groups)}</svg>'
    )


_WORKBENCH_V2_SCRIPT = """
let TOPOLOGY_GRAPH = JSON.parse(document.getElementById('initial-topology').textContent);
const FACEPLATE_TEMPLATES = __FACEPLATE_TEMPLATES__;
const TOPO_COLUMN_ORDER = ['site', 'router', 'switch', 'vlan', 'subnet', 'port', 'equipment', 'ip'];
const TOPO_COL_WIDTH = 180;
const TOPO_ROW_HEIGHT = 56;
const TOPO_PAD_X = 24;
const TOPO_PAD_Y = 36;

function templatePortsAttr(vendor, model) {
  const v = String(vendor || '').trim().toLowerCase();
  const m = String(model || '').trim().toLowerCase();
  for (let i = 0; i < FACEPLATE_TEMPLATES.length; i++) {
    const row = FACEPLATE_TEMPLATES[i];
    if (v === row[0] && m === row[1]) return row[2];
  }
  return null;
}

function faceplateColumns(portCount) {
  if (portCount === 24) return 12;
  if (portCount === 48) return 24;
  if (!portCount || portCount < 0) return 0;
  return Math.ceil(portCount / 2);
}

function poeBadgeText(poeStatus) {
  if (poeStatus === null || poeStatus === undefined) return '';
  const text = String(poeStatus).trim();
  const lower = text.toLowerCase();
  if (!text || lower === 'off' || lower === 'disabled' || lower === 'none') return '';
  return text;
}

function portIsStale(device, port, results, equipment) {
  const hostname = device.hostname || '';
  const deviceId = device.device_id || '';
  const portId = port.port_id || '';
  const portName = port.name || '';
  const connected = port.connected_device_id || '';
  const nameKey = hostname + ':' + portName;
  const refs = {};
  [portId, deviceId + ':' + portName, hostname + ':' + portName, portName].forEach(ref => {
    if (ref) refs[ref] = true;
  });
  const touching = {};
  (equipment || []).forEach(eq => {
    const connectedPorts = eq.connected_ports || [];
    for (let i = 0; i < connectedPorts.length; i++) {
      if (refs[connectedPorts[i]]) {
        touching[eq.equipment_id] = true;
        break;
      }
    }
  });
  for (let i = 0; i < (results || []).length; i++) {
    const res = results[i];
    if (res.classification !== 'Stale / Likely Unused') continue;
    const itemId = res.item_id || '';
    if (itemId === portId) return true;
    if (res.name === nameKey) return true;
    if (connected && itemId === connected) return true;
    if (touching[itemId]) return true;
  }
  return false;
}

function portIsUplink(device, port, graph) {
  const portName = String(port.name || '');
  const lowered = portName.toLowerCase();
  if (lowered.indexOf('trunk') !== -1 || lowered.indexOf('uplink') !== -1) return true;
  const deviceId = device.device_id || '';
  const ids = {};
  ids[deviceId] = true;
  ids['router:' + deviceId] = true;
  ids['switch:' + deviceId] = true;
  const edges = (graph && graph.edges) || [];
  for (let i = 0; i < edges.length; i++) {
    const edge = edges[i];
    if (edge.relation !== 'uplink_to' || edge.port_name !== portName) continue;
    if (ids[edge.source_id] || ids[edge.target_id]) return true;
  }
  return false;
}

function renderSwitchFaceplate() {
  const site = (WORKBENCH_STATE && WORKBENCH_STATE.site) || {};
  const devices = site.devices || [];
  const sel = document.getElementById('pm-device-id');
  const selectedId = sel ? sel.value : '';
  const device = devices.find(d => d.device_id === selectedId) || devices[0] || null;
  const face = document.getElementById('switch-faceplate');
  if (!face) return;
  if (!device) {
    face.setAttribute('data-device-id', '');
    face.setAttribute('data-rows', '2');
    face.setAttribute('data-faceplate-columns', '0');
    face.removeAttribute('data-template-ports');
    face.innerHTML = '<em>No ports provisioned</em>';
    return;
  }
  const ports = device.ports || [];
  const columns = faceplateColumns(ports.length);
  const templatePorts = templatePortsAttr(device.vendor, device.model);
  face.setAttribute('data-device-id', device.device_id || '');
  face.setAttribute('data-rows', '2');
  face.setAttribute('data-faceplate-columns', String(columns));
  if (templatePorts) face.setAttribute('data-template-ports', templatePorts);
  else face.removeAttribute('data-template-ports');
  face.style.gridTemplateColumns = columns
    ? 'repeat(' + columns + ', minmax(0, 1fr))'
    : '';
  if (!ports.length) {
    face.innerHTML = '<em>No ports provisioned</em>';
    return;
  }
  const results = (WORKBENCH_STATE && WORKBENCH_STATE.results) || [];
  const equipment = site.equipment || [];
  face.innerHTML = ports.map(port => {
    let fill = 'faceplate-down';
    if (portIsStale(device, port, results, equipment)) fill = 'faceplate-stale';
    else if (portIsUplink(device, port, TOPOLOGY_GRAPH)) fill = 'faceplate-uplink';
    else if (String(port.oper_status || '').trim().toLowerCase() === 'up') fill = 'faceplate-up';
    const poe = poeBadgeText(port.poe_status);
    const badge = poe
      ? '<span class="' + 'faceplate-poe-badge' + '">' + escapeHtml(poe) + '</span>'
      : '';
    return '<button type="button" class="' + 'faceplate-port' + ' ' + fill
      + '" data-port-id="' + escapeHtml(port.port_id)
      + '" data-port-name="' + escapeHtml(port.name) + '">'
      + escapeHtml(port.name) + badge + '</button>';
  }).join('');
}

function drawTopology(graph) {
  const nodes = (graph && graph.nodes) || [];
  const edges = (graph && graph.edges) || [];
  const grouped = {};
  TOPO_COLUMN_ORDER.forEach(nodeType => { grouped[nodeType] = []; });
  nodes.forEach(node => {
    if (!grouped[node.node_type]) grouped[node.node_type] = [];
    grouped[node.node_type].push(node);
  });
  const positions = {};
  let maxRows = 1;
  TOPO_COLUMN_ORDER.forEach((nodeType, colIndex) => {
    const columnNodes = grouped[nodeType] || [];
    if (columnNodes.length > maxRows) maxRows = columnNodes.length;
    columnNodes.forEach((node, rowIndex) => {
      positions[node.node_id] = {
        x: TOPO_PAD_X + colIndex * TOPO_COL_WIDTH,
        y: TOPO_PAD_Y + rowIndex * TOPO_ROW_HEIGHT
      };
    });
  });
  const width = TOPO_PAD_X * 2 + TOPO_COLUMN_ORDER.length * TOPO_COL_WIDTH;
  const height = TOPO_PAD_Y + maxRows * TOPO_ROW_HEIGHT + 16;
  const svg = document.getElementById('topology-svg');
  svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  const lines = edges.map(edge => {
    const src = positions[edge.source_id] || {x: 0, y: 0};
    const dst = positions[edge.target_id] || {x: 0, y: 0};
    return '<line class="' + 'topo-edge' + '" data-relation="' + escapeHtml(edge.relation)
      + '" x1="' + src.x + '" y1="' + src.y + '" x2="' + dst.x + '" y2="' + dst.y + '" />';
  }).join('');
  const groups = nodes.map(node => {
    const pos = positions[node.node_id] || {x: 0, y: 0};
    return '<g class="' + 'topo-node' + '" data-node-id="' + escapeHtml(node.node_id)
      + '" data-node-type="' + escapeHtml(node.node_type)
      + '" transform="translate(' + pos.x + ',' + pos.y + ')"><text>'
      + escapeHtml(node.label) + '</text></g>';
  }).join('');
  svg.innerHTML = lines + groups;
  document.getElementById('topology-mermaid').innerHTML = escapeHtml((graph && graph.mermaid) || '');
}

async function refreshTopologyMap() {
  const resp = await fetch('/api/topology');
  if (!resp.ok) return;
  const data = await resp.json();
  TOPOLOGY_GRAPH = data;
  drawTopology(data);
  renderSwitchFaceplate();
}

function fillPortManagerForm(deviceId, fields) {
  switchTab('tab-devices-ports');
  const devSel = document.getElementById('pm-device-id');
  if (deviceId) devSel.value = deviceId;
  document.getElementById('pm-port-name').value = fields.name || '';
  document.getElementById('pm-range-spec').value = '';
  document.getElementById('pm-admin-status').value = fields.admin_status || '';
  document.getElementById('pm-oper-status').value = fields.oper_status || '';
  document.getElementById('pm-poe-status').value = fields.poe_status || '';
  document.getElementById('pm-vlan-id').value = fields.vlan_id || '';
  document.getElementById('pm-connected-mac').value = fields.connected_mac || '';
  document.getElementById('pm-connected-device').value = fields.connected_device_id || '';
  renderSwitchFaceplate();
}

function onTopologyNodeClick(el) {
  document.querySelectorAll('.topo-node').forEach(nodeEl => {
    nodeEl.classList.remove('topo-selected');
  });
  el.classList.add('topo-selected');
  const nodeId = el.getAttribute('data-node-id');
  const nodeType = el.getAttribute('data-node-type');
  const nodes = (TOPOLOGY_GRAPH && TOPOLOGY_GRAPH.nodes) || [];
  let node = null;
  for (let i = 0; i < nodes.length; i++) {
    if (nodes[i].node_id === nodeId) {
      node = nodes[i];
      break;
    }
  }
  if (nodeType === 'site' || nodeType === 'subnet') {
    return;
  }
  if (!node) return;
  if (nodeType === 'router' || nodeType === 'switch') {
    openEditModal('NetworkDevice', node.node_id);
    return;
  }
  if (nodeType === 'equipment') {
    openEditModal('Equipment', node.node_id);
    return;
  }
  if (nodeType === 'ip') {
    openEditModal('IPAddress', node.node_id);
    return;
  }
  if (nodeType === 'port') {
    const meta = node.metadata || {};
    fillPortManagerForm(meta.device_id, {
      name: meta.name,
      admin_status: meta.admin_status,
      oper_status: meta.oper_status,
      poe_status: meta.poe_status,
      vlan_id: node.vlan_id || meta.vlan_id,
      connected_mac: node.mac || meta.connected_mac,
      connected_device_id: meta.connected_device_id
    });
    return;
  }
  if (nodeType === 'vlan') {
    switchTab('tab-vlans');
    const meta = node.metadata || {};
    document.getElementById('vlan-id-input').value = node.vlan_id || '';
    document.getElementById('vlan-name-input').value = node.label || '';
    document.getElementById('vlan-subnet-id-input').value = meta.subnet_id || '';
    document.getElementById('vlan-cidr-input').value = meta.cidr || '';
    document.getElementById('vlan-gateway-input').value = meta.gateway || '';
  }
}

function onFaceplatePortClick(btn) {
  const portId = btn.getAttribute('data-port-id');
  const face = btn.closest('#switch-faceplate');
  const site = (WORKBENCH_STATE && WORKBENCH_STATE.site) || {};
  const sel = document.getElementById('pm-device-id');
  const deviceId = (sel && sel.value) || (face ? face.getAttribute('data-device-id') : '');
  const device = (site.devices || []).find(d => d.device_id === deviceId);
  if (!device) return;
  const port = (device.ports || []).find(p => p.port_id === portId);
  if (!port) return;
  fillPortManagerForm(device.device_id, {
    name: port.name,
    admin_status: port.admin_status,
    oper_status: port.oper_status,
    poe_status: port.poe_status,
    vlan_id: port.vlan_id,
    connected_mac: port.connected_mac,
    connected_device_id: port.connected_device_id
  });
}

document.getElementById('pm-device-id').addEventListener('change', renderSwitchFaceplate);
document.getElementById('topology-svg').addEventListener('click', ev => {
  const el = ev.target.closest ? ev.target.closest('.topo-node') : null;
  if (el) onTopologyNodeClick(el);
});
document.getElementById('switch-faceplate').addEventListener('click', ev => {
  const btn = ev.target.closest ? ev.target.closest('.faceplate-port') : null;
  if (btn) onFaceplatePortClick(btn);
});
""".replace(
    "__FACEPLATE_TEMPLATES__",
    json.dumps([list(row) for row in _FACEPLATE_TEMPLATES]),
)


def render_workbench_html(
    state: WorkbenchState,
    *,
    title: str = DEFAULT_WORKBENCH_TITLE,
) -> str:
    """Render a complete, self-contained HTML5 Workbench UI pre-seeded with `state`."""
    with state._lock:
        payload = state.get_state_payload(audit_limit=100)
        graph = TopologyGraphBuilder().build(state.site, state.results)
    site_dict = payload["site"]
    results_list = payload["results"]
    templates_list = payload["templates"]
    patches_list = payload["patches"]
    vlan_summary_list = payload["vlan_subnet_summary"]
    summary = payload["summary"]
    audit_log_list = payload["audit_log"]

    cls_counts = summary.get("classification_counts", {})
    confirmed_cnt = cls_counts.get(
        ValidationClassification.CONFIRMED_ACTIVE.value, 0
    )
    stale_cnt = cls_counts.get(
        ValidationClassification.STALE_LIKELY_UNUSED.value, 0
    )
    unreachable_cnt = cls_counts.get(
        ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value, 0
    )
    insufficient_cnt = cls_counts.get(
        ValidationClassification.INSUFFICIENT_DATA.value, 0
    )

    result_by_key: dict[tuple[str, str], dict[str, Any]] = {
        (r["item_type"], r["item_id"]): r for r in results_list
    }
    patch_by_key: dict[tuple[str, str], dict[str, Any]] = {
        (p["target_type"], p["target_id"]): p
        for p in patches_list
        if not p.get("deleted")
    }

    # Build initial server-rendered Inventory Table rows
    inventory_rows_html: list[str] = []
    for dev in site_dict.get("devices", []):
        dev_id = dev["device_id"]
        res = result_by_key.get(("NetworkDevice", dev_id), {})
        patch = patch_by_key.get(("NetworkDevice", dev_id), {})
        cls_val = res.get(
            "classification", ValidationClassification.INSUFFICIENT_DATA.value
        )
        room_val = patch.get("room") or ""
        vlan_val = patch.get("vlan_id") or ""
        notes_val = patch.get("notes") or ""
        ports_cnt = len(dev.get("ports", []))
        inventory_rows_html.append(
            f'<tr data-target-type="NetworkDevice" data-target-id="{_esc(dev_id)}" '
            f'data-vlan="{_esc(vlan_val)}" data-classification="{_esc(cls_val)}">'
            f"<td><code>NetworkDevice</code></td>"
            f"<td><code>{_esc(dev_id)}</code></td>"
            f"<td><strong>{_esc(dev.get('hostname'))}</strong></td>"
            f"<td>{_esc(dev.get('role') or 'switch')} ({_esc(dev.get('vendor') or '')} {_esc(dev.get('model') or '')})</td>"
            f"<td>{_esc(room_val)}</td>"
            f"<td>{_esc(vlan_val)}</td>"
            f"<td>{_esc(dev.get('management_ip') or '')} ({ports_cnt} ports)</td>"
            f"<td>{_esc(notes_val)}</td>"
            f'<td><span class="badge {_badge_class(cls_val)}">{_esc(cls_val)}</span></td>'
            f'<td><button type="button" class="btn btn-sm" '
            f"onclick=\"openEditModal('NetworkDevice', '{_esc(dev_id)}')\">Edit</button></td>"
            f"</tr>"
        )

    for eq in site_dict.get("equipment", []):
        eq_id = eq["equipment_id"]
        res = result_by_key.get(("Equipment", eq_id), {})
        patch = patch_by_key.get(("Equipment", eq_id), {})
        cls_val = res.get(
            "classification", ValidationClassification.INSUFFICIENT_DATA.value
        )
        custom_attrs = patch.get("custom_attributes") or {}
        room_val = patch.get("room") or custom_attrs.get("room") or ""
        vlan_val = patch.get("vlan_id") or custom_attrs.get("vlan_id") or ""
        notes_val = patch.get("notes") or ""
        ips_str = ", ".join(eq.get("assigned_ips", []))
        ports_str = ", ".join(eq.get("connected_ports", []))
        conn_summary = ips_str + (f" [{ports_str}]" if ports_str else "")
        inventory_rows_html.append(
            f'<tr data-target-type="Equipment" data-target-id="{_esc(eq_id)}" '
            f'data-vlan="{_esc(vlan_val)}" data-classification="{_esc(cls_val)}">'
            f"<td><code>Equipment</code></td>"
            f"<td><code>{_esc(eq_id)}</code></td>"
            f"<td><strong>{_esc(eq.get('name'))}</strong></td>"
            f"<td>{_esc(eq.get('category'))}</td>"
            f"<td>{_esc(room_val)}</td>"
            f"<td>{_esc(vlan_val)}</td>"
            f"<td>{_esc(conn_summary)}</td>"
            f"<td>{_esc(notes_val)}</td>"
            f'<td><span class="badge {_badge_class(cls_val)}">{_esc(cls_val)}</span></td>'
            f'<td><button type="button" class="btn btn-sm" '
            f"onclick=\"openEditModal('Equipment', '{_esc(eq_id)}')\">Edit</button></td>"
            f"</tr>"
        )

    for ip_rec in site_dict.get("ip_addresses", []):
        ip_val = ip_rec["ip"]
        res = result_by_key.get(("IPAddress", ip_val), {})
        patch = patch_by_key.get(("IPAddress", ip_val), {})
        cls_val = res.get(
            "classification", ValidationClassification.INSUFFICIENT_DATA.value
        )
        subnet_id = ip_rec.get("subnet_id") or ""
        notes_val = patch.get("notes") or ""
        assigned_info = ip_rec.get("assigned_object_id") or ""
        inventory_rows_html.append(
            f'<tr data-target-type="IPAddress" data-target-id="{_esc(ip_val)}" '
            f'data-subnet="{_esc(subnet_id)}" data-classification="{_esc(cls_val)}">'
            f"<td><code>IPAddress</code></td>"
            f"<td><code>{_esc(ip_val)}</code></td>"
            f"<td><strong>{_esc(patch.get('name') or ip_val)}</strong></td>"
            f"<td>IP Assignment</td>"
            f"<td>{_esc(patch.get('room') or '')}</td>"
            f"<td>{_esc(subnet_id)}</td>"
            f"<td>{_esc(assigned_info)} {_esc(ip_rec.get('arp_mac') or '')}</td>"
            f"<td>{_esc(notes_val)}</td>"
            f'<td><span class="badge {_badge_class(cls_val)}">{_esc(cls_val)}</span></td>'
            f'<td><button type="button" class="btn btn-sm" '
            f"onclick=\"openEditModal('IPAddress', '{_esc(ip_val)}')\">Edit</button></td>"
            f"</tr>"
        )

    # Template options
    template_options_html = ['<option value="">-- Custom Device (No Template) --</option>']
    for tpl in templates_list:
        tpl_id = tpl["template_id"]
        label = (
            f"{tpl['vendor']} {tpl['model']} ({tpl['role']}, "
            f"{tpl['default_port_count']} ports)"
        )
        template_options_html.append(
            f'<option value="{_esc(tpl_id)}">{_esc(label)} [{_esc(tpl_id)}]</option>'
        )

    # Device options for port manager
    device_options_html: list[str] = []
    for dev in site_dict.get("devices", []):
        device_options_html.append(
            f'<option value="{_esc(dev["device_id"])}">'
            f'{_esc(dev["hostname"])} ({_esc(dev["device_id"])})</option>'
        )

    # Device port cards
    device_cards_html: list[str] = []
    for dev in site_dict.get("devices", []):
        ports_chips: list[str] = []
        for p in dev.get("ports", []):
            oper = (p.get("oper_status") or "down").lower()
            chip_cls = "port-up" if oper == "up" else "port-down"
            poe_badge = f"⚡{_esc(p['poe_status'])}" if p.get("poe_status") else ""
            vlan_badge = f"V{_esc(p['vlan_id'])}" if p.get("vlan_id") else ""
            mac_badge = f"MAC:{_esc(p['connected_mac'])}" if p.get("connected_mac") else ""
            ports_chips.append(
                f'<div class="port-chip {chip_cls}" '
                f'title="Port {_esc(p["name"])} | Admin: {_esc(p.get("admin_status"))} | Oper: {_esc(p.get("oper_status"))} | VLAN: {_esc(p.get("vlan_id"))} | MAC: {_esc(p.get("connected_mac"))} | Connected: {_esc(p.get("connected_device_id"))}">'
                f'<span class="port-name">{_esc(p["name"])}</span>'
                f'<span class="port-meta">{vlan_badge} {poe_badge} {mac_badge}</span>'
                f"</div>"
            )
        device_cards_html.append(
            f'<div class="device-card" data-device-id="{_esc(dev["device_id"])}">'
            f'<div class="device-card-header">'
            f'<strong>{_esc(dev["hostname"])}</strong> '
            f'<code>({_esc(dev["device_id"])})</code> — '
            f'{_esc(dev.get("vendor") or "")} {_esc(dev.get("model") or "")} '
            f'[{_esc(dev.get("role") or "switch")}] '
            f'IP: <code>{_esc(dev.get("management_ip") or "N/A")}</code>'
            f"</div>"
            f'<div class="port-grid">{"".join(ports_chips) or "<em>No ports provisioned</em>"}</div>'
            f"</div>"
        )

    # VLAN & Subnet summary rows
    vlan_rows_html: list[str] = []
    for vs in vlan_summary_list:
        vlan_rows_html.append(
            f"<tr>"
            f"<td><code>{_esc(vs.get('vlan_id') or '-')}</code></td>"
            f"<td><strong>{_esc(vs.get('vlan_name') or '-')}</strong></td>"
            f"<td><code>{_esc(vs.get('subnet_id') or '-')}</code></td>"
            f"<td><code>{_esc(vs.get('cidr') or '-')}</code></td>"
            f"<td><code>{_esc(vs.get('gateway') or '-')}</code></td>"
            f"<td>{int(vs.get('ip_count', 0))}</td>"
            f"<td>{int(vs.get('device_port_count', 0))}</td>"
            f"<td>{int(vs.get('equipment_count', 0))}</td>"
            f"</tr>"
        )

    # Audit log rows
    audit_rows_html: list[str] = []
    for entry in audit_log_list:
        changes_json = json.dumps(entry.get("changes", {}))
        audit_rows_html.append(
            f"<tr>"
            f"<td><code>{_esc(entry.get('timestamp'))}</code></td>"
            f"<td>{_esc(entry.get('actor'))}</td>"
            f"<td><span class=\"badge badge-info\">{_esc(entry.get('action'))}</span></td>"
            f"<td><code>{_esc(entry.get('target_type'))}:{_esc(entry.get('target_id'))}</code></td>"
            f"<td><code>{_esc(changes_json)}</code></td>"
            f"<td>{_esc(entry.get('reason'))}</td>"
            f"</tr>"
        )

    # Filter options
    vlan_filter_opts = ['<option value="">All VLANs</option>']
    for v in site_dict.get("vlans", []):
        vlan_filter_opts.append(
            f'<option value="{_esc(v["vlan_id"])}">VLAN {_esc(v["vlan_id"])} ({_esc(v.get("name") or "")})</option>'
        )

    subnet_filter_opts = ['<option value="">All Subnets</option>']
    for s in site_dict.get("subnets", []):
        subnet_filter_opts.append(
            f'<option value="{_esc(s["subnet_id"])}">{_esc(s["cidr"])} ({_esc(s["subnet_id"])})</option>'
        )

    cls_filter_opts = ['<option value="">All Classifications</option>']
    for cls_enum in ValidationClassification:
        cls_filter_opts.append(
            f'<option value="{_esc(cls_enum.value)}">{_esc(cls_enum.value)}</option>'
        )

    role_opts = "".join(
        f'<option value="{_esc(r)}">{_esc(r)}</option>' for r in VALID_DEVICE_ROLES
    )
    cat_opts = "".join(
        f'<option value="{_esc(c.value)}">{_esc(c.value)}</option>'
        for c in EquipmentCategory
    )
    pin_opts = ['<option value="">-- Automatic (Unpinned) --</option>'] + [
        f'<option value="{_esc(c.value)}">{_esc(c.value)}</option>'
        for c in ValidationClassification
    ]

    embedded_state_json = _safe_json_for_script(payload)
    topology_payload = graph.to_dict()
    topology_payload["mermaid"] = graph.to_mermaid()
    embedded_topology_json = _safe_json_for_script(topology_payload)
    faceplate_html = _render_switch_faceplate(site_dict, results_list, graph)
    topology_svg = _render_topology_svg(graph)
    mermaid_html = _esc(topology_payload["mermaid"])
    v2_script = _WORKBENCH_V2_SCRIPT

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)} — {_esc(site_dict.get("name"))}</title>
<style>
:root {{
  --bg: #0f172a;
  --panel: #1e293b;
  --panel-alt: #334155;
  --text: #f8fafc;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --border: #475569;
  --active: #22c55e;
  --stale: #ef4444;
  --unreachable: #f59e0b;
  --insufficient: #64748b;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}}
header {{
  padding: 1rem 1.5rem;
  background: var(--panel);
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
}}
header h1 {{ margin: 0; font-size: 1.35rem; }}
.container {{ max-width: 1440px; margin: 0 auto; padding: 1.25rem; }}
.kpi-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 0.85rem;
  margin-bottom: 1.25rem;
}}
.kpi-card {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.9rem 1rem;
}}
.kpi-card .label {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase; }}
.kpi-card .value {{ font-size: 1.55rem; font-weight: 700; margin-top: 0.25rem; }}
.kpi-card .sub {{ font-size: 0.8rem; color: var(--muted); margin-top: 0.2rem; }}
.filter-bar {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.85rem 1rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  margin-bottom: 1rem;
}}
.filter-bar input, .filter-bar select, form input, form select, form textarea {{
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.45rem 0.65rem;
  font-size: 0.9rem;
}}
.tabs {{
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
}}
.tab-btn {{
  background: var(--panel);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.5rem 1rem;
  cursor: pointer;
  font-weight: 600;
}}
.tab-btn.active {{
  background: var(--accent);
  color: #0f172a;
  border-color: var(--accent);
}}
.tab-panel {{ display: none; }}
.tab-panel.active {{ display: block; }}
table {{
  width: 100%;
  border-collapse: collapse;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}}
th, td {{
  padding: 0.6rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
  font-size: 0.88rem;
}}
th {{ background: var(--panel-alt); font-weight: 600; }}
.badge {{
  display: inline-block;
  padding: 0.2rem 0.55rem;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
}}
.badge-active {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; }}
.badge-stale {{ background: rgba(239, 68, 68, 0.2); color: #f87171; }}
.badge-unreachable {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
.badge-insufficient {{ background: rgba(100, 116, 139, 0.25); color: #cbd5e1; }}
.badge-info {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; }}
.btn {{
  background: var(--accent);
  color: #0f172a;
  border: none;
  border-radius: 6px;
  padding: 0.45rem 0.85rem;
  font-weight: 600;
  cursor: pointer;
}}
.btn-sm {{ padding: 0.25rem 0.6rem; font-size: 0.8rem; }}
.btn-danger {{ background: var(--stale); color: #fff; }}
.grid-2 {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 1rem;
  margin-bottom: 1.25rem;
}}
.card {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
}}
.card h3 {{ margin-top: 0; font-size: 1.05rem; }}
.form-row {{
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  margin-bottom: 0.65rem;
}}
.form-row label {{ font-size: 0.82rem; color: var(--muted); }}
.device-card {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.85rem 1rem;
  margin-bottom: 0.85rem;
}}
.device-card-header {{ margin-bottom: 0.6rem; font-size: 0.92rem; }}
.port-grid {{
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}}
.port-chip {{
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.3rem 0.5rem;
  font-size: 0.75rem;
  display: flex;
  flex-direction: column;
  min-width: 72px;
}}
.port-up {{ background: rgba(34, 197, 94, 0.15); border-color: #22c55e; }}
.port-down {{ background: rgba(100, 116, 139, 0.15); }}
.port-name {{ font-weight: 700; }}
.port-meta {{ font-size: 0.68rem; color: var(--muted); }}
.modal-backdrop {{
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.75);
  align-items: center;
  justify-content: center;
  z-index: 50;
}}
.modal-backdrop.open {{ display: flex; }}
.modal {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
  width: 100%;
  max-width: 520px;
}}
#status-banner {{
  display: none;
  padding: 0.6rem 1rem;
  border-radius: 6px;
  margin-bottom: 1rem;
  font-weight: 600;
}}
#topology-svg {{
  width: 100%;
  height: auto;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
}}
.topo-node {{ cursor: pointer; }}
.topo-node text {{ fill: var(--text); font-size: 12px; }}
.topo-edge {{ stroke: #64748b; stroke-width: 1.5; }}
.topo-node.topo-selected {{ outline: 2px solid #38bdf8; }}
#topology-mermaid {{
  margin-top: 0.75rem;
  background: var(--panel);
  color: var(--muted);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem;
  overflow: auto;
  white-space: pre-wrap;
}}
#switch-faceplate {{
  display: grid;
  grid-auto-flow: row;
  grid-template-rows: repeat(2, auto);
  gap: 0.35rem;
  margin-bottom: 1rem;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.75rem;
}}
.faceplate-port {{
  color: #fff;
  border: 1px solid rgba(15, 23, 42, 0.35);
  border-radius: 4px;
  min-height: 2rem;
  font-size: 0.75rem;
  font-weight: 700;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.25rem;
  padding: 0.2rem 0.4rem;
}}
.faceplate-up {{ background: #10b981; }}
.faceplate-down {{ background: #64748b; }}
.faceplate-uplink {{ background: #4f46e5; }}
.faceplate-stale {{ background: #e11d48; }}
.faceplate-poe-badge {{ background: #f59e0b; color: #0f172a; border-radius: 999px; padding: 0 0.35rem; font-size: 0.68rem; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>{_esc(title)}</h1>
    <small>Site: <strong id="site-header-name">{_esc(site_dict.get("name"))}</strong> (<code>{_esc(site_dict.get("site_id"))}</code>) — Address: {_esc(site_dict.get("address") or "N/A")}</small>
  </div>
  <div>
    <button type="button" class="btn btn-sm" onclick="refreshFromApi()">Refresh State</button>
  </div>
</header>

<div class="container">
  <div id="status-banner"></div>

  <!-- 1. Overview KPI Cards & Filter Bar -->
  <section id="kpi-overview" class="kpi-grid">
    <div class="kpi-card">
      <div class="label">Network Devices</div>
      <div class="value" id="kpi-total-devices">{summary["total_devices"]}</div>
      <div class="sub">Routers, Switches &amp; Hosts</div>
    </div>
    <div class="kpi-card">
      <div class="label">Switch / Router Ports</div>
      <div class="value" id="kpi-total-ports">{summary["total_ports"]}</div>
      <div class="sub"><span id="kpi-active-ports">{summary["active_ports"]}</span> UP / <span id="kpi-poe-ports">{summary["poe_ports"]}</span> PoE</div>
    </div>
    <div class="kpi-card">
      <div class="label">VLANs &amp; /24 Subnets</div>
      <div class="value"><span id="kpi-total-vlans">{summary["total_vlans"]}</span> / <span id="kpi-total-subnets">{summary["total_subnets"]}</span></div>
      <div class="sub">Segmented Networks</div>
    </div>
    <div class="kpi-card">
      <div class="label">Equipment &amp; IPs</div>
      <div class="value"><span id="kpi-total-equipment">{summary["total_equipment"]}</span> / <span id="kpi-total-ips">{summary["total_ips"]}</span></div>
      <div class="sub">Servers, VMs, UPS, SAN, IPs</div>
    </div>
    <div class="kpi-card">
      <div class="label">Validation Breakdown</div>
      <div class="value" id="kpi-confirmed-active">{confirmed_cnt} Active</div>
      <div class="sub">
        <span id="kpi-stale">{stale_cnt}</span> Stale ·
        <span id="kpi-unreachable">{unreachable_cnt}</span> Review ·
        <span id="kpi-insufficient">{insufficient_cnt}</span> Insuff
      </div>
    </div>
  </section>

  <section id="filter-bar" class="filter-bar">
    <input type="search" id="inventory-search" placeholder="Search hostname, ID, IP, MAC, notes..." oninput="applyInventoryFilters()">
    <select id="filter-vlan" onchange="applyInventoryFilters()">
      {"".join(vlan_filter_opts)}
    </select>
    <select id="filter-subnet" onchange="applyInventoryFilters()">
      {"".join(subnet_filter_opts)}
    </select>
    <select id="filter-classification" onchange="applyInventoryFilters()">
      {"".join(cls_filter_opts)}
    </select>
  </section>

  <!-- Navigation Tabs -->
  <nav class="tabs">
    <button type="button" class="tab-btn active" data-tab="tab-inventory" onclick="switchTab('tab-inventory')">Modifiable Inventory</button>
    <button type="button" class="tab-btn" data-tab="tab-devices-ports" onclick="switchTab('tab-devices-ports')">Routers, Switches &amp; Port Manager</button>
    <button type="button" class="tab-btn" data-tab="tab-topology" onclick="switchTab('tab-topology')">Topology Map</button>
    <button type="button" class="tab-btn" data-tab="tab-vlans" onclick="switchTab('tab-vlans')">VLAN &amp; Subnet Manager</button>
    <button type="button" class="tab-btn" data-tab="tab-audit-log" onclick="switchTab('tab-audit-log')">Audit Log</button>
  </nav>

  <!-- 2. Modifiable Inventory Table Tab -->
  <section id="tab-inventory" class="tab-panel active">
    <table id="inventory-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>ID</th>
          <th>Name / Hostname</th>
          <th>Category / Role</th>
          <th>Room</th>
          <th>VLAN / Subnet</th>
          <th>IPs / Ports</th>
          <th>Operator Notes</th>
          <th>Classification</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="inventory-tbody">
        {"".join(inventory_rows_html)}
      </tbody>
    </table>
  </section>

  <!-- 3. Routers, Switches & Port Manager Tab -->
  <section id="tab-devices-ports" class="tab-panel">
    <div class="grid-2">
      <div class="card">
        <h3>Add Network Device (Template or Custom)</h3>
        <form id="create-device-form" onsubmit="submitCreateDevice(event)">
          <div class="form-row">
            <label for="dev-hostname">Hostname *</label>
            <input type="text" id="dev-hostname" name="hostname" required placeholder="e.g. sw-idf2-01">
          </div>
          <div class="form-row">
            <label for="dev-device-id">Device ID (optional, auto-generated from hostname)</label>
            <input type="text" id="dev-device-id" name="device_id" placeholder="e.g. dev-sw-idf2-01">
          </div>
          <div class="form-row">
            <label for="dev-template-id">Hardware / Virtual Template</label>
            <select id="dev-template-id" name="template_id">
              {"".join(template_options_html)}
            </select>
          </div>
          <div class="form-row">
            <label for="dev-mgmt-ip">Management IP</label>
            <input type="text" id="dev-mgmt-ip" name="management_ip" placeholder="e.g. 10.1.1.10">
          </div>
          <div class="form-row">
            <label for="dev-role">Role Override</label>
            <select id="dev-role" name="role">
              <option value="">-- Use Template Default --</option>
              {role_opts}
            </select>
          </div>
          <div class="form-row">
            <label for="dev-port-count">Port Count Override</label>
            <input type="number" id="dev-port-count" name="port_count" min="0" max="256" placeholder="Default from template">
          </div>
          <div class="form-row">
            <label for="dev-default-vlan">Default VLAN ID</label>
            <input type="text" id="dev-default-vlan" name="default_vlan_id" placeholder="e.g. 10">
          </div>
          <div class="form-row">
            <label for="dev-reason">Audit Reason</label>
            <input type="text" id="dev-reason" name="reason" placeholder="Provisioned new closet switch">
          </div>
          <button type="submit" class="btn">Create Device</button>
        </form>
      </div>

      <div class="card">
        <h3>Switch / Router Port Manager (Single or Range)</h3>
        <form id="port-manager-form" onsubmit="submitPortManager(event)">
          <div class="form-row">
            <label for="pm-device-id">Target Network Device *</label>
            <select id="pm-device-id" name="device_id" required onchange="renderSwitchFaceplate()">
              {"".join(device_options_html)}
            </select>
          </div>
          <div class="form-row">
            <label for="pm-port-name">Single Port Name (e.g. <code>1:1</code>, <code>eth1</code>)</label>
            <input type="text" id="pm-port-name" name="name" placeholder="1:1">
          </div>
          <div class="form-row">
            <label for="pm-range-spec">Or Port Range Spec (e.g. <code>1:1..1:24</code>, <code>eth1..eth8</code>)</label>
            <input type="text" id="pm-range-spec" name="range_spec" placeholder="1:1..1:24">
          </div>
          <div class="form-row">
            <label for="pm-admin-status">Admin Status</label>
            <select id="pm-admin-status" name="admin_status">
              <option value="up">up</option>
              <option value="down">down</option>
            </select>
          </div>
          <div class="form-row">
            <label for="pm-oper-status">Operational Link Status</label>
            <select id="pm-oper-status" name="oper_status">
              <option value="up">up</option>
              <option value="down">down</option>
            </select>
          </div>
          <div class="form-row">
            <label for="pm-poe-status">PoE Status</label>
            <input type="text" id="pm-poe-status" name="poe_status" placeholder="delivering / auto / off">
          </div>
          <div class="form-row">
            <label for="pm-vlan-id">Assigned VLAN ID</label>
            <input type="text" id="pm-vlan-id" name="vlan_id" placeholder="e.g. 20">
          </div>
          <div class="form-row">
            <label for="pm-connected-mac">Connected Host MAC Address</label>
            <input type="text" id="pm-connected-mac" name="connected_mac" placeholder="aa:bb:cc:dd:ee:ff">
          </div>
          <div class="form-row">
            <label for="pm-connected-device">Connected Equipment / Device ID</label>
            <input type="text" id="pm-connected-device" name="connected_device_id" placeholder="eq-srv-01">
          </div>
          <div class="form-row">
            <label for="pm-reason">Audit Reason</label>
            <input type="text" id="pm-reason" name="reason" placeholder="Patched access ports to VLAN 20">
          </div>
          <button type="submit" class="btn">Provision / Update Ports</button>
        </form>
      </div>
    </div>

    {faceplate_html}

    <div id="device-port-grids">
      {"".join(device_cards_html)}
    </div>
  </section>

  <section id="tab-topology" class="tab-panel">
    {topology_svg}
    <pre id="topology-mermaid">{mermaid_html}</pre>
  </section>

  <!-- 4. VLAN & Subnet Manager Tab -->
  <section id="tab-vlans" class="tab-panel">
    <div class="grid-2">
      <div class="card">
        <h3>Add / Update VLAN &amp; /24 Subnet</h3>
        <form id="vlan-form" onsubmit="submitVlanForm(event)">
          <div class="form-row">
            <label for="vlan-id-input">VLAN ID *</label>
            <input type="text" id="vlan-id-input" name="vlan_id" required placeholder="e.g. 30">
          </div>
          <div class="form-row">
            <label for="vlan-name-input">VLAN Name</label>
            <input type="text" id="vlan-name-input" name="name" placeholder="e.g. Voice / VoIP">
          </div>
          <div class="form-row">
            <label for="vlan-subnet-id-input">Subnet ID (optional)</label>
            <input type="text" id="vlan-subnet-id-input" name="subnet_id" placeholder="e.g. sub-vlan-30">
          </div>
          <div class="form-row">
            <label for="vlan-cidr-input">IPv4 /24 CIDR</label>
            <input type="text" id="vlan-cidr-input" name="cidr" placeholder="e.g. 10.1.30.0/24">
          </div>
          <div class="form-row">
            <label for="vlan-gateway-input">Default Gateway IP</label>
            <input type="text" id="vlan-gateway-input" name="gateway" placeholder="e.g. 10.1.30.1">
          </div>
          <div class="form-row">
            <label for="vlan-reason-input">Audit Reason</label>
            <input type="text" id="vlan-reason-input" name="reason" placeholder="Added VLAN 30 subnet">
          </div>
          <button type="submit" class="btn">Save VLAN &amp; Subnet</button>
        </form>
      </div>

      <div class="card">
        <h3>Site VLAN &amp; /24 Subnet Summary</h3>
        <table id="vlan-summary-table">
          <thead>
            <tr>
              <th>VLAN ID</th>
              <th>Name</th>
              <th>Subnet ID</th>
              <th>CIDR</th>
              <th>Gateway</th>
              <th>IPs</th>
              <th>Switch Ports</th>
              <th>Equipment</th>
            </tr>
          </thead>
          <tbody id="vlan-summary-tbody">
            {"".join(vlan_rows_html)}
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- 5. Audit Log Tab -->
  <section id="tab-audit-log" class="tab-panel">
    <table id="audit-log-table">
      <thead>
        <tr>
          <th>Timestamp (UTC)</th>
          <th>Actor</th>
          <th>Action</th>
          <th>Target</th>
          <th>Changes</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody id="audit-log-tbody">
        {"".join(audit_rows_html)}
      </tbody>
    </table>
  </section>
</div>

<!-- Inline Item Edit Modal -->
<div id="item-edit-modal" class="modal-backdrop">
  <div class="modal">
    <h3>Edit Inventory Item</h3>
    <form id="item-edit-form" onsubmit="submitItemPatch(event)">
      <input type="hidden" id="edit-target-type" name="target_type">
      <input type="hidden" id="edit-target-id" name="target_id">
      <div class="form-row">
        <label for="edit-name">Name / Hostname</label>
        <input type="text" id="edit-name" name="name">
      </div>
      <div class="form-row">
        <label for="edit-category-role">Category / Device Role</label>
        <input type="text" id="edit-category-role" name="category_or_role" list="category-role-list">
        <datalist id="category-role-list">
          {cat_opts}
          {role_opts}
        </datalist>
      </div>
      <div class="form-row">
        <label for="edit-room">Room / Closet</label>
        <input type="text" id="edit-room" name="room" placeholder="e.g. Server Room B">
      </div>
      <div class="form-row">
        <label for="edit-vlan-id">VLAN ID</label>
        <input type="text" id="edit-vlan-id" name="vlan_id" placeholder="e.g. 10">
      </div>
      <div class="form-row">
        <label for="edit-notes">Operator Notes</label>
        <textarea id="edit-notes" name="notes" rows="2"></textarea>
      </div>
      <div class="form-row">
        <label for="edit-pinned-classification">Pin Validation Classification</label>
        <select id="edit-pinned-classification" name="pinned_classification">
          {"".join(pin_opts)}
        </select>
      </div>
      <div class="form-row">
        <label for="edit-reason">Audit Reason</label>
        <input type="text" id="edit-reason" name="reason" placeholder="Verified during site walkthrough">
      </div>
      <div style="display:flex; gap:0.5rem; justify-content:space-between; margin-top:1rem;">
        <button type="button" class="btn btn-danger" onclick="submitDeleteCurrentItem()">Delete Item</button>
        <div style="display:flex; gap:0.5rem;">
          <button type="button" class="btn" style="background:var(--panel-alt);color:var(--text);" onclick="closeEditModal()">Cancel</button>
          <button type="submit" class="btn">Save Changes</button>
        </div>
      </div>
    </form>
  </div>
</div>

<script id="initial-workbench-state" type="application/json">{embedded_state_json}</script>
<script id="initial-topology" type="application/json">{embedded_topology_json}</script>
<script>
let WORKBENCH_STATE = JSON.parse(document.getElementById('initial-workbench-state').textContent);

function escapeHtml(val) {{
  if (val === null || val === undefined) return '';
  return String(val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}}

function badgeClass(cls) {{
  if (cls === 'Confirmed Active') return 'badge-active';
  if (cls === 'Stale / Likely Unused') return 'badge-stale';
  if (cls === 'Unreachable / Needs Manual Review') return 'badge-unreachable';
  return 'badge-insufficient';
}}

function showBanner(msg, isError) {{
  const el = document.getElementById('status-banner');
  el.style.display = 'block';
  el.style.background = isError ? 'rgba(239, 68, 68, 0.25)' : 'rgba(34, 197, 94, 0.25)';
  el.style.border = isError ? '1px solid #ef4444' : '1px solid #22c55e';
  el.textContent = msg;
}}

function switchTab(tabId) {{
  document.querySelectorAll('.tab-btn').forEach(btn => {{
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  }});
  document.querySelectorAll('.tab-panel').forEach(panel => {{
    panel.classList.toggle('active', panel.id === tabId);
  }});
}}

function renderState(state) {{
  WORKBENCH_STATE = state;
  const s = state.summary || {{}};
  const clsCounts = s.classification_counts || {{}};
  document.getElementById('kpi-total-devices').textContent = s.total_devices || 0;
  document.getElementById('kpi-total-ports').textContent = s.total_ports || 0;
  document.getElementById('kpi-active-ports').textContent = s.active_ports || 0;
  document.getElementById('kpi-poe-ports').textContent = s.poe_ports || 0;
  document.getElementById('kpi-total-vlans').textContent = s.total_vlans || 0;
  document.getElementById('kpi-total-subnets').textContent = s.total_subnets || 0;
  document.getElementById('kpi-total-equipment').textContent = s.total_equipment || 0;
  document.getElementById('kpi-total-ips').textContent = s.total_ips || 0;
  document.getElementById('kpi-confirmed-active').textContent = (clsCounts['Confirmed Active'] || 0) + ' Active';
  document.getElementById('kpi-stale').textContent = clsCounts['Stale / Likely Unused'] || 0;
  document.getElementById('kpi-unreachable').textContent = clsCounts['Unreachable / Needs Manual Review'] || 0;
  document.getElementById('kpi-insufficient').textContent = clsCounts['Insufficient Data'] || 0;

  const resMap = {{}};
  (state.results || []).forEach(r => {{ resMap[r.item_type + ':' + r.item_id] = r; }});
  const patchMap = {{}};
  (state.patches || []).forEach(p => {{ if (!p.deleted) patchMap[p.target_type + ':' + p.target_id] = p; }});

  const site = state.site || {{}};
  const invRows = [];
  (site.devices || []).forEach(dev => {{
    const key = 'NetworkDevice:' + dev.device_id;
    const res = resMap[key] || {{}};
    const patch = patchMap[key] || {{}};
    const cls = res.classification || 'Insufficient Data';
    const room = patch.room || '';
    const vlan = patch.vlan_id || '';
    const notes = patch.notes || '';
    const pCount = (dev.ports || []).length;
    invRows.push(`<tr data-target-type="NetworkDevice" data-target-id="${{escapeHtml(dev.device_id)}}" data-vlan="${{escapeHtml(vlan)}}" data-classification="${{escapeHtml(cls)}}">
      <td><code>NetworkDevice</code></td>
      <td><code>${{escapeHtml(dev.device_id)}}</code></td>
      <td><strong>${{escapeHtml(dev.hostname)}}</strong></td>
      <td>${{escapeHtml(dev.role || 'switch')}} (${{escapeHtml(dev.vendor || '')}} ${{escapeHtml(dev.model || '')}})</td>
      <td>${{escapeHtml(room)}}</td>
      <td>${{escapeHtml(vlan)}}</td>
      <td>${{escapeHtml(dev.management_ip || '')}} (${{pCount}} ports)</td>
      <td>${{escapeHtml(notes)}}</td>
      <td><span class="badge ${{badgeClass(cls)}}">${{escapeHtml(cls)}}</span></td>
      <td><button type="button" class="btn btn-sm" onclick="openEditModal('NetworkDevice', '${{escapeHtml(dev.device_id)}}')">Edit</button></td>
    </tr>`);
  }});

  (site.equipment || []).forEach(eq => {{
    const key = 'Equipment:' + eq.equipment_id;
    const res = resMap[key] || {{}};
    const patch = patchMap[key] || {{}};
    const cls = res.classification || 'Insufficient Data';
    const custom = patch.custom_attributes || {{}};
    const room = patch.room || custom.room || '';
    const vlan = patch.vlan_id || custom.vlan_id || '';
    const notes = patch.notes || '';
    const ips = (eq.assigned_ips || []).join(', ');
    const ports = (eq.connected_ports || []).join(', ');
    invRows.push(`<tr data-target-type="Equipment" data-target-id="${{escapeHtml(eq.equipment_id)}}" data-vlan="${{escapeHtml(vlan)}}" data-classification="${{escapeHtml(cls)}}">
      <td><code>Equipment</code></td>
      <td><code>${{escapeHtml(eq.equipment_id)}}</code></td>
      <td><strong>${{escapeHtml(eq.name)}}</strong></td>
      <td>${{escapeHtml(eq.category)}}</td>
      <td>${{escapeHtml(room)}}</td>
      <td>${{escapeHtml(vlan)}}</td>
      <td>${{escapeHtml(ips)}} ${{ports ? '[' + escapeHtml(ports) + ']' : ''}}</td>
      <td>${{escapeHtml(notes)}}</td>
      <td><span class="badge ${{badgeClass(cls)}}">${{escapeHtml(cls)}}</span></td>
      <td><button type="button" class="btn btn-sm" onclick="openEditModal('Equipment', '${{escapeHtml(eq.equipment_id)}}')">Edit</button></td>
    </tr>`);
  }});

  (site.ip_addresses || []).forEach(ipRec => {{
    const key = 'IPAddress:' + ipRec.ip;
    const res = resMap[key] || {{}};
    const patch = patchMap[key] || {{}};
    const cls = res.classification || 'Insufficient Data';
    const notes = patch.notes || '';
    invRows.push(`<tr data-target-type="IPAddress" data-target-id="${{escapeHtml(ipRec.ip)}}" data-subnet="${{escapeHtml(ipRec.subnet_id || '')}}" data-classification="${{escapeHtml(cls)}}">
      <td><code>IPAddress</code></td>
      <td><code>${{escapeHtml(ipRec.ip)}}</code></td>
      <td><strong>${{escapeHtml(patch.name || ipRec.ip)}}</strong></td>
      <td>IP Assignment</td>
      <td>${{escapeHtml(patch.room || '')}}</td>
      <td>${{escapeHtml(ipRec.subnet_id || '')}}</td>
      <td>${{escapeHtml(ipRec.assigned_object_id || '')}} ${{escapeHtml(ipRec.arp_mac || '')}}</td>
      <td>${{escapeHtml(notes)}}</td>
      <td><span class="badge ${{badgeClass(cls)}}">${{escapeHtml(cls)}}</span></td>
      <td><button type="button" class="btn btn-sm" onclick="openEditModal('IPAddress', '${{escapeHtml(ipRec.ip)}}')">Edit</button></td>
    </tr>`);
  }});
  document.getElementById('inventory-tbody').innerHTML = invRows.join('');

  // Update device select and port grids
  const devSelect = document.getElementById('pm-device-id');
  devSelect.innerHTML = (site.devices || []).map(d =>
    `<option value="${{escapeHtml(d.device_id)}}">${{escapeHtml(d.hostname)}} (${{escapeHtml(d.device_id)}})</option>`
  ).join('');

  const devCards = (site.devices || []).map(d => {{
    const chips = (d.ports || []).map(p => {{
      const oper = (p.oper_status || 'down').toLowerCase();
      const cls = oper === 'up' ? 'port-up' : 'port-down';
      const meta = [
        p.vlan_id ? 'V' + p.vlan_id : '',
        p.poe_status ? '⚡' + p.poe_status : '',
        p.connected_mac ? 'MAC:' + p.connected_mac : ''
      ].filter(Boolean).join(' ');
      return `<div class="port-chip ${{cls}}">
        <span class="port-name">${{escapeHtml(p.name)}}</span>
        <span class="port-meta">${{escapeHtml(meta)}}</span>
      </div>`;
    }}).join('');
    return `<div class="device-card" data-device-id="${{escapeHtml(d.device_id)}}">
      <div class="device-card-header">
        <strong>${{escapeHtml(d.hostname)}}</strong> <code>(${{escapeHtml(d.device_id)}})</code> —
        ${{escapeHtml(d.vendor || '')}} ${{escapeHtml(d.model || '')}} [${{escapeHtml(d.role || 'switch')}}]
        IP: <code>${{escapeHtml(d.management_ip || 'N/A')}}</code>
      </div>
      <div class="port-grid">${{chips || '<em>No ports provisioned</em>'}}</div>
    </div>`;
  }}).join('');
  document.getElementById('device-port-grids').innerHTML = devCards;

  // Update VLAN summary table
  const vlanRows = (state.vlan_subnet_summary || []).map(vs => `<tr>
    <td><code>${{escapeHtml(vs.vlan_id || '-')}}</code></td>
    <td><strong>${{escapeHtml(vs.vlan_name || '-')}}</strong></td>
    <td><code>${{escapeHtml(vs.subnet_id || '-')}}</code></td>
    <td><code>${{escapeHtml(vs.cidr || '-')}}</code></td>
    <td><code>${{escapeHtml(vs.gateway || '-')}}</code></td>
    <td>${{Number(vs.ip_count || 0)}}</td>
    <td>${{Number(vs.device_port_count || 0)}}</td>
    <td>${{Number(vs.equipment_count || 0)}}</td>
  </tr>`).join('');
  document.getElementById('vlan-summary-tbody').innerHTML = vlanRows;

  // Update Audit log table
  const auditRows = (state.audit_log || []).map(a => `<tr>
    <td><code>${{escapeHtml(a.timestamp)}}</code></td>
    <td>${{escapeHtml(a.actor)}}</td>
    <td><span class="badge badge-info">${{escapeHtml(a.action)}}</span></td>
    <td><code>${{escapeHtml(a.target_type)}}:${{escapeHtml(a.target_id)}}</code></td>
    <td><code>${{escapeHtml(JSON.stringify(a.changes || {{}}))}}</code></td>
    <td>${{escapeHtml(a.reason)}}</td>
  </tr>`).join('');
  document.getElementById('audit-log-tbody').innerHTML = auditRows;

  applyInventoryFilters();
  renderSwitchFaceplate();
  refreshTopologyMap();
}}

function applyInventoryFilters() {{
  const q = (document.getElementById('inventory-search').value || '').toLowerCase();
  const vlan = document.getElementById('filter-vlan').value || '';
  const subnet = document.getElementById('filter-subnet').value || '';
  const cls = document.getElementById('filter-classification').value || '';

  document.querySelectorAll('#inventory-tbody tr').forEach(row => {{
    const text = row.textContent.toLowerCase();
    const rowVlan = row.getAttribute('data-vlan') || '';
    const rowSubnet = row.getAttribute('data-subnet') || '';
    const rowCls = row.getAttribute('data-classification') || '';
    const matchQ = !q || text.includes(q);
    const matchVlan = !vlan || rowVlan === vlan;
    const matchSubnet = !subnet || rowSubnet === subnet;
    const matchCls = !cls || rowCls === cls;
    row.style.display = (matchQ && matchVlan && matchSubnet && matchCls) ? '' : 'none';
  }});
}}

async function refreshFromApi() {{
  const resp = await fetch('/api/state');
  if (resp.ok) {{
    const data = await resp.json();
    renderState(data);
  }}
}}

async function refreshAuditLog() {{
  const resp = await fetch('/api/audit-log');
  if (resp.ok) {{
    const data = await resp.json();
    if (data.audit_log) {{
      WORKBENCH_STATE.audit_log = data.audit_log;
      renderState(WORKBENCH_STATE);
    }}
  }}
}}

function openEditModal(targetType, targetId) {{
  document.getElementById('edit-target-type').value = targetType;
  document.getElementById('edit-target-id').value = targetId;
  const site = WORKBENCH_STATE.site || {{}};
  const patches = WORKBENCH_STATE.patches || [];
  const patch = patches.find(p => p.target_type === targetType && p.target_id === targetId && !p.deleted) || {{}};

  let name = patch.name || patch.hostname || '';
  let catRole = patch.category || patch.role || '';
  if (targetType === 'NetworkDevice') {{
    const dev = (site.devices || []).find(d => d.device_id === targetId) || {{}};
    name = name || dev.hostname || '';
    catRole = catRole || dev.role || '';
  }} else if (targetType === 'Equipment') {{
    const eq = (site.equipment || []).find(e => e.equipment_id === targetId) || {{}};
    name = name || eq.name || '';
    catRole = catRole || eq.category || '';
  }} else if (targetType === 'IPAddress') {{
    name = name || targetId;
  }}

  document.getElementById('edit-name').value = name;
  document.getElementById('edit-category-role').value = catRole;
  document.getElementById('edit-room').value = patch.room || (patch.custom_attributes && patch.custom_attributes.room) || '';
  document.getElementById('edit-vlan-id').value = patch.vlan_id || (patch.custom_attributes && patch.custom_attributes.vlan_id) || '';
  document.getElementById('edit-notes').value = patch.notes || '';
  document.getElementById('edit-pinned-classification').value = patch.pinned_classification || '';
  document.getElementById('edit-reason').value = '';
  document.getElementById('item-edit-modal').classList.add('open');
}}

function closeEditModal() {{
  document.getElementById('item-edit-modal').classList.remove('open');
}}

async function submitItemPatch(ev) {{
  ev.preventDefault();
  const targetType = document.getElementById('edit-target-type').value;
  const targetId = document.getElementById('edit-target-id').value;
  const nameVal = document.getElementById('edit-name').value;
  const catRoleVal = document.getElementById('edit-category-role').value;
  const payload = {{
    target_type: targetType,
    target_id: targetId,
    name: nameVal || null,
    hostname: targetType === 'NetworkDevice' ? (nameVal || null) : null,
    category: targetType === 'Equipment' ? (catRoleVal || null) : null,
    role: targetType === 'NetworkDevice' ? (catRoleVal || null) : null,
    room: document.getElementById('edit-room').value || null,
    vlan_id: document.getElementById('edit-vlan-id').value || null,
    notes: document.getElementById('edit-notes').value || null,
    pinned_classification: document.getElementById('edit-pinned-classification').value || null,
    reason: document.getElementById('edit-reason').value || 'Updated via Workbench UI'
  }};
  const resp = await fetch('/api/items/patch', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify(payload)
  }});
  const data = await resp.json();
  if (resp.ok && data.state) {{
    closeEditModal();
    renderState(data.state);
    showBanner('Saved item patch for ' + targetType + ' ' + targetId, false);
  }} else {{
    showBanner(data.error || 'Failed to save patch', true);
  }}
}}

async function submitDeleteCurrentItem() {{
  const targetType = document.getElementById('edit-target-type').value;
  const targetId = document.getElementById('edit-target-id').value;
  const resp = await fetch('/api/items/patch', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      target_type: targetType,
      target_id: targetId,
      deleted: true,
      reason: document.getElementById('edit-reason').value || 'Deleted via Workbench UI'
    }})
  }});
  const data = await resp.json();
  if (resp.ok && data.state) {{
    closeEditModal();
    renderState(data.state);
    showBanner('Deleted ' + targetType + ' ' + targetId, false);
  }} else {{
    showBanner(data.error || 'Failed to delete item', true);
  }}
}}

async function submitCreateDevice(ev) {{
  ev.preventDefault();
  const payload = {{
    hostname: document.getElementById('dev-hostname').value,
    device_id: document.getElementById('dev-device-id').value || null,
    template_id: document.getElementById('dev-template-id').value || null,
    management_ip: document.getElementById('dev-mgmt-ip').value || null,
    role: document.getElementById('dev-role').value || null,
    port_count: document.getElementById('dev-port-count').value ? Number(document.getElementById('dev-port-count').value) : null,
    default_vlan_id: document.getElementById('dev-default-vlan').value || null,
    reason: document.getElementById('dev-reason').value || 'Created device via Workbench UI'
  }};
  const resp = await fetch('/api/devices', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify(payload)
  }});
  const data = await resp.json();
  if (resp.ok && data.state) {{
    document.getElementById('create-device-form').reset();
    renderState(data.state);
    showBanner('Created device ' + data.device.hostname, false);
  }} else {{
    showBanner(data.error || 'Failed to create device', true);
  }}
}}

async function submitPortManager(ev) {{
  ev.preventDefault();
  const payload = {{
    device_id: document.getElementById('pm-device-id').value,
    name: document.getElementById('pm-port-name').value || null,
    range_spec: document.getElementById('pm-range-spec').value || null,
    admin_status: document.getElementById('pm-admin-status').value || 'up',
    oper_status: document.getElementById('pm-oper-status').value || 'down',
    poe_status: document.getElementById('pm-poe-status').value || null,
    vlan_id: document.getElementById('pm-vlan-id').value || null,
    connected_mac: document.getElementById('pm-connected-mac').value || null,
    connected_device_id: document.getElementById('pm-connected-device').value || null,
    reason: document.getElementById('pm-reason').value || 'Updated ports via Workbench UI'
  }};
  const resp = await fetch('/api/devices/ports', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify(payload)
  }});
  const data = await resp.json();
  if (resp.ok && data.state) {{
    renderState(data.state);
    showBanner('Updated ' + (data.ports ? data.ports.length : 0) + ' port(s)', false);
  }} else {{
    showBanner(data.error || 'Failed to update ports', true);
  }}
}}

async function submitVlanForm(ev) {{
  ev.preventDefault();
  const payload = {{
    vlan_id: document.getElementById('vlan-id-input').value,
    name: document.getElementById('vlan-name-input').value || null,
    subnet_id: document.getElementById('vlan-subnet-id-input').value || null,
    cidr: document.getElementById('vlan-cidr-input').value || null,
    gateway: document.getElementById('vlan-gateway-input').value || null,
    reason: document.getElementById('vlan-reason-input').value || 'Saved VLAN/Subnet via Workbench UI'
  }};
  const resp = await fetch('/api/vlans', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify(payload)
  }});
  const data = await resp.json();
  if (resp.ok && data.state) {{
    document.getElementById('vlan-form').reset();
    renderState(data.state);
    showBanner('Saved VLAN ' + data.vlan.vlan_id, false);
  }} else {{
    showBanner(data.error || 'Failed to save VLAN', true);
  }}
}}
{v2_script}
</script>
</body>
</html>
"""


__all__ = [
    "DEFAULT_WORKBENCH_TITLE",
    "render_workbench_html",
]
