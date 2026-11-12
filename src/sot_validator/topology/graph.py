"""Network topology graph builder for routers, switches, VLANs, ports, and hosts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import ipaddress
import json
import re
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationResult,
    _require_non_empty_str,
)
from sot_validator.topology.device_types import normalize_mac_address

VALID_NODE_TYPES: tuple[str, ...] = (
    "site",
    "router",
    "switch",
    "vlan",
    "subnet",
    "port",
    "equipment",
    "ip",
)

VALID_EDGE_RELATIONS: tuple[str, ...] = (
    "routes_vlan",
    "uplink_to",
    "member_of_vlan",
    "connected_port",
    "assigned_ip",
    "hosts_vm",
)

_ROUTER_DEVICE_ROLES: frozenset[str] = frozenset(
    {"router", "l3_switch", "firewall", "gateway"}
)
_ROUTER_HOSTNAME_TOKENS: frozenset[str] = frozenset(
    {"router", "gw", "gateway", "rtr", "udm", "edge"}
)
_ACTIVE_POE_STATES: frozenset[str] = frozenset(
    {"delivering", "active", "on", "searching", "fault"}
)
_MERMAID_RESERVED_WORDS: frozenset[str] = frozenset(
    {"end", "subgraph", "flowchart", "graph", "style", "class", "click", "default"}
)
_NON_ALNUM_PATTERN = re.compile(r"[^a-zA-Z0-9_]+")
_TOKEN_SPLIT_PATTERN = re.compile(r"[^a-z0-9]+")


def _normalize_optional_mac(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str) or not mac.strip():
        return None
    try:
        return normalize_mac_address(mac)
    except ValueError:
        return mac.strip().lower()


def _is_router_hostname(hostname: str) -> bool:
    lower = hostname.strip().lower()
    if any(sub in lower for sub in ("router", "gateway", "udm")):
        return True
    tokens = {tok for tok in _TOKEN_SPLIT_PATTERN.split(lower) if tok}
    return bool(tokens & _ROUTER_HOSTNAME_TOKENS)


def _sanitize_mermaid_id(raw_id: str) -> str:
    cleaned = _NON_ALNUM_PATTERN.sub("_", raw_id.strip()).strip("_")
    if not cleaned:
        cleaned = "node"
    if cleaned[0].isdigit() or cleaned.lower() in _MERMAID_RESERVED_WORDS:
        cleaned = f"n_{cleaned}"
    return cleaned


def _escape_mermaid_label(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace('"', "'")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def _escape_mermaid_edge_label(text: str) -> str:
    return (
        text.replace("|", "/")
        .replace('"', "'")
        .replace("\n", " ")
        .replace("\r", " ")
    )


@dataclass
class TopologyNode:
    """Single vertex in a site network topology graph."""

    node_id: str
    node_type: str
    label: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    vlan_id: Optional[str] = None
    status: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.node_id, "node_id")
        _require_non_empty_str(self.node_type, "node_type")
        _require_non_empty_str(self.label, "label")

        normalized_type = self.node_type.strip().lower()
        if normalized_type not in VALID_NODE_TYPES:
            raise ValueError(
                f"Invalid node_type {self.node_type!r}; must be one of {VALID_NODE_TYPES}"
            )
        self.node_type = normalized_type
        self.mac = _normalize_optional_mac(self.mac)

        if self.metadata is None:
            self.metadata = {}
        elif isinstance(self.metadata, Mapping):
            self.metadata = dict(self.metadata)
        else:
            raise ValueError("metadata must be a mapping or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "ip": self.ip,
            "mac": self.mac,
            "vlan_id": self.vlan_id,
            "status": self.status,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TopologyNode:
        return cls(
            node_id=data["node_id"],
            node_type=data["node_type"],
            label=data["label"],
            ip=data.get("ip"),
            mac=data.get("mac"),
            vlan_id=data.get("vlan_id"),
            status=data.get("status"),
            metadata=data.get("metadata") or {},
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> TopologyNode:
        return cls.from_dict(json.loads(raw))


@dataclass
class TopologyEdge:
    """Directed relationship between two TopologyNode records."""

    source_id: str
    target_id: str
    relation: str
    port_name: Optional[str] = None
    vlan_id: Optional[str] = None
    poe_status: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.source_id, "source_id")
        _require_non_empty_str(self.target_id, "target_id")
        _require_non_empty_str(self.relation, "relation")

        normalized_relation = self.relation.strip().lower()
        if normalized_relation not in VALID_EDGE_RELATIONS:
            raise ValueError(
                f"Invalid edge relation {self.relation!r}; must be one of {VALID_EDGE_RELATIONS}"
            )
        self.relation = normalized_relation

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "port_name": self.port_name,
            "vlan_id": self.vlan_id,
            "poe_status": self.poe_status,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TopologyEdge:
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            relation=data["relation"],
            port_name=data.get("port_name"),
            vlan_id=data.get("vlan_id"),
            poe_status=data.get("poe_status"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> TopologyEdge:
        return cls.from_dict(json.loads(raw))


@dataclass
class TopologyGraph:
    """Complete site network topology graph with nodes, directed edges, and summary counts."""

    site_id: str
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)
    summary_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.site_id, "site_id")
        self.nodes = [
            n if isinstance(n, TopologyNode) else TopologyNode.from_dict(n)
            for n in self.nodes
        ]
        self.edges = [
            e if isinstance(e, TopologyEdge) else TopologyEdge.from_dict(e)
            for e in self.edges
        ]
        self.summary_counts = self.compute_summary_counts()

    def compute_summary_counts(self) -> dict[str, int]:
        """Compute node type, edge relation, and total counts for the graph."""
        counts: dict[str, int] = {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
        }
        for node_type in VALID_NODE_TYPES:
            counts[node_type] = 0
        for relation in VALID_EDGE_RELATIONS:
            counts[relation] = 0

        for node in self.nodes:
            counts[node.node_type] = counts.get(node.node_type, 0) + 1
        for edge in self.edges:
            counts[edge.relation] = counts.get(edge.relation, 0) + 1

        self.summary_counts = counts
        return counts

    def get_node(self, node_id: str) -> Optional[TopologyNode]:
        """Return the TopologyNode matching node_id, or None if not found."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None

    def get_edges_for_node(self, node_id: str) -> list[TopologyEdge]:
        """Return all TopologyEdge instances where node_id is the source or target."""
        return [
            edge
            for edge in self.edges
            if edge.source_id == node_id or edge.target_id == node_id
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "summary_counts": dict(self. compute_summary_counts()),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TopologyGraph:
        return cls(
            site_id=data["site_id"],
            nodes=[
                n if isinstance(n, TopologyNode) else TopologyNode.from_dict(n)
                for n in data.get("nodes", [])
            ],
            edges=[
                e if isinstance(e, TopologyEdge) else TopologyEdge.from_dict(e)
                for e in data.get("edges", [])
            ],
            summary_counts=dict(data.get("summary_counts") or {}),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> TopologyGraph:
        return cls.from_dict(json.loads(raw))

    def to_mermaid(self) -> str:
        """Serialize the topology graph to a Mermaid flowchart LR diagram."""
        lines: list[str] = ["flowchart LR"]
        mermaid_ids: dict[str, str] = {}
        used_ids: set[str] = set()

        def resolve_mermaid_id(raw_node_id: str) -> str:
            if raw_node_id in mermaid_ids:
                return mermaid_ids[raw_node_id]
            base = _sanitize_mermaid_id(raw_node_id)
            candidate = base
            suffix = 2
            while candidate in used_ids:
                candidate = f"{base}_{suffix}"
                suffix += 1
            used_ids.add(candidate)
            mermaid_ids[raw_node_id] = candidate
            return candidate

        for node in self.nodes:
            m_id = resolve_mermaid_id(node.node_id)
            label_parts = [node.label]
            if node.ip and node.ip != node.label:
                label_parts.append(node.ip)
            escaped_label = _escape_mermaid_label(" - ".join(label_parts))
            lines.append(f'    {m_id}["{escaped_label}"]')

        for edge in self.edges:
            src_id = resolve_mermaid_id(edge.source_id)
            dst_id = resolve_mermaid_id(edge.target_id)
            details: list[str] = [edge.relation]
            if edge.port_name:
                details.append(edge.port_name)
            if edge.vlan_id:
                details.append(f"VLAN {edge.vlan_id}")
            if edge.poe_status:
                details.append(f"PoE:{edge.poe_status}")
            edge_label = _escape_mermaid_edge_label(" ".join(details))
            lines.append(f"    {src_id} -->|{edge_label}| {dst_id}")

        return "\n".join(lines)


class TopologyGraphBuilder:
    """Builds a deterministic TopologyGraph from a Site snapshot and optional ValidationResults."""

    def __init__(self, *, include_unconnected_ports: bool = False) -> None:
        self.include_unconnected_ports = include_unconnected_ports

    def build(
        self,
        site: Site,
        validation_results: Optional[Sequence[ValidationResult]] = None,
        *,
        include_unconnected_ports: Optional[bool] = None,
    ) -> TopologyGraph:
        """Construct a TopologyGraph for the given Site and optional ValidationResult sequence."""
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")

        include_all_ports = (
            self.include_unconnected_ports
            if include_unconnected_ports is None
            else include_unconnected_ports
        )

        val_by_id: dict[str, ValidationResult] = {}
        val_by_name: dict[str, ValidationResult] = {}
        if validation_results:
            for res in validation_results:
                val_by_id[res.item_id] = res
                val_by_name[res.name] = res

        nodes: list[TopologyNode] = []
        node_by_id: dict[str, TopologyNode] = {}

        def register_node(
            raw_id: str,
            node_type: str,
            label: str,
            *,
            ip: Optional[str] = None,
            mac: Optional[str] = None,
            vlan_id: Optional[str] = None,
            status: Optional[str] = None,
            metadata: Optional[dict[str, Any]] = None,
            entity_id_for_validation: Optional[str] = None,
        ) -> TopologyNode:
            candidate_id = (
                raw_id if raw_id not in node_by_id else f"{node_type}:{raw_id}"
            )
            if candidate_id in node_by_id:
                return node_by_id[candidate_id]

            meta = dict(metadata) if metadata else {}
            resolved_status = status

            lookup_keys = [raw_id, candidate_id]
            if entity_id_for_validation:
                lookup_keys.insert(0, entity_id_for_validation)
            if ip:
                lookup_keys.append(ip)

            matched_val: Optional[ValidationResult] = None
            for key in lookup_keys:
                if key in val_by_id:
                    matched_val = val_by_id[key]
                    break
            if matched_val is None and label in val_by_name:
                matched_val = val_by_name[label]

            if matched_val is not None:
                resolved_status = matched_val.classification.value
                meta["confidence"] = matched_val.confidence

            node = TopologyNode(
                node_id=candidate_id,
                node_type=node_type,
                label=label,
                ip=ip,
                mac=mac,
                vlan_id=vlan_id,
                status=resolved_status,
                metadata=meta,
            )
            nodes.append(node)
            node_by_id[candidate_id] = node
            return node

        # 1. Site node
        site_node = register_node(
            site.site_id,
            "site",
            site.name,
            metadata={
                "address": site.address,
                "contact_info": site.contact_info,
                "rooms": list(site.rooms),
            },
        )

        # Helper lookups for subnets, VLANs, IPs, and MACs
        subnet_by_id: dict[str, Subnet] = {s.subnet_id: s for s in site.subnets}
        parsed_subnets: list[tuple[ipaddress._BaseNetwork, Subnet]] = []
        for s in site.subnets:
            try:
                parsed_subnets.append((ipaddress.ip_network(s.cidr, strict=False), s))
            except ValueError:
                continue

        vlan_by_id: dict[str, VLAN] = {v.vlan_id: v for v in site.vlans}
        parsed_vlans: list[tuple[ipaddress._BaseNetwork, VLAN]] = []
        for v in site.vlans:
            if v.cidr:
                try:
                    parsed_vlans.append((ipaddress.ip_network(v.cidr, strict=False), v))
                except ValueError:
                    continue

        site_gateway_ips: set[str] = set()
        for v in site.vlans:
            if v.gateway and v.gateway.strip():
                site_gateway_ips.add(v.gateway.strip())
        for s in site.subnets:
            if s.gateway and s.gateway.strip():
                site_gateway_ips.add(s.gateway.strip())

        def infer_vlan_for_subnet_id(subnet_id: Optional[str]) -> Optional[str]:
            if not subnet_id:
                return None
            sub = subnet_by_id.get(subnet_id)
            if sub and sub.vlan_id:
                return sub.vlan_id
            for v in site.vlans:
                if v.subnet_id == subnet_id:
                    return v.vlan_id
                if sub and v.cidr and v.cidr == sub.cidr:
                    return v.vlan_id
            return None

        def infer_subnet_and_vlan_for_ip(
            ip_str: Optional[str],
        ) -> tuple[Optional[str], Optional[str]]:
            if not ip_str or not ip_str.strip():
                return None, None
            cleaned = ip_str.strip()
            for ip_rec in site.ip_addresses:
                if ip_rec.ip == cleaned:
                    return ip_rec.subnet_id, infer_vlan_for_subnet_id(ip_rec.subnet_id)
            try:
                ip_obj = ipaddress.ip_address(cleaned)
            except ValueError:
                return None, None
            for net, sub in parsed_subnets:
                if ip_obj in net:
                    return sub.subnet_id, sub.vlan_id or infer_vlan_for_subnet_id(
                        sub.subnet_id
                    )
            for net, v in parsed_vlans:
                if ip_obj in net:
                    return v.subnet_id, v.vlan_id
            return None, None

        ip_rec_by_ip: dict[str, IPAddress] = {
            ip_rec.ip: ip_rec for ip_rec in site.ip_addresses
        }

        def extract_ip_mac(ip_rec: IPAddress) -> Optional[str]:
            raw_mac = ip_rec.arp_mac or (
                ip_rec.arp_entry.arp_mac if ip_rec.arp_entry is not None else None
            )
            return _normalize_optional_mac(raw_mac)

        # 2. Router and Switch nodes
        device_node_id_by_dev_id: dict[str, str] = {}
        router_dev_ids: list[str] = []
        switch_dev_ids: list[str] = []

        for dev in site.devices:
            role_lower = (dev.role or "").strip().lower()
            mgmt_ip = dev.management_ip.strip() if dev.management_ip else None
            is_router = (
                role_lower in _ROUTER_DEVICE_ROLES
                or (mgmt_ip is not None and mgmt_ip in site_gateway_ips)
                or (not role_lower and _is_router_hostname(dev.hostname))
            )
            dev_node_type = "router" if is_router else "switch"

            dev_mac: Optional[str] = None
            if mgmt_ip and mgmt_ip in ip_rec_by_ip:
                dev_mac = extract_ip_mac(ip_rec_by_ip[mgmt_ip])
            if dev_mac is None:
                for ip_rec in site.ip_addresses:
                    if ip_rec.assigned_object_id == dev.device_id:
                        dev_mac = extract_ip_mac(ip_rec)
                        if dev_mac:
                            break

            _, dev_vlan_id = infer_subnet_and_vlan_for_ip(mgmt_ip)
            if dev_vlan_id is None:
                for p in dev.ports:
                    if p.vlan_id:
                        dev_vlan_id = p.vlan_id
                        break

            dev_node = register_node(
                dev.device_id,
                dev_node_type,
                dev.hostname,
                ip=mgmt_ip,
                mac=dev_mac,
                vlan_id=dev_vlan_id,
                metadata={
                    "vendor": dev.vendor,
                    "model": dev.model,
                    "role": dev.role,
                    "port_count": len(dev.ports),
                },
            )
            device_node_id_by_dev_id[dev.device_id] = dev_node.node_id
            if is_router:
                router_dev_ids.append(dev.device_id)
            else:
                switch_dev_ids.append(dev.device_id)

        # 3. VLAN nodes (from site.vlans + any referenced VLAN IDs in subnets/ports)
        vlan_node_id_by_vlan_id: dict[str, str] = {}
        for vlan in site.vlans:
            v_node = register_node(
                vlan.vlan_id,
                "vlan",
                vlan.name or f"VLAN {vlan.vlan_id}",
                vlan_id=vlan.vlan_id,
                metadata={
                    "subnet_id": vlan.subnet_id,
                    "cidr": vlan.cidr,
                    "gateway": vlan.gateway,
                },
            )
            vlan_node_id_by_vlan_id[vlan.vlan_id] = v_node.node_id

        referenced_vlan_ids: list[str] = []
        for sub in site.subnets:
            if sub.vlan_id and sub.vlan_id not in vlan_node_id_by_vlan_id:
                if sub.vlan_id not in referenced_vlan_ids:
                    referenced_vlan_ids.append(sub.vlan_id)
        for dev in site.devices:
            for port in dev.ports:
                if port.vlan_id and port.vlan_id not in vlan_node_id_by_vlan_id:
                    if port.vlan_id not in referenced_vlan_ids:
                        referenced_vlan_ids.append(port.vlan_id)

        for ref_vlan_id in referenced_vlan_ids:
            matching_sub = next(
                (s for s in site.subnets if s.vlan_id == ref_vlan_id), None
            )
            v_node = register_node(
                ref_vlan_id,
                "vlan",
                (
                    matching_sub.name
                    if matching_sub and matching_sub.name
                    else f"VLAN {ref_vlan_id}"
                ),
                vlan_id=ref_vlan_id,
                metadata={
                    "subnet_id": matching_sub.subnet_id if matching_sub else None,
                    "cidr": matching_sub.cidr if matching_sub else None,
                    "gateway": matching_sub.gateway if matching_sub else None,
                },
            )
            vlan_node_id_by_vlan_id[ref_vlan_id] = v_node.node_id

        # 4. Subnet nodes
        subnet_node_id_by_subnet_id: dict[str, str] = {}
        for sub in site.subnets:
            resolved_vlan = sub.vlan_id or infer_vlan_for_subnet_id(sub.subnet_id)
            s_node = register_node(
                sub.subnet_id,
                "subnet",
                sub.name or sub.cidr,
                ip=sub.gateway,
                vlan_id=resolved_vlan,
                metadata={
                    "cidr": sub.cidr,
                    "gateway": sub.gateway,
                },
            )
            subnet_node_id_by_subnet_id[sub.subnet_id] = s_node.node_id

        # Collect all port references from Equipment.connected_ports
        referenced_port_refs: set[str] = set()
        for eq in site.equipment:
            for p_ref in eq.connected_ports:
                if p_ref and p_ref.strip():
                    referenced_port_refs.add(p_ref.strip())

        # 5. Port nodes
        port_node_id_by_port_id: dict[str, str] = {}
        included_ports: list[tuple[NetworkDevice, Port, str]] = []

        for dev in site.devices:
            for port in dev.ports:
                oper_lower = (port.oper_status or "").strip().lower()
                poe_lower = (port.poe_status or "").strip().lower()
                is_referenced_by_eq = (
                    port.port_id in referenced_port_refs
                    or port.name in referenced_port_refs
                    or f"{dev.device_id}:{port.name}" in referenced_port_refs
                    or f"{dev.hostname}:{port.name}" in referenced_port_refs
                )
                has_validation = (
                    port.port_id in val_by_id
                    or f"{dev.hostname}:{port.name}" in val_by_name
                )
                is_active_or_connected = (
                    bool(port.connected_device_id and port.connected_device_id.strip())
                    or bool(port.connected_mac and port.connected_mac.strip())
                    or oper_lower == "up"
                    or poe_lower in _ACTIVE_POE_STATES
                    or is_referenced_by_eq
                    or has_validation
                )

                if include_all_ports or is_active_or_connected:
                    p_node = register_node(
                        port.port_id,
                        "port",
                        f"{dev.hostname}:{port.name}",
                        mac=port.connected_mac,
                        vlan_id=port.vlan_id,
                        status=port.oper_status,
                        metadata={
                            "device_id": port.device_id,
                            "name": port.name,
                            "admin_status": port.admin_status,
                            "oper_status": port.oper_status,
                            "poe_status": port.poe_status,
                            "connected_device_id": port.connected_device_id,
                        },
                    )
                    port_node_id_by_port_id[port.port_id] = p_node.node_id
                    included_ports.append((dev, port, p_node.node_id))

        # 6. Equipment nodes
        eq_node_id_by_eq_id: dict[str, str] = {}
        eq_by_id: dict[str, Equipment] = {eq.equipment_id: eq for eq in site.equipment}
        eq_mac_by_eq_id: dict[str, Optional[str]] = {}
        eq_vlans_by_eq_id: dict[str, list[str]] = {}

        for eq in site.equipment:
            primary_ip = eq.assigned_ips[0] if eq.assigned_ips else None
            resolved_mac: Optional[str] = None
            eq_vlans: list[str] = []

            # Check ports connected to this equipment
            for dev in site.devices:
                for port in dev.ports:
                    if (
                        port.connected_device_id == eq.equipment_id
                        or port.port_id in eq.connected_ports
                        or port.name in eq.connected_ports
                        or f"{dev.device_id}:{port.name}" in eq.connected_ports
                        or f"{dev.hostname}:{port.name}" in eq.connected_ports
                    ):
                        if resolved_mac is None and port.connected_mac:
                            resolved_mac = _normalize_optional_mac(port.connected_mac)
                        if port.vlan_id and port.vlan_id not in eq_vlans:
                            eq_vlans.append(port.vlan_id)

            # Check IPAddress records matching this equipment
            for ip_rec in site.ip_addresses:
                if (
                    ip_rec.assigned_object_id == eq.equipment_id
                    or ip_rec.ip in eq.assigned_ips
                ):
                    if resolved_mac is None:
                        resolved_mac = extract_ip_mac(ip_rec)
                    v_id = infer_vlan_for_subnet_id(ip_rec.subnet_id)
                    if v_id and v_id not in eq_vlans:
                        eq_vlans.append(v_id)

            # Check assigned IPs against subnets/VLANs
            for ip_str in eq.assigned_ips:
                _, v_id = infer_subnet_and_vlan_for_ip(ip_str)
                if v_id and v_id not in eq_vlans:
                    eq_vlans.append(v_id)

            # If resolved_mac matches a switch port with a VLAN, record that VLAN too
            if resolved_mac:
                for dev in site.devices:
                    for port in dev.ports:
                        if (
                            _normalize_optional_mac(port.connected_mac) == resolved_mac
                            and port.vlan_id
                            and port.vlan_id not in eq_vlans
                        ):
                            eq_vlans.append(port.vlan_id)

            primary_vlan = eq_vlans[0] if eq_vlans else None
            eq_mac_by_eq_id[eq.equipment_id] = resolved_mac
            eq_vlans_by_eq_id[eq.equipment_id] = eq_vlans

            category_val = (
                eq.category.value
                if hasattr(eq.category, "value")
                else str(eq.category)
            )
            eq_node = register_node(
                eq.equipment_id,
                "equipment",
                eq.name,
                ip=primary_ip,
                mac=resolved_mac,
                vlan_id=primary_vlan,
                status=eq.power_state,
                metadata={
                    "category": category_val,
                    "assigned_ips": list(eq.assigned_ips),
                    "connected_ports": list(eq.connected_ports),
                    "hypervisor_id": eq.hypervisor_id,
                    "power_state": eq.power_state,
                },
            )
            eq_node_id_by_eq_id[eq.equipment_id] = eq_node.node_id

        # 7. IP nodes (from site.ip_addresses + any Equipment.assigned_ips not in site.ip_addresses)
        ip_node_id_by_ip: dict[str, str] = {}
        for ip_rec in site.ip_addresses:
            _, v_id = infer_subnet_and_vlan_for_ip(ip_rec.ip)
            ip_mac = extract_ip_mac(ip_rec)
            ip_node = register_node(
                ip_rec.ip,
                "ip",
                ip_rec.ip,
                ip=ip_rec.ip,
                mac=ip_mac,
                vlan_id=v_id,
                metadata={
                    "subnet_id": ip_rec.subnet_id,
                    "assigned_object_type": ip_rec.assigned_object_type,
                    "assigned_object_id": ip_rec.assigned_object_id,
                    "arp_source_device_id": ip_rec.arp_source_device_id,
                },
            )
            ip_node_id_by_ip[ip_rec.ip] = ip_node.node_id

        for eq in site.equipment:
            for ip_str in eq.assigned_ips:
                cleaned_ip = ip_str.strip()
                if not cleaned_ip or cleaned_ip in ip_node_id_by_ip:
                    continue
                sub_id, v_id = infer_subnet_and_vlan_for_ip(cleaned_ip)
                ip_node = register_node(
                    cleaned_ip,
                    "ip",
                    cleaned_ip,
                    ip=cleaned_ip,
                    mac=eq_mac_by_eq_id.get(eq.equipment_id),
                    vlan_id=v_id,
                    metadata={
                        "subnet_id": sub_id,
                        "assigned_object_type": "equipment",
                        "assigned_object_id": eq.equipment_id,
                        "arp_source_device_id": None,
                    },
                )
                ip_node_id_by_ip[cleaned_ip] = ip_node.node_id

        # Edge management (deduplicated by (source_id, target_id, relation))
        edges: list[TopologyEdge] = []
        edge_by_key: dict[tuple[str, str, str], TopologyEdge] = {}

        def add_edge(
            source_id: str,
            target_id: str,
            relation: str,
            *,
            port_name: Optional[str] = None,
            vlan_id: Optional[str] = None,
            poe_status: Optional[str] = None,
        ) -> TopologyEdge:
            key = (source_id, target_id, relation)
            if key in edge_by_key:
                existing = edge_by_key[key]
                if existing.port_name is None and port_name is not None:
                    existing.port_name = port_name
                if existing.vlan_id is None and vlan_id is not None:
                    existing.vlan_id = vlan_id
                if existing.poe_status is None and poe_status is not None:
                    existing.poe_status = poe_status
                return existing
            edge = TopologyEdge(
                source_id=source_id,
                target_id=target_id,
                relation=relation,
                port_name=port_name,
                vlan_id=vlan_id,
                poe_status=poe_status,
            )
            edges.append(edge)
            edge_by_key[key] = edge
            return edge

        # Edge group A: uplink_to (Site -> Routers, Switch -> Router/Switch)
        if router_dev_ids:
            for r_dev_id in router_dev_ids:
                add_edge(
                    site_node.node_id,
                    device_node_id_by_dev_id[r_dev_id],
                    "uplink_to",
                )
        else:
            for sw_dev_id in switch_dev_ids:
                add_edge(
                    site_node.node_id,
                    device_node_id_by_dev_id[sw_dev_id],
                    "uplink_to",
                )

        # Track which switches have an explicit device-to-device uplink
        switches_with_uplink: set[str] = set()
        router_id_set = set(router_dev_ids)
        switch_id_set = set(switch_dev_ids)

        for dev in site.devices:
            for port in dev.ports:
                conn_id = (
                    port.connected_device_id.strip()
                    if port.connected_device_id
                    else None
                )
                if not conn_id or conn_id not in device_node_id_by_dev_id:
                    continue

                if dev.device_id in switch_id_set and conn_id in router_id_set:
                    add_edge(
                        device_node_id_by_dev_id[dev.device_id],
                        device_node_id_by_dev_id[conn_id],
                        "uplink_to",
                        port_name=port.name,
                        vlan_id=port.vlan_id,
                        poe_status=port.poe_status,
                    )
                    switches_with_uplink.add(dev.device_id)
                elif dev.device_id in router_id_set and conn_id in switch_id_set:
                    add_edge(
                        device_node_id_by_dev_id[conn_id],
                        device_node_id_by_dev_id[dev.device_id],
                        "uplink_to",
                        port_name=port.name,
                        vlan_id=port.vlan_id,
                        poe_status=port.poe_status,
                    )
                    switches_with_uplink.add(conn_id)
                elif (
                    dev.device_id in switch_id_set
                    and conn_id in switch_id_set
                    and dev.device_id != conn_id
                ):
                    add_edge(
                        device_node_id_by_dev_id[dev.device_id],
                        device_node_id_by_dev_id[conn_id],
                        "uplink_to",
                        port_name=port.name,
                        vlan_id=port.vlan_id,
                        poe_status=port.poe_status,
                    )
                    switches_with_uplink.add(dev.device_id)

        # Fallback uplink: if a switch has no explicit device-to-device uplink, connect to site router
        if router_dev_ids:
            primary_router_node_id = device_node_id_by_dev_id[router_dev_ids[0]]
            for sw_dev_id in switch_dev_ids:
                if sw_dev_id not in switches_with_uplink:
                    add_edge(
                        device_node_id_by_dev_id[sw_dev_id],
                        primary_router_node_id,
                        "uplink_to",
                    )

        # Edge group B: routes_vlan (Router -> VLAN, VLAN -> Subnet)
        router_served_vlans: dict[str, set[str]] = {
            r_id: set() for r_id in router_dev_ids
        }
        dev_by_id: dict[str, NetworkDevice] = {d.device_id: d for d in site.devices}

        for r_id in router_dev_ids:
            r_dev = dev_by_id[r_id]
            r_ips: set[str] = set()
            if r_dev.management_ip:
                r_ips.add(r_dev.management_ip.strip())
            for ip_rec in site.ip_addresses:
                if ip_rec.assigned_object_id == r_id:
                    r_ips.add(ip_rec.ip)

            for port in r_dev.ports:
                if port.vlan_id and port.vlan_id in vlan_node_id_by_vlan_id:
                    router_served_vlans[r_id].add(port.vlan_id)

            for v_id in vlan_node_id_by_vlan_id:
                v_obj = vlan_by_id.get(v_id)
                if v_obj and v_obj.gateway and v_obj.gateway.strip() in r_ips:
                    router_served_vlans[r_id].add(v_id)
                for sub in site.subnets:
                    if (
                        sub.vlan_id == v_id
                        and sub.gateway
                        and sub.gateway.strip() in r_ips
                    ):
                        router_served_vlans[r_id].add(v_id)

            for r_ip in r_ips:
                _, v_id = infer_subnet_and_vlan_for_ip(r_ip)
                if v_id and v_id in vlan_node_id_by_vlan_id:
                    router_served_vlans[r_id].add(v_id)

        # Any VLAN not explicitly matched to a specific router is routed by the site's router(s)
        if router_dev_ids:
            explicitly_routed_vlans: set[str] = set()
            for v_set in router_served_vlans.values():
                explicitly_routed_vlans.update(v_set)
            for v_id in vlan_node_id_by_vlan_id:
                if v_id not in explicitly_routed_vlans:
                    for r_id in router_dev_ids:
                        router_served_vlans[r_id].add(v_id)

            for r_id, v_ids in router_served_vlans.items():
                r_node_id = device_node_id_by_dev_id[r_id]
                for v_id in v_ids:
                    if v_id in vlan_node_id_by_vlan_id:
                        add_edge(
                            r_node_id,
                            vlan_node_id_by_vlan_id[v_id],
                            "routes_vlan",
                            vlan_id=v_id,
                        )

        # VLAN -> Subnet edges (or Router -> Subnet if subnet has no VLAN)
        for sub in site.subnets:
            sub_node_id = subnet_node_id_by_subnet_id[sub.subnet_id]
            matched_vlan_ids: list[str] = []
            if sub.vlan_id and sub.vlan_id in vlan_node_id_by_vlan_id:
                matched_vlan_ids.append(sub.vlan_id)
            for v in site.vlans:
                if (
                    v.subnet_id == sub.subnet_id
                    or (v.cidr and v.cidr == sub.cidr)
                ) and v.vlan_id not in matched_vlan_ids:
                    matched_vlan_ids.append(v.vlan_id)

            if matched_vlan_ids:
                for v_id in matched_vlan_ids:
                    add_edge(
                        vlan_node_id_by_vlan_id[v_id],
                        sub_node_id,
                        "routes_vlan",
                        vlan_id=v_id,
                    )
            elif router_dev_ids:
                add_edge(
                    device_node_id_by_dev_id[router_dev_ids[0]],
                    sub_node_id,
                    "routes_vlan",
                )

        # Edge group C: connected_port (Device -> Port, Port -> Equipment / Device / IP)
        for dev, port, p_node_id in included_ports:
            dev_node_id = device_node_id_by_dev_id[dev.device_id]
            add_edge(
                dev_node_id,
                p_node_id,
                "connected_port",
                port_name=port.name,
                vlan_id=port.vlan_id,
                poe_status=port.poe_status,
            )

            downstream_targets: list[str] = []

            # 1. port.connected_device_id
            if port.connected_device_id:
                conn_id = port.connected_device_id.strip()
                if conn_id in eq_node_id_by_eq_id:
                    downstream_targets.append(eq_node_id_by_eq_id[conn_id])
                elif conn_id in device_node_id_by_dev_id:
                    downstream_targets.append(device_node_id_by_dev_id[conn_id])

            # 2. Equipment.connected_ports referencing this port
            for eq in site.equipment:
                if (
                    port.port_id in eq.connected_ports
                    or port.name in eq.connected_ports
                    or f"{dev.device_id}:{port.name}" in eq.connected_ports
                    or f"{dev.hostname}:{port.name}" in eq.connected_ports
                ):
                    eq_target = eq_node_id_by_eq_id[eq.equipment_id]
                    if eq_target not in downstream_targets:
                        downstream_targets.append(eq_target)

            # 3. port.connected_mac correlation against equipment and IP ARP entries
            norm_port_mac = _normalize_optional_mac(port.connected_mac)
            if norm_port_mac:
                for eq_id, eq_mac in eq_mac_by_eq_id.items():
                    if eq_mac == norm_port_mac:
                        eq_target = eq_node_id_by_eq_id[eq_id]
                        if eq_target not in downstream_targets:
                            downstream_targets.append(eq_target)

                for ip_rec in site.ip_addresses:
                    if extract_ip_mac(ip_rec) == norm_port_mac:
                        obj_id = ip_rec.assigned_object_id
                        if obj_id and obj_id in eq_node_id_by_eq_id:
                            eq_target = eq_node_id_by_eq_id[obj_id]
                            if eq_target not in downstream_targets:
                                downstream_targets.append(eq_target)
                        elif obj_id and obj_id in device_node_id_by_dev_id:
                            dev_target = device_node_id_by_dev_id[obj_id]
                            if dev_target not in downstream_targets:
                                downstream_targets.append(dev_target)
                        elif ip_rec.ip in ip_node_id_by_ip:
                            ip_target = ip_node_id_by_ip[ip_rec.ip]
                            if ip_target not in downstream_targets:
                                downstream_targets.append(ip_target)

            for target_node_id in downstream_targets:
                add_edge(
                    p_node_id,
                    target_node_id,
                    "connected_port",
                    port_name=port.name,
                    vlan_id=port.vlan_id,
                    poe_status=port.poe_status,
                )

        # Edge group D: member_of_vlan (VLAN -> Equipment, Switch, unassigned IP)
        for eq in site.equipment:
            eq_node_id = eq_node_id_by_eq_id[eq.equipment_id]
            for v_id in eq_vlans_by_eq_id.get(eq.equipment_id, []):
                if v_id in vlan_node_id_by_vlan_id:
                    add_edge(
                        vlan_node_id_by_vlan_id[v_id],
                        eq_node_id,
                        "member_of_vlan",
                        vlan_id=v_id,
                    )

        for sw_id in switch_dev_ids:
            sw_dev = dev_by_id[sw_id]
            sw_node_id = device_node_id_by_dev_id[sw_id]
            sw_vlans: list[str] = []
            _, mgmt_vlan = infer_subnet_and_vlan_for_ip(sw_dev.management_ip)
            if mgmt_vlan and mgmt_vlan in vlan_node_id_by_vlan_id:
                sw_vlans.append(mgmt_vlan)
            for port in sw_dev.ports:
                if (
                    port.vlan_id
                    and port.vlan_id in vlan_node_id_by_vlan_id
                    and port.vlan_id not in sw_vlans
                ):
                    sw_vlans.append(port.vlan_id)
            for v_id in sw_vlans:
                add_edge(
                    vlan_node_id_by_vlan_id[v_id],
                    sw_node_id,
                    "member_of_vlan",
                    vlan_id=v_id,
                )

        # Unassigned IP nodes -> member_of_vlan
        assigned_ip_set: set[str] = set()
        for eq in site.equipment:
            for ip_str in eq.assigned_ips:
                assigned_ip_set.add(ip_str.strip())

        for ip_rec in site.ip_addresses:
            obj_id = ip_rec.assigned_object_id
            is_assigned_to_known = bool(
                (obj_id and (obj_id in eq_node_id_by_eq_id or obj_id in device_node_id_by_dev_id))
                or ip_rec.ip in assigned_ip_set
            )
            if not is_assigned_to_known:
                _, v_id = infer_subnet_and_vlan_for_ip(ip_rec.ip)
                if v_id and v_id in vlan_node_id_by_vlan_id:
                    add_edge(
                        vlan_node_id_by_vlan_id[v_id],
                        ip_node_id_by_ip[ip_rec.ip],
                        "member_of_vlan",
                        vlan_id=v_id,
                    )

        # Edge group E: assigned_ip (Equipment / Device -> IP)
        for eq in site.equipment:
            eq_node_id = eq_node_id_by_eq_id[eq.equipment_id]
            for ip_str in eq.assigned_ips:
                cleaned_ip = ip_str.strip()
                if cleaned_ip in ip_node_id_by_ip:
                    add_edge(
                        eq_node_id,
                        ip_node_id_by_ip[cleaned_ip],
                        "assigned_ip",
                    )

        for ip_rec in site.ip_addresses:
            ip_node_id = ip_node_id_by_ip[ip_rec.ip]
            obj_id = ip_rec.assigned_object_id
            if obj_id and obj_id in eq_node_id_by_eq_id:
                add_edge(
                    eq_node_id_by_eq_id[obj_id],
                    ip_node_id,
                    "assigned_ip",
                )
            elif obj_id and obj_id in device_node_id_by_dev_id:
                add_edge(
                    device_node_id_by_dev_id[obj_id],
                    ip_node_id,
                    "assigned_ip",
                )

        for dev in site.devices:
            if dev.management_ip and dev.management_ip.strip() in ip_node_id_by_ip:
                add_edge(
                    device_node_id_by_dev_id[dev.device_id],
                    ip_node_id_by_ip[dev.management_ip.strip()],
                    "assigned_ip",
                )

        # Edge group F: hosts_vm (Hypervisor -> VM Equipment)
        eq_node_id_by_name_lower: dict[str, str] = {
            eq.name.strip().lower(): eq_node_id_by_eq_id[eq.equipment_id]
            for eq in site.equipment
        }
        dev_node_id_by_hostname_lower: dict[str, str] = {
            dev.hostname.strip().lower(): device_node_id_by_dev_id[dev.device_id]
            for dev in site.devices
        }

        for eq in site.equipment:
            if not eq.hypervisor_id or not eq.hypervisor_id.strip():
                continue
            hv_ref = eq.hypervisor_id.strip()
            hv_node_id: Optional[str] = None
            if hv_ref in eq_node_id_by_eq_id:
                hv_node_id = eq_node_id_by_eq_id[hv_ref]
            elif hv_ref in device_node_id_by_dev_id:
                hv_node_id = device_node_id_by_dev_id[hv_ref]
            elif hv_ref.lower() in eq_node_id_by_name_lower:
                hv_node_id = eq_node_id_by_name_lower[hv_ref.lower()]
            elif hv_ref.lower() in dev_node_id_by_hostname_lower:
                hv_node_id = dev_node_id_by_hostname_lower[hv_ref.lower()]

            if hv_node_id is not None and hv_node_id != eq_node_id_by_eq_id[eq.equipment_id]:
                add_edge(
                    hv_node_id,
                    eq_node_id_by_eq_id[eq.equipment_id],
                    "hosts_vm",
                )

        return TopologyGraph(
            site_id=site.site_id,
            nodes=nodes,
            edges=edges,
        )


__all__ = [
    "TopologyEdge",
    "TopologyGraph",
    "TopologyGraphBuilder",
    "TopologyNode",
    "VALID_EDGE_RELATIONS",
    "VALID_NODE_TYPES",
]
