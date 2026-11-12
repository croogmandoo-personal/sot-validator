"""Device type catalog, switch/router port builder, network role identifier, and topology graph builder."""

from __future__ import annotations

from sot_validator.topology.device_types import (
    BUILTIN_DEVICE_TEMPLATES,
    DevicePortManager,
    DeviceTypeCatalog,
    DeviceTypeTemplate,
    PortSpec,
    VALID_DEVICE_ROLES,
    normalize_mac_address,
)
from sot_validator.topology.graph import (
    TopologyEdge,
    TopologyGraph,
    TopologyGraphBuilder,
    TopologyNode,
    VALID_EDGE_RELATIONS,
    VALID_NODE_TYPES,
)
from sot_validator.topology.identifier import (
    ConsolidatedRouter,
    HostIdentification,
    KNOWN_OUI_VENDORS,
    KNOWN_SCAN_TCP_PORTS,
    NetworkRoleIdentifier,
    VALID_HOST_ROLES,
)

__all__ = [
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
]
