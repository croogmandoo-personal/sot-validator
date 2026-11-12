"""Device type catalog, switch/router port builder, and network role/VLAN identifier."""

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
    "VALID_DEVICE_ROLES",
    "VALID_HOST_ROLES",
    "normalize_mac_address",
]
