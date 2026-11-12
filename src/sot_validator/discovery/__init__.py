"""Scoped /16-to-/24 subnet discovery and Site snapshot bootstrapper package."""

from sot_validator.discovery.scanner import (
    DEFAULT_GATEWAY_OCTETS,
    DEFAULT_TCP_PORTS,
    DiscoveredHost,
    DiscoveryConfig,
    SubnetDiscoveryScanner,
    parse_ip_neigh_output,
)

__all__ = [
    "DEFAULT_GATEWAY_OCTETS",
    "DEFAULT_TCP_PORTS",
    "DiscoveredHost",
    "DiscoveryConfig",
    "SubnetDiscoveryScanner",
    "parse_ip_neigh_output",
]
