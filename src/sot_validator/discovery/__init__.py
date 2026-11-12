"""Scoped /16-to-/24 subnet discovery and Site snapshot bootstrapper package."""

from sot_validator.discovery.scanner import (
    DiscoveredHost,
    DiscoveryConfig,
    SubnetDiscoveryScanner,
    parse_ip_neigh_output,
)

__all__ = [
    "DiscoveredHost",
    "DiscoveryConfig",
    "SubnetDiscoveryScanner",
    "parse_ip_neigh_output",
]
