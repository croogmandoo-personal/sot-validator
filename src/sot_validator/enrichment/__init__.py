"""Offline MAC enrichment package: IEEE OUI registry and MAC classification."""

from __future__ import annotations

from sot_validator.enrichment.oui import (
    OuiMatch,
    OuiRegistry,
    classify_mac,
    is_locally_administered,
    is_multicast,
)

__all__ = [
    "OuiMatch",
    "OuiRegistry",
    "classify_mac",
    "is_locally_administered",
    "is_multicast",
]
