"""Offline IEEE OUI registry (MA-L/MA-M/MA-S) and MAC address classification helpers."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from sot_validator.topology.device_types import normalize_mac_address
from sot_validator.topology.identifier import KNOWN_OUI_VENDORS

REGISTRY_PREFIX_BITS: dict[str, int] = {"MA-L": 24, "MA-M": 28, "MA-S": 36}
REGISTRY_BUILTIN = "builtin"
MAC_CLASS_INVALID = "invalid"
MAC_CLASS_MULTICAST = "multicast"
MAC_CLASS_LOCALLY_ADMINISTERED = "locally_administered"
MAC_CLASS_UNIVERSAL = "universal"

_REQUIRED_HEADERS = ("Registry", "Assignment", "Organization Name")
_HEX_DIGITS = frozenset("0123456789abcdef")
# Longest prefix first: MA-S (9 hex digits), MA-M (7), MA-L (6).
_LOOKUP_ORDER: tuple[tuple[str, int], ...] = (("MA-S", 36), ("MA-M", 28), ("MA-L", 24))


@dataclass(frozen=True)
class OuiMatch:
    """A vendor match for a MAC address prefix."""

    vendor: str
    prefix: str
    prefix_bits: int
    registry: str
    role_hint: Optional[str] = None


def _looks_like_ipv4(value: str) -> bool:
    parts = value.strip().split(".")
    return len(parts) == 4 and all(part.isdecimal() and len(part) <= 3 for part in parts)


def _normalized_hex(mac: object) -> Optional[str]:
    # normalize_mac_address strips dots, so a 12-digit dotted quad would pass as a MAC.
    if not isinstance(mac, str) or _looks_like_ipv4(mac):
        return None
    try:
        return normalize_mac_address(mac).replace(":", "")
    except ValueError:
        return None


def _first_octet(mac: object) -> Optional[int]:
    hex_only = _normalized_hex(mac)
    if hex_only is None:
        return None
    return int(hex_only[:2], 16)


def is_multicast(mac: object) -> bool:
    """Return True when the I/G (multicast) bit of the first octet is set."""
    octet = _first_octet(mac)
    return octet is not None and bool(octet & 0x01)


def is_locally_administered(mac: object) -> bool:
    """Return True when the U/L (locally-administered) bit of the first octet is set."""
    octet = _first_octet(mac)
    return octet is not None and bool(octet & 0x02)


def classify_mac(mac: object) -> str:
    """Classify a MAC as invalid, multicast, locally_administered or universal."""
    octet = _first_octet(mac)
    if octet is None:
        return MAC_CLASS_INVALID
    if octet & 0x01:
        return MAC_CLASS_MULTICAST
    if octet & 0x02:
        return MAC_CLASS_LOCALLY_ADMINISTERED
    return MAC_CLASS_UNIVERSAL


class OuiRegistry:
    """Longest-prefix IEEE OUI lookup loaded from offline CSV exports, with a built-in fallback."""

    def __init__(self) -> None:
        self._tables: dict[int, dict[str, str]] = {
            bits: {} for bits in REGISTRY_PREFIX_BITS.values()
        }
        self._builtin: dict[str, tuple[str, str]] = {
            prefix.replace(":", ""): (vendor, role)
            for prefix, (vendor, role) in KNOWN_OUI_VENDORS.items()
        }

    @classmethod
    def from_ieee_csv(cls, *paths: Union[str, Path]) -> "OuiRegistry":
        registry = cls()
        for path in paths:
            registry._load_csv(Path(path))
        return registry

    def _load_csv(self, path: Path) -> None:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            fieldnames = reader.fieldnames or []
            missing = [name for name in _REQUIRED_HEADERS if name not in fieldnames]
            if missing:
                raise ValueError(
                    f"IEEE OUI file {str(path)!r} is missing required headers: {', '.join(missing)}"
                )
            for row in reader:
                bits = REGISTRY_PREFIX_BITS.get((row.get("Registry") or "").strip())
                if bits is None:
                    continue
                vendor = (row.get("Organization Name") or "").strip()
                if not vendor:
                    continue
                assignment = (row.get("Assignment") or "").strip().lower()
                if len(assignment) != bits // 4 or any(
                    ch not in _HEX_DIGITS for ch in assignment
                ):
                    continue
                self._tables[bits][assignment] = vendor

    def lookup(self, mac: object) -> Optional[OuiMatch]:
        """Return the longest-prefix vendor match for ``mac``, or None."""
        hex_only = _normalized_hex(mac)
        if hex_only is None:
            return None
        for registry_name, bits in _LOOKUP_ORDER:
            prefix = hex_only[: bits // 4]
            vendor = self._tables[bits].get(prefix)
            if vendor is not None:
                return OuiMatch(
                    vendor=vendor,
                    prefix=prefix,
                    prefix_bits=bits,
                    registry=registry_name,
                )
        prefix = hex_only[:6]
        builtin = self._builtin.get(prefix)
        if builtin is not None:
            return OuiMatch(
                vendor=builtin[0],
                prefix=prefix,
                prefix_bits=24,
                registry=REGISTRY_BUILTIN,
                role_hint=builtin[1],
            )
        return None
