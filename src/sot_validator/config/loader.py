"""Unified TOML fleet configuration loader with env-referenced secrets."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
import os
from pathlib import Path
import re
import tomllib
from typing import Any, Callable, Mapping, Optional

ENV_REFERENCE_PATTERN = re.compile(r"^\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}$")
REDACTED = "***"
MAX_PROBES_PER_SITE_CAP = 64
SNMP_VERSIONS: tuple[str, ...] = ("v1", "v2c")

_ROOT_KEYS = frozenset({"policy", "sites", "vcenters", "snmp_profiles", "proxmox"})
_POLICY_DAY_PAIRS: tuple[tuple[str, str], ...] = (
    ("arp_active_within_days", "arp_stale_after_days"),
    ("last_seen_active_within_days", "last_seen_stale_after_days"),
)
_SITE_KEYS = frozenset({"site_id", "name", "block", "active_subnets"})
_VCENTER_KEYS = frozenset({"name", "host", "username", "password", "verify_tls"})
_SNMP_KEYS = frozenset({"name", "version", "community"})
_PROXMOX_KEYS = frozenset(
    {"name", "host", "port", "token_id", "token_secret", "verify_tls"}
)


class ConfigError(ValueError):
    """Raised when a fleet configuration file cannot be read or fails validation."""


@dataclass(frozen=True, repr=False)
class SecretValue:
    """Resolved secret whose repr and str are always redacted."""

    _value: str

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return REDACTED

    def __str__(self) -> str:
        return REDACTED


@dataclass(frozen=True)
class PolicyConfig:
    arp_active_within_days: float = 7.0
    arp_stale_after_days: float = 30.0
    last_seen_active_within_days: float = 7.0
    last_seen_stale_after_days: float = 30.0
    quarantine_min_stale_runs: int = 3
    max_concurrent_probes_per_site: int = 32
    max_concurrent_sites: int = 4


@dataclass(frozen=True)
class SiteConfig:
    site_id: str
    name: str
    block: ipaddress.IPv4Network
    active_subnets: tuple[ipaddress.IPv4Network, ...]


@dataclass(frozen=True)
class VCenterConfig:
    name: str
    host: str
    username: str
    password: SecretValue
    verify_tls: bool


@dataclass(frozen=True)
class SnmpProfile:
    name: str
    version: str
    community: SecretValue


@dataclass(frozen=True)
class ProxmoxConfig:
    name: str
    host: str
    port: int
    token_id: str
    token_secret: SecretValue
    verify_tls: bool


@dataclass(frozen=True)
class AppConfig:
    source_path: Path
    policy: PolicyConfig
    sites: tuple[SiteConfig, ...]
    vcenters: tuple[VCenterConfig, ...]
    snmp_profiles: tuple[SnmpProfile, ...]
    proxmox: tuple[ProxmoxConfig, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict with networks as strings and secrets redacted."""
        return {
            "source_path": str(self.source_path),
            "policy": {
                "arp_active_within_days": self.policy.arp_active_within_days,
                "arp_stale_after_days": self.policy.arp_stale_after_days,
                "last_seen_active_within_days": self.policy.last_seen_active_within_days,
                "last_seen_stale_after_days": self.policy.last_seen_stale_after_days,
                "quarantine_min_stale_runs": self.policy.quarantine_min_stale_runs,
                "max_concurrent_probes_per_site": self.policy.max_concurrent_probes_per_site,
                "max_concurrent_sites": self.policy.max_concurrent_sites,
            },
            "sites": [
                {
                    "site_id": site.site_id,
                    "name": site.name,
                    "block": str(site.block),
                    "active_subnets": [str(subnet) for subnet in site.active_subnets],
                }
                for site in self.sites
            ],
            "vcenters": [
                {
                    "name": vcenter.name,
                    "host": vcenter.host,
                    "username": vcenter.username,
                    "password": REDACTED,
                    "verify_tls": vcenter.verify_tls,
                }
                for vcenter in self.vcenters
            ],
            "snmp_profiles": [
                {
                    "name": profile.name,
                    "version": profile.version,
                    "community": REDACTED,
                }
                for profile in self.snmp_profiles
            ],
            "proxmox": [
                {
                    "name": node.name,
                    "host": node.host,
                    "port": node.port,
                    "token_id": node.token_id,
                    "token_secret": REDACTED,
                    "verify_tls": node.verify_tls,
                }
                for node in self.proxmox
            ],
        }


_MISSING = object()


class _Table:
    """One TOML table being validated, used to build located error messages."""

    def __init__(self, source: str, name: str, data: Mapping[str, Any]) -> None:
        self.source = source
        self.name = name
        self.data = data

    def error(self, key: str, reason: str) -> ConfigError:
        return ConfigError(f"{self.source}: [{self.name}] {key}: {reason}")

    def reject_unknown(self, allowed: frozenset[str]) -> None:
        for key in sorted(self.data):
            if key not in allowed:
                raise self.error(key, "unknown key")

    def raw(self, key: str, default: Any) -> Any:
        value = self.data.get(key, _MISSING)
        if value is _MISSING:
            if default is _MISSING:
                raise self.error(key, "required key is missing")
            return default
        return value

    def resolve_env(self, key: str, value: str) -> str:
        match = ENV_REFERENCE_PATTERN.fullmatch(value)
        if match is None:
            return value
        variable = match.group(1)
        resolved = os.environ.get(variable, "")
        if not resolved:
            raise self.error(
                key, f"environment variable {variable} is unset or empty"
            )
        return resolved

    def string(self, key: str, *, default: Any = _MISSING, non_empty: bool = False) -> str:
        value = self.raw(key, default)
        if not isinstance(value, str):
            raise self.error(key, f"expected a string, got {_type_name(value)}")
        value = self.resolve_env(key, value)
        if non_empty and not value.strip():
            raise self.error(key, "must be a non-empty string")
        return value

    def secret(self, key: str) -> SecretValue:
        value = self.raw(key, _MISSING)
        if not isinstance(value, str) or ENV_REFERENCE_PATTERN.fullmatch(value) is None:
            raise self.error(
                key,
                "secret must be written as a ${env:NAME} reference; "
                "literal values are not allowed",
            )
        return SecretValue(self.resolve_env(key, value))

    def boolean(self, key: str, *, default: Any = _MISSING) -> bool:
        value = self.raw(key, default)
        if not isinstance(value, bool):
            raise self.error(key, f"expected a boolean, got {_type_name(value)}")
        return value

    def integer(self, key: str, *, default: Any = _MISSING, minimum: int, maximum: Optional[int] = None) -> int:
        value = self.raw(key, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise self.error(key, f"expected an integer, got {_type_name(value)}")
        if value < minimum:
            raise self.error(key, f"must be >= {minimum}, got {value}")
        if maximum is not None and value > maximum:
            raise self.error(key, f"must be <= {maximum}, got {value}")
        return value

    def positive_days(self, key: str, *, default: float) -> float:
        value = self.raw(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise self.error(key, f"expected a number, got {_type_name(value)}")
        if not math.isfinite(value) or value <= 0:
            raise self.error(key, f"must be a finite number > 0, got {value}")
        return float(value)


def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "table"
    return type(value).__name__


def load_config(path: str | os.PathLike) -> AppConfig:
    """Read, validate and resolve a TOML fleet configuration file."""
    source = os.fspath(path)
    try:
        with open(source, "rb") as handle:
            document = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source}: invalid TOML: {exc}") from None
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise ConfigError(f"{source}: cannot read config file: {reason}") from None

    root = _Table(source, "root", document)
    root.reject_unknown(_ROOT_KEYS)

    return AppConfig(
        source_path=Path(source),
        policy=_parse_policy(root),
        sites=_parse_sites(root),
        vcenters=_parse_named(root, "vcenters", _parse_vcenter),
        snmp_profiles=_parse_named(root, "snmp_profiles", _parse_snmp_profile),
        proxmox=_parse_named(root, "proxmox", _parse_proxmox),
    )


def _parse_named(root: _Table, key: str, parse: Callable[[_Table], Any]) -> tuple[Any, ...]:
    """Parse an optional array of tables whose entries must have unique names."""
    entries: list[Any] = []
    seen: dict[str, str] = {}
    for table in _array_of_tables(root, key, required=False):
        entry = parse(table)
        if entry.name in seen:
            raise table.error(
                "name", f"duplicate name (also used in {seen[entry.name]})"
            )
        seen[entry.name] = table.name
        entries.append(entry)
    return tuple(entries)


def _array_of_tables(root: _Table, key: str, *, required: bool) -> list[_Table]:
    value = root.data.get(key, _MISSING)
    if value is _MISSING:
        if required:
            raise root.error(key, "required key is missing")
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise root.error(key, f"expected an array of tables ([[{key}]])")
    if required and not value:
        raise root.error(key, "must contain at least one entry")
    return [_Table(root.source, f"{key}[{index}]", item) for index, item in enumerate(value)]


def _parse_policy(root: _Table) -> PolicyConfig:
    value = root.data.get("policy", _MISSING)
    if value is _MISSING:
        return PolicyConfig()
    if not isinstance(value, dict):
        raise root.error("policy", "expected a table ([policy])")
    table = _Table(root.source, "policy", value)
    defaults = PolicyConfig()
    allowed = {name for pair in _POLICY_DAY_PAIRS for name in pair} | {
        "quarantine_min_stale_runs",
        "max_concurrent_probes_per_site",
        "max_concurrent_sites",
    }
    table.reject_unknown(frozenset(allowed))

    days: dict[str, float] = {}
    for active_key, stale_key in _POLICY_DAY_PAIRS:
        active = table.positive_days(active_key, default=getattr(defaults, active_key))
        stale = table.positive_days(stale_key, default=getattr(defaults, stale_key))
        if active > stale:
            raise table.error(
                active_key, f"must be <= {stale_key} ({stale}), got {active}"
            )
        days[active_key] = active
        days[stale_key] = stale

    return PolicyConfig(
        **days,
        quarantine_min_stale_runs=table.integer(
            "quarantine_min_stale_runs",
            default=defaults.quarantine_min_stale_runs,
            minimum=1,
        ),
        max_concurrent_probes_per_site=table.integer(
            "max_concurrent_probes_per_site",
            default=defaults.max_concurrent_probes_per_site,
            minimum=1,
            maximum=MAX_PROBES_PER_SITE_CAP,
        ),
        max_concurrent_sites=table.integer(
            "max_concurrent_sites", default=defaults.max_concurrent_sites, minimum=1
        ),
    )


def _parse_network(table: _Table, key: str, raw: str, label: str) -> ipaddress.IPv4Network:
    # Values resolved from ${env:NAME} are reported by their reference, never echoed.
    value = table.resolve_env(key, raw)
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        detail = f": {exc}" if value == raw else ""
        raise table.error(key, f"{label}{raw!r} is not a valid network{detail}") from None
    if not isinstance(network, ipaddress.IPv4Network):
        raise table.error(key, f"{label}{raw!r} must be an IPv4 network")
    return network


def _parse_sites(root: _Table) -> tuple[SiteConfig, ...]:
    sites: list[SiteConfig] = []
    seen_ids: dict[str, str] = {}
    seen_blocks: dict[ipaddress.IPv4Network, str] = {}
    for table in _array_of_tables(root, "sites", required=True):
        table.reject_unknown(_SITE_KEYS)
        site_id = table.string("site_id", non_empty=True)
        name = table.string("name", non_empty=True)

        raw_block = table.raw("block", _MISSING)
        if not isinstance(raw_block, str):
            raise table.error("block", f"expected a string, got {_type_name(raw_block)}")
        block = _parse_network(table, "block", raw_block, "")
        if block.prefixlen != 16 or block.network_address.packed[0] != 10:
            raise table.error("block", f"{str(block)!r} must be a 10.x.0.0/16 block")

        raw_subnets = table.raw("active_subnets", _MISSING)
        if not isinstance(raw_subnets, list):
            raise table.error(
                "active_subnets", f"expected an array of strings, got {_type_name(raw_subnets)}"
            )
        if not raw_subnets:
            raise table.error("active_subnets", "must list at least one /24 subnet")
        subnets: list[ipaddress.IPv4Network] = []
        for index, raw in enumerate(raw_subnets):
            label = f"entry {index} "
            if not isinstance(raw, str):
                raise table.error(
                    "active_subnets", f"{label}expected a string, got {_type_name(raw)}"
                )
            subnet = _parse_network(table, "active_subnets", raw, label)
            if subnet.prefixlen != 24:
                raise table.error("active_subnets", f"{label}{str(subnet)!r} must be a /24")
            if not subnet.subnet_of(block):
                raise table.error(
                    "active_subnets", f"{label}{str(subnet)!r} is not inside block {block}"
                )
            if subnet in subnets:
                raise table.error("active_subnets", f"{label}{str(subnet)!r} is duplicated")
            subnets.append(subnet)

        if site_id in seen_ids:
            raise table.error(
                "site_id", f"duplicate site_id (also used in {seen_ids[site_id]})"
            )
        if block in seen_blocks:
            raise table.error(
                "block", f"duplicate block {block} (also used in {seen_blocks[block]})"
            )
        seen_ids[site_id] = table.name
        seen_blocks[block] = table.name
        sites.append(
            SiteConfig(
                site_id=site_id, name=name, block=block, active_subnets=tuple(subnets)
            )
        )
    return tuple(sites)


def _parse_vcenter(table: _Table) -> VCenterConfig:
    table.reject_unknown(_VCENTER_KEYS)
    return VCenterConfig(
        name=table.string("name", non_empty=True),
        host=table.string("host", non_empty=True),
        username=table.string("username"),
        password=table.secret("password"),
        verify_tls=table.boolean("verify_tls", default=True),
    )


def _parse_snmp_profile(table: _Table) -> SnmpProfile:
    table.reject_unknown(_SNMP_KEYS)
    name = table.string("name", non_empty=True)
    version = table.string("version", default="v2c")
    if version not in SNMP_VERSIONS:
        raise table.error("version", f"must be one of {', '.join(SNMP_VERSIONS)}")
    return SnmpProfile(name=name, version=version, community=table.secret("community"))


def _parse_proxmox(table: _Table) -> ProxmoxConfig:
    table.reject_unknown(_PROXMOX_KEYS)
    return ProxmoxConfig(
        name=table.string("name", non_empty=True),
        host=table.string("host", non_empty=True),
        port=table.integer("port", default=8006, minimum=1, maximum=65535),
        token_id=table.string("token_id"),
        token_secret=table.secret("token_secret"),
        verify_tls=table.boolean("verify_tls", default=True),
    )
