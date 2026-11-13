"""Deterministic VLAN consistency audit: SoT vs FDB, router ARP and DHCP scopes."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import json
import re
from typing import Any, Iterable, Optional, Sequence

from sot_validator.discovery.router_tables import (
    RouterArpRecord,
    _vlan_from_interface,
    _vlan_from_ip,
)
from sot_validator.models import Port, Site, Subnet
from sot_validator.quality.checks import (
    _TRUNK_PORT_MODES,
    QualityFinding,
    _compute_finding_id,
    _normalized_network,
)
from sot_validator.topology.fdb_mapper import (
    FdbEntry,
    PortClassificationResult,
    SwitchFdbPortMapper,
    _site_gateway_ips,
)

RULE_VLAN_UNDOCUMENTED = "vlan_undocumented"
RULE_VLAN_UNOBSERVED = "vlan_unobserved"
RULE_SUBNET_VLAN_MISMATCH = "subnet_vlan_mismatch"
RULE_ACCESS_PORT_VLAN_MISMATCH = "access_port_vlan_mismatch"
RULE_DHCP_SCOPE_WITHOUT_SUBNET = "dhcp_scope_without_subnet"
RULE_SUBNET_WITHOUT_DHCP_SCOPE = "subnet_without_dhcp_scope"

VLAN_RULE_NAMES: tuple[str, ...] = (
    RULE_VLAN_UNDOCUMENTED,
    RULE_VLAN_UNOBSERVED,
    RULE_SUBNET_VLAN_MISMATCH,
    RULE_ACCESS_PORT_VLAN_MISMATCH,
    RULE_DHCP_SCOPE_WITHOUT_SUBNET,
    RULE_SUBNET_WITHOUT_DHCP_SCOPE,
)

_DIGITS_ONLY = re.compile(r"[0-9]+")

_REASON_NO_OBSERVED = "no FDB or router ARP data supplied"
_REASON_NO_ROUTER = "no router ARP data supplied"
_REASON_NO_CLASSIFICATIONS = "no FDB port classifications supplied"
_REASON_NO_SCOPES = "no DHCP scopes supplied"
_REASON_NO_EXPECTED = "no DHCP-expected subnet set supplied"


def _require_optional_datetime(value: Any, field_name: str) -> None:
    if value is not None and not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a datetime or None, got {value!r}")


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


@dataclass
class FdbObservation:
    """FDB entries and port classifications read from one switch in one run."""

    device_id: str
    observed_at: Optional[datetime] = None
    entries: list[FdbEntry] = field(default_factory=list)
    port_classifications: list[PortClassificationResult] = field(default_factory=list)
    source: str = "fdb"

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, str) or not self.device_id.strip():
            raise ValueError("device_id must be a non-empty string")
        self.device_id = self.device_id.strip()
        _require_optional_datetime(self.observed_at, "observed_at")
        self.entries = list(self.entries)
        self.port_classifications = list(self.port_classifications)


@dataclass
class DhcpScope:
    """DHCPv4 scope (pool network) read from a DHCP server or export."""

    cidr: str
    source: Optional[str] = None
    observed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        network = _normalized_network(self.cidr)
        if network is None:
            raise ValueError(f"cidr must be an IPv4 network, got {self.cidr!r}")
        self.cidr = self.cidr.strip()
        _require_optional_datetime(self.observed_at, "observed_at")

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.cidr, strict=False)


@dataclass
class VlanAuditResult:
    """Findings of one VLAN audit plus the rules skipped for missing inputs."""

    site_id: str
    findings: list[QualityFinding] = field(default_factory=list)
    skipped_rules: dict[str, str] = field(default_factory=dict)


def _normalize_vlan_id(value: Any) -> Optional[str]:
    """Return a comparable VLAN key: ``str(int)`` for digits, else case-folded text."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(int(value))
    text = str(value).strip()
    if not text:
        return None
    if _DIGITS_ONLY.fullmatch(text):
        return str(int(text))
    return text.casefold()


def _normalize_observed_vlan(value: Any) -> Optional[str]:
    """Return an observed VLAN ID from 1 to 4094, ignoring VLAN names and junk."""
    normalized = _normalize_vlan_id(value)
    if normalized is None or not _DIGITS_ONLY.fullmatch(normalized):
        return None
    return normalized if 1 <= int(normalized) <= 4094 else None


def _trusted_router_vlan(record: RouterArpRecord) -> Optional[str]:
    """Return the VLAN a router record really observed, dropping third-octet guesses."""
    if not record.vlan_id:
        return None
    tagged = _vlan_from_interface(record.interface)
    if tagged is not None:
        return _normalize_observed_vlan(tagged)
    if _normalize_vlan_id(record.vlan_id) == _normalize_vlan_id(_vlan_from_ip(record.ip)):
        return None
    return _normalize_observed_vlan(record.vlan_id)


def _fdb_source(observation: FdbObservation) -> dict[str, Any]:
    return {
        "source": observation.source,
        "device_id": observation.device_id,
        "observed_at": _iso(observation.observed_at),
    }


def _router_source(record: RouterArpRecord) -> dict[str, Any]:
    return {
        "source": "router",
        "router_id": record.router_id,
        "interface": record.interface,
        "observed_at": _iso(record.observed_at),
    }


def _dhcp_source(scope: DhcpScope) -> dict[str, Any]:
    return {
        "source": "dhcp",
        "server": scope.source,
        "observed_at": _iso(scope.observed_at),
    }


def _dedupe_sources(sources: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for source in sources:
        unique.setdefault(json.dumps(source, sort_keys=True), source)
    return [unique[key] for key in sorted(unique)]


def _vlan_sort_key(vlan_id: str) -> tuple[int, str]:
    return (int(vlan_id), vlan_id) if vlan_id.isdigit() else (1 << 16, vlan_id)


def _resolve_port(site: Site, device_id: str, port_name: str) -> Optional[Port]:
    for device in site.devices:
        if device.device_id != device_id:
            continue
        for port in device.ports:
            if port.port_id == port_name or port.name == port_name:
                return port
    return None


class VlanConsistencyAuditor:
    """Compare one SoT site's VLANs against observed FDB, router ARP and DHCP data."""

    def audit(
        self,
        site: Site,
        *,
        fdb: Optional[Sequence[FdbObservation]] = None,
        router_arp: Optional[Sequence[RouterArpRecord]] = None,
        dhcp_scopes: Optional[Sequence[DhcpScope]] = None,
        dhcp_expected_subnets: Optional[Iterable[str]] = None,
    ) -> VlanAuditResult:
        if isinstance(dhcp_expected_subnets, str):
            raise TypeError(
                "dhcp_expected_subnets must be an iterable of subnet ids or CIDRs, "
                "not a single string"
            )
        observations = list(fdb) if fdb is not None else []
        records = list(router_arp) if router_arp is not None else []
        scopes = list(dhcp_scopes) if dhcp_scopes is not None else []
        expected = (
            list(dhcp_expected_subnets) if dhcp_expected_subnets is not None else []
        )
        has_classifications = any(o.port_classifications for o in observations)

        findings: list[QualityFinding] = []
        skipped: dict[str, str] = {}

        if observations or records:
            observed = self._observed_vlans(observations, records)
            findings.extend(self._check_vlan_undocumented(site, observed))
            findings.extend(
                self._check_vlan_unobserved(site, observed, observations, records)
            )
        else:
            skipped[RULE_VLAN_UNDOCUMENTED] = _REASON_NO_OBSERVED
            skipped[RULE_VLAN_UNOBSERVED] = _REASON_NO_OBSERVED

        if records:
            findings.extend(self._check_subnet_vlan_mismatch(site, records))
        else:
            skipped[RULE_SUBNET_VLAN_MISMATCH] = _REASON_NO_ROUTER

        if has_classifications:
            findings.extend(self._check_access_port_vlan_mismatch(site, observations))
        else:
            skipped[RULE_ACCESS_PORT_VLAN_MISMATCH] = _REASON_NO_CLASSIFICATIONS

        if scopes:
            findings.extend(self._check_dhcp_scope_without_subnet(site, scopes))
        else:
            skipped[RULE_DHCP_SCOPE_WITHOUT_SUBNET] = _REASON_NO_SCOPES

        if scopes and expected:
            findings.extend(
                self._check_subnet_without_dhcp_scope(site, scopes, expected)
            )
        elif not scopes and not expected:
            skipped[RULE_SUBNET_WITHOUT_DHCP_SCOPE] = (
                "no DHCP scopes or DHCP-expected subnet set supplied"
            )
        elif not scopes:
            skipped[RULE_SUBNET_WITHOUT_DHCP_SCOPE] = _REASON_NO_SCOPES
        else:
            skipped[RULE_SUBNET_WITHOUT_DHCP_SCOPE] = _REASON_NO_EXPECTED

        return VlanAuditResult(
            site_id=site.site_id,
            findings=self._finalize(findings),
            skipped_rules={r: skipped[r] for r in VLAN_RULE_NAMES if r in skipped},
        )

    def _finalize(self, findings: list[QualityFinding]) -> list[QualityFinding]:
        deduped: dict[str, QualityFinding] = {}
        for finding in findings:
            deduped.setdefault(finding.finding_id, finding)
        return sorted(
            deduped.values(),
            key=lambda f: (f.rule, tuple(f.record_ids), f.finding_id),
        )

    def _make_finding(
        self,
        *,
        site_id: str,
        rule: str,
        severity: str,
        record_type: str,
        record_ids: Iterable[str],
        message: str,
        evidence: dict[str, Any],
    ) -> QualityFinding:
        ids = sorted({f"site:{site_id}", *record_ids})
        return QualityFinding(
            finding_id=_compute_finding_id(rule, ids),
            site_id=site_id,
            rule=rule,
            severity=severity,
            record_type=record_type,
            record_ids=ids,
            message=message,
            evidence=evidence,
        )

    def _observed_vlans(
        self,
        observations: list[FdbObservation],
        records: list[RouterArpRecord],
    ) -> dict[str, list[dict[str, Any]]]:
        sources: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for observation in observations:
            raw_ids: list[Any] = [entry.vlan_id for entry in observation.entries]
            for result in observation.port_classifications:
                raw_ids.extend(result.vlan_ids)
            for raw in raw_ids:
                vlan_id = _normalize_observed_vlan(raw)
                if vlan_id is not None:
                    sources[vlan_id].append(_fdb_source(observation))
        for record in records:
            vlan_id = _trusted_router_vlan(record)
            if vlan_id is not None:
                sources[vlan_id].append(_router_source(record))
        return {vlan_id: _dedupe_sources(found) for vlan_id, found in sources.items()}

    def _check_vlan_undocumented(
        self, site: Site, observed: dict[str, list[dict[str, Any]]]
    ) -> list[QualityFinding]:
        documented = {_normalize_vlan_id(v.vlan_id) for v in site.vlans}
        documented.update(_normalize_vlan_id(s.vlan_id) for s in site.subnets)
        findings: list[QualityFinding] = []
        for vlan_id in sorted(observed, key=_vlan_sort_key):
            if vlan_id in documented:
                continue
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_VLAN_UNDOCUMENTED,
                    severity="warning",
                    record_type="VLAN",
                    record_ids=[f"vlan:{vlan_id}"],
                    message=(
                        f"VLAN {vlan_id} was observed on the network but is not "
                        f"documented in the SoT for site {site.site_id}"
                    ),
                    evidence={"vlan_id": vlan_id, "sources": observed[vlan_id]},
                )
            )
        return findings

    def _check_vlan_unobserved(
        self,
        site: Site,
        observed: dict[str, list[dict[str, Any]]],
        observations: list[FdbObservation],
        records: list[RouterArpRecord],
    ) -> list[QualityFinding]:
        consulted = _dedupe_sources(
            [_fdb_source(o) for o in observations] + [_router_source(r) for r in records]
        )
        gateway_ips = _site_gateway_ips(site)
        site_switches = sorted(
            {
                d.device_id
                for d in site.devices
                if SwitchFdbPortMapper._classify_network_device_role(d, gateway_ips)
                == "switch"
            }
        )
        covered = sorted({o.device_id for o in observations})
        uncovered = sorted(set(site_switches) - set(covered))
        confidence = "low" if uncovered else "high"

        findings: list[QualityFinding] = []
        for vlan in site.vlans:
            vlan_id = _normalize_vlan_id(vlan.vlan_id)
            if vlan_id in observed:
                continue
            message = (
                f"VLAN {vlan.vlan_id} is documented in the SoT for site "
                f"{site.site_id} but was not observed in any supplied data"
            )
            if uncovered:
                message += (
                    f"; the observed data covers only part of the site's switches "
                    f"({len(site_switches) - len(uncovered)} of {len(site_switches)})"
                )
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_VLAN_UNOBSERVED,
                    severity="info",
                    record_type="VLAN",
                    record_ids=[f"vlan:{vlan.vlan_id}"],
                    message=message,
                    evidence={
                        "vlan_id": vlan_id,
                        "sources": consulted,
                        "site_switches": site_switches,
                        "covered_switches": covered,
                        "uncovered_switches": uncovered,
                        "confidence": confidence,
                    },
                )
            )
        return findings

    def _check_subnet_vlan_mismatch(
        self, site: Site, records: list[RouterArpRecord]
    ) -> list[QualityFinding]:
        candidates: list[tuple[ipaddress.IPv4Network, Subnet, str]] = []
        for subnet in site.subnets:
            network = _normalized_network(subnet.cidr)
            sot_vlan = _normalize_vlan_id(subnet.vlan_id)
            if network is not None and sot_vlan is not None:
                candidates.append((network, subnet, sot_vlan))

        mismatched: dict[str, list[tuple[str, RouterArpRecord]]] = defaultdict(list)
        subnet_by_id: dict[str, tuple[Subnet, str]] = {}
        for record in records:
            observed = _trusted_router_vlan(record)
            if observed is None:
                continue
            address = ipaddress.ip_address(record.ip)
            containing = [c for c in candidates if address in c[0]]
            if not containing:
                continue
            _, subnet, sot_vlan = max(
                containing, key=lambda c: (c[0].prefixlen, c[1].subnet_id)
            )
            if observed != sot_vlan:
                mismatched[subnet.subnet_id].append((observed, record))
                subnet_by_id[subnet.subnet_id] = (subnet, sot_vlan)

        findings: list[QualityFinding] = []
        for subnet_id in sorted(mismatched):
            subnet, sot_vlan = subnet_by_id[subnet_id]
            observed_ids = sorted(
                {vid for vid, _ in mismatched[subnet_id]}, key=_vlan_sort_key
            )
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_SUBNET_VLAN_MISMATCH,
                    severity="error",
                    record_type="Subnet",
                    record_ids=[f"subnet:{subnet_id}"],
                    message=(
                        f"Subnet {subnet.cidr} is documented on VLAN {sot_vlan} but "
                        f"router ARP observed it on VLAN {', '.join(observed_ids)}"
                    ),
                    evidence={
                        "cidr": subnet.cidr,
                        "sot_vlan_id": sot_vlan,
                        "observed_vlan_ids": observed_ids,
                        "sources": _dedupe_sources(
                            _router_source(r) for _, r in mismatched[subnet_id]
                        ),
                    },
                )
            )
        return findings

    def _check_access_port_vlan_mismatch(
        self, site: Site, observations: list[FdbObservation]
    ) -> list[QualityFinding]:
        ports: dict[str, Port] = {}
        modes: dict[str, set[str]] = defaultdict(set)
        access_vlans: dict[str, set[str]] = defaultdict(set)
        access_sources: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for observation in observations:
            for result in observation.port_classifications:
                port = _resolve_port(site, result.device_id, result.port_name)
                if port is None:
                    continue
                ports[port.port_id] = port
                modes[port.port_id].add(result.port_mode)
                if result.port_mode != "access":
                    continue
                access_sources[port.port_id].append(_fdb_source(observation))
                for raw in result.vlan_ids:
                    vlan_id = _normalize_observed_vlan(raw)
                    if vlan_id is not None:
                        access_vlans[port.port_id].add(vlan_id)

        findings: list[QualityFinding] = []
        for port_id in sorted(ports):
            port = ports[port_id]
            sot_vlan = _normalize_vlan_id(port.vlan_id)
            if modes[port_id] & _TRUNK_PORT_MODES or "access" not in modes[port_id]:
                continue
            observed_ids = sorted(access_vlans[port_id], key=_vlan_sort_key)
            if sot_vlan is None or not observed_ids or sot_vlan in observed_ids:
                continue
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_ACCESS_PORT_VLAN_MISMATCH,
                    severity="warning",
                    record_type="Port",
                    record_ids=[f"port:{port_id}"],
                    message=(
                        f"Access port {port.name} on {port.device_id} is documented "
                        f"on VLAN {sot_vlan} but FDB observed VLAN "
                        f"{', '.join(observed_ids)}"
                    ),
                    evidence={
                        "device_id": port.device_id,
                        "port_name": port.name,
                        "sot_vlan_id": sot_vlan,
                        "observed_vlan_ids": observed_ids,
                        "sources": _dedupe_sources(access_sources[port_id]),
                    },
                )
            )
        return findings

    def _check_dhcp_scope_without_subnet(
        self, site: Site, scopes: list[DhcpScope]
    ) -> list[QualityFinding]:
        sot_networks = {_normalized_network(s.cidr) for s in site.subnets}
        unmatched: dict[ipaddress.IPv4Network, list[DhcpScope]] = defaultdict(list)
        for scope in scopes:
            if scope.network not in sot_networks:
                unmatched[scope.network].append(scope)

        findings: list[QualityFinding] = []
        for network in sorted(unmatched):
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_DHCP_SCOPE_WITHOUT_SUBNET,
                    severity="warning",
                    record_type="DhcpScope",
                    record_ids=[f"dhcp_scope:{network}"],
                    message=(
                        f"DHCP scope {network} has no matching SoT subnet "
                        f"in site {site.site_id}"
                    ),
                    evidence={
                        "cidr": str(network),
                        "sources": _dedupe_sources(
                            _dhcp_source(s) for s in unmatched[network]
                        ),
                    },
                )
            )
        return findings

    def _check_subnet_without_dhcp_scope(
        self, site: Site, scopes: list[DhcpScope], expected: list[str]
    ) -> list[QualityFinding]:
        expected_ids = {e.strip() for e in expected if isinstance(e, str)}
        expected_networks = {_normalized_network(e) for e in expected}
        expected_networks.discard(None)
        scope_networks = {s.network for s in scopes}
        all_sources = _dedupe_sources(_dhcp_source(s) for s in scopes)

        findings: list[QualityFinding] = []
        for subnet in sorted(site.subnets, key=lambda s: s.subnet_id):
            network = _normalized_network(subnet.cidr)
            if network is None:
                continue
            if subnet.subnet_id not in expected_ids and network not in expected_networks:
                continue
            if network in scope_networks:
                continue
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_SUBNET_WITHOUT_DHCP_SCOPE,
                    severity="warning",
                    record_type="Subnet",
                    record_ids=[f"subnet:{subnet.subnet_id}"],
                    message=(
                        f"Subnet {subnet.cidr} is expected to have DHCP but no "
                        f"supplied DHCP scope covers it"
                    ),
                    evidence={"cidr": subnet.cidr, "sources": all_sources},
                )
            )
        return findings


__all__ = [
    "DhcpScope",
    "FdbObservation",
    "RULE_ACCESS_PORT_VLAN_MISMATCH",
    "RULE_DHCP_SCOPE_WITHOUT_SUBNET",
    "RULE_SUBNET_VLAN_MISMATCH",
    "RULE_SUBNET_WITHOUT_DHCP_SCOPE",
    "RULE_VLAN_UNDOCUMENTED",
    "RULE_VLAN_UNOBSERVED",
    "VLAN_RULE_NAMES",
    "VlanAuditResult",
    "VlanConsistencyAuditor",
]
