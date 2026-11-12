"""Deterministic SoT data-quality conflict detection rules."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import ipaddress
import re
from typing import Any, Iterable, Mapping, Optional, Sequence

from sot_validator.models import IPAddress, Port, Site
from sot_validator.signals.directory_dns import normalize_hostname
from sot_validator.topology.fdb_mapper import VALID_PORT_MODES

RULE_DUPLICATE_IP = "duplicate_ip"
RULE_DUPLICATE_MAC = "duplicate_mac"
RULE_IP_OUTSIDE_SITE_BLOCK = "ip_outside_site_block"
RULE_IP_OUTSIDE_ACTIVE_SUBNET = "ip_outside_active_subnet"
RULE_ORPHAN_REFERENCE = "orphan_reference"
RULE_HOSTNAME_MISMATCH = "hostname_mismatch"
RULE_CROSS_SITE_DUPLICATE_IP = "cross_site_duplicate_ip"
RULE_CROSS_SITE_DUPLICATE_MAC = "cross_site_duplicate_mac"

SINGLE_SITE_RULES: tuple[str, ...] = (
    RULE_DUPLICATE_IP,
    RULE_DUPLICATE_MAC,
    RULE_IP_OUTSIDE_SITE_BLOCK,
    RULE_IP_OUTSIDE_ACTIVE_SUBNET,
    RULE_ORPHAN_REFERENCE,
    RULE_HOSTNAME_MISMATCH,
)

CROSS_SITE_RULES: tuple[str, ...] = (
    RULE_CROSS_SITE_DUPLICATE_IP,
    RULE_CROSS_SITE_DUPLICATE_MAC,
)

ALL_RULE_NAMES: tuple[str, ...] = SINGLE_SITE_RULES + CROSS_SITE_RULES

VALID_SEVERITIES: tuple[str, ...] = ("error", "warning", "info")

_TRUNK_PORT_MODES: frozenset[str] = frozenset({"trunk", "uplink"})

# Six colon/dash-separated octets, three dot-separated quads, or 12 bare hex digits.
_MAC_PATTERN = re.compile(
    r"(?:[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}"
    r"|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
    r"|[0-9a-f]{12})"
)


def _compute_finding_id(rule: str, record_ids: Iterable[str]) -> str:
    """Return the stable SHA-256 identity of a rule plus its sorted record ids."""
    canonical = f"{rule}|{', '.join(sorted(record_ids))}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class QualityFinding:
    """Single internal SoT data-quality conflict."""

    finding_id: str
    site_id: str
    rule: str
    severity: str
    record_type: str
    record_ids: list[str]
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {VALID_SEVERITIES}, got {self.severity!r}"
            )
        self.record_ids = list(self.record_ids)
        self.evidence = dict(self.evidence)


def _canonical_ip_key(value: str) -> str:
    """Return a canonical lookup key, normalizing strings that parse as IP addresses."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (AttributeError, ValueError):
        return value


def _normalized_ip(value: Optional[str]) -> Optional[ipaddress.IPv4Address]:
    """Return the IPv4 address for a value, or None when it is not one."""
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return address if isinstance(address, ipaddress.IPv4Address) else None


def _normalized_network(cidr: Optional[str]) -> Optional[ipaddress.IPv4Network]:
    """Return the IPv4 network for a CIDR string, or None when it is not one."""
    if not isinstance(cidr, str):
        return None
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    return network if isinstance(network, ipaddress.IPv4Network) else None


def _normalized_mac(value: Optional[str]) -> Optional[str]:
    """Return a canonical MAC address, or None for blanks, IPs and malformed values."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    if not _MAC_PATTERN.fullmatch(cleaned):
        return None
    hex_only = re.sub(r"[:.-]", "", cleaned)
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def _ip_assignment_ref(record: IPAddress) -> str:
    """Return the stable identity of an IP assignment record."""
    if record.assigned_object_type and record.assigned_object_id:
        return f"{record.assigned_object_type}:{record.assigned_object_id}"
    return f"ip:{_canonical_ip_key(record.ip)}"


def _parse_site_block(
    value: Optional[str | ipaddress.IPv4Network],
) -> Optional[ipaddress.IPv4Network]:
    if value is None:
        return None
    if isinstance(value, ipaddress.IPv4Network):
        network = value
    else:
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError as exc:
            raise ValueError(
                f"site_block must be a valid IPv4 /16 network: {value!r}"
            ) from exc
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 16:
        raise ValueError(f"site_block must be an IPv4 /16 network: {value!r}")
    return network


def _parse_port_modes(
    port_modes: Optional[Mapping[str, str]],
) -> dict[str, str]:
    if port_modes is None:
        return {}
    modes: dict[str, str] = {}
    for port_id, mode in port_modes.items():
        if not isinstance(port_id, str) or not port_id.strip():
            raise ValueError(
                f"port_modes keys must be non-empty strings, got {port_id!r}"
            )
        if mode not in VALID_PORT_MODES:
            raise ValueError(
                f"Invalid port mode for {port_id!r}: {mode!r} "
                f"(expected one of {VALID_PORT_MODES})"
            )
        modes[port_id] = mode
    return modes


def _parse_name_map(
    names: Optional[Mapping[str, str]],
) -> dict[str, str]:
    if names is None:
        return {}
    parsed: dict[str, str] = {}
    for key, value in names.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(
                f"hostname signal keys must be non-empty strings, got {key!r}"
            )
        if not isinstance(value, str):
            raise ValueError(f"hostname signal values must be strings, got {value!r}")
        parsed[_canonical_ip_key(key)] = value
    return parsed


def _lookup_name(names: Mapping[str, str], key: Optional[str]) -> Optional[str]:
    if not isinstance(key, str) or not key.strip():
        return None
    return names.get(_canonical_ip_key(key))


def _derive_site_block(site: Site) -> Optional[ipaddress.IPv4Network]:
    """Derive the site /16: most common subnet supernet, ties lexicographic."""
    counts: Counter[str] = Counter()
    for subnet in site.subnets:
        network = _normalized_network(subnet.cidr)
        if network is None:
            continue
        if network.prefixlen >= 16:
            block = network.supernet(new_prefix=16)
        else:
            block = ipaddress.ip_network(
                f"{network.network_address}/16", strict=False
            )
        counts[str(block)] += 1
    if not counts:
        return None
    best = min(counts.items(), key=lambda item: (-item[1], item[0]))
    return ipaddress.ip_network(best[0])


class DataQualityChecker:
    """Runs deterministic internal-consistency rules over extracted site snapshots."""

    def __init__(
        self,
        *,
        disabled_rules: Optional[Iterable[str]] = None,
        site_block: Optional[str | ipaddress.IPv4Network] = None,
        port_modes: Optional[Mapping[str, str]] = None,
        dns_ptr_names: Optional[Mapping[str, str]] = None,
        ad_names: Optional[Mapping[str, str]] = None,
    ) -> None:
        if isinstance(disabled_rules, str):
            raise ValueError(
                "disabled_rules must be an iterable of rule names, not a string"
            )
        disabled = list(disabled_rules or ())
        unknown = sorted(
            {
                str(rule)
                for rule in disabled
                if not isinstance(rule, str) or rule not in ALL_RULE_NAMES
            }
        )
        if unknown:
            raise ValueError(f"Unknown rule name(s): {', '.join(unknown)}")
        disabled_names = {rule for rule in disabled if isinstance(rule, str)}
        self._enabled_rules = tuple(
            rule for rule in ALL_RULE_NAMES if rule not in disabled_names
        )
        self._site_block = _parse_site_block(site_block)
        self._port_modes = _parse_port_modes(port_modes)
        self._dns_ptr_names = _parse_name_map(dns_ptr_names)
        self._ad_names = _parse_name_map(ad_names)

    def check_site(self, site: Site) -> list[QualityFinding]:
        """Run the single-site rules against one site."""
        findings: list[QualityFinding] = []
        if RULE_DUPLICATE_IP in self._enabled_rules:
            findings.extend(self._check_duplicate_ip(site))
        if RULE_DUPLICATE_MAC in self._enabled_rules:
            findings.extend(self._check_duplicate_mac(site))
        if RULE_IP_OUTSIDE_SITE_BLOCK in self._enabled_rules:
            findings.extend(self._check_ip_outside_site_block(site))
        if RULE_IP_OUTSIDE_ACTIVE_SUBNET in self._enabled_rules:
            findings.extend(self._check_ip_outside_active_subnet(site))
        if RULE_ORPHAN_REFERENCE in self._enabled_rules:
            findings.extend(self._check_orphan_reference(site))
        if RULE_HOSTNAME_MISMATCH in self._enabled_rules:
            findings.extend(self._check_hostname_mismatch(site))
        return self._finalize(findings)

    def check_sites(self, sites: Sequence[Site]) -> list[QualityFinding]:
        """Run per-site rules plus the cross-site rules when given several sites."""
        ordered = list(sites)
        findings: list[QualityFinding] = []
        for site in ordered:
            findings.extend(self.check_site(site))
        if len(ordered) > 1:
            if RULE_CROSS_SITE_DUPLICATE_IP in self._enabled_rules:
                findings.extend(self._check_cross_site_duplicate_ip(ordered))
            if RULE_CROSS_SITE_DUPLICATE_MAC in self._enabled_rules:
                findings.extend(self._check_cross_site_duplicate_mac(ordered))
        return self._finalize(findings)

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
        # Every record id carries its site so identical record names in two
        # sites still hash to distinct, globally stable finding ids.
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

    def _site_block_for(self, site: Site) -> Optional[ipaddress.IPv4Network]:
        if self._site_block is not None:
            return self._site_block
        return _derive_site_block(site)

    def _check_duplicate_ip(self, site: Site) -> list[QualityFinding]:
        grouped: dict[str, list[IPAddress]] = defaultdict(list)
        for record in site.ip_addresses:
            address = _normalized_ip(record.ip)
            if address is None:
                continue
            grouped[str(address)].append(record)

        findings: list[QualityFinding] = []
        for ip_text in sorted(grouped):
            records = grouped[ip_text]
            if len(records) < 2:
                continue
            ordered = sorted(
                records,
                key=lambda r: (_ip_assignment_ref(r), r.subnet_id or ""),
            )
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_DUPLICATE_IP,
                    severity="error",
                    record_type="IPAddress",
                    record_ids=[_ip_assignment_ref(r) for r in ordered],
                    message=(
                        f"IP {ip_text} is assigned to {len(records)} records "
                        f"in site {site.site_id}"
                    ),
                    evidence={
                        "ip": ip_text,
                        "assignment_count": len(records),
                        "assignments": [
                            {
                                "ref": _ip_assignment_ref(r),
                                "subnet_id": r.subnet_id,
                                "assigned_object_type": r.assigned_object_type,
                                "assigned_object_id": r.assigned_object_id,
                            }
                            for r in ordered
                        ],
                    },
                )
            )
        return findings

    def _port_mode(self, port_id: str) -> str:
        """Return the known port mode, treating unknown ports as access."""
        return self._port_modes.get(port_id, "access")

    def _mac_occurrences(self, site: Site) -> dict[str, list[dict[str, Any]]]:
        """Collect MAC sightings, dropping trunk/uplink port sightings."""
        occurrences: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in site.ip_addresses:
            mac = _normalized_mac(record.arp_mac)
            if mac is None:
                continue
            occurrences[mac].append(
                {
                    "source": "ip",
                    "ref": f"ip:{_canonical_ip_key(record.ip)}",
                    "ip": record.ip,
                    "subnet_id": record.subnet_id,
                }
            )
        for device in site.devices:
            for port in device.ports:
                mac = _normalized_mac(port.connected_mac)
                if mac is None:
                    continue
                mode = self._port_mode(port.port_id)
                if mode in _TRUNK_PORT_MODES:
                    continue
                occurrences[mac].append(
                    {
                        "source": "port",
                        "ref": f"port:{port.port_id}",
                        "port_id": port.port_id,
                        "device_id": port.device_id,
                        "port_mode": mode,
                    }
                )
        return occurrences

    def _check_duplicate_mac(self, site: Site) -> list[QualityFinding]:
        by_mac = self._mac_occurrences(site)
        findings: list[QualityFinding] = []
        for mac in sorted(by_mac):
            occurrences = by_mac[mac]
            if len(occurrences) < 2:
                continue
            ordered = sorted(
                occurrences, key=lambda o: (o["source"], o["ref"])
            )
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_DUPLICATE_MAC,
                    severity="warning",
                    record_type="MAC",
                    record_ids=[o["ref"] for o in ordered],
                    message=(
                        f"MAC {mac} appears on {len(ordered)} records "
                        f"in site {site.site_id}"
                    ),
                    evidence={
                        "mac": mac,
                        "occurrence_count": len(ordered),
                        "occurrences": ordered,
                    },
                )
            )
        return findings

    def _check_ip_outside_site_block(self, site: Site) -> list[QualityFinding]:
        block = self._site_block_for(site)
        if block is None:
            return []
        findings: list[QualityFinding] = []
        for record in sorted(site.ip_addresses, key=_ip_assignment_ref):
            address = _normalized_ip(record.ip)
            if address is None or address in block:
                continue
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_IP_OUTSIDE_SITE_BLOCK,
                    severity="error",
                    record_type="IPAddress",
                    record_ids=[_ip_assignment_ref(record)],
                    message=(
                        f"IP {address} is outside the site block {block} "
                        f"for site {site.site_id}"
                    ),
                    evidence={
                        "ip": str(address),
                        "site_block": str(block),
                        "subnet_id": record.subnet_id,
                    },
                )
            )
        return findings

    def _check_ip_outside_active_subnet(self, site: Site) -> list[QualityFinding]:
        block = self._site_block_for(site)
        if block is None:
            return []
        networks = sorted(
            network
            for network in (_normalized_network(s.cidr) for s in site.subnets)
            if network is not None
        )
        findings: list[QualityFinding] = []
        for record in sorted(site.ip_addresses, key=_ip_assignment_ref):
            address = _normalized_ip(record.ip)
            if address is None or address not in block:
                continue
            if any(address in network for network in networks):
                continue
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_IP_OUTSIDE_ACTIVE_SUBNET,
                    severity="warning",
                    record_type="IPAddress",
                    record_ids=[_ip_assignment_ref(record)],
                    message=(
                        f"IP {address} is inside site block {block} but outside "
                        f"every known subnet"
                    ),
                    evidence={
                        "ip": str(address),
                        "site_block": str(block),
                        "subnet_id": record.subnet_id,
                        "active_subnets": [str(n) for n in networks],
                    },
                )
            )
        return findings

    def _check_orphan_reference(self, site: Site) -> list[QualityFinding]:
        device_ids = {device.device_id for device in site.devices}
        equipment_ids = {equipment.equipment_id for equipment in site.equipment}
        subnet_ids = {subnet.subnet_id for subnet in site.subnets}
        port_ids = {
            port.port_id for device in site.devices for port in device.ports
        }

        findings: list[QualityFinding] = []
        for device in site.devices:
            for port in device.ports:
                if port.device_id not in device_ids:
                    findings.append(
                        self._make_finding(
                            site_id=site.site_id,
                            rule=RULE_ORPHAN_REFERENCE,
                            severity="error",
                            record_type="Port",
                            record_ids=[
                                f"port:{port.port_id}",
                                f"device:{port.device_id}",
                            ],
                            message=(
                                f"Port {port.port_id} references unknown device "
                                f"{port.device_id}"
                            ),
                            evidence={
                                "reference_field": "device_id",
                                "port_id": port.port_id,
                                "missing_id": port.device_id,
                            },
                        )
                    )
                if (
                    port.connected_device_id
                    and port.connected_device_id not in device_ids
                    and port.connected_device_id not in equipment_ids
                ):
                    findings.append(
                        self._make_finding(
                            site_id=site.site_id,
                            rule=RULE_ORPHAN_REFERENCE,
                            severity="error",
                            record_type="Port",
                            record_ids=[
                                f"port:{port.port_id}",
                                f"device:{port.connected_device_id}",
                            ],
                            message=(
                                f"Port {port.port_id} references unknown connected "
                                f"device {port.connected_device_id}"
                            ),
                            evidence={
                                "reference_field": "connected_device_id",
                                "port_id": port.port_id,
                                "missing_id": port.connected_device_id,
                            },
                        )
                    )
        for record in site.ip_addresses:
            if record.subnet_id in subnet_ids:
                continue
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_ORPHAN_REFERENCE,
                    severity="error",
                    record_type="IPAddress",
                    record_ids=[
                        _ip_assignment_ref(record),
                        f"subnet:{record.subnet_id}",
                    ],
                    message=(
                        f"IP {record.ip} references unknown subnet {record.subnet_id}"
                    ),
                    evidence={
                        "reference_field": "subnet_id",
                        "ip": record.ip,
                        "missing_id": record.subnet_id,
                    },
                )
            )
        for vlan in site.vlans:
            if not vlan.subnet_id or vlan.subnet_id in subnet_ids:
                continue
            findings.append(
                self._make_finding(
                    site_id=site.site_id,
                    rule=RULE_ORPHAN_REFERENCE,
                    severity="error",
                    record_type="VLAN",
                    record_ids=[f"vlan:{vlan.vlan_id}", f"subnet:{vlan.subnet_id}"],
                    message=(
                        f"VLAN {vlan.vlan_id} references unknown subnet "
                        f"{vlan.subnet_id}"
                    ),
                    evidence={
                        "reference_field": "subnet_id",
                        "vlan_id": vlan.vlan_id,
                        "missing_id": vlan.subnet_id,
                    },
                )
            )
        for equipment in site.equipment:
            for port_id in equipment.connected_ports:
                if port_id in port_ids:
                    continue
                findings.append(
                    self._make_finding(
                        site_id=site.site_id,
                        rule=RULE_ORPHAN_REFERENCE,
                        severity="error",
                        record_type="Equipment",
                        record_ids=[
                            f"equipment:{equipment.equipment_id}",
                            f"port:{port_id}",
                        ],
                        message=(
                            f"Equipment {equipment.equipment_id} references unknown "
                            f"port {port_id}"
                        ),
                        evidence={
                            "reference_field": "connected_ports",
                            "equipment_id": equipment.equipment_id,
                            "missing_id": port_id,
                        },
                    )
                )
        return findings

    def _observed_names(
        self, record_id: str, ip_addresses: Iterable[str]
    ) -> list[dict[str, str]]:
        """Collect DNS PTR and AD names observed for a record and its IPs."""
        ips = sorted(
            {
                canonical
                for canonical in (_canonical_ip_key(ip) for ip in ip_addresses)
                if _normalized_ip(canonical) is not None
            }
        )
        observed: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for source, names, keys in (
            ("ad", self._ad_names, [record_id, *ips]),
            ("dns", self._dns_ptr_names, ips),
        ):
            for key in keys:
                name = _lookup_name(names, key)
                if name is None:
                    continue
                fingerprint = (source, _canonical_ip_key(key))
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                observed.append({"source": source, "key": key, "name": name})
        return observed

    def _check_hostname_mismatch(self, site: Site) -> list[QualityFinding]:
        if not self._dns_ptr_names and not self._ad_names:
            return []
        findings: list[QualityFinding] = []
        for device in site.devices:
            ips = [device.management_ip] if device.management_ip else []
            findings.extend(
                self._hostname_finding(
                    site=site,
                    owner_ref=f"device:{device.device_id}",
                    record_type="NetworkDevice",
                    sot_name=device.hostname,
                    observed=self._observed_names(device.device_id, ips),
                )
            )
        for equipment in site.equipment:
            findings.extend(
                self._hostname_finding(
                    site=site,
                    owner_ref=f"equipment:{equipment.equipment_id}",
                    record_type="Equipment",
                    sot_name=equipment.name,
                    observed=self._observed_names(
                        equipment.equipment_id, equipment.assigned_ips
                    ),
                )
            )
        return findings

    def _hostname_finding(
        self,
        *,
        site: Site,
        owner_ref: str,
        record_type: str,
        sot_name: str,
        observed: list[dict[str, str]],
    ) -> list[QualityFinding]:
        sot_short = normalize_hostname(sot_name)
        if sot_short is None:
            return []
        mismatches = [
            entry
            for entry in observed
            if normalize_hostname(entry["name"]) not in (None, sot_short)
        ]
        if not mismatches:
            return []
        mismatches.sort(key=lambda entry: (entry["source"], entry["key"]))
        described = ", ".join(
            f"{entry['source']}:{entry['key']}={entry['name']}" for entry in mismatches
        )
        return [
            self._make_finding(
                site_id=site.site_id,
                rule=RULE_HOSTNAME_MISMATCH,
                severity="info",
                record_type=record_type,
                record_ids=[owner_ref],
                message=(
                    f"SoT hostname {sot_name!r} for {owner_ref} disagrees with "
                    f"observed {described}"
                ),
                evidence={
                    "sot_hostname": sot_name,
                    "observed_names": mismatches,
                },
            )
        ]

    def _check_cross_site_duplicate_ip(
        self, sites: Sequence[Site]
    ) -> list[QualityFinding]:
        grouped: dict[str, dict[str, list[IPAddress]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for site in sites:
            for record in site.ip_addresses:
                address = _normalized_ip(record.ip)
                if address is None:
                    continue
                grouped[str(address)][site.site_id].append(record)

        findings: list[QualityFinding] = []
        for ip_text in sorted(grouped):
            per_site = grouped[ip_text]
            if len(per_site) < 2:
                continue
            site_ids = sorted(per_site)
            findings.append(
                self._make_finding(
                    site_id=site_ids[0],
                    rule=RULE_CROSS_SITE_DUPLICATE_IP,
                    severity="error",
                    record_type="IPAddress",
                    record_ids=[f"ip:{ip_text}", *(f"site:{s}" for s in site_ids)],
                    message=(
                        f"IP {ip_text} appears in multiple sites: "
                        f"{', '.join(site_ids)}"
                    ),
                    evidence={
                        "ip": ip_text,
                        "site_ids": site_ids,
                        "assignments": {
                            site_id: sorted(
                                {_ip_assignment_ref(r) for r in per_site[site_id]}
                            )
                            for site_id in site_ids
                        },
                    },
                )
            )
        return findings

    def _check_cross_site_duplicate_mac(
        self, sites: Sequence[Site]
    ) -> list[QualityFinding]:
        grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for site in sites:
            for mac, occurrences in self._mac_occurrences(site).items():
                grouped[mac][site.site_id].extend(occurrences)

        findings: list[QualityFinding] = []
        for mac in sorted(grouped):
            per_site = grouped[mac]
            if len(per_site) < 2:
                continue
            site_ids = sorted(per_site)
            findings.append(
                self._make_finding(
                    site_id=site_ids[0],
                    rule=RULE_CROSS_SITE_DUPLICATE_MAC,
                    severity="warning",
                    record_type="MAC",
                    record_ids=[f"mac:{mac}", *(f"site:{s}" for s in site_ids)],
                    message=(
                        f"MAC {mac} appears in multiple sites: "
                        f"{', '.join(site_ids)}"
                    ),
                    evidence={
                        "mac": mac,
                        "site_ids": site_ids,
                        "occurrences": {
                            site_id: sorted(
                                (o["ref"] for o in per_site[site_id])
                            )
                            for site_id in site_ids
                        },
                    },
                )
            )
        return findings
