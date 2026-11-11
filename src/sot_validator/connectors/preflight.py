"""Pre-flight cutover readiness validator for live pilot site waves."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
from typing import Any, Optional

from sot_validator.connectors.live import (
    AuthenticatedScraperSession,
    SnmpWalkConnector,
    VSphereRestConnector,
)
from sot_validator.extraction.client import SoTClient
from sot_validator.models import EquipmentCategory, Site, Subnet
from sot_validator.signals.icmp import ScopeViolationError, _parse_ipv4_host
from sot_validator.signals.management import SNMPV2_MIB_OIDS

_PRIVATE_10_NETWORK = ipaddress.IPv4Network("10.0.0.0/8")


@dataclass
class PreFlightCheckResult:
    """Individual pre-flight readiness check outcome."""

    check_name: str
    passed: bool
    severity: str = "blocking"
    message: str = ""
    site_id: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_name": self.check_name,
            "passed": self.passed,
            "severity": self.severity,
            "message": self.message,
            "site_id": self.site_id,
            "details": dict(self.details),
        }


@dataclass
class PreFlightReport:
    """Aggregated pre-flight cutover readiness report for a pilot site cohort."""

    ready: bool
    pilot_site_ids: list[str]
    checks: list[PreFlightCheckResult] = field(default_factory=list)
    blocking_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evaluated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "pilot_site_ids": list(self.pilot_site_ids),
            "checks": [c.to_dict() for c in self.checks],
            "blocking_errors": list(self.blocking_errors),
            "warnings": list(self.warnings),
            "evaluated_at": self.evaluated_at.isoformat(),
        }


class PilotCutoverValidator:
    """Pre-flight validator verifying /24 scoping, read-only guardrails, and endpoint readiness."""

    def __init__(
        self,
        *,
        sot_client: Optional[SoTClient] = None,
        scraper_session: Optional[AuthenticatedScraperSession] = None,
        vsphere_connector: Optional[VSphereRestConnector] = None,
        snmp_connector: Optional[SnmpWalkConnector] = None,
        recommended_min_sites: int = 3,
        recommended_max_sites: int = 5,
    ) -> None:
        if recommended_min_sites < 1 or recommended_max_sites < recommended_min_sites:
            raise ValueError(
                "recommended_min_sites must be >= 1 and <= recommended_max_sites"
            )
        self.sot_client = sot_client
        self.scraper_session = scraper_session
        self.vsphere_connector = vsphere_connector
        self.snmp_connector = snmp_connector
        self.recommended_min_sites = recommended_min_sites
        self.recommended_max_sites = recommended_max_sites

    def validate(
        self,
        pilot_site_ids: Optional[Sequence[str | Site]] = None,
        *,
        sites: Optional[Sequence[Site]] = None,
        target_subnets_by_site: Optional[Mapping[str, Sequence[str]]] = None,
        target_Subnets_by_site: Optional[Mapping[str, Sequence[str]]] = None,
    ) -> PreFlightReport:
        """Execute all pre-flight readiness checks for the target pilot site cohort."""
        checks: list[PreFlightCheckResult] = []
        blocking_errors: list[str] = []
        warnings: list[str] = []

        explicit_subnets: dict[str, list[str]] = {}
        for subnet_map in (target_subnets_by_site, target_Subnets_by_site):
            if subnet_map:
                for sid, cidrs in subnet_map.items():
                    explicit_subnets.setdefault(str(sid).strip(), []).extend(
                        str(c).strip() for c in cidrs if str(c).strip()
                    )

        site_lookup: dict[str, Site] = {}
        if sites is not None:
            for s in sites:
                site_lookup[s.site_id] = s

        normalized_site_ids: list[str] = []
        raw_cohort: Sequence[str | Site] = (
            pilot_site_ids
            if pilot_site_ids is not None
            else ([s.site_id for s in sites] if sites is not None else ())
        )
        for entry in raw_cohort:
            if isinstance(entry, Site):
                site_lookup[entry.site_id] = entry
                sid = entry.site_id.strip()
            elif isinstance(entry, str):
                sid = entry.strip()
            else:
                sid = str(entry).strip()
            if sid and sid not in normalized_site_ids:
                normalized_site_ids.append(sid)

        # -------------------------------------------------------------------
        # 1. Pilot Cohort Scope Check (pilot_cohort_scope)
        # -------------------------------------------------------------------
        resolved_sites: dict[str, Site] = {}
        if not normalized_site_ids:
            err_msg = "Pilot cohort is empty; at least one pilot site_id is required"
            blocking_errors.append(err_msg)
            checks.append(
                PreFlightCheckResult(
                    check_name="pilot_cohort_scope",
                    passed=False,
                    severity="blocking",
                    message=err_msg,
                    details={"pilot_site_count": 0},
                )
            )
        else:
            cohort_count = len(normalized_site_ids)
            if not (
                self.recommended_min_sites
                <= cohort_count
                <= self.recommended_max_sites
            ):
                warn_msg = (
                    f"Pilot cohort has {cohort_count} site(s); recommended pilot wave size is "
                    f"{self.recommended_min_sites}-{self.recommended_max_sites} sites"
                )
                warnings.append(warn_msg)
                checks.append(
                    PreFlightCheckResult(
                        check_name="pilot_cohort_scope",
                        passed=True,
                        severity="warning",
                        message=warn_msg,
                        details={
                            "pilot_site_count": cohort_count,
                            "recommended_min_sites": self.recommended_min_sites,
                            "recommended_max_sites": self.recommended_max_sites,
                        },
                    )
                )
            else:
                checks.append(
                    PreFlightCheckResult(
                        check_name="pilot_cohort_scope",
                        passed=True,
                        severity="blocking",
                        message=(
                            f"Pilot cohort size ({cohort_count} sites) is within recommended "
                            f"{self.recommended_min_sites}-{self.recommended_max_sites} range"
                        ),
                        details={"pilot_site_count": cohort_count},
                    )
                )

            for sid in normalized_site_ids:
                if sid in site_lookup:
                    resolved_sites[sid] = site_lookup[sid]
                elif self.sot_client is not None:
                    try:
                        resolved_sites[sid] = self.sot_client.get_site(sid)
                    except Exception as exc:  # noqa: BLE001
                        err_msg = f"Pilot site {sid!r} could not be loaded from SoT client: {exc}"
                        blocking_errors.append(err_msg)
                        checks.append(
                            PreFlightCheckResult(
                                check_name="pilot_cohort_scope",
                                passed=False,
                                severity="blocking",
                                site_id=sid,
                                message=err_msg,
                            )
                        )
                elif sid in explicit_subnets:
                    resolved_sites[sid] = Site(
                        site_id=sid,
                        name=sid,
                        subnets=[
                            Subnet(
                                subnet_id=f"{sid}-sub-{idx}",
                                site_id=sid,
                                cidr=cidr_str,
                            )
                            for idx, cidr_str in enumerate(explicit_subnets[sid], 1)
                        ],
                    )
                else:
                    err_msg = (
                        f"Pilot site {sid!r} could not be resolved (no Site object, SoTClient, "
                        "or target_subnets_by_site entry provided)"
                    )
                    blocking_errors.append(err_msg)
                    checks.append(
                        PreFlightCheckResult(
                            check_name="pilot_cohort_scope",
                            passed=False,
                            severity="blocking",
                            site_id=sid,
                            message=err_msg,
                        )
                    )

        # -------------------------------------------------------------------
        # 2. /24 Subnet & 10.x.0.0/16 Scope Safety Check (subnet_scope_safety)
        # -------------------------------------------------------------------
        for sid, site_obj in resolved_sites.items():
            raw_cidrs: list[str] = []
            for sub in site_obj.subnets:
                if sub.cidr and sub.cidr.strip() not in raw_cidrs:
                    raw_cidrs.append(sub.cidr.strip())
            for extra_cidr in explicit_subnets.get(sid, []):
                if extra_cidr not in raw_cidrs:
                    raw_cidrs.append(extra_cidr)

            site_errors: list[str] = []
            valid_networks: list[ipaddress.IPv4Network] = []
            parent_slash16s: set[ipaddress.IPv4Network] = set()

            if not raw_cidrs:
                site_errors.append(
                    f"Site {sid!r} has no allocated /24 subnets configured"
                )
            else:
                for cidr_str in raw_cidrs:
                    try:
                        net = ipaddress.ip_network(cidr_str, strict=True)
                    except ValueError as exc:
                        site_errors.append(
                            f"Site {sid!r} has invalid subnet CIDR {cidr_str!r}: {exc}"
                        )
                        continue

                    if not isinstance(net, ipaddress.IPv4Network):
                        site_errors.append(
                            f"Site {sid!r} subnet {cidr_str!r} is not an IPv4 network"
                        )
                        continue

                    if not net.subnet_of(_PRIVATE_10_NETWORK):
                        site_errors.append(
                            f"Site {sid!r} subnet {net} falls outside 10.0.0.0/8 private space"
                        )
                        continue

                    if net.prefixlen < 24:
                        site_errors.append(
                            f"Site {sid!r} subnet {net} has prefix /{net.prefixlen}; "
                            "unsegmented /16 or prefixes broader than /24 are prohibited"
                        )
                        continue

                    slash16 = ipaddress.IPv4Network(
                        f"{net.network_address}/16", strict=False
                    )
                    parent_slash16s.add(slash16)
                    valid_networks.append(net)

                if len(parent_slash16s) > 1:
                    sorted_parents = sorted(str(p) for p in parent_slash16s)
                    site_errors.append(
                        f"Site {sid!r} subnets span multiple 10.x.0.0/16 blocks: {sorted_parents}"
                    )

            if valid_networks and not site_errors:
                host_entries: list[tuple[str, str]] = []
                for dev in site_obj.devices:
                    if dev.management_ip and dev.management_ip.strip():
                        host_entries.append(
                            (f"device {dev.device_id}", dev.management_ip.strip())
                        )
                for eq in site_obj.equipment:
                    for ip_str in eq.assigned_ips:
                        if ip_str and ip_str.strip():
                            host_entries.append(
                                (f"equipment {eq.equipment_id}", ip_str.strip())
                            )
                for ip_rec in site_obj.ip_addresses:
                    if ip_rec.ip and ip_rec.ip.strip():
                        host_entries.append(
                            (f"ip_record {ip_rec.ip}", ip_rec.ip.strip())
                        )

                for label, raw_ip in host_entries:
                    try:
                        addr = _parse_ipv4_host(raw_ip)
                    except ScopeViolationError as exc:
                        site_errors.append(
                            f"Site {sid!r} {label} has invalid host IP {raw_ip!r}: {exc}"
                        )
                        continue
                    if not any(addr in net for net in valid_networks):
                        site_errors.append(
                            f"Site {sid!r} {label} IP {addr} is outside allocated /24 subnets "
                            f"{[str(n) for n in valid_networks]}"
                        )

            if site_errors:
                blocking_errors.extend(site_errors)
                checks.append(
                    PreFlightCheckResult(
                        check_name="subnet_scope_safety",
                        passed=False,
                        severity="blocking",
                        site_id=sid,
                        message="; ".join(site_errors),
                        details={
                            "subnets": raw_cidrs,
                            "errors": site_errors,
                        },
                    )
                )
            else:
                parent_str = (
                    str(next(iter(parent_slash16s))) if parent_slash16s else None
                )
                checks.append(
                    PreFlightCheckResult(
                        check_name="subnet_scope_safety",
                        passed=True,
                        severity="blocking",
                        site_id=sid,
                        message=(
                            f"Site {sid!r} has {len(valid_networks)} valid /24 subnet(s) "
                            f"within {parent_str}"
                        ),
                        details={
                            "site_prefix": parent_str,
                            "subnets": [str(n) for n in valid_networks],
                        },
                    )
                )

        # -------------------------------------------------------------------
        # 3. Read-Only Guardrail Verification Check (readonly_guardrails)
        # -------------------------------------------------------------------
        guardrail_failures: list[str] = []
        verified_connectors: list[str] = []

        if self.scraper_session is not None:
            verified_connectors.append("scraper_session")
            for bad_method, bad_path in (
                ("POST", "/sites"),
                ("DELETE", "/sites/site-001"),
                ("GET", "/actions/port-admin"),
                ("GET", "/sites/site-001?action=disable"),
            ):
                if not self._assert_raises_permission_error(
                    lambda m=bad_method, p=bad_path: self.scraper_session.request(m, p)  # type: ignore[union-attr]
                ):
                    guardrail_failures.append(
                        f"AuthenticatedScraperSession failed to block mutating request {bad_method} {bad_path}"
                    )

        if self.vsphere_connector is not None:
            verified_connectors.append("vsphere_connector")
            probe_inst = (
                self.vsphere_connector.configured_instances[0]
                if self.vsphere_connector.configured_instances
                else "vcenter-01.corp.internal"
            )
            for bad_method, bad_path in (
                ("POST", "/api/vcenter/vm"),
                ("DELETE", "/api/vcenter/vm/vm-101"),
                ("PATCH", "/api/vcenter/vm/vm-101"),
                ("GET", "/api/vcenter/vm/vm-101/power/stop"),
            ):
                if not self._assert_raises_permission_error(
                    lambda m=bad_method, p=bad_path: self.vsphere_connector.request(  # type: ignore[union-attr]
                        m, probe_inst, p
                    )
                ):
                    guardrail_failures.append(
                        f"VSphereRestConnector failed to block mutating request {bad_method} {bad_path}"
                    )

        if self.snmp_connector is not None:
            verified_connectors.append("snmp_connector")
            if not self._assert_raises_permission_error(
                lambda: self.snmp_connector.query("10.1.1.2", operation="SET")  # type: ignore[union-attr]
            ):
                guardrail_failures.append(
                    "SnmpWalkConnector.query failed to block SNMP SET operation"
                )
            if not self._assert_raises_permission_error(
                lambda: self.snmp_connector.set(  # type: ignore[union-attr]
                    "10.1.1.2", {"1.3.6.1.2.1.1.5.0": "mutated"}
                )
            ):
                guardrail_failures.append(
                    "SnmpWalkConnector.set failed to raise PermissionError"
                )

        if guardrail_failures:
            blocking_errors.extend(guardrail_failures)
            checks.append(
                PreFlightCheckResult(
                    check_name="readonly_guardrails",
                    passed=False,
                    severity="blocking",
                    message="; ".join(guardrail_failures),
                    details={
                        "verified_connectors": verified_connectors,
                        "failures": guardrail_failures,
                    },
                )
            )
        else:
            checks.append(
                PreFlightCheckResult(
                    check_name="readonly_guardrails",
                    passed=True,
                    severity="blocking",
                    message="All configured connectors enforced read-only PermissionError guardrails",
                    details={"verified_connectors": verified_connectors},
                )
            )

        # -------------------------------------------------------------------
        # 4. Endpoint Reachability & Credential Readiness (endpoint_reachability)
        # -------------------------------------------------------------------
        reachability_errors: list[str] = []
        reachability_details: dict[str, Any] = {}

        if self.scraper_session is not None:
            scraper_ok = self.scraper_session.check_health("/sites")
            reachability_details["scraper_healthy"] = scraper_ok
            if not scraper_ok:
                reachability_errors.append(
                    f"AuthenticatedScraperSession health check failed for {self.scraper_session.base_url}/sites"
                )

        if self.vsphere_connector is not None:
            try:
                vms = self.vsphere_connector.fetch_vms()
                reachability_details["vcenter_vm_count"] = len(vms)
            except Exception as exc:  # noqa: BLE001
                reachability_errors.append(
                    f"VSphereRestConnector failed to fetch VM inventory: {exc}"
                )
            if self.vsphere_connector.unreachable_instances:
                unreach_sorted = sorted(self.vsphere_connector.unreachable_instances)
                reachability_details["unreachable_vcenters"] = unreach_sorted
                reachability_errors.append(
                    f"Unreachable vCenter instance(s): {', '.join(unreach_sorted)}"
                )

        if self.snmp_connector is not None:
            if not self.snmp_connector.has_valid_credentials:
                reachability_errors.append(
                    f"SnmpWalkConnector is missing read-only credentials for SNMP v{self.snmp_connector.version}"
                )
            elif self.snmp_connector.has_live_transport:
                probed_sites: dict[str, str] = {}
                for sid, site_obj in resolved_sites.items():
                    mgmt_ips = [
                        dev.management_ip.strip()
                        for dev in site_obj.devices
                        if dev.management_ip and dev.management_ip.strip()
                    ]
                    if not mgmt_ips:
                        mgmt_ips = [
                            ip.strip()
                            for eq in site_obj.equipment
                            if eq.category is EquipmentCategory.UPS
                            for ip in eq.assigned_ips
                            if ip and ip.strip()
                        ]
                    if not mgmt_ips:
                        warn_msg = f"Pilot site {sid!r} has no device or UPS management IP to probe via SNMP"
                        warnings.append(warn_msg)
                        continue

                    probe_ip = mgmt_ips[0]
                    try:
                        oids = self.snmp_connector.get(probe_ip, SNMPV2_MIB_OIDS)
                        if not oids:
                            reachability_errors.append(
                                f"SNMP pre-flight probe to {probe_ip} in site {sid!r} returned empty OID response"
                            )
                        else:
                            probed_sites[sid] = probe_ip
                    except Exception as exc:  # noqa: BLE001
                        reachability_errors.append(
                            f"SNMP pre-flight probe failed for {probe_ip} in site {sid!r}: {exc}"
                        )
                reachability_details["snmp_probed_sites"] = probed_sites

        if reachability_errors:
            blocking_errors.extend(reachability_errors)
            checks.append(
                PreFlightCheckResult(
                    check_name="endpoint_reachability",
                    passed=False,
                    severity="blocking",
                    message="; ".join(reachability_errors),
                    details=reachability_details,
                )
            )
        else:
            checks.append(
                PreFlightCheckResult(
                    check_name="endpoint_reachability",
                    passed=True,
                    severity="blocking",
                    message="All configured pilot endpoints and credentials passed readiness checks",
                    details=reachability_details,
                )
            )

        ready = len(blocking_errors) == 0
        return PreFlightReport(
            ready=ready,
            pilot_site_ids=normalized_site_ids,
            checks=checks,
            blocking_errors=blocking_errors,
            warnings=warnings,
        )

    @staticmethod
    def _assert_raises_permission_error(fn: Any) -> bool:
        try:
            fn()
        except PermissionError:
            return True
        except Exception:  # noqa: BLE001
            return False
        return False


__all__ = [
    "PilotCutoverValidator",
    "PreFlightCheckResult",
    "PreFlightReport",
]
