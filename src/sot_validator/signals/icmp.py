"""Scoped ICMP reachability signal collector and /24 subnet scoping guard."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import pathlib
import threading
import time
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from sot_validator.models import (
    Equipment,
    IPAddress,
    NetworkDevice,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    ValidationSignal,
)


class ScopeViolationError(ValueError):
    """Raised when an active network probe target violates /24 subnet or SoT IP scoping."""


@dataclass(frozen=True)
class IcmpProbeResponse:
    """Result returned by an ICMP echo probe transport."""

    reachable: bool
    latency_ms: Optional[float] = None
    detail: Optional[str] = None


IcmpProbeCallable = Callable[[str, float], bool | IcmpProbeResponse]


def _parse_ipv4_host(ip_str: str) -> ipaddress.IPv4Address:
    """Parse an IPv4 address and reject non-IPv4, CIDR strings, or non-host addresses."""
    if not isinstance(ip_str, str) or not ip_str.strip():
        raise ScopeViolationError("Target IP address must be a non-empty string")
    raw = ip_str.strip()
    if "/" in raw:
        raise ScopeViolationError(
            f"Target IP {raw!r} contains a prefix length; CIDR sweeps are not valid host IPs"
        )
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ScopeViolationError(f"Invalid IP address {raw!r}: {exc}") from exc

    if not isinstance(addr, ipaddress.IPv4Address):
        raise ScopeViolationError(f"Only IPv4 host addresses are supported, got {raw!r}")

    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        raise ScopeViolationError(
            f"IP address {raw!r} is a reserved loopback/multicast/unspecified address"
        )

    slash24 = ipaddress.ip_network(f"{addr}/24", strict=False)
    if addr == slash24.network_address or addr == slash24.broadcast_address:
        raise ScopeViolationError(
            f"IP address {raw!r} is a /24 network or broadcast address, not a host address"
        )
    return addr


def _parse_allocated_slash24(cidr: str | Subnet) -> ipaddress.IPv4Network:
    """Validate that a subnet CIDR is strictly an IPv4 /24 prefix."""
    cidr_str = cidr.cidr if isinstance(cidr, Subnet) else cidr
    if not isinstance(cidr_str, str) or not cidr_str.strip():
        raise ScopeViolationError("Subnet CIDR must be a non-empty string")
    raw = cidr_str.strip()
    try:
        net = ipaddress.ip_network(raw, strict=True)
    except ValueError as exc:
        raise ScopeViolationError(f"Invalid subnet CIDR {raw!r}: {exc}") from exc

    if not isinstance(net, ipaddress.IPv4Network):
        raise ScopeViolationError(f"Subnet {raw!r} must be an IPv4 network")

    if net.prefixlen != 24:
        raise ScopeViolationError(
            f"Subnet {raw!r} has prefix length /{net.prefixlen}; active probing requires "
            "strictly allocated /24 subnets and prohibits /16 or non-/24 sweeps"
        )
    return net


class SubnetScopeGuard:
    """Enforces strict /24 subnet and recorded SoT IP scoping for active probes.

    Each site owns a ``10.x.0.0/16`` summary prefix with ~10 active ``/24`` blocks.
    Probes are strictly limited to allocated ``/24`` subnets and recorded SoT host IPs,
    rejecting full ``/16`` sweeps and unallocated ``/24`` blocks.
    """

    def __init__(
        self,
        subnets: Optional[Iterable[Subnet | str]] = None,
        recorded_ips: Optional[Iterable[IPAddress | str]] = None,
        *,
        site_prefix: Optional[str] = None,
    ) -> None:
        self._site_prefix: Optional[ipaddress.IPv4Network] = None
        if site_prefix is not None:
            try:
                parsed_prefix = ipaddress.ip_network(site_prefix.strip(), strict=True)
            except ValueError as exc:
                raise ScopeViolationError(
                    f"Invalid site_prefix {site_prefix!r}: {exc}"
                ) from exc
            if not isinstance(parsed_prefix, ipaddress.IPv4Network):
                raise ScopeViolationError(
                    f"site_prefix {site_prefix!r} must be an IPv4 network"
                )
            self._site_prefix = parsed_prefix

        allocated: list[ipaddress.IPv4Network] = []
        seen_nets: set[ipaddress.IPv4Network] = set()
        for item in subnets or ():
            net = _parse_allocated_slash24(item)
            if self._site_prefix is not None and not net.subnet_of(self._site_prefix):
                raise ScopeViolationError(
                    f"Allocated /24 subnet {net} falls outside site prefix {self._site_prefix}"
                )
            if net not in seen_nets:
                seen_nets.add(net)
                allocated.append(net)
        self._allocated_subnets: tuple[ipaddress.IPv4Network, ...] = tuple(allocated)

        recorded: set[str] = set()
        for ip_item in recorded_ips or ():
            ip_str = ip_item.ip if isinstance(ip_item, IPAddress) else ip_item
            if ip_str is not None and str(ip_str).strip():
                addr = _parse_ipv4_host(str(ip_str))
                recorded.add(str(addr))
        self._recorded_ips: frozenset[str] = frozenset(recorded)

    @classmethod
    def from_site(
        cls,
        site: Site,
        *,
        site_prefix: Optional[str] = None,
    ) -> SubnetScopeGuard:
        """Build a scoping guard from a Site's allocated /24 subnets and recorded SoT IPs."""
        recorded_ips: list[str] = []
        for ip_rec in site.ip_addresses:
            if ip_rec.ip:
                recorded_ips.append(ip_rec.ip)
        for dev in site.devices:
            if dev.management_ip:
                recorded_ips.append(dev.management_ip)
        for eq in site.equipment:
            for assigned_ip in eq.assigned_ips:
                if assigned_ip:
                    recorded_ips.append(assigned_ip)
        return cls(
            subnets=site.subnets,
            recorded_ips=recorded_ips,
            site_prefix=site_prefix,
        )

    @property
    def allocated_subnets(self) -> tuple[ipaddress.IPv4Network, ...]:
        """Allocated IPv4 /24 subnets permitted for active probing."""
        return self._allocated_subnets

    @property
    def recorded_ips(self) -> frozenset[str]:
        """Explicitly recorded SoT IPv4 addresses."""
        return self._recorded_ips

    @property
    def site_prefix(self) -> Optional[ipaddress.IPv4Network]:
        """Optional parent summary prefix (e.g. 10.42.0.0/16) for the site."""
        return self._site_prefix

    def validate_cidr_scope(self, cidr: str | Subnet) -> ipaddress.IPv4Network:
        """Validate that ``cidr`` is an allocated /24 subnet; reject /16 or unallocated blocks."""
        net = _parse_allocated_slash24(cidr)
        if self._site_prefix is not None and not net.subnet_of(self._site_prefix):
            raise ScopeViolationError(
                f"Subnet {net} is outside site prefix {self._site_prefix}"
            )
        if not self._allocated_subnets:
            raise ScopeViolationError(
                f"Cannot sweep subnet {net}: no allocated /24 subnets are registered in scope"
            )
        if net not in self._allocated_subnets:
            raise ScopeViolationError(
                f"Subnet {net} is not in the site's allocated /24 subnets"
            )
        return net

    def expand_scoped_hosts(self, cidr: str | Subnet) -> list[str]:
        """Return host IPs for an allocated /24 subnet, rejecting /16 or unallocated blocks."""
        net = self.validate_cidr_scope(cidr)
        return [str(host) for host in net.hosts()]

    def validate_target_ip(self, ip_str: str) -> str:
        """Validate that ``ip_str`` is an in-scope host IPv4 address and return normalized IP."""
        addr = _parse_ipv4_host(ip_str)
        normalized = str(addr)

        if self._site_prefix is not None and addr not in self._site_prefix:
            raise ScopeViolationError(
                f"IP {normalized} falls outside site summary prefix {self._site_prefix}"
            )

        if self._allocated_subnets:
            if not any(addr in subnet for subnet in self._allocated_subnets):
                raise ScopeViolationError(
                    f"IP {normalized} is not within any allocated /24 subnet "
                    f"({', '.join(str(s) for s in self._allocated_subnets)})"
                )
            return normalized

        if self._recorded_ips:
            if normalized not in self._recorded_ips:
                raise ScopeViolationError(
                    f"IP {normalized} is not in the site's recorded SoT IP inventory"
                )
            return normalized

        raise ScopeViolationError(
            f"IP {normalized} rejected: scope guard has no allocated /24 subnets or recorded IPs"
        )

    def is_ip_in_scope(self, ip_str: str) -> bool:
        """Return True if ``ip_str`` passes the /24 subnet and recorded-IP scope guard."""
        try:
            self.validate_target_ip(ip_str)
            return True
        except ScopeViolationError:
            return False


def _default_icmp_probe(ip: str, timeout_seconds: float) -> IcmpProbeResponse:
    """Default safe no-op offline ICMP probe returning unreachable when no transport is injected."""
    _ = (ip, timeout_seconds)
    return IcmpProbeResponse(
        reachable=False,
        latency_ms=None,
        detail="No live ICMP transport configured (offline default)",
    )


class IcmpProbeCollector:
    """Scoped active ICMP echo reachability signal collector.

    Enforces `/24` subnet and recorded SoT IP scoping guards, bounded concurrency,
    configurable timeouts, and retry counts.
    """

    def __init__(
        self,
        *,
        max_concurrency: int = 32,
        timeout_seconds: float = 1.0,
        retries: int = 1,
        probe_fn: Optional[IcmpProbeCallable] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
        source: str = "icmp_probe",
    ) -> None:
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int) or max_concurrency < 1:
            raise ValueError("max_concurrency must be an integer >= 1")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a number > 0")
        if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:
            raise ValueError("retries must be an integer >= 0")

        self.max_concurrency: int = max_concurrency
        self.timeout_seconds: float = float(timeout_seconds)
        self.retries: int = retries
        self._probe_fn: IcmpProbeCallable = probe_fn or _default_icmp_probe
        self.scope_guard: Optional[SubnetScopeGuard] = scope_guard
        self.source: str = source
        self._semaphore = threading.BoundedSemaphore(self.max_concurrency)

    @classmethod
    def from_fixture_file(
        cls,
        fixture_path: str | pathlib.Path,
        *,
        max_concurrency: int = 32,
        timeout_seconds: float = 1.0,
        retries: int = 1,
    ) -> IcmpProbeCollector:
        """Create an IcmpProbeCollector backed by a discovery fixture JSON file."""
        path = pathlib.Path(fixture_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        scoped_subnets = data.get("scoped_subnets", [])
        site_prefix = data.get("site_prefix")
        targets = data.get("targets", {})

        reachability_by_ip: dict[str, bool] = {}
        recorded_ips: list[str] = []
        for target in targets.values():
            ip = target.get("ip_address")
            if ip:
                recorded_ips.append(ip)
                reachability_by_ip[ip] = bool(target.get("icmp_reachable", False))

        guard = SubnetScopeGuard(
            subnets=scoped_subnets,
            recorded_ips=recorded_ips,
            site_prefix=site_prefix,
        )

        def _fixture_probe(ip: str, timeout: float) -> IcmpProbeResponse:
            _ = timeout
            is_up = reachability_by_ip.get(ip, False)
            return IcmpProbeResponse(
                reachable=is_up,
                latency_ms=1.2 if is_up else None,
                detail="fixture_icmp_reply" if is_up else "fixture_icmp_timeout",
            )

        return cls(
            max_concurrency=max_concurrency,
            timeout_seconds=timeout_seconds,
            retries=retries,
            probe_fn=_fixture_probe,
            scope_guard=guard,
        )

    def _resolve_scope_guard(
        self,
        site: Optional[Site] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> Optional[SubnetScopeGuard]:
        if scope_guard is not None:
            return scope_guard
        if site is not None:
            return SubnetScopeGuard.from_site(site)
        return self.scope_guard

    def validate_target_ip(
        self,
        ip: str,
        *,
        site: Optional[Site] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> str:
        """Validate a target IP against the active /24 scope guard or raise ScopeViolationError."""
        guard = self._resolve_scope_guard(site=site, scope_guard=scope_guard)
        if guard is not None:
            return guard.validate_target_ip(ip)
        return str(_parse_ipv4_host(ip))

    def validate_cidr_scope(
        self,
        cidr: str | Subnet,
        *,
        site: Optional[Site] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ipaddress.IPv4Network:
        """Validate a CIDR block for active probing; rejects /16 or unallocated /24 sweeps."""
        guard = self._resolve_scope_guard(site=site, scope_guard=scope_guard)
        if guard is not None:
            return guard.validate_cidr_scope(cidr)
        return _parse_allocated_slash24(cidr)

    def _probe_validated_ip(self, normalized_ip: str) -> ValidationSignal:
        """Execute up to ``1 + retries`` bounded-concurrency ICMP probes against a validated IP."""
        total_attempts = 1 + self.retries
        last_error: Optional[Exception] = None
        had_timeout_or_false = False

        for attempt in range(1, total_attempts + 1):
            start = time.monotonic()
            try:
                with self._semaphore:
                    raw_result = self._probe_fn(normalized_ip, self.timeout_seconds)
            except TimeoutError:
                had_timeout_or_false = True
                continue
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue

            elapsed_ms = (time.monotonic() - start) * 1000.0
            if isinstance(raw_result, IcmpProbeResponse):
                reachable = raw_result.reachable
                latency_ms = (
                    raw_result.latency_ms
                    if raw_result.latency_ms is not None
                    else elapsed_ms
                )
                extra_detail = raw_result.detail
            else:
                reachable = bool(raw_result)
                latency_ms = elapsed_ms
                extra_detail = None

            if reachable:
                detail_msg = (
                    f"ICMP echo reply from {normalized_ip} "
                    f"(attempt {attempt}/{total_attempts}, latency={latency_ms:.2f}ms)"
                )
                if extra_detail:
                    detail_msg = f"{detail_msg} [{extra_detail}]"
                return ValidationSignal(
                    signal_type=SignalType.ICMP_REACHABILITY,
                    status=SignalStatus.ACTIVE,
                    observed_at=datetime.now(timezone.utc),
                    age_seconds=0.0,
                    details=detail_msg,
                    source=self.source,
                )

            had_timeout_or_false = True

        if last_error is not None and not had_timeout_or_false:
            return ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.ERROR,
                observed_at=datetime.now(timezone.utc),
                age_seconds=0.0,
                details=(
                    f"ICMP probe error for {normalized_ip} after {total_attempts} "
                    f"attempt(s): {type(last_error).__name__}: {last_error}"
                ),
                source=self.source,
            )

        return ValidationSignal(
            signal_type=SignalType.ICMP_REACHABILITY,
            status=SignalStatus.UNREACHABLE,
            observed_at=datetime.now(timezone.utc),
            age_seconds=0.0,
            details=(
                f"ICMP unreachable for {normalized_ip} after {total_attempts} "
                f"attempt(s) (timeout={self.timeout_seconds}s)"
            ),
            source=self.source,
        )

    def collect_for_ip(
        self,
        ip_record: IPAddress | str,
        site: Optional[Site] = None,
        *,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ValidationSignal:
        """Evaluate ICMP reachability for a single IPAddress record or IP string."""
        raw_ip = ip_record.ip if isinstance(ip_record, IPAddress) else ip_record
        if raw_ip is None or not str(raw_ip).strip():
            return ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=datetime.now(timezone.utc),
                details="No IP address provided for ICMP probe",
                source=self.source,
            )

        try:
            normalized_ip = self.validate_target_ip(
                str(raw_ip), site=site, scope_guard=scope_guard
            )
        except ScopeViolationError as exc:
            return ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.ERROR,
                observed_at=datetime.now(timezone.utc),
                details=f"Scope guard rejected IP {raw_ip!r}: {exc}",
                source=self.source,
            )

        return self._probe_validated_ip(normalized_ip)

    def collect_for_device(
        self,
        device: NetworkDevice,
        site: Optional[Site] = None,
        *,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ValidationSignal:
        """Evaluate ICMP reachability for a NetworkDevice's management_ip."""
        if device.management_ip is None or not device.management_ip.strip():
            return ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=datetime.now(timezone.utc),
                details=f"NetworkDevice {device.device_id} ({device.hostname}) has no management_ip",
                source=self.source,
            )
        return self.collect_for_ip(
            device.management_ip, site=site, scope_guard=scope_guard
        )

    def collect_for_equipment(
        self,
        equipment: Equipment,
        site: Optional[Site] = None,
        *,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> ValidationSignal:
        """Evaluate ICMP reachability across an Equipment record's assigned_ips."""
        clean_ips = [ip.strip() for ip in equipment.assigned_ips if ip and ip.strip()]
        if not clean_ips:
            return ValidationSignal(
                signal_type=SignalType.ICMP_REACHABILITY,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=datetime.now(timezone.utc),
                details=f"Equipment {equipment.equipment_id} ({equipment.name}) has no assigned_ips",
                source=self.source,
            )

        signals: list[ValidationSignal] = []
        for ip_str in clean_ips:
            sig = self.collect_for_ip(ip_str, site=site, scope_guard=scope_guard)
            if sig.status is SignalStatus.ACTIVE:
                return sig
            signals.append(sig)

        for sig in signals:
            if sig.status is SignalStatus.ERROR:
                return sig
        return signals[0]

    def probe_ips(
        self,
        ips: Sequence[str],
        *,
        site: Optional[Site] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> dict[str, ValidationSignal]:
        """Probe a batch of IP addresses concurrently using max_concurrency."""
        guard = self._resolve_scope_guard(site=site, scope_guard=scope_guard)
        unique_ips = list(dict.fromkeys(ips))
        if not unique_ips:
            return {}

        results: dict[str, ValidationSignal] = {}
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as executor:
            future_to_ip = {
                executor.submit(self.collect_for_ip, ip, scope_guard=guard): ip
                for ip in unique_ips
            }
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                results[ip] = future.result()

        return {ip: results[ip] for ip in unique_ips}

    def collect_site(
        self,
        site: Site,
        *,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> dict[str, ValidationSignal]:
        """Collect ICMP reachability signals for all devices, equipment, and IPs in a Site."""
        guard = scope_guard or self.scope_guard or SubnetScopeGuard.from_site(site)

        candidate_ips: list[str] = []
        for dev in site.devices:
            if dev.management_ip and dev.management_ip.strip():
                candidate_ips.append(dev.management_ip.strip())
        for eq in site.equipment:
            for ip_str in eq.assigned_ips:
                if ip_str and ip_str.strip():
                    candidate_ips.append(ip_str.strip())
        for ip_rec in site.ip_addresses:
            if ip_rec.ip and ip_rec.ip.strip():
                candidate_ips.append(ip_rec.ip.strip())

        ip_signals = self.probe_ips(candidate_ips, scope_guard=guard)

        output: dict[str, ValidationSignal] = {}
        for ip_rec in site.ip_addresses:
            key = ip_rec.ip.strip()
            if key in ip_signals:
                output[ip_rec.ip] = ip_signals[key]
            else:
                output[ip_rec.ip] = self.collect_for_ip(ip_rec, scope_guard=guard)

        for dev in site.devices:
            if not dev.management_ip or not dev.management_ip.strip():
                output[dev.device_id] = self.collect_for_device(dev, scope_guard=guard)
            else:
                output[dev.device_id] = ip_signals[dev.management_ip.strip()]

        for eq in site.equipment:
            clean_ips = [ip.strip() for ip in eq.assigned_ips if ip and ip.strip()]
            if not clean_ips:
                output[eq.equipment_id] = self.collect_for_equipment(eq, scope_guard=guard)
            else:
                eq_sigs = [ip_signals[ip] for ip in clean_ips]
                active_sig = next(
                    (s for s in eq_sigs if s.status is SignalStatus.ACTIVE), None
                )
                if active_sig is not None:
                    output[eq.equipment_id] = active_sig
                else:
                    error_sig = next(
                        (s for s in eq_sigs if s.status is SignalStatus.ERROR), None
                    )
                    output[eq.equipment_id] = error_sig or eq_sigs[0]

        return output


__all__ = [
    "IcmpProbeCallable",
    "IcmpProbeCollector",
    "IcmpProbeResponse",
    "ScopeViolationError",
    "SubnetScopeGuard",
]
