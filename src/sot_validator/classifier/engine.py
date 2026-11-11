"""Multi-signal classification engine and calibrated confidence scoring."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)
from sot_validator.signals.arp import ArpSignalEvaluator
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    normalize_utc_datetime,
    resolve_evaluation_time,
    validate_recency_thresholds,
)
from sot_validator.signals.directory_dns import (
    ActiveDirectoryCollector,
    DnsDhcpLeaseCollector,
)
from sot_validator.signals.hypervisor import (
    HypervisorInventoryProvider,
    VmPowerState,
    VmPowerStateCollector,
    _extract_equipment_vm_hints,
    normalize_vm_power_state,
)
from sot_validator.signals.icmp import IcmpProbeCollector
from sot_validator.signals.last_seen import LastSeenSignalEvaluator
from sot_validator.signals.management import ManagementProbeCollector
from sot_validator.signals.port_state import PortStateSignalEvaluator

DEFAULT_SIGNAL_WEIGHTS: dict[SignalType, float] = {
    SignalType.VM_POWER_STATE: 0.45,
    SignalType.AD_COMPUTER_ACCOUNT: 0.40,
    SignalType.SNMP_API_REACHABILITY: 0.40,
    SignalType.ICMP_REACHABILITY: 0.35,
    SignalType.ARP_RECENCY: 0.35,
    SignalType.DNS_DHCP_LEASE: 0.35,
    SignalType.PORT_STATE: 0.25,
    SignalType.LAST_SEEN_TIMESTAMP: 0.15,
}

_SUBSTANTIVE_STALE_SIGNAL_TYPES: frozenset[SignalType] = frozenset(
    {
        SignalType.ARP_RECENCY,
        SignalType.PORT_STATE,
        SignalType.VM_POWER_STATE,
        SignalType.LAST_SEEN_TIMESTAMP,
        SignalType.AD_COMPUTER_ACCOUNT,
        SignalType.DNS_DHCP_LEASE,
    }
)

_HIGH_CONFIDENCE_ACTIVE_SIGNAL_TYPES: frozenset[SignalType] = frozenset(
    {
        SignalType.ICMP_REACHABILITY,
        SignalType.SNMP_API_REACHABILITY,
        SignalType.ARP_RECENCY,
        SignalType.VM_POWER_STATE,
        SignalType.AD_COMPUTER_ACCOUNT,
        SignalType.DNS_DHCP_LEASE,
    }
)

_ACTIVE_PROBE_SIGNAL_TYPES: frozenset[SignalType] = frozenset(
    {
        SignalType.ICMP_REACHABILITY,
        SignalType.SNMP_API_REACHABILITY,
    }
)


def _default_signal_weights() -> dict[SignalType, float]:
    return dict(DEFAULT_SIGNAL_WEIGHTS)


@dataclass
class ClassificationPolicy:
    """Configurable recency thresholds, rules, and signal weights for classification."""

    active_within_days: float = 7.0
    stale_after_days: float = 30.0
    windows_vm_ignore_icmp_unreachable: bool = True
    signal_weights: dict[SignalType, float] = field(
        default_factory=_default_signal_weights
    )

    def __post_init__(self) -> None:
        self.active_within_days, self.stale_after_days = validate_recency_thresholds(
            self.active_within_days,
            self.stale_after_days,
        )
        if not isinstance(self.windows_vm_ignore_icmp_unreachable, bool):
            raise ValueError("windows_vm_ignore_icmp_unreachable must be a boolean")
        if not isinstance(self.signal_weights, Mapping):
            raise ValueError("signal_weights must be a mapping of SignalType to float")

        normalized_weights: dict[SignalType, float] = dict(DEFAULT_SIGNAL_WEIGHTS)
        for raw_key, raw_val in self.signal_weights.items():
            key = (
                raw_key
                if isinstance(raw_key, SignalType)
                else SignalType(str(raw_key))
            )
            if isinstance(raw_val, bool) or not isinstance(raw_val, (int, float)):
                raise ValueError(
                    f"Signal weight for {key.value} must be a non-negative number"
                )
            weight = float(raw_val)
            if weight < 0.0:
                raise ValueError(
                    f"Signal weight for {key.value} must be non-negative"
                )
            normalized_weights[key] = weight

        self.signal_weights = normalized_weights

    @property
    def active_threshold_seconds(self) -> float:
        """Active recency window in seconds."""
        return self.active_within_days * SECONDS_PER_DAY

    @property
    def stale_threshold_seconds(self) -> float:
        """Stale inactivity threshold in seconds."""
        return self.stale_after_days * SECONDS_PER_DAY

    def weight_for(self, signal_type: SignalType) -> float:
        """Return the configured non-negative weight for a SignalType."""
        return self.signal_weights.get(
            signal_type, DEFAULT_SIGNAL_WEIGHTS.get(signal_type, 0.1)
        )


@dataclass(frozen=True)
class _EvaluatedSignalView:
    """Internal normalized view of a ValidationSignal under a ClassificationPolicy."""

    signal: ValidationSignal
    effective_status: SignalStatus
    is_intermediate: bool = False
    is_stale: bool = False
    discounted: bool = False


def _has_healthy_tools_detail(details: Optional[str]) -> bool:
    if not details:
        return False
    lower = details.lower()
    return any(
        token in lower
        for token in (
            "toolsok",
            "toolsold",
            "heartbeat=green",
            "bonus confidence",
            "guest tools heartbeat active",
        )
    )


def _is_windows_context(
    target: Optional[Any], signals: Sequence[_EvaluatedSignalView]
) -> bool:
    for view in signals:
        if view.signal.signal_type is SignalType.AD_COMPUTER_ACCOUNT:
            return True
        details_lower = (view.signal.details or "").lower()
        if "windows" in details_lower or "os=windows" in details_lower:
            return True
        os_meta = str(
            view.signal.metadata.get("operatingSystem")
            or view.signal.metadata.get("operating_system")
            or ""
        ).lower()
        if "windows" in os_meta:
            return True
    if isinstance(target, Equipment):
        if target.category is EquipmentCategory.VM:
            name_lower = target.name.lower()
            if "win" in name_lower:
                return True
    return False


def _sot_power_state_is_active(equipment: Equipment) -> bool:
    if not equipment.power_state or not equipment.power_state.strip():
        return False
    try:
        return normalize_vm_power_state(equipment.power_state) is VmPowerState.POWERED_ON
    except ValueError:
        return False


def _has_actionable_identifiers(
    target: Optional[Any], site: Optional[Site] = None
) -> bool:
    """Return True if the inventory target has at least one actionable identifier."""
    if target is None:
        return True

    if isinstance(target, IPAddress):
        return bool(target.ip and target.ip.strip())

    if isinstance(target, NetworkDevice):
        if target.management_ip and target.management_ip.strip():
            return True
        if target.ports:
            return True
        if target.last_seen is not None:
            return True
        if site is not None:
            for ip_rec in site.ip_addresses:
                if ip_rec.assigned_object_id == target.device_id:
                    return True
            for dev in site.devices:
                for port in dev.ports:
                    if (
                        port.device_id == target.device_id
                        or port.connected_device_id == target.device_id
                    ):
                        return True
        return False

    if isinstance(target, Equipment):
        if any(ip and ip.strip() for ip in target.assigned_ips):
            return True
        if any(p and p.strip() for p in target.connected_ports):
            return True
        if target.last_seen is not None:
            return True
        if target.hypervisor_id and target.hypervisor_id.strip():
            return True
        if target.power_state and target.power_state.strip():
            return True
        uuids, inst_hint, moref_hint, macs, _ = _extract_equipment_vm_hints(target)
        if uuids or inst_hint or moref_hint or macs:
            return True
        if site is not None:
            for ip_rec in site.ip_addresses:
                if ip_rec.assigned_object_id == target.equipment_id:
                    return True
            for dev in site.devices:
                for port in dev.ports:
                    if port.connected_device_id == target.equipment_id:
                        return True
        return False

    return True


class ClassificationEngine:
    """Rule-based multi-signal classification engine producing ValidationResult records."""

    def __init__(
        self,
        policy: Optional[ClassificationPolicy] = None,
        *,
        arp_evaluator: Optional[ArpSignalEvaluator] = None,
        port_evaluator: Optional[PortStateSignalEvaluator] = None,
        last_seen_evaluator: Optional[LastSeenSignalEvaluator] = None,
        icmp_collector: Optional[IcmpProbeCollector] = None,
        management_collector: Optional[ManagementProbeCollector] = None,
        vm_collector: Optional[VmPowerStateCollector] = None,
        hypervisor_provider: Optional[HypervisorInventoryProvider] = None,
        ad_collector: Optional[ActiveDirectoryCollector] = None,
        dns_dhcp_collector: Optional[DnsDhcpLeaseCollector] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> None:
        if policy is not None and not isinstance(policy, ClassificationPolicy):
            raise ValueError("policy must be a ClassificationPolicy instance")
        self.policy: ClassificationPolicy = policy or ClassificationPolicy()
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.arp_evaluator: ArpSignalEvaluator = arp_evaluator or ArpSignalEvaluator(
            active_within_days=self.policy.active_within_days,
            stale_after_days=self.policy.stale_after_days,
            evaluation_time=self.evaluation_time,
        )
        self.port_evaluator: PortStateSignalEvaluator = (
            port_evaluator
            or PortStateSignalEvaluator(evaluation_time=self.evaluation_time)
        )
        self.last_seen_evaluator: LastSeenSignalEvaluator = (
            last_seen_evaluator
            or LastSeenSignalEvaluator(
                active_within_days=self.policy.active_within_days,
                stale_after_days=self.policy.stale_after_days,
                evaluation_time=self.evaluation_time,
            )
        )
        self.icmp_collector: Optional[IcmpProbeCollector] = icmp_collector
        self.management_collector: Optional[ManagementProbeCollector] = (
            management_collector
        )
        self.hypervisor_provider: Optional[HypervisorInventoryProvider] = (
            hypervisor_provider
            if hypervisor_provider is not None
            else (vm_collector.provider if vm_collector is not None else None)
        )
        self.vm_collector: Optional[VmPowerStateCollector] = vm_collector or (
            VmPowerStateCollector(
                provider=self.hypervisor_provider,
                evaluation_time=self.evaluation_time,
            )
            if self.hypervisor_provider is not None
            else None
        )
        self.ad_collector: Optional[ActiveDirectoryCollector] = ad_collector
        self.dns_dhcp_collector: Optional[DnsDhcpLeaseCollector] = dns_dhcp_collector

    def _resolve_eval_time(
        self, evaluation_time: Optional[datetime | str] = None
    ) -> datetime:
        if evaluation_time is not None:
            return resolve_evaluation_time(evaluation_time)
        if self.evaluation_time is not None:
            return self.evaluation_time
        return resolve_evaluation_time(None)

    @staticmethod
    def _gather_ports(
        site: Optional[Site], ports: Optional[Sequence[Port]]
    ) -> list[Port]:
        collected: list[Port] = []
        seen: set[tuple[str, str, str]] = set()

        def _add(port: Port) -> None:
            key = (port.device_id, port.port_id, port.name)
            if key not in seen:
                seen.add(key)
                collected.append(port)

        if ports:
            for p in ports:
                _add(p)
        if site is not None:
            for dev in site.devices:
                for p in dev.ports:
                    _add(p)
        return collected

    @staticmethod
    def _gather_ips(
        site: Optional[Site], ip_addresses: Optional[Sequence[IPAddress]]
    ) -> list[IPAddress]:
        collected: list[IPAddress] = []
        seen: set[int] = set()
        if ip_addresses:
            for ip_rec in ip_addresses:
                if id(ip_rec) not in seen:
                    seen.add(id(ip_rec))
                    collected.append(ip_rec)
        if site is not None:
            for ip_rec in site.ip_addresses:
                if id(ip_rec) not in seen:
                    seen.add(id(ip_rec))
                    collected.append(ip_rec)
        return collected

    def collect_signals(
        self,
        target: Any,
        *,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> list[ValidationSignal]:
        """Collect all applicable passive, hypervisor, and active signals for a target."""
        eval_dt = self._resolve_eval_time(evaluation_time)
        ip_addresses: Optional[Sequence[IPAddress]] = kwargs.get("ip_addresses")
        arp_entries: Optional[Sequence[ArpEntry]] = kwargs.get("arp_entries")
        ports: Optional[Sequence[Port]] = kwargs.get("ports")
        scope_guard = kwargs.get("scope_guard")
        provider: Optional[HypervisorInventoryProvider] = (
            kwargs.get("provider") or self.hypervisor_provider
        )

        if isinstance(target, NetworkDevice):
            signals: list[ValidationSignal] = [
                self.arp_evaluator.evaluate(
                    target,
                    site=site,
                    ip_addresses=ip_addresses,
                    arp_entries=arp_entries,
                    ports=ports,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                ),
                self.port_evaluator.evaluate(
                    target,
                    site=site,
                    ports=ports,
                    evaluation_time=eval_dt,
                ),
                self.last_seen_evaluator.evaluate(
                    target,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                ),
            ]
            if self.ad_collector is not None:
                signals.append(
                    self.ad_collector.evaluate(
                        target, site=site, evaluation_time=eval_dt
                    )
                )
            if self.dns_dhcp_collector is not None:
                signals.append(
                    self.dns_dhcp_collector.evaluate(
                        target,
                        site=site,
                        ip_addresses=ip_addresses,
                        scope_guard=scope_guard,
                        evaluation_time=eval_dt,
                    )
                )
            if self.icmp_collector is not None:
                signals.append(
                    self.icmp_collector.collect_for_device(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            if self.management_collector is not None:
                signals.append(
                    self.management_collector.collect_for_device(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            return signals

        if isinstance(target, IPAddress):
            signals = [
                self.arp_evaluator.evaluate(
                    target,
                    site=site,
                    ip_addresses=ip_addresses,
                    arp_entries=arp_entries,
                    ports=ports,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                ),
            ]
            if getattr(target, "last_seen", None) is not None:
                signals.append(
                    self.last_seen_evaluator.evaluate(
                        target,
                        evaluation_time=eval_dt,
                        active_within_days=self.policy.active_within_days,
                        stale_after_days=self.policy.stale_after_days,
                    )
                )
            if self.dns_dhcp_collector is not None:
                signals.append(
                    self.dns_dhcp_collector.evaluate(
                        target,
                        site=site,
                        ip_addresses=ip_addresses,
                        scope_guard=scope_guard,
                        evaluation_time=eval_dt,
                    )
                )
            if self.icmp_collector is not None:
                signals.append(
                    self.icmp_collector.collect_for_ip(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            if self.management_collector is not None:
                signals.append(
                    self.management_collector.collect_for_ip(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            return signals

        if isinstance(target, Equipment):
            if (
                not _has_actionable_identifiers(target, site=site)
                and provider is None
                and self.ad_collector is None
                and self.dns_dhcp_collector is None
            ):
                return [
                    self.arp_evaluator.evaluate(
                        target,
                        site=site,
                        ip_addresses=ip_addresses,
                        arp_entries=arp_entries,
                        ports=ports,
                        evaluation_time=eval_dt,
                        active_within_days=self.policy.active_within_days,
                        stale_after_days=self.policy.stale_after_days,
                    ),
                    self.port_evaluator.evaluate(
                        target,
                        site=site,
                        ports=ports,
                        evaluation_time=eval_dt,
                    ),
                    self.last_seen_evaluator.evaluate(
                        target,
                        evaluation_time=eval_dt,
                        active_within_days=self.policy.active_within_days,
                        stale_after_days=self.policy.stale_after_days,
                    ),
                ]

            if target.category is EquipmentCategory.VM:
                all_ports = self._gather_ports(site, ports)
                dedicated_ports = [
                    p
                    for p in all_ports
                    if not (
                        p.connected_device_id is not None
                        and p.connected_device_id.strip() != ""
                        and p.connected_device_id != target.equipment_id
                    )
                ]
                all_ips = self._gather_ips(site, ip_addresses)
                arp_sig = self.arp_evaluator.evaluate(
                    target,
                    site=None,
                    ip_addresses=all_ips,
                    arp_entries=arp_entries,
                    ports=dedicated_ports,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                )
                port_sig = self.port_evaluator.evaluate(
                    target,
                    site=None,
                    ports=dedicated_ports,
                    evaluation_time=eval_dt,
                )
            else:
                arp_sig = self.arp_evaluator.evaluate(
                    target,
                    site=site,
                    ip_addresses=ip_addresses,
                    arp_entries=arp_entries,
                    ports=ports,
                    evaluation_time=eval_dt,
                    active_within_days=self.policy.active_within_days,
                    stale_after_days=self.policy.stale_after_days,
                )
                port_sig = self.port_evaluator.evaluate(
                    target,
                    site=site,
                    ports=ports,
                    evaluation_time=eval_dt,
                )

            last_seen_sig = self.last_seen_evaluator.evaluate(
                target,
                evaluation_time=eval_dt,
                active_within_days=self.policy.active_within_days,
                stale_after_days=self.policy.stale_after_days,
            )

            signals = [arp_sig, port_sig, last_seen_sig]

            _, _, _, _, has_vm_hint = _extract_equipment_vm_hints(
                target,
                bios_uuid=kwargs.get("bios_uuid"),
                vcenter_instance=kwargs.get("vcenter_instance"),
                vm_moref=kwargs.get("vm_moref"),
                mac_addresses=kwargs.get("mac_addresses"),
            )
            if (
                self.vm_collector is not None
                or provider is not None
                or has_vm_hint
            ):
                vm_collector = self.vm_collector or VmPowerStateCollector(
                    provider=provider,
                    evaluation_time=eval_dt,
                )
                signals.append(
                    vm_collector.evaluate(
                        target,
                        provider=provider,
                        site=site,
                        ip_addresses=ip_addresses,
                        arp_entries=arp_entries,
                        ports=ports,
                        bios_uuid=kwargs.get("bios_uuid"),
                        vcenter_instance=kwargs.get("vcenter_instance"),
                        vm_moref=kwargs.get("vm_moref"),
                        mac_addresses=kwargs.get("mac_addresses"),
                        inactive_threshold_days=kwargs.get("inactive_threshold_days"),
                        evaluation_time=eval_dt,
                    )
                )

            if self.ad_collector is not None:
                signals.append(
                    self.ad_collector.evaluate(
                        target, site=site, evaluation_time=eval_dt
                    )
                )
            if self.dns_dhcp_collector is not None:
                signals.append(
                    self.dns_dhcp_collector.evaluate(
                        target,
                        site=site,
                        ip_addresses=ip_addresses,
                        scope_guard=scope_guard,
                        evaluation_time=eval_dt,
                    )
                )
            if self.icmp_collector is not None:
                signals.append(
                    self.icmp_collector.collect_for_equipment(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            if self.management_collector is not None:
                signals.append(
                    self.management_collector.collect_for_equipment(
                        target, site=site, scope_guard=scope_guard
                    )
                )
            return signals

        raise ValueError(
            f"Unsupported target type for signal collection: {type(target).__name__}"
        )

    def _normalize_signals(
        self,
        signals: Sequence[ValidationSignal],
        eval_dt: datetime,
    ) -> list[_EvaluatedSignalView]:
        active_sec = self.policy.active_threshold_seconds
        stale_sec = self.policy.stale_threshold_seconds

        preliminary: list[_EvaluatedSignalView] = []
        for raw_sig in signals:
            sig = (
                raw_sig
                if isinstance(raw_sig, ValidationSignal)
                else ValidationSignal.from_dict(raw_sig)
            )
            status = sig.status
            age_sec = sig.age_seconds
            if (
                age_sec is None
                and sig.observed_at is not None
                and status in (SignalStatus.ACTIVE, SignalStatus.INACTIVE)
                and sig.signal_type
                in (SignalType.ARP_RECENCY, SignalType.LAST_SEEN_TIMESTAMP)
            ):
                obs_utc = normalize_utc_datetime(
                    sig.observed_at, field_name="observed_at"
                )
                age_sec = max(0.0, (eval_dt - obs_utc).total_seconds())

            details_lower = (sig.details or "").lower()
            is_intermediate = False
            is_stale = False

            if sig.signal_type in (
                SignalType.ARP_RECENCY,
                SignalType.LAST_SEEN_TIMESTAMP,
            ):
                if status in (SignalStatus.ACTIVE, SignalStatus.INACTIVE):
                    if age_sec is not None:
                        if age_sec <= active_sec:
                            status = SignalStatus.ACTIVE
                        elif age_sec <= stale_sec:
                            status = SignalStatus.INACTIVE
                            is_intermediate = True
                        else:
                            status = SignalStatus.INACTIVE
                            is_stale = True
                    elif status is SignalStatus.INACTIVE:
                        if "intermediate" in details_lower or "<= stale threshold" in details_lower:
                            is_intermediate = True
                        else:
                            is_stale = True
            elif sig.signal_type is SignalType.VM_POWER_STATE:
                if status is SignalStatus.INACTIVE:
                    if "<= threshold" in details_lower or "intermediate" in details_lower:
                        is_intermediate = True
                    else:
                        is_stale = True
            elif sig.signal_type is SignalType.PORT_STATE:
                if status is SignalStatus.INACTIVE:
                    if age_sec is not None:
                        if age_sec <= active_sec:
                            status = SignalStatus.ACTIVE
                        elif age_sec <= stale_sec:
                            is_intermediate = True
                        else:
                            is_stale = True
                    elif "intermediate" in details_lower or "<= threshold" in details_lower:
                        is_intermediate = True
                    else:
                        is_stale = True
            elif sig.signal_type is SignalType.AD_COMPUTER_ACCOUNT:
                if status is SignalStatus.INACTIVE:
                    if (
                        sig.metadata.get("enabled") is False
                        or "disabled" in details_lower
                        or "enabled=false" in details_lower
                        or sig.metadata.get("account_stale") is True
                    ):
                        is_stale = True
                    elif "intermediate" in details_lower or "<= stale threshold" in details_lower:
                        is_intermediate = True
                    else:
                        is_stale = True
            elif sig.signal_type is SignalType.DNS_DHCP_LEASE:
                if status is SignalStatus.INACTIVE:
                    if (
                        sig.metadata.get("dns_mismatch") is True
                        or "dns_mismatch=true" in details_lower
                    ):
                        is_intermediate = True
                    else:
                        is_stale = True

            normalized_sig = (
                sig
                if status is sig.status and age_sec == sig.age_seconds
                else ValidationSignal(
                    signal_type=sig.signal_type,
                    status=status,
                    observed_at=sig.observed_at,
                    age_seconds=age_sec,
                    details=sig.details,
                    source=sig.source,
                    metadata=sig.metadata,
                )
            )
            preliminary.append(
                _EvaluatedSignalView(
                    signal=normalized_sig,
                    effective_status=status,
                    is_intermediate=is_intermediate,
                    is_stale=is_stale,
                    discounted=False,
                )
            )

        # Discount shared physical host trunk PORT_STATE == ACTIVE when VM_POWER_STATE == INACTIVE
        has_vm_inactive = any(
            v.signal.signal_type is SignalType.VM_POWER_STATE
            and v.effective_status is SignalStatus.INACTIVE
            for v in preliminary
        )
        if not has_vm_inactive:
            return preliminary

        final_views: list[_EvaluatedSignalView] = []
        for view in preliminary:
            if (
                view.signal.signal_type is SignalType.PORT_STATE
                and view.effective_status is SignalStatus.ACTIVE
            ):
                final_views.append(
                    _EvaluatedSignalView(
                        signal=view.signal,
                        effective_status=view.effective_status,
                        is_intermediate=view.is_intermediate,
                        is_stale=view.is_stale,
                        discounted=True,
                    )
                )
            else:
                final_views.append(view)
        return final_views

    def classify_signals(
        self,
        signals: Sequence[ValidationSignal],
        *,
        item_type: str = "Equipment",
        item_id: str = "unknown",
        site_id: str = "unknown",
        name: Optional[str] = None,
        target: Optional[Any] = None,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> ValidationResult:
        """Classify a sequence of ValidationSignal objects into a ValidationResult."""
        eval_dt = self._resolve_eval_time(evaluation_time)
        resolved_name = name.strip() if isinstance(name, str) and name.strip() else item_id
        views = self._normalize_signals(signals, eval_dt)
        normalized_signals = [v.signal for v in views]

        # 1. Check Insufficient Data
        applicable_views = [
            v
            for v in views
            if v.effective_status is not SignalStatus.NOT_APPLICABLE
        ]
        has_directory_or_dns_match = any(
            v.signal.signal_type
            in (SignalType.AD_COMPUTER_ACCOUNT, SignalType.DNS_DHCP_LEASE)
            for v in applicable_views
        )
        if (
            not views
            or not applicable_views
            or (
                not _has_actionable_identifiers(target, site=site)
                and not has_directory_or_dns_match
            )
        ):
            rationale = (
                f"Insufficient Data for {item_type} {resolved_name} ({item_id}): "
                "no actionable identifiers or applicable validation signals available "
                "(all signals absent or NOT_APPLICABLE)."
            )
            return ValidationResult(
                item_type=item_type,
                item_id=item_id,
                site_id=site_id,
                name=resolved_name,
                classification=ValidationClassification.INSUFFICIENT_DATA,
                confidence=0.0,
                signals=normalized_signals,
                rationale=rationale,
                evaluated_at=eval_dt,
            )

        effective_views = [v for v in applicable_views if not v.discounted]
        by_type: dict[SignalType, list[_EvaluatedSignalView]] = {}
        for v in effective_views:
            by_type.setdefault(v.signal.signal_type, []).append(v)

        def _has_status(sig_type: SignalType, status: SignalStatus) -> bool:
            return any(
                v.effective_status is status for v in by_type.get(sig_type, ())
            )

        icmp_active = _has_status(SignalType.ICMP_REACHABILITY, SignalStatus.ACTIVE)
        snmp_active = _has_status(
            SignalType.SNMP_API_REACHABILITY, SignalStatus.ACTIVE
        )
        arp_active = _has_status(SignalType.ARP_RECENCY, SignalStatus.ACTIVE)
        vm_active = _has_status(SignalType.VM_POWER_STATE, SignalStatus.ACTIVE)
        ad_active = _has_status(SignalType.AD_COMPUTER_ACCOUNT, SignalStatus.ACTIVE)
        dns_dhcp_active = _has_status(
            SignalType.DNS_DHCP_LEASE, SignalStatus.ACTIVE
        )
        port_active = _has_status(SignalType.PORT_STATE, SignalStatus.ACTIVE)
        last_seen_active = _has_status(
            SignalType.LAST_SEEN_TIMESTAMP, SignalStatus.ACTIVE
        )

        icmp_unreachable = _has_status(
            SignalType.ICMP_REACHABILITY, SignalStatus.UNREACHABLE
        )
        snmp_unreachable = _has_status(
            SignalType.SNMP_API_REACHABILITY, SignalStatus.UNREACHABLE
        )
        vm_unreachable = _has_status(
            SignalType.VM_POWER_STATE, SignalStatus.UNREACHABLE
        )
        vm_inactive = _has_status(SignalType.VM_POWER_STATE, SignalStatus.INACTIVE)
        arp_inactive = _has_status(SignalType.ARP_RECENCY, SignalStatus.INACTIVE)
        ad_disabled = any(
            v.effective_status is SignalStatus.INACTIVE
            and (
                v.signal.metadata.get("enabled") is False
                or "disabled" in (v.signal.details or "").lower()
                or "enabled=false" in (v.signal.details or "").lower()
            )
            for v in by_type.get(SignalType.AD_COMPUTER_ACCOUNT, ())
        )

        any_error = any(
            v.effective_status is SignalStatus.ERROR for v in effective_views
        )
        any_non_active = any(
            v.effective_status
            in (
                SignalStatus.INACTIVE,
                SignalStatus.UNREACHABLE,
                SignalStatus.ERROR,
            )
            for v in effective_views
        )

        # 2. Check Confirmed Active
        has_high_confidence_active = False
        windows_firewall_override = False

        if snmp_active or icmp_active:
            has_high_confidence_active = True
        elif vm_active or arp_active or ad_active or (dns_dhcp_active and not ad_disabled and not vm_inactive):
            if icmp_unreachable and not self.policy.windows_vm_ignore_icmp_unreachable:
                has_high_confidence_active = False
            else:
                has_high_confidence_active = True
                if icmp_unreachable:
                    windows_firewall_override = True

        port_or_last_seen_confirmed = False
        if not has_high_confidence_active:
            if port_active and not any_error and not vm_unreachable and not vm_inactive:
                other_active = any(
                    v.effective_status is SignalStatus.ACTIVE
                    and v.signal.signal_type is not SignalType.PORT_STATE
                    for v in effective_views
                )
                probe_failed = (
                    icmp_unreachable
                    or snmp_unreachable
                    or _has_status(SignalType.ICMP_REACHABILITY, SignalStatus.ERROR)
                    or _has_status(
                        SignalType.SNMP_API_REACHABILITY, SignalStatus.ERROR
                    )
                )
                last_seen_inactive = _has_status(
                    SignalType.LAST_SEEN_TIMESTAMP, SignalStatus.INACTIVE
                )
                if not probe_failed and not arp_inactive and (
                    other_active or not last_seen_inactive
                ):
                    port_or_last_seen_confirmed = True
            elif last_seen_active and not any_non_active:
                port_or_last_seen_confirmed = True

        if has_high_confidence_active or port_or_last_seen_confirmed:
            confidence = self._score_confirmed_active(
                effective_views,
                windows_firewall_override=windows_firewall_override,
                target=target,
            )
            rationale = self._build_confirmed_active_rationale(
                item_type=item_type,
                item_id=item_id,
                name=resolved_name,
                views=effective_views,
                windows_firewall_override=windows_firewall_override,
                target=target,
            )
            return ValidationResult(
                item_type=item_type,
                item_id=item_id,
                site_id=site_id,
                name=resolved_name,
                classification=ValidationClassification.CONFIRMED_ACTIVE,
                confidence=confidence,
                signals=normalized_signals,
                rationale=rationale,
                evaluated_at=eval_dt,
            )

        # 3. Check Unreachable / Needs Manual Review vs Stale / Likely Unused
        has_intermediate = any(v.is_intermediate for v in effective_views)
        has_substantive_stale = any(
            v.signal.signal_type in _SUBSTANTIVE_STALE_SIGNAL_TYPES
            and v.effective_status is SignalStatus.INACTIVE
            and v.is_stale
            for v in effective_views
        )

        sot_claimed_on_conflict = False
        if isinstance(target, Equipment) and not vm_inactive:
            if _sot_power_state_is_active(target) or (
                target.category is EquipmentCategory.VM
                and not _has_status(
                    SignalType.VM_POWER_STATE, SignalStatus.INACTIVE
                )
                and (icmp_unreachable or snmp_unreachable)
            ):
                sot_claimed_on_conflict = True

        has_conflict = (
            port_active
            or last_seen_active
            or vm_active
            or arp_active
            or ad_active
            or dns_dhcp_active
            or sot_claimed_on_conflict
        )
        all_unreachable = all(
            v.effective_status is SignalStatus.UNREACHABLE for v in effective_views
        )

        if (
            has_conflict
            or any_error
            or vm_unreachable
            or has_intermediate
            or all_unreachable
            or not has_substantive_stale
        ):
            confidence = self._score_unreachable_needs_review(
                effective_views,
                has_conflict=has_conflict,
                any_error=any_error,
                vm_unreachable=vm_unreachable,
                has_intermediate=has_intermediate,
            )
            rationale = self._build_unreachable_rationale(
                item_type=item_type,
                item_id=item_id,
                name=resolved_name,
                views=effective_views,
                has_conflict=has_conflict,
                sot_claimed_on_conflict=sot_claimed_on_conflict,
                any_error=any_error,
                vm_unreachable=vm_unreachable,
                has_intermediate=has_intermediate,
            )
            return ValidationResult(
                item_type=item_type,
                item_id=item_id,
                site_id=site_id,
                name=resolved_name,
                classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                confidence=confidence,
                signals=normalized_signals,
                rationale=rationale,
                evaluated_at=eval_dt,
            )

        # 4. Stale / Likely Unused
        confidence = self._score_stale_likely_unused(views)
        rationale = self._build_stale_rationale(
            item_type=item_type,
            item_id=item_id,
            name=resolved_name,
            views=views,
        )
        return ValidationResult(
            item_type=item_type,
            item_id=item_id,
            site_id=site_id,
            name=resolved_name,
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=confidence,
            signals=normalized_signals,
            rationale=rationale,
            evaluated_at=eval_dt,
        )

    def _score_confirmed_active(
        self,
        views: Sequence[_EvaluatedSignalView],
        *,
        windows_firewall_override: bool,
        target: Optional[Any],
    ) -> float:
        active_views = [
            v for v in views if v.effective_status is SignalStatus.ACTIVE
        ]
        active_types = {v.signal.signal_type for v in active_views}

        base = 0.65
        if SignalType.VM_POWER_STATE in active_types:
            base = max(base, 0.86)
            if any(
                _has_healthy_tools_detail(v.signal.details)
                for v in active_views
                if v.signal.signal_type is SignalType.VM_POWER_STATE
            ):
                base += 0.04
        if SignalType.SNMP_API_REACHABILITY in active_types:
            base = max(base, 0.86)
        if SignalType.AD_COMPUTER_ACCOUNT in active_types:
            base = max(base, 0.85)
        if SignalType.ARP_RECENCY in active_types:
            if windows_firewall_override or _is_windows_context(target, views):
                base = max(base, 0.85)
            else:
                base = max(base, 0.82)
        if SignalType.DNS_DHCP_LEASE in active_types:
            base = max(base, 0.82)
        if SignalType.ICMP_REACHABILITY in active_types:
            base = max(base, 0.82)
        if SignalType.PORT_STATE in active_types:
            base = max(base, 0.72)
        if SignalType.LAST_SEEN_TIMESTAMP in active_types:
            base = max(base, 0.65)

        corroboration_bonus = 0.0
        if len(active_types) > 1:
            sorted_weights = sorted(
                (self.policy.weight_for(st) for st in active_types),
                reverse=True,
            )
            for extra_weight in sorted_weights[1:]:
                corroboration_bonus += min(0.06, extra_weight * 0.15)

        penalty = 0.0
        for v in views:
            if v.effective_status in (SignalStatus.INACTIVE, SignalStatus.ERROR):
                penalty += 0.04
            elif (
                v.effective_status is SignalStatus.ACTIVE
                and v.signal.metadata.get("dns_mismatch") is True
            ):
                penalty += 0.04
            elif v.effective_status is SignalStatus.UNREACHABLE:
                if (
                    windows_firewall_override
                    and v.signal.signal_type in _ACTIVE_PROBE_SIGNAL_TYPES
                ):
                    continue
                if (
                    v.signal.signal_type in _ACTIVE_PROBE_SIGNAL_TYPES
                    and SignalType.ARP_RECENCY in active_types
                    and SignalType.PORT_STATE in active_types
                ):
                    continue
                penalty += 0.03

        score = base + corroboration_bonus - penalty
        if windows_firewall_override and (
            SignalType.VM_POWER_STATE in active_types
            or SignalType.ARP_RECENCY in active_types
            or SignalType.AD_COMPUTER_ACCOUNT in active_types
            or (
                SignalType.DNS_DHCP_LEASE in active_types
                and not any(
                    v.signal.metadata.get("dns_mismatch") is True
                    for v in active_views
                )
            )
        ):
            score = max(0.85, score)

        return round(min(1.0, max(0.60, score)), 4)

    def _score_stale_likely_unused(
        self, views: Sequence[_EvaluatedSignalView]
    ) -> float:
        effective = [v for v in views if not v.discounted]
        stale_types = {
            v.signal.signal_type
            for v in effective
            if v.signal.signal_type in _SUBSTANTIVE_STALE_SIGNAL_TYPES
            and v.effective_status is SignalStatus.INACTIVE
            and v.is_stale
        }
        unreachable_probe_types = {
            v.signal.signal_type
            for v in effective
            if v.signal.signal_type in _ACTIVE_PROBE_SIGNAL_TYPES
            and v.effective_status is SignalStatus.UNREACHABLE
        }

        base = 0.72 if SignalType.VM_POWER_STATE in stale_types else 0.66
        bonus = 0.0
        sorted_stale_weights = sorted(
            (self.policy.weight_for(st) for st in stale_types),
            reverse=True,
        )
        for idx, weight in enumerate(sorted_stale_weights):
            if idx == 0:
                bonus += min(0.06, weight * 0.12)
            else:
                bonus += min(0.09, 0.05 + weight * 0.12)

        for probe_type in unreachable_probe_types:
            bonus += min(0.06, 0.03 + self.policy.weight_for(probe_type) * 0.08)

        score = base + bonus
        return round(min(1.0, max(0.60, score)), 4)

    def _score_unreachable_needs_review(
        self,
        views: Sequence[_EvaluatedSignalView],
        *,
        has_conflict: bool,
        any_error: bool,
        vm_unreachable: bool,
        has_intermediate: bool,
    ) -> float:
        if any_error:
            base = 0.30
        elif vm_unreachable:
            base = 0.40
        elif has_conflict:
            base = 0.55
        elif has_intermediate:
            base = 0.50
        else:
            base = 0.45

        non_na_count = sum(
            1
            for v in views
            if v.effective_status is not SignalStatus.NOT_APPLICABLE
        )
        adjustment = min(0.10, max(0, non_na_count - 1) * 0.03)
        score = base + adjustment
        return round(min(0.75, max(0.20, score)), 4)

    def _build_confirmed_active_rationale(
        self,
        *,
        item_type: str,
        item_id: str,
        name: str,
        views: Sequence[_EvaluatedSignalView],
        windows_firewall_override: bool,
        target: Optional[Any],
    ) -> str:
        active_summaries = [
            f"{v.signal.signal_type.value}=ACTIVE"
            for v in views
            if v.effective_status is SignalStatus.ACTIVE
        ]
        notes: list[str] = []
        if windows_firewall_override:
            if _is_windows_context(target, views):
                notes.append(
                    "Windows VM rule applied: active vCenter power state / Guest Tools heartbeat "
                    "or recent ARP overrides ICMP_REACHABILITY=UNREACHABLE (host firewall blocks ICMP)"
                )
            else:
                notes.append(
                    "active vCenter/ARP signal overrides ICMP_REACHABILITY=UNREACHABLE"
                )
        for v in views:
            if (
                v.signal.signal_type is SignalType.VM_POWER_STATE
                and v.effective_status is SignalStatus.ACTIVE
                and _has_healthy_tools_detail(v.signal.details)
            ):
                notes.append("VMware Guest Tools heartbeat healthy")
                break

        note_str = f" ({'; '.join(notes)})" if notes else ""
        return (
            f"Confirmed Active for {item_type} {name} ({item_id}): "
            f"corroborated by {', '.join(active_summaries)}"
            f" within {self.policy.active_within_days:g}d active window{note_str}."
        )

    def _build_unreachable_rationale(
        self,
        *,
        item_type: str,
        item_id: str,
        name: str,
        views: Sequence[_EvaluatedSignalView],
        has_conflict: bool,
        sot_claimed_on_conflict: bool,
        any_error: bool,
        vm_unreachable: bool,
        has_intermediate: bool,
    ) -> str:
        sig_summaries = [
            f"{v.signal.signal_type.value}={v.effective_status.value}"
            for v in views
        ]
        reasons: list[str] = []
        if has_conflict:
            if any(
                v.signal.signal_type is SignalType.PORT_STATE
                and v.effective_status is SignalStatus.ACTIVE
                for v in views
            ):
                reasons.append(
                    "conflicting signals: switch port is ACTIVE (link UP or PoE power draw) "
                    "while network probes/ARP are unreachable or stale"
                )
            elif sot_claimed_on_conflict:
                reasons.append(
                    "conflicting signals: record is marked active/VM in SoT while probes fail "
                    "and no recent ARP or vCenter power-off confirmation is available"
                )
            else:
                reasons.append(
                    "conflicting active and inactive/unreachable validation signals"
                )
        if vm_unreachable:
            reasons.append(
                "vCenter hypervisor inventory is UNREACHABLE for VM verification"
            )
        if any_error:
            reasons.append("signal evaluation or probe returned ERROR")
        if has_intermediate:
            reasons.append(
                f"activity timestamp is in intermediate aging window "
                f"(> {self.policy.active_within_days:g}d and <= {self.policy.stale_after_days:g}d)"
            )
        if not reasons:
            reasons.append(
                "active probes timed out (UNREACHABLE) without corroborating historical inactivity"
            )

        return (
            f"Unreachable / Needs Manual Review for {item_type} {name} ({item_id}): "
            f"{'; '.join(reasons)} [{', '.join(sig_summaries)}]."
        )

    def _build_stale_rationale(
        self,
        *,
        item_type: str,
        item_id: str,
        name: str,
        views: Sequence[_EvaluatedSignalView],
    ) -> str:
        effective = [v for v in views if not v.discounted]
        discounted = [v for v in views if v.discounted]
        sig_summaries = [
            f"{v.signal.signal_type.value}={v.effective_status.value}"
            for v in effective
        ]
        discount_note = (
            " (shared hypervisor trunk PORT_STATE=ACTIVE discounted for powered-off VM)"
            if discounted
            else ""
        )
        return (
            f"Stale / Likely Unused for {item_type} {name} ({item_id}): "
            f"all applicable signals indicate inactivity beyond {self.policy.stale_after_days:g}d "
            f"stale threshold [{', '.join(sig_summaries)}]{discount_note}."
        )

    def classify_device(
        self,
        device: NetworkDevice,
        signals: Optional[Sequence[ValidationSignal]] = None,
        *,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """Classify a NetworkDevice (e.g. Extreme Networks switch)."""
        resolved_signals = (
            list(signals)
            if signals is not None
            else self.collect_signals(
                device,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        )
        site_id = device.site_id or (site.site_id if site is not None else "unknown")
        return self.classify_signals(
            resolved_signals,
            item_type="NetworkDevice",
            item_id=device.device_id,
            site_id=site_id,
            name=device.hostname,
            target=device,
            site=site,
            evaluation_time=evaluation_time,
        )

    def classify_ip(
        self,
        ip_address: IPAddress,
        signals: Optional[Sequence[ValidationSignal]] = None,
        *,
        site: Optional[Site] = None,
        site_id: Optional[str] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """Classify an IPAddress record."""
        resolved_signals = (
            list(signals)
            if signals is not None
            else self.collect_signals(
                ip_address,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        )
        resolved_site_id = (
            site_id
            or (site.site_id if site is not None else None)
            or ip_address.subnet_id
            or "unknown"
        )
        return self.classify_signals(
            resolved_signals,
            item_type="IPAddress",
            item_id=ip_address.ip,
            site_id=resolved_site_id,
            name=ip_address.ip,
            target=ip_address,
            site=site,
            evaluation_time=evaluation_time,
        )

    def classify_equipment(
        self,
        equipment: Equipment,
        signals: Optional[Sequence[ValidationSignal]] = None,
        *,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """Classify an Equipment record (Server, SAN, APC UPS, VM, etc.)."""
        resolved_signals = (
            list(signals)
            if signals is not None
            else self.collect_signals(
                equipment,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        )
        site_id = equipment.site_id or (site.site_id if site is not None else "unknown")
        return self.classify_signals(
            resolved_signals,
            item_type="Equipment",
            item_id=equipment.equipment_id,
            site_id=site_id,
            name=equipment.name,
            target=equipment,
            site=site,
            evaluation_time=evaluation_time,
        )

    def classify(
        self,
        target: Any,
        signals: Optional[Sequence[ValidationSignal]] = None,
        *,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """Classify a domain record (NetworkDevice, IPAddress, Equipment) or signal sequence."""
        if isinstance(target, NetworkDevice):
            return self.classify_device(
                target,
                signals=signals,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        if isinstance(target, IPAddress):
            return self.classify_ip(
                target,
                signals=signals,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        if isinstance(target, Equipment):
            return self.classify_equipment(
                target,
                signals=signals,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        if (
            isinstance(target, Sequence)
            and not isinstance(target, (str, bytes))
            and all(isinstance(s, ValidationSignal) for s in target)
        ):
            return self.classify_signals(
                target,
                site=site,
                evaluation_time=evaluation_time,
                **kwargs,
            )
        if signals is not None:
            item_type = kwargs.pop("item_type", type(target).__name__)
            item_id = kwargs.pop("item_id", str(getattr(target, "id", "unknown")))
            site_id = kwargs.pop(
                "site_id",
                getattr(target, "site_id", site.site_id if site is not None else "unknown"),
            )
            name = kwargs.pop("name", getattr(target, "name", item_id))
            return self.classify_signals(
                signals,
                item_type=item_type,
                item_id=item_id,
                site_id=site_id,
                name=name,
                target=target,
                site=site,
                evaluation_time=evaluation_time,
            )
        raise ValueError(
            f"Unsupported target type for classification: {type(target).__name__}"
        )

    def classify_site(
        self,
        site: Site,
        *,
        evaluation_time: Optional[datetime | str] = None,
        include_ip_addresses: bool = True,
        **kwargs: Any,
    ) -> list[ValidationResult]:
        """Classify all devices, equipment, and (optionally) IP addresses in a Site batch."""
        results: list[ValidationResult] = []
        for device in site.devices:
            results.append(
                self.classify_device(
                    device,
                    site=site,
                    evaluation_time=evaluation_time,
                    **kwargs,
                )
            )
        for equipment in site.equipment:
            results.append(
                self.classify_equipment(
                    equipment,
                    site=site,
                    evaluation_time=evaluation_time,
                    **kwargs,
                )
            )
        if include_ip_addresses:
            for ip_rec in site.ip_addresses:
                results.append(
                    self.classify_ip(
                        ip_rec,
                        site=site,
                        site_id=site.site_id,
                        evaluation_time=evaluation_time,
                        **kwargs,
                    )
                )
        return results

    score = classify
    score_signals = classify_signals


ScoringConfig = ClassificationPolicy
ValidationScorer = ClassificationEngine

__all__ = [
    "ClassificationEngine",
    "ClassificationPolicy",
    "DEFAULT_SIGNAL_WEIGHTS",
    "ScoringConfig",
    "ValidationScorer",
]
