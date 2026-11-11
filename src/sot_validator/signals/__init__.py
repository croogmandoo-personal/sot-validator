"""Passive and active validation signal collectors and evaluators."""

from __future__ import annotations

from sot_validator.signals.arp import ArpSignalEvaluator
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    SignalCollector,
    evaluate_timestamp_recency,
    normalize_utc_datetime,
    resolve_evaluation_time,
    validate_recency_thresholds,
)
from sot_validator.signals.hypervisor import (
    GuestToolsStatus,
    HypervisorInventoryProvider,
    HypervisorVmRecord,
    MultiVCenterInventoryProvider,
    VmNicBinding,
    VmPowerState,
    VmPowerStateCollector,
    normalize_guest_tools_status,
    normalize_vm_power_state,
)
from sot_validator.signals.icmp import (
    IcmpProbeCallable,
    IcmpProbeCollector,
    IcmpProbeResponse,
    ScopeViolationError,
    SubnetScopeGuard,
)
from sot_validator.signals.last_seen import LastSeenSignalEvaluator
from sot_validator.signals.management import (
    FixtureManagementTransport,
    HttpsProbeResponse,
    ManagementProbeCollector,
    ReadOnlyViolationError,
    parse_apc_ups_oids,
    parse_extreme_switch_oids,
    validate_readonly_http_method,
    validate_readonly_snmp_request,
)
from sot_validator.signals.port_state import (
    PortStateSignalEvaluator,
    evaluate_single_port,
)

__all__ = [
    "ArpSignalEvaluator",
    "FixtureManagementTransport",
    "GuestToolsStatus",
    "HttpsProbeResponse",
    "HypervisorInventoryProvider",
    "HypervisorVmRecord",
    "IcmpProbeCallable",
    "IcmpProbeCollector",
    "IcmpProbeResponse",
    "LastSeenSignalEvaluator",
    "ManagementProbeCollector",
    "MultiVCenterInventoryProvider",
    "PortStateSignalEvaluator",
    "ReadOnlyViolationError",
    "SECONDS_PER_DAY",
    "ScopeViolationError",
    "SignalCollector",
    "SubnetScopeGuard",
    "VmNicBinding",
    "VmPowerState",
    "VmPowerStateCollector",
    "evaluate_single_port",
    "evaluate_timestamp_recency",
    "normalize_guest_tools_status",
    "normalize_utc_datetime",
    "normalize_vm_power_state",
    "parse_apc_ups_oids",
    "parse_extreme_switch_oids",
    "resolve_evaluation_time",
    "validate_readonly_http_method",
    "validate_readonly_snmp_request",
    "validate_recency_thresholds",
]
