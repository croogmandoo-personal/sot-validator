"""Active and passive validation signal collectors for sot-validator."""

from __future__ import annotations

from sot_validator.signals.icmp import (
    IcmpProbeCallable,
    IcmpProbeCollector,
    IcmpProbeResponse,
    ScopeViolationError,
    SubnetScopeGuard,
)
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

__all__ = [
    "FixtureManagementTransport",
    "HttpsProbeResponse",
    "IcmpProbeCallable",
    "IcmpProbeCollector",
    "IcmpProbeResponse",
    "ManagementProbeCollector",
    "ReadOnlyViolationError",
    "ScopeViolationError",
    "SubnetScopeGuard",
    "parse_apc_ups_oids",
    "parse_extreme_switch_oids",
    "validate_readonly_http_method",
    "validate_readonly_snmp_request",
]
