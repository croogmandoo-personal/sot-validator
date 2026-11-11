"""Phase 4 read-only live pilot connectors and pre-flight cutover validator."""

from __future__ import annotations

from sot_validator.connectors.live import (
    APC_UPS_MIB_OIDS,
    EXTREME_SWITCH_MIB_OIDS,
    LLDP_MIB_OIDS,
    LLDP_REM_PORT_DESC_PREFIX,
    LLDP_REM_PORT_ID_PREFIX,
    LLDP_REM_SYS_NAME_PREFIX,
    PETH_PSE_PORT_ADMIN_ENABLE_PREFIX,
    PETH_PSE_PORT_DETECTION_STATUS_PREFIX,
    POWER_ETHERNET_MIB_OIDS,
    AuthenticatedScraperSession,
    ConnectorReadOnlyError,
    RequestTelemetry,
    SnmpWalkConnector,
    VSphereRestConnector,
)
from sot_validator.connectors.preflight import (
    PilotCutoverValidator,
    PreFlightCheckResult,
    PreFlightReport,
)

__all__ = [
    "APC_UPS_MIB_OIDS",
    "AuthenticatedScraperSession",
    "ConnectorReadOnlyError",
    "EXTREME_SWITCH_MIB_OIDS",
    "LLDP_MIB_OIDS",
    "LLDP_REM_PORT_DESC_PREFIX",
    "LLDP_REM_PORT_ID_PREFIX",
    "LLDP_REM_SYS_NAME_PREFIX",
    "PETH_PSE_PORT_ADMIN_ENABLE_PREFIX",
    "PETH_PSE_PORT_DETECTION_STATUS_PREFIX",
    "POWER_ETHERNET_MIB_OIDS",
    "PilotCutoverValidator",
    "PreFlightCheckResult",
    "PreFlightReport",
    "RequestTelemetry",
    "SnmpWalkConnector",
    "VSphereRestConnector",
]
