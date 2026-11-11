"""Multi-site campaign orchestration, outage circuit breakers, and alert sinks."""

from __future__ import annotations

from sot_validator.campaign.alerts import (
    AlertEvent,
    AlertSeverity,
    AlertSink,
    AlertType,
    InMemoryAlertSink,
    JsonFileAlertSink,
    WebhookPayloadFormatter,
)
from sot_validator.campaign.orchestrator import (
    CampaignConfig,
    CampaignOrchestrator,
    CampaignRunSummary,
    CircuitBreakerTrippedError,
    SiteWaveResult,
    SiteWaveStatus,
)

__all__ = [
    "AlertEvent",
    "AlertSeverity",
    "AlertSink",
    "AlertType",
    "CampaignConfig",
    "CampaignOrchestrator",
    "CampaignRunSummary",
    "CircuitBreakerTrippedError",
    "InMemoryAlertSink",
    "JsonFileAlertSink",
    "SiteWaveResult",
    "SiteWaveStatus",
    "WebhookPayloadFormatter",
]
