"""Alert types, structured events, sinks, and offline webhook formatters for multi-site campaigns."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.models import _require_non_empty_str
from sot_validator.signals.base import normalize_utc_datetime


class AlertType(str, Enum):
    """Supported alert event categories emitted during multi-site validation campaigns."""

    CRITICAL_INFRA_UNREACHABLE = "CRITICAL_INFRA_UNREACHABLE"
    SITE_OUTAGE_SUSPECTED = "SITE_OUTAGE_SUSPECTED"
    HIGH_STALE_RATIO_DETECTED = "HIGH_STALE_RATIO_DETECTED"
    CAMPAIGN_CIRCUIT_BREAKER_TRIPPED = "CAMPAIGN_CIRCUIT_BREAKER_TRIPPED"


class AlertSeverity(str, Enum):
    """Severity levels for campaign alert events."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


_DEFAULT_SEVERITY_BY_TYPE: dict[AlertType, AlertSeverity] = {
    AlertType.CRITICAL_INFRA_UNREACHABLE: AlertSeverity.CRITICAL,
    AlertType.SITE_OUTAGE_SUSPECTED: AlertSeverity.CRITICAL,
    AlertType.HIGH_STALE_RATIO_DETECTED: AlertSeverity.WARNING,
    AlertType.CAMPAIGN_CIRCUIT_BREAKER_TRIPPED: AlertSeverity.CRITICAL,
}


@dataclass
class AlertEvent:
    """Structured alert emitted for critical infrastructure, site outage, or campaign anomalies."""

    alert_type: AlertType
    severity: Optional[AlertSeverity] = None  # type: ignore[assignment]
    message: str = ""
    site_id: Optional[str] = None
    wave_index: Optional[int] = None
    item_type: Optional[str] = None
    item_id: Optional[str] = None
    item_name: Optional[str] = None
    category: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.alert_type, AlertType):
            try:
                self.alert_type = AlertType(self.alert_type)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid alert_type: {self.alert_type!r}"
                ) from exc

        if self.severity is None:
            self.severity = _DEFAULT_SEVERITY_BY_TYPE.get(
                self.alert_type, AlertSeverity.CRITICAL
            )
        elif not isinstance(self.severity, AlertSeverity):
            try:
                self.severity = AlertSeverity(self.severity)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid severity: {self.severity!r}"
                ) from exc

        _require_non_empty_str(self.message, "message")

        if self.wave_index is not None:
            if isinstance(self.wave_index, bool) or not isinstance(
                self.wave_index, int
            ):
                raise ValueError("wave_index must be a non-negative integer")
            if self.wave_index < 0:
                raise ValueError("wave_index must be non-negative")

        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        else:
            self.created_at = normalize_utc_datetime(
                self.created_at, field_name="created_at"
            )

        if self.details is None:
            self.details = {}
        elif isinstance(self.details, Mapping):
            self.details = dict(self.details)
        else:
            raise ValueError("details must be a mapping")

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "message": self.message,
            "site_id": self.site_id,
            "wave_index": self.wave_index,
            "item_type": self.item_type,
            "item_id": self.item_id,
            "item_name": self.item_name,
            "category": self.category,
            "created_at": self.created_at.isoformat(),
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AlertEvent:
        return cls(
            alert_type=AlertType(data["alert_type"]),
            severity=(
                AlertSeverity(data["severity"])
                if data.get("severity") is not None
                else None
            ),
            message=data["message"],
            site_id=data.get("site_id"),
            wave_index=data.get("wave_index"),
            item_type=data.get("item_type"),
            item_id=data.get("item_id"),
            item_name=data.get("item_name"),
            category=data.get("category"),
            created_at=data.get("created_at") or datetime.now(timezone.utc),
            details=dict(data.get("details") or {}),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> AlertEvent:
        return cls.from_dict(json.loads(raw))


class AlertSink(ABC):
    """Abstract base interface for dispatching campaign AlertEvent records."""

    @abstractmethod
    def emit(self, event: AlertEvent) -> None:
        """Emit a single AlertEvent."""
        raise NotImplementedError

    def emit_many(self, events: Sequence[AlertEvent]) -> None:
        """Emit a sequence of AlertEvent instances in order."""
        for event in events:
            self.emit(event)


class InMemoryAlertSink(AlertSink):
    """In-memory AlertSink storing emitted AlertEvent records for inspection and testing."""

    def __init__(self) -> None:
        self.events: list[AlertEvent] = []

    def emit(self, event: AlertEvent) -> None:
        if not isinstance(event, AlertEvent):
            raise ValueError("event must be an AlertEvent instance")
        self.events.append(event)

    def clear(self) -> None:
        """Clear all stored alert events."""
        self.events.clear()

    def filter_by_type(self, alert_type: AlertType | str) -> list[AlertEvent]:
        """Return all stored events matching the given AlertType."""
        resolved = (
            alert_type
            if isinstance(alert_type, AlertType)
            else AlertType(str(alert_type))
        )
        return [ev for ev in self.events if ev.alert_type is resolved]


class JsonFileAlertSink(AlertSink):
    """Local disk AlertSink writing emitted AlertEvent records as JSON or JSON Lines."""

    def __init__(
        self,
        file_path: Path | str,
        *,
        jsonl: bool = False,
        indent: Optional[int] = 2,
    ) -> None:
        if isinstance(file_path, Path):
            self.file_path = file_path
        elif isinstance(file_path, str) and file_path.strip():
            self.file_path = Path(file_path)
        else:
            raise ValueError("file_path must be a non-empty path or string")
        if not isinstance(jsonl, bool):
            raise ValueError("jsonl must be a boolean")
        self.jsonl = jsonl
        self.indent = indent

    def emit(self, event: AlertEvent) -> None:
        if not isinstance(event, AlertEvent):
            raise ValueError("event must be an AlertEvent instance")
        self.emit_many([event])

    def emit_many(self, events: Sequence[AlertEvent]) -> None:
        if not events:
            return
        for ev in events:
            if not isinstance(ev, AlertEvent):
                raise ValueError("All events must be AlertEvent instances")

        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        if self.jsonl:
            with self.file_path.open("a", encoding="utf-8") as fh:
                for ev in events:
                    fh.write(ev.to_json(indent=None) + "\n")
            return

        existing = self.read_events() if self.file_path.exists() else []
        combined = existing + list(events)
        payload = [ev.to_dict() for ev in combined]
        self.file_path.write_text(
            json.dumps(payload, indent=self.indent),
            encoding="utf-8",
        )

    def read_events(self) -> list[AlertEvent]:
        """Read and deserialize all AlertEvent records persisted in file_path."""
        if not self.file_path.exists():
            return []
        raw = self.file_path.read_text(encoding="utf-8").strip()
        if not raw:
            return []

        if self.jsonl:
            return [
                AlertEvent.from_json(line)
                for line in raw.splitlines()
                if line.strip()
            ]

        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [AlertEvent.from_dict(item) for item in parsed]
        if isinstance(parsed, Mapping):
            if "events" in parsed and isinstance(parsed["events"], list):
                return [AlertEvent.from_dict(item) for item in parsed["events"]]
            return [AlertEvent.from_dict(parsed)]
        raise ValueError(f"Unexpected JSON structure in {self.file_path}")


class WebhookPayloadFormatter:
    """Offline webhook payload builder for generic JSON, Slack, and Microsoft Teams."""

    _SEVERITY_COLORS: dict[AlertSeverity, str] = {
        AlertSeverity.CRITICAL: "D92D20",
        AlertSeverity.WARNING: "F79009",
        AlertSeverity.INFO: "1570EF",
    }

    @staticmethod
    def _coerce_events(
        event_or_events: AlertEvent | Sequence[AlertEvent],
    ) -> list[AlertEvent]:
        if isinstance(event_or_events, AlertEvent):
            return [event_or_events]
        if isinstance(event_or_events, Sequence) and not isinstance(
            event_or_events, (str, bytes)
        ):
            events = list(event_or_events)
            for ev in events:
                if not isinstance(ev, AlertEvent):
                    raise ValueError("All elements must be AlertEvent instances")
            if not events:
                raise ValueError("At least one AlertEvent is required")
            return events
        raise ValueError(
            "Expected an AlertEvent or a non-empty sequence of AlertEvent instances"
        )

    @classmethod
    def _highest_severity(cls, events: Sequence[AlertEvent]) -> AlertSeverity:
        order = {
            AlertSeverity.INFO: 0,
            AlertSeverity.WARNING: 1,
            AlertSeverity.CRITICAL: 2,
        }
        return max(
            (ev.severity for ev in events),
            key=lambda sev: order.get(sev, 0),
            default=AlertSeverity.INFO,
        )

    @classmethod
    def format_generic(
        cls, event: AlertEvent | Sequence[AlertEvent]
    ) -> dict[str, Any]:
        """Build a canonical generic webhook payload dictionary."""
        events = cls._coerce_events(event)
        highest = cls._highest_severity(events)
        primary = events[0]
        return {
            "target": "generic",
            "alert_count": len(events),
            "severity": highest.value,
            "summary": primary.message
            if len(events) == 1
            else f"{len(events)} campaign alert(s) emitted (highest severity: {highest.value})",
            "alert": primary.to_dict() if len(events) == 1 else None,
            "alerts": [ev.to_dict() for ev in events],
        }

    @classmethod
    def format_slack(
        cls, event: AlertEvent | Sequence[AlertEvent]
    ) -> dict[str, Any]:
        """Build an offline Slack webhook payload with text, blocks, and attachments."""
        events = cls._coerce_events(event)
        highest = cls._highest_severity(events)
        primary = events[0]
        summary_text = (
            f"[{primary.severity.value}] {primary.alert_type.value}: {primary.message}"
            if len(events) == 1
            else f"[{highest.value}] {len(events)} SoT Campaign Alert(s): {primary.message}"
        )

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"SoT Campaign Alert ({highest.value})",
                },
            }
        ]
        attachments: list[dict[str, Any]] = []

        for ev in events:
            fields: list[dict[str, str]] = [
                {"type": "mrkdwn", "text": f"*Type:* `{ev.alert_type.value}`"},
                {"type": "mrkdwn", "text": f"*Severity:* `{ev.severity.value}`"},
            ]
            if ev.site_id:
                fields.append({"type": "mrkdwn", "text": f"*Site:* `{ev.site_id}`"})
            if ev.wave_index is not None:
                fields.append(
                    {"type": "mrkdwn", "text": f"*Wave:* `{ev.wave_index}`"}
                )
            if ev.category:
                fields.append(
                    {"type": "mrkdwn", "text": f"*Category:* `{ev.category}`"}
                )
            if ev.item_id or ev.item_name:
                item_label = f"{ev.item_name or ev.item_id} ({ev.item_id or 'n/a'})"
                fields.append(
                    {"type": "mrkdwn", "text": f"*Item:* `{item_label}`"}
                )

            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": ev.message},
                    "fields": fields,
                }
            )
            attachments.append(
                {
                    "color": f"#{cls._SEVERITY_COLORS.get(ev.severity, 'D92D20')}",
                    "title": f"{ev.alert_type.value} ({ev.severity.value})",
                    "text": ev.message,
                    "fields": [
                        {
                            "title": "alert_type",
                            "value": ev.alert_type.value,
                            "short": True,
                        },
                        {
                            "title": "severity",
                            "value": ev.severity.value,
                            "short": True,
                        },
                        {
                            "title": "site_id",
                            "value": ev.site_id or "n/a",
                            "short": True,
                        },
                        {
                            "title": "item_id",
                            "value": ev.item_id or "n/a",
                            "short": True,
                        },
                        {
                            "title": "category",
                            "value": ev.category or "n/a",
                            "short": True,
                        },
                    ],
                }
            )

        return {
            "text": summary_text,
            "blocks": blocks,
            "attachments": attachments,
        }

    @classmethod
    def format_teams(
        cls, event: AlertEvent | Sequence[AlertEvent]
    ) -> dict[str, Any]:
        """Build an offline Microsoft Teams MessageCard webhook payload."""
        events = cls._coerce_events(event)
        highest = cls._highest_severity(events)
        primary = events[0]
        summary_text = (
            f"[{primary.severity.value}] {primary.alert_type.value}: {primary.message}"
            if len(events) == 1
            else f"[{highest.value}] {len(events)} SoT Campaign Alert(s)"
        )

        sections: list[dict[str, Any]] = []
        for ev in events:
            facts: list[dict[str, str]] = [
                {"name": "Alert Type", "value": ev.alert_type.value},
                {"name": "Severity", "value": ev.severity.value},
            ]
            if ev.site_id is not None:
                facts.append({"name": "Site ID", "value": ev.site_id})
            if ev.wave_index is not None:
                facts.append({"name": "Wave Index", "value": str(ev.wave_index)})
            if ev.item_type is not None:
                facts.append({"name": "Item Type", "value": ev.item_type})
            if ev.item_id is not None:
                facts.append({"name": "Item ID", "value": ev.item_id})
            if ev.item_name is not None:
                facts.append({"name": "Item Name", "value": ev.item_name})
            if ev.category is not None:
                facts.append({"name": "Category", "value": ev.category})
            facts.append({"name": "Timestamp", "value": ev.created_at.isoformat()})

            sections.append(
                {
                    "activityTitle": f"{ev.alert_type.value} ({ev.severity.value})",
                    "text": ev.message,
                    "facts": facts,
                }
            )

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": summary_text,
            "themeColor": cls._SEVERITY_COLORS.get(highest, "D92D20"),
            "title": f"SoT Campaign Alert: {primary.alert_type.value}"
            if len(events) == 1
            else f"SoT Campaign Alerts ({len(events)} events)",
            "sections": sections,
        }

    @classmethod
    def format_payload(
        cls,
        event: AlertEvent | Sequence[AlertEvent],
        target: str = "generic",
    ) -> dict[str, Any]:
        """Format one or more AlertEvents for the specified webhook target ('generic', 'slack', 'teams')."""
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")
        normalized = target.strip().lower()
        if normalized == "generic":
            return cls.format_generic(event)
        if normalized == "slack":
            return cls.format_slack(event)
        if normalized == "teams":
            return cls.format_teams(event)
        raise ValueError(
            f"Unsupported webhook target {target!r}; expected one of: generic, slack, teams"
        )


__all__ = [
    "AlertEvent",
    "AlertSeverity",
    "AlertSink",
    "AlertType",
    "InMemoryAlertSink",
    "JsonFileAlertSink",
    "WebhookPayloadFormatter",
]
