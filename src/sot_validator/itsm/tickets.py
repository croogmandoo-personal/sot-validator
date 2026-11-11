"""Phase 6 ITSM Change-Ticket & Approval Governance Sink (ServiceNow, Jira, and Webhook)."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Optional, Protocol, runtime_checkable
import uuid

from sot_validator.models import (
    _format_optional_datetime,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.reconciliation.reconciler import (
    ALL_DISCREPANCY_TYPES,
    DiscrepancyRecord,
    DiscrepancyType,
    ReconciliationReport,
)
from sot_validator.remediation.executor import (
    RemediationExecutionError,
    SqlRemediationScriptGenerator,
    SqlRemediationScripts,
)
from sot_validator.remediation.port_reclamation import (
    BlockedPortRecord,
    ExtremeCliDialect,
    PortReclamationCandidate,
    PortReclamationPlan,
)
from sot_validator.remediation.quarantine import (
    ApprovalStatus,
    QuarantineGraduationStatus,
    QuarantineManifestEntry,
    RemediationApprovalManifest,
    RemediationOperation,
)
from sot_validator.signals.base import normalize_utc_datetime, resolve_evaluation_time
from sot_validator.signals.ups_health import (
    UpsAdvisoryCode,
    UpsFleetHealthReport,
    UpsHealthRecord,
    UpsHealthStatus,
)

# Compatibility alias for callers referencing QuarantineReport.
QuarantineReport = RemediationApprovalManifest


class ItsmWorkflowType(str, Enum):
    """Supported Phase 6 ITSM operational change, onboarding, and incident workflows."""

    QUARANTINE_DECOMMISSION = "QUARANTINE_DECOMMISSION"
    PORT_RECLAMATION = "PORT_RECLAMATION"
    SHADOW_IT_ONBOARDING = "SHADOW_IT_ONBOARDING"
    UPS_HARDWARE_INCIDENT = "UPS_HARDWARE_INCIDENT"

    @classmethod
    def _missing_(cls, value: object) -> Optional[ItsmWorkflowType]:
        if isinstance(value, str):
            norm = value.strip().lower().replace("-", "_").replace(" ", "_")
            if norm in (
                "quarantine_decommission",
                "quarantine",
                "stale_quarantine",
                "decommission",
                "sot_quarantine",
                "remediation",
            ):
                return cls.QUARANTINE_DECOMMISSION
            if norm in (
                "port_reclamation",
                "port_shutdown",
                "port_shutdowns",
                "extreme_port_reclamation",
                "reclaim_ports",
                "switch_port_reclamation",
                "poe_reclamation",
            ):
                return cls.PORT_RECLAMATION
            if norm in (
                "shadow_it_onboarding",
                "onboarding",
                "reconciliation",
                "shadow_it",
                "asset_onboarding",
                "untracked_inventory",
            ):
                return cls.SHADOW_IT_ONBOARDING
            if norm in (
                "ups_hardware_incident",
                "ups_incident",
                "ups_health",
                "apc_ups_alert",
                "ups_alert",
                "battery_replacement",
                "ups",
            ):
                return cls.UPS_HARDWARE_INCIDENT
        return None


class ItsmProvider(str, Enum):
    """Supported ITSM payload and webhook target providers."""

    SERVICENOW = "servicenow"
    JIRA = "jira"
    WEBHOOK = "webhook"

    @classmethod
    def _missing_(cls, value: object) -> Optional[ItsmProvider]:
        if isinstance(value, str):
            norm = value.strip().lower().replace("-", "_")
            if norm in ("servicenow", "service_now", "snow"):
                return cls.SERVICENOW
            if norm in ("jira", "jira_cloud", "jira_server", "atlassian"):
                return cls.JIRA
            if norm in ("webhook", "generic", "json", "generic_webhook"):
                return cls.WEBHOOK
        return None


class TicketApprovalStatus(str, Enum):
    """Standardized ITSM change-ticket and task approval states."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    SCHEDULED = "SCHEDULED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    IMPLEMENTED = "IMPLEMENTED"

    @classmethod
    def _missing_(cls, value: object) -> Optional[TicketApprovalStatus]:
        if isinstance(value, str):
            norm = value.strip().upper().replace("-", "_").replace(" ", "_")
            if norm in ("PENDING", "REQUESTED", "NOT_YET_REQUESTED", "NEW", "OPEN", "REVIEW"):
                return cls.PENDING
            if norm in ("APPROVED", "AUTHORIZED", "CAB_APPROVED"):
                return cls.APPROVED
            if norm in ("SCHEDULED", "PLANNED", "READY"):
                return cls.SCHEDULED
            if norm in ("REJECTED", "DENIED", "DECLINED"):
                return cls.REJECTED
            if norm in ("CANCELLED", "CANCELED", "WITHDRAWN"):
                return cls.CANCELLED
            if norm in ("IMPLEMENTED", "CLOSED", "COMPLETED", "DONE", "RESOLVED"):
                return cls.IMPLEMENTED
        return None


# Alias for callers importing ItsmApprovalStatus.
ItsmApprovalStatus = TicketApprovalStatus


class TicketRisk(str, Enum):
    """Standardized ServiceNow / ITSM change risk levels."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def _missing_(cls, value: object) -> Optional[TicketRisk]:
        if isinstance(value, str):
            norm = value.strip().lower()
            if norm in ("low", "minor", "4"):
                return cls.LOW
            if norm in ("moderate", "medium", "normal", "3"):
                return cls.MODERATE
            if norm in ("high", "major", "2"):
                return cls.HIGH
            if norm in ("critical", "very_high", "very high", "1"):
                return cls.CRITICAL
        return None


class TicketPriority(str, Enum):
    """Standardized Jira / ITSM priority levels."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @classmethod
    def _missing_(cls, value: object) -> Optional[TicketPriority]:
        if isinstance(value, str):
            norm = value.strip().lower()
            if norm in ("low", "minor", "4", "p4"):
                return cls.LOW
            if norm in ("medium", "moderate", "normal", "3", "p3"):
                return cls.MEDIUM
            if norm in ("high", "major", "2", "p2"):
                return cls.HIGH
            if norm in ("critical", "highest", "blocker", "1", "p1"):
                return cls.CRITICAL
        return None


def _coerce_workflow_type(
    value: ItsmWorkflowType | str,
    field_name: str = "workflow_type",
) -> ItsmWorkflowType:
    if isinstance(value, ItsmWorkflowType):
        return value
    if isinstance(value, str):
        try:
            return ItsmWorkflowType(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_provider(
    value: ItsmProvider | str,
    field_name: str = "provider",
) -> ItsmProvider:
    if isinstance(value, ItsmProvider):
        return value
    if isinstance(value, str):
        try:
            return ItsmProvider(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_ticket_approval_status(
    value: TicketApprovalStatus | str,
    field_name: str = "approval_status",
) -> TicketApprovalStatus:
    if isinstance(value, TicketApprovalStatus):
        return value
    if isinstance(value, str):
        try:
            return TicketApprovalStatus(value)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    raise ValueError(f"Invalid {field_name}: {value!r}")


def _coerce_risk(value: TicketRisk | str) -> str:
    if isinstance(value, TicketRisk):
        return value.value
    if isinstance(value, str):
        try:
            return TicketRisk(value).value
        except ValueError:
            cleaned = value.strip().lower()
            if cleaned:
                return cleaned
    raise ValueError(f"Invalid risk: {value!r}")


def _coerce_priority(value: TicketPriority | str) -> str:
    if isinstance(value, TicketPriority):
        return value.value
    if isinstance(value, str):
        try:
            return TicketPriority(value).value
        except ValueError:
            cleaned = value.strip()
            if cleaned:
                return cleaned
    raise ValueError(f"Invalid priority: {value!r}")


def _normalize_str_list(values: Optional[Iterable[Any]]) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        cleaned = values.strip()
        return [cleaned] if cleaned else []
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        if item is None:
            continue
        text = str(item.value if isinstance(item, Enum) else item).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def compute_artifact_sha256(
    artifact: (
        RemediationApprovalManifest
        | PortReclamationPlan
        | ReconciliationReport
        | UpsFleetHealthReport
        | UpsHealthRecord
        | Mapping[str, Any]
        | str
    ),
) -> str:
    """Compute or extract a deterministic SHA-256 hex digest for a remediation plan or report."""
    if isinstance(artifact, RemediationApprovalManifest):
        if artifact.manifest_sha256 and len(artifact.manifest_sha256.strip()) == 64:
            return artifact.manifest_sha256.strip().lower()
        return artifact.compute_digest()

    if isinstance(artifact, PortReclamationPlan):
        canonical_candidates = sorted(
            (
                {
                    "port_id": c.port_id,
                    "device_id": c.device_id,
                    "port_name": c.port_name,
                    "site_id": c.site_id,
                    "device_hostname": c.device_hostname,
                    "inactive_runs": c.inactive_runs,
                    "inactive_days": round(float(c.inactive_days), 4),
                    "estimated_poe_watts_saved": round(
                        float(c.estimated_poe_watts_saved), 2
                    ),
                    "exos_disable_commands": list(c.exos_disable_commands),
                    "exos_rollback_commands": list(c.exos_rollback_commands),
                    "exos_rollback_command": c.exos_rollback_command,
                    "voss_disable_commands": list(c.voss_disable_commands),
                    "voss_rollback_commands": list(c.voss_rollback_commands),
                    "voss_rollback_command": c.voss_rollback_command,
                }
                for c in artifact.candidates
            ),
            key=lambda item: (
                str(item["site_id"] or ""),
                str(item["device_id"]),
                str(item["port_id"]),
            ),
        )
        canonical_blocked = sorted(
            (
                {
                    "port_id": b.port_id,
                    "device_id": b.device_id,
                    "port_name": b.port_name,
                    "site_id": b.site_id,
                    "block_reason": b.block_reason,
                    "matched_rules": list(b.matched_rules),
                }
                for b in artifact.blocked_ports
            ),
            key=lambda item: (
                str(item["site_id"] or ""),
                str(item["device_id"]),
                str(item["port_id"]),
            ),
        )
        canonical_payload = {
            "dialect": artifact.dialect.value,
            "min_inactive_runs": artifact.min_inactive_runs,
            "min_inactive_days": round(float(artifact.min_inactive_days), 4),
            "estimated_poe_watts_saved": round(
                float(artifact.estimated_poe_watts_saved), 2
            ),
            "candidates": canonical_candidates,
            "blocked_ports": canonical_blocked,
            "exos_commands": list(artifact.exos_commands),
            "exos_rollback_commands": list(artifact.exos_rollback_commands),
            "voss_commands": list(artifact.voss_commands),
            "voss_rollback_commands": list(artifact.voss_rollback_commands),
        }
        serialized = json.dumps(
            canonical_payload, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if isinstance(artifact, ReconciliationReport):
        canonical_discrepancies = sorted(
            (d.to_dict() for d in artifact.discrepancies),
            key=lambda item: (
                str(item.get("site_id") or ""),
                str(item.get("discrepancy_type") or ""),
                str(item.get("discrepancy_id") or ""),
            ),
        )
        serialized = json.dumps(
            canonical_discrepancies, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if isinstance(artifact, UpsFleetHealthReport):
        canonical_records = sorted(
            (
                {
                    "equipment_id": r.equipment_id,
                    "site_id": r.site_id,
                    "name": r.name,
                    "status": r.status.value,
                    "advisories": sorted(r.advisories),
                    "needs_battery_replacement": r.needs_battery_replacement,
                    "on_battery": r.on_battery,
                    "is_low_runtime": r.is_low_runtime,
                    "is_high_temperature": r.is_high_temperature,
                    "is_high_load": r.is_high_load,
                }
                for r in artifact.records
            ),
            key=lambda item: (item["site_id"], item["equipment_id"]),
        )
        serialized = json.dumps(
            canonical_records, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if isinstance(artifact, UpsHealthRecord):
        payload = {
            "equipment_id": artifact.equipment_id,
            "site_id": artifact.site_id,
            "name": artifact.name,
            "status": artifact.status.value,
            "advisories": sorted(artifact.advisories),
            "needs_battery_replacement": artifact.needs_battery_replacement,
            "on_battery": artifact.on_battery,
        }
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    if isinstance(artifact, str):
        cleaned = artifact.strip()
        if len(cleaned) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in cleaned):
            return cleaned.lower()
        return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()

    if isinstance(artifact, Mapping):
        for digest_key in (
            "artifact_sha256",
            "manifest_sha256",
            "plan_sha256",
            "u_artifact_sha256",
            "sha256",
        ):
            raw_digest = artifact.get(digest_key)
            if isinstance(raw_digest, str) and raw_digest.strip():
                return raw_digest.strip().lower()
        if "entries" in artifact and (
            "manifest_id" in artifact or "policy" in artifact
        ):
            return compute_artifact_sha256(
                RemediationApprovalManifest.from_dict(artifact)
            )
        if "candidates" in artifact or "blocked_ports" in artifact or "plan_id" in artifact:
            return compute_artifact_sha256(PortReclamationPlan.from_dict(artifact))
        if "discrepancies" in artifact:
            return compute_artifact_sha256(ReconciliationReport.from_dict(artifact))
        if "records" in artifact and (
            "critical_count" in artifact or "battery_replacement_units" in artifact
        ):
            return compute_artifact_sha256(UpsFleetHealthReport.from_dict(artifact))
        serialized = json.dumps(
            dict(artifact), sort_keys=True, separators=(",", ":"), default=str
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    raise TypeError(
        f"Unsupported artifact type for SHA-256 computation: {type(artifact)!r}"
    )


def _deterministic_ticket_id(
    prefix: str,
    workflow_type: ItsmWorkflowType,
    seed: str,
) -> str:
    digest = hashlib.sha256(
        f"{workflow_type.value}:{seed}".encode("utf-8")
    ).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


@dataclass
class ItsmTicketRequest:
    """Provider-agnostic ITSM change request, onboarding task, or hardware incident ticket."""

    ticket_id: str
    workflow_type: ItsmWorkflowType
    title: str
    description: str
    category: str = "Network Source of Truth"
    risk: str = "moderate"
    priority: str = "Medium"
    implementation_plan: str = ""
    backout_plan: str = ""
    cmdb_ci: str = "sot-inventory"
    affected_cis: list[str] = field(default_factory=list)
    site_ids: list[str] = field(default_factory=list)
    item_ids: list[str] = field(default_factory=list)
    artifact_id: Optional[str] = None
    artifact_sha256: Optional[str] = None
    approval_status: TicketApprovalStatus = TicketApprovalStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    labels: list[str] = field(default_factory=list)
    project_key: str = "NETOPS"
    issue_type: str = "Change"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    dry_run: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.ticket_id = _require_non_empty_str(self.ticket_id, "ticket_id").strip()
        self.workflow_type = _coerce_workflow_type(
            self.workflow_type, "workflow_type"
        )
        self.title = _require_non_empty_str(self.title, "title").strip()
        self.description = _require_non_empty_str(
            self.description, "description"
        ).strip()
        self.category = _require_non_empty_str(self.category, "category").strip()
        self.risk = _coerce_risk(self.risk)
        self.priority = _coerce_priority(self.priority)
        self.implementation_plan = _require_non_empty_str(
            self.implementation_plan, "implementation_plan"
        ).strip()
        self.backout_plan = _require_non_empty_str(
            self.backout_plan, "backout_plan"
        ).strip()
        self.cmdb_ci = _require_non_empty_str(self.cmdb_ci, "cmdb_ci").strip()

        self.affected_cis = _normalize_str_list(self.affected_cis)
        if self.cmdb_ci not in self.affected_cis:
            self.affected_cis.insert(0, self.cmdb_ci)

        self.site_ids = _normalize_str_list(self.site_ids)
        self.item_ids = _normalize_str_list(self.item_ids)

        if self.artifact_id is not None:
            cleaned_art = str(self.artifact_id).strip()
            self.artifact_id = cleaned_art if cleaned_art else None

        if self.artifact_sha256 is not None:
            cleaned_sha = str(self.artifact_sha256).strip().lower()
            self.artifact_sha256 = cleaned_sha if cleaned_sha else None

        self.approval_status = _coerce_ticket_approval_status(
            self.approval_status, "approval_status"
        )
        if self.approved_by is not None:
            cleaned_by = str(self.approved_by).strip()
            self.approved_by = cleaned_by if cleaned_by else None

        if self.approved_at is not None:
            self.approved_at = normalize_utc_datetime(
                self.approved_at, field_name="approved_at"
            )

        self.labels = _normalize_str_list(self.labels)
        if "sot-validator" not in self.labels:
            self.labels.insert(0, "sot-validator")

        self.project_key = _require_non_empty_str(
            self.project_key, "project_key"
        ).strip()
        self.issue_type = _require_non_empty_str(
            self.issue_type, "issue_type"
        ).strip()

        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        else:
            self.created_at = normalize_utc_datetime(
                self.created_at, field_name="created_at"
            )

        if not isinstance(self.dry_run, bool):
            raise ValueError("dry_run must be a boolean")

        if self.metadata is None:
            self.metadata = {}
        elif isinstance(self.metadata, Mapping):
            self.metadata = dict(self.metadata)
        else:
            raise ValueError("metadata must be a mapping")

    @property
    def short_description(self) -> str:
        """ServiceNow alias for title."""
        return self.title

    @property
    def summary(self) -> str:
        """Jira alias for title."""
        return self.title

    @property
    def rollback_plan(self) -> str:
        """Alias for backout_plan."""
        return self.backout_plan

    @property
    def cmdb_cis(self) -> list[str]:
        """Alias for affected_cis."""
        return self.affected_cis

    @property
    def manifest_sha256(self) -> Optional[str]:
        """Alias for artifact_sha256."""
        return self.artifact_sha256

    @property
    def plan_sha256(self) -> Optional[str]:
        """Alias for artifact_sha256."""
        return self.artifact_sha256

    @property
    def sha256(self) -> Optional[str]:
        """Alias for artifact_sha256."""
        return self.artifact_sha256

    @property
    def is_approved(self) -> bool:
        """Return True if approval_status is APPROVED."""
        return self.approval_status is TicketApprovalStatus.APPROVED

    def to_servicenow_payload(self) -> dict[str, Any]:
        """Format this ticket request as a ServiceNow change_request / incident payload dictionary."""
        snow_table = (
            "incident"
            if self.workflow_type is ItsmWorkflowType.UPS_HARDWARE_INCIDENT
            else "change_request"
        )
        desc_lines = [self.description]
        if self.artifact_sha256 and self.artifact_sha256 not in self.description:
            desc_lines.append(f"Artifact SHA-256: {self.artifact_sha256}")
        full_description = "\n\n".join(desc_lines)

        return {
            "ticket_id": self.ticket_id,
            "table": snow_table,
            "short_description": self.title,
            "description": full_description,
            "category": self.category,
            "risk": self.risk,
            "priority": self.priority,
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
            "cmdb_ci": self.cmdb_ci,
            "approval": self.approval_status.value.lower(),
            "approval_status": self.approval_status.value,
            "u_workflow_type": self.workflow_type.value,
            "u_artifact_id": self.artifact_id,
            "u_artifact_sha256": self.artifact_sha256,
            "u_site_ids": list(self.site_ids),
            "u_item_ids": list(self.item_ids),
            "u_affected_cis": list(self.affected_cis),
            "u_dry_run": self.dry_run,
        }

    def to_jira_payload(self, project_key: Optional[str] = None) -> dict[str, Any]:
        """Format this ticket request as a Jira issue creation payload dictionary."""
        resolved_project_key = (
            _require_non_empty_str(project_key, "project_key").strip()
            if project_key is not None
            else self.project_key
        )
        jira_description_sections = [
            self.description,
            f"h3. Implementation Plan\n{self.implementation_plan}",
            f"h3. Backout / Rollback Plan\n{self.backout_plan}",
            f"*Primary CMDB CI:* {self.cmdb_ci}\n*Category:* {self.category}\n*Risk:* {self.risk}",
        ]
        if self.artifact_id:
            jira_description_sections.append(f"*Artifact ID:* {self.artifact_id}")
        if self.artifact_sha256:
            jira_description_sections.append(
                f"*Artifact SHA-256:* {self.artifact_sha256}"
            )
        jira_description = "\n\n".join(jira_description_sections)

        project_obj = {"key": resolved_project_key}
        issuetype_obj = {"name": self.issue_type}
        priority_obj = {"name": self.priority}
        labels_list = list(self.labels)

        fields_dict: dict[str, Any] = {
            "project": dict(project_obj),
            "summary": self.title,
            "description": jira_description,
            "issuetype": dict(issuetype_obj),
            "priority": dict(priority_obj),
            "labels": list(labels_list),
            "ticket_id": self.ticket_id,
            "workflow_type": self.workflow_type.value,
            "approval_status": self.approval_status.value,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "cmdb_ci": self.cmdb_ci,
            "site_ids": list(self.site_ids),
            "item_ids": list(self.item_ids),
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
        }

        return {
            "ticket_id": self.ticket_id,
            "project": project_obj,
            "summary": self.title,
            "description": jira_description,
            "issuetype": issuetype_obj,
            "priority": priority_obj,
            "labels": labels_list,
            "approval_status": self.approval_status.value,
            "workflow_type": self.workflow_type.value,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "cmdb_ci": self.cmdb_ci,
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
            "fields": fields_dict,
        }

    def to_webhook_payload(self) -> dict[str, Any]:
        """Format this ticket request as a generic ITSM webhook event payload."""
        return {
            "event_type": f"itsm.{self.workflow_type.value.lower()}",
            "ticket_id": self.ticket_id,
            "workflow_type": self.workflow_type.value,
            "approval_status": self.approval_status.value,
            "approved_by": self.approved_by,
            "approved_at": _format_optional_datetime(self.approved_at),
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "site_ids": list(self.site_ids),
            "item_ids": list(self.item_ids),
            "created_at": _format_optional_datetime(self.created_at),
            "dry_run": self.dry_run,
            "ticket": self.to_dict(),
            "servicenow": self.to_servicenow_payload(),
            "jira": self.to_jira_payload(),
        }

    def format_for_provider(
        self,
        provider: ItsmProvider | str = ItsmProvider.SERVICENOW,
        *,
        project_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """Format this ticket request for the given ITSM provider ('servicenow', 'jira', 'webhook')."""
        coerced = _coerce_provider(provider, "provider")
        if coerced is ItsmProvider.SERVICENOW:
            return self.to_servicenow_payload()
        if coerced is ItsmProvider.JIRA:
            return self.to_jira_payload(project_key=project_key)
        return self.to_webhook_payload()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "workflow_type": self.workflow_type.value,
            "title": self.title,
            "short_description": self.title,
            "summary": self.title,
            "description": self.description,
            "category": self.category,
            "risk": self.risk,
            "priority": self.priority,
            "implementation_plan": self.implementation_plan,
            "backout_plan": self.backout_plan,
            "cmdb_ci": self.cmdb_ci,
            "affected_cis": list(self.affected_cis),
            "site_ids": list(self.site_ids),
            "item_ids": list(self.item_ids),
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "approval_status": self.approval_status.value,
            "approved_by": self.approved_by,
            "approved_at": _format_optional_datetime(self.approved_at),
            "labels": list(self.labels),
            "project_key": self.project_key,
            "issue_type": self.issue_type,
            "created_at": _format_optional_datetime(self.created_at),
            "dry_run": self.dry_run,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ItsmTicketRequest:
        if isinstance(data, cls):
            return data
        title = (
            data.get("title")
            or data.get("short_description")
            or data.get("summary")
            or ""
        )
        backout = (
            data.get("backout_plan")
            or data.get("rollback_plan")
            or "Restore from pre-change snapshot."
        )
        artifact_sha = (
            data.get("artifact_sha256")
            or data.get("u_artifact_sha256")
            or data.get("manifest_sha256")
            or data.get("plan_sha256")
        )
        raw_created = data.get("created_at")
        created_at = (
            _parse_optional_datetime(raw_created, "created_at")
            if raw_created is not None
            else datetime.now(timezone.utc)
        )
        raw_approved_at = data.get("approved_at")
        approved_at = (
            _parse_optional_datetime(raw_approved_at, "approved_at")
            if raw_approved_at is not None
            else None
        )
        return cls(
            ticket_id=str(data["ticket_id"]),
            workflow_type=data.get(
                "workflow_type",
                data.get("u_workflow_type", ItsmWorkflowType.QUARANTINE_DECOMMISSION),
            ),
            title=str(title),
            description=str(data.get("description") or title),
            category=str(data.get("category") or "Network Source of Truth"),
            risk=str(data.get("risk") or "moderate"),
            priority=str(data.get("priority") or "Medium"),
            implementation_plan=str(
                data.get("implementation_plan") or "Execute approved plan."
            ),
            backout_plan=str(backout),
            cmdb_ci=str(data.get("cmdb_ci") or "sot-inventory"),
            affected_cis=list(
                data.get("affected_cis", data.get("u_affected_cis", []))
            ),
            site_ids=list(data.get("site_ids", data.get("u_site_ids", []))),
            item_ids=list(data.get("item_ids", data.get("u_item_ids", []))),
            artifact_id=data.get("artifact_id", data.get("u_artifact_id")),
            artifact_sha256=artifact_sha,
            approval_status=data.get(
                "approval_status", data.get("approval", TicketApprovalStatus.PENDING)
            ),
            approved_by=data.get("approved_by"),
            approved_at=approved_at,
            labels=list(data.get("labels", [])),
            project_key=str(data.get("project_key") or "NETOPS"),
            issue_type=str(data.get("issue_type") or "Change"),
            created_at=created_at or datetime.now(timezone.utc),
            dry_run=bool(data.get("dry_run", data.get("u_dry_run", True))),
            metadata=dict(data.get("metadata") or {}),
        )

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> ItsmTicketRequest:
        return cls.from_dict(json.loads(raw))


class ItsmTicketPayloadBuilder:
    """Deterministic ITSM change-ticket, onboarding task, and hardware incident payload builder."""

    def __init__(
        self,
        *,
        default_project_key: str = "NETOPS",
        default_cmdb_ci: str = "sot-inventory",
        evaluation_time: Optional[datetime | str] = None,
    ) -> None:
        self.default_project_key = _require_non_empty_str(
            default_project_key, "default_project_key"
        ).strip()
        self.default_cmdb_ci = _require_non_empty_str(
            default_cmdb_ci, "default_cmdb_ci"
        ).strip()
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )

    def _resolve_timestamp(
        self, fallback: Optional[datetime | str] = None
    ) -> datetime:
        if self.evaluation_time is not None:
            return self.evaluation_time
        if fallback is not None:
            return resolve_evaluation_time(fallback)
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Workflow 1: Stale SoT Quarantine / Decommission Change Request
    # ------------------------------------------------------------------

    def build_quarantine_ticket(
        self,
        manifest: RemediationApprovalManifest | Mapping[str, Any],
        *,
        ticket_id: Optional[str] = None,
        approval_status: TicketApprovalStatus | str = TicketApprovalStatus.PENDING,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        sql_scripts: Optional[SqlRemediationScripts] = None,
        site_id: Optional[str] = None,
        project_key: Optional[str] = None,
        cmdb_ci: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Build a Stale SoT Quarantine / Decommission Change Request from a RemediationApprovalManifest."""
        manifest_obj = (
            manifest
            if isinstance(manifest, RemediationApprovalManifest)
            else RemediationApprovalManifest.from_dict(manifest)
        )
        manifest_sha = compute_artifact_sha256(manifest_obj)

        all_entries = manifest_obj.entries
        if site_id is not None:
            clean_site = site_id.strip()
            scoped_entries = [e for e in all_entries if e.site_id == clean_site]
        else:
            scoped_entries = list(all_entries)

        actionable_entries = [
            e
            for e in scoped_entries
            if e.approval_status is ApprovalStatus.APPROVED
        ]
        if not actionable_entries:
            actionable_entries = [
                e
                for e in scoped_entries
                if e.graduation_status is QuarantineGraduationStatus.ELIGIBLE
                and e.approval_status is not ApprovalStatus.REJECTED
                and e.approval_status is not ApprovalStatus.EXEMPT
            ]
        if not actionable_entries:
            actionable_entries = list(scoped_entries)

        actionable_entries.sort(
            key=lambda e: (e.site_id, e.item_type, e.item_id)
        )

        site_ids = sorted({e.site_id for e in actionable_entries})
        if not site_ids and site_id:
            site_ids = [site_id.strip()]
        item_ids = [e.item_id for e in actionable_entries]

        op_counts: dict[str, int] = {}
        for entry in actionable_entries:
            op_val = entry.target_operation.value
            op_counts[op_val] = op_counts.get(op_val, 0) + 1

        primary_ci = (
            cmdb_ci.strip()
            if cmdb_ci and cmdb_ci.strip()
            else (site_ids[0] if len(site_ids) == 1 else self.default_cmdb_ci)
        )
        affected_cis = [primary_ci, *site_ids, *item_ids]

        resolved_scripts = sql_scripts
        if resolved_scripts is None and manifest_obj.approved_entries:
            try:
                resolved_scripts = SqlRemediationScriptGenerator().generate(
                    manifest_obj,
                    execution_id=f"exec-{manifest_obj.manifest_id}",
                    executed_at=manifest_obj.generated_at,
                )
            except Exception:
                resolved_scripts = None

        forward_lines: list[str] = [
            f"1. Verify change ticket approval and manifest SHA-256 digest ({manifest_sha}).",
            f"2. Execute gated SoT quarantine remediation for manifest {manifest_obj.manifest_id} ({len(actionable_entries)} record(s) across {len(site_ids) or 1} site(s)):",
        ]
        for entry in actionable_entries:
            forward_lines.append(
                f"   - [{entry.site_id}] {entry.item_type} {entry.item_id} ({entry.name}): "
                f"{entry.target_operation.value} (stale {entry.consecutive_stale_runs} runs / {entry.stale_duration_days:.1f} days, confidence={entry.confidence:.2f})"
            )
        if resolved_scripts is not None and resolved_scripts.remediate_sql.strip():
            forward_lines.append("")
            forward_lines.append("Forward SQL Script (remediate.sql):")
            forward_lines.append(resolved_scripts.remediate_sql.strip())
        else:
            forward_lines.append("")
            forward_lines.append(
                f"CLI Execution: sot-validator remediate --execute-approved-plan {manifest_obj.manifest_id}.json --confirm-write"
            )

        backout_lines: list[str] = [
            f"1. Restore pre-change SoT database records from rollback script (rollback.sql) or append-only journal (remediation_journal.jsonl) for manifest {manifest_obj.manifest_id}.",
            "2. Re-verify restored record status in SoT snapshot.",
        ]
        if resolved_scripts is not None and resolved_scripts.rollback_sql.strip():
            backout_lines.append("")
            backout_lines.append("Rollback SQL Script (rollback.sql):")
            backout_lines.append(resolved_scripts.rollback_sql.strip())
        else:
            for entry in reversed(actionable_entries):
                backout_lines.append(
                    f"   - Restore [{entry.site_id}] {entry.item_type} {entry.item_id} ({entry.name}) to pre-quarantine state."
                )

        op_summary_str = (
            ", ".join(f"{k}={v}" for k, v in sorted(op_counts.items()))
            or "none"
        )
        site_label = (
            site_ids[0]
            if len(site_ids) == 1
            else f"{len(site_ids)} sites"
        )
        title = (
            f"[SoT Quarantine] Decommission/quarantine {len(actionable_entries)} stale inventory record(s) "
            f"at {site_label} ({manifest_obj.manifest_id})"
        )
        description = (
            f"Phase 2/6 Stale SoT Inventory Quarantine & Decommission Change Request.\n"
            f"Manifest ID: {manifest_obj.manifest_id}\n"
            f"Manifest SHA-256: {manifest_sha}\n"
            f"Total Manifest Entries: {len(manifest_obj.entries)} "
            f"(Actionable: {len(actionable_entries)}, Exempt: {len(manifest_obj.exempt_entries)})\n"
            f"Sites Affected: {', '.join(site_ids) if site_ids else 'N/A'}\n"
            f"Operations Breakdown: {op_summary_str}\n"
            f"Policy Thresholds: min_consecutive_stale_runs={manifest_obj.policy.min_consecutive_stale_runs}, "
            f"min_stale_days={manifest_obj.policy.min_stale_days}, "
            f"min_confidence={manifest_obj.policy.min_confidence}"
        )

        has_decommission_or_port = any(
            e.target_operation
            in (
                RemediationOperation.DECOMMISSION_VM_RECORD,
                RemediationOperation.PROPOSE_PORT_SHUTDOWN,
            )
            for e in actionable_entries
        )
        risk = (
            TicketRisk.HIGH.value
            if len(actionable_entries) >= 10 or has_decommission_or_port
            else TicketRisk.MODERATE.value
        )
        priority = (
            TicketPriority.HIGH.value
            if risk == TicketRisk.HIGH.value
            else TicketPriority.MEDIUM.value
        )

        resolved_ticket_id = (
            ticket_id.strip()
            if ticket_id and ticket_id.strip()
            else _deterministic_ticket_id(
                "CHG",
                ItsmWorkflowType.QUARANTINE_DECOMMISSION,
                f"{manifest_obj.manifest_id}:{manifest_sha}",
            )
        )

        return ItsmTicketRequest(
            ticket_id=resolved_ticket_id,
            workflow_type=ItsmWorkflowType.QUARANTINE_DECOMMISSION,
            title=title,
            description=description,
            category="Network Source of Truth",
            risk=risk,
            priority=priority,
            implementation_plan="\n".join(forward_lines),
            backout_plan="\n".join(backout_lines),
            cmdb_ci=primary_ci,
            affected_cis=affected_cis,
            site_ids=site_ids,
            item_ids=item_ids,
            artifact_id=manifest_obj.manifest_id,
            artifact_sha256=manifest_sha,
            approval_status=approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            labels=[
                "sot-validator",
                "quarantine",
                "decommission",
                *(f"site:{s}" for s in site_ids),
            ],
            project_key=project_key or self.default_project_key,
            issue_type="Change",
            created_at=self._resolve_timestamp(manifest_obj.generated_at),
            dry_run=manifest_obj.dry_run,
            metadata={
                "manifest_id": manifest_obj.manifest_id,
                "manifest_sha256": manifest_sha,
                "total_entries": len(manifest_obj.entries),
                "actionable_count": len(actionable_entries),
                "exempt_count": len(manifest_obj.exempt_entries),
                "summary_by_status": dict(manifest_obj.summary_by_status),
                "summary_by_operation": op_counts,
            },
        )

    from_quarantine_manifest = build_quarantine_ticket
    build_quarantine_change_request = build_quarantine_ticket

    # ------------------------------------------------------------------
    # Workflow 2: Extreme Switch Port & PoE Reclamation Change Request
    # ------------------------------------------------------------------

    def build_port_reclamation_ticket(
        self,
        plan: PortReclamationPlan | Mapping[str, Any],
        *,
        ticket_id: Optional[str] = None,
        dialect: Optional[ExtremeCliDialect | str] = None,
        approval_status: TicketApprovalStatus | str = TicketApprovalStatus.PENDING,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        project_key: Optional[str] = None,
        cmdb_ci: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Build an Extreme Switch Port & PoE Reclamation Change Request from a PortReclamationPlan."""
        plan_obj = (
            plan
            if isinstance(plan, PortReclamationPlan)
            else PortReclamationPlan.from_dict(plan)
        )
        plan_sha = compute_artifact_sha256(plan_obj)
        active_dialect = (
            ExtremeCliDialect(dialect)
            if dialect is not None
            else plan_obj.dialect
        )

        candidates = list(plan_obj.candidates)
        blocked_ports = list(plan_obj.blocked_ports)

        site_ids = sorted(
            {
                s
                for s in (
                    *(c.site_id for c in candidates),
                    *(b.site_id for b in blocked_ports),
                )
                if s
            }
        )
        device_ids = sorted(
            {
                d
                for d in (
                    *(c.device_id for c in candidates),
                    *(b.device_id for b in blocked_ports),
                )
                if d
            }
        )
        port_ids = [c.port_id for c in candidates]

        primary_ci = (
            cmdb_ci.strip()
            if cmdb_ci and cmdb_ci.strip()
            else (
                device_ids[0]
                if len(device_ids) == 1
                else (site_ids[0] if len(site_ids) == 1 else self.default_cmdb_ci)
            )
        )
        affected_cis = [primary_ci, *device_ids, *site_ids, *port_ids]

        # Build LLDP Uplink Safety Guard audit summary
        guard_lines: list[str] = [
            f"LLDP Uplink Guard Audit: {len(blocked_ports)} port(s) protected/blocked from shutdown; "
            f"{len(candidates)} access port(s) eligible."
        ]
        for b_rec in blocked_ports:
            rules_str = (
                f" [rules: {', '.join(b_rec.matched_rules)}]"
                if b_rec.matched_rules
                else ""
            )
            guard_lines.append(
                f"  - BLOCKED {b_rec.device_id}:{b_rec.port_name} ({b_rec.port_id}): "
                f"{b_rec.block_reason}{rules_str}"
            )
        guard_summary_text = "\n".join(guard_lines)

        # Forward implementation plan including ExtremeXOS and VOSS commands
        forward_script = plan_obj.format_cli_script(active_dialect).strip()
        impl_lines: list[str] = [
            f"1. Verify change ticket approval and plan SHA-256 digest ({plan_sha}).",
            "2. Confirm LLDP Uplink Guard audit checks pass prior to switch CLI session.",
            guard_summary_text,
            "",
            f"3. Apply staged Extreme Networks ({active_dialect.value.upper()}) port & PoE disable commands "
            f"({len(candidates)} eligible port(s), estimated PoE savings: {plan_obj.estimated_poe_watts_saved:.2f}W):",
            forward_script,
        ]
        if active_dialect is ExtremeCliDialect.EXOS and plan_obj.voss_commands:
            impl_lines.extend(
                [
                    "",
                    "Equivalent Extreme VOSS Commands:",
                    *plan_obj.voss_commands,
                ]
            )
        elif active_dialect is ExtremeCliDialect.VOSS and plan_obj.exos_commands:
            impl_lines.extend(
                [
                    "",
                    "Equivalent ExtremeXOS Commands:",
                    *plan_obj.exos_commands,
                ]
            )

        # Backout / Rollback plan including 1-command rollback strings and full rollback script
        rollback_script = plan_obj.format_rollback_script(active_dialect).strip()
        backout_lines: list[str] = [
            f"1. Execute 1-command per-port rollback or staged rollback script on affected Extreme switches ({', '.join(device_ids) or primary_ci}):",
        ]
        for cand in candidates:
            one_cmd = (
                cand.voss_rollback_command
                if active_dialect is ExtremeCliDialect.VOSS
                else cand.exos_rollback_command
            )
            backout_lines.append(
                f"   - {cand.device_id}:{cand.port_name} ({cand.port_id}) 1-command rollback: {one_cmd}"
            )
        backout_lines.extend(
            [
                "",
                f"Staged {active_dialect.value.upper()} Rollback Script:",
                rollback_script,
            ]
        )

        target_label = (
            device_ids[0]
            if len(device_ids) == 1
            else (site_ids[0] if len(site_ids) == 1 else f"{len(device_ids) or 1} switch(es)")
        )
        title = (
            f"[Extreme Port Reclamation] Disable {len(candidates)} stale access port(s) & reclaim "
            f"{plan_obj.estimated_poe_watts_saved:.2f}W PoE on {target_label} ({plan_obj.plan_id})"
        )
        description = (
            f"Phase 4/6 Extreme Networks Switch Port & PoE Reclamation Change Request.\n"
            f"Plan ID: {plan_obj.plan_id}\n"
            f"Plan SHA-256: {plan_sha}\n"
            f"CLI Dialect: {active_dialect.value.upper()}\n"
            f"Eligible Ports: {len(candidates)} | Blocked by LLDP Uplink Guard: {len(blocked_ports)}\n"
            f"Estimated PoE Power Saved: {plan_obj.estimated_poe_watts_saved:.2f}W\n"
            f"Thresholds: min_inactive_runs={plan_obj.min_inactive_runs}, "
            f"min_inactive_days={plan_obj.min_inactive_days:.1f}\n\n"
            f"{guard_summary_text}"
        )

        risk = (
            TicketRisk.MODERATE.value
            if len(candidates) <= 24
            else TicketRisk.HIGH.value
        )
        priority = (
            TicketPriority.MEDIUM.value
            if risk == TicketRisk.MODERATE.value
            else TicketPriority.HIGH.value
        )

        resolved_ticket_id = (
            ticket_id.strip()
            if ticket_id and ticket_id.strip()
            else _deterministic_ticket_id(
                "CHG",
                ItsmWorkflowType.PORT_RECLAMATION,
                f"{plan_obj.plan_id}:{plan_sha}",
            )
        )

        return ItsmTicketRequest(
            ticket_id=resolved_ticket_id,
            workflow_type=ItsmWorkflowType.PORT_RECLAMATION,
            title=title,
            description=description,
            category="Network Switching / Extreme Networks",
            risk=risk,
            priority=priority,
            implementation_plan="\n".join(impl_lines),
            backout_plan="\n".join(backout_lines),
            cmdb_ci=primary_ci,
            affected_cis=affected_cis,
            site_ids=site_ids,
            item_ids=port_ids,
            artifact_id=plan_obj.plan_id,
            artifact_sha256=plan_sha,
            approval_status=approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            labels=[
                "sot-validator",
                "port-reclamation",
                "extreme-networks",
                f"dialect:{active_dialect.value}",
                *(f"site:{s}" for s in site_ids),
            ],
            project_key=project_key or self.default_project_key,
            issue_type="Change",
            created_at=self._resolve_timestamp(plan_obj.generated_at),
            dry_run=plan_obj.dry_run,
            metadata={
                "plan_id": plan_obj.plan_id,
                "plan_sha256": plan_sha,
                "dialect": active_dialect.value,
                "eligible_port_count": len(candidates),
                "blocked_port_count": len(blocked_ports),
                "estimated_poe_watts_saved": plan_obj.estimated_poe_watts_saved,
                "exos_commands": list(plan_obj.exos_commands),
                "exos_rollback_commands": list(plan_obj.exos_rollback_commands),
                "voss_commands": list(plan_obj.voss_commands),
                "voss_rollback_commands": list(plan_obj.voss_rollback_commands),
                "one_command_rollbacks": [
                    {
                        "port_id": c.port_id,
                        "device_id": c.device_id,
                        "port_name": c.port_name,
                        "exos_rollback_command": c.exos_rollback_command,
                        "voss_rollback_command": c.voss_rollback_command,
                    }
                    for c in candidates
                ],
                "lldp_guard_blocked_ports": [
                    {
                        "port_id": b.port_id,
                        "device_id": b.device_id,
                        "port_name": b.port_name,
                        "block_reason": b.block_reason,
                        "matched_rules": list(b.matched_rules),
                    }
                    for b in blocked_ports
                ],
            },
        )

    from_port_reclamation_plan = build_port_reclamation_ticket
    build_port_reclamation_change_request = build_port_reclamation_ticket

    # ------------------------------------------------------------------
    # Workflow 3: Shadow IT Asset Onboarding Task
    # ------------------------------------------------------------------

    def build_onboarding_ticket(
        self,
        report: ReconciliationReport | Mapping[str, Any],
        *,
        ticket_id: Optional[str] = None,
        site_id: Optional[str] = None,
        approval_status: TicketApprovalStatus | str = TicketApprovalStatus.PENDING,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        project_key: Optional[str] = None,
        cmdb_ci: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Build a Shadow IT Asset Onboarding Task ticket from a ReconciliationReport."""
        report_obj = (
            report
            if isinstance(report, ReconciliationReport)
            else ReconciliationReport.from_dict(report)
        )
        if site_id is not None:
            clean_site = site_id.strip()
            scoped_discs = [
                d for d in report_obj.discrepancies if d.site_id == clean_site
            ]
            scoped_report = ReconciliationReport(
                discrepancies=scoped_discs,
                generated_at=report_obj.generated_at,
            )
        else:
            scoped_report = report_obj

        report_sha = compute_artifact_sha256(scoped_report)
        discrepancies = scoped_report.discrepancies
        site_ids = sorted({d.site_id for d in discrepancies})
        if not site_ids and site_id:
            site_ids = [site_id.strip()]
        item_ids = [d.discrepancy_id for d in discrepancies]

        by_type = scoped_report.summary_by_type
        untracked_count = (
            by_type.get(DiscrepancyType.UNTRACKED_VM.value, 0)
            + by_type.get(DiscrepancyType.UNTRACKED_DEVICE.value, 0)
            + by_type.get(DiscrepancyType.UNTRACKED_IP.value, 0)
        )
        mismatch_count = by_type.get(DiscrepancyType.ATTRIBUTE_MISMATCH.value, 0)

        primary_ci = (
            cmdb_ci.strip()
            if cmdb_ci and cmdb_ci.strip()
            else (site_ids[0] if len(site_ids) == 1 else self.default_cmdb_ci)
        )
        affected_cis = [
            primary_ci,
            *site_ids,
            *(
                d.observed_hostname or d.observed_ip or d.observed_identifier
                for d in discrepancies
            ),
        ]

        onboarding_sql = scoped_report.generate_onboarding_sql().strip()
        onboarding_csv = scoped_report.generate_onboarding_csv().strip()

        impl_lines: list[str] = [
            f"1. Review {len(discrepancies)} discovered Shadow IT discrepancy record(s) "
            f"({untracked_count} untracked asset(s), {mismatch_count} attribute mismatch(es)):",
        ]
        for disc in discrepancies:
            host_or_id = disc.observed_hostname or disc.observed_identifier
            ip_part = f" (IP: {disc.observed_ip})" if disc.observed_ip else ""
            mac_part = f" [MAC: {disc.observed_mac}]" if disc.observed_mac else ""
            action_part = (
                f" -> {disc.recommended_onboarding_action}"
                if disc.recommended_onboarding_action
                else ""
            )
            impl_lines.append(
                f"   - [{disc.site_id}] {disc.discrepancy_type.value} ({disc.discrepancy_id}): "
                f"{host_or_id}{ip_part}{mac_part} via {disc.source}{action_part}"
            )
        if onboarding_sql:
            impl_lines.extend(
                [
                    "",
                    "2. Execute SoT Onboarding SQL INSERT Statements:",
                    onboarding_sql,
                ]
            )
        if onboarding_csv:
            impl_lines.extend(
                [
                    "",
                    "3. Onboarding CSV Import Template:",
                    onboarding_csv,
                ]
            )

        backout_lines: list[str] = [
            "1. If any onboarded asset was registered in error, remove the newly inserted SoT records by primary key:",
        ]
        for entry in scoped_report._build_onboarding_entries():
            table = entry.get("target_table")
            rec_id = entry.get("item_id")
            rec_site = entry.get("site_id")
            if table == "equipment":
                backout_lines.append(
                    f"   DELETE FROM equipment WHERE equipment_id = '{rec_id}' AND site_id = '{rec_site}';"
                )
            elif table == "network_devices":
                backout_lines.append(
                    f"   DELETE FROM network_devices WHERE device_id = '{rec_id}' AND site_id = '{rec_site}';"
                )
            elif table == "ip_arp_entries":
                backout_lines.append(
                    f"   DELETE FROM ip_arp_entries WHERE ip_id = '{rec_id}' AND site_id = '{rec_site}';"
                )
        if len(backout_lines) == 1:
            backout_lines.append(
                "   Revert any manual attribute mismatch updates in the SoT database."
            )

        site_label = (
            site_ids[0]
            if len(site_ids) == 1
            else f"{len(site_ids) or 1} site(s)"
        )
        title = (
            f"[Shadow IT Onboarding] Reconcile {len(discrepancies)} untracked/mismatched inventory asset(s) "
            f"at {site_label}"
        )
        type_summary_str = ", ".join(
            f"{dtype.value}={by_type.get(dtype.value, 0)}"
            for dtype in ALL_DISCREPANCY_TYPES
        )
        description = (
            f"Phase 3/6 Reverse Discovery & Shadow IT Asset Onboarding Task.\n"
            f"Reconciliation Digest SHA-256: {report_sha}\n"
            f"Total Discrepancies: {len(discrepancies)} ({type_summary_str})\n"
            f"Sites Affected: {', '.join(site_ids) if site_ids else 'N/A'}\n"
            f"Untracked VMs, switches, UPS units, and active /24 IPs detected across live vCenter, ARP, SNMP, and ICMP feeds."
        )

        artifact_id = f"recon-{report_sha[:12]}"
        resolved_ticket_id = (
            ticket_id.strip()
            if ticket_id and ticket_id.strip()
            else _deterministic_ticket_id(
                "TASK",
                ItsmWorkflowType.SHADOW_IT_ONBOARDING,
                report_sha,
            )
        )

        risk = (
            TicketRisk.MODERATE.value
            if by_type.get(DiscrepancyType.UNTRACKED_DEVICE.value, 0) > 0
            or len(discrepancies) >= 5
            else TicketRisk.LOW.value
        )
        priority = (
            TicketPriority.HIGH.value
            if by_type.get(DiscrepancyType.UNTRACKED_DEVICE.value, 0) > 0
            else TicketPriority.MEDIUM.value
        )

        return ItsmTicketRequest(
            ticket_id=resolved_ticket_id,
            workflow_type=ItsmWorkflowType.SHADOW_IT_ONBOARDING,
            title=title,
            description=description,
            category="Inventory Reconciliation / Shadow IT",
            risk=risk,
            priority=priority,
            implementation_plan="\n".join(impl_lines),
            backout_plan="\n".join(backout_lines),
            cmdb_ci=primary_ci,
            affected_cis=affected_cis,
            site_ids=site_ids,
            item_ids=item_ids,
            artifact_id=artifact_id,
            artifact_sha256=report_sha,
            approval_status=approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            labels=[
                "sot-validator",
                "shadow-it",
                "onboarding",
                "reconciliation",
                *(f"site:{s}" for s in site_ids),
            ],
            project_key=project_key or self.default_project_key,
            issue_type="Task",
            created_at=self._resolve_timestamp(scoped_report.generated_at),
            dry_run=True,
            metadata={
                "total_discrepancies": len(discrepancies),
                "summary_by_type": dict(by_type),
                "summary_by_site": dict(scoped_report.summary_by_site),
                "onboarding_sql": onboarding_sql,
                "onboarding_csv": onboarding_csv,
            },
        )

    from_reconciliation_report = build_onboarding_ticket
    build_shadow_it_onboarding_ticket = build_onboarding_ticket

    # ------------------------------------------------------------------
    # Workflow 4: APC UPS Battery / Hardware Incident Alert
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_ups_report(
        report: (
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ),
    ) -> UpsFleetHealthReport:
        if isinstance(report, UpsFleetHealthReport):
            return report
        if isinstance(report, UpsHealthRecord):
            return UpsFleetHealthReport(
                records=[report], evaluated_at=report.evaluated_at
            )
        if isinstance(report, Mapping):
            if "records" in report:
                return UpsFleetHealthReport.from_dict(report)
            if "equipment_id" in report and "status" in report:
                rec = UpsHealthRecord.from_dict(report)
                return UpsFleetHealthReport(
                    records=[rec], evaluated_at=rec.evaluated_at
                )
        if isinstance(report, Sequence) and not isinstance(report, (str, bytes)):
            recs = [
                r if isinstance(r, UpsHealthRecord) else UpsHealthRecord.from_dict(r)
                for r in report
            ]
            eval_at = next(
                (r.evaluated_at for r in recs if r.evaluated_at is not None),
                None,
            )
            return UpsFleetHealthReport(records=recs, evaluated_at=eval_at)
        raise TypeError(
            f"Unsupported UPS health report input: {type(report)!r}"
        )

    def build_ups_incident_ticket(
        self,
        report: (
            UpsFleetHealthReport
            | UpsHealthRecord
            | Sequence[UpsHealthRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ),
        *,
        ticket_id: Optional[str] = None,
        site_id: Optional[str] = None,
        include_warnings: bool = True,
        approval_status: TicketApprovalStatus | str = TicketApprovalStatus.PENDING,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        project_key: Optional[str] = None,
        cmdb_ci: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Build an APC UPS Battery / Hardware Incident Alert ticket from a UpsFleetHealthReport."""
        fleet_report = self._coerce_ups_report(report)

        candidate_records = fleet_report.records
        if site_id is not None:
            clean_site = site_id.strip()
            candidate_records = [
                r for r in candidate_records if r.site_id == clean_site
            ]

        actionable_records: list[UpsHealthRecord] = []
        for rec in candidate_records:
            if rec.status in (UpsHealthStatus.CRITICAL, UpsHealthStatus.UNREACHABLE):
                actionable_records.append(rec)
            elif include_warnings and (
                rec.status is UpsHealthStatus.WARNING or bool(rec.advisories)
            ):
                actionable_records.append(rec)

        actionable_records.sort(
            key=lambda r: (
                0
                if r.status is UpsHealthStatus.CRITICAL
                else (
                    1
                    if r.status is UpsHealthStatus.WARNING
                    else (2 if r.status is UpsHealthStatus.UNREACHABLE else 3)
                ),
                r.site_id,
                r.equipment_id,
            )
        )

        scoped_fleet = UpsFleetHealthReport(
            records=actionable_records,
            evaluated_at=fleet_report.evaluated_at,
        )
        report_sha = compute_artifact_sha256(scoped_fleet)

        site_ids = sorted({r.site_id for r in actionable_records})
        if not site_ids and site_id:
            site_ids = [site_id.strip()]
        item_ids = [r.equipment_id for r in actionable_records]

        all_advisories: list[str] = []
        seen_adv: set[str] = set()
        for rec in actionable_records:
            for adv in rec.advisories:
                if adv not in seen_adv:
                    seen_adv.add(adv)
                    all_advisories.append(adv)

        primary_ci = (
            cmdb_ci.strip()
            if cmdb_ci and cmdb_ci.strip()
            else (
                actionable_records[0].name
                if len(actionable_records) == 1
                else (site_ids[0] if len(site_ids) == 1 else self.default_cmdb_ci)
            )
        )
        affected_cis = [
            primary_ci,
            *(r.name for r in actionable_records),
            *item_ids,
            *site_ids,
        ]

        has_critical = any(
            r.status is UpsHealthStatus.CRITICAL
            or r.on_battery
            or r.needs_battery_replacement
            or UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED.value in r.advisories
            or UpsAdvisoryCode.ON_BATTERY_ALERT.value in r.advisories
            or UpsAdvisoryCode.CRITICAL_RUNTIME.value in r.advisories
            for r in actionable_records
        )
        risk = (
            TicketRisk.CRITICAL.value
            if has_critical
            else TicketRisk.HIGH.value
        )
        priority = (
            TicketPriority.CRITICAL.value
            if has_critical
            else TicketPriority.HIGH.value
        )

        impl_lines: list[str] = [
            f"1. Dispatch facility/field operations for {len(actionable_records)} APC UPS unit(s) with active PowerNet-MIB health advisories:",
        ]
        for rec in actionable_records:
            adv_str = ", ".join(rec.advisories) if rec.advisories else rec.status.value
            metrics_parts: list[str] = []
            if rec.model:
                metrics_parts.append(f"model={rec.model}")
            if rec.ip_address:
                metrics_parts.append(f"ip={rec.ip_address}")
            if rec.runtime_remaining_minutes is not None:
                metrics_parts.append(
                    f"runtime={rec.runtime_remaining_minutes:.1f}min"
                )
            if rec.temperature_celsius is not None:
                metrics_parts.append(f"temp={rec.temperature_celsius:.1f}C")
            if rec.output_load_pct is not None:
                metrics_parts.append(f"load={rec.output_load_pct:.1f}%")
            if rec.output_status:
                metrics_parts.append(f"output={rec.output_status}")
            metrics_suffix = (
                f" ({', '.join(metrics_parts)})" if metrics_parts else ""
            )
            impl_lines.append(
                f"   - [{rec.site_id}] {rec.name} ({rec.equipment_id}) [{rec.status.value}]: "
                f"advisories=[{adv_str}]{metrics_suffix}"
            )
            if rec.needs_battery_replacement or (
                UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED.value in rec.advisories
            ):
                impl_lines.append(
                    f"     * Action: Replace hot-swappable APC RBC battery cartridge on {rec.name} and run UPS self-test."
                )
            if rec.on_battery or (
                UpsAdvisoryCode.ON_BATTERY_ALERT.value in rec.advisories
            ):
                impl_lines.append(
                    f"     * Action: Verify utility AC input feed for {rec.name} (fail cause: {rec.input_line_fail_cause or 'unknown'})."
                )
            if rec.is_low_runtime:
                impl_lines.append(
                    f"     * Action: Inspect battery capacity and shed non-critical load on {rec.name}."
                )
            if rec.is_high_temperature:
                impl_lines.append(
                    f"     * Action: Check MDF/IDF room HVAC and UPS fan airflow for {rec.name}."
                )

        impl_lines.append(
            "2. Run post-maintenance SNMP PowerNet-MIB verification (`sot-validator ups-health`) to confirm HEALTHY status."
        )

        backout_lines: list[str] = [
            "1. If APC UPS battery module replacement causes a fault alarm, engage maintenance bypass (if equipped) or reinstall prior battery tray while keeping utility AC online.",
            "2. Escalate to APC/Schneider Electric field service if hardware fault persists (`upsBasicBatteryStatus = batteryInFaultCondition(4)`).",
        ]

        site_label = (
            site_ids[0]
            if len(site_ids) == 1
            else f"{len(site_ids) or 1} site(s)"
        )
        title = (
            f"[APC UPS Hardware Alert] {len(actionable_records)} UPS unit(s) require maintenance/intervention "
            f"at {site_label} ({', '.join(all_advisories[:3]) or 'HEALTH_ALERT'})"
        )
        description = (
            f"Phase 6 APC UPS Fleet Health Telemetry Incident / Maintenance Request.\n"
            f"Health Report SHA-256: {report_sha}\n"
            f"Actionable Units: {len(actionable_records)} "
            f"(Critical: {scoped_fleet.critical_count}, Warning: {scoped_fleet.warning_count}, "
            f"Unreachable: {scoped_fleet.unreachable_count}, Healthy Filtered Out: {fleet_report.healthy_count})\n"
            f"Battery Replacement Needed: {len(scoped_fleet.battery_replacement_units)} | "
            f"Low Runtime: {len(scoped_fleet.low_runtime_units)} | "
            f"On Battery: {len(scoped_fleet.on_battery_units)} | "
            f"Thermal Alerts: {len(scoped_fleet.thermal_alert_units)}\n"
            f"Active Advisory Codes: {', '.join(all_advisories) if all_advisories else 'NONE'}\n"
            f"Sites Affected: {', '.join(site_ids) if site_ids else 'N/A'}"
        )

        artifact_id = f"ups-health-{report_sha[:12]}"
        resolved_ticket_id = (
            ticket_id.strip()
            if ticket_id and ticket_id.strip()
            else _deterministic_ticket_id(
                "INC",
                ItsmWorkflowType.UPS_HARDWARE_INCIDENT,
                report_sha,
            )
        )

        return ItsmTicketRequest(
            ticket_id=resolved_ticket_id,
            workflow_type=ItsmWorkflowType.UPS_HARDWARE_INCIDENT,
            title=title,
            description=description,
            category="Facility Power / APC UPS",
            risk=risk,
            priority=priority,
            implementation_plan="\n".join(impl_lines),
            backout_plan="\n".join(backout_lines),
            cmdb_ci=primary_ci,
            affected_cis=affected_cis,
            site_ids=site_ids,
            item_ids=item_ids,
            artifact_id=artifact_id,
            artifact_sha256=report_sha,
            approval_status=approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            labels=[
                "sot-validator",
                "apc-ups",
                "hardware-incident",
                *(adv.lower().replace("_", "-") for adv in all_advisories),
                *(f"site:{s}" for s in site_ids),
            ],
            project_key=project_key or self.default_project_key,
            issue_type="Incident",
            created_at=self._resolve_timestamp(fleet_report.evaluated_at),
            dry_run=True,
            metadata={
                "actionable_unit_count": len(actionable_records),
                "healthy_filtered_count": fleet_report.healthy_count,
                "critical_count": scoped_fleet.critical_count,
                "warning_count": scoped_fleet.warning_count,
                "unreachable_count": scoped_fleet.unreachable_count,
                "battery_replacement_count": len(
                    scoped_fleet.battery_replacement_units
                ),
                "low_runtime_count": len(scoped_fleet.low_runtime_units),
                "thermal_alert_count": len(scoped_fleet.thermal_alert_units),
                "on_battery_count": len(scoped_fleet.on_battery_units),
                "advisories": all_advisories,
                "units": [r.to_dict() for r in actionable_records],
            },
        )

    from_ups_health_report = build_ups_incident_ticket
    build_ups_hardware_incident = build_ups_incident_ticket

    def build_ups_incident_tickets(
        self,
        report: UpsFleetHealthReport | Sequence[UpsHealthRecord] | Mapping[str, Any],
        *,
        per_site: bool = False,
        include_warnings: bool = True,
        **kwargs: Any,
    ) -> list[ItsmTicketRequest]:
        """Build individual APC UPS incident tickets per actionable unit or per site."""
        fleet_report = self._coerce_ups_report(report)
        actionable = [
            r
            for r in fleet_report.records
            if r.status in (UpsHealthStatus.CRITICAL, UpsHealthStatus.UNREACHABLE)
            or (include_warnings and (r.status is UpsHealthStatus.WARNING or bool(r.advisories)))
        ]
        if not actionable:
            return []
        if per_site:
            by_site: dict[str, list[UpsHealthRecord]] = {}
            for rec in actionable:
                by_site.setdefault(rec.site_id, []).append(rec)
            return [
                self.build_ups_incident_ticket(
                    site_recs,
                    site_id=s_id,
                    include_warnings=include_warnings,
                    **kwargs,
                )
                for s_id, site_recs in sorted(by_site.items())
            ]
        return [
            self.build_ups_incident_ticket(
                rec,
                include_warnings=include_warnings,
                **kwargs,
            )
            for rec in actionable
        ]

    # ------------------------------------------------------------------
    # Unified Dispatch & Provider Formatters
    # ------------------------------------------------------------------

    def build_ticket(
        self,
        artifact: Any,
        workflow_type: Optional[ItsmWorkflowType | str] = None,
        **kwargs: Any,
    ) -> ItsmTicketRequest:
        """Auto-detect or dispatch ticket generation for any supported Phase 2-6 workflow artifact."""
        resolved_wf: Optional[ItsmWorkflowType] = (
            _coerce_workflow_type(workflow_type)
            if workflow_type is not None
            else None
        )
        if resolved_wf is None:
            if isinstance(artifact, RemediationApprovalManifest):
                resolved_wf = ItsmWorkflowType.QUARANTINE_DECOMMISSION
            elif isinstance(artifact, PortReclamationPlan):
                resolved_wf = ItsmWorkflowType.PORT_RECLAMATION
            elif isinstance(artifact, ReconciliationReport):
                resolved_wf = ItsmWorkflowType.SHADOW_IT_ONBOARDING
            elif isinstance(artifact, (UpsFleetHealthReport, UpsHealthRecord)):
                resolved_wf = ItsmWorkflowType.UPS_HARDWARE_INCIDENT
            elif isinstance(artifact, Mapping):
                if "entries" in artifact or "manifest_id" in artifact:
                    resolved_wf = ItsmWorkflowType.QUARANTINE_DECOMMISSION
                elif "candidates" in artifact or "plan_id" in artifact:
                    resolved_wf = ItsmWorkflowType.PORT_RECLAMATION
                elif "discrepancies" in artifact:
                    resolved_wf = ItsmWorkflowType.SHADOW_IT_ONBOARDING
                elif "records" in artifact or "equipment_id" in artifact:
                    resolved_wf = ItsmWorkflowType.UPS_HARDWARE_INCIDENT

        if resolved_wf is ItsmWorkflowType.QUARANTINE_DECOMMISSION:
            return self.build_quarantine_ticket(artifact, **kwargs)
        if resolved_wf is ItsmWorkflowType.PORT_RECLAMATION:
            return self.build_port_reclamation_ticket(artifact, **kwargs)
        if resolved_wf is ItsmWorkflowType.SHADOW_IT_ONBOARDING:
            return self.build_onboarding_ticket(artifact, **kwargs)
        if resolved_wf is ItsmWorkflowType.UPS_HARDWARE_INCIDENT:
            return self.build_ups_incident_ticket(artifact, **kwargs)

        raise ValueError(
            f"Could not determine ITSM workflow type for artifact {type(artifact)!r}"
        )

    @staticmethod
    def format_servicenow(
        ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> dict[str, Any]:
        """Format an ItsmTicketRequest into a ServiceNow change_request / incident dictionary."""
        ticket_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return ticket_obj.to_servicenow_payload()

    @staticmethod
    def format_jira(
        ticket: ItsmTicketRequest | Mapping[str, Any],
        *,
        project_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """Format an ItsmTicketRequest into a Jira issue creation dictionary."""
        ticket_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return ticket_obj.to_jira_payload(project_key=project_key)

    @staticmethod
    def format_webhook(
        ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> dict[str, Any]:
        """Format an ItsmTicketRequest into a generic webhook payload dictionary."""
        ticket_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return ticket_obj.to_webhook_payload()


# ---------------------------------------------------------------------------
# Protocol-Based Offline ITSM Sinks & Webhook Serializer
# ---------------------------------------------------------------------------


@runtime_checkable
class ItsmSink(Protocol):
    """Protocol for offline-capable ITSM change-ticket governance sinks."""

    def submit_ticket(self, ticket: ItsmTicketRequest) -> ItsmTicketRequest:
        """Persist or emit a change ticket request and return the stored ticket."""
        ...

    def get_ticket(self, ticket_id: str) -> Optional[ItsmTicketRequest]:
        """Retrieve a stored ticket by its ticket_id, or None if not found."""
        ...

    def list_tickets(
        self,
        workflow_type: Optional[ItsmWorkflowType | str] = None,
        approval_status: Optional[TicketApprovalStatus | str] = None,
    ) -> list[ItsmTicketRequest]:
        """List stored tickets, optionally filtered by workflow_type and/or approval_status."""
        ...

    def update_approval_status(
        self,
        ticket_id: str,
        approval_status: TicketApprovalStatus | str,
        *,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        """Transition a stored ticket's approval status and return the updated ticket."""
        ...


class ItsmWebhookSerializer:
    """Deterministic JSON serializer for ServiceNow, Jira, and generic ITSM webhooks."""

    @staticmethod
    def format_payload(
        ticket: ItsmTicketRequest | Mapping[str, Any],
        provider: ItsmProvider | str = ItsmProvider.WEBHOOK,
        *,
        project_key: Optional[str] = None,
    ) -> dict[str, Any]:
        ticket_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return ticket_obj.format_for_provider(provider, project_key=project_key)

    @classmethod
    def serialize(
        cls,
        ticket: ItsmTicketRequest | Mapping[str, Any],
        provider: ItsmProvider | str = ItsmProvider.WEBHOOK,
        *,
        project_key: Optional[str] = None,
        indent: Optional[int] = 2,
    ) -> str:
        payload = cls.format_payload(
            ticket, provider=provider, project_key=project_key
        )
        return json.dumps(payload, indent=indent, sort_keys=True)


class InMemoryItsmSink:
    """In-memory ITSM ticket governance sink for offline execution and unit testing."""

    def __init__(
        self,
        tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, ItsmTicketRequest | Mapping[str, Any]]
        ] = None,
    ) -> None:
        self._tickets_by_id: dict[str, ItsmTicketRequest] = {}
        if tickets is not None:
            if isinstance(tickets, Mapping):
                for key, raw in tickets.items():
                    t_obj = (
                        raw
                        if isinstance(raw, ItsmTicketRequest)
                        else ItsmTicketRequest.from_dict(
                            {**raw, "ticket_id": raw.get("ticket_id", key)}
                        )
                    )
                    self._tickets_by_id[t_obj.ticket_id] = t_obj
            else:
                for raw in tickets:
                    t_obj = (
                        raw
                        if isinstance(raw, ItsmTicketRequest)
                        else ItsmTicketRequest.from_dict(raw)
                    )
                    self._tickets_by_id[t_obj.ticket_id] = t_obj

    @property
    def tickets(self) -> list[ItsmTicketRequest]:
        """Return all stored tickets in insertion order."""
        return list(self._tickets_by_id.values())

    def submit_ticket(
        self, ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> ItsmTicketRequest:
        t_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        self._tickets_by_id[t_obj.ticket_id] = t_obj
        return t_obj

    emit = submit_ticket
    create_ticket = submit_ticket

    def get_ticket(self, ticket_id: str) -> Optional[ItsmTicketRequest]:
        if not isinstance(ticket_id, str) or not ticket_id.strip():
            return None
        return self._tickets_by_id.get(ticket_id.strip())

    def list_tickets(
        self,
        workflow_type: Optional[ItsmWorkflowType | str] = None,
        approval_status: Optional[TicketApprovalStatus | str] = None,
    ) -> list[ItsmTicketRequest]:
        resolved_wf = (
            _coerce_workflow_type(workflow_type)
            if workflow_type is not None
            else None
        )
        resolved_status = (
            _coerce_ticket_approval_status(approval_status)
            if approval_status is not None
            else None
        )
        results: list[ItsmTicketRequest] = []
        for ticket in self._tickets_by_id.values():
            if resolved_wf is not None and ticket.workflow_type is not resolved_wf:
                continue
            if (
                resolved_status is not None
                and ticket.approval_status is not resolved_status
            ):
                continue
            results.append(ticket)
        return results

    def update_approval_status(
        self,
        ticket_id: str,
        approval_status: TicketApprovalStatus | str,
        *,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        ticket = self.get_ticket(ticket_id)
        if ticket is None:
            raise KeyError(f"ITSM ticket {ticket_id!r} not found in sink")
        ticket.approval_status = _coerce_ticket_approval_status(approval_status)
        if approved_by is not None:
            ticket.approved_by = approved_by.strip() or None
        if approved_at is not None:
            ticket.approved_at = normalize_utc_datetime(
                approved_at, field_name="approved_at"
            )
        elif ticket.approval_status in (
            TicketApprovalStatus.APPROVED,
            TicketApprovalStatus.SCHEDULED,
        ) and ticket.approved_at is None:
            ticket.approved_at = datetime.now(timezone.utc)
        if artifact_sha256 is not None:
            ticket.artifact_sha256 = artifact_sha256.strip().lower() or None
        return ticket

    def approve_ticket(
        self,
        ticket_id: str,
        *,
        approved_by: str = "cab-approver",
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        return self.update_approval_status(
            ticket_id,
            TicketApprovalStatus.APPROVED,
            approved_by=approved_by,
            approved_at=approved_at,
            artifact_sha256=artifact_sha256,
        )

    def reject_ticket(
        self,
        ticket_id: str,
        *,
        approved_by: str = "cab-approver",
        approved_at: Optional[datetime | str] = None,
    ) -> ItsmTicketRequest:
        return self.update_approval_status(
            ticket_id,
            TicketApprovalStatus.REJECTED,
            approved_by=approved_by,
            approved_at=approved_at,
        )

    def clear(self) -> None:
        self._tickets_by_id.clear()


class JsonFileItsmSink(InMemoryItsmSink):
    """Offline ITSM change-ticket sink backed by a local JSON or JSON Lines file."""

    def __init__(
        self,
        file_path: Path | str,
        *,
        jsonl: bool = False,
        indent: Optional[int] = 2,
    ) -> None:
        super().__init__()
        if isinstance(file_path, Path):
            self.file_path = file_path
        elif isinstance(file_path, str) and file_path.strip():
            self.file_path = Path(file_path.strip())
        else:
            raise ValueError("file_path must be a non-empty Path or string")
        self.jsonl = bool(jsonl)
        self.indent = indent
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        if not self.file_path.exists():
            return
        raw_text = self.file_path.read_text(encoding="utf-8").strip()
        if not raw_text:
            return
        self._tickets_by_id.clear()
        if self.jsonl:
            for line in raw_text.splitlines():
                stripped = line.strip()
                if stripped:
                    ticket = ItsmTicketRequest.from_json(stripped)
                    self._tickets_by_id[ticket.ticket_id] = ticket
            return

        parsed = json.loads(raw_text)
        if isinstance(parsed, list):
            for item in parsed:
                ticket = ItsmTicketRequest.from_dict(item)
                self._tickets_by_id[ticket.ticket_id] = ticket
        elif isinstance(parsed, Mapping):
            if "tickets" in parsed and isinstance(parsed["tickets"], list):
                for item in parsed["tickets"]:
                    ticket = ItsmTicketRequest.from_dict(item)
                    self._tickets_by_id[ticket.ticket_id] = ticket
            elif "ticket_id" in parsed:
                ticket = ItsmTicketRequest.from_dict(parsed)
                self._tickets_by_id[ticket.ticket_id] = ticket

    def _flush_to_disk(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        if self.jsonl:
            lines = [
                t.to_json(indent=None) for t in self._tickets_by_id.values()
            ]
            content = "\n".join(lines) + ("\n" if lines else "")
            self.file_path.write_text(content, encoding="utf-8")
            return

        payload = [t.to_dict() for t in self._tickets_by_id.values()]
        self.file_path.write_text(
            json.dumps(payload, indent=self.indent),
            encoding="utf-8",
        )

    def submit_ticket(
        self, ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> ItsmTicketRequest:
        self._load_from_disk()
        stored = super().submit_ticket(ticket)
        self._flush_to_disk()
        return stored

    emit = submit_ticket
    create_ticket = submit_ticket

    def get_ticket(self, ticket_id: str) -> Optional[ItsmTicketRequest]:
        self._load_from_disk()
        return super().get_ticket(ticket_id)

    def list_tickets(
        self,
        workflow_type: Optional[ItsmWorkflowType | str] = None,
        approval_status: Optional[TicketApprovalStatus | str] = None,
    ) -> list[ItsmTicketRequest]:
        self._load_from_disk()
        return super().list_tickets(
            workflow_type=workflow_type, approval_status=approval_status
        )

    def update_approval_status(
        self,
        ticket_id: str,
        approval_status: TicketApprovalStatus | str,
        *,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        self._load_from_disk()
        updated = super().update_approval_status(
            ticket_id,
            approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            artifact_sha256=artifact_sha256,
        )
        self._flush_to_disk()
        return updated

    def read_tickets(self) -> list[ItsmTicketRequest]:
        """Reload and return all tickets persisted in file_path."""
        self._load_from_disk()
        return self.tickets


class WebhookItsmSink(InMemoryItsmSink):
    """Offline ITSM webhook sink that serializes submitted tickets into provider webhook payloads."""

    def __init__(
        self,
        *,
        provider: ItsmProvider | str = ItsmProvider.WEBHOOK,
        project_key: str = "NETOPS",
        callback: Optional[Callable[[dict[str, Any]], None]] = None,
        output_path: Optional[Path | str] = None,
    ) -> None:
        super().__init__()
        self.provider = _coerce_provider(provider)
        self.project_key = _require_non_empty_str(
            project_key, "project_key"
        ).strip()
        self.callback = callback
        self.output_path = Path(output_path) if output_path is not None else None
        self.payloads: list[dict[str, Any]] = []
        self.serialized_payloads: list[str] = []

    def submit_ticket(
        self, ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> ItsmTicketRequest:
        stored = super().submit_ticket(ticket)
        self._record_webhook_payload(stored)
        return stored

    emit = submit_ticket
    create_ticket = submit_ticket

    def update_approval_status(
        self,
        ticket_id: str,
        approval_status: TicketApprovalStatus | str,
        *,
        approved_by: Optional[str] = None,
        approved_at: Optional[datetime | str] = None,
        artifact_sha256: Optional[str] = None,
    ) -> ItsmTicketRequest:
        updated = super().update_approval_status(
            ticket_id,
            approval_status,
            approved_by=approved_by,
            approved_at=approved_at,
            artifact_sha256=artifact_sha256,
        )
        self._record_webhook_payload(updated)
        return updated

    def _record_webhook_payload(self, ticket: ItsmTicketRequest) -> None:
        payload = ItsmWebhookSerializer.format_payload(
            ticket, provider=self.provider, project_key=self.project_key
        )
        serialized = ItsmWebhookSerializer.serialize(
            ticket, provider=self.provider, project_key=self.project_key
        )
        self.payloads.append(payload)
        self.serialized_payloads.append(serialized)
        if self.callback is not None:
            self.callback(payload)
        if self.output_path is not None:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.output_path.write_text(
                json.dumps(self.payloads, indent=2),
                encoding="utf-8",
            )


# ---------------------------------------------------------------------------
# ITSM Approval Gate Verifier
# ---------------------------------------------------------------------------


class ItsmGateVerificationError(RemediationExecutionError):
    """Raised when an ITSM change ticket is missing, unapproved, or fails SHA-256 digest verification."""


@dataclass(frozen=True)
class ItsmGateVerificationResult:
    """Structured result of verifying an ITSM change ticket against a remediation manifest or plan."""

    approved: bool
    ticket_id: str
    approval_status: str
    expected_sha256: Optional[str] = None
    actual_sha256: Optional[str] = None
    digest_matches: bool = False
    reason: str = ""
    verified_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    ticket: Optional[ItsmTicketRequest] = None

    @property
    def is_approved(self) -> bool:
        """Alias for approved."""
        return self.approved

    @property
    def valid(self) -> bool:
        """Alias for approved."""
        return self.approved

    def __bool__(self) -> bool:
        return self.approved

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "ticket_id": self.ticket_id,
            "approval_status": self.approval_status,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "digest_matches": self.digest_matches,
            "reason": self.reason,
            "verified_at": _format_optional_datetime(self.verified_at),
            "ticket": self.ticket.to_dict() if self.ticket is not None else None,
        }


class ItsmGateVerifier:
    """Verifies that a change ticket is APPROVED (or SCHEDULED) and matches the target SHA-256 digest."""

    def __init__(
        self,
        sink: Optional[ItsmSink] = None,
        *,
        tickets: Optional[
            Sequence[ItsmTicketRequest | Mapping[str, Any]]
            | Mapping[str, ItsmTicketRequest | Mapping[str, Any]]
        ] = None,
        allow_scheduled: bool = False,
        raise_on_failure: bool = False,
    ) -> None:
        if sink is not None:
            self.sink: ItsmSink = sink
            if tickets is not None:
                temp_sink = InMemoryItsmSink(tickets)
                for t in temp_sink.tickets:
                    self.sink.submit_ticket(t)
        else:
            self.sink = InMemoryItsmSink(tickets)
        self.allow_scheduled = bool(allow_scheduled)
        self.raise_on_failure = bool(raise_on_failure)

    def register_ticket(
        self, ticket: ItsmTicketRequest | Mapping[str, Any]
    ) -> ItsmTicketRequest:
        """Register or update a ticket in the verifier's backing sink."""
        t_obj = (
            ticket
            if isinstance(ticket, ItsmTicketRequest)
            else ItsmTicketRequest.from_dict(ticket)
        )
        return self.sink.submit_ticket(t_obj)

    def _resolve_ticket(
        self,
        ticket_or_id: Optional[ItsmTicketRequest | Mapping[str, Any] | str],
        *,
        sink: Optional[ItsmSink] = None,
    ) -> tuple[Optional[ItsmTicketRequest], str]:
        if ticket_or_id is None:
            return None, ""
        if isinstance(ticket_or_id, ItsmTicketRequest):
            return ticket_or_id, ticket_or_id.ticket_id
        if isinstance(ticket_or_id, Mapping):
            t_obj = ItsmTicketRequest.from_dict(ticket_or_id)
            return t_obj, t_obj.ticket_id
        if isinstance(ticket_or_id, str):
            clean_id = ticket_or_id.strip()
            if not clean_id:
                return None, ""
            active_sink = sink if sink is not None else self.sink
            found = active_sink.get_ticket(clean_id)
            return found, clean_id
        raise TypeError(f"Unsupported ticket reference: {type(ticket_or_id)!r}")

    @staticmethod
    def _resolve_expected_digest(
        expected_sha256: Optional[Any] = None,
        *,
        manifest: Optional[Any] = None,
        plan: Optional[Any] = None,
        artifact: Optional[Any] = None,
    ) -> tuple[Optional[str], Optional[str]]:
        """Return (expected_sha256, integrity_error_message)."""
        target = (
            manifest
            if manifest is not None
            else (plan if plan is not None else artifact)
        )
        if target is None and expected_sha256 is not None and not isinstance(
            expected_sha256, str
        ):
            target = expected_sha256
            expected_sha256 = None

        if isinstance(target, RemediationApprovalManifest):
            if not target.verify_digest():
                return (
                    target.manifest_sha256,
                    f"Manifest {target.manifest_id!r} failed SHA-256 integrity verification",
                )
            if expected_sha256 is None:
                expected_sha256 = target.manifest_sha256
        elif target is not None and expected_sha256 is None:
            expected_sha256 = compute_artifact_sha256(target)

        if isinstance(expected_sha256, str) and expected_sha256.strip():
            return expected_sha256.strip().lower(), None
        return None, None

    def verify_change_ticket_approved(
        self,
        ticket_or_id: Optional[ItsmTicketRequest | Mapping[str, Any] | str],
        expected_sha256: Optional[Any] = None,
        *,
        manifest: Optional[Any] = None,
        plan: Optional[Any] = None,
        artifact: Optional[Any] = None,
        allow_scheduled: Optional[bool] = None,
        raise_on_failure: Optional[bool] = None,
        sink: Optional[ItsmSink] = None,
    ) -> ItsmGateVerificationResult:
        """Verify that a change ticket is APPROVED (or SCHEDULED) and matches the expected SHA-256 digest."""
        effective_allow_scheduled = (
            self.allow_scheduled if allow_scheduled is None else bool(allow_scheduled)
        )
        effective_raise = (
            self.raise_on_failure if raise_on_failure is None else bool(raise_on_failure)
        )
        now = datetime.now(timezone.utc)

        resolved_expected_sha, integrity_error = self._resolve_expected_digest(
            expected_sha256,
            manifest=manifest,
            plan=plan,
            artifact=artifact,
        )

        ticket, lookup_id = self._resolve_ticket(ticket_or_id, sink=sink)
        if ticket is None:
            reason = f"Change ticket {lookup_id!r} not found in ITSM governance sink"
            result = ItsmGateVerificationResult(
                approved=False,
                ticket_id=lookup_id,
                approval_status="MISSING",
                expected_sha256=resolved_expected_sha,
                actual_sha256=None,
                digest_matches=False,
                reason=reason,
                verified_at=now,
                ticket=None,
            )
            if effective_raise:
                raise ItsmGateVerificationError(reason)
            return result

        actual_sha = (
            ticket.artifact_sha256.strip().lower()
            if ticket.artifact_sha256 and ticket.artifact_sha256.strip()
            else None
        )

        if integrity_error is not None:
            result = ItsmGateVerificationResult(
                approved=False,
                ticket_id=ticket.ticket_id,
                approval_status=ticket.approval_status.value,
                expected_sha256=resolved_expected_sha,
                actual_sha256=actual_sha,
                digest_matches=False,
                reason=integrity_error,
                verified_at=now,
                ticket=ticket,
            )
            if effective_raise:
                raise ItsmGateVerificationError(integrity_error)
            return result

        allowed_statuses = {TicketApprovalStatus.APPROVED}
        if effective_allow_scheduled:
            allowed_statuses.add(TicketApprovalStatus.SCHEDULED)

        status_ok = ticket.approval_status in allowed_statuses

        if resolved_expected_sha is not None:
            digest_ok = bool(
                actual_sha is not None
                and hmac.compare_digest(actual_sha, resolved_expected_sha)
            )
        else:
            digest_ok = bool(actual_sha)

        if not status_ok:
            allowed_names = ", ".join(s.value for s in sorted(allowed_statuses, key=lambda x: x.value))
            reason = (
                f"Change ticket {ticket.ticket_id!r} has approval_status={ticket.approval_status.value!r}; "
                f"requires {allowed_names}"
            )
            result = ItsmGateVerificationResult(
                approved=False,
                ticket_id=ticket.ticket_id,
                approval_status=ticket.approval_status.value,
                expected_sha256=resolved_expected_sha,
                actual_sha256=actual_sha,
                digest_matches=digest_ok,
                reason=reason,
                verified_at=now,
                ticket=ticket,
            )
            if effective_raise:
                raise ItsmGateVerificationError(reason)
            return result

        if not digest_ok:
            if actual_sha is None:
                reason = (
                    f"Change ticket {ticket.ticket_id!r} is missing artifact_sha256 digest "
                    f"(expected {resolved_expected_sha!r})"
                )
            else:
                reason = (
                    f"Change ticket {ticket.ticket_id!r} SHA-256 digest mismatch: "
                    f"ticket has {actual_sha!r}, expected {resolved_expected_sha!r}"
                )
            result = ItsmGateVerificationResult(
                approved=False,
                ticket_id=ticket.ticket_id,
                approval_status=ticket.approval_status.value,
                expected_sha256=resolved_expected_sha,
                actual_sha256=actual_sha,
                digest_matches=False,
                reason=reason,
                verified_at=now,
                ticket=ticket,
            )
            if effective_raise:
                raise ItsmGateVerificationError(reason)
            return result

        ok_reason = (
            f"Change ticket {ticket.ticket_id!r} verified ({ticket.approval_status.value}, "
            f"sha256={actual_sha})"
        )
        return ItsmGateVerificationResult(
            approved=True,
            ticket_id=ticket.ticket_id,
            approval_status=ticket.approval_status.value,
            expected_sha256=resolved_expected_sha or actual_sha,
            actual_sha256=actual_sha,
            digest_matches=True,
            reason=ok_reason,
            verified_at=now,
            ticket=ticket,
        )

    def require_change_ticket_approved(
        self,
        ticket_or_id: Optional[ItsmTicketRequest | Mapping[str, Any] | str],
        expected_sha256: Optional[Any] = None,
        **kwargs: Any,
    ) -> ItsmGateVerificationResult:
        """Verify change ticket approval and always raise ItsmGateVerificationError on failure."""
        kwargs["raise_on_failure"] = True
        return self.verify_change_ticket_approved(
            ticket_or_id, expected_sha256, **kwargs
        )


__all__ = [
    "InMemoryItsmSink",
    "ItsmApprovalStatus",
    "ItsmGateVerificationError",
    "ItsmGateVerificationResult",
    "ItsmGateVerifier",
    "ItsmProvider",
    "ItsmSink",
    "ItsmTicketPayloadBuilder",
    "ItsmTicketRequest",
    "ItsmWebhookSerializer",
    "ItsmWorkflowType",
    "JsonFileItsmSink",
    "QuarantineReport",
    "TicketApprovalStatus",
    "TicketPriority",
    "TicketRisk",
    "WebhookItsmSink",
    "compute_artifact_sha256",
]
