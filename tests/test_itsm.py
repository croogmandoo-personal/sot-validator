"""Unit tests for Phase 6 ITSM Change-Ticket Governance Sink (ServiceNow, Jira, and Webhook)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from sot_validator.itsm import (
    InMemoryItsmSink,
    ItsmApprovalStatus,
    ItsmGateVerificationError,
    ItsmGateVerificationResult,
    ItsmGateVerifier,
    ItsmProvider,
    ItsmSink,
    ItsmTicketPayloadBuilder,
    ItsmTicketRequest,
    ItsmWebhookSerializer,
    ItsmWorkflowType,
    JsonFileItsmSink,
    QuarantineReport,
    TicketApprovalStatus,
    TicketPriority,
    TicketRisk,
    WebhookItsmSink,
    compute_artifact_sha256,
)
from sot_validator.models import ValidationClassification
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    DiscrepancyType,
    ReconciliationReport,
)
from sot_validator.remediation.executor import RemediationExecutionError
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
    QuarantinePolicy,
    RemediationApprovalManifest,
    RemediationOperation,
)
from sot_validator.signals.ups_health import (
    UpsAdvisoryCode,
    UpsFleetHealthReport,
    UpsHealthRecord,
    UpsHealthStatus,
)


FIXED_TIME = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)

SERVICENOW_REQUIRED_KEYS = {
    "short_description",
    "description",
    "category",
    "risk",
    "implementation_plan",
    "backout_plan",
    "cmdb_ci",
}

JIRA_REQUIRED_KEYS = {
    "project",
    "summary",
    "description",
    "issuetype",
    "priority",
    "labels",
}


def _make_quarantine_manifest() -> RemediationApprovalManifest:
    entries = [
        QuarantineManifestEntry(
            site_id="site-001",
            item_type="Equipment",
            item_id="eq-001-vm-01",
            name="win-legacy-01.corp.local",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.95,
            consecutive_stale_runs=5,
            stale_duration_days=45.0,
            target_operation=RemediationOperation.DECOMMISSION_VM_RECORD,
            graduation_status=QuarantineGraduationStatus.ELIGIBLE,
            approval_status=ApprovalStatus.APPROVED,
            reviewed_by="netops-lead",
            review_note="Verified powered off across all vCenters for 45 days",
            reviewed_at=FIXED_TIME,
        ),
        QuarantineManifestEntry(
            site_id="site-001",
            item_type="IPAddress",
            item_id="10.1.10.55",
            name="10.1.10.55",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.92,
            consecutive_stale_runs=4,
            stale_duration_days=38.0,
            target_operation=RemediationOperation.RECLAIM_STALE_IP,
            graduation_status=QuarantineGraduationStatus.ELIGIBLE,
            approval_status=ApprovalStatus.APPROVED,
            reviewed_by="netops-lead",
            reviewed_at=FIXED_TIME,
        ),
        QuarantineManifestEntry(
            site_id="site-001",
            item_type="Equipment",
            item_id="eq-001-ups-01",
            name="apc-ups-01.site001.local",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.90,
            consecutive_stale_runs=4,
            stale_duration_days=40.0,
            target_operation=RemediationOperation.EXEMPT_PROTECTED,
            graduation_status=QuarantineGraduationStatus.EXEMPT_PROTECTED,
            approval_status=ApprovalStatus.EXEMPT,
            exemption_reason="Protected critical infrastructure category: ups",
        ),
    ]
    return RemediationApprovalManifest(
        entries=entries,
        policy=QuarantinePolicy(
            min_consecutive_stale_runs=3,
            min_stale_days=30.0,
            min_confidence=0.85,
            protected_categories=("ups",),
        ),
        generated_at=FIXED_TIME,
        manifest_id="manifest-site001-q4",
    )


def _make_port_reclamation_plan(
    dialect: ExtremeCliDialect = ExtremeCliDialect.EXOS,
) -> PortReclamationPlan:
    candidates = (
        PortReclamationCandidate(
            port_id="port-sw01-10",
            device_id="dev-001-sw-01",
            port_name="1:10",
            site_id="site-001",
            device_hostname="exos-sw-01.site001.local",
            admin_status="up",
            oper_status="down",
            poe_status="delivering (7.5W)",
            vlan_id="10",
            description="Access Cubicle 104",
            inactive_runs=5,
            inactive_days=62.0,
            estimated_poe_watts_saved=7.5,
            dialect=dialect,
        ),
        PortReclamationCandidate(
            port_id="port-sw01-11",
            device_id="dev-001-sw-01",
            port_name="1:11",
            site_id="site-001",
            device_hostname="exos-sw-01.site001.local",
            admin_status="up",
            oper_status="down",
            poe_status="enabled (4.0W)",
            vlan_id="10",
            description="Access Cubicle 105",
            inactive_runs=4,
            inactive_days=48.0,
            estimated_poe_watts_saved=4.0,
            dialect=dialect,
        ),
    )
    blocked_ports = (
        BlockedPortRecord(
            port_id="port-sw01-48",
            device_id="dev-001-sw-01",
            port_name="1:48",
            site_id="site-001",
            device_hostname="exos-sw-01.site001.local",
            blocked=True,
            block_reason="LLDP neighbor exos-core-01 advertises bridge/router capability on uplink trunk",
            matched_rules=("lldp_neighbor_capability", "description_keyword:uplink"),
            admin_status="up",
            oper_status="down",
            vlan_id="1,10,20",
            description="UPLINK to Core Switch",
            inactive_runs=4,
            inactive_days=45.0,
        ),
    )
    return PortReclamationPlan(
        candidates=candidates,
        blocked_ports=blocked_ports,
        dialect=dialect,
        generated_at=FIXED_TIME,
        plan_id="port-plan-site001-sw01",
    )


def _make_reconciliation_report() -> ReconciliationReport:
    discrepancies = [
        DiscrepancyRecord(
            discrepancy_id="disc-site001-vm-01",
            discrepancy_type=DiscrepancyType.UNTRACKED_VM,
            site_id="site-001",
            observed_identifier="vm-9021",
            observed_ip="10.1.20.44",
            observed_mac="00:50:56:aa:bb:cc",
            observed_hostname="win-shadow-sql01.corp.local",
            source="vcenter",
            details="vcenter_instance=vc-east-01, vm_moref=vm-9021, guest_os=Windows Server 2022",
            recommended_onboarding_action="Insert untracked Windows VM into SoT equipment table",
        ),
        DiscrepancyRecord(
            discrepancy_id="disc-site001-dev-01",
            discrepancy_type=DiscrepancyType.UNTRACKED_DEVICE,
            site_id="site-001",
            observed_identifier="10.1.1.25",
            observed_ip="10.1.1.25",
            observed_mac="00:04:96:11:22:33",
            observed_hostname="exos-idf3-sw02.site001.local",
            source="snmp",
            details="vendor=Extreme_Networks, model=ExtremeSwitching_X440G2, role=access-switch",
            recommended_onboarding_action="Onboard untracked Extreme switch into network_devices",
        ),
        DiscrepancyRecord(
            discrepancy_id="disc-site001-ip-01",
            discrepancy_type=DiscrepancyType.UNTRACKED_IP,
            site_id="site-001",
            observed_identifier="10.1.30.88",
            observed_ip="10.1.30.88",
            observed_mac="00:1b:21:44:55:66",
            observed_hostname="filesvr-temp.site001.local",
            source="arp",
            details="subnet_id=sub-001-030, arp_source_device_id=dev-001-sw-01",
            recommended_onboarding_action="Register active /24 IP assignment in ip_arp_entries",
        ),
        DiscrepancyRecord(
            discrepancy_id="disc-site001-mismatch-01",
            discrepancy_type=DiscrepancyType.ATTRIBUTE_MISMATCH,
            site_id="site-001",
            observed_identifier="eq-001-srv-02",
            observed_ip="10.1.10.12",
            observed_mac="00:50:56:99:88:77",
            observed_hostname="win-app-02.corp.local",
            source="vcenter",
            sot_item_id="eq-001-srv-02",
            details="SoT MAC 00:50:56:00:00:11 differs from live vCenter MAC 00:50:56:99:88:77",
            recommended_onboarding_action="Update MAC address on eq-001-srv-02 in SoT",
        ),
    ]
    return ReconciliationReport(
        discrepancies=discrepancies,
        generated_at=FIXED_TIME,
    )


def _make_ups_health_report() -> UpsFleetHealthReport:
    records = [
        UpsHealthRecord(
            equipment_id="eq-001-ups-01",
            site_id="site-001",
            name="apc-ups-mdf-01.site001.local",
            status=UpsHealthStatus.CRITICAL,
            ip_address="10.1.1.50",
            vendor="APC",
            model="Smart-UPS RT 5000 XL",
            reachable=True,
            battery_status="batteryLow",
            battery_status_code=3,
            battery_replace_indicator=2,
            needs_battery_replacement=True,
            battery_capacity_pct=18.0,
            runtime_remaining_minutes=4.0,
            temperature_celsius=44.5,
            output_load_pct=78.0,
            output_status="onBattery",
            on_battery=True,
            input_line_fail_cause="blackout",
            is_low_runtime=True,
            is_high_temperature=True,
            advisories=[
                UpsAdvisoryCode.BATTERY_REPLACEMENT_NEEDED.value,
                UpsAdvisoryCode.ON_BATTERY_ALERT.value,
                UpsAdvisoryCode.CRITICAL_RUNTIME.value,
                UpsAdvisoryCode.HIGH_TEMP_WARNING.value,
            ],
            evaluated_at=FIXED_TIME,
        ),
        UpsHealthRecord(
            equipment_id="eq-001-ups-02",
            site_id="site-001",
            name="apc-ups-idf1-02.site001.local",
            status=UpsHealthStatus.WARNING,
            ip_address="10.1.1.51",
            vendor="APC",
            model="Smart-UPS 3000",
            reachable=True,
            battery_status="batteryNormal",
            battery_status_code=2,
            battery_replace_indicator=1,
            needs_battery_replacement=False,
            battery_capacity_pct=65.0,
            runtime_remaining_minutes=11.0,
            temperature_celsius=32.0,
            output_load_pct=62.0,
            output_status="onLine",
            on_battery=False,
            is_low_runtime=True,
            advisories=[UpsAdvisoryCode.LOW_RUNTIME_WARNING.value],
            evaluated_at=FIXED_TIME,
        ),
        UpsHealthRecord(
            equipment_id="eq-001-ups-03",
            site_id="site-001",
            name="apc-ups-healthy-03.site001.local",
            status=UpsHealthStatus.HEALTHY,
            ip_address="10.1.1.52",
            vendor="APC",
            model="Smart-UPS 2200",
            reachable=True,
            battery_status="batteryNormal",
            battery_status_code=2,
            battery_replace_indicator=1,
            needs_battery_replacement=False,
            battery_capacity_pct=100.0,
            runtime_remaining_minutes=48.0,
            temperature_celsius=26.0,
            output_load_pct=34.0,
            output_status="onLine",
            on_battery=False,
            advisories=[],
            evaluated_at=FIXED_TIME,
        ),
    ]
    return UpsFleetHealthReport(records=records, evaluated_at=FIXED_TIME)


# ---------------------------------------------------------------------------
# Workflow 1-4 Ticket Generation & ServiceNow / Jira Payload Formatting Tests
# ---------------------------------------------------------------------------


def test_workflow_1_quarantine_servicenow_and_jira_payload_formatting() -> None:
    manifest = _make_quarantine_manifest()
    assert QuarantineReport is RemediationApprovalManifest

    builder = ItsmTicketPayloadBuilder(
        default_project_key="NETOPS",
        evaluation_time=FIXED_TIME,
    )
    ticket = builder.build_quarantine_ticket(manifest)

    assert ticket.workflow_type is ItsmWorkflowType.QUARANTINE_DECOMMISSION
    assert ticket.artifact_id == "manifest-site001-q4"
    assert ticket.artifact_sha256 == manifest.manifest_sha256
    assert ticket.manifest_sha256 == manifest.manifest_sha256
    assert ticket.site_ids == ["site-001"]
    assert "eq-001-vm-01" in ticket.item_ids
    assert "10.1.10.55" in ticket.item_ids
    assert "eq-001-ups-01" not in ticket.item_ids  # Exempt entry excluded from actionable items
    assert manifest.manifest_sha256 in ticket.description
    assert "UPDATE equipment SET status = 'QUARANTINED_STALE'" in ticket.implementation_plan
    assert "UPDATE ip_arp_entries SET status = 'AVAILABLE_RECLAIMED'" in ticket.implementation_plan
    assert "Rollback SQL Script (rollback.sql):" in ticket.backout_plan

    # ServiceNow payload validation
    snow = ticket.to_servicenow_payload()
    assert SERVICENOW_REQUIRED_KEYS.issubset(snow.keys())
    assert snow["table"] == "change_request"
    assert snow["short_description"] == ticket.title
    assert snow["cmdb_ci"] == "site-001"
    assert snow["risk"] in ("moderate", "high")
    assert snow["u_artifact_sha256"] == manifest.manifest_sha256
    assert "BEGIN TRANSACTION;" in snow["implementation_plan"]
    assert "BEGIN TRANSACTION;" in snow["backout_plan"]

    # Jira payload validation
    jira = ticket.to_jira_payload(project_key="INFRA")
    assert JIRA_REQUIRED_KEYS.issubset(jira.keys())
    assert JIRA_REQUIRED_KEYS.issubset(jira["fields"].keys())
    assert jira["project"] == {"key": "INFRA"}
    assert jira["summary"] == ticket.title
    assert jira["issuetype"] == {"name": "Change"}
    assert jira["priority"]["name"] in ("Medium", "High", "Critical")
    assert "quarantine" in jira["labels"]
    assert manifest.manifest_sha256 in jira["description"]


def test_workflow_2_port_reclamation_servicenow_and_jira_payload_formatting() -> None:
    exos_plan = _make_port_reclamation_plan(dialect=ExtremeCliDialect.EXOS)
    builder = ItsmTicketPayloadBuilder(evaluation_time=FIXED_TIME)

    ticket = builder.build_port_reclamation_ticket(exos_plan)
    expected_sha = compute_artifact_sha256(exos_plan)

    assert ticket.workflow_type is ItsmWorkflowType.PORT_RECLAMATION
    assert ticket.artifact_id == "port-plan-site001-sw01"
    assert ticket.artifact_sha256 == expected_sha
    assert ticket.plan_sha256 == expected_sha
    assert ticket.cmdb_ci == "dev-001-sw-01"
    assert ticket.item_ids == ["port-sw01-10", "port-sw01-11"]
    assert ticket.metadata["estimated_poe_watts_saved"] == 11.5

    # Forward CLI commands & LLDP guard audit included
    assert "configure inline-power operator-limit 0 ports 1:10" in ticket.implementation_plan
    assert "disable ports 1:10" in ticket.implementation_plan
    assert "disable ports 1:11" in ticket.implementation_plan
    assert "LLDP Uplink Guard Audit: 1 port(s) protected/blocked" in ticket.implementation_plan
    assert "BLOCKED dev-001-sw-01:1:48" in ticket.implementation_plan
    assert "lldp_neighbor_capability" in ticket.implementation_plan

    # 1-command rollback & rollback script included
    assert (
        "enable ports 1:10; configure inline-power operator-limit 30000 ports 1:10"
        in ticket.backout_plan
    )
    assert (
        "enable ports 1:11; configure inline-power operator-limit 30000 ports 1:11"
        in ticket.backout_plan
    )

    # VOSS dialect ticket generation
    voss_ticket = builder.build_port_reclamation_ticket(
        exos_plan, dialect=ExtremeCliDialect.VOSS
    )
    assert "interface GigabitEthernet 1:10" in voss_ticket.implementation_plan
    assert "poe-shutdown" in voss_ticket.implementation_plan
    assert (
        "interface GigabitEthernet 1:10; no poe-shutdown; no shutdown; exit"
        in voss_ticket.backout_plan
    )

    # ServiceNow & Jira formatting
    snow = builder.format_servicenow(ticket)
    assert SERVICENOW_REQUIRED_KEYS.issubset(snow.keys())
    assert snow["category"] == "Network Switching / Extreme Networks"
    assert "disable ports 1:10" in snow["implementation_plan"]
    assert "enable ports 1:10" in snow["backout_plan"]

    jira = builder.format_jira(ticket)
    assert JIRA_REQUIRED_KEYS.issubset(jira.keys())
    assert "port-reclamation" in jira["labels"]
    assert "extreme-networks" in jira["labels"]


def test_workflow_3_shadow_it_onboarding_servicenow_and_jira_payload_formatting() -> None:
    recon_report = _make_reconciliation_report()
    builder = ItsmTicketPayloadBuilder(evaluation_time=FIXED_TIME)

    ticket = builder.build_onboarding_ticket(recon_report)

    assert ticket.workflow_type is ItsmWorkflowType.SHADOW_IT_ONBOARDING
    assert ticket.issue_type == "Task"
    assert ticket.site_ids == ["site-001"]
    assert len(ticket.item_ids) == 4
    assert "UNTRACKED_VM=1" in ticket.description
    assert "UNTRACKED_DEVICE=1" in ticket.description
    assert "UNTRACKED_IP=1" in ticket.description
    assert "ATTRIBUTE_MISMATCH=1" in ticket.description

    # Onboarding SQL & CSV templates embedded in implementation_plan
    assert "INSERT INTO equipment" in ticket.implementation_plan
    assert "win-shadow-sql01.corp.local" in ticket.implementation_plan
    assert "INSERT INTO network_devices" in ticket.implementation_plan
    assert "exos-idf3-sw02.site001.local" in ticket.implementation_plan
    assert "INSERT INTO ip_arp_entries" in ticket.implementation_plan
    assert "record_type,target_table,item_id" in ticket.implementation_plan

    # Backout DELETE statements embedded in backout_plan
    assert "DELETE FROM equipment WHERE equipment_id =" in ticket.backout_plan
    assert "DELETE FROM network_devices WHERE device_id =" in ticket.backout_plan
    assert "DELETE FROM ip_arp_entries WHERE ip_id =" in ticket.backout_plan

    snow = ticket.to_servicenow_payload()
    assert SERVICENOW_REQUIRED_KEYS.issubset(snow.keys())
    assert snow["category"] == "Inventory Reconciliation / Shadow IT"

    jira = ticket.to_jira_payload()
    assert JIRA_REQUIRED_KEYS.issubset(jira.keys())
    assert jira["issuetype"] == {"name": "Task"}
    assert "shadow-it" in jira["labels"]
    assert "onboarding" in jira["labels"]


def test_workflow_4_ups_hardware_incident_servicenow_and_jira_payload_formatting() -> None:
    ups_report = _make_ups_health_report()
    builder = ItsmTicketPayloadBuilder(evaluation_time=FIXED_TIME)

    ticket = builder.build_ups_incident_ticket(ups_report)

    assert ticket.workflow_type is ItsmWorkflowType.UPS_HARDWARE_INCIDENT
    assert ticket.issue_type == "Incident"
    assert ticket.risk == TicketRisk.CRITICAL.value
    assert ticket.priority == TicketPriority.CRITICAL.value
    # Healthy UPS (eq-001-ups-03) must be filtered out; only critical & warning included
    assert ticket.item_ids == ["eq-001-ups-01", "eq-001-ups-02"]
    assert "eq-001-ups-03" not in ticket.item_ids
    assert ticket.metadata["healthy_filtered_count"] == 1
    assert ticket.metadata["critical_count"] == 1
    assert ticket.metadata["warning_count"] == 1

    # Advisory codes & hardware remediation steps present
    assert "BATTERY_REPLACEMENT_NEEDED" in ticket.description
    assert "ON_BATTERY_ALERT" in ticket.description
    assert "LOW_RUNTIME_WARNING" in ticket.description
    assert "HIGH_TEMP_WARNING" in ticket.description
    assert "Replace hot-swappable APC RBC battery cartridge" in ticket.implementation_plan
    assert "apc-ups-mdf-01.site001.local" in ticket.implementation_plan
    assert "apc-ups-healthy-03.site001.local" not in ticket.implementation_plan

    snow = ticket.to_servicenow_payload()
    assert SERVICENOW_REQUIRED_KEYS.issubset(snow.keys())
    assert snow["table"] == "incident"
    assert snow["risk"] == "critical"

    jira = ticket.to_jira_payload()
    assert JIRA_REQUIRED_KEYS.issubset(jira.keys())
    assert jira["issuetype"] == {"name": "Incident"}
    assert jira["priority"] == {"name": "Critical"}
    assert "apc-ups" in jira["labels"]
    assert "battery-replacement-needed" in jira["labels"]

    # Per-unit ticket generation helper
    per_unit_tickets = builder.build_ups_incident_tickets(ups_report)
    assert len(per_unit_tickets) == 2
    assert per_unit_tickets[0].cmdb_ci == "apc-ups-mdf-01.site001.local"


def test_unified_build_ticket_auto_detects_all_four_workflows() -> None:
    builder = ItsmTicketPayloadBuilder(evaluation_time=FIXED_TIME)

    q_ticket = builder.build_ticket(_make_quarantine_manifest())
    assert q_ticket.workflow_type is ItsmWorkflowType.QUARANTINE_DECOMMISSION

    p_ticket = builder.build_ticket(_make_port_reclamation_plan())
    assert p_ticket.workflow_type is ItsmWorkflowType.PORT_RECLAMATION

    r_ticket = builder.build_ticket(_make_reconciliation_report())
    assert r_ticket.workflow_type is ItsmWorkflowType.SHADOW_IT_ONBOARDING

    u_ticket = builder.build_ticket(_make_ups_health_report())
    assert u_ticket.workflow_type is ItsmWorkflowType.UPS_HARDWARE_INCIDENT


# ---------------------------------------------------------------------------
# ItsmGateVerifier Approval & SHA-256 Digest Verification Tests
# ---------------------------------------------------------------------------


def test_gate_verifier_approves_valid_approved_ticket_and_matching_digest() -> None:
    manifest = _make_quarantine_manifest()
    builder = ItsmTicketPayloadBuilder(evaluation_time=FIXED_TIME)
    sink = InMemoryItsmSink()

    ticket = builder.build_quarantine_ticket(
        manifest,
        ticket_id="CHG0010001",
        approval_status="PENDING",
    )
    sink.submit_ticket(ticket)

    verifier = ItsmGateVerifier(sink=sink)

    # 1. Pending ticket is rejected
    pending_res = verifier.verify_change_ticket_approved(
        "CHG0010001", manifest=manifest
    )
    assert not pending_res
    assert pending_res.approved is False
    assert pending_res.approval_status == "PENDING"
    assert "requires APPROVED" in pending_res.reason

    # 2. Transition ticket to APPROVED in sink
    sink.approve_ticket("CHG0010001", approved_by="cab-manager")

    approved_res = verifier.verify_change_ticket_approved(
        "CHG0010001", manifest=manifest
    )
    assert bool(approved_res) is True
    assert approved_res.approved is True
    assert approved_res.is_approved is True
    assert approved_res.digest_matches is True
    assert approved_res.expected_sha256 == manifest.manifest_sha256
    assert approved_res.actual_sha256 == manifest.manifest_sha256

    # Also works when passing the PortReclamationPlan directly
    port_plan = _make_port_reclamation_plan()
    port_ticket = builder.build_port_reclamation_ticket(
        port_plan,
        ticket_id="CHG0010002",
        approval_status="APPROVED",
        approved_by="netops-cab",
    )
    sink.submit_ticket(port_ticket)
    port_res = verifier.verify_change_ticket_approved(
        "CHG0010002", plan=port_plan
    )
    assert port_res.approved is True
    assert port_res.digest_matches is True


def test_gate_verifier_scheduled_status_and_rejection_cases() -> None:
    manifest = _make_quarantine_manifest()
    builder = ItsmTicketPayloadBuilder(evaluation_time=FIXED_TIME)
    sink = InMemoryItsmSink()

    scheduled_ticket = builder.build_quarantine_ticket(
        manifest,
        ticket_id="CHG-SCHED-01",
        approval_status=TicketApprovalStatus.SCHEDULED,
    )
    sink.submit_ticket(scheduled_ticket)

    verifier_strict = ItsmGateVerifier(sink=sink, allow_scheduled=False)
    assert verifier_strict.verify_change_ticket_approved(
        "CHG-SCHED-01", manifest=manifest
    ).approved is False

    verifier_sched = ItsmGateVerifier(sink=sink, allow_scheduled=True)
    assert verifier_sched.verify_change_ticket_approved(
        "CHG-SCHED-01", manifest=manifest
    ).approved is True

    # Reject unknown ticket ID
    missing_res = verifier_strict.verify_change_ticket_approved(
        "CHG-DOES-NOT-EXIST", expected_sha256=manifest.manifest_sha256
    )
    assert missing_res.approved is False
    assert missing_res.approval_status == "MISSING"
    assert "not found" in missing_res.reason

    # Reject REJECTED ticket
    sink.reject_ticket("CHG-SCHED-01", approved_by="security-reviewer")
    rejected_res = verifier_sched.verify_change_ticket_approved(
        "CHG-SCHED-01", manifest=manifest
    )
    assert rejected_res.approved is False
    assert rejected_res.approval_status == "REJECTED"


def test_gate_verifier_rejects_mismatched_sha256_and_tampered_manifest() -> None:
    manifest = _make_quarantine_manifest()
    builder = ItsmTicketPayloadBuilder(evaluation_time=FIXED_TIME)
    sink = InMemoryItsmSink()

    ticket = builder.build_quarantine_ticket(
        manifest,
        ticket_id="CHG-DIGEST-01",
        approval_status="APPROVED",
        approved_by="cab-lead",
    )
    sink.submit_ticket(ticket)
    verifier = ItsmGateVerifier(sink=sink)

    # 1. Ticket approved for an older/different manifest SHA-256 digest
    wrong_sha = "a" * 64
    mismatch_res = verifier.verify_change_ticket_approved(
        "CHG-DIGEST-01", expected_sha256=wrong_sha
    )
    assert mismatch_res.approved is False
    assert mismatch_res.digest_matches is False
    assert "SHA-256 digest mismatch" in mismatch_res.reason

    with pytest.raises(ItsmGateVerificationError, match="SHA-256 digest mismatch"):
        verifier.require_change_ticket_approved(
            "CHG-DIGEST-01", expected_sha256=wrong_sha
        )
    assert issubclass(ItsmGateVerificationError, RemediationExecutionError)

    # 2. Tampering with manifest entries after ticket creation invalidates verification
    manifest.entries[0].target_operation = RemediationOperation.FLAG_STALE_IN_SOT
    # Before recomputing manifest_sha256, manifest.verify_digest() is False
    tampered_res = verifier.verify_change_ticket_approved(
        "CHG-DIGEST-01", manifest=manifest
    )
    assert tampered_res.approved is False
    assert "failed SHA-256 integrity verification" in tampered_res.reason

    # Even if attacker recomputes manifest_sha256, it no longer matches the approved ticket's digest
    manifest.update_digest()
    recomputed_res = verifier.verify_change_ticket_approved(
        "CHG-DIGEST-01", manifest=manifest
    )
    assert recomputed_res.approved is False
    assert recomputed_res.digest_matches is False
    assert "SHA-256 digest mismatch" in recomputed_res.reason


# ---------------------------------------------------------------------------
# Offline Sinks & Webhook Serializer Round-Trip Tests
# ---------------------------------------------------------------------------


def test_json_file_sink_and_webhook_sink_offline_persistence(
    tmp_path: Path,
) -> None:
    manifest = _make_quarantine_manifest()
    port_plan = _make_port_reclamation_plan()
    builder = ItsmTicketPayloadBuilder(evaluation_time=FIXED_TIME)

    q_ticket = builder.build_quarantine_ticket(manifest, ticket_id="CHG-JSON-01")
    p_ticket = builder.build_port_reclamation_ticket(
        port_plan, ticket_id="CHG-JSON-02"
    )

    # 1. Standard JSON file sink round-trip
    json_path = tmp_path / "itsm_tickets.json"
    file_sink = JsonFileItsmSink(json_path)
    assert isinstance(file_sink, ItsmSink)

    file_sink.submit_ticket(q_ticket)
    file_sink.submit_ticket(p_ticket)
    file_sink.approve_ticket("CHG-JSON-01", approved_by="offline-cab")

    reloaded_sink = JsonFileItsmSink(json_path)
    loaded_q = reloaded_sink.get_ticket("CHG-JSON-01")
    assert loaded_q is not None
    assert loaded_q.approval_status is TicketApprovalStatus.APPROVED
    assert loaded_q.approved_by == "offline-cab"
    assert loaded_q.artifact_sha256 == manifest.manifest_sha256
    assert len(reloaded_sink.list_tickets(approval_status="APPROVED")) == 1
    assert (
        len(
            reloaded_sink.list_tickets(
                workflow_type=ItsmWorkflowType.PORT_RECLAMATION
            )
        )
        == 1
    )

    # 2. JSONL file sink round-trip
    jsonl_path = tmp_path / "itsm_tickets.jsonl"
    jsonl_sink = JsonFileItsmSink(jsonl_path, jsonl=True)
    jsonl_sink.submit_ticket(q_ticket)
    jsonl_sink.submit_ticket(p_ticket)
    assert len(jsonl_sink.read_tickets()) == 2

    # 3. WebhookItsmSink & ItsmWebhookSerializer
    captured: list[dict[str, object]] = []
    webhook_out = tmp_path / "webhook_payloads.json"
    webhook_sink = WebhookItsmSink(
        provider=ItsmProvider.WEBHOOK,
        callback=captured.append,
        output_path=webhook_out,
    )
    webhook_sink.submit_ticket(p_ticket)
    webhook_sink.approve_ticket("CHG-JSON-02", approved_by="netops-approver")

    assert len(captured) == 2
    assert captured[-1]["ticket_id"] == "CHG-JSON-02"
    assert captured[-1]["approval_status"] == "APPROVED"
    assert "servicenow" in captured[-1]
    assert "jira" in captured[-1]
    assert webhook_out.exists()

    raw_json = ItsmWebhookSerializer.serialize(
        p_ticket, provider=ItsmProvider.SERVICENOW
    )
    parsed_snow = json.loads(raw_json)
    assert parsed_snow["ticket_id"] == "CHG-JSON-02"
    assert SERVICENOW_REQUIRED_KEYS.issubset(parsed_snow.keys())
