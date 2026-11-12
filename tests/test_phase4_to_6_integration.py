"""End-to-end tests for Phase 4-6 CLI subcommands, HTML5 dashboard integration, and ITSM approval gate."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from sot_validator.cli import main
from sot_validator.extraction import FixtureSoTClient
from sot_validator.itsm import (
    InMemoryItsmSink,
    ItsmGateVerificationError,
    ItsmGateVerifier,
    ItsmTicketPayloadBuilder,
    JsonFileItsmSink,
    TicketApprovalStatus,
)
from sot_validator.migration import (
    CutoverRecommendation,
    ModernSoTExporter,
    ModernSoTParityValidator,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.reconciliation import (
    DiscrepancyRecord,
    DiscrepancyType,
    ReconciliationReport,
)
from sot_validator.remediation import (
    ApprovalStatus,
    ExtremePortReclamationPlanner,
    QuarantineGraduationStatus,
    QuarantineManifestEntry,
    RemediationApprovalManifest,
    RemediationExecutionError,
    RemediationExecutor,
    RemediationOperation,
)
from sot_validator.reporting import generate_html_dashboard
from sot_validator.signals.ups_health import ApcUpsHealthEvaluator


def _build_sample_site() -> Site:
    return Site(
        site_id="site-042",
        name="Site 042 Manufacturing",
        address="42 Industrial Way",
        contact_info="NetOps <netops@example.com>",
        subnets=[
            Subnet(
                subnet_id="sub-042-10",
                site_id="site-042",
                cidr="10.42.10.0/24",
                vlan_id="10",
                name="Users-VLAN10",
            )
        ],
        devices=[
            NetworkDevice(
                device_id="sw-042-edge-01",
                site_id="site-042",
                hostname="sw-042-edge-01.corp.local",
                management_ip="10.42.10.2",
                vendor="Extreme Networks",
                model="X465-48W",
                role="access",
                last_seen=datetime(2026, 2, 12, 11, 0, tzinfo=timezone.utc),
                ports=[
                    Port(
                        port_id="port-042-1",
                        device_id="sw-042-edge-01",
                        name="1:5",
                        admin_status="up",
                        oper_status="down",
                        poe_status="searching",
                        vlan_id="10",
                    ),
                    Port(
                        port_id="port-042-uplink",
                        device_id="sw-042-edge-01",
                        name="1:48",
                        admin_status="up",
                        oper_status="down",
                        poe_status="disabled",
                        vlan_id="10",
                        connected_device_id="sw-042-core-01",
                    ),
                ],
            )
        ],
        equipment=[
            Equipment(
                equipment_id="ups-042-01",
                site_id="site-042",
                name="ups-042-mdf-01",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.10.50"],
                last_seen=datetime(2026, 2, 12, 11, 0, tzinfo=timezone.utc),
            ),
            Equipment(
                equipment_id="srv-042-stale-01",
                site_id="site-042",
                name="srv-042-legacy-01",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.10.99"],
                last_seen=datetime(2025, 11, 1, 0, 0, tzinfo=timezone.utc),
            ),
        ],
    )


def test_remediation_executor_enforces_itsm_approval_gate(tmp_path: Path) -> None:
    entry = QuarantineManifestEntry(
        item_type="Equipment",
        item_id="srv-042-stale-01",
        site_id="site-042",
        name="srv-042-legacy-01",
        consecutive_stale_runs=4,
        stale_duration_days=45.0,
        confidence=0.95,
        graduation_status=QuarantineGraduationStatus.ELIGIBLE,
        target_operation=RemediationOperation.FLAG_STALE_IN_SOT,
        approval_status=ApprovalStatus.APPROVED,
        reviewed_by="netops-lead",
    )
    manifest = RemediationApprovalManifest(
        manifest_id="manifest-itsm-001",
        entries=[entry],
    )
    manifest.update_digest()

    builder = ItsmTicketPayloadBuilder()
    ticket = builder.build_quarantine_ticket(
        manifest,
        ticket_id="CHG0099001",
        approval_status=TicketApprovalStatus.PENDING,
    )
    sink = InMemoryItsmSink([ticket])

    executor = RemediationExecutor(
        dry_run=True,
        require_itsm_approval=True,
        itsm_sink=sink,
        itsm_ticket_id="CHG0099001",
    )

    # 1. Pending ticket must be rejected by RemediationExecutor
    with pytest.raises(ItsmGateVerificationError, match="PENDING"):
        executor.execute(manifest)

    # 2. Approve ticket -> execution succeeds
    sink.approve_ticket("CHG0099001", approved_by="cab-manager")
    res = executor.execute(manifest, sql_output_dir=tmp_path)
    assert res.applied_count == 1

    # 3. Tamper with ticket SHA-256 digest -> rejected by RemediationExecutor
    sink.update_approval_status(
        "CHG0099001",
        TicketApprovalStatus.APPROVED,
        artifact_sha256="0" * 64,
    )
    with pytest.raises(ItsmGateVerificationError, match="SHA-256 digest mismatch"):
        executor.execute(manifest)


def test_html_dashboard_renders_phase4_to_phase6_sections(tmp_path: Path) -> None:
    site = _build_sample_site()
    results = [
        ValidationResult(
            item_type="NetworkDevice",
            item_id="sw-042-edge-01",
            site_id="site-042",
            name="sw-042-edge-01.corp.local",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
            rationale="Active switch",
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="ups-042-01",
            site_id="site-042",
            name="ups-042-mdf-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
            rationale="Active APC UPS",
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="srv-042-stale-01",
            site_id="site-042",
            name="srv-042-legacy-01",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.92,
            rationale="Stale server",
        ),
    ]

    # Phase 4 Port Reclamation Plan
    from sot_validator.history import ItemStreakSummary

    port_streak = ItemStreakSummary(
        site_id="site-042",
        item_type="Port",
        item_id="port-042-1",
        name="1:5",
        current_classification=ValidationClassification.STALE_LIKELY_UNUSED,
        current_confidence=0.95,
        consecutive_stale_runs=4,
        total_runs_seen=4,
        first_seen_at=datetime(2025, 12, 1, 0, 0, tzinfo=timezone.utc),
        first_stale_at=datetime(2025, 12, 1, 0, 0, tzinfo=timezone.utc),
        stale_duration_days=45.0,
    )
    planner = ExtremePortReclamationPlanner(
        min_inactive_runs=3, min_inactive_days=30.0
    )
    port_plan = planner.plan(sites=[site], streaks=[port_streak])

    # Phase 5 Modern SoT Export & Parity Report
    exporter = ModernSoTExporter(sites=[site], validation_results=results)
    golden_bundle = exporter.to_dict()
    parity_report = ModernSoTParityValidator(
        golden_bundle=golden_bundle,
        modern_bundle=golden_bundle,
        sites=[site],
        validation_results=results,
    ).evaluate_sites()

    # Phase 6 APC UPS Health Report
    ups_eval = ApcUpsHealthEvaluator(
        telemetry_by_target={
            "10.42.10.50": {
                "oids": {
                    "1.3.6.1.4.1.318.1.1.1.1.1.1.0": "Smart-UPS 3000 RM",
                    "1.3.6.1.4.1.318.1.1.1.2.1.1.0": 3,
                    "1.3.6.1.4.1.318.1.1.1.2.2.4.0": 2,
                    "1.3.6.1.4.1.318.1.1.1.2.2.3.0": 48000,
                    "1.3.6.1.4.1.318.1.1.1.2.2.2.0": 44,
                    "1.3.6.1.4.1.318.1.1.1.4.2.3.0": 85,
                    "1.3.6.1.4.1.318.1.1.1.4.1.1.0": 3,
                    "1.3.6.1.4.1.318.1.1.1.3.2.5.0": 4,
                }
            }
        }
    )
    ups_report = ups_eval.evaluate_fleet([site])

    # Phase 6 ITSM Tickets
    builder = ItsmTicketPayloadBuilder()
    port_ticket = builder.build_port_reclamation_ticket(port_plan)
    ups_ticket = builder.build_ups_incident_ticket(ups_report)

    dashboard_path = tmp_path / "validation_dashboard.html"
    html_text = generate_html_dashboard(
        results,
        sites=[site],
        port_reclamation_plan=port_plan,
        parity_report=parity_report,
        ups_health_report=ups_report,
        itsm_tickets=[port_ticket, ups_ticket],
        output_path=dashboard_path,
    )

    assert dashboard_path.exists()
    assert 'id="port-reclamation-section"' in html_text
    assert "disable ports 1:5" in html_text
    assert 'id="modern-sot-parity-section"' in html_text
    assert CutoverRecommendation.READY_FOR_CUTOVER.value in html_text
    assert 'id="ups-health-section"' in html_text
    assert "BATTERY_REPLACEMENT_NEEDED" in html_text
    assert 'id="itsm-governance-section"' in html_text
    assert port_ticket.ticket_id in html_text
    assert ups_ticket.ticket_id in html_text


def test_cli_end_to_end_phase4_to_phase6_pipeline(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    snap_dir = out_dir / "snapshots"

    # 1. Extract & validate fixtures
    assert (
        main(
            [
                "run",
                "--fixtures",
                "--num-sites",
                "2",
                "--snapshot-dir",
                str(snap_dir),
                "--output-dir",
                str(out_dir),
            ]
        )
        == 0
    )

    # 2. Phase 4 reclaim-ports CLI
    assert (
        main(
            [
                "reclaim-ports",
                "--snapshot-dir",
                str(snap_dir),
                "--output-dir",
                str(out_dir),
                "--min-inactive-runs",
                "1",
                "--min-inactive-days",
                "0",
            ]
        )
        == 0
    )
    assert (out_dir / "port_reclamation_plan.json").exists()
    assert (out_dir / "reclaim_ports_exos.xsf").exists()
    assert (out_dir / "reclaim_ports_voss.cli").exists()

    # 3. Phase 5 export-modern-sot & parity-check CLI
    assert (
        main(
            [
                "export-modern-sot",
                "--snapshot-dir",
                str(snap_dir),
                "--results-file",
                str(out_dir / "validation_results.json"),
                "--output-dir",
                str(out_dir),
                "--target-platform",
                "netbox",
            ]
        )
        == 0
    )
    golden_path = out_dir / "netbox_golden_bundle.json"
    assert golden_path.exists()
    assert (out_dir / "netbox_csv_bundle" / "devices.csv").exists()

    assert (
        main(
            [
                "parity-check",
                "--snapshot-dir",
                str(snap_dir),
                "--golden-bundle",
                str(golden_path),
                "--modern-bundle",
                str(golden_path),
                "--output-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    assert (out_dir / "parity_report.json").exists()

    # 4. Phase 6 ups-health CLI
    assert (
        main(
            [
                "ups-health",
                "--snapshot-dir",
                str(snap_dir),
                "--output-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    assert (out_dir / "ups_health_report.json").exists()

    # 5. Phase 6 itsm CLI + report HTML dashboard with all artifacts
    assert (
        main(
            [
                "itsm",
                "--port-plan-file",
                str(out_dir / "port_reclamation_plan.json"),
                "--ticket-id",
                "CHG0044001",
                "--approval-status",
                "APPROVED",
                "--approved-by",
                "cab-operator",
                "--verify-ticket-id",
                "CHG0044001",
                "--output-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    assert (out_dir / "itsm_tickets.json").exists()
    assert (out_dir / "itsm_servicenow_payloads.json").exists()
    assert (out_dir / "itsm_verification_result.json").exists()

    assert (
        main(
            [
                "report",
                "--input-dir",
                str(out_dir),
                "--output-dir",
                str(out_dir),
                "--html-dashboard",
            ]
        )
        == 0
    )
    dashboard_html = (out_dir / "validation_dashboard.html").read_text(
        encoding="utf-8"
    )
    assert "CHG0044001" in dashboard_html
    assert 'id="port-reclamation-section"' in dashboard_html
    assert 'id="modern-sot-parity-section"' in dashboard_html
    assert 'id="ups-health-section"' in dashboard_html
