"""End-to-end integration tests for Phase 4-6 CLI subcommands, HTML5 dashboard panels, package exports, and docs."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

import sot_validator
from sot_validator import (
    ActiveDirectoryCollector,
    ApcUpsHealthEvaluator,
    ApprovalStatus,
    AuthenticatedScraperSession,
    CutoverRecommendation,
    DnsDhcpLeaseCollector,
    DualRunParityChecker,
    Equipment,
    EquipmentCategory,
    ExtremePortReclamationPlanner,
    GoldenInventoryFilter,
    HtmlDashboardGenerator,
    ItsmGateVerificationError,
    ItsmGateVerifier,
    ItsmTicketPayloadBuilder,
    ItsmWorkflowType,
    JsonFileItsmSink,
    LldpUplinkGuard,
    MigrationParityReport,
    ModernSoTExporter,
    NetworkDevice,
    ParityDiscrepancy,
    ParityDiscrepancyType,
    PilotCutoverValidator,
    Port,
    PortReclamationPlan,
    PreFlightReport,
    QuarantineGraduationStatus,
    QuarantineManifestEntry,
    RemediationApprovalManifest,
    RemediationExecutor,
    RemediationOperation,
    Site,
    SiteMigrationReadinessScorecard,
    SnmpWalkConnector,
    Subnet,
    TicketApprovalStatus,
    UpsFleetHealthReport,
    VSphereRestConnector,
    ValidationClassification,
    ValidationResult,
    generate_all_reports,
    generate_html_dashboard,
)
from sot_validator.cli import main
from sot_validator.history import ItemStreakSummary


def test_top_level_phase4_phase6_exports_and_docs() -> None:
    expected_symbols = [
        "PilotCutoverValidator",
        "PreFlightReport",
        "PreFlightCheckResult",
        "AuthenticatedScraperSession",
        "VSphereRestConnector",
        "SnmpWalkConnector",
        "ConnectorReadOnlyError",
        "RequestTelemetry",
        "APC_UPS_MIB_OIDS",
        "EXTREME_SWITCH_MIB_OIDS",
        "LLDP_MIB_OIDS",
        "LLDP_REM_PORT_DESC_PREFIX",
        "LLDP_REM_PORT_ID_PREFIX",
        "LLDP_REM_SYS_NAME_PREFIX",
        "PETH_PSE_PORT_ADMIN_ENABLE_PREFIX",
        "PETH_PSE_PORT_DETECTION_STATUS_PREFIX",
        "POWER_ETHERNET_MIB_OIDS",
        "ActiveDirectoryCollector",
        "AdComputerRecord",
        "DnsDhcpLeaseCollector",
        "DnsRecord",
        "DhcpLeaseRecord",
        "normalize_hostname",
        "ExtremePortReclamationPlanner",
        "LldpUplinkGuard",
        "PortReclamationPlan",
        "PortReclamationCandidate",
        "BlockedPortRecord",
        "LldpGuardDecision",
        "LldpNeighborRecord",
        "ExtremeCliDialect",
        "GoldenInventoryFilter",
        "ModernSoTExporter",
        "DualRunParityChecker",
        "MigrationParityReport",
        "SiteMigrationReadinessScorecard",
        "ParityDiscrepancy",
        "ParityDiscrepancyType",
        "CutoverRecommendation",
        "ENTITY_COLLECTION_KEYS",
        "CSV_COLUMNS_BY_ENTITY",
        "PARITY_ENTITY_COLLECTIONS",
        "SUPPORTED_TARGET_PLATFORMS",
        "ALL_PARITY_DISCREPANCY_TYPES",
        "ALL_CUTOVER_RECOMMENDATIONS",
        "slugify",
        "ApcUpsHealthEvaluator",
        "UpsFleetHealthReport",
        "UpsHealthRecord",
        "UpsHealthStatus",
        "UpsAdvisoryCode",
        "EquipmentType",
        "parse_powernet_telemetry",
        "APC_UPS_ADV_BATTERY_REPLACE_INDICATOR_OID",
        "APC_UPS_ADV_BATTERY_RUN_TIME_REMAINING_OID",
        "APC_UPS_ADV_BATTERY_TEMPERATURE_OID",
        "APC_UPS_ADV_INPUT_LINE_FAIL_CAUSE_OID",
        "APC_UPS_BASIC_BATTERY_STATUS_OID",
        "APC_UPS_BASIC_OUTPUT_STATUS_OID",
        "APC_UPS_HEALTH_OIDS",
        "ItsmTicketPayloadBuilder",
        "ItsmTicketRequest",
        "ItsmGateVerifier",
        "ItsmGateVerificationResult",
        "ItsmGateVerificationError",
        "JsonFileItsmSink",
        "InMemoryItsmSink",
        "WebhookItsmSink",
        "ItsmSink",
        "ItsmWorkflowType",
        "ItsmProvider",
        "TicketApprovalStatus",
        "ItsmApprovalStatus",
        "TicketPriority",
        "TicketRisk",
        "ItsmWebhookSerializer",
        "QuarantineReport",
        "compute_artifact_sha256",
    ]
    for sym in expected_symbols:
        assert hasattr(sot_validator, sym), f"Missing {sym} on sot_validator"
        assert sym in sot_validator.__all__, f"Missing {sym} in sot_validator.__all__"

    repo_root = Path(__file__).resolve().parents[1]
    readme_text = (repo_root / "README.md").read_text(encoding="utf-8")
    arch_text = (repo_root / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    for token in (
        "preflight",
        "reclaim-ports",
        "export-modern-sot",
        "parity-check",
        "ups-health",
        "itsm",
        "connectors/",
        "migration/",
        "itsm/",
    ):
        assert token in readme_text, f"Missing {token} in README.md"
        assert token in arch_text, f"Missing {token} in docs/ARCHITECTURE.md"


def test_cli_preflight_subcommand(tmp_path: Path) -> None:
    rc = main(
        [
            "preflight",
            "--fixtures",
            "--num-sites",
            "3",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc == 0
    report_path = tmp_path / "preflight_report.json"
    assert report_path.exists()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["ready"] is True
    assert data["pilot_site_ids"] == ["site-001", "site-002", "site-003"]


def test_cli_reclaim_ports_subcommand(tmp_path: Path) -> None:
    rc = main(
        [
            "reclaim-ports",
            "--csv-dir",
            "tests/fixtures/sot_samples/csv",
            "--snmp-fixture",
            "tests/fixtures/sot_samples/snmp/extreme_and_apc_walks.json",
            "--min-inactive-runs",
            "1",
            "--min-inactive-days",
            "0",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc == 0
    plan_file = tmp_path / "port_reclamation_plan.json"
    disable_file = tmp_path / "port_reclamation_disable.cli"
    rollback_file = tmp_path / "port_reclamation_rollback.cli"
    assert plan_file.exists()
    assert disable_file.exists()
    assert rollback_file.exists()

    plan = PortReclamationPlan.from_json(plan_file.read_text(encoding="utf-8"))
    assert len(plan.blocked_ports) >= 1
    assert len(plan.candidates) >= 1
    for cand in plan.candidates:
        assert cand.exos_rollback_command
        assert cand.voss_rollback_command


def test_cli_export_modern_sot_and_parity_check(tmp_path: Path) -> None:
    rc_export = main(
        [
            "export-modern-sot",
            "--fixtures",
            "--num-sites",
            "1",
            "--target-platform",
            "netbox",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc_export == 0

    bundle_path = tmp_path / "modern_sot_bundle.json"
    csv_dir = tmp_path / "csv_bundle"
    assert bundle_path.exists()
    for csv_name in (
        "sites.csv",
        "vlans.csv",
        "prefixes.csv",
        "devices.csv",
        "interfaces.csv",
        "ip_addresses.csv",
        "virtual_machines.csv",
    ):
        assert (csv_dir / csv_name).exists()

    rc_parity = main(
        [
            "parity-check",
            "--golden-bundle",
            str(bundle_path),
            "--modern-bundle",
            str(bundle_path),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc_parity == 0

    parity_path = tmp_path / "migration_parity_report.json"
    assert parity_path.exists()
    parity_data = json.loads(parity_path.read_text(encoding="utf-8"))
    assert parity_data["overall_parity_percentage"] == 100.0
    assert (
        parity_data["scorecards"][0]["recommendation"]
        == CutoverRecommendation.READY_FOR_CUTOVER.value
    )


def test_cli_ups_health_subcommand(tmp_path: Path) -> None:
    rc = main(
        [
            "ups-health",
            "--csv-dir",
            "tests/fixtures/sot_samples/csv",
            "--snmp-fixture",
            "tests/fixtures/sot_samples/snmp/extreme_and_apc_walks.json",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc == 0
    ups_path = tmp_path / "ups_health_report.json"
    assert ups_path.exists()
    report = UpsFleetHealthReport.from_json(ups_path.read_text(encoding="utf-8"))
    assert report.total_units >= 1
    assert any(
        r.battery_capacity_pct is not None
        or r.output_load_pct is not None
        or r.output_status is not None
        for r in report.records
    )


def test_cli_itsm_and_remediate_ticket_gate(tmp_path: Path) -> None:
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
        manifest_id="manifest-cli-itsm-001",
        entries=[entry],
    )
    manifest.update_digest()
    manifest_path = tmp_path / "approval_manifest.json"
    manifest.export_json(manifest_path)

    tickets_path = tmp_path / "tickets.json"

    # 1. Create PENDING ticket via CLI itsm
    rc_itsm = main(
        [
            "itsm",
            "--manifest",
            str(manifest_path),
            "--tickets-file",
            str(tickets_path),
            "--provider",
            "servicenow",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc_itsm == 0
    sink = JsonFileItsmSink(tickets_path)
    assert len(sink.tickets) == 1
    ticket = sink.tickets[0]
    assert ticket.approval_status is TicketApprovalStatus.PENDING
    assert ticket.artifact_sha256 == manifest.manifest_sha256

    # 2. Running remediate while ticket is PENDING raises ItsmGateVerificationError
    with pytest.raises(ItsmGateVerificationError, match="PENDING"):
        main(
            [
                "remediate",
                "--manifest",
                str(manifest_path),
                "--itsm-ticket-id",
                ticket.ticket_id,
                "--itsm-tickets-file",
                str(tickets_path),
                "--confirm-write",
                "--output-dir",
                str(tmp_path),
            ]
        )

    # 3. Approve ticket via CLI itsm
    rc_approve = main(
        [
            "itsm",
            "--tickets-file",
            str(tickets_path),
            "--approve-ticket",
            ticket.ticket_id,
            "--approved-by",
            "cab-lead",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc_approve == 0

    # 4. Now remediate succeeds
    rc_rem = main(
        [
            "remediate",
            "--manifest",
            str(manifest_path),
            "--itsm-ticket-id",
            ticket.ticket_id,
            "--itsm-tickets-file",
            str(tickets_path),
            "--confirm-write",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc_rem == 0
    assert (tmp_path / "remediation_result.json").exists()


def test_cli_validate_with_ad_dns_dhcp_signals(tmp_path: Path) -> None:
    ad_path = tmp_path / "ad_records.json"
    ad_path.write_text(
        json.dumps(
            {
                "computers": [
                    {
                        "sAMAccountName": "VM-001-WIN01$",
                        "dNSHostName": "vm-001-win01.site001.corp.local",
                        "operatingSystem": "Windows Server 2022",
                        "enabled": True,
                        "lastLogonTimestamp": "2026-02-11T10:00:00Z",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    dns_path = tmp_path / "dns_records.json"
    dns_path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "record_type": "A",
                        "hostname": "vm-001-win01.site001.corp.local",
                        "ip": "10.1.10.21",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    dhcp_path = tmp_path / "dhcp_leases.json"
    dhcp_path.write_text(
        json.dumps(
            {
                "leases": [
                    {
                        "ip": "10.1.10.21",
                        "hostname": "vm-001-win01.site001.corp.local",
                        "subnet_cidr": "10.1.10.0/24",
                        "status": "active",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    rc = main(
        [
            "validate",
            "--fixtures",
            "--num-sites",
            "1",
            "--ad-json",
            str(ad_path),
            "--dns-json",
            str(dns_path),
            "--dhcp-json",
            str(dhcp_path),
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc == 0
    results_text = (tmp_path / "validation_results.json").read_text(encoding="utf-8")
    assert "AD_COMPUTER_ACCOUNT" in results_text
    assert "DNS_DHCP_LEASE" in results_text


def test_html_dashboard_phase4_phase6_sections_xss_and_airgapped(
    tmp_path: Path,
) -> None:
    site = Site(
        site_id="site-042",
        name="Site 042 <script>alert(1)</script>",
        subnets=[
            Subnet(
                subnet_id="sub-042-10",
                site_id="site-042",
                cidr="10.42.10.0/24",
                vlan_id="10",
            )
        ],
        devices=[
            NetworkDevice(
                device_id="sw-042-01",
                site_id="site-042",
                hostname="sw-042-01",
                management_ip="10.42.10.2",
                vendor="Extreme Networks",
                ports=[
                    Port(
                        port_id="port-042-5",
                        device_id="sw-042-01",
                        name="1:5",
                        admin_status="up",
                        oper_status="down",
                        poe_status="searching",
                        vlan_id="10",
                    )
                ],
            )
        ],
        equipment=[
            Equipment(
                equipment_id="ups-042-01",
                site_id="site-042",
                name="ups-042-01",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.10.50"],
            )
        ],
    )
    results = [
        ValidationResult(
            item_type="NetworkDevice",
            item_id="sw-042-01",
            site_id="site-042",
            name="sw-042-01",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
            rationale="Active switch",
        )
    ]

    port_streak = ItemStreakSummary(
        site_id="site-042",
        item_type="Port",
        item_id="port-042-5",
        name="1:5",
        current_classification=ValidationClassification.STALE_LIKELY_UNUSED,
        current_confidence=0.95,
        consecutive_stale_runs=4,
        total_runs_seen=4,
        first_seen_at=datetime(2025, 12, 1, 0, 0, tzinfo=timezone.utc),
        first_stale_at=datetime(2025, 12, 1, 0, 0, tzinfo=timezone.utc),
        stale_duration_days=45.0,
    )
    port_plan = ExtremePortReclamationPlanner(
        min_inactive_runs=3, min_inactive_days=30.0
    ).plan(sites=[site], streaks=[port_streak])

    scorecard = SiteMigrationReadinessScorecard(
        site_id="site-042",
        site_name="Site 042 <script>xss()</script>",
        readiness_score=95.0,
        recommendation=CutoverRecommendation.READY_FOR_CUTOVER,
        parity_match_percentage=100.0,
        expected_golden_items=4,
        matched_modern_items=4,
        discrepancies=[
            ParityDiscrepancy(
                discrepancy_id="disc-xss",
                discrepancy_type=ParityDiscrepancyType.ATTRIBUTE_MISMATCH,
                site_id="site-042",
                entity_type="devices",
                item_identifier="sw-042-01",
                attribute_name="role",
                expected_value="access",
                actual_value="<script>evil()</script>",
                waived=True,
                details="Waived role note <img src=x onerror=alert(1)>",
            )
        ],
    )
    parity_report = MigrationParityReport(scorecards=[scorecard])

    ups_report = ApcUpsHealthEvaluator(
        telemetry_by_target={
            "10.42.10.50": {
                "oids": {
                    "1.3.6.1.4.1.318.1.1.1.1.1.1.0": "Smart-UPS 3000",
                    "1.3.6.1.4.1.318.1.1.1.2.1.1.0": 2,
                    "1.3.6.1.4.1.318.1.1.1.2.2.4.0": 2,
                    "1.3.6.1.4.1.318.1.1.1.2.2.3.0": 54000,
                    "1.3.6.1.4.1.318.1.1.1.2.2.2.0": 42,
                    "1.3.6.1.4.1.318.1.1.1.4.2.3.0": 75,
                    "1.3.6.1.4.1.318.1.1.1.4.1.1.0": 2,
                }
            }
        }
    ).evaluate_fleet([site])

    ticket = ItsmTicketPayloadBuilder().build_port_reclamation_ticket(
        port_plan,
        ticket_id="CHG0077001",
        cmdb_ci="CI-<script>bad()</script>",
    )

    gen = HtmlDashboardGenerator()
    html_text = gen.render(
        results,
        sites=[site],
        port_reclamation_plan=port_plan,
        migration_parity_report=parity_report,
        ups_health_report=ups_report,
        itsm_tickets=[ticket],
    )

    assert 'id="port-reclamation-section"' in html_text
    assert 'id="migration-parity-section"' in html_text
    assert 'id="ups-health-section"' in html_text
    assert 'id="itsm-governance-section"' in html_text
    assert 'data-kpi="reclaimable-ports"' in html_text
    assert 'data-kpi="migration-ready-sites"' in html_text
    assert 'data-kpi="ups-critical-alerts"' in html_text
    assert 'data-kpi="itsm-tickets-count"' in html_text

    # Strict XSS escaping and zero external URLs
    assert "<script>alert(1)</script>" not in html_text
    assert "<script>xss()</script>" not in html_text
    assert "<script>evil()</script>" not in html_text
    assert "<script>bad()</script>" not in html_text
    assert "&lt;script&gt;" in html_text
    assert "http://" not in html_text
    assert "https://" not in html_text

    # Verify generate_all_reports default 4-key contract and html_dashboard forwarding
    default_paths = generate_all_reports(results, tmp_path / "rep_default")
    assert set(default_paths.keys()) == {
        "json",
        "csv",
        "markdown",
        "remediation_plan",
    }
    html_paths = generate_all_reports(
        results,
        tmp_path / "rep_html",
        include_html_dashboard=True,
        port_reclamation_plan=port_plan,
        migration_parity_report=parity_report,
        ups_health_report=ups_report,
        itsm_tickets=[ticket],
    )
    assert "html_dashboard" in html_paths
    assert html_paths["html_dashboard"].exists()
