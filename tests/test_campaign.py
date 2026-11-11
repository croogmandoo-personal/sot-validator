"""Unit tests for multi-site campaign orchestration, circuit breakers, and alert sinks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest

from sot_validator.campaign import (
    AlertEvent,
    AlertSeverity,
    AlertSink,
    AlertType,
    CampaignConfig,
    CampaignOrchestrator,
    CampaignRunSummary,
    CircuitBreakerTrippedError,
    InMemoryAlertSink,
    JsonFileAlertSink,
    SiteWaveResult,
    SiteWaveStatus,
    WebhookPayloadFormatter,
)
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


EVAL_TIME = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)


def _make_active_site(site_id: str, name: str | None = None) -> Site:
    """Create a site whose inventory items classify as Confirmed Active."""
    recent_ts = EVAL_TIME - timedelta(hours=2)
    return Site(
        site_id=site_id,
        name=name or f"Site {site_id}",
        devices=[
            NetworkDevice(
                device_id=f"{site_id}-sw-01",
                site_id=site_id,
                hostname=f"{site_id}-extreme-sw01",
                management_ip="10.10.1.2",
                vendor="Extreme Networks",
                last_seen=recent_ts,
                ports=[
                    Port(
                        port_id=f"{site_id}-p1",
                        device_id=f"{site_id}-sw-01",
                        name="1:1",
                        admin_status="up",
                        oper_status="up",
                    )
                ],
            )
        ],
        equipment=[
            Equipment(
                equipment_id=f"{site_id}-ups-01",
                site_id=site_id,
                name=f"{site_id}-apc-ups01",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.10.1.10"],
                last_seen=recent_ts,
            ),
            Equipment(
                equipment_id=f"{site_id}-vm-01",
                site_id=site_id,
                name=f"{site_id}-win-vm01",
                category=EquipmentCategory.VM,
                assigned_ips=["10.10.1.20"],
                last_seen=recent_ts,
            ),
        ],
        ip_addresses=[
            IPAddress(
                ip="10.10.1.2",
                subnet_id=f"{site_id}-sub1",
                assigned_object_type="NetworkDevice",
                assigned_object_id=f"{site_id}-sw-01",
                arp_mac="00:04:96:00:00:01",
                arp_last_seen=recent_ts,
            ),
            IPAddress(
                ip="10.10.1.10",
                subnet_id=f"{site_id}-sub1",
                assigned_object_type="Equipment",
                assigned_object_id=f"{site_id}-ups-01",
                arp_mac="00:c0:b7:00:00:02",
                arp_last_seen=recent_ts,
            ),
            IPAddress(
                ip="10.10.1.20",
                subnet_id=f"{site_id}-sub1",
                assigned_object_type="Equipment",
                assigned_object_id=f"{site_id}-vm-01",
                arp_mac="00:50:56:00:00:03",
                arp_last_seen=recent_ts,
            ),
        ],
    )


def _make_outage_site(site_id: str, name: str | None = None) -> Site:
    """Create a site whose items fall into Unreachable / Needs Manual Review."""
    # Intermediate timestamp (e.g. 14 days old, between 7d active and 30d stale)
    # causes items to classify as Unreachable / Needs Manual Review.
    intermediate_ts = EVAL_TIME - timedelta(days=14)
    return Site(
        site_id=site_id,
        name=name or f"Site {site_id}",
        devices=[
            NetworkDevice(
                device_id=f"{site_id}-sw-01",
                site_id=site_id,
                hostname=f"{site_id}-extreme-sw01",
                management_ip="10.20.1.2",
                vendor="Extreme Networks",
                last_seen=intermediate_ts,
            )
        ],
        equipment=[
            Equipment(
                equipment_id=f"{site_id}-ups-01",
                site_id=site_id,
                name=f"{site_id}-apc-ups01",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.20.1.10"],
                last_seen=intermediate_ts,
            ),
            Equipment(
                equipment_id=f"{site_id}-san-01",
                site_id=site_id,
                name=f"{site_id}-san01",
                category=EquipmentCategory.SAN,
                assigned_ips=["10.20.1.11"],
                last_seen=intermediate_ts,
            ),
            Equipment(
                equipment_id=f"{site_id}-vm-01",
                site_id=site_id,
                name=f"{site_id}-win-vm01",
                category=EquipmentCategory.VM,
                assigned_ips=["10.20.1.20"],
                last_seen=intermediate_ts,
            ),
        ],
    )


def _make_stale_heavy_site(site_id: str, name: str | None = None) -> Site:
    """Create a site with >40% Stale / Likely Unused items and <=50% Unreachable."""
    recent_ts = EVAL_TIME - timedelta(hours=1)
    stale_ts = EVAL_TIME - timedelta(days=90)
    return Site(
        site_id=site_id,
        name=name or f"Site {site_id}",
        devices=[
            NetworkDevice(
                device_id=f"{site_id}-sw-01",
                site_id=site_id,
                hostname=f"{site_id}-extreme-sw01",
                management_ip="10.30.1.2",
                last_seen=recent_ts,
            )
        ],
        equipment=[
            Equipment(
                equipment_id=f"{site_id}-srv-01",
                site_id=site_id,
                name=f"{site_id}-old-srv01",
                category=EquipmentCategory.SERVER,
                last_seen=stale_ts,
            ),
            Equipment(
                equipment_id=f"{site_id}-srv-02",
                site_id=site_id,
                name=f"{site_id}-old-srv02",
                category=EquipmentCategory.SERVER,
                last_seen=stale_ts,
            ),
        ],
    )


def test_campaign_config_validation_and_serialization() -> None:
    cfg = CampaignConfig()
    assert cfg.cohort_size == 5
    assert cfg.max_unreachable_ratio_per_site == 0.50
    assert cfg.max_consecutive_aborted_sites == 2
    assert cfg.critical_categories == ("ups", "network_device", "san")
    assert cfg.high_stale_ratio_threshold == 0.40
    assert cfg.raise_on_circuit_breaker is False
    assert cfg.include_ip_addresses is True

    roundtrip = CampaignConfig.from_dict(cfg.to_dict())
    assert roundtrip == cfg

    custom = CampaignConfig(
        cohort_size=3,
        max_unreachable_ratio_per_site=0.65,
        max_consecutive_aborted_sites=4,
        critical_categories=("UPS", "Network_Device", "ups"),
        high_stale_ratio_threshold=0.5,
        raise_on_circuit_breaker=True,
        include_ip_addresses=False,
    )
    assert custom.critical_categories == ("ups", "network_device")

    with pytest.raises(ValueError, match="cohort_size"):
        CampaignConfig(cohort_size=0)
    with pytest.raises(ValueError, match="cohort_size"):
        CampaignConfig(cohort_size=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_unreachable_ratio_per_site"):
        CampaignConfig(max_unreachable_ratio_per_site=0.0)
    with pytest.raises(ValueError, match="max_unreachable_ratio_per_site"):
        CampaignConfig(max_unreachable_ratio_per_site=1.5)
    with pytest.raises(ValueError, match="max_consecutive_aborted_sites"):
        CampaignConfig(max_consecutive_aborted_sites=0)
    with pytest.raises(ValueError, match="high_stale_ratio_threshold"):
        CampaignConfig(high_stale_ratio_threshold=0.0)
    with pytest.raises(ValueError, match="critical_categories"):
        CampaignConfig(critical_categories="ups")  # type: ignore[arg-type]


def test_rolling_cohort_wave_execution_and_high_stale_ratio_alert() -> None:
    sites = [
        _make_active_site("site-01"),
        _make_active_site("site-02"),
        _make_stale_heavy_site("site-03"),
        _make_active_site("site-04"),
        _make_active_site("site-05"),
    ]
    sink = InMemoryAlertSink()
    cfg = CampaignConfig(
        cohort_size=2,
        high_stale_ratio_threshold=0.40,
        include_ip_addresses=False,
    )
    orchestrator = CampaignOrchestrator(
        config=cfg,
        alert_sinks=[sink],
        evaluation_time=EVAL_TIME,
    )

    cohorts = orchestrator.iter_cohorts(sites)
    assert [len(c) for c in cohorts] == [2, 2, 1]

    summary = orchestrator.run(sites, campaign_id="wave-test-01")
    assert summary.campaign_id == "wave-test-01"
    assert summary.total_sites_scheduled == 5
    assert summary.total_sites_evaluated == 5
    assert summary.total_waves_executed == 3
    assert summary.circuit_breaker_tripped is False
    assert summary.committed_site_ids == [
        "site-01",
        "site-02",
        "site-03",
        "site-04",
        "site-05",
    ]
    assert summary.quarantined_site_ids == []
    assert summary.skipped_site_ids == []

    # Check wave indices assigned to each site
    wave_indices = [sr.wave_index for sr in summary.site_results]
    assert wave_indices == [0, 0, 1, 1, 2]

    # All sites were committed, so all site results are in committed_validation_results
    expected_total_items = sum(sr.total_items for sr in summary.site_results)
    assert len(summary.committed_validation_results) == expected_total_items

    # site-03 has 2 stale out of 3 items (66.67% > 40% threshold)
    stale_alerts = sink.filter_by_type(AlertType.HIGH_STALE_RATIO_DETECTED)
    assert len(stale_alerts) == 1
    assert stale_alerts[0].site_id == "site-03"
    assert stale_alerts[0].wave_index == 1
    assert stale_alerts[0].severity is AlertSeverity.WARNING
    assert stale_alerts[0].details["stale_count"] == 2
    assert stale_alerts[0].details["total_items"] == 3

    # Verify CampaignRunSummary JSON roundtrip
    raw_json = summary.to_json()
    restored = CampaignRunSummary.from_json(raw_json)
    assert restored.campaign_id == summary.campaign_id
    assert restored.committed_site_ids == summary.committed_site_ids
    assert len(restored.site_results) == 5
    assert len(restored.committed_validation_results) == expected_total_items


def test_site_outage_quarantine_excludes_results_from_streak_tracking() -> None:
    sites = [
        _make_active_site("site-healthy"),
        _make_outage_site("site-wan-down"),
    ]
    sink = InMemoryAlertSink()
    cfg = CampaignConfig(
        cohort_size=2,
        max_unreachable_ratio_per_site=0.50,
        max_consecutive_aborted_sites=2,
        include_ip_addresses=False,
    )
    orchestrator = CampaignOrchestrator(
        config=cfg,
        alert_sinks=[sink],
        evaluation_time=EVAL_TIME,
    )

    summary = orchestrator.run(sites)
    assert summary.circuit_breaker_tripped is False
    assert summary.committed_site_ids == ["site-healthy"]
    assert summary.quarantined_site_ids == ["site-wan-down"]

    healthy_res, outage_res = summary.site_results
    assert healthy_res.status is SiteWaveStatus.COMMITTED
    assert healthy_res.quarantined is False
    assert healthy_res.eligible_for_streak_tracking is True
    assert len(healthy_res.committed_results) == healthy_res.total_items

    assert outage_res.status is SiteWaveStatus.QUARANTINED_OUTAGE_SUSPECTED
    assert outage_res.quarantined is True
    assert outage_res.eligible_for_streak_tracking is False
    assert outage_res.unreachable_ratio == 1.0
    assert len(outage_res.results) == 4
    assert outage_res.committed_results == []

    # Committed results in summary must only contain items from site-healthy
    assert all(
        r.site_id == "site-healthy"
        for r in summary.committed_validation_results
    )

    outage_alerts = sink.filter_by_type(AlertType.SITE_OUTAGE_SUSPECTED)
    assert len(outage_alerts) == 1
    assert outage_alerts[0].site_id == "site-wan-down"
    assert outage_alerts[0].severity is AlertSeverity.CRITICAL
    assert outage_alerts[0].details["unreachable_ratio"] == 1.0


def test_circuit_breaker_resets_on_healthy_site_and_trips_on_consecutive_outages() -> None:
    # Wave 1: outage, healthy (resets counter to 0)
    # Wave 2: outage, outage (hits 2 consecutive -> trips circuit breaker)
    # Wave 3: healthy (skipped because breaker tripped)
    sites = [
        _make_outage_site("site-01-outage"),
        _make_active_site("site-02-healthy"),
        _make_outage_site("site-03-outage"),
        _make_outage_site("site-04-outage"),
        _make_active_site("site-05-skipped"),
        _make_active_site("site-06-skipped"),
    ]
    sink = InMemoryAlertSink()
    cfg = CampaignConfig(
        cohort_size=2,
        max_unreachable_ratio_per_site=0.50,
        max_consecutive_aborted_sites=2,
        include_ip_addresses=False,
    )
    orchestrator = CampaignOrchestrator(
        config=cfg,
        alert_sinks=[sink],
        evaluation_time=EVAL_TIME,
    )

    summary = orchestrator.run(sites, campaign_id="cb-campaign")
    assert summary.circuit_breaker_tripped is True
    assert summary.consecutive_aborted_sites == 2
    assert summary.total_sites_scheduled == 6
    assert summary.total_sites_evaluated == 4
    assert summary.total_waves_executed == 2
    assert summary.committed_site_ids == ["site-02-healthy"]
    assert summary.quarantined_site_ids == [
        "site-01-outage",
        "site-03-outage",
        "site-04-outage",
    ]
    assert summary.skipped_site_ids == ["site-05-skipped", "site-06-skipped"]

    cb_alerts = sink.filter_by_type(AlertType.CAMPAIGN_CIRCUIT_BREAKER_TRIPPED)
    assert len(cb_alerts) == 1
    assert cb_alerts[0].site_id == "site-04-outage"
    assert cb_alerts[0].wave_index == 1
    assert cb_alerts[0].details["consecutive_aborted_sites"] == 2
    assert cb_alerts[0].details["aborted_site_ids"] == [
        "site-03-outage",
        "site-04-outage",
    ]

    # Also verify raising CircuitBreakerTrippedError when raise_on_circuit_breaker=True
    sink.clear()
    with pytest.raises(CircuitBreakerTrippedError) as exc_info:
        orchestrator.run(
            sites,
            campaign_id="cb-raise-campaign",
            raise_on_circuit_breaker=True,
        )

    err = exc_info.value
    assert err.consecutive_aborted_sites == 2
    assert err.aborted_site_ids == ["site-03-outage", "site-04-outage"]
    assert err.wave_index == 1
    assert err.summary is not None
    assert err.summary.circuit_breaker_tripped is True
    assert err.summary.skipped_site_ids == [
        "site-05-skipped",
        "site-06-skipped",
    ]


def test_critical_infrastructure_unreachable_alerts_filter_by_category() -> None:
    site = Site(
        site_id="site-crit",
        name="Critical Infra Site",
        devices=[
            NetworkDevice(
                device_id="dev-extreme-01",
                site_id="site-crit",
                hostname="extreme-core-sw01",
                vendor="Extreme Networks",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-apc-ups-01",
                site_id="site-crit",
                name="apc-smart-ups-01",
                category=EquipmentCategory.UPS,
            ),
            Equipment(
                equipment_id="eq-san-01",
                site_id="site-crit",
                name="netapp-san-01",
                category=EquipmentCategory.SAN,
            ),
            Equipment(
                equipment_id="eq-vm-01",
                site_id="site-crit",
                name="win-app-vm01",
                category=EquipmentCategory.VM,
            ),
            Equipment(
                equipment_id="eq-other-01",
                site_id="site-crit",
                name="badge-reader-01",
                category=EquipmentCategory.OTHER,
            ),
        ],
    )

    precomputed = {
        "site-crit": [
            ValidationResult(
                item_type="NetworkDevice",
                item_id="dev-extreme-01",
                site_id="site-crit",
                name="extreme-core-sw01",
                classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                confidence=0.45,
                rationale="SNMP & ICMP timeout on Extreme switch",
                evaluated_at=EVAL_TIME,
            ),
            ValidationResult(
                item_type="Equipment",
                item_id="eq-apc-ups-01",
                site_id="site-crit",
                name="apc-smart-ups-01",
                classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                confidence=0.45,
                rationale="APC PowerNet-MIB SNMP unreachable",
                evaluated_at=EVAL_TIME,
            ),
            ValidationResult(
                item_type="Equipment",
                item_id="eq-san-01",
                site_id="site-crit",
                name="netapp-san-01",
                classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                confidence=0.45,
                rationale="SAN management unreachable",
                evaluated_at=EVAL_TIME,
            ),
            ValidationResult(
                item_type="Equipment",
                item_id="eq-vm-01",
                site_id="site-crit",
                name="win-app-vm01",
                classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                confidence=0.40,
                rationale="VM unreachable",
                evaluated_at=EVAL_TIME,
            ),
            ValidationResult(
                item_type="Equipment",
                item_id="eq-other-01",
                site_id="site-crit",
                name="badge-reader-01",
                classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                confidence=0.40,
                rationale="Other device unreachable",
                evaluated_at=EVAL_TIME,
            ),
        ]
    }

    sink = InMemoryAlertSink()
    orchestrator = CampaignOrchestrator(
        alert_sinks=[sink],
        evaluation_time=EVAL_TIME,
    )
    orchestrator.run([site], precomputed_results=precomputed)

    crit_alerts = sink.filter_by_type(AlertType.CRITICAL_INFRA_UNREACHABLE)
    assert len(crit_alerts) == 3

    by_id = {a.item_id: a for a in crit_alerts}
    assert set(by_id.keys()) == {
        "dev-extreme-01",
        "eq-apc-ups-01",
        "eq-san-01",
    }
    assert by_id["dev-extreme-01"].category == "network_device"
    assert by_id["dev-extreme-01"].item_type == "NetworkDevice"
    assert by_id["eq-apc-ups-01"].category == "ups"
    assert by_id["eq-san-01"].category == "san"
    assert all(a.severity is AlertSeverity.CRITICAL for a in crit_alerts)


def test_json_file_alert_sink_and_webhook_payload_formatter(
    tmp_path: Path,
) -> None:
    event1 = AlertEvent(
        alert_type=AlertType.CRITICAL_INFRA_UNREACHABLE,
        message="Extreme switch sw-core-01 unreachable at site-01",
        site_id="site-01",
        wave_index=0,
        item_type="NetworkDevice",
        item_id="dev-01",
        item_name="sw-core-01",
        category="network_device",
        created_at=EVAL_TIME,
        details={"vendor": "Extreme Networks"},
    )
    event2 = AlertEvent(
        alert_type=AlertType.HIGH_STALE_RATIO_DETECTED,
        message="High stale ratio (55%) at site-02",
        site_id="site-02",
        wave_index=1,
        created_at=EVAL_TIME,
        details={"stale_ratio": 0.55},
    )

    # Default severities based on alert_type
    assert event1.severity is AlertSeverity.CRITICAL
    assert event2.severity is AlertSeverity.WARNING

    # JSON array file sink
    json_path = tmp_path / "alerts" / "campaign_alerts.json"
    json_sink = JsonFileAlertSink(json_path, jsonl=False)
    json_sink.emit(event1)
    json_sink.emit(event2)

    loaded_json = json_sink.read_events()
    assert len(loaded_json) == 2
    assert loaded_json[0].alert_type is AlertType.CRITICAL_INFRA_UNREACHABLE
    assert loaded_json[0].item_id == "dev-01"
    assert loaded_json[1].alert_type is AlertType.HIGH_STALE_RATIO_DETECTED

    # JSONL file sink
    jsonl_path = tmp_path / "alerts" / "campaign_alerts.jsonl"
    jsonl_sink = JsonFileAlertSink(jsonl_path, jsonl=True)
    jsonl_sink.emit_many([event1, event2])
    loaded_jsonl = jsonl_sink.read_events()
    assert len(loaded_jsonl) == 2
    assert loaded_jsonl[0].to_dict() == event1.to_dict()
    assert loaded_jsonl[1].to_dict() == event2.to_dict()

    # WebhookPayloadFormatter: generic, slack, teams
    generic_payload = WebhookPayloadFormatter.format_payload(
        event1, target="generic"
    )
    assert generic_payload["target"] == "generic"
    assert generic_payload["alert_count"] == 1
    assert generic_payload["severity"] == "CRITICAL"
    assert generic_payload["alert"]["item_id"] == "dev-01"
    json.dumps(generic_payload)

    slack_payload = WebhookPayloadFormatter.format_payload(
        [event1, event2], target="slack"
    )
    assert "text" in slack_payload
    assert "blocks" in slack_payload
    assert "attachments" in slack_payload
    assert len(slack_payload["attachments"]) == 2
    assert "sw-core-01" in json.dumps(slack_payload)

    teams_payload = WebhookPayloadFormatter.format_payload(
        event1, target="teams"
    )
    assert teams_payload["@type"] == "MessageCard"
    assert teams_payload["themeColor"] == "D92D20"
    assert len(teams_payload["sections"]) == 1
    facts = {
        f["name"]: f["value"] for f in teams_payload["sections"][0]["facts"]
    }
    assert facts["Site ID"] == "site-01"
    assert facts["Category"] == "network_device"
    json.dumps(teams_payload)

    with pytest.raises(ValueError, match="Unsupported webhook target"):
        WebhookPayloadFormatter.format_payload(event1, target="discord")
