"""Unit tests for Phase 2 stale quarantine policy engine and SHA-256 approval manifests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest

from sot_validator.history import HistoryStore, ItemStreakSummary
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)
from sot_validator.remediation import (
    ApprovalStatus,
    DryRunActionPlan,
    DryRunActionPlanGenerator,
    ProposedRemediationAction,
    QuarantineEngine,
    QuarantineGraduationStatus,
    QuarantineManifestEntry,
    QuarantinePolicy,
    ReadOnlyViolationError,
    RemediationActionSink,
    RemediationActionType,
    RemediationApprovalManifest,
    RemediationOperation,
)


def _make_stale_result(
    item_type: str,
    item_id: str,
    *,
    site_id: str = "site-042",
    name: str | None = None,
    confidence: float = 0.90,
    classification: ValidationClassification = ValidationClassification.STALE_LIKELY_UNUSED,
    signals: list[ValidationSignal] | None = None,
    evaluated_at: datetime | None = None,
) -> ValidationResult:
    return ValidationResult(
        item_type=item_type,
        item_id=item_id,
        site_id=site_id,
        name=name or item_id,
        classification=classification,
        confidence=confidence,
        signals=signals or [],
        rationale=f"{classification.value} for {item_id}",
        evaluated_at=evaluated_at,
    )


def _make_streak(
    item_type: str,
    item_id: str,
    *,
    site_id: str = "site-042",
    name: str | None = None,
    classification: ValidationClassification = ValidationClassification.STALE_LIKELY_UNUSED,
    confidence: float = 0.90,
    consecutive_stale_runs: int = 3,
    stale_duration_days: float = 35.0,
) -> ItemStreakSummary:
    t0 = datetime(2026, 2, 1, 12, 0, tzinfo=timezone.utc)
    return ItemStreakSummary(
        site_id=site_id,
        item_type=item_type,
        item_id=item_id,
        name=name or item_id,
        current_classification=classification,
        current_confidence=confidence,
        consecutive_stale_runs=consecutive_stale_runs,
        total_runs_seen=max(consecutive_stale_runs, 1),
        first_seen_at=t0 - timedelta(days=max(stale_duration_days, 1.0)),
        first_stale_at=t0 - timedelta(days=stale_duration_days),
        stale_duration_days=stale_duration_days,
    )


def test_quarantine_policy_defaults_and_validation() -> None:
    policy = QuarantinePolicy()
    assert policy.min_consecutive_stale_runs == 3
    assert policy.min_stale_days == 30.0
    assert policy.min_confidence == 0.85
    assert policy.protected_item_ids == ()
    assert policy.protected_categories == ()
    assert policy.protected_subnets == ()
    assert policy.protected_Subnets == ()
    assert policy.allow_protected_override is False

    # Test protected_Subnets alias and CIDR normalization
    custom_policy = QuarantinePolicy(
        min_consecutive_stale_runs=4,
        min_stale_days=45.0,
        min_confidence=0.90,
        protected_item_ids=["sw-core-01", "ups-01", "sw-core-01"],
        protected_categories=[EquipmentCategory.UPS, "Core_Switch"],
        protected_Subnets=["10.42.1.5/24", "10.42.2.0/24"],
        protected_vendors=["Extreme", "APC"],
    )
    assert custom_policy.min_consecutive_stale_runs == 4
    assert custom_policy.min_stale_days == 45.0
    assert custom_policy.min_confidence == 0.90
    assert custom_policy.protected_item_ids == ("sw-core-01", "ups-01")
    assert custom_policy.protected_categories == ("ups", "core_switch")
    assert custom_policy.protected_subnets == ("10.42.1.0/24", "10.42.2.0/24")
    assert custom_policy.protected_Subnets == ("10.42.1.0/24", "10.42.2.0/24")
    assert custom_policy.protected_vendors == ("extreme", "apc")

    # Round-trip serialization
    restored = QuarantinePolicy.from_json(custom_policy.to_json())
    assert restored == custom_policy

    # Setter for protected_Subnets
    restored.protected_Subnets = ["10.99.0.0/24"]
    assert restored.protected_subnets == ("10.99.0.0/24",)
    assert restored.protected_Subnets == ("10.99.0.0/24",)

    # Validation errors
    with pytest.raises(ValueError, match="min_consecutive_stale_runs"):
        QuarantinePolicy(min_consecutive_stale_runs=0)
    with pytest.raises(ValueError, match="min_stale_days"):
        QuarantinePolicy(min_stale_days=-1.0)
    with pytest.raises(ValueError, match="min_confidence"):
        QuarantinePolicy(min_confidence=1.5)
    with pytest.raises(ValueError, match="Invalid subnet CIDR"):
        QuarantinePolicy(protected_subnets=["not-a-cidr"])


def test_quarantine_engine_graduation_thresholds_and_target_operations() -> None:
    engine = QuarantineEngine()

    site = Site(
        site_id="site-042",
        name="Site 42",
        devices=[
            NetworkDevice(
                device_id="sw-acc-01",
                site_id="site-042",
                hostname="EXTREME-ACC-01",
                role="access",
                ports=[
                    Port(
                        port_id="port-ge-1-24",
                        device_id="sw-acc-01",
                        name="1:24",
                    )
                ],
            )
        ],
        subnets=[
            Subnet(
                subnet_id="sub-42-10",
                site_id="site-042",
                cidr="10.42.10.0/24",
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.10.50",
                subnet_id="sub-42-10",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-srv-01",
                site_id="site-042",
                name="LEGACY-SRV-01",
                category=EquipmentCategory.SERVER,
            ),
            Equipment(
                equipment_id="eq-win-01",
                site_id="site-042",
                name="WIN-APP-01",
                category=EquipmentCategory.VM,
            ),
        ],
    )

    results = [
        # Eligible items across all 4 target operation categories
        _make_stale_result("Equipment", "eq-srv-01", name="LEGACY-SRV-01", confidence=0.90),
        _make_stale_result("Equipment", "eq-win-01", name="WIN-APP-01", confidence=0.92),
        _make_stale_result("IPAddress", "10.42.10.50", name="10.42.10.50", confidence=0.88),
        _make_stale_result("Port", "port-ge-1-24", name="1:24", confidence=0.86),
        # Below consecutive stale runs threshold (2 < 3)
        _make_stale_result("Equipment", "eq-low-runs", confidence=0.95),
        # Below stale duration days threshold (20.0 < 30.0)
        _make_stale_result("Equipment", "eq-low-days", confidence=0.95),
        # Below confidence threshold (0.80 < 0.85)
        _make_stale_result("Equipment", "eq-low-conf", confidence=0.80),
        # Active item (ignored)
        _make_stale_result(
            "Equipment",
            "eq-active",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.99,
        ),
    ]

    streaks = [
        _make_streak("Equipment", "eq-srv-01", consecutive_stale_runs=3, stale_duration_days=30.0),
        _make_streak("Equipment", "eq-win-01", consecutive_stale_runs=4, stale_duration_days=45.0),
        _make_streak("IPAddress", "10.42.10.50", consecutive_stale_runs=3, stale_duration_days=32.0),
        _make_streak("Port", "port-ge-1-24", consecutive_stale_runs=5, stale_duration_days=60.0),
        _make_streak("Equipment", "eq-low-runs", consecutive_stale_runs=2, stale_duration_days=40.0),
        _make_streak("Equipment", "eq-low-days", consecutive_stale_runs=4, stale_duration_days=20.0),
        _make_streak("Equipment", "eq-low-conf", consecutive_stale_runs=4, stale_duration_days=45.0, confidence=0.80),
        _make_streak(
            "Equipment",
            "eq-active",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            consecutive_stale_runs=0,
            stale_duration_days=0.0,
        ),
    ]

    manifest = engine.evaluate(results, streaks, sites=[site])
    assert manifest.verify_digest() is True

    by_id = {e.item_id: e for e in manifest.entries}
    assert set(by_id.keys()) == {
        "eq-srv-01",
        "eq-win-01",
        "10.42.10.50",
        "port-ge-1-24",
    }

    assert by_id["eq-srv-01"].target_operation is RemediationOperation.FLAG_STALE_IN_SOT
    assert by_id["eq-win-01"].target_operation is RemediationOperation.DECOMMISSION_VM_RECORD
    assert by_id["10.42.10.50"].target_operation is RemediationOperation.RECLAIM_STALE_IP
    assert by_id["port-ge-1-24"].target_operation is RemediationOperation.PROPOSE_PORT_SHUTDOWN

    for entry in manifest.entries:
        assert entry.approval_status is ApprovalStatus.PENDING
        assert entry.graduation_status is QuarantineGraduationStatus.ELIGIBLE
        assert entry.action.action_type is RemediationActionType.MARK_STALE_CANDIDATE


def test_quarantine_engine_protected_infrastructure_exemptions_and_override() -> None:
    site = Site(
        site_id="site-042",
        name="Site 42",
        devices=[
            NetworkDevice(
                device_id="sw-core-01",
                site_id="site-042",
                hostname="EXTREME-CORE-01",
                vendor="Extreme Networks",
                role="core",
                management_ip="10.42.0.2",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="ups-apc-01",
                site_id="site-042",
                name="APC-SMARTUPS-01",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.0.10"],
            ),
            Equipment(
                equipment_id="srv-protected-id",
                site_id="site-042",
                name="CRITICAL-DB-01",
                category=EquipmentCategory.SERVER,
            ),
            Equipment(
                equipment_id="srv-normal-01",
                site_id="site-042",
                name="OLD-APP-01",
                category=EquipmentCategory.SERVER,
            ),
        ],
        subnets=[
            Subnet(
                subnet_id="sub-mgmt",
                site_id="site-042",
                cidr="10.42.99.0/24",
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.99.15",
                subnet_id="sub-mgmt",
            )
        ],
    )

    policy = QuarantinePolicy(
        protected_item_ids=["srv-protected-id"],
        protected_categories=["ups", "core"],
        protected_Subnets=["10.42.99.0/24"],
    )
    engine = QuarantineEngine(policy=policy)

    results = [
        _make_stale_result("NetworkDevice", "sw-core-01", name="EXTREME-CORE-01"),
        _make_stale_result("Equipment", "ups-apc-01", name="APC-SMARTUPS-01"),
        _make_stale_result("Equipment", "srv-protected-id", name="CRITICAL-DB-01"),
        _make_stale_result("IPAddress", "10.42.99.15", name="10.42.99.15"),
        _make_stale_result("Equipment", "srv-normal-01", name="OLD-APP-01"),
    ]
    streaks = [
        _make_streak("NetworkDevice", "sw-core-01", consecutive_stale_runs=5, stale_duration_days=60.0),
        _make_streak("Equipment", "ups-apc-01", consecutive_stale_runs=5, stale_duration_days=60.0),
        _make_streak("Equipment", "srv-protected-id", consecutive_stale_runs=5, stale_duration_days=60.0),
        _make_streak("IPAddress", "10.42.99.15", consecutive_stale_runs=5, stale_duration_days=60.0),
        _make_streak("Equipment", "srv-normal-01", consecutive_stale_runs=5, stale_duration_days=60.0),
    ]

    manifest = engine.evaluate(results, streaks, sites=[site])
    by_id = {e.item_id: e for e in manifest.entries}

    for protected_id in ("sw-core-01", "ups-apc-01", "srv-protected-id", "10.42.99.15"):
        entry = by_id[protected_id]
        assert entry.graduation_status is QuarantineGraduationStatus.EXEMPT_PROTECTED
        assert entry.approval_status is ApprovalStatus.EXEMPT
        assert entry.exemption_reason is not None and len(entry.exemption_reason) > 0

    normal_entry = by_id["srv-normal-01"]
    assert normal_entry.graduation_status is QuarantineGraduationStatus.ELIGIBLE
    assert normal_entry.approval_status is ApprovalStatus.PENDING
    assert normal_entry.exemption_reason is None

    # Explicit override allows protected items to graduate to ELIGIBLE / PENDING
    overridden_manifest = engine.evaluate(
        results, streaks, sites=[site], override_protected=True
    )
    for entry in overridden_manifest.entries:
        assert entry.graduation_status is QuarantineGraduationStatus.ELIGIBLE
        assert entry.approval_status is ApprovalStatus.PENDING


def test_quarantine_engine_with_history_store_integration() -> None:
    store = HistoryStore(":memory:")
    t0 = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)

    run_results = [
        _make_stale_result("IPAddress", "10.42.1.25", confidence=0.91),
        _make_stale_result("Equipment", "ups-main-01", name="APC-UPS-MAIN", confidence=0.93),
    ]

    store.record_run(run_results, run_id="run-1", recorded_at=t0)
    store.record_run(run_results, run_id="run-2", recorded_at=t0 + timedelta(days=15))
    store.record_run(run_results, run_id="run-3", recorded_at=t0 + timedelta(days=35))

    policy = QuarantinePolicy(protected_categories=["ups"])
    engine = QuarantineEngine(policy=policy)

    manifest = engine.evaluate(run_results, store)
    assert len(manifest.entries) == 2

    ip_entry = manifest.get_entry("10.42.1.25")
    assert ip_entry is not None
    assert ip_entry.approval_status is ApprovalStatus.PENDING
    assert ip_entry.graduation_status is QuarantineGraduationStatus.ELIGIBLE
    assert ip_entry.target_operation is RemediationOperation.RECLAIM_STALE_IP
    assert ip_entry.consecutive_stale_runs == 3
    assert ip_entry.stale_duration_days == 35.0

    ups_entry = manifest.get_entry("ups-main-01")
    assert ups_entry is not None
    assert ups_entry.approval_status is ApprovalStatus.EXEMPT
    assert ups_entry.graduation_status is QuarantineGraduationStatus.EXEMPT_PROTECTED


def test_manifest_approval_transitions_and_sha256_tamper_detection() -> None:
    policy = QuarantinePolicy(protected_item_ids=["ups-01"])
    engine = QuarantineEngine(policy=policy)

    results = [
        _make_stale_result("Equipment", "srv-01", confidence=0.90),
        _make_stale_result("IPAddress", "10.42.1.10", confidence=0.92),
        _make_stale_result("Equipment", "ups-01", name="APC-UPS-01", confidence=0.95),
    ]
    streaks = [
        _make_streak("Equipment", "srv-01", consecutive_stale_runs=3, stale_duration_days=31.0),
        _make_streak("IPAddress", "10.42.1.10", consecutive_stale_runs=4, stale_duration_days=40.0),
        _make_streak("Equipment", "ups-01", consecutive_stale_runs=5, stale_duration_days=50.0),
    ]

    manifest = engine.evaluate(results, streaks)
    initial_digest = manifest.manifest_sha256
    assert len(initial_digest) == 64
    assert manifest.verify_digest() is True

    # Set individual decision
    updated = manifest.set_entry_decision(
        "srv-01",
        ApprovalStatus.REJECTED,
        reviewer="netops-alice",
        note="Server used quarterly for cold backups",
    )
    assert updated.approval_status is ApprovalStatus.REJECTED
    assert updated.reviewed_by == "netops-alice"
    assert updated.review_note == "Server used quarterly for cold backups"
    assert manifest.manifest_sha256 != initial_digest
    assert manifest.verify_digest() is True

    # Cannot approve EXEMPT item without explicit override
    with pytest.raises(ValueError, match="EXEMPT_PROTECTED"):
        manifest.set_entry_decision(
            "ups-01", ApprovalStatus.APPROVED, reviewer="netops-bob"
        )

    # approve_all approves non-exempt entries and leaves EXEMPT entries untouched
    manifest.approve_all(reviewer="netops-bob", note="Batch approved for cleanup")
    assert manifest.verify_digest() is True
    assert manifest.get_entry("srv-01").approval_status is ApprovalStatus.APPROVED
    assert manifest.get_entry("10.42.1.10").approval_status is ApprovalStatus.APPROVED
    assert manifest.get_entry("ups-01").approval_status is ApprovalStatus.EXEMPT
    assert manifest.get_entry("srv-01").reviewed_by == "netops-bob"

    approved_digest = manifest.manifest_sha256

    # Direct mutation of an entry field without recomputing digest fails verification
    srv_entry = manifest.get_entry("srv-01")
    assert srv_entry is not None
    srv_entry.target_operation = RemediationOperation.PROPOSE_PORT_SHUTDOWN
    assert manifest.manifest_sha256 == approved_digest
    assert manifest.verify_digest() is False

    # Restore field -> verification passes again
    srv_entry.target_operation = RemediationOperation.FLAG_STALE_IN_SOT
    assert manifest.verify_digest() is True

    # Mutate approval_status directly -> fails verification
    ups_entry = manifest.get_entry("ups-01")
    assert ups_entry is not None
    ups_entry.approval_status = ApprovalStatus.APPROVED
    assert manifest.verify_digest() is False
    ups_entry.approval_status = ApprovalStatus.EXEMPT
    assert manifest.verify_digest() is True

    # Mutate manifest_sha256 directly -> fails verification
    manifest.manifest_sha256 = "0" * 64
    assert manifest.verify_digest() is False
    manifest.update_digest()
    assert manifest.manifest_sha256 == approved_digest
    assert manifest.verify_digest() is True


def test_manifest_json_and_csv_export_import_round_trip(tmp_path: Path) -> None:
    policy = QuarantinePolicy(
        min_consecutive_stale_runs=3,
        min_stale_days=30.0,
        min_confidence=0.85,
        protected_item_ids=["ups-01"],
        protected_Subnets=["10.42.0.0/24"],
    )
    engine = QuarantineEngine(policy=policy)

    results = [
        _make_stale_result("Equipment", "srv-01", name="WIN-SRV-01", confidence=0.91),
        _make_stale_result("IPAddress", "10.42.5.20", name="10.42.5.20", confidence=0.89),
        _make_stale_result("Equipment", "ups-01", name="APC-UPS-01", confidence=0.95),
    ]
    streaks = [
        _make_streak("Equipment", "srv-01", consecutive_stale_runs=3, stale_duration_days=35.0),
        _make_streak("IPAddress", "10.42.5.20", consecutive_stale_runs=4, stale_duration_days=42.0),
        _make_streak("Equipment", "ups-01", consecutive_stale_runs=6, stale_duration_days=90.0),
    ]

    manifest = engine.evaluate(results, streaks)
    manifest.set_entry_decision(
        "srv-01",
        ApprovalStatus.APPROVED,
        reviewer="operator-1",
        note="Verified decommissioned",
    )

    # JSON file export & import
    json_path = tmp_path / "approval_manifest.json"
    exported_json = manifest.export_json(json_path)
    assert json_path.exists()

    imported_from_file = RemediationApprovalManifest.import_json(json_path)
    assert imported_from_file.manifest_sha256 == manifest.manifest_sha256
    assert imported_from_file.verify_digest() is True
    assert imported_from_file.policy == policy
    assert len(imported_from_file.entries) == 3

    # Tampered JSON file must fail verify_digest() on import
    tampered_data = json.loads(exported_json)
    tampered_data["entries"][0]["approval_status"] = "APPROVED"
    tampered_data["entries"][0]["item_id"] = "tampered-item-id"
    tampered_path = tmp_path / "tampered_manifest.json"
    tampered_path.write_text(json.dumps(tampered_data), encoding="utf-8")

    tampered_manifest = RemediationApprovalManifest.import_json(tampered_path)
    assert tampered_manifest.manifest_sha256 == manifest.manifest_sha256
    assert tampered_manifest.verify_digest() is False

    # CSV file export & import
    csv_path = tmp_path / "approval_manifest.csv"
    exported_csv = manifest.export_csv(csv_path)
    assert csv_path.exists()
    assert "srv-01" in exported_csv

    imported_from_csv = RemediationApprovalManifest.import_csv(
        csv_path, policy=policy, manifest_sha256=manifest.manifest_sha256
    )
    assert imported_from_csv.manifest_sha256 == manifest.manifest_sha256
    assert imported_from_csv.verify_digest() is True
    assert len(imported_from_csv.entries) == 3
    assert imported_from_csv.get_entry("srv-01").approval_status is ApprovalStatus.APPROVED
    assert imported_from_csv.get_entry("ups-01").approval_status is ApprovalStatus.EXEMPT
