"""Unit tests for multi-run validation history ledger, streak tracker, and drift analyzer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from sot_validator.history import (
    DriftEvent,
    DriftTransitionType,
    HistoryStore,
    ItemStreakSummary,
    SubnetUtilizationSummary,
    ValidationRunRecord,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Site,
    Subnet,
    ValidationClassification,
    ValidationResult,
)


def _make_result(
    item_type: str,
    item_id: str,
    classification: ValidationClassification,
    *,
    site_id: str = "site-042",
    name: str | None = None,
    confidence: float = 0.85,
    evaluated_at: datetime | None = None,
) -> ValidationResult:
    return ValidationResult(
        item_type=item_type,
        item_id=item_id,
        site_id=site_id,
        name=name or item_id,
        classification=classification,
        confidence=confidence,
        rationale=f"{classification.value} for {item_id}",
        evaluated_at=evaluated_at,
    )


def test_history_models_serialization_and_validation() -> None:
    t0 = datetime(2026, 1, 10, 12, 0, tzinfo=timezone.utc)
    run_rec = ValidationRunRecord(
        run_id="run-001",
        recorded_at="2026-01-10T12:00:00Z",  # type: ignore[arg-type]
        site_ids=["site-042", "site-001", "site-042"],
        total_items=3,
        classification_counts={
            ValidationClassification.CONFIRMED_ACTIVE.value: 2,
            ValidationClassification.STALE_LIKELY_UNUSED.value: 1,
        },
    )
    assert run_rec.recorded_at == t0
    assert run_rec.site_ids == ["site-001", "site-042"]
    assert (
        run_rec.classification_counts[
            ValidationClassification.UNREACHABLE_NEEDS_REVIEW.value
        ]
        == 0
    )
    assert (
        run_rec.classification_counts[
            ValidationClassification.INSUFFICIENT_DATA.value
        ]
        == 0
    )
    assert ValidationRunRecord.from_json(run_rec.to_json()) == run_rec

    streak = ItemStreakSummary(
        site_id="site-042",
        item_type="Equipment",
        item_id="eq-win-01",
        name="WIN-SRV-01",
        current_classification=ValidationClassification.STALE_LIKELY_UNUSED,
        current_confidence=0.88,
        consecutive_stale_runs=3,
        total_runs_seen=4,
        first_seen_at=t0 - timedelta(days=21),
        first_stale_at=t0 - timedelta(days=14),
        last_confirmed_active_at=t0 - timedelta(days=21),
        stale_duration_days=14.0,
        previous_classification=ValidationClassification.STALE_LIKELY_UNUSED,
        transition_type=None,
    )
    assert ItemStreakSummary.from_json(streak.to_json()) == streak

    drift = DriftEvent(
        run_id="run-002",
        recorded_at=t0,
        site_id="site-042",
        item_type="Equipment",
        item_id="eq-win-01",
        name="WIN-SRV-01",
        previous_classification=ValidationClassification.CONFIRMED_ACTIVE,
        new_classification=ValidationClassification.STALE_LIKELY_UNUSED,
        transition_type=DriftTransitionType.NEWLY_STALE,
        confidence=0.84,
    )
    assert drift.current_classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert DriftEvent.NEWLY_STALE is DriftTransitionType.NEWLY_STALE
    assert DriftEvent.NEWLY_UNREACHABLE is DriftTransitionType.NEWLY_UNREACHABLE
    assert DriftEvent.RESURRECTED is DriftTransitionType.RESURRECTED
    assert DriftEvent.RECOVERED is DriftTransitionType.RECOVERED
    assert DriftEvent.from_json(drift.to_json()) == drift

    sub_summary = SubnetUtilizationSummary(
        subnet_id="sub-042-01",
        site_id="site-042",
        cidr="10.42.1.0/24",
        total_assigned_ips=10,
        confirmed_active_ips=7,
        stale_reclaimable_ips=2,
        active_utilization_pct=70.0,
    )
    assert (
        SubnetUtilizationSummary.from_json(sub_summary.to_json())
        == sub_summary
    )

    with pytest.raises(ValueError):
        SubnetUtilizationSummary(
            subnet_id="sub-bad",
            cidr="10.42.1.0/24",
            total_assigned_ips=-1,
            confirmed_active_ips=0,
            stale_reclaimable_ips=0,
            active_utilization_pct=0.0,
        )

    with pytest.raises(ValueError):
        SubnetUtilizationSummary(
            subnet_id="sub-bad-pct",
            cidr="10.42.1.0/24",
            total_assigned_ips=5,
            confirmed_active_ips=5,
            stale_reclaimable_ips=0,
            active_utilization_pct=105.0,
        )


def test_multi_run_stale_streak_accumulation_and_resurrection_reset() -> None:
    store = HistoryStore()
    t1 = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(days=7)
    t3 = t1 + timedelta(days=14)
    t4 = t1 + timedelta(days=21)
    t5 = t1 + timedelta(days=28)

    # Run 1: item starts Confirmed Active
    run1 = store.record_run(
        [
            _make_result(
                "Equipment",
                "eq-vm-01",
                ValidationClassification.CONFIRMED_ACTIVE,
                name="WIN-SQL-01",
                confidence=0.92,
            )
        ],
        run_id="run-1",
        recorded_at=t1,
    )
    assert run1.total_items == 1
    assert (
        run1.classification_counts[
            ValidationClassification.CONFIRMED_ACTIVE.value
        ]
        == 1
    )
    s1 = store.get_item_streak("Equipment", "eq-vm-01")
    assert s1 is not None
    assert s1.consecutive_stale_runs == 0
    assert s1.total_runs_seen == 1
    assert s1.first_seen_at == t1
    assert s1.first_stale_at is None
    assert s1.last_confirmed_active_at == t1
    assert s1.stale_duration_days == 0.0
    assert s1.previous_classification is None
    assert s1.transition_type is None
    assert store.detect_drift("run-1") == []

    # Run 2: item becomes Stale / Likely Unused (streak = 1, NEWLY_STALE)
    store.record_run(
        [
            _make_result(
                "Equipment",
                "eq-vm-01",
                ValidationClassification.STALE_LIKELY_UNUSED,
                name="WIN-SQL-01",
                confidence=0.81,
            )
        ],
        run_id="run-2",
        recorded_at=t2,
    )
    s2 = store.get_item_streak("Equipment", "eq-vm-01")
    assert s2 is not None
    assert s2.consecutive_stale_runs == 1
    assert s2.total_runs_seen == 2
    assert s2.first_seen_at == t1
    assert s2.first_stale_at == t2
    assert s2.last_confirmed_active_at == t1
    assert s2.stale_duration_days == 0.0
    assert (
        s2.previous_classification
        is ValidationClassification.CONFIRMED_ACTIVE
    )
    assert s2.transition_type is DriftTransitionType.NEWLY_STALE

    # Run 3: item remains Stale / Likely Unused (streak = 2, duration = 7d)
    store.record_run(
        [
            _make_result(
                "Equipment",
                "eq-vm-01",
                ValidationClassification.STALE_LIKELY_UNUSED,
                name="WIN-SQL-01",
                confidence=0.86,
            )
        ],
        run_id="run-3",
        recorded_at=t3,
    )
    s3 = store.get_item_streak("Equipment", "eq-vm-01")
    assert s3 is not None
    assert s3.consecutive_stale_runs == 2
    assert s3.total_runs_seen == 3
    assert s3.first_stale_at == t2
    assert s3.stale_duration_days == 7.0
    assert (
        s3.previous_classification
        is ValidationClassification.STALE_LIKELY_UNUSED
    )
    assert s3.transition_type is None
    assert store.detect_drift("run-3") == []

    # Run 4: item remains Stale / Likely Unused (streak = 3, duration = 14d)
    store.record_run(
        [
            _make_result(
                "Equipment",
                "eq-vm-01",
                ValidationClassification.STALE_LIKELY_UNUSED,
                name="WIN-SQL-01",
                confidence=0.89,
            )
        ],
        run_id="run-4",
        recorded_at=t4,
    )
    s4 = store.get_item_streak("Equipment", "eq-vm-01")
    assert s4 is not None
    assert s4.consecutive_stale_runs == 3
    assert s4.total_runs_seen == 4
    assert s4.first_stale_at == t2
    assert s4.stale_duration_days == 14.0
    assert len(store.list_streaks(min_consecutive_stale=3)) == 1
    assert len(store.list_streaks(min_consecutive_stale=4)) == 0

    # Run 5: item resurrects to Confirmed Active -> resets streak to 0 and emits RESURRECTED
    store.record_run(
        [
            _make_result(
                "Equipment",
                "eq-vm-01",
                ValidationClassification.CONFIRMED_ACTIVE,
                name="WIN-SQL-01",
                confidence=0.95,
            )
        ],
        run_id="run-5",
        recorded_at=t5,
    )
    s5 = store.get_item_streak("Equipment", "eq-vm-01")
    assert s5 is not None
    assert s5.consecutive_stale_runs == 0
    assert s5.total_runs_seen == 5
    assert s5.first_seen_at == t1
    assert s5.first_stale_at is None
    assert s5.last_confirmed_active_at == t5
    assert s5.stale_duration_days == 0.0
    assert (
        s5.previous_classification
        is ValidationClassification.STALE_LIKELY_UNUSED
    )
    assert s5.transition_type is DriftTransitionType.RESURRECTED

    drift_run5 = store.detect_drift("run-5")
    assert len(drift_run5) == 1
    assert drift_run5[0].transition_type is DriftTransitionType.RESURRECTED
    assert (
        drift_run5[0].previous_classification
        is ValidationClassification.STALE_LIKELY_UNUSED
    )
    assert (
        drift_run5[0].new_classification
        is ValidationClassification.CONFIRMED_ACTIVE
    )
    assert drift_run5[0].item_id == "eq-vm-01"


def test_drift_detection_all_transition_types_and_filters() -> None:
    store = HistoryStore()
    assert store.detect_drift() == []

    t1 = datetime(2026, 2, 1, 8, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(days=7)
    t3 = t1 + timedelta(days=14)

    # Run 1: baseline across two sites
    store.record_run(
        [
            _make_result(
                "Equipment",
                "eq-1",
                ValidationClassification.CONFIRMED_ACTIVE,
                site_id="site-001",
            ),
            _make_result(
                "NetworkDevice",
                "sw-1",
                ValidationClassification.CONFIRMED_ACTIVE,
                site_id="site-001",
            ),
            _make_result(
                "Equipment",
                "eq-2",
                ValidationClassification.STALE_LIKELY_UNUSED,
                site_id="site-002",
            ),
            _make_result(
                "NetworkDevice",
                "ups-2",
                ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                site_id="site-002",
            ),
        ],
        run_id="wave-1",
        recorded_at=t1,
    )
    assert store.detect_drift("wave-1") == []

    # Run 2: trigger all four drift transitions
    # eq-1: Confirmed Active -> Stale / Likely Unused (NEWLY_STALE)
    # sw-1: Confirmed Active -> Unreachable / Needs Manual Review (NEWLY_UNREACHABLE)
    # eq-2: Stale / Likely Unused -> Confirmed Active (RESURRECTED)
    # ups-2: Unreachable / Needs Manual Review -> Confirmed Active (RECOVERED)
    store.record_run(
        [
            _make_result(
                "Equipment",
                "eq-1",
                ValidationClassification.STALE_LIKELY_UNUSED,
                site_id="site-001",
            ),
            _make_result(
                "NetworkDevice",
                "sw-1",
                ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                site_id="site-001",
            ),
            _make_result(
                "Equipment",
                "eq-2",
                ValidationClassification.CONFIRMED_ACTIVE,
                site_id="site-002",
            ),
            _make_result(
                "NetworkDevice",
                "ups-2",
                ValidationClassification.CONFIRMED_ACTIVE,
                site_id="site-002",
            ),
        ],
        run_id="wave-2",
        recorded_at=t2,
    )

    events = store.detect_drift()  # defaults to latest run ("wave-2")
    assert len(events) == 4
    by_item = {e.item_id: e for e in events}
    assert by_item["eq-1"].transition_type is DriftTransitionType.NEWLY_STALE
    assert (
        by_item["sw-1"].transition_type is DriftTransitionType.NEWLY_UNREACHABLE
    )
    assert by_item["eq-2"].transition_type is DriftTransitionType.RESURRECTED
    assert by_item["ups-2"].transition_type is DriftTransitionType.RECOVERED

    site1_events = store.detect_drift("wave-2", site_id="site-001")
    assert {e.item_id for e in site1_events} == {"eq-1", "sw-1"}

    recovered_only = store.detect_drift(
        "wave-2", transition_type=DriftTransitionType.RECOVERED
    )
    assert len(recovered_only) == 1
    assert recovered_only[0].item_id == "ups-2"

    # Run 3: eq-1 moves from Stale -> Unreachable (resets stale streak, not a tracked drift transition)
    store.record_run(
        [
            _make_result(
                "Equipment",
                "eq-1",
                ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                site_id="site-001",
            )
        ],
        run_id="wave-3",
        recorded_at=t3,
    )
    eq1_streak = store.get_item_streak("Equipment", "eq-1")
    assert eq1_streak is not None
    assert eq1_streak.consecutive_stale_runs == 0
    assert eq1_streak.first_stale_at is None
    assert eq1_streak.stale_duration_days == 0.0
    assert eq1_streak.last_confirmed_active_at == t1
    assert eq1_streak.transition_type is None
    assert store.detect_drift("wave-3") == []

    with pytest.raises(KeyError):
        store.detect_drift("non-existent-run")


def test_subnet_utilization_summary_calculation() -> None:
    site = Site(
        site_id="site-042",
        name="Dallas DC",
        subnets=[
            Subnet(
                subnet_id="sub-042-summary",
                site_id="site-042",
                cidr="10.42.0.0/16",
                name="Site /16 Summary",
            ),
            Subnet(
                subnet_id="sub-042-01",
                site_id="site-042",
                cidr="10.42.1.0/24",
                name="Server VLAN 10",
            ),
            Subnet(
                subnet_id="sub-042-02",
                site_id="site-042",
                cidr="10.42.2.0/24",
                name="Management VLAN 20",
            ),
            Subnet(
                subnet_id="sub-042-03",
                site_id="site-042",
                cidr="10.42.3.0/24",
                name="Empty Spare Subnet",
            ),
        ],
        devices=[
            NetworkDevice(
                device_id="sw-042-01",
                site_id="site-042",
                hostname="ex-sw-01",
                management_ip="10.42.2.2",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-042-01",
                site_id="site-042",
                name="WIN-APP-01",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.1.10"],
            ),
            Equipment(
                equipment_id="eq-042-02",
                site_id="site-042",
                name="WIN-LEGACY-02",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.1.11"],
            ),
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.1.10",
                subnet_id="sub-042-01",
                assigned_object_type="Equipment",
                assigned_object_id="eq-042-01",
            ),
            IPAddress(
                ip="10.42.1.11",
                subnet_id="sub-042-01",
                assigned_object_type="Equipment",
                assigned_object_id="eq-042-02",
            ),
            IPAddress(
                ip="10.42.1.12",
                subnet_id="sub-042-01",
            ),
            IPAddress(
                ip="10.42.1.13",
                subnet_id="sub-042-01",
            ),
            IPAddress(
                ip="10.42.2.2",
                subnet_id="sub-042-02",
                assigned_object_type="NetworkDevice",
                assigned_object_id="sw-042-01",
            ),
            IPAddress(
                ip="10.42.2.50",
                subnet_id="sub-042-02",
            ),
        ],
    )

    results = [
        # Subnet 1 (10.42.1.0/24): 4 assigned IPs -> 2 Confirmed Active, 1 Stale, 1 Unreachable
        _make_result(
            "Equipment",
            "eq-042-01",
            ValidationClassification.CONFIRMED_ACTIVE,
        ),
        _make_result(
            "Equipment",
            "eq-042-02",
            ValidationClassification.STALE_LIKELY_UNUSED,
        ),
        _make_result(
            "IPAddress",
            "10.42.1.12",
            ValidationClassification.CONFIRMED_ACTIVE,
        ),
        _make_result(
            "IPAddress",
            "10.42.1.13",
            ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
        ),
        # Subnet 2 (10.42.2.0/24): 2 assigned IPs -> 1 Confirmed Active (via sw-042-01), 1 Stale
        _make_result(
            "NetworkDevice",
            "sw-042-01",
            ValidationClassification.CONFIRMED_ACTIVE,
        ),
        _make_result(
            "IPAddress",
            "10.42.2.50",
            ValidationClassification.STALE_LIKELY_UNUSED,
        ),
    ]

    store = HistoryStore()
    summaries = store.compute_subnet_utilization([site], results)

    # /16 summary subnet is excluded; only the three /24 subnets are returned
    assert [s.subnet_id for s in summaries] == [
        "sub-042-01",
        "sub-042-02",
        "sub-042-03",
    ]

    sub1, sub2, sub3 = summaries
    assert sub1.site_id == "site-042"
    assert sub1.cidr == "10.42.1.0/24"
    assert sub1.total_assigned_ips == 4
    assert sub1.confirmed_active_ips == 2
    assert sub1.stale_reclaimable_ips == 1
    assert sub1.active_utilization_pct == 50.0

    assert sub2.cidr == "10.42.2.0/24"
    assert sub2.total_assigned_ips == 2
    assert sub2.confirmed_active_ips == 1
    assert sub2.stale_reclaimable_ips == 1
    assert sub2.active_utilization_pct == 50.0

    assert sub3.cidr == "10.42.3.0/24"
    assert sub3.total_assigned_ips == 0
    assert sub3.confirmed_active_ips == 0
    assert sub3.stale_reclaimable_ips == 0
    assert sub3.active_utilization_pct == 0.0


def test_sqlite_file_persistence_and_json_export_import(tmp_path: Path) -> None:
    db_file = tmp_path / "ledger" / "history.sqlite"
    json_file = tmp_path / "ledger" / "history_export.json"

    t1 = datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)
    t2 = t1 + timedelta(days=10)

    with HistoryStore(db_file) as store1:
        store1.record_run(
            [
                _make_result(
                    "Equipment",
                    "eq-100",
                    ValidationClassification.CONFIRMED_ACTIVE,
                    site_id="site-010",
                ),
                _make_result(
                    "IPAddress",
                    "10.10.1.25",
                    ValidationClassification.STALE_LIKELY_UNUSED,
                    site_id="site-010",
                ),
            ],
            run_id="run-a",
            recorded_at=t1,
        )
        store1.record_run(
            [
                _make_result(
                    "Equipment",
                    "eq-100",
                    ValidationClassification.STALE_LIKELY_UNUSED,
                    site_id="site-010",
                ),
                _make_result(
                    "IPAddress",
                    "10.10.1.25",
                    ValidationClassification.STALE_LIKELY_UNUSED,
                    site_id="site-010",
                ),
            ],
            run_id="run-b",
            recorded_at=t2,
        )

    # Reopen from on-disk SQLite file in a new HistoryStore instance
    with HistoryStore(db_file) as store2:
        runs = store2.list_runs()
        assert [r.run_id for r in runs] == ["run-a", "run-b"]
        assert store2.get_run("run-a") is not None
        assert store2.get_run("missing") is None

        ip_streak = store2.get_item_streak("IPAddress", "10.10.1.25")
        assert ip_streak is not None
        assert ip_streak.consecutive_stale_runs == 2
        assert ip_streak.stale_duration_days == 10.0

        drift = store2.detect_drift("run-b")
        assert len(drift) == 1
        assert drift[0].item_id == "eq-100"
        assert drift[0].transition_type is DriftTransitionType.NEWLY_STALE

        exported_path = store2.export_json(json_file)
        assert exported_path == json_file
        assert json_file.exists()
        expected_dict = store2.to_dict()

    # Import JSON via classmethod and via instance method
    restored_cls = HistoryStore.import_json(json_file)
    assert restored_cls.to_dict() == expected_dict

    restored_inst = HistoryStore()
    restored_inst.import_json(json_file)
    assert restored_inst.to_dict() == expected_dict

    with pytest.raises(ValueError):
        restored_inst.record_run([], run_id="run-a", recorded_at=t1)
