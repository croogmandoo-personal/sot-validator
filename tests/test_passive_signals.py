"""Unit tests for passive validation signal evaluators (ARP recency, port state, last-seen)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from sot_validator import (
    ArpEntry,
    ArpSignalEvaluator,
    Equipment,
    EquipmentCategory,
    IPAddress,
    LastSeenSignalEvaluator,
    NetworkDevice,
    Port,
    PortStateSignalEvaluator,
    SignalCollector,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals import (
    SECONDS_PER_DAY,
    normalize_utc_datetime,
    resolve_evaluation_time,
    validate_recency_thresholds,
)


FIXED_EVAL_TIME = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def test_base_timestamp_normalization_and_thresholds() -> None:
    naive_dt = datetime(2026, 6, 15, 12, 0, 0)
    norm_naive = normalize_utc_datetime(naive_dt)
    assert norm_naive == FIXED_EVAL_TIME
    assert norm_naive.tzinfo == timezone.utc

    offset_tz = timezone(timedelta(hours=-5))
    aware_dt = datetime(2026, 6, 15, 7, 0, 0, tzinfo=offset_tz)
    norm_aware = normalize_utc_datetime(aware_dt)
    assert norm_aware == FIXED_EVAL_TIME
    assert norm_aware.tzinfo == timezone.utc

    assert normalize_utc_datetime("2026-06-15T12:00:00Z") == FIXED_EVAL_TIME
    assert normalize_utc_datetime("2026-06-15T07:00:00-05:00") == FIXED_EVAL_TIME
    assert normalize_utc_datetime("2026-06-15T12:00:00") == FIXED_EVAL_TIME

    with pytest.raises(ValueError, match="valid ISO-8601"):
        normalize_utc_datetime("not-a-timestamp")
    with pytest.raises(ValueError, match="empty string"):
        normalize_utc_datetime("   ")
    with pytest.raises(ValueError, match="datetime instance or ISO-8601"):
        normalize_utc_datetime(12345)  # type: ignore[arg-type]

    resolved_now = resolve_evaluation_time(None)
    assert resolved_now.tzinfo == timezone.utc
    assert resolve_evaluation_time("2026-06-15T12:00:00Z") == FIXED_EVAL_TIME

    assert validate_recency_thresholds(7, 30) == (7.0, 30.0)
    with pytest.raises(ValueError, match="non-negative"):
        validate_recency_thresholds(-1.0, 30.0)
    with pytest.raises(ValueError, match="must not exceed"):
        validate_recency_thresholds(45.0, 30.0)
    with pytest.raises(ValueError, match="non-negative number"):
        validate_recency_thresholds(True, 30.0)  # type: ignore[arg-type]


def test_arp_signal_evaluator_fresh_intermediate_and_stale() -> None:
    evaluator = ArpSignalEvaluator(
        active_within_days=7.0,
        stale_after_days=30.0,
        evaluation_time=FIXED_EVAL_TIME,
    )
    assert isinstance(evaluator, SignalCollector)

    # 1. Fresh ARP entry (2 days old)
    fresh_ts = FIXED_EVAL_TIME - timedelta(days=2)
    ip_fresh = IPAddress(
        ip="10.10.1.25",
        subnet_id="SUB1",
        arp_mac="00:11:22:33:44:55",
        arp_last_seen=fresh_ts,
    )
    sig_fresh = evaluator.evaluate(ip_fresh)
    assert isinstance(sig_fresh, ValidationSignal)
    assert sig_fresh.signal_type is SignalType.ARP_RECENCY
    assert sig_fresh.status is SignalStatus.ACTIVE
    assert sig_fresh.observed_at == fresh_ts
    assert sig_fresh.age_seconds == pytest.approx(2 * SECONDS_PER_DAY)
    assert sig_fresh.details is not None
    assert "10.10.1.25" in sig_fresh.details

    # 2. Intermediate ARP entry (15 days old: > 7d and <= 30d)
    inter_ts = FIXED_EVAL_TIME - timedelta(days=15)
    ip_inter = IPAddress(
        ip="10.10.1.26",
        subnet_id="SUB1",
        arp_entry=ArpEntry(
            ip="10.10.1.26",
            arp_mac="00:11:22:33:44:56",
            arp_last_seen=inter_ts,
        ),
    )
    sig_inter = evaluator.evaluate(ip_inter)
    assert sig_inter.signal_type is SignalType.ARP_RECENCY
    assert sig_inter.status is SignalStatus.INACTIVE
    assert sig_inter.observed_at == inter_ts
    assert sig_inter.age_seconds == pytest.approx(15 * SECONDS_PER_DAY)
    assert sig_inter.details is not None
    assert "intermediate" in sig_inter.details.lower()

    # 3. Stale ARP entry (45 days old: > 30d)
    stale_ts = FIXED_EVAL_TIME - timedelta(days=45)
    arp_stale = ArpEntry(
        ip="10.10.1.27",
        arp_mac="00:11:22:33:44:57",
        arp_last_seen=stale_ts,
    )
    sig_stale = evaluator.evaluate(arp_stale)
    assert sig_stale.signal_type is SignalType.ARP_RECENCY
    assert sig_stale.status is SignalStatus.INACTIVE
    assert sig_stale.observed_at == stale_ts
    assert sig_stale.age_seconds == pytest.approx(45 * SECONDS_PER_DAY)
    assert sig_stale.details is not None
    assert "stale" in sig_stale.details.lower()


def test_arp_signal_evaluator_missing_and_malformed_timestamps() -> None:
    evaluator = ArpSignalEvaluator(evaluation_time=FIXED_EVAL_TIME)

    # Missing ARP timestamp on IPAddress
    ip_no_arp = IPAddress(ip="10.10.1.30", subnet_id="SUB1")
    sig_missing = evaluator.evaluate(ip_no_arp)
    assert sig_missing.signal_type is SignalType.ARP_RECENCY
    assert sig_missing.status is SignalStatus.NOT_APPLICABLE
    assert sig_missing.observed_at is None
    assert sig_missing.age_seconds is None

    # Equipment with no IPs or correlated ARP data
    eq_no_ips = Equipment(equipment_id="EQ-EMPTY", site_id="S1", name="bare-chassis")
    sig_eq_empty = evaluator.evaluate(eq_no_ips)
    assert sig_eq_empty.status is SignalStatus.NOT_APPLICABLE

    # Malformed timestamp mutated onto IPAddress
    ip_malformed = IPAddress(ip="10.10.1.31", subnet_id="SUB1")
    ip_malformed.arp_last_seen = "invalid-arp-timestamp"  # type: ignore[assignment]
    sig_error = evaluator.evaluate(ip_malformed)
    assert sig_error.signal_type is SignalType.ARP_RECENCY
    assert sig_error.status is SignalStatus.ERROR
    assert sig_error.observed_at is None
    assert sig_error.age_seconds is None
    assert sig_error.details is not None
    assert "malformed" in sig_error.details.lower()


def test_arp_signal_evaluator_timezone_normalization_and_clock_skew() -> None:
    evaluator = ArpSignalEvaluator(evaluation_time="2026-06-15T12:00:00Z")

    # Naive datetime assumed UTC (1 hour before evaluation_time)
    naive_arp = ArpEntry(
        ip="10.10.1.40",
        arp_mac="aa:bb:cc:dd:ee:01",
        arp_last_seen=datetime(2026, 6, 15, 11, 0, 0),
    )
    sig_naive = evaluator.evaluate(naive_arp)
    assert sig_naive.status is SignalStatus.ACTIVE
    assert sig_naive.observed_at == datetime(2026, 6, 15, 11, 0, 0, tzinfo=timezone.utc)
    assert sig_naive.age_seconds == pytest.approx(3600.0)

    # Non-UTC timezone offset (-04:00) equivalent to 2 hours before evaluation_time
    tz_minus_4 = timezone(timedelta(hours=-4))
    aware_arp = ArpEntry(
        ip="10.10.1.41",
        arp_mac="aa:bb:cc:dd:ee:02",
        arp_last_seen=datetime(2026, 6, 15, 6, 0, 0, tzinfo=tz_minus_4),
    )
    sig_aware = evaluator.evaluate(aware_arp)
    assert sig_aware.status is SignalStatus.ACTIVE
    assert sig_aware.observed_at == datetime(2026, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
    assert sig_aware.age_seconds == pytest.approx(7200.0)

    # Slight future timestamp due to clock skew clamped to 0.0
    future_arp = ArpEntry(
        ip="10.10.1.42",
        arp_mac="aa:bb:cc:dd:ee:03",
        arp_last_seen=FIXED_EVAL_TIME + timedelta(seconds=30),
    )
    sig_future = evaluator.evaluate(future_arp)
    assert sig_future.status is SignalStatus.ACTIVE
    assert sig_future.age_seconds == 0.0


def test_arp_signal_evaluator_multi_ip_equipment_and_device_correlation() -> None:
    evaluator = ArpSignalEvaluator(
        active_within_days=7.0,
        stale_after_days=30.0,
        evaluation_time=FIXED_EVAL_TIME,
    )

    fresh_dt = FIXED_EVAL_TIME - timedelta(days=1)
    stale_dt = FIXED_EVAL_TIME - timedelta(days=60)

    site = Site(
        site_id="S1",
        name="Site 1",
        devices=[
            NetworkDevice(
                device_id="SW1",
                site_id="S1",
                hostname="sw1.s1",
                management_ip="10.1.0.2",
                ports=[
                    Port(
                        port_id="P1",
                        device_id="SW1",
                        name="1/1",
                        connected_device_id="EQ1",
                        connected_mac="AA:BB:CC:11:22:33",
                    )
                ],
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.1.10.10",
                subnet_id="SUB10",
                assigned_object_id="EQ1",
                arp_mac="00:11:22:33:44:01",
                arp_last_seen=stale_dt,
            ),
            IPAddress(
                ip="10.1.10.11",
                subnet_id="SUB10",
                assigned_object_id="EQ1",
                arp_mac="00:11:22:33:44:02",
                arp_last_seen=None,
            ),
            IPAddress(
                ip="10.1.10.12",
                subnet_id="SUB10",
                arp_mac="aa-bb-cc-11-22-33",
                arp_last_seen=fresh_dt,
            ),
            IPAddress(
                ip="10.1.0.2",
                subnet_id="SUB0",
                assigned_object_id="SW1",
                arp_mac="00:11:22:99:99:99",
                arp_last_seen=fresh_dt,
            ),
        ],
    )

    eq = Equipment(
        equipment_id="EQ1",
        site_id="S1",
        name="srv-multi-nic",
        category=EquipmentCategory.SERVER,
        assigned_ips=["10.1.10.10", "10.1.10.11"],
        connected_ports=["P1"],
    )

    sig_eq = evaluator.evaluate(eq, site=site)
    assert sig_eq.status is SignalStatus.ACTIVE
    assert sig_eq.observed_at == fresh_dt
    assert sig_eq.age_seconds == pytest.approx(SECONDS_PER_DAY)
    assert sig_eq.details is not None
    assert "10.1.10.10" in sig_eq.details
    assert "10.1.10.11" in sig_eq.details
    assert "10.1.10.12" in sig_eq.details

    # When only stale and missing IPs are present, aggregate to INACTIVE with most recent timestamp
    eq_stale_only = Equipment(
        equipment_id="EQ2",
        site_id="S1",
        name="srv-stale",
        assigned_ips=["10.1.10.10", "10.1.10.11"],
    )
    sig_stale_eq = evaluator.evaluate(eq_stale_only, site=site)
    assert sig_stale_eq.status is SignalStatus.INACTIVE
    assert sig_stale_eq.observed_at == stale_dt
    assert sig_stale_eq.age_seconds == pytest.approx(60 * SECONDS_PER_DAY)

    # NetworkDevice ARP correlation via management_ip
    sig_dev = evaluator.evaluate(site.devices[0], site=site)
    assert sig_dev.status is SignalStatus.ACTIVE
    assert sig_dev.observed_at == fresh_dt


def test_port_state_signal_evaluator_single_port_states() -> None:
    evaluator = PortStateSignalEvaluator(evaluation_time=FIXED_EVAL_TIME)
    assert isinstance(evaluator, SignalCollector)

    # Link UP
    p_up = Port(
        port_id="P1",
        device_id="SW1",
        name="1/1",
        admin_status="up",
        oper_status="up",
        poe_status="off",
    )
    sig_up = evaluator.evaluate(p_up)
    assert sig_up.signal_type is SignalType.PORT_STATE
    assert sig_up.status is SignalStatus.ACTIVE
    assert sig_up.observed_at == FIXED_EVAL_TIME
    assert sig_up.details is not None
    assert "link UP" in sig_up.details

    # PoE delivering power even when oper_status is None
    p_poe = Port(
        port_id="P2",
        device_id="SW1",
        name="1/2",
        admin_status="enabled",
        oper_status=None,
        poe_status="15.4W",
    )
    sig_poe = evaluator.evaluate(p_poe)
    assert sig_poe.status is SignalStatus.ACTIVE
    assert sig_poe.details is not None
    assert "PoE delivering power" in sig_poe.details

    # Administratively disabled overrides oper_status
    p_admin_down = Port(
        port_id="P3",
        device_id="SW1",
        name="1/3",
        admin_status="disabled",
        oper_status="up",
    )
    sig_admin_down = evaluator.evaluate(p_admin_down)
    assert sig_admin_down.status is SignalStatus.INACTIVE
    assert sig_admin_down.details is not None
    assert "administratively disabled" in sig_admin_down.details

    # Oper status DOWN and PoE 0W
    p_down = Port(
        port_id="P4",
        device_id="SW1",
        name="1/4",
        admin_status="up",
        oper_status="down",
        poe_status="0.0W",
    )
    sig_down = evaluator.evaluate(p_down)
    assert sig_down.status is SignalStatus.INACTIVE

    # No port state recorded
    p_empty = Port(port_id="P5", device_id="SW1", name="1/5")
    sig_empty = evaluator.evaluate(p_empty)
    assert sig_empty.status is SignalStatus.NOT_APPLICABLE


def test_port_state_signal_evaluator_multi_port_aggregation() -> None:
    evaluator = PortStateSignalEvaluator(evaluation_time=FIXED_EVAL_TIME)

    port_down = Port(
        port_id="P10",
        device_id="SW1",
        name="1/10",
        admin_status="up",
        oper_status="down",
        connected_device_id="EQ-REDUNDANT",
    )
    port_admin_shut = Port(
        port_id="P11",
        device_id="SW1",
        name="1/11",
        admin_status="shutdown",
        oper_status="down",
    )
    port_up = Port(
        port_id="P12",
        device_id="SW2",
        name="1/12",
        admin_status="up",
        oper_status="up",
    )

    site = Site(
        site_id="S1",
        name="Site 1",
        devices=[
            NetworkDevice(
                device_id="SW1",
                site_id="S1",
                hostname="sw1",
                ports=[port_down, port_admin_shut],
            ),
            NetworkDevice(
                device_id="SW2",
                site_id="S1",
                hostname="sw2",
                ports=[port_up],
            ),
        ],
    )

    # Equipment with one DOWN port, one shutdown port, and one UP redundant port -> ACTIVE
    eq_redundant = Equipment(
        equipment_id="EQ-REDUNDANT",
        site_id="S1",
        name="san-dual-homed",
        category=EquipmentCategory.SAN,
        connected_ports=["P11", "SW2:1/12"],
    )
    sig_active = evaluator.evaluate(eq_redundant, site=site)
    assert sig_active.signal_type is SignalType.PORT_STATE
    assert sig_active.status is SignalStatus.ACTIVE
    assert sig_active.details is not None
    assert "P10" in sig_active.details
    assert "P11" in sig_active.details
    assert "P12" in sig_active.details

    # NetworkDevice SW1 has only DOWN/shutdown ports -> INACTIVE
    sig_sw1 = evaluator.evaluate(site.devices[0])
    assert sig_sw1.status is SignalStatus.INACTIVE
    assert sig_sw1.details is not None
    assert "P10" in sig_sw1.details
    assert "P11" in sig_sw1.details

    # Equipment with no mapped ports -> NOT_APPLICABLE
    eq_unmapped = Equipment(
        equipment_id="EQ-UNMAPPED",
        site_id="S1",
        name="vm-no-physical-port",
        category=EquipmentCategory.VM,
    )
    sig_unmapped = evaluator.evaluate(eq_unmapped, site=site)
    assert sig_unmapped.status is SignalStatus.NOT_APPLICABLE
    assert sig_unmapped.details is not None
    assert "no mapped switch ports" in sig_unmapped.details.lower()


def test_last_seen_signal_evaluator_equipment_and_device_recency() -> None:
    evaluator = LastSeenSignalEvaluator(
        active_within_days=7.0,
        stale_after_days=30.0,
        evaluation_time=FIXED_EVAL_TIME,
    )
    assert isinstance(evaluator, SignalCollector)

    # 1. Active NetworkDevice (seen 3 days ago)
    dev_active = NetworkDevice(
        device_id="SW1",
        site_id="S1",
        hostname="sw1.s1",
        last_seen=FIXED_EVAL_TIME - timedelta(days=3),
    )
    sig_active = evaluator.evaluate(dev_active)
    assert sig_active.signal_type is SignalType.LAST_SEEN_TIMESTAMP
    assert sig_active.status is SignalStatus.ACTIVE
    assert sig_active.observed_at == FIXED_EVAL_TIME - timedelta(days=3)
    assert sig_active.age_seconds == pytest.approx(3 * SECONDS_PER_DAY)
    assert sig_active.details is not None
    assert "active" in sig_active.details.lower()

    # 2. Intermediate Equipment (seen 20 days ago: > 7d, <= 30d)
    eq_inter = Equipment(
        equipment_id="EQ1",
        site_id="S1",
        name="ups-01",
        category=EquipmentCategory.UPS,
        last_seen=FIXED_EVAL_TIME - timedelta(days=20),
    )
    sig_inter = evaluator.evaluate(eq_inter)
    assert sig_inter.signal_type is SignalType.LAST_SEEN_TIMESTAMP
    assert sig_inter.status is SignalStatus.INACTIVE
    assert sig_inter.observed_at == FIXED_EVAL_TIME - timedelta(days=20)
    assert sig_inter.age_seconds == pytest.approx(20 * SECONDS_PER_DAY)
    assert sig_inter.details is not None
    assert "intermediate" in sig_inter.details.lower()

    # 3. Stale Equipment (seen 90 days ago: > 30d)
    eq_stale = Equipment(
        equipment_id="EQ2",
        site_id="S1",
        name="old-srv-01",
        category=EquipmentCategory.SERVER,
        last_seen=FIXED_EVAL_TIME - timedelta(days=90),
    )
    sig_stale = evaluator.evaluate(eq_stale)
    assert sig_stale.signal_type is SignalType.LAST_SEEN_TIMESTAMP
    assert sig_stale.status is SignalStatus.INACTIVE
    assert sig_stale.observed_at == FIXED_EVAL_TIME - timedelta(days=90)
    assert sig_stale.age_seconds == pytest.approx(90 * SECONDS_PER_DAY)
    assert sig_stale.details is not None
    assert "stale" in sig_stale.details.lower()


def test_last_seen_signal_evaluator_missing_malformed_and_timezones() -> None:
    evaluator = LastSeenSignalEvaluator(evaluation_time=FIXED_EVAL_TIME)

    # Missing last_seen -> NOT_APPLICABLE
    eq_missing = Equipment(equipment_id="EQ-NONE", site_id="S1", name="srv-no-ts")
    sig_missing = evaluator.evaluate(eq_missing)
    assert sig_missing.signal_type is SignalType.LAST_SEEN_TIMESTAMP
    assert sig_missing.status is SignalStatus.NOT_APPLICABLE
    assert sig_missing.observed_at is None
    assert sig_missing.age_seconds is None

    # Malformed string mutated onto Equipment.last_seen -> ERROR
    eq_bad = Equipment(equipment_id="EQ-BAD", site_id="S1", name="srv-bad-ts")
    eq_bad.last_seen = "not-a-valid-date"  # type: ignore[assignment]
    sig_bad = evaluator.evaluate(eq_bad)
    assert sig_bad.status is SignalStatus.ERROR
    assert sig_bad.observed_at is None
    assert sig_bad.age_seconds is None
    assert sig_bad.details is not None
    assert "invalid last_seen" in sig_bad.details.lower()

    # Invalid type mutated onto NetworkDevice.last_seen -> ERROR
    dev_bad_type = NetworkDevice(device_id="SW-BAD", site_id="S1", hostname="sw-bad")
    dev_bad_type.last_seen = 99999  # type: ignore[assignment]
    sig_bad_type = evaluator.evaluate(dev_bad_type)
    assert sig_bad_type.status is SignalStatus.ERROR

    # Naive and timezone-offset normalization on NetworkDevice
    tz_plus_2 = timezone(timedelta(hours=2))
    dev_tz = NetworkDevice(
        device_id="SW-TZ",
        site_id="S1",
        hostname="sw-tz",
        last_seen=datetime(2026, 6, 15, 13, 0, 0, tzinfo=tz_plus_2),
    )
    sig_tz = evaluator.evaluate(dev_tz)
    assert sig_tz.status is SignalStatus.ACTIVE
    assert sig_tz.observed_at == datetime(2026, 6, 15, 11, 0, 0, tzinfo=timezone.utc)
    assert sig_tz.age_seconds == pytest.approx(3600.0)
