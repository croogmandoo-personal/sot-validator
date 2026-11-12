"""Unit tests for the snapshot diff engine and drift alert dispatcher."""

from __future__ import annotations

from datetime import datetime, timezone
import io
import json
import logging
from typing import Any, Mapping
import urllib.error
import urllib.request

import pytest

from sot_validator.curation import CurationStore, ItemEditPatch
from sot_validator.discovery import (
    DiscoveredHost,
    DriftAlertDispatcher,
    DriftAlertTarget,
    DriftDispatchResult,
    ScanDriftEvent,
    ScanDriftEventType,
    SnapshotDiffEngine,
    SnapshotDiffReport,
)
from sot_validator.discovery import monitor
from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
)

SITE = "site-42"
BASE_TS = datetime(2026, 1, 1, 8, 0, tzinfo=timezone.utc)
CUR_TS = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
TOKEN = "s3cr3t-token"


def _ip(ip: str, *, obj_type: str | None = None, obj_id: str | None = None, mac: str | None = None) -> IPAddress:
    return IPAddress(
        ip=ip,
        subnet_id="sn-10",
        assigned_object_type=obj_type,
        assigned_object_id=obj_id,
        arp_mac=mac,
    )


def _site(**kwargs: Any) -> Site:
    return Site(site_id=SITE, name="Site 42", **kwargs)


def _diff(baseline: Site, current: Site, **kwargs: Any) -> SnapshotDiffReport:
    kwargs.setdefault("baseline_timestamp", BASE_TS)
    kwargs.setdefault("current_timestamp", CUR_TS)
    return SnapshotDiffEngine().diff(baseline, current, **kwargs)


def _of_type(report: SnapshotDiffReport, event_type: ScanDriftEventType) -> list[ScanDriftEvent]:
    return [e for e in report.events if e.event_type is event_type]


class RecordingSender:
    def __init__(self, statuses: list[Any] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.statuses = list(statuses or [])

    def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> int:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        status = self.statuses.pop(0) if self.statuses else 200
        if isinstance(status, Exception):
            raise status
        return status


# ---------------------------------------------------------------------------
# Event types


def test_new_host_joined_event() -> None:
    baseline = _site()
    current = _site(
        ip_addresses=[_ip("10.42.10.20", obj_type="Equipment", obj_id="eq-20", mac="00-04-96-AA-BB-01")]
    )
    report = _diff(baseline, current)
    assert len(report.events) == 1
    event = report.events[0]
    assert event.event_type is ScanDriftEventType.NEW_HOST_JOINED
    assert event.severity == "warning"
    assert event.ip == "10.42.10.20"
    assert event.target_id == "eq-20"
    assert event.previous_value is None
    assert event.current_value == "00:04:96:aa:bb:01"
    assert "10.42.10.20" in event.summary and "eq-20" in event.summary


def test_new_host_without_mac_or_assignment_targets_ip() -> None:
    report = _diff(_site(), _site(ip_addresses=[_ip("10.42.10.21")]))
    event = report.events[0]
    assert event.target_id == "10.42.10.21"
    assert event.current_value is None


def test_host_went_offline_non_critical_stays_warning() -> None:
    baseline = _site(
        ip_addresses=[_ip("10.42.10.30", obj_type="Equipment", obj_id="eq-30", mac="00:04:96:aa:bb:30")],
        equipment=[Equipment(equipment_id="eq-30", site_id=SITE, name="printer", assigned_ips=["10.42.10.30"])],
    )
    report = _diff(baseline, _site())
    assert len(report.events) == 1
    event = report.events[0]
    assert event.event_type is ScanDriftEventType.HOST_WENT_OFFLINE
    assert event.severity == "warning"
    assert event.ip == "10.42.10.30"
    assert event.target_id == "eq-30"
    assert event.previous_value == "00:04:96:aa:bb:30"
    assert event.current_value is None


def test_record_level_offline_for_device_without_ip_record() -> None:
    baseline = _site(
        devices=[NetworkDevice(device_id="dev-ap", site_id=SITE, hostname="ap-01", management_ip="10.42.10.60", role="ap")],
        equipment=[Equipment(equipment_id="eq-nas", site_id=SITE, name="nas-01")],
    )
    report = _diff(baseline, _site())
    offline = _of_type(report, ScanDriftEventType.HOST_WENT_OFFLINE)
    assert [(e.target_id, e.ip, e.previous_value, e.current_value) for e in offline] == [
        ("dev-ap", "10.42.10.60", "ap-01", None),
        ("eq-nas", None, "nas-01", None),
    ]
    assert all(e.severity == "warning" for e in offline)


def test_device_disappearing_with_its_ip_yields_one_offline_event() -> None:
    baseline = _site(
        devices=[NetworkDevice(device_id="dev-sw1", site_id=SITE, hostname="sw-01", management_ip="10.42.10.2")],
        ip_addresses=[_ip("10.42.10.2", obj_type="NetworkDevice", obj_id="dev-sw1")],
    )
    report = _diff(baseline, _site())
    assert len(report.events) == 1
    assert report.events[0].event_type is ScanDriftEventType.HOST_WENT_OFFLINE
    assert report.events[0].target_id == "dev-sw1"


def test_critical_router_offline_acceptance() -> None:
    baseline = _site(
        devices=[NetworkDevice(device_id="dev-rtr", site_id=SITE, hostname="rtr-01", management_ip="10.42.10.5", role="router")],
        ip_addresses=[_ip("10.42.10.5", obj_type="NetworkDevice", obj_id="dev-rtr", mac="00:04:96:00:00:05")],
    )
    report = _diff(baseline, _site())
    assert len(report.events) == 1
    event = report.events[0]
    assert event.event_type is ScanDriftEventType.CRITICAL_ASSET_OFFLINE
    assert event.severity == "critical"
    assert event.ip == "10.42.10.5"
    assert event.target_id == "dev-rtr"
    assert event.previous_value == "00:04:96:00:00:05"
    assert event.current_value is None
    assert "role router" in event.summary
    assert not _of_type(report, ScanDriftEventType.HOST_WENT_OFFLINE)


def test_critical_offline_via_pinned_patch_list() -> None:
    baseline = _site(ip_addresses=[_ip("10.42.10.40", obj_type="Equipment", obj_id="eq-40")])
    patches = [
        ItemEditPatch(
            target_type="Equipment",
            target_id="eq-40",
            pinned_classification=ValidationClassification.CONFIRMED_ACTIVE,
        )
    ]
    report = _diff(baseline, _site(), curation=patches)
    event = report.events[0]
    assert event.event_type is ScanDriftEventType.CRITICAL_ASSET_OFFLINE
    assert event.severity == "critical"
    assert event.ip == "10.42.10.40"
    assert event.target_id == "eq-40"
    assert event.previous_value is None and event.current_value is None
    assert "pinned Confirmed Active" in event.summary


def test_critical_offline_via_curation_store_and_ignores_deleted_and_other_site() -> None:
    store = CurationStore(":memory:")
    store.upsert_patch(
        ItemEditPatch(
            target_type="IPAddress",
            target_id="10.42.10.41",
            site_id=SITE,
            pinned_classification="Confirmed Active",
        )
    )
    store.upsert_patch(
        ItemEditPatch(
            target_type="IPAddress",
            target_id="10.42.10.42",
            site_id="other-site",
            pinned_classification="Confirmed Active",
        )
    )
    deleted = [
        ItemEditPatch(
            target_type="IPAddress",
            target_id="10.42.10.43",
            role="router",
            deleted=True,
        )
    ]
    baseline = _site(ip_addresses=[_ip("10.42.10.41"), _ip("10.42.10.42"), _ip("10.42.10.43")])
    patches_before = [p.to_dict() for p in store.list_patches()]

    report = _diff(baseline, _site(), curation=store)
    types = {e.ip: e.event_type for e in report.events}
    assert types["10.42.10.41"] is ScanDriftEventType.CRITICAL_ASSET_OFFLINE
    assert types["10.42.10.42"] is ScanDriftEventType.HOST_WENT_OFFLINE
    assert [p.to_dict() for p in store.list_patches()] == patches_before

    report_deleted = _diff(baseline, _site(), curation=deleted)
    assert {e.ip: e.event_type for e in report_deleted.events}["10.42.10.43"] is (
        ScanDriftEventType.HOST_WENT_OFFLINE
    )
    store.close()


def test_critical_offline_via_discovered_host_inferred_role() -> None:
    baseline = _site(ip_addresses=[_ip("10.42.10.50", obj_type="Equipment", obj_id="eq-esx")])
    hosts = [
        DiscoveredHost(
            ip="10.42.10.50",
            subnet_cidr="10.42.10.0/24",
            vlan_id="10",
            open_tcp_ports=[443, 902],
            inferred_role="Hypervisor",
        )
    ]
    report = _diff(baseline, _site(), baseline_open_ports=hosts)
    event = report.events[0]
    assert event.event_type is ScanDriftEventType.CRITICAL_ASSET_OFFLINE
    assert event.severity == "critical"
    assert event.target_id == "eq-esx"
    assert "role hypervisor" in event.summary


def test_critical_offline_via_curation_role_on_record_level() -> None:
    baseline = _site(equipment=[Equipment(equipment_id="eq-esx2", site_id=SITE, name="esx-02", category=EquipmentCategory.SERVER)])
    patches = [ItemEditPatch(target_type="Equipment", target_id="eq-esx2", role=" Hypervisor ")]
    report = _diff(baseline, _site(), curation=patches)
    event = report.events[0]
    assert event.event_type is ScanDriftEventType.CRITICAL_ASSET_OFFLINE
    assert event.target_id == "eq-esx2"
    assert event.ip is None
    assert event.previous_value == "esx-02"


def test_mac_address_changed_non_critical_warning() -> None:
    baseline = _site(ip_addresses=[_ip("10.42.10.70", obj_type="Equipment", obj_id="eq-70", mac="00:04:96:aa:aa:70")])
    current = _site(ip_addresses=[_ip("10.42.10.70", obj_type="Equipment", obj_id="eq-70", mac="00:04:96:bb:bb:70")])
    report = _diff(baseline, current)
    assert len(report.events) == 1
    event = report.events[0]
    assert event.event_type is ScanDriftEventType.MAC_ADDRESS_CHANGED
    assert event.severity == "warning"
    assert event.ip == "10.42.10.70"
    assert event.target_id == "eq-70"
    assert event.previous_value == "00:04:96:aa:aa:70"
    assert event.current_value == "00:04:96:bb:bb:70"


def test_mac_change_critical_via_pinned_patch() -> None:
    baseline = _site(ip_addresses=[_ip("10.42.10.71", mac="00:04:96:aa:aa:71")])
    current = _site(
        ip_addresses=[
            IPAddress(
                ip="10.42.10.71",
                subnet_id="sn-10",
                arp_entry=ArpEntry(ip="10.42.10.71", arp_mac="00:04:96:BB:BB:71"),
            )
        ]
    )
    patches = [ItemEditPatch(target_type="IPAddress", target_id="10.42.10.71", pinned_classification="Confirmed Active")]
    event = _diff(baseline, current, curation=patches).events[0]
    assert event.event_type is ScanDriftEventType.MAC_ADDRESS_CHANGED
    assert event.severity == "critical"
    assert event.target_id == "10.42.10.71"
    assert event.current_value == "00:04:96:bb:bb:71"
    assert "pinned Confirmed Active" in event.summary


def test_mac_change_critical_via_device_role() -> None:
    device = NetworkDevice(device_id="dev-sw2", site_id=SITE, hostname="sw-02", management_ip="10.42.10.3", role="switch")
    baseline = _site(devices=[device], ip_addresses=[_ip("10.42.10.3", obj_type="NetworkDevice", obj_id="dev-sw2", mac="00:04:96:00:00:03")])
    current = _site(devices=[device], ip_addresses=[_ip("10.42.10.3", obj_type="NetworkDevice", obj_id="dev-sw2", mac="00:04:96:00:00:33")])
    event = _diff(baseline, current).events[0]
    assert event.event_type is ScanDriftEventType.MAC_ADDRESS_CHANGED
    assert event.severity == "critical"
    assert event.target_id == "dev-sw2"
    assert "role switch" in event.summary


def test_mac_appearing_disappearing_or_format_only_is_not_a_change() -> None:
    baseline = _site(
        ip_addresses=[
            _ip("10.42.10.80"),
            _ip("10.42.10.81", mac="00:04:96:aa:bb:81"),
            _ip("10.42.10.82", mac="00-04-96-AA-BB-CC"),
        ]
    )
    current = _site(
        ip_addresses=[
            _ip("10.42.10.80", mac="00:04:96:aa:bb:80"),
            _ip("10.42.10.81"),
            _ip("10.42.10.82", mac="0004.96aa.bbcc"),
        ]
    )
    report = _diff(baseline, current)
    assert report.events == []


def test_open_ports_changed_with_mappings_and_hosts() -> None:
    baseline = _site(ip_addresses=[_ip("10.42.10.90", obj_type="Equipment", obj_id="eq-90"), _ip("10.42.10.91")])
    current = _site(ip_addresses=[_ip("10.42.10.90", obj_type="Equipment", obj_id="eq-90"), _ip("10.42.10.91")])
    report = _diff(
        baseline,
        current,
        baseline_open_ports={"10.42.10.90": [443, 22], "10.42.10.91": [80]},
        current_open_ports=[
            DiscoveredHost(ip="10.42.10.90", subnet_cidr="10.42.10.0/24", vlan_id="10", open_tcp_ports=[8443, 22]),
        ],
    )
    events = _of_type(report, ScanDriftEventType.OPEN_PORTS_CHANGED)
    assert len(events) == 1
    event = events[0]
    assert event.severity == "info"
    assert event.ip == "10.42.10.90"
    assert event.target_id == "eq-90"
    assert event.previous_value == [22, 443]
    assert event.current_value == [22, 8443]


def test_no_port_or_classification_events_without_both_inputs() -> None:
    baseline = _site(ip_addresses=[_ip("10.42.10.92")])
    current = _site(ip_addresses=[_ip("10.42.10.92")])
    results_a = [ValidationResult("IPAddress", "10.42.10.92", SITE, "h", ValidationClassification.CONFIRMED_ACTIVE)]
    results_b = [ValidationResult("IPAddress", "10.42.10.92", SITE, "h", ValidationClassification.STALE_LIKELY_UNUSED)]

    report = _diff(baseline, current)
    assert not _of_type(report, ScanDriftEventType.OPEN_PORTS_CHANGED)
    assert not _of_type(report, ScanDriftEventType.CLASSIFICATION_CHANGED)

    report = _diff(baseline, current, baseline_open_ports={"10.42.10.92": [22]}, baseline_results=results_a)
    assert not _of_type(report, ScanDriftEventType.OPEN_PORTS_CHANGED)
    assert not _of_type(report, ScanDriftEventType.CLASSIFICATION_CHANGED)

    report = _diff(baseline, current, current_open_ports={"10.42.10.92": [80]}, current_results=results_b)
    assert report.events == []


def test_new_subnet_discovered_events() -> None:
    baseline = _site(subnets=[Subnet(subnet_id="sn-10", site_id=SITE, cidr="10.42.10.0/24")])
    current = _site(
        subnets=[
            Subnet(subnet_id="sn-10", site_id=SITE, cidr="10.42.10.0/24"),
            Subnet(subnet_id="sn-20", site_id=SITE, cidr="10.42.20.7/24", gateway="10.42.20.1"),
        ],
        vlans=[
            VLAN(vlan_id="10", site_id=SITE, cidr="10.42.10.0/24"),
            VLAN(vlan_id="30", site_id=SITE, cidr="10.42.30.0/24", gateway="10.42.30.1"),
            VLAN(vlan_id="99", site_id=SITE),
        ],
    )
    events = _of_type(_diff(baseline, current), ScanDriftEventType.NEW_SUBNET_DISCOVERED)
    assert [(e.target_id, e.ip, e.previous_value, e.current_value, e.severity) for e in events] == [
        ("sn-20", "10.42.20.1", None, "10.42.20.0/24", "warning"),
        ("30", "10.42.30.1", None, "10.42.30.0/24", "warning"),
        ("99", None, None, "99", "warning"),
    ]
    assert "gateway 10.42.20.1" in events[0].summary


def test_classification_changed_event() -> None:
    site = _site()
    baseline_results = [
        ValidationResult("Equipment", "eq-1", SITE, "srv-1", ValidationClassification.CONFIRMED_ACTIVE),
        ValidationResult("Equipment", "eq-2", "other-site", "srv-2", ValidationClassification.CONFIRMED_ACTIVE),
    ]
    current_results = [
        ValidationResult("Equipment", "eq-1", SITE, "srv-1", ValidationClassification.STALE_LIKELY_UNUSED),
        ValidationResult("Equipment", "eq-2", "other-site", "srv-2", ValidationClassification.STALE_LIKELY_UNUSED),
    ]
    report = _diff(site, site, baseline_results=baseline_results, current_results=current_results)
    assert len(report.events) == 1
    event = report.events[0]
    assert event.event_type is ScanDriftEventType.CLASSIFICATION_CHANGED
    assert event.severity == "info"
    assert event.ip is None
    assert event.target_id == "eq-1"
    assert event.previous_value == "Confirmed Active"
    assert event.current_value == "Stale / Likely Unused"


def test_default_severities_constant_and_docstring() -> None:
    expected = {
        ScanDriftEventType.NEW_HOST_JOINED: "warning",
        ScanDriftEventType.HOST_WENT_OFFLINE: "warning",
        ScanDriftEventType.CRITICAL_ASSET_OFFLINE: "critical",
        ScanDriftEventType.MAC_ADDRESS_CHANGED: "warning",
        ScanDriftEventType.OPEN_PORTS_CHANGED: "info",
        ScanDriftEventType.NEW_SUBNET_DISCOVERED: "warning",
        ScanDriftEventType.CLASSIFICATION_CHANGED: "info",
    }
    assert monitor.DEFAULT_DRIFT_SEVERITY == expected
    doc = SnapshotDiffEngine.__doc__ or ""
    for event_type, severity in expected.items():
        assert f"``{event_type.value}``: ``{severity}``" in doc


def test_event_type_members_in_order() -> None:
    assert [m.value for m in ScanDriftEventType] == [
        "NEW_HOST_JOINED",
        "HOST_WENT_OFFLINE",
        "CRITICAL_ASSET_OFFLINE",
        "MAC_ADDRESS_CHANGED",
        "OPEN_PORTS_CHANGED",
        "NEW_SUBNET_DISCOVERED",
        "CLASSIFICATION_CHANGED",
    ]


# ---------------------------------------------------------------------------
# Engine contract


def test_mismatched_site_id_and_bad_inputs_raise() -> None:
    other = Site(site_id="site-99", name="Other")
    with pytest.raises(ValueError):
        SnapshotDiffEngine().diff(_site(), other)
    with pytest.raises(ValueError):
        SnapshotDiffEngine().diff(_site(), {"site_id": SITE})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        SnapshotDiffEngine().diff(_site(), _site(), curation="not-a-store")  # type: ignore[arg-type]


def _rich_pair() -> tuple[Site, Site]:
    baseline = _site(
        devices=[NetworkDevice(device_id="dev-rtr", site_id=SITE, hostname="rtr-01", management_ip="10.42.10.1", role="router")],
        ip_addresses=[
            _ip("10.42.10.1", obj_type="NetworkDevice", obj_id="dev-rtr", mac="00:04:96:00:00:01"),
            _ip("10.42.10.9", mac="00:04:96:00:00:09"),
            _ip("10.42.10.11", mac="00:04:96:00:00:11"),
        ],
        subnets=[Subnet(subnet_id="sn-10", site_id=SITE, cidr="10.42.10.0/24")],
    )
    current = _site(
        ip_addresses=[
            _ip("10.42.10.9", mac="00:04:96:00:00:99"),
            _ip("10.42.10.11", mac="00:04:96:00:00:11"),
            _ip("10.42.10.100"),
            _ip("10.42.10.20"),
        ],
        subnets=[
            Subnet(subnet_id="sn-10", site_id=SITE, cidr="10.42.10.0/24"),
            Subnet(subnet_id="sn-20", site_id=SITE, cidr="10.42.20.0/24", gateway="10.42.20.1"),
        ],
    )
    return baseline, current


def test_inputs_are_not_mutated() -> None:
    baseline, current = _rich_pair()
    base_ports = {"10.42.10.11": [22, 80]}
    cur_ports = {"10.42.10.11": [22]}
    patches = [ItemEditPatch(target_type="IPAddress", target_id="10.42.10.9", pinned_classification="Confirmed Active")]
    results = [ValidationResult("IPAddress", "10.42.10.9", SITE, "h", ValidationClassification.CONFIRMED_ACTIVE)]
    before = (
        baseline.to_dict(),
        current.to_dict(),
        json.dumps(base_ports),
        json.dumps(cur_ports),
        [p.to_dict() for p in patches],
        [r.to_dict() for r in results],
    )
    _diff(
        baseline,
        current,
        baseline_open_ports=base_ports,
        current_open_ports=cur_ports,
        curation=patches,
        baseline_results=results,
        current_results=results,
    )
    after = (
        baseline.to_dict(),
        current.to_dict(),
        json.dumps(base_ports),
        json.dumps(cur_ports),
        [p.to_dict() for p in patches],
        [r.to_dict() for r in results],
    )
    assert before == after


def test_deterministic_ids_and_severity_order() -> None:
    baseline, current = _rich_pair()
    first = _diff(baseline, current, current_timestamp=CUR_TS)
    second = _diff(baseline, current, current_timestamp=datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert [e.event_id for e in first.events] == [e.event_id for e in second.events]
    assert all(e.event_id.startswith("drift-") and len(e.event_id) == 22 for e in first.events)
    assert [(e.event_type.value, e.ip) for e in first.events] == [
        ("CRITICAL_ASSET_OFFLINE", "10.42.10.1"),
        ("NEW_HOST_JOINED", "10.42.10.20"),
        ("NEW_HOST_JOINED", "10.42.10.100"),
        ("MAC_ADDRESS_CHANGED", "10.42.10.9"),
        ("NEW_SUBNET_DISCOVERED", "10.42.20.1"),
    ]
    assert first.highest_severity == "critical"
    assert first.events[0].detected_at == CUR_TS


def test_timestamp_defaults() -> None:
    report = SnapshotDiffEngine().diff(_site(), _site(ip_addresses=[_ip("10.42.10.5")]), current_timestamp="2026-01-01T09:00:00")
    assert report.baseline_timestamp is None
    assert report.current_timestamp == CUR_TS
    assert report.events[0].detected_at == CUR_TS


# ---------------------------------------------------------------------------
# Event and report models


def test_scan_drift_event_validates_severity_and_type() -> None:
    kwargs: dict[str, Any] = dict(
        event_id="drift-1",
        event_type="NEW_HOST_JOINED",
        severity="warning",
        site_id=SITE,
        target_id="10.42.10.5",
        ip="10.42.10.5",
        previous_value=None,
        current_value=None,
        detected_at="2026-01-01T09:00:00Z",
        summary="New host.",
    )
    event = ScanDriftEvent(**kwargs)
    assert event.event_type is ScanDriftEventType.NEW_HOST_JOINED
    assert event.detected_at == CUR_TS
    for bad in ("WARNING", "high"):
        with pytest.raises(ValueError):
            ScanDriftEvent(**{**kwargs, "severity": bad})
    with pytest.raises(ValueError):
        ScanDriftEvent(**{**kwargs, "event_type": "NOPE"})
    with pytest.raises(ValueError):
        ScanDriftEvent(**{**kwargs, "summary": ""})


def test_summary_counts_and_json_round_trip() -> None:
    empty = SnapshotDiffReport(site_id=SITE, baseline_timestamp=None, current_timestamp=CUR_TS)
    assert empty.summary_counts == {
        "total": 0,
        "by_type": {m.value: 0 for m in ScanDriftEventType},
        "by_severity": {"critical": 0, "warning": 0, "info": 0},
    }
    assert empty.highest_severity is None

    baseline, current = _rich_pair()
    report = _diff(baseline, current)
    data = json.loads(report.to_json())
    assert data["site_id"] == SITE
    assert data["baseline_timestamp"] == BASE_TS.isoformat()
    assert data["current_timestamp"] == CUR_TS.isoformat()
    assert datetime.fromisoformat(data["events"][0]["detected_at"]) == CUR_TS
    assert data["events"][0]["event_type"] == "CRITICAL_ASSET_OFFLINE"
    assert data["highest_severity"] == "critical"
    assert data["summary_counts"]["total"] == 5
    assert data["summary_counts"]["by_severity"] == {"critical": 1, "warning": 4, "info": 0}
    assert data["summary_counts"]["by_type"]["NEW_HOST_JOINED"] == 2
    assert data["summary_counts"]["by_type"]["OPEN_PORTS_CHANGED"] == 0
    assert json.loads(empty.to_json())["baseline_timestamp"] is None


def test_to_markdown_rows_escaping_and_empty() -> None:
    baseline = _site(ip_addresses=[_ip("10.42.10.7", obj_type="Equipment", obj_id="eq|pipe")])
    current = _site(ip_addresses=[_ip("10.42.10.8")])
    report = _diff(
        baseline,
        current,
        curation=[ItemEditPatch(target_type="Equipment", target_id="eq|pipe", role="router")],
    )
    md = report.to_markdown()
    assert md.startswith(f"# Snapshot Drift Report: {SITE}")
    assert f"Baseline: {BASE_TS.isoformat()}" in md
    assert "- Total: 2" in md
    assert "- critical: 1" in md
    assert "- NEW_HOST_JOINED: 1" in md
    assert "| Severity | Type | Target | IP | Previous | Current | Summary |" in md
    assert "eq\\|pipe" in md
    critical_row = md.index("| critical | CRITICAL_ASSET_OFFLINE |")
    warning_row = md.index("| warning | NEW_HOST_JOINED |")
    assert critical_row < warning_row
    assert "| - |" in md

    ports_report = _diff(
        _site(ip_addresses=[_ip("10.42.10.9")]),
        _site(ip_addresses=[_ip("10.42.10.9")]),
        baseline_open_ports={"10.42.10.9": [22]},
        current_open_ports={"10.42.10.9": [22, 443]},
    )
    assert "| 22 | 22, 443 |" in ports_report.to_markdown()

    empty = SnapshotDiffReport(site_id=SITE, baseline_timestamp=None, current_timestamp=CUR_TS)
    empty_md = empty.to_markdown()
    assert "Baseline: unknown" in empty_md
    assert "No drift detected." in empty_md
    assert "| Severity |" not in empty_md


# ---------------------------------------------------------------------------
# Dispatcher


def _report() -> SnapshotDiffReport:
    baseline, current = _rich_pair()
    return _diff(baseline, current)


def test_dispatcher_writes_json_file_into_new_nested_folder(tmp_path) -> None:
    path = tmp_path / "a" / "b" / "drift.json"
    report = _report()
    results = DriftAlertDispatcher([DriftAlertTarget(kind="json_file", destination=str(path))]).dispatch(report)
    assert results == [
        DriftDispatchResult(
            name="json_file",
            kind="json_file",
            status="sent",
            http_status=None,
            destination=str(path),
            detail=None,
        )
    ]
    assert json.loads(path.read_text(encoding="utf-8")) == report.to_dict()


def test_generic_webhook_post() -> None:
    sender = RecordingSender([204])
    url = "https://hooks.example.com/hook/abc123secretid"
    results = DriftAlertDispatcher(
        [DriftAlertTarget(kind="webhook", destination=url, name="ops")],
        sender=sender,
        timeout_seconds=3.5,
    ).dispatch(_report())
    assert results[0].status == "sent"
    assert results[0].http_status == 204
    assert results[0].destination == "https://hooks.example.com"
    call = sender.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == url
    assert call["headers"] == {"Content-Type": "application/json"}
    assert call["timeout"] == 3.5
    payload = json.loads(call["body"].decode("utf-8"))
    assert set(payload) == {
        "source",
        "event_type",
        "site_id",
        "baseline_timestamp",
        "current_timestamp",
        "highest_severity",
        "event_count",
        "summary_counts",
        "events",
    }
    assert payload["source"] == "sot-validator"
    assert payload["event_count"] == len(payload["events"]) == 5


def test_home_assistant_event_and_webhook_posts() -> None:
    sender = RecordingSender([200, 200])
    targets = [
        DriftAlertTarget(kind="home_assistant_event", destination="http://ha.local:8123/", token=TOKEN),
        DriftAlertTarget(kind="home_assistant_webhook", destination="http://ha.local:8123/api/webhook/drift-hook-id"),
    ]
    results = DriftAlertDispatcher(targets, sender=sender).dispatch(_report())
    assert [r.status for r in results] == ["sent", "sent"]

    event_call, webhook_call = sender.calls
    assert event_call["url"] == "http://ha.local:8123/api/events/sot_validator_drift"
    assert event_call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert event_call["headers"]["Content-Type"] == "application/json"
    assert event_call["timeout"] == 10.0
    assert TOKEN.encode() not in event_call["body"]
    body = json.loads(event_call["body"])
    assert body["event_type"] == "sot_validator_drift"
    assert body["site_id"] == SITE
    assert body["highest_severity"] == "critical"
    assert body["summary_counts"]["total"] == 5
    assert len(body["events"]) == 5

    assert webhook_call["url"] == "http://ha.local:8123/api/webhook/drift-hook-id"
    assert webhook_call["headers"] == {"Content-Type": "application/json"}
    assert results[1].destination == "http://ha.local:8123"


def test_dispatch_sends_empty_report() -> None:
    sender = RecordingSender()
    empty = SnapshotDiffReport(site_id=SITE, baseline_timestamp=None, current_timestamp=CUR_TS)
    results = DriftAlertDispatcher([DriftAlertTarget(kind="webhook", destination="http://hook.local/x")], sender=sender).dispatch(empty)
    assert results[0].status == "sent"
    payload = json.loads(sender.calls[0]["body"])
    assert payload["event_count"] == 0
    assert payload["highest_severity"] is None


def test_failures_are_isolated_and_redacted(tmp_path, caplog) -> None:
    ha_base = "http://ha.local:8123"
    ha_url = f"{ha_base}/api/events/sot_validator_drift"
    hook_url = "https://hooks.example.com/hook/very-secret-hook-id"
    sender = RecordingSender(
        [
            ConnectionError(f"failed to reach {ha_url} with Bearer {TOKEN}"),
            500,
            200,
        ]
    )
    targets = [
        DriftAlertTarget(kind="home_assistant_event", destination=ha_base, token=TOKEN, name="ha"),
        DriftAlertTarget(kind="webhook", destination=hook_url, name="hook"),
        DriftAlertTarget(kind="home_assistant_webhook", destination="http://ha.local:8123/api/webhook/other-id", name="ha-hook"),
        DriftAlertTarget(kind="json_file", destination=str(tmp_path / "out.json"), name="file"),
    ]
    dispatcher = DriftAlertDispatcher(targets, sender=sender)
    with caplog.at_level(logging.DEBUG):
        results = dispatcher.dispatch(_report())

    assert [r.status for r in results] == ["failed", "failed", "sent", "sent"]
    assert results[0].detail == "ConnectionError: failed to reach *** with Bearer ***"
    assert results[0].http_status is None
    assert results[1].detail == "HTTP 500"
    assert results[1].http_status == 500
    assert results[1].destination == "https://hooks.example.com"

    texts = [repr(r) for r in results] + [str(r) for r in results]
    texts += [repr(t) for t in targets] + [str(t) for t in targets]
    texts += [repr(dispatcher), str(dispatcher), caplog.text]
    for text in texts:
        assert TOKEN not in text
    for text in [repr(r) for r in results] + [repr(dispatcher), caplog.text]:
        assert ha_url not in text
        assert hook_url not in text
    assert "failed" in caplog.text


def test_target_validation_rejects_bad_targets() -> None:
    assert TOKEN not in repr(DriftAlertTarget(kind="home_assistant_event", destination="http://ha.local:8123", token=TOKEN))
    bad_cases = [
        dict(kind="webhook", destination="ftp://hooks.example.com/x"),
        dict(kind="home_assistant_webhook", destination="file:///etc/passwd"),
        dict(kind="webhook", destination="https:///no-host"),
        dict(kind="home_assistant_event", destination="http://ha.local:8123"),
        dict(kind="home_assistant_event", destination="http://ha.local:8123", token="  "),
        dict(kind="webhook", destination="https://hooks.example.com/x", token=TOKEN),
        dict(kind="json_file", destination="out.json", token=TOKEN),
        dict(kind="home_assistant_event", destination="ftp://ha.local", token=TOKEN),
        dict(kind="slack", destination="https://hooks.example.com/x"),
    ]
    for case in bad_cases:
        with pytest.raises(ValueError) as excinfo:
            DriftAlertTarget(**case)
        assert TOKEN not in str(excinfo.value)
    with pytest.raises(ValueError):
        DriftAlertDispatcher([])
    with pytest.raises(ValueError):
        DriftAlertDispatcher([DriftAlertTarget(kind="json_file", destination="x.json")], timeout_seconds=0)


def test_default_sender_refuses_redirects(monkeypatch) -> None:
    handler = monitor._RefuseRedirectHandler()
    request = urllib.request.Request(
        "http://ha.local:8123/api/events/sot_validator_drift",
        data=b"{}",
        headers={"Authorization": f"Bearer {TOKEN}"},
        method="POST",
    )
    assert handler.redirect_request(request, None, 302, "Found", {}, "http://evil.example/") is None

    captured: dict[str, Any] = {}

    class FakeResponse:
        status = 201

        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: Any) -> None:
            return None

    class FakeOpener:
        def open(self, req: urllib.request.Request, timeout: float) -> FakeResponse:
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["timeout"] = timeout
            return FakeResponse()

    def fake_build_opener(*handlers: Any) -> FakeOpener:
        captured["handlers"] = handlers
        return FakeOpener()

    monkeypatch.setattr(monitor.urllib.request, "build_opener", fake_build_opener)
    status = monitor._default_sender("POST", "http://hook.local/x", {"Content-Type": "application/json"}, b"{}", 2.0)
    assert status == 201
    assert captured["timeout"] == 2.0
    assert captured["method"] == "POST"
    assert any(isinstance(h, monitor._RefuseRedirectHandler) for h in captured["handlers"])


def test_default_sender_returns_http_error_code(monkeypatch) -> None:
    class ErrorOpener:
        def open(self, req: urllib.request.Request, timeout: float) -> Any:
            raise urllib.error.HTTPError(req.full_url, 302, "Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(monitor.urllib.request, "build_opener", lambda *handlers: ErrorOpener())
    assert monitor._default_sender("POST", "http://hook.local/x", {}, b"{}", 1.0) == 302
