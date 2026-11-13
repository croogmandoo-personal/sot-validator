"""Tests for the offline UPS power-dependency map, blast radius, and risk ranking."""

from __future__ import annotations

import json
import pathlib

import pytest

from sot_validator.models import Equipment, EquipmentCategory, NetworkDevice, Site
from sot_validator.signals.ups_health import UpsHealthRecord, UpsHealthStatus
from sot_validator.topology import (
    BlastRadius,
    PowerCycleError,
    PowerDependencyGraph,
    PowerFeed,
    PowerMapLoader,
    VALID_POWER_SOURCE_TYPES,
    device_criticality,
    find_false_redundancy,
    find_single_fed_critical,
    generate_power_json_report,
    generate_power_markdown_report,
    rank_power_risk,
)

SITE_ID = "site-042"


def _device(device_id: str, role: str | None) -> NetworkDevice:
    return NetworkDevice(
        device_id=device_id, site_id=SITE_ID, hostname=f"{device_id}.example.internal", role=role
    )


def _equipment(equipment_id: str, category: EquipmentCategory) -> Equipment:
    return Equipment(
        equipment_id=equipment_id, site_id=SITE_ID, name=equipment_id, category=category
    )


def _site() -> Site:
    return Site(
        site_id=SITE_ID,
        name="Site 042",
        devices=[
            _device("rtr-01", "router"),
            _device("core-01", "core-switch"),
            _device("core-02", "Core Switch"),
            _device("acc-01", "access-switch"),
            _device("sw-01", "switch"),
            _device("dev-norole", None),
        ],
        equipment=[
            _equipment("UPS-A", EquipmentCategory.UPS),
            _equipment("UPS-B", EquipmentCategory.UPS),
            _equipment("UPS-C", EquipmentCategory.UPS),
            _equipment("srv-01", EquipmentCategory.SERVER),
        ],
    )


def _health(
    equipment_id: str,
    status: UpsHealthStatus,
    *,
    replace: bool = False,
    low_runtime: bool = False,
) -> UpsHealthRecord:
    return UpsHealthRecord(
        equipment_id=equipment_id,
        site_id=SITE_ID,
        name=equipment_id,
        status=status,
        needs_battery_replacement=replace,
        is_low_runtime=low_runtime,
    )


def _feed(device_id: str, source_id: str, source_type: str, psu: str | None = None) -> PowerFeed:
    return PowerFeed(device_id=device_id, source_id=source_id, source_type=source_type, psu=psu)


# ---------------------------------------------------------------------------
# PowerFeed
# ---------------------------------------------------------------------------


def test_power_feed_normalises_fields() -> None:
    feed = PowerFeed(
        device_id="  rtr-01 ", source_id=" UPS-A ", source_type=" UPS ", psu="", outlet="  "
    )
    assert feed.device_id == "rtr-01"
    assert feed.source_id == "UPS-A"
    assert feed.source_type == "ups"
    assert feed.psu is None
    assert feed.outlet is None
    assert feed.to_dict() == {
        "device_id": "rtr-01",
        "psu": None,
        "source_id": "UPS-A",
        "source_type": "ups",
        "outlet": None,
    }
    assert VALID_POWER_SOURCE_TYPES == ("ups", "pdu", "outlet_group", "utility")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"device_id": "", "source_id": "UPS-A", "source_type": "ups"},
        {"device_id": "rtr-01", "source_id": "  ", "source_type": "ups"},
        {"device_id": "rtr-01", "source_id": "UPS-A", "source_type": "generator"},
        {"device_id": "rtr-01", "source_id": "UPS-A", "source_type": ""},
    ],
)
def test_power_feed_rejects_invalid_values(kwargs: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        PowerFeed(**kwargs)


# ---------------------------------------------------------------------------
# Graph and blast radius
# ---------------------------------------------------------------------------


def test_chain_traversal_excludes_intermediates() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("PDU-1", "UPS-A", "ups"),
            _feed("OG-1", "PDU-1", "pdu"),
            _feed("rtr-01", "OG-1", "outlet_group"),
        ]
    )
    radius = graph.blast_radius("UPS-A")
    assert isinstance(radius, BlastRadius)
    assert radius.loses_all_power == ["rtr-01"]
    assert radius.loses_redundancy == []
    assert graph.power_roots("rtr-01") == {"UPS-A"}
    assert graph.end_devices == ["rtr-01"]
    assert radius.to_dict() == {
        "source_id": "UPS-A",
        "loses_all_power": ["rtr-01"],
        "loses_redundancy": [],
    }
    # Failing an intermediate also darkens the device, and never lists the intermediate.
    pdu_radius = graph.blast_radius("PDU-1")
    assert pdu_radius.loses_all_power == ["rtr-01"]
    assert "OG-1" not in pdu_radius.loses_all_power + pdu_radius.loses_redundancy


def test_dual_feed_and_utility_only_lose_redundancy() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("core-01", "UPS-A", "ups", psu="PSU1"),
            _feed("core-01", "UPS-B", "ups", psu="PSU2"),
            _feed("rtr-01", "UPS-A", "ups", psu="PSU1"),
            _feed("rtr-01", "utility-grid", "utility", psu="PSU2"),
        ]
    )
    radius = graph.blast_radius("UPS-A")
    assert radius.loses_all_power == []
    assert radius.loses_redundancy == ["core-01", "rtr-01"]
    assert graph.power_roots("core-01") == {"UPS-A", "UPS-B"}
    assert graph.power_roots("rtr-01") == {"UPS-A", "utility-grid"}


def test_false_redundancy_through_two_pdus_on_one_ups() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("PDU-1", "UPS-A", "ups"),
            _feed("PDU-2", "UPS-A", "ups"),
            _feed("core-01", "PDU-1", "pdu", psu="PSU1"),
            _feed("core-01", "PDU-2", "pdu", psu="PSU2"),
            _feed("PDU-3", "UPS-B", "ups"),
            _feed("core-02", "PDU-1", "pdu", psu="PSU1"),
            _feed("core-02", "PDU-3", "pdu", psu="PSU2"),
        ]
    )
    assert find_false_redundancy(graph) == ["core-01"]
    radius = graph.blast_radius("UPS-A")
    assert radius.loses_all_power == ["core-01"]
    assert radius.loses_redundancy == ["core-02"]


def test_false_redundancy_requires_distinct_psus_and_ups_root() -> None:
    graph = PowerDependencyGraph(
        [
            # Two feeds but the same PSU: not a dual-PSU device.
            _feed("rtr-01", "UPS-A", "ups", psu="PSU1"),
            _feed("rtr-01", "UPS-A", "ups", psu="PSU1"),
            # Dual PSU but single root is a utility, not a UPS.
            _feed("sw-01", "grid", "utility", psu="PSU1"),
            _feed("sw-01", "grid", "utility", psu="PSU2"),
            # Missing PSU labels do not count as distinct PSUs.
            _feed("acc-01", "UPS-A", "ups"),
            _feed("acc-01", "UPS-A", "ups"),
        ]
    )
    assert find_false_redundancy(graph) == []


def test_cycle_raises_power_cycle_error_naming_ids() -> None:
    with pytest.raises(PowerCycleError) as excinfo:
        PowerDependencyGraph(
            [
                _feed("PDU-1", "PDU-2", "pdu"),
                _feed("PDU-2", "PDU-1", "pdu"),
                _feed("rtr-01", "PDU-1", "pdu"),
            ]
        )
    assert isinstance(excinfo.value, ValueError)
    assert "PDU-1" in str(excinfo.value)
    assert "PDU-2" in str(excinfo.value)


def test_longer_cycle_names_every_id() -> None:
    with pytest.raises(PowerCycleError) as excinfo:
        PowerDependencyGraph(
            [
                _feed("PDU-1", "UPS-A", "ups"),
                _feed("OG-1", "PDU-1", "pdu"),
                _feed("OG-2", "OG-1", "outlet_group"),
                _feed("PDU-1", "OG-2", "outlet_group"),
            ]
        )
    for node in ("PDU-1", "OG-1", "OG-2"):
        assert node in str(excinfo.value)
    assert "UPS-A" not in str(excinfo.value)


def test_blast_radius_unknown_source_raises() -> None:
    graph = PowerDependencyGraph([_feed("rtr-01", "UPS-A", "ups")])
    with pytest.raises(ValueError):
        graph.blast_radius("nope")
    # A fed end device is not a source either.
    with pytest.raises(ValueError):
        graph.blast_radius("rtr-01")


def test_blast_radius_is_independent_of_feed_order() -> None:
    feeds = [
        _feed("PDU-1", "UPS-A", "ups"),
        _feed("OG-1", "PDU-1", "pdu"),
        _feed("core-01", "OG-1", "outlet_group", psu="PSU1"),
        _feed("core-01", "UPS-B", "ups", psu="PSU2"),
        _feed("rtr-01", "OG-1", "outlet_group"),
    ]
    forward = PowerDependencyGraph(feeds)
    backward = PowerDependencyGraph(list(reversed(feeds)))
    for source in ("UPS-A", "UPS-B", "PDU-1", "OG-1"):
        assert forward.blast_radius(source) == backward.blast_radius(source)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_LOADER_ROWS = [
    {"device_id": "PDU-1", "psu": "", "source_id": "UPS-A", "source_type": "ups", "outlet": ""},
    {"device_id": "rtr-01", "psu": "PSU1", "source_id": "PDU-1", "source_type": "pdu", "outlet": "3"},
    {"device_id": "ghost-99", "psu": "", "source_id": "UPS-A", "source_type": "ups", "outlet": ""},
    {"device_id": "core-01", "psu": "", "source_id": "UPS-Z", "source_type": "ups", "outlet": ""},
    {"device_id": "core-02", "psu": "", "source_id": "srv-01", "source_type": "ups", "outlet": ""},
    {"device_id": "acc-01", "psu": "", "source_id": "PDU-9", "source_type": "pdu", "outlet": ""},
    {"device_id": "sw-01", "psu": "", "source_id": "utility-grid", "source_type": "Utility", "outlet": ""},
]


def _write_csv(path: pathlib.Path, rows: list[dict[str, str]]) -> None:
    header = "device_id,psu,source_id,source_type,outlet"
    lines = [header] + [
        ",".join(row[col] for col in header.split(",")) for row in rows
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _assert_loader_result(result) -> None:
    codes = {(problem.code, problem.feed_index, problem.entity_id) for problem in result.problems}
    assert codes == {
        ("UNKNOWN_DEVICE", 3, "ghost-99"),
        ("UNKNOWN_UPS", 4, "UPS-Z"),
        ("UNKNOWN_UPS", 5, "srv-01"),
        ("UNKNOWN_SOURCE", 6, "PDU-9"),
    }
    kept = [(feed.device_id, feed.source_id) for feed in result.feeds]
    assert kept == [("PDU-1", "UPS-A"), ("rtr-01", "PDU-1"), ("sw-01", "utility-grid")]
    rtr_feed = result.feeds[1]
    assert rtr_feed.psu == "PSU1"
    assert rtr_feed.outlet == "3"
    assert result.feeds[0].psu is None
    assert result.feeds[2].source_type == "utility"
    for problem in result.problems:
        assert problem.to_dict()["code"] == problem.code


def test_loader_json_list_reports_unknown_ids(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "power.json"
    path.write_text(json.dumps(_LOADER_ROWS), encoding="utf-8")
    _assert_loader_result(PowerMapLoader(_site()).load(path))


def test_loader_json_feeds_object(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "power.JSON"
    path.write_text(json.dumps({"feeds": _LOADER_ROWS}), encoding="utf-8")
    _assert_loader_result(PowerMapLoader(_site()).load(path))


def test_loader_json_optional_keys_may_be_absent_or_null(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "power.json"
    rows = [
        {"source_type": "ups", "source_id": "UPS-A", "device_id": "rtr-01"},
        {"device_id": "rtr-01", "source_id": "UPS-B", "source_type": "ups", "psu": None, "outlet": None},
    ]
    path.write_text(json.dumps(rows), encoding="utf-8")
    result = PowerMapLoader(_site()).load(path)
    assert result.problems == []
    assert [feed.source_id for feed in result.feeds] == ["UPS-A", "UPS-B"]


def test_loader_csv_reports_unknown_ids(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "power.Csv"
    _write_csv(path, _LOADER_ROWS)
    _assert_loader_result(PowerMapLoader(_site()).load(path))


def test_loader_csv_column_order_does_not_matter(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "power.csv"
    path.write_text(
        "outlet,source_type,source_id,psu,device_id\n,ups,UPS-A,PSU1,rtr-01\n",
        encoding="utf-8",
    )
    result = PowerMapLoader(_site()).load(path)
    assert result.problems == []
    assert result.feeds[0].to_dict() == {
        "device_id": "rtr-01",
        "psu": "PSU1",
        "source_id": "UPS-A",
        "source_type": "ups",
        "outlet": None,
    }


def test_loader_cascades_unknown_source_downstream(tmp_path: pathlib.Path) -> None:
    """A PDU whose only upstream feed is excluded cannot become an independent root."""
    path = tmp_path / "power.json"
    rows = [
        {"device_id": "PDU-1", "source_id": "UPS-Z", "source_type": "ups"},
        {"device_id": "OG-1", "source_id": "PDU-1", "source_type": "pdu"},
        {"device_id": "rtr-01", "source_id": "OG-1", "source_type": "outlet_group"},
    ]
    path.write_text(json.dumps(rows), encoding="utf-8")
    result = PowerMapLoader(_site()).load(path)
    assert result.feeds == []
    assert [(p.code, p.feed_index) for p in result.problems] == [
        ("UNKNOWN_UPS", 1),
        ("UNKNOWN_SOURCE", 2),
        ("UNKNOWN_SOURCE", 3),
    ]


def test_loader_invalid_source_type_raises_with_row_index(tmp_path: pathlib.Path) -> None:
    json_path = tmp_path / "power.json"
    json_path.write_text(
        json.dumps(
            [
                {"device_id": "rtr-01", "source_id": "UPS-A", "source_type": "ups"},
                {"device_id": "rtr-01", "source_id": "UPS-B", "source_type": "battery"},
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="row 2"):
        PowerMapLoader(_site()).load(json_path)

    csv_path = tmp_path / "power.csv"
    csv_path.write_text(
        "device_id,psu,source_id,source_type,outlet\nrtr-01,,UPS-A,generator,\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="row 1"):
        PowerMapLoader(_site()).load(csv_path)


def test_loader_missing_fields_raise(tmp_path: pathlib.Path) -> None:
    json_path = tmp_path / "power.json"
    json_path.write_text(json.dumps([{"device_id": "rtr-01", "source_type": "ups"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="row 1"):
        PowerMapLoader(_site()).load(json_path)

    csv_path = tmp_path / "power.csv"
    csv_path.write_text(
        "device_id,psu,source_id,source_type,outlet\nrtr-01,,,ups,\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="row 1"):
        PowerMapLoader(_site()).load(csv_path)

    header_path = tmp_path / "short.csv"
    header_path.write_text("device_id,source_id\nrtr-01,UPS-A\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing columns"):
        PowerMapLoader(_site()).load(header_path)


def test_loader_rejects_bad_shapes_and_extensions(tmp_path: pathlib.Path) -> None:
    bad_ext = tmp_path / "power.yaml"
    bad_ext.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        PowerMapLoader(_site()).load(bad_ext)

    no_feeds = tmp_path / "power.json"
    no_feeds.write_text(json.dumps({"rows": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        PowerMapLoader(_site()).load(no_feeds)

    non_object = tmp_path / "rows.json"
    non_object.write_text(json.dumps(["rtr-01"]), encoding="utf-8")
    with pytest.raises(ValueError, match="row 1"):
        PowerMapLoader(_site()).load(non_object)

    non_string = tmp_path / "num.json"
    non_string.write_text(
        json.dumps([{"device_id": 7, "source_id": "UPS-A", "source_type": "ups"}]),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="row 1"):
        PowerMapLoader(_site()).load(non_string)


def test_loader_does_not_modify_file(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "power.json"
    payload = json.dumps(_LOADER_ROWS)
    path.write_text(payload, encoding="utf-8")
    PowerMapLoader(_site()).load(path)
    assert path.read_text(encoding="utf-8") == payload
    assert sorted(p.name for p in tmp_path.iterdir()) == ["power.json"]


# ---------------------------------------------------------------------------
# Criticality and risk ranking
# ---------------------------------------------------------------------------


def test_device_criticality_roles() -> None:
    site = _site()
    assert device_criticality(site, "rtr-01") == "critical"
    assert device_criticality(site, "core-01") == "critical"
    assert device_criticality(site, "core-02") == "critical"
    assert device_criticality(site, "acc-01") == "standard"
    assert device_criticality(site, "sw-01") == "standard"
    assert device_criticality(site, "dev-norole") == "standard"
    assert device_criticality(site, "srv-01") == "standard"
    assert device_criticality(site, "UPS-A") == "standard"
    assert device_criticality(site, "unknown-device") == "standard"


def test_find_single_fed_critical() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("rtr-01", "UPS-A", "ups"),
            _feed("core-01", "UPS-A", "ups"),
            _feed("core-01", "UPS-B", "ups"),
            _feed("acc-01", "UPS-A", "ups"),
            _feed("srv-01", "UPS-A", "ups"),
        ]
    )
    assert find_single_fed_critical(_site(), graph) == ["rtr-01"]


def _risk_graph() -> PowerDependencyGraph:
    return PowerDependencyGraph(
        [
            # UPS-A: two single-fed critical devices plus non-critical ones.
            _feed("rtr-01", "UPS-A", "ups"),
            _feed("core-01", "UPS-A", "ups"),
            _feed("acc-01", "UPS-A", "ups"),
            _feed("srv-01", "UPS-A", "ups"),
            # UPS-B: two single-fed critical devices.
            _feed("core-02", "UPS-B", "ups"),
            _feed("PDU-1", "UPS-B", "ups"),
            _feed("dev-norole", "PDU-1", "pdu"),
            _feed("rtr-02", "PDU-1", "pdu"),
        ]
    )


def _risk_site() -> Site:
    site = _site()
    site.devices.append(_device("rtr-02", "router"))
    return site


def test_rank_power_risk_orders_by_score() -> None:
    site = _risk_site()
    graph = _risk_graph()
    entries = rank_power_risk(
        site,
        [
            _health("UPS-A", UpsHealthStatus.HEALTHY),
            _health("UPS-B", UpsHealthStatus.CRITICAL, replace=True),
            _health("srv-01", UpsHealthStatus.CRITICAL, replace=True, low_runtime=True),
        ],
        graph,
    )
    assert [entry.ups_id for entry in entries] == ["UPS-B", "UPS-A", "UPS-C"]
    top, second, third = entries
    assert top.severity == 4
    assert top.health_status == "CRITICAL"
    assert top.single_fed_critical == ["core-02", "rtr-02"]
    assert top.score == 8
    assert second.severity == 1
    assert second.single_fed_critical == ["core-01", "rtr-01"]
    assert second.score == 2
    # UPS-C is not in the graph and has no health record.
    assert third.single_fed_critical == []
    assert third.health_unknown is True
    assert third.health_status == "UNKNOWN"
    assert third.severity == 2
    assert third.score == 0
    assert top.to_dict() == {
        "ups_id": "UPS-B",
        "health_status": "CRITICAL",
        "health_unknown": False,
        "severity": 4,
        "single_fed_critical": ["core-02", "rtr-02"],
        "score": 8,
    }


def test_rank_power_risk_low_runtime_adds_severity() -> None:
    entries = rank_power_risk(
        _risk_site(),
        [_health("UPS-A", UpsHealthStatus.WARNING, replace=True, low_runtime=True)],
        _risk_graph(),
    )
    by_id = {entry.ups_id: entry for entry in entries}
    assert by_id["UPS-A"].severity == 4
    assert by_id["UPS-A"].score == 8
    assert by_id["UPS-B"].health_unknown is True
    assert by_id["UPS-B"].score == 4
    assert by_id["UPS-C"].score == 0


def test_rank_power_risk_redundancy_only_scores_zero() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("rtr-01", "UPS-A", "ups"),
            _feed("rtr-01", "UPS-B", "ups"),
            _feed("core-01", "UPS-A", "ups"),
            _feed("core-01", "grid", "utility"),
        ]
    )
    entries = rank_power_risk(
        _site(),
        [
            _health("UPS-A", UpsHealthStatus.UNREACHABLE, replace=True),
            _health("UPS-B", UpsHealthStatus.CRITICAL),
        ],
        graph,
    )
    by_id = {entry.ups_id: entry for entry in entries}
    assert by_id["UPS-A"].single_fed_critical == []
    assert by_id["UPS-A"].score == 0
    assert by_id["UPS-A"].severity == 4
    # All scores tie at 0, so severity then ups_id decide.
    assert [entry.ups_id for entry in entries] == ["UPS-A", "UPS-B", "UPS-C"]


def test_rank_power_risk_ties_ordered_by_ups_id() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("rtr-01", "UPS-B", "ups"),
            _feed("core-01", "UPS-A", "ups"),
            _feed("core-02", "UPS-C", "ups"),
        ]
    )
    entries = rank_power_risk(
        _site(),
        [_health(ups_id, UpsHealthStatus.WARNING) for ups_id in ("UPS-C", "UPS-B", "UPS-A")],
        graph,
    )
    assert [entry.ups_id for entry in entries] == ["UPS-A", "UPS-B", "UPS-C"]
    assert {entry.score for entry in entries} == {2}


def test_rank_power_risk_counts_false_redundancy_and_ignores_non_critical() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("PDU-1", "UPS-A", "ups"),
            _feed("PDU-2", "UPS-A", "ups"),
            _feed("core-01", "PDU-1", "pdu", psu="PSU1"),
            _feed("core-01", "PDU-2", "pdu", psu="PSU2"),
            _feed("acc-01", "UPS-A", "ups"),
            _feed("srv-01", "UPS-A", "ups"),
        ]
    )
    entries = rank_power_risk(_site(), [_health("UPS-A", UpsHealthStatus.HEALTHY)], graph)
    assert entries[0].ups_id == "UPS-A"
    assert entries[0].single_fed_critical == ["core-01"]
    assert entries[0].score == 1


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def _report_graph() -> PowerDependencyGraph:
    return PowerDependencyGraph(
        [
            _feed("PDU-1", "UPS-A", "ups"),
            _feed("PDU-2", "UPS-A", "ups"),
            _feed("core-01", "PDU-1", "pdu", psu="PSU1"),
            _feed("core-01", "PDU-2", "pdu", psu="PSU2"),
            _feed("rtr-01", "UPS-B", "ups"),
            _feed("core-02", "UPS-A", "ups", psu="PSU1"),
            _feed("core-02", "UPS-B", "ups", psu="PSU2"),
        ]
    )


def test_json_report_keys_and_ids() -> None:
    site = _site()
    graph = _report_graph()
    first = generate_power_json_report(site, graph)
    assert first == generate_power_json_report(site, graph)
    payload = json.loads(first)
    assert set(payload) == {"site_id", "ups_blast_radius", "single_fed_critical", "false_redundancy"}
    assert payload["site_id"] == SITE_ID
    assert payload["ups_blast_radius"] == [
        {"source_id": "UPS-A", "loses_all_power": ["core-01"], "loses_redundancy": ["core-02"]},
        {"source_id": "UPS-B", "loses_all_power": ["rtr-01"], "loses_redundancy": ["core-02"]},
    ]
    assert payload["single_fed_critical"] == ["core-01", "rtr-01"]
    assert payload["false_redundancy"] == ["core-01"]


def test_markdown_report_sections_and_determinism() -> None:
    site = _site()
    graph = _report_graph()
    first = generate_power_markdown_report(site, graph)
    assert first == generate_power_markdown_report(site, graph)
    assert first.startswith(f"# Power Dependency Report: {SITE_ID}\n")
    for ups_id in ("UPS-A", "UPS-B"):
        assert f"### UPS {ups_id}" in first
    false_section = first.split("### False redundancy", 1)[1]
    assert "- core-01" in false_section
    assert "Single-fed critical devices" in first


def test_markdown_report_empty_lists_and_escaping() -> None:
    site = Site(
        site_id="site|x",
        name="Escapes",
        equipment=[_equipment("UPS|A", EquipmentCategory.UPS)],
        devices=[_device("dev\nbad|id", "access")],
    )
    graph = PowerDependencyGraph(
        [
            _feed("dev\nbad|id", "UPS|A", "ups"),
            _feed("dev\nbad|id", "grid", "utility"),
        ]
    )
    report = generate_power_markdown_report(site, graph)
    assert "# Power Dependency Report: site\\|x" in report
    assert "### UPS UPS\\|A" in report
    assert "- dev bad\\|id" in report
    assert "dev\nbad" not in report
    # loses_all_power, single-fed critical and false redundancy are all empty.
    assert report.count("\nNone\n") == 3


def test_reports_with_no_ups_sources() -> None:
    graph = PowerDependencyGraph([_feed("rtr-01", "grid", "utility")])
    payload = json.loads(generate_power_json_report(_site(), graph))
    assert payload["ups_blast_radius"] == []
    assert payload["single_fed_critical"] == ["rtr-01"]
    report = generate_power_markdown_report(_site(), graph)
    assert "## UPS Blast Radius\n\nNone\n" in report


def test_rank_power_risk_stringly_flags_and_duplicate_records() -> None:
    graph = PowerDependencyGraph([_feed("rtr-01", "UPS-A", "ups")])
    stringly = _health("UPS-A", UpsHealthStatus.HEALTHY)
    stringly.needs_battery_replacement = "false"  # type: ignore[assignment]
    stringly.is_low_runtime = "0"  # type: ignore[assignment]
    entries = rank_power_risk(_site(), [stringly], graph)
    assert entries[0].ups_id == "UPS-A"
    assert entries[0].severity == 1

    # With several records for one UPS, the most severe one wins regardless of order.
    records = [
        _health("UPS-A", UpsHealthStatus.HEALTHY),
        _health("UPS-A", UpsHealthStatus.WARNING, low_runtime=True),
    ]
    for ordered in (records, list(reversed(records))):
        top = rank_power_risk(_site(), ordered, graph)[0]
        assert (top.ups_id, top.health_status, top.severity, top.score) == (
            "UPS-A",
            "WARNING",
            3,
            3,
        )


# ---------------------------------------------------------------------------
# Utility-fed UPS roots
# ---------------------------------------------------------------------------


def test_utility_fed_ups_blast_radius_at_chain_depth() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("UPS-A", "grid", "utility"),
            _feed("PDU-1", "UPS-A", "ups"),
            _feed("OG-1", "PDU-1", "pdu"),
            _feed("rtr-01", "OG-1", "outlet_group"),
        ]
    )
    radius = graph.blast_radius("UPS-A")
    assert radius.loses_all_power == ["rtr-01"]
    assert radius.loses_redundancy == []
    assert graph.power_roots("rtr-01") == {"UPS-A"}
    assert graph.end_devices == ["rtr-01"]


def test_false_redundancy_behind_utility_fed_ups() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("UPS-A", "grid", "utility"),
            _feed("PDU-1", "UPS-A", "ups"),
            _feed("PDU-2", "UPS-A", "ups"),
            _feed("core-01", "PDU-1", "pdu", psu="PSU1"),
            _feed("core-01", "PDU-2", "pdu", psu="PSU2"),
        ]
    )
    assert find_false_redundancy(graph) == ["core-01"]


def test_utility_fed_ups_plus_utility_dual_feed() -> None:
    graph = PowerDependencyGraph(
        [
            _feed("UPS-A", "grid", "utility"),
            _feed("rtr-01", "UPS-A", "ups", psu="PSU1"),
            _feed("rtr-01", "grid", "utility", psu="PSU2"),
        ]
    )
    assert graph.power_roots("rtr-01") == {"UPS-A", "grid"}
    assert graph.protected_roots("rtr-01") == {"UPS-A"}
    assert find_single_fed_critical(_site(), graph) == []
    assert find_false_redundancy(graph) == []
    radius = graph.blast_radius("UPS-A")
    assert radius.loses_all_power == []
    assert radius.loses_redundancy == ["rtr-01"]


def test_utility_root_only_when_reached_without_ups() -> None:
    # Feed order must not change which roots are UPS-protected.
    feeds = [
        _feed("UPS-A", "grid", "utility"),
        _feed("PDU-1", "UPS-A", "ups"),
        _feed("PDU-2", "grid", "utility"),
        _feed("core-01", "PDU-1", "pdu", psu="PSU1"),
        _feed("core-01", "PDU-2", "pdu", psu="PSU2"),
        _feed("acc-01", "PDU-1", "pdu"),
    ]
    for ordered in (feeds, list(reversed(feeds))):
        graph = PowerDependencyGraph(ordered)
        assert graph.power_roots("acc-01") == {"UPS-A"}
        assert graph.power_roots("core-01") == {"UPS-A", "grid"}
        assert graph.protected_roots("core-01") == {"UPS-A"}
        assert graph.protected_roots("PDU-2") == set()
        with pytest.raises(ValueError):
            graph.protected_roots("nope")
