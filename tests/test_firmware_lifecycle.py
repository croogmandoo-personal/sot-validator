"""Unit tests for the firmware version parser and lifecycle compliance checker."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import re

import pytest

from sot_validator.lifecycle import (
    FIRMWARE_STATUSES,
    OS_AOS,
    OS_EXOS,
    OS_FABRIC_ENGINE,
    OS_SWITCH_ENGINE,
    OS_VOSS,
    FirmwareComplianceChecker,
    FirmwareFinding,
    FirmwareInfo,
    FirmwareObservation,
    FirmwareParser,
    LifecycleCatalog,
    compare_versions,
    generate_firmware_json_report,
    generate_firmware_markdown_report,
    parse_version,
    sort_firmware_findings,
)
from sot_validator.signals.management import (
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_NAME,
    parse_extreme_switch_oids,
)

EXAMPLE_PATH = (
    Path(__file__).resolve().parents[1] / "examples" / "lifecycle-catalog.example.json"
)
NOW = datetime(2030, 6, 15, 12, 0, tzinfo=timezone.utc)
GENERATED_AT = "2030-06-15T12:00:00+00:00"

EXOS_DESCR = (
    "ExtremeXOS (X460G2-48p-10G4) version 31.7.1.4 by release-manager on "
    "Mon Jan 1 00:00:00 EST 2024"
)
SWITCH_ENGINE_DESCR = (
    "ExtremeXOS (5520-24T-SwitchEngine) version 32.2.1.3 32.2.1.3 by release-manager"
)
SWITCH_ENGINE_RENAMED_DESCR = "Switch Engine (5520-24T) version 32.6.1.2 by release-manager"
VOSS_DESCR = "VSP-7254XSQ (8.1.0.0) BoxType: VSP-7254XSQ"
FABRIC_ENGINE_DESCR = "5520-24T-FabricEngine (8.10.0.0) BoxType: 5520-24T-FabricEngine"
FABRIC_ENGINE_TEXT_DESCR = "VSP-7400-48Y-8C (8.10.1.0) Extreme Networks Fabric Engine"
APC_DESCR = (
    "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin "
    "AF1:v6.9.6 AN1:apc_hw05_sumx_696.bin MN:AP9631 HR:05 SN: ZA0000000000 "
    "MD:01/01/2020)"
)
APC_MN_ONLY_DESCR = (
    "APC Web/SNMP Management Card (MB:v3.9.2 PF:v6.4.6 PN:apc_aos_646.bin "
    "AF1:v6.4.6 AN1:apc_sumx_646.bin MN:AP9630 HR:05 SN: ZA0000000001)"
)


def _catalog(*entries, note=None) -> LifecycleCatalog:
    data = {"entries": list(entries)}
    if note is not None:
        data["note"] = note
    return LifecycleCatalog.from_dict(data)


def _observation(sys_descr, **overrides) -> FirmwareObservation:
    values = {"site_id": "S1", "device": "sw1", "ip": "10.1.1.1", "sys_descr": sys_descr}
    values.update(overrides)
    return FirmwareObservation(**values)


def _evaluate_one(catalog, sys_descr, now=NOW, **overrides) -> FirmwareFinding:
    findings = FirmwareComplianceChecker(catalog).evaluate(
        [_observation(sys_descr, **overrides)], now=now
    )
    assert len(findings) == 1
    return findings[0]


# --- Parser -------------------------------------------------------------------


def test_parse_exos():
    info = FirmwareParser().parse(EXOS_DESCR)
    assert info == FirmwareInfo(
        vendor="extreme", platform="X460G2-48p-10G4", os_family=OS_EXOS, version="31.7.1.4"
    )


def test_parse_exos_keeps_version_suffix():
    info = FirmwareParser().parse("ExtremeXOS (X440G2-24t-10G4) version 31.7.1.4-patch1-2 by x")
    assert info.version == "31.7.1.4-patch1-2"
    assert info.platform == "X440G2-24t-10G4"


@pytest.mark.parametrize(
    ("sys_descr", "platform", "version"),
    [
        (SWITCH_ENGINE_DESCR, "5520-24T-SwitchEngine", "32.2.1.3"),
        (SWITCH_ENGINE_RENAMED_DESCR, "5520-24T", "32.6.1.2"),
    ],
)
def test_parse_switch_engine(sys_descr, platform, version):
    info = FirmwareParser().parse(sys_descr)
    assert info == FirmwareInfo("extreme", platform, OS_SWITCH_ENGINE, version)


@pytest.mark.parametrize(
    "sys_descr",
    [
        "ExtremeXOS (X460G2-48p-10G4) version 31.7.1.4 by Switch Engine team",
        "ExtremeXOS (X460G2-48p-10G4) version 31.7.1.4 by release-manager SwitchEngine build",
    ],
)
def test_parse_exos_ignores_switch_engine_in_free_text(sys_descr):
    info = FirmwareParser().parse(sys_descr)
    assert info == FirmwareInfo("extreme", "X460G2-48p-10G4", OS_EXOS, "31.7.1.4")


@pytest.mark.parametrize(
    ("sys_descr", "expected"),
    [
        (
            "VSP-7254XSQ (8.1.0.0) managed via Switch Engine tooling",
            FirmwareInfo("extreme", "VSP-7254XSQ", OS_VOSS, "8.1.0.0"),
        ),
        (
            "VSP-7254XSQ (8.1.0.0) uplink to ExtremeXOS core and APC UPS",
            FirmwareInfo("extreme", "VSP-7254XSQ", OS_VOSS, "8.1.0.0"),
        ),
        (
            "APC Web/SNMP Management Card "
            "(MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin ExtremeXOS)",
            FirmwareInfo("apc", "hw05", OS_AOS, "6.9.6"),
        ),
        (
            "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 MN:AP9631) near Switch Engine",
            FirmwareInfo("apc", "AP9631", OS_AOS, "6.9.6"),
        ),
    ],
)
def test_parse_ignores_other_family_keywords_in_free_text(sys_descr, expected):
    assert FirmwareParser().parse(sys_descr) == expected


def test_parse_voss():
    info = FirmwareParser().parse(VOSS_DESCR)
    assert info == FirmwareInfo("extreme", "VSP-7254XSQ", OS_VOSS, "8.1.0.0")


def test_parse_voss_build_suffix():
    info = FirmwareParser().parse("VSP-8284XSQ (8.1.0.0_B011) BoxType: VSP-8284XSQ")
    assert info.version == "8.1.0.0_B011"
    assert info.os_family == OS_VOSS


@pytest.mark.parametrize(
    ("sys_descr", "platform", "version"),
    [
        (FABRIC_ENGINE_DESCR, "5520-24T-FabricEngine", "8.10.0.0"),
        (FABRIC_ENGINE_TEXT_DESCR, "VSP-7400-48Y-8C", "8.10.1.0"),
    ],
)
def test_parse_fabric_engine(sys_descr, platform, version):
    info = FirmwareParser().parse(sys_descr)
    assert info == FirmwareInfo("extreme", platform, OS_FABRIC_ENGINE, version)


def test_parse_apc_issue_string():
    info = FirmwareParser().parse(APC_DESCR)
    assert info == FirmwareInfo("apc", "hw05", OS_AOS, "6.9.6")


def test_parse_apc_mn_only():
    info = FirmwareParser().parse(APC_MN_ONLY_DESCR)
    assert info == FirmwareInfo("apc", "AP9630", OS_AOS, "6.4.6")


@pytest.mark.parametrize(
    "sys_descr",
    [
        None,
        "",
        "   ",
        12345,
        b"ExtremeXOS (X460G2) version 31.7.1.4",
        ["ExtremeXOS"],
        "Linux router 5.10",
        "Linux router (5.10)",
        "ExtremeXOS (X460G2-48p-10G4) by release-manager",
        "ExtremeXOS (X460G2-48p-10G4) version",
        "ExtremeXOS (5520-24T) on a box",
        "Switch Engine (5520-24T)",
        "VSP-7254XSQ () BoxType: VSP-7254XSQ",
        "APC Web/SNMP Management Card (MB:v4.1.0 PN:apc_hw05_aos_696.bin)",
        "APC Web/SNMP Management Card (PF:v6.9.6)",
        "Cisco IOS Software, C2960 (C2960-LANBASEK9-M), Version 15.0(2)SE",
    ],
)
def test_parse_returns_none_without_raising(sys_descr):
    assert FirmwareParser().parse(sys_descr) is None


# --- Version comparison -------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("31.10", "31.9", 1),
        ("31.9", "31.10", -1),
        ("31.7", "31.7.0.0", 0),
        ("v6.9.6", "6.9.6", 0),
        ("V6.9.6", "6.9.6", 0),
        ("31.7.1.4-patch1-2", "31.7.1.4", 1),
        ("31.7.1.4", "31.7.1.4-patch1-2", -1),
        ("31.7.1.4-patch1-2", "31.7.1.4-patch1-10", -1),
        ("31.7.1.4-patch1-2", "31.7.1.5", -1),
        ("8.1.0.0_B011", "8.1.0.0", 1),
        ("8.1.0.0_B011", "8.1.0.0_B009", 1),
        ("8.1", "8.1.0.0_B001", -1),
    ],
)
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


@pytest.mark.parametrize("text", ["abc", "", "x.1", "31.7.x.4", "31..7", "31.7.", None, 31])
def test_parse_version_rejects_non_numeric(text):
    with pytest.raises(ValueError):
        parse_version(text)


def test_non_numeric_version_is_unparsed_not_raised():
    catalog = _catalog({"vendor": "extreme", "platform": "X460G2-*", "minimum_version": "1.0"})
    finding = _evaluate_one(catalog, "ExtremeXOS (X460G2-48p-10G4) version 31.7.x.4 by x")
    assert finding.status == "unparsed"
    assert finding.conditions == ["unparsed"]
    assert finding.version == "31.7.x.4"


def test_non_numeric_version_from_custom_parser_is_unparsed():
    class StubParser(FirmwareParser):
        def parse(self, sys_descr):
            return FirmwareInfo("extreme", "X460G2-48p-10G4", OS_EXOS, "release-candidate")

    catalog = _catalog({"vendor": "extreme", "platform": "X460G2-*", "minimum_version": "1.0"})
    findings = FirmwareComplianceChecker(catalog, parser=StubParser()).evaluate(
        [_observation("anything")], now=NOW
    )
    assert findings[0].status == "unparsed"


def test_unparseable_sys_descr_is_unparsed():
    catalog = _catalog({"vendor": "extreme", "platform": "*"})
    finding = _evaluate_one(catalog, "Linux router 5.10")
    assert finding.status == "unparsed"
    assert finding.conditions == ["unparsed"]
    assert (finding.vendor, finding.platform, finding.os_family, finding.version) == (
        None,
        None,
        None,
        None,
    )
    assert finding.catalog_platform is None


def test_missing_sys_descr_is_unparsed():
    catalog = _catalog({"vendor": "extreme", "platform": "*"})
    finding = _evaluate_one(catalog, None)
    assert finding.status == "unparsed"


# --- Catalog ------------------------------------------------------------------


def test_catalog_match_is_case_insensitive():
    catalog = _catalog({"vendor": "EXTREME", "platform": "x460g2-*"})
    assert catalog.match("extreme", "X460G2-48p-10G4").platform == "x460g2-*"
    assert catalog.match("Extreme", "x460G2-48P-10g4") is not None
    assert catalog.match("apc", "X460G2-48p-10G4") is None


def test_catalog_first_match_wins():
    catalog = _catalog(
        {"vendor": "extreme", "platform": "X460G2-*", "minimum_version": "31.0"},
        {"vendor": "extreme", "platform": "X4*", "minimum_version": "1.0"},
    )
    assert catalog.match("extreme", "X460G2-48p-10G4").platform == "X460G2-*"
    assert catalog.match("extreme", "X440G2-24t").platform == "X4*"
    finding = _evaluate_one(catalog, EXOS_DESCR)
    assert finding.catalog_platform == "X460G2-*"
    assert finding.minimum_version == "31.0"


def test_unmatched_platform_is_unknown_platform():
    catalog = _catalog({"vendor": "extreme", "platform": "X670*"})
    finding = _evaluate_one(catalog, EXOS_DESCR)
    assert finding.status == "unknown_platform"
    assert finding.conditions == ["unknown_platform"]
    assert finding.platform == "X460G2-48p-10G4"
    assert finding.catalog_platform is None


def test_catalog_load_rejects_invalid_json(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text('{"entries": [', encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        LifecycleCatalog.load(path)


@pytest.mark.parametrize(
    ("data", "pattern"),
    [
        ([], "entries"),
        ({}, "entries"),
        ({"entries": {}}, "entries"),
        ({"entries": [], "note": 5}, "note"),
        ({"entries": ["X4*"]}, "entry 0"),
    ],
)
def test_catalog_rejects_bad_shape(data, pattern):
    with pytest.raises(ValueError, match=pattern):
        LifecycleCatalog.from_dict(data)


def test_catalog_missing_platform_names_index():
    data = {"entries": [{"vendor": "extreme", "platform": "X4*"}, {"vendor": "apc"}]}
    with pytest.raises(ValueError, match=r"entry 1\b.*platform must be"):
        LifecycleCatalog.from_dict(data)


def test_catalog_missing_vendor_names_index_and_platform():
    data = {"entries": [{"platform": "X4*"}]}
    with pytest.raises(ValueError, match=r"entry 0 \(platform 'X4\*'\).*vendor"):
        LifecycleCatalog.from_dict(data)


def test_catalog_invalid_date_names_index_and_platform(tmp_path):
    data = {
        "entries": [
            {"vendor": "extreme", "platform": "X4*"},
            {"vendor": "extreme", "platform": "X460G2-*", "end_of_sale": "2026-13-01"},
        ]
    }
    with pytest.raises(ValueError, match=r"entry 1 \(platform 'X460G2-\*'\).*end_of_sale"):
        LifecycleCatalog.from_dict(data)
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match=r"entry 1"):
        LifecycleCatalog.load(path)


@pytest.mark.parametrize(
    "value", ["20260101", "2026-1-01", "2026-01-01T00:00:00", 20260101, True, "2026-02-30"]
)
def test_catalog_rejects_non_iso_dates(value):
    data = {"entries": [{"vendor": "apc", "platform": "*", "end_of_support": value}]}
    with pytest.raises(ValueError, match=r"entry 0.*end_of_support"):
        LifecycleCatalog.from_dict(data)


@pytest.mark.parametrize("value", ["latest", "", 6, False])
def test_catalog_rejects_unparseable_versions(value):
    data = {"entries": [{"vendor": "apc", "platform": "hw05", "recommended_version": value}]}
    with pytest.raises(ValueError, match=r"entry 0 \(platform 'hw05'\).*recommended_version"):
        LifecycleCatalog.from_dict(data)


def test_example_catalog_loads():
    catalog = LifecycleCatalog.load(EXAMPLE_PATH)
    assert "placeholder" in catalog.note.lower()
    assert catalog.entries
    parser = FirmwareParser()
    for sys_descr in (
        EXOS_DESCR,
        SWITCH_ENGINE_DESCR,
        VOSS_DESCR,
        FABRIC_ENGINE_DESCR,
        APC_DESCR,
        APC_MN_ONLY_DESCR,
    ):
        info = parser.parse(sys_descr)
        assert catalog.match(info.vendor, info.platform) is not None, sys_descr


# --- Status precedence and dates ----------------------------------------------


def test_end_of_support_boundary():
    catalog = _catalog(
        {"vendor": "extreme", "platform": "X460G2-*", "end_of_support": "2030-06-15"}
    )
    on_day = _evaluate_one(
        catalog, EXOS_DESCR, now=datetime(2030, 6, 15, 0, 0, tzinfo=timezone.utc)
    )
    assert on_day.status == "end_of_support"
    assert on_day.end_of_support == "2030-06-15"
    day_before = _evaluate_one(
        catalog, EXOS_DESCR, now=datetime(2030, 6, 14, 23, 59, 59, tzinfo=timezone.utc)
    )
    assert day_before.status != "end_of_support"
    assert day_before.status == "compliant"


def test_end_of_sale_boundary():
    catalog = _catalog({"vendor": "extreme", "platform": "X460G2-*", "end_of_sale": "2030-06-15"})
    on_day = _evaluate_one(catalog, EXOS_DESCR, now=datetime(2030, 6, 15, tzinfo=timezone.utc))
    assert on_day.status == "end_of_sale"
    day_before = _evaluate_one(catalog, EXOS_DESCR, now=datetime(2030, 6, 14, tzinfo=timezone.utc))
    assert day_before.status == "compliant"


def test_naive_now_is_utc_and_aware_now_uses_utc_date():
    catalog = _catalog({"vendor": "extreme", "platform": "X460G2-*", "end_of_sale": "2030-06-15"})
    naive = _evaluate_one(catalog, EXOS_DESCR, now=datetime(2030, 6, 15, 0, 30))
    assert naive.status == "end_of_sale"
    # 2030-06-14 20:00 at UTC-05:00 is already 2030-06-15 in UTC.
    minus_five = timezone(timedelta(hours=-5))
    shifted = _evaluate_one(
        catalog, EXOS_DESCR, now=datetime(2030, 6, 14, 20, 0, tzinfo=minus_five)
    )
    assert shifted.status == "end_of_sale"


def test_now_must_be_datetime():
    catalog = _catalog({"vendor": "extreme", "platform": "*"})
    with pytest.raises(ValueError):
        FirmwareComplianceChecker(catalog).evaluate([_observation(EXOS_DESCR)], now="2030-01-01")


def test_below_minimum_outranks_end_of_sale():
    catalog = _catalog(
        {
            "vendor": "extreme",
            "platform": "X460G2-*",
            "minimum_version": "32.0",
            "end_of_sale": "2020-01-01",
        }
    )
    finding = _evaluate_one(catalog, EXOS_DESCR)
    assert finding.status == "below_minimum"
    assert finding.conditions == ["below_minimum", "end_of_sale"]


def test_all_conditions_listed_in_precedence_order():
    catalog = _catalog(
        {
            "vendor": "extreme",
            "platform": "X460G2-*",
            "minimum_version": "32.0",
            "recommended_version": "33.0",
            "end_of_sale": "2020-01-01",
            "end_of_support": "2021-01-01",
        }
    )
    finding = _evaluate_one(catalog, EXOS_DESCR)
    assert finding.status == "end_of_support"
    assert finding.conditions == [
        "end_of_support",
        "below_minimum",
        "end_of_sale",
        "below_recommended",
    ]


def test_below_recommended_only():
    catalog = _catalog(
        {
            "vendor": "extreme",
            "platform": "X460G2-*",
            "minimum_version": "31.7.1.4",
            "recommended_version": "31.7.1.4-patch1-2",
        }
    )
    finding = _evaluate_one(catalog, EXOS_DESCR)
    assert finding.status == "below_recommended"
    assert finding.conditions == ["below_recommended"]


def test_fully_compliant_device():
    catalog = _catalog(
        {
            "vendor": "extreme",
            "platform": "X460G2-*",
            "minimum_version": "31.7",
            "recommended_version": "31.7.1.4",
            "end_of_sale": "2099-01-01",
            "end_of_support": "2099-12-31",
        }
    )
    finding = _evaluate_one(catalog, EXOS_DESCR)
    assert finding.status == "compliant"
    assert finding.conditions == ["compliant"]
    assert finding.to_dict()["catalog_platform"] == "X460G2-*"
    assert finding.to_dict()["end_of_support"] == "2099-12-31"


def test_entry_without_fields_is_compliant():
    catalog = _catalog({"vendor": "apc", "platform": "hw05"})
    finding = _evaluate_one(catalog, APC_DESCR)
    assert finding.status == "compliant"
    assert (finding.minimum_version, finding.end_of_sale) == (None, None)


def test_evaluate_returns_one_finding_per_observation():
    catalog = _catalog({"vendor": "extreme", "platform": "X460G2-*"})
    observations = [
        _observation(EXOS_DESCR, device="a"),
        _observation(EXOS_DESCR, device="b"),
        _observation("junk", device="c"),
    ]
    findings = FirmwareComplianceChecker(catalog).evaluate(observations, now=NOW)
    assert [f.device for f in findings] == ["a", "b", "c"]


# --- Observation --------------------------------------------------------------


def test_observation_from_extreme_oid_parse():
    parsed = parse_extreme_switch_oids(
        {SNMPV2_MIB_SYS_DESCR: EXOS_DESCR, SNMPV2_MIB_SYS_NAME: "core-sw1"}
    )
    observation = FirmwareObservation.from_dict({**parsed, "site_id": "S1", "device": "core-sw1"})
    assert observation.sys_descr == EXOS_DESCR
    assert observation.ip is None
    catalog = _catalog({"vendor": "extreme", "platform": "X460G2-*", "minimum_version": "31.0"})
    findings = FirmwareComplianceChecker(catalog).evaluate([observation], now=NOW)
    assert findings[0].status == "compliant"
    assert findings[0].device == "core-sw1"
    # A plain mapping is accepted by evaluate() too.
    from_mapping = FirmwareComplianceChecker(catalog).evaluate(
        [{**parsed, "site_id": "S1", "device": "core-sw1"}], now=NOW
    )
    assert from_mapping[0].to_dict() == findings[0].to_dict()


def test_observation_hostname_fallback_and_round_trip():
    observation = FirmwareObservation.from_dict(
        {"site_id": "S1", "hostname": "ups1", "ip": "10.1.1.5", "sys_descr": APC_DESCR}
    )
    assert observation.device == "ups1"
    assert FirmwareObservation.from_dict(observation.to_dict()) == observation


@pytest.mark.parametrize(
    "data",
    [
        {"device": "sw1"},
        {"site_id": "", "device": "sw1"},
        {"site_id": "S1"},
        {"site_id": "S1", "device": "  "},
        {"site_id": "S1", "device": "sw1", "sys_descr": 5},
        {"site_id": "S1", "device": "sw1", "ip": 167837953},
    ],
)
def test_observation_validation(data):
    with pytest.raises(ValueError):
        FirmwareObservation.from_dict(data)


# --- Ordering and reports -----------------------------------------------------


def _report_findings() -> list[FirmwareFinding]:
    catalog = _catalog(
        {"vendor": "extreme", "platform": "X460G2-*", "minimum_version": "32.0"},
        {"vendor": "extreme", "platform": "VSP-*", "end_of_support": "2000-01-01"},
        {"vendor": "extreme", "platform": "*-FabricEngine", "recommended_version": "9.0"},
        {"vendor": "apc", "platform": "*", "end_of_sale": "2000-01-01"},
        {"vendor": "extreme", "platform": "5520-*"},
    )
    observations = [
        _observation(EXOS_DESCR, site_id="S2", device="b"),
        _observation(EXOS_DESCR, site_id="S1", device="z"),
        _observation(VOSS_DESCR, site_id="S1", device="v"),
        _observation(FABRIC_ENGINE_DESCR, site_id="S3", device="f"),
        _observation(APC_DESCR, site_id="S1", device="ups1"),
        _observation(APC_MN_ONLY_DESCR, site_id="S1", device="ups2"),
        _observation(SWITCH_ENGINE_RENAMED_DESCR, site_id="S1", device="se"),
        _observation("ExtremeXOS (X670-G2) version 30.1.1.1", site_id="S1", device="x670"),
        _observation("garbage", site_id="S9", device="g"),
        _observation(None, site_id="S0", device="n", ip=None),
    ]
    return FirmwareComplianceChecker(catalog).evaluate(observations, now=NOW)


def test_sort_by_status_then_platform():
    ordered = sort_firmware_findings(_report_findings())
    assert [(f.status, f.platform, f.site_id, f.device) for f in ordered] == [
        ("unparsed", None, "S0", "n"),
        ("unparsed", None, "S9", "g"),
        ("unknown_platform", "X670-G2", "S1", "x670"),
        ("end_of_support", "VSP-7254XSQ", "S1", "v"),
        ("below_minimum", "X460G2-48p-10G4", "S1", "z"),
        ("below_minimum", "X460G2-48p-10G4", "S2", "b"),
        ("end_of_sale", "AP9630", "S1", "ups2"),
        ("end_of_sale", "hw05", "S1", "ups1"),
        ("below_recommended", "5520-24T-FabricEngine", "S3", "f"),
        ("compliant", "5520-24T", "S1", "se"),
    ]


def test_json_report_is_deterministic_and_complete():
    findings = _report_findings()
    expected = generate_firmware_json_report(findings, generated_at=GENERATED_AT)
    rng = random.Random(7)
    for _ in range(5):
        shuffled = list(findings)
        rng.shuffle(shuffled)
        assert generate_firmware_json_report(shuffled, generated_at=GENERATED_AT) == expected
    report = json.loads(expected)
    assert report["generated_at"] == GENERATED_AT
    assert report["total_findings"] == len(findings)
    assert set(report["status_counts"]) == set(FIRMWARE_STATUSES)
    assert len(report["status_counts"]) == 7
    assert report["status_counts"]["below_minimum"] == 2
    assert report["status_counts"]["end_of_sale"] == 2
    statuses = [finding["status"] for finding in report["findings"]]
    assert statuses == sorted(statuses, key=FIRMWARE_STATUSES.index)
    platforms = [
        finding["platform"] for finding in report["findings"] if finding["status"] == "end_of_sale"
    ]
    assert platforms == ["AP9630", "hw05"]
    assert expected == json.dumps(report, indent=2, sort_keys=True)


def test_json_report_empty_has_zero_counts():
    report = json.loads(generate_firmware_json_report([], generated_at=GENERATED_AT))
    assert report["total_findings"] == 0
    assert report["status_counts"] == {status: 0 for status in FIRMWARE_STATUSES}
    assert report["findings"] == []


def _unescaped_pipes(line: str) -> int:
    # A pipe is escaped only when preceded by an odd number of backslashes.
    return len(re.findall(r"(?<!\\)(?:\\\\)*\|", line))


def _table(markdown: str, heading: str) -> list[str]:
    lines = markdown.splitlines()
    start = lines.index(heading) + 2
    rows = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        rows.append(line)
    return rows


def test_markdown_sections_in_precedence_order():
    findings = _report_findings()
    markdown = generate_firmware_markdown_report(findings, generated_at=GENERATED_AT)
    assert markdown.startswith("# Firmware Lifecycle Compliance\n")
    assert GENERATED_AT in markdown
    assert f"Total findings: {len(findings)}" in markdown
    headings = [line[3:] for line in markdown.splitlines() if line[3:] in FIRMWARE_STATUSES]
    assert headings == list(FIRMWARE_STATUSES)
    counts = _table(markdown, "## Status Counts")
    assert counts[2:] == [
        "| unparsed | 2 |",
        "| unknown_platform | 1 |",
        "| end_of_support | 1 |",
        "| below_minimum | 2 |",
        "| end_of_sale | 2 |",
        "| below_recommended | 1 |",
        "| compliant | 1 |",
    ]
    rows = _table(markdown, "## below_minimum")
    assert len(rows) == 4
    assert rows[2].startswith("| S1 | z |")
    assert rows[3].startswith("| S2 | b |")
    rng = random.Random(3)
    shuffled = list(findings)
    rng.shuffle(shuffled)
    assert generate_firmware_markdown_report(shuffled, generated_at=GENERATED_AT) == markdown


def test_markdown_skips_empty_sections():
    catalog = _catalog({"vendor": "apc", "platform": "*"})
    findings = FirmwareComplianceChecker(catalog).evaluate([_observation(APC_DESCR)], now=NOW)
    markdown = generate_firmware_markdown_report(findings, generated_at=GENERATED_AT)
    assert "## compliant" in markdown
    assert "## unparsed" not in markdown
    empty = generate_firmware_markdown_report([], generated_at=GENERATED_AT)
    assert "No firmware findings." in empty
    assert not any(f"## {status}\n" in empty for status in FIRMWARE_STATUSES)


def test_markdown_escapes_device_supplied_text():
    catalog = _catalog({"vendor": "extreme", "platform": "*"})
    observations = [
        _observation("evil | descr\nwith | newline\rand \\| backslash", device="dev|1"),
        _observation(EXOS_DESCR + " | extra\r\n| row", site_id="S|2", device="d\n2"),
    ]
    findings = FirmwareComplianceChecker(catalog).evaluate(observations, now=NOW)
    markdown = generate_firmware_markdown_report(findings, generated_at=GENERATED_AT)
    for status in {finding.status for finding in findings}:
        rows = _table(markdown, f"## {status}")
        header_pipes = _unescaped_pipes(rows[0])
        assert len(rows) == 3
        assert all(_unescaped_pipes(row) == header_pipes for row in rows)
    assert "evil \\| descr with \\| newline and \\\\\\| backslash" in markdown
    assert "dev\\|1" in markdown
