"""Unit tests for the offline IEEE OUI registry and MAC classification helpers."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path
import time

import pytest

from sot_validator.enrichment import (
    OuiMatch,
    OuiRegistry,
    classify_mac,
    is_locally_administered,
    is_multicast,
)
from sot_validator.topology.identifier import KNOWN_OUI_VENDORS

OUI_DIR = Path(__file__).resolve().parent / "fixtures" / "oui"
MA_L_CSV = OUI_DIR / "oui.csv"
MA_M_CSV = OUI_DIR / "mam.csv"
MA_S_CSV = OUI_DIR / "oui36.csv"

HEADER = "Registry,Assignment,Organization Name,Organization Address\n"
MALFORMED_INPUTS = [
    "",
    "   ",
    None,
    12345,
    b"00:04:96:00:00:01",
    "00:04:96:00:00",
    "00:04:96:00:00:01:02",
    "zz:04:96:00:00:01",
    "00:04:96:00:00:0g",
    "10.0.0.1",
    "192.168.100.200",
    "nope",
]


def _write_csv(path: Path, body: str) -> Path:
    path.write_text(HEADER + body, encoding="utf-8")
    return path


def test_package_exports() -> None:
    import sot_validator.enrichment as enrichment

    assert sorted(enrichment.__all__) == sorted(
        ["OuiRegistry", "OuiMatch", "is_locally_administered", "is_multicast", "classify_mac"]
    )


def test_oui_match_is_frozen() -> None:
    match = OuiMatch(vendor="X", prefix="000000", prefix_bits=24, registry="MA-L")
    assert match.role_hint is None
    with pytest.raises(FrozenInstanceError):
        match.vendor = "Y"  # type: ignore[misc]


# --- Loading fixtures ---------------------------------------------------------


def test_load_ma_l_fixture_alone() -> None:
    registry = OuiRegistry.from_ieee_csv(MA_L_CSV)
    match = registry.lookup("00:50:56:01:02:03")
    assert match == OuiMatch(
        vendor="VMware, Inc.", prefix="005056", prefix_bits=24, registry="MA-L"
    )
    assert registry.lookup("70:b3:d5:12:34:56").registry == "MA-L"


def test_load_ma_m_fixture_alone() -> None:
    registry = OuiRegistry.from_ieee_csv(str(MA_M_CSV))
    match = registry.lookup("f4:a4:54:2a:bb:cc")
    assert match == OuiMatch(
        vendor="Sample Sensors Inc", prefix="f4a4542", prefix_bits=28, registry="MA-M"
    )
    # Outside the 28-bit block and no MA-L entry loaded.
    assert registry.lookup("f4:a4:54:3a:bb:cc") is None


def test_load_ma_s_fixture_alone() -> None:
    registry = OuiRegistry.from_ieee_csv(MA_S_CSV)
    match = registry.lookup("8c:1f:64:ab:cd:ef")
    assert match == OuiMatch(
        vendor="Industrial Gateways BV",
        prefix="8c1f64abc",
        prefix_bits=36,
        registry="MA-S",
    )
    assert registry.lookup("8c:1f:64:ab:dd:ef") is None


def test_load_all_fixtures_together() -> None:
    registry = OuiRegistry.from_ieee_csv(MA_L_CSV, MA_M_CSV, MA_S_CSV)
    assert registry.lookup("00:50:56:aa:bb:cc").registry == "MA-L"
    assert registry.lookup("f4:a4:54:2a:bb:cc").registry == "MA-M"
    assert registry.lookup("8c:1f:64:ab:cd:ef").registry == "MA-S"


def test_quoted_organization_name_with_comma() -> None:
    registry = OuiRegistry.from_ieee_csv(MA_L_CSV, MA_M_CSV, MA_S_CSV)
    assert registry.lookup("bc:24:11:00:00:01").vendor == "Proxmox Server Solutions, GmbH"
    assert registry.lookup("70:b3:d5:1f:00:01").vendor == "Block Holder, Medium Ltd"
    assert registry.lookup("70:b3:d5:12:30:01").vendor == "Tiny Block, Small Co"


def test_registry_type_comes_from_row_not_file_name(tmp_path: Path) -> None:
    mixed = _write_csv(
        tmp_path / "oui.csv",
        "MA-S,0A1B2C3D4,Small In Large File,Addr\n"
        "MA-M,0A1B2C5,Medium In Large File,Addr\n",
    )
    registry = OuiRegistry.from_ieee_csv(mixed)
    small = registry.lookup("0a:1b:2c:3d:4e:5f")
    assert (small.registry, small.prefix_bits, small.prefix) == ("MA-S", 36, "0a1b2c3d4")
    medium = registry.lookup("0a:1b:2c:5d:4e:5f")
    assert (medium.registry, medium.prefix_bits, medium.prefix) == ("MA-M", 28, "0a1b2c5")


def test_from_ieee_csv_with_no_paths_uses_only_builtin() -> None:
    registry = OuiRegistry.from_ieee_csv()
    assert registry.lookup("00:50:56:01:02:03") is None
    assert registry.lookup("00:04:96:01:02:03").registry == "builtin"


def test_utf8_bom_header_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "bom.csv"
    path.write_text(HEADER + "MA-L,ABCDEF,Bom Vendor,Addr\n", encoding="utf-8-sig")
    assert OuiRegistry.from_ieee_csv(path).lookup("ab:cd:ef:00:00:01").vendor == "Bom Vendor"


# --- Longest-prefix precedence ------------------------------------------------


def test_longest_prefix_precedence() -> None:
    registry = OuiRegistry.from_ieee_csv(MA_L_CSV, MA_M_CSV, MA_S_CSV)

    small = registry.lookup("70:b3:d5:12:3a:bc")
    assert small == OuiMatch(
        vendor="Tiny Block, Small Co",
        prefix="70b3d5123",
        prefix_bits=36,
        registry="MA-S",
    )

    medium = registry.lookup("70:b3:d5:1f:ff:ff")
    assert medium == OuiMatch(
        vendor="Block Holder, Medium Ltd",
        prefix="70b3d51",
        prefix_bits=28,
        registry="MA-M",
    )

    large = registry.lookup("70:b3:d5:20:00:00")
    assert large == OuiMatch(
        vendor="IEEE Registration Authority",
        prefix="70b3d5",
        prefix_bits=24,
        registry="MA-L",
    )
    assert len({small.vendor, medium.vendor, large.vendor}) == 3


def test_precedence_independent_of_load_order() -> None:
    registry = OuiRegistry.from_ieee_csv(MA_S_CSV, MA_M_CSV, MA_L_CSV)
    assert registry.lookup("70:b3:d5:12:3a:bc").registry == "MA-S"
    assert registry.lookup("70:b3:d5:1f:ff:ff").registry == "MA-M"
    assert registry.lookup("70:b3:d5:20:00:00").registry == "MA-L"


def test_duplicate_prefix_last_loaded_wins(tmp_path: Path) -> None:
    first = _write_csv(tmp_path / "a.csv", "MA-L,123456,First Vendor,Addr\n")
    second = _write_csv(
        tmp_path / "b.csv",
        "MA-L,123456,Second Vendor,Addr\nMA-L,123456,Third Vendor,Addr\n",
    )
    assert OuiRegistry.from_ieee_csv(first, second).lookup("12:34:56:00:00:01").vendor == (
        "Third Vendor"
    )
    assert OuiRegistry.from_ieee_csv(second, first).lookup("12:34:56:00:00:01").vendor == (
        "First Vendor"
    )


# --- MAC input formats --------------------------------------------------------


@pytest.mark.parametrize(
    "mac",
    [
        "70:b3:d5:12:3a:bc",
        "70-b3-d5-12-3a-bc",
        "70b3.d512.3abc",
        "70b3d5123abc",
        "70:B3:D5:12:3A:BC",
        "70-B3-d5-12-3A-bc",
        "70B3.D512.3ABC",
        "70B3D5123ABC",
        "  70:b3:d5:12:3a:bc  ",
    ],
)
def test_mac_formats_resolve_identically(mac: str) -> None:
    registry = OuiRegistry.from_ieee_csv(MA_L_CSV, MA_M_CSV, MA_S_CSV)
    assert registry.lookup(mac) == OuiMatch(
        vendor="Tiny Block, Small Co",
        prefix="70b3d5123",
        prefix_bits=36,
        registry="MA-S",
    )


# --- MAC classification -------------------------------------------------------


@pytest.mark.parametrize(
    ("mac", "multicast", "local", "expected"),
    [
        ("00:04:96:00:00:01", False, False, "universal"),
        ("00-C0-B7-01-02-03", False, False, "universal"),
        ("aa:9c:6c:00:00:01", False, True, "locally_administered"),
        ("02:00:00:00:00:01", False, True, "locally_administered"),
        ("DA:A1:19:00:00:01", False, True, "locally_administered"),
        ("01:00:5e:00:00:01", True, False, "multicast"),
        ("33:33:00:00:00:01", True, True, "multicast"),
        ("03:00:00:00:00:01", True, True, "multicast"),
        ("ff:ff:ff:ff:ff:ff", True, True, "multicast"),
        ("0100.5e00.0001", True, False, "multicast"),
    ],
)
def test_mac_classification(mac: str, multicast: bool, local: bool, expected: str) -> None:
    assert is_multicast(mac) is multicast
    assert is_locally_administered(mac) is local
    assert classify_mac(mac) == expected


def test_classification_independent_of_registry() -> None:
    registry = OuiRegistry.from_ieee_csv()
    assert registry.lookup("aa:9c:6c:12:34:56").vendor == "Ubiquiti UniFi"
    assert classify_mac("aa:9c:6c:12:34:56") == "locally_administered"


# --- Malformed input ----------------------------------------------------------


@pytest.mark.parametrize("bad", MALFORMED_INPUTS)
def test_malformed_input_never_raises(bad: object) -> None:
    registry = OuiRegistry.from_ieee_csv(MA_L_CSV, MA_M_CSV, MA_S_CSV)
    assert registry.lookup(bad) is None
    assert is_multicast(bad) is False
    assert is_locally_administered(bad) is False
    assert classify_mac(bad) == "invalid"


# --- Malformed CSV rows and headers -------------------------------------------


def test_malformed_fixture_rows_are_skipped() -> None:
    registry = OuiRegistry.from_ieee_csv(MA_L_CSV, MA_M_CSV, MA_S_CSV)
    # MA-L row with an empty Organization Name.
    assert registry.lookup("f0:d1:a9:00:00:01") is None
    # Unknown Registry value.
    assert registry.lookup("d8:eb:97:00:00:01") is None
    # MA-S row with non-hex assignment must not shadow the MA-M entry.
    assert registry.lookup("70:b3:d5:1f:ff:ff").registry == "MA-M"
    # MA-M row with a 6-digit assignment must not become an MA-L or MA-M entry.
    vendors = {
        registry.lookup(mac).vendor
        for mac in ("70:b3:d5:00:00:01", "70:b3:d5:50:00:01", "70:b3:d5:f0:00:01")
    }
    assert vendors == {"IEEE Registration Authority"}


@pytest.mark.parametrize(
    "row",
    [
        "MA-L,00ZZ11,Bad Hex,Addr\n",
        "MA-L,0011,Short,Addr\n",
        "MA-L,0011223,Too Long For MA-L,Addr\n",
        "MA-M,001122,Too Short For MA-M,Addr\n",
        "MA-S,00112233,Too Short For MA-S,Addr\n",
        "MA-L,001122,,Addr\n",
        "MA-L,001122,   ,Addr\n",
        "IAB,001122,Unsupported Registry,Addr\n",
        ",001122,Empty Registry,Addr\n",
        "MA-L\n",
        "MA-L,00:11:22,Separated Prefix,Addr\n",
    ],
)
def test_malformed_row_is_skipped(tmp_path: Path, row: str) -> None:
    path = _write_csv(tmp_path / "bad.csv", row + "MA-L,AABBCC,Good Vendor,Addr\n")
    registry = OuiRegistry.from_ieee_csv(path)
    assert registry.lookup("00:11:22:33:44:55") is None
    assert registry.lookup("aa:bb:cc:00:00:01").vendor == "Good Vendor"


def test_missing_header_raises_value_error_naming_file(tmp_path: Path) -> None:
    path = tmp_path / "wrong_headers.csv"
    path.write_text("Registry,Prefix,Organization Name\nMA-L,001122,X\n", encoding="utf-8")
    with pytest.raises(ValueError, match="wrong_headers.csv") as excinfo:
        OuiRegistry.from_ieee_csv(path)
    assert "Assignment" in str(excinfo.value)


def test_empty_file_raises_value_error(tmp_path: Path) -> None:
    path = tmp_path / "empty.csv"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty.csv"):
        OuiRegistry.from_ieee_csv(path)


def test_nonexistent_path_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        OuiRegistry.from_ieee_csv(tmp_path / "missing.csv")


# --- Built-in fallback --------------------------------------------------------


def test_builtin_fallback_without_csv() -> None:
    registry = OuiRegistry.from_ieee_csv()
    match = registry.lookup("00-04-96-AA-BB-CC")
    assert match == OuiMatch(
        vendor="Extreme Networks",
        prefix="000496",
        prefix_bits=24,
        registry="builtin",
        role_hint="switch",
    )
    for prefix, (vendor, role) in KNOWN_OUI_VENDORS.items():
        found = registry.lookup(f"{prefix}:01:02:03")
        assert (found.vendor, found.role_hint, found.registry) == (vendor, role, "builtin")
        assert found.prefix == prefix.replace(":", "")


def test_csv_overrides_builtin_fallback() -> None:
    assert "00:c0:b7" in KNOWN_OUI_VENDORS
    registry = OuiRegistry.from_ieee_csv(MA_L_CSV)
    match = registry.lookup("00:c0:b7:01:02:03")
    assert match == OuiMatch(
        vendor="American Power Conversion Corp",
        prefix="00c0b7",
        prefix_bits=24,
        registry="MA-L",
        role_hint=None,
    )
    # Built-in prefixes not in the CSV still fall back.
    assert registry.lookup("aa:9c:6c:00:00:01").registry == "builtin"


def test_longer_csv_prefix_beats_builtin(tmp_path: Path) -> None:
    path = _write_csv(tmp_path / "mam.csv", "MA-M,0004961,Medium Under Extreme,Addr\n")
    registry = OuiRegistry.from_ieee_csv(path)
    assert registry.lookup("00:04:96:1a:00:01").registry == "MA-M"
    assert registry.lookup("00:04:96:2a:00:01").registry == "builtin"


def test_builtin_table_is_not_mutated() -> None:
    before = dict(KNOWN_OUI_VENDORS)
    OuiRegistry.from_ieee_csv(MA_L_CSV, MA_M_CSV, MA_S_CSV)
    assert KNOWN_OUI_VENDORS == before


# --- Load-time ----------------------------------------------------------------


def test_large_ma_l_file_loads_under_one_second(tmp_path: Path) -> None:
    path = tmp_path / "oui_large.csv"
    rows = 35_000
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(HEADER)
        for index in range(rows):
            handle.write(
                f'MA-L,{index:06X},"Vendor {index}, Inc.","{index} Example Road, Somewhere US"\n'
            )

    start = time.perf_counter()
    registry = OuiRegistry.from_ieee_csv(path)
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0, f"loading {rows} rows took {elapsed:.3f}s"
    match = registry.lookup("00:88:b7:01:02:03")
    assert match is not None
    assert (match.vendor, match.prefix, match.registry) == ("Vendor 34999, Inc.", "0088b7", "MA-L")
