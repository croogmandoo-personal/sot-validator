"""Extreme / APC firmware version parsing and lifecycle (baseline / EOL) compliance."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timezone
import fnmatch
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Optional

from sot_validator.reporting.generators import (
    _escape_md_cell,
    _resolve_report_timestamp,
)

VENDOR_EXTREME = "extreme"
VENDOR_APC = "apc"

OS_EXOS = "EXOS"
OS_SWITCH_ENGINE = "Switch Engine"
OS_VOSS = "VOSS"
OS_FABRIC_ENGINE = "Fabric Engine"
OS_AOS = "AOS"
OS_FAMILIES: tuple[str, ...] = (
    OS_EXOS,
    OS_SWITCH_ENGINE,
    OS_VOSS,
    OS_FABRIC_ENGINE,
    OS_AOS,
)

STATUS_UNPARSED = "unparsed"
STATUS_UNKNOWN_PLATFORM = "unknown_platform"
STATUS_END_OF_SUPPORT = "end_of_support"
STATUS_BELOW_MINIMUM = "below_minimum"
STATUS_END_OF_SALE = "end_of_sale"
STATUS_BELOW_RECOMMENDED = "below_recommended"
STATUS_COMPLIANT = "compliant"
# Status precedence: a finding's status is the first of these that applies.
FIRMWARE_STATUSES: tuple[str, ...] = (
    STATUS_UNPARSED,
    STATUS_UNKNOWN_PLATFORM,
    STATUS_END_OF_SUPPORT,
    STATUS_BELOW_MINIMUM,
    STATUS_END_OF_SALE,
    STATUS_BELOW_RECOMMENDED,
    STATUS_COMPLIANT,
)

# "ExtremeXOS (X460G2-48p-10G4) version 31.7.1.4 ..." and the "Switch Engine (...)" rename.
_EXOS_PATTERN = re.compile(
    r"\b(ExtremeXOS|Switch\s*Engine)\s*\(([^()]*)\)\s*version\s+[vV]?(\d[\w.\-]*)",
    re.IGNORECASE,
)
_SWITCH_ENGINE_PATTERN = re.compile(r"switch\s*engine", re.IGNORECASE)
# "VSP-7254XSQ (8.1.0.0) ..." and "5520-24T-FabricEngine (8.10.0.0) ...".
_VOSS_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9][\w.\-]*)\s*\(\s*[vV]?(\d+(?:\.\d+)+(?:[-_][\w.\-]*)?)\s*\)"
)
_FABRIC_ENGINE_PATTERN = re.compile(r"fabric\s*engine", re.IGNORECASE)
_VOSS_MARKER_PATTERN = re.compile(r"\bVOSS\b", re.IGNORECASE)
# "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin ...)".
_APC_PATTERN = re.compile(r"\bAPC\b", re.IGNORECASE)
_APC_PF_PATTERN = re.compile(r"(?<![A-Za-z0-9])PF:\s*[vV]?(\d[\w.\-]*)")
_APC_PN_PATTERN = re.compile(r"(?<![A-Za-z0-9])PN:\s*([^\s()]+)")
_APC_HW_PATTERN = re.compile(r"(?<![A-Za-z0-9])(hw\d+)(?![0-9])", re.IGNORECASE)
_APC_MN_PATTERN = re.compile(r"(?<![A-Za-z0-9])MN:\s*([^\s()]+)")

_VERSION_PATTERN = re.compile(r"[vV]?(\d+(?:\.\d+)*)(?:[-_](.+))?")
_ISO_DATE_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")
_TRAILING_PUNCTUATION = ".,;:-_"


def _clean_version(text: str) -> str:
    return text.rstrip(_TRAILING_PUNCTUATION)


@dataclass
class FirmwareInfo:
    """Vendor, platform, OS family and firmware version parsed from a ``sysDescr``."""

    vendor: str
    platform: str
    os_family: str
    version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "platform": self.platform,
            "os_family": self.os_family,
            "version": self.version,
        }


class FirmwareParser:
    """Parse Extreme EXOS / Switch Engine / VOSS / Fabric Engine and APC NMC ``sysDescr``."""

    def parse(self, sys_descr: Any) -> Optional[FirmwareInfo]:
        if not isinstance(sys_descr, str) or not sys_descr.strip():
            return None
        # Each family parser needs its own full header, so a keyword in another family's free
        # text (for example "ExtremeXOS" in an APC string) only falls through to the next one.
        return (
            self._parse_exos(sys_descr)
            or self._parse_apc(sys_descr)
            or self._parse_voss(sys_descr)
        )

    @staticmethod
    def _parse_exos(sys_descr: str) -> Optional[FirmwareInfo]:
        match = _EXOS_PATTERN.search(sys_descr)
        if match is None:
            return None
        platform = match.group(2).strip()
        version = _clean_version(match.group(3))
        if not platform or not version:
            return None
        # Decide from the header and platform tokens only, so free text after the version
        # (for example "by Switch Engine team") cannot flip an EXOS string.
        renamed = _SWITCH_ENGINE_PATTERN.search(match.group(1)) or _SWITCH_ENGINE_PATTERN.search(
            platform
        )
        family = OS_SWITCH_ENGINE if renamed else OS_EXOS
        return FirmwareInfo(VENDOR_EXTREME, platform, family, version)

    @staticmethod
    def _parse_voss(sys_descr: str) -> Optional[FirmwareInfo]:
        match = _VOSS_PATTERN.match(sys_descr)
        if match is None:
            return None
        platform, version = match.group(1), _clean_version(match.group(2))
        if _FABRIC_ENGINE_PATTERN.search(sys_descr):
            family = OS_FABRIC_ENGINE
        elif platform.upper().startswith("VSP") or _VOSS_MARKER_PATTERN.search(sys_descr):
            family = OS_VOSS
        else:
            return None
        return FirmwareInfo(VENDOR_EXTREME, platform, family, version)

    @staticmethod
    def _parse_apc(sys_descr: str) -> Optional[FirmwareInfo]:
        if not _APC_PATTERN.search(sys_descr):
            return None
        version_match = _APC_PF_PATTERN.search(sys_descr)
        if version_match is None:
            return None
        version = _clean_version(version_match.group(1))
        platform: Optional[str] = None
        pn_match = _APC_PN_PATTERN.search(sys_descr)
        if pn_match is not None:
            hw_match = _APC_HW_PATTERN.search(pn_match.group(1))
            if hw_match is not None:
                platform = hw_match.group(1)
        if platform is None:
            mn_match = _APC_MN_PATTERN.search(sys_descr)
            if mn_match is not None:
                platform = mn_match.group(1)
        if not platform or not version:
            return None
        return FirmwareInfo(VENDOR_APC, platform, OS_AOS, version)


def parse_version(text: Any) -> tuple[tuple[int, ...], Optional[tuple[int, ...]]]:
    """Return ``(numeric segments, suffix integers or None)`` for a firmware version.

    Raises ``ValueError`` when ``text`` has no leading numeric dotted part.
    """
    if not isinstance(text, str):
        raise ValueError(f"version must be a string, got {type(text).__name__}")
    match = _VERSION_PATTERN.fullmatch(text.strip())
    if match is None:
        raise ValueError(f"unparseable version {text!r}")
    numbers = tuple(int(part) for part in match.group(1).split("."))
    suffix = match.group(2)
    suffix_numbers = (
        tuple(int(part) for part in re.findall(r"\d+", suffix)) if suffix is not None else None
    )
    return numbers, suffix_numbers


def _cmp(a: Any, b: Any) -> int:
    return (a > b) - (a < b)


def compare_versions(a: str, b: str) -> int:
    """Return -1, 0 or 1 as version ``a`` sorts before, equal to or after ``b``."""
    numbers_a, suffix_a = parse_version(a)
    numbers_b, suffix_b = parse_version(b)
    width = max(len(numbers_a), len(numbers_b))
    padded_a = numbers_a + (0,) * (width - len(numbers_a))
    padded_b = numbers_b + (0,) * (width - len(numbers_b))
    result = _cmp(padded_a, padded_b)
    if result:
        return result
    if suffix_a is None or suffix_b is None:
        # A suffixed build sorts after the same base version without one.
        return _cmp(suffix_a is not None, suffix_b is not None)
    # Only the suffix integers count, so digit-free suffixes such as "-a" and "-b" compare equal.
    return _cmp(suffix_a, suffix_b)


@dataclass
class LifecycleEntry:
    """One catalog baseline: a vendor plus platform glob with optional versions and dates."""

    vendor: str
    platform: str
    minimum_version: Optional[str] = None
    recommended_version: Optional[str] = None
    end_of_sale: Optional[date] = None
    end_of_support: Optional[date] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "platform": self.platform,
            "minimum_version": self.minimum_version,
            "recommended_version": self.recommended_version,
            "end_of_sale": self.end_of_sale.isoformat() if self.end_of_sale else None,
            "end_of_support": self.end_of_support.isoformat() if self.end_of_support else None,
        }


def _entry_error(index: int, platform: Any, message: str) -> ValueError:
    where = f"catalog entry {index}"
    if isinstance(platform, str) and platform.strip():
        where += f" (platform {platform!r})"
    return ValueError(f"{where}: {message}")


def _parse_entry(index: int, raw: Any) -> LifecycleEntry:
    if not isinstance(raw, Mapping):
        raise _entry_error(index, None, "must be a JSON object")
    platform = raw.get("platform")
    for name in ("vendor", "platform"):
        value = raw.get(name)
        if not isinstance(value, str) or not value.strip():
            raise _entry_error(index, platform, f"{name} must be a non-empty string")
    versions: dict[str, Optional[str]] = {}
    for name in ("minimum_version", "recommended_version"):
        value = raw.get(name)
        if value is not None:
            try:
                parse_version(value)
            except ValueError as exc:
                raise _entry_error(index, platform, f"{name}: {exc}") from None
        versions[name] = value
    dates: dict[str, Optional[date]] = {}
    for name in ("end_of_sale", "end_of_support"):
        value = raw.get(name)
        parsed: Optional[date] = None
        if value is not None:
            if not isinstance(value, str) or not _ISO_DATE_PATTERN.fullmatch(value):
                raise _entry_error(
                    index, platform, f"{name} must be a YYYY-MM-DD date, got {value!r}"
                )
            try:
                parsed = date.fromisoformat(value)
            except ValueError:
                raise _entry_error(
                    index, platform, f"{name} is not a valid date: {value!r}"
                ) from None
        dates[name] = parsed
    return LifecycleEntry(
        vendor=raw["vendor"].strip(),
        platform=raw["platform"].strip(),
        minimum_version=versions["minimum_version"],
        recommended_version=versions["recommended_version"],
        end_of_sale=dates["end_of_sale"],
        end_of_support=dates["end_of_support"],
    )


class LifecycleCatalog:
    """Operator-maintained firmware baselines and end-of-sale / end-of-support dates."""

    def __init__(self, entries: Iterable[LifecycleEntry], note: Optional[str] = None) -> None:
        self.entries: list[LifecycleEntry] = list(entries)
        self.note = note

    @classmethod
    def from_dict(cls, data: Any) -> LifecycleCatalog:
        if not isinstance(data, Mapping):
            raise ValueError("lifecycle catalog must be a JSON object with an 'entries' array")
        entries = data.get("entries")
        if not isinstance(entries, list):
            raise ValueError("lifecycle catalog must have an 'entries' array")
        note = data.get("note")
        if note is not None and not isinstance(note, str):
            raise ValueError("lifecycle catalog 'note' must be a string")
        return cls([_parse_entry(index, raw) for index, raw in enumerate(entries)], note=note)

    @classmethod
    def load(cls, path: Path | str) -> LifecycleCatalog:
        text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"lifecycle catalog is not valid JSON (line {exc.lineno}, column {exc.colno}): "
                f"{exc.msg}"
            ) from None
        return cls.from_dict(data)

    def match(self, vendor: str, platform: str) -> Optional[LifecycleEntry]:
        """Return the first entry, in file order, matching ``vendor`` and ``platform``."""
        vendor_key = vendor.strip().lower()
        platform_key = platform.lower()
        for entry in self.entries:
            if entry.vendor.lower() == vendor_key and fnmatch.fnmatchcase(
                platform_key, entry.platform.lower()
            ):
                return entry
        return None


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _optional_text(value: Any, field_name: str) -> Optional[str]:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    return value


@dataclass
class FirmwareObservation:
    """One device's raw ``sysDescr`` as observed at a site."""

    site_id: str
    device: str
    ip: Optional[str] = None
    sys_descr: Optional[str] = None

    def __post_init__(self) -> None:
        self.site_id = _require_text(self.site_id, "site_id")
        self.device = _require_text(self.device, "device")
        self.ip = _optional_text(self.ip, "ip")
        self.sys_descr = _optional_text(self.sys_descr, "sys_descr")

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "device": self.device,
            "ip": self.ip,
            "sys_descr": self.sys_descr,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FirmwareObservation:
        device = data.get("device")
        if device is None:
            device = data.get("hostname")
        return cls(
            site_id=data.get("site_id"),
            device=device,
            ip=data.get("ip"),
            sys_descr=data.get("sys_descr"),
        )


@dataclass
class FirmwareFinding:
    """Lifecycle compliance status of one observed device."""

    site_id: str
    device: str
    ip: Optional[str]
    sys_descr: Optional[str]
    vendor: Optional[str]
    platform: Optional[str]
    os_family: Optional[str]
    version: Optional[str]
    status: str
    conditions: list[str]
    catalog_platform: Optional[str] = None
    minimum_version: Optional[str] = None
    recommended_version: Optional[str] = None
    end_of_sale: Optional[str] = None
    end_of_support: Optional[str] = None

    def __post_init__(self) -> None:
        if self.status not in FIRMWARE_STATUSES:
            raise ValueError(f"status must be one of {FIRMWARE_STATUSES}, got {self.status!r}")
        self.conditions = list(self.conditions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "device": self.device,
            "ip": self.ip,
            "sys_descr": self.sys_descr,
            "vendor": self.vendor,
            "platform": self.platform,
            "os_family": self.os_family,
            "version": self.version,
            "status": self.status,
            "conditions": list(self.conditions),
            "catalog_platform": self.catalog_platform,
            "minimum_version": self.minimum_version,
            "recommended_version": self.recommended_version,
            "end_of_sale": self.end_of_sale,
            "end_of_support": self.end_of_support,
        }


def _below(version: str, baseline: Optional[str]) -> bool:
    return baseline is not None and compare_versions(version, baseline) < 0


def _reached(today: date, boundary: Optional[date]) -> bool:
    return boundary is not None and today >= boundary


class FirmwareComplianceChecker:
    """Compare parsed device firmware against a ``LifecycleCatalog``."""

    def __init__(self, catalog: LifecycleCatalog, parser: Optional[FirmwareParser] = None) -> None:
        self.catalog = catalog
        self.parser = parser if parser is not None else FirmwareParser()

    def evaluate(
        self,
        observations: Iterable[FirmwareObservation | Mapping[str, Any]],
        now: Optional[datetime] = None,
    ) -> list[FirmwareFinding]:
        if now is None:
            now = datetime.now(timezone.utc)
        elif not isinstance(now, datetime):
            raise ValueError("now must be a datetime instance or None")
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        today = now.astimezone(timezone.utc).date()
        findings = []
        for observation in observations:
            if not isinstance(observation, FirmwareObservation):
                observation = FirmwareObservation.from_dict(observation)
            findings.append(self._evaluate_one(observation, today))
        return findings

    def _evaluate_one(self, observation: FirmwareObservation, today: date) -> FirmwareFinding:
        info = self.parser.parse(observation.sys_descr)
        base = {
            "site_id": observation.site_id,
            "device": observation.device,
            "ip": observation.ip,
            "sys_descr": observation.sys_descr,
        }
        if info is None:
            return FirmwareFinding(
                **base,
                vendor=None,
                platform=None,
                os_family=None,
                version=None,
                status=STATUS_UNPARSED,
                conditions=[STATUS_UNPARSED],
            )

        try:
            parse_version(info.version)
            comparable = True
        except ValueError:
            comparable = False
        entry = self.catalog.match(info.vendor, info.platform)
        conditions: list[str] = []
        if not comparable:
            conditions.append(STATUS_UNPARSED)
        if entry is None:
            conditions.append(STATUS_UNKNOWN_PLATFORM)
        else:
            if _reached(today, entry.end_of_support):
                conditions.append(STATUS_END_OF_SUPPORT)
            if comparable and _below(info.version, entry.minimum_version):
                conditions.append(STATUS_BELOW_MINIMUM)
            if _reached(today, entry.end_of_sale):
                conditions.append(STATUS_END_OF_SALE)
            if comparable and _below(info.version, entry.recommended_version):
                conditions.append(STATUS_BELOW_RECOMMENDED)
        if not conditions:
            conditions.append(STATUS_COMPLIANT)
        catalog_values = entry.to_dict() if entry is not None else {}
        return FirmwareFinding(
            **base,
            vendor=info.vendor,
            platform=info.platform,
            os_family=info.os_family,
            version=info.version,
            status=conditions[0],
            conditions=conditions,
            catalog_platform=catalog_values.get("platform"),
            minimum_version=catalog_values.get("minimum_version"),
            recommended_version=catalog_values.get("recommended_version"),
            end_of_sale=catalog_values.get("end_of_sale"),
            end_of_support=catalog_values.get("end_of_support"),
        )


def _text_key(value: Optional[str]) -> tuple[bool, str]:
    return (value is None, value or "")


def sort_firmware_findings(findings: Iterable[FirmwareFinding]) -> list[FirmwareFinding]:
    """Sort by status precedence, then platform (case-insensitive, unknown last), site,
    device and IP.

    The remaining fields break ties so the order never depends on the input order.
    """
    return sorted(
        findings,
        key=lambda f: (
            FIRMWARE_STATUSES.index(f.status),
            f.platform is None,
            (f.platform or "").lower(),
            f.site_id,
            f.device,
            _text_key(f.ip),
            f.platform or "",
            _text_key(f.vendor),
            _text_key(f.os_family),
            _text_key(f.version),
            _text_key(f.sys_descr),
            tuple(f.conditions),
            _text_key(f.catalog_platform),
        ),
    )


def _status_counts(findings: Iterable[FirmwareFinding]) -> dict[str, int]:
    counts = Counter(finding.status for finding in findings)
    return {status: counts.get(status, 0) for status in FIRMWARE_STATUSES}


def generate_firmware_json_report(
    findings: Iterable[FirmwareFinding],
    generated_at: Optional[datetime | str] = None,
) -> str:
    """Return a deterministic JSON firmware lifecycle compliance report."""
    ordered = sort_firmware_findings(findings)
    report = {
        "generated_at": _resolve_report_timestamp(generated_at).isoformat(),
        "total_findings": len(ordered),
        "status_counts": _status_counts(ordered),
        "findings": [finding.to_dict() for finding in ordered],
    }
    return json.dumps(report, indent=2, sort_keys=True)


def _md_cell(value: Any) -> str:
    if value is None:
        return ""
    # Escape backslashes first so a device-supplied "\|" cannot cancel the pipe escape, and
    # fold lone carriage returns into newlines because they also end a Markdown line.
    text = str(value).replace("\\", "\\\\").replace("\r\n", "\n").replace("\r", "\n")
    return _escape_md_cell(text)


def _md_row(cells: Iterable[Any]) -> str:
    return "| " + " | ".join(_md_cell(cell) for cell in cells) + " |"


_FINDING_COLUMNS = (
    "Site",
    "Device",
    "IP",
    "Vendor",
    "Platform",
    "OS Family",
    "Version",
    "Conditions",
    "Catalog Platform",
    "Minimum",
    "Recommended",
    "End of Sale",
    "End of Support",
    "sysDescr",
)


def generate_firmware_markdown_report(
    findings: Iterable[FirmwareFinding],
    generated_at: Optional[datetime | str] = None,
) -> str:
    """Return a deterministic Markdown firmware lifecycle compliance report."""
    ordered = sort_firmware_findings(findings)
    timestamp = _resolve_report_timestamp(generated_at).isoformat()
    counts = _status_counts(ordered)
    lines = [
        "# Firmware Lifecycle Compliance",
        "",
        f"Generated at: {timestamp}",
        "",
        f"Total findings: {len(ordered)}",
        "",
        "## Status Counts",
        "",
        "| Status | Count |",
        "| --- | --- |",
    ]
    lines.extend(_md_row([status, counts[status]]) for status in FIRMWARE_STATUSES)
    if not ordered:
        lines.extend(["", "No firmware findings."])

    for status in FIRMWARE_STATUSES:
        section = [finding for finding in ordered if finding.status == status]
        if not section:
            continue
        lines.extend(
            [
                "",
                f"## {status}",
                "",
                _md_row(_FINDING_COLUMNS),
                "| " + " | ".join("---" for _ in _FINDING_COLUMNS) + " |",
            ]
        )
        for finding in section:
            lines.append(
                _md_row(
                    [
                        finding.site_id,
                        finding.device,
                        finding.ip,
                        finding.vendor,
                        finding.platform,
                        finding.os_family,
                        finding.version,
                        ", ".join(finding.conditions),
                        finding.catalog_platform,
                        finding.minimum_version,
                        finding.recommended_version,
                        finding.end_of_sale,
                        finding.end_of_support,
                        finding.sys_descr,
                    ]
                )
            )
    return "\n".join(lines) + "\n"
