"""Offline UPS power-dependency map, blast-radius analysis, and false-redundancy detection."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import csv
from dataclasses import dataclass, field
import json
import pathlib
from typing import Any, Optional

from sot_validator.models import EquipmentCategory, Site
from sot_validator.reporting.generators import _escape_md_cell
from sot_validator.signals.ups_health import UpsHealthRecord, UpsHealthStatus

VALID_POWER_SOURCE_TYPES: tuple[str, ...] = ("ups", "pdu", "outlet_group", "utility")

_INTERMEDIATE_SOURCE_TYPES: frozenset[str] = frozenset({"pdu", "outlet_group"})
_CRITICAL_ROLES: frozenset[str] = frozenset({"router", "core_switch", "core"})
_CSV_COLUMNS: tuple[str, ...] = ("device_id", "psu", "source_id", "source_type", "outlet")
_REQUIRED_FIELDS: tuple[str, ...] = ("device_id", "source_id", "source_type")

_HEALTH_SEVERITY: dict[UpsHealthStatus, int] = {
    UpsHealthStatus.HEALTHY: 1,
    UpsHealthStatus.WARNING: 2,
    UpsHealthStatus.CRITICAL: 3,
    UpsHealthStatus.UNREACHABLE: 3,
}
_UNKNOWN_HEALTH_SEVERITY = 2

PROBLEM_UNKNOWN_UPS = "UNKNOWN_UPS"
PROBLEM_UNKNOWN_SOURCE = "UNKNOWN_SOURCE"
PROBLEM_UNKNOWN_DEVICE = "UNKNOWN_DEVICE"


def _require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _optional_str(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    return value.strip() or None


@dataclass
class PowerFeed:
    """One power feed: ``device_id`` (optionally a specific PSU) draws power from ``source_id``."""

    device_id: str
    source_id: str
    source_type: str
    psu: Optional[str] = None
    outlet: Optional[str] = None

    def __post_init__(self) -> None:
        self.device_id = _require_str(self.device_id, "device_id")
        self.source_id = _require_str(self.source_id, "source_id")
        source_type = _require_str(self.source_type, "source_type").lower()
        if source_type not in VALID_POWER_SOURCE_TYPES:
            raise ValueError(
                f"Invalid source_type: {self.source_type!r} "
                f"(expected one of {', '.join(VALID_POWER_SOURCE_TYPES)})"
            )
        self.source_type = source_type
        self.psu = _optional_str(self.psu, "psu")
        self.outlet = _optional_str(self.outlet, "outlet")

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "psu": self.psu,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "outlet": self.outlet,
        }


@dataclass
class PowerMapProblem:
    """A power-map feed excluded from the graph because an ID could not be resolved."""

    code: str
    feed_index: int
    entity_id: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "feed_index": self.feed_index,
            "entity_id": self.entity_id,
            "message": self.message,
        }


@dataclass
class PowerMapLoadResult:
    """Validated feeds plus the problems that excluded the remaining feeds."""

    feeds: list[PowerFeed] = field(default_factory=list)
    problems: list[PowerMapProblem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "feeds": [feed.to_dict() for feed in self.feeds],
            "problems": [problem.to_dict() for problem in self.problems],
        }


def _feed_from_row(row: Any, index: int) -> PowerFeed:
    if not isinstance(row, Mapping):
        raise ValueError(f"Power map row {index}: expected an object, got {type(row).__name__}")
    for name in _REQUIRED_FIELDS:
        if row.get(name) is None:
            raise ValueError(f"Power map row {index}: missing field {name!r}")
    try:
        return PowerFeed(
            device_id=row["device_id"],
            source_id=row["source_id"],
            source_type=row["source_type"],
            psu=row.get("psu"),
            outlet=row.get("outlet"),
        )
    except ValueError as exc:
        raise ValueError(f"Power map row {index}: {exc}") from exc


class PowerMapLoader:
    """Read-only loader for operator-maintained JSON/CSV power maps, validated against a ``Site``."""

    def __init__(self, site: Site) -> None:
        self.site = site

    def load(self, path: str | pathlib.Path) -> PowerMapLoadResult:
        file_path = pathlib.Path(path)
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            rows = self._read_json(file_path)
        elif suffix == ".csv":
            rows = self._read_csv(file_path)
        else:
            raise ValueError(
                f"Unsupported power map extension {file_path.suffix!r} (expected .json or .csv)"
            )
        feeds = [_feed_from_row(row, index) for index, row in enumerate(rows, start=1)]
        return self._validate(feeds)

    @staticmethod
    def _read_json(file_path: pathlib.Path) -> list[Any]:
        with file_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, Mapping):
            data = data.get("feeds")
        if not isinstance(data, list):
            raise ValueError(
                "Power map JSON must be a list of feeds or an object with a 'feeds' list"
            )
        return data

    @staticmethod
    def _read_csv(file_path: pathlib.Path) -> list[Any]:
        with file_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            header = [name.strip() for name in reader.fieldnames or []]
            missing = [name for name in _CSV_COLUMNS if name not in header]
            if missing:
                raise ValueError(f"Power map CSV is missing columns: {', '.join(missing)}")
            reader.fieldnames = header
            return list(reader)

    def _validate(self, feeds: Iterable[PowerFeed]) -> PowerMapLoadResult:
        """Split ``feeds`` into resolvable feeds and problems; problem indexes are 1-based."""
        indexed = list(enumerate(feeds, start=1))
        ups_ids = {
            item.equipment_id
            for item in self.site.equipment
            if item.category is EquipmentCategory.UPS
        }
        inventory_ids = {device.device_id for device in self.site.devices} | {
            item.equipment_id for item in self.site.equipment
        }
        intermediate_ids = {
            feed.source_id
            for _, feed in indexed
            if feed.source_type in _INTERMEDIATE_SOURCE_TYPES
        }

        problems: dict[int, list[PowerMapProblem]] = {}
        for index, feed in indexed:
            found: list[PowerMapProblem] = []
            if feed.device_id not in inventory_ids and feed.device_id not in intermediate_ids:
                found.append(
                    PowerMapProblem(
                        PROBLEM_UNKNOWN_DEVICE,
                        index,
                        feed.device_id,
                        f"Fed device {feed.device_id!r} is not a site device, equipment item, "
                        "or mapped PDU/outlet group",
                    )
                )
            if feed.source_type == "ups" and feed.source_id not in ups_ids:
                found.append(
                    PowerMapProblem(
                        PROBLEM_UNKNOWN_UPS,
                        index,
                        feed.source_id,
                        f"UPS source {feed.source_id!r} is not UPS equipment in site "
                        f"{self.site.site_id!r}",
                    )
                )
            if found:
                problems[index] = found

        # An intermediate source must itself be fed by a retained feed; repeat until stable so
        # a PDU whose only upstream feed was excluded cannot become an independent power root.
        while True:
            fed_ids: dict[str, set[int]] = {}
            for index, feed in indexed:
                if index not in problems:
                    fed_ids.setdefault(feed.device_id, set()).add(index)
            newly_excluded = False
            for index, feed in indexed:
                if index in problems or feed.source_type not in _INTERMEDIATE_SOURCE_TYPES:
                    continue
                if fed_ids.get(feed.source_id, set()) - {index}:
                    continue
                problems[index] = [
                    PowerMapProblem(
                        PROBLEM_UNKNOWN_SOURCE,
                        index,
                        feed.source_id,
                        f"{feed.source_type} source {feed.source_id!r} has no valid upstream feed",
                    )
                ]
                newly_excluded = True
            if not newly_excluded:
                break

        return PowerMapLoadResult(
            feeds=[feed for index, feed in indexed if index not in problems],
            problems=[problem for index in sorted(problems) for problem in problems[index]],
        )


class PowerCycleError(ValueError):
    """Raised when following feeds from a device to its sources leads back to the same ID."""

    def __init__(self, cycle: list[str]) -> None:
        self.cycle = list(cycle)
        super().__init__(f"Power map contains a cycle: {' -> '.join(self.cycle)}")


@dataclass
class BlastRadius:
    """End devices affected when ``source_id`` fails."""

    source_id: str
    loses_all_power: list[str] = field(default_factory=list)
    loses_redundancy: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "loses_all_power": list(self.loses_all_power),
            "loses_redundancy": list(self.loses_redundancy),
        }


class PowerDependencyGraph:
    """Acyclic device-to-source power graph supporting failure simulation."""

    def __init__(self, feeds: Iterable[PowerFeed]) -> None:
        self.feeds: list[PowerFeed] = list(feeds)
        self._feeds_by_device: dict[str, list[PowerFeed]] = {}
        for feed in self.feeds:
            self._feeds_by_device.setdefault(feed.device_id, []).append(feed)
        self.sources: set[str] = {feed.source_id for feed in self.feeds}
        fed = set(self._feeds_by_device)
        self.roots: set[str] = {
            feed.source_id
            for feed in self.feeds
            if feed.source_id not in fed or feed.source_type == "utility"
        }
        self.end_devices: list[str] = sorted(fed - self.sources)
        self._order = self._topological_order()
        self._roots_by_node: dict[str, frozenset[str]] = {}
        for node in self._order:
            if node in self.roots:
                self._roots_by_node[node] = frozenset({node})
            else:
                self._roots_by_node[node] = frozenset().union(
                    *(self._roots_by_node[f.source_id] for f in self._feeds_by_device[node])
                )

    def _upstream(self, node: str) -> list[str]:
        if node in self.roots:
            return []
        return sorted({feed.source_id for feed in self._feeds_by_device.get(node, [])})

    def _topological_order(self) -> list[str]:
        """Return nodes with every source before the devices it feeds; raise on cycles."""
        order: list[str] = []
        done: set[str] = set()
        for start in sorted(self.sources | set(self._feeds_by_device)):
            if start in done:
                continue
            path: list[str] = [start]
            on_path: set[str] = {start}
            stack: list[Iterable[str]] = [iter(self._upstream(start))]
            while stack:
                upstream = next(stack[-1], None)
                if upstream is None:
                    node = path.pop()
                    on_path.discard(node)
                    stack.pop()
                    done.add(node)
                    order.append(node)
                    continue
                if upstream in on_path:
                    raise PowerCycleError(path[path.index(upstream):] + [upstream])
                if upstream in done:
                    continue
                path.append(upstream)
                on_path.add(upstream)
                stack.append(iter(self._upstream(upstream)))
        return order

    def ups_sources(self) -> list[str]:
        """Sorted IDs used as the ``source_id`` of at least one ``ups`` feed."""
        return sorted({feed.source_id for feed in self.feeds if feed.source_type == "ups"})

    def feeds_for(self, device_id: str) -> list[PowerFeed]:
        return list(self._feeds_by_device.get(device_id, []))

    def power_roots(self, device_id: str) -> set[str]:
        if device_id not in self._roots_by_node:
            raise ValueError(f"Unknown power map ID: {device_id!r}")
        return set(self._roots_by_node[device_id])

    def blast_radius(self, source_id: str) -> BlastRadius:
        if source_id not in self.sources:
            raise ValueError(f"{source_id!r} is not a power source in this map")
        powered: dict[str, bool] = {}
        for node in self._order:
            if node == source_id:
                powered[node] = False
            elif node in self.roots:
                powered[node] = True
            else:
                powered[node] = any(
                    powered[feed.source_id] for feed in self._feeds_by_device[node]
                )
        loses_all: list[str] = []
        loses_redundancy: list[str] = []
        for device_id in self.end_devices:
            if not powered[device_id]:
                loses_all.append(device_id)
            elif any(
                not powered[feed.source_id] for feed in self._feeds_by_device[device_id]
            ):
                loses_redundancy.append(device_id)
        return BlastRadius(
            source_id=source_id,
            loses_all_power=loses_all,
            loses_redundancy=loses_redundancy,
        )


def _normalize_role(role: Optional[str]) -> str:
    if not isinstance(role, str):
        return ""
    return role.strip().lower().replace("-", "_").replace(" ", "_")


def device_criticality(site: Site, device_id: str) -> str:
    for device in site.devices:
        if device.device_id == device_id:
            return "critical" if _normalize_role(device.role) in _CRITICAL_ROLES else "standard"
    return "standard"


def find_single_fed_critical(site: Site, graph: PowerDependencyGraph) -> list[str]:
    return sorted(
        device_id
        for device_id in graph.end_devices
        if device_criticality(site, device_id) == "critical"
        and len(graph.power_roots(device_id)) == 1
    )


def find_false_redundancy(graph: PowerDependencyGraph) -> list[str]:
    ups_sources = set(graph.ups_sources())
    flagged: list[str] = []
    for device_id in graph.end_devices:
        psus = {feed.psu for feed in graph.feeds_for(device_id) if feed.psu is not None}
        roots = graph.power_roots(device_id)
        if len(psus) >= 2 and len(roots) == 1 and next(iter(roots)) in ups_sources:
            flagged.append(device_id)
    return sorted(flagged)


@dataclass
class PowerRiskEntry:
    """UPS risk score: health severity multiplied by critical devices that would go dark."""

    ups_id: str
    health_status: str
    health_unknown: bool
    severity: int
    single_fed_critical: list[str] = field(default_factory=list)
    score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ups_id": self.ups_id,
            "health_status": self.health_status,
            "health_unknown": self.health_unknown,
            "severity": self.severity,
            "single_fed_critical": list(self.single_fed_critical),
            "score": self.score,
        }


def _health_severity(record: UpsHealthRecord) -> int:
    severity = _HEALTH_SEVERITY[UpsHealthStatus(record.status)]
    if record.needs_battery_replacement is True:
        severity += 1
    if record.is_low_runtime is True:
        severity += 1
    return severity


def rank_power_risk(
    site: Site,
    ups_health_results: Iterable[UpsHealthRecord],
    graph: PowerDependencyGraph,
) -> list[PowerRiskEntry]:
    ups_ids = sorted(
        {
            item.equipment_id
            for item in site.equipment
            if item.category is EquipmentCategory.UPS
        }
    )
    # When a UPS has several health records, rank on the most severe one.
    health: dict[str, tuple[int, UpsHealthRecord]] = {}
    for record in ups_health_results:
        if record.equipment_id not in ups_ids:
            continue
        severity = _health_severity(record)
        current = health.get(record.equipment_id)
        if current is None or severity > current[0]:
            health[record.equipment_id] = (severity, record)

    sources = graph.sources
    entries: list[PowerRiskEntry] = []
    for ups_id in ups_ids:
        if ups_id in health:
            severity, record = health[ups_id]
            status = UpsHealthStatus(record.status).value
            unknown = False
        else:
            severity, status, unknown = _UNKNOWN_HEALTH_SEVERITY, "UNKNOWN", True
        critical: list[str] = []
        if ups_id in sources:
            critical = sorted(
                device_id
                for device_id in graph.blast_radius(ups_id).loses_all_power
                if device_criticality(site, device_id) == "critical"
            )
        entries.append(
            PowerRiskEntry(
                ups_id=ups_id,
                health_status=status,
                health_unknown=unknown,
                severity=severity,
                single_fed_critical=critical,
                score=severity * len(critical),
            )
        )
    entries.sort(key=lambda entry: (-entry.score, -entry.severity, entry.ups_id))
    return entries


def generate_power_json_report(site: Site, graph: PowerDependencyGraph) -> str:
    """Return a deterministic JSON power-dependency report for ``site``."""
    payload = {
        "site_id": site.site_id,
        "ups_blast_radius": [
            graph.blast_radius(ups_id).to_dict() for ups_id in graph.ups_sources()
        ],
        "single_fed_critical": find_single_fed_critical(site, graph),
        "false_redundancy": find_false_redundancy(graph),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _md_cell(value: Any) -> str:
    if value is None:
        return ""
    # Lone carriage returns also end a Markdown line, so fold them into newlines first.
    return _escape_md_cell(str(value).replace("\r\n", "\n").replace("\r", "\n"))


def _md_list(items: Iterable[str]) -> list[str]:
    lines = [f"- {_md_cell(item)}" for item in items]
    return lines or ["None"]


def generate_power_markdown_report(site: Site, graph: PowerDependencyGraph) -> str:
    """Return a deterministic Markdown power-dependency report for ``site``."""
    lines = [f"# Power Dependency Report: {_md_cell(site.site_id)}", "", "## UPS Blast Radius", ""]
    ups_ids = graph.ups_sources()
    if not ups_ids:
        lines.extend(["None", ""])
    for ups_id in ups_ids:
        radius = graph.blast_radius(ups_id)
        lines.extend([f"### UPS {_md_cell(ups_id)}", "", "Loses all power:", ""])
        lines.extend(_md_list(radius.loses_all_power))
        lines.extend(["", "Loses redundancy:", ""])
        lines.extend(_md_list(radius.loses_redundancy))
        lines.append("")
    lines.extend(["## Site Summary", "", "### Single-fed critical devices", ""])
    lines.extend(_md_list(find_single_fed_critical(site, graph)))
    lines.extend(["", "### False redundancy", ""])
    lines.extend(_md_list(find_false_redundancy(graph)))
    lines.append("")
    return "\n".join(lines)
