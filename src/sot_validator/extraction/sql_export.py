"""SQL dump, CSV directory, and JSON table export adapter for read-only SoT ingestion."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping, Optional, Sequence

from sot_validator.extraction.client import ReadOnlyViolationError, SoTClient
from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
)

_FORBIDDEN_SQL_PATTERN = re.compile(
    r"^\s*(DROP|DELETE|UPDATE|ALTER|TRUNCATE|REPLACE|GRANT|REVOKE|ATTACH|DETACH)\b",
    re.IGNORECASE,
)

_ALLOWED_SQL_PATTERN = re.compile(
    r"^\s*(CREATE\s+TABLE|INSERT\s+INTO|SELECT|BEGIN|COMMIT|END)\b",
    re.IGNORECASE,
)

_INSERT_WITH_COLS_PATTERN = re.compile(
    r"^\s*INSERT\s+INTO\s+[`\"']?(\w+)[`\"']?\s*\(([^)]+)\)",
    re.IGNORECASE | re.DOTALL,
)


def _strip_sql_comments(sql: str) -> str:
    """Remove `--` line comments and `/* ... */` block comments from a SQL statement."""
    no_block = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    lines = []
    for line in no_block.splitlines():
        stripped = line.strip()
        if stripped.startswith("--"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _split_sql_statements(sql_script: str) -> list[str]:
    """Split a SQL script into individual semicolon-terminated statements respecting quotes."""
    statements: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    length = len(sql_script)

    while i < length:
        ch = sql_script[i]
        if ch == "'" and not in_double:
            current.append(ch)
            if in_single and i + 1 < length and sql_script[i + 1] == "'":
                current.append(sql_script[i + 1])
                i += 2
                continue
            in_single = not in_single
        elif ch == '"' and not in_single:
            current.append(ch)
            in_double = not in_double
        elif ch == ";" and not in_single and not in_double:
            stmt = _strip_sql_comments("".join(current))
            if stmt:
                statements.append(stmt)
            current = []
        else:
            current.append(ch)
        i += 1

    trailing = _strip_sql_comments("".join(current))
    if trailing:
        statements.append(trailing)
    return statements


def _validate_read_only_sql(statements: Sequence[str]) -> None:
    """Ensure SQL dump statements contain no destructive DDL/DML operations."""
    for stmt in statements:
        if _FORBIDDEN_SQL_PATTERN.match(stmt):
            keyword = stmt.split(None, 1)[0].upper()
            raise ReadOnlyViolationError(
                f"Mutating or destructive SQL statement ({keyword}) is forbidden in read-only mode"
            )
        if not _ALLOWED_SQL_PATTERN.match(stmt):
            keyword = stmt.split(None, 1)[0].upper() if stmt.split() else "UNKNOWN"
            raise ReadOnlyViolationError(
                f"Disallowed SQL statement starting with {keyword!r} in read-only SQL ingestion"
            )


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    text = str(value).strip()
    return text if text else None


def _split_delimited_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except ValueError:
                pass
        delimiter = ";" if ";" in stripped else ","
        return [part.strip() for part in stripped.split(delimiter) if part.strip()]
    return [str(value).strip()]


def _normalize_category(raw_category: Any) -> EquipmentCategory:
    if isinstance(raw_category, EquipmentCategory):
        return raw_category
    text = _clean_optional_str(raw_category)
    if not text:
        return EquipmentCategory.OTHER
    lowered = text.lower()
    mapping = {
        "server": EquipmentCategory.SERVER,
        "physical_server": EquipmentCategory.SERVER,
        "baremetal": EquipmentCategory.SERVER,
        "san": EquipmentCategory.SAN,
        "nas": EquipmentCategory.SAN,
        "storage": EquipmentCategory.SAN,
        "ups": EquipmentCategory.UPS,
        "apc": EquipmentCategory.UPS,
        "apc_ups": EquipmentCategory.UPS,
        "vm": EquipmentCategory.VM,
        "virtual_machine": EquipmentCategory.VM,
        "windows_vm": EquipmentCategory.VM,
        "other": EquipmentCategory.OTHER,
    }
    return mapping.get(lowered, EquipmentCategory.OTHER)


def _is_existing_path(candidate: Path | str) -> Optional[Path]:
    if isinstance(candidate, Path):
        return candidate if candidate.exists() else None
    if "\n" in candidate or len(candidate) > 4096:
        return None
    try:
        path = Path(candidate)
        return path if path.exists() else None
    except OSError:
        return None


class SqlExportSoTClient(SoTClient):
    """Read-only SoT adapter ingesting SQL dumps, CSV exports, or JSON table exports."""

    def __init__(
        self,
        source: Optional[Path | str | Mapping[str, Any] | Sequence[Any]] = None,
        *,
        sql_dump: Optional[Path | str] = None,
        csv_dir: Optional[Path | str | Mapping[str, Any]] = None,
        json_source: Optional[Path | str | Mapping[str, Any] | Sequence[Any]] = None,
        tables: Optional[Mapping[str, Sequence[Mapping[str, Any]]]] = None,
    ) -> None:
        self._sites: dict[str, Site] = {}

        if tables is not None:
            self._sites = self._build_sites_from_tables(tables)
        elif sql_dump is not None:
            self._sites = self._load_from_sql_dump(sql_dump)
        elif csv_dir is not None:
            self._sites = self._load_from_csv(csv_dir)
        elif json_source is not None:
            self._sites = self._load_from_json(json_source)
        elif source is not None:
            self._sites = self._load_from_auto_source(source)
        else:
            raise ValueError(
                "SqlExportSoTClient requires one of: source, sql_dump, csv_dir, json_source, or tables"
            )

    @classmethod
    def from_sql_dump(cls, sql_source: Path | str) -> SqlExportSoTClient:
        """Construct SqlExportSoTClient from a `.sql` file path or raw SQL dump string."""
        return cls(sql_dump=sql_source)

    @classmethod
    def from_csv_dir(
        cls, csv_source: Path | str | Mapping[str, Any]
    ) -> SqlExportSoTClient:
        """Construct SqlExportSoTClient from a directory of CSV files or table->CSV mapping."""
        return cls(csv_dir=csv_source)

    @classmethod
    def from_json(
        cls, json_source: Path | str | Mapping[str, Any] | Sequence[Any]
    ) -> SqlExportSoTClient:
        """Construct SqlExportSoTClient from a JSON export file, JSON string, or parsed object."""
        return cls(json_source=json_source)

    def _load_from_auto_source(
        self, source: Path | str | Mapping[str, Any] | Sequence[Any]
    ) -> dict[str, Site]:
        if isinstance(source, (Mapping, list, tuple)):
            return self._load_from_json(source)
        existing = _is_existing_path(source)
        if existing is not None:
            if existing.is_dir():
                return self._load_from_csv(existing)
            suffix = existing.suffix.lower()
            if suffix == ".json":
                return self._load_from_json(existing)
            return self._load_from_sql_dump(existing)
        if isinstance(source, str):
            stripped = source.lstrip()
            if stripped.startswith("{") or stripped.startswith("["):
                return self._load_from_json(source)
            return self._load_from_sql_dump(source)
        raise ValueError(f"Unsupported export source: {source!r}")

    @classmethod
    def _load_from_sql_dump(cls, sql_source: Path | str) -> dict[str, Site]:
        existing = _is_existing_path(sql_source)
        if existing is not None:
            sql_text = existing.read_text(encoding="utf-8")
        elif isinstance(sql_source, Path):
            raise FileNotFoundError(f"SQL dump file not found: {sql_source}")
        else:
            sql_text = str(sql_source)

        statements = _split_sql_statements(sql_text)
        _validate_read_only_sql(statements)

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        try:
            created_tables: set[str] = set()
            for stmt in statements:
                insert_match = _INSERT_WITH_COLS_PATTERN.match(stmt)
                if insert_match:
                    table_name = insert_match.group(1)
                    if table_name.lower() not in created_tables:
                        cols_raw = insert_match.group(2)
                        cols = [
                            c.strip().strip("`\"'")
                            for c in cols_raw.split(",")
                            if c.strip()
                        ]
                        col_defs = ", ".join(f'"{col}" TEXT' for col in cols)
                        conn.execute(
                            f'CREATE TABLE IF NOT EXISTS "{table_name}" ({col_defs})'
                        )
                        created_tables.add(table_name.lower())
                conn.execute(stmt)
                if stmt.upper().lstrip().startswith("CREATE"):
                    cursor = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                    created_tables = {row["name"].lower() for row in cursor.fetchall()}

            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            table_names = [row["name"] for row in cursor.fetchall()]
            tables: dict[str, list[dict[str, Any]]] = {}
            for tname in table_names:
                rows = conn.execute(f'SELECT * FROM "{tname}"').fetchall()
                tables[tname.lower()] = [dict(r) for r in rows]
        finally:
            conn.close()

        return cls._build_sites_from_tables(tables)

    @classmethod
    def _load_from_csv(
        cls, csv_source: Path | str | Mapping[str, Any]
    ) -> dict[str, Site]:
        tables: dict[str, list[dict[str, Any]]] = {}
        if isinstance(csv_source, Mapping):
            for table_name, content_or_path in csv_source.items():
                key = table_name.lower().removesuffix(".csv")
                if isinstance(content_or_path, list):
                    tables[key] = [dict(row) for row in content_or_path]
                else:
                    existing = _is_existing_path(content_or_path)
                    csv_text = (
                        existing.read_text(encoding="utf-8")
                        if existing is not None
                        else str(content_or_path)
                    )
                    reader = csv.DictReader(io.StringIO(csv_text))
                    tables[key] = [dict(row) for row in reader]
        else:
            directory = Path(csv_source)
            if not directory.is_dir():
                raise FileNotFoundError(f"CSV export directory not found: {directory}")
            for csv_file in sorted(directory.glob("*.csv")):
                key = csv_file.stem.lower()
                with csv_file.open("r", encoding="utf-8", newline="") as handle:
                    reader = csv.DictReader(handle)
                    tables[key] = [dict(row) for row in reader]

        return cls._build_sites_from_tables(tables)

    @classmethod
    def _load_from_json(
        cls, json_source: Path | str | Mapping[str, Any] | Sequence[Any]
    ) -> dict[str, Site]:
        if isinstance(json_source, (Mapping, list, tuple)):
            data: Any = json_source
        else:
            existing = _is_existing_path(json_source)
            if existing is not None:
                raw_text = existing.read_text(encoding="utf-8")
            elif isinstance(json_source, Path):
                raise FileNotFoundError(f"JSON export file not found: {json_source}")
            else:
                raw_text = str(json_source)
            data = json.loads(raw_text)

        if isinstance(data, list):
            # List of serialized Site dicts
            sites = [
                item if isinstance(item, Site) else Site.from_dict(item)
                for item in data
            ]
            return {
                site.site_id: site
                for site in sorted(sites, key=lambda s: s.site_id)
            }

        if isinstance(data, Mapping):
            # Check if `sites` contains full hierarchical Site objects (already nested)
            table_keys = {k.lower() for k in data.keys()}
            has_separate_tables = bool(
                table_keys
                & {
                    "network_devices",
                    "devices",
                    "ports",
                    "vlans_subnets",
                    "vlans",
                    "subnets",
                    "ip_arp_entries",
                    "ip_addresses",
                    "equipment",
                }
            )
            if (
                "sites" in data
                and isinstance(data["sites"], list)
                and not has_separate_tables
                and all(
                    isinstance(s, Mapping)
                    and (
                        "devices" in s
                        or "subnets" in s
                        or "ip_addresses" in s
                        or "equipment" in s
                    )
                    for s in data["sites"]
                )
            ):
                sites = [Site.from_dict(item) for item in data["sites"]]
                return {
                    site.site_id: site
                    for site in sorted(sites, key=lambda s: s.site_id)
                }

            normalized_tables: dict[str, Sequence[Mapping[str, Any]]] = {
                k.lower(): v for k, v in data.items() if isinstance(v, Sequence)
            }
            return cls._build_sites_from_tables(normalized_tables)

        raise ValueError("Unsupported JSON export structure")

    @classmethod
    def _build_sites_from_tables(
        cls, tables: Mapping[str, Sequence[Mapping[str, Any]]]
    ) -> dict[str, Site]:
        norm_tables = {k.lower(): list(v) for k, v in tables.items()}

        raw_sites = norm_tables.get("sites", [])
        raw_devices = norm_tables.get(
            "network_devices", norm_tables.get("devices", [])
        )
        raw_ports = norm_tables.get("ports", [])
        raw_vlans_subnets = norm_tables.get("vlans_subnets", [])
        raw_vlans = norm_tables.get("vlans", [])
        raw_subnets = norm_tables.get("subnets", [])
        raw_ips = norm_tables.get(
            "ip_arp_entries", norm_tables.get("ip_addresses", [])
        )
        raw_equipment = norm_tables.get("equipment", [])

        # 1. Ports grouped by device_id
        ports_by_device: dict[str, list[Port]] = {}
        for row in raw_ports:
            port_id = _clean_optional_str(row.get("port_id"))
            device_id = _clean_optional_str(row.get("device_id"))
            name = _clean_optional_str(row.get("name") or row.get("port_name"))
            if not port_id or not device_id or not name:
                continue
            port = Port(
                port_id=port_id,
                device_id=device_id,
                name=name,
                admin_status=_clean_optional_str(row.get("admin_status")),
                oper_status=_clean_optional_str(row.get("oper_status")),
                poe_status=_clean_optional_str(row.get("poe_status")),
                connected_device_id=_clean_optional_str(
                    row.get("connected_device_id")
                    or row.get("connected_equipment_id")
                ),
                connected_mac=_clean_optional_str(row.get("connected_mac")),
                vlan_id=_clean_optional_str(row.get("vlan_id")),
            )
            ports_by_device.setdefault(device_id, []).append(port)

        # 2. Devices grouped by site_id
        devices_by_site: dict[str, list[NetworkDevice]] = {}
        for row in raw_devices:
            device_id = _clean_optional_str(row.get("device_id"))
            site_id = _clean_optional_str(row.get("site_id"))
            hostname = _clean_optional_str(row.get("hostname") or row.get("name"))
            if not device_id or not site_id or not hostname:
                continue
            nested_ports_raw = row.get("ports")
            if isinstance(nested_ports_raw, list) and nested_ports_raw:
                dev_ports = [
                    p if isinstance(p, Port) else Port.from_dict(p)
                    for p in nested_ports_raw
                ]
            else:
                dev_ports = list(ports_by_device.get(device_id, []))

            device = NetworkDevice(
                device_id=device_id,
                site_id=site_id,
                hostname=hostname,
                management_ip=_clean_optional_str(
                    row.get("management_ip") or row.get("mgmt_ip")
                ),
                vendor=_clean_optional_str(row.get("vendor")),
                model=_clean_optional_str(row.get("model")),
                role=_clean_optional_str(row.get("role")),
                last_seen=_clean_optional_str(row.get("last_seen")),
                ports=dev_ports,
            )
            devices_by_site.setdefault(site_id, []).append(device)

        # 3. VLANs and Subnets grouped by site_id
        vlans_by_site: dict[str, list[VLAN]] = {}
        subnets_by_site: dict[str, list[Subnet]] = {}
        subnet_to_site: dict[str, str] = {}

        for row in raw_vlans_subnets:
            site_id = _clean_optional_str(row.get("site_id"))
            vlan_id = _clean_optional_str(row.get("vlan_id"))
            subnet_id = _clean_optional_str(row.get("subnet_id"))
            cidr = _clean_optional_str(row.get("cidr"))
            gateway = _clean_optional_str(
                row.get("gateway") or row.get("gateway_ip")
            )
            vlan_name = _clean_optional_str(
                row.get("vlan_name") or row.get("name")
            )
            subnet_name = _clean_optional_str(
                row.get("description") or row.get("name") or row.get("vlan_name")
            )
            if not site_id:
                continue
            if vlan_id:
                vlans_by_site.setdefault(site_id, []).append(
                    VLAN(
                        vlan_id=vlan_id,
                        site_id=site_id,
                        name=vlan_name,
                        subnet_id=subnet_id,
                        cidr=cidr,
                        gateway=gateway,
                    )
                )
            if subnet_id and cidr:
                subnet_to_site[subnet_id] = site_id
                subnets_by_site.setdefault(site_id, []).append(
                    Subnet(
                        subnet_id=subnet_id,
                        site_id=site_id,
                        cidr=cidr,
                        vlan_id=vlan_id,
                        gateway=gateway,
                        name=subnet_name,
                    )
                )

        for row in raw_vlans:
            site_id = _clean_optional_str(row.get("site_id"))
            vlan_id = _clean_optional_str(row.get("vlan_id"))
            if not site_id or not vlan_id:
                continue
            vlans_by_site.setdefault(site_id, []).append(
                VLAN(
                    vlan_id=vlan_id,
                    site_id=site_id,
                    name=_clean_optional_str(
                        row.get("name") or row.get("vlan_name")
                    ),
                    subnet_id=_clean_optional_str(row.get("subnet_id")),
                    cidr=_clean_optional_str(row.get("cidr")),
                    gateway=_clean_optional_str(
                        row.get("gateway") or row.get("gateway_ip")
                    ),
                )
            )

        for row in raw_subnets:
            site_id = _clean_optional_str(row.get("site_id"))
            subnet_id = _clean_optional_str(row.get("subnet_id"))
            cidr = _clean_optional_str(row.get("cidr"))
            if not site_id or not subnet_id or not cidr:
                continue
            subnet_to_site[subnet_id] = site_id
            subnets_by_site.setdefault(site_id, []).append(
                Subnet(
                    subnet_id=subnet_id,
                    site_id=site_id,
                    cidr=cidr,
                    vlan_id=_clean_optional_str(row.get("vlan_id")),
                    gateway=_clean_optional_str(
                        row.get("gateway") or row.get("gateway_ip")
                    ),
                    name=_clean_optional_str(
                        row.get("name")
                        or row.get("description")
                        or row.get("vlan_name")
                    ),
                )
            )

        # 4. IP Addresses & ARP Entries grouped by site_id
        ips_by_site: dict[str, list[IPAddress]] = {}
        for row in raw_ips:
            ip_val = _clean_optional_str(row.get("ip") or row.get("ip_address"))
            subnet_id = _clean_optional_str(row.get("subnet_id"))
            if not ip_val or not subnet_id:
                continue
            site_id = _clean_optional_str(row.get("site_id")) or subnet_to_site.get(
                subnet_id
            )
            if not site_id:
                continue

            arp_mac = _clean_optional_str(
                row.get("arp_mac") or row.get("mac_address")
            )
            arp_last_seen = _clean_optional_str(row.get("arp_last_seen"))
            arp_source_device_id = _clean_optional_str(
                row.get("arp_source_device_id")
            )

            raw_arp_entry = row.get("arp_entry")
            if isinstance(raw_arp_entry, ArpEntry):
                arp_entry: Optional[ArpEntry] = raw_arp_entry
            elif isinstance(raw_arp_entry, Mapping):
                arp_entry = ArpEntry.from_dict(raw_arp_entry)
            elif arp_mac:
                arp_entry = ArpEntry(
                    ip=ip_val,
                    arp_mac=arp_mac,
                    arp_last_seen=arp_last_seen,
                    arp_source_device_id=arp_source_device_id,
                    subnet_id=subnet_id,
                )
            else:
                arp_entry = None

            ip_obj = IPAddress(
                ip=ip_val,
                subnet_id=subnet_id,
                assigned_object_type=_clean_optional_str(
                    row.get("assigned_object_type")
                    or row.get("assigned_target_type")
                ),
                assigned_object_id=_clean_optional_str(
                    row.get("assigned_object_id")
                    or row.get("assigned_target_id")
                ),
                arp_mac=arp_mac,
                arp_last_seen=arp_last_seen,
                arp_source_device_id=arp_source_device_id,
                arp_entry=arp_entry,
            )
            ips_by_site.setdefault(site_id, []).append(ip_obj)

        # 5. Equipment grouped by site_id
        equipment_by_site: dict[str, list[Equipment]] = {}
        for row in raw_equipment:
            equipment_id = _clean_optional_str(row.get("equipment_id"))
            site_id = _clean_optional_str(row.get("site_id"))
            name = _clean_optional_str(row.get("name") or row.get("hostname"))
            if not equipment_id or not site_id or not name:
                continue

            raw_cat = row.get("category") or row.get("equipment_type")
            category = _normalize_category(raw_cat)

            assigned_ips = _split_delimited_list(
                row.get("assigned_ips")
                if row.get("assigned_ips") is not None
                else row.get("primary_ip")
            )
            connected_ports = _split_delimited_list(
                row.get("connected_ports")
                if row.get("connected_ports") is not None
                else row.get("connected_port_id")
            )

            eq = Equipment(
                equipment_id=equipment_id,
                site_id=site_id,
                name=name,
                category=category,
                assigned_ips=assigned_ips,
                connected_ports=connected_ports,
                hypervisor_id=_clean_optional_str(
                    row.get("hypervisor_id") or row.get("vcenter_instance")
                ),
                power_state=_clean_optional_str(row.get("power_state")),
                last_seen=_clean_optional_str(row.get("last_seen")),
            )
            equipment_by_site.setdefault(site_id, []).append(eq)

        # 6. Assemble Site objects
        sites: dict[str, Site] = {}
        for row in raw_sites:
            site_id = _clean_optional_str(row.get("site_id"))
            name = _clean_optional_str(row.get("name") or row.get("site_name"))
            if not site_id or not name:
                continue

            contact_info = _clean_optional_str(row.get("contact_info"))
            if not contact_info:
                parts = [
                    _clean_optional_str(row.get("contact_name")),
                    _clean_optional_str(row.get("contact_email")),
                    _clean_optional_str(row.get("contact_phone")),
                ]
                non_empty = [p for p in parts if p]
                contact_info = " | ".join(non_empty) if non_empty else None

            rooms = _split_delimited_list(row.get("rooms"))

            site = Site(
                site_id=site_id,
                name=name,
                address=_clean_optional_str(row.get("address")),
                contact_info=contact_info,
                rooms=rooms,
                devices=devices_by_site.get(site_id, []),
                vlans=vlans_by_site.get(site_id, []),
                subnets=subnets_by_site.get(site_id, []),
                ip_addresses=ips_by_site.get(site_id, []),
                equipment=equipment_by_site.get(site_id, []),
            )
            sites[site_id] = site

        return dict(sorted(sites.items(), key=lambda kv: kv[0]))

    def list_sites(self) -> list[Site]:
        return [
            Site.from_dict(site.to_dict())
            for _, site in sorted(self._sites.items(), key=lambda kv: kv[0])
        ]

    def get_site(self, site_id: str) -> Site:
        if site_id not in self._sites:
            raise KeyError(f"Unknown site_id: {site_id!r}")
        return Site.from_dict(self._sites[site_id].to_dict())


__all__ = ["SqlExportSoTClient"]
