"""GET-only HTML scraper adapter for legacy SoT web UI pages."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
from typing import Callable, Optional
from urllib.error import HTTPError
from urllib.parse import urljoin

from sot_validator.extraction.client import (
    ReadOnlyViolationError,
    SoTClient,
    validate_read_only_request,
)
from sot_validator.extraction.guard import ReadOnlyHttpGuard
from sot_validator.extraction.sql_export import (
    _clean_optional_str,
    _normalize_category,
    _split_delimited_list,
)
from sot_validator.models import (
    ArpEntry,
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
)

_IGNORED_TAGS = frozenset({"form", "button", "input", "script", "style"})
_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)
_PLACEHOLDER_VALUES = frozenset({"", "-", "--", "n/a", "none", "null"})


def _clean_cell_value(value: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(value)
    if cleaned is None:
        return None
    if cleaned.lower() in _PLACEHOLDER_VALUES:
        return None
    return cleaned


@dataclass
class _HtmlNode:
    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[_HtmlNode] = field(default_factory=list)
    text_parts: list[str] = field(default_factory=list)

    @property
    def id(self) -> Optional[str]:
        return self.attrs.get("id")

    @property
    def classes(self) -> set[str]:
        raw = self.attrs.get("class", "")
        return {c.strip() for c in raw.split() if c.strip()}

    def text(self) -> str:
        parts: list[str] = list(self.text_parts)
        for child in self.children:
            child_text = child.text()
            if child_text:
                parts.append(child_text)
        return " ".join(p.strip() for p in parts if p.strip()).strip()

    def find_all(
        self,
        *,
        tag: Optional[str] = None,
        elem_id: Optional[str] = None,
        class_name: Optional[str] = None,
        attr_name: Optional[str] = None,
    ) -> list[_HtmlNode]:
        results: list[_HtmlNode] = []
        for child in self.children:
            matches = True
            if tag is not None and child.tag != tag.lower():
                matches = False
            if elem_id is not None and child.id != elem_id:
                matches = False
            if class_name is not None and class_name not in child.classes:
                matches = False
            if attr_name is not None and attr_name not in child.attrs:
                matches = False
            if matches:
                results.append(child)
            results.extend(
                child.find_all(
                    tag=tag,
                    elem_id=elem_id,
                    class_name=class_name,
                    attr_name=attr_name,
                )
            )
        return results

    def find_first(
        self,
        *,
        tag: Optional[str] = None,
        elem_id: Optional[str] = None,
        class_name: Optional[str] = None,
        attr_name: Optional[str] = None,
    ) -> Optional[_HtmlNode]:
        matches = self.find_all(
            tag=tag, elem_id=elem_id, class_name=class_name, attr_name=attr_name
        )
        return matches[0] if matches else None


class _SafeSoTHtmlParser(HTMLParser):
    """DOM parser that strips mutating forms, buttons, inputs, and action columns."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _HtmlNode(tag="document")
        self._stack: list[_HtmlNode] = [self.root]
        self._ignored_depth: int = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, Optional[str]]]
    ) -> None:
        tag_lower = tag.lower()
        if self._ignored_depth > 0:
            if tag_lower not in _VOID_TAGS:
                self._ignored_depth += 1
            return

        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        classes = {c.strip() for c in attr_dict.get("class", "").split() if c.strip()}

        if tag_lower in _IGNORED_TAGS or "col-ops-actions" in classes:
            if tag_lower not in _VOID_TAGS:
                self._ignored_depth = 1
            return

        node = _HtmlNode(tag=tag_lower, attrs=attr_dict)
        self._stack[-1].children.append(node)
        if tag_lower not in _VOID_TAGS:
            self._stack.append(node)

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, Optional[str]]]
    ) -> None:
        if self._ignored_depth > 0:
            return
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        classes = {c.strip() for c in attr_dict.get("class", "").split() if c.strip()}
        if tag_lower in _IGNORED_TAGS or "col-ops-actions" in classes:
            return
        node = _HtmlNode(tag=tag_lower, attrs=attr_dict)
        self._stack[-1].children.append(node)

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in _VOID_TAGS:
            return
        if self._ignored_depth > 0:
            self._ignored_depth -= 1
            return
        if len(self._stack) > 1 and self._stack[-1].tag == tag_lower:
            self._stack.pop()

    def handle_data(self, data: str) -> None:
        if self._ignored_depth > 0:
            return
        if data.strip():
            self._stack[-1].text_parts.append(data)


def _parse_html(html_text: str) -> _HtmlNode:
    parser = _SafeSoTHtmlParser()
    parser.feed(html_text)
    parser.close()
    return parser.root


def _extract_row_fields(
    row: _HtmlNode, headers: list[str]
) -> dict[str, Optional[str]]:
    """Extract key/value pairs from a `<tr>` using `data-*`, `td.col-*`, and `<th>` headers."""
    fields: dict[str, Optional[str]] = {}
    for k, v in row.attrs.items():
        if k.startswith("data-"):
            norm_key = k.removeprefix("data-").replace("-", "_")
            fields[norm_key] = _clean_cell_value(v)

    cells = [c for c in row.children if c.tag == "td"]
    for idx, cell in enumerate(cells):
        cell_text = _clean_cell_value(cell.text())
        for cls_name in cell.classes:
            if cls_name.startswith("col-"):
                norm_key = cls_name.removeprefix("col-").replace("-", "_")
                fields.setdefault(norm_key, cell_text)
        for k, v in cell.attrs.items():
            if k.startswith("data-"):
                norm_key = k.removeprefix("data-").replace("-", "_")
                fields.setdefault(norm_key, _clean_cell_value(v))
        if idx < len(headers) and headers[idx]:
            fields.setdefault(headers[idx], cell_text)

    return fields


def _extract_table_rows(table: Optional[_HtmlNode]) -> list[dict[str, Optional[str]]]:
    if table is None:
        return []
    headers: list[str] = []
    thead = table.find_first(tag="thead")
    header_parent = thead if thead is not None else table
    th_nodes = header_parent.find_all(tag="th")
    for th in th_nodes:
        if "col-ops-actions" in th.classes:
            continue
        col_key = th.attrs.get("data-col") or th.text()
        norm_col = re.sub(r"[^a-z0-9]+", "_", col_key.strip().lower()).strip("_")
        headers.append(norm_col)

    tbody = table.find_first(tag="tbody")
    row_container = tbody if tbody is not None else table
    rows = [
        tr
        for tr in row_container.find_all(tag="tr")
        if not tr.find_all(tag="th")
    ]
    return [_extract_row_fields(r, headers) for r in rows]


def _default_urllib_transport(method: str, url: str) -> str:
    validate_read_only_request(method, url)
    raw_bytes = ReadOnlyHttpGuard().request(
        method, url, headers={"User-Agent": "sot-validator/0.1 (read-only)"}, timeout=15
    )
    return raw_bytes.decode("utf-8", errors="replace")


class HtmlScraperSoTClient(SoTClient):
    """Read-only HTML scraper client that strictly enforces GET/HEAD-only requests."""

    def __init__(
        self,
        base_url: str = "https://sot.internal",
        transport: Optional[Callable[[str, str], str]] = None,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty URL string")
        self.base_url = base_url.rstrip("/")
        self._transport: Callable[[str, str], str] = (
            transport if transport is not None else _default_urllib_transport
        )

    def _resolve_url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return urljoin(self.base_url + "/", path_or_url.lstrip("/"))

    def request(self, method: str, path_or_url: str) -> str:
        """Issue a validated read-only HTTP request via the configured transport."""
        full_url = self._resolve_url(path_or_url)
        validate_read_only_request(method, full_url)
        return self._transport(method.strip().upper(), full_url)

    def fetch_page(self, path_or_url: str, *, method: str = "GET") -> str:
        """Fetch an HTML page from the legacy SoT after validating read-only constraints."""
        return self.request(method, path_or_url)

    def list_site_ids(self) -> list[str]:
        html_text = self.fetch_page("/sites")
        doc = _parse_html(html_text)
        site_ids: set[str] = set()

        for node in doc.find_all(attr_name="data-site-id"):
            sid = _clean_optional_str(node.attrs.get("data-site-id"))
            if sid:
                site_ids.add(sid)

        for link in doc.find_all(tag="a", attr_name="href"):
            href = link.attrs.get("href", "")
            match = re.search(r"/sites/([^/?#]+)$", href)
            if match:
                site_ids.add(match.group(1))

        return sorted(site_ids)

    def list_sites(self) -> list[Site]:
        html_text = self.fetch_page("/sites")
        doc = _parse_html(html_text)

        summaries: dict[str, tuple[str, Optional[str], Optional[str]]] = {}
        for node in doc.find_all(attr_name="data-site-id"):
            sid = _clean_optional_str(node.attrs.get("data-site-id"))
            if not sid:
                continue
            name = (
                _clean_optional_str(node.attrs.get("data-site-name"))
                or _clean_optional_str(node.attrs.get("data-name"))
                or _clean_optional_str(node.text())
                or sid
            )
            address = _clean_optional_str(node.attrs.get("data-address"))
            contact = _clean_optional_str(node.attrs.get("data-contact"))
            summaries[sid] = (name, address, contact)

        for link in doc.find_all(tag="a", attr_name="href"):
            href = link.attrs.get("href", "")
            match = re.search(r"/sites/([^/?#]+)$", href)
            if match:
                sid = match.group(1)
                if sid not in summaries:
                    name = _clean_optional_str(link.text()) or sid
                    summaries[sid] = (name, None, None)

        sites: list[Site] = []
        for sid in sorted(summaries.keys()):
            try:
                sites.append(self.get_site(sid))
            except (KeyError, HTTPError, OSError):
                name, address, contact = summaries[sid]
                sites.append(
                    Site(
                        site_id=sid,
                        name=name,
                        address=address,
                        contact_info=contact,
                    )
                )
        return sites

    def get_site(self, site_id: str) -> Site:
        try:
            html_text = self.fetch_page(f"/sites/{site_id}")
        except HTTPError as exc:
            if exc.code == 404:
                raise KeyError(f"Unknown site_id: {site_id!r}") from exc
            raise
        if not html_text or not html_text.strip():
            raise KeyError(f"Empty response for site_id: {site_id!r}")

        doc = _parse_html(html_text)
        overview = doc.find_first(elem_id="site-overview") or doc

        parsed_site_id = (
            _clean_optional_str(overview.attrs.get("data-site-id")) or site_id
        )
        name_node = overview.find_first(class_name="site-name") or overview.find_first(
            tag="h1"
        )
        site_name = (
            _clean_optional_str(overview.attrs.get("data-site-name"))
            or _clean_optional_str(overview.attrs.get("data-name"))
            or (_clean_optional_str(name_node.text()) if name_node else None)
            or parsed_site_id
        )

        addr_node = overview.find_first(class_name="site-address")
        address = _clean_optional_str(overview.attrs.get("data-address")) or (
            _clean_optional_str(addr_node.text()) if addr_node else None
        )

        contact_node = overview.find_first(class_name="site-contact")
        contact_info = _clean_optional_str(overview.attrs.get("data-contact")) or (
            _clean_optional_str(contact_node.text()) if contact_node else None
        )
        if not contact_info:
            contact_parts = []
            for cls_name in ("contact-name", "contact-email", "contact-phone"):
                cnode = overview.find_first(class_name=cls_name)
                if cnode and _clean_optional_str(cnode.text()):
                    contact_parts.append(_clean_optional_str(cnode.text()) or "")
            if contact_parts:
                contact_info = " | ".join(contact_parts)

        room_nodes = overview.find_all(class_name="room-item")
        if not room_nodes:
            room_list = overview.find_first(class_name="room-list")
            if room_list:
                room_nodes = room_list.find_all(tag="li")
        rooms = [
            _clean_optional_str(r.text()) or ""
            for r in room_nodes
            if _clean_optional_str(r.text())
        ]
        if not rooms and overview.attrs.get("data-rooms"):
            rooms = _split_delimited_list(overview.attrs.get("data-rooms"))

        # Parse VLANs and Subnets from table#subnets-table
        vlans: list[VLAN] = []
        subnets: list[Subnet] = []
        subnets_table = doc.find_first(elem_id="subnets-table")
        for row in _extract_table_rows(subnets_table):
            vlan_id = row.get("vlan_id") or row.get("vlan")
            subnet_id = row.get("subnet_id") or row.get("subnet")
            cidr = row.get("cidr")
            gateway = row.get("gateway") or row.get("gateway_ip")
            vlan_name = row.get("vlan_name") or row.get("name")
            subnet_name = (
                row.get("description") or row.get("name") or row.get("vlan_name")
            )
            if vlan_id:
                vlans.append(
                    VLAN(
                        vlan_id=vlan_id,
                        site_id=parsed_site_id,
                        name=vlan_name,
                        subnet_id=subnet_id,
                        cidr=cidr,
                        gateway=gateway,
                    )
                )
            if subnet_id and cidr:
                subnets.append(
                    Subnet(
                        subnet_id=subnet_id,
                        site_id=parsed_site_id,
                        cidr=cidr,
                        vlan_id=vlan_id,
                        gateway=gateway,
                        name=subnet_name,
                    )
                )

        # Parse IP and ARP records from table#ip-arp-table
        ip_addresses: list[IPAddress] = []
        ip_table = doc.find_first(elem_id="ip-arp-table")
        for row in _extract_table_rows(ip_table):
            ip_val = row.get("ip") or row.get("ip_address")
            subnet_id = row.get("subnet_id") or row.get("subnet")
            if not ip_val or not subnet_id:
                continue
            arp_mac = (
                row.get("arp_mac") or row.get("mac_address") or row.get("mac")
            )
            arp_last_seen = row.get("arp_last_seen") or row.get("last_seen")
            arp_source = (
                row.get("arp_source_device_id")
                or row.get("arp_source_device")
                or row.get("arp_source")
            )
            arp_entry = (
                ArpEntry(
                    ip=ip_val,
                    arp_mac=arp_mac,
                    arp_last_seen=arp_last_seen,
                    arp_source_device_id=arp_source,
                    subnet_id=subnet_id,
                )
                if arp_mac
                else None
            )
            ip_addresses.append(
                IPAddress(
                    ip=ip_val,
                    subnet_id=subnet_id,
                    assigned_object_type=row.get("assigned_object_type")
                    or row.get("assigned_target_type")
                    or row.get("assigned_type"),
                    assigned_object_id=row.get("assigned_object_id")
                    or row.get("assigned_target_id")
                    or row.get("assigned_id"),
                    arp_mac=arp_mac,
                    arp_last_seen=arp_last_seen,
                    arp_source_device_id=arp_source,
                    arp_entry=arp_entry,
                )
            )

        # Parse Equipment from table#equipment-table
        equipment: list[Equipment] = []
        eq_table = doc.find_first(elem_id="equipment-table")
        for row in _extract_table_rows(eq_table):
            eq_id = row.get("equipment_id") or row.get("id")
            eq_name = row.get("name") or row.get("hostname")
            if not eq_id or not eq_name:
                continue
            category = _normalize_category(
                row.get("category")
                or row.get("equipment_type")
                or row.get("type")
            )
            assigned_ips = _split_delimited_list(
                row.get("assigned_ips")
                or row.get("primary_ip")
                or row.get("ip")
            )
            connected_ports = _split_delimited_list(
                row.get("connected_ports")
                or row.get("connected_port_id")
                or row.get("port")
            )
            equipment.append(
                Equipment(
                    equipment_id=eq_id,
                    site_id=parsed_site_id,
                    name=eq_name,
                    category=category,
                    assigned_ips=assigned_ips,
                    connected_ports=connected_ports,
                    hypervisor_id=row.get("hypervisor_id")
                    or row.get("vcenter_instance")
                    or row.get("hypervisor")
                    or row.get("vcenter"),
                    power_state=row.get("power_state"),
                    last_seen=row.get("last_seen"),
                )
            )

        # Discover linked devices on site page and scrape each device detail page
        device_ids: list[str] = []
        inline_device_rows: dict[str, dict[str, Optional[str]]] = {}

        devices_table = doc.find_first(elem_id="devices-table")
        for row in _extract_table_rows(devices_table):
            did = row.get("device_id") or row.get("id")
            if did and did not in inline_device_rows:
                inline_device_rows[did] = row
                device_ids.append(did)

        for node in doc.find_all(attr_name="data-device-id"):
            did = _clean_optional_str(node.attrs.get("data-device-id"))
            if did and did not in device_ids:
                device_ids.append(did)

        for link in doc.find_all(tag="a", attr_name="href"):
            href = link.attrs.get("href", "")
            match = re.search(
                rf"/sites/{re.escape(parsed_site_id)}/devices/([^/?#]+)$", href
            )
            if not match:
                match = re.search(r"/devices/([^/?#]+)$", href)
            if match:
                did = match.group(1)
                if did not in device_ids:
                    device_ids.append(did)

        devices: list[NetworkDevice] = []
        for did in device_ids:
            try:
                devices.append(self.get_device_detail(parsed_site_id, did))
            except (KeyError, HTTPError, OSError):
                row = inline_device_rows.get(did, {})
                hostname = row.get("hostname") or row.get("name") or did
                devices.append(
                    NetworkDevice(
                        device_id=did,
                        site_id=parsed_site_id,
                        hostname=hostname,
                        management_ip=row.get("management_ip")
                        or row.get("mgmt_ip"),
                        vendor=row.get("vendor"),
                        model=row.get("model"),
                        role=row.get("role"),
                        last_seen=row.get("last_seen"),
                        ports=[],
                    )
                )

        return Site(
            site_id=parsed_site_id,
            name=site_name,
            address=address,
            contact_info=contact_info,
            rooms=rooms,
            devices=devices,
            vlans=vlans,
            subnets=subnets,
            ip_addresses=ip_addresses,
            equipment=equipment,
        )

    def get_device_detail(self, site_id: str, device_id: str) -> NetworkDevice:
        """Scrape a single device detail page (`/sites/{site_id}/devices/{device_id}`)."""
        html_text = self.fetch_page(f"/sites/{site_id}/devices/{device_id}")
        if not html_text or not html_text.strip():
            raise KeyError(
                f"Empty device detail page for site_id={site_id!r}, device_id={device_id!r}"
            )
        doc = _parse_html(html_text)
        detail = doc.find_first(elem_id="device-detail") or doc

        parsed_device_id = (
            _clean_optional_str(detail.attrs.get("data-device-id")) or device_id
        )
        parsed_site_id = (
            _clean_optional_str(detail.attrs.get("data-site-id")) or site_id
        )

        host_node = detail.find_first(
            class_name="device-hostname"
        ) or detail.find_first(tag="h1")
        hostname = (
            _clean_optional_str(detail.attrs.get("data-hostname"))
            or (_clean_optional_str(host_node.text()) if host_node else None)
            or parsed_device_id
        )

        mgmt_node = detail.find_first(class_name="device-mgmt-ip")
        management_ip = (
            _clean_optional_str(detail.attrs.get("data-mgmt-ip"))
            or _clean_optional_str(detail.attrs.get("data-management-ip"))
            or (_clean_optional_str(mgmt_node.text()) if mgmt_node else None)
        )

        vendor_node = detail.find_first(class_name="device-vendor")
        vendor = _clean_optional_str(detail.attrs.get("data-vendor")) or (
            _clean_optional_str(vendor_node.text()) if vendor_node else None
        )

        model_node = detail.find_first(class_name="device-model")
        model = _clean_optional_str(detail.attrs.get("data-model")) or (
            _clean_optional_str(model_node.text()) if model_node else None
        )

        role_node = detail.find_first(class_name="device-role")
        role = _clean_optional_str(detail.attrs.get("data-role")) or (
            _clean_optional_str(role_node.text()) if role_node else None
        )

        seen_node = detail.find_first(class_name="device-last-seen")
        last_seen = _clean_optional_str(detail.attrs.get("data-last-seen")) or (
            _clean_optional_str(seen_node.text()) if seen_node else None
        )

        ports: list[Port] = []
        ports_table = doc.find_first(elem_id="ports-table")
        for row in _extract_table_rows(ports_table):
            port_id = row.get("port_id") or row.get("id")
            port_name = row.get("port_name") or row.get("name")
            if not port_id or not port_name:
                continue
            ports.append(
                Port(
                    port_id=port_id,
                    device_id=parsed_device_id,
                    name=port_name,
                    admin_status=row.get("admin_status"),
                    oper_status=row.get("oper_status"),
                    poe_status=row.get("poe_status"),
                    connected_device_id=row.get("connected_device_id")
                    or row.get("connected_equipment_id")
                    or row.get("connected_device"),
                    connected_mac=row.get("connected_mac") or row.get("mac"),
                    vlan_id=row.get("vlan_id") or row.get("vlan"),
                )
            )

        return NetworkDevice(
            device_id=parsed_device_id,
            site_id=parsed_site_id,
            hostname=hostname,
            management_ip=management_ip,
            vendor=vendor,
            model=model,
            role=role,
            last_seen=last_seen,
            ports=ports,
        )


__all__ = ["HtmlScraperSoTClient"]
