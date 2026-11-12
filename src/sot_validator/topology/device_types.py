"""Device type templates, catalog, and switch/router port builder for sot-validator."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import re
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    Subnet,
    _require_non_empty_str,
)

VALID_DEVICE_ROLES: tuple[str, ...] = (
    "router",
    "switch",
    "l3_switch",
    "firewall",
    "hypervisor",
    "ups",
    "nas",
)

_HEX_DIGITS = frozenset("0123456789abcdef")
_RANGE_ENDPOINT_PATTERN = re.compile(r"^(.*?)(\d+)$")
_UPDATABLE_PORT_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "admin_status",
        "oper_status",
        "poe_status",
        "vlan_id",
        "connected_device_id",
        "connected_mac",
    }
)


def normalize_mac_address(mac: str) -> str:
    """Normalize a MAC address string to lowercase colon-separated format (aa:bb:cc:dd:ee:ff)."""
    if not isinstance(mac, str) or not mac.strip():
        raise ValueError("mac_address must be a non-empty string")
    cleaned = mac.strip().lower()
    hex_only = "".join(
        ch for ch in cleaned if ch not in (":", "-", ".", " ")
    )
    if len(hex_only) != 12 or any(ch not in _HEX_DIGITS for ch in hex_only):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def _try_normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str) or not mac.strip():
        return None
    try:
        return normalize_mac_address(mac)
    except ValueError:
        return None


@dataclass
class PortSpec:
    """Template specification for a single device port."""

    name: str
    admin_status: Optional[str] = "up"
    oper_status: Optional[str] = "down"
    poe_status: Optional[str] = None
    vlan_id: Optional[str] = None

    def __post_init__(self) -> None:
        _require_non_empty_str(self.name, "name")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "admin_status": self.admin_status,
            "oper_status": self.oper_status,
            "poe_status": self.poe_status,
            "vlan_id": self.vlan_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PortSpec:
        return cls(
            name=data["name"],
            admin_status=data.get("admin_status", "up"),
            oper_status=data.get("oper_status", "down"),
            poe_status=data.get("poe_status"),
            vlan_id=data.get("vlan_id"),
        )


@dataclass
class DeviceTypeTemplate:
    """Reusable hardware/virtual device template for instantiating NetworkDevice records."""

    template_id: str
    vendor: str
    model: str
    role: str
    default_port_count: int = 0
    port_naming_pattern: str = "{n}"
    supports_poe: bool = False
    supports_vlans: bool = False
    default_vlan_id: Optional[str] = None
    default_ports: list[PortSpec] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.template_id, "template_id")
        _require_non_empty_str(self.vendor, "vendor")
        _require_non_empty_str(self.model, "model")
        _require_non_empty_str(self.role, "role")

        normalized_role = self.role.strip().lower()
        if normalized_role not in VALID_DEVICE_ROLES:
            raise ValueError(
                f"Invalid device role {self.role!r}; must be one of {VALID_DEVICE_ROLES}"
            )
        self.role = normalized_role

        if (
            isinstance(self.default_port_count, bool)
            or not isinstance(self.default_port_count, int)
            or self.default_port_count < 0
        ):
            raise ValueError("default_port_count must be a non-negative integer")

        self.default_ports = [
            p if isinstance(p, PortSpec) else PortSpec.from_dict(p)
            for p in self.default_ports
        ]

        if self.default_port_count > 0 and not self.default_ports:
            if (
                not isinstance(self.port_naming_pattern, str)
                or "{n}" not in self.port_naming_pattern
            ):
                raise ValueError(
                    "port_naming_pattern must contain '{n}' when default_port_count > 0"
                )

    def build_port_specs(
        self,
        port_count: Optional[int] = None,
        default_vlan_id: Optional[str] = None,
    ) -> list[PortSpec]:
        """Generate PortSpec items from this template."""
        resolved_vlan = (
            default_vlan_id if default_vlan_id is not None else self.default_vlan_id
        )

        if port_count is None and self.default_ports:
            return [
                PortSpec(
                    name=spec.name,
                    admin_status=spec.admin_status,
                    oper_status=spec.oper_status,
                    poe_status=spec.poe_status,
                    vlan_id=spec.vlan_id if spec.vlan_id is not None else resolved_vlan,
                )
                for spec in self.default_ports
            ]

        count = self.default_port_count if port_count is None else port_count
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("port_count must be a non-negative integer")
        if count > 0 and (
            not isinstance(self.port_naming_pattern, str)
            or "{n}" not in self.port_naming_pattern
        ):
            raise ValueError("port_naming_pattern must contain '{n}'")

        poe_default = "auto" if self.supports_poe else None
        return [
            PortSpec(
                name=self.port_naming_pattern.format(n=n),
                admin_status="up",
                oper_status="down",
                poe_status=poe_default,
                vlan_id=resolved_vlan,
            )
            for n in range(1, count + 1)
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "vendor": self.vendor,
            "model": self.model,
            "role": self.role,
            "default_port_count": self.default_port_count,
            "port_naming_pattern": self.port_naming_pattern,
            "supports_poe": self.supports_poe,
            "supports_vlans": self.supports_vlans,
            "default_vlan_id": self.default_vlan_id,
            "default_ports": [p.to_dict() for p in self.default_ports],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DeviceTypeTemplate:
        return cls(
            template_id=data["template_id"],
            vendor=data["vendor"],
            model=data["model"],
            role=data["role"],
            default_port_count=data.get("default_port_count", 0),
            port_naming_pattern=data.get("port_naming_pattern", "{n}"),
            supports_poe=bool(data.get("supports_poe", False)),
            supports_vlans=bool(data.get("supports_vlans", False)),
            default_vlan_id=data.get("default_vlan_id"),
            default_ports=[
                p if isinstance(p, PortSpec) else PortSpec.from_dict(p)
                for p in data.get("default_ports", [])
            ],
        )


BUILTIN_DEVICE_TEMPLATES: tuple[DeviceTypeTemplate, ...] = (
    DeviceTypeTemplate(
        template_id="extreme-exos-48p",
        vendor="Extreme Networks",
        model="Summit X460-G2-48p",
        role="switch",
        default_port_count=48,
        port_naming_pattern="1:{n}",
        supports_poe=True,
        supports_vlans=True,
        default_vlan_id="1",
    ),
    DeviceTypeTemplate(
        template_id="extreme-exos-24p",
        vendor="Extreme Networks",
        model="Summit X440-G2-24p",
        role="switch",
        default_port_count=24,
        port_naming_pattern="1:{n}",
        supports_poe=True,
        supports_vlans=True,
        default_vlan_id="1",
    ),
    DeviceTypeTemplate(
        template_id="extreme-voss-core",
        vendor="Extreme Networks",
        model="VSP 7400-48Y",
        role="l3_switch",
        default_port_count=48,
        port_naming_pattern="1/{n}",
        supports_poe=False,
        supports_vlans=True,
        default_vlan_id="1",
    ),
    DeviceTypeTemplate(
        template_id="unifi-multi-vlan-router",
        vendor="Ubiquiti",
        model="UniFi Gateway Enterprise",
        role="router",
        default_port_count=8,
        port_naming_pattern="eth{n}",
        supports_poe=False,
        supports_vlans=True,
    ),
    DeviceTypeTemplate(
        template_id="proxmox-ve-host",
        vendor="Proxmox",
        model="Proxmox VE Host",
        role="hypervisor",
        default_port_count=4,
        port_naming_pattern="vmbr{n}",
        supports_poe=False,
        supports_vlans=True,
    ),
    DeviceTypeTemplate(
        template_id="apc-smart-ups",
        vendor="APC",
        model="Smart-UPS SMT1500RM2U",
        role="ups",
        default_port_count=1,
        port_naming_pattern="mgmt{n}",
        supports_poe=False,
        supports_vlans=False,
    ),
    DeviceTypeTemplate(
        template_id="generic-smb-nas",
        vendor="Synology",
        model="RackStation NAS",
        role="nas",
        default_port_count=2,
        port_naming_pattern="eth{n}",
        supports_poe=False,
        supports_vlans=True,
    ),
)


class DeviceTypeCatalog:
    """Registry of built-in and custom DeviceTypeTemplate definitions."""

    def __init__(
        self,
        templates: Optional[Sequence[DeviceTypeTemplate]] = None,
        *,
        include_builtins: bool = True,
    ) -> None:
        self._templates: dict[str, DeviceTypeTemplate] = {}
        if include_builtins:
            for tpl in BUILTIN_DEVICE_TEMPLATES:
                self._templates[tpl.template_id.lower()] = tpl
        if templates:
            for tpl in templates:
                self.register(tpl, overwrite=True)

    def get(self, template_id: str) -> DeviceTypeTemplate:
        """Retrieve a template by ID (case-insensitive); raises KeyError if unknown."""
        if not isinstance(template_id, str) or not template_id.strip():
            raise KeyError(f"Unknown device template: {template_id!r}")
        key = template_id.strip().lower()
        if key not in self._templates:
            raise KeyError(f"Unknown device template: {template_id!r}")
        return self._templates[key]

    def list_templates(self, role: Optional[str] = None) -> list[DeviceTypeTemplate]:
        """Return all registered templates, optionally filtered by device role."""
        all_templates = list(self._templates.values())
        if role is None:
            return all_templates
        normalized_role = role.strip().lower()
        return [tpl for tpl in all_templates if tpl.role == normalized_role]

    def register(
        self, template: DeviceTypeTemplate, *, overwrite: bool = False
    ) -> DeviceTypeTemplate:
        """Register a custom DeviceTypeTemplate."""
        if not isinstance(template, DeviceTypeTemplate):
            raise ValueError("template must be a DeviceTypeTemplate instance")
        key = template.template_id.strip().lower()
        if key in self._templates and not overwrite:
            raise ValueError(
                f"Device template {template.template_id!r} is already registered"
            )
        self._templates[key] = template
        return template

    def instantiate_device(
        self,
        template_id: str,
        *,
        device_id: str,
        site_id: str,
        hostname: str,
        management_ip: Optional[str] = None,
        port_count: Optional[int] = None,
        default_vlan_id: Optional[str] = None,
        last_seen: Optional[datetime] = None,
    ) -> NetworkDevice:
        """Instantiate a canonical NetworkDevice populated with ports from a template."""
        template = self.get(template_id)
        port_specs = template.build_port_specs(
            port_count=port_count,
            default_vlan_id=default_vlan_id,
        )
        ports = [
            Port(
                port_id=f"{device_id}:{spec.name}",
                device_id=device_id,
                name=spec.name,
                admin_status=spec.admin_status,
                oper_status=spec.oper_status,
                poe_status=spec.poe_status,
                vlan_id=spec.vlan_id,
            )
            for spec in port_specs
        ]
        return NetworkDevice(
            device_id=device_id,
            site_id=site_id,
            hostname=hostname,
            management_ip=management_ip,
            vendor=template.vendor,
            model=template.model,
            role=template.role,
            last_seen=last_seen,
            ports=ports,
        )


class DevicePortManager:
    """Helper for adding, updating, and binding switch/router ports on a NetworkDevice."""

    def __init__(self, device: NetworkDevice) -> None:
        if not isinstance(device, NetworkDevice):
            raise ValueError("device must be a NetworkDevice instance")
        self.device = device

    def add_port(
        self,
        name: str,
        *,
        port_id: Optional[str] = None,
        admin_status: Optional[str] = "up",
        oper_status: Optional[str] = "down",
        poe_status: Optional[str] = None,
        vlan_id: Optional[str] = None,
        connected_device_id: Optional[str] = None,
        connected_mac: Optional[str] = None,
        overwrite: bool = False,
    ) -> Port:
        """Add a single Port to the managed NetworkDevice."""
        _require_non_empty_str(name, "name")
        resolved_port_id = (
            port_id if port_id is not None else f"{self.device.device_id}:{name}"
        )
        norm_mac = (
            normalize_mac_address(connected_mac)
            if connected_mac is not None
            else None
        )
        new_port = Port(
            port_id=resolved_port_id,
            device_id=self.device.device_id,
            name=name,
            admin_status=admin_status,
            oper_status=oper_status,
            poe_status=poe_status,
            connected_device_id=connected_device_id,
            connected_mac=norm_mac,
            vlan_id=vlan_id,
        )

        matching_indices = [
            idx
            for idx, existing in enumerate(self.device.ports)
            if existing.name == name or existing.port_id == resolved_port_id
        ]
        if matching_indices:
            if not overwrite:
                raise ValueError(
                    f"Port {name!r} (id={resolved_port_id!r}) already exists on device {self.device.device_id!r}"
                )
            first_idx = matching_indices[0]
            self.device.ports[first_idx] = new_port
            for idx in reversed(matching_indices[1:]):
                del self.device.ports[idx]
        else:
            self.device.ports.append(new_port)

        return new_port

    def add_port_range(
        self,
        range_spec: Optional[str] = None,
        *,
        start: Optional[int] = None,
        end: Optional[int] = None,
        naming_pattern: str = "{n}",
        admin_status: Optional[str] = "up",
        oper_status: Optional[str] = "down",
        poe_status: Optional[str] = None,
        vlan_id: Optional[str] = None,
        overwrite: bool = False,
    ) -> list[Port]:
        """Add a range of ports to the managed NetworkDevice."""
        if range_spec is not None:
            parsed_start, parsed_end, resolved_pattern = self._parse_range_spec(
                range_spec, default_pattern=naming_pattern
            )
        else:
            if (
                start is None
                or end is None
                or isinstance(start, bool)
                or isinstance(end, bool)
                or not isinstance(start, int)
                or not isinstance(end, int)
            ):
                raise ValueError(
                    "Either range_spec or integer start and end must be provided"
                )
            parsed_start = start
            parsed_end = end
            resolved_pattern = naming_pattern

        if parsed_start < 0 or parsed_start > parsed_end:
            raise ValueError(
                f"Invalid port range: start={parsed_start}, end={parsed_end}"
            )
        if not isinstance(resolved_pattern, str) or "{n}" not in resolved_pattern:
            raise ValueError("naming_pattern must contain '{n}'")

        created: list[Port] = []
        for n in range(parsed_start, parsed_end + 1):
            port_name = resolved_pattern.format(n=n)
            port = self.add_port(
                port_name,
                admin_status=admin_status,
                oper_status=oper_status,
                poe_status=poe_status,
                vlan_id=vlan_id,
                overwrite=overwrite,
            )
            created.append(port)
        return created

    @staticmethod
    def _parse_range_spec(
        range_spec: str, *, default_pattern: str = "{n}"
    ) -> tuple[int, int, str]:
        if not isinstance(range_spec, str) or not range_spec.strip():
            raise ValueError("range_spec must be a non-empty string")
        cleaned = range_spec.strip()
        if ".." in cleaned:
            parts = cleaned.split("..")
        elif "-" in cleaned:
            parts = cleaned.split("-")
        else:
            raise ValueError(f"Malformed port range specification: {range_spec!r}")

        if len(parts) != 2:
            raise ValueError(f"Malformed port range specification: {range_spec!r}")

        left, right = parts[0].strip(), parts[1].strip()
        m_left = _RANGE_ENDPOINT_PATTERN.match(left)
        m_right = _RANGE_ENDPOINT_PATTERN.match(right)
        if not m_left or not m_right:
            raise ValueError(f"Malformed port range endpoints: {range_spec!r}")

        prefix_left, start_str = m_left.group(1), m_left.group(2)
        prefix_right, end_str = m_right.group(1), m_right.group(2)
        if prefix_right and prefix_right != prefix_left:
            raise ValueError(
                f"Mismatched port range prefixes {prefix_left!r} vs {prefix_right!r}"
            )

        start_num = int(start_str)
        end_num = int(end_str)
        pattern = f"{prefix_left}{{n}}" if prefix_left else default_pattern
        return start_num, end_num, pattern

    def get_port(self, port_name_or_id: str) -> Port:
        """Find a port on the device by port.name or port.port_id; raises KeyError if missing."""
        for port in self.device.ports:
            if port.name == port_name_or_id or port.port_id == port_name_or_id:
                return port
        raise KeyError(
            f"Port {port_name_or_id!r} not found on device {self.device.device_id!r}"
        )

    def update_port(self, port_name_or_id: str, **attributes: Any) -> Port:
        """Update attributes on an existing port."""
        unknown = set(attributes) - _UPDATABLE_PORT_ATTRIBUTES
        if unknown:
            raise ValueError(
                f"Unsupported port attribute(s): {', '.join(sorted(unknown))}"
            )
        port = self.get_port(port_name_or_id)
        for attr, value in attributes.items():
            if attr == "connected_mac" and value is not None:
                value = normalize_mac_address(value)
            setattr(port, attr, value)
        return port

    def bind_mac_to_port(
        self,
        port_name_or_id: str,
        mac_address: str,
        *,
        connected_device_id: Optional[str] = None,
        vlan_id: Optional[str] = None,
        oper_status: str = "up",
    ) -> Port:
        """Bind a normalized MAC address (and optional device/VLAN) to a port."""
        port = self.get_port(port_name_or_id)
        port.connected_mac = normalize_mac_address(mac_address)
        if oper_status is not None:
            port.oper_status = oper_status
        if connected_device_id is not None:
            port.connected_device_id = connected_device_id
        if vlan_id is not None:
            port.vlan_id = vlan_id
        return port

    def bind_discovered_hosts(
        self,
        port_mac_map: Mapping[str, str],
        *,
        arp_entries: Sequence[ArpEntry] = (),
        ip_addresses: Sequence[IPAddress] = (),
        equipment: Sequence[Equipment] = (),
        devices: Sequence[NetworkDevice] = (),
        subnets: Sequence[Subnet] = (),
    ) -> list[Port]:
        """Bind discovered MAC addresses to ports and correlate against ARP, IP, Equipment, and Subnet records."""
        subnet_by_id: dict[str, Subnet] = {s.subnet_id: s for s in subnets}
        parsed_subnets: list[tuple[ipaddress._BaseNetwork, Subnet]] = []
        for s in subnets:
            try:
                parsed_subnets.append((ipaddress.ip_network(s.cidr, strict=False), s))
            except ValueError:
                continue

        updated_ports: list[Port] = []
        for port_ref, raw_mac in port_mac_map.items():
            norm_mac = normalize_mac_address(raw_mac)
            port = self.get_port(port_ref)

            matched_ips: set[str] = set()
            matched_subnet_ids: list[str] = []
            matched_assigned_ids: list[str] = []

            for entry in arp_entries:
                if _try_normalize_mac(entry.arp_mac) == norm_mac:
                    matched_ips.add(entry.ip)
                    if entry.subnet_id and entry.subnet_id not in matched_subnet_ids:
                        matched_subnet_ids.append(entry.subnet_id)

            for ip_rec in ip_addresses:
                rec_mac = _try_normalize_mac(ip_rec.arp_mac) or (
                    _try_normalize_mac(ip_rec.arp_entry.arp_mac)
                    if ip_rec.arp_entry is not None
                    else None
                )
                if rec_mac == norm_mac or ip_rec.ip in matched_ips:
                    matched_ips.add(ip_rec.ip)
                    if ip_rec.subnet_id and ip_rec.subnet_id not in matched_subnet_ids:
                        matched_subnet_ids.append(ip_rec.subnet_id)
                    if (
                        ip_rec.assigned_object_id
                        and ip_rec.assigned_object_id not in matched_assigned_ids
                    ):
                        matched_assigned_ids.append(ip_rec.assigned_object_id)

            matched_device_id: Optional[str] = None
            matched_equipment_objs: list[Equipment] = []

            for eq in equipment:
                eq_ips = {ip.strip() for ip in eq.assigned_ips if ip and ip.strip()}
                if (
                    eq.equipment_id in matched_assigned_ids
                    or bool(eq_ips & matched_ips)
                    or port.port_id in eq.connected_ports
                    or port.name in eq.connected_ports
                ):
                    matched_equipment_objs.append(eq)
                    if matched_device_id is None:
                        matched_device_id = eq.equipment_id

            if matched_device_id is None:
                for dev in devices:
                    if dev.device_id == self.device.device_id:
                        continue
                    if dev.device_id in matched_assigned_ids or (
                        dev.management_ip and dev.management_ip.strip() in matched_ips
                    ):
                        matched_device_id = dev.device_id
                        break

            if matched_device_id is None and matched_assigned_ids:
                matched_device_id = matched_assigned_ids[0]

            inferred_vlan: Optional[str] = None
            for sub_id in matched_subnet_ids:
                sub = subnet_by_id.get(sub_id)
                if sub is not None and sub.vlan_id is not None:
                    inferred_vlan = sub.vlan_id
                    break

            if inferred_vlan is None and matched_ips and parsed_subnets:
                for ip_str in matched_ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                    except ValueError:
                        continue
                    for net, sub in parsed_subnets:
                        if ip_obj in net and sub.vlan_id is not None:
                            inferred_vlan = sub.vlan_id
                            break
                    if inferred_vlan is not None:
                        break

            port.connected_mac = norm_mac
            port.oper_status = "up"
            if matched_device_id is not None:
                port.connected_device_id = matched_device_id
            if port.vlan_id is None and inferred_vlan is not None:
                port.vlan_id = inferred_vlan

            for eq in matched_equipment_objs:
                if port.port_id not in eq.connected_ports:
                    eq.connected_ports.append(port.port_id)

            updated_ports.append(port)

        return updated_ports


__all__ = [
    "BUILTIN_DEVICE_TEMPLATES",
    "DevicePortManager",
    "DeviceTypeCatalog",
    "DeviceTypeTemplate",
    "PortSpec",
    "VALID_DEVICE_ROLES",
    "normalize_mac_address",
]
