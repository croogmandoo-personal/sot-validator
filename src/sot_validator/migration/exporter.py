"""Validated Golden Inventory Exporter for NetBox and Nautobot bulk migration."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import csv
from datetime import datetime, timezone
import io
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Literal, Optional

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
    ValidationClassification,
    ValidationResult,
    _format_optional_datetime,
    _parse_optional_datetime,
)
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    DiscrepancyType,
    ReconciliationReport,
    _extract_detail_kv,
    _infer_subnet_id,
    _short_hostname,
)

TargetPlatform = Literal["netbox", "nautobot"]

SUPPORTED_TARGET_PLATFORMS: frozenset[str] = frozenset({"netbox", "nautobot"})

ENTITY_COLLECTION_KEYS: tuple[str, ...] = (
    "sites",
    "vlans",
    "prefixes",
    "devices",
    "interfaces",
    "ip_addresses",
    "virtual_machines",
)

CSV_COLUMNS_BY_ENTITY: dict[str, tuple[str, ...]] = {
    "sites": (
        "name",
        "slug",
        "status",
        "physical_address",
        "contact_name",
        "contact_email",
        "legacy_sot_id",
    ),
    "vlans": (
        "vid",
        "name",
        "slug",
        "site",
        "status",
        "legacy_sot_id",
    ),
    "prefixes": (
        "prefix",
        "slug",
        "site",
        "vlan",
        "status",
        "description",
        "legacy_sot_id",
    ),
    "devices": (
        "name",
        "slug",
        "manufacturer",
        "role",
        "device_type",
        "site",
        "status",
        "legacy_sot_id",
    ),
    "interfaces": (
        "name",
        "slug",
        "device",
        "enabled",
        "poe_mode",
        "description",
        "untagged_vlan",
        "legacy_sot_id",
    ),
    "ip_addresses": (
        "address",
        "slug",
        "site",
        "status",
        "dns_name",
        "assigned_object",
        "legacy_sot_id",
    ),
    "virtual_machines": (
        "name",
        "slug",
        "site",
        "cluster",
        "status",
        "vcpus",
        "memory",
        "os_family",
        "legacy_sot_id",
    ),
}

_LINUX_NAME_INDICATORS: tuple[str, ...] = (
    "linux",
    "lin-",
    "ubuntu",
    "rhel",
    "centos",
    "debian",
)


def slugify(value: str) -> str:
    """Convert an arbitrary string into a deterministic URL-safe lowercase slug."""
    if value is None:
        return "item"
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(value).strip().lower()).strip("-")
    return cleaned or "item"


def _resolve_timestamp(value: Optional[datetime | str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = _parse_optional_datetime(value, "generated_at")
    assert parsed is not None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _strip_ip_mask(raw_ip: Optional[str]) -> str:
    if not raw_ip:
        return ""
    return str(raw_ip).strip().split("/", 1)[0].strip()


def _parse_vlan_vid(raw_vlan_id: Optional[str | int], *, fallback: Optional[int] = 1) -> Optional[int]:
    if raw_vlan_id is None:
        return fallback
    if isinstance(raw_vlan_id, int) and not isinstance(raw_vlan_id, bool):
        return raw_vlan_id if 1 <= raw_vlan_id <= 4094 else fallback
    text = str(raw_vlan_id).strip()
    if not text:
        return fallback
    if text.isdigit():
        vid = int(text)
        return vid if 1 <= vid <= 4094 else fallback
    match = re.search(r"(\d+)$", text)
    if match:
        vid = int(match.group(1))
        if 1 <= vid <= 4094:
            return vid
    return fallback


def _parse_contact_info(contact_info: Optional[str]) -> tuple[str, str]:
    """Extract (contact_name, contact_email) from a pipe-delimited or freeform contact string."""
    if not contact_info or not contact_info.strip():
        return "", ""

    raw = contact_info.strip()
    email_match = re.search(r"[^\s|<>;,]+@[^\s|<>;,]+", raw)
    contact_email = email_match.group(0).strip() if email_match else ""

    segments = [seg.strip() for seg in raw.split("|") if seg.strip()]
    contact_name = ""
    for seg in segments:
        without_angle = re.sub(r"<[^>]*>", "", seg).strip()
        if "@" in without_angle:
            continue
        if re.fullmatch(r"[+\d\s().-]+", without_angle):
            continue
        if without_angle:
            contact_name = without_angle
            break

    return contact_name, contact_email


def _infer_equipment_manufacturer_and_model(equipment: Equipment) -> tuple[str, str]:
    name_lower = equipment.name.lower()
    category = equipment.category

    explicit_vendor = getattr(equipment, "vendor", None)
    explicit_model = getattr(equipment, "model", None)

    if category is EquipmentCategory.UPS or "apc" in name_lower or "smart-ups" in name_lower:
        manufacturer = explicit_vendor or "APC"
        model = explicit_model or "Smart-UPS"
        return manufacturer, model

    if category is EquipmentCategory.SAN or "netapp" in name_lower or "san" in name_lower:
        if "synology" in name_lower or "nas" in name_lower:
            manufacturer = explicit_vendor or "Synology"
        else:
            manufacturer = explicit_vendor or "NetApp"
        model = explicit_model or "Storage Array"
        return manufacturer, model

    if "synology" in name_lower or "nas" in name_lower:
        return explicit_vendor or "Synology", explicit_model or "Storage Array"

    if "hp" in name_lower or "proliant" in name_lower:
        return explicit_vendor or "HP", explicit_model or "PowerEdge Server"

    if "extreme" in name_lower:
        return explicit_vendor or "Extreme Networks", explicit_model or "ExtremeSwitching"

    if category is EquipmentCategory.SERVER:
        return explicit_vendor or "Dell", explicit_model or "PowerEdge Server"

    return explicit_vendor or "Generic", explicit_model or "Generic Appliance"


def _infer_vm_os_family(vm_name: str, details: Optional[str] = None) -> str:
    combined = f"{vm_name} {details or ''}".lower()
    if any(token in combined for token in _LINUX_NAME_INDICATORS):
        return "linux"
    return "windows"


def _normalize_sites_input(
    sites: Optional[Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site],
) -> list[Site]:
    if sites is None:
        return []
    if isinstance(sites, Site):
        return [sites]
    if isinstance(sites, Mapping):
        if "site_id" in sites and "name" in sites:
            return [Site.from_dict(sites)]
        if "sites" in sites and isinstance(sites["sites"], Sequence):
            return [
                s if isinstance(s, Site) else Site.from_dict(s)
                for s in sites["sites"]
            ]
        normalized: list[Site] = []
        for val in sites.values():
            if isinstance(val, Site):
                normalized.append(val)
            elif isinstance(val, Mapping) and "site_id" in val:
                normalized.append(Site.from_dict(val))
        return sorted(normalized, key=lambda s: s.site_id)

    return [s if isinstance(s, Site) else Site.from_dict(s) for s in sites]


def _normalize_validation_results(
    validation_results: Optional[
        Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
    ],
) -> list[ValidationResult]:
    if validation_results is None:
        return []
    if isinstance(validation_results, Mapping):
        if "results" in validation_results and isinstance(
            validation_results["results"], Sequence
        ):
            raw_list = validation_results["results"]
            return [
                r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
                for r in raw_list
            ]
        if "item_id" in validation_results and "classification" in validation_results:
            return [ValidationResult.from_dict(validation_results)]
        results: list[ValidationResult] = []
        for key, val in validation_results.items():
            if isinstance(val, ValidationResult):
                results.append(val)
            elif isinstance(val, Mapping) and "classification" in val:
                item_dict = dict(val)
                item_dict.setdefault("item_id", str(key))
                item_dict.setdefault("item_type", "Equipment")
                item_dict.setdefault("site_id", "unknown")
                item_dict.setdefault("name", str(key))
                results.append(ValidationResult.from_dict(item_dict))
        return results

    return [
        r if isinstance(r, ValidationResult) else ValidationResult.from_dict(r)
        for r in validation_results
    ]


def _normalize_discrepancies(
    reconciliation_report: Optional[
        ReconciliationReport
        | Sequence[DiscrepancyRecord | Mapping[str, Any]]
        | Mapping[str, Any]
    ],
) -> list[DiscrepancyRecord]:
    if reconciliation_report is None:
        return []
    if isinstance(reconciliation_report, ReconciliationReport):
        return list(reconciliation_report.discrepancies)
    if isinstance(reconciliation_report, Mapping):
        if "discrepancies" in reconciliation_report and isinstance(
            reconciliation_report["discrepancies"], Sequence
        ):
            return [
                d
                if isinstance(d, DiscrepancyRecord)
                else DiscrepancyRecord.from_dict(d)
                for d in reconciliation_report["discrepancies"]
            ]
        if "discrepancy_id" in reconciliation_report:
            return [DiscrepancyRecord.from_dict(reconciliation_report)]
        return []
    return [
        d if isinstance(d, DiscrepancyRecord) else DiscrepancyRecord.from_dict(d)
        for d in reconciliation_report
    ]


class GoldenInventoryFilter:
    """Filters Site inventory to Confirmed Active records and merges verified untracked assets."""

    def __init__(
        self,
        include_stale: bool = False,
        include_unreachable: bool = False,
        include_insufficient_data: bool = False,
        merge_untracked: bool = True,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
    ) -> None:
        self.include_stale = bool(include_stale)
        self.include_unreachable = bool(include_unreachable)
        self.include_insufficient_data = bool(include_insufficient_data)
        self.merge_untracked = bool(merge_untracked)
        self.approved_discrepancy_ids: Optional[set[str]] = (
            {str(item).strip() for item in approved_discrepancy_ids if str(item).strip()}
            if approved_discrepancy_ids is not None
            else None
        )
        self._stale_item_keys: set[tuple[str, str]] = set()

    @property
    def allowed_classifications(self) -> set[ValidationClassification]:
        allowed = {ValidationClassification.CONFIRMED_ACTIVE}
        if self.include_stale:
            allowed.add(ValidationClassification.STALE_LIKELY_UNUSED)
        if self.include_unreachable:
            allowed.add(ValidationClassification.UNREACHABLE_NEEDS_REVIEW)
        if self.include_insufficient_data:
            allowed.add(ValidationClassification.INSUFFICIENT_DATA)
        return allowed

    def is_stale(self, site_id: str, item_id: str) -> bool:
        """Return True if (site_id, item_id) was retained via include_stale=True."""
        return (
            (site_id, item_id) in self._stale_item_keys
            or ("*", item_id) in self._stale_item_keys
        )

    def _is_discrepancy_approved(
        self,
        disc: DiscrepancyRecord,
        override_approved_ids: Optional[set[str]] = None,
    ) -> bool:
        approved_set = (
            override_approved_ids
            if override_approved_ids is not None
            else self.approved_discrepancy_ids
        )
        if approved_set is None:
            return True
        candidates = {
            disc.discrepancy_id,
            disc.observed_identifier,
        }
        if disc.observed_ip:
            candidates.add(disc.observed_ip)
        if disc.observed_hostname:
            candidates.add(disc.observed_hostname)
        return bool(candidates & approved_set)

    @staticmethod
    def _match_subnet_for_ip(site: Site, ip_str: Optional[str], hint: Optional[str] = None) -> str:
        if hint and hint.strip():
            return hint.strip()
        clean_ip = _strip_ip_mask(ip_str)
        if clean_ip:
            try:
                addr = ipaddress.ip_address(clean_ip)
                for subnet in site.subnets:
                    try:
                        net = ipaddress.ip_network(subnet.cidr.strip(), strict=False)
                        if addr in net:
                            return subnet.subnet_id
                    except ValueError:
                        continue
            except ValueError:
                pass
        if site.subnets:
            return site.subnets[0].subnet_id
        return _infer_subnet_id(site.site_id, clean_ip, hint)

    def filter_site(
        self,
        site: Site | Mapping[str, Any],
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        *,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
    ) -> Site:
        """Return a filtered Site copy containing only validated active records and merged untracked assets."""
        site_obj = site if isinstance(site, Site) else Site.from_dict(site)
        norm_results = _normalize_validation_results(validation_results)
        norm_discs = _normalize_discrepancies(reconciliation_report)
        override_approved: Optional[set[str]] = (
            {str(x).strip() for x in approved_discrepancy_ids if str(x).strip()}
            if approved_discrepancy_ids is not None
            else None
        )

        # Index classifications for this site (or global wildcard)
        self._stale_item_keys = {
            k for k in self._stale_item_keys if k[0] != site_obj.site_id
        }
        classification_by_id: dict[str, ValidationClassification] = {}
        for res in norm_results:
            if res.site_id not in (site_obj.site_id, "unknown", "*"):
                continue
            classification_by_id[res.item_id] = res.classification
            stripped_ip = _strip_ip_mask(res.item_id)
            if stripped_ip:
                classification_by_id.setdefault(stripped_ip, res.classification)
            if res.name:
                classification_by_id.setdefault(res.name, res.classification)

        allowed = self.allowed_classifications

        retained_devices: list[NetworkDevice] = []
        retained_device_ids: set[str] = set()
        excluded_object_ids: set[str] = set()
        excluded_ips: set[str] = set()
        stale_object_ids: set[str] = set()

        for dev in site_obj.devices:
            cls = classification_by_id.get(dev.device_id) or classification_by_id.get(
                dev.hostname
            )
            if cls is not None and cls not in allowed:
                excluded_object_ids.add(dev.device_id)
                if dev.management_ip:
                    excluded_ips.add(_strip_ip_mask(dev.management_ip))
                continue
            if cls is ValidationClassification.STALE_LIKELY_UNUSED:
                self._stale_item_keys.add((site_obj.site_id, dev.device_id))
                self._stale_item_keys.add((site_obj.site_id, dev.hostname))
                stale_object_ids.add(dev.device_id)
            retained_device_ids.add(dev.device_id)
            retained_devices.append(NetworkDevice.from_dict(dev.to_dict()))

        retained_equipment: list[Equipment] = []
        retained_equipment_ids: set[str] = set()

        for eq in site_obj.equipment:
            cls = classification_by_id.get(eq.equipment_id) or classification_by_id.get(
                eq.name
            )
            if cls is not None and cls not in allowed:
                excluded_object_ids.add(eq.equipment_id)
                for raw_ip in eq.assigned_ips:
                    excluded_ips.add(_strip_ip_mask(raw_ip))
                continue
            if cls is ValidationClassification.STALE_LIKELY_UNUSED:
                self._stale_item_keys.add((site_obj.site_id, eq.equipment_id))
                self._stale_item_keys.add((site_obj.site_id, eq.name))
                stale_object_ids.add(eq.equipment_id)
            retained_equipment_ids.add(eq.equipment_id)
            retained_equipment.append(Equipment.from_dict(eq.to_dict()))

        valid_connected_ids = retained_device_ids | retained_equipment_ids
        for dev in retained_devices:
            cleaned_ports: list[Port] = []
            for port in dev.ports:
                port_copy = Port.from_dict(port.to_dict())
                if (
                    port_copy.connected_device_id
                    and port_copy.connected_device_id in excluded_object_ids
                    and port_copy.connected_device_id not in valid_connected_ids
                ):
                    port_copy.connected_device_id = None
                cleaned_ports.append(port_copy)
            dev.ports = cleaned_ports

        retained_object_ips: set[str] = set()
        for dev in retained_devices:
            if dev.management_ip:
                retained_object_ips.add(_strip_ip_mask(dev.management_ip))
        for eq in retained_equipment:
            for raw_ip in eq.assigned_ips:
                retained_object_ips.add(_strip_ip_mask(raw_ip))

        retained_ips: list[IPAddress] = []
        existing_ip_set: set[str] = set()

        for ip_rec in site_obj.ip_addresses:
            clean_ip = _strip_ip_mask(ip_rec.ip)
            cls = classification_by_id.get(ip_rec.ip) or classification_by_id.get(
                clean_ip
            )
            if cls is not None:
                if cls not in allowed:
                    continue
                if cls is ValidationClassification.STALE_LIKELY_UNUSED:
                    self._stale_item_keys.add((site_obj.site_id, ip_rec.ip))
                    self._stale_item_keys.add((site_obj.site_id, clean_ip))
            else:
                if (
                    ip_rec.assigned_object_id
                    and ip_rec.assigned_object_id in excluded_object_ids
                ):
                    continue
                if clean_ip in excluded_ips and clean_ip not in retained_object_ips:
                    continue
                if (
                    ip_rec.assigned_object_id
                    and ip_rec.assigned_object_id in stale_object_ids
                ):
                    self._stale_item_keys.add((site_obj.site_id, ip_rec.ip))
                    self._stale_item_keys.add((site_obj.site_id, clean_ip))

            retained_ips.append(IPAddress.from_dict(ip_rec.to_dict()))
            existing_ip_set.add(clean_ip)

        filtered_site = Site(
            site_id=site_obj.site_id,
            name=site_obj.name,
            address=site_obj.address,
            contact_info=site_obj.contact_info,
            rooms=list(site_obj.rooms),
            devices=retained_devices,
            vlans=[VLAN.from_dict(v.to_dict()) for v in site_obj.vlans],
            subnets=[Subnet.from_dict(s.to_dict()) for s in site_obj.subnets],
            ip_addresses=retained_ips,
            equipment=retained_equipment,
        )

        if self.merge_untracked and norm_discs:
            self._merge_site_discrepancies(
                filtered_site,
                norm_discs,
                existing_ip_set=existing_ip_set,
                override_approved_ids=override_approved,
            )

        return filtered_site

    def _merge_site_discrepancies(
        self,
        site: Site,
        discrepancies: Sequence[DiscrepancyRecord],
        *,
        existing_ip_set: set[str],
        override_approved_ids: Optional[set[str]] = None,
    ) -> None:
        existing_dev_ids = {d.device_id for d in site.devices}
        existing_dev_names = {d.hostname.lower() for d in site.devices}
        existing_eq_ids = {e.equipment_id for e in site.equipment}
        existing_eq_names = {e.name.lower() for e in site.equipment}

        for disc in discrepancies:
            if disc.site_id != site.site_id:
                continue
            if disc.discrepancy_type is DiscrepancyType.ATTRIBUTE_MISMATCH:
                continue
            if not self._is_discrepancy_approved(disc, override_approved_ids):
                continue

            kv = _extract_detail_kv(disc.details)

            if disc.discrepancy_type is DiscrepancyType.UNTRACKED_VM:
                hostname = disc.observed_hostname or disc.observed_identifier
                short_host = _short_hostname(hostname) or disc.observed_identifier
                eq_id = (
                    kv.get("item_id")
                    or f"eq-{slugify(site.site_id)}-vm-{slugify(short_host)}"
                )
                vcenter_inst = kv.get("vcenter_instance")
                vm_moref = kv.get("vm_moref") or (
                    disc.observed_identifier
                    if disc.observed_identifier.lower().startswith("vm-")
                    else None
                )
                bios_uuid = kv.get("bios_uuid")
                if vcenter_inst and vm_moref:
                    hypervisor_id = f"{vcenter_inst}:{vm_moref}"
                elif vcenter_inst:
                    hypervisor_id = vcenter_inst
                elif vm_moref:
                    hypervisor_id = f"vcenter-default:{vm_moref}"
                elif bios_uuid:
                    hypervisor_id = bios_uuid
                else:
                    hypervisor_id = disc.observed_identifier

                clean_ip = _strip_ip_mask(disc.observed_ip)
                if (
                    eq_id not in existing_eq_ids
                    and hostname.lower() not in existing_eq_names
                ):
                    vm_eq = Equipment(
                        equipment_id=eq_id,
                        site_id=site.site_id,
                        name=hostname,
                        category=EquipmentCategory.VM,
                        assigned_ips=[clean_ip] if clean_ip else [],
                        connected_ports=[],
                        hypervisor_id=hypervisor_id,
                        power_state="poweredOn",
                    )
                    site.equipment.append(vm_eq)
                    existing_eq_ids.add(eq_id)
                    existing_eq_names.add(hostname.lower())

                if clean_ip and clean_ip not in existing_ip_set:
                    subnet_id = self._match_subnet_for_ip(
                        site, clean_ip, kv.get("subnet_id")
                    )
                    site.ip_addresses.append(
                        IPAddress(
                            ip=clean_ip,
                            subnet_id=subnet_id,
                            assigned_object_type="equipment",
                            assigned_object_id=eq_id,
                            arp_mac=disc.observed_mac,
                        )
                    )
                    existing_ip_set.add(clean_ip)

            elif disc.discrepancy_type is DiscrepancyType.UNTRACKED_DEVICE:
                hostname = disc.observed_hostname or disc.observed_identifier
                short_host = _short_hostname(hostname) or disc.observed_identifier
                details_lower = f"{disc.details or ''} {hostname}".lower()

                if "vendor" in kv:
                    vendor = kv["vendor"].replace("_", " ")
                elif "extreme" in details_lower:
                    vendor = "Extreme Networks"
                elif "apc" in details_lower or "smart-ups" in details_lower or "ups" in details_lower:
                    vendor = "APC"
                else:
                    vendor = "Extreme Networks"

                if "model" in kv:
                    model = kv["model"].replace("_", " ")
                elif vendor == "Extreme Networks":
                    model_match = re.search(r"\(([^)]+)\)", disc.details or "")
                    model = (
                        f"ExtremeSwitching {model_match.group(1)}"
                        if model_match
                        else "ExtremeSwitching"
                    )
                elif vendor == "APC":
                    model = "Smart-UPS"
                else:
                    model = "Generic Device"

                if "role" in kv:
                    role = kv["role"]
                elif vendor == "APC":
                    role = "ups"
                else:
                    role = "access-switch"

                dev_id = (
                    kv.get("item_id")
                    or f"dev-{slugify(site.site_id)}-{slugify(short_host)}"
                )
                clean_ip = _strip_ip_mask(disc.observed_ip) or (
                    _strip_ip_mask(disc.observed_identifier)
                    if disc.observed_identifier and disc.observed_identifier[0].isdigit()
                    else ""
                )

                if (
                    dev_id not in existing_dev_ids
                    and hostname.lower() not in existing_dev_names
                    and hostname.lower() not in existing_eq_names
                ):
                    new_dev = NetworkDevice(
                        device_id=dev_id,
                        site_id=site.site_id,
                        hostname=hostname,
                        management_ip=clean_ip or None,
                        vendor=vendor,
                        model=model,
                        role=role,
                        ports=[],
                    )
                    site.devices.append(new_dev)
                    existing_dev_ids.add(dev_id)
                    existing_dev_names.add(hostname.lower())

                if clean_ip and clean_ip not in existing_ip_set:
                    subnet_id = self._match_subnet_for_ip(
                        site, clean_ip, kv.get("subnet_id")
                    )
                    site.ip_addresses.append(
                        IPAddress(
                            ip=clean_ip,
                            subnet_id=subnet_id,
                            assigned_object_type="network_device",
                            assigned_object_id=dev_id,
                            arp_mac=disc.observed_mac,
                        )
                    )
                    existing_ip_set.add(clean_ip)

            elif disc.discrepancy_type is DiscrepancyType.UNTRACKED_IP:
                clean_ip = _strip_ip_mask(disc.observed_ip or disc.observed_identifier)
                if clean_ip and clean_ip not in existing_ip_set:
                    subnet_id = self._match_subnet_for_ip(
                        site, clean_ip, kv.get("subnet_id")
                    )
                    site.ip_addresses.append(
                        IPAddress(
                            ip=clean_ip,
                            subnet_id=subnet_id,
                            assigned_object_type=kv.get("target_type"),
                            assigned_object_id=kv.get("target_id") or disc.observed_hostname,
                            arp_mac=disc.observed_mac,
                            arp_source_device_id=kv.get("arp_source_device_id"),
                        )
                    )
                    existing_ip_set.add(clean_ip)

    def filter_sites(
        self,
        sites: Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        *,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
    ) -> list[Site]:
        """Filter a sequence or mapping of sites and return sorted filtered Site records."""
        norm_sites = _normalize_sites_input(sites)
        filtered = [
            self.filter_site(
                s,
                validation_results=validation_results,
                reconciliation_report=reconciliation_report,
                approved_discrepancy_ids=approved_discrepancy_ids,
            )
            for s in norm_sites
        ]
        return sorted(filtered, key=lambda s: slugify(s.site_id))


class ModernSoTExporter:
    """Exports validated golden inventory into normalized NetBox or Nautobot JSON and CSV bundles."""

    def __init__(
        self,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        *,
        target_platform: str = "netbox",
        inventory_filter: Optional[GoldenInventoryFilter] = None,
        include_stale: bool = False,
        merge_untracked: bool = True,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> None:
        if not isinstance(target_platform, str):
            raise ValueError(
                f"Invalid target_platform {target_platform!r}; must be one of {sorted(SUPPORTED_TARGET_PLATFORMS)}"
            )
        norm_platform = target_platform.strip().lower()
        if norm_platform not in SUPPORTED_TARGET_PLATFORMS:
            raise ValueError(
                f"Invalid target_platform {target_platform!r}; must be one of {sorted(SUPPORTED_TARGET_PLATFORMS)}"
            )
        self.target_platform: TargetPlatform = norm_platform  # type: ignore[assignment]
        self.generated_at: datetime = _resolve_timestamp(generated_at)

        if inventory_filter is not None:
            self.inventory_filter = inventory_filter
        else:
            self.inventory_filter = GoldenInventoryFilter(
                include_stale=include_stale,
                merge_untracked=merge_untracked,
                approved_discrepancy_ids=approved_discrepancy_ids,
            )

        self._raw_sites = _normalize_sites_input(sites)
        self._validation_results = _normalize_validation_results(validation_results)
        self._discrepancies = _normalize_discrepancies(reconciliation_report)
        self._approved_discrepancy_ids = approved_discrepancy_ids

    def get_filtered_sites(self) -> list[Site]:
        """Return the filtered Site records produced by GoldenInventoryFilter."""
        return self.inventory_filter.filter_sites(
            self._raw_sites,
            validation_results=self._validation_results,
            reconciliation_report=self._discrepancies,
            approved_discrepancy_ids=self._approved_discrepancy_ids,
        )

    @staticmethod
    def _resolve_ip_with_prefix(site: Site, raw_ip: str, subnet_id: Optional[str] = None) -> str:
        text = raw_ip.strip()
        if "/" in text:
            ip_part, mask_part = text.split("/", 1)
            return f"{ip_part.strip()}/{mask_part.strip()}"

        prefix_len = 24
        if subnet_id:
            for subnet in site.subnets:
                if subnet.subnet_id == subnet_id and "/" in subnet.cidr:
                    try:
                        prefix_len = int(subnet.cidr.split("/", 1)[1].strip())
                        return f"{text}/{prefix_len}"
                    except ValueError:
                        pass

        try:
            addr = ipaddress.ip_address(text)
            for subnet in site.subnets:
                try:
                    net = ipaddress.ip_network(subnet.cidr.strip(), strict=False)
                    if addr in net:
                        prefix_len = net.prefixlen
                        break
                except ValueError:
                    continue
        except ValueError:
            pass

        return f"{text}/{prefix_len}"

    def build_bundle(
        self,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
    ) -> dict[str, Any]:
        """Build the normalized NetBox / Nautobot export dictionary across all 7 entity collections."""
        if (
            sites is not None
            or validation_results is not None
            or reconciliation_report is not None
        ):
            target_sites = self.inventory_filter.filter_sites(
                sites if sites is not None else self._raw_sites,
                validation_results=(
                    validation_results
                    if validation_results is not None
                    else self._validation_results
                ),
                reconciliation_report=(
                    reconciliation_report
                    if reconciliation_report is not None
                    else self._discrepancies
                ),
                approved_discrepancy_ids=self._approved_discrepancy_ids,
            )
        else:
            target_sites = self.get_filtered_sites()

        sites_out: list[dict[str, Any]] = []
        vlans_out: list[dict[str, Any]] = []
        prefixes_out: list[dict[str, Any]] = []
        devices_out: list[dict[str, Any]] = []
        interfaces_out: list[dict[str, Any]] = []
        ip_addresses_out: list[dict[str, Any]] = []
        virtual_machines_out: list[dict[str, Any]] = []

        seen_vlans: set[tuple[str, int]] = set()
        seen_ips: set[tuple[str, str]] = set()

        for site in target_sites:
            site_slug = slugify(site.site_id)
            contact_name, contact_email = _parse_contact_info(site.contact_info)

            sites_out.append(
                {
                    "name": site.name,
                    "slug": site_slug,
                    "status": "active",
                    "physical_address": site.address or "",
                    "contact_name": contact_name,
                    "contact_email": contact_email,
                    "custom_fields": {
                        "legacy_sot_id": site.site_id,
                    },
                }
            )

            # 2. VLANs (from site.vlans and synthesized from site.subnets if missing)
            for vlan in site.vlans:
                vid = _parse_vlan_vid(vlan.vlan_id, fallback=1)
                assert vid is not None
                if (site_slug, vid) in seen_vlans:
                    continue
                seen_vlans.add((site_slug, vid))
                vlan_name = vlan.name or f"VLAN-{vid}"
                legacy_vlan_id = (
                    vlan.vlan_id
                    if vlan.vlan_id.startswith(f"{site.site_id}:vlan:")
                    else f"{site.site_id}:vlan:{vlan.vlan_id}"
                )
                vlans_out.append(
                    {
                        "vid": vid,
                        "name": vlan_name,
                        "slug": slugify(f"{site.site_id}-vlan-{vid}-{vlan_name}"),
                        "site": site_slug,
                        "status": "active",
                        "custom_fields": {
                            "legacy_sot_id": legacy_vlan_id,
                        },
                    }
                )

            for subnet in site.subnets:
                if subnet.vlan_id is not None:
                    vid = _parse_vlan_vid(subnet.vlan_id, fallback=None)
                    if vid is not None and (site_slug, vid) not in seen_vlans:
                        seen_vlans.add((site_slug, vid))
                        vlan_name = subnet.name or f"VLAN-{vid}"
                        legacy_vlan_id = f"{site.site_id}:vlan:{subnet.vlan_id}"
                        vlans_out.append(
                            {
                                "vid": vid,
                                "name": vlan_name,
                                "slug": slugify(
                                    f"{site.site_id}-vlan-{vid}-{vlan_name}"
                                ),
                                "site": site_slug,
                                "status": "active",
                                "custom_fields": {
                                    "legacy_sot_id": legacy_vlan_id,
                                },
                            }
                        )

            # 3. Prefixes
            for subnet in site.subnets:
                vlan_vid = _parse_vlan_vid(subnet.vlan_id, fallback=None)
                prefixes_out.append(
                    {
                        "prefix": subnet.cidr.strip(),
                        "slug": slugify(f"{site.site_id}-{subnet.subnet_id}"),
                        "site": site_slug,
                        "vlan": vlan_vid,
                        "status": "active",
                        "description": subnet.name or "",
                        "custom_fields": {
                            "legacy_sot_id": subnet.subnet_id,
                        },
                    }
                )

            # Index object IDs and IPs -> hostname for DNS / assigned_object resolution
            hostname_by_object_id: dict[str, str] = {}
            hostname_by_ip: dict[str, str] = {}
            stale_by_object_id: dict[str, bool] = {}

            # 4a. NetworkDevices -> devices & 5. Ports -> interfaces
            for dev in site.devices:
                is_stale = self.inventory_filter.is_stale(
                    site.site_id, dev.device_id
                ) or self.inventory_filter.is_stale(site.site_id, dev.hostname)
                hostname_by_object_id[dev.device_id] = dev.hostname
                stale_by_object_id[dev.device_id] = is_stale
                if dev.management_ip:
                    hostname_by_ip[_strip_ip_mask(dev.management_ip)] = dev.hostname

                vendor = dev.vendor or "Extreme Networks"
                role_slug = slugify(dev.role or "switch")
                if dev.model:
                    device_type = dev.model
                elif vendor.upper() == "APC" or role_slug == "ups":
                    device_type = "Smart-UPS"
                else:
                    device_type = "ExtremeSwitching"

                devices_out.append(
                    {
                        "name": dev.hostname,
                        "slug": slugify(dev.hostname),
                        "manufacturer": vendor,
                        "role": role_slug,
                        "device_type": device_type,
                        "site": site_slug,
                        "status": "decommissioning" if is_stale else "active",
                        "custom_fields": {
                            "legacy_sot_id": dev.device_id,
                        },
                    }
                )

                for port in dev.ports:
                    admin_lower = (port.admin_status or "up").strip().lower()
                    enabled = admin_lower not in ("down", "disabled", "false", "0", "off")
                    poe_lower = (port.poe_status or "").strip().lower()
                    poe_mode = (
                        "pse"
                        if poe_lower
                        in ("delivering", "enabled", "up", "searching", "active", "on")
                        else "disabled"
                    )
                    description = (
                        f"Connected to {port.connected_device_id}"
                        if port.connected_device_id
                        else ""
                    )
                    untagged_vlan = _parse_vlan_vid(port.vlan_id, fallback=None)

                    interfaces_out.append(
                        {
                            "name": port.name,
                            "slug": slugify(f"{dev.hostname}-{port.name}"),
                            "device": dev.hostname,
                            "enabled": enabled,
                            "poe_mode": poe_mode,
                            "description": description,
                            "untagged_vlan": untagged_vlan,
                            "custom_fields": {
                                "legacy_sot_id": port.port_id,
                            },
                        }
                    )

            # 4b. Physical Equipment -> devices & 7. VMs -> virtual_machines
            for eq in site.equipment:
                is_stale = self.inventory_filter.is_stale(
                    site.site_id, eq.equipment_id
                ) or self.inventory_filter.is_stale(site.site_id, eq.name)
                hostname_by_object_id[eq.equipment_id] = eq.name
                stale_by_object_id[eq.equipment_id] = is_stale
                for raw_ip in eq.assigned_ips:
                    hostname_by_ip[_strip_ip_mask(raw_ip)] = eq.name

                if eq.category is EquipmentCategory.VM:
                    if eq.hypervisor_id and ":" in eq.hypervisor_id:
                        cluster = eq.hypervisor_id.split(":", 1)[0].strip() or "vcenter-default"
                    else:
                        cluster = (eq.hypervisor_id or "").strip() or "vcenter-default"

                    virtual_machines_out.append(
                        {
                            "name": eq.name,
                            "slug": slugify(eq.name),
                            "site": site_slug,
                            "cluster": cluster,
                            "status": "decommissioning" if is_stale else "active",
                            "vcpus": int(getattr(eq, "vcpus", 2) or 2),
                            "memory": int(getattr(eq, "memory", 4096) or 4096),
                            "custom_fields": {
                                "legacy_sot_id": eq.equipment_id,
                                "os_family": _infer_vm_os_family(eq.name),
                            },
                        }
                    )
                else:
                    manufacturer, device_type = _infer_equipment_manufacturer_and_model(
                        eq
                    )
                    devices_out.append(
                        {
                            "name": eq.name,
                            "slug": slugify(eq.name),
                            "manufacturer": manufacturer,
                            "role": eq.category.value,
                            "device_type": device_type,
                            "site": site_slug,
                            "status": "decommissioning" if is_stale else "active",
                            "custom_fields": {
                                "legacy_sot_id": eq.equipment_id,
                            },
                        }
                    )

            # 6. IP Addresses
            for ip_rec in site.ip_addresses:
                clean_ip = _strip_ip_mask(ip_rec.ip)
                if not clean_ip:
                    continue
                address = self._resolve_ip_with_prefix(
                    site, ip_rec.ip, ip_rec.subnet_id
                )
                if (site_slug, address) in seen_ips:
                    continue
                seen_ips.add((site_slug, address))

                resolved_host = (
                    hostname_by_object_id.get(ip_rec.assigned_object_id or "")
                    or hostname_by_ip.get(clean_ip)
                    or ""
                )
                assigned_obj = resolved_host or (ip_rec.assigned_object_id or "")

                is_ip_stale = (
                    self.inventory_filter.is_stale(site.site_id, ip_rec.ip)
                    or self.inventory_filter.is_stale(site.site_id, clean_ip)
                    or (
                        bool(ip_rec.assigned_object_id)
                        and stale_by_object_id.get(ip_rec.assigned_object_id or "", False)
                    )
                )
                if is_ip_stale:
                    ip_status = (
                        "deprecated"
                        if self.target_platform == "netbox"
                        else "decommissioning"
                    )
                else:
                    ip_status = "active"

                ip_addresses_out.append(
                    {
                        "address": address,
                        "slug": slugify(f"{site.site_id}-{address}"),
                        "site": site_slug,
                        "status": ip_status,
                        "dns_name": resolved_host,
                        "assigned_object": assigned_obj,
                        "custom_fields": {
                            "legacy_sot_id": f"{site.site_id}:ip:{clean_ip}",
                        },
                    }
                )

            # Ensure management IPs and equipment assigned IPs not in site.ip_addresses are also exported
            for dev in site.devices:
                if not dev.management_ip:
                    continue
                clean_ip = _strip_ip_mask(dev.management_ip)
                address = self._resolve_ip_with_prefix(site, dev.management_ip)
                if (site_slug, address) in seen_ips:
                    continue
                seen_ips.add((site_slug, address))
                is_ip_stale = stale_by_object_id.get(dev.device_id, False)
                ip_status = (
                    ("deprecated" if self.target_platform == "netbox" else "decommissioning")
                    if is_ip_stale
                    else "active"
                )
                ip_addresses_out.append(
                    {
                        "address": address,
                        "slug": slugify(f"{site.site_id}-{address}"),
                        "site": site_slug,
                        "status": ip_status,
                        "dns_name": dev.hostname,
                        "assigned_object": dev.hostname,
                        "custom_fields": {
                            "legacy_sot_id": f"{site.site_id}:ip:{clean_ip}",
                        },
                    }
                )

            for eq in site.equipment:
                for raw_ip in eq.assigned_ips:
                    clean_ip = _strip_ip_mask(raw_ip)
                    if not clean_ip:
                        continue
                    address = self._resolve_ip_with_prefix(site, raw_ip)
                    if (site_slug, address) in seen_ips:
                        continue
                    seen_ips.add((site_slug, address))
                    is_ip_stale = stale_by_object_id.get(eq.equipment_id, False)
                    ip_status = (
                        ("deprecated" if self.target_platform == "netbox" else "decommissioning")
                        if is_ip_stale
                        else "active"
                    )
                    ip_addresses_out.append(
                        {
                            "address": address,
                            "slug": slugify(f"{site.site_id}-{address}"),
                            "site": site_slug,
                            "status": ip_status,
                            "dns_name": eq.name,
                            "assigned_object": eq.name,
                            "custom_fields": {
                                "legacy_sot_id": f"{site.site_id}:ip:{clean_ip}",
                            },
                        }
                    )

        sites_out.sort(key=lambda r: r["slug"])
        vlans_out.sort(key=lambda r: (r["site"], r["vid"], r["slug"]))
        prefixes_out.sort(key=lambda r: (r["site"], r["prefix"], r["slug"]))
        devices_out.sort(key=lambda r: (r["site"], r["slug"]))
        interfaces_out.sort(key=lambda r: (r["device"], r["slug"]))
        ip_addresses_out.sort(key=lambda r: (r["site"], r["address"], r["slug"]))
        virtual_machines_out.sort(key=lambda r: (r["site"], r["slug"]))

        collections: dict[str, list[dict[str, Any]]] = {
            "sites": sites_out,
            "vlans": vlans_out,
            "prefixes": prefixes_out,
            "devices": devices_out,
            "interfaces": interfaces_out,
            "ip_addresses": ip_addresses_out,
            "virtual_machines": virtual_machines_out,
        }

        summary = {key: len(collections[key]) for key in ENTITY_COLLECTION_KEYS}

        return {
            "target_platform": self.target_platform,
            "generated_at": _format_optional_datetime(self.generated_at),
            "summary": summary,
            **collections,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the complete NetBox / Nautobot export bundle as a dictionary."""
        return self.build_bundle()

    def export_json(
        self,
        *,
        indent: Optional[int] = 2,
        output_path: Optional[Path | str] = None,
    ) -> str:
        """Serialize the golden inventory bundle to JSON and optionally write it to output_path."""
        payload = self.to_dict()
        content = json.dumps(payload, indent=indent)
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return content

    def export_csv_bundle(self, output_dir: Path | str) -> dict[str, Path]:
        """Write deterministic per-entity CSV import files to output_dir and return a path map."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        bundle = self.to_dict()
        written_files: dict[str, Path] = {}

        for entity_key in ENTITY_COLLECTION_KEYS:
            columns = CSV_COLUMNS_BY_ENTITY[entity_key]
            records: list[dict[str, Any]] = bundle.get(entity_key, [])
            csv_file = out_path / f"{entity_key}.csv"

            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator="\n")
            writer.writerow(columns)

            for record in records:
                custom_fields = record.get("custom_fields") or {}
                row: list[Any] = []
                for col in columns:
                    if col in custom_fields:
                        val = custom_fields[col]
                    else:
                        val = record.get(col)
                    row.append("" if val is None else val)
                writer.writerow(row)

            csv_file.write_text(buf.getvalue(), encoding="utf-8")
            written_files[entity_key] = csv_file

        return written_files


__all__ = [
    "CSV_COLUMNS_BY_ENTITY",
    "ENTITY_COLLECTION_KEYS",
    "GoldenInventoryFilter",
    "ModernSoTExporter",
    "SUPPORTED_TARGET_PLATFORMS",
    "slugify",
]
