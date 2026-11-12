"""Interactive Web Workbench HTTP server, JSON REST API, and state manager."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import threading
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from sot_validator.classifier.engine import ClassificationEngine
from sot_validator.curation.store import (
    AuditLogEntry,
    CurationStore,
    ItemEditPatch,
    apply_curation_overlay,
)
from sot_validator.models import (
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.topology.device_types import (
    DevicePortManager,
    DeviceTypeCatalog,
    normalize_mac_address,
)
from sot_validator.topology.graph import TopologyGraphBuilder
from sot_validator.workbench.ui import render_workbench_html

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(value: str, prefix: str = "dev") -> str:
    slug = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    if not slug:
        slug = "item"
    return f"{prefix}-{slug}" if not slug.startswith(f"{prefix}-") else slug


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value).strip() or None
    stripped = value.strip()
    return stripped if stripped else None


class WorkbenchNotFoundError(KeyError):
    """Raised when a requested workbench resource (such as a device) does not exist."""


class WorkbenchState:
    """Thread-safe state container for the interactive inventory and topology workbench."""

    def __init__(
        self,
        site: Site,
        store: Optional[CurationStore] = None,
        catalog: Optional[DeviceTypeCatalog] = None,
        classifier: Optional[ClassificationEngine] = None,
        initial_results: Optional[Sequence[ValidationResult]] = None,
    ) -> None:
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")
        self._lock = threading.RLock()
        self.base_site: Site = Site.from_dict(site.to_dict())
        self.store: CurationStore = (
            store if store is not None else CurationStore(":memory:")
        )
        # Ensure underlying SQLite connection can be used across HTTP worker threads
        try:
            import sqlite3

            if getattr(self.store, "db_path", None) not in (None, ":memory:"):
                old_conn = self.store._conn
                self.store._conn = sqlite3.connect(
                    str(self.store.db_path), check_same_thread=False
                )
                self.store._conn.row_factory = sqlite3.Row
                old_conn.close()
            else:
                snapshot = self.store.to_dict()
                old_conn = self.store._conn
                self.store._conn = sqlite3.connect(
                    ":memory:", check_same_thread=False
                )
                self.store._conn.row_factory = sqlite3.Row
                self.store._init_schema()
                self.store._load_state_from_mapping(snapshot)
                old_conn.close()
        except Exception:
            pass

        self.catalog: DeviceTypeCatalog = (
            catalog if catalog is not None else DeviceTypeCatalog()
        )
        self.classifier: ClassificationEngine = (
            classifier if classifier is not None else ClassificationEngine()
        )
        self._base_results: list[ValidationResult] = (
            [
                ValidationResult.from_dict(r.to_dict())
                if isinstance(r, ValidationResult)
                else ValidationResult.from_dict(r)
                for r in initial_results
            ]
            if initial_results is not None
            else []
        )
        self.site: Site = Site.from_dict(self.base_site.to_dict())
        self.results: list[ValidationResult] = []
        self.refresh()

    def refresh(self) -> tuple[Site, list[ValidationResult]]:
        """Re-apply curation overlay and re-run classification on the curated site."""
        with self._lock:
            curated_site, _ = apply_curation_overlay(
                self.base_site, self.store, self._base_results
            )
            fresh_results = self.classifier.classify_site(curated_site)

            if self._base_results:
                base_by_key: dict[tuple[str, str], ValidationResult] = {
                    (r.item_type, r.item_id): r for r in self._base_results
                }
                merged_results: list[ValidationResult] = []
                for fresh in fresh_results:
                    key = (fresh.item_type, fresh.item_id)
                    initial = base_by_key.get(key)
                    if (
                        initial is not None
                        and initial.signals
                        and fresh.classification
                        == ValidationClassification.INSUFFICIENT_DATA
                        and initial.classification
                        != ValidationClassification.INSUFFICIENT_DATA
                    ):
                        preserved = ValidationResult.from_dict(initial.to_dict())
                        preserved.name = fresh.name
                        merged_results.append(preserved)
                    else:
                        merged_results.append(fresh)
                classified_results = merged_results
            else:
                classified_results = fresh_results

            final_site, final_results = apply_curation_overlay(
                curated_site, self.store, classified_results
            )
            self.site = final_site
            self.results = final_results
            return self.site, self.results

    def _build_vlan_subnet_summary(
        self, patches: Sequence[ItemEditPatch]
    ) -> list[dict[str, Any]]:
        patch_by_key: dict[tuple[str, str], ItemEditPatch] = {
            (p.target_type, p.target_id): p for p in patches if not p.deleted
        }
        vlans_by_id: dict[str, VLAN] = {v.vlan_id: v for v in self.site.vlans}
        subnets_by_id: dict[str, Subnet] = {s.subnet_id: s for s in self.site.subnets}
        subnets_by_vlan: dict[str, list[Subnet]] = {}
        for sub in self.site.subnets:
            if sub.vlan_id:
                subnets_by_vlan.setdefault(sub.vlan_id, []).append(sub)

        parsed_subnets: dict[str, ipaddress._BaseNetwork] = {}
        for sub in self.site.subnets:
            try:
                parsed_subnets[sub.subnet_id] = ipaddress.ip_network(
                    sub.cidr, strict=False
                )
            except ValueError:
                continue

        def _count_for(
            vlan_id: Optional[str], subnet_id: Optional[str], cidr: Optional[str]
        ) -> tuple[int, int, int]:
            target_subnet_ids: set[str] = set()
            if subnet_id:
                target_subnet_ids.add(subnet_id)
            if vlan_id:
                for s in subnets_by_vlan.get(vlan_id, ()):
                    target_subnet_ids.add(s.subnet_id)

            net_objs: list[ipaddress._BaseNetwork] = [
                parsed_subnets[sid]
                for sid in target_subnet_ids
                if sid in parsed_subnets
            ]
            if cidr and not net_objs:
                try:
                    net_objs.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass

            ip_count = 0
            matched_ips: set[str] = set()
            for ip_rec in self.site.ip_addresses:
                if ip_rec.subnet_id in target_subnet_ids:
                    ip_count += 1
                    matched_ips.add(ip_rec.ip)
                elif net_objs:
                    try:
                        ip_val = ipaddress.ip_address(ip_rec.ip)
                        if any(ip_val in net for net in net_objs):
                            ip_count += 1
                            matched_ips.add(ip_rec.ip)
                    except ValueError:
                        pass

            port_count = 0
            port_ids_in_vlan: set[str] = set()
            if vlan_id:
                for dev in self.site.devices:
                    for port in dev.ports:
                        if port.vlan_id == vlan_id:
                            port_count += 1
                            port_ids_in_vlan.add(port.port_id)
                            port_ids_in_vlan.add(port.name)

            eq_count = 0
            for eq in self.site.equipment:
                eq_patch = patch_by_key.get(("Equipment", eq.equipment_id))
                eq_vlan = (
                    (eq_patch.vlan_id or eq_patch.custom_attributes.get("vlan_id"))
                    if eq_patch is not None
                    else None
                )
                eq_subnet = (
                    (eq_patch.subnet_id or eq_patch.custom_attributes.get("subnet_id"))
                    if eq_patch is not None
                    else None
                )
                in_vlan = bool(vlan_id and eq_vlan == vlan_id)
                in_subnet = bool(
                    target_subnet_ids and eq_subnet in target_subnet_ids
                )
                has_port = bool(
                    port_ids_in_vlan
                    and any(cp in port_ids_in_vlan for cp in eq.connected_ports)
                )
                has_ip = False
                for raw_ip in eq.assigned_ips:
                    if raw_ip in matched_ips:
                        has_ip = True
                        break
                    if net_objs:
                        try:
                            ip_val = ipaddress.ip_address(raw_ip)
                            if any(ip_val in net for net in net_objs):
                                has_ip = True
                                break
                        except ValueError:
                            pass
                if in_vlan or in_subnet or has_port or has_ip:
                    eq_count += 1

            return ip_count, port_count, eq_count

        summaries: list[dict[str, Any]] = []
        handled_subnet_ids: set[str] = set()

        for vlan in self.site.vlans:
            linked_subnets = list(subnets_by_vlan.get(vlan.vlan_id, ()))
            if vlan.subnet_id and vlan.subnet_id in subnets_by_id:
                primary_sub = subnets_by_id[vlan.subnet_id]
                if primary_sub not in linked_subnets:
                    linked_subnets.insert(0, primary_sub)

            if linked_subnets:
                for sub in linked_subnets:
                    handled_subnet_ids.add(sub.subnet_id)
                    ip_cnt, port_cnt, eq_cnt = _count_for(
                        vlan.vlan_id, sub.subnet_id, sub.cidr or vlan.cidr
                    )
                    summaries.append(
                        {
                            "vlan_id": vlan.vlan_id,
                            "vlan_name": vlan.name or sub.name or f"VLAN {vlan.vlan_id}",
                            "subnet_id": sub.subnet_id,
                            "cidr": sub.cidr or vlan.cidr,
                            "gateway": sub.gateway or vlan.gateway,
                            "ip_count": ip_cnt,
                            "device_port_count": port_cnt,
                            "equipment_count": eq_cnt,
                        }
                    )
            else:
                ip_cnt, port_cnt, eq_cnt = _count_for(
                    vlan.vlan_id, vlan.subnet_id, vlan.cidr
                )
                summaries.append(
                    {
                        "vlan_id": vlan.vlan_id,
                        "vlan_name": vlan.name or f"VLAN {vlan.vlan_id}",
                        "subnet_id": vlan.subnet_id,
                        "cidr": vlan.cidr,
                        "gateway": vlan.gateway,
                        "ip_count": ip_cnt,
                        "device_port_count": port_cnt,
                        "equipment_count": eq_cnt,
                    }
                )

        for sub in self.site.subnets:
            if sub.subnet_id in handled_subnet_ids:
                continue
            vlan_obj = vlans_by_id.get(sub.vlan_id) if sub.vlan_id else None
            ip_cnt, port_cnt, eq_cnt = _count_for(
                sub.vlan_id, sub.subnet_id, sub.cidr
            )
            summaries.append(
                {
                    "vlan_id": sub.vlan_id,
                    "vlan_name": (
                        vlan_obj.name
                        if vlan_obj and vlan_obj.name
                        else (sub.name or (f"VLAN {sub.vlan_id}" if sub.vlan_id else sub.subnet_id))
                    ),
                    "subnet_id": sub.subnet_id,
                    "cidr": sub.cidr,
                    "gateway": sub.gateway,
                    "ip_count": ip_cnt,
                    "device_port_count": port_cnt,
                    "equipment_count": eq_cnt,
                }
            )

        return summaries

    def get_state_payload(self, audit_limit: int = 50) -> dict[str, Any]:
        """Return a JSON-serializable state payload for the UI and REST API."""
        with self._lock:
            patches = self.store.list_patches(site_id=self.site.site_id)
            all_ports = [p for d in self.site.devices for p in d.ports]
            active_ports = sum(
                1
                for p in all_ports
                if (p.oper_status or "").strip().lower() == "up"
            )
            poe_ports = sum(
                1
                for p in all_ports
                if p.poe_status is not None
                and (p.poe_status or "").strip().lower()
                not in ("", "off", "disabled", "none")
            )
            classification_counts: dict[str, int] = {
                cls.value: 0 for cls in ValidationClassification
            }
            for res in self.results:
                classification_counts[res.classification.value] = (
                    classification_counts.get(res.classification.value, 0) + 1
                )

            summary = {
                "total_devices": len(self.site.devices),
                "total_ports": len(all_ports),
                "active_ports": active_ports,
                "poe_ports": poe_ports,
                "total_vlans": len(self.site.vlans),
                "total_subnets": len(self.site.subnets),
                "total_ips": len(self.site.ip_addresses),
                "total_equipment": len(self.site.equipment),
                "classification_counts": classification_counts,
            }

            audit_entries = self.store.list_audit_log(
                site_id=self.site.site_id, limit=audit_limit
            )

            return {
                "site": self.site.to_dict(),
                "results": [r.to_dict() for r in self.results],
                "templates": [t.to_dict() for t in self.catalog.list_templates()],
                "patches": [p.to_dict() for p in patches],
                "vlan_subnet_summary": self._build_vlan_subnet_summary(patches),
                "summary": summary,
                "audit_log": [a.to_dict() for a in audit_entries],
            }

    def apply_item_patch(
        self,
        payload: Mapping[str, Any] | ItemEditPatch,
        *,
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Apply an ItemEditPatch (or item deletion) to the CurationStore and refresh state."""
        with self._lock:
            if isinstance(payload, ItemEditPatch):
                patch = (
                    payload
                    if payload.site_id is not None
                    else replace(payload, site_id=self.site.site_id)
                )
            elif isinstance(payload, Mapping):
                data = dict(payload)
                if not data.get("site_id"):
                    data["site_id"] = self.site.site_id
                custom_attrs = dict(data.get("custom_attributes") or {})
                patch = ItemEditPatch(
                    target_type=data["target_type"],
                    target_id=data["target_id"],
                    site_id=data.get("site_id"),
                    name=_optional_str(data.get("name")),
                    hostname=_optional_str(data.get("hostname")),
                    category=_optional_str(data.get("category")),
                    role=_optional_str(data.get("role")),
                    vendor=_optional_str(data.get("vendor")),
                    model=_optional_str(data.get("model")),
                    vlan_id=_optional_str(data.get("vlan_id")),
                    subnet_id=_optional_str(data.get("subnet_id")),
                    room=_optional_str(data.get("room")),
                    notes=_optional_str(data.get("notes")),
                    pinned_classification=_optional_str(
                        data.get("pinned_classification")
                    ),
                    custom_attributes=custom_attrs,
                    deleted=bool(data.get("deleted", False)),
                )
            else:
                raise ValueError("payload must be a Mapping or ItemEditPatch")

            if patch.target_type == "Equipment":
                merged_attrs = dict(patch.custom_attributes)
                if patch.vlan_id is not None:
                    merged_attrs["vlan_id"] = patch.vlan_id
                if patch.subnet_id is not None:
                    merged_attrs["subnet_id"] = patch.subnet_id
                if patch.room is not None:
                    merged_attrs["room"] = patch.room
                if merged_attrs != patch.custom_attributes:
                    patch = replace(patch, custom_attributes=merged_attrs)

            if patch.deleted:
                entry = self.store.delete_item(
                    patch.target_type,
                    patch.target_id,
                    actor=actor,
                    reason=reason,
                    site_id=patch.site_id or self.site.site_id,
                )
            else:
                entry = self.store.upsert_patch(patch, actor=actor, reason=reason)

            self.refresh()
            return entry

    def create_device(
        self,
        payload: Mapping[str, Any],
        *,
        actor: str = "operator",
        reason: str = "",
    ) -> tuple[NetworkDevice, AuditLogEntry]:
        """Create a NetworkDevice (from a template or custom fields), persist it, and refresh state."""
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        with self._lock:
            hostname = _require_non_empty_str(
                payload.get("hostname"), "hostname"
            ).strip()
            site_id = (
                _optional_str(payload.get("site_id")) or self.site.site_id
            )
            raw_device_id = _optional_str(payload.get("device_id"))
            device_id = raw_device_id if raw_device_id else _slugify(hostname, prefix="dev")

            template_id = _optional_str(payload.get("template_id"))
            management_ip = _optional_str(payload.get("management_ip"))
            vendor = _optional_str(payload.get("vendor"))
            model = _optional_str(payload.get("model"))
            role = _optional_str(payload.get("role"))
            default_vlan_id = _optional_str(payload.get("default_vlan_id"))
            last_seen = _parse_optional_datetime(
                payload.get("last_seen"), "last_seen"
            )

            raw_port_count = payload.get("port_count")
            port_count: Optional[int] = None
            if raw_port_count is not None and raw_port_count != "":
                if isinstance(raw_port_count, bool):
                    raise ValueError("port_count must be a non-negative integer")
                try:
                    port_count = int(raw_port_count)
                except (TypeError, ValueError) as exc:
                    raise ValueError("port_count must be a non-negative integer") from exc
                if port_count < 0:
                    raise ValueError("port_count must be a non-negative integer")

            if template_id:
                device = self.catalog.instantiate_device(
                    template_id,
                    device_id=device_id,
                    site_id=site_id,
                    hostname=hostname,
                    management_ip=management_ip,
                    port_count=port_count,
                    default_vlan_id=default_vlan_id,
                    last_seen=last_seen,
                )
                if vendor is not None:
                    device.vendor = vendor
                if model is not None:
                    device.model = model
                if role is not None:
                    device.role = role
            else:
                device = NetworkDevice(
                    device_id=device_id,
                    site_id=site_id,
                    hostname=hostname,
                    management_ip=management_ip,
                    vendor=vendor,
                    model=model,
                    role=role,
                    last_seen=last_seen,
                    ports=[],
                )
                if port_count is not None and port_count > 0:
                    naming_pattern = (
                        _optional_str(payload.get("port_naming_pattern")) or "1:{n}"
                    )
                    mgr = DevicePortManager(device)
                    mgr.add_port_range(
                        start=1,
                        end=port_count,
                        naming_pattern=naming_pattern,
                        vlan_id=default_vlan_id,
                        overwrite=True,
                    )

            explicit_ports = payload.get("ports")
            if explicit_ports is not None:
                if not isinstance(explicit_ports, Sequence) or isinstance(
                    explicit_ports, (str, bytes)
                ):
                    raise ValueError("ports must be a list of port specifications")
                mgr = DevicePortManager(device)
                for p_spec in explicit_ports:
                    if isinstance(p_spec, Port):
                        mgr.add_port(
                            p_spec.name,
                            port_id=p_spec.port_id,
                            admin_status=p_spec.admin_status,
                            oper_status=p_spec.oper_status,
                            poe_status=p_spec.poe_status,
                            vlan_id=p_spec.vlan_id,
                            connected_device_id=p_spec.connected_device_id,
                            connected_mac=p_spec.connected_mac,
                            overwrite=True,
                        )
                    elif isinstance(p_spec, Mapping):
                        p_name = _require_non_empty_str(
                            p_spec.get("name"), "port.name"
                        ).strip()
                        mgr.add_port(
                            p_name,
                            port_id=_optional_str(p_spec.get("port_id")),
                            admin_status=_optional_str(p_spec.get("admin_status")) or "up",
                            oper_status=_optional_str(p_spec.get("oper_status")) or "down",
                            poe_status=_optional_str(p_spec.get("poe_status")),
                            vlan_id=_optional_str(p_spec.get("vlan_id")) or default_vlan_id,
                            connected_device_id=_optional_str(
                                p_spec.get("connected_device_id")
                            ),
                            connected_mac=_optional_str(p_spec.get("connected_mac")),
                            overwrite=True,
                        )
                    else:
                        raise ValueError("Each entry in ports must be a Port or mapping")

            entry = self.store.add_custom_device(device, actor=actor, reason=reason)
            self.refresh()
            created = next(
                (d for d in self.site.devices if d.device_id == device.device_id),
                device,
            )
            return created, entry

    def upsert_device_ports(
        self,
        payload: Mapping[str, Any],
        *,
        actor: str = "operator",
        reason: str = "",
    ) -> tuple[list[Port], list[AuditLogEntry]]:
        """Provision or update single ports, port ranges, or batch port lists on a NetworkDevice."""
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        with self._lock:
            device_id = _require_non_empty_str(
                payload.get("device_id"), "device_id"
            ).strip()
            target_dev = next(
                (d for d in self.site.devices if d.device_id == device_id), None
            )
            if target_dev is None:
                raise WorkbenchNotFoundError(
                    f"NetworkDevice {device_id!r} not found in site {self.site.site_id!r}"
                )

            working_dev = NetworkDevice.from_dict(target_dev.to_dict())
            mgr = DevicePortManager(working_dev)
            overwrite = bool(payload.get("overwrite", True))

            default_admin = _optional_str(payload.get("admin_status"))
            default_oper = _optional_str(payload.get("oper_status"))
            default_poe = _optional_str(payload.get("poe_status"))
            default_vlan = _optional_str(payload.get("vlan_id"))
            default_conn_dev = _optional_str(payload.get("connected_device_id"))
            default_conn_mac = _optional_str(payload.get("connected_mac"))

            def _upsert_single(spec: Mapping[str, Any]) -> Port:
                raw_name = _optional_str(spec.get("name"))
                raw_port_id = _optional_str(spec.get("port_id"))
                if not raw_name and not raw_port_id:
                    raise ValueError("Port specification requires 'name' or 'port_id'")

                existing_port: Optional[Port] = None
                for p in working_dev.ports:
                    if (raw_port_id and p.port_id == raw_port_id) or (
                        raw_name and p.name == raw_name
                    ):
                        existing_port = p
                        break

                resolved_name = (
                    raw_name
                    or (existing_port.name if existing_port is not None else None)
                    or (
                        raw_port_id.split(":", 1)[1]
                        if raw_port_id and ":" in raw_port_id
                        else raw_port_id
                    )
                )
                assert resolved_name is not None
                resolved_port_id = (
                    raw_port_id
                    or (existing_port.port_id if existing_port is not None else None)
                    or f"{device_id}:{resolved_name}"
                )

                admin_status = (
                    _optional_str(spec["admin_status"])
                    if "admin_status" in spec
                    else (
                        default_admin
                        if default_admin is not None
                        else (existing_port.admin_status if existing_port else "up")
                    )
                )
                oper_status = (
                    _optional_str(spec["oper_status"])
                    if "oper_status" in spec
                    else (
                        default_oper
                        if default_oper is not None
                        else (existing_port.oper_status if existing_port else "down")
                    )
                )
                poe_status = (
                    _optional_str(spec["poe_status"])
                    if "poe_status" in spec
                    else (
                        default_poe
                        if "poe_status" in payload
                        else (existing_port.poe_status if existing_port else None)
                    )
                )
                vlan_id = (
                    _optional_str(spec["vlan_id"])
                    if "vlan_id" in spec
                    else (
                        default_vlan
                        if "vlan_id" in payload
                        else (existing_port.vlan_id if existing_port else None)
                    )
                )
                connected_device_id = (
                    _optional_str(spec["connected_device_id"])
                    if "connected_device_id" in spec
                    else (
                        default_conn_dev
                        if "connected_device_id" in payload
                        else (
                            existing_port.connected_device_id if existing_port else None
                        )
                    )
                )
                raw_mac = (
                    _optional_str(spec["connected_mac"])
                    if "connected_mac" in spec
                    else (
                        default_conn_mac
                        if "connected_mac" in payload
                        else (existing_port.connected_mac if existing_port else None)
                    )
                )
                item_overwrite = bool(spec.get("overwrite", overwrite))
                return mgr.add_port(
                    resolved_name,
                    port_id=resolved_port_id,
                    admin_status=admin_status,
                    oper_status=oper_status,
                    poe_status=poe_status,
                    vlan_id=vlan_id,
                    connected_device_id=connected_device_id,
                    connected_mac=raw_mac,
                    overwrite=item_overwrite,
                )

            touched_ports: list[Port] = []
            batch_ports = payload.get("ports")
            range_spec = _optional_str(payload.get("range_spec"))
            raw_start = payload.get("start")
            raw_end = payload.get("end")

            if batch_ports is not None:
                if not isinstance(batch_ports, Sequence) or isinstance(
                    batch_ports, (str, bytes)
                ):
                    raise ValueError("ports must be a sequence of port mappings")
                if not batch_ports:
                    raise ValueError("ports list must not be empty")
                for item in batch_ports:
                    if not isinstance(item, Mapping):
                        raise ValueError("Each item in ports must be a mapping")
                    touched_ports.append(_upsert_single(item))
            elif range_spec is not None or (
                raw_start is not None and raw_end is not None
            ):
                start_int: Optional[int] = None
                end_int: Optional[int] = None
                if raw_start is not None or raw_end is not None:
                    if isinstance(raw_start, bool) or isinstance(raw_end, bool):
                        raise ValueError("start and end must be integers")
                    try:
                        start_int = int(raw_start)  # type: ignore[arg-type]
                        end_int = int(raw_end)  # type: ignore[arg-type]
                    except (TypeError, ValueError) as exc:
                        raise ValueError("start and end must be integers") from exc
                naming_pattern = (
                    _optional_str(payload.get("naming_pattern")) or "{n}"
                )
                created_range = mgr.add_port_range(
                    range_spec,
                    start=start_int,
                    end=end_int,
                    naming_pattern=naming_pattern,
                    admin_status=default_admin or "up",
                    oper_status=default_oper or "down",
                    poe_status=default_poe,
                    vlan_id=default_vlan,
                    overwrite=overwrite,
                )
                norm_mac = (
                    normalize_mac_address(default_conn_mac)
                    if default_conn_mac is not None
                    else None
                )
                for p in created_range:
                    if default_conn_dev is not None:
                        p.connected_device_id = default_conn_dev
                    if norm_mac is not None:
                        p.connected_mac = norm_mac
                touched_ports.extend(created_range)
            else:
                touched_ports.append(_upsert_single(payload))

            audit_entries: list[AuditLogEntry] = []
            for p in touched_ports:
                entry = self.store.add_or_update_port(
                    device_id,
                    p,
                    actor=actor,
                    reason=reason,
                    site_id=self.site.site_id,
                )
                audit_entries.append(entry)

            self.refresh()
            return touched_ports, audit_entries

    def upsert_vlan(
        self,
        payload: Mapping[str, Any],
        *,
        actor: str = "operator",
        reason: str = "",
    ) -> tuple[VLAN, Optional[Subnet], AuditLogEntry]:
        """Add or update a VLAN and optional associated Subnet, persist it, and refresh state."""
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        with self._lock:
            raw_vlan_id = payload.get("vlan_id")
            if raw_vlan_id is None or str(raw_vlan_id).strip() == "":
                raise ValueError("vlan_id must be a non-empty string")
            vlan_id = str(raw_vlan_id).strip()
            site_id = (
                _optional_str(payload.get("site_id")) or self.site.site_id
            )
            name = _optional_str(payload.get("name"))
            subnet_id = _optional_str(payload.get("subnet_id"))
            cidr = _optional_str(payload.get("cidr"))
            gateway = _optional_str(payload.get("gateway"))

            subnet_payload = payload.get("subnet")
            if isinstance(subnet_payload, Mapping):
                subnet_id = _optional_str(subnet_payload.get("subnet_id")) or subnet_id
                cidr = _optional_str(subnet_payload.get("cidr")) or cidr
                gateway = _optional_str(subnet_payload.get("gateway")) or gateway
                if name is None:
                    name = _optional_str(subnet_payload.get("name"))

            if cidr is not None:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid subnet CIDR: {cidr!r}") from exc

            subnet_obj: Optional[Subnet] = None
            if cidr is not None:
                resolved_subnet_id = (
                    subnet_id or f"{site_id}-subnet-vlan-{vlan_id}"
                )
                subnet_obj = Subnet(
                    subnet_id=resolved_subnet_id,
                    site_id=site_id,
                    cidr=cidr,
                    vlan_id=vlan_id,
                    gateway=gateway,
                    name=name or f"VLAN {vlan_id}",
                )
                subnet_id = resolved_subnet_id

            vlan_obj = VLAN(
                vlan_id=vlan_id,
                site_id=site_id,
                name=name,
                subnet_id=subnet_id,
                cidr=cidr,
                gateway=gateway,
            )

            entry = self.store.add_custom_vlan(
                vlan_obj, subnet=subnet_obj, actor=actor, reason=reason
            )
            self.refresh()
            return vlan_obj, subnet_obj, entry


class WorkbenchServer(ThreadingHTTPServer):
    """Standard-library threaded HTTP server hosting the interactive workbench."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        state: WorkbenchState,
        RequestHandlerClass: type[BaseHTTPRequestHandler] = None,  # type: ignore[assignment]
    ) -> None:
        if not isinstance(state, WorkbenchState):
            raise ValueError("state must be a WorkbenchState instance")
        self.state = state
        handler_cls = RequestHandlerClass or WorkbenchRequestHandler
        super().__init__(server_address, handler_cls)


class WorkbenchRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler serving the workbench UI and JSON REST API."""

    server: WorkbenchServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy default stderr logging during automated runs/tests
        return

    def _send_json(self, status_code: int, payload: Mapping[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status_code: int, html_text: str) -> None:
        raw = html_text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict[str, Any]:
        content_length_str = self.headers.get("Content-Length")
        if not content_length_str:
            raise ValueError("Request body is required")
        try:
            length = int(content_length_str)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length <= 0:
            raise ValueError("Request body must not be empty")
        raw_bytes = self.rfile.read(length)
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON payload: {exc}") from exc
        if not isinstance(parsed, Mapping):
            raise ValueError("JSON body must be an object")
        return dict(parsed)

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        route = parsed_url.path.rstrip("/") or "/"
        query = parse_qs(parsed_url.query)

        try:
            if route in ("/", "/index.html"):
                html_doc = render_workbench_html(self.server.state)
                self._send_html(200, html_doc)
                return

            if route == "/api/health":
                self._send_json(200, {"status": "ok"})
                return

            if route == "/api/state":
                limit = 50
                if "audit_limit" in query and query["audit_limit"]:
                    limit = int(query["audit_limit"][0])
                self._send_json(
                    200, self.server.state.get_state_payload(audit_limit=limit)
                )
                return

            if route == "/api/topology":
                with self.server.state._lock:
                    graph = TopologyGraphBuilder().build(
                        self.server.state.site, self.server.state.results
                    )
                    payload = graph.to_dict()
                    payload["mermaid"] = graph.to_mermaid()
                self._send_json(200, payload)
                return

            if route == "/api/audit-log":
                limit = 100
                if "limit" in query and query["limit"]:
                    limit = int(query["limit"][0])
                site_id: Optional[str] = self.server.state.site.site_id
                if "site_id" in query and query["site_id"]:
                    raw_site = query["site_id"][0].strip()
                    site_id = raw_site if raw_site else None
                with self.server.state._lock:
                    entries = self.server.state.store.list_audit_log(
                        site_id=site_id, limit=limit
                    )
                self._send_json(
                    200,
                    {"audit_log": [entry.to_dict() for entry in entries]},
                )
                return

            self._send_json(404, {"status": "error", "error": "Not found"})
        except (ValueError, KeyError) as exc:
            self._send_json(400, {"status": "error", "error": str(exc)})

    def do_POST(self) -> None:
        parsed_url = urlparse(self.path)
        route = parsed_url.path.rstrip("/") or "/"

        if route not in (
            "/api/items/patch",
            "/api/devices",
            "/api/devices/ports",
            "/api/vlans",
        ):
            self._send_json(404, {"status": "error", "error": "Not found"})
            return

        try:
            body = self._read_json_body()
            actor = _optional_str(body.get("actor")) or "operator"
            reason = _optional_str(body.get("reason")) or ""

            if route == "/api/items/patch":
                entry = self.server.state.apply_item_patch(
                    body, actor=actor, reason=reason
                )
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "audit_entry": entry.to_dict(),
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return

            if route == "/api/devices":
                device, entry = self.server.state.create_device(
                    body, actor=actor, reason=reason
                )
                self._send_json(
                    201,
                    {
                        "status": "ok",
                        "device": device.to_dict(),
                        "audit_entry": entry.to_dict(),
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return

            if route == "/api/devices/ports":
                ports, entries = self.server.state.upsert_device_ports(
                    body, actor=actor, reason=reason
                )
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "ports": [p.to_dict() for p in ports],
                        "audit_entries": [e.to_dict() for e in entries],
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return

            if route == "/api/vlans":
                vlan, subnet, entry = self.server.state.upsert_vlan(
                    body, actor=actor, reason=reason
                )
                self._send_json(
                    201,
                    {
                        "status": "ok",
                        "vlan": vlan.to_dict(),
                        "subnet": subnet.to_dict() if subnet is not None else None,
                        "audit_entry": entry.to_dict(),
                        "state": self.server.state.get_state_payload(),
                    },
                )
                return
        except WorkbenchNotFoundError as exc:
            self._send_json(404, {"status": "error", "error": str(exc)})
        except (ValueError, KeyError, TypeError) as exc:
            self._send_json(400, {"status": "error", "error": str(exc)})


def create_workbench_server(
    state: WorkbenchState,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> WorkbenchServer:
    """Create a WorkbenchServer bound to `(host, port)` for `state`."""
    return WorkbenchServer((host, port), state)


__all__ = [
    "WorkbenchNotFoundError",
    "WorkbenchRequestHandler",
    "WorkbenchServer",
    "WorkbenchState",
    "create_workbench_server",
]
