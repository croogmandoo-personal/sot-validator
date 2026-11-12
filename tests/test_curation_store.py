"""Unit tests for CurationStore, ItemEditPatch, AuditLogEntry, and apply_curation_overlay."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path
import pytest

from sot_validator.curation import (
    AuditLogEntry,
    CurationStore,
    ItemEditPatch,
    apply_curation_overlay,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)


def _build_sample_site() -> Site:
    return Site(
        site_id="site-042",
        name="Site 42 HQ",
        address="100 Main St",
        contact_info="netops@example.com",
        rooms=["MDF-1"],
        devices=[
            NetworkDevice(
                device_id="dev-sw-01",
                site_id="site-042",
                hostname="sw01.site42.local",
                management_ip="10.42.1.2",
                vendor="Extreme Networks",
                model="X460-G2",
                role="access-switch",
                ports=[
                    Port(
                        port_id="port-sw01-1",
                        device_id="dev-sw-01",
                        name="1/1",
                        admin_status="UP",
                        oper_status="UP",
                        vlan_id="vlan-10",
                    ),
                    Port(
                        port_id="port-sw01-2",
                        device_id="dev-sw-01",
                        name="1/2",
                        admin_status="UP",
                        oper_status="DOWN",
                        vlan_id="vlan-10",
                    ),
                ],
            )
        ],
        vlans=[
            VLAN(
                vlan_id="vlan-10",
                site_id="site-042",
                name="Users",
                subnet_id="sub-10",
                cidr="10.42.10.0/24",
                gateway="10.42.10.1",
            )
        ],
        subnets=[
            Subnet(
                subnet_id="sub-10",
                site_id="site-042",
                cidr="10.42.10.0/24",
                vlan_id="vlan-10",
                gateway="10.42.10.1",
                name="Users-Subnet",
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.10.50",
                subnet_id="sub-10",
                assigned_object_type="Equipment",
                assigned_object_id="eq-srv-01",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-srv-01",
                site_id="site-042",
                name="win-app-01",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.50"],
                connected_ports=["port-sw01-1"],
                power_state="poweredOn",
            ),
            Equipment(
                equipment_id="eq-old-01",
                site_id="site-042",
                name="legacy-nas-01",
                category=EquipmentCategory.SAN,
                assigned_ips=[],
            ),
        ],
    )


def _build_sample_results() -> list[ValidationResult]:
    now = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
    return [
        ValidationResult(
            item_type="NetworkDevice",
            item_id="dev-sw-01",
            site_id="site-042",
            name="sw01.site42.local",
            classification=ValidationClassification.CONFIRMED_ACTIVE,
            confidence=0.95,
            signals=[
                ValidationSignal(
                    signal_type=SignalType.SNMP_API_REACHABILITY,
                    status=SignalStatus.ACTIVE,
                    observed_at=now,
                )
            ],
            rationale="SNMP polling active",
            evaluated_at=now,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-srv-01",
            site_id="site-042",
            name="win-app-01",
            classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
            confidence=0.55,
            signals=[
                ValidationSignal(
                    signal_type=SignalType.ICMP_REACHABILITY,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=now,
                )
            ],
            rationale="ICMP echo blocked by Windows firewall",
            evaluated_at=now,
        ),
        ValidationResult(
            item_type="Equipment",
            item_id="eq-old-01",
            site_id="site-042",
            name="legacy-nas-01",
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=0.9,
            signals=[],
            rationale="No recent signals",
            evaluated_at=now,
        ),
    ]


class TestItemEditPatchAndAuditLogEntry:
    """Tests for ItemEditPatch and AuditLogEntry models and serialization."""

    def test_item_edit_patch_normalization_and_round_trip(self) -> None:
        ts = datetime(2026, 2, 1, 10, 30, tzinfo=timezone.utc)
        patch = ItemEditPatch(
            target_type="equipment",
            target_id="eq-srv-01",
            site_id="site-042",
            name="win-sql-prod-01",
            category="server",
            room="ServerRoom-B",
            notes="Verified active with DBA team",
            pinned_classification="Confirmed Active",
            custom_attributes={"owner": "dba-team", "rack": "R04"},
            deleted=False,
            updated_at=ts,
        )

        assert patch.target_type == "Equipment"
        assert patch.category is EquipmentCategory.SERVER
        assert (
            patch.pinned_classification
            is ValidationClassification.CONFIRMED_ACTIVE
        )

        raw_json = patch.to_json(indent=2)
        restored = ItemEditPatch.from_json(raw_json)
        assert restored == patch
        assert restored.to_dict() == patch.to_dict()

    def test_item_edit_patch_validation_errors(self) -> None:
        with pytest.raises(ValueError, match="Invalid target_type"):
            ItemEditPatch(target_type="UnknownType", target_id="id-1")

        with pytest.raises(ValueError, match="target_id must be a non-empty string"):
            ItemEditPatch(target_type="Port", target_id="   ")

        with pytest.raises(ValueError, match="Invalid category"):
            ItemEditPatch(
                target_type="Equipment",
                target_id="eq-1",
                category="not-a-category",
            )

        with pytest.raises(ValueError, match="Invalid pinned_classification"):
            ItemEditPatch(
                target_type="Equipment",
                target_id="eq-1",
                pinned_classification="Invalid Status",
            )

    def test_audit_log_entry_immutability_and_serialization(self) -> None:
        entry = AuditLogEntry(
            actor="alice",
            action="UPSERT_PATCH",
            target_type="NetworkDevice",
            target_id="dev-sw-01",
            changes={"hostname": "core-sw-01"},
            reason="Standardized naming",
            site_id="site-042",
        )
        assert entry.entry_id.startswith("audit-")
        assert entry.timestamp.tzinfo is not None

        with pytest.raises(FrozenInstanceError):
            entry.actor = "bob"  # type: ignore[misc]

        restored = AuditLogEntry.from_json(entry.to_json())
        assert restored == entry


class TestCurationStoreCRUD:
    """Tests for CurationStore SQLite CRUD, incremental patches, audit log, and JSON export/import."""

    def test_incremental_upsert_patch_and_audit_trail(self, tmp_path: Path) -> None:
        db_file = tmp_path / "curation" / "overlay.db"
        with CurationStore(db_file) as store:
            entry1 = store.upsert_patch(
                ItemEditPatch(
                    target_type="Equipment",
                    target_id="eq-srv-01",
                    site_id="site-042",
                    name="win-app-prod-01",
                    category=EquipmentCategory.SERVER,
                    custom_attributes={"tier": "gold"},
                ),
                actor="netops-admin",
                reason="Renamed VM to physical server role",
            )
            assert entry1.action == "UPSERT_PATCH"
            assert entry1.actor == "netops-admin"
            assert entry1.site_id == "site-042"

            # Second incremental patch pins classification and merges custom_attributes
            # without wiping prior name or category
            entry2 = store.upsert_patch(
                ItemEditPatch(
                    target_type="Equipment",
                    target_id="eq-srv-01",
                    pinned_classification=ValidationClassification.CONFIRMED_ACTIVE,
                    notes="Firewall blocks ping; confirmed via vCenter",
                    custom_attributes={"ticket": "CHG00123"},
                ),
                actor="secops",
                reason="Pin active status",
            )
            assert entry2.site_id == "site-042"

            patches = store.list_patches(site_id="site-042")
            assert len(patches) == 1
            merged = patches[0]
            assert merged.name == "win-app-prod-01"
            assert merged.category is EquipmentCategory.SERVER
            assert (
                merged.pinned_classification
                is ValidationClassification.CONFIRMED_ACTIVE
            )
            assert merged.notes == "Firewall blocks ping; confirmed via vCenter"
            assert merged.custom_attributes == {
                "tier": "gold",
                "ticket": "CHG00123",
            }

            logs = store.list_audit_log(site_id="site-042")
            assert len(logs) == 2
            assert [e.actor for e in logs] == ["netops-admin", "secops"]
            assert store.list_audit_log(site_id="site-042", limit=1) == [logs[0]]

        # Re-open from SQLite file to verify persistence
        with CurationStore(db_file) as reopened:
            assert len(reopened.list_patches(site_id="site-042")) == 1
            assert len(reopened.list_audit_log(site_id="site-042")) == 2

    def test_custom_items_and_delete_item_crud(self, tmp_path: Path) -> None:
        store = CurationStore()

        custom_dev = NetworkDevice(
            device_id="dev-fw-01",
            site_id="site-042",
            hostname="fw01.site42.local",
            management_ip="10.42.1.1",
            vendor="Palo Alto",
            model="PA-440",
            role="firewall",
        )
        e_dev = store.add_custom_device(
            custom_dev, actor="alice", reason="Add perimeter firewall"
        )
        assert e_dev.action == "ADD_DEVICE"
        assert e_dev.target_type == "NetworkDevice"

        custom_port = Port(
            port_id="port-fw01-1",
            device_id="wrong-device-id",
            name="ethernet1/1",
            admin_status="UP",
            oper_status="UP",
            vlan_id="vlan-200",
        )
        e_port = store.add_or_update_port(
            "dev-fw-01", custom_port, actor="alice", reason="Add WAN uplink port"
        )
        assert e_port.action == "UPSERT_PORT"
        assert e_port.site_id == "site-042"
        assert e_port.changes["device_id"] == "dev-fw-01"

        custom_eq = Equipment(
            equipment_id="eq-ups-01",
            site_id="site-042",
            name="apc-ups-mdf1",
            category=EquipmentCategory.UPS,
            assigned_ips=["10.42.1.10"],
        )
        e_eq = store.add_custom_equipment(
            custom_eq, actor="bob", reason="Add rack UPS"
        )
        assert e_eq.action == "ADD_EQUIPMENT"

        custom_vlan = VLAN(
            vlan_id="vlan-200",
            site_id="site-042",
            name="Voice",
            subnet_id="sub-200",
            cidr="10.42.200.0/24",
            gateway="10.42.200.1",
        )
        custom_subnet = Subnet(
            subnet_id="sub-200",
            site_id="site-042",
            cidr="10.42.200.0/24",
            vlan_id="vlan-200",
            gateway="10.42.200.1",
            name="Voice-Subnet",
        )
        e_vlan = store.add_custom_vlan(
            custom_vlan, subnet=custom_subnet, actor="charlie"
        )
        assert e_vlan.action == "ADD_VLAN"
        assert "subnet" in e_vlan.changes

        e_del = store.delete_item(
            "Equipment",
            "eq-old-01",
            actor="dave",
            reason="Decommissioned NAS",
            site_id="site-042",
        )
        assert e_del.action == "DELETE_ITEM"
        del_patch = store.get_patch("Equipment", "eq-old-01")
        assert del_patch is not None and del_patch.deleted is True

        # Export to JSON and import into a fresh CurationStore
        json_path = tmp_path / "export" / "curation_state.json"
        store.export_json(json_path)
        assert json_path.is_file()

        imported_cls = CurationStore.import_json(json_path)
        assert imported_cls.to_dict() == store.to_dict()

        imported_inst = CurationStore()
        imported_inst.import_json(json_path)
        assert imported_inst.to_dict() == store.to_dict()

        store.close()
        imported_cls.close()
        imported_inst.close()


class TestApplyCurationOverlay:
    """Tests for non-destructive and idempotent apply_curation_overlay execution."""

    def test_apply_curation_overlay_merges_edits_pins_deletions_and_custom_items(
        self,
    ) -> None:
        original_site = _build_sample_site()
        original_results = _build_sample_results()
        site_snapshot_before = original_site.to_dict()
        results_snapshot_before = [r.to_dict() for r in original_results]

        store = CurationStore()

        # 1. Add custom VLAN + Subnet
        store.add_custom_vlan(
            VLAN(
                vlan_id="vlan-50",
                site_id="site-042",
                name="Management",
                subnet_id="sub-50",
                cidr="10.42.50.0/24",
            ),
            subnet=Subnet(
                subnet_id="sub-50",
                site_id="site-042",
                cidr="10.42.50.0/24",
                vlan_id="vlan-50",
                name="Mgmt-Subnet",
            ),
        )

        # 2. Add custom NetworkDevice and a custom Port on existing switch
        store.add_custom_device(
            NetworkDevice(
                device_id="dev-rtr-01",
                site_id="site-042",
                hostname="rtr01.site42.local",
                management_ip="10.42.1.1",
                vendor="Extreme Networks",
                model="X690",
                role="router",
            )
        )
        store.add_or_update_port(
            "dev-sw-01",
            Port(
                port_id="port-sw01-3",
                device_id="dev-sw-01",
                name="1/3",
                admin_status="UP",
                oper_status="UP",
                vlan_id="vlan-50",
            ),
            site_id="site-042",
        )

        # 3. Add custom Equipment and pin its classification
        store.add_custom_equipment(
            Equipment(
                equipment_id="eq-ups-01",
                site_id="site-042",
                name="apc-smartups-01",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.50.10"],
            )
        )
        store.upsert_patch(
            ItemEditPatch(
                target_type="Equipment",
                target_id="eq-ups-01",
                site_id="site-042",
                pinned_classification=ValidationClassification.CONFIRMED_ACTIVE,
                notes="New APC UPS installed in IDF-2",
                room="IDF-2",
            )
        )

        # 4. Patch existing NetworkDevice, Port, VLAN, Subnet, IPAddress, and Equipment
        store.upsert_patch(
            ItemEditPatch(
                target_type="NetworkDevice",
                target_id="dev-sw-01",
                site_id="site-042",
                hostname="core-sw01.site42.local",
                role="core-switch",
                vendor="Extreme",
                model="X460-G2-48p",
                room="MDF-2",
            )
        )
        store.upsert_patch(
            ItemEditPatch(
                target_type="Port",
                target_id="port-sw01-1",
                site_id="site-042",
                name="1/1-uplink",
                vlan_id="vlan-50",
            )
        )
        store.upsert_patch(
            ItemEditPatch(
                target_type="VLAN",
                target_id="vlan-10",
                site_id="site-042",
                name="Corp-Users",
                subnet_id="sub-50",
            )
        )
        store.upsert_patch(
            ItemEditPatch(
                target_type="Subnet",
                target_id="sub-10",
                site_id="site-042",
                name="Corp-Users-Net",
                vlan_id="vlan-50",
            )
        )
        store.upsert_patch(
            ItemEditPatch(
                target_type="IPAddress",
                target_id="10.42.10.50",
                site_id="site-042",
                subnet_id="sub-50",
            )
        )
        store.upsert_patch(
            ItemEditPatch(
                target_type="Equipment",
                target_id="eq-srv-01",
                site_id="site-042",
                name="win-dc-01",
                category=EquipmentCategory.SERVER,
                pinned_classification=ValidationClassification.CONFIRMED_ACTIVE,
                notes="Domain controller drops ICMP",
            )
        )

        # 5. Delete stale equipment and unused port
        store.delete_item("Equipment", "eq-old-01", site_id="site-042")
        store.delete_item("Port", "port-sw01-2", site_id="site-042")

        curated_site, curated_results = apply_curation_overlay(
            original_site, store, original_results
        )

        # Verify original inputs were NOT mutated
        assert original_site.to_dict() == site_snapshot_before
        assert [r.to_dict() for r in original_results] == results_snapshot_before

        # Verify site rooms include newly patched rooms without duplicates
        assert curated_site.rooms == ["MDF-1", "MDF-2", "IDF-2"]

        # Verify devices and ports
        devs_by_id = {d.device_id: d for d in curated_site.devices}
        assert set(devs_by_id) == {"dev-sw-01", "dev-rtr-01"}
        sw01 = devs_by_id["dev-sw-01"]
        assert sw01.hostname == "core-sw01.site42.local"
        assert sw01.role == "core-switch"
        assert sw01.vendor == "Extreme"
        assert sw01.model == "X460-G2-48p"

        ports_by_id = {p.port_id: p for p in sw01.ports}
        assert set(ports_by_id) == {"port-sw01-1", "port-sw01-3"}
        assert ports_by_id["port-sw01-1"].name == "1/1-uplink"
        assert ports_by_id["port-sw01-1"].vlan_id == "vlan-50"

        # Verify VLANs, Subnets, and IPAddresses
        vlans_by_id = {v.vlan_id: v for v in curated_site.vlans}
        assert set(vlans_by_id) == {"vlan-10", "vlan-50"}
        assert vlans_by_id["vlan-10"].name == "Corp-Users"
        assert vlans_by_id["vlan-10"].subnet_id == "sub-50"

        subnets_by_id = {s.subnet_id: s for s in curated_site.subnets}
        assert set(subnets_by_id) == {"sub-10", "sub-50"}
        assert subnets_by_id["sub-10"].name == "Corp-Users-Net"
        assert subnets_by_id["sub-10"].vlan_id == "vlan-50"

        assert curated_site.ip_addresses[0].subnet_id == "sub-50"

        # Verify Equipment
        eq_by_id = {e.equipment_id: e for e in curated_site.equipment}
        assert set(eq_by_id) == {"eq-srv-01", "eq-ups-01"}
        assert eq_by_id["eq-srv-01"].name == "win-dc-01"
        assert eq_by_id["eq-srv-01"].category is EquipmentCategory.SERVER

        # Verify ValidationResults: deleted item removed, existing item updated & pinned, custom pinned item synthesized
        res_by_key = {(r.item_type, r.item_id): r for r in curated_results}
        assert ("Equipment", "eq-old-01") not in res_by_key
        assert res_by_key[("NetworkDevice", "dev-sw-01")].name == "core-sw01.site42.local"

        srv_res = res_by_key[("Equipment", "eq-srv-01")]
        assert srv_res.name == "win-dc-01"
        assert (
            srv_res.classification is ValidationClassification.CONFIRMED_ACTIVE
        )
        assert srv_res.confidence == 1.0
        assert "Pinned to Confirmed Active by operator" in (srv_res.rationale or "")
        assert "Domain controller drops ICMP" in (srv_res.rationale or "")

        ups_res = res_by_key[("Equipment", "eq-ups-01")]
        assert ups_res.name == "apc-smartups-01"
        assert (
            ups_res.classification is ValidationClassification.CONFIRMED_ACTIVE
        )
        assert ups_res.confidence == 1.0

        # Verify idempotence across repeated scans and repeated overlay application
        second_site, second_results = apply_curation_overlay(
            curated_site, store, curated_results
        )
        assert second_site.to_dict() == curated_site.to_dict()
        assert [r.to_dict() for r in second_results] == [
            r.to_dict() for r in curated_results
        ]

        rescan_site, rescan_results = apply_curation_overlay(
            original_site, store, original_results
        )
        assert rescan_site.to_dict() == curated_site.to_dict()
        assert [r.to_dict() for r in rescan_results] == [
            r.to_dict() for r in curated_results
        ]

        store.close()
