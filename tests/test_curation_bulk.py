"""Unit tests for bulk CSV curation import: parse, preview, and confirm-token apply."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io

import pytest

from sot_validator.curation import (
    BulkApplyRefused,
    CsvPatchRow,
    CurationStore,
    ItemEditPatch,
    PatchCsvError,
    apply_curation_overlay,
    apply_patches,
    parse_patch_csv,
    preview_patches,
    verify_audit_chain,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
)

HEADER = "record_type,record_id,field,new_value,reason\n"


def _site() -> Site:
    return Site(
        site_id="site-1",
        name="Bulk Lab",
        devices=[
            NetworkDevice(
                device_id="dev-1",
                site_id="site-1",
                hostname="sw-01",
                management_ip="10.1.1.2",
                vendor="Extreme Networks",
                role="switch",
                ports=[
                    Port(port_id="p-1", device_id="dev-1", name="1:1", vlan_id="10")
                ],
            ),
            NetworkDevice(
                device_id="dev-2",
                site_id="site-1",
                hostname="sw-02",
                management_ip="10.1.1.3",
            ),
        ],
        vlans=[VLAN(vlan_id="10", site_id="site-1", name="Users", subnet_id="sub-10")],
        subnets=[
            Subnet(subnet_id="sub-10", site_id="site-1", cidr="10.1.10.0/24", vlan_id="10")
        ],
        ip_addresses=[IPAddress(ip="10.1.10.5", subnet_id="sub-10")],
        equipment=[
            Equipment(
                equipment_id="eq-1",
                site_id="site-1",
                name="ups-01",
                category=EquipmentCategory.UPS,
            )
        ],
    )


def _csv(*rows: str) -> io.StringIO:
    return io.StringIO(HEADER + "".join(f"{row}\n" for row in rows))


def _errors(text: str) -> list[tuple[int, str]]:
    with pytest.raises(PatchCsvError) as excinfo:
        parse_patch_csv(io.StringIO(text))
    return excinfo.value.errors


def _preview(store: CurationStore, *rows: str, as_of=None):
    return preview_patches(store, _site(), parse_patch_csv(_csv(*rows)), as_of)


# --- parsing ---------------------------------------------------------------


def test_parse_returns_single_field_patches_with_rows_and_reasons() -> None:
    text = (
        "﻿ Field , RECORD_ID,record_type,reason,new_value\n"
        "hostname,dev-1,device, renamed ,  sw-core \n"
        ",,,,\n"
        "deleted,eq-1,equipment,,YES\n"
        "category,eq-1,Equipment,,server\n"
        "pinned_classification,10.1.10.5,ip,,confirmed active\n"
    )
    patches = parse_patch_csv(io.StringIO(text))
    assert all(isinstance(p, (CsvPatchRow, ItemEditPatch)) for p in patches)
    assert [p.row_number for p in patches] == [2, 4, 5, 6]
    first = patches[0]
    assert (first.target_type, first.target_id, first.field_name) == (
        "NetworkDevice",
        "dev-1",
        "hostname",
    )
    assert first.hostname == "sw-core"
    assert first.reason == "renamed"
    assert first.name is None and first.deleted is False
    assert patches[1].deleted is True
    assert patches[2].category == EquipmentCategory.SERVER
    assert patches[3].target_type == "IPAddress"
    assert patches[3].pinned_classification.value == "Confirmed Active"


@pytest.mark.parametrize("raw", ["false", "FALSE", "no", "0"])
def test_falsey_strings_parse_as_false_not_truthy(raw: str) -> None:
    patches = parse_patch_csv(_csv(f"device,dev-1,deleted,{raw},"))
    assert patches[0].deleted is False


def test_bad_header_columns_are_row_1_errors() -> None:
    errors = _errors("record_type,record_id,field,new_value\ndevice,dev-1,hostname,x\n")
    assert errors == [(1, "missing header column 'reason'")]
    errors = _errors(
        "record_type,record_id,field,new_value,reason,reason,extra\n"
        "device,dev-1,hostname,x,,,\n"
    )
    assert [row for row, _ in errors] == [1, 1]
    assert any("duplicate" in m for _, m in errors)
    assert any("unknown header column 'extra'" in m for _, m in errors)


def test_bad_header_and_bad_rows_are_reported_together() -> None:
    errors = _errors(
        "record_type,record_id,field,new_value,reason,extra\n"
        "device,dev-1,bogus,x,,\n"
        "device,dev-1,deleted,maybe,,\n"
    )
    assert [row for row, _ in errors] == [1, 2, 3]


def test_empty_file_and_header_only_file_are_errors() -> None:
    assert _errors("") == [(1, "file is empty; expected a header row")]
    errors = _errors(HEADER + "\n,,,,\n")
    assert errors == [(1, "file has a header but no data rows")]


def test_unknown_record_type_is_reported_with_row() -> None:
    errors = _errors(HEADER + "router,r-1,hostname,x,\n")
    assert errors == [(2, "unknown record_type 'router'")]


def test_field_not_allowed_for_type_is_reported_with_row() -> None:
    errors = _errors(HEADER + "port,p-1,hostname,x,\n")
    assert len(errors) == 1
    assert errors[0][0] == 2
    assert "not allowed for Port" in errors[0][1]


def test_bad_boolean_classification_and_category_are_reported() -> None:
    errors = _errors(
        HEADER
        + "device,dev-1,deleted,maybe,\n"
        + "device,dev-1,pinned_classification,probably fine,\n"
        + "equipment,eq-1,category,toaster,\n"
    )
    assert [row for row, _ in errors] == [2, 3, 4]
    assert "deleted must be one of" in errors[0][1]
    assert "invalid pinned_classification" in errors[1][1]
    assert "invalid category" in errors[2][1]


def test_empty_values_and_wrong_cell_count_are_reported() -> None:
    errors = _errors(
        HEADER
        + "device,dev-1,hostname,   ,\n"
        + "device,,hostname,x,\n"
        + "device,dev-1,,x,\n"
        + "device,dev-1,hostname\n"
    )
    assert errors == [
        (2, "new_value must not be empty"),
        (3, "record_id must not be empty"),
        (4, "field must not be empty"),
        (5, "expected 5 cells, found 3"),
    ]


def test_several_bad_rows_reported_together_and_str_lists_each() -> None:
    text = (
        HEADER
        + "device,dev-1,hostname,ok,\n"
        + "\n"
        + "widget,w-1,name,x,\n"
        + "device,dev-1,deleted,maybe,\n"
    )
    with pytest.raises(PatchCsvError) as excinfo:
        parse_patch_csv(io.StringIO(text))
    assert [row for row, _ in excinfo.value.errors] == [4, 5]
    assert str(excinfo.value).splitlines() == [
        "row 4: unknown record_type 'widget'",
        "row 5: deleted must be one of true/false/yes/no/1/0, got 'maybe'",
    ]


def test_row_numbers_count_csv_records_not_physical_lines() -> None:
    errors = _errors(
        HEADER + 'device,dev-1,notes,"line one\nline two",\n' + "device,dev-1,bogus,x,\n"
    )
    assert [row for row, _ in errors] == [3]


# --- preview ---------------------------------------------------------------


def test_preview_statuses_change_no_op_and_invalid() -> None:
    store = CurationStore()
    preview = _preview(
        store,
        "device,dev-1,hostname,sw-core,rename",
        "device,dev-1,vendor,Extreme Networks,",
        "device,ghost,hostname,x,",
        "port,p-1,vlan_id,20,",
        "equipment,eq-1,category,UPS,",
        "device,dev-2,deleted,false,",
    )
    statuses = [(r.row_number, r.status) for r in preview.rows]
    assert statuses == [
        (2, "change"),
        (3, "no_op"),
        (4, "invalid"),
        (5, "change"),
        (6, "no_op"),
        (7, "no_op"),
    ]
    first = preview.rows[0]
    assert (first.old_value, first.new_value, first.reason, first.detail) == (
        "sw-01",
        "sw-core",
        "rename",
        "",
    )
    assert preview.rows[2].detail
    assert preview.counts == {"change": 2, "no_op": 3, "conflict": 0, "invalid": 1}
    assert preview.can_apply is False
    assert store.to_dict()["audit_log"] == []
    data = preview.to_dict()
    assert set(data) == {"site_id", "as_of", "rows", "confirm_token", "counts", "can_apply"}


def test_patch_only_fields_read_old_value_from_stored_patch() -> None:
    store = CurationStore()
    store.upsert_patch(
        ItemEditPatch(
            target_type="NetworkDevice",
            target_id="dev-1",
            site_id="site-1",
            room="MDF",
            notes="keep",
            pinned_classification="Confirmed Active",
        )
    )
    preview = _preview(
        store,
        "device,dev-1,room,MDF,",
        "device,dev-1,notes,changed,",
        "device,dev-1,pinned_classification,confirmed active,",
        "device,dev-2,room,IDF,",
    )
    assert [r.status for r in preview.rows] == ["no_op", "change", "no_op", "change"]
    assert preview.rows[1].old_value == "keep"
    assert preview.rows[3].old_value is None


def test_as_of_conflict_uses_newest_audit_entry() -> None:
    store = CurationStore()
    as_of = datetime.now(timezone.utc) - timedelta(hours=1)
    store.upsert_patch(
        ItemEditPatch(target_type="Port", target_id="p-1", site_id="site-1", name="up")
    )
    preview = _preview(
        store, "port,p-1,name,uplink,", "device,dev-1,hostname,x,", as_of=as_of.isoformat()
    )
    assert [r.status for r in preview.rows] == ["conflict", "change"]
    assert "after as_of" in preview.rows[0].detail
    assert preview.as_of == as_of
    later = _preview(store, "port,p-1,name,uplink,", as_of=datetime.now(timezone.utc))
    assert later.rows[0].status == "change"


def test_duplicate_field_rows_all_conflict() -> None:
    store = CurationStore()
    preview = _preview(
        store,
        "device,dev-1,hostname,a,",
        "device,dev-1,vendor,Cisco,",
        "network_device,dev-1,hostname,b,",
    )
    assert [r.status for r in preview.rows] == ["conflict", "change", "conflict"]
    assert "rows 2, 4" in preview.rows[0].detail


def test_deleted_plus_other_rows_conflict() -> None:
    store = CurationStore()
    preview = _preview(
        store,
        "device,dev-1,deleted,true,",
        "device,dev-1,hostname,x,",
        "device,dev-2,hostname,y,",
    )
    assert [r.status for r in preview.rows] == ["conflict", "conflict", "change"]


def test_different_fields_of_one_record_do_not_conflict() -> None:
    store = CurationStore()
    preview = _preview(
        store,
        "device,dev-1,hostname,sw-core,",
        "device,dev-1,role,core,",
        "device,dev-1,model,X465,",
    )
    assert [r.status for r in preview.rows] == ["change", "change", "change"]
    assert preview.can_apply is True


def test_deleted_record_rows_are_invalid_except_restore() -> None:
    store = CurationStore()
    store.delete_item("NetworkDevice", "dev-1", site_id="site-1")
    preview = _preview(store, "device,dev-1,hostname,x,")
    assert preview.rows[0].status == "invalid"
    assert preview.rows[0].old_value == "sw-01"
    restore = _preview(store, "device,dev-1,deleted,false,")
    assert restore.rows[0].status == "change"
    assert restore.rows[0].old_value is True
    again = _preview(store, "device,dev-1,deleted,true,")
    assert again.rows[0].status == "no_op"


def test_token_is_stable_and_changes_with_store() -> None:
    store = CurationStore()
    rows = ("device,dev-1,hostname,sw-core,", "vlan,10,name,Staff,")
    first = _preview(store, *rows)
    second = _preview(store, *rows)
    assert first.confirm_token == second.confirm_token
    assert len(first.confirm_token) == 64
    store.upsert_patch(
        ItemEditPatch(target_type="VLAN", target_id="10", site_id="site-1", name="Guests")
    )
    third = _preview(store, *rows)
    assert third.confirm_token != first.confirm_token
    reasoned = _preview(store, "device,dev-1,hostname,sw-core,other reason", rows[1])
    assert reasoned.confirm_token != third.confirm_token


# --- apply -----------------------------------------------------------------


def test_token_mismatch_is_refused_and_store_unchanged() -> None:
    store = CurationStore()
    preview = _preview(store, "device,dev-1,hostname,sw-core,")
    before = store.to_dict()
    for bad in ("0" * 64, "", None, preview.confirm_token + "\n"):
        with pytest.raises(BulkApplyRefused):
            apply_patches(store, preview, "op", bad)
    assert store.to_dict() == before


def test_stale_store_is_refused() -> None:
    store = CurationStore()
    preview = _preview(store, "device,dev-1,hostname,sw-core,")
    store.upsert_patch(
        ItemEditPatch(
            target_type="NetworkDevice", target_id="dev-1", site_id="site-1", hostname="other"
        )
    )
    before = store.to_dict()
    with pytest.raises(BulkApplyRefused, match="changed since"):
        apply_patches(store, preview, "op", preview.confirm_token)
    assert store.to_dict() == before


@pytest.mark.parametrize(
    "rows",
    [
        ("device,ghost,hostname,x,", "device,dev-1,hostname,y,"),
        ("device,dev-1,hostname,x,", "device,dev-1,hostname,y,"),
    ],
)
def test_preview_with_conflict_or_invalid_rows_is_refused(rows: tuple[str, ...]) -> None:
    store = CurationStore()
    preview = _preview(store, *rows)
    with pytest.raises(BulkApplyRefused):
        apply_patches(store, preview, "op", preview.confirm_token)
    assert store.to_dict()["audit_log"] == []
    assert store.list_patches() == []


def test_failure_mid_batch_rolls_back_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    store = CurationStore()
    store.upsert_patch(
        ItemEditPatch(target_type="VLAN", target_id="10", site_id="site-1", name="Users")
    )
    before = store.to_dict()
    preview = _preview(store, "device,dev-1,hostname,sw-core,", "port,p-1,name,uplink,")
    original = CurationStore._record_audit
    calls = {"n": 0}

    def flaky(self, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk full")
        return original(self, **kwargs)

    monkeypatch.setattr(CurationStore, "_record_audit", flaky)
    with pytest.raises(RuntimeError, match="disk full"):
        apply_patches(store, preview, "op", preview.confirm_token)
    monkeypatch.undo()
    assert store.to_dict() == before
    assert verify_audit_chain(store).ok


def test_apply_writes_one_entry_per_change_with_shared_batch_id() -> None:
    store = CurationStore()
    store.upsert_patch(
        ItemEditPatch(target_type="Subnet", target_id="sub-10", site_id="site-1", name="old"),
        reason="seed",
    )
    preview = _preview(
        store,
        "device,dev-1,hostname,sw-core,rename core",
        "device,dev-1,vendor,Extreme Networks,unchanged",
        "equipment,eq-1,category,server,recategorise",
        "subnet,sub-10,name,Users /24,",
        "ip,10.1.10.5,notes,reserved,note it",
    )
    assert preview.can_apply
    result = apply_patches(store, preview, "alice", preview.confirm_token)
    assert result.batch_id.startswith("batch-") and len(result.batch_id) == 18
    assert len(result.entries) == 4
    assert {e.changes["batch_id"] for e in result.entries} == {result.batch_id}
    assert [e.reason for e in result.entries] == [
        "rename core",
        "recategorise",
        "",
        "note it",
    ]
    assert {e.actor for e in result.entries} == {"alice"}
    assert result.entries[0].changes == {
        "site_id": "site-1",
        "hostname": "sw-core",
        "batch_id": result.batch_id,
    }
    log = store.list_audit_log()
    assert len(log) == 5
    assert "batch_id" not in log[0].changes
    report = verify_audit_chain(store)
    assert report.ok and report.entries_checked == 5

    curated, _ = apply_curation_overlay(_site(), store)
    assert curated.devices[0].hostname == "sw-core"
    assert curated.equipment[0].category == EquipmentCategory.SERVER
    assert curated.subnets[0].name == "Users /24"
    assert store.get_patch("Subnet", "sub-10").name == "Users /24"


def test_no_op_only_preview_applies_nothing() -> None:
    store = CurationStore()
    preview = _preview(store, "device,dev-1,hostname,sw-01,")
    assert preview.can_apply is False
    result = apply_patches(store, preview, "op", preview.confirm_token)
    assert result.entries == []
    assert store.to_dict()["audit_log"] == []


def test_deleted_true_row_hides_record_and_restore_brings_it_back() -> None:
    store = CurationStore()
    preview = _preview(store, "equipment,eq-1,deleted,1,retired")
    result = apply_patches(store, preview, "op", preview.confirm_token)
    assert result.entries[0].action == "DELETE_ITEM"
    assert result.entries[0].changes == {"deleted": True, "batch_id": result.batch_id}
    curated, _ = apply_curation_overlay(_site(), store)
    assert curated.equipment == []

    restore = _preview(store, "equipment,eq-1,deleted,no,back")
    assert restore.rows[0].status == "change"
    restored = apply_patches(store, restore, "op", restore.confirm_token)
    assert restored.entries[0].changes["deleted"] is False
    curated, _ = apply_curation_overlay(_site(), store)
    assert [e.equipment_id for e in curated.equipment] == ["eq-1"]
    assert verify_audit_chain(store).ok
