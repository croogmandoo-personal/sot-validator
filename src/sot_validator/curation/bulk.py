"""Bulk CSV curation import: parse, diff-preview against the store, and confirm-token apply.

CSV format
----------
The header row must contain exactly these columns, in any order (names are
matched case-insensitively after stripping whitespace; a leading UTF-8 BOM is
ignored)::

    record_type, record_id, field, new_value, reason

Each data row is one field edit of one existing record. Row numbers are
spreadsheet rows: the header is row 1 and data records count from row 2.
Fully blank records are skipped but still counted.

Allowed fields per record type (``record_type`` accepts any name
``ItemEditPatch`` accepts, e.g. ``device``, ``ip``, ``network_device``):

==============  ==========================================
Record type     Fields
==============  ==========================================
NetworkDevice   hostname, role, vendor, model, room
Port            name, vlan_id
VLAN            name, subnet_id
Subnet          name, vlan_id
IPAddress       subnet_id (``record_id`` is the IP)
Equipment       name, category, room
All types       notes, pinned_classification, deleted
==============  ==========================================

Value rules:

- ``record_id`` and ``field`` must not be empty.
- ``new_value`` is stripped and must not be empty (a field cannot be cleared).
- ``deleted`` accepts ``true/false/yes/no/1/0``, case-insensitively.
- ``pinned_classification`` must name a ``ValidationClassification`` and
  ``category`` an ``EquipmentCategory``; the enum value is stored.
- ``reason`` may be blank; it becomes the audit reason for that row.

``preview_patches`` marks every row ``change``, ``no_op``, ``conflict`` or
``invalid`` and computes a SHA-256 ``confirm_token``; ``apply_patches`` writes
the ``change`` rows in one transaction only when that token still matches, and
stores a shared ``batch_id`` in each audit entry's ``changes``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Optional
import uuid

from sot_validator.curation.store import (
    AuditLogEntry,
    CurationStore,
    ItemEditPatch,
    _coerce_equipment_category,
    _coerce_validation_classification,
    _normalize_target_type,
    apply_curation_overlay,
)
from sot_validator.models import (
    EquipmentCategory,
    Site,
    ValidationClassification,
    _format_optional_datetime,
)
from sot_validator.signals.base import normalize_utc_datetime

CSV_COLUMNS: tuple[str, ...] = (
    "record_type",
    "record_id",
    "field",
    "new_value",
    "reason",
)

_COMMON_FIELDS: tuple[str, ...] = ("notes", "pinned_classification", "deleted")

ALLOWED_FIELDS: dict[str, tuple[str, ...]] = {
    "NetworkDevice": ("hostname", "role", "vendor", "model", "room") + _COMMON_FIELDS,
    "Port": ("name", "vlan_id") + _COMMON_FIELDS,
    "VLAN": ("name", "subnet_id") + _COMMON_FIELDS,
    "Subnet": ("name", "vlan_id") + _COMMON_FIELDS,
    "IPAddress": ("subnet_id",) + _COMMON_FIELDS,
    "Equipment": ("name", "category", "room") + _COMMON_FIELDS,
}

# Fields the overlay does not reflect on the record; their old value is read from the stored patch.
_PATCH_ONLY_FIELDS: tuple[str, ...] = ("room", "notes", "pinned_classification")

_TRUE_VALUES = frozenset({"true", "yes", "1"})
_FALSE_VALUES = frozenset({"false", "no", "0"})

PREVIEW_STATUSES: tuple[str, ...] = ("change", "no_op", "conflict", "invalid")


class PatchCsvError(ValueError):
    """Raised when a bulk patch CSV has one or more problems; `errors` lists `(row, message)`."""

    def __init__(self, errors: Sequence[tuple[int, str]]) -> None:
        self.errors: list[tuple[int, str]] = sorted(errors, key=lambda item: item[0])
        super().__init__(
            "\n".join(f"row {row}: {message}" for row, message in self.errors)
        )


class BulkApplyRefused(ValueError):
    """Raised when a bulk apply is refused; nothing has been written."""


@dataclass
class CsvPatchRow(ItemEditPatch):
    """One parsed CSV row: an ItemEditPatch carrying exactly one field plus its source row."""

    row_number: int = 0
    field_name: str = ""
    reason: str = ""


def _normalize_value(field_name: str, raw: str) -> Any:
    if field_name == "deleted":
        lowered = raw.lower()
        if lowered in _TRUE_VALUES:
            return True
        if lowered in _FALSE_VALUES:
            return False
        raise ValueError(
            f"deleted must be one of true/false/yes/no/1/0, got {raw!r}"
        )
    if field_name == "pinned_classification":
        try:
            return _coerce_validation_classification(raw).value
        except ValueError:
            allowed = ", ".join(c.value for c in ValidationClassification)
            raise ValueError(
                f"invalid pinned_classification {raw!r}; expected one of: {allowed}"
            ) from None
    if field_name == "category":
        try:
            return _coerce_equipment_category(raw).value
        except ValueError:
            allowed = ", ".join(c.value for c in EquipmentCategory)
            raise ValueError(
                f"invalid category {raw!r}; expected one of: {allowed}"
            ) from None
    return raw


def _parse_data_row(
    row_number: int, cells: dict[str, str]
) -> tuple[Optional[CsvPatchRow], list[str]]:
    problems: list[str] = []
    raw_type = cells["record_type"].strip()
    record_id = cells["record_id"].strip()
    field_name = cells["field"].strip()
    new_value = cells["new_value"].strip()
    reason = cells["reason"].strip()

    record_type: Optional[str] = None
    if not raw_type:
        problems.append("record_type must not be empty")
    else:
        try:
            record_type = _normalize_target_type(raw_type, "record_type")
        except ValueError:
            problems.append(f"unknown record_type {raw_type!r}")
    if not record_id:
        problems.append("record_id must not be empty")
    if not field_name:
        problems.append("field must not be empty")
    elif record_type is not None and field_name not in ALLOWED_FIELDS[record_type]:
        allowed = ", ".join(ALLOWED_FIELDS[record_type])
        problems.append(
            f"field {field_name!r} is not allowed for {record_type}; allowed: {allowed}"
        )
    if not new_value:
        problems.append("new_value must not be empty")

    value: Any = None
    if not problems:
        try:
            value = _normalize_value(field_name, new_value)
        except ValueError as exc:
            problems.append(str(exc))
    if problems:
        return None, problems

    kwargs: dict[str, Any] = {field_name: value}
    patch = CsvPatchRow(
        target_type=record_type,
        target_id=record_id,
        row_number=row_number,
        field_name=field_name,
        reason=reason,
        **kwargs,
    )
    return patch, []


def parse_patch_csv(stream: Iterable[str]) -> list[CsvPatchRow]:
    """Parse and fully validate a bulk patch CSV; raise PatchCsvError listing every problem."""
    errors: list[tuple[int, str]] = []
    records: list[list[str]] = []
    reader = csv.reader(stream)
    try:
        for record in reader:
            records.append(record)
    except csv.Error as exc:
        raise PatchCsvError([(len(records) + 1, f"malformed CSV: {exc}")]) from None

    if not records:
        raise PatchCsvError([(1, "file is empty; expected a header row")])

    header = [cell.strip().lower() for cell in records[0]]
    if header:
        header[0] = header[0].lstrip("﻿").strip()
    column_index: dict[str, int] = {}
    for position, name in enumerate(header):
        if name not in CSV_COLUMNS:
            errors.append((1, f"unknown header column {name!r}"))
        elif name in column_index:
            errors.append((1, f"duplicate header column {name!r}"))
        else:
            column_index[name] = position
    missing = [name for name in CSV_COLUMNS if name not in column_index]
    for name in missing:
        errors.append((1, f"missing header column {name!r}"))
    if missing:
        # Without every column the data rows cannot be read; report the header alone.
        raise PatchCsvError(errors)

    patches: list[CsvPatchRow] = []
    data_rows = 0
    for row_number, record in enumerate(records[1:], start=2):
        if all(not cell.strip() for cell in record):
            continue
        data_rows += 1
        if len(record) != len(header):
            errors.append(
                (row_number, f"expected {len(header)} cells, found {len(record)}")
            )
            continue
        cells = {name: record[position] for name, position in column_index.items()}
        patch, problems = _parse_data_row(row_number, cells)
        for problem in problems:
            errors.append((row_number, problem))
        if patch is not None:
            patches.append(patch)

    if data_rows == 0:
        errors.append((1, "file has a header but no data rows"))
    if errors:
        raise PatchCsvError(errors)
    return patches


@dataclass
class PreviewRow:
    """Diff of one CSV row against the current curated state."""

    row_number: int
    record_type: str
    record_id: str
    field: str
    old_value: Any
    new_value: Any
    status: str
    reason: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "row_number": self.row_number,
            "record_type": self.record_type,
            "record_id": self.record_id,
            "field": self.field,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "status": self.status,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass
class PatchPreview:
    """Preview of a parsed CSV against the store, sealed by a SHA-256 confirm token."""

    site_id: str
    as_of: Optional[datetime]
    rows: list[PreviewRow]
    confirm_token: str
    counts: dict[str, int]
    can_apply: bool
    patches: list[CsvPatchRow] = field(default_factory=list, repr=False, compare=False)
    site: Optional[Site] = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "as_of": _format_optional_datetime(self.as_of),
            "rows": [row.to_dict() for row in self.rows],
            "confirm_token": self.confirm_token,
            "counts": dict(self.counts),
            "can_apply": self.can_apply,
        }


@dataclass
class BulkApplyResult:
    """Outcome of a successful bulk apply: the batch id and one audit entry per changed row."""

    batch_id: str
    entries: list[AuditLogEntry]

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def _index_site(site: Site) -> dict[tuple[str, str], Any]:
    index: dict[tuple[str, str], Any] = {}
    for dev in site.devices:
        index.setdefault(("NetworkDevice", dev.device_id), dev)
        for port in dev.ports:
            index.setdefault(("Port", port.port_id), port)
    for vlan in site.vlans:
        index.setdefault(("VLAN", vlan.vlan_id), vlan)
    for subnet in site.subnets:
        index.setdefault(("Subnet", subnet.subnet_id), subnet)
    for ip_rec in site.ip_addresses:
        index.setdefault(("IPAddress", ip_rec.ip), ip_rec)
    for eq in site.equipment:
        index.setdefault(("Equipment", eq.equipment_id), eq)
    return index


def _plain(value: Any) -> Any:
    if isinstance(value, (EquipmentCategory, ValidationClassification)):
        return value.value
    return value


def _old_value(
    field_name: str,
    record: Any,
    stored: Optional[ItemEditPatch],
    is_deleted_record: bool,
) -> Any:
    if field_name == "deleted":
        return stored.deleted if stored is not None else False
    stored_value = (
        _plain(getattr(stored, field_name)) if stored is not None else None
    )
    if field_name in _PATCH_ONLY_FIELDS:
        return stored_value
    if is_deleted_record and stored_value is not None:
        return stored_value
    return _plain(getattr(record, field_name, None))


def _latest_audit_timestamp(
    store: CurationStore, target_type: str, target_id: str
) -> Optional[datetime]:
    rows = store._conn.execute(
        "SELECT timestamp FROM audit_log WHERE target_type = ? AND target_id = ?",
        (target_type, target_id),
    ).fetchall()
    stamps = [normalize_utc_datetime(r["timestamp"]) for r in rows]
    return max(stamps) if stamps else None


def _compute_confirm_token(
    site_id: str, as_of: Optional[datetime], rows: Sequence[PreviewRow]
) -> str:
    canonical = json.dumps(
        {
            "site_id": site_id,
            "as_of": _format_optional_datetime(as_of),
            "rows": [row.to_dict() for row in rows],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def preview_patches(
    store: CurationStore,
    site: Site,
    patches: Sequence[CsvPatchRow],
    as_of: Optional[datetime | str] = None,
) -> PatchPreview:
    """Diff parsed CSV rows against the curated `site` without writing to `store`."""
    if not isinstance(store, CurationStore):
        raise ValueError("store must be a CurationStore instance")
    if not isinstance(site, Site):
        raise ValueError("site must be a Site instance")
    patch_list = list(patches)
    for patch in patch_list:
        if not isinstance(patch, CsvPatchRow):
            raise ValueError("patches must be CsvPatchRow items from parse_patch_csv")
    as_of_dt = (
        normalize_utc_datetime(as_of, field_name="as_of") if as_of is not None else None
    )

    curated_index = _index_site(apply_curation_overlay(site, store)[0])
    base_index = _index_site(site)

    field_rows: dict[tuple[str, str, str], list[int]] = {}
    record_rows: dict[tuple[str, str], list[CsvPatchRow]] = {}
    for patch in patch_list:
        key = (patch.target_type, patch.target_id)
        field_rows.setdefault(key + (patch.field_name,), []).append(patch.row_number)
        record_rows.setdefault(key, []).append(patch)

    latest_audit: dict[tuple[str, str], Optional[datetime]] = {}
    rows: list[PreviewRow] = []
    for patch in patch_list:
        key = (patch.target_type, patch.target_id)
        stored = store.get_patch(patch.target_type, patch.target_id)
        record = curated_index.get(key)
        is_deleted_record = False
        if record is None and stored is not None and stored.deleted:
            record = base_index.get(key)
            is_deleted_record = record is not None

        new_value = _plain(getattr(patch, patch.field_name))
        old_value: Any = None
        status = "change"
        detail = ""
        if record is None:
            status = "invalid"
            detail = f"{patch.target_type} {patch.target_id!r} was not found in site {site.site_id!r}"
        else:
            old_value = _old_value(patch.field_name, record, stored, is_deleted_record)
            if is_deleted_record and patch.field_name != "deleted":
                status = "invalid"
                detail = (
                    "record is deleted; restore it with deleted=false in its own "
                    "batch before editing other fields"
                )

        if status == "change":
            if as_of_dt is not None:
                if key not in latest_audit:
                    latest_audit[key] = _latest_audit_timestamp(store, *key)
                latest = latest_audit[key]
                if latest is not None and latest > as_of_dt:
                    status = "conflict"
                    detail = (
                        f"record was changed at {latest.isoformat()}, after as_of "
                        f"{as_of_dt.isoformat()}"
                    )
        if status == "change":
            same_field = field_rows[key + (patch.field_name,)]
            siblings = record_rows[key]
            if len(same_field) > 1:
                status = "conflict"
                detail = f"field {patch.field_name!r} is set by more than one row (rows {', '.join(str(n) for n in same_field)})"
            elif len(siblings) > 1 and any(p.field_name == "deleted" for p in siblings):
                status = "conflict"
                detail = (
                    "record has a deleted row and other rows (rows "
                    f"{', '.join(str(p.row_number) for p in siblings)}); put deleted in its own batch"
                )
        if status == "change" and new_value == old_value:
            status = "no_op"
            detail = "new value equals the current value"

        rows.append(
            PreviewRow(
                row_number=patch.row_number,
                record_type=patch.target_type,
                record_id=patch.target_id,
                field=patch.field_name,
                old_value=old_value,
                new_value=new_value,
                status=status,
                reason=patch.reason,
                detail=detail,
            )
        )

    counts = {status: 0 for status in PREVIEW_STATUSES}
    for row in rows:
        counts[row.status] += 1
    can_apply = (
        counts["conflict"] == 0 and counts["invalid"] == 0 and counts["change"] > 0
    )
    return PatchPreview(
        site_id=site.site_id,
        as_of=as_of_dt,
        rows=rows,
        confirm_token=_compute_confirm_token(site.site_id, as_of_dt, rows),
        counts=counts,
        can_apply=can_apply,
        patches=patch_list,
        site=site,
    )


def _tokens_match(supplied: Any, expected: str) -> bool:
    if not isinstance(supplied, str):
        return False
    return hmac.compare_digest(
        supplied.encode("utf-8", "replace"), expected.encode("utf-8")
    )


def apply_patches(
    store: CurationStore,
    preview: PatchPreview,
    actor: str,
    confirm_token: str,
) -> BulkApplyResult:
    """Apply every `change` row of `preview` in one transaction, or refuse and write nothing."""
    if not isinstance(store, CurationStore):
        raise ValueError("store must be a CurationStore instance")
    if not isinstance(preview, PatchPreview) or preview.site is None:
        raise ValueError("preview must be a PatchPreview from preview_patches")
    if not _tokens_match(confirm_token, preview.confirm_token):
        raise BulkApplyRefused(
            "confirm token does not match this preview; preview again"
        )
    if preview.counts.get("conflict", 0) or preview.counts.get("invalid", 0):
        raise BulkApplyRefused(
            "preview has conflict or invalid rows; fix the file and preview again"
        )

    batch_id = f"batch-{uuid.uuid4().hex[:12]}"
    entries: list[AuditLogEntry] = []
    with store._write_transaction():
        fresh = preview_patches(store, preview.site, preview.patches, preview.as_of)
        if not _tokens_match(fresh.confirm_token, preview.confirm_token):
            raise BulkApplyRefused(
                "the curation store changed since this preview; preview again"
            )
        for row, patch in zip(fresh.rows, preview.patches):
            if row.status != "change":
                continue
            if patch.field_name == "deleted" and patch.deleted:
                entries.append(
                    store._delete_item_locked(
                        patch.target_type,
                        patch.target_id,
                        actor,
                        patch.reason,
                        preview.site_id,
                        batch_id=batch_id,
                    )
                )
                continue
            single = ItemEditPatch(
                target_type=patch.target_type,
                target_id=patch.target_id,
                site_id=preview.site_id,
                **{patch.field_name: getattr(patch, patch.field_name)},
            )
            entries.append(
                store._upsert_patch_locked(
                    single,
                    datetime.now(timezone.utc),
                    actor,
                    patch.reason,
                    batch_id=batch_id,
                )
            )
    return BulkApplyResult(batch_id=batch_id, entries=entries)


__all__ = [
    "ALLOWED_FIELDS",
    "BulkApplyRefused",
    "BulkApplyResult",
    "CSV_COLUMNS",
    "CsvPatchRow",
    "PatchCsvError",
    "PatchPreview",
    "PreviewRow",
    "apply_patches",
    "parse_patch_csv",
    "preview_patches",
]
