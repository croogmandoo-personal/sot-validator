"""Batch extraction engine and local JSON snapshot store with checkpoint resume."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Callable, Iterator, Optional, Sequence

from sot_validator.extraction.client import ReadOnlyViolationError, SoTClient
from sot_validator.models import Site


class SnapshotStore:
    """Local filesystem store for normalized Site snapshots, batch manifests, and checkpoints."""

    def __init__(self, snapshot_dir: Path | str) -> None:
        self.snapshot_dir = Path(snapshot_dir)
        self.sites_dir = self.snapshot_dir / "sites"
        self.batches_dir = self.snapshot_dir / "batches"
        self.checkpoint_path = self.snapshot_dir / "checkpoint.json"

    def _ensure_dirs(self) -> None:
        self.sites_dir.mkdir(parents=True, exist_ok=True)
        self.batches_dir.mkdir(parents=True, exist_ok=True)

    def _read_checkpoint_data(self) -> dict[str, Any]:
        if not self.checkpoint_path.exists():
            return {"completed_site_ids": [], "batches": [], "updated_at": None}
        try:
            data = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {"completed_site_ids": [], "batches": [], "updated_at": None}

    def _write_checkpoint(
        self,
        *,
        extra_site_ids: Sequence[str] = (),
        batch_record: Optional[dict[str, Any]] = None,
    ) -> None:
        self._ensure_dirs()
        state = self._read_checkpoint_data()
        completed = set(state.get("completed_site_ids", []))
        for site_file in self.sites_dir.glob("*.json"):
            completed.add(site_file.stem)
        completed.update(extra_site_ids)

        batches: list[dict[str, Any]] = list(state.get("batches", []))
        if batch_record is not None:
            batches = [
                b
                for b in batches
                if b.get("batch_index") != batch_record.get("batch_index")
            ]
            batches.append(batch_record)
            batches.sort(key=lambda b: int(b.get("batch_index", 0)))

        updated_state = {
            "completed_site_ids": sorted(completed),
            "batches": batches,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self.checkpoint_path.write_text(
            json.dumps(updated_state, indent=2), encoding="utf-8"
        )

    def save_site(self, site: Site) -> Path:
        """Persist a single Site snapshot to `<snapshot_dir>/sites/<site_id>.json`."""
        self._ensure_dirs()
        site_path = self.sites_dir / f"{site.site_id}.json"
        site_path.write_text(site.to_json(indent=2), encoding="utf-8")
        self._write_checkpoint(extra_site_ids=[site.site_id])
        return site_path

    def save_batch(self, batch_index: int, sites: Sequence[Site]) -> Path:
        """Persist a batch of Site objects and write `<snapshot_dir>/batches/batch_<index:04d>.json`."""
        self._ensure_dirs()
        site_ids: list[str] = []
        for site in sites:
            site_path = self.sites_dir / f"{site.site_id}.json"
            site_path.write_text(site.to_json(indent=2), encoding="utf-8")
            site_ids.append(site.site_id)

        batch_filename = f"batch_{batch_index:04d}.json"
        batch_path = self.batches_dir / batch_filename
        batch_payload = {
            "batch_index": batch_index,
            "site_ids": site_ids,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "sites": [site.to_dict() for site in sites],
        }
        batch_path.write_text(
            json.dumps(batch_payload, indent=2), encoding="utf-8"
        )
        self._write_checkpoint(
            extra_site_ids=site_ids,
            batch_record={
                "batch_index": batch_index,
                "site_ids": site_ids,
                "file": f"batches/{batch_filename}",
            },
        )
        return batch_path

    def load_site(self, site_id: str) -> Site:
        """Load a previously saved Site from `<snapshot_dir>/sites/<site_id>.json`."""
        site_path = self.sites_dir / f"{site_id}.json"
        if not site_path.exists():
            raise KeyError(f"Snapshot for site_id {site_id!r} not found at {site_path}")
        return Site.from_json(site_path.read_text(encoding="utf-8"))

    def load_all_sites(self) -> list[Site]:
        """Load and return all saved Site records sorted by site_id."""
        if not self.sites_dir.exists():
            return []
        sites: list[Site] = []
        for site_path in sorted(self.sites_dir.glob("*.json")):
            sites.append(Site.from_json(site_path.read_text(encoding="utf-8")))
        return sorted(sites, key=lambda s: s.site_id)

    def completed_site_ids(self) -> set[str]:
        """Return the set of site_ids that have persisted snapshots on disk."""
        completed: set[str] = set()
        if self.sites_dir.exists():
            for site_file in self.sites_dir.glob("*.json"):
                completed.add(site_file.stem)
        if self.checkpoint_path.exists():
            state = self._read_checkpoint_data()
            for sid in state.get("completed_site_ids", []):
                if (self.sites_dir / f"{sid}.json").exists():
                    completed.add(sid)
        return completed

    def is_completed(self, site_id: str) -> bool:
        """Return True if a snapshot for `site_id` already exists in the store."""
        return (self.sites_dir / f"{site_id}.json").exists()


class BatchExtractor:
    """Extracts sites from a read-only SoTClient in configurable batches with checkpointing."""

    def __init__(
        self,
        client: SoTClient,
        snapshot_store: Optional[SnapshotStore] = None,
        *,
        sites_per_batch: int = 10,
        request_delay_seconds: float = 0.0,
        max_retries: int = 3,
        backoff_seconds: float = 0.05,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if isinstance(sites_per_batch, bool) or sites_per_batch < 1:
            raise ValueError("sites_per_batch must be an integer >= 1")
        if isinstance(request_delay_seconds, bool) or request_delay_seconds < 0.0:
            raise ValueError("request_delay_seconds must be >= 0.0")
        if isinstance(max_retries, bool) or max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if isinstance(backoff_seconds, bool) or backoff_seconds < 0.0:
            raise ValueError("backoff_seconds must be >= 0.0")

        self.client = client
        self.snapshot_store = snapshot_store
        self.sites_per_batch = sites_per_batch
        self.request_delay_seconds = float(request_delay_seconds)
        self.max_retries = max_retries
        self.backoff_seconds = float(backoff_seconds)
        self.sleep_fn = sleep_fn

    def _fetch_site_with_retry(self, site_id: str) -> Site:
        attempt = 0
        while True:
            try:
                return self.client.get_site(site_id)
            except ReadOnlyViolationError:
                raise
            except (OSError, TimeoutError, ConnectionError):
                if attempt >= self.max_retries:
                    raise
                delay = self.backoff_seconds * (2**attempt)
                if delay > 0.0:
                    self.sleep_fn(delay)
                attempt += 1

    def iter_batches(
        self,
        site_ids: Optional[Sequence[str]] = None,
        *,
        resume: bool = True,
    ) -> Iterator[list[Site]]:
        """Yield batches of extracted Site objects, skipping completed sites when resume=True."""
        target_ids = (
            list(site_ids) if site_ids is not None else self.client.list_site_ids()
        )
        if resume and self.snapshot_store is not None:
            completed = self.snapshot_store.completed_site_ids()
            pending_ids = [sid for sid in target_ids if sid not in completed]
        else:
            pending_ids = list(target_ids)

        existing_batches_count = 0
        if (
            resume
            and self.snapshot_store is not None
            and self.snapshot_store.batches_dir.exists()
        ):
            existing_batches_count = len(
                list(self.snapshot_store.batches_dir.glob("batch_*.json"))
            )

        requests_made = 0
        for offset in range(0, len(pending_ids), self.sites_per_batch):
            chunk_ids = pending_ids[offset : offset + self.sites_per_batch]
            batch_sites: list[Site] = []
            for sid in chunk_ids:
                if requests_made > 0 and self.request_delay_seconds > 0.0:
                    self.sleep_fn(self.request_delay_seconds)
                site = self._fetch_site_with_retry(sid)
                requests_made += 1
                batch_sites.append(site)

            batch_index = existing_batches_count + (offset // self.sites_per_batch)
            if self.snapshot_store is not None:
                self.snapshot_store.save_batch(batch_index, batch_sites)
            yield batch_sites

    def extract_all(
        self,
        site_ids: Optional[Sequence[str]] = None,
        *,
        resume: bool = True,
    ) -> list[Site]:
        """Extract all target sites across batches, combining resumed snapshots with newly extracted sites."""
        target_ids = (
            list(site_ids) if site_ids is not None else self.client.list_site_ids()
        )
        extracted_by_id: dict[str, Site] = {}

        if resume and self.snapshot_store is not None:
            for sid in target_ids:
                if self.snapshot_store.is_completed(sid):
                    extracted_by_id[sid] = self.snapshot_store.load_site(sid)

        for batch in self.iter_batches(target_ids, resume=resume):
            for site in batch:
                extracted_by_id[site.site_id] = site

        return [
            extracted_by_id[sid] for sid in target_ids if sid in extracted_by_id
        ]


__all__ = ["BatchExtractor", "SnapshotStore"]
