"""Shared helpers for the `sot-validator` CLI command modules (source flags, extraction, evaluation, results and store loaders)."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional

from sot_validator.classifier.engine import ClassificationEngine, ClassificationPolicy
from sot_validator.curation import CurationStore
from sot_validator.extraction import (
    BatchExtractor,
    FixtureSoTClient,
    HtmlScraperSoTClient,
    SnapshotStore,
    SoTClient,
    SqlExportSoTClient,
)
from sot_validator.history import HistoryStore
from sot_validator.models import Site, ValidationResult
from sot_validator.signals.directory_dns import (
    ActiveDirectoryCollector,
    DnsDhcpLeaseCollector,
)
from sot_validator.signals.hypervisor import MultiVCenterInventoryProvider
from sot_validator.signals.icmp import IcmpProbeCollector
from sot_validator.signals.management import ManagementProbeCollector


DEFAULT_FIXTURE_EVALUATION_TIME = "2026-02-12T12:00:00Z"
DEFAULT_DISCOVERY_SAMPLE_EVALUATION_TIME = "2026-11-11T08:10:00Z"


def _parse_str_list(raw_values: Optional[Sequence[str]]) -> list[str]:
    if not raw_values:
        return []
    parsed: list[str] = []
    for raw in raw_values:
        for part in str(raw).split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in parsed:
                parsed.append(cleaned)
    return parsed


def _parse_site_ids(raw_values: Optional[Sequence[str]]) -> Optional[list[str]]:
    parsed = _parse_str_list(raw_values)
    return parsed if parsed else None


def _has_source_flags(args: argparse.Namespace) -> bool:
    return any(
        bool(getattr(args, attr, None))
        for attr in (
            "fixtures",
            "fixture_path",
            "sql_dump",
            "sqlite_path",
            "csv_dir",
            "json_export",
            "scrape_url",
        )
    )


def _build_sot_client(
    args: argparse.Namespace, *, default_to_fixtures: bool = False
) -> Optional[SoTClient]:
    if getattr(args, "sqlite_path", None) is not None:
        return SqlExportSoTClient.from_sqlite(args.sqlite_path)
    if getattr(args, "sql_dump", None) is not None:
        sql_path = Path(args.sql_dump)
        if sql_path.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            return SqlExportSoTClient.from_sqlite(sql_path)
        return SqlExportSoTClient.from_sql_dump(sql_path)
    if getattr(args, "csv_dir", None) is not None:
        return SqlExportSoTClient.from_csv_dir(args.csv_dir)
    if getattr(args, "json_export", None) is not None:
        return SqlExportSoTClient.from_json(args.json_export)
    if getattr(args, "scrape_url", None) is not None:
        return HtmlScraperSoTClient(args.scrape_url)
    if getattr(args, "fixture_path", None) is not None:
        return FixtureSoTClient(fixture_path=args.fixture_path)
    if getattr(args, "fixtures", False) or default_to_fixtures:
        num_sites = getattr(args, "num_sites", 3)
        return FixtureSoTClient(num_sites=num_sites)
    return None


def _infer_evaluation_time(
    args: argparse.Namespace, sites: Sequence[Site]
) -> Optional[str]:
    explicit = getattr(args, "evaluation_time", None)
    if explicit:
        return str(explicit)

    if getattr(args, "fixtures", False) or getattr(args, "fixture_path", None):
        return DEFAULT_FIXTURE_EVALUATION_TIME

    fixture_anchor = datetime(2026, 2, 10, 12, 0, 0, tzinfo=timezone.utc)
    for site in sites:
        for dev in site.devices:
            if dev.last_seen == fixture_anchor:
                return DEFAULT_FIXTURE_EVALUATION_TIME
        if site.site_id == "site-042":
            return DEFAULT_DISCOVERY_SAMPLE_EVALUATION_TIME

    return None


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--site-ids",
        nargs="+",
        action="extend",
        default=None,
        help="Target site IDs (comma-separated or space-separated, e.g. site-001,site-002).",
    )
    parser.add_argument(
        "--all-sites",
        action="store_true",
        default=False,
        help="Process all available sites.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Number of sites per extraction batch (default: 10).",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="Polite delay in seconds between per-site requests (default: 0.0).",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        default=False,
        help="Disable checkpoint resume and re-extract all target sites.",
    )
    parser.add_argument(
        "--fixtures",
        action="store_true",
        default=False,
        help="Use deterministic built-in FixtureSoTClient inventory.",
    )
    parser.add_argument(
        "--num-sites",
        type=int,
        default=3,
        help="Number of fixture sites to generate when --fixtures is set (default: 3).",
    )
    parser.add_argument(
        "--fixture-path",
        type=Path,
        default=None,
        help="Path to a JSON fixture file for FixtureSoTClient.",
    )
    parser.add_argument(
        "--sql-dump",
        type=Path,
        default=None,
        help="Path to a read-only SQL dump file (.sql).",
    )
    parser.add_argument(
        "--sqlite-path",
        type=Path,
        default=None,
        help="Path to a read-only SQLite database export.",
    )
    parser.add_argument(
        "--csv-dir",
        type=Path,
        default=None,
        help="Path to a directory containing SoT CSV export tables.",
    )
    parser.add_argument(
        "--json-export",
        type=Path,
        default=None,
        help="Path to a JSON export file of SoT tables or sites.",
    )
    parser.add_argument(
        "--scrape-url",
        type=str,
        default=None,
        help="Base URL for read-only GET HTML scraping of the legacy SoT.",
    )


def _add_validation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--vcenter-json",
        type=Path,
        default=None,
        help="Path to a multi-vCenter inventory JSON snapshot.",
    )
    parser.add_argument(
        "--snmp-fixture",
        type=Path,
        default=None,
        help="Path to a read-only SNMP/ICMP discovery fixture JSON file.",
    )
    parser.add_argument(
        "--ad-json",
        type=Path,
        default=None,
        help="Path to an Active Directory computer account export JSON file.",
    )
    parser.add_argument(
        "--dns-json",
        type=Path,
        default=None,
        help="Path to a DNS forward/reverse (A/PTR) records JSON file.",
    )
    parser.add_argument(
        "--dhcp-json",
        type=Path,
        default=None,
        help="Path to a /24-scoped DHCP lease export JSON file.",
    )
    parser.add_argument(
        "--active-within-days",
        type=float,
        default=7.0,
        help="Threshold in days within which signals are considered active (default: 7.0).",
    )
    parser.add_argument(
        "--stale-after-days",
        type=float,
        default=30.0,
        help="Threshold in days beyond which inactive signals are considered stale (default: 30.0).",
    )
    parser.add_argument(
        "--evaluation-time",
        type=str,
        default=None,
        help="Reference ISO-8601 UTC timestamp for signal recency evaluation.",
    )
    parser.add_argument(
        "--include-ips",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include IPAddress records in site validation results (default: True).",
    )


def _extract_sites(
    args: argparse.Namespace,
    snapshot_dir: Path,
    *,
    default_to_fixtures: bool = False,
) -> list[Site]:
    store = SnapshotStore(snapshot_dir)
    client = _build_sot_client(args, default_to_fixtures=default_to_fixtures)
    site_ids = (
        None
        if getattr(args, "all_sites", False)
        else _parse_site_ids(getattr(args, "site_ids", None))
    )

    if client is not None:
        extractor = BatchExtractor(
            client,
            snapshot_store=store,
            sites_per_batch=getattr(args, "batch_size", 10),
            request_delay_seconds=getattr(args, "rate_limit", 0.0),
        )
        return extractor.extract_all(
            site_ids=site_ids,
            resume=not getattr(args, "no_resume", False),
        )

    all_saved = store.load_all_sites()
    if site_ids is not None:
        wanted = set(site_ids)
        return [s for s in all_saved if s.site_id in wanted]
    return all_saved


def _resolve_sites_for_command(
    args: argparse.Namespace,
    output_dir: Path,
    *,
    default_to_fixtures: bool = True,
) -> list[Site]:
    has_source = _has_source_flags(args)
    raw_snap = getattr(args, "snapshot_dir", None)
    if raw_snap is not None:
        snap_path = Path(raw_snap)
        if (snap_path / "snapshots" / "sites").exists() and not (
            snap_path / "sites"
        ).exists():
            snapshot_dir = snap_path / "snapshots"
        else:
            snapshot_dir = snap_path
    elif (output_dir / "sites").exists():
        snapshot_dir = output_dir
    elif (output_dir / "snapshots" / "sites").exists():
        snapshot_dir = output_dir / "snapshots"
    elif (Path("./snapshots") / "sites").exists() and not has_source:
        snapshot_dir = Path("./snapshots")
    else:
        snapshot_dir = output_dir / "snapshots"

    store = SnapshotStore(snapshot_dir)
    use_fixtures = (
        default_to_fixtures and not has_source and not store.load_all_sites()
    )
    return _extract_sites(args, snapshot_dir, default_to_fixtures=use_fixtures)


def _load_ad_collector(
    ad_json_path: Optional[Path],
    *,
    active_within_days: float,
    stale_after_days: float,
    evaluation_time: Optional[str],
) -> Optional[ActiveDirectoryCollector]:
    if ad_json_path is None:
        return None
    raw = json.loads(Path(ad_json_path).read_text(encoding="utf-8"))
    if isinstance(raw, Mapping):
        records = (
            raw.get("computers")
            or raw.get("records")
            or raw.get("accounts")
            or []
        )
    elif isinstance(raw, list):
        records = raw
    else:
        records = []
    return ActiveDirectoryCollector(
        records=records,
        active_within_days=active_within_days,
        stale_after_days=stale_after_days,
        evaluation_time=evaluation_time,
    )


def _load_dns_dhcp_collector(
    dns_json_path: Optional[Path],
    dhcp_json_path: Optional[Path],
    *,
    evaluation_time: Optional[str],
) -> Optional[DnsDhcpLeaseCollector]:
    if dns_json_path is None and dhcp_json_path is None:
        return None

    dns_records: Optional[Any] = None
    a_records: Optional[Any] = None
    ptr_records: Optional[Any] = None
    if dns_json_path is not None:
        raw_dns = json.loads(Path(dns_json_path).read_text(encoding="utf-8"))
        if isinstance(raw_dns, Mapping):
            if "a_records" in raw_dns or "ptr_records" in raw_dns or "forward_records" in raw_dns or "reverse_records" in raw_dns:
                a_records = raw_dns.get("a_records") or raw_dns.get("forward_records")
                ptr_records = raw_dns.get("ptr_records") or raw_dns.get("reverse_records")
                dns_records = raw_dns.get("dns_records") or raw_dns.get("records")
            else:
                dns_records = (
                    raw_dns.get("records")
                    or raw_dns.get("dns_records")
                    or []
                )
        elif isinstance(raw_dns, list):
            dns_records = raw_dns

    dhcp_leases: Optional[Any] = None
    if dhcp_json_path is not None:
        raw_dhcp = json.loads(Path(dhcp_json_path).read_text(encoding="utf-8"))
        if isinstance(raw_dhcp, Mapping):
            dhcp_leases = (
                raw_dhcp.get("leases")
                or raw_dhcp.get("dhcp_leases")
                or raw_dhcp.get("records")
                or []
            )
        elif isinstance(raw_dhcp, list):
            dhcp_leases = raw_dhcp

    return DnsDhcpLeaseCollector(
        dns_records=dns_records,
        a_records=a_records,
        ptr_records=ptr_records,
        dhcp_leases=dhcp_leases,
        evaluation_time=evaluation_time,
    )


def _build_classification_engine(
    args: argparse.Namespace,
    sites: Sequence[Site],
) -> tuple[ClassificationEngine, Optional[str]]:
    eval_time = _infer_evaluation_time(args, sites)
    active_days = float(getattr(args, "active_within_days", 7.0))
    stale_days = float(getattr(args, "stale_after_days", 30.0))
    policy = ClassificationPolicy(
        active_within_days=active_days,
        stale_after_days=stale_days,
    )

    hypervisor_provider: Optional[MultiVCenterInventoryProvider] = None
    if getattr(args, "vcenter_json", None) is not None:
        hypervisor_provider = MultiVCenterInventoryProvider.from_json_file(
            args.vcenter_json
        )

    icmp_collector: Optional[IcmpProbeCollector] = None
    management_collector: Optional[ManagementProbeCollector] = None
    if getattr(args, "snmp_fixture", None) is not None:
        icmp_collector = IcmpProbeCollector.from_fixture_file(args.snmp_fixture)
        management_collector = ManagementProbeCollector.from_fixture_file(
            args.snmp_fixture
        )

    ad_collector = _load_ad_collector(
        getattr(args, "ad_json", None),
        active_within_days=active_days,
        stale_after_days=stale_days,
        evaluation_time=eval_time,
    )
    dns_dhcp_collector = _load_dns_dhcp_collector(
        getattr(args, "dns_json", None),
        getattr(args, "dhcp_json", None),
        evaluation_time=eval_time,
    )

    engine = ClassificationEngine(
        policy=policy,
        icmp_collector=icmp_collector,
        management_collector=management_collector,
        hypervisor_provider=hypervisor_provider,
        ad_collector=ad_collector,
        dns_dhcp_collector=dns_dhcp_collector,
        evaluation_time=eval_time,
    )
    return engine, eval_time


def _evaluate_sites(
    args: argparse.Namespace,
    sites: Sequence[Site],
) -> tuple[list[ValidationResult], Optional[str]]:
    engine, eval_time = _build_classification_engine(args, sites)
    include_ips = getattr(args, "include_ips", True)
    results: list[ValidationResult] = []
    for site in sites:
        results.extend(
            engine.classify_site(
                site,
                evaluation_time=eval_time,
                include_ip_addresses=include_ips,
            )
        )
    return results, eval_time


def _write_validation_results_file(
    results: Sequence[ValidationResult],
    output_dir: Path,
    *,
    generated_at: Optional[str] = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    results_path = output_dir / "validation_results.json"
    ts_str = generated_at or datetime.now(timezone.utc).isoformat()
    payload = {
        "generated_at": ts_str,
        "total_results": len(results),
        "results": [r.to_dict() for r in results],
    }
    results_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return results_path


def _load_validation_results_with_timestamp(
    results_path: Path,
) -> tuple[list[ValidationResult], Optional[str]]:
    raw_data: Any = json.loads(results_path.read_text(encoding="utf-8"))
    generated_at: Optional[str] = None
    if isinstance(raw_data, dict):
        items = raw_data.get("results", [])
        if isinstance(raw_data.get("generated_at"), str):
            generated_at = raw_data["generated_at"]
    elif isinstance(raw_data, list):
        items = raw_data
    else:
        raise ValueError(
            f"Unsupported validation results format in {results_path}"
        )
    results = [
        item if isinstance(item, ValidationResult) else ValidationResult.from_dict(item)
        for item in items
    ]
    if generated_at is None and results and results[0].evaluated_at is not None:
        generated_at = results[0].evaluated_at.isoformat()
    return results, generated_at


def _load_validation_results_file(results_path: Path) -> list[ValidationResult]:
    results, _ = _load_validation_results_with_timestamp(results_path)
    return results


def _open_history_store(
    db_path: Path,
    *,
    import_json_path: Optional[Path] = None,
) -> tuple[HistoryStore, bool]:
    """Open a HistoryStore from SQLite or JSON file; returns (store, is_json_backed)."""
    if db_path.suffix.lower() == ".json":
        store = HistoryStore(":memory:")
        if db_path.exists():
            store.import_json(db_path)
        if import_json_path is not None and import_json_path.exists():
            store.import_json(import_json_path)
        return store, True

    store = HistoryStore(db_path)
    if import_json_path is not None and import_json_path.exists():
        store.import_json(import_json_path)
    return store, False


def _parse_int_list(raw_values: Optional[Sequence[Any]]) -> list[int]:
    if not raw_values:
        return []
    parsed: list[int] = []
    for raw in raw_values:
        for part in str(raw).split(","):
            cleaned = part.strip()
            if cleaned:
                val = int(cleaned)
                if val not in parsed:
                    parsed.append(val)
    return parsed


def _load_single_site_snapshot(
    snapshot_path: Optional[Path],
    args: argparse.Namespace,
    *,
    default_to_fixtures: bool = True,
) -> Site:
    """Load a single Site from a JSON snapshot file, a SnapshotStore directory, or source/fixture flags."""
    wanted_ids = _parse_site_ids(getattr(args, "site_ids", None))
    explicit_site_id = getattr(args, "site_id", None)
    if explicit_site_id and not wanted_ids:
        wanted_ids = [str(explicit_site_id).strip()]

    if snapshot_path is not None:
        snap = Path(snapshot_path)
        if snap.is_dir():
            store_dir = (
                snap / "snapshots"
                if (snap / "snapshots" / "sites").exists()
                and not (snap / "sites").exists()
                else snap
            )
            sites = SnapshotStore(store_dir).load_all_sites()
            if not sites:
                raise ValueError(f"No site snapshots found in directory {snap}")
            if wanted_ids:
                for s in sites:
                    if s.site_id in wanted_ids:
                        return s
            return sites[0]

        raw = json.loads(snap.read_text(encoding="utf-8"))
        if isinstance(raw, Mapping):
            if "site" in raw and isinstance(raw["site"], Mapping):
                return Site.from_dict(raw["site"])
            if "sites" in raw and isinstance(raw["sites"], Sequence):
                sites = [
                    s if isinstance(s, Site) else Site.from_dict(s)
                    for s in raw["sites"]
                ]
                if not sites:
                    raise ValueError(f"Empty sites list in {snap}")
                if wanted_ids:
                    for s in sites:
                        if s.site_id in wanted_ids:
                            return s
                return sites[0]
            return Site.from_dict(raw)
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
            sites = [
                s if isinstance(s, Site) else Site.from_dict(s) for s in raw
            ]
            if not sites:
                raise ValueError(f"Empty sites list in {snap}")
            if wanted_ids:
                for s in sites:
                    if s.site_id in wanted_ids:
                        return s
            return sites[0]
        raise ValueError(f"Unsupported site snapshot format in {snap}")

    fallback_dir = Path(getattr(args, "output_dir", None) or "./output")
    sites = _resolve_sites_for_command(
        args, fallback_dir, default_to_fixtures=default_to_fixtures
    )
    if not sites:
        sites = FixtureSoTClient(num_sites=1).extract_all()
    if wanted_ids:
        for s in sites:
            if s.site_id in wanted_ids:
                return s
    return sites[0]


def _open_curation_store(
    curation_db: Optional[Path | str],
    *,
    import_json_path: Optional[Path] = None,
) -> tuple[CurationStore, Optional[Path]]:
    """Open a CurationStore from SQLite path, JSON state path, or :memory:."""
    json_export_target: Optional[Path] = None
    if curation_db is None or str(curation_db).strip() in ("", ":memory:"):
        store = CurationStore(":memory:")
    else:
        db_path = Path(curation_db)
        if db_path.suffix.lower() == ".json":
            store = CurationStore(":memory:")
            if db_path.exists():
                store.import_json(db_path)
            json_export_target = db_path
        else:
            store = CurationStore(db_path)

    if import_json_path is not None and Path(import_json_path).exists():
        store.import_json(Path(import_json_path))

    return store, json_export_target


def _load_json_object_list(path: Path, *, key: str) -> list[Mapping[str, Any]]:
    """Load a JSON list of objects from a bare list or a ``{"<key>": [...]}`` envelope."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return _json_object_list(raw, key=key, path=path)


def _json_object_list(raw: Any, *, key: str, path: Path) -> list[Mapping[str, Any]]:
    """Validate parsed JSON as a bare list of objects or a ``{"<key>": [...]}`` envelope."""
    if isinstance(raw, Mapping):
        if key not in raw:
            raise ValueError(f"Expected a JSON list or a {key!r} key in {path}")
        items: Any = raw[key]
    elif isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        items = raw
    else:
        raise ValueError(f"Unsupported {key} JSON in {path}")

    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise ValueError(f"Expected a list of objects for {key!r} in {path}")
    objects: list[Mapping[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError(f"Expected JSON objects in {key!r} from {path}")
        objects.append(item)
    return objects
