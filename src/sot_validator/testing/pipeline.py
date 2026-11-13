"""Shared timed pipeline runner for synthetic fleet smoke and performance tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import time
from typing import Any

from sot_validator.classifier.engine import ClassificationEngine
from sot_validator.discovery.monitor import SnapshotDiffEngine
from sot_validator.models import Site, ValidationResult
from sot_validator.reporting.dashboard import generate_html_dashboard
from sot_validator.signals.directory_dns import DnsDhcpLeaseCollector
from sot_validator.testing.synthetic import SyntheticFleet
from sot_validator.topology.fdb_mapper import SwitchFdbPortMapper

DEFAULT_DRIFT_FRACTION = 0.05


@dataclass
class PipelineTimings:
    """Per-stage wall-clock seconds summed across sites, plus output counts."""

    classification_seconds: float = 0.0
    fdb_mapping_seconds: float = 0.0
    snapshot_diff_seconds: float = 0.0
    dashboard_seconds: float = 0.0
    result_count: int = 0
    port_classification_count: int = 0
    drift_event_count: int = 0
    html_length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification_seconds": self.classification_seconds,
            "fdb_mapping_seconds": self.fdb_mapping_seconds,
            "snapshot_diff_seconds": self.snapshot_diff_seconds,
            "dashboard_seconds": self.dashboard_seconds,
            "result_count": self.result_count,
            "port_classification_count": self.port_classification_count,
            "drift_event_count": self.drift_event_count,
            "html_length": self.html_length,
        }


def run_pipeline(
    fleet: SyntheticFleet, *, drift_fraction: float = DEFAULT_DRIFT_FRACTION
) -> PipelineTimings:
    """Run classification, FDB mapping, snapshot diffing and the dashboard over ``fleet``."""
    timings = PipelineTimings()
    reference_time = fleet.reference_time
    baseline_timestamp = reference_time - timedelta(days=1)
    all_results: list[ValidationResult] = []

    for site in fleet.sites:
        leases = fleet.dhcp_leases.get(site.site_id, [])
        fdb_entries = fleet.fdb_entries.get(site.site_id, [])
        arp_entries = fleet.arp_entries.get(site.site_id, [])

        start = time.perf_counter()
        engine = ClassificationEngine(
            evaluation_time=reference_time,
            dns_dhcp_collector=DnsDhcpLeaseCollector(
                dhcp_leases=leases, site=site, evaluation_time=reference_time
            ),
        )
        results = engine.classify_site(site)
        timings.classification_seconds += time.perf_counter() - start
        all_results.extend(results)

        # map_site_ports mutates its site, so it runs on an untimed copy
        mapped_site = Site.from_dict(site.to_dict())
        start = time.perf_counter()
        port_results = SwitchFdbPortMapper().map_site_ports(
            mapped_site, fdb_entries, arp_entries=arp_entries
        )
        timings.fdb_mapping_seconds += time.perf_counter() - start
        timings.port_classification_count += len(port_results)

        drifted = fleet.drift(site, change_fraction=drift_fraction)
        start = time.perf_counter()
        report = SnapshotDiffEngine().diff(
            site,
            drifted,
            baseline_timestamp=baseline_timestamp,
            current_timestamp=reference_time,
            detected_at=reference_time,
        )
        timings.snapshot_diff_seconds += time.perf_counter() - start
        timings.drift_event_count += len(report.events)

    start = time.perf_counter()
    html = generate_html_dashboard(all_results, sites=fleet.sites)
    timings.dashboard_seconds = time.perf_counter() - start
    timings.result_count = len(all_results)
    timings.html_length = len(html)
    return timings


__all__ = ["DEFAULT_DRIFT_FRACTION", "PipelineTimings", "run_pipeline"]
