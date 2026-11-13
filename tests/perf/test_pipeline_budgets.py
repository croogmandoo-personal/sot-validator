"""Wall-clock and peak-memory budgets for the full 100-site synthetic fleet pipeline.

Fleet: ``SyntheticFleetGenerator(seed=FLEET_SEED, sites=100, subnets_per_site=10,
hosts_per_subnet=60)``, timed by the shared ``run_pipeline`` runner (stage
seconds summed across sites, one fleet-wide dashboard render).

Headroom rule: every budget is at least 3x the value measured below, to absorb
CI and shared-runner noise. Re-measure and update this table when a budget is
changed.

Measured on an AMD Ryzen 7 5800X (8 cores, CachyOS Linux 7.3 x86_64), Python 3.14.9:

Stage                 Measured         Budget
--------------------  ---------------  ----------------------------------------
classification        50.5 s           150.0 s (CLASSIFICATION_BUDGET_SECONDS)
FDB mapping           2.88 s           9.0 s (FDB_MAPPING_BUDGET_SECONDS)
snapshot diffing      0.43 s           1.5 s (SNAPSHOT_DIFF_BUDGET_SECONDS)
HTML dashboard        7.0 s            21.0 s (DASHBOARD_BUDGET_SECONDS)
tracemalloc peak      1205 MiB         3700 MiB (PEAK_MEMORY_BUDGET_BYTES)

Classification was measured after caching the DHCP collector's /24-scoped
lease list and ARP MAC normalization; before those fixes a 600-host site took
about 19 s to classify.

Peak memory is measured with ``tracemalloc`` in its own test so its overhead
does not distort the wall-clock budgets. These tests are marked ``perf`` and
excluded from the default run; use ``python3 -m pytest -m perf``.
"""

from __future__ import annotations

import tracemalloc

import pytest

from sot_validator.testing import (
    PipelineTimings,
    SyntheticFleet,
    SyntheticFleetGenerator,
    run_pipeline,
)

pytestmark = pytest.mark.perf

FLEET_SEED = 2026
FLEET_SITES = 100
FLEET_SUBNETS_PER_SITE = 10
FLEET_HOSTS_PER_SUBNET = 60

CLASSIFICATION_BUDGET_SECONDS = 150.0
FDB_MAPPING_BUDGET_SECONDS = 9.0
SNAPSHOT_DIFF_BUDGET_SECONDS = 1.5
DASHBOARD_BUDGET_SECONDS = 21.0
PEAK_MEMORY_BUDGET_BYTES = 3700 * 1024 * 1024


@pytest.fixture(scope="module")
def fleet() -> SyntheticFleet:
    return SyntheticFleetGenerator(
        FLEET_SEED,
        sites=FLEET_SITES,
        subnets_per_site=FLEET_SUBNETS_PER_SITE,
        hosts_per_subnet=FLEET_HOSTS_PER_SUBNET,
    ).generate()


@pytest.fixture(scope="module")
def timings(fleet: SyntheticFleet) -> PipelineTimings:
    return run_pipeline(fleet)


def test_classification_within_budget(timings: PipelineTimings) -> None:
    assert timings.result_count > 0
    assert timings.classification_seconds <= CLASSIFICATION_BUDGET_SECONDS, (
        f"classification took {timings.classification_seconds:.2f}s "
        f"(budget {CLASSIFICATION_BUDGET_SECONDS}s)"
    )


def test_fdb_mapping_within_budget(timings: PipelineTimings) -> None:
    assert timings.port_classification_count > 0
    assert timings.fdb_mapping_seconds <= FDB_MAPPING_BUDGET_SECONDS, (
        f"FDB mapping took {timings.fdb_mapping_seconds:.2f}s "
        f"(budget {FDB_MAPPING_BUDGET_SECONDS}s)"
    )


def test_snapshot_diff_within_budget(timings: PipelineTimings) -> None:
    assert timings.drift_event_count > 0
    assert timings.snapshot_diff_seconds <= SNAPSHOT_DIFF_BUDGET_SECONDS, (
        f"snapshot diffing took {timings.snapshot_diff_seconds:.2f}s "
        f"(budget {SNAPSHOT_DIFF_BUDGET_SECONDS}s)"
    )


def test_dashboard_render_within_budget(timings: PipelineTimings) -> None:
    assert timings.html_length > 0
    assert timings.dashboard_seconds <= DASHBOARD_BUDGET_SECONDS, (
        f"dashboard render took {timings.dashboard_seconds:.2f}s "
        f"(budget {DASHBOARD_BUDGET_SECONDS}s)"
    )


def test_pipeline_peak_memory_within_budget(fleet: SyntheticFleet) -> None:
    tracemalloc.start()
    try:
        result = run_pipeline(fleet)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result.result_count > 0
    assert peak <= PEAK_MEMORY_BUDGET_BYTES, (
        f"tracemalloc peak {peak / 2**20:.1f} MiB "
        f"(budget {PEAK_MEMORY_BUDGET_BYTES / 2**20:.0f} MiB)"
    )
