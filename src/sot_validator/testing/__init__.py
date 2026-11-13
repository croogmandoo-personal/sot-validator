"""Deterministic synthetic fleet generator and shared pipeline runner for tests."""

from sot_validator.testing.pipeline import (
    DEFAULT_DRIFT_FRACTION,
    PipelineTimings,
    run_pipeline,
)
from sot_validator.testing.synthetic import (
    DEFAULT_REFERENCE_TIME,
    SyntheticFleet,
    SyntheticFleetGenerator,
    drift_site,
)

__all__ = [
    "DEFAULT_DRIFT_FRACTION",
    "DEFAULT_REFERENCE_TIME",
    "PipelineTimings",
    "SyntheticFleet",
    "SyntheticFleetGenerator",
    "drift_site",
    "run_pipeline",
]
