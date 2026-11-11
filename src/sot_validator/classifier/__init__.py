"""Multi-signal classification engine package exports."""

from __future__ import annotations

from sot_validator.classifier.engine import (
    DEFAULT_SIGNAL_WEIGHTS,
    ClassificationEngine,
    ClassificationPolicy,
    ScoringConfig,
    ValidationScorer,
)

__all__ = [
    "ClassificationEngine",
    "ClassificationPolicy",
    "DEFAULT_SIGNAL_WEIGHTS",
    "ScoringConfig",
    "ValidationScorer",
]
