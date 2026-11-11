"""Phase 5 migration package for exporting validated golden inventory to NetBox and Nautobot."""

from __future__ import annotations

from sot_validator.migration.exporter import (
    CSV_COLUMNS_BY_ENTITY,
    ENTITY_COLLECTION_KEYS,
    SUPPORTED_TARGET_PLATFORMS,
    GoldenInventoryFilter,
    ModernSoTExporter,
    slugify,
)
from sot_validator.migration.parity import (
    ALL_CUTOVER_RECOMMENDATIONS,
    ALL_PARITY_DISCREPANCY_TYPES,
    PARITY_ENTITY_COLLECTIONS,
    CutoverRecommendation,
    DualRunParityChecker,
    MigrationParityReport,
    ParityDiscrepancy,
    ParityDiscrepancyType,
    SiteMigrationReadinessScorecard,
)

__all__ = [
    "ALL_CUTOVER_RECOMMENDATIONS",
    "ALL_PARITY_DISCREPANCY_TYPES",
    "CSV_COLUMNS_BY_ENTITY",
    "CutoverRecommendation",
    "DualRunParityChecker",
    "ENTITY_COLLECTION_KEYS",
    "GoldenInventoryFilter",
    "MigrationParityReport",
    "ModernSoTExporter",
    "PARITY_ENTITY_COLLECTIONS",
    "ParityDiscrepancy",
    "ParityDiscrepancyType",
    "SUPPORTED_TARGET_PLATFORMS",
    "SiteMigrationReadinessScorecard",
    "slugify",
]
