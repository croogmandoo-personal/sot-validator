"""Phase 5 migration package for exporting validated golden inventory to NetBox and Nautobot."""

from __future__ import annotations

from sot_validator.migration.exporter import (
    CSV_COLUMNS_BY_ENTITY,
    ENTITY_COLLECTION_KEYS,
    SUPPORTED_TARGET_PLATFORMS,
    GoldenInventoryFilter,
    ModernSoTExporter,
    TargetPlatform,
    slugify,
)
from sot_validator.migration.parity import (
    ALL_CUTOVER_RECOMMENDATIONS,
    ALL_PARITY_DISCREPANCY_TYPES,
    PARITY_ENTITY_COLLECTIONS,
    CutoverRecommendation,
    DualRunParityChecker,
    MigrationParityReport,
    ModernSoTParityValidator,
    ParityDiscrepancy,
    ParityDiscrepancyType,
    ParityValidationReport,
    SiteMigrationReadinessScorecard,
)

ModernSoTPlatform = TargetPlatform
NETBOX_CSV_SCHEMAS = CSV_COLUMNS_BY_ENTITY
NAUTOBOT_CSV_SCHEMAS = CSV_COLUMNS_BY_ENTITY
slugify_identifier = slugify

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
    "ModernSoTParityValidator",
    "ModernSoTPlatform",
    "NAUTOBOT_CSV_SCHEMAS",
    "NETBOX_CSV_SCHEMAS",
    "PARITY_ENTITY_COLLECTIONS",
    "ParityDiscrepancy",
    "ParityDiscrepancyType",
    "ParityValidationReport",
    "SUPPORTED_TARGET_PLATFORMS",
    "SiteMigrationReadinessScorecard",
    "TargetPlatform",
    "slugify",
    "slugify_identifier",
]
