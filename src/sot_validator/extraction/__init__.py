"""Read-only Source of Truth (SoT) extraction adapters and batch snapshot store."""

from __future__ import annotations

from sot_validator.extraction.batch import BatchExtractor, SnapshotStore
from sot_validator.extraction.client import (
    FixtureSoTClient,
    ReadOnlyViolationError,
    SoTClient,
    validate_read_only_request,
)
from sot_validator.extraction.scraper import HtmlScraperSoTClient
from sot_validator.extraction.sql_export import SqlExportSoTClient

__all__ = [
    "BatchExtractor",
    "FixtureSoTClient",
    "HtmlScraperSoTClient",
    "ReadOnlyViolationError",
    "SnapshotStore",
    "SoTClient",
    "SqlExportSoTClient",
    "validate_read_only_request",
]
