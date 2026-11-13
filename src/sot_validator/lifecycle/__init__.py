"""TLS certificate expiry and weak-crypto inventory package."""

from __future__ import annotations

from sot_validator.lifecycle.certificates import (
    DEFAULT_WARN_DAYS,
    EXPIRING_ISSUE_PREFIX,
    ISSUE_EXPIRED,
    ISSUE_HOSTNAME_MISMATCH,
    ISSUE_NOT_YET_VALID,
    ISSUE_RSA_KEY_LT_2048,
    ISSUE_SELF_SIGNED,
    ISSUE_SHA1_SIGNATURE,
    MIN_RSA_KEY_BITS,
    SHA1_WITH_RSA_OID,
    VALID_SEVERITIES,
    WARNING_DAYS_THRESHOLD,
    CertificateFinding,
    CertificateInventory,
    CertificateRecord,
    expiring_issue,
    generate_certificate_json_report,
    generate_certificate_markdown_report,
    sort_findings,
)

__all__ = [
    "CertificateFinding",
    "CertificateInventory",
    "CertificateRecord",
    "DEFAULT_WARN_DAYS",
    "EXPIRING_ISSUE_PREFIX",
    "ISSUE_EXPIRED",
    "ISSUE_HOSTNAME_MISMATCH",
    "ISSUE_NOT_YET_VALID",
    "ISSUE_RSA_KEY_LT_2048",
    "ISSUE_SELF_SIGNED",
    "ISSUE_SHA1_SIGNATURE",
    "MIN_RSA_KEY_BITS",
    "SHA1_WITH_RSA_OID",
    "VALID_SEVERITIES",
    "WARNING_DAYS_THRESHOLD",
    "expiring_issue",
    "generate_certificate_json_report",
    "generate_certificate_markdown_report",
    "sort_findings",
]
