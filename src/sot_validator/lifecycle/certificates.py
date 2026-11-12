"""Deterministic TLS certificate expiry and weak-crypto inventory checks."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Any, Iterable, Mapping, Optional

from sot_validator.models import _parse_optional_datetime
from sot_validator.reporting.generators import (
    _escape_md_cell,
    _resolve_report_timestamp,
)

ISSUE_EXPIRED = "expired"
ISSUE_NOT_YET_VALID = "not_yet_valid"
ISSUE_SELF_SIGNED = "self_signed"
ISSUE_SHA1_SIGNATURE = "sha1_signature"
ISSUE_RSA_KEY_LT_2048 = "rsa_key_lt_2048"
ISSUE_HOSTNAME_MISMATCH = "hostname_mismatch"
EXPIRING_ISSUE_PREFIX = "expiring_"

VALID_SEVERITIES: tuple[str, ...] = ("error", "warning", "info")
DEFAULT_WARN_DAYS: tuple[int, ...] = (90, 60, 30)
WARNING_DAYS_THRESHOLD = 30
MIN_RSA_KEY_BITS = 2048
SHA1_WITH_RSA_OID = "1.2.840.113549.1.1.5"

# The CN attribute of an RFC 4514 DN, where `,`, `;` and `+` separate attributes.
_ISSUER_CN_PATTERN = re.compile(r"(?:^|[,;+])\s*CN\s*=\s*([^,;+]*)", re.IGNORECASE)
# The CN attribute of an OpenSSL oneline DN ("/C=US/CN=name"), where only `/` separates.
_ONELINE_ISSUER_CN_PATTERN = re.compile(r"/\s*CN\s*=\s*([^/]*)", re.IGNORECASE)


def expiring_issue(days: int) -> str:
    """Return the expiry bucket flag name for a warning window of ``days``."""
    return f"{EXPIRING_ISSUE_PREFIX}{days}d"


def _to_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Return an aware UTC datetime, treating naive values as UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _optional_text(value: Any, field_name: str) -> Optional[str]:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string or None")
    return value


def _strict_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _known(value: Optional[str]) -> bool:
    return value is not None and bool(value.strip())


@dataclass
class CertificateRecord:
    """TLS certificate observed on one service endpoint, plus its SoT hostname."""

    site_id: str
    ip: str
    port: int
    subject_cn: Optional[str] = None
    san_dns_names: list[str] = field(default_factory=list)
    issuer: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    signature_algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_bits: Optional[int] = None
    sot_hostname: Optional[str] = None

    def __post_init__(self) -> None:
        self.site_id = _require_text(self.site_id, "site_id")
        ip_text = _require_text(self.ip, "ip")
        try:
            self.ip = str(ipaddress.ip_address(ip_text.strip()))
        except ValueError as exc:
            raise ValueError(f"ip must be a valid IP address, got {ip_text!r}") from exc
        if not _strict_int(self.port) or not 1 <= self.port <= 65535:
            raise ValueError(f"port must be an integer from 1 to 65535, got {self.port!r}")
        self.subject_cn = _optional_text(self.subject_cn, "subject_cn")
        if self.san_dns_names is None:
            self.san_dns_names = []
        if isinstance(self.san_dns_names, str) or not all(
            isinstance(name, str) for name in self.san_dns_names
        ):
            raise ValueError("san_dns_names must be a list of strings")
        self.san_dns_names = list(self.san_dns_names)
        self.issuer = _optional_text(self.issuer, "issuer")
        self.not_before = _to_utc(_parse_optional_datetime(self.not_before, "not_before"))
        self.not_after = _to_utc(_parse_optional_datetime(self.not_after, "not_after"))
        self.signature_algorithm = _optional_text(
            self.signature_algorithm, "signature_algorithm"
        )
        self.key_type = _optional_text(self.key_type, "key_type")
        if self.key_bits is not None and not _strict_int(self.key_bits):
            raise ValueError(f"key_bits must be an integer or None, got {self.key_bits!r}")
        self.sot_hostname = _optional_text(self.sot_hostname, "sot_hostname")

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "ip": self.ip,
            "port": self.port,
            "subject_cn": self.subject_cn,
            "san_dns_names": list(self.san_dns_names),
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "signature_algorithm": self.signature_algorithm,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "sot_hostname": self.sot_hostname,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CertificateRecord:
        return cls(
            site_id=data.get("site_id"),
            ip=data.get("ip"),
            port=data.get("port"),
            subject_cn=data.get("subject_cn"),
            san_dns_names=data.get("san_dns_names") or [],
            issuer=data.get("issuer"),
            not_before=data.get("not_before"),
            not_after=data.get("not_after"),
            signature_algorithm=data.get("signature_algorithm"),
            key_type=data.get("key_type"),
            key_bits=data.get("key_bits"),
            sot_hostname=data.get("sot_hostname"),
        )


@dataclass
class CertificateFinding:
    """Expiry and weak-crypto issues found on one certificate endpoint."""

    site_id: str
    ip: str
    port: int
    subject_cn: Optional[str]
    issuer: Optional[str]
    not_after: Optional[datetime]
    days_remaining: Optional[int]
    issues: list[str]
    severity: str

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {VALID_SEVERITIES}, got {self.severity!r}"
            )
        self.issues = list(self.issues)
        self.not_after = _to_utc(self.not_after)

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "ip": self.ip,
            "port": self.port,
            "subject_cn": self.subject_cn,
            "issuer": self.issuer,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_remaining": self.days_remaining,
            "issues": list(self.issues),
            "severity": self.severity,
        }


def _normalize_warn_days(warn_days: Iterable[int]) -> tuple[int, ...]:
    values = tuple(warn_days)
    for value in values:
        if not _strict_int(value) or value <= 0:
            raise ValueError(f"warn_days must be positive integers, got {value!r}")
    return tuple(sorted(set(values)))


def _issuer_common_name(issuer: str) -> str:
    pattern = (
        _ONELINE_ISSUER_CN_PATTERN if issuer.lstrip().startswith("/") else _ISSUER_CN_PATTERN
    )
    match = pattern.search(issuer)
    if match is not None:
        return match.group(1)
    return issuer


def _is_sha1(signature_algorithm: str) -> bool:
    if signature_algorithm.strip() == SHA1_WITH_RSA_OID:
        return True
    return "sha1" in re.sub(r"[^a-z0-9]", "", signature_algorithm.lower())


def _normalize_dns_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _name_matches(cert_name: str, sot_hostname: str) -> bool:
    if cert_name == sot_hostname:
        return True
    if "." not in sot_hostname:
        return not cert_name.startswith("*") and cert_name.split(".", 1)[0] == sot_hostname
    if cert_name.startswith("*."):
        first_label, _, rest = sot_hostname.partition(".")
        return bool(first_label) and rest == cert_name[2:]
    return False


def _hostname_mismatch(record: CertificateRecord) -> bool:
    if not _known(record.sot_hostname):
        return False
    sot_hostname = _normalize_dns_name(record.sot_hostname)
    names = [
        _normalize_dns_name(name)
        for name in [record.subject_cn, *record.san_dns_names]
        if _known(name)
    ]
    names = [name for name in names if name]
    if not sot_hostname or not names:
        return False
    return not any(_name_matches(name, sot_hostname) for name in names)


def _ip_sort_key(ip: str) -> tuple[int, int]:
    address = ipaddress.ip_address(ip)
    return (address.version, int(address))


def sort_findings(findings: Iterable[CertificateFinding]) -> list[CertificateFinding]:
    """Sort by days remaining (unknown last), then site, numeric IP and port.

    The remaining fields break ties between findings on the same endpoint so the
    order never depends on the input order.
    """
    return sorted(
        findings,
        key=lambda f: (
            f.days_remaining is None,
            f.days_remaining if f.days_remaining is not None else 0,
            f.site_id,
            _ip_sort_key(f.ip),
            f.port,
            f.severity,
            tuple(f.issues),
            f.subject_cn or "",
            f.issuer or "",
            f.not_after.isoformat() if f.not_after else "",
        ),
    )


class CertificateInventory:
    """Evaluate TLS certificate records for expiry and weak-crypto issues."""

    def evaluate(
        self,
        records: Iterable[CertificateRecord | Mapping[str, Any]],
        now: Optional[datetime] = None,
        warn_days: Iterable[int] = DEFAULT_WARN_DAYS,
    ) -> list[CertificateFinding]:
        buckets = _normalize_warn_days(warn_days)
        if now is None:
            now = datetime.now(timezone.utc)
        elif not isinstance(now, datetime):
            raise ValueError("now must be a datetime instance or None")
        now = _to_utc(now)
        findings = []
        for record in records:
            if not isinstance(record, CertificateRecord):
                record = CertificateRecord.from_dict(record)
            finding = self._evaluate_record(record, now, buckets)
            if finding is not None:
                findings.append(finding)
        return sort_findings(findings)

    @staticmethod
    def _evaluate_record(
        record: CertificateRecord, now: datetime, buckets: tuple[int, ...]
    ) -> Optional[CertificateFinding]:
        issues: list[str] = []
        days_remaining: Optional[int] = None
        expired = False
        if record.not_after is not None:
            days_remaining = (record.not_after - now).days
            expired = record.not_after < now
            if expired:
                issues.append(ISSUE_EXPIRED)
            else:
                bucket = next((n for n in buckets if days_remaining <= n), None)
                if bucket is not None:
                    issues.append(expiring_issue(bucket))
        if record.not_before is not None and record.not_before > now:
            issues.append(ISSUE_NOT_YET_VALID)
        if (
            _known(record.issuer)
            and _known(record.subject_cn)
            and _issuer_common_name(record.issuer).strip().lower()
            == record.subject_cn.strip().lower()
        ):
            issues.append(ISSUE_SELF_SIGNED)
        if _known(record.signature_algorithm) and _is_sha1(record.signature_algorithm):
            issues.append(ISSUE_SHA1_SIGNATURE)
        if (
            _known(record.key_type)
            and record.key_type.strip().lower() == "rsa"
            and record.key_bits is not None
            and record.key_bits < MIN_RSA_KEY_BITS
        ):
            issues.append(ISSUE_RSA_KEY_LT_2048)
        if _hostname_mismatch(record):
            issues.append(ISSUE_HOSTNAME_MISMATCH)
        if not issues:
            return None

        if ISSUE_EXPIRED in issues or ISSUE_NOT_YET_VALID in issues:
            severity = "error"
        elif (
            (days_remaining is not None and days_remaining <= WARNING_DAYS_THRESHOLD)
            or ISSUE_SHA1_SIGNATURE in issues
            or ISSUE_RSA_KEY_LT_2048 in issues
        ):
            severity = "warning"
        else:
            severity = "info"
        return CertificateFinding(
            site_id=record.site_id,
            ip=record.ip,
            port=record.port,
            subject_cn=record.subject_cn,
            issuer=record.issuer,
            not_after=record.not_after,
            days_remaining=days_remaining,
            issues=issues,
            severity=severity,
        )


def _severity_counts(findings: Iterable[CertificateFinding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity: counts.get(severity, 0) for severity in VALID_SEVERITIES}


def generate_certificate_json_report(
    findings: Iterable[CertificateFinding],
    generated_at: Optional[datetime | str] = None,
) -> str:
    """Return a deterministic JSON certificate inventory report."""
    ordered = sort_findings(findings)
    report = {
        "generated_at": _resolve_report_timestamp(generated_at).isoformat(),
        "total_findings": len(ordered),
        "severity_counts": _severity_counts(ordered),
        "findings": [finding.to_dict() for finding in ordered],
    }
    return json.dumps(report, indent=2, sort_keys=True)


def _md_cell(value: Any) -> str:
    if value is None:
        return ""
    # Lone carriage returns also end a Markdown line, so fold them into newlines first.
    return _escape_md_cell(str(value).replace("\r\n", "\n").replace("\r", "\n"))


def _md_row(cells: Iterable[Any]) -> str:
    return "| " + " | ".join(_md_cell(cell) for cell in cells) + " |"


def generate_certificate_markdown_report(
    findings: Iterable[CertificateFinding],
    generated_at: Optional[datetime | str] = None,
) -> str:
    """Return a deterministic Markdown certificate inventory report."""
    ordered = sort_findings(findings)
    timestamp = _resolve_report_timestamp(generated_at).isoformat()
    lines = [
        "# TLS Certificate Inventory",
        "",
        f"Generated at: {timestamp}",
        "",
        f"Total findings: {len(ordered)}",
        "",
    ]
    if not ordered:
        lines.extend(["No certificate findings.", ""])

    lines.extend(
        [
            "## Findings by Site",
            "",
            "| Site | Error | Warning | Info | Total |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    by_site: dict[str, list[CertificateFinding]] = {}
    for finding in ordered:
        by_site.setdefault(finding.site_id, []).append(finding)
    for site_id in sorted(by_site):
        counts = _severity_counts(by_site[site_id])
        lines.append(
            _md_row(
                [
                    site_id,
                    counts["error"],
                    counts["warning"],
                    counts["info"],
                    len(by_site[site_id]),
                ]
            )
        )

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Site | IP | Port | Subject CN | Issuer | Not After | Days Remaining | Severity | Issues |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in ordered:
        lines.append(
            _md_row(
                [
                    finding.site_id,
                    finding.ip,
                    finding.port,
                    finding.subject_cn,
                    finding.issuer,
                    finding.not_after.isoformat() if finding.not_after else None,
                    finding.days_remaining,
                    finding.severity,
                    ", ".join(finding.issues),
                ]
            )
        )
    return "\n".join(lines) + "\n"
