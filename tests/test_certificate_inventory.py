"""Unit tests for the TLS certificate expiry and weak-crypto inventory."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import random
import re

import pytest

from sot_validator.lifecycle import (
    ISSUE_EXPIRED,
    ISSUE_HOSTNAME_MISMATCH,
    ISSUE_NOT_YET_VALID,
    ISSUE_RSA_KEY_LT_2048,
    ISSUE_SELF_SIGNED,
    ISSUE_SHA1_SIGNATURE,
    VALID_SEVERITIES,
    CertificateFinding,
    CertificateInventory,
    CertificateRecord,
    expiring_issue,
    generate_certificate_json_report,
    generate_certificate_markdown_report,
    sort_findings,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
GENERATED_AT = "2026-01-01T12:00:00+00:00"
FAR_FUTURE = NOW + timedelta(days=3650)


def _record(**overrides) -> CertificateRecord:
    values = {"site_id": "S1", "ip": "10.1.1.1", "port": 443}
    values.update(overrides)
    return CertificateRecord(**values)


def _evaluate(*records, **kwargs) -> list[CertificateFinding]:
    return CertificateInventory().evaluate(list(records), now=NOW, **kwargs)


def _single(record: CertificateRecord, **kwargs) -> CertificateFinding:
    findings = _evaluate(record, **kwargs)
    assert len(findings) == 1
    return findings[0]


def _finding(**overrides) -> CertificateFinding:
    values = {
        "site_id": "S1",
        "ip": "10.1.1.1",
        "port": 443,
        "subject_cn": "sw01.corp.local",
        "issuer": "CN=Corp CA",
        "not_after": NOW + timedelta(days=10),
        "days_remaining": 10,
        "issues": [expiring_issue(30)],
        "severity": "warning",
    }
    values.update(overrides)
    return CertificateFinding(**values)


# --- Expiry boundaries --------------------------------------------------------


@pytest.mark.parametrize(
    ("days", "expected_issues", "severity"),
    [
        (0, ["expiring_30d"], "warning"),
        (29, ["expiring_30d"], "warning"),
        (30, ["expiring_30d"], "warning"),
        (31, ["expiring_60d"], "info"),
        (59, ["expiring_60d"], "info"),
        (60, ["expiring_60d"], "info"),
        (61, ["expiring_90d"], "info"),
        (89, ["expiring_90d"], "info"),
        (90, ["expiring_90d"], "info"),
    ],
)
def test_expiry_bucket_boundaries(days, expected_issues, severity):
    finding = _single(_record(not_after=NOW + timedelta(days=days)))
    assert finding.issues == expected_issues
    assert finding.days_remaining == days
    assert finding.severity == severity


def test_beyond_largest_bucket_gives_no_finding():
    assert _evaluate(_record(not_after=NOW + timedelta(days=91))) == []


def test_days_remaining_is_floored():
    finding = _single(_record(not_after=NOW + timedelta(days=30, hours=23)))
    assert finding.days_remaining == 30
    assert finding.issues == ["expiring_30d"]


def test_custom_unsorted_warn_days_pick_tightest_bucket():
    record = _record(not_after=NOW + timedelta(days=10))
    assert _single(record, warn_days=[45, 7, 14]).issues == ["expiring_14d"]
    assert _single(record, warn_days=(10, 100)).issues == ["expiring_10d"]
    assert _evaluate(record, warn_days=[5, 9]) == []


def test_empty_warn_days_disables_buckets_but_keeps_warning_threshold():
    record = _record(not_after=NOW + timedelta(days=10))
    assert _evaluate(record, warn_days=()) == []
    # Severity's fixed 30-day threshold still applies when another issue exists.
    record = _record(not_after=NOW + timedelta(days=10), issuer="CN=x", subject_cn="x")
    finding = _single(record, warn_days=())
    assert finding.issues == [ISSUE_SELF_SIGNED]
    assert finding.severity == "warning"


def test_custom_warn_days_do_not_move_warning_threshold():
    finding = _single(_record(not_after=NOW + timedelta(days=40)), warn_days=[45])
    assert finding.issues == ["expiring_45d"]
    assert finding.severity == "info"


@pytest.mark.parametrize(
    "warn_days", [[0], [-5], [30, 0], [30.0], ["30"], [True], "30", [None]]
)
def test_bad_warn_days_raise(warn_days):
    with pytest.raises(ValueError):
        CertificateInventory().evaluate([], now=NOW, warn_days=warn_days)


# --- Expired / not yet valid --------------------------------------------------


def test_expired_is_error_without_expiring_flag():
    finding = _single(_record(not_after=NOW - timedelta(hours=1)))
    assert finding.issues == [ISSUE_EXPIRED]
    assert finding.days_remaining == -1
    assert finding.severity == "error"


def test_expiring_exactly_now_is_not_expired():
    finding = _single(_record(not_after=NOW))
    assert finding.issues == ["expiring_30d"]
    assert finding.days_remaining == 0


def test_not_yet_valid_is_error():
    finding = _single(_record(not_before=NOW + timedelta(days=1), not_after=FAR_FUTURE))
    assert finding.issues == [ISSUE_NOT_YET_VALID]
    assert finding.severity == "error"


def test_not_before_in_past_not_flagged():
    assert _evaluate(_record(not_before=NOW - timedelta(days=1), not_after=FAR_FUTURE)) == []


# --- Self-signed --------------------------------------------------------------


def test_self_signed_from_issuer_dn():
    finding = _single(
        _record(issuer="CN=sw01.corp.local, O=X", subject_cn="sw01.corp.local")
    )
    assert finding.issues == [ISSUE_SELF_SIGNED]
    assert finding.severity == "info"


@pytest.mark.parametrize(
    "issuer",
    ["  SW01.Corp.Local ", "O=X, cn = SW01.corp.local", "/C=US/CN=sw01.corp.local"],
)
def test_self_signed_variants(issuer):
    assert _single(_record(issuer=issuer, subject_cn="sw01.corp.local")).issues == [
        ISSUE_SELF_SIGNED
    ]


def test_self_signed_cn_parsing_by_dn_style():
    # RFC 4514 DNs may carry "/" inside a CN; OpenSSL oneline DNs may carry ",".
    assert _single(_record(issuer="CN=web/admin, O=X", subject_cn="web/admin")).issues == [
        ISSUE_SELF_SIGNED
    ]
    assert _single(_record(issuer="/O=X/CN=Corp, Inc", subject_cn="Corp, Inc")).issues == [
        ISSUE_SELF_SIGNED
    ]
    # An unescaped "+" starts a new attribute of a multi-valued RDN.
    assert _single(_record(issuer="CN=sw01+OU=Net, O=X", subject_cn="sw01")).issues == [
        ISSUE_SELF_SIGNED
    ]


def test_escaped_dn_separators_are_not_unescaped():
    # Known limit: RFC 4514 escapes ("\\," and "\\+") are not decoded, so the CN
    # ends at the escaped separator and the self-signed check does not match.
    for issuer, cn in (("CN=Foo\\, Inc", "Foo, Inc"), ("CN=a\\+b", "a+b")):
        record = _record(issuer=issuer, subject_cn=cn, not_after=FAR_FUTURE)
        assert _evaluate(record) == []


@pytest.mark.parametrize(
    "issuer", ["CN=Corp Issuing CA, O=X", "O=sw01.corp.local", "XCN=sw01.corp.local"]
)
def test_not_self_signed(issuer):
    assert _evaluate(_record(issuer=issuer, subject_cn="sw01.corp.local")) == []


def test_self_signed_skipped_without_subject_or_issuer():
    assert _evaluate(_record(issuer="CN=sw01")) == []
    assert _evaluate(_record(subject_cn="sw01")) == []
    assert _evaluate(_record(issuer="  ", subject_cn="  ")) == []


# --- Weak crypto --------------------------------------------------------------


@pytest.mark.parametrize(
    "algorithm",
    ["sha1WithRSAEncryption", "ecdsa-with-SHA1", "SHA-1", "1.2.840.113549.1.1.5"],
)
def test_sha1_signature_flagged(algorithm):
    finding = _single(_record(signature_algorithm=algorithm))
    assert finding.issues == [ISSUE_SHA1_SIGNATURE]
    assert finding.severity == "warning"


@pytest.mark.parametrize(
    "algorithm", ["sha256WithRSAEncryption", "ecdsa-with-SHA384", "1.2.840.113549.1.1.11", ""]
)
def test_strong_signature_not_flagged(algorithm):
    assert _evaluate(_record(signature_algorithm=algorithm)) == []


@pytest.mark.parametrize(("key_type", "bits"), [("RSA", 1024), ("rsa", 2047)])
def test_small_rsa_key_flagged(key_type, bits):
    finding = _single(_record(key_type=key_type, key_bits=bits))
    assert finding.issues == [ISSUE_RSA_KEY_LT_2048]
    assert finding.severity == "warning"


@pytest.mark.parametrize(
    ("key_type", "bits"), [("RSA", 2048), ("RSA", 4096), ("EC", 256), ("RSA", None), (None, 1024)]
)
def test_rsa_key_not_flagged(key_type, bits):
    assert _evaluate(_record(key_type=key_type, key_bits=bits)) == []


# --- Hostname ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sot_hostname", "subject_cn", "sans"),
    [
        ("sw01.corp.local", "sw01.corp.local", []),
        ("SW01.corp.local.", "sw01.CORP.local", []),
        ("sw01.corp.local", None, ["*.corp.local"]),
        ("sw01.corp.local", "other.corp.local", ["sw01.corp.local."]),
        ("sw01", "SW01.corp.local", []),
        ("sw01", None, ["sw01"]),
    ],
)
def test_hostname_matches(sot_hostname, subject_cn, sans):
    record = _record(sot_hostname=sot_hostname, subject_cn=subject_cn, san_dns_names=sans)
    assert _evaluate(record) == []


@pytest.mark.parametrize(
    ("sot_hostname", "subject_cn", "sans"),
    [
        ("a.b.corp.local", None, ["*.corp.local"]),
        ("corp.local", None, ["*.corp.local"]),
        ("sw01", None, ["*.corp.local"]),
        ("sw01.corp.local", "sw02.corp.local", ["sw0*.corp.local"]),
        ("sw01.corp.local", "sw01", []),
        ("sw01", "sw011.corp.local", []),
    ],
)
def test_hostname_mismatch(sot_hostname, subject_cn, sans):
    record = _record(sot_hostname=sot_hostname, subject_cn=subject_cn, san_dns_names=sans)
    finding = _single(record)
    assert finding.issues == [ISSUE_HOSTNAME_MISMATCH]
    assert finding.severity == "info"


def test_hostname_rule_skipped_without_sot_hostname_or_cert_names():
    assert _evaluate(_record(subject_cn="sw01.corp.local")) == []
    assert _evaluate(_record(subject_cn="sw01.corp.local", sot_hostname="  ")) == []
    assert _evaluate(_record(sot_hostname="sw01.corp.local")) == []
    assert _evaluate(_record(sot_hostname="sw01.corp.local", san_dns_names=["", "."])) == []


# --- Combined ordering of issues and severity --------------------------------


def test_issue_order_and_error_precedence():
    record = _record(
        not_after=NOW - timedelta(days=2),
        not_before=NOW + timedelta(days=1),
        issuer="CN=x.corp.local",
        subject_cn="x.corp.local",
        signature_algorithm="sha1WithRSAEncryption",
        key_type="RSA",
        key_bits=1024,
        sot_hostname="y.corp.local",
    )
    finding = _single(record)
    assert finding.issues == [
        ISSUE_EXPIRED,
        ISSUE_NOT_YET_VALID,
        ISSUE_SELF_SIGNED,
        ISSUE_SHA1_SIGNATURE,
        ISSUE_RSA_KEY_LT_2048,
        ISSUE_HOSTNAME_MISMATCH,
    ]
    assert finding.severity == "error"


def test_expiring_flag_precedes_other_issues():
    finding = _single(
        _record(not_after=NOW + timedelta(days=50), signature_algorithm="SHA-1")
    )
    assert finding.issues == ["expiring_60d", ISSUE_SHA1_SIGNATURE]
    assert finding.severity == "warning"


# --- Missing data and clean records -------------------------------------------


def test_bare_record_gives_no_finding():
    assert _evaluate(CertificateRecord(site_id="S1", ip="10.1.1.1", port=443)) == []


def test_clean_record_gives_no_finding():
    record = _record(
        subject_cn="sw01.corp.local",
        san_dns_names=["sw01.corp.local"],
        issuer="CN=Corp Issuing CA, O=Corp",
        not_before=NOW - timedelta(days=100),
        not_after=NOW + timedelta(days=365),
        signature_algorithm="sha256WithRSAEncryption",
        key_type="RSA",
        key_bits=2048,
        sot_hostname="sw01.corp.local",
    )
    assert _evaluate(record) == []


# --- Datetimes ----------------------------------------------------------------


def test_naive_datetimes_are_utc():
    record = _record(not_after=datetime(2026, 1, 31), not_before=datetime(2025, 1, 1))
    assert record.not_after == datetime(2026, 1, 31, tzinfo=timezone.utc)
    assert record.not_before.tzinfo == timezone.utc
    finding = CertificateInventory().evaluate([record], now=datetime(2026, 1, 1))[0]
    assert finding.days_remaining == 30
    assert finding.not_after.tzinfo == timezone.utc


def test_aware_datetimes_converted_to_utc():
    eastern = timezone(timedelta(hours=-5))
    record = _record(not_after=datetime(2026, 1, 30, 19, 0, tzinfo=eastern))
    assert record.not_after == datetime(2026, 1, 31, tzinfo=timezone.utc)
    assert record.not_after.utcoffset() == timedelta(0)
    now = datetime(2025, 12, 31, 19, 0, tzinfo=eastern)
    assert CertificateInventory().evaluate([record], now=now)[0].days_remaining == 30


def test_bad_now_rejected():
    with pytest.raises(ValueError):
        CertificateInventory().evaluate([], now="2026-01-01")


# --- Record validation and dict round-trip -----------------------------------


def test_from_dict_with_iso_strings_and_missing_keys():
    record = CertificateRecord.from_dict(
        {
            "site_id": "S1",
            "ip": "10.1.1.1",
            "port": 8443,
            "not_after": "2026-01-31T00:00:00Z",
            "not_before": "2025-01-01T00:00:00",
        }
    )
    assert record.not_after == datetime(2026, 1, 31, tzinfo=timezone.utc)
    assert record.not_before == datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert record.san_dns_names == []
    assert record.subject_cn is None and record.key_bits is None
    assert CertificateRecord.from_dict(record.to_dict()) == record


def test_from_dict_ignores_key_order():
    data = {
        "sot_hostname": "sw01",
        "key_bits": 1024,
        "key_type": "RSA",
        "port": 443,
        "ip": "10.1.1.1",
        "site_id": "S1",
    }
    reversed_data = dict(reversed(list(data.items())))
    assert CertificateRecord.from_dict(data) == CertificateRecord.from_dict(reversed_data)


def test_to_dict_writes_iso_strings():
    data = _record(not_after=NOW).to_dict()
    assert data["not_after"] == "2026-01-01T00:00:00+00:00"
    assert data["not_before"] is None


def test_evaluate_accepts_mappings():
    findings = CertificateInventory().evaluate(
        [{"site_id": "S1", "ip": "10.1.1.1", "port": 443, "not_after": "2026-01-11T00:00:00+00:00"}],
        now=NOW,
    )
    assert findings[0].issues == ["expiring_30d"]
    assert findings[0].days_remaining == 10


def test_ip_canonicalised():
    assert _record(ip=" 2001:DB8::0001 ").ip == "2001:db8::1"


@pytest.mark.parametrize(
    "overrides",
    [
        {"site_id": ""},
        {"site_id": None},
        {"ip": ""},
        {"ip": "not-an-ip"},
        {"ip": "10.1.1.256"},
        {"port": 0},
        {"port": 65536},
        {"port": "443"},
        {"port": True},
        {"key_bits": "1024"},
        {"key_bits": False},
        {"san_dns_names": "sw01.corp.local"},
        {"san_dns_names": [None]},
        {"not_after": "yesterday"},
        {"not_after": 12345},
        {"subject_cn": 7},
    ],
)
def test_invalid_record_fields_raise(overrides):
    with pytest.raises(ValueError):
        _record(**overrides)


def test_from_dict_missing_required_raises_value_error():
    with pytest.raises(ValueError):
        CertificateRecord.from_dict({"ip": "10.1.1.1", "port": 443})


def test_finding_severity_validated():
    assert VALID_SEVERITIES == ("error", "warning", "info")
    with pytest.raises(ValueError):
        _finding(severity="critical")


@pytest.mark.parametrize("value", ["2026-01-01", 1767225600, "not-a-date"])
def test_finding_not_after_must_be_a_datetime(value):
    with pytest.raises(ValueError, match="not_after"):
        _finding(not_after=value)


def test_finding_to_dict():
    data = _finding().to_dict()
    assert data == {
        "site_id": "S1",
        "ip": "10.1.1.1",
        "port": 443,
        "subject_cn": "sw01.corp.local",
        "issuer": "CN=Corp CA",
        "not_after": "2026-01-11T00:00:00+00:00",
        "days_remaining": 10,
        "issues": ["expiring_30d"],
        "severity": "warning",
    }
    assert _finding(not_after=None, days_remaining=None).to_dict()["not_after"] is None


# --- Ordering -----------------------------------------------------------------


def _ordering_records() -> list[CertificateRecord]:
    return [
        _record(site_id="S1", ip="10.0.0.10", not_after=NOW + timedelta(days=5)),
        _record(site_id="S1", ip="10.0.0.9", not_after=NOW + timedelta(days=5)),
        _record(site_id="S0", ip="10.0.0.50", not_after=NOW + timedelta(days=5)),
        _record(site_id="S1", ip="10.0.0.9", port=8443, not_after=NOW + timedelta(days=5)),
        _record(site_id="S1", ip="::1", not_after=NOW + timedelta(days=5)),
        _record(site_id="S9", ip="10.0.0.1", not_after=NOW - timedelta(days=3)),
        _record(site_id="A0", ip="10.0.0.1", signature_algorithm="SHA-1"),
        _record(site_id="S2", ip="10.0.0.1", not_after=NOW + timedelta(days=80)),
    ]


EXPECTED_ORDER = [
    ("S9", "10.0.0.1", 443),
    ("S0", "10.0.0.50", 443),
    ("S1", "10.0.0.9", 443),
    ("S1", "10.0.0.9", 8443),
    ("S1", "10.0.0.10", 443),
    ("S1", "::1", 443),
    ("S2", "10.0.0.1", 443),
    ("A0", "10.0.0.1", 443),
]


def _keys(findings) -> list[tuple[str, str, int]]:
    return [(f.site_id, f.ip, f.port) for f in findings]


def test_evaluate_orders_findings_for_any_input_order():
    records = _ordering_records()
    for seed in range(5):
        shuffled = list(records)
        random.Random(seed).shuffle(shuffled)
        assert _keys(_evaluate(*shuffled)) == EXPECTED_ORDER


def test_sort_findings_none_last_and_numeric_ip():
    findings = _evaluate(*_ordering_records())
    shuffled = list(reversed(findings))
    assert _keys(sort_findings(shuffled)) == EXPECTED_ORDER
    assert sort_findings(shuffled)[-1].days_remaining is None


def test_reports_are_order_independent_and_repeatable():
    findings = _evaluate(*_ordering_records())
    shuffled = list(findings)
    random.Random(7).shuffle(shuffled)
    json_a = generate_certificate_json_report(findings, generated_at=GENERATED_AT)
    json_b = generate_certificate_json_report(shuffled, generated_at=GENERATED_AT)
    md_a = generate_certificate_markdown_report(findings, generated_at=GENERATED_AT)
    md_b = generate_certificate_markdown_report(shuffled, generated_at=GENERATED_AT)
    assert json_a == json_b == generate_certificate_json_report(shuffled, generated_at=GENERATED_AT)
    assert md_a == md_b == generate_certificate_markdown_report(shuffled, generated_at=GENERATED_AT)
    reported = [(f["site_id"], f["ip"], f["port"]) for f in json.loads(json_a)["findings"]]
    assert reported == EXPECTED_ORDER


def test_same_endpoint_findings_have_a_total_order():
    a = _record(signature_algorithm="SHA-1", subject_cn="a")
    b = _record(key_type="RSA", key_bits=1024, subject_cn="a")
    c = _record(signature_algorithm="SHA-1", issuer="CN=Corp CA", subject_cn="a")
    findings = _evaluate(a, b, c)
    assert _evaluate(c, b, a) == findings
    for report in (generate_certificate_json_report, generate_certificate_markdown_report):
        forward = report(findings, generated_at=GENERATED_AT)
        assert report(list(reversed(findings)), generated_at=GENERATED_AT) == forward
        assert report([findings[1], findings[2], findings[0]], generated_at=GENERATED_AT) == forward


def test_none_and_empty_cn_or_issuer_sort_deterministically():
    expiring = {"not_after": NOW + timedelta(days=10)}
    none_values = _record(subject_cn=None, issuer=None, **expiring)
    empty_values = _record(subject_cn="", issuer="", **expiring)
    findings = _evaluate(none_values, empty_values)
    assert _evaluate(empty_values, none_values) == findings
    assert [f.subject_cn for f in findings] == [None, ""]
    for report in (generate_certificate_json_report, generate_certificate_markdown_report):
        forward = report(findings, generated_at=GENERATED_AT)
        assert report(list(reversed(findings)), generated_at=GENERATED_AT) == forward
    empty_cn_only = _record(subject_cn="", issuer=None, **expiring)
    empty_issuer_only = _record(subject_cn=None, issuer="", **expiring)
    mixed = _evaluate(empty_cn_only, empty_issuer_only)
    assert _evaluate(empty_issuer_only, empty_cn_only) == mixed
    assert [(f.subject_cn, f.issuer) for f in mixed] == [(None, ""), ("", None)]


# --- JSON report --------------------------------------------------------------


def test_json_report_shape_and_values():
    findings = _evaluate(*_ordering_records())
    report = json.loads(generate_certificate_json_report(findings, generated_at=GENERATED_AT))
    assert set(report) == {"generated_at", "total_findings", "severity_counts", "findings"}
    assert report["generated_at"] == "2026-01-01T12:00:00+00:00"
    assert report["total_findings"] == 8
    assert report["severity_counts"] == {"error": 1, "warning": 6, "info": 1}
    assert report["findings"][0] == {
        "site_id": "S9",
        "ip": "10.0.0.1",
        "port": 443,
        "subject_cn": None,
        "issuer": None,
        "not_after": "2025-12-29T00:00:00+00:00",
        "days_remaining": -3,
        "issues": ["expired"],
        "severity": "error",
    }


def test_json_report_empty_and_naive_generated_at():
    report = json.loads(
        generate_certificate_json_report([], generated_at=datetime(2026, 1, 1, 12))
    )
    assert report["generated_at"] == "2026-01-01T12:00:00+00:00"
    assert report["total_findings"] == 0
    assert report["severity_counts"] == {"error": 0, "warning": 0, "info": 0}
    assert report["findings"] == []


# --- Markdown report ----------------------------------------------------------


def _unescaped_pipes(line: str) -> int:
    return len(re.findall(r"(?<!\\)\|", line))


def _table(markdown: str, heading: str) -> list[str]:
    lines = markdown.splitlines()
    start = lines.index(heading) + 2
    rows = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        rows.append(line)
    return rows


def test_markdown_report_structure_and_site_counts():
    findings = _evaluate(*_ordering_records())
    markdown = generate_certificate_markdown_report(findings, generated_at=GENERATED_AT)
    assert markdown.startswith("# TLS Certificate Inventory\n")
    assert "2026-01-01T12:00:00+00:00" in markdown
    assert "Total findings: 8" in markdown
    assert markdown.index("## Findings by Site") < markdown.index("## Findings\n")
    site_rows = _table(markdown, "## Findings by Site")
    assert site_rows == [
        "| Site | Error | Warning | Info | Total |",
        "| --- | --- | --- | --- | --- |",
        "| A0 | 0 | 1 | 0 | 1 |",
        "| S0 | 0 | 1 | 0 | 1 |",
        "| S1 | 0 | 4 | 0 | 4 |",
        "| S2 | 0 | 0 | 1 | 1 |",
        "| S9 | 1 | 0 | 0 | 1 |",
    ]
    finding_rows = _table(markdown, "## Findings")
    assert finding_rows[0] == (
        "| Site | IP | Port | Subject CN | Issuer | Not After | Days Remaining "
        "| Severity | Issues |"
    )
    assert len(finding_rows) == 2 + 8
    assert finding_rows[2] == (
        "| S9 | 10.0.0.1 | 443 |  |  | 2025-12-29T00:00:00+00:00 | -3 | error | expired |"
    )
    assert finding_rows[-1] == "| A0 | 10.0.0.1 | 443 |  |  |  |  | warning | sha1_signature |"


def test_markdown_escapes_pipes_and_newlines():
    finding = _finding(
        site_id="S|1",
        subject_cn="evil\rname",
        issuer="CN=Evil | CA\nO=Corp\r\nOU=x",
        issues=[expiring_issue(30), ISSUE_SELF_SIGNED],
    )
    markdown = generate_certificate_markdown_report([finding], generated_at=GENERATED_AT)
    for heading in ("## Findings by Site", "## Findings"):
        rows = _table(markdown, heading)
        header_pipes = _unescaped_pipes(rows[0])
        assert len(rows) == 3
        assert all(_unescaped_pipes(row) == header_pipes for row in rows)
    assert "CN=Evil \\| CA O=Corp OU=x" in markdown
    assert "evil name" in markdown
    assert "expiring_30d, self_signed" in markdown


def test_markdown_empty_report():
    markdown = generate_certificate_markdown_report([], generated_at=GENERATED_AT)
    assert "No certificate findings." in markdown
    assert "Total findings: 0" in markdown
    assert _table(markdown, "## Findings by Site") == [
        "| Site | Error | Warning | Info | Total |",
        "| --- | --- | --- | --- | --- |",
    ]
    assert len(_table(markdown, "## Findings")) == 2


# --- Purity -------------------------------------------------------------------


def test_module_imports_no_network_or_process_libraries():
    from pathlib import Path

    import sot_validator.lifecycle.certificates as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    pattern = re.compile(
        r"^\s*(import|from)\s+(socket|ssl|asyncio|urllib|http|subprocess)\b", re.MULTILINE
    )
    assert pattern.search(source) is None
