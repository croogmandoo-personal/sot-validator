"""CLI surface snapshot tests: `--help` text and parsed Namespaces for every subcommand.

These pin the argparse surface of `sot_validator.cli.build_parser()` so the CLI can be
restructured without changing flags, defaults, help strings, aliases or handler mapping.
Regenerate the help fixtures with `UPDATE_CLI_HELP_SNAPSHOTS=1 python3 -m pytest
tests/test_cli_surface.py`.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterator
import os
from pathlib import Path
import re
from typing import Any

import pytest

from sot_validator.cli import build_parser

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "cli_help"
TOP_LEVEL_FIXTURE = "sot-validator"
UPDATE_ENV = "UPDATE_CLI_HELP_SNAPSHOTS"
HELP_COLUMNS = "100"

# `-x METAVAR, --long METAVAR` (and `--a METAVAR, --b METAVAR`): drop all but the last metavar.
_REPEATED_METAVAR_RE = re.compile(
    r"(--?[\w-]+) (\S(?:(?!, ).)*?), (?=--?[\w-]+(?:, --?[\w-]+)* \2(?:,| |$))"
)
_WHITESPACE_RE = re.compile(r"\s+")


def _normalise_help(text: str) -> str:
    """Strip argparse formatting that varies across supported Python versions.

    The project allows Python 3.11+, and argparse output differs between releases:
    3.13 prints `-x, --long METAVAR` where older versions print `-x METAVAR, --long
    METAVAR` (the same applies to two long aliases of one option), 3.10 renamed `optional arguments:` to `options:`, and line wrapping
    shifts with indentation changes. Comparing this normalised form keeps the
    snapshots about flags and help text, not about the interpreter running them.
    """
    text = text.replace("optional arguments:", "options:")
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return _REPEATED_METAVAR_RE.sub(r"\1, ", text)


def _iter_parsers(
    parser: argparse.ArgumentParser, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], argparse.ArgumentParser]]:
    """Yield `(command path, parser)` for the parser and every primary subcommand, recursively."""
    yield path, parser
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        seen: set[int] = set()
        # `choices` maps the primary name first, then each alias, to the same parser.
        for name, subparser in action.choices.items():
            if id(subparser) in seen:
                continue
            seen.add(id(subparser))
            yield from _iter_parsers(subparser, path + (name,))


def _iter_aliases(parser: argparse.ArgumentParser) -> Iterator[tuple[str, str]]:
    """Yield `(alias, primary name)` for every subcommand alias, recursively."""
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        primaries: dict[int, str] = {}
        for name, subparser in action.choices.items():
            if id(subparser) in primaries:
                yield name, primaries[id(subparser)]
                continue
            primaries[id(subparser)] = name
            yield from _iter_aliases(subparser)


def _fixture_name(path: tuple[str, ...]) -> str:
    return ".".join(path) if path else TOP_LEVEL_FIXTURE


def _render_help(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Render every parser's help with a fixed width and colour off."""
    monkeypatch.setenv("COLUMNS", HELP_COLUMNS)
    monkeypatch.setenv("PYTHON_COLORS", "0")
    monkeypatch.setenv("NO_COLOR", "1")
    return {_fixture_name(path): parser.format_help() for path, parser in _iter_parsers(build_parser())}


def _update_snapshots(rendered: dict[str, str]) -> None:
    """Rewrite the raw help fixtures from the live parser (only when UPDATE_ENV is set)."""
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for stale in FIXTURE_DIR.glob("*.txt"):
        if stale.stem not in rendered:
            stale.unlink()
    for name, text in rendered.items():
        (FIXTURE_DIR / f"{name}.txt").write_text(text, encoding="utf-8")


def test_help_snapshots_match_registered_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    rendered = _render_help(monkeypatch)
    if os.environ.get(UPDATE_ENV) == "1":
        _update_snapshots(rendered)

    fixtures = {path.stem for path in FIXTURE_DIR.glob("*.txt")}
    missing = sorted(set(rendered) - fixtures)
    orphaned = sorted(fixtures - set(rendered))
    assert not missing, f"registered commands without a help fixture: {missing}"
    assert not orphaned, f"help fixtures without a registered command: {orphaned}"

    mismatched = [
        name
        for name, text in rendered.items()
        if _normalise_help(text)
        != _normalise_help((FIXTURE_DIR / f"{name}.txt").read_text(encoding="utf-8"))
    ]
    assert not mismatched, f"help output differs from fixture for: {mismatched}"


def test_normalise_help_removes_version_specific_formatting() -> None:
    old = "optional arguments:\n  -s SITE_ID, --site-id SITE_ID\n        Target   site."
    new = "options:\n  -s, --site-id SITE_ID  Target site."
    assert _normalise_help(old) == _normalise_help(new) == "options: -s, --site-id SITE_ID Target site."
    old_aliases = "  --manifest-file MANIFEST_FILE, --manifest MANIFEST_FILE\n  -i A B, --in A B, --input A B"
    new_aliases = "  --manifest-file, --manifest MANIFEST_FILE\n  -i, --in, --input A B"
    assert _normalise_help(old_aliases) == _normalise_help(new_aliases)
    assert _normalise_help("--site-ids SITE_IDS [SITE_IDS ...]") == "--site-ids SITE_IDS [SITE_IDS ...]"


NAMESPACE_CASES = [
    pytest.param(
        ["extract", "--fixtures", "--site-ids", "site-001,site-002", "--batch-size", "5"],
        {"subcommand": "extract",
         "snapshot_dir": Path("snapshots"),
         "site_ids": ["site-001,site-002"],
         "all_sites": False,
         "batch_size": 5,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_extract"},
        id="extract",
    ),
    pytest.param(
        ["validate", "--fixtures", "--output-dir", "out", "--stale-after-days", "45"],
        {"subcommand": "validate",
         "snapshot_dir": None,
         "output_dir": Path("out"),
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "vcenter_json": None,
         "snmp_fixture": None,
         "ad_json": None,
         "dns_json": None,
         "dhcp_json": None,
         "active_within_days": 7.0,
         "stale_after_days": 45.0,
         "evaluation_time": None,
         "include_ips": True,
         "func": "cmd_validate"},
        id="validate",
    ),
    pytest.param(
        ["report", "--results-file", "results.json", "--html-dashboard"],
        {"subcommand": "report",
         "results_file": Path("results.json"),
         "input_dir": None,
         "snapshot_dir": None,
         "output_dir": None,
         "evaluation_time": None,
         "html_dashboard": True,
         "html_output": None,
         "manifest_file": None,
         "reconciliation_file": None,
         "port_plan_file": None,
         "parity_file": None,
         "ups_health_file": None,
         "itsm_tickets_file": None,
         "func": "cmd_report"},
        id="report",
    ),
    pytest.param(
        ["run", "--fixtures", "--all-sites", "--evaluation-time", "2026-02-12T12:00:00Z"],
        {"subcommand": "run",
         "snapshot_dir": None,
         "output_dir": Path("output"),
         "html_dashboard": False,
         "html_output": None,
         "site_ids": None,
         "all_sites": True,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "vcenter_json": None,
         "snmp_fixture": None,
         "ad_json": None,
         "dns_json": None,
         "dhcp_json": None,
         "active_within_days": 7.0,
         "stale_after_days": 30.0,
         "evaluation_time": "2026-02-12T12:00:00Z",
         "include_ips": True,
         "func": "cmd_run"},
        id="run",
    ),
    pytest.param(
        ["history", "--db-path", "history.db", "--site-id", "site-001", "--min-consecutive-stale", "3"],
        {"subcommand": "history",
         "db_path": Path("history.db"),
         "import_json": None,
         "results_file": None,
         "run_id": None,
         "recorded_at": None,
         "site_id": "site-001",
         "min_consecutive_stale": 3,
         "export_json": None,
         "drift_output": None,
         "output_dir": None,
         "func": "cmd_history"},
        id="history",
    ),
    pytest.param(
        ["history-prune", "--config", "fleet.toml"],
        {"subcommand": "history-prune",
         "db_path": Path("history.db"),
         "config": Path("fleet.toml"),
         "apply": False,
         "now": None,
         "func": "cmd_history_prune"},
        id="history-prune",
    ),
    pytest.param(
        ["quarantine", "--results-file", "results.json", "--approve-all", "--reviewer", "ops"],
        {"subcommand": "quarantine",
         "results_file": Path("results.json"),
         "db_path": None,
         "snapshot_dir": None,
         "manifest_in": None,
         "output": Path("output/approval_manifest.json"),
         "csv_out": None,
         "min_consecutive_stale_runs": 3,
         "min_stale_days": 30.0,
         "min_confidence": 0.85,
         "protected_item_ids": None,
         "protected_categories": None,
         "protected_subnets": None,
         "protected_vendors": None,
         "allow_protected_override": False,
         "include_below_threshold": False,
         "approve_all": True,
         "approve_items": None,
         "reject_items": None,
         "reviewer": "ops",
         "review_note": None,
         "manifest_id": None,
         "generated_at": None,
         "func": "cmd_quarantine"},
        id="quarantine",
    ),
    pytest.param(
        ["remediate", "--execute-approved-plan", "manifest.json", "--confirm-write"],
        {"subcommand": "remediate",
         "manifest": Path("manifest.json"),
         "output_dir": Path("output"),
         "journal_path": None,
         "snapshot_dir": None,
         "sqlite_db": None,
         "confirm_write": True,
         "strict_approval": False,
         "execution_id": None,
         "reviewer": None,
         "rollback_execution_id": None,
         "require_itsm_approval": False,
         "itsm_ticket_id": None,
         "itsm_tickets_file": None,
         "itsm_ticket_file": None,
         "itsm_allow_scheduled": False,
         "func": "cmd_remediate"},
        id="remediate",
    ),
    pytest.param(
        ["reconcile", "--fixtures", "--arp-json", "arp.json"],
        {"subcommand": "reconcile",
         "snapshot_dir": None,
         "output_dir": Path("output"),
         "vcenter_json": None,
         "snmp_fixture": None,
         "arp_json": Path("arp.json"),
         "icmp_json": None,
         "generated_at": None,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_reconcile"},
        id="reconcile",
    ),
    pytest.param(
        ["campaign", "--fixtures", "--cohort-size", "4", "--webhook-format", "slack"],
        {"subcommand": "campaign",
         "snapshot_dir": None,
         "output_dir": Path("output"),
         "campaign_id": "campaign-run",
         "cohort_size": 4,
         "max_unreachable_ratio": 0.5,
         "max_consecutive_aborted_sites": 2,
         "high_stale_ratio_threshold": 0.4,
         "alerts_file": None,
         "webhook_format": "slack",
         "history_db": None,
         "html_dashboard": False,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "vcenter_json": None,
         "snmp_fixture": None,
         "ad_json": None,
         "dns_json": None,
         "dhcp_json": None,
         "active_within_days": 7.0,
         "stale_after_days": 30.0,
         "evaluation_time": None,
         "include_ips": True,
         "func": "cmd_campaign"},
        id="campaign",
    ),
    pytest.param(
        ["preflight", "--fixtures", "--pilot-sites", "site-001", "--strict"],
        {"subcommand": "preflight",
         "snapshot_dir": None,
         "output_dir": Path("reports"),
         "output": None,
         "pilot_sites": ["site-001"],
         "target_subnets_json": None,
         "vcenter_json": None,
         "snmp_fixture": None,
         "recommended_min_sites": 3,
         "recommended_max_sites": 5,
         "strict": True,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_preflight"},
        id="preflight",
    ),
    pytest.param(
        ["reclaim-ports", "--fixtures", "--dialect", "exos", "--min-inactive-runs", "2"],
        {"subcommand": "reclaim-ports",
         "snapshot_dir": None,
         "output_dir": Path("reports"),
         "output_file": None,
         "db_path": None,
         "streaks_json": None,
         "lldp_json": None,
         "snmp_fixture": None,
         "dialect": "exos",
         "min_inactive_runs": 2,
         "min_inactive_days": 30.0,
         "evaluation_time": None,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_reclaim_ports"},
        id="reclaim-ports",
    ),
    pytest.param(
        ["export-modern-sot", "--fixtures", "--target-platform", "nautobot", "--include-stale"],
        {"subcommand": "export-modern-sot",
         "snapshot_dir": None,
         "output_dir": Path("reports"),
         "target_platform": "nautobot",
         "results_file": None,
         "reconciliation_file": None,
         "include_stale": True,
         "merge_untracked": True,
         "approved_discrepancy_ids": None,
         "json_out": None,
         "csv_bundle_dir": None,
         "generated_at": None,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_export_modern_sot"},
        id="export-modern-sot",
    ),
    pytest.param(
        ["parity-check", "--fixtures", "--waive-all", "--output-file", "parity.json"],
        {"subcommand": "parity-check",
         "snapshot_dir": None,
         "output_dir": Path("reports"),
         "output_file": Path("parity.json"),
         "golden_bundle": None,
         "modern_bundle": None,
         "target_platform": "netbox",
         "results_file": None,
         "reconciliation_file": None,
         "stale_item_ids": None,
         "waive_discrepancies": None,
         "waive_all": True,
         "evaluated_at": None,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_parity_check"},
        id="parity-check",
    ),
    pytest.param(
        ["ups-health", "--fixtures", "--min-runtime-minutes", "15"],
        {"subcommand": "ups-health",
         "snapshot_dir": None,
         "output_dir": Path("reports"),
         "output_file": None,
         "snmp_fixture": None,
         "min_runtime_minutes": 15.0,
         "critical_runtime_minutes": 5.0,
         "max_temp_celsius": 40.0,
         "critical_temp_celsius": 50.0,
         "max_load_pct": 80.0,
         "critical_load_pct": 95.0,
         "evaluation_time": None,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_ups_health"},
        id="ups-health",
    ),
    pytest.param(
        ["itsm", "--provider", "jira", "--project-key", "OPS", "--site-id", "site-001"],
        {"subcommand": "itsm",
         "output_dir": Path("reports"),
         "output": None,
         "sink_file": None,
         "manifest_file": None,
         "port_plan_file": None,
         "reconciliation_file": None,
         "ups_health_file": None,
         "artifact_file": None,
         "workflow_type": None,
         "ticket_id": None,
         "site_id": "site-001",
         "cmdb_ci": None,
         "provider": "jira",
         "project_key": "OPS",
         "approval_status": "PENDING",
         "approve_ticket_id": None,
         "reject_ticket_id": None,
         "approved_by": "cab-approver",
         "approved_at": None,
         "verify_ticket_id": None,
         "allow_scheduled": False,
         "expected_sha256": None,
         "payload_out": None,
         "evaluation_time": None,
         "func": "cmd_itsm"},
        id="itsm",
    ),
    pytest.param(
        ["discover", "--cidr", "10.1.0.0/16", "--site-id", "site-001", "--fixtures"],
        {"subcommand": "discover",
         "cidr": "10.1.0.0/16",
         "site_id": "site-001",
         "site_name": "Discovered Site",
         "output": None,
         "output_dir": None,
         "snapshot_dir": None,
         "gateway_octets": None,
         "tcp_ports": None,
         "max_concurrency": 128,
         "max_active_subnets": 32,
         "ping_timeout": 1.0,
         "tcp_timeout": 0.35,
         "mock_config": None,
         "fixtures": True,
         "router_arp": None,
         "dhcp_leases": None,
         "proxmox_snapshot": None,
         "evaluation_time": None,
         "validate": False,
         "report": False,
         "html_dashboard": False,
         "html_output": None,
         "func": "cmd_discover"},
        id="discover",
    ),
    pytest.param(
        ["serve", "--host", "127.0.0.1", "--port", "0", "--check"],
        {"subcommand": "serve",
         "host": "127.0.0.1",
         "port": 0,
         "token": None,
         "allow_remote": False,
         "snapshot": None,
         "snapshot_dir": None,
         "curation_db": None,
         "results_file": None,
         "site_id": None,
         "once": False,
         "check": True,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": False,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_serve"},
        id="serve",
    ),
    pytest.param(
        ["curate", "--db-path", "curation.db", "--site-id", "site-001", "--target-type", "device", "--target-id", "dev-1", "--name", "core"],
        {"subcommand": "curate",
         "curation_db": Path("curation.db"),
         "snapshot": None,
         "output": None,
         "export_json": None,
         "import_json": None,
         "site_id": "site-001",
         "actor": "cli-operator",
         "reason": "",
         "target_type": "device",
         "target_id": "dev-1",
         "name": "core",
         "hostname": None,
         "category": None,
         "role": None,
         "vendor": None,
         "model": None,
         "vlan_id": None,
         "subnet_id": None,
         "room": None,
         "notes": None,
         "pin_classification": None,
         "delete": False,
         "add_device": None,
         "template_id": None,
         "device_id": None,
         "management_ip": None,
         "port_count": None,
         "add_port": None,
         "port_range": None,
         "poe_status": None,
         "admin_status": None,
         "oper_status": None,
         "connected_device_id": None,
         "connected_mac": None,
         "add_vlan": None,
         "cidr": None,
         "gateway": None,
         "list_audit": False,
         "limit": 100,
         "func": "cmd_curate"},
        id="curate",
    ),
    pytest.param(
        ["topology", "--fixtures", "--site-id", "site-001", "--include-unconnected-ports"],
        {"subcommand": "topology",
         "snapshot": None,
         "snapshot_dir": None,
         "curation_db": None,
         "results_file": None,
         "site_id": "site-001",
         "include_unconnected_ports": True,
         "output_json": None,
         "output_mermaid": None,
         "output_dir": None,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": True,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_topology"},
        id="topology",
    ),
    pytest.param(
        ["fingerprint", "--banners", "banners.json", "--site-id", "site-001"],
        {"subcommand": "fingerprint",
         "snapshot": None,
         "banners": Path("banners.json"),
         "output": None,
         "site_id": "site-001",
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": False,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_fingerprint"},
        id="fingerprint",
    ),
    pytest.param(
        ["map-ports", "--fdb-file", "fdb.txt", "--device-id", "dev-1"],
        {"subcommand": "map-ports",
         "snapshot": None,
         "fdb_file": Path("fdb.txt"),
         "device_id": "dev-1",
         "curation_db": None,
         "output": None,
         "site_id": None,
         "site_ids": None,
         "all_sites": False,
         "batch_size": 10,
         "rate_limit": 0.0,
         "no_resume": False,
         "fixtures": False,
         "num_sites": 3,
         "fixture_path": None,
         "sql_dump": None,
         "sqlite_path": None,
         "csv_dir": None,
         "json_export": None,
         "scrape_url": None,
         "func": "cmd_map_ports"},
        id="map-ports",
    ),
    pytest.param(
        ["diff-scans", "--baseline", "a.json", "--current", "b.json", "--output-md", "drift.md"],
        {"subcommand": "diff-scans",
         "baseline": Path("a.json"),
         "current": Path("b.json"),
         "curation_db": None,
         "output_json": None,
         "output_md": Path("drift.md"),
         "alert_file": None,
         "func": "cmd_diff_scans"},
        id="diff-scans",
    ),
]

ALIAS_CASES = [
    pytest.param(["migrate-export"], "cmd_export_modern_sot", id="migrate-export"),
    pytest.param(["migration-parity"], "cmd_parity_check", id="migration-parity"),
    pytest.param(["itsm-sync"], "cmd_itsm", id="itsm-sync"),
]


@pytest.mark.parametrize(("argv", "expected"), NAMESPACE_CASES)
def test_parse_args_namespace(argv: list[str], expected: dict[str, Any]) -> None:
    parsed = vars(build_parser().parse_args(argv))
    parsed["func"] = parsed["func"].__name__
    assert parsed == expected


@pytest.mark.parametrize(("argv", "handler"), ALIAS_CASES)
def test_alias_dispatches_to_primary_handler(argv: list[str], handler: str) -> None:
    parser = build_parser()
    primary = dict(_iter_aliases(parser))[argv[0]]
    assert parser.parse_args(argv).func.__name__ == handler
    assert parser.parse_args([primary]).func.__name__ == handler


def test_every_command_and_alias_has_namespace_case() -> None:
    parser = build_parser()
    commands = {" ".join(path) for path, _ in _iter_parsers(parser) if path}
    covered = {
        " ".join(param.values[0][:depth])
        for param in NAMESPACE_CASES
        for depth in range(1, len(param.values[0]) + 1)
    }
    assert sorted(commands - covered) == [], "subcommands without a Namespace case"
    aliases = {alias for alias, _ in _iter_aliases(parser)}
    covered_aliases = {param.values[0][0] for param in ALIAS_CASES}
    assert sorted(aliases - covered_aliases) == [], "aliases without a Namespace case"
