"""Tests for the unified TOML fleet configuration loader."""

from __future__ import annotations

import dataclasses
import ipaddress
import json
from pathlib import Path

import pytest

from sot_validator.config import (
    AppConfig,
    ConfigError,
    PolicyConfig,
    ProxmoxConfig,
    SecretValue,
    SiteConfig,
    SnmpProfile,
    VCenterConfig,
    load_config,
)

EXAMPLE_PATH = Path(__file__).resolve().parents[1] / "examples" / "sot-validator.example.toml"

SITE = """
[[sites]]
site_id = "SITE-001"
name = "HQ"
block = "10.1.0.0/16"
active_subnets = ["10.1.10.0/24", "10.1.20.0/24"]
"""

SECOND_SITE = """
[[sites]]
site_id = "SITE-002"
name = "Branch"
block = "10.2.0.0/16"
active_subnets = ["10.2.10.0/24"]
"""

VCENTER = """
[[vcenters]]
name = "vc1"
host = "vc1.example.invalid"
username = "reader"
password = "${env:VC_PW}"
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "fleet.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _site(block: str = "10.1.0.0/16", subnets: str = '["10.1.10.0/24"]', site_id: str = "S1") -> str:
    return (
        "[[sites]]\n"
        f'site_id = "{site_id}"\n'
        'name = "Site"\n'
        f'block = "{block}"\n'
        f"active_subnets = {subnets}\n"
    )


def _error(tmp_path: Path, text: str, table: str, key: str) -> str:
    """Load text, expect a ConfigError and check it names the file, table and key."""
    path = _write(tmp_path, text)
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    message = str(excinfo.value)
    assert str(path) in message
    assert f"[{table}] {key}:" in message
    return message


# --- valid loads --------------------------------------------------------------------


def test_valid_load_types_and_policy_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "pw")
    path = _write(tmp_path, SITE + SECOND_SITE + VCENTER)
    cfg = load_config(path)

    assert isinstance(cfg, AppConfig)
    assert cfg.source_path == path
    assert cfg.policy == PolicyConfig()
    assert cfg.policy.arp_active_within_days == 7.0
    assert cfg.policy.arp_stale_after_days == 30.0
    assert cfg.policy.last_seen_active_within_days == 7.0
    assert cfg.policy.last_seen_stale_after_days == 30.0
    assert cfg.policy.quarantine_min_stale_runs == 3
    assert cfg.policy.max_concurrent_probes_per_site == 32
    assert cfg.policy.max_concurrent_sites == 4

    assert isinstance(cfg.sites, tuple) and len(cfg.sites) == 2
    site = cfg.sites[0]
    assert isinstance(site, SiteConfig)
    assert site.site_id == "SITE-001"
    assert site.block == ipaddress.IPv4Network("10.1.0.0/16")
    assert isinstance(site.active_subnets, tuple)
    assert all(isinstance(net, ipaddress.IPv4Network) for net in site.active_subnets)
    assert site.active_subnets == (
        ipaddress.IPv4Network("10.1.10.0/24"),
        ipaddress.IPv4Network("10.1.20.0/24"),
    )

    vcenter = cfg.vcenters[0]
    assert isinstance(vcenter, VCenterConfig)
    assert isinstance(vcenter.password, SecretValue)
    assert vcenter.verify_tls is True
    assert cfg.snmp_profiles == ()
    assert cfg.proxmox == ()


def test_collector_defaults_and_explicit_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("COMM", "c0mm")
    monkeypatch.setenv("TOKEN", "t0ken")
    text = (
        "[policy]\n"
        "arp_active_within_days = 2\n"
        "arp_stale_after_days = 2.5\n"
        "quarantine_min_stale_runs = 5\n"
        "max_concurrent_probes_per_site = 64\n"
        "max_concurrent_sites = 10\n"
        + SITE
        + '[[snmp_profiles]]\nname = "p"\ncommunity = "${env:COMM}"\n'
        + '[[proxmox]]\nname = "pve"\nhost = "10.1.10.5"\ntoken_id = "a@pve!b"\n'
        + 'token_secret = "${env:TOKEN}"\nverify_tls = false\n'
    )
    cfg = load_config(_write(tmp_path, text))
    assert cfg.policy.arp_active_within_days == 2.0
    assert isinstance(cfg.policy.arp_active_within_days, float)
    assert cfg.policy.arp_stale_after_days == 2.5
    assert cfg.policy.last_seen_stale_after_days == 30.0
    assert cfg.policy.quarantine_min_stale_runs == 5
    assert cfg.policy.max_concurrent_probes_per_site == 64
    assert cfg.policy.max_concurrent_sites == 10

    profile = cfg.snmp_profiles[0]
    assert isinstance(profile, SnmpProfile)
    assert profile.version == "v2c"
    assert profile.community.reveal() == "c0mm"
    node = cfg.proxmox[0]
    assert isinstance(node, ProxmoxConfig)
    assert node.port == 8006
    assert node.verify_tls is False
    assert node.token_secret.reveal() == "t0ken"


def test_shipped_example_loads(monkeypatch):
    monkeypatch.setenv("SOT_VCENTER_PASSWORD", "vc-secret")
    monkeypatch.setenv("SOT_SNMP_COMMUNITY", "snmp-secret")
    monkeypatch.setenv("SOT_PROXMOX_TOKEN_SECRET", "pve-secret")
    cfg = load_config(EXAMPLE_PATH)
    assert len(cfg.sites) == 2
    assert cfg.sites[0].block.prefixlen == 16
    assert cfg.sites[0].active_subnets[0].prefixlen == 24
    assert all(len(site.active_subnets) >= 2 for site in cfg.sites)
    assert len(cfg.vcenters) == len(cfg.snmp_profiles) == len(cfg.proxmox) == 1
    assert cfg.vcenters[0].password.reveal() == "vc-secret"
    assert cfg.snmp_profiles[0].community.reveal() == "snmp-secret"
    assert cfg.proxmox[0].token_secret.reveal() == "pve-secret"


def test_loaded_config_is_frozen(tmp_path):
    cfg = load_config(_write(tmp_path, SITE))
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.policy.max_concurrent_sites = 9
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.sites[0].name = "other"
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.sites = ()


# --- file and TOML errors -------------------------------------------------------------


def test_missing_file(tmp_path):
    path = tmp_path / "absent.toml"
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert str(path) in str(excinfo.value)


def test_unparseable_toml(tmp_path):
    path = _write(tmp_path, "[[sites]\nsite_id = \n")
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    assert str(path) in str(excinfo.value)
    assert "invalid TOML" in str(excinfo.value)


def test_config_error_is_value_error():
    assert issubclass(ConfigError, ValueError)


# --- missing keys and wrong types ---------------------------------------------------


def test_missing_sites_table(tmp_path):
    _error(tmp_path, "[policy]\nmax_concurrent_sites = 2\n", "root", "sites")


def test_empty_sites_array(tmp_path):
    _error(tmp_path, "sites = []\n", "root", "sites")


def test_missing_required_site_key(tmp_path):
    text = '[[sites]]\nsite_id = "S1"\nname = "x"\nactive_subnets = ["10.1.1.0/24"]\n'
    message = _error(tmp_path, text, "sites[0]", "block")
    assert "missing" in message


def test_missing_required_vcenter_secret(tmp_path):
    text = SITE + '[[vcenters]]\nname = "vc"\nhost = "h"\nusername = "u"\n'
    _error(tmp_path, text, "vcenters[0]", "password")


def test_wrong_type_site_id(tmp_path):
    _error(tmp_path, SITE.replace('"SITE-001"', "1"), "sites[0]", "site_id")


def test_wrong_type_block(tmp_path):
    _error(tmp_path, SITE.replace('"10.1.0.0/16"', "10"), "sites[0]", "block")


def test_wrong_type_active_subnets(tmp_path):
    _error(tmp_path, _site(subnets='"10.1.10.0/24"'), "sites[0]", "active_subnets")
    _error(tmp_path, _site(subnets="[1]"), "sites[0]", "active_subnets")


def test_wrong_type_verify_tls_string_is_not_truthy(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "pw")
    _error(tmp_path, SITE + VCENTER + 'verify_tls = "false"\n', "vcenters[0]", "verify_tls")
    _error(tmp_path, SITE + VCENTER + "verify_tls = 0\n", "vcenters[0]", "verify_tls")


def test_wrong_type_policy_table(tmp_path):
    _error(tmp_path, "policy = 3\n" + SITE, "root", "policy")


def test_wrong_type_sites_not_tables(tmp_path):
    _error(tmp_path, 'sites = ["10.1.0.0/16"]\n', "root", "sites")


def test_empty_site_id_rejected(tmp_path):
    _error(tmp_path, _site(site_id=""), "sites[0]", "site_id")


def test_proxmox_port_range(tmp_path, monkeypatch):
    monkeypatch.setenv("TOKEN", "t")
    base = SITE + '[[proxmox]]\nname = "p"\nhost = "h"\ntoken_id = "i"\ntoken_secret = "${env:TOKEN}"\n'
    for bad in ("0", "65536", "true", '"8006"'):
        _error(tmp_path, base + f"port = {bad}\n", "proxmox[0]", "port")


def test_snmp_version_choices(tmp_path, monkeypatch):
    monkeypatch.setenv("COMM", "c")
    base = SITE + '[[snmp_profiles]]\nname = "p"\ncommunity = "${env:COMM}"\n'
    assert load_config(_write(tmp_path, base + 'version = "v1"\n')).snmp_profiles[0].version == "v1"
    _error(tmp_path, base + 'version = "v3"\n', "snmp_profiles[0]", "version")


# --- unknown keys -----------------------------------------------------------------------


def test_unknown_key_in_site(tmp_path):
    message = _error(tmp_path, SITE + 'blokc = "10.9.0.0/16"\n', "sites[0]", "blokc")
    assert "unknown key" in message


def test_unknown_key_in_policy(tmp_path):
    text = "[policy]\nmax_concurent_sites = 2\n" + SITE
    _error(tmp_path, text, "policy", "max_concurent_sites")


def test_unknown_top_level_key(tmp_path):
    _error(tmp_path, 'version = 1\n' + SITE, "root", "version")


def test_unknown_key_in_collector_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "pw")
    _error(tmp_path, SITE + VCENTER + 'datacenter = "dc"\n', "vcenters[0]", "datacenter")
    _error(
        tmp_path,
        SITE + '[[snmp_profiles]]\nname = "p"\ncommunity = "${env:VC_PW}"\nretries = 2\n',
        "snmp_profiles[0]",
        "retries",
    )
    _error(
        tmp_path,
        SITE + '[[proxmox]]\nname = "p"\nhost = "h"\ntoken_id = "i"\n'
        'token_secret = "${env:VC_PW}"\nnode = "n"\n',
        "proxmox[0]",
        "node",
    )


# --- site block -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "block",
    [
        "192.168.0.0/16",  # outside 10.0.0.0/8
        "10.1.0.0/24",  # wrong prefix length
        "10.1.2.0/16",  # host bits set
        "10.1.0.0/8",
        "10.0.0.0/8",
        "11.1.0.0/16",
        "10.1.0.0",  # no prefix: /32
        "not-a-network",
        "fd00::/16",  # IPv6
        "010.1.0.0/16",  # leading-zero lookalike
        " 10.1.0.0/16",
    ],
)
def test_invalid_site_block(tmp_path, block):
    _error(tmp_path, _site(block=block), "sites[0]", "block")


def test_invalid_block_in_second_site_is_indexed(tmp_path):
    _error(tmp_path, SITE + _site(block="172.16.0.0/16", site_id="S2"), "sites[1]", "block")


# --- active subnets ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "subnets",
    [
        '["10.2.5.0/24"]',  # outside its own block
        '["10.1.4.0/23"]',  # not a /24
        '["10.1.4.0/25"]',
        '["10.1.4.1/24"]',  # host bits set
        '["10.1.4.0"]',
        '["bogus"]',
        "[]",  # empty
        '["10.1.4.0/24", "10.1.4.0/24"]',  # duplicate
    ],
)
def test_invalid_active_subnets(tmp_path, subnets):
    _error(tmp_path, _site(subnets=subnets), "sites[0]", "active_subnets")


def test_active_subnet_inside_another_sites_block_is_rejected(tmp_path):
    text = SITE + _site(block="10.2.0.0/16", subnets='["10.1.10.0/24"]', site_id="S2")
    _error(tmp_path, text, "sites[1]", "active_subnets")


# --- uniqueness -------------------------------------------------------------------------


def test_duplicate_site_id(tmp_path):
    text = _site(site_id="S1") + _site(block="10.2.0.0/16", subnets='["10.2.1.0/24"]', site_id="S1")
    _error(tmp_path, text, "sites[1]", "site_id")


def test_duplicate_block(tmp_path):
    text = _site(site_id="S1") + _site(site_id="S2", subnets='["10.1.11.0/24"]')
    _error(tmp_path, text, "sites[1]", "block")


def test_duplicate_vcenter_name(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "pw")
    _error(tmp_path, SITE + VCENTER + VCENTER, "vcenters[1]", "name")


def test_duplicate_snmp_profile_name(tmp_path, monkeypatch):
    monkeypatch.setenv("COMM", "c")
    entry = '[[snmp_profiles]]\nname = "p"\ncommunity = "${env:COMM}"\n'
    _error(tmp_path, SITE + entry + entry, "snmp_profiles[1]", "name")


def test_duplicate_proxmox_name(tmp_path, monkeypatch):
    monkeypatch.setenv("TOKEN", "t")
    entry = '[[proxmox]]\nname = "p"\nhost = "h"\ntoken_id = "i"\ntoken_secret = "${env:TOKEN}"\n'
    _error(tmp_path, SITE + entry + entry.replace('"h"', '"h2"'), "proxmox[1]", "name")


# --- thresholds -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "arp_active_within_days",
        "arp_stale_after_days",
        "last_seen_active_within_days",
        "last_seen_stale_after_days",
    ],
)
@pytest.mark.parametrize("value", ["0", "-1.5", "true", '"7"', "nan", "inf"])
def test_invalid_day_thresholds(tmp_path, key, value):
    _error(tmp_path, f"[policy]\n{key} = {value}\n" + SITE, "policy", key)


@pytest.mark.parametrize("prefix", ["arp", "last_seen"])
def test_active_must_not_exceed_stale(tmp_path, prefix):
    text = f"[policy]\n{prefix}_active_within_days = 31\n{prefix}_stale_after_days = 30\n" + SITE
    _error(tmp_path, text, "policy", f"{prefix}_active_within_days")
    # Exceeding the default stale threshold is also caught.
    _error(tmp_path, f"[policy]\n{prefix}_active_within_days = 45\n" + SITE, "policy", f"{prefix}_active_within_days")


def test_active_equal_to_stale_is_allowed(tmp_path):
    text = "[policy]\narp_active_within_days = 10\narp_stale_after_days = 10\n" + SITE
    assert load_config(_write(tmp_path, text)).policy.arp_active_within_days == 10.0


@pytest.mark.parametrize("value", ["0", "-1", "true", "2.5", '"3"'])
def test_invalid_quarantine_min_stale_runs(tmp_path, value):
    _error(tmp_path, f"[policy]\nquarantine_min_stale_runs = {value}\n" + SITE, "policy", "quarantine_min_stale_runs")


# --- concurrency ------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["65", "0", "true", "8.0", '"8"'])
def test_invalid_max_concurrent_probes_per_site(tmp_path, value):
    text = f"[policy]\nmax_concurrent_probes_per_site = {value}\n" + SITE
    _error(tmp_path, text, "policy", "max_concurrent_probes_per_site")


def test_max_concurrent_probes_per_site_cap_loads(tmp_path):
    cfg = load_config(_write(tmp_path, "[policy]\nmax_concurrent_probes_per_site = 64\n" + SITE))
    assert cfg.policy.max_concurrent_probes_per_site == 64


@pytest.mark.parametrize("value", ["0", "-2", "false", "1.0"])
def test_invalid_max_concurrent_sites(tmp_path, value):
    text = f"[policy]\nmax_concurrent_sites = {value}\n" + SITE
    _error(tmp_path, text, "policy", "max_concurrent_sites")


def test_max_concurrent_sites_has_no_upper_cap(tmp_path):
    cfg = load_config(_write(tmp_path, "[policy]\nmax_concurrent_sites = 500\n" + SITE))
    assert cfg.policy.max_concurrent_sites == 500


# --- env references ---------------------------------------------------------------------


def test_env_resolution_in_secret_and_non_secret_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "pw-value")
    monkeypatch.setenv("VC_HOST", "vc9.example.invalid")
    monkeypatch.setenv("SITE_BLOCK", "10.7.0.0/16")
    text = (
        _site(block="${env:SITE_BLOCK}", subnets='["10.7.1.0/24"]')
        + VCENTER.replace('"vc1.example.invalid"', '"${env:VC_HOST}"')
    )
    cfg = load_config(_write(tmp_path, text))
    assert cfg.vcenters[0].host == "vc9.example.invalid"
    assert cfg.vcenters[0].password.reveal() == "pw-value"
    assert cfg.sites[0].block == ipaddress.IPv4Network("10.7.0.0/16")


def test_partial_env_reference_is_not_interpolated(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "pw")
    monkeypatch.setenv("SUFFIX", "zzz")
    text = SITE + VCENTER.replace('"reader"', '"svc-${env:SUFFIX}"')
    assert load_config(_write(tmp_path, text)).vcenters[0].username == "svc-${env:SUFFIX}"


def test_missing_env_var_names_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("VC_PW", raising=False)
    message = _error(tmp_path, SITE + VCENTER, "vcenters[0]", "password")
    assert "VC_PW" in message


def test_empty_env_var_counts_as_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "")
    message = _error(tmp_path, SITE + VCENTER, "vcenters[0]", "password")
    assert "VC_PW" in message


def test_missing_env_var_in_non_secret_field(tmp_path, monkeypatch):
    monkeypatch.delenv("SITE_NAME", raising=False)
    message = _error(tmp_path, SITE.replace('"HQ"', '"${env:SITE_NAME}"'), "sites[0]", "name")
    assert "SITE_NAME" in message


@pytest.mark.parametrize(
    "key, entry",
    [
        ("community", '[[snmp_profiles]]\nname = "p"\ncommunity = "public"\n'),
        ("password", VCENTER.replace('"${env:VC_PW}"', '"public"')),
        (
            "token_secret",
            '[[proxmox]]\nname = "p"\nhost = "h"\ntoken_id = "i"\ntoken_secret = "public"\n',
        ),
    ],
)
def test_literal_secret_rejected_without_echo(tmp_path, key, entry):
    table = {"community": "snmp_profiles[0]", "password": "vcenters[0]", "token_secret": "proxmox[0]"}[key]
    message = _error(tmp_path, SITE + entry, table, key)
    assert "public" not in message


@pytest.mark.parametrize(
    "literal",
    [
        "prefix-${env:VC_PW}",  # partial reference
        "${env:VC_PW}\\n",  # trailing newline after a valid reference
        "${env:1BAD}",
        "${ENV:VC_PW}",
    ],
)
def test_secret_lookalike_references_are_literals(tmp_path, monkeypatch, literal):
    monkeypatch.setenv("VC_PW", "s3cr3t")
    text = SITE + f'[[snmp_profiles]]\nname = "p"\ncommunity = "{literal}"\n'
    message = _error(tmp_path, text, "snmp_profiles[0]", "community")
    assert "s3cr3t" not in message
    assert "VC_PW" not in message


def test_non_string_secret_rejected(tmp_path):
    message = _error(tmp_path, SITE + '[[snmp_profiles]]\nname = "p"\ncommunity = 12345\n', "snmp_profiles[0]", "community")
    assert "12345" not in message


def test_env_resolved_value_not_echoed_in_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "s3cr3t")
    message = _error(tmp_path, _site(block="${env:VC_PW}"), "sites[0]", "block")
    assert "s3cr3t" not in message
    message = _error(tmp_path, _site(subnets='["${env:VC_PW}"]'), "sites[0]", "active_subnets")
    assert "s3cr3t" not in message
    text = SITE + '[[snmp_profiles]]\nname = "p"\nversion = "${env:VC_PW}"\ncommunity = "${env:VC_PW}"\n'
    message = _error(tmp_path, text, "snmp_profiles[0]", "version")
    assert "s3cr3t" not in message


# --- redaction --------------------------------------------------------------------------


def test_secrets_redacted_in_repr_str_and_json(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "s3cr3t")
    monkeypatch.setenv("COMM", "c0mmun1ty")
    monkeypatch.setenv("TOKEN", "t0k3n-value")
    text = (
        SITE
        + VCENTER
        + '[[snmp_profiles]]\nname = "p"\ncommunity = "${env:COMM}"\n'
        + '[[proxmox]]\nname = "pve"\nhost = "h"\ntoken_id = "i"\ntoken_secret = "${env:TOKEN}"\n'
    )
    cfg = load_config(_write(tmp_path, text))
    secrets = ("s3cr3t", "c0mmun1ty", "t0k3n-value")

    rendered = [
        repr(cfg),
        str(cfg),
        f"{cfg}",
        repr(cfg.vcenters[0]),
        repr(cfg.snmp_profiles[0]),
        repr(cfg.proxmox[0]),
        str(cfg.vcenters[0].password),
        f"{cfg.vcenters[0].password}",
    ]
    dumped = json.dumps(cfg.to_dict())
    for secret in secrets:
        assert all(secret not in text for text in rendered)
        assert secret not in dumped

    assert str(cfg.vcenters[0].password) == "***"
    assert repr(cfg.vcenters[0].password) == "***"
    assert cfg.vcenters[0].password.reveal() == "s3cr3t"
    assert cfg.snmp_profiles[0].community.reveal() == "c0mmun1ty"
    assert cfg.proxmox[0].token_secret.reveal() == "t0k3n-value"

    data = json.loads(dumped)
    assert data["source_path"] == str(cfg.source_path)
    assert data["sites"][0]["block"] == "10.1.0.0/16"
    assert data["sites"][0]["active_subnets"] == ["10.1.10.0/24", "10.1.20.0/24"]
    assert data["vcenters"][0]["password"] == "***"
    assert data["snmp_profiles"][0]["community"] == "***"
    assert data["proxmox"][0]["token_secret"] == "***"
    assert data["policy"]["max_concurrent_probes_per_site"] == 32


def test_secret_with_control_characters_stays_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv("VC_PW", "line1\nline2\x07")
    cfg = load_config(_write(tmp_path, SITE + VCENTER))
    assert "line1" not in repr(cfg)
    assert "line1" not in json.dumps(cfg.to_dict())
    assert cfg.vcenters[0].password.reveal() == "line1\nline2\x07"
