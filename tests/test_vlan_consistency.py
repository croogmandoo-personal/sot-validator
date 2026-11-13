"""Unit tests for the VLAN consistency auditor."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json

import pytest

from sot_validator.discovery.router_tables import RouterArpRecord
from sot_validator.models import NetworkDevice, Port, Site, Subnet, VLAN
from sot_validator.quality import (
    RULE_ACCESS_PORT_VLAN_MISMATCH,
    RULE_DHCP_SCOPE_WITHOUT_SUBNET,
    RULE_SUBNET_VLAN_MISMATCH,
    RULE_SUBNET_WITHOUT_DHCP_SCOPE,
    RULE_VLAN_UNDOCUMENTED,
    RULE_VLAN_UNOBSERVED,
    VLAN_RULE_NAMES,
    DhcpScope,
    FdbObservation,
    VlanAuditResult,
    VlanConsistencyAuditor,
)
from sot_validator.quality.checks import ALL_RULE_NAMES, _compute_finding_id
from sot_validator.topology.fdb_mapper import FdbEntry, PortClassificationResult

SITE_ID = "site-001"
T1 = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)


def _switch(device_id: str = "sw-01", *, vlan_id: str = "10") -> NetworkDevice:
    return NetworkDevice(
        device_id=device_id,
        site_id=SITE_ID,
        hostname=f"{device_id}-host",
        management_ip=None,
        role="switch",
        ports=[
            Port(port_id=f"{device_id}-p1", device_id=device_id, name="1:1", vlan_id=vlan_id),
        ],
    )


def _build_site(*, extra_switch: bool = False) -> Site:
    devices = [_switch("sw-01")]
    if extra_switch:
        devices.append(_switch("sw-02"))
    return Site(
        site_id=SITE_ID,
        name="Site 001",
        devices=devices,
        vlans=[
            VLAN(vlan_id="10", site_id=SITE_ID, subnet_id="sub-10", cidr="10.1.10.0/24"),
            VLAN(vlan_id="20", site_id=SITE_ID, subnet_id="sub-20", cidr="10.1.20.0/24"),
        ],
        subnets=[
            Subnet(subnet_id="sub-10", site_id=SITE_ID, cidr="10.1.10.0/24", vlan_id="10"),
            Subnet(subnet_id="sub-20", site_id=SITE_ID, cidr="10.1.20.0/24", vlan_id="20"),
        ],
    )


def _entry(vlan_id, *, device_id: str = "sw-01", mac: str = "00:11:22:33:44:55") -> FdbEntry:
    return FdbEntry(device_id=device_id, port_name="1:1", mac_address=mac, vlan_id=vlan_id)


def _obs(*vlans, device_id: str = "sw-01", observed_at=T1, classifications=()) -> FdbObservation:
    return FdbObservation(
        device_id=device_id,
        observed_at=observed_at,
        entries=[_entry(v, device_id=device_id) for v in vlans],
        port_classifications=list(classifications),
    )


def _classification(mode: str, vlan_ids, *, port_name: str = "1:1") -> PortClassificationResult:
    return PortClassificationResult(
        device_id="sw-01", port_name=port_name, port_mode=mode, vlan_ids=list(vlan_ids)
    )


def _by_rule(result: VlanAuditResult, rule: str) -> list:
    return [f for f in result.findings if f.rule == rule]


def test_rule_names_are_ordered_and_separate_from_checker_rules() -> None:
    assert VLAN_RULE_NAMES == (
        "vlan_undocumented",
        "vlan_unobserved",
        "subnet_vlan_mismatch",
        "access_port_vlan_mismatch",
        "dhcp_scope_without_subnet",
        "subnet_without_dhcp_scope",
    )
    assert not set(VLAN_RULE_NAMES) & set(ALL_RULE_NAMES)


def test_no_observed_data_skips_every_rule() -> None:
    result = VlanConsistencyAuditor().audit(_build_site())
    assert result.site_id == SITE_ID
    assert result.findings == []
    assert list(result.skipped_rules) == list(VLAN_RULE_NAMES)
    assert all(reason for reason in result.skipped_rules.values())
    assert "FDB" in result.skipped_rules[RULE_VLAN_UNDOCUMENTED]
    assert "router" in result.skipped_rules[RULE_SUBNET_VLAN_MISMATCH]
    assert "DHCP scopes" in result.skipped_rules[RULE_DHCP_SCOPE_WITHOUT_SUBNET]


def test_empty_sequences_count_as_not_supplied() -> None:
    result = VlanConsistencyAuditor().audit(
        _build_site(), fdb=[], router_arp=[], dhcp_scopes=[], dhcp_expected_subnets=set()
    )
    assert result.findings == []
    assert list(result.skipped_rules) == list(VLAN_RULE_NAMES)


def test_undocumented_and_unobserved_with_full_coverage() -> None:
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[_obs("10", "30")])

    undocumented = _by_rule(result, RULE_VLAN_UNDOCUMENTED)
    assert len(undocumented) == 1
    assert undocumented[0].severity == "warning"
    assert undocumented[0].record_type == "VLAN"
    assert undocumented[0].record_ids == [f"site:{SITE_ID}", "vlan:30"]
    assert undocumented[0].evidence["vlan_id"] == "30"
    assert undocumented[0].evidence["sources"] == [
        {"source": "fdb", "device_id": "sw-01", "observed_at": T1.isoformat()}
    ]

    unobserved = _by_rule(result, RULE_VLAN_UNOBSERVED)
    assert len(unobserved) == 1
    finding = unobserved[0]
    assert finding.severity == "info"
    assert finding.record_ids == [f"site:{SITE_ID}", "vlan:20"]
    assert finding.evidence["confidence"] == "high"
    assert finding.evidence["site_switches"] == ["sw-01"]
    assert finding.evidence["covered_switches"] == ["sw-01"]
    assert finding.evidence["uncovered_switches"] == []
    assert "only part" not in finding.message
    assert RULE_VLAN_UNDOCUMENTED not in result.skipped_rules
    assert RULE_VLAN_UNOBSERVED not in result.skipped_rules


def test_unobserved_downgraded_on_partial_switch_coverage() -> None:
    result = VlanConsistencyAuditor().audit(
        _build_site(extra_switch=True), fdb=[_obs("10", "30")]
    )
    finding = _by_rule(result, RULE_VLAN_UNOBSERVED)[0]
    assert finding.severity == "info"
    assert finding.evidence["confidence"] == "low"
    assert finding.evidence["site_switches"] == ["sw-01", "sw-02"]
    assert finding.evidence["uncovered_switches"] == ["sw-02"]
    assert "covers only part of the site's switches" in finding.message


def test_site_without_switches_has_high_confidence() -> None:
    site = _build_site()
    site.devices = []
    result = VlanConsistencyAuditor().audit(site, fdb=[_obs("10")])
    finding = _by_rule(result, RULE_VLAN_UNOBSERVED)[0]
    assert finding.evidence["site_switches"] == []
    assert finding.evidence["uncovered_switches"] == []
    assert finding.evidence["confidence"] == "high"


def test_negative_undocumented_and_unobserved_when_consistent() -> None:
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[_obs("10", "20")])
    assert _by_rule(result, RULE_VLAN_UNDOCUMENTED) == []
    assert _by_rule(result, RULE_VLAN_UNOBSERVED) == []


def test_subnet_vlan_id_documents_a_vlan_for_undocumented_only() -> None:
    site = _build_site()
    site.subnets.append(
        Subnet(subnet_id="sub-40", site_id=SITE_ID, cidr="10.1.40.0/24", vlan_id="40")
    )
    result = VlanConsistencyAuditor().audit(site, fdb=[_obs("10", "20", "40")])
    assert _by_rule(result, RULE_VLAN_UNDOCUMENTED) == []


@pytest.mark.parametrize("raw", [10, "10", " 10 ", "010"])
def test_vlan_id_normalisation_matches_sot(raw) -> None:
    site = _build_site()
    site.vlans = [VLAN(vlan_id=" 10 ", site_id=SITE_ID)]
    result = VlanConsistencyAuditor().audit(site, fdb=[_obs(raw)])
    assert _by_rule(result, RULE_VLAN_UNDOCUMENTED) == []
    assert _by_rule(result, RULE_VLAN_UNOBSERVED) == []


@pytest.mark.parametrize("raw", ["Voice", "0", "4095", "-1"])
def test_non_numeric_or_out_of_range_observed_vlans_are_ignored(raw) -> None:
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[_obs("10", "20", raw)])
    assert _by_rule(result, RULE_VLAN_UNDOCUMENTED) == []


def test_never_seen_across_runs_of_the_same_switch() -> None:
    first = _obs("10", observed_at=T1)
    second = _obs("20", observed_at=T2)
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[first, second])
    assert _by_rule(result, RULE_VLAN_UNOBSERVED) == []

    result = VlanConsistencyAuditor().audit(
        _build_site(), fdb=[_obs("10", observed_at=T1), _obs("10", observed_at=T2)]
    )
    finding = _by_rule(result, RULE_VLAN_UNOBSERVED)[0]
    assert finding.record_ids == [f"site:{SITE_ID}", "vlan:20"]
    assert finding.evidence["covered_switches"] == ["sw-01"]
    assert finding.evidence["sources"] == [
        {"source": "fdb", "device_id": "sw-01", "observed_at": T1.isoformat()},
        {"source": "fdb", "device_id": "sw-01", "observed_at": T2.isoformat()},
    ]


def test_subnet_vlan_mismatch_from_tagged_interface() -> None:
    record = RouterArpRecord(
        ip="10.1.10.5", interface="vlan20", vlan_id="20", router_id="rtr-01", observed_at=T1
    )
    result = VlanConsistencyAuditor().audit(_build_site(), router_arp=[record])
    findings = _by_rule(result, RULE_SUBNET_VLAN_MISMATCH)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "error"
    assert finding.record_type == "Subnet"
    assert finding.record_ids == [f"site:{SITE_ID}", "subnet:sub-10"]
    assert finding.evidence["cidr"] == "10.1.10.0/24"
    assert finding.evidence["sot_vlan_id"] == "10"
    assert finding.evidence["observed_vlan_ids"] == ["20"]
    assert finding.evidence["sources"] == [
        {
            "source": "router",
            "router_id": "rtr-01",
            "interface": "vlan20",
            "observed_at": T1.isoformat(),
        }
    ]


def test_subnet_vlan_mismatch_uses_most_specific_subnet() -> None:
    site = _build_site()
    site.subnets.append(
        Subnet(subnet_id="sub-wide", site_id=SITE_ID, cidr="10.1.0.0/16", vlan_id="99")
    )
    record = RouterArpRecord(ip="10.1.10.5", interface="vlan10", vlan_id="10")
    result = VlanConsistencyAuditor().audit(site, router_arp=[record])
    assert _by_rule(result, RULE_SUBNET_VLAN_MISMATCH) == []


def test_subnet_vlan_mismatch_explicit_vlan_differing_from_ip_guess() -> None:
    record = RouterArpRecord(ip="10.1.10.5", interface="ge-0/0/1", vlan_id="20")
    result = VlanConsistencyAuditor().audit(_build_site(), router_arp=[record])
    assert len(_by_rule(result, RULE_SUBNET_VLAN_MISMATCH)) == 1


def test_negative_subnet_vlan_mismatch_when_router_agrees() -> None:
    record = RouterArpRecord(ip="10.1.10.5", interface="eth1.10", vlan_id="10")
    result = VlanConsistencyAuditor().audit(_build_site(), router_arp=[record])
    assert _by_rule(result, RULE_SUBNET_VLAN_MISMATCH) == []
    assert RULE_SUBNET_VLAN_MISMATCH not in result.skipped_rules


def test_ip_guessed_router_vlan_is_ignored() -> None:
    site = _build_site()
    site.subnets[0].vlan_id = "99"
    guessed = [
        RouterArpRecord(ip="10.1.30.5", vlan_id="30", interface=None),
        RouterArpRecord(ip="10.1.10.5", vlan_id="10", interface="ge-0/0/1"),
    ]
    result = VlanConsistencyAuditor().audit(site, router_arp=guessed)
    assert _by_rule(result, RULE_VLAN_UNDOCUMENTED) == []
    assert _by_rule(result, RULE_SUBNET_VLAN_MISMATCH) == []
    # The router data still counts as supplied, so nothing in SoT was seen.
    unobserved = _by_rule(result, RULE_VLAN_UNOBSERVED)
    assert [f.evidence["vlan_id"] for f in unobserved] == ["10", "20"]
    assert all(f.evidence["sources"] for f in unobserved)


def test_router_skip_reason_when_only_fdb_supplied() -> None:
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[_obs("10", "20")])
    assert "router" in result.skipped_rules[RULE_SUBNET_VLAN_MISMATCH]
    assert RULE_VLAN_UNDOCUMENTED not in result.skipped_rules


def test_access_port_vlan_mismatch() -> None:
    observation = _obs(classifications=[_classification("access", ["20"])])
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[observation])
    findings = _by_rule(result, RULE_ACCESS_PORT_VLAN_MISMATCH)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "warning"
    assert finding.record_type == "Port"
    assert finding.record_ids == ["port:sw-01-p1", f"site:{SITE_ID}"]
    assert finding.evidence["device_id"] == "sw-01"
    assert finding.evidence["port_name"] == "1:1"
    assert finding.evidence["sot_vlan_id"] == "10"
    assert finding.evidence["observed_vlan_ids"] == ["20"]
    assert finding.evidence["sources"] == [
        {"source": "fdb", "device_id": "sw-01", "observed_at": T1.isoformat()}
    ]


def test_access_port_resolves_by_port_id() -> None:
    observation = _obs(
        classifications=[_classification("access", ["20"], port_name="sw-01-p1")]
    )
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[observation])
    assert len(_by_rule(result, RULE_ACCESS_PORT_VLAN_MISMATCH)) == 1


@pytest.mark.parametrize("mode", ["trunk", "uplink"])
def test_access_port_rule_excludes_trunk_and_uplink(mode: str) -> None:
    observation = _obs(classifications=[_classification(mode, ["20"])])
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[observation])
    assert _by_rule(result, RULE_ACCESS_PORT_VLAN_MISMATCH) == []

    mixed = [
        _obs(classifications=[_classification("access", ["20"])], observed_at=T1),
        _obs(classifications=[_classification(mode, ["20", "30"])], observed_at=T2),
    ]
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=mixed)
    assert _by_rule(result, RULE_ACCESS_PORT_VLAN_MISMATCH) == []


def test_negative_access_port_cases() -> None:
    auditor = VlanConsistencyAuditor()
    # The SoT VLAN is among the observed access VLANs (e.g. data + voice).
    ok = _obs(classifications=[_classification("access", ["10", "20"])])
    assert _by_rule(auditor.audit(_build_site(), fdb=[ok]), RULE_ACCESS_PORT_VLAN_MISMATCH) == []
    # Union across runs contains the SoT VLAN.
    runs = [
        _obs(classifications=[_classification("access", ["20"])], observed_at=T1),
        _obs(classifications=[_classification("access", ["010"])], observed_at=T2),
    ]
    assert _by_rule(auditor.audit(_build_site(), fdb=runs), RULE_ACCESS_PORT_VLAN_MISMATCH) == []
    # Empty-only, unresolved port, and a port without a SoT VLAN.
    empty = _obs(classifications=[_classification("empty", [])])
    assert _by_rule(auditor.audit(_build_site(), fdb=[empty]), RULE_ACCESS_PORT_VLAN_MISMATCH) == []
    unknown = _obs(classifications=[_classification("access", ["20"], port_name="9:9")])
    assert _by_rule(auditor.audit(_build_site(), fdb=[unknown]), RULE_ACCESS_PORT_VLAN_MISMATCH) == []
    site = _build_site()
    site.devices[0].ports[0].vlan_id = None
    flagged = _obs(classifications=[_classification("access", ["20"])])
    assert _by_rule(auditor.audit(site, fdb=[flagged]), RULE_ACCESS_PORT_VLAN_MISMATCH) == []


def test_access_port_rule_skipped_without_classifications() -> None:
    result = VlanConsistencyAuditor().audit(_build_site(), fdb=[_obs("10", "20")])
    assert "classification" in result.skipped_rules[RULE_ACCESS_PORT_VLAN_MISMATCH]


def test_dhcp_scope_without_subnet() -> None:
    scopes = [
        DhcpScope("10.1.99.0/24", source="dhcp-01", observed_at=T1),
        DhcpScope("10.1.10.5/24", source="dhcp-01"),
    ]
    result = VlanConsistencyAuditor().audit(_build_site(), dhcp_scopes=scopes)
    findings = _by_rule(result, RULE_DHCP_SCOPE_WITHOUT_SUBNET)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "warning"
    assert finding.record_type == "DhcpScope"
    assert finding.record_ids == ["dhcp_scope:10.1.99.0/24", f"site:{SITE_ID}"]
    assert finding.evidence["cidr"] == "10.1.99.0/24"
    assert finding.evidence["sources"] == [
        {"source": "dhcp", "server": "dhcp-01", "observed_at": T1.isoformat()}
    ]
    assert RULE_SUBNET_WITHOUT_DHCP_SCOPE in result.skipped_rules
    assert "DHCP-expected" in result.skipped_rules[RULE_SUBNET_WITHOUT_DHCP_SCOPE]


def test_negative_dhcp_scope_without_subnet() -> None:
    result = VlanConsistencyAuditor().audit(
        _build_site(), dhcp_scopes=[DhcpScope("10.1.20.0/24")]
    )
    assert _by_rule(result, RULE_DHCP_SCOPE_WITHOUT_SUBNET) == []
    assert RULE_DHCP_SCOPE_WITHOUT_SUBNET not in result.skipped_rules


def test_subnet_without_dhcp_scope() -> None:
    scopes = [DhcpScope("10.1.10.0/24", source="dhcp-01", observed_at=T2)]
    result = VlanConsistencyAuditor().audit(
        _build_site(),
        dhcp_scopes=scopes,
        dhcp_expected_subnets={"sub-10", "10.1.20.7/24", "sub-missing", "10.9.9.0/24"},
    )
    findings = _by_rule(result, RULE_SUBNET_WITHOUT_DHCP_SCOPE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "warning"
    assert finding.record_type == "Subnet"
    assert finding.record_ids == [f"site:{SITE_ID}", "subnet:sub-20"]
    assert finding.evidence["cidr"] == "10.1.20.0/24"
    assert finding.evidence["sources"] == [
        {"source": "dhcp", "server": "dhcp-01", "observed_at": T2.isoformat()}
    ]
    assert result.skipped_rules == {
        RULE_VLAN_UNDOCUMENTED: "no FDB or router ARP data supplied",
        RULE_VLAN_UNOBSERVED: "no FDB or router ARP data supplied",
        RULE_SUBNET_VLAN_MISMATCH: "no router ARP data supplied",
        RULE_ACCESS_PORT_VLAN_MISMATCH: "no FDB port classifications supplied",
    }


def test_negative_subnet_without_dhcp_scope() -> None:
    result = VlanConsistencyAuditor().audit(
        _build_site(),
        dhcp_scopes=[DhcpScope("10.1.10.0/24"), DhcpScope("10.1.20.0/24")],
        dhcp_expected_subnets=["sub-10", "sub-20"],
    )
    assert _by_rule(result, RULE_SUBNET_WITHOUT_DHCP_SCOPE) == []


def test_dhcp_rules_skipped_without_scopes() -> None:
    result = VlanConsistencyAuditor().audit(
        _build_site(), dhcp_expected_subnets=["sub-10"]
    )
    assert result.findings == []
    assert "DHCP scopes" in result.skipped_rules[RULE_DHCP_SCOPE_WITHOUT_SUBNET]
    assert "DHCP scopes" in result.skipped_rules[RULE_SUBNET_WITHOUT_DHCP_SCOPE]


def test_bare_string_expected_set_is_rejected() -> None:
    with pytest.raises(TypeError):
        VlanConsistencyAuditor().audit(
            _build_site(), dhcp_scopes=[DhcpScope("10.1.10.0/24")], dhcp_expected_subnets="sub-10"
        )


@pytest.mark.parametrize("cidr", ["not-a-network", "2001:db8::/64", "", None])
def test_dhcp_scope_rejects_non_ipv4(cidr) -> None:
    with pytest.raises(ValueError):
        DhcpScope(cidr)


@pytest.mark.parametrize("device_id", ["", "   ", None])
def test_fdb_observation_requires_device_id(device_id) -> None:
    with pytest.raises(ValueError):
        FdbObservation(device_id=device_id)


def test_fdb_observation_copies_sequences() -> None:
    entries = [_entry("10")]
    observation = FdbObservation(device_id="sw-01", entries=entries)
    entries.append(_entry("20"))
    assert len(observation.entries) == 1


def _full_inputs():
    site = _build_site(extra_switch=True)
    fdb = [
        _obs("10", "30", observed_at=T1, classifications=[_classification("access", ["30"])]),
        _obs("10", observed_at=T2),
    ]
    router = [
        RouterArpRecord(ip="10.1.10.5", interface="vlan30", vlan_id="30", observed_at=T1),
        RouterArpRecord(ip="10.1.30.5", vlan_id="30"),
    ]
    scopes = [DhcpScope("10.1.99.0/24", source="dhcp-01", observed_at=T1)]
    expected = {"sub-20"}
    return site, fdb, router, scopes, expected


def test_all_rules_evidence_is_json_serialisable_with_sources() -> None:
    site, fdb, router, scopes, expected = _full_inputs()
    result = VlanConsistencyAuditor().audit(
        site, fdb=fdb, router_arp=router, dhcp_scopes=scopes, dhcp_expected_subnets=expected
    )
    assert {f.rule for f in result.findings} == set(VLAN_RULE_NAMES)
    assert result.skipped_rules == {}
    json.dumps([f.evidence for f in result.findings])
    assert all(f.evidence["sources"] for f in result.findings)


def test_audit_does_not_mutate_inputs() -> None:
    site, fdb, router, scopes, expected = _full_inputs()
    site_before = copy.deepcopy(site.to_dict())
    fdb_before = copy.deepcopy(fdb)
    router_before = [r.to_dict() for r in router]
    scopes_before = copy.deepcopy(scopes)
    expected_before = set(expected)

    VlanConsistencyAuditor().audit(
        site, fdb=fdb, router_arp=router, dhcp_scopes=scopes, dhcp_expected_subnets=expected
    )

    assert site.to_dict() == site_before
    assert fdb == fdb_before
    assert [r.to_dict() for r in router] == router_before
    assert scopes == scopes_before
    assert expected == expected_before


def test_deterministic_ids_and_ordering() -> None:
    site, fdb, router, scopes, expected = _full_inputs()
    auditor = VlanConsistencyAuditor()
    first = auditor.audit(
        site, fdb=fdb, router_arp=router, dhcp_scopes=scopes, dhcp_expected_subnets=expected
    )
    second = auditor.audit(
        site,
        fdb=list(reversed(fdb)),
        router_arp=list(reversed(router)),
        dhcp_scopes=scopes,
        dhcp_expected_subnets=sorted(expected),
    )
    assert first == second
    keys = [(f.rule, tuple(f.record_ids), f.finding_id) for f in first.findings]
    assert keys == sorted(keys)
    for finding in first.findings:
        assert finding.site_id == SITE_ID
        assert finding.record_ids == sorted(finding.record_ids)
        assert f"site:{SITE_ID}" in finding.record_ids
        assert finding.finding_id == _compute_finding_id(finding.rule, finding.record_ids)
    assert len({f.finding_id for f in first.findings}) == len(first.findings)
