"""Unit tests for the SoT data-quality conflict detector."""

from __future__ import annotations

import copy
import re

import pytest

from sot_validator.models import (
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
)
from sot_validator.quality import (
    ALL_RULE_NAMES,
    CROSS_SITE_RULES,
    RULE_CROSS_SITE_DUPLICATE_IP,
    RULE_CROSS_SITE_DUPLICATE_MAC,
    RULE_DUPLICATE_IP,
    RULE_DUPLICATE_MAC,
    RULE_HOSTNAME_MISMATCH,
    RULE_IP_OUTSIDE_ACTIVE_SUBNET,
    RULE_IP_OUTSIDE_SITE_BLOCK,
    RULE_ORPHAN_REFERENCE,
    SINGLE_SITE_RULES,
    DataQualityChecker,
    QualityFinding,
)


def _build_site(site_id: str = "site-042") -> Site:
    """Build a consistent site that trips no rule."""
    return Site(
        site_id=site_id,
        name=f"Site {site_id}",
        rooms=["MDF"],
        subnets=[
            Subnet(
                subnet_id="sub-001",
                site_id=site_id,
                cidr="10.42.1.0/24",
                vlan_id="1",
                gateway="10.42.1.1",
            ),
            Subnet(
                subnet_id="sub-010",
                site_id=site_id,
                cidr="10.42.10.0/24",
                vlan_id="10",
                gateway="10.42.10.1",
            ),
        ],
        vlans=[
            VLAN(
                vlan_id="10",
                site_id=site_id,
                name="SERVER",
                subnet_id="sub-010",
                cidr="10.42.10.0/24",
                gateway="10.42.10.1",
            )
        ],
        devices=[
            NetworkDevice(
                device_id="dev-01",
                site_id=site_id,
                hostname="sw-042-01",
                management_ip="10.42.1.10",
                vendor="Extreme",
                ports=[
                    Port(
                        port_id="p-01",
                        device_id="dev-01",
                        name="Gi0/1",
                        connected_mac="aa:bb:cc:00:00:01",
                        vlan_id="10",
                    ),
                    Port(
                        port_id="p-02",
                        device_id="dev-01",
                        name="Gi0/2",
                        connected_mac="aa:bb:cc:00:00:02",
                        vlan_id="10",
                    ),
                ],
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.10.20",
                subnet_id="sub-010",
                assigned_object_type="Equipment",
                assigned_object_id="eq-01",
                arp_mac="aa:bb:cc:00:00:21",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-01",
                site_id=site_id,
                name="srv-042-01",
                category="server",
                assigned_ips=["10.42.10.20"],
                connected_ports=["p-01"],
            )
        ],
    )


def _rules(findings: list[QualityFinding]) -> list[str]:
    return [finding.rule for finding in findings]


def _findings_for(findings: list[QualityFinding], rule: str) -> list[QualityFinding]:
    return [finding for finding in findings if finding.rule == rule]


def test_barrel_exports_public_symbols() -> None:
    import sot_validator.quality as quality

    assert "DataQualityChecker" in quality.__all__
    assert "QualityFinding" in quality.__all__
    assert "ALL_RULE_NAMES" in quality.__all__
    assert set(SINGLE_SITE_RULES) | set(CROSS_SITE_RULES) == set(ALL_RULE_NAMES)
    assert len(ALL_RULE_NAMES) == 8
    for name in quality.__all__:
        assert hasattr(quality, name)


def test_clean_site_emits_no_findings() -> None:
    assert DataQualityChecker().check_site(_build_site()) == []


def test_duplicate_ip_detected() -> None:
    site = _build_site()
    site.ip_addresses.append(
        IPAddress(
            ip="10.42.10.20",
            subnet_id="sub-010",
            assigned_object_type="Equipment",
            assigned_object_id="eq-02",
        )
    )

    findings = DataQualityChecker().check_site(site)

    assert _rules(findings) == [RULE_DUPLICATE_IP]
    finding = findings[0]
    assert finding.severity == "error"
    assert finding.record_type == "IPAddress"
    assert finding.record_ids == [
        "Equipment:eq-01",
        "Equipment:eq-02",
        "site:site-042",
    ]
    assert finding.evidence["ip"] == "10.42.10.20"
    assert finding.evidence["assignment_count"] == 2


def test_duplicate_ip_absent_with_distinct_ips() -> None:
    site = _build_site()
    site.ip_addresses.append(
        IPAddress(ip="10.42.10.21", subnet_id="sub-010")
    )

    assert _findings_for(DataQualityChecker().check_site(site), RULE_DUPLICATE_IP) == []


def test_duplicate_mac_between_ip_and_access_port() -> None:
    site = _build_site()
    site.devices[0].ports[0].connected_mac = "aa:bb:cc:00:00:21"

    findings = DataQualityChecker().check_site(site)

    assert _rules(findings) == [RULE_DUPLICATE_MAC]
    finding = findings[0]
    assert finding.severity == "warning"
    assert finding.record_ids == [
        "ip:10.42.10.20",
        "port:p-01",
        "site:site-042",
    ]
    assert finding.evidence["mac"] == "aa:bb:cc:00:00:21"


def test_duplicate_mac_absent_when_macs_are_unique() -> None:
    findings = DataQualityChecker().check_site(_build_site())

    assert _findings_for(findings, RULE_DUPLICATE_MAC) == []


def test_duplicate_mac_compares_case_and_separators() -> None:
    site = _build_site()
    site.devices[0].ports[0].connected_mac = "AA-BB-CC-00-00-99"
    site.devices[0].ports[1].connected_mac = "aa:bb:cc:00:00:99"

    findings = _findings_for(DataQualityChecker().check_site(site), RULE_DUPLICATE_MAC)

    assert len(findings) == 1
    assert findings[0].evidence["mac"] == "aa:bb:cc:00:00:99"


def test_duplicate_mac_suppressed_on_trunk_and_uplink_ports() -> None:
    site = _build_site()
    site.devices[0].ports[0].connected_mac = "aa:bb:cc:00:00:99"
    site.devices[0].ports[1].connected_mac = "aa:bb:cc:00:00:99"

    suppressed = DataQualityChecker(
        port_modes={"p-01": "trunk", "p-02": "uplink"}
    ).check_site(site)
    assert _findings_for(suppressed, RULE_DUPLICATE_MAC) == []

    access = DataQualityChecker(
        port_modes={"p-01": "access", "p-02": "access"}
    ).check_site(site)
    assert len(_findings_for(access, RULE_DUPLICATE_MAC)) == 1

    unmapped = DataQualityChecker().check_site(site)
    assert len(_findings_for(unmapped, RULE_DUPLICATE_MAC)) == 1


def test_duplicate_mac_unknown_port_mode_treated_as_access() -> None:
    site = _build_site()
    site.devices[0].ports[0].connected_mac = "aa:bb:cc:00:00:21"

    findings = DataQualityChecker(port_modes={"p-02": "trunk"}).check_site(site)

    assert len(_findings_for(findings, RULE_DUPLICATE_MAC)) == 1


def test_ip_looking_mac_is_ignored() -> None:
    site = _build_site()
    site.devices[0].ports[0].connected_mac = "10.42.10.20"

    findings = DataQualityChecker().check_site(site)

    assert _findings_for(findings, RULE_DUPLICATE_MAC) == []


def test_ip_outside_site_block_detected() -> None:
    site = _build_site()
    site.ip_addresses.append(
        IPAddress(
            ip="10.99.1.5",
            subnet_id="sub-001",
            assigned_object_type="Equipment",
            assigned_object_id="eq-02",
        )
    )

    findings = _findings_for(
        DataQualityChecker().check_site(site), RULE_IP_OUTSIDE_SITE_BLOCK
    )

    assert len(findings) == 1
    assert findings[0].severity == "error"
    assert findings[0].evidence["site_block"] == "10.42.0.0/16"
    assert findings[0].evidence["ip"] == "10.99.1.5"


def test_ip_inside_site_block_not_flagged() -> None:
    site = _build_site()
    assert (
        _findings_for(
            DataQualityChecker().check_site(site), RULE_IP_OUTSIDE_SITE_BLOCK
        )
        == []
    )


def test_ip_outside_active_subnet_detected() -> None:
    site = _build_site()
    site.ip_addresses.append(
        IPAddress(
            ip="10.42.20.5",
            subnet_id="sub-001",
            assigned_object_type="Equipment",
            assigned_object_id="eq-02",
        )
    )

    findings = _findings_for(
        DataQualityChecker().check_site(site), RULE_IP_OUTSIDE_ACTIVE_SUBNET
    )

    assert len(findings) == 1
    assert findings[0].severity == "warning"
    assert findings[0].evidence["site_block"] == "10.42.0.0/16"
    assert "10.42.1.0/24" in findings[0].evidence["active_subnets"]


def test_ip_outside_active_subnet_absent_for_known_subnet() -> None:
    assert (
        _findings_for(
            DataQualityChecker().check_site(_build_site()),
            RULE_IP_OUTSIDE_ACTIVE_SUBNET,
        )
        == []
    )


def test_site_block_override_is_used() -> None:
    site = _build_site()

    matching = DataQualityChecker(site_block="10.42.0.0/16").check_site(site)
    assert _findings_for(matching, RULE_IP_OUTSIDE_SITE_BLOCK) == []

    mismatched = DataQualityChecker(site_block="10.99.0.0/16").check_site(site)
    findings = _findings_for(mismatched, RULE_IP_OUTSIDE_SITE_BLOCK)
    assert len(findings) == 1
    assert findings[0].evidence["site_block"] == "10.99.0.0/16"


def test_site_block_derivation_uses_most_common_supernet() -> None:
    site = _build_site()
    site.subnets.append(
        Subnet(subnet_id="sub-043", site_id="site-042", cidr="10.43.1.0/24")
    )
    site.ip_addresses.append(
        IPAddress(ip="10.43.1.20", subnet_id="sub-043")
    )

    findings = DataQualityChecker().check_site(site)

    outside = _findings_for(findings, RULE_IP_OUTSIDE_SITE_BLOCK)
    assert len(outside) == 1
    assert outside[0].evidence["site_block"] == "10.42.0.0/16"
    assert outside[0].evidence["ip"] == "10.43.1.20"
    assert _findings_for(findings, RULE_IP_OUTSIDE_ACTIVE_SUBNET) == []


def test_site_block_derivation_breaks_ties_lexicographically() -> None:
    site = Site(
        site_id="site-tie",
        name="Tie Site",
        subnets=[
            Subnet(subnet_id="sub-43", site_id="site-tie", cidr="10.43.1.0/24"),
            Subnet(subnet_id="sub-42", site_id="site-tie", cidr="10.42.1.0/24"),
        ],
        ip_addresses=[IPAddress(ip="10.43.1.20", subnet_id="sub-43")],
    )

    findings = DataQualityChecker().check_site(site)

    outside = _findings_for(findings, RULE_IP_OUTSIDE_SITE_BLOCK)
    assert len(outside) == 1
    assert outside[0].evidence["site_block"] == "10.42.0.0/16"


def test_orphan_reference_detected_for_every_reference_field() -> None:
    site = _build_site()
    site.devices[0].ports[0].connected_device_id = "eq-99"
    site.devices[0].ports.append(
        Port(port_id="p-99", device_id="dev-99", name="Gi0/9")
    )
    site.ip_addresses.append(
        IPAddress(ip="10.42.10.21", subnet_id="sub-999")
    )
    site.vlans.append(VLAN(vlan_id="99", site_id="site-042", subnet_id="sub-999"))
    site.equipment[0].connected_ports.append("p-999")

    findings = DataQualityChecker().check_site(site)

    orphans = _findings_for(findings, RULE_ORPHAN_REFERENCE)
    assert len(orphans) == 5
    assert {finding.evidence["reference_field"] for finding in orphans} == {
        "connected_device_id",
        "device_id",
        "connected_ports",
        "subnet_id",
    }
    for finding in orphans:
        assert finding.severity == "error"
        assert finding.evidence["missing_id"] in finding.record_ids[-1] or any(
            finding.evidence["missing_id"] in record_id
            for record_id in finding.record_ids
        )


def test_orphan_reference_absent_for_consistent_site() -> None:
    findings = DataQualityChecker().check_site(_build_site())

    assert _findings_for(findings, RULE_ORPHAN_REFERENCE) == []


def test_hostname_mismatch_against_dns_ptr() -> None:
    checker = DataQualityChecker(
        dns_ptr_names={"10.42.1.10": "edge-sw-42.corp.example.com"}
    )

    findings = _findings_for(
        checker.check_site(_build_site()), RULE_HOSTNAME_MISMATCH
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "info"
    assert finding.record_type == "NetworkDevice"
    assert finding.record_ids == ["device:dev-01", "site:site-042"]
    assert finding.evidence["sot_hostname"] == "sw-042-01"
    assert finding.evidence["observed_names"] == [
        {
            "source": "dns",
            "key": "10.42.1.10",
            "name": "edge-sw-42.corp.example.com",
        }
    ]


def test_hostname_mismatch_against_ad_name() -> None:
    checker = DataQualityChecker(ad_names={"eq-01": "SRV-042-99"})

    findings = _findings_for(
        checker.check_site(_build_site()), RULE_HOSTNAME_MISMATCH
    )

    assert len(findings) == 1
    assert findings[0].record_ids == ["equipment:eq-01", "site:site-042"]
    assert findings[0].evidence["observed_names"][0]["source"] == "ad"


def test_hostname_match_is_case_insensitive_short_name() -> None:
    checker = DataQualityChecker(
        dns_ptr_names={"10.42.1.10": "SW-042-01.corp.example.com"},
        ad_names={"eq-01": "srv-042-01$"},
    )

    assert _findings_for(
        checker.check_site(_build_site()), RULE_HOSTNAME_MISMATCH
    ) == []


def test_hostname_mismatch_silent_without_signal_data() -> None:
    assert (
        _findings_for(
            DataQualityChecker().check_site(_build_site()), RULE_HOSTNAME_MISMATCH
        )
        == []
    )


def test_cross_site_rules_absent_with_one_site() -> None:
    findings = DataQualityChecker().check_sites([_build_site()])

    assert _rules(findings) == []


def test_cross_site_rules_present_with_two_sites() -> None:
    findings = DataQualityChecker().check_sites(
        [_build_site("site-042"), _build_site("site-043")]
    )

    ip_findings = _findings_for(findings, RULE_CROSS_SITE_DUPLICATE_IP)
    mac_findings = _findings_for(findings, RULE_CROSS_SITE_DUPLICATE_MAC)
    assert len(ip_findings) == 1
    assert ip_findings[0].severity == "error"
    assert ip_findings[0].evidence["site_ids"] == ["site-042", "site-043"]
    assert ip_findings[0].evidence["ip"] == "10.42.10.20"
    assert len(mac_findings) == 3
    for finding in mac_findings:
        assert finding.severity == "warning"
        assert finding.evidence["site_ids"] == ["site-042", "site-043"]


def test_cross_site_rules_ignore_suppressed_trunk_macs() -> None:
    sites = [_build_site("site-042"), _build_site("site-043")]
    for site in sites:
        for port in site.devices[0].ports:
            port.connected_mac = "aa:bb:cc:00:00:99"
    checker = DataQualityChecker(
        port_modes={"p-01": "trunk", "p-02": "uplink"}
    )

    findings = _findings_for(
        checker.check_sites(sites), RULE_CROSS_SITE_DUPLICATE_MAC
    )

    assert [f.evidence["mac"] for f in findings] == ["aa:bb:cc:00:00:21"]


def test_disabled_rule_emits_nothing() -> None:
    site = _build_site()
    site.ip_addresses.append(
        IPAddress(
            ip="10.42.10.20",
            subnet_id="sub-010",
            assigned_object_id="eq-02",
        )
    )

    checker = DataQualityChecker(disabled_rules=[RULE_DUPLICATE_IP])

    assert _findings_for(checker.check_site(site), RULE_DUPLICATE_IP) == []


def test_disabled_cross_site_rule_emits_nothing() -> None:
    checker = DataQualityChecker(disabled_rules=[RULE_CROSS_SITE_DUPLICATE_IP])

    findings = checker.check_sites([_build_site("site-042"), _build_site("site-043")])

    assert _findings_for(findings, RULE_CROSS_SITE_DUPLICATE_IP) == []
    assert len(_findings_for(findings, RULE_CROSS_SITE_DUPLICATE_MAC)) == 3


def test_unknown_rule_name_raises_value_error() -> None:
    with pytest.raises(ValueError):
        DataQualityChecker(disabled_rules=["no_such_rule"])
    with pytest.raises(ValueError):
        DataQualityChecker(disabled_rules=[RULE_DUPLICATE_IP, "no_such_rule"])
    with pytest.raises(ValueError):
        DataQualityChecker(disabled_rules=[None])  # type: ignore[list-item]


def test_same_record_ids_in_two_sites_get_distinct_finding_ids() -> None:
    def duplicate_site(site_id: str) -> Site:
        site = _build_site(site_id)
        site.ip_addresses.append(
            IPAddress(
                ip="10.42.10.20",
                subnet_id="sub-010",
                assigned_object_type="Equipment",
                assigned_object_id="eq-02",
            )
        )
        return site

    findings = DataQualityChecker().check_sites(
        [duplicate_site("site-042"), duplicate_site("site-043")]
    )

    duplicates = _findings_for(findings, RULE_DUPLICATE_IP)
    assert len(duplicates) == 2
    assert len({f.finding_id for f in duplicates}) == 2
    assert {f.site_id for f in duplicates} == {"site-042", "site-043"}


def test_invalid_port_mode_raises_value_error() -> None:
    with pytest.raises(ValueError):
        DataQualityChecker(port_modes={"p-01": "hybrid"})


def test_invalid_severity_raises_value_error() -> None:
    with pytest.raises(ValueError):
        QualityFinding(
            finding_id="abc",
            site_id="site-042",
            rule=RULE_DUPLICATE_IP,
            severity="critical",
            record_type="IPAddress",
            record_ids=["ip:10.42.10.20"],
            message="boom",
        )


def test_finding_id_is_stable_across_runs() -> None:
    site = _build_site()
    site.ip_addresses.append(
        IPAddress(
            ip="10.42.10.20",
            subnet_id="sub-010",
            assigned_object_id="eq-02",
        )
    )

    first = DataQualityChecker().check_site(site)
    second = DataQualityChecker().check_site(site)

    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert re.fullmatch(r"[0-9a-f]{64}", first[0].finding_id) is not None


def test_finding_id_changes_when_record_id_changes() -> None:
    def duplicate_site(assigned_object_id: str) -> Site:
        site = _build_site()
        site.ip_addresses.append(
            IPAddress(
                ip="10.42.10.20",
                subnet_id="sub-010",
                assigned_object_type="Equipment",
                assigned_object_id=assigned_object_id,
            )
        )
        return site

    first = DataQualityChecker().check_site(duplicate_site("eq-02"))
    second = DataQualityChecker().check_site(duplicate_site("eq-03"))

    assert [f.finding_id for f in first] != [f.finding_id for f in second]


def test_check_site_is_deterministic() -> None:
    site = _build_site()
    site.ip_addresses.append(
        IPAddress(ip="10.42.10.20", subnet_id="sub-010", assigned_object_id="eq-02")
    )
    site.devices[0].ports[0].connected_mac = "aa:bb:cc:00:00:02"

    first = [f.finding_id for f in DataQualityChecker().check_site(site)]
    second = [f.finding_id for f in DataQualityChecker().check_site(site)]

    assert first == second
    assert len(first) == len(set(first))


def test_check_sites_is_order_independent() -> None:
    site_a = _build_site("site-042")
    site_b = _build_site("site-043")
    checker = DataQualityChecker()

    forward = [f.finding_id for f in checker.check_sites([site_a, site_b])]
    reverse = [f.finding_id for f in checker.check_sites([site_b, site_a])]

    assert forward == reverse


def test_check_site_readonly_does_not_mutate_input() -> None:
    site = _build_site()
    site.ip_addresses.append(
        IPAddress(ip="10.42.10.20", subnet_id="sub-010", assigned_object_id="eq-02")
    )
    site.devices[0].ports[0].connected_mac = "aa:bb:cc:00:00:02"
    site.equipment[0].connected_ports.append("p-404")
    snapshot = copy.deepcopy(site)

    DataQualityChecker(
        port_modes={"p-01": "trunk", "p-02": "uplink"},
        dns_ptr_names={"10.42.1.10": "other-sw.corp.example.com"},
    ).check_site(site)

    assert site == snapshot
    assert site.to_dict() == snapshot.to_dict()


@pytest.mark.parametrize(
    "bad_mac",
    ["aa:bb:cc:dd:ee:f:f", "a:abbcc:00:00:21", "aa:bb-cc:00:00:21", "zz:bb:cc:00:00:21"],
)
def test_malformed_mac_groups_are_ignored(bad_mac: str) -> None:
    site = _build_site()
    site.devices[0].ports[0].connected_mac = bad_mac
    site.devices[0].ports[1].connected_mac = bad_mac

    findings = DataQualityChecker().check_site(site)

    assert _findings_for(findings, RULE_DUPLICATE_MAC) == []


def test_mac_on_trunk_and_access_port_is_not_duplicate() -> None:
    site = _build_site()
    site.devices[0].ports[0].connected_mac = "aa:bb:cc:00:00:99"
    site.devices[0].ports[1].connected_mac = "aa:bb:cc:00:00:99"

    findings = DataQualityChecker(port_modes={"p-01": "trunk"}).check_site(site)

    assert _findings_for(findings, RULE_DUPLICATE_MAC) == []


def test_bare_string_disabled_rules_raises_value_error() -> None:
    with pytest.raises(ValueError):
        DataQualityChecker(disabled_rules=RULE_DUPLICATE_IP)  # type: ignore[arg-type]


def test_unassigned_duplicate_ip_refs_are_canonical() -> None:
    site = _build_site()
    site.ip_addresses.append(IPAddress(ip=" 10.42.10.30", subnet_id="sub-010"))
    site.ip_addresses.append(IPAddress(ip="10.42.10.30", subnet_id="sub-001"))

    findings = _findings_for(DataQualityChecker().check_site(site), RULE_DUPLICATE_IP)

    assert len(findings) == 1
    assert findings[0].record_ids == ["ip:10.42.10.30", "site:site-042"]
    assert findings[0].evidence["assignment_count"] == 2
    assert {a["subnet_id"] for a in findings[0].evidence["assignments"]} == {
        "sub-001",
        "sub-010",
    }
