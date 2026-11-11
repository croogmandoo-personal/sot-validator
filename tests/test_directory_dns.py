"""Unit tests for Active Directory computer account and /24 DNS/DHCP lease correlation collectors."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from sot_validator.classifier.engine import (
    ClassificationEngine,
    ClassificationPolicy,
    DEFAULT_SIGNAL_WEIGHTS,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Signal,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    ValidationClassification,
    ValidationSignal,
)
from sot_validator.scoring.engine import ScoringConfig, ValidationScorer
from sot_validator.signals import (
    ActiveDirectoryCollector,
    AdComputerRecord,
    DhcpLeaseRecord,
    DnsDhcpLeaseCollector,
    DnsRecord,
    SECONDS_PER_DAY,
    SubnetScopeGuard,
    normalize_hostname,
)

FIXED_EVAL_TIME = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)


def test_signal_type_and_signal_metadata_serialization() -> None:
    sig = Signal(
        signal_type=SignalType.DNS_DHCP_LEASE,
        status=SignalStatus.ACTIVE,
        observed_at=FIXED_EVAL_TIME,
        age_seconds=0.0,
        details="Active /24 DHCP lease; dns_mismatch=True",
        source="dns_dhcp",
        metadata={"dns_mismatch": True, "dhcp_lease_active": True},
    )
    assert sig.metadata["dns_mismatch"] is True
    assert ValidationSignal.from_dict(sig.to_dict()) == sig
    assert ValidationSignal.from_json(sig.to_json()) == sig

    with pytest.raises(ValueError, match="metadata"):
        ValidationSignal(
            signal_type=SignalType.AD_COMPUTER_ACCOUNT,
            status=SignalStatus.ACTIVE,
            metadata="invalid",  # type: ignore[arg-type]
        )


def test_normalize_hostname_variants() -> None:
    assert normalize_hostname("WIN-SQL01$") == "win-sql01"
    assert normalize_hostname("WIN-SQL01$.corp.local.") == "win-sql01"
    assert normalize_hostname("  Win-App02.Site042.Example.Internal  ") == "win-app02"
    assert normalize_hostname("ext-sw01") == "ext-sw01"
    assert normalize_hostname("10.42.10.25") == "10.42.10.25"
    assert normalize_hostname("") is None
    assert normalize_hostname("   ") is None
    assert normalize_hostname(None) is None


def test_ad_computer_record_and_active_directory_collector_active_disabled_stale() -> None:
    recent_logon = FIXED_EVAL_TIME - timedelta(days=5)
    recent_pwd = FIXED_EVAL_TIME - timedelta(days=18)
    intermediate_ts = FIXED_EVAL_TIME - timedelta(days=45)
    stale_ts = FIXED_EVAL_TIME - timedelta(days=120)

    rec_active = AdComputerRecord(
        sAMAccountName="WIN-SQL01$",
        dNSHostName="WIN-SQL01.site042.example.internal",
        operatingSystem="Windows Server 2022 Datacenter",
        enabled=True,
        lastLogonTimestamp=recent_logon.isoformat(),
        pwdLastSet=stale_ts.isoformat(),
        distinguishedName="CN=WIN-SQL01,OU=Servers,OU=Site042,DC=example,DC=internal",
    )
    assert rec_active.sAMAccountName == "WIN-SQL01$"
    assert rec_active.dNSHostName == "WIN-SQL01.site042.example.internal"
    assert rec_active.operatingSystem == "Windows Server 2022 Datacenter"
    assert rec_active.distinguishedName is not None
    assert rec_active.ou == rec_active.distinguishedName
    assert AdComputerRecord.from_dict(rec_active.to_dict()) == rec_active

    rec_pwd_recent = {
        "sAMAccountName": "WIN-APP02$",
        "dNSHostName": "win-app02.site042.example.internal",
        "operatingSystem": "Windows Server 2019 Standard",
        "enabled": True,
        "lastLogonTimestamp": stale_ts.isoformat(),
        "pwdLastSet": recent_pwd.isoformat(),
        "OU": "OU=AppServers,OU=Site042,DC=example,DC=internal",
    }

    rec_disabled = {
        "sAMAccountName": "WIN-DECOMM01$",
        "dNSHostName": "win-decomm01.site042.example.internal",
        "operatingSystem": "Windows Server 2016 Standard",
        "enabled": False,
        "lastLogonTimestamp": recent_logon.isoformat(),
        "pwdLastSet": recent_pwd.isoformat(),
        "distinguishedName": "CN=WIN-DECOMM01,OU=Disabled,DC=example,DC=internal",
    }

    rec_stale = {
        "sAMAccountName": "WIN-OLD99$",
        "dNSHostName": "win-old99.site042.example.internal",
        "operatingSystem": "Windows Server 2012 R2",
        "enabled": True,
        "lastLogonTimestamp": stale_ts.isoformat(),
        "pwdLastSet": stale_ts.isoformat(),
        "distinguishedName": "CN=WIN-OLD99,OU=Legacy,DC=example,DC=internal",
    }

    rec_intermediate = {
        "sAMAccountName": "WIN-MID50$",
        "dNSHostName": "win-mid50.site042.example.internal",
        "operatingSystem": "Windows Server 2022",
        "enabled": True,
        "lastLogonTimestamp": intermediate_ts.isoformat(),
    }

    rec_netdev = {
        "sAMAccountName": "WIN-MGMTGW01$",
        "dNSHostName": "win-mgmtgw01.site042.example.internal",
        "operatingSystem": "Windows Server 2022",
        "enabled": True,
        "lastLogonTimestamp": recent_logon.isoformat(),
    }

    collector = ActiveDirectoryCollector(
        records=[
            rec_active,
            rec_pwd_recent,
            rec_disabled,
            rec_stale,
            rec_intermediate,
            rec_netdev,
        ],
        active_threshold_days=30.0,
        stale_threshold_days=90.0,
        evaluation_time=FIXED_EVAL_TIME,
    )

    # 1. Active via recent lastLogonTimestamp (matching short SoT name against FQDN/sAMAccountName)
    eq_sql = Equipment(
        equipment_id="eq-042-sql01",
        site_id="site-042",
        name="win-sql01",
        category=EquipmentCategory.VM,
        assigned_ips=["10.42.10.25"],
    )
    sig_sql = collector.evaluate(eq_sql)
    assert sig_sql.signal_type is SignalType.AD_COMPUTER_ACCOUNT
    assert sig_sql.status is SignalStatus.ACTIVE
    assert sig_sql.age_seconds == pytest.approx(5.0 * SECONDS_PER_DAY)
    assert sig_sql.metadata["sAMAccountName"] == "WIN-SQL01$"
    assert sig_sql.metadata["operatingSystem"] == "Windows Server 2022 Datacenter"
    assert sig_sql.metadata["enabled"] is True
    assert sig_sql.metadata["account_stale"] is False

    # 2. Active via recent pwdLastSet even when lastLogonTimestamp is older
    eq_app = Equipment(
        equipment_id="eq-042-app02",
        site_id="site-042",
        name="WIN-APP02.SITE042.EXAMPLE.INTERNAL",
        category=EquipmentCategory.SERVER,
        assigned_ips=["10.42.10.26"],
    )
    sig_app = collector.collect_for_equipment(eq_app)
    assert sig_app.status is SignalStatus.ACTIVE
    assert sig_app.age_seconds == pytest.approx(18.0 * SECONDS_PER_DAY)
    assert sig_app.metadata["account_stale"] is False

    # 3. Disabled computer account (enabled=False) -> INACTIVE regardless of recent timestamps
    eq_disabled = Equipment(
        equipment_id="eq-042-decomm01",
        site_id="site-042",
        name="win-decomm01.site042.example.internal",
        category=EquipmentCategory.VM,
    )
    sig_disabled = collector.evaluate(eq_disabled)
    assert sig_disabled.status is SignalStatus.INACTIVE
    assert sig_disabled.metadata["enabled"] is False
    assert sig_disabled.metadata["account_stale"] is True
    assert "disabled" in (sig_disabled.details or "").lower()

    # 4. Stale computer account (> 90 days) -> INACTIVE
    eq_stale = Equipment(
        equipment_id="eq-042-old99",
        site_id="site-042",
        name="win-old99",
        category=EquipmentCategory.VM,
    )
    sig_stale = collector.evaluate(eq_stale)
    assert sig_stale.status is SignalStatus.INACTIVE
    assert sig_stale.metadata["enabled"] is True
    assert sig_stale.metadata["account_stale"] is True
    assert "stale" in (sig_stale.details or "").lower()

    # 5. Intermediate computer account (30d < age <= 90d) -> INACTIVE with intermediate window
    eq_mid = Equipment(
        equipment_id="eq-042-mid50",
        site_id="site-042",
        name="win-mid50",
        category=EquipmentCategory.VM,
    )
    sig_mid = collector.evaluate(eq_mid)
    assert sig_mid.status is SignalStatus.INACTIVE
    assert sig_mid.metadata["account_stale"] is False
    assert "intermediate" in (sig_mid.details or "").lower()

    # 6. NetworkDevice match and unmatched Equipment -> NOT_APPLICABLE
    dev = NetworkDevice(
        device_id="dev-042-gw01",
        site_id="site-042",
        hostname="win-mgmtgw01.site042.example.internal",
        management_ip="10.42.1.5",
    )
    sig_dev = collector.collect_for_device(dev)
    assert sig_dev.status is SignalStatus.ACTIVE

    eq_linux = Equipment(
        equipment_id="eq-042-lnx01",
        site_id="site-042",
        name="lnx-redis01.site042.example.internal",
        category=EquipmentCategory.VM,
    )
    sig_unmatched = collector.evaluate(eq_linux)
    assert sig_unmatched.status is SignalStatus.NOT_APPLICABLE


def test_dns_dhcp_lease_collector_slash24_scoping_and_dns_mismatch() -> None:
    site = Site(
        site_id="site-042",
        name="Site 42",
        subnets=[
            Subnet(subnet_id="sub-042-010", site_id="site-042", cidr="10.42.10.0/24"),
            Subnet(subnet_id="sub-042-020", site_id="site-042", cidr="10.42.20.0/24"),
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.10.25",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-sql01",
            ),
            IPAddress(
                ip="10.42.10.30",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-drift01",
            ),
            IPAddress(
                ip="10.42.10.40",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-expired01",
            ),
        ],
        equipment=[
            Equipment(
                equipment_id="eq-042-sql01",
                site_id="site-042",
                name="win-sql01.site042.example.internal",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.25"],
            ),
            Equipment(
                equipment_id="eq-042-drift01",
                site_id="site-042",
                name="win-drift01.site042.example.internal",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.30"],
            ),
            Equipment(
                equipment_id="eq-042-expired01",
                site_id="site-042",
                name="win-expired01.site042.example.internal",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.10.40"],
            ),
        ],
    )

    dns_records = [
        # Aligned A and PTR for win-sql01 (10.42.10.25)
        DnsRecord(
            record_type="A",
            hostname="win-sql01.site042.example.internal",
            ip="10.42.10.25",
        ),
        DnsRecord(
            record_type="PTR",
            hostname="win-sql01.site042.example.internal",
            ip="10.42.10.25",
        ),
        # Mismatched A and PTR for win-drift01 (SoT IP 10.42.10.30, but PTR points to win-oldname)
        DnsRecord(
            record_type="A",
            hostname="win-drift01.site042.example.internal",
            ip="10.42.10.30",
        ),
        DnsRecord(
            record_type="PTR",
            hostname="win-oldname.site042.example.internal",
            ip="10.42.10.30",
        ),
    ]

    dhcp_leases = [
        # Active /24 lease for 10.42.10.25
        DhcpLeaseRecord(
            ip="10.42.10.25",
            hostname="WIN-SQL01.site042.example.internal",
            mac_address="00:50:56:9a:42:25",
            subnet_cidr="10.42.10.0/24",
            status="active",
            lease_expiration=FIXED_EVAL_TIME + timedelta(hours=8),
            observed_at=FIXED_EVAL_TIME - timedelta(minutes=15),
        ),
        # Expired /24 lease for 10.42.10.40
        DhcpLeaseRecord(
            ip="10.42.10.40",
            hostname="win-expired01.site042.example.internal",
            mac_address="00:50:56:9a:42:40",
            subnet_cidr="10.42.10.0/24",
            status="active",
            lease_expiration=FIXED_EVAL_TIME - timedelta(days=5),
            observed_at=FIXED_EVAL_TIME - timedelta(days=6),
        ),
        # Out-of-scope /16 or unallocated /24 lease that must be ignored by scope guard
        DhcpLeaseRecord(
            ip="10.42.99.50",
            hostname="win-unscoped.site042.example.internal",
            subnet_cidr="10.42.99.0/24",
            status="active",
        ),
    ]

    collector = DnsDhcpLeaseCollector(
        dns_records=dns_records,
        dhcp_leases=dhcp_leases,
        site=site,
        evaluation_time=FIXED_EVAL_TIME,
    )

    # 1. Active /24 DHCP lease + aligned A/PTR -> ACTIVE, dns_mismatch=False
    sig_sql_eq = collector.collect_for_equipment(site.equipment[0], site=site)
    assert sig_sql_eq.signal_type is SignalType.DNS_DHCP_LEASE
    assert sig_sql_eq.status is SignalStatus.ACTIVE
    assert sig_sql_eq.metadata["dns_mismatch"] is False
    assert sig_sql_eq.metadata["dhcp_lease_active"] is True

    sig_sql_ip = collector.collect_for_ip(site.ip_addresses[0], site=site)
    assert sig_sql_ip.status is SignalStatus.ACTIVE
    assert sig_sql_ip.metadata["dns_mismatch"] is False

    # 2. Forward A and Reverse PTR disagree (no active DHCP lease) -> INACTIVE, dns_mismatch=True
    sig_drift_eq = collector.collect_for_equipment(site.equipment[1], site=site)
    assert sig_drift_eq.status is SignalStatus.INACTIVE
    assert sig_drift_eq.metadata["dns_mismatch"] is True
    assert "dns_mismatch=True" in (sig_drift_eq.details or "")

    sig_drift_ip = collector.collect_for_ip(site.ip_addresses[1], site=site)
    assert sig_drift_ip.status is SignalStatus.INACTIVE
    assert sig_drift_ip.metadata["dns_mismatch"] is True

    # 3. Active DHCP lease with DNS A/PTR mismatch -> ACTIVE, dns_mismatch=True
    sig_active_with_mismatch = collector.evaluate(
        site.equipment[1],
        site=site,
        dhcp_leases=[
            DhcpLeaseRecord(
                ip="10.42.10.30",
                hostname="win-drift01.site042.example.internal",
                subnet_cidr="10.42.10.0/24",
                status="active",
                lease_expiration=FIXED_EVAL_TIME + timedelta(hours=4),
            )
        ],
    )
    assert sig_active_with_mismatch.status is SignalStatus.ACTIVE
    assert sig_active_with_mismatch.metadata["dns_mismatch"] is True
    assert sig_active_with_mismatch.metadata["dhcp_lease_active"] is True

    # 4. Expired /24 DHCP lease with no DNS alignment -> INACTIVE, dns_mismatch=False
    sig_expired = collector.collect_for_equipment(site.equipment[2], site=site)
    assert sig_expired.status is SignalStatus.INACTIVE
    assert sig_expired.metadata["dns_mismatch"] is False
    assert sig_expired.metadata["dhcp_lease_active"] is False

    # 5. Out-of-scope /24 IP rejected by SubnetScopeGuard -> NOT_APPLICABLE
    out_of_scope_ip = IPAddress(ip="10.42.99.50", subnet_id="sub-042-099")
    sig_oos = collector.collect_for_ip(
        out_of_scope_ip,
        scope_guard=SubnetScopeGuard.from_site(site),
    )
    assert sig_oos.status is SignalStatus.NOT_APPLICABLE
    assert "10.42.99.50" in sig_oos.metadata["out_of_scope_ips"]


def test_scoring_and_classification_with_ad_and_dns_dhcp_signals() -> None:
    assert ScoringConfig is ClassificationPolicy
    assert ValidationScorer is ClassificationEngine
    assert set(DEFAULT_SIGNAL_WEIGHTS.keys()) == set(SignalType)
    assert DEFAULT_SIGNAL_WEIGHTS[SignalType.AD_COMPUTER_ACCOUNT] == pytest.approx(0.40)
    assert DEFAULT_SIGNAL_WEIGHTS[SignalType.DNS_DHCP_LEASE] == pytest.approx(0.35)

    ad_collector = ActiveDirectoryCollector(
        records=[
            {
                "sAMAccountName": "WIN-FILE01$",
                "dNSHostName": "win-file01.site042.example.internal",
                "operatingSystem": "Windows Server 2022",
                "enabled": True,
                "lastLogonTimestamp": (FIXED_EVAL_TIME - timedelta(days=2)).isoformat(),
            },
            {
                "sAMAccountName": "WIN-RETIRED01$",
                "dNSHostName": "win-retired01.site042.example.internal",
                "operatingSystem": "Windows Server 2012 R2",
                "enabled": False,
                "lastLogonTimestamp": (FIXED_EVAL_TIME - timedelta(days=150)).isoformat(),
            },
        ],
        evaluation_time=FIXED_EVAL_TIME,
    )
    dns_dhcp_collector = DnsDhcpLeaseCollector(
        a_records={"win-file01.site042.example.internal": "10.42.10.55"},
        ptr_records={"10.42.10.55": "win-file01.site042.example.internal"},
        dhcp_leases=[
            {
                "ip": "10.42.10.55",
                "hostname": "win-file01.site042.example.internal",
                "subnet_cidr": "10.42.10.0/24",
                "status": "active",
            },
            {
                "ip": "10.42.10.66",
                "hostname": "win-retired01.site042.example.internal",
                "subnet_cidr": "10.42.10.0/24",
                "status": "expired",
            },
        ],
        subnets=["10.42.10.0/24"],
        evaluation_time=FIXED_EVAL_TIME,
    )

    scorer = ValidationScorer(
        config if (config := ScoringConfig()) else None,
        ad_collector=ad_collector,
        dns_dhcp_collector=dns_dhcp_collector,
        evaluation_time=FIXED_EVAL_TIME,
    )

    site = Site(
        site_id="site-042",
        name="Site 42",
        subnets=[Subnet(subnet_id="sub-042-010", site_id="site-042", cidr="10.42.10.0/24")],
        devices=[
            NetworkDevice(
                device_id="dev-042-sw01",
                site_id="site-042",
                hostname="sw01.site042.example.internal",
                management_ip="10.42.10.2",
            )
        ],
        ip_addresses=[
            IPAddress(
                ip="10.42.10.55",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-file01",
            ),
            IPAddress(
                ip="10.42.10.66",
                subnet_id="sub-042-010",
                assigned_object_type="equipment",
                assigned_object_id="eq-042-retired01",
            ),
        ],
        equipment=[
            Equipment(
                equipment_id="eq-042-file01",
                site_id="site-042",
                name="win-file01.site042.example.internal",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.10.55"],
            ),
            Equipment(
                equipment_id="eq-042-retired01",
                site_id="site-042",
                name="win-retired01.site042.example.internal",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.10.66"],
            ),
        ],
    )

    # 1. Active Windows server collected via AD + DNS/DHCP classifies as Confirmed Active
    res_active = scorer.classify_equipment(site.equipment[0], site=site)
    assert res_active.classification is ValidationClassification.CONFIRMED_ACTIVE
    assert res_active.confidence >= 0.88

    # 2. Windows server blocking ICMP ping is still Confirmed Active when AD + DHCP are ACTIVE
    ad_sig = ad_collector.evaluate(site.equipment[0], site=site)
    dhcp_sig = dns_dhcp_collector.evaluate(site.equipment[0], site=site)
    icmp_unreach = ValidationSignal(
        signal_type=SignalType.ICMP_REACHABILITY,
        status=SignalStatus.UNREACHABLE,
        observed_at=FIXED_EVAL_TIME,
        age_seconds=0.0,
        details="ICMP unreachable (Windows Firewall drop)",
    )
    res_fw = scorer.score_signals(
        [ad_sig, dhcp_sig, icmp_unreach],
        item_type="Equipment",
        item_id="eq-042-file01",
        site_id="site-042",
        name="win-file01.site042.example.internal",
        target=site.equipment[0],
    )
    assert res_fw.classification is ValidationClassification.CONFIRMED_ACTIVE
    assert res_fw.confidence >= 0.85

    # 3. Disabled AD account + expired DHCP lease classifies as Stale / Likely Unused
    res_retired = scorer.classify_equipment(site.equipment[1], site=site)
    assert res_retired.classification is ValidationClassification.STALE_LIKELY_UNUSED
    assert res_retired.confidence >= 0.70

    # 4. IPAddress classification invokes both ad_collector and dns_dhcp_collector with non-empty site.devices
    res_ip_active = scorer.classify_ip(site.ip_addresses[0], site=site)
    assert res_ip_active.classification is ValidationClassification.CONFIRMED_ACTIVE
    ip_sig_types = {s.signal_type: s.status for s in res_ip_active.signals}
    assert ip_sig_types[SignalType.AD_COMPUTER_ACCOUNT] is SignalStatus.ACTIVE
    assert ip_sig_types[SignalType.DNS_DHCP_LEASE] is SignalStatus.ACTIVE

    res_ip_retired = scorer.classify_ip(site.ip_addresses[1], site=site)
    assert res_ip_retired.classification is ValidationClassification.STALE_LIKELY_UNUSED
    retired_ip_sig_types = {s.signal_type: s.status for s in res_ip_retired.signals}
    assert retired_ip_sig_types[SignalType.AD_COMPUTER_ACCOUNT] is SignalStatus.INACTIVE
    assert retired_ip_sig_types[SignalType.DNS_DHCP_LEASE] is SignalStatus.INACTIVE
