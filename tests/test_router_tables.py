"""Unit tests for the cross-VLAN router ARP/neighbor and DHCP lease table collector."""

from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from sot_validator.discovery import (
    DhcpLeaseRecord,
    DiscoveredHost,
    DiscoveryConfig,
    RouterArpDhcpCollector,
    RouterArpRecord,
    RouterTableParsers,
    SubnetDiscoveryScanner,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
)

OBSERVED = datetime(2026, 11, 12, 15, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- records


def test_router_arp_record_normalization_and_round_trip() -> None:
    rec = RouterArpRecord(
        ip=" 10.42.10.25 ",
        mac_address="00:04:96:1:2:3",
        interface=" eth1.10 ",
        vlan_id=10,
        state=" stale ",
        router_id=" core-rtr-01 ",
        observed_at="2026-11-12T15:00:00",
    )
    assert rec.ip == "10.42.10.25"
    assert rec.mac_address == "00:04:96:01:02:03"
    assert rec.interface == "eth1.10"
    assert rec.vlan_id == "10"
    assert rec.state == "STALE"
    assert rec.router_id == "core-rtr-01"
    assert rec.observed_at == OBSERVED

    payload = rec.to_dict()
    assert payload["observed_at"] == "2026-11-12T15:00:00+00:00"
    assert RouterArpRecord.from_dict(payload) == rec
    assert RouterArpRecord.from_dict(json.loads(json.dumps(payload))) == rec

    defaults = RouterArpRecord(ip="10.42.10.26")
    assert defaults.state == "REACHABLE"
    assert defaults.mac_address is None
    assert RouterArpRecord(ip="10.42.10.26", state="  ", vlan_id="").state is None
    assert RouterArpRecord(ip="10.42.10.26", vlan_id="").vlan_id is None


@pytest.mark.parametrize(
    "raw_mac",
    [
        "00:04:96:01:02:03",
        "00-04-96-01-02-03",
        "0004.9601.0203",
        "00 04 96 01 02 03",
        "0x000496010203",
        "000496010203",
        "00:04:96:1:2:3",
        "00:04:96:01:02:03 ",
        "00:04:96:01:02:03".upper(),
    ],
)
def test_router_arp_record_mac_normalization_formats(raw_mac: str) -> None:
    assert RouterArpRecord(ip="10.42.10.5", mac_address=raw_mac).mac_address == (
        "00:04:96:01:02:03"
    )


@pytest.mark.parametrize(
    "placeholder", ["incomplete", "(incomplete)", "failed", "none", "00:00:00:00:00:00", ""]
)
def test_router_arp_record_mac_placeholders_become_none(placeholder: str) -> None:
    assert RouterArpRecord(ip="10.42.10.5", mac_address=placeholder).mac_address is None


def test_router_arp_record_rejects_invalid_values() -> None:
    for bad_ip in ("", "10.42.10.300", "fe80::1", "not-an-ip"):
        with pytest.raises(ValueError):
            RouterArpRecord(ip=bad_ip)
    for bad_mac in (
        "zz:zz:zz:zz:zz:zz",
        "00:04:96:01:02",
        "0004.9601",
        "12345",
        "1.2.3",
        "00.04.96",
        "004.9601.0203",
    ):
        with pytest.raises(ValueError):
            RouterArpRecord(ip="10.42.10.5", mac_address=bad_mac)
    with pytest.raises(ValueError):
        RouterArpRecord(ip="10.42.10.5", observed_at="yesterday")
    with pytest.raises(ValueError):
        RouterArpRecord(ip="10.42.10.5", state=5)  # type: ignore[arg-type]


def test_router_arp_record_observed_at_formats() -> None:
    epoch = int(OBSERVED.timestamp())
    assert RouterArpRecord(ip="10.42.10.5", observed_at=epoch).observed_at == OBSERVED
    assert (
        RouterArpRecord(ip="10.42.10.5", observed_at=float(epoch)).observed_at == OBSERVED
    )
    assert (
        RouterArpRecord(ip="10.42.10.5", observed_at="2026-11-12T15:00:00Z").observed_at
        == OBSERVED
    )
    naive = datetime(2026, 11, 12, 15, 0, 0)
    assert RouterArpRecord(ip="10.42.10.5", observed_at=naive).observed_at == OBSERVED


def test_dhcp_lease_record_normalization_and_round_trip() -> None:
    lease = DhcpLeaseRecord(
        ip="10.42.20.50",
        mac_address="BC-24-11-00-11-22",
        hostname="  pve-node-01 ",
        lease_expires_at="2026/11/12 15:00:00",
        subnet_id=20,
        client_id=" 01:bc:24:11:00:11:22 ",
    )
    assert lease.mac_address == "bc:24:11:00:11:22"
    assert lease.hostname == "pve-node-01"
    assert lease.lease_expires_at == OBSERVED
    assert lease.subnet_id == "20"
    assert lease.client_id == "01:bc:24:11:00:11:22"
    assert DhcpLeaseRecord.from_dict(lease.to_dict()) == lease

    epoch = int(OBSERVED.timestamp())
    for raw_expiry in (epoch, float(epoch), str(epoch), "2026-11-12T15:00:00+00:00"):
        assert (
            DhcpLeaseRecord(ip="10.42.20.50", lease_expires_at=raw_expiry).lease_expires_at
            == OBSERVED
        )
    for infinite in (None, "", "0", 0, "infinite", "never", "NEVER"):
        assert (
            DhcpLeaseRecord(ip="10.42.20.50", lease_expires_at=infinite).lease_expires_at
            is None
        )
    wildcard = DhcpLeaseRecord(ip="10.42.20.50", hostname="*", client_id="*", subnet_id="")
    assert wildcard.hostname is None
    assert wildcard.client_id is None
    assert wildcard.subnet_id is None

    with pytest.raises(ValueError):
        DhcpLeaseRecord(ip="10.42.20.256")
    with pytest.raises(ValueError):
        DhcpLeaseRecord(ip="10.42.20.50", mac_address="not-a-mac")
    with pytest.raises(ValueError):
        DhcpLeaseRecord(ip="10.42.20.50", lease_expires_at="tomorrow")


# --------------------------------------------------------------------------- ARP parsers


IP_NEIGH_OUTPUT = """\
10.42.10.25 dev eth1.10 lladdr 00:04:96:aa:bb:cc REACHABLE
10.42.20.10 dev br20 lladdr bc:24:11:00:11:22 router STALE
10.42.10.99 dev eth0 INCOMPLETE
10.42.50.7 dev switch0.50 lladdr 44:61:32:01:02:03 DELAY
10.42.60.8 dev vlan.60 lladdr 00:c0:b7:01:02:03 PERMANENT
10.42.70.9 dev bond0.70 lladdr 00:11:22:33:44:55 REACHABLE
10.42.80.10 dev vlan80 lladdr 00:11:22:33:44:66 FAILED
fe80::1 dev eth0 lladdr 00:11:22:33:44:77 STALE
garbage line here
"""


def test_parse_ip_neigh_linux_unifi_edgeos() -> None:
    records = RouterTableParsers.parse_ip_neigh(
        IP_NEIGH_OUTPUT, router_id="edge-rtr", observed_at="2026-11-12T15:00:00+00:00"
    )
    by_ip = {r.ip: r for r in records}
    assert list(by_ip) == [
        "10.42.10.25",
        "10.42.20.10",
        "10.42.10.99",
        "10.42.50.7",
        "10.42.60.8",
        "10.42.70.9",
        "10.42.80.10",
    ]
    first = by_ip["10.42.10.25"]
    assert first.mac_address == "00:04:96:aa:bb:cc"
    assert first.interface == "eth1.10"
    assert first.vlan_id == "10"
    assert first.state == "REACHABLE"
    assert first.router_id == "edge-rtr"
    assert first.observed_at == OBSERVED

    assert by_ip["10.42.20.10"].vlan_id == "20"
    assert by_ip["10.42.20.10"].state == "STALE"
    assert by_ip["10.42.10.99"].mac_address is None
    assert by_ip["10.42.10.99"].state == "INCOMPLETE"
    # eth0 has no VLAN tag: fall back to the IPv4 third octet
    assert by_ip["10.42.10.99"].vlan_id == "10"
    assert by_ip["10.42.50.7"].vlan_id == "50"
    assert by_ip["10.42.60.8"].vlan_id == "60"
    assert by_ip["10.42.70.9"].vlan_id == "70"
    assert by_ip["10.42.80.10"].vlan_id == "80"
    assert by_ip["10.42.80.10"].state == "FAILED"

    assert RouterTableParsers.parse_ip_neigh("") == []


EXOS_OUTPUT_WITH_VR = """\
VR               Destination      Mac                Age  Static  VLAN          VID   Port
VR-Default       10.42.10.15      00:04:96:aa:bb:cc     5     NO  VLAN_0010       10   1:1
VR-Default       10.42.10.16      00:04:96:aa:bb:cd     0    YES  VLAN_0010       10   1:2
VR-Default       10.42.30.5       00:c0:b7:11:22:33     2     NO  Servers30        -   2:4

Dynamic Entries  :          2    Static Entries   :          1
Pending Entries  :          0    In Request       :          0
"""

EXOS_OUTPUT_NO_VR = """\
Destination      Mac                Age  Static  VLAN          VID   Port
10.42.10.15      00:04:96:aa:bb:cc     5  STATIC  Default     4095   1:24
10.42.40.9       00:04:96:aa:bb:ce     3      NO  Data           40   1:3
"""


def test_parse_extremexos_iparp_with_and_without_vr_column() -> None:
    records = RouterTableParsers.parse_extremexos_arp(
        EXOS_OUTPUT_WITH_VR, router_id="exos-core", observed_at=OBSERVED
    )
    assert [r.ip for r in records] == ["10.42.10.15", "10.42.10.16", "10.42.30.5"]
    dynamic, static, by_name = records
    assert dynamic.mac_address == "00:04:96:aa:bb:cc"
    assert dynamic.state == "DYNAMIC"
    assert dynamic.vlan_id == "10"
    assert dynamic.interface == "1:1"
    assert dynamic.router_id == "exos-core"
    assert dynamic.observed_at == OBSERVED
    assert static.state == "STATIC"
    assert static.interface == "1:2"
    # Non-numeric VID: digits in the VLAN name win
    assert by_name.vlan_id == "30"
    assert by_name.interface == "2:4"

    no_vr = RouterTableParsers.parse_extremexos_arp(EXOS_OUTPUT_NO_VR)
    assert [r.ip for r in no_vr] == ["10.42.10.15", "10.42.40.9"]
    assert no_vr[0].state == "STATIC"
    assert no_vr[0].vlan_id == "4095"
    assert no_vr[0].interface == "1:24"
    assert no_vr[1].state == "DYNAMIC"
    assert no_vr[1].vlan_id == "40"


VOSS_OUTPUT = """\
================================================================================
                              IP Arp - GlobalRouter
================================================================================
IP_ADDRESS      MAC_ADDRESS        VLAN  PORT   TYPE     TTL(10 Sec) TUNNEL
--------------------------------------------------------------------------------
10.42.20.20     00:c0:b7:aa:bb:cc  20    1/2    DYNAMIC  2160
10.42.20.21     00c0.b711.2233     20    v20    STATIC   0
10.42.20.1      00:04:96:20:00:01  20    -      LOCAL    2160

3 out of 3 ARP entries displayed
"""


def test_parse_voss_show_ip_arp() -> None:
    records = RouterTableParsers.parse_voss_arp(VOSS_OUTPUT, router_id="voss-dist")
    assert [r.ip for r in records] == ["10.42.20.20", "10.42.20.21", "10.42.20.1"]
    dyn, static, local = records
    assert dyn.mac_address == "00:c0:b7:aa:bb:cc"
    assert dyn.vlan_id == "20"
    assert dyn.interface == "1/2"
    assert dyn.state == "DYNAMIC"
    assert static.mac_address == "00:c0:b7:11:22:33"
    assert static.interface == "v20"
    assert static.state == "STATIC"
    assert local.interface is None
    assert local.state == "LOCAL"
    assert all(r.router_id == "voss-dist" for r in records)


def test_parse_cli_arp_auto_detects_formats() -> None:
    linux = RouterTableParsers.parse_cli_arp(IP_NEIGH_OUTPUT)
    assert linux == RouterTableParsers.parse_ip_neigh(IP_NEIGH_OUTPUT)

    exos = RouterTableParsers.parse_cli_arp(EXOS_OUTPUT_WITH_VR)
    assert exos == RouterTableParsers.parse_extremexos_arp(EXOS_OUTPUT_WITH_VR)
    exos_no_vr = RouterTableParsers.parse_cli_arp(EXOS_OUTPUT_NO_VR)
    assert exos_no_vr == RouterTableParsers.parse_extremexos_arp(EXOS_OUTPUT_NO_VR)

    voss = RouterTableParsers.parse_cli_arp(VOSS_OUTPUT)
    assert voss == RouterTableParsers.parse_voss_arp(VOSS_OUTPUT)

    mixed = RouterTableParsers.parse_cli_arp(
        IP_NEIGH_OUTPUT + EXOS_OUTPUT_WITH_VR + VOSS_OUTPUT, router_id="mixed"
    )
    assert len(mixed) == len(linux) + len(exos) + len(voss)
    assert {r.router_id for r in mixed} == {"mixed"}


def test_parse_cli_arp_voss_numeric_port_and_exos_numeric_static() -> None:
    voss = RouterTableParsers.parse_cli_arp(
        "10.42.20.21     00c0.b711.2233     20    1      STATIC   0\n"
    )
    assert len(voss) == 1
    assert voss[0].interface == "1"
    assert voss[0].vlan_id == "20"
    assert voss[0].state == "STATIC"
    assert voss == RouterTableParsers.parse_voss_arp(
        "10.42.20.21     00c0.b711.2233     20    1      STATIC   0\n"
    )

    exos = RouterTableParsers.parse_cli_arp(
        "10.42.10.15  00:04:96:aa:bb:cc  5  1  Default  10  1:24\n"
    )
    assert len(exos) == 1
    assert exos[0].state == "STATIC"
    assert exos[0].interface == "1:24"
    assert exos[0].vlan_id == "10"


SNMP_OIDS = {
    "1.3.6.1.2.1.4.22.1.2.12.10.42.10.25": "00:04:96:aa:bb:cc",
    "1.3.6.1.2.1.4.22.1.3.12.10.42.10.25": "10.42.10.25",
    "1.3.6.1.2.1.4.22.1.4.12.10.42.10.25": 3,
    ".1.3.6.1.2.1.4.22.1.2.13.10.42.20.40": "Hex-STRING: 00 C0 B7 01 02 03",
    "1.3.6.1.2.1.4.22.1.4.13.10.42.20.40": "static(4)",
    "1.3.6.1.2.1.4.22.1.3.14.10.42.30.9": "10.42.30.9",
    "1.3.6.1.2.1.4.35.1.4.15.1.4.10.42.50.7": "0x446132010203",
    "1.3.6.1.2.1.4.35.1.4.16.10.42.60.8": "bc:24:11:00:00:08",
    "1.3.6.1.2.1.4.35.1.4.16.2.16.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.1": "00:11:22:33:44:55",
    "1.3.6.1.2.1.2.2.1.2.12": "VLAN_0010",
    "1.3.6.1.2.1.31.1.1.1.1.12": "vlan10",
    "1.3.6.1.2.1.2.2.1.2.13": "Port 1:13",
    "1.3.6.1.2.1.31.1.1.1.1.15": "eth0.50",
    "1.3.6.1.2.1.1.5.0": "core-rtr",
}


def test_parse_snmp_arp_oid_walk_dict_and_json() -> None:
    records = RouterTableParsers.parse_snmp_arp(
        SNMP_OIDS, router_id="snmp-core", observed_at=OBSERVED
    )
    by_ip = {r.ip: r for r in records}
    assert [r.ip for r in records] == [
        "10.42.10.25",
        "10.42.20.40",
        "10.42.30.9",
        "10.42.50.7",
        "10.42.60.8",
    ]
    media = by_ip["10.42.10.25"]
    assert media.mac_address == "00:04:96:aa:bb:cc"
    assert media.state == "DYNAMIC"
    assert media.interface == "vlan10"  # ifName preferred over ifDescr
    assert media.vlan_id == "10"
    assert media.router_id == "snmp-core"
    assert media.observed_at == OBSERVED

    hex_string = by_ip["10.42.20.40"]
    assert hex_string.mac_address == "00:c0:b7:01:02:03"
    assert hex_string.state == "STATIC"
    assert hex_string.interface == "Port 1:13"
    assert hex_string.vlan_id == "20"

    net_only = by_ip["10.42.30.9"]
    assert net_only.mac_address is None
    assert net_only.state is None
    assert net_only.interface == "14"

    physical = by_ip["10.42.50.7"]
    assert physical.mac_address == "44:61:32:01:02:03"
    assert physical.interface == "eth0.50"
    assert physical.vlan_id == "50"
    assert by_ip["10.42.60.8"].mac_address == "bc:24:11:00:00:08"

    wrapped = RouterTableParsers.parse_snmp_arp(
        {"oids": SNMP_OIDS}, router_id="snmp-core", observed_at=OBSERVED
    )
    assert wrapped == records
    from_json = RouterTableParsers.parse_snmp_arp(
        json.dumps({"oids": SNMP_OIDS}), router_id="snmp-core", observed_at=OBSERVED
    )
    assert from_json == records
    assert RouterTableParsers.parse_snmp_arp("") == []


def test_parse_snmp_arp_oid_walk_order_independent() -> None:
    net_first = {
        "1.3.6.1.2.1.4.22.1.3.5.10.42.10.25": "IpAddress: 10.42.10.25",
        "1.3.6.1.2.1.4.22.1.2.5.10.42.10.25": "Hex-STRING: 00 04 96 AA BB CC",
        "1.3.6.1.2.1.4.22.1.4.5.10.42.10.25": "INTEGER: dynamic(3)",
        "1.3.6.1.2.1.4.22.1.3.6.10.42.20.40": "10.42.20.40",
        "1.3.6.1.2.1.4.35.1.4.6.1.4.10.42.20.40": "00:c0:b7:01:02:03",
    }
    records = RouterTableParsers.parse_snmp_arp(net_first)
    assert [(r.ip, r.mac_address, r.state) for r in records] == [
        ("10.42.10.25", "00:04:96:aa:bb:cc", "DYNAMIC"),
        ("10.42.20.40", "00:c0:b7:01:02:03", "REACHABLE"),
    ]
    reversed_oids = dict(reversed(list(net_first.items())))
    assert RouterTableParsers.parse_snmp_arp(reversed_oids) == records


def test_parse_snmp_arp_record_lists() -> None:
    rows = [
        {"ip": "10.42.10.25", "mac_address": "00-04-96-aa-bb-cc", "interface": "eth1.10"},
        {
            "ipNetToMediaNetAddress": "10.42.20.40",
            "ipNetToMediaPhysAddress": "00 c0 b7 01 02 03",
            "ifIndex": 13,
            "ipNetToMediaType": 4,
        },
        {"ip": "10.42.30.9", "mac": "bc:24:11:00:00:09", "vlan_id": 300, "state": "stale"},
        {"ip": "not-an-ip", "mac": "bc:24:11:00:00:10"},
        "skip-me",
    ]
    records = RouterTableParsers.parse_snmp_arp(rows, router_id="snmp-rows")
    assert [r.ip for r in records] == ["10.42.10.25", "10.42.20.40", "10.42.30.9"]
    assert records[0].mac_address == "00:04:96:aa:bb:cc"
    assert records[0].vlan_id == "10"
    assert records[0].state == "REACHABLE"
    assert records[1].interface == "13"
    assert records[1].state == "STATIC"
    assert records[1].vlan_id == "20"
    assert records[2].vlan_id == "300"
    assert records[2].state == "STALE"
    assert {r.router_id for r in records} == {"snmp-rows"}

    assert RouterTableParsers.parse_snmp_arp(json.dumps(rows[:1]))[0].ip == "10.42.10.25"


# --------------------------------------------------------------------------- DHCP parsers


DNSMASQ_LEASES = """\
# dnsmasq lease database
1794495600 bc:24:11:00:11:22 10.42.20.50 pve-node-01 01:bc:24:11:00:11:22
0 44:61:32:01:02:03 10.42.50.7 * *
1794495600 00:c0:b7:aa:bb:cc 10.42.10.25 ups-closet-a *
duid 00:01:00:01:2a:3b:4c:5d:00:11:22:33:44:55
1794495600 1234 2001:db8::5 v6-host 00:01:00:01
"""


def test_parse_dnsmasq_leases() -> None:
    leases = RouterTableParsers.parse_dnsmasq_leases(DNSMASQ_LEASES, subnet_id="lan")
    assert [lease.ip for lease in leases] == ["10.42.20.50", "10.42.50.7", "10.42.10.25"]
    first, infinite, ups = leases
    assert first.mac_address == "bc:24:11:00:11:22"
    assert first.hostname == "pve-node-01"
    assert first.client_id == "01:bc:24:11:00:11:22"
    assert first.lease_expires_at == datetime.fromtimestamp(1794495600, tz=timezone.utc)
    assert first.subnet_id == "lan"
    assert infinite.lease_expires_at is None
    assert infinite.hostname is None
    assert infinite.client_id is None
    assert ups.hostname == "ups-closet-a"
    assert RouterTableParsers.parse_dhcp_leases(DNSMASQ_LEASES, subnet_id="lan") == leases


KEA_RESPONSE = {
    "result": 0,
    "text": "2 IPv4 lease(s) found.",
    "arguments": {
        "leases": [
            {
                "ip-address": "10.42.10.30",
                "hw-address": "bc:24:11:00:00:30",
                "hostname": "pve-node-02",
                "cltt": 1794492000,
                "valid-lft": 3600,
                "subnet-id": 10,
                "client-id": "01:bc:24:11:00:00:30",
            },
            {
                "ip-address": "10.42.10.31",
                "hw-address": "bc:24:11:00:00:31",
                "hostname": "",
                "cltt": 1794492000,
                "valid-lft": 4294967295,
                "subnet-id": 10,
            },
        ]
    },
}


def test_parse_json_dhcp_leases_kea_isc_and_generic() -> None:
    kea = RouterTableParsers.parse_json_dhcp_leases(KEA_RESPONSE)
    assert [lease.ip for lease in kea] == ["10.42.10.30", "10.42.10.31"]
    assert kea[0].mac_address == "bc:24:11:00:00:30"
    assert kea[0].hostname == "pve-node-02"
    assert kea[0].lease_expires_at == datetime.fromtimestamp(
        1794495600, tz=timezone.utc
    )
    assert kea[0].subnet_id == "10"
    assert kea[0].client_id == "01:bc:24:11:00:00:30"
    assert kea[1].hostname is None
    assert kea[1].lease_expires_at is None

    # Kea API responses arrive wrapped in a list
    assert RouterTableParsers.parse_json_dhcp_leases(json.dumps([KEA_RESPONSE])) == kea

    isc_json = {
        "leases": [
            {
                "ip_address": "10.42.20.60",
                "hardware": "ethernet 00:c0:b7:00:00:60",
                "client-hostname": "ups-rack-2",
                "ends": "2026/11/12 15:00:00",
            }
        ]
    }
    isc = RouterTableParsers.parse_json_dhcp_leases(isc_json, subnet_id="sub-20")
    assert isc[0].mac_address == "00:c0:b7:00:00:60"
    assert isc[0].hostname == "ups-rack-2"
    assert isc[0].lease_expires_at == OBSERVED
    assert isc[0].subnet_id == "sub-20"

    generic_list = [
        {"ip": "10.42.30.5", "mac": "00:04:96:00:00:05", "fqdn": "sw-30.example.net",
         "expires_at": "2026-11-12T15:00:00Z"},
        {"ip": "bogus", "mac": "00:04:96:00:00:06"},
    ]
    generic = RouterTableParsers.parse_json_dhcp_leases(generic_list)
    assert [lease.ip for lease in generic] == ["10.42.30.5"]
    assert generic[0].hostname == "sw-30.example.net"
    assert generic[0].lease_expires_at == OBSERVED

    ip_keyed = {
        "10.42.40.20": {"mac_address": "aa:bb:cc:dd:ee:20", "hostname": "desk-20",
                        "lease_expires_at": 0},
        "metadata": {"exported": "today"},
    }
    keyed = RouterTableParsers.parse_json_dhcp_leases(json.dumps(ip_keyed))
    assert len(keyed) == 1
    assert keyed[0].ip == "10.42.40.20"
    assert keyed[0].hostname == "desk-20"
    assert keyed[0].lease_expires_at is None

    assert RouterTableParsers.parse_dhcp_leases(KEA_RESPONSE) == kea
    assert RouterTableParsers.parse_dhcp_leases(json.dumps(KEA_RESPONSE)) == kea


ISC_DHCPD_LEASES = """\
# The format of this file is documented in the dhcpd.leases(5) manual page.
authoring-byte-order little-endian;

lease 10.42.50.77 {
  starts 4 2026/11/12 14:00:00;
  ends 4 2026/11/12 15:00:00;
  cltt 4 2026/11/12 14:00:00;
  binding state active;
  next binding state free;
  hardware ethernet 44:61:32:00:00:77;
  uid "\\001Da2\\000\\000w";
  client-hostname "ecobee-hall";
}
lease 10.42.50.78 {
  starts 4 2026/11/12 14:00:00;
  ends never;
  hardware ethernet 00:11:22:33:44:78;
}
"""


def test_parse_isc_dhcpd_leases_text() -> None:
    leases = RouterTableParsers.parse_isc_dhcpd_leases(ISC_DHCPD_LEASES, subnet_id="s50")
    assert [lease.ip for lease in leases] == ["10.42.50.77", "10.42.50.78"]
    assert leases[0].mac_address == "44:61:32:00:00:77"
    assert leases[0].hostname == "ecobee-hall"
    assert leases[0].lease_expires_at == OBSERVED
    assert leases[0].client_id is not None
    assert leases[0].subnet_id == "s50"
    assert leases[1].lease_expires_at is None
    assert leases[1].hostname is None
    assert RouterTableParsers.parse_dhcp_leases(ISC_DHCPD_LEASES, subnet_id="s50") == leases


CSV_LEASES = """\
IP_Address,MAC,Hostname,Expire,Subnet_ID,Client-ID
10.42.10.25,00-C0-B7-AA-BB-CC,ups-closet-a,1794495600,10,
10.42.20.50,bc24.1100.1122,*,0,20,01:bc:24:11:00:11:22
not-an-ip,00:11:22:33:44:55,bad,0,20,
"""

KEA_CSV_LEASES = """\
address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context
10.42.30.12,00:04:96:00:30:12,,3600,1794495600,30,0,0,sw-access-30,0,
"""


def test_parse_csv_dhcp_leases_exports() -> None:
    leases = RouterTableParsers.parse_csv_dhcp_leases(CSV_LEASES, subnet_id="fallback")
    assert [lease.ip for lease in leases] == ["10.42.10.25", "10.42.20.50"]
    assert leases[0].mac_address == "00:c0:b7:aa:bb:cc"
    assert leases[0].hostname == "ups-closet-a"
    assert leases[0].lease_expires_at == datetime.fromtimestamp(
        1794495600, tz=timezone.utc
    )
    assert leases[0].subnet_id == "10"
    assert leases[0].client_id is None
    assert leases[1].mac_address == "bc:24:11:00:11:22"
    assert leases[1].hostname is None
    assert leases[1].lease_expires_at is None
    assert leases[1].client_id == "01:bc:24:11:00:11:22"
    assert RouterTableParsers.parse_dhcp_leases(CSV_LEASES, subnet_id="fallback") == leases

    kea = RouterTableParsers.parse_dhcp_leases(KEA_CSV_LEASES)
    assert len(kea) == 1
    assert kea[0].ip == "10.42.30.12"
    assert kea[0].mac_address == "00:04:96:00:30:12"
    assert kea[0].hostname == "sw-access-30"
    assert kea[0].subnet_id == "30"


def test_parse_dhcp_leases_empty_inputs() -> None:
    assert RouterTableParsers.parse_dhcp_leases("") == []
    assert RouterTableParsers.parse_dhcp_leases("   \n") == []
    assert RouterTableParsers.parse_dhcp_leases([]) == []
    assert RouterTableParsers.parse_dhcp_leases({}) == []


# --------------------------------------------------------------------------- collector


def test_collector_indexes_and_prefers_best_records() -> None:
    older = datetime(2026, 11, 12, 14, 0, tzinfo=timezone.utc)
    collector = RouterArpDhcpCollector(
        arp_records=[
            RouterArpRecord(ip="10.42.10.25", state="INCOMPLETE"),
            RouterArpRecord(ip="10.42.10.25", mac_address="00:04:96:00:00:01", state="STALE"),
            RouterArpRecord(
                ip="10.42.10.25",
                mac_address="00:04:96:00:00:02",
                state="REACHABLE",
                observed_at=older,
            ),
            {"ip": "10.42.10.25", "mac_address": "00:04:96:00:00:03",
             "state": "DYNAMIC", "observed_at": OBSERVED.isoformat()},
            {"ip": "10.42.10.26", "mac_address": "00:04:96:00:00:26", "state": "FAILED"},
        ],
        dhcp_leases=[
            DhcpLeaseRecord(ip="10.42.10.25", hostname=None, lease_expires_at=OBSERVED),
            DhcpLeaseRecord(ip="10.42.10.25", hostname="old-name", lease_expires_at=older),
            {"ip": "10.42.10.25", "hostname": "new-name",
             "lease_expires_at": OBSERVED.isoformat()},
        ],
        observed_at="2026-11-12T15:00:00+00:00",
    )
    assert collector.observed_at == OBSERVED
    assert collector.arp_by_ip["10.42.10.25"].mac_address == "00:04:96:00:00:03"
    assert collector.arp_by_ip["10.42.10.26"].state == "FAILED"
    assert collector.leases_by_ip["10.42.10.25"].hostname == "new-name"

    # An infinite lease (no expiry) is the latest, so it beats a finite one
    collector.add_dhcp_leases(
        [
            DhcpLeaseRecord(ip="10.42.10.50", hostname="a", lease_expires_at=1700000000),
            DhcpLeaseRecord(ip="10.42.10.50", hostname="b", lease_expires_at="infinite"),
            DhcpLeaseRecord(ip="10.42.10.50", hostname="c", lease_expires_at=1800000000),
        ]
    )
    assert collector.leases_by_ip["10.42.10.50"].hostname == "b"

    # A worse record added later does not replace the indexed one
    collector.add_arp_records([RouterArpRecord(ip="10.42.10.25", state="FAILED")])
    assert collector.arp_by_ip["10.42.10.25"].mac_address == "00:04:96:00:00:03"

    with pytest.raises(ValueError):
        RouterArpDhcpCollector(gateway_octets=())


def _routed_hosts() -> list[DiscoveredHost]:
    return [
        DiscoveredHost(
            ip="10.42.40.1", subnet_cidr="10.42.40.0/24", vlan_id="40",
            icmp_reachable=True, mac_address="00:04:96:40:00:01",
            arp_state="REACHABLE", inferred_role="switch",
        ),
        DiscoveredHost(
            ip="10.42.40.20", subnet_cidr="10.42.40.0/24", vlan_id="40",
            icmp_reachable=True, mac_address="aa:bb:cc:dd:ee:20", arp_state="REACHABLE",
        ),
        DiscoveredHost(
            ip="10.42.10.1", subnet_cidr="10.42.10.0/24", vlan_id="10",
            icmp_reachable=True, inferred_role="router",
        ),
        DiscoveredHost(
            ip="10.42.10.25", subnet_cidr="10.42.10.0/24", vlan_id="10",
            icmp_reachable=True,
        ),
        DiscoveredHost(
            ip="10.42.10.30", subnet_cidr="10.42.10.0/24", vlan_id="10",
            icmp_reachable=True, open_tcp_ports=[22], inferred_role="server",
        ),
        DiscoveredHost(
            ip="10.42.30.1", subnet_cidr="10.42.30.0/24", vlan_id="30",
            icmp_reachable=True, inferred_role="router",
        ),
        DiscoveredHost(
            ip="10.42.50.77", subnet_cidr="10.42.50.0/24", vlan_id="50",
            icmp_reachable=True,
        ),
    ]


ROUTER_EXOS = """\
VR-Default  10.42.10.25  00:c0:b7:aa:bb:cc  5  NO  VLAN_0010  10  1:5
VR-Default  10.42.10.30  bc:24:11:00:00:30  2  NO  VLAN_0010  10  1:6
VR-Default  10.42.30.1   00:04:96:30:00:01  0  YES Mgmt30     30  1:1
VR-Default  10.42.40.20  aa:bb:cc:dd:ee:99  1  NO  Data       40  1:9
"""

ROUTER_NEIGH = """\
10.42.50.77 dev eth1.50 lladdr 44:61:32:00:00:77 STALE
10.42.50.88 dev eth1.50 lladdr 00:11:22:33:44:88 REACHABLE
"""

ROUTER_LEASES = """\
1794495600 bc:24:11:00:00:30 10.42.10.30 pve-node-02 *
1794495600 00:04:96:30:00:01 10.42.30.1 core-rtr-30 *
1794495600 44:61:32:00:00:77 10.42.50.77 ecobee-hall *
1794495600 00:11:22:33:44:88 10.42.50.88 printer-50 *
1794495600 00:11:22:33:44:99 10.42.50.99 laptop-99 *
"""


def _router_collector() -> RouterArpDhcpCollector:
    arp = RouterTableParsers.parse_cli_arp(ROUTER_EXOS, router_id="core-rtr-01")
    arp += RouterTableParsers.parse_cli_arp(ROUTER_NEIGH, observed_at=OBSERVED)
    leases = RouterTableParsers.parse_dhcp_leases(ROUTER_LEASES)
    return RouterArpDhcpCollector(arp, leases, observed_at=OBSERVED)


def test_collector_enrich_hosts_backfills_cross_vlan_fields() -> None:
    hosts = _routed_hosts()
    collector = _router_collector()
    enriched = collector.enrich_hosts(hosts)
    assert enriched[3] is hosts[3]
    by_ip = {h.ip: h for h in enriched}

    ups = by_ip["10.42.10.25"]
    assert ups.mac_address == "00:c0:b7:aa:bb:cc"
    assert ups.arp_state == "DYNAMIC"
    assert ups.hostname is None
    assert ups.inferred_role == "ups"

    pve = by_ip["10.42.10.30"]
    assert pve.mac_address == "bc:24:11:00:00:30"
    assert pve.hostname == "pve-node-02"
    assert pve.inferred_role == "hypervisor"

    router = by_ip["10.42.30.1"]
    assert router.mac_address == "00:04:96:30:00:01"
    assert router.arp_state == "STATIC"
    assert router.hostname == "core-rtr-30"
    assert router.inferred_role == "switch"

    iot = by_ip["10.42.50.77"]
    assert iot.mac_address == "44:61:32:00:00:77"
    assert iot.arp_state == "STALE"
    assert iot.hostname == "ecobee-hall"
    assert iot.inferred_role == "iot_device"

    # Local VLAN host keeps its kernel ARP MAC without overwrite
    local = by_ip["10.42.40.20"]
    assert local.mac_address == "aa:bb:cc:dd:ee:20"
    assert local.arp_state == "REACHABLE"

    # Hosts without router data are untouched
    assert by_ip["10.42.10.1"].mac_address is None
    assert by_ip["10.42.10.1"].inferred_role == "router"


def test_collector_enrich_hosts_dhcp_mac_fallback_mappings_and_overwrite() -> None:
    collector = RouterArpDhcpCollector(
        dhcp_leases=[{"ip": "10.42.20.5", "mac_address": "00:c0:b7:00:20:05",
                      "hostname": "ups-20"}],
    )
    enriched = collector.enrich_hosts(
        [{"ip": "10.42.20.5", "subnet_cidr": "10.42.20.0/24", "vlan_id": "20"}]
    )
    assert isinstance(enriched[0], DiscoveredHost)
    assert enriched[0].mac_address == "00:c0:b7:00:20:05"
    assert enriched[0].arp_state == "REACHABLE"
    assert enriched[0].hostname == "ups-20"
    assert enriched[0].inferred_role == "ups"

    local = DiscoveredHost(
        ip="10.42.40.20", subnet_cidr="10.42.40.0/24", vlan_id="40",
        mac_address="aa:bb:cc:dd:ee:20", arp_state="REACHABLE", hostname="old",
    )
    collector.enrich_hosts(
        [local],
        arp_records=[RouterArpRecord(ip="10.42.40.20", mac_address="00:04:96:00:40:20",
                                     state="STALE")],
        dhcp_leases=[DhcpLeaseRecord(ip="10.42.40.20", hostname="sw-desk")],
        overwrite=True,
    )
    assert local.mac_address == "00:04:96:00:40:20"
    assert local.arp_state == "STALE"
    assert local.hostname == "sw-desk"
    assert local.inferred_role == "switch"


def _scanner_site() -> Site:
    scanner = SubnetDiscoveryScanner(DiscoveryConfig(cidr="10.42.0.0/16"))
    site = scanner.build_site_snapshot(
        _routed_hosts(), site_id="site-42", site_name="Site 42", observed_at=OBSERVED
    )
    # SoT-style record with no assigned object for a DHCP-only printer
    site.ip_addresses.append(IPAddress(ip="10.42.50.88", subnet_id="site-42-sub-50"))
    return site


def test_collector_enrich_site_multi_vlan_scanner_snapshot() -> None:
    site = _scanner_site()
    ip_recs = {rec.ip: rec for rec in site.ip_addresses}
    assert ip_recs["10.42.10.25"].arp_mac is None
    assert ip_recs["10.42.10.25"].arp_entry is None

    later = datetime(2026, 11, 12, 16, 0, tzinfo=timezone.utc)
    result = _router_collector().enrich_site(site, observed_at=later)
    assert result is site

    equipment = {eq.equipment_id: eq for eq in site.equipment}
    devices = {dev.device_id: dev for dev in site.devices}

    # VLAN 10 UPS: router ARP only, router_id from EXOS output
    ups_ip = ip_recs["10.42.10.25"]
    assert ups_ip.arp_mac == "00:c0:b7:aa:bb:cc"
    assert ups_ip.arp_last_seen == later
    assert ups_ip.arp_source_device_id == "core-rtr-01"
    assert ups_ip.arp_entry is not None
    assert ups_ip.arp_entry.arp_mac == "00:c0:b7:aa:bb:cc"
    assert ups_ip.arp_entry.arp_last_seen == later
    assert ups_ip.arp_entry.arp_source_device_id == "core-rtr-01"
    assert ups_ip.arp_entry.subnet_id == "site-42-sub-10"
    ups_eq = equipment["site-42-eq-10-42-10-25"]
    assert ups_eq.category is EquipmentCategory.UPS
    assert ups_eq.name == "host-10-42-10-25"

    # VLAN 10 hypervisor: DHCP hostname replaces the synthetic name
    pve_ip = ip_recs["10.42.10.30"]
    assert pve_ip.arp_mac == "bc:24:11:00:00:30"
    assert pve_ip.assigned_object_id == "site-42-eq-10-42-10-30"
    pve_eq = equipment["site-42-eq-10-42-10-30"]
    assert pve_eq.name == "pve-node-02"
    assert pve_eq.category is EquipmentCategory.SERVER
    rtr10 = devices["site-42-dev-10-42-10-1"]
    pve_ports = [p for p in rtr10.ports if p.connected_device_id == pve_eq.equipment_id]
    assert pve_ports and all(p.connected_mac == "bc:24:11:00:00:30" for p in pve_ports)

    # VLAN 30 router: hostname, vendor and mgmt0 port backfilled
    rtr30 = devices["site-42-dev-10-42-30-1"]
    assert rtr30.hostname == "core-rtr-30"
    assert rtr30.vendor == "Extreme Networks"
    mgmt = next(p for p in rtr30.ports if p.name == "mgmt0")
    assert mgmt.connected_mac == "00:04:96:30:00:01"
    assert ip_recs["10.42.30.1"].arp_mac == "00:04:96:30:00:01"

    # VLAN 50 IoT host: ip neigh record without router_id -> subnet gateway device
    iot_ip = ip_recs["10.42.50.77"]
    assert iot_ip.arp_mac == "44:61:32:00:00:77"
    assert iot_ip.arp_last_seen == OBSERVED
    assert iot_ip.arp_source_device_id == "site-42-dev-10-42-50-1"
    assert iot_ip.arp_entry is not None
    assert iot_ip.arp_entry.arp_source_device_id == "site-42-dev-10-42-50-1"
    assert equipment["site-42-eq-10-42-50-77"].name == "ecobee-hall"

    # Unassigned IP picks up the DHCP hostname as its assigned object
    printer_ip = ip_recs["10.42.50.88"]
    assert printer_ip.assigned_object_id == "printer-50"
    assert printer_ip.assigned_object_type == "Equipment"
    assert printer_ip.arp_mac == "00:11:22:33:44:88"

    # Local VLAN record keeps its kernel ARP data without overwrite
    local_ip = ip_recs["10.42.40.20"]
    assert local_ip.arp_mac == "aa:bb:cc:dd:ee:20"
    assert local_ip.arp_last_seen == OBSERVED

    # Leases for IPs not in the snapshot do not create records
    assert "10.42.50.99" not in {rec.ip for rec in site.ip_addresses}


def test_collector_enrich_site_overwrite_and_unlinked_matches() -> None:
    site = Site(
        site_id="s1",
        name="S1",
        devices=[
            NetworkDevice(
                device_id="dev-a", site_id="s1", hostname="real-core",
                management_ip="10.42.20.1", role="router",
                ports=[
                    Port(port_id="dev-a-p1", device_id="dev-a", name="eth1",
                         connected_device_id="eq-nas", connected_mac="11:11:11:11:11:11"),
                ],
            ),
        ],
        equipment=[
            Equipment(equipment_id="eq-nas", site_id="s1", name="Finance NAS",
                      assigned_ips=["10.42.20.40"]),
        ],
        ip_addresses=[
            IPAddress(ip="10.42.20.40", subnet_id="sub-20",
                      arp_mac="11:11:11:11:11:11"),
        ],
    )
    collector = RouterArpDhcpCollector(
        arp_records=[RouterArpRecord(ip="10.42.20.40", mac_address="00:11:32:aa:bb:cc",
                                     observed_at=OBSERVED)],
        dhcp_leases=[DhcpLeaseRecord(ip="10.42.20.40", hostname="synology-fin")],
    )

    collector.enrich_site(site)
    ip_rec = site.ip_addresses[0]
    # Unlinked IP is linked to the equipment carrying it in assigned_ips
    assert ip_rec.assigned_object_id == "eq-nas"
    assert ip_rec.assigned_object_type == "Equipment"
    # Existing ARP MAC and real equipment name are kept without overwrite
    assert ip_rec.arp_mac == "11:11:11:11:11:11"
    assert ip_rec.arp_entry is not None
    assert ip_rec.arp_entry.arp_mac == "11:11:11:11:11:11"
    assert ip_rec.arp_entry.arp_source_device_id == "dev-a"
    assert site.equipment[0].name == "Finance NAS"
    assert site.equipment[0].category is EquipmentCategory.SAN
    assert site.devices[0].ports[0].connected_mac == "11:11:11:11:11:11"

    collector.enrich_site(site, overwrite=True)
    assert ip_rec.arp_mac == "00:11:32:aa:bb:cc"
    assert ip_rec.arp_last_seen == OBSERVED
    assert ip_rec.arp_source_device_id == "dev-a"
    assert ip_rec.arp_entry.arp_mac == "00:11:32:aa:bb:cc"
    assert site.equipment[0].name == "synology-fin"
    assert site.devices[0].ports[0].connected_mac == "00:11:32:aa:bb:cc"
    assert site.devices[0].hostname == "real-core"

    with pytest.raises(ValueError):
        collector.enrich_site("not-a-site")  # type: ignore[arg-type]
