"""Unit tests for the service banner and certificate fingerprinting engine."""

from __future__ import annotations

import asyncio
import random
import socket
import ssl

import pytest

from sot_validator.discovery import (
    HTTP_BANNER_PORTS,
    SSH_BANNER_PORTS,
    TLS_BANNER_PORTS,
    DeviceFingerprint,
    RawServiceBanner,
    ServiceBannerFingerprinter,
)
from sot_validator.discovery.fingerprinter import (
    _SIGNATURES,
    _parse_der_certificate,
    _parse_http_response,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    NetworkDevice,
    Port,
    Site,
)
from sot_validator.topology.device_types import DeviceTypeCatalog

# Self-signed EC test certificate: CN=pve01.lab.example, SAN DNS pve01.lab.example,
# DNS pve01, IP 10.42.1.10, DNS *.lab.example
TEST_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIB4jCCAYigAwIBAgIUCbsAauLZnCqieRjHG0OtnLQdOf0wCgYIKoZIzj0EAwIw
OTEbMBkGA1UECgwSU29UIFZhbGlkYXRvciBUZXN0MRowGAYDVQQDDBFwdmUwMS5s
YWIuZXhhbXBsZTAgFw0yNjExMTIxNTI2MzlaGA8yMTI2MTAxOTE1MjYzOVowOTEb
MBkGA1UECgwSU29UIFZhbGlkYXRvciBUZXN0MRowGAYDVQQDDBFwdmUwMS5sYWIu
ZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBnxVjbO80uFrhajQCe7
qeUBMKRhnYQjbQZphL/m+cTe09sq3Yh/tbaexEdgu/g8Nwhe/kEVkIShwHj9YoAv
34ejbDBqMB0GA1UdDgQWBBT73zhShYMT9XdAGOMl3H5MHh76fTAPBgNVHRMBAf8E
BTADAQH/MDgGA1UdEQQxMC+CEXB2ZTAxLmxhYi5leGFtcGxlggVwdmUwMYcECioB
CoINKi5sYWIuZXhhbXBsZTAKBggqhkjOPQQDAgNIADBFAiBDT7J2U2YtksahIkVD
IFEeHZpM1/bk23eo9o/Sluvh1QIhAOWylQFH947SuhnHFfAYp8f9XxIz9zYs7QoB
8PBoAPtB
-----END CERTIFICATE-----
"""


@pytest.fixture(autouse=True)
def no_outbound_connect(monkeypatch: pytest.MonkeyPatch):
    """Fail any test that attempts a real outbound socket connect."""
    attempts: list[tuple] = []

    def _blocked(self: socket.socket, *args, **kwargs):
        attempts.append(args)
        raise OSError("outbound connect blocked in fingerprinter tests")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    yield attempts
    assert attempts == [], f"unexpected outbound connect attempts: {attempts!r}"


def _fp(**banner_fields) -> DeviceFingerprint:
    banner_fields.setdefault("ip", "10.42.1.10")
    return ServiceBannerFingerprinter().fingerprint(RawServiceBanner(**banner_fields))


def test_port_constants() -> None:
    assert SSH_BANNER_PORTS == (22,)
    assert HTTP_BANNER_PORTS == (80, 5000, 8000, 8080, 8123, 9000)
    assert TLS_BANNER_PORTS == (443, 5001, 8006, 8443, 9443)


def test_raw_service_banner_sanitises_and_validates() -> None:
    banner = RawServiceBanner(
        ip=" 10.42.1.10 ",
        ssh_banner="SSH-2.0-OpenSSH_9.2\x00\x1b[31m" + "A" * 1000,
        http_titles=[
            "  Proxmox\tVirtual\r\nEnvironment ",
            "Proxmox Virtual Environment",
            "",
            "\x07",
        ],
        http_headers={
            "Server": " pve-api-daemon/3.0 ",
            "SERVER": "dup",
            "X-Empty": "  ",
        },
        tls_subject_cn="   ",
        tls_san_dns_names=["a.example", "a.example", "b.example"],
        mdns_name="ha.local\x00",
    )
    assert banner.ip == "10.42.1.10"
    assert banner.ssh_banner is not None
    assert len(banner.ssh_banner) <= 256
    assert banner.ssh_banner.startswith("SSH-2.0-OpenSSH_9.2[31mAAA")
    assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in banner.ssh_banner)
    assert banner.http_titles == ["Proxmox Virtual Environment"]
    assert banner.http_headers == {"server": "pve-api-daemon/3.0"}
    assert banner.tls_subject_cn is None
    assert banner.tls_san_dns_names == ["a.example", "b.example"]
    assert banner.mdns_name == "ha.local"

    capped = RawServiceBanner(
        ip="10.42.1.10",
        http_titles=[f"title-{i}" for i in range(40)],
        http_headers={f"X-H{i}": "v" for i in range(40)},
        tls_san_dns_names=[f"h{i}.example" for i in range(40)],
    )
    assert len(capped.http_titles) == 16
    assert len(capped.http_headers) == 32
    assert len(capped.tls_san_dns_names) == 32
    assert capped.http_titles[0] == "title-0"

    with pytest.raises(ValueError):
        RawServiceBanner(ip="not-an-ip")
    with pytest.raises(ValueError):
        RawServiceBanner(ip="10.42.1.10", ssh_banner=b"SSH-2.0")
    with pytest.raises(ValueError):
        RawServiceBanner(ip="10.42.1.10", http_titles="Proxmox")
    with pytest.raises(ValueError):
        RawServiceBanner(ip="10.42.1.10", http_headers=[("Server", "x")])


def test_dataclass_round_trips() -> None:
    banner = RawServiceBanner(
        ip="10.42.1.10",
        ssh_banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        http_titles=["Proxmox Virtual Environment"],
        http_headers={"server": "pve-api-daemon/3.0"},
        tls_subject_cn="pve01.lab.example",
        tls_san_dns_names=["pve01.lab.example", "pve01"],
        snmp_sys_descr="Linux pve01",
        snmp_sys_name="pve01",
        mdns_name="pve01.local",
    )
    assert RawServiceBanner.from_dict(banner.to_dict()) == banner
    assert RawServiceBanner.from_dict(banner.to_dict()).to_dict() == banner.to_dict()

    fp = ServiceBannerFingerprinter().fingerprint(banner)
    assert DeviceFingerprint.from_dict(fp.to_dict()) == fp
    assert DeviceFingerprint.from_dict(fp.to_dict()).to_dict() == fp.to_dict()


def test_ssh_generic_signatures() -> None:
    fp = _fp(ssh_banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    assert fp.os_family == "Ubuntu"
    assert fp.inferred_role == "server"
    assert fp.vendor is None
    assert fp.recommended_template_id is None
    assert fp.matched_signatures == ["ubuntu"]
    assert 0.0 < fp.confidence <= 0.4

    dropbear = _fp(ssh_banner="SSH-2.0-dropbear_2022.83")
    assert dropbear.matched_signatures == ["dropbear"]
    assert dropbear.os_family == "Embedded Linux"
    assert dropbear.inferred_role == "host"
    assert 0.0 < dropbear.confidence <= 0.4


def test_generic_signatures_ignore_http_tls_sysname_and_mdns() -> None:
    fp = _fp(
        http_titles=["Debian Apache2 Default Page"],
        tls_subject_cn="ubuntu-build01.lab.example",
        snmp_sys_name="debian-build01",
        mdns_name="ups-room2.local",
    )
    assert fp.matched_signatures == []
    assert fp.confidence == 0.0
    # sysName and mDNS never drive appliance identification either
    assert _fp(snmp_sys_name="synology-nas", mdns_name="proxmox.local").vendor is None


def test_proxmox_http_title_and_header() -> None:
    for fields in (
        {"http_titles": ["Proxmox Virtual Environment"]},
        {"http_headers": {"Server": "pve-api-daemon/3.0"}},
    ):
        fp = _fp(**fields)
        assert fp.vendor == "Proxmox"
        assert fp.inferred_role == "hypervisor"
        assert fp.recommended_template_id == "proxmox-ve-host"
        assert fp.os_family == "Proxmox VE"
        assert fp.confidence >= 0.6
        assert fp.matched_signatures == ["proxmox-ve"]


@pytest.mark.parametrize(
    ("fields", "signature", "role"),
    [
        ({"http_titles": ["Home Assistant"]}, "home-assistant", "automation_hub"),
        ({"http_titles": ["Portainer"]}, "portainer", "server"),
        ({"http_titles": ["Pi-hole Admin Console"]}, "pihole", "dns_server"),
        ({"http_titles": ["AdGuard Home"]}, "adguard", "dns_server"),
        ({"http_titles": ["UniFi OS"]}, "unifi-os", "router"),
        ({"http_titles": ["Synology DiskStation"]}, "synology", "nas_storage"),
        ({"http_headers": {"X-Powered-By": "TrueNAS"}}, "truenas", "nas_storage"),
        ({"http_titles": ["EdgeOS"]}, "edgeos", "router"),
        ({"ssh_banner": "SSH-2.0-OpenSSH_9.6 CachyOS"}, "cachyos", "server"),
        ({"snmp_sys_descr": "ISC BIND 9.18.24"}, "bind", "dns_server"),
        ({"http_headers": {"Server": "Samba 4.19"}}, "samba", "nas_storage"),
    ],
)
def test_appliance_signatures_match_expected_role(
    fields: dict, signature: str, role: str
) -> None:
    fp = _fp(**fields)
    assert fp.matched_signatures[0] == signature
    assert fp.inferred_role == role


def test_snmp_extreme_apc_and_bind_word_boundary() -> None:
    exos = _fp(snmp_sys_descr="ExtremeXOS (X460G2-48p-10G4) version 31.7.1.4")
    assert exos.vendor == "Extreme Networks"
    assert exos.model == "X460G2-48p-10G4"
    assert exos.recommended_template_id == "extreme-exos-48p"
    assert exos.inferred_role == "switch"
    assert exos.os_family == "ExtremeXOS"
    assert exos.matched_signatures == ["extreme-exos"]

    voss = _fp(snmp_sys_descr="VSP-4900-48P (8.10.0.0)")
    assert voss.matched_signatures == ["extreme-voss"]
    assert voss.recommended_template_id == "extreme-voss-core"
    assert voss.inferred_role == "switch"
    assert voss.model is None

    apc = _fp(snmp_sys_descr="APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2)")
    assert apc.vendor == "APC"
    assert apc.inferred_role == "ups"
    assert apc.recommended_template_id == "apc-smart-ups"

    binding = _fp(http_titles=["Port Binding Status"])
    assert "bind" not in binding.matched_signatures
    assert binding.matched_signatures == []


def test_precedence_and_determinism() -> None:
    banner = RawServiceBanner(
        ip="10.42.1.10",
        ssh_banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        http_titles=["Proxmox Virtual Environment"],
    )
    fingerprinter = ServiceBannerFingerprinter()
    first = fingerprinter.fingerprint(banner)
    assert first.matched_signatures == ["proxmox-ve", "debian"]
    assert first.vendor == "Proxmox"
    assert first.recommended_template_id == "proxmox-ve-host"
    assert first.os_family == "Proxmox VE"
    assert fingerprinter.fingerprint(banner).to_dict() == first.to_dict()

    # A winner without an os_family borrows it from the first generic match
    hass = _fp(http_titles=["Home Assistant"], ssh_banner="SSH-2.0-dropbear_2022.83")
    assert hass.matched_signatures == ["home-assistant", "dropbear"]
    assert hass.os_family == "Embedded Linux"
    assert hass.vendor == "Home Assistant"


def test_confidence_grows_with_distinct_source_fields() -> None:
    http_only = _fp(http_titles=["Proxmox Virtual Environment"])
    http_and_tls = _fp(
        http_titles=["Proxmox Virtual Environment"],
        tls_subject_cn="Proxmox Virtual Environment",
    )
    three = _fp(
        http_titles=["Proxmox Virtual Environment"],
        http_headers={"Server": "pve-api-daemon/3.0"},
        tls_subject_cn="Proxmox Virtual Environment",
        snmp_sys_descr="pve-manager/8.2.4",
    )
    assert 0.6 <= http_only.confidence <= http_and_tls.confidence <= three.confidence
    assert three.confidence <= 1.0
    assert http_only.confidence < three.confidence

    ssh_only = _fp(ssh_banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    ssh_and_snmp = _fp(
        ssh_banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
        snmp_sys_descr="Linux host 6.8.0-generic Ubuntu",
    )
    assert 0.0 < ssh_only.confidence <= ssh_and_snmp.confidence <= 0.4


def test_signature_templates_resolve_and_fingerprint_validation() -> None:
    catalog = DeviceTypeCatalog()
    names = [sig.name for sig in _SIGNATURES]
    assert names[:3] == ["extreme-exos", "extreme-voss", "apc"]
    assert len(_SIGNATURES) >= 18
    for sig in _SIGNATURES:
        if sig.template_id is not None:
            catalog.get(sig.template_id)

    with pytest.raises(ValueError):
        DeviceFingerprint(ip="10.0.0.1", recommended_template_id="no-such-template")
    with pytest.raises(ValueError):
        DeviceFingerprint(ip="10.0.0.1", confidence=1.5)
    with pytest.raises(ValueError):
        DeviceFingerprint(ip="10.0.0.1", confidence=True)
    with pytest.raises(ValueError):
        DeviceFingerprint(ip="10.0.0.1", confidence="0.5")
    with pytest.raises(ValueError):
        DeviceFingerprint(ip="10.0.0.1", inferred_role="l3_switch")
    with pytest.raises(ValueError):
        DeviceFingerprint(ip="300.0.0.1")
    ok = DeviceFingerprint(ip="10.0.0.1", recommended_template_id="proxmox-ve-host")
    assert ok.inferred_role == "host"
    assert ok.confidence == 0.0


def test_no_match_returns_empty_fingerprint() -> None:
    fp = ServiceBannerFingerprinter().fingerprint(
        RawServiceBanner(ip="10.42.1.99", http_titles=["Welcome"])
    )
    assert fp.ip == "10.42.1.99"
    assert fp.vendor is None
    assert fp.model is None
    assert fp.os_family is None
    assert fp.recommended_template_id is None
    assert fp.inferred_role == "host"
    assert fp.confidence == 0.0
    assert fp.matched_signatures == []

    bare = ServiceBannerFingerprinter().fingerprint(
        RawServiceBanner(ip="10.42.1.98", mdns_name="kiosk.local")
    )
    assert bare.matched_signatures == []
    assert bare.discovered_hostname == "kiosk.local"


def test_hostname_extraction() -> None:
    assert (
        _fp(
            tls_san_dns_names=["*.corp.local", "10.42.1.10", "pve01.corp.local"],
            tls_subject_cn="other.corp.local",
        ).discovered_hostname
        == "pve01.corp.local"
    )
    assert (
        _fp(
            tls_san_dns_names=[],
            tls_subject_cn="localhost",
            snmp_sys_name="SW-CORE-01.",
        ).discovered_hostname
        == "sw-core-01"
    )
    assert (
        _fp(tls_subject_cn="bad_host!name", mdns_name="ha.local").discovered_hostname
        == "ha.local"
    )
    assert (
        _fp(
            tls_san_dns_names=["*.corp.local", "::1", "-bad-.corp.local"],
            tls_subject_cn="localhost.localdomain",
            snmp_sys_name="a" * 64,
            mdns_name=".".join(["abcdefghi"] * 26),
        ).discovered_hostname
        is None
    )
    assert _fp().discovered_hostname is None


def test_der_reader_extracts_cn_and_san_dns_names() -> None:
    der = ssl.PEM_cert_to_DER_cert(TEST_CERT_PEM)
    cn, sans = _parse_der_certificate(der)
    assert cn == "pve01.lab.example"
    assert sans == ["pve01.lab.example", "pve01", "*.lab.example"]

    rng = random.Random(64)
    blobs = [
        b"\x30\x82garbage",
        b"",
        rng.randbytes(20 * 1024),
        der[:-10],
        der + b"\x00",
        b"\x30\x80" + der,
    ]
    blobs.extend(b"\x30\x82" + rng.randbytes(rng.randint(0, 2048)) for _ in range(200))
    for blob in blobs:
        assert _parse_der_certificate(blob) == (None, [])
    assert _parse_der_certificate("not-bytes") == (None, [])


def test_parse_http_response_extracts_headers_and_title() -> None:
    head = (
        b"HTTP/1.1 200 OK\r\nServer: pve-api-daemon/3.0\r\nserver: dup\r\n"
        b"Content-Type: text/html\r\n\r\n"
    )
    body = b"<html><HEAD><TiTlE lang='en'>Proxmox &amp; Friends</title></HEAD>"
    headers, title = _parse_http_response(head, body)
    assert headers == {"server": "pve-api-daemon/3.0", "content-type": "text/html"}
    assert title == "Proxmox & Friends"
    assert _parse_http_response(b"SSH-2.0-OpenSSH\r\n\r\n", b"") is None


def _recording_callbacks(calls: list[tuple], *, use_async: bool):
    def ssh_fn(ip, port, timeout_sec):
        calls.append(("ssh", ip, port))
        return "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"

    def http_fn(ip, port, use_tls, timeout_sec):
        calls.append(("http", ip, port, use_tls))
        return {"Server": "pve-api-daemon/3.0"}, "pve01 - Proxmox Virtual Environment"

    def tls_fn(ip, port, timeout_sec):
        calls.append(("tls", ip, port))
        return "pve01.lab.example", ["pve01.lab.example", "pve01"]

    def snmp_fn(ip, timeout_sec):
        calls.append(("snmp", ip))
        return "Linux pve01 6.8.12-1-pve", "pve01"

    if not use_async:
        return ssh_fn, http_fn, tls_fn, snmp_fn

    def _wrap(fn):
        async def _async(*args):
            await asyncio.sleep(0)
            return fn(*args)

        return _async

    return _wrap(ssh_fn), _wrap(http_fn), _wrap(tls_fn), _wrap(snmp_fn)


def test_collect_contacts_only_banner_ports_and_merges_fields() -> None:
    sync_calls: list[tuple] = []
    ssh_fn, http_fn, tls_fn, snmp_fn = _recording_callbacks(sync_calls, use_async=False)
    fingerprinter = ServiceBannerFingerprinter(
        ssh_fn=ssh_fn, http_fn=http_fn, tls_fn=tls_fn, snmp_fn=snmp_fn
    )
    banner = fingerprinter.collect("10.42.1.10", [3389, 8006, 22])

    assert sorted(sync_calls) == sorted(
        [
            ("ssh", "10.42.1.10", 22),
            ("tls", "10.42.1.10", 8006),
            ("http", "10.42.1.10", 8006, True),
            ("snmp", "10.42.1.10"),
        ]
    )
    assert all(call[1] == "10.42.1.10" for call in sync_calls)
    assert not any(3389 in call for call in sync_calls)
    assert banner.ssh_banner == "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
    assert banner.http_titles == ["pve01 - Proxmox Virtual Environment"]
    assert banner.http_headers == {"server": "pve-api-daemon/3.0"}
    assert banner.tls_subject_cn == "pve01.lab.example"
    assert banner.tls_san_dns_names == ["pve01.lab.example", "pve01"]
    assert banner.snmp_sys_descr == "Linux pve01 6.8.12-1-pve"
    assert banner.snmp_sys_name == "pve01"
    assert banner.mdns_name is None

    async_calls: list[tuple] = []
    a_ssh, a_http, a_tls, a_snmp = _recording_callbacks(async_calls, use_async=True)
    async_banner = ServiceBannerFingerprinter(
        ssh_fn=a_ssh, http_fn=a_http, tls_fn=a_tls, snmp_fn=a_snmp
    ).collect("10.42.1.10", [22, 8006, 3389])
    assert async_banner == banner
    assert sorted(async_calls) == sorted(sync_calls)

    # Works from inside a running event loop via asyncio.run as well
    assert asyncio.run(fingerprinter.collect_async("10.42.1.10", [22, 8006])) == banner

    def failing_ssh(ip, port, timeout_sec):
        raise OSError("connection reset")

    async def failing_tls(ip, port, timeout_sec):
        raise asyncio.TimeoutError()

    errored = ServiceBannerFingerprinter(
        ssh_fn=failing_ssh, http_fn=http_fn, tls_fn=failing_tls
    ).collect("10.42.1.10", [22, 8006])
    assert errored.ssh_banner is None
    assert errored.tls_subject_cn is None
    assert errored.tls_san_dns_names == []
    assert errored.http_titles == ["pve01 - Proxmox Virtual Environment"]
    assert errored.snmp_sys_descr is None


def test_collect_merges_multiple_ports_in_ascending_order() -> None:
    def http_fn(ip, port, use_tls, timeout_sec):
        return {"Server": f"srv-{port}", f"X-Port-{port}": "1"}, f"title-{port}"

    def tls_fn(ip, port, timeout_sec):
        if port == 443:
            return None, ["b.example", "a.example"]
        return f"cn-{port}.example", ["a.example", "c.example"]

    fingerprinter = ServiceBannerFingerprinter(
        ssh_fn=lambda ip, port, t: "   ", http_fn=http_fn, tls_fn=tls_fn
    )
    banner = fingerprinter.collect("10.42.1.10", [8443, 80, 443, 22, 80])
    assert banner.ssh_banner is None
    assert banner.http_titles == ["title-80", "title-443", "title-8443"]
    assert banner.http_headers["server"] == "srv-80"
    assert set(banner.http_headers) == {
        "server",
        "x-port-80",
        "x-port-443",
        "x-port-8443",
    }
    assert banner.tls_subject_cn == "cn-8443.example"
    assert banner.tls_san_dns_names == ["b.example", "a.example", "c.example"]

    with pytest.raises(ValueError):
        fingerprinter.collect("not-an-ip", [22])
    with pytest.raises(ValueError):
        fingerprinter.collect("10.42.1.10", [70000])


def test_collect_many_bounds_concurrency_and_keeps_order() -> None:
    state = {"in_flight": 0, "peak": 0, "calls": 0}

    async def _record(delay: float):
        state["in_flight"] += 1
        state["calls"] += 1
        state["peak"] = max(state["peak"], state["in_flight"])
        await asyncio.sleep(delay)
        state["in_flight"] -= 1

    async def ssh_fn(ip, port, timeout_sec):
        await _record(0.002 * (int(ip.split(".")[-1]) % 3))
        return f"SSH-2.0-OpenSSH_9.6 host-{ip}"

    async def http_fn(ip, port, use_tls, timeout_sec):
        await _record(0.001)
        return {"Server": f"srv-{ip}"}, None

    async def tls_fn(ip, port, timeout_sec):
        await _record(0.001)
        return None, []

    fingerprinter = ServiceBannerFingerprinter(
        ssh_fn=ssh_fn, http_fn=http_fn, tls_fn=tls_fn, max_concurrency=2
    )
    targets = {f"10.42.1.{20 - i}": [22, 80, 443] for i in range(10)}
    banners = fingerprinter.collect_many(targets)

    assert [b.ip for b in banners] == list(targets)
    assert all(b.ssh_banner == f"SSH-2.0-OpenSSH_9.6 host-{b.ip}" for b in banners)
    assert state["calls"] == 10 * 4
    assert state["peak"] <= 2
    assert state["peak"] == 2

    pairs = [("10.42.1.5", (22,)), ("10.42.1.4", [80])]
    pair_banners = fingerprinter.collect_many(pairs)
    assert [b.ip for b in pair_banners] == ["10.42.1.5", "10.42.1.4"]
    assert pair_banners[1].http_headers == {"server": "srv-10.42.1.4"}

    with pytest.raises(ValueError):
        ServiceBannerFingerprinter(max_concurrency=0)
    with pytest.raises(ValueError):
        ServiceBannerFingerprinter(max_concurrency=True)
    with pytest.raises(ValueError):
        ServiceBannerFingerprinter(timeout_sec=0)
    with pytest.raises(ValueError):
        ServiceBannerFingerprinter(timeout_sec=-1.5)


def _enrichment_site() -> Site:
    return Site(
        site_id="site-42",
        name="Site 42",
        devices=[
            NetworkDevice(
                device_id="dev-a",
                site_id="site-42",
                hostname="switch-10-42-1-2",
                management_ip="10.42.1.2",
                vendor=None,
                role="switch",
                ports=[Port(port_id="dev-a-p1", device_id="dev-a", name="1:1")],
            ),
            NetworkDevice(
                device_id="dev-b",
                site_id="site-42",
                hostname="core-sw",
                management_ip="10.42.1.3",
                vendor="Acme",
                role="switch",
            ),
        ],
        equipment=[
            Equipment(
                equipment_id="eq-c",
                site_id="site-42",
                name="hypervisor-10-42-1-10",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.1.10"],
            ),
            Equipment(
                equipment_id="eq-d",
                site_id="site-42",
                name="prod-db",
                category=EquipmentCategory.SERVER,
                assigned_ips=["10.42.1.11"],
            ),
        ],
    )


def test_enrich_site_returns_enriched_copy() -> None:
    site = _enrichment_site()
    before = site.to_dict()
    banners = [
        RawServiceBanner(
            ip="10.42.1.2",
            snmp_sys_descr="ExtremeXOS (X460G2-48p-10G4) version 31.7.1.4",
            snmp_sys_name="SW-EDGE-01",
        ),
        RawServiceBanner(
            ip="10.42.1.3",
            snmp_sys_descr="VSP-4900-48P (8.10.0.0)",
            snmp_sys_name="vsp-core-02",
        ),
        RawServiceBanner(
            ip="10.42.1.10",
            http_titles=["Proxmox Virtual Environment"],
            tls_san_dns_names=["pve01.lab.example"],
        ),
        RawServiceBanner(
            ip="10.42.1.11",
            ssh_banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
            mdns_name="db01.local",
        ),
        RawServiceBanner(ip="10.42.1.200", http_titles=["Home Assistant"]),
    ]

    enriched, fingerprints = ServiceBannerFingerprinter().enrich_site(site, banners)

    assert [fp.ip for fp in fingerprints] == [b.ip for b in banners]
    assert fingerprints[-1].matched_signatures == ["home-assistant"]

    dev_a, dev_b = enriched.devices
    assert dev_a.vendor == "Extreme Networks"
    assert dev_a.model == "X460G2-48p-10G4"
    assert dev_a.hostname == "sw-edge-01"
    assert dev_a.role == "switch"
    assert [p.to_dict() for p in dev_a.ports] == [
        p.to_dict() for p in site.devices[0].ports
    ]
    assert dev_b.vendor == "Acme"
    assert dev_b.hostname == "core-sw"
    assert dev_b.model is None

    eq_c, eq_d = enriched.equipment
    assert eq_c.name == "pve01.lab.example"
    assert eq_c.category is EquipmentCategory.SERVER
    assert eq_c.assigned_ips == ["10.42.1.10"]
    assert eq_d.name == "prod-db"

    assert site.to_dict() == before
    assert enriched is not site
    assert enriched.to_dict() != before

    with pytest.raises(ValueError):
        ServiceBannerFingerprinter().enrich_site(before, banners)
