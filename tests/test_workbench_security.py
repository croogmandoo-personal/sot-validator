"""Security tests for the workbench: bearer auth, origin checks, body limits, headers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import json
import re
import socket
import threading
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from sot_validator.models import NetworkDevice, Site
from sot_validator.workbench import (
    WorkbenchSecurityConfig,
    WorkbenchServer,
    WorkbenchState,
    create_workbench_server,
    render_workbench_html,
)

SECURITY_TEST_TOKEN = "security-test-token"
WRITE_EVENT_ID = "dev-sec-01"


def _sample_site() -> Site:
    return Site(
        site_id="site-sec",
        name="Security Lab",
        devices=[
            NetworkDevice(
                device_id=WRITE_EVENT_ID,
                site_id="site-sec",
                hostname="sw-sec-01",
                management_ip="10.9.1.2",
                vendor="Extreme Networks",
                role="switch",
                ports=[],
            )
        ],
    )


def _patch_payload() -> dict[str, Any]:
    return {
        "target_type": "NetworkDevice",
        "target_id": WRITE_EVENT_ID,
        "name": "sw-sec-01-renamed",
        "room": "MDF-9",
        "reason": "security test edit",
    }


@contextmanager
def _live(
    security: WorkbenchSecurityConfig | None = None,
) -> Iterator[tuple[str, WorkbenchServer, WorkbenchState]]:
    state = WorkbenchState(_sample_site())
    config = security or WorkbenchSecurityConfig(token=SECURITY_TEST_TOKEN)
    server = create_workbench_server(
        state, host="127.0.0.1", port=0, security=config
    )
    host, port = server.server_address[:2]
    base_url = f"http://{host}:{port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield base_url, server, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)


def _http(
    method: str,
    url: str,
    *,
    payload: Any = None,
    raw_body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, Any, bytes]:
    body = raw_body
    if body is None and payload is not None:
        body = json.dumps(payload).encode("utf-8")
    request_headers = dict(headers or {})
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    req = Request(url, data=body, headers=request_headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read()
    except HTTPError as err:
        return err.code, err.headers, err.read()


def _write_headers(base_url: str, token: str | None = SECURITY_TEST_TOKEN) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Origin": base_url}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _assert_hardening_headers(headers: Any) -> None:
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "no-referrer"
    csp = headers.get("Content-Security-Policy")
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "*" not in csp
    assert "http:" not in csp.lower()
    assert "https:" not in csp.lower()


def test_security_config_defaults_generation_and_validation() -> None:
    generated = WorkbenchSecurityConfig()
    assert isinstance(generated.token, str)
    assert len(generated.token) >= 32
    assert generated.allow_remote is False
    assert generated.max_body_bytes == 1_048_576
    assert WorkbenchSecurityConfig().token != generated.token

    supplied = WorkbenchSecurityConfig(
        token="fixed", allow_remote=True, max_body_bytes=1024
    )
    assert supplied.token == "fixed"
    assert supplied.allow_remote is True
    assert supplied.max_body_bytes == 1024

    for bad_size in (0, -1):
        with pytest.raises(ValueError):
            WorkbenchSecurityConfig(token="fixed", max_body_bytes=bad_size)


def test_server_tokens_are_unique_and_supplied_token_is_used() -> None:
    state = WorkbenchState(_sample_site())
    first = create_workbench_server(state, host="127.0.0.1", port=0)
    second = create_workbench_server(state, host="127.0.0.1", port=0)
    try:
        assert first.security.token
        assert second.security.token
        assert first.security.token != second.security.token
    finally:
        first.server_close()
        second.server_close()

    supplied = create_workbench_server(
        state,
        host="127.0.0.1",
        port=0,
        security=WorkbenchSecurityConfig(token="supplied-token"),
    )
    try:
        assert supplied.security.token == "supplied-token"
    finally:
        supplied.server_close()


def test_non_loopback_bind_requires_allow_remote() -> None:
    state = WorkbenchState(_sample_site())
    with pytest.raises(ValueError):
        create_workbench_server(state, host="0.0.0.0", port=0)
    with pytest.raises(ValueError):
        create_workbench_server(
            state,
            host="workbench.example.internal",
            port=0,
            security=WorkbenchSecurityConfig(token="t"),
        )

    remote = create_workbench_server(
        state,
        host="0.0.0.0",
        port=0,
        security=WorkbenchSecurityConfig(token="t", allow_remote=True),
    )
    try:
        assert remote.server_address[0] == "0.0.0.0"
    finally:
        remote.server_close()


def test_loopback_hosts_bind_without_allow_remote() -> None:
    state = WorkbenchState(_sample_site())
    for host in ("localhost", "127.0.0.1"):
        server = create_workbench_server(
            state, host=host, port=0, security=WorkbenchSecurityConfig(token="t")
        )
        try:
            assert server.server_address[1] > 0
        finally:
            server.server_close()


def test_write_without_token_is_rejected_without_state_change() -> None:
    with _live() as (base_url, _server, _state):
        before_status, _before_headers, before_raw = _http(
            "GET", f"{base_url}/api/state"
        )
        assert before_status == 200

        status, headers, raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers={"Content-Type": "application/json"},
        )
        assert status == 401
        assert json.loads(raw.decode("utf-8"))["status"] == "error"
        _assert_hardening_headers(headers)

        after_status, _after_headers, after_raw = _http(
            "GET", f"{base_url}/api/state"
        )
        assert after_status == 200
        assert after_raw == before_raw

        audit_status, _audit_headers, audit_raw = _http(
            "GET", f"{base_url}/api/audit-log"
        )
        assert audit_status == 200
        assert json.loads(audit_raw.decode("utf-8"))["audit_log"] == []


def test_wrong_token_is_rejected_without_state_change() -> None:
    with _live() as (base_url, _server, _state):
        status, _headers, raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers=_write_headers(base_url, token="wrong-token"),
        )
        assert status == 401
        assert json.loads(raw.decode("utf-8"))["status"] == "error"

        _status, _headers, audit_raw = _http("GET", f"{base_url}/api/audit-log")
        assert json.loads(audit_raw.decode("utf-8"))["audit_log"] == []


def test_cross_origin_origin_header_is_rejected() -> None:
    with _live() as (base_url, _server, _state):
        headers = _write_headers(base_url, token=SECURITY_TEST_TOKEN)
        headers["Origin"] = "http://evil.example"
        status, _headers, raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers=headers,
        )
        assert status == 403
        assert json.loads(raw.decode("utf-8"))["status"] == "error"

        _status, _headers, audit_raw = _http("GET", f"{base_url}/api/audit-log")
        assert json.loads(audit_raw.decode("utf-8"))["audit_log"] == []


def test_cross_origin_referer_is_rejected() -> None:
    with _live() as (base_url, _server, _state):
        headers = _write_headers(base_url)
        del headers["Origin"]
        headers["Referer"] = "http://evil.example/page"
        status, _headers, raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers=headers,
        )
        assert status == 403
        assert json.loads(raw.decode("utf-8"))["status"] == "error"

        _status, _headers, audit_raw = _http("GET", f"{base_url}/api/audit-log")
        assert json.loads(audit_raw.decode("utf-8"))["audit_log"] == []


def test_same_origin_referer_is_allowed() -> None:
    with _live() as (base_url, _server, _state):
        headers = _write_headers(base_url)
        del headers["Origin"]
        headers["Referer"] = f"{base_url}/inventory"
        status, _headers, raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers=headers,
        )
        assert status == 200
        assert json.loads(raw.decode("utf-8"))["status"] == "ok"


def test_mutating_methods_require_token_and_reject_authenticated_writes() -> None:
    with _live() as (base_url, _server, _state):
        for method in ("PUT", "PATCH", "DELETE"):
            unauth_status, _headers, unauth_raw = _http(
                method,
                f"{base_url}/api/items/patch",
                payload=_patch_payload(),
                headers={"Content-Type": "application/json"},
            )
            assert unauth_status == 401
            assert json.loads(unauth_raw.decode("utf-8"))["status"] == "error"

            auth_status, _headers, auth_raw = _http(
                method,
                f"{base_url}/api/items/patch",
                payload=_patch_payload(),
                headers=_write_headers(base_url),
            )
            assert auth_status == 405
            assert json.loads(auth_raw.decode("utf-8"))["status"] == "error"


def test_authenticated_patch_applies_and_records_audit_entry() -> None:
    with _live() as (base_url, _server, _state):
        status, _headers, raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers=_write_headers(base_url),
        )
        assert status == 200
        assert json.loads(raw.decode("utf-8"))["status"] == "ok"

        _state_status, _state_headers, state_raw = _http(
            "GET", f"{base_url}/api/state"
        )
        state_payload = json.loads(state_raw.decode("utf-8"))
        assert any(
            patch["target_id"] == WRITE_EVENT_ID and patch["name"] == "sw-sec-01-renamed"
            for patch in state_payload["patches"]
        )

        _audit_status, _audit_headers, audit_raw = _http(
            "GET", f"{base_url}/api/audit-log"
        )
        audit_payload = json.loads(audit_raw.decode("utf-8"))
        assert any(
            entry["target_id"] == WRITE_EVENT_ID
            for entry in audit_payload["audit_log"]
        )


def test_oversized_body_returns_413_without_reading_it() -> None:
    security = WorkbenchSecurityConfig(
        token=SECURITY_TEST_TOKEN, max_body_bytes=256
    )
    with _live(security) as (base_url, server, state):
        host, port = server.server_address[:2]
        body = json.dumps({"target_type": "NetworkDevice", "target_id": "x" * 512})
        assert len(body) > security.max_body_bytes
        request = (
            "POST /api/items/patch HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Authorization: Bearer {SECURITY_TEST_TOKEN}\r\n"
            f"Origin: {base_url}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
        )
        response = b""
        with socket.create_connection((host, port), timeout=5.0) as sock:
            sock.sendall((request + "\r\n").encode("ascii"))
            sock.settimeout(5.0)
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:  # pragma: no cover - failure diagnostic
                    pytest.fail("server did not answer the oversized request")
                if not chunk:
                    break
                response += chunk

        head, _, response_body = response.partition(b"\r\n\r\n")
        assert b" 413 " in head.split(b"\r\n")[0]
        assert b"Connection: close" in head
        assert json.loads(response_body.decode("utf-8"))["status"] == "error"
        assert state.get_state_payload()["patches"] == []
        assert state.get_state_payload()["audit_log"] == []


def test_security_headers_on_get_and_unauthorized_responses() -> None:
    with _live() as (base_url, _server, _state):
        for path in ("/", "/api/state"):
            status, headers, _raw = _http("GET", f"{base_url}{path}")
            assert status == 200
            _assert_hardening_headers(headers)

        status, headers, _raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers={"Content-Type": "application/json"},
        )
        assert status == 401
        _assert_hardening_headers(headers)


def test_get_routes_stay_unauthenticated() -> None:
    with _live() as (base_url, _server, _state):
        for path in (
            "/",
            "/api/health",
            "/api/state",
            "/api/topology",
            "/api/audit-log",
        ):
            status, _headers, _raw = _http("GET", f"{base_url}{path}")
            assert status == 200, path


def test_ui_reads_token_from_fragment_and_sends_authorization_on_writes() -> None:
    state = WorkbenchState(_sample_site())
    page = render_workbench_html(state)
    assert "location.hash" in page
    assert "sessionStorage" in page

    write_fetches = list(
        re.finditer(
            r"fetch\('/api/(?:items/patch|devices|devices/ports|vlans)'", page
        )
    )
    assert len(write_fetches) == 5
    for match in write_fetches:
        window = page[match.start() : match.start() + 400]
        assert "Authorization" in window
        assert "Bearer " in window

    read_fetches = re.findall(r"fetch\('/api/(?:topology|state|audit-log)'", page)
    assert len(read_fetches) == 3
    assert "?token=" not in page

    with _live() as (base_url, server, _live_state):
        status, _headers, raw = _http("GET", f"{base_url}/")
        assert status == 200
        html_page = raw.decode("utf-8")
        assert "location.hash" in html_page
        assert "sessionStorage" in html_page
        assert "?token=" not in html_page
        assert server.security.token not in html_page


@pytest.mark.parametrize(
    "bad_token",
    ["", "secret-token\n", "secret\r\ntoken", "secret token", "secret\x00", "sécret", 12345],
)
def test_supplied_token_with_control_or_whitespace_is_rejected_without_echo(
    bad_token: Any,
) -> None:
    with pytest.raises(ValueError) as excinfo:
        WorkbenchSecurityConfig(token=bad_token)
    message = str(excinfo.value)
    if isinstance(bad_token, str) and bad_token:
        assert bad_token not in message
        assert repr(bad_token) not in message


def test_ipv6_loopback_bind_is_not_refused() -> None:
    state = WorkbenchState(_sample_site())
    try:
        server = create_workbench_server(
            state, host="::1", port=0, security=WorkbenchSecurityConfig(token="t")
        )
    except OSError:  # pragma: no cover - host without IPv6
        return
    server.server_close()


@pytest.mark.parametrize("host", ["", "::", "10.9.1.2", "127.0.0.1.example"])
def test_other_hosts_are_non_loopback(host: str) -> None:
    state = WorkbenchState(_sample_site())
    with pytest.raises(ValueError):
        create_workbench_server(
            state, host=host, port=0, security=WorkbenchSecurityConfig(token="t")
        )


@pytest.mark.parametrize(
    "authorization",
    [
        f"bearer {SECURITY_TEST_TOKEN}",
        f"Bearer  {SECURITY_TEST_TOKEN}",
        f"Bearer {SECURITY_TEST_TOKEN}x",
        f"Basic {SECURITY_TEST_TOKEN}",
        SECURITY_TEST_TOKEN,
        "Bearer ",
    ],
)
def test_malformed_authorization_is_rejected(authorization: str) -> None:
    with _live() as (base_url, _server, _state):
        headers = _write_headers(base_url)
        headers["Authorization"] = authorization
        status, _headers, raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers=headers,
        )
        assert status == 401
        assert SECURITY_TEST_TOKEN not in raw.decode("utf-8")

        _status, _headers, audit_raw = _http("GET", f"{base_url}/api/audit-log")
        assert json.loads(audit_raw.decode("utf-8"))["audit_log"] == []


@pytest.mark.parametrize(
    ("origin", "referer"),
    [
        ("null", None),
        ("", None),
        ("http://127.0.0.1", None),
        (None, "http://[::1/broken"),
        (None, "null"),
        (None, "/relative/page"),
    ],
)
def test_null_or_malformed_origin_and_referer_are_rejected(
    origin: str | None, referer: str | None
) -> None:
    with _live() as (base_url, _server, _state):
        headers = _write_headers(base_url)
        del headers["Origin"]
        if origin is not None:
            headers["Origin"] = origin
        if referer is not None:
            headers["Referer"] = referer
        status, _headers, raw = _http(
            "POST",
            f"{base_url}/api/items/patch",
            payload=_patch_payload(),
            headers=headers,
        )
        assert status == 403
        assert json.loads(raw.decode("utf-8"))["status"] == "error"

        _status, _headers, audit_raw = _http("GET", f"{base_url}/api/audit-log")
        assert json.loads(audit_raw.decode("utf-8"))["audit_log"] == []
