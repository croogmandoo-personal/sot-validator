"""CLI tests for `sot-validator serve` token, remote-bind and start-up wiring."""

from __future__ import annotations

import json
import re
import socket
import threading
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from sot_validator import cli
from sot_validator.cli import _workbench_url, main

URL_RE = re.compile(r"(http://127\.0\.0\.1:(\d+)/)#token=(\S+)")


def test_serve_prints_token_url_once_and_supplied_token_verbatim(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(
        ["serve", "--host", "127.0.0.1", "--port", "0", "--token", "cli-tok_1", "--once"]
    )
    assert rc == 0
    out, err = capsys.readouterr()
    matches = URL_RE.findall(out)
    assert len(matches) == 1
    assert matches[0][2] == "cli-tok_1"
    assert "?token=" not in out
    assert "cli-tok_1" not in err


def test_serve_generates_and_prints_a_fresh_token(
    capsys: pytest.CaptureFixture[str],
) -> None:
    tokens = []
    for _ in range(2):
        assert main(["serve", "--host", "127.0.0.1", "--port", "0", "--once"]) == 0
        match = URL_RE.search(capsys.readouterr().out)
        assert match is not None
        tokens.append(match.group(3))
    assert all(len(token) >= 32 for token in tokens)
    assert tokens[0] != tokens[1]


def test_serve_check_does_not_print_token(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        ["serve", "--host", "127.0.0.1", "--port", "0", "--token", "chk-tok", "--check"]
    )
    assert rc == 0
    out, err = capsys.readouterr()
    assert "chk-tok" not in out + err


@pytest.mark.parametrize("host", ["0.0.0.0", "", "10.9.1.2"])
def test_serve_refuses_non_loopback_host_cleanly(
    host: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["serve", "--host", host, "--port", "0", "--token", "rf-tok", "--check"])
    assert rc == 2
    out, err = capsys.readouterr()
    assert "--allow-remote" in err
    assert "Traceback" not in err
    assert "rf-tok" not in out + err


def test_serve_allow_remote_binds_wildcard_host(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = main(["serve", "--host", "0.0.0.0", "--port", "0", "--allow-remote", "--check"])
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_serve_reports_port_in_use_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        rc = main(
            ["serve", "--host", "127.0.0.1", "--port", str(port), "--token", "busy-tok", "--check"]
        )
    assert rc == 2
    out, err = capsys.readouterr()
    assert err.startswith("error: cannot bind the workbench")
    assert "busy-tok" not in out + err


@pytest.mark.parametrize("bad_token", ["", "has space", "trail\n", "ctl\x01x", "café"])
def test_serve_rejects_bad_token_without_echoing_it(
    bad_token: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["serve", "--host", "127.0.0.1", "--port", "0", "--token", bad_token, "--check"])
    assert rc == 2
    out, err = capsys.readouterr()
    assert err.startswith("error: --token rejected")
    if bad_token:
        assert bad_token not in out + err
    assert "Traceback" not in err


def test_workbench_url_brackets_ipv6_and_maps_wildcards() -> None:
    assert _workbench_url(("::1", 5100, 0, 0)) == "http://[::1]:5100/"
    assert _workbench_url(("0.0.0.0", 5100)) == "http://127.0.0.1:5100/"
    assert _workbench_url(("::", 5100, 0, 0)) == "http://127.0.0.1:5100/"
    assert _workbench_url(("127.0.0.1", 5100)) == "http://127.0.0.1:5100/"


def test_printed_token_url_authenticates_writes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    servers: list[Any] = []
    real_create = cli.create_workbench_server

    def _capture(*args: Any, **kwargs: Any) -> Any:
        server = real_create(*args, **kwargs)
        servers.append(server)
        return server

    monkeypatch.setattr(cli, "create_workbench_server", _capture)
    result: list[int] = []
    thread = threading.Thread(
        target=lambda: result.append(main(["serve", "--host", "127.0.0.1", "--port", "0"])),
        daemon=True,
    )
    thread.start()
    try:
        match = None
        for _ in range(100):
            match = URL_RE.search(capsys.readouterr().out)
            if match:
                break
            thread.join(timeout=0.05)
        assert match is not None
        base_url, token = match.group(1).rstrip("/"), match.group(3)

        state_before = urlopen(f"{base_url}/api/state", timeout=5).read()
        device_id = json.loads(state_before)["site"]["devices"][0]["device_id"]
        body = json.dumps(
            {"target_type": "NetworkDevice", "target_id": device_id, "room": "MDF-CLI"}
        ).encode("utf-8")

        def _post(auth: str | None) -> int:
            headers = {"Content-Type": "application/json", "Origin": base_url}
            if auth is not None:
                headers["Authorization"] = auth
            req = Request(f"{base_url}/api/items/patch", data=body, headers=headers, method="POST")
            try:
                with urlopen(req, timeout=5) as resp:
                    return resp.status
            except HTTPError as exc:
                return exc.code

        assert _post(None) == 401
        assert _post(f"Bearer {token}") == 200
        audit = json.loads(urlopen(f"{base_url}/api/audit-log", timeout=5).read())
        assert any(entry["target_id"] == device_id for entry in audit["audit_log"])
    finally:
        for server in servers:
            server.shutdown()
        thread.join(timeout=5)
    assert result == [0]
