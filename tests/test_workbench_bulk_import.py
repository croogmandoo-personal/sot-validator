"""HTTP tests for the workbench bulk CSV import routes and the Bulk Import tab."""

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

from sot_validator.curation import verify_audit_chain
from sot_validator.models import Equipment, EquipmentCategory, NetworkDevice, Site
from sot_validator.workbench import (
    WorkbenchSecurityConfig,
    WorkbenchServer,
    WorkbenchState,
    create_workbench_server,
    render_workbench_html,
)

TOKEN = "bulk-import-test-token"
HEADER = "record_type,record_id,field,new_value,reason\n"
VALID_CSV = (
    HEADER
    + "device,dev-1,hostname,sw-core,rename core\n"
    + "device,dev-1,vendor,Extreme Networks,unchanged\n"
    + "equipment,eq-1,room,MDF-2,moved\n"
)
ROUTES = ("/api/curation/preview", "/api/curation/apply")


def _sample_site() -> Site:
    return Site(
        site_id="site-bulk",
        name="Bulk Lab",
        devices=[
            NetworkDevice(
                device_id="dev-1",
                site_id="site-bulk",
                hostname="sw-01",
                management_ip="10.7.1.2",
                vendor="Extreme Networks",
                role="switch",
                ports=[],
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-1",
                site_id="site-bulk",
                name="ups-01",
                category=EquipmentCategory.UPS,
            )
        ],
    )


@contextmanager
def _live(
    security: WorkbenchSecurityConfig | None = None,
) -> Iterator[tuple[str, WorkbenchServer, WorkbenchState]]:
    state = WorkbenchState(_sample_site())
    config = security or WorkbenchSecurityConfig(token=TOKEN)
    server = create_workbench_server(state, host="127.0.0.1", port=0, security=config)
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
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, Any, bytes]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = dict(headers or {})
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    req = Request(url, data=body, headers=request_headers, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read()
    except HTTPError as err:
        return err.code, err.headers, err.read()


def _write_headers(base_url: str, token: str | None = TOKEN) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Origin": base_url}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _post(base_url: str, route: str, payload: Any, **kwargs: Any) -> tuple[int, Any]:
    headers = kwargs.pop("headers", None) or _write_headers(base_url)
    status, _, raw = _http("POST", base_url + route, payload=payload, headers=headers)
    return status, json.loads(raw.decode("utf-8"))


def _audit_log(base_url: str) -> list[dict[str, Any]]:
    status, _, raw = _http("GET", base_url + "/api/audit-log")
    assert status == 200
    return json.loads(raw.decode("utf-8"))["audit_log"]


def _apply_payload(csv_text: str, token: str) -> dict[str, Any]:
    return {"csv": csv_text, "confirm_token": token, "actor": "bulk-tester"}


def test_routes_require_token_and_same_origin_without_state_change() -> None:
    with _live() as (base_url, _server, state):
        before = state.store.to_dict()
        for route in ROUTES:
            payload = _apply_payload(VALID_CSV, "0" * 64)
            status, body = _post(
                base_url, route, payload, headers=_write_headers(base_url, token=None)
            )
            assert status == 401
            assert body["status"] == "error"
            status, _ = _post(
                base_url, route, payload, headers=_write_headers(base_url, token="wrong")
            )
            assert status == 401
            cross = _write_headers(base_url)
            cross["Origin"] = "http://evil.example"
            status, _ = _post(base_url, route, payload, headers=cross)
            assert status == 403
        assert state.store.to_dict() == before


@pytest.mark.parametrize("route", ROUTES)
def test_oversized_csv_returns_413_without_state_change(route: str) -> None:
    security = WorkbenchSecurityConfig(token=TOKEN, max_body_bytes=512)
    with _live(security) as (base_url, server, state):
        host, port = server.server_address[:2]
        big_csv = HEADER + "device,dev-1,notes,{},\n".format("x" * 1024)
        body = json.dumps(_apply_payload(big_csv, "0" * 64))
        assert len(body) > security.max_body_bytes
        request = (
            f"POST {route} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Authorization: Bearer {TOKEN}\r\n"
            f"Origin: {base_url}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        )
        response = b""
        with socket.create_connection((host, port), timeout=5.0) as sock:
            sock.sendall(request.encode("ascii"))
            sock.settimeout(5.0)
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        head = response.partition(b"\r\n\r\n")[0]
        assert b" 413 " in head.split(b"\r\n")[0]
        assert state.store.to_dict()["audit_log"] == []
        assert state.store.list_patches() == []


def test_preview_returns_statuses_and_confirm_token() -> None:
    csv_text = VALID_CSV + "device,ghost,hostname,x,\n"
    with _live() as (base_url, _server, state):
        status, body = _post(base_url, "/api/curation/preview", {"csv": csv_text})
        assert status == 200
        preview = body["preview"]
        assert [r["status"] for r in preview["rows"]] == [
            "change",
            "no_op",
            "change",
            "invalid",
        ]
        assert preview["counts"] == {"change": 2, "no_op": 1, "conflict": 0, "invalid": 1}
        assert re.fullmatch(r"[0-9a-f]{64}", preview["confirm_token"])
        assert preview["can_apply"] is False
        assert preview["site_id"] == "site-bulk"
        assert state.store.to_dict()["audit_log"] == []


def test_parse_errors_return_400_with_row_list() -> None:
    csv_text = HEADER + "device,dev-1,bogus,x,\ndevice,dev-1,deleted,maybe,\n"
    with _live() as (base_url, _server, _state):
        for route in ROUTES:
            status, body = _post(base_url, route, _apply_payload(csv_text, "0" * 64))
            assert status == 400
            assert [e["row"] for e in body["errors"]] == [2, 3]
            assert body["error"].splitlines()[0].startswith("row 2: ")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"csv": 42},
        {"csv": VALID_CSV, "as_of": "not-a-date"},
        {"csv": VALID_CSV, "as_of": 5},
    ],
)
def test_bad_preview_body_returns_400(payload: dict[str, Any]) -> None:
    with _live() as (base_url, _server, _state):
        status, body = _post(base_url, "/api/curation/preview", payload)
        assert status == 400
        assert body["status"] == "error"


def test_apply_without_string_confirm_token_returns_400() -> None:
    with _live() as (base_url, _server, state):
        for token in (None, 123):
            status, _ = _post(
                base_url, "/api/curation/apply", {"csv": VALID_CSV, "confirm_token": token}
            )
            assert status == 400
        assert state.store.to_dict()["audit_log"] == []


def test_wrong_confirm_token_returns_409_and_audit_log_unchanged() -> None:
    with _live() as (base_url, _server, _state):
        before = _audit_log(base_url)
        status, body = _post(
            base_url, "/api/curation/apply", _apply_payload(VALID_CSV, "f" * 64)
        )
        assert status == 409
        assert body["status"] == "error"
        assert "preview again" in body["error"]
        assert _audit_log(base_url) == before


def test_apply_with_conflict_rows_returns_409() -> None:
    csv_text = HEADER + "device,dev-1,hostname,a,\ndevice,dev-1,hostname,b,\n"
    with _live() as (base_url, _server, state):
        _, body = _post(base_url, "/api/curation/preview", {"csv": csv_text})
        token = body["preview"]["confirm_token"]
        status, _ = _post(base_url, "/api/curation/apply", _apply_payload(csv_text, token))
        assert status == 409
        assert state.store.to_dict()["audit_log"] == []


def test_successful_apply_updates_state_and_audit_log_with_batch_id() -> None:
    with _live() as (base_url, _server, state):
        _, body = _post(base_url, "/api/curation/preview", {"csv": VALID_CSV})
        token = body["preview"]["confirm_token"]
        status, body = _post(
            base_url, "/api/curation/apply", _apply_payload(VALID_CSV, token)
        )
        assert status == 200
        assert body["status"] == "ok"
        assert body["applied"] == 2
        batch_id = body["batch_id"]
        assert {e["changes"]["batch_id"] for e in body["audit_entries"]} == {batch_id}
        assert body["state"]["site"]["devices"][0]["hostname"] == "sw-core"

        status, _, raw = _http("GET", base_url + "/api/state")
        assert status == 200
        live_state = json.loads(raw.decode("utf-8"))
        assert live_state["site"]["devices"][0]["hostname"] == "sw-core"

        log = _audit_log(base_url)
        assert len(log) == 2
        assert {e["changes"]["batch_id"] for e in log} == {batch_id}
        assert [e["reason"] for e in log] == ["rename core", "moved"]
        assert {e["actor"] for e in log} == {"bulk-tester"}
        assert verify_audit_chain(state.store).ok

        # Re-applying the same token is now stale and refused.
        status, _ = _post(base_url, "/api/curation/apply", _apply_payload(VALID_CSV, token))
        assert status == 409
        assert len(_audit_log(base_url)) == 2


def test_rendered_html_has_bulk_import_tab_controls() -> None:
    with _live() as (base_url, _server, state):
        status, _, raw = _http("GET", base_url + "/")
        assert status == 200
        html = raw.decode("utf-8")
    assert html == render_workbench_html(state)
    assert "data-tab=\"tab-import\"" in html and ">Bulk Import</button>" in html
    assert '<section id="tab-import" class="tab-panel">' in html
    assert re.search(r'<input type="file" id="import-file" accept="\.csv,text/csv"', html)
    assert 'type="datetime-local" id="import-as-of"' in html
    assert 'id="import-status-filter"' in html
    for option in ("change", "no_op", "conflict", "invalid"):
        assert f'<option value="{option}">{option}</option>' in html
    assert 'id="import-preview-table"' in html
    assert re.search(r'<button[^>]*id="import-apply-btn"[^>]*\bdisabled\b', html)
    assert re.search(r"\.import-scroll \{\s*overflow-x: auto;", html)
    assert re.search(
        r'<div class="import-scroll">\s*<table id="import-preview-table">', html
    )
    assert "/api/curation/preview" in html and "/api/curation/apply" in html
    assert "new Date(raw)" in html and ".toISOString()" in html
    assert "file.text()" in html
    assert "upload limit" in html
    assert "Import refused: " in html
    assert "eval(" not in html and "new Function" not in html
    assert "<script src" not in html.lower()


def test_script_values_in_csv_come_back_as_json_and_ui_escapes_them() -> None:
    csv_text = (
        HEADER
        + "device,dev-1,notes,<script>alert(1)</script>,<img src=x onerror=alert(2)>\n"
        + "device,<script>x</script>,hostname,y,\n"
    )
    with _live() as (base_url, _server, state):
        status, headers, raw = _http(
            "POST",
            base_url + "/api/curation/preview",
            payload={"csv": csv_text},
            headers=_write_headers(base_url),
        )
        assert status == 200
        assert headers.get("Content-Type", "").startswith("application/json")
        preview = json.loads(raw.decode("utf-8"))["preview"]
        assert preview["rows"][0]["new_value"] == "<script>alert(1)</script>"
        assert preview["rows"][0]["reason"] == "<img src=x onerror=alert(2)>"
        assert preview["rows"][1]["record_id"] == "<script>x</script>"
        html = render_workbench_html(state)

    renderer = html[html.index("function renderImportPreview") :]
    renderer = renderer[: renderer.index("function applyImportStatusFilter")]
    for column in (
        "row.row_number",
        "row.record_type",
        "row.record_id",
        "row.field",
        "formatImportValue(row.old_value)",
        "formatImportValue(row.new_value)",
        "row.reason",
        "row.detail",
    ):
        assert f"escapeHtml({column})" in renderer
    errors_block = html[html.index("CSV has errors:") :][:300]
    assert "escapeHtml('row ' + e.row + ': ' + e.message)" in errors_block
