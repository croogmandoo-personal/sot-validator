"""Technical enforcement tests for read-only extraction: SQLite mode=ro, HTTP guard, static scan."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sqlite3

import pytest

from sot_validator.extraction import guard as guard_module
from sot_validator.extraction.client import ReadOnlyViolationError
from sot_validator.extraction.guard import (
    READ_ONLY_POST_ALLOWLIST,
    ReadOnlyHttpGuard,
    ReadOnlyViolation,
)
from sot_validator.extraction.sql_export import SqlExportSoTClient, open_read_only_sqlite

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPO_ROOT / "src" / "sot_validator"
SQL_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "sot_samples" / "sql" / "sot_schema_and_seed.sql"
SCANNED_PACKAGES = ("extraction", "signals", "connectors")
GUARD_MODULE = "extraction/guard.py"
MEMORY_CONNECT_ALLOWED = {"extraction/sql_export.py"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_sqlite_export(db_path: Path) -> list[str]:
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SQL_FIXTURE.read_text(encoding="utf-8"))
        conn.commit()
        site_ids = [row[0] for row in conn.execute("SELECT site_id FROM sites ORDER BY site_id")]
    finally:
        conn.close()
    return site_ids


@pytest.fixture()
def sqlite_export(tmp_path: Path) -> tuple[Path, list[str]]:
    db_path = tmp_path / "sot export.db"
    site_ids = _build_sqlite_export(db_path)
    assert site_ids
    return db_path, site_ids


# --- SQLite writes -----------------------------------------------------------


def test_sqlite_export_loads_site_ids_read_only(sqlite_export: tuple[Path, list[str]]) -> None:
    db_path, site_ids = sqlite_export
    before = _sha256(db_path)

    client = SqlExportSoTClient(db_path)

    assert sorted(client.list_site_ids()) == site_ids
    assert _sha256(db_path) == before


def test_sqlite_export_detected_by_header_via_from_sql_dump(tmp_path: Path) -> None:
    db_path = tmp_path / "misnamed_export.sql"
    site_ids = _build_sqlite_export(db_path)
    before = _sha256(db_path)

    client = SqlExportSoTClient.from_sql_dump(str(db_path))

    assert sorted(client.list_site_ids()) == site_ids
    assert _sha256(db_path) == before


def test_sqlite_header_check_keeps_text_dump_with_db_suffix(tmp_path: Path) -> None:
    dump_path = tmp_path / "text_dump.db"
    dump_path.write_text(
        "CREATE TABLE sites (site_id TEXT, name TEXT, site_prefix TEXT);\n"
        "INSERT INTO sites (site_id, name, site_prefix) VALUES ('site-007', 'S7', '10.7.0.0/16');\n",
        encoding="utf-8",
    )

    client = SqlExportSoTClient(dump_path)

    assert client.list_site_ids() == ["site-007"]


@pytest.mark.parametrize(
    "statement_kind",
    ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "ATTACH", "REPLACE"],
)
def test_sqlite_write_statements_rejected(
    sqlite_export: tuple[Path, list[str]], tmp_path: Path, statement_kind: str
) -> None:
    db_path, _ = sqlite_export
    attach_target = tmp_path / "attached_new.db"
    statements = {
        "INSERT": "INSERT INTO sites (site_id, name, site_prefix, address, rooms) "
        "VALUES ('site-999', 'x', '10.99.0.0/16', 'x', 'x')",
        "UPDATE": "UPDATE sites SET name = 'changed'",
        "DELETE": "DELETE FROM sites",
        "DROP": "DROP TABLE equipment",
        "ALTER": "ALTER TABLE sites ADD COLUMN extra TEXT",
        "CREATE": "CREATE TABLE planted (x TEXT)",
        "ATTACH": f"ATTACH DATABASE '{attach_target}' AS planted",
        "REPLACE": "REPLACE INTO sites (site_id, name, site_prefix, address, rooms) "
        "VALUES ('site-042', 'x', '10.42.0.0/16', 'x', 'x')",
    }
    before = _sha256(db_path)

    conn = open_read_only_sqlite(db_path)
    try:
        with pytest.raises(sqlite3.Error):
            conn.execute(statements[statement_kind])
            conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0] >= 1
    finally:
        conn.close()

    assert _sha256(db_path) == before
    assert not attach_target.exists()


def test_sqlite_detach_denied(sqlite_export: tuple[Path, list[str]]) -> None:
    db_path, _ = sqlite_export
    conn = open_read_only_sqlite(db_path)
    try:
        with pytest.raises(sqlite3.Error):
            conn.execute("DETACH DATABASE main")
    finally:
        conn.close()


# --- HTTP guard --------------------------------------------------------------


class _StubResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _StubResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class _RecordingOpener:
    def __init__(self, body: bytes = b"payload") -> None:
        self.body = body
        self.calls: list[tuple[object, float]] = []

    def __call__(self, request: object, timeout: float = 0.0) -> _StubResponse:
        self.calls.append((request, timeout))
        return _StubResponse(self.body)


@pytest.mark.parametrize(
    "method", ["POST", "PUT", "PATCH", "DELETE", "post", "put", "patch", "delete", " Post "]
)
def test_guard_rejects_mutating_methods_without_io(
    method: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _no_request(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Request must not be built for a rejected method")

    monkeypatch.setattr(guard_module, "Request", _no_request)
    opener = _RecordingOpener()
    guard = ReadOnlyHttpGuard(opener=opener)

    with pytest.raises(ReadOnlyViolation):
        guard.request(method, "https://sot.internal/sites")

    assert opener.calls == []


@pytest.mark.parametrize("method", [None, "", "   ", 42])
def test_guard_rejects_empty_or_non_string_method(method: object) -> None:
    opener = _RecordingOpener()
    with pytest.raises(ReadOnlyViolation):
        ReadOnlyHttpGuard(opener=opener).request(method, "https://sot.internal/sites")  # type: ignore[arg-type]
    assert opener.calls == []


@pytest.mark.parametrize("method", ["GET", "HEAD", "get", "head"])
def test_guard_allows_get_and_head(method: str) -> None:
    opener = _RecordingOpener(b"<html>ok</html>")
    guard = ReadOnlyHttpGuard(opener=opener)

    body = guard.request(
        method, "https://sot.internal/sites", headers={"User-Agent": "t"}, timeout=7.5
    )

    assert body == b"<html>ok</html>"
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.get_method() == method.upper()  # type: ignore[attr-defined]
    assert request.get_header("User-agent") == "t"  # type: ignore[attr-defined]
    assert timeout == 7.5


def test_guard_allowed_posts_match_exact_path_only() -> None:
    opener = _RecordingOpener(b"token")
    guard = ReadOnlyHttpGuard(opener=opener, allowed_posts={("POST", "/api/session")})

    assert guard.request("post", "https://vc01.internal/api/session") == b"token"
    assert len(opener.calls) == 1

    for url in (
        "https://vc01.internal/api/vcenter/vm",
        "https://vc01.internal/api/session/extra",
        "https://vc01.internal/API/SESSION",
    ):
        with pytest.raises(ReadOnlyViolation):
            guard.request("POST", url)
    with pytest.raises(ReadOnlyViolation):
        guard.request("PUT", "https://vc01.internal/api/session")
    assert len(opener.calls) == 1


def test_guard_violation_alias_and_empty_allowlist() -> None:
    assert ReadOnlyViolation is ReadOnlyViolationError
    assert READ_ONLY_POST_ALLOWLIST == frozenset()
    assert ReadOnlyHttpGuard(opener=_RecordingOpener())._allowed == frozenset()


# --- Static ast scan ---------------------------------------------------------


def _literal_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            for part in node.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        )
    return None


def _call_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_sqlite3_connect(func: ast.AST) -> bool:
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "connect"
        and isinstance(func.value, ast.Name)
        and func.value.id == "sqlite3"
    )


def scan_source_for_write_paths(source: str, rel_path: str) -> list[str]:
    """Return `rel_path:line: reason` entries for every read-only rule violation in `source`."""
    if rel_path == GUARD_MODULE:
        return []
    violations: list[str] = []
    for node in ast.walk(ast.parse(source, filename=rel_path)):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in {"Request", "urlopen"}:
            violations.append(f"{rel_path}:{node.lineno}: direct {name}() outside {GUARD_MODULE}")
        for kw in node.keywords:
            if kw.arg != "method":
                continue
            text = _literal_text(kw.value)
            if text is not None and text.strip().upper() in MUTATING_METHODS:
                violations.append(f"{rel_path}:{node.lineno}: mutating method={text!r} literal")
        if _is_sqlite3_connect(node.func):
            first = _literal_text(node.args[0]) if node.args else None
            if first == ":memory:" and rel_path in MEMORY_CONNECT_ALLOWED:
                continue
            uri_true = any(
                kw.arg == "uri" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if first is None or "mode=ro" not in first or not uri_true:
                violations.append(
                    f"{rel_path}:{node.lineno}: sqlite3.connect without literal mode=ro and uri=True"
                )
    return violations


def test_static_scan_package_has_no_write_paths() -> None:
    violations: list[str] = []
    scanned = 0
    for package in SCANNED_PACKAGES:
        for py_file in sorted((PACKAGE_ROOT / package).rglob("*.py")):
            rel_path = py_file.relative_to(PACKAGE_ROOT).as_posix()
            violations.extend(
                scan_source_for_write_paths(py_file.read_text(encoding="utf-8"), rel_path)
            )
            scanned += 1
    assert scanned > 3
    assert violations == []


@pytest.mark.parametrize(
    "source",
    [
        'urlopen("http://x")',
        'import urllib.request\nurllib.request.urlopen("http://x")',
        'req = Request("http://x")',
        'import urllib.request\nurllib.request.Request("http://x")',
    ],
)
def test_static_scan_detects_request_and_urlopen(source: str) -> None:
    violations = scan_source_for_write_paths(source, "signals/planted.py")
    assert violations and violations[0].startswith("signals/planted.py:")


@pytest.mark.parametrize("literal", ["POST", "put", "Patch", "DELETE"])
def test_static_scan_detects_mutating_method_literal(literal: str) -> None:
    violations = scan_source_for_write_paths(
        f'session.send("http://x", method="{literal}")', "connectors/planted.py"
    )
    assert any("mutating method" in v for v in violations)


def test_static_scan_ignores_read_only_method_literal() -> None:
    assert scan_source_for_write_paths('send("http://x", method="GET")', "signals/ok.py") == []


@pytest.mark.parametrize(
    "source",
    [
        'import sqlite3\nsqlite3.connect("export.db")',
        'import sqlite3\nsqlite3.connect(":memory:")',
        'import sqlite3\nsqlite3.connect("file:x.db?mode=ro")',
        'import sqlite3\nsqlite3.connect("file:x.db?mode=rw", uri=True)',
        'import sqlite3\nsqlite3.connect(path, uri=True)',
        'import sqlite3\nsqlite3.connect(f"file:{p}?mode=ro", uri=flag)',
    ],
)
def test_static_scan_detects_writable_sqlite_connect(source: str) -> None:
    violations = scan_source_for_write_paths(source, "extraction/planted.py")
    assert any("sqlite3.connect" in v for v in violations)


def test_static_scan_allows_read_only_and_named_memory_connects() -> None:
    assert scan_source_for_write_paths(
        'import sqlite3\nsqlite3.connect(f"file:{p}?mode=ro", uri=True)', "extraction/x.py"
    ) == []
    assert scan_source_for_write_paths(
        'import sqlite3\nsqlite3.connect(":memory:")', "extraction/sql_export.py"
    ) == []
    assert scan_source_for_write_paths('urlopen("http://x")', GUARD_MODULE) == []


# --- Default transports route through the guard --------------------------------


def _patch_guard(monkeypatch: pytest.MonkeyPatch, module: object, opener: _RecordingOpener) -> None:
    monkeypatch.setattr(module, "ReadOnlyHttpGuard", lambda: ReadOnlyHttpGuard(opener=opener))


def test_guard_backs_default_scraper_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    from sot_validator.extraction import scraper

    opener = _RecordingOpener(b"<p>caf\xc3\xa9 \xff</p>")
    _patch_guard(monkeypatch, scraper, opener)

    text = scraper._default_urllib_transport("get", "https://sot.internal/sites")

    assert text == "<p>café �</p>"
    request, timeout = opener.calls[0]
    assert request.get_method() == "GET"  # type: ignore[attr-defined]
    assert request.get_header("User-agent") == "sot-validator/0.1 (read-only)"  # type: ignore[attr-defined]
    assert timeout == 15


def test_guard_backs_default_live_connector_transports(monkeypatch: pytest.MonkeyPatch) -> None:
    from sot_validator.connectors import live

    opener = _RecordingOpener(b"<html/>")
    _patch_guard(monkeypatch, live, opener)
    session = live.AuthenticatedScraperSession("https://sot.internal")
    assert session._default_urlopen("GET", "https://sot.internal/x", {"A": "b"}, 3.0) == "<html/>"
    with pytest.raises(ReadOnlyViolation):
        session._default_urlopen("POST", "https://sot.internal/x", {}, 3.0)

    vsphere = live.VSphereRestConnector(["https://vc01.internal"])
    opener.body = b'{"value": [1]}'
    assert vsphere._default_urlopen("GET", "https://vc01.internal/api/vcenter/vm", {}, 3.0) == {
        "value": [1]
    }
    opener.body = b"  "
    assert vsphere._default_urlopen("GET", "https://vc01.internal/api/vcenter/vm", {}, 3.0) == []
    with pytest.raises(ReadOnlyViolation):
        vsphere._default_urlopen("DELETE", "https://vc01.internal/api/vcenter/vm", {}, 3.0)
    assert len(opener.calls) == 3
