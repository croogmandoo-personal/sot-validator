"""Transport-level read-only HTTP guard: the single place extraction/signals/connectors open URLs."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any, Optional
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from sot_validator.extraction.client import ReadOnlyViolationError

ReadOnlyViolation = ReadOnlyViolationError

_READ_ONLY_METHODS = frozenset({"GET", "HEAD"})

# (METHOD, path) pairs for non-GET/HEAD calls that are known to be read-only.
# Every entry added here MUST carry its own comment explaining why the call
# cannot mutate state (e.g. vCenter `POST /api/session` only creates a session token).
READ_ONLY_POST_ALLOWLIST: frozenset[tuple[str, str]] = frozenset()


class ReadOnlyHttpGuard:
    """Allow only GET/HEAD (plus allow-listed read-only calls) before any request is built."""

    def __init__(
        self,
        *,
        opener: Callable[..., Any] = urlopen,
        allowed_posts: Optional[Iterable[tuple[str, str]]] = None,
    ) -> None:
        self._opener = opener
        extra = {
            (str(method).strip().upper(), str(path))
            for method, path in (allowed_posts or ())
        }
        self._allowed: frozenset[tuple[str, str]] = READ_ONLY_POST_ALLOWLIST | extra

    def check(self, method: Any, url: str) -> str:
        """Return the normalised method, or raise ReadOnlyViolation if it may mutate state."""
        if not isinstance(method, str) or not method.strip():
            raise ReadOnlyViolation("HTTP method must be a non-empty string")
        normalized = method.strip().upper()
        if normalized in _READ_ONLY_METHODS:
            return normalized
        if (normalized, urlsplit(url).path) in self._allowed:
            return normalized
        raise ReadOnlyViolation(
            f"HTTP method {normalized!r} is forbidden by ReadOnlyHttpGuard; "
            f"only {sorted(_READ_ONLY_METHODS)} or allow-listed read-only calls are permitted"
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        timeout: float = 15.0,
    ) -> bytes:
        """Validate the method, then open the URL and return the raw response bytes."""
        normalized = self.check(method, url)
        req = Request(url, method=normalized, headers=dict(headers or {}))
        with self._opener(req, timeout=timeout) as resp:
            raw_bytes: bytes = resp.read()
            return raw_bytes
