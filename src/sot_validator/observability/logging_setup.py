"""Structured text/JSON logging, run/site log context, and key-based secret redaction.

``configure_logging`` installs a single handler on the ``sot_validator`` logger
(never the root logger). Records carry the current ``run_id`` / ``site_id`` from
``contextvars`` and every ``extra`` field, with values under secret-looking keys
(``password``, ``secret``, ``token``, ``community``, ``authorization``; matched
case-insensitively as substrings) replaced by ``REDACTION_MASK``. Message text
and positional args are not scanned.

Example::

    configure_logging("INFO", fmt="json")
    log = get_logger(__name__)
    with log_context(run_id="run-42", site_id="site-007"):
        log.info("site extracted", extra={"records": 120})

Thread propagation: ``contextvars`` do not flow into new threads by themselves.
A ``threading.Thread`` or ``ThreadPoolExecutor`` worker starts with an empty
context, so ``run_id`` / ``site_id`` are ``None`` there. Wrap the callable with
``wrap_with_context`` in the parent thread to carry the current values over::

    with log_context(run_id="run-42", site_id="site-007"):
        future = executor.submit(wrap_with_context(probe_subnet), subnet)
        thread = threading.Thread(target=wrap_with_context(worker))
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
import contextvars
from datetime import datetime, timezone
import functools
import json
import logging
import math
import sys
from typing import IO, Any, Optional, TypeVar, Union

ROOT_LOGGER_NAME = "sot_validator"
REDACTION_MASK = "***REDACTED***"
CYCLE_MARKER = "<cycle>"
SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "community",
    "authorization",
)
VALID_FORMATS: tuple[str, ...] = ("text", "json")

_run_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "sot_validator_run_id", default=None
)
_site_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "sot_validator_site_id", default=None
)

_UNSET: Any = object()
_HANDLER_MARKER = "_sot_validator_observability"
_STANDARD_RECORD_ATTRS = frozenset(
    logging.LogRecord("", logging.INFO, "", 0, "", (), None).__dict__
) | {"message", "asctime"}
_RESERVED_JSON_KEYS = frozenset(
    {"ts", "level", "logger", "msg", "run_id", "site_id", "exc_info"}
)

_T = TypeVar("_T")


def is_sensitive_key(key: Any) -> bool:
    """Return True when ``key`` contains a secret-looking fragment, case-insensitively.

    Matching is by substring, so keys such as ``tokens_count`` are masked too.
    """
    lowered = str(key).lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact(value: Any) -> Any:
    """Return a redacted copy of ``value``; the input object is never mutated.

    Dict values under sensitive keys become ``REDACTION_MASK``; dicts, lists and
    tuples are walked at any depth. A container that contains itself is replaced
    by ``CYCLE_MARKER`` where it recurs. Other values are returned unchanged.
    """
    return _redact(value, frozenset())


def _redact(value: Any, path: frozenset[int]) -> Any:
    if not isinstance(value, (Mapping, list, tuple)):
        return value
    if id(value) in path:
        return CYCLE_MARKER
    inner = path | {id(value)}
    if isinstance(value, Mapping):
        return {
            key: REDACTION_MASK if is_sensitive_key(key) else _redact(item, inner)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, inner) for item in value]
    return tuple(_redact(item, inner) for item in value)


def _extra_fields(record: logging.LogRecord) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.__dict__.items()
        if key not in _STANDARD_RECORD_ATTRS
    }


class RedactionFilter(logging.Filter):
    """Replace secret-looking ``extra`` field values on each record before formatting."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in _extra_fields(record).items():
            setattr(record, key, redact({key: value})[key])
        return True


def _utc_timestamp(record: logging.LogRecord) -> str:
    return datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()


def _json_safe(value: Any) -> Any:
    """Coerce mapping keys and non-finite floats to strings so output is strict JSON."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, Mapping):
        return {
            key if isinstance(key, str) else str(key): _json_safe(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    """Format each record as one single-line JSON object.

    Extras are redacted here as well as in ``RedactionFilter`` so the formatter is
    safe when used on a handler without the filter.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": _utc_timestamp(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "run_id": _run_id_var.get(),
            "site_id": _site_id_var.get(),
        }
        extras = _extra_fields(record)
        for key, value in extras.items():
            field_name = key
            while field_name in _RESERVED_JSON_KEYS or (field_name != key and field_name in extras):
                field_name = f"extra_{field_name}"
            payload[field_name] = redact({key: value})[key]
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(_json_safe(payload), default=str)


class TextFormatter(logging.Formatter):
    """Format each record as a human-readable line with ``key=value`` extras appended.

    Extras are redacted here as well, like ``JsonFormatter``.
    """

    def format(self, record: logging.LogRecord) -> str:
        parts = [
            _utc_timestamp(record),
            record.levelname,
            record.name,
            f"run_id={_run_id_var.get() or '-'}",
            f"site_id={_site_id_var.get() or '-'}",
            record.getMessage(),
        ]
        for key, value in _extra_fields(record).items():
            rendered = json.dumps(_json_safe(redact({key: value})[key]), default=str)
            parts.append(f"{key}={rendered}")
        line = " ".join(parts)
        if record.exc_info:
            line = f"{line}\n{self.formatException(record.exc_info)}"
        return line


def _resolve_level(level: Union[int, str]) -> int:
    if isinstance(level, bool):
        raise ValueError(f"Invalid log level: {level!r}")
    if isinstance(level, int):
        return level
    if isinstance(level, str):
        resolved = logging.getLevelNamesMapping().get(level.strip().upper())
        if resolved is not None:
            return resolved
    raise ValueError(f"Invalid log level: {level!r}")


def configure_logging(
    level: Union[int, str],
    fmt: str = "text",
    stream: Optional[IO[str]] = None,
) -> logging.Handler:
    """Install the observability handler on the ``sot_validator`` logger.

    Replaces any handler a previous call installed; handlers added by others and
    the root logger are left alone. Returns the installed handler.
    """
    if fmt not in VALID_FORMATS:
        raise ValueError(f"fmt must be one of {VALID_FORMATS}, got {fmt!r}")
    resolved_level = _resolve_level(level)

    logger = logging.getLogger(ROOT_LOGGER_NAME)
    for existing in list(logger.handlers):
        if getattr(existing, _HANDLER_MARKER, False):
            logger.removeHandler(existing)
            existing.close()

    handler = logging.StreamHandler(sys.stderr if stream is None else stream)
    setattr(handler, _HANDLER_MARKER, True)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    handler.addFilter(RedactionFilter())
    logger.addHandler(handler)
    logger.setLevel(resolved_level)
    return handler


def get_logger(name: str) -> logging.Logger:
    """Return a standard logger inside the ``sot_validator`` logger tree."""
    if not name:
        raise ValueError("Logger name must be a non-empty string")
    if name == ROOT_LOGGER_NAME or name.startswith(f"{ROOT_LOGGER_NAME}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{ROOT_LOGGER_NAME}.{name}")


def get_log_context() -> dict[str, Optional[str]]:
    """Return the current ``run_id`` and ``site_id`` (``None`` when unset)."""
    return {"run_id": _run_id_var.get(), "site_id": _site_id_var.get()}


@contextmanager
def log_context(
    run_id: Any = _UNSET,
    site_id: Any = _UNSET,
) -> Iterator[None]:
    """Set ``run_id`` and/or ``site_id`` for the block and restore the outer values on exit.

    Only the arguments passed are changed, so ``log_context(site_id=...)`` inside a
    run keeps the outer ``run_id``.
    """
    tokens: list[tuple[contextvars.ContextVar[Optional[str]], contextvars.Token]] = []
    try:
        if run_id is not _UNSET:
            tokens.append((_run_id_var, _run_id_var.set(run_id)))
        if site_id is not _UNSET:
            tokens.append((_site_id_var, _site_id_var.set(site_id)))
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


def wrap_with_context(fn: Callable[..., _T]) -> Callable[..., _T]:
    """Return ``fn`` bound to a copy of the caller's current context.

    Call this in the parent thread; each invocation of the returned callable runs
    in its own copy of that snapshot, so it is safe to call concurrently (for
    example from ``executor.map``).
    """
    snapshot = contextvars.copy_context()

    @functools.wraps(fn)
    def runner(*args: Any, **kwargs: Any) -> _T:
        return snapshot.copy().run(fn, *args, **kwargs)

    return runner


def run_in_context(fn: Callable[..., _T], *args: Any, **kwargs: Any) -> Callable[[], _T]:
    """Return a zero-argument callable running ``fn(*args, **kwargs)`` in the current context.

    Convenient as a thread target: ``threading.Thread(target=run_in_context(fn, x))``.
    """
    wrapped = wrap_with_context(fn)
    return lambda: wrapped(*args, **kwargs)
