"""Read-only live pilot connector transports for SoT HTML scraping, vSphere REST, and SNMP."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
import inspect
import json
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from sot_validator.extraction.client import (
    ReadOnlyViolationError as ExtractionReadOnlyViolationError,
    validate_read_only_request,
)
from sot_validator.signals.hypervisor import (
    HypervisorVmRecord,
    MultiVCenterInventoryProvider,
)
from sot_validator.signals.icmp import (
    ScopeViolationError,
    SubnetScopeGuard,
    _parse_ipv4_host,
)
from sot_validator.signals.management import (
    ALLOWED_HTTP_METHODS,
    ALLOWED_SNMP_OPERATIONS,
    APC_POWERNET_MIB_OIDS,
    EXTREME_MIB_OIDS,
    IF_MIB_OIDS,
    IP_MIB_OIDS,
    ReadOnlyViolationError as ManagementReadOnlyViolationError,
    SNMPV2_MIB_OIDS,
    parse_apc_ups_oids,
    parse_extreme_switch_oids,
)

# ---------------------------------------------------------------------------
# Phase 4 Canonical MIB OID Constants (LLDP-MIB, POWER-ETHERNET-MIB, Composites)
# ---------------------------------------------------------------------------

LLDP_REM_PORT_ID_PREFIX = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC_PREFIX = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME_PREFIX = "1.0.8802.1.1.2.1.4.1.1.9"

LLDP_MIB_OIDS: tuple[str, ...] = (
    LLDP_REM_PORT_ID_PREFIX,
    LLDP_REM_PORT_DESC_PREFIX,
    LLDP_REM_SYS_NAME_PREFIX,
)

PETH_PSE_PORT_ADMIN_ENABLE_PREFIX = "1.3.6.1.2.1.105.1.1.1.3"
PETH_PSE_PORT_DETECTION_STATUS_PREFIX = "1.3.6.1.2.1.105.1.1.1.6"

POWER_ETHERNET_MIB_OIDS: tuple[str, ...] = (
    PETH_PSE_PORT_ADMIN_ENABLE_PREFIX,
    PETH_PSE_PORT_DETECTION_STATUS_PREFIX,
)

EXTREME_SWITCH_MIB_OIDS: tuple[str, ...] = (
    SNMPV2_MIB_OIDS
    + IF_MIB_OIDS
    + IP_MIB_OIDS
    + LLDP_MIB_OIDS
    + POWER_ETHERNET_MIB_OIDS
    + EXTREME_MIB_OIDS
)

APC_UPS_MIB_OIDS: tuple[str, ...] = SNMPV2_MIB_OIDS + APC_POWERNET_MIB_OIDS

_ALLOWED_READONLY_MODES: frozenset[str] = frozenset(
    {"readonly", "read_only", "read-only", "ro"}
)

_FORBIDDEN_WRITE_COMMUNITIES: frozenset[str] = frozenset(
    {"private", "write", "rw", "read-write", "readwrite", "admin-rw", "private-rw"}
)

_ALLOWED_VCENTER_PATH_PREFIXES: tuple[str, ...] = (
    "/api/vcenter/vm",
    "/api/vcenter/host",
    "/api/cis/session",
)

_BLOCKED_VCENTER_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "power",
        "reset",
        "reboot",
        "shutdown",
        "suspend",
        "delete",
        "create",
        "action",
        "reconfigure",
        "relocate",
        "migrate",
        "clone",
        "mount",
        "unmount",
        "disconnect",
        "maintenance",
    }
)


class ConnectorReadOnlyError(
    ManagementReadOnlyViolationError, ExtractionReadOnlyViolationError
):
    """Raised when a live connector blocks a mutating HTTP, vCenter REST, or SNMP operation."""


@dataclass
class RequestTelemetry:
    """Operational request counters and latency metrics for a live connector."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    retried_requests: int = 0
    blocked_mutations: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    last_target: Optional[str] = None
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def average_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return round(sum(self.latencies_ms) / len(self.latencies_ms), 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "retried_requests": self.retried_requests,
            "blocked_mutations": self.blocked_mutations,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "last_target": self.last_target,
            "latencies_ms": list(self.latencies_ms),
            "average_latency_ms": self.average_latency_ms,
        }


def _validate_timeout_and_retries(
    timeout_seconds: float,
    max_retries: int,
    backoff_seconds: float,
) -> tuple[float, int, float]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a number > 0")
    if (
        isinstance(max_retries, bool)
        or not isinstance(max_retries, int)
        or max_retries < 0
    ):
        raise ValueError("max_retries must be an integer >= 0")
    if (
        isinstance(backoff_seconds, bool)
        or not isinstance(backoff_seconds, (int, float))
        or backoff_seconds < 0
    ):
        raise ValueError("backoff_seconds must be a number >= 0")
    return float(timeout_seconds), int(max_retries), float(backoff_seconds)


class AuthenticatedScraperSession:
    """HTTP GET/HEAD-only authenticated session wrapper for the legacy SoT web UI."""

    def __init__(
        self,
        base_url: str = "https://sot.internal",
        *,
        headers: Optional[Mapping[str, str]] = None,
        cookies: Optional[Mapping[str, str]] = None,
        session_token: Optional[str] = None,
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.0,
        transport: Optional[Callable[..., str | bytes | Mapping[str, Any]]] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be a non-empty URL string")
        cleaned_url = base_url.strip().rstrip("/")
        if not cleaned_url.startswith(("http://", "https://")):
            raise ValueError(
                f"base_url must start with 'http://' or 'https://', got {base_url!r}"
            )
        (
            self.timeout_seconds,
            self.max_retries,
            self.backoff_seconds,
        ) = _validate_timeout_and_retries(timeout_seconds, max_retries, backoff_seconds)
        self.base_url: str = cleaned_url
        self._headers: dict[str, str] = (
            {str(k): str(v) for k, v in headers.items()} if headers else {}
        )
        self._cookies: dict[str, str] = (
            {str(k): str(v) for k, v in cookies.items()} if cookies else {}
        )
        self.session_token: Optional[str] = (
            session_token.strip()
            if isinstance(session_token, str) and session_token.strip()
            else None
        )
        self._transport = transport
        self._sleep_fn = sleep_fn
        self.telemetry = RequestTelemetry()

    def build_request_headers(self) -> dict[str, str]:
        """Build merged HTTP headers including User-Agent, Cookie, and Authorization."""
        merged: dict[str, str] = {
            "User-Agent": "sot-validator/0.1 (live-pilot; read-only)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }
        merged.update(self._headers)
        if self._cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            if "Cookie" in merged and merged["Cookie"]:
                merged["Cookie"] = f"{merged['Cookie']}; {cookie_str}"
            else:
                merged["Cookie"] = cookie_str
        if self.session_token and "Authorization" not in merged:
            merged["Authorization"] = f"Bearer {self.session_token}"
        return merged

    def _resolve_url(self, path_or_url: str) -> str:
        if not isinstance(path_or_url, str) or not path_or_url.strip():
            raise ValueError("path_or_url must be a non-empty string")
        raw = path_or_url.strip()
        if raw.startswith(("http://", "https://")):
            return raw
        if not raw.startswith("/"):
            raw = "/" + raw
        return urljoin(self.base_url + "/", raw.lstrip("/"))

    def _validate_read_only(self, method: str, full_url: str) -> str:
        if not isinstance(method, str) or not method.strip():
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError("HTTP method must be a non-empty string")
        normalized_method = method.strip().upper()
        if normalized_method not in ALLOWED_HTTP_METHODS:
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(
                f"HTTP method {normalized_method!r} is forbidden in read-only scraper session; "
                f"only {sorted(ALLOWED_HTTP_METHODS)} are allowed"
            )
        try:
            validate_read_only_request(normalized_method, full_url)
        except ExtractionReadOnlyViolationError as exc:
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(str(exc)) from exc
        return normalized_method

    def _default_urlopen(
        self,
        method: str,
        full_url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> str:
        req = Request(full_url, method=method, headers=dict(headers))
        with urlopen(req, timeout=timeout) as resp:
            raw_bytes: bytes = resp.read()
            return raw_bytes.decode("utf-8", errors="replace")

    def _invoke_transport(
        self,
        method: str,
        full_url: str,
        timeout: float,
    ) -> str:
        headers = self.build_request_headers()
        if self._transport is None:
            return self._default_urlopen(method, full_url, headers, timeout)

        sig = inspect.signature(self._transport)
        pos_params = [
            p
            for p in sig.parameters.values()
            if p.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        has_varargs = any(
            p.kind == inspect.Parameter.VAR_POSITIONAL
            for p in sig.parameters.values()
        )

        if len(pos_params) >= 4 or has_varargs:
            raw = self._transport(method, full_url, headers, timeout)
        elif len(pos_params) == 3:
            third_name = pos_params[2].name.lower()
            if "header" in third_name:
                raw = self._transport(method, full_url, headers)
            else:
                raw = self._transport(method, full_url, timeout)
        else:
            raw = self._transport(method, full_url)

        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        if isinstance(raw, Mapping):
            if "body" in raw:
                return str(raw["body"])
            if "text" in raw:
                return str(raw["text"])
            return json.dumps(dict(raw))
        return str(raw)

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> str:
        """Execute a validated GET or HEAD request with timeout, retries, and telemetry."""
        full_url = self._resolve_url(path_or_url)
        normalized_method = self._validate_read_only(method, full_url)

        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self.timeout_seconds
        )
        if effective_timeout <= 0:
            raise ValueError("timeout_seconds must be > 0")

        self.telemetry.total_requests += 1
        self.telemetry.last_target = full_url

        total_attempts = 1 + self.max_retries
        last_exc: Optional[Exception] = None

        for attempt in range(1, total_attempts + 1):
            if attempt > 1:
                self.telemetry.retried_requests += 1
                if self.backoff_seconds > 0:
                    self._sleep_fn(self.backoff_seconds * (2 ** (attempt - 2)))

            start = time.monotonic()
            try:
                response_text = self._invoke_transport(
                    normalized_method, full_url, effective_timeout
                )
            except PermissionError as exc:
                self.telemetry.blocked_mutations += 1
                self.telemetry.failed_requests += 1
                if isinstance(exc, ConnectorReadOnlyError):
                    raise
                raise ConnectorReadOnlyError(str(exc)) from exc
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue

            elapsed_ms = round((time.monotonic() - start) * 1000.0, 3)
            self.telemetry.latencies_ms.append(elapsed_ms)
            self.telemetry.successful_requests += 1
            return response_text

        self.telemetry.failed_requests += 1
        assert last_exc is not None
        raise last_exc

    def get(
        self,
        path_or_url: str,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> str:
        """Perform a read-only HTTP GET request."""
        return self.request("GET", path_or_url, timeout_seconds=timeout_seconds)

    def head(
        self,
        path_or_url: str,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> str:
        """Perform a read-only HTTP HEAD request."""
        return self.request("HEAD", path_or_url, timeout_seconds=timeout_seconds)

    def __call__(self, method: str, path_or_url: str) -> str:
        """Allow AuthenticatedScraperSession to act directly as HtmlScraperSoTClient transport."""
        return self.request(method, path_or_url)

    def check_health(self, path: str = "/sites") -> bool:
        """Perform a read-only GET probe against `path` and return True when reachable."""
        try:
            body = self.get(path)
            return bool(body and body.strip())
        except ConnectorReadOnlyError:
            raise
        except Exception:  # noqa: BLE001
            return False


class VSphereRestConnector:
    """Read-only VMware vCenter REST connector with multi-instance inventory caching."""

    def __init__(
        self,
        instances: Sequence[str | Mapping[str, Any]],
        *,
        auth_token: Optional[str] = None,
        username: Optional[str] = None,
        role: str = "readonly",
        api_mode: str = "readonly",
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.0,
        cache_ttl_seconds: Optional[float] = 300.0,
        transport: Optional[Callable[..., Any]] = None,
        clock_fn: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if not instances:
            raise ValueError("instances must be a non-empty sequence of vCenter targets")

        if (
            not isinstance(api_mode, str)
            or api_mode.strip().lower() not in _ALLOWED_READONLY_MODES
        ):
            raise ConnectorReadOnlyError(
                f"vCenter api_mode {api_mode!r} is forbidden; must be one of {sorted(_ALLOWED_READONLY_MODES)}"
            )
        if (
            not isinstance(role, str)
            or role.strip().lower() not in _ALLOWED_READONLY_MODES
        ):
            raise ConnectorReadOnlyError(
                f"vCenter role {role!r} is forbidden; must be read-only"
            )

        (
            self.timeout_seconds,
            self.max_retries,
            self.backoff_seconds,
        ) = _validate_timeout_and_retries(timeout_seconds, max_retries, backoff_seconds)

        if cache_ttl_seconds is not None:
            if (
                isinstance(cache_ttl_seconds, bool)
                or not isinstance(cache_ttl_seconds, (int, float))
                or cache_ttl_seconds <= 0
            ):
                raise ValueError("cache_ttl_seconds must be None or a number > 0")
            self.cache_ttl_seconds: Optional[float] = float(cache_ttl_seconds)
        else:
            self.cache_ttl_seconds = None

        self.auth_token: Optional[str] = (
            auth_token.strip()
            if isinstance(auth_token, str) and auth_token.strip()
            else None
        )
        self.username: Optional[str] = (
            username.strip() if isinstance(username, str) and username.strip() else None
        )
        self.role: str = role.strip().lower()
        self.api_mode: str = api_mode.strip().lower()
        self._transport = transport
        self._clock_fn = clock_fn
        self._sleep_fn = sleep_fn
        self.telemetry = RequestTelemetry()

        self._instance_configs: dict[str, dict[str, Any]] = {}
        self._instance_order: list[str] = []
        self.unreachable_instances: set[str] = set()

        for item in instances:
            if isinstance(item, str):
                inst_id = item.strip()
                if not inst_id:
                    raise ValueError("vCenter instance hostname must be non-empty")
                if inst_id not in self._instance_configs:
                    self._instance_order.append(inst_id)
                self._instance_configs[inst_id] = {"vcenter_instance": inst_id}
            elif isinstance(item, Mapping):
                inst_mode = item.get("api_mode") or item.get("mode")
                if (
                    inst_mode is not None
                    and str(inst_mode).strip().lower() not in _ALLOWED_READONLY_MODES
                ):
                    raise ConnectorReadOnlyError(
                        f"vCenter instance mode {inst_mode!r} is forbidden; must be read-only"
                    )
                inst_role = item.get("role")
                if (
                    inst_role is not None
                    and str(inst_role).strip().lower() not in _ALLOWED_READONLY_MODES
                ):
                    raise ConnectorReadOnlyError(
                        f"vCenter instance role {inst_role!r} is forbidden; must be read-only"
                    )
                inst_id_raw = (
                    item.get("vcenter_instance")
                    or item.get("host")
                    or item.get("vcenter_host")
                    or item.get("instance")
                    or item.get("name")
                )
                if not isinstance(inst_id_raw, str) or not inst_id_raw.strip():
                    raise ValueError(
                        f"vCenter instance mapping missing 'vcenter_instance' or 'host': {item!r}"
                    )
                inst_id = inst_id_raw.strip()
                if inst_id not in self._instance_configs:
                    self._instance_order.append(inst_id)
                self._instance_configs[inst_id] = dict(item)
                if item.get("reachable") is False or (
                    isinstance(item.get("status"), str)
                    and item["status"].strip().lower()
                    in {"unreachable", "down", "error", "offline"}
                ):
                    self.unreachable_instances.add(inst_id)
            else:
                raise ValueError(f"Unsupported vCenter instance entry: {item!r}")

        self._vm_cache: dict[str, tuple[float, list[HypervisorVmRecord]]] = {}
        self._host_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    @property
    def configured_instances(self) -> list[str]:
        """Return ordered list of configured vCenter instance identifiers."""
        return list(self._instance_order)

    def _build_headers(self, instance: str) -> dict[str, str]:
        cfg = self._instance_configs.get(instance, {})
        token = cfg.get("auth_token") or self.auth_token
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "sot-validator/0.1 (vsphere-ro)",
        }
        if token:
            headers["vmware-api-session-id"] = str(token)
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _validate_read_only(self, method: str, path_or_url: str) -> tuple[str, str]:
        if not isinstance(method, str) or not method.strip():
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError("HTTP method must be a non-empty string")

        normalized_method = method.strip().upper()
        if normalized_method not in ALLOWED_HTTP_METHODS:
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(
                f"vCenter REST method {normalized_method!r} is forbidden in read-only mode; "
                f"only {sorted(ALLOWED_HTTP_METHODS)} are allowed"
            )

        parsed = urlsplit(path_or_url)
        norm_path = parsed.path or "/"
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        path_lower = norm_path.lower().rstrip("/") or "/"

        if not any(
            path_lower == prefix or path_lower.startswith(prefix + "/")
            for prefix in _ALLOWED_VCENTER_PATH_PREFIXES
        ):
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(
                f"vCenter endpoint {norm_path!r} is outside allowed read-only inventory paths "
                f"{_ALLOWED_VCENTER_PATH_PREFIXES}"
            )

        segments = [seg for seg in path_lower.split("/") if seg]
        for seg in segments:
            if seg in _BLOCKED_VCENTER_PATH_SEGMENTS:
                self.telemetry.blocked_mutations += 1
                raise ConnectorReadOnlyError(
                    f"vCenter endpoint {norm_path!r} contains mutating segment {seg!r}"
                )

        try:
            validate_read_only_request(normalized_method, path_or_url)
        except ExtractionReadOnlyViolationError as exc:
            self.telemetry.blocked_mutations += 1
            raise ConnectorReadOnlyError(str(exc)) from exc

        return normalized_method, norm_path

    def _default_urlopen(
        self,
        method: str,
        full_url: str,
        headers: Mapping[str, str],
        timeout: float,
    ) -> Any:
        req = Request(full_url, method=method, headers=dict(headers))
        with urlopen(req, timeout=timeout) as resp:
            raw_bytes: bytes = resp.read()
            text = raw_bytes.decode("utf-8", errors="replace").strip()
            return json.loads(text) if text else []

    def _invoke_transport(
        self,
        method: str,
        instance: str,
        norm_path: str,
        full_url: str,
        timeout: float,
    ) -> Any:
        headers = self._build_headers(instance)
        if self._transport is None:
            return self._default_urlopen(method, full_url, headers, timeout)

        sig = inspect.signature(self._transport)
        pos_params = [
            p
            for p in sig.parameters.values()
            if p.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        has_varargs = any(
            p.kind == inspect.Parameter.VAR_POSITIONAL
            for p in sig.parameters.values()
        )

        if len(pos_params) >= 4 or has_varargs:
            raw = self._transport(method, full_url, headers, timeout)
        elif len(pos_params) == 3:
            first_name = pos_params[0].name.lower()
            if first_name in {"instance", "inst", "vcenter", "vcenter_instance", "host"}:
                raw = self._transport(instance, norm_path, timeout)
            else:
                raw = self._transport(method, full_url, timeout)
        elif len(pos_params) == 2:
            first_name = pos_params[0].name.lower()
            second_name = pos_params[1].name.lower()
            if first_name in {
                "instance",
                "inst",
                "vcenter",
                "vcenter_instance",
                "host",
            } or (
                second_name in {"path", "endpoint"}
                and first_name not in {"method", "verb", "http_method"}
            ):
                raw = self._transport(instance, norm_path)
            else:
                raw = self._transport(method, full_url)
        elif len(pos_params) == 1:
            raw = self._transport(full_url)
        else:
            raw = self._transport()

        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if isinstance(raw, str):
            stripped = raw.strip()
            if stripped.startswith(("{", "[")):
                return json.loads(stripped)
        return raw

    def request(
        self,
        method: str,
        instance: str,
        path: str = "/api/vcenter/vm",
        *,
        timeout_seconds: Optional[float] = None,
    ) -> Any:
        """Issue a read-only vCenter REST API request with retries and telemetry."""
        if not isinstance(instance, str) or not instance.strip():
            raise ValueError("instance must be a non-empty vCenter hostname/identifier")
        clean_instance = instance.strip()

        normalized_method, norm_path = self._validate_read_only(method, path)
        if path.strip().startswith(("http://", "https://")):
            full_url = path.strip()
        else:
            full_url = f"https://{clean_instance}{norm_path}"

        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self.timeout_seconds
        )
        if effective_timeout <= 0:
            raise ValueError("timeout_seconds must be > 0")

        self.telemetry.total_requests += 1
        self.telemetry.last_target = full_url

        if (
            self._transport is None
            and clean_instance in self.unreachable_instances
        ):
            self.telemetry.failed_requests += 1
            raise ConnectionError(
                f"vCenter instance {clean_instance!r} is marked unreachable"
            )

        total_attempts = 1 + self.max_retries
        last_exc: Optional[Exception] = None

        for attempt in range(1, total_attempts + 1):
            if attempt > 1:
                self.telemetry.retried_requests += 1
                if self.backoff_seconds > 0:
                    self._sleep_fn(self.backoff_seconds * (2 ** (attempt - 2)))

            start = self._clock_fn()
            try:
                payload = self._invoke_transport(
                    normalized_method,
                    clean_instance,
                    norm_path,
                    full_url,
                    effective_timeout,
                )
            except PermissionError as exc:
                self.telemetry.blocked_mutations += 1
                self.telemetry.failed_requests += 1
                if isinstance(exc, ConnectorReadOnlyError):
                    raise
                raise ConnectorReadOnlyError(str(exc)) from exc
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue

            elapsed_ms = round(max(0.0, (self._clock_fn() - start) * 1000.0), 3)
            self.telemetry.latencies_ms.append(elapsed_ms)
            self.telemetry.successful_requests += 1
            return payload

        self.telemetry.failed_requests += 1
        self.unreachable_instances.add(clean_instance)
        assert last_exc is not None
        raise last_exc

    def _is_cache_valid(self, cached_at: float) -> bool:
        if self.cache_ttl_seconds is None:
            return True
        return (self._clock_fn() - cached_at) < self.cache_ttl_seconds

    def _normalize_vm_payload(
        self,
        instance: str,
        raw_payload: Any,
    ) -> list[HypervisorVmRecord]:
        cfg = self._instance_configs.get(instance, {})
        default_site_id = cfg.get("site_id")

        if isinstance(raw_payload, Mapping):
            if "value" in raw_payload and isinstance(raw_payload["value"], Sequence):
                items = raw_payload["value"]
            elif "vms" in raw_payload and isinstance(raw_payload["vms"], Sequence):
                items = raw_payload["vms"]
            elif "vm_moref" in raw_payload or "vm" in raw_payload or "name" in raw_payload:
                items = [raw_payload]
            else:
                items = []
        elif isinstance(raw_payload, Sequence) and not isinstance(
            raw_payload, (str, bytes)
        ):
            items = raw_payload
        else:
            items = []

        records: list[HypervisorVmRecord] = []
        for item in items:
            if isinstance(item, HypervisorVmRecord):
                records.append(item)
            elif isinstance(item, Mapping):
                vm_dict = dict(item)
                if "vm" in vm_dict and "vm_moref" not in vm_dict:
                    vm_dict["vm_moref"] = vm_dict["vm"]
                if default_site_id and not vm_dict.get("site_id"):
                    vm_dict["site_id"] = default_site_id
                records.append(
                    HypervisorVmRecord.from_dict(
                        vm_dict, default_vcenter_instance=instance
                    )
                )
            else:
                raise ValueError(
                    f"Unsupported VM record in vCenter payload for {instance!r}: {item!r}"
                )
        return records

    def _normalize_host_payload(
        self,
        instance: str,
        raw_payload: Any,
    ) -> list[dict[str, Any]]:
        if isinstance(raw_payload, Mapping):
            if "value" in raw_payload and isinstance(raw_payload["value"], Sequence):
                items = raw_payload["value"]
            elif "hosts" in raw_payload and isinstance(raw_payload["hosts"], Sequence):
                items = raw_payload["hosts"]
            else:
                items = [raw_payload]
        elif isinstance(raw_payload, Sequence) and not isinstance(
            raw_payload, (str, bytes)
        ):
            items = raw_payload
        else:
            items = []

        hosts: list[dict[str, Any]] = []
        for item in items:
            if isinstance(item, Mapping):
                entry = dict(item)
                host_id = (
                    entry.get("host")
                    or entry.get("host_id")
                    or entry.get("name")
                    or "host-unknown"
                )
                entry.setdefault("vcenter_instance", instance)
                entry.setdefault("host", str(host_id))
                entry.setdefault(
                    "connection_state",
                    str(entry.get("connection_state") or "CONNECTED"),
                )
                entry.setdefault(
                    "power_state",
                    str(entry.get("power_state") or "POWERED_ON"),
                )
                hosts.append(entry)
        return hosts

    def fetch_vms(
        self,
        instance: Optional[str] = None,
        *,
        force_refresh: bool = False,
    ) -> list[HypervisorVmRecord]:
        """Fetch and cache normalized HypervisorVmRecord objects for one or all vCenters."""
        if instance is not None:
            clean_inst = instance.strip()
            if not force_refresh and clean_inst in self._vm_cache:
                cached_at, cached_vms = self._vm_cache[clean_inst]
                if self._is_cache_valid(cached_at):
                    self.telemetry.cache_hits += 1
                    return list(cached_vms)

            self.telemetry.cache_misses += 1
            raw = self.request("GET", clean_inst, "/api/vcenter/vm")
            records = self._normalize_vm_payload(clean_inst, raw)
            self._vm_cache[clean_inst] = (self._clock_fn(), records)
            self.unreachable_instances.discard(clean_inst)
            return list(records)

        combined: list[HypervisorVmRecord] = []
        for inst_id in self._instance_order:
            try:
                combined.extend(self.fetch_vms(inst_id, force_refresh=force_refresh))
            except ConnectorReadOnlyError:
                raise
            except Exception:  # noqa: BLE001
                self.unreachable_instances.add(inst_id)
        return combined

    def fetch_hosts(
        self,
        instance: Optional[str] = None,
        *,
        force_refresh: bool = False,
    ) -> list[dict[str, Any]]:
        """Fetch and cache ESXi host summaries (`/api/vcenter/host`) for one or all vCenters."""
        if instance is not None:
            clean_inst = instance.strip()
            if not force_refresh and clean_inst in self._host_cache:
                cached_at, cached_hosts = self._host_cache[clean_inst]
                if self._is_cache_valid(cached_at):
                    self.telemetry.cache_hits += 1
                    return [dict(h) for h in cached_hosts]

            self.telemetry.cache_misses += 1
            raw = self.request("GET", clean_inst, "/api/vcenter/host")
            hosts = self._normalize_host_payload(clean_inst, raw)
            self._host_cache[clean_inst] = (self._clock_fn(), hosts)
            self.unreachable_instances.discard(clean_inst)
            return [dict(h) for h in hosts]

        combined: list[dict[str, Any]] = []
        for inst_id in self._instance_order:
            try:
                combined.extend(self.fetch_hosts(inst_id, force_refresh=force_refresh))
            except ConnectorReadOnlyError:
                raise
            except Exception:  # noqa: BLE001
                self.unreachable_instances.add(inst_id)
        return combined

    def invalidate_cache(self, instance: Optional[str] = None) -> None:
        """Clear cached VM and ESXi host inventory for one or all vCenter instances."""
        if instance is None:
            self._vm_cache.clear()
            self._host_cache.clear()
        else:
            clean_inst = instance.strip()
            self._vm_cache.pop(clean_inst, None)
            self._host_cache.pop(clean_inst, None)

    def to_inventory_provider(
        self,
        *,
        force_refresh: bool = False,
    ) -> MultiVCenterInventoryProvider:
        """Build a MultiVCenterInventoryProvider from cached/fetched vCenter VM inventory."""
        vms = self.fetch_vms(force_refresh=force_refresh)
        return MultiVCenterInventoryProvider(
            vms=vms,
            instances=self._instance_order,
            unreachable_instances=self.unreachable_instances,
        )


def _validate_snmp_readonly_config(
    *,
    operation: str = "GET",
    mode: str = "readonly",
    community: Optional[str] = None,
) -> str:
    if not isinstance(mode, str) or mode.strip().lower() not in _ALLOWED_READONLY_MODES:
        raise ConnectorReadOnlyError(
            f"SNMP mode {mode!r} is prohibited; only read-only mode is allowed"
        )
    if community is not None and isinstance(community, str):
        comm_lower = community.strip().lower()
        if comm_lower in _FORBIDDEN_WRITE_COMMUNITIES or comm_lower.endswith(
            ("-rw", "_rw", "-write", "_write")
        ):
            raise ConnectorReadOnlyError(
                f"SNMP community {community!r} is a write community; strictly read-only community required"
            )
    if not isinstance(operation, str) or not operation.strip():
        raise ConnectorReadOnlyError("SNMP operation must be a non-empty string")
    op_upper = operation.strip().upper()
    if op_upper not in ALLOWED_SNMP_OPERATIONS:
        raise ConnectorReadOnlyError(
            f"SNMP operation {operation!r} is strictly prohibited in read-only mode; "
            f"only {sorted(ALLOWED_SNMP_OPERATIONS)} are allowed"
        )
    return op_upper


class SnmpWalkConnector:
    """Read-only SNMP GET/GETNEXT/GETBULK/WALK connector for Extreme switches and APC UPSs."""

    def __init__(
        self,
        *,
        community: Optional[str] = "public-ro",
        snmp_v3_user: Optional[str] = None,
        version: str = "2c",
        mode: str = "readonly",
        port: int = 161,
        timeout_seconds: float = 2.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.0,
        scope_guard: Optional[SubnetScopeGuard] = None,
        transport: Optional[Callable[..., Optional[Mapping[str, Any]]]] = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        _validate_snmp_readonly_config(
            operation="GET",
            mode=mode,
            community=community,
        )

        norm_version = (
            version.strip().lower().removeprefix("v")
            if isinstance(version, str)
            else ""
        )
        if norm_version not in {"2c", "3"}:
            raise ValueError(
                f"Unsupported SNMP version {version!r}; must be '2c' or '3'"
            )
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("port must be an integer between 1 and 65535")

        (
            self.timeout_seconds,
            self.max_retries,
            self.backoff_seconds,
        ) = _validate_timeout_and_retries(timeout_seconds, max_retries, backoff_seconds)

        self.community: Optional[str] = (
            community.strip()
            if isinstance(community, str) and community.strip()
            else None
        )
        self.snmp_v3_user: Optional[str] = (
            snmp_v3_user.strip()
            if isinstance(snmp_v3_user, str) and snmp_v3_user.strip()
            else None
        )
        self.version: str = norm_version
        self.mode: str = "readonly"
        self.port: int = port
        self.scope_guard: Optional[SubnetScopeGuard] = scope_guard
        self._transport = transport
        self._sleep_fn = sleep_fn
        self.telemetry = RequestTelemetry()

    @property
    def has_live_transport(self) -> bool:
        """Return True if an active SNMP transport callable has been configured."""
        return self._transport is not None

    @property
    def has_valid_credentials(self) -> bool:
        """Return True if read-only credentials are present for the configured SNMP version."""
        if self.version == "3":
            return bool(self.snmp_v3_user)
        return bool(self.community)

    def _validate_target(
        self,
        target_ip: str,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> str:
        active_guard = scope_guard if scope_guard is not None else self.scope_guard
        if active_guard is not None:
            return active_guard.validate_target_ip(target_ip)
        return str(_parse_ipv4_host(target_ip))

    def _invoke_transport(
        self,
        normalized_ip: str,
        oids: list[str],
        operation: str,
        timeout: float,
    ) -> dict[str, Any]:
        if self._transport is None:
            return {}

        sig = inspect.signature(self._transport)
        pos_params = [
            p
            for p in sig.parameters.values()
            if p.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        has_varargs = any(
            p.kind == inspect.Parameter.VAR_POSITIONAL
            for p in sig.parameters.values()
        )
        has_kwargs = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()
        )

        kwargs: dict[str, Any] = {}
        if "operation" in sig.parameters or has_kwargs:
            if len(pos_params) < 3:
                kwargs["operation"] = operation

        if len(pos_params) >= 4 or has_varargs:
            raw = self._transport(normalized_ip, oids, operation, timeout)
        elif len(pos_params) == 3:
            third_name = pos_params[2].name.lower()
            if third_name in {"operation", "op", "pdu"}:
                raw = self._transport(normalized_ip, oids, operation)
            else:
                raw = self._transport(normalized_ip, oids, timeout, **kwargs)
        elif len(pos_params) == 2:
            second_name = pos_params[1].name.lower()
            if "timeout" in second_name:
                raw = self._transport(normalized_ip, timeout, **kwargs)
            else:
                raw = self._transport(normalized_ip, oids, **kwargs)
        elif len(pos_params) == 1:
            raw = self._transport(normalized_ip, **kwargs)
        else:
            raw = self._transport(**kwargs)

        if raw is None:
            return {}
        if not isinstance(raw, Mapping):
            raise TypeError(
                f"SNMP transport must return a Mapping[str, Any] or None, got {type(raw).__name__}"
            )
        return dict(raw)

    def query(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        operation: str = "GET",
        timeout_seconds: Optional[float] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> dict[str, Any]:
        """Execute a validated read-only SNMP query against a scoped target IPv4 address."""
        try:
            op_upper = _validate_snmp_readonly_config(
                operation=operation,
                mode=self.mode,
                community=self.community,
            )
        except ConnectorReadOnlyError:
            self.telemetry.blocked_mutations += 1
            raise

        normalized_ip = self._validate_target(target_ip, scope_guard=scope_guard)
        effective_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else self.timeout_seconds
        )
        if effective_timeout <= 0:
            raise ValueError("timeout_seconds must be > 0")

        oid_list = [str(o).strip() for o in oids if str(o).strip()]
        self.telemetry.total_requests += 1
        self.telemetry.last_target = normalized_ip

        total_attempts = 1 + self.max_retries
        last_exc: Optional[Exception] = None

        for attempt in range(1, total_attempts + 1):
            if attempt > 1:
                self.telemetry.retried_requests += 1
                if self.backoff_seconds > 0:
                    self._sleep_fn(self.backoff_seconds * (2 ** (attempt - 2)))

            start = time.monotonic()
            try:
                result = self._invoke_transport(
                    normalized_ip, oid_list, op_upper, effective_timeout
                )
            except PermissionError as exc:
                self.telemetry.blocked_mutations += 1
                self.telemetry.failed_requests += 1
                if isinstance(exc, ConnectorReadOnlyError):
                    raise
                raise ConnectorReadOnlyError(str(exc)) from exc
            except ScopeViolationError:
                self.telemetry.failed_requests += 1
                raise
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue

            elapsed_ms = round((time.monotonic() - start) * 1000.0, 3)
            self.telemetry.latencies_ms.append(elapsed_ms)
            self.telemetry.successful_requests += 1
            return result

        self.telemetry.failed_requests += 1
        assert last_exc is not None
        raise last_exc

    def get(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP GET request."""
        return self.query(
            target_ip, oids, operation="GET", timeout_seconds=timeout_seconds
        )

    def get_next(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP GETNEXT request."""
        return self.query(
            target_ip, oids, operation="GETNEXT", timeout_seconds=timeout_seconds
        )

    def get_bulk(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP GETBULK request."""
        return self.query(
            target_ip, oids, operation="GETBULK", timeout_seconds=timeout_seconds
        )

    def walk(
        self,
        target_ip: str,
        oid_prefixes: Sequence[str] = SNMPV2_MIB_OIDS,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP WALK request."""
        return self.query(
            target_ip,
            oid_prefixes,
            operation="WALK",
            timeout_seconds=timeout_seconds,
        )

    def set(self, *args: Any, **kwargs: Any) -> Any:
        """Unconditionally block SNMP SET operations with ConnectorReadOnlyError."""
        _ = (args, kwargs)
        self.telemetry.blocked_mutations += 1
        raise ConnectorReadOnlyError(
            "SNMP SET is strictly prohibited in read-only mode"
        )

    def walk_extreme_switch(
        self,
        target_ip: str,
        *,
        include_parsed: bool = True,
        include_Parsed: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP WALK of an Extreme switch and parse port/LLDP/PoE metrics."""
        should_parse = include_Parsed if include_Parsed is not None else include_parsed
        raw_oids = self.walk(target_ip, EXTREME_SWITCH_MIB_OIDS)
        if not should_parse:
            return dict(raw_oids)

        metrics = parse_extreme_switch_oids(raw_oids)
        lldp_sys_prefix = f"{LLDP_REM_SYS_NAME_PREFIX}."
        lldp_port_prefix = f"{LLDP_REM_PORT_ID_PREFIX}."
        lldp_neighbors = [
            str(val) for oid, val in raw_oids.items() if oid.startswith(lldp_sys_prefix)
        ]
        if not lldp_neighbors:
            lldp_neighbors = [
                str(val)
                for oid, val in raw_oids.items()
                if oid.startswith(lldp_port_prefix)
            ]

        peth_admin_prefix = f"{PETH_PSE_PORT_ADMIN_ENABLE_PREFIX}."
        peth_detect_prefix = f"{PETH_PSE_PORT_DETECTION_STATUS_PREFIX}."
        peth_admin_enabled_ports = 0
        peth_delivering_ports = 0
        for oid, val in raw_oids.items():
            if oid.startswith(peth_admin_prefix):
                try:
                    if int(val) == 1:
                        peth_admin_enabled_ports += 1
                except (TypeError, ValueError):
                    pass
            elif oid.startswith(peth_detect_prefix):
                try:
                    # IEEE 802.3af pethPsePortDetectionStatus: 3 = deliveringPower
                    if int(val) == 3:
                        peth_delivering_ports += 1
                except (TypeError, ValueError):
                    if str(val).strip().lower() in {"deliveringpower", "delivering"}:
                        peth_delivering_ports += 1

        metrics["lldp_neighbor_count"] = len(lldp_neighbors)
        metrics["lldp_neighbors"] = lldp_neighbors
        metrics["peth_admin_enabled_ports"] = peth_admin_enabled_ports
        metrics["peth_delivering_ports"] = peth_delivering_ports

        return {
            **raw_oids,
            **metrics,
            "oids": dict(raw_oids),
            "metrics": dict(metrics),
        }

    def walk_apc_ups(
        self,
        target_ip: str,
        *,
        include_parsed: bool = True,
    ) -> dict[str, Any]:
        """Perform a read-only SNMP WALK of an APC UPS and parse PowerNet-MIB metrics."""
        raw_oids = self.walk(target_ip, APC_UPS_MIB_OIDS)
        if not include_parsed:
            return dict(raw_oids)
        metrics = parse_apc_ups_oids(raw_oids)
        return {
            **raw_oids,
            **metrics,
            "oids": dict(raw_oids),
            "metrics": dict(metrics),
        }

    def __call__(
        self,
        target_ip: str,
        oids: Sequence[str] = SNMPV2_MIB_OIDS,
        timeout_seconds: Optional[float] = None,
    ) -> dict[str, Any]:
        """Allow SnmpWalkConnector to be passed directly as snmp_probe_fn to ManagementProbeCollector."""
        return self.query(
            target_ip,
            oids,
            operation="GET",
            timeout_seconds=timeout_seconds,
        )


__all__ = [
    "APC_UPS_MIB_OIDS",
    "AuthenticatedScraperSession",
    "ConnectorReadOnlyError",
    "EXTREME_SWITCH_MIB_OIDS",
    "LLDP_MIB_OIDS",
    "LLDP_REM_PORT_DESC_PREFIX",
    "LLDP_REM_PORT_ID_PREFIX",
    "LLDP_REM_SYS_NAME_PREFIX",
    "PETH_PSE_PORT_ADMIN_ENABLE_PREFIX",
    "PETH_PSE_PORT_DETECTION_STATUS_PREFIX",
    "POWER_ETHERNET_MIB_OIDS",
    "RequestTelemetry",
    "SnmpWalkConnector",
    "VSphereRestConnector",
]
