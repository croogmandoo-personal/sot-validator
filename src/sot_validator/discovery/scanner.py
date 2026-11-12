"""Native two-stage /16-to-/24 subnet discovery scanner and live Site bootstrapper."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
import inspect
import ipaddress
import re
import socket
import subprocess
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
)
from sot_validator.signals.icmp import IcmpProbeResponse

DEFAULT_GATEWAY_OCTETS: tuple[int, ...] = (1,)
DEFAULT_TCP_PORTS: tuple[int, ...] = (
    22,
    53,
    80,
    443,
    445,
    5000,
    8000,
    8006,
    8080,
    8123,
    8443,
    9000,
)
_SERVER_TCP_PORTS: frozenset[int] = frozenset({22, 80, 443, 8000, 8080, 8443, 9000})
_NEIGH_STATES: frozenset[str] = frozenset(
    {
        "REACHABLE",
        "STALE",
        "DELAY",
        "PROBE",
        "FAILED",
        "NOARP",
        "PERMANENT",
        "INCOMPLETE",
        "NONE",
    }
)
_PING_RTT_PATTERN = re.compile(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]{1,2}$")


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Normalize a MAC address string to lowercase colon-separated format."""
    if mac is None:
        return None
    if not isinstance(mac, str):
        raise ValueError("mac_address must be a string or None")
    cleaned = mac.strip().lower()
    if not cleaned:
        return None

    if ":" in cleaned or "-" in cleaned:
        sep = ":" if ":" in cleaned else "-"
        parts = cleaned.split(sep)
        if len(parts) == 6 and all(_HEX_RE.match(p) for p in parts):
            return ":".join(p.zfill(2) for p in parts)

    hex_only = "".join(ch for ch in cleaned if ch not in (":", "-", "."))
    if len(hex_only) == 12 and all(ch in "0123456789abcdef" for ch in hex_only):
        return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))

    return cleaned


def _infer_vlan_id_from_subnet(subnet_cidr: str) -> str:
    """Infer a canonical VLAN ID string from a /24 subnet's third octet."""
    net = ipaddress.ip_network(subnet_cidr.strip(), strict=False)
    octets = str(net.network_address).split(".")
    third_octet = int(octets[2]) if len(octets) >= 3 else 1
    return str(third_octet) if third_octet > 0 else "1"


def parse_ip_neigh_output(
    raw_output: str,
) -> dict[str, tuple[Optional[str], Optional[str]]]:
    """Parse ``ip -4 neigh show`` output into ``{ip: (mac_or_none, state_or_none)}``."""
    if not isinstance(raw_output, str) or not raw_output.strip():
        return {}

    neighbors: dict[str, tuple[Optional[str], Optional[str]]] = {}
    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        tokens = line.split()
        if not tokens:
            continue

        ip_candidate = tokens[0]
        try:
            addr = ipaddress.ip_address(ip_candidate)
        except ValueError:
            continue
        if not isinstance(addr, ipaddress.IPv4Address):
            continue

        mac: Optional[str] = None
        for idx, tok in enumerate(tokens[:-1]):
            if tok.lower() == "lladdr":
                mac = _normalize_mac(tokens[idx + 1])
                break

        state: Optional[str] = None
        last_upper = tokens[-1].upper()
        if last_upper in _NEIGH_STATES or (
            last_upper.isalpha() and last_upper == tokens[-1]
        ):
            state = last_upper

        neighbors[str(addr)] = (mac, state)

    return neighbors


def _infer_host_role(
    *,
    ip: str,
    gateway_octets: Sequence[int] = DEFAULT_GATEWAY_OCTETS,
    mac_address: Optional[str] = None,
    open_tcp_ports: Sequence[int] = (),
    hostname: Optional[str] = None,
) -> str:
    """Deterministically infer a host's network/equipment role from discovery signals."""
    norm_mac = (_normalize_mac(mac_address) or "").lower()
    host_lower = (hostname or "").strip().lower()
    port_set = set(open_tcp_ports)

    last_octet: Optional[int] = None
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        last_octet = int(str(addr).split(".")[3])
    except ValueError:
        last_octet = None

    # Extreme Networks switch OUI or switch hostname pattern
    if (
        norm_mac.startswith("00:04:96")
        or "switch" in host_lower
        or "sw-" in host_lower
    ):
        return "switch"

    # Gateway octet router
    if last_octet is not None and last_octet in gateway_octets:
        return "router"

    # APC UPS OUI or UPS hostname
    if norm_mac.startswith("00:c0:b7") or "ups" in host_lower:
        return "ups"

    # Proxmox / ESXi / Hypervisor
    if (
        8006 in port_set
        or norm_mac.startswith("bc:24:11")
        or any(tok in host_lower for tok in ("pve", "proxmox", "esxi", "hypervisor"))
    ):
        return "hypervisor"

    # NAS / SAN / SMB storage
    if (
        5000 in port_set
        or 445 in port_set
        or any(tok in host_lower for tok in ("nas", "san", "synology"))
    ):
        return "nas_storage"

    # DNS server (non-gateway)
    if 53 in port_set:
        return "dns_server"

    # Home Assistant / automation hub
    if 8123 in port_set:
        return "automation_hub"

    # IoT device (e.g. Ecobee OUI 44:61:32)
    if (
        norm_mac.startswith("44:61:32")
        or "iot" in host_lower
        or "ecobee" in host_lower
    ):
        return "iot_device"

    # General server ports
    if port_set & _SERVER_TCP_PORTS:
        return "server"

    return "host"


def _role_to_equipment_category(role: str) -> EquipmentCategory:
    """Map an inferred host role to a canonical EquipmentCategory."""
    norm = (role or "").strip().lower()
    if norm == "ups":
        return EquipmentCategory.UPS
    if norm in ("nas_storage", "san"):
        return EquipmentCategory.SAN
    if norm in ("hypervisor", "dns_server", "server", "automation_hub"):
        return EquipmentCategory.SERVER
    if norm == "vm":
        return EquipmentCategory.VM
    return EquipmentCategory.OTHER


@dataclass
class DiscoveredHost:
    """Host record discovered during a scoped /24 subnet sweep."""

    ip: str
    subnet_cidr: str
    vlan_id: str
    icmp_reachable: bool = False
    rtt_ms: Optional[float] = None
    open_tcp_ports: list[int] = field(default_factory=list)
    mac_address: Optional[str] = None
    arp_state: Optional[str] = None
    hostname: Optional[str] = None
    inferred_role: str = "host"

    def __post_init__(self) -> None:
        if not isinstance(self.ip, str) or not self.ip.strip():
            raise ValueError("ip must be a non-empty string")
        self.ip = str(ipaddress.IPv4Address(self.ip.strip()))

        if not isinstance(self.subnet_cidr, str) or not self.subnet_cidr.strip():
            raise ValueError("subnet_cidr must be a non-empty string")
        net = ipaddress.ip_network(self.subnet_cidr.strip(), strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError("subnet_cidr must be an IPv4 network")
        self.subnet_cidr = str(net)

        if isinstance(self.vlan_id, int) and not isinstance(self.vlan_id, bool):
            self.vlan_id = str(self.vlan_id)
        if not isinstance(self.vlan_id, str) or not self.vlan_id.strip():
            raise ValueError("vlan_id must be a non-empty string")
        self.vlan_id = self.vlan_id.strip()

        self.icmp_reachable = bool(self.icmp_reachable)
        if self.rtt_ms is not None:
            if isinstance(self.rtt_ms, bool) or not isinstance(
                self.rtt_ms, (int, float)
            ):
                raise ValueError("rtt_ms must be a number or None")
            self.rtt_ms = float(self.rtt_ms)

        if self.open_tcp_ports is None:
            self.open_tcp_ports = []
        else:
            normalized_ports: set[int] = set()
            for p in self.open_tcp_ports:
                if isinstance(p, bool) or not isinstance(p, int) or not (1 <= p <= 65535):
                    raise ValueError(f"Invalid TCP port: {p!r}")
                normalized_ports.add(p)
            self.open_tcp_ports = sorted(normalized_ports)

        self.mac_address = _normalize_mac(self.mac_address)
        if isinstance(self.arp_state, str):
            cleaned_state = self.arp_state.strip().upper()
            self.arp_state = cleaned_state if cleaned_state else None
        elif self.arp_state is not None:
            raise ValueError("arp_state must be a string or None")

        if isinstance(self.hostname, str):
            cleaned_host = self.hostname.strip()
            self.hostname = cleaned_host if cleaned_host else None
        elif self.hostname is not None:
            raise ValueError("hostname must be a string or None")

        if not isinstance(self.inferred_role, str) or not self.inferred_role.strip():
            self.inferred_role = "host"
        else:
            self.inferred_role = self.inferred_role.strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "subnet_cidr": self.subnet_cidr,
            "vlan_id": self.vlan_id,
            "icmp_reachable": self.icmp_reachable,
            "rtt_ms": self.rtt_ms,
            "open_tcp_ports": list(self.open_tcp_ports),
            "mac_address": self.mac_address,
            "arp_state": self.arp_state,
            "hostname": self.hostname,
            "inferred_role": self.inferred_role,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DiscoveredHost:
        return cls(
            ip=data["ip"],
            subnet_cidr=data["subnet_cidr"],
            vlan_id=data["vlan_id"],
            icmp_reachable=bool(data.get("icmp_reachable", False)),
            rtt_ms=data.get("rtt_ms"),
            open_tcp_ports=list(data.get("open_tcp_ports", [])),
            mac_address=data.get("mac_address"),
            arp_state=data.get("arp_state"),
            hostname=data.get("hostname"),
            inferred_role=data.get("inferred_role", "host"),
        )


@dataclass
class DiscoveryConfig:
    """Configuration for two-stage /16-to-/24 subnet and host discovery."""

    cidr: str = "10.42.0.0/16"
    gateway_octets: tuple[int, ...] = DEFAULT_GATEWAY_OCTETS
    tcp_ports: tuple[int, ...] = DEFAULT_TCP_PORTS
    max_concurrency: int = 128
    ping_timeout_sec: float = 1.0
    tcp_timeout_sec: float = 0.35
    max_active_subnets: int = 32

    def __post_init__(self) -> None:
        if not isinstance(self.cidr, str) or not self.cidr.strip():
            raise ValueError("cidr must be a non-empty IPv4 /16 or /24 CIDR string")
        try:
            network = ipaddress.ip_network(self.cidr.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR {self.cidr!r}: {exc}") from exc
        if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen not in (
            16,
            24,
        ):
            raise ValueError(
                f"DiscoveryConfig.cidr must be an IPv4 /16 or /24 prefix, got {self.cidr!r}"
            )
        self.cidr = str(network)

        if isinstance(self.gateway_octets, (str, bytes)) or not isinstance(
            self.gateway_octets, Iterable
        ):
            raise ValueError("gateway_octets must be a non-empty sequence of integers")
        gw_list: list[int] = []
        for octet in self.gateway_octets:
            if (
                isinstance(octet, bool)
                or not isinstance(octet, int)
                or not (1 <= octet <= 254)
            ):
                raise ValueError(
                    f"gateway_octets entries must be integers in 1..254, got {octet!r}"
                )
            if octet not in gw_list:
                gw_list.append(octet)
        if not gw_list:
            raise ValueError("gateway_octets must not be empty")
        self.gateway_octets = tuple(gw_list)

        if isinstance(self.tcp_ports, (str, bytes)) or not isinstance(
            self.tcp_ports, Iterable
        ):
            raise ValueError("tcp_ports must be a sequence of integers in 1..65535")
        ports_list: list[int] = []
        for port in self.tcp_ports:
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not (1 <= port <= 65535)
            ):
                raise ValueError(
                    f"tcp_ports entries must be integers in 1..65535, got {port!r}"
                )
            if port not in ports_list:
                ports_list.append(port)
        self.tcp_ports = tuple(ports_list)

        if (
            isinstance(self.max_concurrency, bool)
            or not isinstance(self.max_concurrency, int)
            or self.max_concurrency < 1
        ):
            raise ValueError("max_concurrency must be an integer >= 1")

        if (
            isinstance(self.max_active_subnets, bool)
            or not isinstance(self.max_active_subnets, int)
            or self.max_active_subnets < 1
        ):
            raise ValueError("max_active_subnets must be an integer >= 1")

        if (
            isinstance(self.ping_timeout_sec, bool)
            or not isinstance(self.ping_timeout_sec, (int, float))
            or self.ping_timeout_sec <= 0
        ):
            raise ValueError("ping_timeout_sec must be a number > 0")
        self.ping_timeout_sec = float(self.ping_timeout_sec)

        if (
            isinstance(self.tcp_timeout_sec, bool)
            or not isinstance(self.tcp_timeout_sec, (int, float))
            or self.tcp_timeout_sec <= 0
        ):
            raise ValueError("tcp_timeout_sec must be a number > 0")
        self.tcp_timeout_sec = float(self.tcp_timeout_sec)


def _run_coro_sync(coro: Any) -> Any:
    """Execute a coroutine synchronously, handling existing running event loops safely."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    return asyncio.run(coro)


async def _default_async_ping(
    ip: str, timeout_sec: float
) -> tuple[bool, Optional[float]]:
    """Default async ICMP probe via system ``ping`` binary."""
    wait_arg = str(max(1, int(round(timeout_sec))))
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping",
            "-n",
            "-c",
            "1",
            "-W",
            wait_arg,
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_sec + 1.0
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return False, None
    except OSError:
        return False, None

    if proc.returncode != 0:
        return False, None

    output = stdout_bytes.decode("utf-8", errors="replace")
    match = _PING_RTT_PATTERN.search(output)
    rtt_ms = float(match.group(1)) if match is not None else None
    return True, rtt_ms


async def _default_async_tcp_probe(ip: str, port: int, timeout_sec: float) -> bool:
    """Default async TCP connect probe using ``asyncio.open_connection``."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout_sec
        )
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


def _default_arp_table_reader() -> dict[str, tuple[Optional[str], Optional[str]]]:
    """Default kernel ARP neighbor table reader using ``ip -4 neigh show``."""
    try:
        completed = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if completed.returncode != 0:
        return {}
    return parse_ip_neigh_output(completed.stdout)


async def _default_async_rdns(ip: str) -> Optional[str]:
    """Default reverse DNS lookup using ``socket.gethostbyaddr``."""
    try:
        host, _, _ = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return host.strip() if host and host.strip() else None
    except (socket.herror, socket.gaierror, OSError):
        return None


class SubnetDiscoveryScanner:
    """Two-stage /16-to-/24 subnet discovery scanner and Site snapshot builder."""

    def __init__(
        self,
        config: Optional[DiscoveryConfig] = None,
        *,
        ping_fn: Optional[Callable[..., Any]] = None,
        tcp_probe_fn: Optional[Callable[..., Any]] = None,
        arp_table_fn: Optional[Callable[..., Any]] = None,
        rdns_fn: Optional[Callable[..., Any]] = None,
    ) -> None:
        if config is not None and not isinstance(config, DiscoveryConfig):
            raise ValueError("config must be a DiscoveryConfig instance")
        self.config: DiscoveryConfig = config or DiscoveryConfig()
        self._ping_fn = ping_fn
        self._tcp_probe_fn = tcp_probe_fn
        self._arp_table_fn = arp_table_fn
        self._rdns_fn = rdns_fn

    @staticmethod
    def _normalize_ping_result(raw: Any) -> tuple[bool, Optional[float]]:
        if raw is None:
            return False, None
        if isinstance(raw, bool):
            return raw, None
        if isinstance(raw, (int, float)):
            reachable = float(raw) >= 0.0
            return reachable, (float(raw) if reachable else None)
        if isinstance(raw, IcmpProbeResponse):
            return (
                bool(raw.reachable),
                float(raw.latency_ms) if raw.latency_ms is not None else None,
            )
        if isinstance(raw, tuple) and len(raw) >= 2:
            reachable = bool(raw[0])
            rtt = float(raw[1]) if raw[1] is not None and reachable else None
            return reachable, rtt
        if isinstance(raw, Mapping):
            reachable = bool(raw.get("reachable", False))
            raw_rtt = raw.get("rtt_ms", raw.get("latency_ms"))
            rtt = float(raw_rtt) if raw_rtt is not None and reachable else None
            return reachable, rtt
        if hasattr(raw, "reachable"):
            reachable = bool(getattr(raw, "reachable"))
            raw_rtt = getattr(raw, "rtt_ms", getattr(raw, "latency_ms", None))
            rtt = float(raw_rtt) if raw_rtt is not None and reachable else None
            return reachable, rtt
        return bool(raw), None

    @staticmethod
    def _normalize_arp_table(
        raw: Any,
    ) -> dict[str, tuple[Optional[str], Optional[str]]]:
        if raw is None:
            return {}
        if isinstance(raw, str):
            return parse_ip_neigh_output(raw)
        if isinstance(raw, Mapping):
            normalized: dict[str, tuple[Optional[str], Optional[str]]] = {}
            for raw_ip, val in raw.items():
                try:
                    ip_str = str(ipaddress.IPv4Address(str(raw_ip).strip()))
                except ValueError:
                    continue
                if val is None:
                    normalized[ip_str] = (None, None)
                elif isinstance(val, str):
                    normalized[ip_str] = (_normalize_mac(val), "REACHABLE")
                elif isinstance(val, tuple):
                    mac = _normalize_mac(val[0]) if len(val) > 0 and val[0] else None
                    state = (
                        str(val[1]).strip().upper()
                        if len(val) > 1 and val[1]
                        else None
                    )
                    normalized[ip_str] = (mac, state)
                elif isinstance(val, Mapping):
                    raw_mac = (
                        val.get("mac")
                        or val.get("mac_address")
                        or val.get("lladdr")
                    )
                    raw_state = (
                        val.get("state")
                        or val.get("arp_state")
                        or val.get("status")
                    )
                    mac = _normalize_mac(raw_mac) if raw_mac else None
                    state = str(raw_state).strip().upper() if raw_state else None
                    normalized[ip_str] = (mac, state)
            return normalized
        return {}

    async def _probe_ping(
        self, ip: str, timeout_sec: float
    ) -> tuple[bool, Optional[float]]:
        if self._ping_fn is None:
            return await _default_async_ping(ip, timeout_sec)
        try:
            res = self._ping_fn(ip, timeout_sec)
        except TypeError:
            res = self._ping_fn(ip)
        if inspect.isawaitable(res):
            res = await res
        return self._normalize_ping_result(res)

    async def _probe_tcp(self, ip: str, port: int, timeout_sec: float) -> bool:
        if self._tcp_probe_fn is None:
            return await _default_async_tcp_probe(ip, port, timeout_sec)
        try:
            res = self._tcp_probe_fn(ip, port, timeout_sec)
        except TypeError:
            res = self._tcp_probe_fn(ip, port)
        if inspect.isawaitable(res):
            res = await res
        return bool(res)

    async def _get_arp_table(
        self,
    ) -> dict[str, tuple[Optional[str], Optional[str]]]:
        if self._arp_table_fn is None:
            return await asyncio.to_thread(_default_arp_table_reader)
        res = self._arp_table_fn()
        if inspect.isawaitable(res):
            res = await res
        return self._normalize_arp_table(res)

    async def _resolve_rdns(self, ip: str) -> Optional[str]:
        if self._rdns_fn is None:
            if (
                self._ping_fn is not None
                or self._tcp_probe_fn is not None
                or self._arp_table_fn is not None
            ):
                return None
            return await _default_async_rdns(ip)
        res = self._rdns_fn(ip)
        if inspect.isawaitable(res):
            res = await res
        if isinstance(res, str) and res.strip():
            return res.strip()
        return None

    async def discover_active_subnets_async(
        self,
        *,
        arp_table: Optional[dict[str, tuple[Optional[str], Optional[str]]]] = None,
    ) -> list[str]:
        """Stage 1: Identify active /24 subnets within configured /16 or /24 CIDR."""
        net = ipaddress.IPv4Network(self.config.cidr, strict=False)
        if net.prefixlen == 24:
            return [str(net)]

        resolved_arp = (
            arp_table if arp_table is not None else await self._get_arp_table()
        )
        active_subnet_set: set[ipaddress.IPv4Network] = set()

        for ip_str, (mac, state) in resolved_arp.items():
            if not mac or (state or "").upper() in {"FAILED", "INCOMPLETE"}:
                continue
            try:
                addr = ipaddress.IPv4Address(ip_str)
            except ValueError:
                continue
            if addr in net:
                slash24 = ipaddress.IPv4Network(f"{addr}/24", strict=False)
                active_subnet_set.add(slash24)

        octets = str(net.network_address).split(".")
        prefix_two = f"{octets[0]}.{octets[1]}"
        semaphore = asyncio.Semaphore(self.config.max_concurrency)

        async def _probe_gateway(
            third_octet: int, gw_octet: int
        ) -> Optional[ipaddress.IPv4Network]:
            gw_ip = f"{prefix_two}.{third_octet}.{gw_octet}"
            async with semaphore:
                reachable, _ = await self._probe_ping(
                    gw_ip, self.config.ping_timeout_sec
                )
            if reachable:
                return ipaddress.IPv4Network(
                    f"{prefix_two}.{third_octet}.0/24", strict=False
                )
            return None

        tasks = [
            _probe_gateway(third_octet, gw_octet)
            for third_octet in range(256)
            for gw_octet in self.config.gateway_octets
        ]
        results = await asyncio.gather(*tasks)
        for subnet_net in results:
            if subnet_net is not None:
                active_subnet_set.add(subnet_net)

        sorted_subnets = sorted(active_subnet_set)[: self.config.max_active_subnets]
        return [str(s) for s in sorted_subnets]

    def discover_active_subnets(self) -> list[str]:
        """Synchronous wrapper for Stage 1 active /24 subnet discovery."""
        return _run_coro_sync(self.discover_active_subnets_async())

    async def sweep_subnet_async(
        self,
        subnet_cidr: str,
        *,
        arp_table: Optional[dict[str, tuple[Optional[str], Optional[str]]]] = None,
    ) -> list[DiscoveredHost]:
        """Stage 2: Sweep usable host IPs (.1..254) inside an active /24 subnet."""
        if not isinstance(subnet_cidr, str) or not subnet_cidr.strip():
            raise ValueError("subnet_cidr must be a non-empty /24 CIDR string")
        try:
            subnet = ipaddress.ip_network(subnet_cidr.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid subnet CIDR {subnet_cidr!r}: {exc}") from exc
        if not isinstance(subnet, ipaddress.IPv4Network) or subnet.prefixlen != 24:
            raise ValueError(
                f"sweep_subnet requires an IPv4 /24 CIDR, got {subnet_cidr!r}"
            )

        normalized_subnet_cidr = str(subnet)
        vlan_id = _infer_vlan_id_from_subnet(normalized_subnet_cidr)
        resolved_arp = (
            arp_table if arp_table is not None else await self._get_arp_table()
        )
        semaphore = asyncio.Semaphore(self.config.max_concurrency)

        async def _evaluate_host(host_addr: ipaddress.IPv4Address) -> Optional[DiscoveredHost]:
            ip_str = str(host_addr)
            fourth_octet = int(ip_str.split(".")[3])
            mac_address, arp_state = resolved_arp.get(ip_str, (None, None))
            has_valid_arp = bool(
                mac_address
                and (arp_state or "").upper() not in {"FAILED", "INCOMPLETE"}
            )

            async with semaphore:
                icmp_reachable, rtt_ms = await self._probe_ping(
                    ip_str, self.config.ping_timeout_sec
                )

            open_ports: list[int] = []
            should_probe_tcp = (
                icmp_reachable
                or has_valid_arp
                or (fourth_octet in self.config.gateway_octets)
                or (self._tcp_probe_fn is not None)
            )
            if should_probe_tcp and self.config.tcp_ports:
                for port in self.config.tcp_ports:
                    async with semaphore:
                        is_open = await self._probe_tcp(
                            ip_str, port, self.config.tcp_timeout_sec
                        )
                    if is_open:
                        open_ports.append(port)

            if not (icmp_reachable or open_ports or has_valid_arp):
                return None

            hostname = await self._resolve_rdns(ip_str)
            inferred_role = _infer_host_role(
                ip=ip_str,
                gateway_octets=self.config.gateway_octets,
                mac_address=mac_address,
                open_tcp_ports=open_ports,
                hostname=hostname,
            )
            return DiscoveredHost(
                ip=ip_str,
                subnet_cidr=normalized_subnet_cidr,
                vlan_id=vlan_id,
                icmp_reachable=icmp_reachable,
                rtt_ms=rtt_ms,
                open_tcp_ports=open_ports,
                mac_address=mac_address,
                arp_state=arp_state,
                hostname=hostname,
                inferred_role=inferred_role,
            )

        tasks = [_evaluate_host(host_addr) for host_addr in subnet.hosts()]
        evaluated = await asyncio.gather(*tasks)
        discovered = [h for h in evaluated if h is not None]
        discovered.sort(key=lambda h: ipaddress.IPv4Address(h.ip))
        return discovered

    def sweep_subnet(self, subnet_cidr: str) -> list[DiscoveredHost]:
        """Synchronous wrapper for sweeping a single /24 subnet."""
        return _run_coro_sync(self.sweep_subnet_async(subnet_cidr))

    async def scan_async(self) -> list[DiscoveredHost]:
        """Execute two-stage discovery across configured CIDR and return all discovered hosts."""
        arp_table = await self._get_arp_table()
        active_subnets = await self.discover_active_subnets_async(arp_table=arp_table)
        all_hosts: list[DiscoveredHost] = []
        for subnet_cidr in active_subnets[: self.config.max_active_subnets]:
            subnet_hosts = await self.sweep_subnet_async(
                subnet_cidr, arp_table=arp_table
            )
            all_hosts.extend(subnet_hosts)
        all_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))
        return all_hosts

    def scan(self) -> list[DiscoveredHost]:
        """Synchronous wrapper for two-stage subnet and host discovery."""
        return _run_coro_sync(self.scan_async())

    def build_site_snapshot(
        self,
        hosts: Sequence[DiscoveredHost],
        active_subnets: Optional[Sequence[str]] = None,
        *,
        site_id: str = "site-discovered",
        site_name: str = "Discovered Site",
        observed_at: Optional[datetime | str] = None,
    ) -> Site:
        """Transform discovered subnets and hosts into a ready-to-validate canonical Site."""
        if not isinstance(site_id, str) or not site_id.strip():
            raise ValueError("site_id must be a non-empty string")
        if not isinstance(site_name, str) or not site_name.strip():
            raise ValueError("site_name must be a non-empty string")
        site_id = site_id.strip()
        site_name = site_name.strip()

        if observed_at is None:
            obs_dt = datetime.now(timezone.utc)
        elif isinstance(observed_at, datetime):
            obs_dt = observed_at
        elif isinstance(observed_at, str):
            obs_dt = datetime.fromisoformat(observed_at)
        else:
            raise ValueError("observed_at must be a datetime, ISO-8601 string, or None")

        normalized_hosts = [
            h if isinstance(h, DiscoveredHost) else DiscoveredHost.from_dict(h)
            for h in hosts
        ]
        normalized_hosts.sort(key=lambda h: ipaddress.IPv4Address(h.ip))

        subnet_net_set: set[ipaddress.IPv4Network] = set()
        for raw_cidr in active_subnets or ():
            net = ipaddress.ip_network(raw_cidr.strip(), strict=False)
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 24:
                subnet_net_set.add(net)
        for host in normalized_hosts:
            net = ipaddress.ip_network(host.subnet_cidr, strict=False)
            if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 24:
                subnet_net_set.add(net)

        sorted_subnets = sorted(subnet_net_set)
        hosts_by_subnet: dict[str, list[DiscoveredHost]] = {
            str(net): [] for net in sorted_subnets
        }
        for host in normalized_hosts:
            hosts_by_subnet.setdefault(host.subnet_cidr, []).append(host)

        vlans: list[VLAN] = []
        subnets: list[Subnet] = []
        devices: list[NetworkDevice] = []
        equipment_list: list[Equipment] = []
        ip_addresses: list[IPAddress] = []

        default_gw_octet = self.config.gateway_octets[0]

        for net in sorted_subnets:
            cidr_str = str(net)
            octets = str(net.network_address).split(".")
            third_octet = int(octets[2])
            vlan_id = str(third_octet) if third_octet > 0 else "1"
            subnet_id = f"{site_id}-sub-{third_octet}"
            subnet_hosts = hosts_by_subnet.get(cidr_str, [])

            # Resolve gateway IP for the subnet
            gateway_host = next(
                (
                    h
                    for h in subnet_hosts
                    if h.inferred_role == "router"
                    or int(h.ip.split(".")[3]) in self.config.gateway_octets
                ),
                None,
            )
            gateway_ip = (
                gateway_host.ip
                if gateway_host is not None
                else f"{octets[0]}.{octets[1]}.{octets[2]}.{default_gw_octet}"
            )

            vlans.append(
                VLAN(
                    vlan_id=vlan_id,
                    site_id=site_id,
                    name=f"VLAN {vlan_id}",
                    subnet_id=subnet_id,
                    cidr=cidr_str,
                    gateway=gateway_ip,
                )
            )
            subnets.append(
                Subnet(
                    subnet_id=subnet_id,
                    site_id=site_id,
                    cidr=cidr_str,
                    vlan_id=vlan_id,
                    gateway=gateway_ip,
                    name=f"Subnet {cidr_str}",
                )
            )

            device_hosts = [
                h for h in subnet_hosts if h.inferred_role in {"router", "switch"}
            ]
            eq_hosts = [
                h for h in subnet_hosts if h.inferred_role not in {"router", "switch"}
            ]

            subnet_devices: list[tuple[NetworkDevice, Optional[DiscoveredHost]]] = []
            for dev_host in device_hosts:
                ip_slug = dev_host.ip.replace(".", "-")
                dev_id = f"{site_id}-dev-{ip_slug}"
                dev_hostname = dev_host.hostname or f"{dev_host.inferred_role}-{ip_slug}"
                vendor = (
                    "Extreme Networks"
                    if (dev_host.mac_address or "").startswith("00:04:96")
                    else None
                )
                net_dev = NetworkDevice(
                    device_id=dev_id,
                    site_id=site_id,
                    hostname=dev_hostname,
                    management_ip=dev_host.ip,
                    vendor=vendor,
                    role=dev_host.inferred_role,
                    last_seen=obs_dt,
                    ports=[],
                )
                subnet_devices.append((net_dev, dev_host))

            if not subnet_devices and eq_hosts:
                gw_slug = gateway_ip.replace(".", "-")
                synth_dev = NetworkDevice(
                    device_id=f"{site_id}-dev-{gw_slug}",
                    site_id=site_id,
                    hostname=f"gw-{gw_slug}",
                    management_ip=gateway_ip,
                    role="router",
                    last_seen=obs_dt,
                    ports=[],
                )
                subnet_devices.append((synth_dev, None))

            primary_device: Optional[NetworkDevice] = (
                subnet_devices[0][0] if subnet_devices else None
            )
            switch_device: Optional[NetworkDevice] = next(
                (
                    d
                    for d, _ in subnet_devices
                    if d.role == "switch"
                    and primary_device is not None
                    and d.device_id != primary_device.device_id
                ),
                None,
            )

            # Link secondary network devices to primary gateway device so both have active ports
            if primary_device is not None and len(subnet_devices) > 1:
                for idx, (sec_dev, sec_host) in enumerate(subnet_devices[1:], start=1):
                    uplink_port_id = f"{primary_device.device_id}-uplink-{idx}"
                    primary_device.ports.append(
                        Port(
                            port_id=uplink_port_id,
                            device_id=primary_device.device_id,
                            name=f"uplink{idx}",
                            admin_status="up",
                            oper_status="up",
                            connected_device_id=sec_dev.device_id,
                            connected_mac=(
                                sec_host.mac_address if sec_host is not None else None
                            ),
                            vlan_id=vlan_id,
                        )
                    )
                    sec_uplink_id = f"{sec_dev.device_id}-uplink-0"
                    sec_dev.ports.append(
                        Port(
                            port_id=sec_uplink_id,
                            device_id=sec_dev.device_id,
                            name="uplink0",
                            admin_status="up",
                            oper_status="up",
                            connected_device_id=primary_device.device_id,
                            vlan_id=vlan_id,
                        )
                    )

            for port_idx, eq_host in enumerate(eq_hosts, start=1):
                ip_slug = eq_host.ip.replace(".", "-")
                eq_id = f"{site_id}-eq-{ip_slug}"
                eq_name = eq_host.hostname or f"{eq_host.inferred_role}-{ip_slug}"
                category = _role_to_equipment_category(eq_host.inferred_role)

                connected_port_ids: list[str] = []
                if primary_device is not None:
                    port_id = f"{primary_device.device_id}-p{port_idx}"
                    port_name = f"eth{port_idx}"
                    primary_device.ports.append(
                        Port(
                            port_id=port_id,
                            device_id=primary_device.device_id,
                            name=port_name,
                            admin_status="up",
                            oper_status="up",
                            connected_device_id=eq_id,
                            connected_mac=eq_host.mac_address,
                            vlan_id=vlan_id,
                        )
                    )
                    connected_port_ids.append(port_id)

                if switch_device is not None:
                    sw_port_id = f"{switch_device.device_id}-p{port_idx}"
                    sw_port_name = f"eth{port_idx}"
                    switch_device.ports.append(
                        Port(
                            port_id=sw_port_id,
                            device_id=switch_device.device_id,
                            name=sw_port_name,
                            admin_status="up",
                            oper_status="up",
                            connected_device_id=eq_id,
                            connected_mac=eq_host.mac_address,
                            vlan_id=vlan_id,
                        )
                    )
                    connected_port_ids.append(sw_port_id)

                equipment_list.append(
                    Equipment(
                        equipment_id=eq_id,
                        site_id=site_id,
                        name=eq_name,
                        category=category,
                        assigned_ips=[eq_host.ip],
                        connected_ports=connected_port_ids,
                        last_seen=obs_dt,
                    )
                )

                arp_source_id = (
                    primary_device.device_id if primary_device is not None else None
                )
                arp_entry = (
                    ArpEntry(
                        ip=eq_host.ip,
                        arp_mac=eq_host.mac_address,
                        arp_last_seen=obs_dt,
                        arp_source_device_id=arp_source_id,
                        subnet_id=subnet_id,
                    )
                    if eq_host.mac_address
                    else None
                )
                ip_addresses.append(
                    IPAddress(
                        ip=eq_host.ip,
                        subnet_id=subnet_id,
                        assigned_object_type="Equipment",
                        assigned_object_id=eq_id,
                        arp_mac=eq_host.mac_address,
                        arp_last_seen=obs_dt if eq_host.mac_address else None,
                        arp_source_device_id=(
                            arp_source_id if eq_host.mac_address else None
                        ),
                        arp_entry=arp_entry,
                    )
                )

            # Ensure every NetworkDevice has at least one active port and an IPAddress record
            for net_dev, dev_host in subnet_devices:
                if not net_dev.ports:
                    net_dev.ports.append(
                        Port(
                            port_id=f"{net_dev.device_id}-mgmt0",
                            device_id=net_dev.device_id,
                            name="mgmt0",
                            admin_status="up",
                            oper_status="up",
                            connected_mac=(
                                dev_host.mac_address if dev_host is not None else None
                            ),
                            vlan_id=vlan_id,
                        )
                    )
                devices.append(net_dev)

                if dev_host is not None:
                    arp_source_id = (
                        primary_device.device_id
                        if primary_device is not None
                        else net_dev.device_id
                    )
                    dev_arp_entry = (
                        ArpEntry(
                            ip=dev_host.ip,
                            arp_mac=dev_host.mac_address,
                            arp_last_seen=obs_dt,
                            arp_source_device_id=arp_source_id,
                            subnet_id=subnet_id,
                        )
                        if dev_host.mac_address
                        else None
                    )
                    ip_addresses.append(
                        IPAddress(
                            ip=dev_host.ip,
                            subnet_id=subnet_id,
                            assigned_object_type="NetworkDevice",
                            assigned_object_id=net_dev.device_id,
                            arp_mac=dev_host.mac_address,
                            arp_last_seen=obs_dt if dev_host.mac_address else None,
                            arp_source_device_id=(
                                arp_source_id if dev_host.mac_address else None
                            ),
                            arp_entry=dev_arp_entry,
                        )
                    )

        ip_addresses.sort(key=lambda rec: ipaddress.IPv4Address(rec.ip))

        return Site(
            site_id=site_id,
            name=site_name,
            devices=devices,
            vlans=vlans,
            subnets=subnets,
            ip_addresses=ip_addresses,
            equipment=equipment_list,
        )

    async def discover_site_async(
        self,
        site_id: str = "site-discovered",
        site_name: str = "Discovered Site",
        *,
        observed_at: Optional[datetime | str] = None,
    ) -> Site:
        """Execute two-stage discovery and return a populated canonical Site snapshot."""
        arp_table = await self._get_arp_table()
        active_subnets = await self.discover_active_subnets_async(arp_table=arp_table)
        hosts: list[DiscoveredHost] = []
        for subnet_cidr in active_subnets[: self.config.max_active_subnets]:
            subnet_hosts = await self.sweep_subnet_async(
                subnet_cidr, arp_table=arp_table
            )
            hosts.extend(subnet_hosts)
        return self.build_site_snapshot(
            hosts,
            active_subnets=active_subnets,
            site_id=site_id,
            site_name=site_name,
            observed_at=observed_at,
        )

    def discover_site(
        self,
        site_id: str = "site-discovered",
        site_name: str = "Discovered Site",
        *,
        observed_at: Optional[datetime | str] = None,
    ) -> Site:
        """Synchronous wrapper for discovering and constructing a canonical Site snapshot."""
        return _run_coro_sync(
            self.discover_site_async(
                site_id=site_id,
                site_name=site_name,
                observed_at=observed_at,
            )
        )


__all__ = [
    "DEFAULT_GATEWAY_OCTETS",
    "DEFAULT_TCP_PORTS",
    "DiscoveredHost",
    "DiscoveryConfig",
    "SubnetDiscoveryScanner",
    "parse_ip_neigh_output",
]
