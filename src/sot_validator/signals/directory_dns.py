"""Active Directory computer account and /24-scoped DNS/DHCP lease correlation collectors."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import ipaddress
from typing import Any, Optional

from sot_validator.models import (
    Equipment,
    IPAddress,
    NetworkDevice,
    SignalStatus,
    SignalType,
    Site,
    Subnet,
    ValidationSignal,
)
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    SignalCollector,
    normalize_utc_datetime,
    resolve_evaluation_time,
    validate_recency_thresholds,
)
from sot_validator.signals.icmp import (
    ScopeViolationError,
    SubnetScopeGuard,
    _parse_allocated_slash24,
    _parse_ipv4_host,
)


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    text = str(value).strip()
    return text if text else None


def _parse_bool_flag(value: Any, *, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if not token:
            return default
        if token in ("true", "1", "yes", "y", "enabled", "enable", "active", "on"):
            return True
        if token in ("false", "0", "no", "n", "disabled", "disable", "inactive", "off"):
            return False
    raise ValueError(f"Invalid boolean flag value: {value!r}")


def normalize_hostname(hostname: Optional[str]) -> Optional[str]:
    """Normalize a hostname case-insensitively, stripping domain suffixes and trailing '$'."""
    if hostname is None or not isinstance(hostname, str):
        return None
    cleaned = hostname.strip().rstrip(".")
    if not cleaned:
        return None
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr).lower()
    except ValueError:
        pass
    short = cleaned.split(".", 1)[0].strip().rstrip("$").strip().lower()
    return short if short else None


def _normalize_fqdn(hostname: Optional[str]) -> Optional[str]:
    """Normalize a hostname or FQDN to lowercase without trailing root dot or machine '$'."""
    if hostname is None or not isinstance(hostname, str):
        return None
    cleaned = hostname.strip().rstrip(".")
    if not cleaned:
        return None
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr).lower()
    except ValueError:
        pass
    parts = cleaned.split(".")
    first = parts[0].strip().rstrip("$").strip().lower()
    if not first:
        return None
    rest = [p.strip().lower() for p in parts[1:] if p.strip()]
    if rest:
        return ".".join([first, *rest])
    return first


@dataclass(init=False)
class AdComputerRecord:
    """Active Directory computer account record."""

    sam_account_name: str
    dns_hostname: Optional[str] = None
    operating_system: Optional[str] = None
    enabled: bool = True
    last_logon_timestamp: Optional[datetime] = None
    pwd_last_set: Optional[datetime] = None
    distinguished_name: Optional[str] = None

    def __init__(
        self,
        sam_account_name: Optional[str] = None,
        dns_hostname: Optional[str] = None,
        operating_system: Optional[str] = None,
        enabled: Any = True,
        last_logon_timestamp: Optional[datetime | str] = None,
        pwd_last_set: Optional[datetime | str] = None,
        distinguished_name: Optional[str] = None,
        *,
        sAMAccountName: Optional[str] = None,
        dNSHostName: Optional[str] = None,
        operatingSystem: Optional[str] = None,
        lastLogonTimestamp: Optional[datetime | str] = None,
        pwdLastSet: Optional[datetime | str] = None,
        distinguishedName: Optional[str] = None,
        ou: Optional[str] = None,
        OU: Optional[str] = None,
        name: Optional[str] = None,
        cn: Optional[str] = None,
    ) -> None:
        resolved_dns = _clean_optional_str(
            dns_hostname if dns_hostname is not None else dNSHostName
        )
        resolved_sam = _clean_optional_str(
            sam_account_name
            if sam_account_name is not None
            else (sAMAccountName or name or cn)
        )
        if not resolved_sam and resolved_dns:
            short = normalize_hostname(resolved_dns)
            if short:
                resolved_sam = f"{short.upper()}$"
        if not resolved_sam:
            raise ValueError("sam_account_name (sAMAccountName) must be a non-empty string")

        self.sam_account_name = resolved_sam
        self.dns_hostname = resolved_dns
        self.operating_system = _clean_optional_str(
            operating_system if operating_system is not None else operatingSystem
        )
        self.enabled = _parse_bool_flag(enabled, default=True)

        raw_logon = (
            last_logon_timestamp
            if last_logon_timestamp is not None
            else lastLogonTimestamp
        )
        if raw_logon is not None and (
            not isinstance(raw_logon, str) or raw_logon.strip()
        ):
            self.last_logon_timestamp = normalize_utc_datetime(
                raw_logon, field_name="last_logon_timestamp"
            )
        else:
            self.last_logon_timestamp = None

        raw_pwd = pwd_last_set if pwd_last_set is not None else pwdLastSet
        if raw_pwd is not None and (not isinstance(raw_pwd, str) or raw_pwd.strip()):
            self.pwd_last_set = normalize_utc_datetime(
                raw_pwd, field_name="pwd_last_set"
            )
        else:
            self.pwd_last_set = None

        self.distinguished_name = _clean_optional_str(
            distinguished_name
            if distinguished_name is not None
            else (distinguishedName or ou or OU)
        )

    @property
    def sAMAccountName(self) -> str:
        return self.sam_account_name

    @property
    def dNSHostName(self) -> Optional[str]:
        return self.dns_hostname

    @property
    def operatingSystem(self) -> Optional[str]:
        return self.operating_system

    @property
    def lastLogonTimestamp(self) -> Optional[datetime]:
        return self.last_logon_timestamp

    @property
    def pwdLastSet(self) -> Optional[datetime]:
        return self.pwd_last_set

    @property
    def distinguishedName(self) -> Optional[str]:
        return self.distinguished_name

    @property
    def ou(self) -> Optional[str]:
        return self.distinguished_name

    @property
    def normalized_hostname(self) -> Optional[str]:
        return normalize_hostname(self.dns_hostname or self.sam_account_name)

    def to_dict(self) -> dict[str, Any]:
        logon_iso = (
            self.last_logon_timestamp.isoformat()
            if self.last_logon_timestamp is not None
            else None
        )
        pwd_iso = (
            self.pwd_last_set.isoformat() if self.pwd_last_set is not None else None
        )
        return {
            "sam_account_name": self.sam_account_name,
            "sAMAccountName": self.sam_account_name,
            "dns_hostname": self.dns_hostname,
            "dNSHostName": self.dns_hostname,
            "operating_system": self.operating_system,
            "operatingSystem": self.operating_system,
            "enabled": self.enabled,
            "last_logon_timestamp": logon_iso,
            "lastLogonTimestamp": logon_iso,
            "pwd_last_set": pwd_iso,
            "pwdLastSet": pwd_iso,
            "distinguished_name": self.distinguished_name,
            "distinguishedName": self.distinguished_name,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AdComputerRecord:
        enabled_val = data.get("enabled")
        if enabled_val is None:
            enabled_val = data.get("is_enabled", data.get("account_enabled", True))
        return cls(
            sam_account_name=(
                data.get("sam_account_name")
                or data.get("sAMAccountName")
                or data.get("account_name")
                or data.get("name")
                or data.get("cn")
            ),
            dns_hostname=(
                data.get("dns_hostname")
                or data.get("dNSHostName")
                or data.get("fqdn")
                or data.get("hostname")
            ),
            operating_system=(
                data.get("operating_system")
                or data.get("operatingSystem")
                or data.get("os")
            ),
            enabled=enabled_val,
            last_logon_timestamp=(
                data.get("last_logon_timestamp")
                if data.get("last_logon_timestamp") is not None
                else (data.get("lastLogonTimestamp") or data.get("last_logon"))
            ),
            pwd_last_set=(
                data.get("pwd_last_set")
                if data.get("pwd_last_set") is not None
                else (data.get("pwdLastSet") or data.get("password_last_set"))
            ),
            distinguished_name=(
                data.get("distinguished_name")
                or data.get("distinguishedName")
                or data.get("dn")
                or data.get("ou")
                or data.get("OU")
            ),
        )


class ActiveDirectoryCollector(SignalCollector):
    """Correlate SoT equipment and device hostnames against Active Directory computer accounts."""

    signal_type = SignalType.AD_COMPUTER_ACCOUNT

    def __init__(
        self,
        records: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]] = None,
        *,
        accounts: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]] = None,
        active_threshold_days: Optional[float] = None,
        active_within_days: Optional[float] = None,
        stale_threshold_days: Optional[float] = None,
        stale_after_days: Optional[float] = None,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "active_directory",
    ) -> None:
        resolved_active = (
            active_threshold_days
            if active_threshold_days is not None
            else (active_within_days if active_within_days is not None else 30.0)
        )
        resolved_stale = (
            stale_threshold_days
            if stale_threshold_days is not None
            else (stale_after_days if stale_after_days is not None else 90.0)
        )
        self.active_threshold_days, self.stale_threshold_days = (
            validate_recency_thresholds(resolved_active, resolved_stale)
        )
        self.active_within_days = self.active_threshold_days
        self.stale_after_days = self.stale_threshold_days
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = source

        raw_records = records if records is not None else accounts
        self._records: list[AdComputerRecord] = self._coerce_records(raw_records)

    @staticmethod
    def _coerce_records(
        records: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]],
    ) -> list[AdComputerRecord]:
        if records is None:
            return []
        if isinstance(records, Mapping):
            # Support dict keyed by hostname or {"records": [...]} / {"accounts": [...]}
            if "records" in records and isinstance(records["records"], Iterable):
                records = records["records"]
            elif "accounts" in records and isinstance(records["accounts"], Iterable):
                records = records["accounts"]
            else:
                coerced_map: list[AdComputerRecord] = []
                for key, val in records.items():
                    if isinstance(val, AdComputerRecord):
                        coerced_map.append(val)
                    elif isinstance(val, Mapping):
                        item_dict = dict(val)
                        item_dict.setdefault("sam_account_name", str(key))
                        coerced_map.append(AdComputerRecord.from_dict(item_dict))
                return coerced_map

        out: list[AdComputerRecord] = []
        for item in records:
            if isinstance(item, AdComputerRecord):
                out.append(item)
            elif isinstance(item, Mapping):
                out.append(AdComputerRecord.from_dict(item))
            else:
                raise ValueError(f"Unsupported AD computer record: {item!r}")
        return out

    @property
    def records(self) -> tuple[AdComputerRecord, ...]:
        return tuple(self._records)

    @staticmethod
    def _extract_target_hostnames(
        target: Any, site: Optional[Site] = None
    ) -> tuple[list[str], str]:
        if isinstance(target, Equipment):
            return [target.name], f"Equipment {target.name} ({target.equipment_id})"
        if isinstance(target, NetworkDevice):
            return [target.hostname], f"NetworkDevice {target.hostname} ({target.device_id})"
        if isinstance(target, IPAddress):
            hosts: list[str] = []
            for attr in ("hostname", "dns_name", "name"):
                val = getattr(target, attr, None)
                if isinstance(val, str) and val.strip():
                    hosts.append(val.strip())
            if site is not None:
                for eq in site.equipment:
                    if (
                        target.assigned_object_id == eq.equipment_id
                        or target.ip in eq.assigned_ips
                    ):
                        if eq.name not in hosts:
                            hosts.append(eq.name)
                for dev in site.devices:
                    if (
                        target.assigned_object_id == dev.device_id
                        or dev.management_ip == target.ip
                    ):
                        if dev.hostname not in hosts:
                            hosts.append(dev.hostname)
            return hosts, f"IPAddress {target.ip}"
        if isinstance(target, str):
            cleaned = target.strip()
            return ([cleaned] if cleaned else []), f"hostname {cleaned!r}"
        if isinstance(target, Mapping):
            raw_host = (
                target.get("name")
                or target.get("hostname")
                or target.get("dns_hostname")
                or target.get("dNSHostName")
                or target.get("sam_account_name")
                or target.get("sAMAccountName")
            )
            cleaned = _clean_optional_str(raw_host)
            return ([cleaned] if cleaned else []), "mapping"
        return [], type(target).__name__

    @staticmethod
    def _match_record(
        candidate_hostnames: Sequence[str],
        records: Sequence[AdComputerRecord],
    ) -> Optional[AdComputerRecord]:
        target_fqdns = {
            fqdn
            for h in candidate_hostnames
            if (fqdn := _normalize_fqdn(h)) is not None and "." in fqdn
        }
        target_shorts = {
            short
            for h in candidate_hostnames
            if (short := normalize_hostname(h)) is not None
        }
        if not target_fqdns and not target_shorts:
            return None

        fqdn_matches: list[AdComputerRecord] = []
        short_matches: list[AdComputerRecord] = []

        for rec in records:
            rec_fqdn = _normalize_fqdn(rec.dns_hostname)
            rec_sam_short = normalize_hostname(rec.sam_account_name)
            rec_dns_short = normalize_hostname(rec.dns_hostname)

            if target_fqdns and rec_fqdn in target_fqdns:
                fqdn_matches.append(rec)
                continue

            if (rec_sam_short and rec_sam_short in target_shorts) or (
                rec_dns_short and rec_dns_short in target_shorts
            ):
                short_matches.append(rec)

        matches = fqdn_matches if fqdn_matches else short_matches
        if not matches:
            return None

        def _sort_key(rec: AdComputerRecord) -> tuple[int, float]:
            timestamps = [
                ts.timestamp()
                for ts in (rec.last_logon_timestamp, rec.pwd_last_set)
                if ts is not None
            ]
            freshest_ts = max(timestamps) if timestamps else float("-inf")
            return (1 if rec.enabled else 0, freshest_ts)

        return max(matches, key=_sort_key)

    def evaluate(
        self,
        target: Any,
        *,
        site: Optional[Site] = None,
        records: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]] = None,
        accounts: Optional[Iterable[AdComputerRecord | Mapping[str, Any]]] = None,
        active_threshold_days: Optional[float] = None,
        active_within_days: Optional[float] = None,
        stale_threshold_days: Optional[float] = None,
        stale_after_days: Optional[float] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate Active Directory computer account status and timestamp recency for target."""
        _ = kwargs
        raw_active = (
            active_threshold_days
            if active_threshold_days is not None
            else (
                active_within_days
                if active_within_days is not None
                else self.active_threshold_days
            )
        )
        raw_stale = (
            stale_threshold_days
            if stale_threshold_days is not None
            else (
                stale_after_days
                if stale_after_days is not None
                else self.stale_threshold_days
            )
        )
        active_days, stale_days = validate_recency_thresholds(raw_active, raw_stale)

        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (
                self.evaluation_time
                if self.evaluation_time is not None
                else resolve_evaluation_time(None)
            )
        )

        pool = (
            self._coerce_records(records if records is not None else accounts)
            if (records is not None or accounts is not None)
            else self._records
        )

        candidate_hosts, target_label = self._extract_target_hostnames(
            target, site=site
        )
        if not candidate_hosts:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"No hostname available on {target_label} for AD correlation",
                source=self.source,
                metadata={"matched": False},
            )

        record = self._match_record(candidate_hosts, pool)
        if record is None:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=(
                    f"No matching Active Directory computer account found for {target_label}"
                ),
                source=self.source,
                metadata={
                    "matched": False,
                    "normalized_hostname": normalize_hostname(candidate_hosts[0]),
                },
            )

        timestamp_candidates: list[tuple[str, datetime, float]] = []
        if record.last_logon_timestamp is not None:
            age_logon = max(
                0.0, (eval_dt - record.last_logon_timestamp).total_seconds()
            )
            timestamp_candidates.append(
                ("lastLogonTimestamp", record.last_logon_timestamp, age_logon)
            )
        if record.pwd_last_set is not None:
            age_pwd = max(0.0, (eval_dt - record.pwd_last_set).total_seconds())
            timestamp_candidates.append(("pwdLastSet", record.pwd_last_set, age_pwd))

        freshest_attr: Optional[str] = None
        freshest_dt: Optional[datetime] = None
        freshest_age_sec: Optional[float] = None
        if timestamp_candidates:
            freshest_attr, freshest_dt, freshest_age_sec = min(
                timestamp_candidates,
                key=lambda item: (item[2], -item[1].timestamp()),
            )

        os_label = record.operating_system or "Windows"
        active_sec = active_days * SECONDS_PER_DAY
        stale_sec = stale_days * SECONDS_PER_DAY

        if not record.enabled:
            status = SignalStatus.INACTIVE
            account_stale = True
            ts_note = (
                f", {freshest_attr}={freshest_dt.isoformat()} "
                f"(age {freshest_age_sec / SECONDS_PER_DAY:.2f}d)"
                if freshest_dt is not None and freshest_age_sec is not None
                else ""
            )
            details = (
                f"AD computer account {record.sam_account_name} is disabled "
                f"(enabled=False, os={os_label}{ts_note})"
            )
        elif freshest_dt is None or freshest_age_sec is None:
            status = SignalStatus.INACTIVE
            account_stale = True
            details = (
                f"AD computer account {record.sam_account_name} is enabled "
                f"(os={os_label}) but has no lastLogonTimestamp or pwdLastSet recorded"
            )
        elif freshest_age_sec <= active_sec:
            status = SignalStatus.ACTIVE
            account_stale = False
            age_days = freshest_age_sec / SECONDS_PER_DAY
            details = (
                f"AD computer account {record.sam_account_name} is active "
                f"(enabled=True, os={os_label}, {freshest_attr}={freshest_dt.isoformat()}, "
                f"age {age_days:.2f}d <= active threshold {active_days:g}d)"
            )
        elif freshest_age_sec <= stale_sec:
            status = SignalStatus.INACTIVE
            account_stale = False
            age_days = freshest_age_sec / SECONDS_PER_DAY
            details = (
                f"AD computer account {record.sam_account_name} is in intermediate aging window "
                f"(enabled=True, os={os_label}, {freshest_attr}={freshest_dt.isoformat()}, "
                f"age {age_days:.2f}d > active threshold {active_days:g}d, "
                f"<= stale threshold {stale_days:g}d)"
            )
        else:
            status = SignalStatus.INACTIVE
            account_stale = True
            age_days = freshest_age_sec / SECONDS_PER_DAY
            details = (
                f"AD computer account {record.sam_account_name} is stale "
                f"(enabled=True, os={os_label}, {freshest_attr}={freshest_dt.isoformat()}, "
                f"age {age_days:.2f}d > stale threshold {stale_days:g}d)"
            )

        metadata: dict[str, Any] = {
            "matched": True,
            "sAMAccountName": record.sam_account_name,
            "sam_account_name": record.sam_account_name,
            "dNSHostName": record.dns_hostname,
            "dns_hostname": record.dns_hostname,
            "operatingSystem": record.operating_system,
            "operating_system": record.operating_system,
            "enabled": record.enabled,
            "distinguishedName": record.distinguished_name,
            "distinguished_name": record.distinguished_name,
            "lastLogonTimestamp": (
                record.last_logon_timestamp.isoformat()
                if record.last_logon_timestamp is not None
                else None
            ),
            "pwdLastSet": (
                record.pwd_last_set.isoformat()
                if record.pwd_last_set is not None
                else None
            ),
            "account_stale": account_stale,
            "normalized_hostname": record.normalized_hostname,
        }

        return ValidationSignal(
            signal_type=self.signal_type,
            status=status,
            observed_at=freshest_dt,
            age_seconds=freshest_age_sec,
            details=details,
            source=self.source,
            metadata=metadata,
        )

    def collect(self, target: Any, **kwargs: Any) -> ValidationSignal:
        """Convenience alias for evaluate()."""
        return self.evaluate(target, **kwargs)

    def collect_for_equipment(
        self, equipment: Equipment, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate AD computer account signal for an Equipment record."""
        return self.evaluate(equipment, **kwargs)

    def collect_for_device(
        self, device: NetworkDevice, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate AD computer account signal for a NetworkDevice record."""
        return self.evaluate(device, **kwargs)


@dataclass(init=False)
class DnsRecord:
    """Forward ('A') or reverse ('PTR') DNS record."""

    record_type: str
    hostname: str
    ip: str
    ttl: Optional[int] = None
    observed_at: Optional[datetime] = None

    def __init__(
        self,
        record_type: str = "A",
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        ttl: Optional[int] = None,
        observed_at: Optional[datetime | str] = None,
        *,
        type: Optional[str] = None,
        name: Optional[str] = None,
        fqdn: Optional[str] = None,
        ptrdname: Optional[str] = None,
        target: Optional[str] = None,
        ip_address: Optional[str] = None,
        address: Optional[str] = None,
    ) -> None:
        raw_type = _clean_optional_str(type if type is not None else record_type)
        if not raw_type:
            raise ValueError("record_type must be 'A' or 'PTR'")
        norm_type = raw_type.upper()
        if norm_type not in ("A", "PTR"):
            raise ValueError(f"Unsupported DNS record_type {raw_type!r}; expected 'A' or 'PTR'")

        raw_host = _clean_optional_str(
            hostname
            if hostname is not None
            else (name or fqdn or ptrdname or target)
        )
        if not raw_host:
            raise ValueError("DNS record hostname must be a non-empty string")

        raw_ip = _clean_optional_str(
            ip if ip is not None else (ip_address or address)
        )
        if not raw_ip:
            raise ValueError("DNS record ip must be a non-empty string")
        parsed_ip = _parse_ipv4_host(raw_ip)

        self.record_type = norm_type
        self.hostname = raw_host
        self.ip = str(parsed_ip)
        self.ttl = int(ttl) if ttl is not None else None
        if observed_at is not None and (
            not isinstance(observed_at, str) or observed_at.strip()
        ):
            self.observed_at = normalize_utc_datetime(
                observed_at, field_name="observed_at"
            )
        else:
            self.observed_at = None

    @property
    def normalized_hostname(self) -> Optional[str]:
        return normalize_hostname(self.hostname)

    @property
    def ip_address(self) -> str:
        return self.ip

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "hostname": self.hostname,
            "ip": self.ip,
            "ttl": self.ttl,
            "observed_at": (
                self.observed_at.isoformat() if self.observed_at is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DnsRecord:
        return cls(
            record_type=data.get("record_type") or data.get("type") or "A",
            hostname=(
                data.get("hostname")
                or data.get("name")
                or data.get("fqdn")
                or data.get("ptrdname")
                or data.get("target")
            ),
            ip=data.get("ip") or data.get("ip_address") or data.get("address"),
            ttl=data.get("ttl"),
            observed_at=data.get("observed_at"),
        )


@dataclass(init=False)
class DhcpLeaseRecord:
    """DHCP lease record scoped to a site's /24 IPv4 subnet."""

    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    subnet_cidr: Optional[str] = None
    status: str = "active"
    lease_expiration: Optional[datetime] = None
    observed_at: Optional[datetime] = None

    def __init__(
        self,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
        mac_address: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
        status: Optional[str] = None,
        lease_expiration: Optional[datetime | str] = None,
        observed_at: Optional[datetime | str] = None,
        *,
        ip_address: Optional[str] = None,
        client_hostname: Optional[str] = None,
        name: Optional[str] = None,
        fqdn: Optional[str] = None,
        mac: Optional[str] = None,
        client_mac: Optional[str] = None,
        subnet: Optional[str] = None,
        cidr: Optional[str] = None,
        scope: Optional[str] = None,
        active: Optional[bool] = None,
        expires_at: Optional[datetime | str] = None,
        lease_end: Optional[datetime | str] = None,
        expiration: Optional[datetime | str] = None,
        last_seen: Optional[datetime | str] = None,
        timestamp: Optional[datetime | str] = None,
    ) -> None:
        raw_ip = _clean_optional_str(ip if ip is not None else ip_address)
        if not raw_ip:
            raise ValueError("DHCP lease ip must be a non-empty string")
        parsed_ip = _parse_ipv4_host(raw_ip)
        self.ip = str(parsed_ip)

        self.hostname = _clean_optional_str(
            hostname
            if hostname is not None
            else (client_hostname or name or fqdn)
        )
        self.mac_address = _clean_optional_str(
            mac_address if mac_address is not None else (mac or client_mac)
        )
        self.subnet_cidr = _clean_optional_str(
            subnet_cidr
            if subnet_cidr is not None
            else (subnet or cidr or scope)
        )

        if status is not None and str(status).strip():
            self.status = str(status).strip().lower()
        elif active is not None:
            self.status = "active" if _parse_bool_flag(active) else "expired"
        else:
            self.status = "active"

        raw_exp = (
            lease_expiration
            if lease_expiration is not None
            else (expires_at or lease_end or expiration)
        )
        if raw_exp is not None and (not isinstance(raw_exp, str) or raw_exp.strip()):
            self.lease_expiration = normalize_utc_datetime(
                raw_exp, field_name="lease_expiration"
            )
        else:
            self.lease_expiration = None

        raw_obs = (
            observed_at
            if observed_at is not None
            else (last_seen or timestamp)
        )
        if raw_obs is not None and (not isinstance(raw_obs, str) or raw_obs.strip()):
            self.observed_at = normalize_utc_datetime(
                raw_obs, field_name="observed_at"
            )
        else:
            self.observed_at = None

    @property
    def ip_address(self) -> str:
        return self.ip

    @property
    def client_hostname(self) -> Optional[str]:
        return self.hostname

    @property
    def normalized_hostname(self) -> Optional[str]:
        return normalize_hostname(self.hostname)

    def is_active(
        self, evaluation_time: Optional[datetime | str] = None
    ) -> bool:
        """Return True if the DHCP lease status is active and not expired."""
        norm_status = self.status.strip().lower()
        if norm_status in (
            "expired",
            "inactive",
            "free",
            "released",
            "abandoned",
            "disabled",
            "false",
            "0",
        ):
            return False
        if norm_status not in (
            "active",
            "bound",
            "leased",
            "reserved",
            "true",
            "1",
        ):
            return False

        if self.lease_expiration is not None:
            if evaluation_time is not None:
                eval_dt = resolve_evaluation_time(evaluation_time)
                if self.lease_expiration <= eval_dt:
                    return False
            elif (
                self.observed_at is not None
                and self.lease_expiration <= self.observed_at
            ):
                return False
        return True

    @property
    def active(self) -> bool:
        return self.is_active()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "subnet_cidr": self.subnet_cidr,
            "status": self.status,
            "lease_expiration": (
                self.lease_expiration.isoformat()
                if self.lease_expiration is not None
                else None
            ),
            "observed_at": (
                self.observed_at.isoformat() if self.observed_at is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DhcpLeaseRecord:
        return cls(
            ip=data.get("ip") or data.get("ip_address"),
            hostname=(
                data.get("hostname")
                or data.get("client_hostname")
                or data.get("name")
                or data.get("fqdn")
            ),
            mac_address=(
                data.get("mac_address")
                or data.get("mac")
                or data.get("client_mac")
            ),
            subnet_cidr=(
                data.get("subnet_cidr")
                or data.get("subnet")
                or data.get("cidr")
                or data.get("scope")
            ),
            status=data.get("status"),
            active=data.get("active"),
            lease_expiration=(
                data.get("lease_expiration")
                if data.get("lease_expiration") is not None
                else (
                    data.get("expires_at")
                    or data.get("lease_end")
                    or data.get("expiration")
                )
            ),
            observed_at=(
                data.get("observed_at")
                if data.get("observed_at") is not None
                else (data.get("last_seen") or data.get("timestamp"))
            ),
        )


class DnsDhcpLeaseCollector(SignalCollector):
    """Correlate forward/reverse DNS ('A'/'PTR') and /24-scoped DHCP leases against SoT records."""

    signal_type = SignalType.DNS_DHCP_LEASE

    def __init__(
        self,
        dns_records: Optional[Iterable[DnsRecord | Mapping[str, Any]]] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        *,
        leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        a_records: Optional[Any] = None,
        forward_records: Optional[Any] = None,
        ptr_records: Optional[Any] = None,
        reverse_records: Optional[Any] = None,
        subnets: Optional[Iterable[Subnet | str]] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "dns_dhcp",
    ) -> None:
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = source

        if scope_guard is not None:
            self.scope_guard: Optional[SubnetScopeGuard] = scope_guard
        elif subnets is not None:
            self.scope_guard = SubnetScopeGuard(subnets=subnets)
        elif site is not None and site.subnets:
            self.scope_guard = SubnetScopeGuard.from_site(site)
        else:
            self.scope_guard = None

        self._dns_records: list[DnsRecord] = self._coerce_dns_records(
            dns_records=dns_records,
            a_records=a_records if a_records is not None else forward_records,
            ptr_records=ptr_records if ptr_records is not None else reverse_records,
        )
        raw_leases = dhcp_leases if dhcp_leases is not None else leases
        self._dhcp_leases: list[DhcpLeaseRecord] = self._coerce_dhcp_leases(raw_leases)
        self._scoped_lease_cache: Optional[
            tuple[
                Optional[SubnetScopeGuard],
                list[tuple[DhcpLeaseRecord, Optional[str]]],
            ]
        ] = None

    @staticmethod
    def _coerce_dns_records(
        *,
        dns_records: Optional[Iterable[DnsRecord | Mapping[str, Any]]] = None,
        a_records: Optional[Any] = None,
        ptr_records: Optional[Any] = None,
    ) -> list[DnsRecord]:
        out: list[DnsRecord] = []

        if dns_records is not None:
            for item in dns_records:
                if isinstance(item, DnsRecord):
                    out.append(item)
                elif isinstance(item, Mapping):
                    out.append(DnsRecord.from_dict(item))
                else:
                    raise ValueError(f"Unsupported DNS record: {item!r}")

        if a_records is not None:
            if isinstance(a_records, Mapping):
                for host, ip_val in a_records.items():
                    if isinstance(ip_val, str):
                        out.append(
                            DnsRecord(record_type="A", hostname=str(host), ip=ip_val)
                        )
                    elif isinstance(ip_val, Iterable):
                        for ip_str in ip_val:
                            out.append(
                                DnsRecord(
                                    record_type="A",
                                    hostname=str(host),
                                    ip=str(ip_str),
                                )
                            )
            elif isinstance(a_records, Iterable):
                for item in a_records:
                    if isinstance(item, DnsRecord):
                        out.append(item)
                    elif isinstance(item, Mapping):
                        d = dict(item)
                        d.setdefault("record_type", "A")
                        out.append(DnsRecord.from_dict(d))
                    else:
                        raise ValueError(f"Unsupported A record: {item!r}")

        if ptr_records is not None:
            if isinstance(ptr_records, Mapping):
                for ip_key, host_val in ptr_records.items():
                    if isinstance(host_val, str):
                        out.append(
                            DnsRecord(
                                record_type="PTR", hostname=host_val, ip=str(ip_key)
                            )
                        )
                    elif isinstance(host_val, Iterable):
                        for host_str in host_val:
                            out.append(
                                DnsRecord(
                                    record_type="PTR",
                                    hostname=str(host_str),
                                    ip=str(ip_key),
                                )
                            )
            elif isinstance(ptr_records, Iterable):
                for item in ptr_records:
                    if isinstance(item, DnsRecord):
                        out.append(item)
                    elif isinstance(item, Mapping):
                        d = dict(item)
                        d.setdefault("record_type", "PTR")
                        out.append(DnsRecord.from_dict(d))
                    else:
                        raise ValueError(f"Unsupported PTR record: {item!r}")

        return out

    @staticmethod
    def _coerce_dhcp_leases(
        leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]],
    ) -> list[DhcpLeaseRecord]:
        if leases is None:
            return []
        if isinstance(leases, Mapping):
            if "leases" in leases and isinstance(leases["leases"], Iterable):
                leases = leases["leases"]
            elif "dhcp_leases" in leases and isinstance(
                leases["dhcp_leases"], Iterable
            ):
                leases = leases["dhcp_leases"]
            else:
                coerced: list[DhcpLeaseRecord] = []
                for ip_key, val in leases.items():
                    if isinstance(val, DhcpLeaseRecord):
                        coerced.append(val)
                    elif isinstance(val, Mapping):
                        d = dict(val)
                        d.setdefault("ip", str(ip_key))
                        coerced.append(DhcpLeaseRecord.from_dict(d))
                return coerced

        out: list[DhcpLeaseRecord] = []
        for item in leases:
            if isinstance(item, DhcpLeaseRecord):
                out.append(item)
            elif isinstance(item, Mapping):
                out.append(DhcpLeaseRecord.from_dict(item))
            else:
                raise ValueError(f"Unsupported DHCP lease record: {item!r}")
        return out

    def _resolve_scope_guard(
        self,
        *,
        site: Optional[Site] = None,
        subnets: Optional[Iterable[Subnet | str]] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
    ) -> Optional[SubnetScopeGuard]:
        if scope_guard is not None:
            return scope_guard
        if subnets is not None:
            return SubnetScopeGuard(subnets=subnets)
        if self.scope_guard is not None:
            return self.scope_guard
        if site is not None and site.subnets:
            return SubnetScopeGuard.from_site(site)
        return None

    @staticmethod
    def _is_lease_in_slash24_scope(
        lease: DhcpLeaseRecord,
        guard: Optional[SubnetScopeGuard],
    ) -> bool:
        try:
            addr = _parse_ipv4_host(lease.ip)
        except ScopeViolationError:
            return False

        if lease.subnet_cidr is not None:
            try:
                lease_net = _parse_allocated_slash24(lease.subnet_cidr)
            except ScopeViolationError:
                return False
            if addr not in lease_net:
                return False
            if guard is not None and guard.allocated_subnets:
                try:
                    guard.validate_cidr_scope(lease.subnet_cidr)
                except ScopeViolationError:
                    return False

        if guard is not None:
            return guard.is_ip_in_scope(str(addr))
        return True

    @staticmethod
    def _resolve_target_context(
        target: Any,
        *,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        expected_hostname: Optional[str] = None,
    ) -> tuple[list[str], list[str], str]:
        """Return (target_ips, expected_hostnames, target_label)."""
        ips: list[str] = []
        hosts: list[str] = []

        def _add_ip(raw_ip: Optional[str]) -> None:
            cleaned = _clean_optional_str(raw_ip)
            if cleaned and cleaned not in ips:
                ips.append(cleaned)

        def _add_host(raw_host: Optional[str]) -> None:
            cleaned = _clean_optional_str(raw_host)
            if cleaned and cleaned not in hosts:
                hosts.append(cleaned)

        if expected_hostname:
            _add_host(expected_hostname)

        all_ip_recs: list[IPAddress] = []
        if ip_addresses:
            all_ip_recs.extend(ip_addresses)
        if site is not None:
            all_ip_recs.extend(site.ip_addresses)

        if isinstance(target, IPAddress):
            _add_ip(target.ip)
            for attr in ("hostname", "dns_name", "name"):
                val = getattr(target, attr, None)
                if isinstance(val, str):
                    _add_host(val)
            if site is not None:
                for eq in site.equipment:
                    if (
                        target.assigned_object_id == eq.equipment_id
                        or target.ip in eq.assigned_ips
                    ):
                        _add_host(eq.name)
                for dev in site.devices:
                    if (
                        target.assigned_object_id == dev.device_id
                        or dev.management_ip == target.ip
                    ):
                        _add_host(dev.hostname)
            return ips, hosts, f"IPAddress {target.ip}"

        if isinstance(target, Equipment):
            _add_host(target.name)
            for ip_str in target.assigned_ips:
                _add_ip(ip_str)
            for ip_rec in all_ip_recs:
                if ip_rec.assigned_object_id == target.equipment_id:
                    _add_ip(ip_rec.ip)
            return ips, hosts, f"Equipment {target.name} ({target.equipment_id})"

        if isinstance(target, NetworkDevice):
            _add_host(target.hostname)
            _add_ip(target.management_ip)
            for ip_rec in all_ip_recs:
                if ip_rec.assigned_object_id == target.device_id:
                    _add_ip(ip_rec.ip)
            return ips, hosts, f"NetworkDevice {target.hostname} ({target.device_id})"

        if isinstance(target, str):
            cleaned = target.strip()
            try:
                addr = _parse_ipv4_host(cleaned)
                _add_ip(str(addr))
                return ips, hosts, f"IP {addr}"
            except ScopeViolationError:
                _add_host(cleaned)
                return ips, hosts, f"hostname {cleaned!r}"

        if isinstance(target, Mapping):
            _add_ip(target.get("ip") or target.get("ip_address"))
            _add_host(
                target.get("hostname")
                or target.get("name")
                or target.get("fqdn")
            )
            return ips, hosts, "mapping"

        return ips, hosts, type(target).__name__

    def evaluate(
        self,
        target: Any,
        *,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        dns_records: Optional[Iterable[DnsRecord | Mapping[str, Any]]] = None,
        a_records: Optional[Any] = None,
        forward_records: Optional[Any] = None,
        ptr_records: Optional[Any] = None,
        reverse_records: Optional[Any] = None,
        dhcp_leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        leases: Optional[Iterable[DhcpLeaseRecord | Mapping[str, Any]]] = None,
        subnets: Optional[Iterable[Subnet | str]] = None,
        scope_guard: Optional[SubnetScopeGuard] = None,
        hostname: Optional[str] = None,
        expected_hostname: Optional[str] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate /24-scoped DHCP leases and forward/reverse DNS records for target."""
        _ = kwargs
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (
                self.evaluation_time
                if self.evaluation_time is not None
                else resolve_evaluation_time(None)
            )
        )

        guard = self._resolve_scope_guard(
            site=site, subnets=subnets, scope_guard=scope_guard
        )

        has_custom_dns = any(
            x is not None
            for x in (
                dns_records,
                a_records,
                forward_records,
                ptr_records,
                reverse_records,
            )
        )
        dns_pool = (
            self._coerce_dns_records(
                dns_records=dns_records,
                a_records=a_records if a_records is not None else forward_records,
                ptr_records=ptr_records if ptr_records is not None else reverse_records,
            )
            if has_custom_dns
            else self._dns_records
        )

        raw_leases = dhcp_leases if dhcp_leases is not None else leases
        lease_pool = (
            self._coerce_dhcp_leases(raw_leases)
            if raw_leases is not None
            else self._dhcp_leases
        )

        raw_target_ips, raw_expected_hosts, target_label = self._resolve_target_context(
            target,
            site=site,
            ip_addresses=ip_addresses,
            expected_hostname=expected_hostname or hostname,
        )

        in_scope_target_ips: list[str] = []
        out_of_scope_target_ips: list[str] = []
        for raw_ip in raw_target_ips:
            try:
                parsed_ip = str(_parse_ipv4_host(raw_ip))
            except ScopeViolationError:
                out_of_scope_target_ips.append(raw_ip)
                continue
            if guard is not None and not guard.is_ip_in_scope(parsed_ip):
                out_of_scope_target_ips.append(parsed_ip)
            else:
                in_scope_target_ips.append(parsed_ip)

        sot_ip_set = set(in_scope_target_ips)
        sot_host_set = {
            norm
            for h in raw_expected_hosts
            if (norm := normalize_hostname(h)) is not None
        }

        if not sot_ip_set and not sot_host_set:
            detail_msg = (
                f"Target {target_label} IP(s) {out_of_scope_target_ips} outside allocated /24 subnet scope"
                if out_of_scope_target_ips
                else f"No in-scope IP or hostname available for {target_label}"
            )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=detail_msg,
                source=self.source,
                metadata={
                    "dns_mismatch": False,
                    "dhcp_lease_active": False,
                    "out_of_scope_ips": out_of_scope_target_ips,
                },
            )

        # Filter DHCP leases to allocated /24 scope and match against target
        cached = self._scoped_lease_cache
        if lease_pool is self._dhcp_leases and cached is not None and cached[0] is guard:
            # The collector's own lease pool only needs filtering once per guard
            scoped_leases = cached[1]
        else:
            scoped_leases = [
                (lease, lease.normalized_hostname)
                for lease in lease_pool
                if self._is_lease_in_slash24_scope(lease, guard)
            ]
            if lease_pool is self._dhcp_leases:
                self._scoped_lease_cache = (guard, scoped_leases)

        matched_leases: list[DhcpLeaseRecord] = []
        for lease, lease_host in scoped_leases:
            ip_match = bool(sot_ip_set and lease.ip in sot_ip_set)
            host_match = bool(
                sot_host_set and lease_host is not None and lease_host in sot_host_set
            )
            if ip_match or host_match:
                matched_leases.append(lease)

        active_leases = [
            lease for lease in matched_leases if lease.is_active(eval_dt)
        ]
        expired_leases = [
            lease for lease in matched_leases if not lease.is_active(eval_dt)
        ]

        # Match forward (A) and reverse (PTR) DNS records
        all_a = [rec for rec in dns_pool if rec.record_type == "A"]
        all_ptr = [rec for rec in dns_pool if rec.record_type == "PTR"]

        matched_a: list[DnsRecord] = []
        matched_ptr: list[DnsRecord] = []

        for rec in all_a:
            if (sot_ip_set and rec.ip in sot_ip_set) or (
                sot_host_set
                and rec.normalized_hostname is not None
                and rec.normalized_hostname in sot_host_set
            ):
                matched_a.append(rec)

        for rec in all_ptr:
            if (sot_ip_set and rec.ip in sot_ip_set) or (
                sot_host_set
                and rec.normalized_hostname is not None
                and rec.normalized_hostname in sot_host_set
            ):
                matched_ptr.append(rec)

        # Expand cross-references so A<->PTR disagreement is detected even when target is IP-only or host-only
        discovered_hosts = {
            rec.normalized_hostname
            for rec in (*matched_a, *matched_ptr)
            if rec.normalized_hostname is not None
        }
        discovered_ips = {rec.ip for rec in (*matched_a, *matched_ptr)}

        for rec in all_a:
            if rec not in matched_a and (
                rec.ip in discovered_ips
                or (
                    rec.normalized_hostname is not None
                    and rec.normalized_hostname in discovered_hosts
                )
            ):
                matched_a.append(rec)

        for rec in all_ptr:
            if rec not in matched_ptr and (
                rec.ip in discovered_ips
                or (
                    rec.normalized_hostname is not None
                    and rec.normalized_hostname in discovered_hosts
                )
            ):
                matched_ptr.append(rec)

        if not matched_leases and not matched_a and not matched_ptr:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details=f"No matching /24 DHCP lease or DNS A/PTR records found for {target_label}",
                source=self.source,
                metadata={
                    "dns_mismatch": False,
                    "dhcp_lease_active": False,
                    "out_of_scope_ips": out_of_scope_target_ips,
                },
            )

        # Evaluate DNS/SoT alignment and detect drift
        dns_mismatch = False
        mismatch_reasons: list[str] = []

        a_ips = {rec.ip for rec in matched_a}
        ptr_ips = {rec.ip for rec in matched_ptr}
        a_hosts = {
            rec.normalized_hostname
            for rec in matched_a
            if rec.normalized_hostname is not None
        }
        ptr_hosts = {
            rec.normalized_hostname
            for rec in matched_ptr
            if rec.normalized_hostname is not None
        }

        if sot_ip_set:
            bad_a_ips = sorted(a_ips - sot_ip_set)
            if bad_a_ips:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"DNS A record IP(s) {bad_a_ips} disagree with SoT IP(s) {sorted(sot_ip_set)}"
                )
            bad_ptr_ips = sorted(ptr_ips - sot_ip_set)
            if bad_ptr_ips:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"DNS PTR record IP(s) {bad_ptr_ips} disagree with SoT IP(s) {sorted(sot_ip_set)}"
                )

        if sot_host_set:
            bad_a_hosts = sorted(a_hosts - sot_host_set)
            if bad_a_hosts:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"DNS A hostname(s) {bad_a_hosts} disagree with SoT hostname(s) {sorted(sot_host_set)}"
                )
            bad_ptr_hosts = sorted(ptr_hosts - sot_host_set)
            if bad_ptr_hosts:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"DNS PTR hostname(s) {bad_ptr_hosts} disagree with SoT hostname(s) {sorted(sot_host_set)}"
                )

        if matched_a and matched_ptr:
            if a_ips != ptr_ips:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"forward A IP(s) {sorted(a_ips)} and reverse PTR IP(s) {sorted(ptr_ips)} disagree"
                )
            if a_hosts != ptr_hosts:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"forward A hostname(s) {sorted(a_hosts)} and reverse PTR hostname(s) {sorted(ptr_hosts)} disagree"
                )

        for lease in active_leases:
            if (
                sot_host_set
                and lease.normalized_hostname is not None
                and lease.normalized_hostname not in sot_host_set
            ):
                dns_mismatch = True
                mismatch_reasons.append(
                    f"active DHCP lease hostname {lease.normalized_hostname!r} disagrees with SoT {sorted(sot_host_set)}"
                )
            if sot_ip_set and lease.ip not in sot_ip_set:
                dns_mismatch = True
                mismatch_reasons.append(
                    f"active DHCP lease IP {lease.ip} disagrees with SoT IP(s) {sorted(sot_ip_set)}"
                )
            if (
                lease.normalized_hostname is not None
                and (a_hosts or ptr_hosts)
                and lease.normalized_hostname not in (a_hosts | ptr_hosts)
            ):
                dns_mismatch = True
                mismatch_reasons.append(
                    f"active DHCP lease hostname {lease.normalized_hostname!r} disagrees with DNS {sorted(a_hosts | ptr_hosts)}"
                )

        # Resolve observed_at and age_seconds from matching lease/DNS timestamps if available
        obs_candidates: list[datetime] = []
        for lease in active_leases or expired_leases:
            if lease.observed_at is not None:
                obs_candidates.append(lease.observed_at)
        for rec in (*matched_a, *matched_ptr):
            if rec.observed_at is not None:
                obs_candidates.append(rec.observed_at)

        observed_at = max(obs_candidates) if obs_candidates else eval_dt
        age_seconds = max(0.0, (eval_dt - observed_at).total_seconds())

        has_dns_records = bool(matched_a or matched_ptr)
        if active_leases:
            status = SignalStatus.ACTIVE
            lease_ips = [lease.ip for lease in active_leases]
            detail_parts = [
                f"Active /24 DHCP lease on {', '.join(lease_ips)} for {target_label}"
            ]
            if has_dns_records and not dns_mismatch:
                detail_parts.append("DNS A/PTR aligned (dns_mismatch=False)")
            elif dns_mismatch:
                detail_parts.append(
                    f"dns_mismatch=True ({'; '.join(mismatch_reasons)})"
                )
            details = "; ".join(detail_parts)
        elif has_dns_records and not dns_mismatch:
            status = SignalStatus.ACTIVE
            details = (
                f"DNS records aligned for {target_label} "
                f"(A={len(matched_a)}, PTR={len(matched_ptr)}, dns_mismatch=False)"
            )
        elif dns_mismatch:
            status = SignalStatus.INACTIVE
            details = (
                f"DNS/SoT mismatch for {target_label}: "
                f"dns_mismatch=True ({'; '.join(mismatch_reasons)})"
            )
        else:
            status = SignalStatus.INACTIVE
            exp_ips = [lease.ip for lease in expired_leases]
            details = (
                f"Expired/inactive /24 DHCP lease on {', '.join(exp_ips)} for {target_label} "
                "(dns_mismatch=False)"
            )

        metadata = {
            "dns_mismatch": dns_mismatch,
            "mismatch_reasons": mismatch_reasons,
            "dhcp_lease_active": bool(active_leases),
            "lease_active": bool(active_leases),
            "matched_ips": sorted(
                {
                    *(lease.ip for lease in matched_leases),
                    *a_ips,
                    *ptr_ips,
                }
            ),
            "a_records": [rec.to_dict() for rec in matched_a],
            "ptr_records": [rec.to_dict() for rec in matched_ptr],
            "dhcp_leases": [lease.to_dict() for lease in matched_leases],
            "out_of_scope_ips": out_of_scope_target_ips,
        }

        return ValidationSignal(
            signal_type=self.signal_type,
            status=status,
            observed_at=observed_at,
            age_seconds=age_seconds,
            details=details,
            source=self.source,
            metadata=metadata,
        )

    def collect(self, target: Any, **kwargs: Any) -> ValidationSignal:
        """Convenience alias for evaluate()."""
        return self.evaluate(target, **kwargs)

    def collect_for_ip(
        self, ip_address: IPAddress | str, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate DNS/DHCP signal for an IPAddress record or IP string."""
        return self.evaluate(ip_address, **kwargs)

    def collect_for_equipment(
        self, equipment: Equipment, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate DNS/DHCP signal for an Equipment record."""
        return self.evaluate(equipment, **kwargs)

    def collect_for_device(
        self, device: NetworkDevice, **kwargs: Any
    ) -> ValidationSignal:
        """Evaluate DNS/DHCP signal for a NetworkDevice record."""
        return self.evaluate(device, **kwargs)


__all__ = [
    "ActiveDirectoryCollector",
    "AdComputerRecord",
    "DhcpLeaseRecord",
    "DnsDhcpLeaseCollector",
    "DnsRecord",
    "normalize_hostname",
]
