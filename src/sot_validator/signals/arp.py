"""Passive validation signal evaluator for ARP discovery recency."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Any, Iterable, Optional, Sequence

from sot_validator.models import (
    ArpEntry,
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals.base import (
    SignalCollector,
    evaluate_timestamp_recency,
    normalize_utc_datetime,
    resolve_evaluation_time,
    validate_recency_thresholds,
)


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not isinstance(mac, str):
        return None
    return _normalize_mac_str(mac)


# Called for every IP record on every equipment target, so cache the string work
@lru_cache(maxsize=65536)
def _normalize_mac_str(mac: str) -> Optional[str]:
    cleaned = mac.strip().lower()
    if not cleaned:
        return None
    hex_only = "".join(ch for ch in cleaned if ch not in (":", "-", "."))
    return hex_only or cleaned


def _collect_ports(
    site: Optional[Site], ports: Optional[Sequence[Port]]
) -> list[Port]:
    collected: list[Port] = []
    seen_ids: set[tuple[str, str, str]] = set()

    def _add(port: Port) -> None:
        key = (port.device_id, port.port_id, port.name)
        if key not in seen_ids:
            seen_ids.add(key)
            collected.append(port)

    if ports:
        for port in ports:
            _add(port)
    if site is not None:
        for device in site.devices:
            for port in device.ports:
                _add(port)
    return collected


def _resolve_equipment_macs(
    equipment: Equipment,
    site: Optional[Site],
    ports: Optional[Sequence[Port]],
) -> set[str]:
    macs: set[str] = set()
    connected_refs = set(equipment.connected_ports)
    for port in _collect_ports(site, ports):
        if (
            port.port_id in connected_refs
            or port.name in connected_refs
            or f"{port.device_id}:{port.name}" in connected_refs
            or port.connected_device_id == equipment.equipment_id
        ):
            norm_mac = _normalize_mac(port.connected_mac)
            if norm_mac:
                macs.add(norm_mac)
    return macs


@dataclass
class _ArpCandidate:
    ip: str
    mac: Optional[str]
    raw_timestamp: Any
    source_device_id: Optional[str] = None


class ArpSignalEvaluator(SignalCollector):
    """Evaluate ARP discovery timestamp recency for IPs, ARP entries, equipment, and devices."""

    signal_type = SignalType.ARP_RECENCY

    def __init__(
        self,
        active_within_days: float = 7.0,
        stale_after_days: float = 30.0,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "sot.arp",
    ) -> None:
        self.active_within_days, self.stale_after_days = validate_recency_thresholds(
            active_within_days, stale_after_days
        )
        self.evaluation_time: Optional[datetime] = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = source

    def evaluate(
        self,
        target: Any,
        *,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        arp_entries: Optional[Sequence[ArpEntry]] = None,
        ports: Optional[Sequence[Port]] = None,
        evaluation_time: Optional[datetime | str] = None,
        active_within_days: Optional[float] = None,
        stale_after_days: Optional[float] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate ARP recency for an inventory target."""
        active_days = (
            self.active_within_days
            if active_within_days is None
            else active_within_days
        )
        stale_days = (
            self.stale_after_days if stale_after_days is None else stale_after_days
        )
        active_days, stale_days = validate_recency_thresholds(active_days, stale_days)

        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (
                self.evaluation_time
                if self.evaluation_time is not None
                else resolve_evaluation_time(None)
            )
        )

        candidates = self._extract_candidates(
            target=target,
            site=site,
            ip_addresses=ip_addresses,
            arp_entries=arp_entries,
            ports=ports,
        )

        if not candidates:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=None,
                age_seconds=None,
                details="No correlated IP or ARP records found for target",
                source=self.source,
            )

        active_obs: list[tuple[datetime, float, str]] = []
        inactive_obs: list[tuple[datetime, float, str]] = []
        error_details: list[str] = []
        missing_details: list[str] = []
        per_item_details: list[str] = []

        for cand in candidates:
            ident = f"IP {cand.ip}" + (f" (MAC {cand.mac})" if cand.mac else "")
            if cand.raw_timestamp is None or (
                isinstance(cand.raw_timestamp, str) and not cand.raw_timestamp.strip()
            ):
                msg = f"{ident}: no ARP timestamp recorded"
                missing_details.append(msg)
                per_item_details.append(msg)
                continue

            try:
                obs_dt = normalize_utc_datetime(
                    cand.raw_timestamp, field_name="arp_last_seen"
                )
            except ValueError as exc:
                msg = f"{ident}: malformed ARP timestamp ({exc})"
                error_details.append(msg)
                per_item_details.append(msg)
                continue

            status, obs_utc, age_seconds, summary = evaluate_timestamp_recency(
                observed_at=obs_dt,
                evaluation_time=eval_dt,
                active_within_days=active_days,
                stale_after_days=stale_days,
                label=f"ARP for {ident}",
            )
            per_item_details.append(summary)
            if status is SignalStatus.ACTIVE:
                active_obs.append((obs_utc, age_seconds, summary))
            else:
                inactive_obs.append((obs_utc, age_seconds, summary))

        combined_details = "; ".join(per_item_details)

        if active_obs:
            # Choose freshest active observation (minimum age_seconds / latest observed_at)
            freshest_dt, freshest_age, _ = min(
                active_obs, key=lambda item: (item[1], -item[0].timestamp())
            )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.ACTIVE,
                observed_at=freshest_dt,
                age_seconds=freshest_age,
                details=combined_details,
                source=self.source,
            )

        if inactive_obs:
            # Choose most recent inactive observation (minimum age_seconds / latest observed_at)
            freshest_dt, freshest_age, _ = min(
                inactive_obs, key=lambda item: (item[1], -item[0].timestamp())
            )
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.INACTIVE,
                observed_at=freshest_dt,
                age_seconds=freshest_age,
                details=combined_details,
                source=self.source,
            )

        if error_details:
            return ValidationSignal(
                signal_type=self.signal_type,
                status=SignalStatus.ERROR,
                observed_at=None,
                age_seconds=None,
                details=combined_details,
                source=self.source,
            )

        return ValidationSignal(
            signal_type=self.signal_type,
            status=SignalStatus.NOT_APPLICABLE,
            observed_at=None,
            age_seconds=None,
            details=combined_details or "No ARP timestamp recorded",
            source=self.source,
        )

    def _extract_candidates(
        self,
        *,
        target: Any,
        site: Optional[Site],
        ip_addresses: Optional[Sequence[IPAddress]],
        arp_entries: Optional[Sequence[ArpEntry]],
        ports: Optional[Sequence[Port]],
    ) -> list[_ArpCandidate]:
        if isinstance(target, ArpEntry):
            return [
                _ArpCandidate(
                    ip=target.ip,
                    mac=target.arp_mac,
                    raw_timestamp=target.arp_last_seen,
                    source_device_id=target.arp_source_device_id,
                )
            ]

        if isinstance(target, IPAddress):
            return self._candidates_from_ip_address(target)

        if isinstance(target, Equipment):
            return self._candidates_for_equipment(
                equipment=target,
                site=site,
                ip_addresses=ip_addresses,
                arp_entries=arp_entries,
                ports=ports,
            )

        if isinstance(target, NetworkDevice):
            return self._candidates_for_device(
                device=target,
                site=site,
                ip_addresses=ip_addresses,
                arp_entries=arp_entries,
            )

        if isinstance(target, Iterable) and not isinstance(target, (str, bytes, dict)):
            candidates: list[_ArpCandidate] = []
            for item in target:
                candidates.extend(
                    self._extract_candidates(
                        target=item,
                        site=site,
                        ip_addresses=ip_addresses,
                        arp_entries=arp_entries,
                        ports=ports,
                    )
                )
            return candidates

        return []

    @staticmethod
    def _candidates_from_ip_address(ip_rec: IPAddress) -> list[_ArpCandidate]:
        candidates: list[_ArpCandidate] = []
        top_ts = ip_rec.arp_last_seen
        top_mac = ip_rec.arp_mac
        entry = ip_rec.arp_entry

        if entry is not None and isinstance(entry, ArpEntry):
            entry_ts = entry.arp_last_seen
            entry_mac = entry.arp_mac or top_mac
            if top_ts is not None and entry_ts is not None and top_ts != entry_ts:
                candidates.append(
                    _ArpCandidate(
                        ip=ip_rec.ip,
                        mac=top_mac or entry_mac,
                        raw_timestamp=top_ts,
                        source_device_id=ip_rec.arp_source_device_id,
                    )
                )
                candidates.append(
                    _ArpCandidate(
                        ip=entry.ip or ip_rec.ip,
                        mac=entry_mac,
                        raw_timestamp=entry_ts,
                        source_device_id=entry.arp_source_device_id
                        or ip_rec.arp_source_device_id,
                    )
                )
            else:
                chosen_ts = entry_ts if entry_ts is not None else top_ts
                candidates.append(
                    _ArpCandidate(
                        ip=entry.ip or ip_rec.ip,
                        mac=entry_mac,
                        raw_timestamp=chosen_ts,
                        source_device_id=entry.arp_source_device_id
                        or ip_rec.arp_source_device_id,
                    )
                )
        else:
            candidates.append(
                _ArpCandidate(
                    ip=ip_rec.ip,
                    mac=top_mac,
                    raw_timestamp=top_ts,
                    source_device_id=ip_rec.arp_source_device_id,
                )
            )
        return candidates

    def _candidates_for_equipment(
        self,
        *,
        equipment: Equipment,
        site: Optional[Site],
        ip_addresses: Optional[Sequence[IPAddress]],
        arp_entries: Optional[Sequence[ArpEntry]],
        ports: Optional[Sequence[Port]],
    ) -> list[_ArpCandidate]:
        all_ips: list[IPAddress] = []
        if ip_addresses:
            all_ips.extend(ip_addresses)
        if site is not None:
            all_ips.extend(site.ip_addresses)

        target_ips = {ip.strip() for ip in equipment.assigned_ips if ip and ip.strip()}
        target_macs = _resolve_equipment_macs(equipment, site, ports)

        matched_candidates: list[_ArpCandidate] = []
        matched_ip_set: set[str] = set()
        seen_records: set[int] = set()

        for ip_rec in all_ips:
            if id(ip_rec) in seen_records:
                continue
            ip_mac_norm = _normalize_mac(ip_rec.arp_mac) or (
                _normalize_mac(ip_rec.arp_entry.arp_mac)
                if isinstance(ip_rec.arp_entry, ArpEntry)
                else None
            )
            if (
                ip_rec.ip in target_ips
                or ip_rec.assigned_object_id == equipment.equipment_id
                or (ip_mac_norm is not None and ip_mac_norm in target_macs)
            ):
                seen_records.add(id(ip_rec))
                matched_ip_set.add(ip_rec.ip)
                matched_candidates.extend(self._candidates_from_ip_address(ip_rec))

        if arp_entries:
            for entry in arp_entries:
                entry_mac_norm = _normalize_mac(entry.arp_mac)
                if entry.ip in target_ips or (
                    entry_mac_norm is not None and entry_mac_norm in target_macs
                ):
                    matched_ip_set.add(entry.ip)
                    matched_candidates.append(
                        _ArpCandidate(
                            ip=entry.ip,
                            mac=entry.arp_mac,
                            raw_timestamp=entry.arp_last_seen,
                            source_device_id=entry.arp_source_device_id,
                        )
                    )

        # Include assigned IPs that had no matching IPAddress/ArpEntry record so details reflect them
        for assigned_ip in equipment.assigned_ips:
            cleaned = assigned_ip.strip()
            if cleaned and cleaned not in matched_ip_set:
                matched_ip_set.add(cleaned)
                matched_candidates.append(
                    _ArpCandidate(
                        ip=cleaned,
                        mac=None,
                        raw_timestamp=None,
                    )
                )

        return matched_candidates

    def _candidates_for_device(
        self,
        *,
        device: NetworkDevice,
        site: Optional[Site],
        ip_addresses: Optional[Sequence[IPAddress]],
        arp_entries: Optional[Sequence[ArpEntry]],
    ) -> list[_ArpCandidate]:
        all_ips: list[IPAddress] = []
        if ip_addresses:
            all_ips.extend(ip_addresses)
        if site is not None:
            all_ips.extend(site.ip_addresses)

        mgmt_ip = device.management_ip.strip() if device.management_ip else None
        matched_candidates: list[_ArpCandidate] = []
        matched_ip_set: set[str] = set()
        seen_records: set[int] = set()

        for ip_rec in all_ips:
            if id(ip_rec) in seen_records:
                continue
            if (mgmt_ip and ip_rec.ip == mgmt_ip) or (
                ip_rec.assigned_object_id == device.device_id
            ):
                seen_records.add(id(ip_rec))
                matched_ip_set.add(ip_rec.ip)
                matched_candidates.extend(self._candidates_from_ip_address(ip_rec))

        if arp_entries and mgmt_ip:
            for entry in arp_entries:
                if entry.ip == mgmt_ip:
                    matched_ip_set.add(entry.ip)
                    matched_candidates.append(
                        _ArpCandidate(
                            ip=entry.ip,
                            mac=entry.arp_mac,
                            raw_timestamp=entry.arp_last_seen,
                            source_device_id=entry.arp_source_device_id,
                        )
                    )

        if mgmt_ip and mgmt_ip not in matched_ip_set:
            matched_candidates.append(
                _ArpCandidate(
                    ip=mgmt_ip,
                    mac=None,
                    raw_timestamp=None,
                )
            )

        return matched_candidates


__all__ = ["ArpSignalEvaluator"]
