"""Thread-safe run metrics registry and atomic Prometheus textfile writer.

``MetricsRegistry`` holds counters, gauges and histograms and renders them in the
Prometheus text exposition format (``# HELP`` / ``# TYPE`` lines, metrics sorted by
name, series sorted by label values, trailing newline). ``write_textfile(path,
registry)`` is the canonical writer; ``MetricsRegistry.write_textfile(path)``
delegates to it. The file is written to a temp file in the same directory and
moved into place with ``os.replace``, so a scraper never sees a partial file.

node_exporter textfile collector usage: point ``--collector.textfile.directory``
at a directory and write a ``*.prom`` file there at the end of each run, e.g.
``write_textfile("/var/lib/node_exporter/textfile/sot_validator.prom", registry)``.
The temp file uses a ``.tmp`` suffix, so the collector never reads it.

Starter metric set (``register_starter_metrics``):

- ``sot_run_last_success_timestamp_seconds`` (gauge, no labels): Unix time the
  last validation run finished successfully.
- ``sot_run_duration_seconds`` (gauge, no labels): wall-clock duration of the
  last validation run, in seconds.
- ``sot_site_status`` (gauge, labels ``site``, ``status``): 1 for the site's
  current run status (e.g. ``ok``, ``failed``, ``skipped``), 0 otherwise.
- ``sot_records_total`` (counter, labels ``site``, ``classification``): records
  classified per site and classification.
- ``sot_collector_errors_total`` (counter, label ``collector``): errors raised by
  each signal collector.
- ``sot_probe_duration_seconds`` (histogram, no labels, buckets
  ``DEFAULT_PROBE_BUCKETS``): latency of individual active probes, in seconds.

Unlabelled counters and gauges render a ``0`` sample before their first update;
labelled metrics render only the series that have been updated. Histogram ``le``
bounds use Python float formatting (``0.1``, ``1.0``) plus ``+Inf``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
import math
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Union

METRIC_NAME_PATTERN = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
LABEL_NAME_PATTERN = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
DEFAULT_PROBE_BUCKETS: tuple[float, ...] = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)

LabelValues = tuple[str, ...]


def _format_value(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if float(value).is_integer():
        return str(int(value))
    return repr(float(value))


def _format_bound(bound: float) -> str:
    return "+Inf" if math.isinf(bound) else repr(float(bound))


def _escape_help(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n")


def _escape_label_value(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_labels(pairs: Sequence[tuple[str, str]]) -> str:
    if not pairs:
        return ""
    body = ",".join(f'{name}="{_escape_label_value(value)}"' for name, value in pairs)
    return "{" + body + "}"


def _validate_number(value: Any, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{what} must be a number, got {value!r}")
    number = float(value)
    if math.isnan(number):
        raise ValueError(f"{what} must not be NaN")
    return number


class _Metric:
    metric_type = ""

    def __init__(
        self,
        name: str,
        help: str,
        labelnames: tuple[str, ...],
        lock: threading.RLock,
    ) -> None:
        if not isinstance(help, str):
            raise ValueError(f"Metric {name!r} help text must be a string")
        self.name = name
        self.help = help
        self.labelnames = labelnames
        self._lock = lock
        self._series: dict[LabelValues, Any] = {}

    def _key(self, labels: dict[str, Any]) -> LabelValues:
        if set(labels) != set(self.labelnames) or len(labels) != len(self.labelnames):
            raise ValueError(
                f"Metric {self.name!r} expects labels {list(self.labelnames)}, "
                f"got {sorted(labels)}"
            )
        return tuple(str(labels[name]) for name in self.labelnames)

    def _render_samples(self) -> list[str]:
        raise NotImplementedError

    def render(self) -> list[str]:
        lines = [
            f"# HELP {self.name} {_escape_help(self.help)}",
            f"# TYPE {self.name} {self.metric_type}",
        ]
        lines.extend(self._render_samples())
        return lines


class _ScalarMetric(_Metric):
    def _render_samples(self) -> list[str]:
        series = dict(self._series)
        if not self.labelnames and not series:
            series[()] = 0.0
        return [
            f"{self.name}{_format_labels(list(zip(self.labelnames, key)))} {_format_value(value)}"
            for key, value in sorted(series.items())
        ]

    def get(self, **labels: Any) -> float:
        """Return the current value of a series (0 when never updated)."""
        key = self._key(labels)
        with self._lock:
            return self._series.get(key, 0.0)


class Counter(_ScalarMetric):
    """Monotonic counter; increments must be non-negative."""

    metric_type = "counter"

    def inc(self, amount: float = 1, /, **labels: Any) -> None:
        number = _validate_number(amount, "Counter increment")
        if number < 0:
            raise ValueError(f"Counter {self.name!r} increment must be >= 0, got {amount!r}")
        key = self._key(labels)
        with self._lock:
            self._series[key] = self._series.get(key, 0.0) + number


class Gauge(_ScalarMetric):
    """Gauge that can be set, increased and decreased."""

    metric_type = "gauge"

    def set(self, value: float, /, **labels: Any) -> None:
        number = _validate_number(value, "Gauge value")
        key = self._key(labels)
        with self._lock:
            self._series[key] = number

    def inc(self, amount: float = 1, /, **labels: Any) -> None:
        number = _validate_number(amount, "Gauge increment")
        key = self._key(labels)
        with self._lock:
            self._series[key] = self._series.get(key, 0.0) + number

    def dec(self, amount: float = 1, /, **labels: Any) -> None:
        number = _validate_number(amount, "Gauge decrement")
        key = self._key(labels)
        with self._lock:
            self._series[key] = self._series.get(key, 0.0) - number


class Histogram(_Metric):
    """Fixed-bucket histogram; ``+Inf`` is always the last bucket."""

    metric_type = "histogram"

    def __init__(
        self,
        name: str,
        help: str,
        labelnames: tuple[str, ...],
        lock: threading.RLock,
        buckets: tuple[float, ...],
    ) -> None:
        super().__init__(name, help, labelnames, lock)
        self.buckets = buckets

    def observe(self, value: float, /, **labels: Any) -> None:
        number = _validate_number(value, "Histogram observation")
        key = self._key(labels)
        with self._lock:
            state = self._series.get(key)
            if state is None:
                state = {"counts": [0] * len(self.buckets), "sum": 0.0, "count": 0}
                self._series[key] = state
            for index, bound in enumerate(self.buckets):
                if number <= bound:
                    state["counts"][index] += 1
                    break
            state["sum"] += number
            state["count"] += 1

    def _render_samples(self) -> list[str]:
        series = dict(self._series)
        if not self.labelnames and not series:
            series[()] = {"counts": [0] * len(self.buckets), "sum": 0.0, "count": 0}
        lines: list[str] = []
        for key, state in sorted(series.items()):
            pairs = list(zip(self.labelnames, key))
            cumulative = 0
            for bound, count in zip(self.buckets, state["counts"]):
                cumulative += count
                labels = _format_labels(pairs + [("le", _format_bound(bound))])
                lines.append(f"{self.name}_bucket{labels} {cumulative}")
            lines.append(f"{self.name}_sum{_format_labels(pairs)} {_format_value(state['sum'])}")
            lines.append(f"{self.name}_count{_format_labels(pairs)} {state['count']}")
        return lines


def _validate_metric_name(name: Any) -> str:
    if not isinstance(name, str) or not METRIC_NAME_PATTERN.fullmatch(name):
        raise ValueError(f"Invalid metric name: {name!r}")
    return name


def _validate_labelnames(labelnames: Iterable[str], *, histogram: bool) -> tuple[str, ...]:
    if isinstance(labelnames, str):
        raise ValueError("labelnames must be a sequence of names, not a string")
    names = tuple(labelnames)
    for label in names:
        if not isinstance(label, str) or not LABEL_NAME_PATTERN.fullmatch(label):
            raise ValueError(f"Invalid label name: {label!r}")
        if label.startswith("__"):
            raise ValueError(f"Label names starting with '__' are reserved: {label!r}")
        if histogram and label == "le":
            raise ValueError("'le' is reserved for histogram buckets")
    if len(set(names)) != len(names):
        raise ValueError(f"Duplicate label names: {list(names)}")
    return names


def _validate_buckets(buckets: Iterable[float]) -> tuple[float, ...]:
    bounds = tuple(_validate_number(bound, "Histogram bucket") for bound in buckets)
    if not bounds:
        raise ValueError("Histogram buckets must not be empty")
    for previous, current in zip(bounds, bounds[1:]):
        if not current > previous:
            raise ValueError(f"Histogram buckets must be strictly increasing: {list(bounds)}")
    if not math.isinf(bounds[-1]):
        bounds = bounds + (math.inf,)
    return bounds


class MetricsRegistry:
    """Thread-safe collection of counters, gauges and histograms."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._metrics: dict[str, _Metric] = {}

    def _register(self, cls: type[_Metric], name: str, labelnames: tuple[str, ...], build: Any) -> Any:
        with self._lock:
            existing = self._metrics.get(name)
            if existing is not None:
                if type(existing) is not cls:
                    raise ValueError(
                        f"Metric {name!r} already registered as {existing.metric_type}"
                    )
                if existing.labelnames != labelnames:
                    raise ValueError(
                        f"Metric {name!r} already registered with labels {list(existing.labelnames)}"
                    )
                return existing
            metric = build()
            self._metrics[name] = metric
            return metric

    def counter(self, name: str, help: str, labelnames: Iterable[str] = ()) -> Counter:
        _validate_metric_name(name)
        labels = _validate_labelnames(labelnames, histogram=False)
        return self._register(Counter, name, labels, lambda: Counter(name, help, labels, self._lock))

    def gauge(self, name: str, help: str, labelnames: Iterable[str] = ()) -> Gauge:
        _validate_metric_name(name)
        labels = _validate_labelnames(labelnames, histogram=False)
        return self._register(Gauge, name, labels, lambda: Gauge(name, help, labels, self._lock))

    def histogram(
        self,
        name: str,
        help: str,
        labelnames: Iterable[str] = (),
        buckets: Iterable[float] = DEFAULT_PROBE_BUCKETS,
    ) -> Histogram:
        _validate_metric_name(name)
        labels = _validate_labelnames(labelnames, histogram=True)
        bounds = _validate_buckets(buckets)
        return self._register(
            Histogram, name, labels, lambda: Histogram(name, help, labels, self._lock, bounds)
        )

    def render(self) -> str:
        """Return the Prometheus text exposition of every registered metric."""
        with self._lock:
            lines: list[str] = []
            for name in sorted(self._metrics):
                lines.extend(self._metrics[name].render())
        return "\n".join(lines) + "\n"

    def write_textfile(self, path: Union[str, os.PathLike[str]]) -> None:
        """Atomically write ``render()`` to ``path``; see module-level ``write_textfile``."""
        write_textfile(path, self)


def write_textfile(path: Union[str, os.PathLike[str]], registry: MetricsRegistry) -> None:
    """Atomically write ``registry.render()`` to ``path`` (canonical writer).

    The content goes to a temp file in the same directory, which is flushed,
    fsynced and closed, then moved onto ``path`` with ``os.replace``. On any
    failure the temp file is removed, an existing ``path`` is left unchanged,
    and the exception propagates.
    """
    target = Path(path)
    content = registry.render()
    fd, tmp_name = tempfile.mkstemp(
        dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def register_starter_metrics(registry: MetricsRegistry) -> dict[str, Any]:
    """Register the six starter run metrics on ``registry`` and return them by name."""
    metrics: list[_Metric] = [
        registry.gauge(
            "sot_run_last_success_timestamp_seconds",
            "Unix time the last validation run finished successfully.",
        ),
        registry.gauge(
            "sot_run_duration_seconds",
            "Wall-clock duration of the last validation run in seconds.",
        ),
        registry.gauge(
            "sot_site_status",
            "1 for the current run status of each site, 0 otherwise.",
            ("site", "status"),
        ),
        registry.counter(
            "sot_records_total",
            "Records classified per site and classification.",
            ("site", "classification"),
        ),
        registry.counter(
            "sot_collector_errors_total",
            "Errors raised by each signal collector.",
            ("collector",),
        ),
        registry.histogram(
            "sot_probe_duration_seconds",
            "Latency of individual active probes in seconds.",
            buckets=DEFAULT_PROBE_BUCKETS,
        ),
    ]
    return {metric.name: metric for metric in metrics}
