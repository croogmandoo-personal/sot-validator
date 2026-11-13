"""Tests for structured logging, secret redaction and Prometheus textfile metrics."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timedelta
import io
import json
import logging
import os
import subprocess
import sys
import threading

import pytest

from sot_validator.observability import (
    REDACTION_MASK,
    MetricsRegistry,
    RedactionFilter,
    configure_logging,
    get_logger,
    log_context,
    redact,
    register_starter_metrics,
    run_in_context,
    wrap_with_context,
    write_textfile,
)
from sot_validator.observability import metrics as metrics_module


@pytest.fixture(autouse=True)
def _reset_sot_logger():
    logger = logging.getLogger("sot_validator")
    handlers = list(logger.handlers)
    level = logger.level
    yield
    for handler in list(logger.handlers):
        if handler not in handlers:
            logger.removeHandler(handler)
    logger.setLevel(level)


def _json_lines(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def _observability_handlers() -> list[logging.Handler]:
    return [
        handler
        for handler in logging.getLogger("sot_validator").handlers
        if any(isinstance(f, RedactionFilter) for f in handler.filters)
    ]


# --- Logging shape -----------------------------------------------------------


def test_json_line_shape_and_utc_timestamp():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    get_logger("x").info("hello %s", "world", extra={"foo": 1})
    get_logger("x").warning("multi\nline", extra={"foo": 2})

    raw_lines = stream.getvalue().splitlines()
    assert len(raw_lines) == 2
    records = _json_lines(stream)
    for record in records:
        assert {"ts", "level", "logger", "msg", "run_id", "site_id", "foo"} <= set(record)
        ts = record["ts"]
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        parsed = datetime.fromisoformat(ts)
        assert parsed.utcoffset() == timedelta(0)
        assert record["run_id"] is None
        assert record["site_id"] is None
        assert record["logger"] == "sot_validator.x"
    assert records[0]["msg"] == "hello world"
    assert records[0]["level"] == "INFO"
    assert records[0]["foo"] == 1
    assert records[1]["msg"] == "multi\nline"


def test_json_excludes_standard_record_attributes():
    stream = io.StringIO()
    configure_logging(logging.DEBUG, fmt="json", stream=stream)
    get_logger("x").debug("m", extra={"foo": 1})
    record = _json_lines(stream)[0]
    for attr in ("args", "levelno", "pathname", "lineno", "funcName", "thread", "created", "msecs"):
        assert attr not in record
    assert set(record) == {"ts", "level", "logger", "msg", "run_id", "site_id", "foo"}


def test_reserved_extra_key_does_not_overwrite_core_fields():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    with log_context(run_id="real"):
        get_logger("x").info("m", extra={"run_id": "fake", "ts": "fake", "level": "fake"})
    record = _json_lines(stream)[0]
    assert record["run_id"] == "real"
    assert record["level"] == "INFO"
    assert record["ts"] != "fake"
    assert record["extra_run_id"] == "fake"
    assert record["extra_ts"] == "fake"


def test_non_serialisable_extra_is_stringified():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    marker = object()
    get_logger("x").info("m", extra={"obj": marker, "tags": {"a"}, "keyed": {(1, 2): "v"}})
    record = _json_lines(stream)[0]
    assert record["obj"] == str(marker)
    assert record["tags"] == "{'a'}"
    assert record["keyed"] == {"(1, 2)": "v"}


def test_exc_info_is_included_as_string():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    try:
        raise KeyError("boom")
    except KeyError:
        get_logger("x").error("failed", exc_info=True)
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert isinstance(record["exc_info"], str)
    assert "KeyError" in record["exc_info"]


def test_text_format_contains_core_fields_and_extras():
    stream = io.StringIO()
    configure_logging("INFO", fmt="text", stream=stream)
    with log_context(run_id="r9"):
        get_logger("x").info("hello", extra={"foo": 1})
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    line = lines[0]
    assert "INFO" in line
    assert "sot_validator.x" in line
    assert "hello" in line
    assert "foo=1" in line
    assert "run_id=r9" in line
    assert datetime.fromisoformat(line.split(" ")[0]).utcoffset() == timedelta(0)


def test_configure_logging_twice_installs_one_handler():
    first = io.StringIO()
    second = io.StringIO()
    foreign = logging.NullHandler()
    logging.getLogger("sot_validator").addHandler(foreign)
    try:
        configure_logging("INFO", fmt="json", stream=first)
        configure_logging("INFO", fmt="json", stream=second)
        get_logger("x").info("once")
        assert first.getvalue() == ""
        assert len(second.getvalue().splitlines()) == 1
        assert len(_observability_handlers()) == 1
        assert foreign in logging.getLogger("sot_validator").handlers
    finally:
        logging.getLogger("sot_validator").removeHandler(foreign)


def test_configure_logging_does_not_touch_root_logger():
    root = logging.getLogger()
    before = (list(root.handlers), root.level)
    configure_logging("DEBUG", fmt="text", stream=io.StringIO())
    assert (list(root.handlers), root.level) == before


def test_configure_logging_level_and_format_validation():
    with pytest.raises(ValueError):
        configure_logging("INFO", fmt="xml")
    with pytest.raises(ValueError):
        configure_logging("LOUD")
    configure_logging("warning", stream=io.StringIO())
    assert logging.getLogger("sot_validator").level == logging.WARNING
    configure_logging(logging.DEBUG, stream=io.StringIO())
    assert logging.getLogger("sot_validator").level == logging.DEBUG


def test_configure_logging_defaults_to_stderr(capsys):
    configure_logging("INFO", fmt="json")
    get_logger("x").info("to-stderr")
    captured = capsys.readouterr()
    assert "to-stderr" in captured.err


def test_get_logger_names():
    assert get_logger("foo").name == "sot_validator.foo"
    assert get_logger("sot_validator.bar").name == "sot_validator.bar"
    assert get_logger("sot_validator").name == "sot_validator"
    assert get_logger("sot_validatorx").name == "sot_validator.sot_validatorx"


# --- Context -----------------------------------------------------------------


def test_log_context_sets_resets_and_nests():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    log = get_logger("x")
    with log_context(run_id="r1", site_id="s1"):
        log.info("outer")
        with log_context(run_id="r2", site_id="s2"):
            log.info("inner")
        with log_context(site_id="s3"):
            log.info("site-only")
        log.info("outer-again")
    log.info("after")
    records = _json_lines(stream)
    assert [(r["run_id"], r["site_id"]) for r in records] == [
        ("r1", "s1"),
        ("r2", "s2"),
        ("r1", "s3"),
        ("r1", "s1"),
        (None, None),
    ]


def test_log_context_resets_on_exception():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    with pytest.raises(RuntimeError):
        with log_context(run_id="r1", site_id="s1"):
            raise RuntimeError("x")
    get_logger("x").info("after")
    record = _json_lines(stream)[0]
    assert record["run_id"] is None
    assert record["site_id"] is None


def test_context_propagates_to_threads_only_with_helper():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    log = get_logger("x")

    def work(label):
        log.info(label)

    with log_context(run_id="parent-run", site_id="parent-site"):
        plain = threading.Thread(target=work, args=("plain",))
        plain.start()
        plain.join()
        wrapped = threading.Thread(target=run_in_context(work, "wrapped"))
        wrapped.start()
        wrapped.join()
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(wrap_with_context(work), ["pool-1", "pool-2"]))

    by_msg = {r["msg"]: r for r in _json_lines(stream)}
    assert (by_msg["plain"]["run_id"], by_msg["plain"]["site_id"]) == (None, None)
    for label in ("wrapped", "pool-1", "pool-2"):
        assert (by_msg[label]["run_id"], by_msg[label]["site_id"]) == ("parent-run", "parent-site")


def test_two_threads_with_different_contexts_log_their_own_values():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    log = get_logger("x")
    barrier = threading.Barrier(2)

    def work(run_id, site_id):
        with log_context(run_id=run_id, site_id=site_id):
            barrier.wait()
            log.info(run_id)
            barrier.wait()
            log.info(run_id)

    threads = [
        threading.Thread(target=work, args=("run-a", "site-a")),
        threading.Thread(target=work, args=("run-b", "site-b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    records = _json_lines(stream)
    assert len(records) == 4
    for record in records:
        assert record["site_id"] == record["run_id"].replace("run", "site")


# --- Redaction ---------------------------------------------------------------


def _secret_extra():
    return {
        "snmp_community": "public",
        "cfg": {"API_Token": "abc", "hosts": [{"Password": "p", "name": "h1"}]},
        "authorization": ("Bearer x",),
    }


def test_json_redaction_nested_and_no_mutation():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    extra = _secret_extra()
    snapshot = copy.deepcopy(extra)
    get_logger("x").info("connecting", extra=extra)

    output = stream.getvalue()
    record = json.loads(output)
    assert record["snmp_community"] == REDACTION_MASK
    assert record["cfg"]["API_Token"] == REDACTION_MASK
    assert record["cfg"]["hosts"][0]["Password"] == REDACTION_MASK
    assert record["cfg"]["hosts"][0]["name"] == "h1"
    assert record["authorization"] == REDACTION_MASK
    for secret in ("public", "abc", '"p"', "Bearer x"):
        assert secret not in output
    assert extra == snapshot


def test_text_redaction():
    stream = io.StringIO()
    configure_logging("INFO", fmt="text", stream=stream)
    extra = _secret_extra()
    snapshot = copy.deepcopy(extra)
    get_logger("x").info("connecting", extra=extra)
    output = stream.getvalue()
    for secret in ("public", "abc", '"p"', "Bearer x"):
        assert secret not in output
    assert REDACTION_MASK in output
    assert "h1" in output
    assert extra == snapshot


def test_redaction_covers_other_handlers_on_the_record():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    record = logging.LogRecord("sot_validator.x", logging.INFO, "", 0, "m", (), None)
    record.client_secret = "s3cr3t"
    record.ok = {"nested": [{"db_password": 5}]}
    assert RedactionFilter().filter(record) is True
    assert record.client_secret == REDACTION_MASK
    assert record.ok == {"nested": [{"db_password": REDACTION_MASK}]}


@pytest.mark.parametrize(
    "key",
    ["password", "PASSWORD", "snmp_community", "API_Token", "Authorization", "clientSecret"],
)
def test_redact_matches_keys_case_insensitively(key):
    assert redact({key: {"anything": 1}}) == {key: REDACTION_MASK}


def test_redact_leaves_non_matching_and_does_not_mutate():
    value = {"name": "h1", "items": [{"token_count": 3}, "plain"], "pair": ({"secret": 1}, 2)}
    snapshot = copy.deepcopy(value)
    result = redact(value)
    assert result == {
        "name": "h1",
        "items": [{"token_count": REDACTION_MASK}, "plain"],
        "pair": ({"secret": REDACTION_MASK}, 2),
    }
    assert value == snapshot
    assert redact("password=hunter2") == "password=hunter2"


def test_message_text_is_not_scanned():
    stream = io.StringIO()
    configure_logging("INFO", fmt="json", stream=stream)
    get_logger("x").info("community is %s", "public")
    assert json.loads(stream.getvalue())["msg"] == "community is public"


# --- Metrics -----------------------------------------------------------------


def test_label_value_escaping_and_help_type_lines():
    registry = MetricsRegistry()
    counter = registry.counter("m", "Help with \\ and\nnewline", ("l",))
    counter.inc(l='a\\b"c\nd')
    registry.gauge("g", "A gauge")
    output = registry.render()
    lines = output.splitlines()
    assert 'm{l="a\\\\b\\"c\\nd"} 1' in lines
    assert "# HELP m Help with \\\\ and\\nnewline" in lines
    assert "# TYPE m counter" in lines
    assert "# HELP g A gauge" in lines
    assert "# TYPE g gauge" in lines
    assert "g 0" in lines
    assert output.endswith("\n")


def test_histogram_cumulative_buckets():
    registry = MetricsRegistry()
    hist = registry.histogram("h", "Latency", buckets=(0.1, 1.0))
    for value in (0.0625, 0.0625, 0.5, 2.0, 3.0):
        hist.observe(value)
    lines = registry.render().splitlines()
    assert lines == [
        "# HELP h Latency",
        "# TYPE h histogram",
        'h_bucket{le="0.1"} 2',
        'h_bucket{le="1.0"} 3',
        'h_bucket{le="+Inf"} 5',
        "h_sum 5.625",
        "h_count 5",
    ]


def test_histogram_with_labels_and_explicit_inf():
    registry = MetricsRegistry()
    hist = registry.histogram("h", "Latency", ("probe",), buckets=(1, float("inf")))
    hist.observe(0.5, probe="icmp")
    lines = registry.render().splitlines()
    assert 'h_bucket{probe="icmp",le="1.0"} 1' in lines
    assert 'h_bucket{probe="icmp",le="+Inf"} 1' in lines
    assert sum(1 for line in lines if 'le="+Inf"' in line) == 1
    assert 'h_count{probe="icmp"} 1' in lines


def test_gauge_operations():
    registry = MetricsRegistry()
    gauge = registry.gauge("g", "G", ("site",))
    gauge.set(5, site="a")
    gauge.inc(site="a")
    gauge.dec(2, site="a")
    gauge.set(1.5, site="b")
    assert gauge.get(site="a") == 4
    lines = registry.render().splitlines()
    assert lines[2:] == ['g{site="a"} 4', 'g{site="b"} 1.5']


def test_label_named_like_parameter_is_allowed():
    registry = MetricsRegistry()
    counter = registry.counter("c", "C", ("amount",))
    counter.inc(2, amount="x")
    assert 'c{amount="x"} 2' in registry.render().splitlines()


@pytest.mark.parametrize("name", ["1bad", "bad-name", "", "has space"])
def test_invalid_metric_names(name):
    with pytest.raises(ValueError):
        MetricsRegistry().counter(name, "help")


@pytest.mark.parametrize("label", ["bad-label", "__x", "1x", ""])
def test_invalid_label_names(label):
    with pytest.raises(ValueError):
        MetricsRegistry().gauge("g", "help", (label,))


def test_metric_validation_errors():
    registry = MetricsRegistry()
    with pytest.raises(ValueError):
        registry.histogram("h", "help", ("le",))
    assert registry.counter("le_ok", "help", ("le",)).labelnames == ("le",)

    counter = registry.counter("c", "help", ("a",))
    assert registry.counter("c", "other help", ("a",)) is counter
    with pytest.raises(ValueError):
        registry.gauge("c", "help", ("a",))
    with pytest.raises(ValueError):
        registry.counter("c", "help", ("b",))
    with pytest.raises(ValueError):
        registry.counter("c", "help", ("a", "b"))
    with pytest.raises(ValueError):
        counter.inc(-1, a="x")
    with pytest.raises(ValueError):
        counter.inc(1, b="x")
    with pytest.raises(ValueError):
        counter.inc(1)
    with pytest.raises(ValueError):
        counter.inc(1, a="x", b="y")
    with pytest.raises(ValueError):
        counter.inc("1", a="x")
    with pytest.raises(ValueError):
        registry.counter("dup", "help", ("a", "a"))

    with pytest.raises(ValueError):
        registry.histogram("h_empty", "help", buckets=())
    with pytest.raises(ValueError):
        registry.histogram("h_flat", "help", buckets=(1.0, 1.0))
    with pytest.raises(ValueError):
        registry.histogram("h_down", "help", buckets=(2.0, 1.0))


def test_concurrent_counter_increments():
    registry = MetricsRegistry()
    counter = registry.counter("c", "help", ("worker",))
    plain = registry.counter("total", "help")

    def work():
        for _ in range(1000):
            counter.inc(worker="w")
            plain.inc()

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    lines = registry.render().splitlines()
    assert 'c{worker="w"} 8000' in lines
    assert "total 8000" in lines


def _populate(registry: MetricsRegistry, order: list[str]) -> None:
    for name in order:
        if name == "a":
            registry.counter("a_total", "A", ("site",)).inc(site="z")
            registry.counter("a_total", "A", ("site",)).inc(site="b")
        elif name == "b":
            registry.gauge("b", "B").set(3)
        else:
            registry.histogram("c", "C", buckets=(1.0,)).observe(0.5)


def test_render_is_deterministic():
    first = MetricsRegistry()
    _populate(first, ["a", "b", "c"])
    second = MetricsRegistry()
    _populate(second, ["c", "b", "a"])
    assert first.render() == first.render()
    assert first.render() == second.render()
    lines = first.render().splitlines()
    assert lines.index('a_total{site="b"} 1') < lines.index('a_total{site="z"} 1')


def test_write_textfile_creates_file_with_no_leftovers(tmp_path):
    registry = MetricsRegistry()
    registry.gauge("g", "G").set(1)
    target = tmp_path / "sot.prom"
    write_textfile(target, registry)
    assert target.read_text() == registry.render()
    assert os.listdir(tmp_path) == ["sot.prom"]

    registry.gauge("g", "G").set(2)
    registry.write_textfile(str(target))
    assert "g 2" in target.read_text().splitlines()
    assert os.listdir(tmp_path) == ["sot.prom"]


def test_write_textfile_failure_keeps_previous_file(tmp_path, monkeypatch):
    registry = MetricsRegistry()
    registry.gauge("g", "G").set(1)
    target = tmp_path / "sot.prom"
    target.write_text("previous\n")

    def failing_replace(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr(metrics_module.os, "replace", failing_replace)
    with pytest.raises(OSError, match="replace failed"):
        write_textfile(target, registry)
    assert target.read_text() == "previous\n"
    assert os.listdir(tmp_path) == ["sot.prom"]


def test_write_textfile_render_failure_keeps_previous_file(tmp_path, monkeypatch):
    registry = MetricsRegistry()
    target = tmp_path / "sot.prom"
    target.write_text("previous\n")

    def failing_render():
        raise RuntimeError("render failed")

    monkeypatch.setattr(registry, "render", failing_render)
    with pytest.raises(RuntimeError, match="render failed"):
        write_textfile(target, registry)
    assert target.read_text() == "previous\n"
    assert os.listdir(tmp_path) == ["sot.prom"]


def test_starter_metrics():
    registry = MetricsRegistry()
    metrics = register_starter_metrics(registry)
    expected = {
        "sot_run_last_success_timestamp_seconds": ("gauge", ()),
        "sot_run_duration_seconds": ("gauge", ()),
        "sot_site_status": ("gauge", ("site", "status")),
        "sot_records_total": ("counter", ("site", "classification")),
        "sot_collector_errors_total": ("counter", ("collector",)),
        "sot_probe_duration_seconds": ("histogram", ()),
    }
    assert {name: (m.metric_type, m.labelnames) for name, m in metrics.items()} == expected
    assert register_starter_metrics(registry)["sot_records_total"] is metrics["sot_records_total"]
    output = registry.render()
    for name, (metric_type, _) in expected.items():
        assert f"# TYPE {name} {metric_type}" in output
        assert f"# HELP {name} " in output


def test_metrics_module_docstring_names_starter_metrics():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sot_validator.observability.metrics as m; print(m.__doc__)",
        ],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    for name in (
        "sot_run_last_success_timestamp_seconds",
        "sot_run_duration_seconds",
        "sot_site_status",
        "sot_records_total",
        "sot_collector_errors_total",
        "sot_probe_duration_seconds",
    ):
        assert name in result.stdout
    assert ".prom" in result.stdout
