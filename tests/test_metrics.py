import pytest
import os
import subprocess
import sys
import tempfile
import textwrap
from prometheus_client import Counter, Gauge, Histogram
from unittest.mock import patch, MagicMock

from cdispyutils.metrics import BaseMetrics


@pytest.fixture
def prometheus_dir():
    """
    Fixture to create a temporary directory for Prometheus metrics
    """
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname


def test_metrics_initialization_disabled():
    """
    Test the initialization of BaseMetrics with metrics disabled
    """
    metrics = BaseMetrics(enabled=False)
    assert metrics.enabled is False
    assert not metrics.prometheus_metrics


def test_metrics_initialization_enabled(prometheus_dir):
    """
    Test the initialization of BaseMetrics with metrics enabled
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    assert metrics.enabled is True
    assert os.environ["PROMETHEUS_MULTIPROC_DIR"] == prometheus_dir
    assert isinstance(metrics.prometheus_metrics, dict)


def test_get_latest_metrics_disabled():
    """
    Test that you don't get metrics data when it's disabled, even though
    we've incremented something
    """
    metrics = BaseMetrics(enabled=False)
    name = "test_counter1"
    labels = {"label1": "value1"}
    metrics.increment_counter(name, labels)
    metrics_data, content_type = metrics.get_latest_metrics()
    assert metrics_data == b""


def test_get_latest_metrics_enabled(prometheus_dir):
    """
    Test that you get metrics data when it's enabled we've incremented something
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    name = "test_counter2"
    labels = {"label1": "value1"}
    metrics.increment_counter(name, labels)
    metrics_data, content_type = metrics.get_latest_metrics()
    assert name.encode() in metrics_data


def test_increment_counter(prometheus_dir):
    """
    Test that incrementing a counter yields updated metrics
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    name = "test_counter3"
    labels = {"label1": "value1"}
    metrics.increment_counter(name, labels)
    assert name in metrics.prometheus_metrics
    assert isinstance(metrics.prometheus_metrics[name], Counter)

    # Increment again and check
    metrics.increment_counter(name, labels)
    assert metrics.prometheus_metrics[name].labels("value1")._value.get() == 2


def test_increment_counter_error_existing_gauge(prometheus_dir):
    """
    Test that we get ValueError when trying to increment a counter that
    already exists as a gauge
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    name = "test_metric4"
    labels = {"label1": "value1"}
    metrics.prometheus_metrics[name] = Gauge(name, "description", ["label1"])

    with pytest.raises(ValueError):
        metrics.increment_counter(name, labels)


def test_increment_counter_disabled():
    """
    Test that incrementing a counter does nothing when metrics are disabled
    """
    metrics = BaseMetrics(enabled=False)
    name = "test_counter5"
    labels = {"label1": "value1"}
    metrics.increment_counter(name, labels)
    assert name not in metrics.prometheus_metrics


def test_set_gauge(prometheus_dir):
    """
    Test setting a gauge metric sets the value in the metrics
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    name = "test_gauge6"
    labels = {"label1": "value1"}
    value = 5
    metrics.set_gauge(name, labels, value)
    assert name in metrics.prometheus_metrics
    assert isinstance(metrics.prometheus_metrics[name], Gauge)
    assert metrics.prometheus_metrics[name].labels("value1")._value.get() == value


def test_set_gauge_error_existing_counter(prometheus_dir):
    """
    Test error handling when trying to set a gauge that already exists as a counter.
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    name = "test_metric7"
    labels = {"label1": "value1"}
    value = 5
    metrics.prometheus_metrics[name] = Counter(name, "description", ["label1"])

    with pytest.raises(ValueError):
        metrics.set_gauge(name, labels, value)


def test_set_gauge_disabled():
    """
    Test that setting a gauge does nothing when metrics are disabled.
    """
    metrics = BaseMetrics(enabled=False)
    name = "test_gauge8"
    labels = {"label1": "value1"}
    value = 5
    metrics.set_gauge(name, labels, value)
    assert name not in metrics.prometheus_metrics


def test_metrics_are_written_for_multiprocess_collection(prometheus_dir):
    """
    Test that counters are stored where a multiprocess registry can read them.

    Run in a subprocess because prometheus_client resolves its storage backend once per
    interpreter, from PROMETHEUS_MULTIPROC_DIR, and the test suite's own imports have already
    settled that choice for this process.
    """
    source = textwrap.dedent(
        f"""
        from cdispyutils.metrics import BaseMetrics

        metrics = BaseMetrics(enabled=True, prometheus_dir={prometheus_dir!r})
        metrics.increment_counter("subprocess_counter", {{"label1": "value1"}})
        """
    )
    env = {k: v for k, v in os.environ.items() if k != "PROMETHEUS_MULTIPROC_DIR"}

    result = subprocess.run(
        [sys.executable, "-c", source], env=env, capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr
    assert [name for name in os.listdir(prometheus_dir) if name.endswith(".db")]


def test_latest_metrics_reports_each_metric_once(prometheus_dir):
    """
    Test that a metric family is exposed once, not once per collector in the registry.

    A duplicated `# HELP` line for one metric name is a parse error to Prometheus.
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    metrics.increment_counter("test_counter_once", {"label1": "value1"})

    text, _ = metrics.get_latest_metrics()
    lines = text.decode()

    assert lines.count("# HELP test_counter_once_total") == 1


def test_asgi_app_is_available_when_metrics_are_disabled():
    """
    Test that the ASGI metrics endpoint can be built while metrics are disabled.

    A caller mounts the endpoint before knowing whether metrics are on, so this must not raise.
    """
    metrics = BaseMetrics(enabled=False)

    assert callable(metrics.get_asgi_app())


def test_wsgi_app_is_available_when_metrics_are_disabled():
    """
    Test that the WSGI metrics endpoint can be built while metrics are disabled.
    """
    metrics = BaseMetrics(enabled=False)

    assert callable(metrics.get_wsgi_app())


def test_disabled_wsgi_app_serves_an_empty_response():
    """
    Test that scraping a disabled metrics endpoint succeeds and returns no metrics.
    """
    metrics = BaseMetrics(enabled=False)
    metrics.increment_counter("disabled_counter", {"label1": "value1"})

    captured = {}

    def start_response(status, headers):
        captured["status"] = status

    body = b"".join(
        metrics.get_wsgi_app()(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "QUERY_STRING": ""},
            start_response,
        )
    )

    assert captured["status"].startswith("200")
    assert b"disabled_counter" not in body


def test_observe_histogram(prometheus_dir):
    """
    Test that observing a histogram records the value in the right bucket.
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    name = "test_histogram1"
    labels = {"label1": "value1"}
    metrics.observe_histogram(name, labels, 0.3, buckets=[0.1, 0.5, 1.0])

    assert isinstance(metrics.prometheus_metrics[name], Histogram)

    samples = {
        sample.labels["le"]: sample.value
        for metric in metrics.prometheus_metrics[name].collect()
        for sample in metric.samples
        if sample.name.endswith("_bucket")
    }
    assert samples["0.1"] == 0.0
    assert samples["0.5"] == 1.0
    assert samples["1.0"] == 1.0


def test_observe_histogram_uses_default_buckets(prometheus_dir):
    """
    Test that omitting buckets falls back to the client's defaults rather than failing.
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    name = "test_histogram2"
    metrics.observe_histogram(name, {"label1": "value1"}, 0.3)

    text, _ = metrics.get_latest_metrics()
    lines = text.decode()
    assert lines.count(f"{name}_bucket") > 3


def test_observe_histogram_rejects_a_name_used_by_another_type(prometheus_dir):
    """
    Test that reusing a counter's name for a histogram raises.
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    name = "test_histogram3"
    metrics.increment_counter(name, {"label1": "value1"})

    with pytest.raises(ValueError):
        metrics.observe_histogram(name, {"label1": "value1"}, 0.3)


def test_observe_histogram_disabled():
    """
    Test that observing a histogram does nothing when metrics are disabled.
    """
    metrics = BaseMetrics(enabled=False)
    name = "test_histogram4"
    metrics.observe_histogram(name, {"label1": "value1"}, 0.3)

    assert name not in metrics.prometheus_metrics
