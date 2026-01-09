import pytest
import os
import tempfile
from prometheus_client import Counter, Gauge
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
    metrics_data, content_type = metrics.get_latest_metrics()
    name = "test_counter1"
    labels = {"label1": "value1"}
    metrics.increment_counter(name, labels)
    assert metrics_data == ""


def test_get_latest_metrics_enabled(prometheus_dir):
    """
    Test that you get metrics data when it's enabled we've incremented something
    """
    metrics = BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)
    metrics_data, content_type = metrics.get_latest_metrics()
    name = "test_counter2"
    labels = {"label1": "value1"}
    metrics.increment_counter(name, labels)
    assert metrics_data != ""


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
