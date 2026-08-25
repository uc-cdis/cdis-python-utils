"""
Some generalized metrics classes and abstraction.

For now, just a small wrapper around the Prometheus client for metrics gathering in a multi-
process Python environment. This is intended to be extended and instantiated by
services, stored at some application context level, and then used to add metrics
(which are likely later exposed at the /metrics endpoint for Prometheus to scrape).
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
import os
import pathlib
from typing import Dict

from cdislogging import get_logger
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
    make_wsgi_app,
    make_asgi_app,
    values,
)


logger = get_logger(__name__)


class AbstractBaseMetrics(ABC):
    def __init__(self) -> None:
        return

    @abstractmethod
    def get_metrics_app(self, **kwargs: Dict[str, str]) -> Callable:
        """Return a WSGI/ASGI app for metrics."""
        raise NotImplementedError()

    @abstractmethod
    def get_asgi_app(self) -> Callable:
        """Return an ASGI app for the metrics endpoint."""
        raise NotImplementedError()

    @abstractmethod
    def get_wsgi_app(self) -> Callable:
        """Return a WSGI app for the metrics endpoint."""
        raise NotImplementedError()

    @abstractmethod
    def get_latest_metrics(self) -> tuple[bytes, str]:
        """
        Generate the latest metrics.

        Returns:
            str: Latest Prometheus metrics
            str: Content type of the latest Prometheus metrics
        """
        raise NotImplementedError()

    @abstractmethod
    def increment_counter(
        self, name: str, labels: Dict[str, str], description: str = ""
    ) -> None:
        """Increment a counter metric."""
        raise NotImplementedError()

    @abstractmethod
    def dec_gauge(
        self, name: str, labels: Dict[str, str], value: float, description: str = ""
    ) -> None:
        """Decrement a gauge metric."""
        raise NotImplementedError()

    @abstractmethod
    def inc_gauge(
        self, name: str, labels: Dict[str, str], value: float, description: str = ""
    ) -> None:
        """Increment a gauge metric."""
        raise NotImplementedError()

    @abstractmethod
    def set_gauge(
        self, name: str, labels: Dict[str, str], value: float, description: str = ""
    ) -> None:
        """Set a gauge metric."""
        raise NotImplementedError()


class BaseMetrics(AbstractBaseMetrics):
    """
    Class to handle Prometheus metrics

    Attributes:
        enabled (bool): If this is false, the class functions will be no-ops (no operations), effectively
                        doing nothing. This is the behavior when metrics are disabled. Why? So application code
                        doesn't have to check, it always tries to log a metric.
        prometheus_metrics (dict): Dictionary to store Prometheus metrics
        _registry (CollectorRegistry): Prometheus registry
    """

    def __init__(self, enabled=True, prometheus_dir="/var/tmp/prometheus_metrics"):
        """
        Create a metrics class.

        Args:
            enabled (bool): If this is false, the class functions will be no-ops (no operations), effectively
                            doing nothing. This is the behavior when metrics are disabled. Why? So application code
                            doesn't have to check, it always tries to log a metric.
            prometheus_dir (str): Directory to use when setting PROMETHEUS_MULTIPROC_DIR env var (which prometheus requires
                                  for multiprocess metrics collection). Note that this the prometheus client is very
                                  finicky about when the ENV var is set: any metric created before this constructor
                                  runs keeps storing its value in process memory and will not appear in a
                                  multiprocess registry.
        """
        self.enabled = enabled
        self.prometheus_metrics = {}

        # Created even when disabled, so `get_asgi_app`, `get_wsgi_app` and `get_latest_metrics`
        # serve an empty 200 rather than raising AttributeError. A caller mounting the endpoint
        # should not have to know whether metrics are on.
        self._registry = CollectorRegistry()
        if not enabled:
            return

        pathlib.Path(prometheus_dir).mkdir(parents=True, exist_ok=True)
        os.environ["PROMETHEUS_MULTIPROC_DIR"] = prometheus_dir

        # prometheus_client chooses between its in-memory and its multiprocess value class once,
        # when prometheus_client.values is first imported, from PROMETHEUS_MULTIPROC_DIR - and
        # this module's own import wins that race against a caller setting the variable here.
        # Re-running the choice is what keeps counters out of process memory; without it they
        # stay in memory while /metrics serves a multiprocess registry over an empty directory,
        # returning 200 with no data. Metrics built before this runs keep the class they got.
        values.ValueClass = values.get_value_class()

        logger.info(
            f"PROMETHEUS_MULTIPROC_DIR is {os.environ['PROMETHEUS_MULTIPROC_DIR']}"
        )

    def get_metrics_app(self, **kwargs) -> Callable:
        """
        Required for Prometheus multiprocess setup
        See: https://prometheus.github.io/client_python/multiprocess/
        """
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry, **kwargs)
        return make_asgi_app(registry=registry)

    def get_asgi_app(self) -> Callable:
        """
        Get the ASGI app for the metrics endpoint, (for asgi apps, e.g FastAPI)
        Returns:
            ASGI app: ASGI app for the metrics endpoint
        """
        return make_asgi_app(self._registry)

    def get_wsgi_app(self) -> Callable:
        """
        Get the WSGI app for the metrics endpoint, (for wsgi apps, e.g Flask)
        Returns:
            WSGI app: WSGI app for the metrics endpoint
        """
        return make_wsgi_app(self._registry)

    def get_latest_metrics(self) -> tuple[bytes, str]:
        """
        Generate the latest Prometheus metrics
        Returns:
            bytes: Latest Prometheus metrics, in the exposition format `generate_latest` emits.
                   Bytes in both branches, so a caller handing this to a response does not have
                   to know whether metrics were enabled.
            str: Content type of the latest Prometheus metrics
        """
        # When metrics gathering is not enabled, the metrics endpoint should not error, but it should
        # not return any data.
        if not self.enabled:
            return b"", CONTENT_TYPE_LATEST

        return generate_latest(self._registry), CONTENT_TYPE_LATEST

    def increment_counter(self, name, labels, description="") -> None:
        """
        Increment a Prometheus counter metric.
        Note that this function should not be called directly - implement a function like
        `add_login_event` instead. A metric's labels should always be consistent.
        Args:
            name (str): Name of the metric
            labels (dict): Dictionary of labels for the metric
        """
        if not self.enabled:
            return

        # create the counter if it doesn't already exist
        if name not in self.prometheus_metrics:
            logger.info(
                f"Creating counter '{name}' with description '{description}' and labels: {labels}"
            )
            self.prometheus_metrics[name] = Counter(
                name, description, [*labels.keys()], registry=self._registry
            )
        elif type(self.prometheus_metrics[name]) is not Counter:
            raise ValueError(
                f"Trying to create counter '{name}' but a {type(self.prometheus_metrics[name])} with this name already exists"
            )

        logger.debug(f"Incrementing counter '{name}' with labels: {labels}")
        self.prometheus_metrics[name].labels(*labels.values()).inc()

    def dec_gauge(self, name, labels, value, description="") -> None:
        """
        Decrement a Prometheus gauge metric.
        Note that this function should not be called directly - implement a function like
        `add_signed_url_event` instead. A metric's labels should always be consistent.
        Args:
            name (str): Name of the metric
            labels (dict): Dictionary of labels for the metric
            value (int): Value to set the metric to
            description (str): describing the gauge in case it doesn't already exist
        """
        if not self.enabled:
            return

        self._create_gauge_if_not_exist(name, labels, value, description)
        logger.debug(f"Decrementing gauge '{name}' by '{value}' with labels: {labels}")
        self.prometheus_metrics[name].labels(*labels.values()).dec(value)

    def inc_gauge(self, name, labels, value, description="") -> None:
        """
        Increment a Prometheus gauge metric.
        Note that this function should not be called directly - implement a function like
        `add_signed_url_event` instead. A metric's labels should always be consistent.
        Args:
            name (str): Name of the metric
            labels (dict): Dictionary of labels for the metric
            value (int): Value to set the metric to
            description (str): describing the gauge in case it doesn't already exist
        """
        if not self.enabled:
            return

        self._create_gauge_if_not_exist(name, labels, value, description)
        logger.debug(f"Incrementing gauge '{name}' by '{value}' with labels: {labels}")
        self.prometheus_metrics[name].labels(*labels.values()).inc(value)

    def set_gauge(self, name, labels, value, description="") -> None:
        """
        Set a Prometheus gauge metric.
        Note that this function should not be called directly - implement a function like
        `add_signed_url_event` instead. A metric's labels should always be consistent.
        Args:
            name (str): Name of the metric
            labels (dict): Dictionary of labels for the metric
            value (int): Value to set the metric to
        """
        if not self.enabled:
            return

        self._create_gauge_if_not_exist(name, labels, value, description)
        logger.debug(f"Setting gauge '{name}' with '{value}' with labels: {labels}")
        self.prometheus_metrics[name].labels(*labels.values()).set(value)

    def _create_gauge_if_not_exist(self, name, labels, value, description) -> None:
        # create the gauge if it doesn't already exist
        if name not in self.prometheus_metrics:
            logger.info(
                f"Creating gauge '{name}' with description '{description}' and labels: {labels}"
            )
            self.prometheus_metrics[name] = Gauge(
                name, description, [*labels.keys()], registry=self._registry
            )
        elif type(self.prometheus_metrics[name]) is not Gauge:
            raise ValueError(
                f"Trying to create gauge '{name}' but a {type(self.prometheus_metrics[name])} with this name already exists"
            )

    def observe_histogram(
        self, name, labels, value, description="", buckets=None
    ) -> None:
        """
        Record one observation in a Prometheus histogram metric.

        Not part of AbstractBaseMetrics: adding an abstract method to that contract would stop
        any existing implementation of it from instantiating. Check with `hasattr` before
        calling this on something typed as the abstract base.

        Args:
            name (str): Name of the metric.
            labels (dict): Dictionary of labels for the metric. A histogram stores one bucket
                series per label combination, so it multiplies the cost of every label far
                faster than a counter does.
            value (float): The observation, for example a duration in seconds.
            description (str): Help text, used only when the histogram is first created.
            buckets (Sequence[float] | None): Upper bounds of the buckets. None takes
                prometheus_client's defaults, which span 5ms to 10s and suit request latency.

        Raises:
            ValueError: If a metric of a different type already exists under this name.
        """
        if not self.enabled:
            return

        # create the histogram if it doesn't already exist
        if name not in self.prometheus_metrics:
            logger.info(
                f"Creating histogram '{name}' with description '{description}' and labels: {labels}"
            )
            extra_kwargs = {} if buckets is None else {"buckets": buckets}
            self.prometheus_metrics[name] = Histogram(
                name,
                description,
                [*labels.keys()],
                registry=self._registry,
                **extra_kwargs,
            )
        elif type(self.prometheus_metrics[name]) is not Histogram:
            raise ValueError(
                f"Trying to create histogram '{name}' but a {type(self.prometheus_metrics[name])} with this name already exists"
            )

        logger.debug(
            f"Observing '{value}' for histogram '{name}' with labels: {labels}"
        )
        self.prometheus_metrics[name].labels(*labels.values()).observe(value)
