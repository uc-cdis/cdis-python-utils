"""
Small wrapper around the Prometheus client for metrics gathering in a multi-
process Python environment. This is intended to be extended and instantiated by
services, stored at some application context level, and then used to add metrics
(which are likely later exposed at the /metrics endpoint for Prometheus to scrape).
"""
import os
import pathlib

from cdislogging import get_logger
from prometheus_client import (
    CollectorRegistry,
    multiprocess,
    Counter,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)


logger = get_logger(__name__)


class BaseMetrics(object):
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
                                  finicky about when the ENV var is set.
        """
        self.enabled = enabled
        self.prometheus_metrics = {}
        if not enabled:
            return

        pathlib.Path(prometheus_dir).mkdir(parents=True, exist_ok=True)
        os.environ["PROMETHEUS_MULTIPROC_DIR"] = prometheus_dir

        logger.info(
            f"PROMETHEUS_MULTIPROC_DIR is {os.environ['PROMETHEUS_MULTIPROC_DIR']}"
        )

        self._registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(self._registry)

    def get_latest_metrics(self):
        """
        Generate the latest Prometheus metrics
        Returns:
            str: Latest Prometheus metrics
            str: Content type of the latest Prometheus metrics
        """
        # When metrics gathering is not enabled, the metrics endpoint should not error, but it should
        # not return any data.
        if not self.enabled:
            return "", CONTENT_TYPE_LATEST

        return generate_latest(self._registry), CONTENT_TYPE_LATEST

    def increment_counter(self, name, labels, description=""):
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
            self.prometheus_metrics[name] = Counter(name, description, [*labels.keys()])
        elif type(self.prometheus_metrics[name]) is not Counter:
            raise ValueError(
                f"Trying to create counter '{name}' but a {type(self.prometheus_metrics[name])} with this name already exists"
            )

        logger.debug(f"Incrementing counter '{name}' with labels: {labels}")
        self.prometheus_metrics[name].labels(*labels.values()).inc()

    def set_gauge(self, name, labels, value, description=""):
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

        # create the gauge if it doesn't already exist
        if name not in self.prometheus_metrics:
            logger.info(
                f"Creating gauge '{name}' with description '{description}' and labels: {labels}"
            )
            self.prometheus_metrics[name] = Gauge(name, description, [*labels.keys()])
        elif type(self.prometheus_metrics[name]) is not Gauge:
            raise ValueError(
                f"Trying to create gauge '{name}' but a {type(self.prometheus_metrics[name])} with this name already exists"
            )

        logger.debug(f"Setting gauge '{name}' with labels: {labels}")
        self.prometheus_metrics[name].labels(*labels.values()).set(value)
