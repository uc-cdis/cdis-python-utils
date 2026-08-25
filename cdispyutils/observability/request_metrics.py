"""
Prometheus metrics for the HTTP requests a FastAPI application serves.

Requires the `observability` extra.
"""

import time
from collections.abc import Awaitable, Callable, Collection, Mapping
from typing import Protocol, cast

from cdislogging import get_logger
from fastapi import FastAPI
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cdispyutils.metrics import AbstractBaseMetrics
from cdispyutils.observability.constants import (
    DEFAULT_ENDPOINTS_WITHOUT_METRICS,
    UNKNOWN_LABEL_VALUE,
    UNMATCHED_PATH,
)

logger = get_logger(__name__)

# Labels the middleware records itself, which an extra-label provider may not shadow.
RESERVED_LABEL_NAMES = frozenset({"method", "path", "status_code"})

ExtraLabelsProvider = Callable[[Request], Awaitable[Mapping[str, str]]]


class HistogramRecorder(Protocol):
    """
    A metrics client that can record histograms.

    `observe_histogram` is on `BaseMetrics` rather than on `AbstractBaseMetrics`, so this names
    the extra capability that `add_request_metrics_middleware` checks for before accepting a
    `duration_histogram_name`.
    """

    def observe_histogram(
        self,
        name: str,
        labels: Mapping[str, str],
        value: float,
        description: str = "",
        buckets: Collection[float] | None = None,
    ) -> None:
        """Record one observation."""


def add_request_metrics_middleware(
    app: FastAPI,
    metrics: AbstractBaseMetrics | None,
    *,
    counter_name: str,
    counter_description: str = "",
    duration_histogram_name: str | None = None,
    duration_histogram_description: str = "",
    duration_buckets: Collection[float] | None = None,
    excluded_paths: Collection[str] = DEFAULT_ENDPOINTS_WITHOUT_METRICS,
    metrics_path: str | None = "/metrics",
    extra_unrouted_paths: Collection[str] = (),
    extra_label_names: Collection[str] = (),
    extra_labels: ExtraLabelsProvider | None = None,
) -> None:
    """
    Count every HTTP request the app serves, labelled by route template.

    Requests are labelled with the template that matched them, for example `/things/{thing_id}`,
    never the URL that was requested, so a path parameter does not mint one Prometheus time
    series per value. A request matching no route is labelled UNMATCHED_PATH.

    Installs nothing when metrics are disabled, so callers never have to guard this call.

    Args:
        app (FastAPI): The application to instrument. Must not have started serving yet;
            Starlette refuses new middleware once it has.
        metrics (AbstractBaseMetrics | None): The metrics client to record through. None, or a
            client reporting itself disabled, installs nothing.
        counter_name (str): Name of the counter, for example `gen3_workflow_api_requests`.
            Prometheus exposes it with a `_total` suffix.
        counter_description (str): Help text, used only when the counter is first created.
        duration_histogram_name (str | None): Name of a histogram to record request duration in
            seconds under, or None to record no timings. Timing covers the whole response,
            including a streamed body. The histogram carries the same labels as the counter and
            stores one bucket series per label combination, so `extra_label_names` costs far
            more with one of these enabled.
        duration_histogram_description (str): Help text for the histogram.
        duration_buckets (Collection[float] | None): Upper bounds of the histogram's buckets.
            None takes prometheus_client's defaults, which span 5ms to 10s.
        excluded_paths (Collection[str]): Path labels to record nothing for. Matched against the
            resolved label, so against a route template rather than a URL. `metrics_path` is
            always excluded whether or not it appears here.
        metrics_path (str | None): Where the Prometheus endpoint is mounted, or None if the app
            has none. A mounted sub-application leaves no route on the request scope, so the
            middleware can only recognise it by path.
        extra_unrouted_paths (Collection[str]): Further paths the app serves without an API
            route, such as other mounted sub-applications. Anything served without a route and
            not listed here is labelled UNMATCHED_PATH.
        extra_label_names (Collection[str]): Names of the labels `extra_labels` supplies. The
            counter is created with exactly these, in this order, on top of `method`, `path`, and
            `status_code`. Every name multiplies the counter's cardinality.
        extra_labels (ExtraLabelsProvider | None): Async callable returning values for
            `extra_label_names`, called once per counted request after the response. It receives
            a Request with no receive channel, so it can read headers, cookies, and query
            parameters, but reaching for the body raises rather than hanging on a channel whose
            content is already consumed. Any exception it raises, and any name it omits, yields
            UNKNOWN_LABEL_VALUE for that label.

    Raises:
        ValueError: If `extra_label_names` and `extra_labels` are not either both given or both
            omitted, if a name in `extra_label_names` is one of `method`, `path`, or
            `status_code`, or if `duration_histogram_name` is given for a metrics client that
            cannot record histograms.
    """
    label_names = tuple(extra_label_names)

    if bool(label_names) != bool(extra_labels):
        raise ValueError(
            "extra_label_names and extra_labels must be given together; got names="
            f"{sorted(label_names)} and provider={extra_labels!r}"
        )

    reserved = RESERVED_LABEL_NAMES.intersection(label_names)
    if reserved:
        raise ValueError(
            f"extra_label_names may not reuse the built-in labels: {sorted(reserved)}"
        )

    # `observe_histogram` is on BaseMetrics rather than on the abstract base, so checking is the
    # only honest option. Failing here makes it a startup error rather than an AttributeError on
    # the first request.
    if duration_histogram_name and not hasattr(metrics, "observe_histogram"):
        raise ValueError(
            f"{type(metrics).__name__} cannot record histograms, so "
            f"duration_histogram_name={duration_histogram_name!r} cannot be honoured"
        )

    # `enabled` is on BaseMetrics rather than on the abstract base, so a third-party
    # implementation of the contract need not carry it.
    if metrics is None or not getattr(metrics, "enabled", True):
        logger.info(
            f"Metrics are disabled, so requests will not be counted under '{counter_name}'"
        )
        return

    # A scrape must never be able to count itself, however the caller configured exclusions:
    # that makes the counter climb on its own and turns any rate() over it into noise.
    always_excluded = (
        {metrics_path, metrics_path.rstrip("/") + "/"} if metrics_path else set()
    )

    # Endpoints FastAPI and Starlette serve without an APIRoute: the docs, the spec, and any
    # mounted sub-application. None of them leave a route on the scope, so the middleware has to
    # recognise them by path or collapse them into UNMATCHED_PATH.
    unrouted_paths = frozenset(
        path
        for path in (
            app.docs_url,
            app.redoc_url,
            app.openapi_url,
            metrics_path,
            *extra_unrouted_paths,
        )
        if path
    )

    app.add_middleware(
        _RequestMetricsMiddleware,
        metrics=metrics,
        # The hasattr check above is what establishes this; the cast only says so in the types.
        histogram_metrics=(
            cast(HistogramRecorder, metrics) if duration_histogram_name else None
        ),
        counter_name=counter_name,
        counter_description=counter_description,
        duration_histogram_name=duration_histogram_name,
        duration_histogram_description=duration_histogram_description,
        duration_buckets=duration_buckets,
        excluded_paths=frozenset(excluded_paths) | always_excluded,
        unrouted_paths=unrouted_paths,
        extra_label_names=label_names,
        extra_labels=extra_labels,
    )


class _RequestMetricsMiddleware:
    """
    ASGI middleware recording one counter increment per served request.

    Written against the raw ASGI interface rather than as a BaseHTTPMiddleware subclass: that
    base allocates an anyio task group and a memory object stream per request and buffers
    streaming responses, which is more interference than a helper needing only the response
    status should impose on a service that streams.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        metrics: AbstractBaseMetrics,
        histogram_metrics: HistogramRecorder | None,
        counter_name: str,
        counter_description: str,
        duration_histogram_name: str | None,
        duration_histogram_description: str,
        duration_buckets: Collection[float] | None,
        excluded_paths: frozenset[str],
        unrouted_paths: frozenset[str],
        extra_label_names: tuple[str, ...],
        extra_labels: ExtraLabelsProvider | None,
    ) -> None:
        self.app = app
        self._metrics = metrics
        self._histogram_metrics = histogram_metrics
        self._counter_name = counter_name
        self._counter_description = counter_description
        self._duration_histogram_name = duration_histogram_name
        self._duration_histogram_description = duration_histogram_description
        self._duration_buckets = duration_buckets
        self._excluded_paths = excluded_paths
        self._unrouted_paths = unrouted_paths
        self._extra_label_names = extra_label_names
        self._extra_labels = extra_labels

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Serve one ASGI event, counting it if it is an HTTP request.

        Args:
            scope (Scope): The connection scope.
            receive (Receive): The ASGI receive channel.
            send (Send): The ASGI send channel.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Stands until an http.response.start goes past. If the app raises instead, this is the
        # status the error handler above this middleware is about to send.
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        # perf_counter around the whole downstream call, which for a streaming response returns
        # only after the last body message: the duration therefore covers the transfer, not just
        # the time to headers.
        started = time.perf_counter()
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # Routing runs inside the call above and updates this same scope dict in place, so
            # the matched route is only readable afterwards.
            await self._record(scope, status_code, time.perf_counter() - started)

    async def _record(
        self, scope: Scope, status_code: int, duration_seconds: float
    ) -> None:
        """
        Record one finished request.

        Args:
            scope (Scope): The scope of a request that has already been routed.
            status_code (int): The status the response went out with.
            duration_seconds (float): How long the whole response took.
        """
        path = _path_label(scope, self._unrouted_paths)
        if path in self._excluded_paths:
            return

        # Assembled in a fixed order every time: increment_counter creates the counter from the
        # first call's key order and thereafter passes values positionally, so a dict that
        # iterates differently on a later request would file values under the wrong labels.
        labels = {
            "method": scope.get("method", ""),
            "path": path,
            "status_code": str(status_code),
        }
        labels.update(await self._resolve_extra_labels(scope))

        try:
            self._metrics.increment_counter(
                name=self._counter_name,
                labels=labels,
                description=self._counter_description,
            )
            if self._histogram_metrics and self._duration_histogram_name:
                self._histogram_metrics.observe_histogram(
                    name=self._duration_histogram_name,
                    labels=labels,
                    value=duration_seconds,
                    description=self._duration_histogram_description,
                    buckets=self._duration_buckets,
                )
        except Exception as exc:
            # A metric must never be the reason a response fails.
            logger.warning(
                f"Could not record counter '{self._counter_name}' for '{path}'. Error: '{exc}'"
            )

    async def _resolve_extra_labels(self, scope: Scope) -> dict[str, str]:
        """
        Ask the caller's provider for its labels.

        Args:
            scope (Scope): The scope of the request being counted.

        Returns:
            dict[str, str]: One entry per declared name, in declared order. A name the provider
                did not supply, and every name if the provider raised, gets UNKNOWN_LABEL_VALUE,
                which keeps the counter's label set the shape it was created with.
        """
        if not self._extra_label_names:
            return {}

        provided: Mapping[str, str] = {}
        if self._extra_labels:
            try:
                # No receive channel: the body is already consumed, so a provider reaching for it
                # gets Starlette's RuntimeError rather than awaiting a channel that never yields.
                provided = await self._extra_labels(Request(scope))
            except Exception as exc:
                logger.debug(
                    f"Extra metric labels unavailable. Error: '{exc}'. "
                    f"Using '{UNKNOWN_LABEL_VALUE}'"
                )

        return {
            name: str(provided.get(name, UNKNOWN_LABEL_VALUE))
            for name in self._extra_label_names
        }


def _path_label(scope: Scope, unrouted_paths: frozenset[str]) -> str:
    """
    Return the label to record a request's path under.

    Args:
        scope (Scope): The scope of a request that has already been routed.
        unrouted_paths (frozenset[str]): Paths the app serves without an APIRoute, which
            therefore have no template to be labelled with.

    Returns:
        str: The matched route's template, for example `/things/{thing_id}`, one of
            `unrouted_paths`, or UNMATCHED_PATH. Never the request's own URL, whose path
            parameters would each become a separate Prometheus time series.
    """
    # Only fastapi.routing.APIRoute puts `route` on the scope. A plain Starlette route, which is
    # what /docs, /redoc and /openapi.json are, does not, hence the fallbacks below.
    template = getattr(scope.get("route"), "path", None)
    if template:
        return template

    for candidate in (_route_path(scope), _mount_prefix(scope)):
        if candidate in unrouted_paths:
            return candidate

    return UNMATCHED_PATH


def _route_path(scope: Scope) -> str:
    """
    Return the path the router matched against, with the app's own prefix removed.

    Args:
        scope (Scope): The scope of a request that has already been routed.

    Returns:
        str: The path as the app's routes declare it. An app deployed behind a prefix carries
            that prefix in both `path` and `root_path`, so the raw path never equals a declared
            path such as `/docs`.
    """
    path = scope.get("path", "")
    root_path = scope.get("root_path", "")
    if root_path and path.startswith(root_path):
        return path.removeprefix(root_path) or "/"
    return path


def _mount_prefix(scope: Scope) -> str:
    """
    Return the prefix of the mount that served this request.

    Args:
        scope (Scope): The scope of a request that has already been routed.

    Returns:
        str: The mount's prefix as the app declares it, or `root_path` when no mount handled the
            request. Starlette moves a mount's prefix off the path and onto `root_path` before
            handing the request to the sub-application, and records the app's own prefix in
            `app_root_path`, so a `/metrics` mount under an app at `/svc` arrives as
            `root_path="/svc/metrics"`. Without subtracting the app's own prefix the label falls
            through to UNMATCHED_PATH, misses the exclusion check, and every scrape counts
            itself.
    """
    root_path = scope.get("root_path", "")
    app_root_path = scope.get("app_root_path", "")
    if app_root_path and root_path.startswith(app_root_path):
        return root_path.removeprefix(app_root_path)
    return root_path
