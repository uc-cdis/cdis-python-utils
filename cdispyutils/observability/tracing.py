"""
OpenTelemetry tracing for FastAPI services.

Requires the `observability` extra.
"""

import functools
import inspect
import re
from collections.abc import Collection, Iterable
from types import FunctionType, ModuleType
from typing import Any, Protocol, cast

from cdislogging import get_logger
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter as GrpcSpanExporter,
)
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter as HttpSpanExporter,
)
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
)

from cdispyutils.observability._config import env_bool, env_str, resolve
from cdispyutils.observability.constants import DEFAULT_ENDPOINTS_WITHOUT_METRICS
from cdispyutils.observability.continuous_profiling import profiling_active

logger = get_logger(__name__)

GRPC_PROTOCOL = "grpc"


class Instrumentor(Protocol):
    """
    What `configure_tracing` needs from a library instrumentation.

    Structural rather than `BaseInstrumentor`, so an adapter that merely wraps one - such as
    `LoggingInstrumentorWithContext` - satisfies it without subclassing an ABC whose
    `_instrument` and `_uninstrument` contract it has no use for.
    """

    def instrument(self) -> None:
        """Enable this instrumentation."""


# A marker to be set on already `traced` items. Instrumenting the same class or module twice in one
# process - which every `get_app()` in a test suite does - would otherwise nest a second span
# around every call.
#
# The value is historical and shared with the copy of this code in gen3-ai. A service part way
# through migrating from that copy to this one may have a function decorated by one and inspected
# by the other; a different marker here would wrap it twice.
_TRACED_MARKER = "_gen3_traced"

# Set by `no_trace` to keep the module and class walks off a function.
_NO_TRACE_MARKER = "_gen3_no_trace"

# What `configure_tracing` resolved `enabled` to, or None before it has run. Lets a service
# that configures tracing from a config file rather than the environment have that choice
# reach `instrument_class` and `instrument_module`, which run after it.
_tracing_enabled_override: bool | None = None


def configure_tracing(
    app: FastAPI,
    service_name: str,
    *,
    enabled: bool | None = None,
    otlp_endpoint: str | None = None,
    otlp_protocol: str | None = None,
    excluded_urls: Collection[str] = DEFAULT_ENDPOINTS_WITHOUT_METRICS,
    instrumentors: Iterable[Instrumentor] | None = None,
) -> None:
    """
    Install a tracer provider and instrument the app to emit request spans.

    When the Pyroscope agent is already running, spans are also tagged so Grafana can jump from a
    span to the profile for that request. Call
    `cdispyutils.observability.continuous_profiling.configure_profiling` first, otherwise this
    cannot know the agent exists and the link is left out.

    Args:
        app (FastAPI): The application to instrument.
        service_name (str): Value for the `service.name` resource attribute.
        enabled (bool | None): Whether to install anything at all.
            Env ENABLE_OPENTELEMETRY_TRACES, default True.
        otlp_endpoint (str | None): Signal-agnostic base URL of the OTLP collector. An empty
            value selects the console exporter, which is how local development inspects spans
            without a collector. Env OTEL_EXPORTER_OTLP_ENDPOINT, default "".
        otlp_protocol (str | None): Either `grpc` or `http/protobuf`.
            Env OTEL_EXPORTER_OTLP_PROTOCOL, default `http/protobuf`.
        excluded_urls (Collection[str]): Paths to emit no request spans for. Liveness and
            readiness probes hit these every few seconds per replica, and a span each would swamp
            real traffic.
        instrumentors (Iterable[Instrumentor] | None): Library instrumentations to enable
            alongside the app's own. Defaults to HTTPX, requests, and logging. Database
            instrumentation is not included, because the right one differs per service; pass
            `AsyncPGInstrumentor()` or the equivalent to add it.
    """
    global _tracing_enabled_override

    _tracing_enabled_override = resolve(
        enabled, "ENABLE_OPENTELEMETRY_TRACES", True, env_bool
    )
    if not _tracing_enabled_override:
        logger.info("OpenTelemetry traces are disabled, skipping setup")
        return

    if _tracer_provider_is_set():
        # A provider installed by something else (e.g. the `opentelemetry-instrument`
        # wrapper) wins: set_tracer_provider ignores the second call and only warns.
        logger.info("A tracer provider is already installed, reusing it")
    else:
        endpoint = resolve(otlp_endpoint, "OTEL_EXPORTER_OTLP_ENDPOINT", "", env_str)
        protocol = resolve(
            otlp_protocol, "OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf", env_str
        )

        provider = TracerProvider(
            resource=Resource.create(attributes={"service.name": service_name})
        )
        provider.add_span_processor(
            BatchSpanProcessor(_span_exporter(endpoint, protocol))
        )
        trace.set_tracer_provider(provider)

    _link_spans_to_profiles()

    FastAPIInstrumentor.instrument_app(
        app, excluded_urls=excluded_url_patterns(excluded_urls)
    )

    for instrumentor in _resolve_instrumentors(instrumentors):
        instrumentor.instrument()


def get_tracer(name: str) -> trace.Tracer:
    """
    Return a tracer for one instrumentation scope.

    Args:
        name (str): The scope, conventionally the calling module's `__name__`.

    Returns:
        trace.Tracer: A tracer. Safe to hold from import time: until a provider is installed
            this is a proxy, and it starts recording once one is.
    """
    return trace.get_tracer(name)


def traced[Function: FunctionType](fn: Function) -> Function:
    """
    Wrap a function so each call emits a span named `<module>.<qualified name>`.

    Qualified name includes anything inside the module the named function is *in* (e.g.
    if it's in a class, then the qualname is "SomeClass.some_function")

    Args:
        fn (Function): A sync or async function. Bound to `FunctionType` rather than a callable,
            because this reads `fn.__module__` and `fn.__qualname__` and hands `fn` to
            `functools.wraps`, none of which an arbitrary callable object carries.

    Returns:
        Function: A wrapped function, or `fn` itself when custom tracing is disabled or `fn` is
            already wrapped.

    Raises:
        TypeError: If `fn` is a generator or async generator function. A span around one of
            those ends when the generator object is created, so it measures nothing, and the
            wrapper also hides the function's generator-ness from callers that introspect it,
            such as FastAPI's dependency injection. The message says what to do instead, which
            is to open a span inside the function with `get_tracer`.
    """
    if inspect.isgeneratorfunction(fn) or inspect.isasyncgenfunction(fn):
        # Raised even when tracing is off, so the mistake cannot hide behind a config value.
        raise TypeError(
            f"cannot trace generator function {fn.__qualname__}: the span would end when the "
            "generator object is created, before any of the body runs, and wrapping also hides "
            "the function's generator-ness from FastAPI's dependency injection. Instead, open "
            "the span inside the function around the work you want measured: "
            "`with get_tracer(__name__).start_as_current_span('name'): ...`."
        )

    if not _custom_tracing_enabled() or getattr(fn, _TRACED_MARKER, False):
        return fn

    tracer = trace.get_tracer(fn.__module__)
    span_name = f"{fn.__module__}.{fn.__qualname__}"

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            with tracer.start_as_current_span(span_name):
                return await fn(*args, **kwargs)

        wrapper = async_wrapper
    else:

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            with tracer.start_as_current_span(span_name):
                return fn(*args, **kwargs)

        wrapper = sync_wrapper

    setattr(wrapper, _TRACED_MARKER, True)
    return cast(Function, wrapper)


def no_trace[Function: FunctionType](fn: Function) -> Function:
    """
    Mark a function for `instrument_module` and `instrument_class` to skip.

    Use this on a function called once per row or per loop iteration inside a module that is
    otherwise worth tracing, where a span per call would cost more than it reports.

    Args:
        fn (Function): The function to leave alone.

    Returns:
        Function: `fn`, unchanged.
    """
    setattr(fn, _NO_TRACE_MARKER, True)
    return fn


def instrument_class(cls: type) -> None:
    """
    Replace the methods a class defines with traced versions, in place.

    Only the class's own attributes are considered, so inherited methods are left to the class
    that defines them, and dunder methods are skipped.

    A method defined with `@staticmethod`, `@classmethod` or `@property` is skipped too: the
    class dict holds a descriptor for those, not the underlying function, so there is nothing
    here to wrap. To trace one, decorate it where it is defined and keep `@traced` innermost,
    directly above the `def`.

    Args:
        cls (type): The class to instrument.
    """
    if not _custom_tracing_enabled():
        return

    for name, attr in list(vars(cls).items()):
        if not name.startswith("__") and _is_traceable(attr):
            setattr(cls, name, traced(attr))


def instrument_module(module: ModuleType) -> None:
    """
    Replace the functions a module defines with traced versions, in place.

    Functions the module merely imported are skipped, so instrumenting one module cannot
    silently instrument another's code, or a third-party library's.

    Only calls that look the function up on the module are traced. A caller that did
    `from x import work` holds the original function and keeps calling it untraced, so a
    module whose consumers import it that way needs `@traced` at each definition instead.

    Args:
        module (ModuleType): The module to instrument.
    """
    if not _custom_tracing_enabled():
        return

    for name, attr in list(vars(module).items()):
        if _is_traceable(attr) and attr.__module__ == module.__name__:
            setattr(module, name, traced(attr))


def excluded_url_patterns(paths: Collection[str]) -> str:
    """
    Build the URL exclusion list for the request instrumentation.

    The instrumentation matches these against a whole URL, `scheme://host/path`, using a search
    rather than a full match, so each pattern is anchored at the end. The ASGI path already
    carries any root_path, which a suffix match tolerates.

    Args:
        paths (Collection[str]): The paths to exempt. Must not contain `"/"`, which anchored as
            `/$` would match every URL ending in a slash.

    Returns:
        str: A comma-separated list of regexes, in the form
            `opentelemetry.util.http.parse_excluded_urls` expects.
    """
    return ",".join(sorted(re.escape(path) + "$" for path in paths))


def _resolve_instrumentors(
    instrumentors: Iterable[Instrumentor] | None,
) -> list[Instrumentor]:
    """
    Return the library instrumentations to enable.

    Args:
        instrumentors (Iterable[Instrumentor] | None): The caller's choice, or None for the
            default set.

    Returns:
        list[Instrumentor]: Outbound HTTP in both its async and sync forms, plus log
            correlation, which puts otelTraceID/otelSpanID/otelServiceName on every record for
            the logging formatters to render.
    """
    if instrumentors is not None:
        return list(instrumentors)

    # Imported here rather than at module scope so that installing a narrower set of the
    # instrumentation packages does not break importing this module.
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor

    return [
        HTTPXClientInstrumentor(),
        RequestsInstrumentor(),
        LoggingInstrumentorWithContext(),
    ]


class LoggingInstrumentorWithContext:
    """
    LoggingInstrumentor with the one argument that makes log correlation happen.

    A bare `LoggingInstrumentor()` does not inject trace context, so logs carry no trace id and
    nothing joins them to spans. Pass this instead when supplying your own `instrumentors` list.
    """

    def __init__(self, instrumentor: BaseInstrumentor | None = None) -> None:
        if instrumentor is None:
            from opentelemetry.instrumentation.logging import LoggingInstrumentor

            instrumentor = LoggingInstrumentor()
        self._instrumentor = instrumentor

    def instrument(self) -> None:
        """Enable log correlation."""
        self._instrumentor.instrument(inject_trace_context=True)


def _span_exporter(endpoint: str, protocol: str) -> SpanExporter:
    """
    Build the span exporter selected by the OTLP protocol.

    Args:
        endpoint (str): Signal-agnostic base URL of the collector, or "" for the console.
        protocol (str): Either `grpc` or `http/protobuf`.

    Returns:
        SpanExporter: A gRPC, HTTP, or console exporter.
    """
    if not endpoint:
        return ConsoleSpanExporter()

    if protocol == GRPC_PROTOCOL:
        return GrpcSpanExporter(endpoint=endpoint)

    # The endpoint is a signal-agnostic base per the OTLP spec, and the HTTP exporter only
    # appends `/v1/traces` when it reads that variable itself. An `endpoint` passed to the
    # constructor is used verbatim, so the path has to be added here.
    return HttpSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")


def _link_spans_to_profiles() -> None:
    """
    Add the span processor that joins traces to Pyroscope profiles, when both are running.

    Skipped unless the profiler is active: the processor tags the profiler's thread on every root
    span, which with no agent to receive the tags is cost on the request path for nothing.
    """
    if not profiling_active():
        return

    provider = trace.get_tracer_provider()
    if not isinstance(provider, TracerProvider):
        # A provider installed by something else need not be the SDK's, and only the SDK's has
        # add_span_processor. Traces and profiles both keep working, just unlinked.
        logger.warning(
            "The installed tracer provider takes no span processors, so profiles will not link "
            "to traces"
        )
        return

    from pyroscope.otel import PyroscopeSpanProcessor

    provider.add_span_processor(PyroscopeSpanProcessor())


def _custom_tracing_enabled() -> bool:
    """
    Report whether the per-function span helpers should wrap anything.

    Prefers what `configure_tracing` resolved, falling back to the environment. The fallback is
    what `@traced` gets: it runs when the decorated module is imported, before any
    `configure_tracing` call, so only the environment can gate it. `instrument_class` and
    `instrument_module` run from an app factory afterwards and do see the resolved value.

    Returns:
        bool: True when tracing is on and the kill switch is off. The kill switch is read from
            the environment either way, so it can disable custom tracing in a deployment whose
            service configures `enabled` in code.
    """
    if env_bool("FORCE_DISABLE_CUSTOM_TRACING", False):
        return False

    if _tracing_enabled_override is not None:
        return _tracing_enabled_override

    return env_bool("ENABLE_OPENTELEMETRY_TRACES", True)


def reset_tracing_state() -> None:
    """
    Forget what `configure_tracing` resolved.

    Exists for tests: the override is process-wide, so without this the first test to configure
    tracing decides the answer for every test after it.
    """
    global _tracing_enabled_override

    _tracing_enabled_override = None


def _is_traceable(attr: object) -> bool:
    """Return whether a class or module attribute is a function `traced` can wrap."""
    return (
        inspect.isfunction(attr)
        and not inspect.isgeneratorfunction(attr)
        and not inspect.isasyncgenfunction(attr)
        and not getattr(attr, _NO_TRACE_MARKER, False)
        # This would indicate it's already traced
        and not getattr(attr, _TRACED_MARKER, False)
    )


def _tracer_provider_is_set() -> bool:
    """Return whether a real tracer provider has already replaced the default proxy."""
    return not isinstance(trace.get_tracer_provider(), trace.ProxyTracerProvider)
