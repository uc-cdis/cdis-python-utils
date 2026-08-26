"""
Tests for the OpenTelemetry tracing helpers.
"""

import asyncio
import time
from types import ModuleType

import pytest
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode
from opentelemetry.util.http import parse_excluded_urls

from cdispyutils.observability.constants import DEFAULT_ENDPOINTS_WITHOUT_METRICS
from cdispyutils.observability.tracing import (
    configure_tracing,
    excluded_url_patterns,
    get_tracer,
    instrument_class,
    instrument_module,
    no_trace,
    reset_tracing_state,
    traced,
)

SLEEP_SECONDS = 0.01


@pytest.fixture(scope="session")
def exporter():
    """
    Install one SDK tracer provider for the whole session.

    Session-scoped because `set_tracer_provider` only warns on a second call, so a narrower
    fixture would silently keep using the first provider it installed.
    """
    in_memory = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(in_memory))
    trace.set_tracer_provider(provider)
    return in_memory


@pytest.fixture(autouse=True)
def spans(exporter):
    """Give each test an empty span buffer."""
    exporter.clear()
    return exporter


@pytest.fixture(autouse=True)
def tracing_enabled(monkeypatch):
    """Turn custom tracing on, as a default deployment has it, and leave no state behind."""
    monkeypatch.setenv("ENABLE_OPENTELEMETRY_TRACES", "true")
    monkeypatch.delenv("FORCE_DISABLE_CUSTOM_TRACING", raising=False)
    reset_tracing_state()
    yield
    reset_tracing_state()


def build_module(source: str, name: str = "sample_module") -> ModuleType:
    """Build a module from source so module-level instrumentation can be exercised."""
    module = ModuleType(name)
    exec(compile(source, name, "exec"), module.__dict__)
    return module


def test_span_is_named_for_the_function(spans):
    """A traced function emits one span named for its module and qualified name."""

    @traced
    def work():
        return "done"

    assert work() == "done"

    finished = spans.get_finished_spans()
    assert len(finished) == 1
    assert finished[0].name.endswith(
        "test_span_is_named_for_the_function.<locals>.work"
    )


def test_async_function_is_traced_across_its_await(spans):
    """An async function returns its value and its span covers the awaited work."""

    @traced
    async def work():
        await asyncio.sleep(SLEEP_SECONDS)
        return "done"

    assert asyncio.run(work()) == "done"

    finished = spans.get_finished_spans()
    assert len(finished) == 1
    assert finished[0].end_time - finished[0].start_time >= SLEEP_SECONDS * 1e9


def test_nested_calls_are_linked_as_parent_and_child(spans):
    """A traced function called from another is recorded as its child."""

    @traced
    def inner():
        return 1

    @traced
    def outer():
        return inner()

    outer()

    finished = spans.get_finished_spans()
    child = next(s for s in finished if s.name.endswith("inner"))
    parent = next(s for s in finished if s.name.endswith("outer"))
    assert child.parent.span_id == parent.context.span_id


def test_exception_is_recorded_and_still_propagates(spans):
    """A raising function marks its span as an error and does not swallow the exception."""

    @traced
    def work():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        work()

    span = spans.get_finished_spans()[0]
    assert span.status.status_code is StatusCode.ERROR
    assert len([event for event in span.events if event.name == "exception"]) == 1


@pytest.mark.parametrize("kill_switch", ["true", "false"])
def test_generator_functions_are_rejected(monkeypatch, kill_switch):
    """Tracing a generator raises whether or not the kill switch is on."""
    monkeypatch.setenv("FORCE_DISABLE_CUSTOM_TRACING", kill_switch)

    def gen():
        yield 1

    async def agen():
        yield 1

    with pytest.raises(TypeError):
        traced(gen)
    with pytest.raises(TypeError):
        traced(agen)


def test_instrument_class_traces_the_methods_it_defines(spans):
    """Instrumenting a class traces its own methods, including private ones."""

    class Service:
        def public(self):
            return self._private()

        def _private(self):
            return 1

    instrument_class(Service)
    Service().public()

    names = [span.name for span in spans.get_finished_spans()]
    assert any(name.endswith("Service.public") for name in names)
    assert any(name.endswith("Service._private") for name in names)


def test_instrument_class_is_idempotent(spans):
    """Instrumenting a class twice does not nest a second span around every call."""

    class Service:
        def work(self):
            return 1

    instrument_class(Service)
    instrument_class(Service)
    Service().work()

    assert len(spans.get_finished_spans()) == 1


def test_instrument_class_skips_dunders_and_descriptors(spans):
    """Constructors, static methods, class methods and properties are left alone."""

    class Service:
        def __init__(self):
            self.value = 1

        @staticmethod
        def helper():
            return 1

        @classmethod
        def build(cls):
            return cls()

        @property
        def doubled(self):
            return self.value * 2

    instrument_class(Service)
    Service.helper()
    Service.build().doubled

    assert spans.get_finished_spans() == ()


def test_instrument_module_traces_only_its_own_functions(spans):
    """A module's own functions are traced and the ones it imported are not."""
    module = build_module(
        "from json import dumps\n" "def own():\n" "    return dumps({})\n"
    )
    instrument_module(module)
    module.own()

    names = [span.name for span in spans.get_finished_spans()]
    assert len(names) == 1
    assert names[0].endswith("own")


def test_instrument_module_leaves_generators_alone(spans):
    """A module holding a generator can be instrumented without raising."""
    module = build_module(
        "def gen():\n" "    yield 1\n" "def work():\n" "    return list(gen())\n"
    )
    instrument_module(module)

    assert module.work() == [1]
    assert len(spans.get_finished_spans()) == 1


def test_no_trace_excludes_a_function(spans):
    """A function marked no_trace is skipped by the module walk."""
    module = build_module(
        "from cdispyutils.observability.tracing import no_trace\n"
        "@no_trace\n"
        "def skipped():\n"
        "    return 1\n"
        "def traced_one():\n"
        "    return skipped()\n"
    )
    instrument_module(module)
    module.traced_one()

    names = [span.name for span in spans.get_finished_spans()]
    assert len(names) == 1
    assert names[0].endswith("traced_one")


@pytest.mark.parametrize(
    "env",
    [
        {"ENABLE_OPENTELEMETRY_TRACES": "false"},
        {"FORCE_DISABLE_CUSTOM_TRACING": "true"},
    ],
)
def test_disabled_tracing_returns_the_original_function(monkeypatch, env):
    """With tracing off, the decorator hands back the function untouched."""
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    def work():
        return 1

    assert traced(work) is work


def test_get_tracer_produces_usable_spans(spans):
    """A tracer taken by name records the spans opened through it."""
    with get_tracer(__name__).start_as_current_span("manual"):
        pass

    assert [span.name for span in spans.get_finished_spans()] == ["manual"]


@pytest.mark.parametrize(
    "url",
    [
        "http://host/_status",
        "http://host/_status/",
        "http://host/metrics",
        "http://host/ai/embeddings/_status",
    ],
)
def test_polled_endpoints_are_excluded(url):
    """Probe and scrape endpoints produce no request spans, including behind a prefix."""
    excluded = parse_excluded_urls(
        excluded_url_patterns(DEFAULT_ENDPOINTS_WITHOUT_METRICS)
    )

    assert excluded.url_disabled(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://host/",
        "http://host/docs",
        "http://host/openapi.json",
        "http://host/collections",
        "http://host/collections/",
        "http://host/collections/a-name",
    ],
)
def test_real_traffic_is_not_excluded(url):
    """Ordinary routes, including trailing-slash forms, still produce request spans."""
    excluded = parse_excluded_urls(
        excluded_url_patterns(DEFAULT_ENDPOINTS_WITHOUT_METRICS)
    )

    assert not excluded.url_disabled(url)


def test_configure_tracing_respects_the_environment(monkeypatch):
    """With traces disabled in the environment, the app is left uninstrumented."""
    monkeypatch.setenv("ENABLE_OPENTELEMETRY_TRACES", "false")
    app = FastAPI()
    configure_tracing(app, "test_service")

    assert not hasattr(app, "_is_instrumented_by_opentelemetry") or not getattr(
        app, "_is_instrumented_by_opentelemetry"
    )


def test_configure_tracing_instruments_the_app(monkeypatch):
    """An enabled service gets its FastAPI app instrumented."""
    app = FastAPI()
    configure_tracing(app, "test_service", instrumentors=())

    assert getattr(app, "_is_instrumented_by_opentelemetry")


def test_configure_tracing_choice_reaches_the_instrument_helpers(monkeypatch):
    """A service configuring tracing in code, not the environment, still gates instrument_class."""
    monkeypatch.delenv("ENABLE_OPENTELEMETRY_TRACES", raising=False)
    configure_tracing(FastAPI(), "test_service", enabled=False, instrumentors=())

    class Service:
        def work(self):
            """Do nothing."""

    original = Service.work
    instrument_class(Service)

    assert Service.work is original


def test_kill_switch_overrides_a_configured_choice(monkeypatch):
    """FORCE_DISABLE_CUSTOM_TRACING wins over a service that enabled tracing explicitly."""
    configure_tracing(FastAPI(), "test_service", enabled=True, instrumentors=())
    monkeypatch.setenv("FORCE_DISABLE_CUSTOM_TRACING", "true")

    def work():
        return 1

    assert traced(work) is work


def test_reset_sends_the_helpers_back_to_the_environment(monkeypatch):
    """Resetting forgets the configured choice so the environment decides again."""
    configure_tracing(FastAPI(), "test_service", enabled=False, instrumentors=())
    reset_tracing_state()
    monkeypatch.setenv("ENABLE_OPENTELEMETRY_TRACES", "true")

    def work():
        return 1

    assert traced(work) is not work
