"""
Tests for the FastAPI request-metrics middleware.
"""

import tempfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse

from cdispyutils.metrics import BaseMetrics
from cdispyutils.observability.request_metrics import add_request_metrics_middleware

COUNTER_NAME = "test_api_requests"
HISTOGRAM_NAME = "test_api_request_duration_seconds"


@pytest.fixture
def metrics():
    """A metrics client writing to a throwaway directory."""
    with tempfile.TemporaryDirectory() as prometheus_dir:
        yield BaseMetrics(enabled=True, prometheus_dir=prometheus_dir)


def build_app(metrics, **kwargs) -> FastAPI:
    """Build an instrumented app exposing one route of each interesting shape."""
    app = FastAPI(**kwargs.pop("app_kwargs", {}))

    @app.get("/")
    def root():
        return {"ok": True}

    @app.get("/_status")
    def status():
        return {"ok": True}

    @app.get("/things/{thing_id}")
    def thing(thing_id: str):
        return {"thing_id": thing_id}

    @app.get("/boom")
    def boom():
        raise RuntimeError("kaboom")

    @app.get("/stream")
    def stream():
        return StreamingResponse(iter([b"chunk-a", b"chunk-b"]))

    if metrics is not None:
        app.mount("/metrics", metrics.get_asgi_app())

    add_request_metrics_middleware(app, metrics, counter_name=COUNTER_NAME, **kwargs)
    return app


def client(app) -> TestClient:
    """A test client that reports server errors as 500s instead of re-raising them."""
    return TestClient(app, raise_server_exceptions=False)


def samples(test_client) -> list[str]:
    """Return the counter's sample lines from a scrape of the metrics endpoint."""
    body = test_client.get("/metrics").text
    return [
        line for line in body.splitlines() if line.startswith(f"{COUNTER_NAME}_total{{")
    ]


def label_sets(test_client) -> list[str]:
    """Return just the label portion of each of the counter's sample lines."""
    return [
        line[line.index("{") : line.rindex("}") + 1] for line in samples(test_client)
    ]


def test_served_request_is_counted(metrics):
    """A served request is counted with its method, path and status."""
    c = client(build_app(metrics))
    c.get("/")

    assert any(
        'method="GET"' in s and 'path="/"' in s and 'status_code="200"' in s
        for s in label_sets(c)
    )


def test_path_parameter_is_recorded_as_its_route_template(metrics):
    """A path parameter is labelled with its template, not the value that was requested."""
    c = client(build_app(metrics))
    c.get("/things/abc")
    c.get("/things/def")

    recorded = label_sets(c)
    assert any('path="/things/{thing_id}"' in s for s in recorded)
    assert not any("abc" in s or "def" in s for s in recorded)


def test_unmatched_requests_share_one_path_label(metrics):
    """Requests matching no route collapse into a single time series."""
    c = client(build_app(metrics))
    c.get("/nope/one")
    c.get("/nope/two")

    unmatched = [s for s in label_sets(c) if 'status_code="404"' in s]
    assert len(unmatched) == 1
    assert not any("nope" in s for s in label_sets(c))


def test_method_not_allowed_is_recorded_under_its_route_template(metrics):
    """A 405 is labelled with the template it partially matched."""
    c = client(build_app(metrics))
    c.post("/things/abc")

    assert any(
        'path="/things/{thing_id}"' in s and 'status_code="405"' in s
        for s in label_sets(c)
    )


@pytest.mark.parametrize("path", ["/docs", "/openapi.json"])
def test_documentation_endpoints_are_counted_under_their_own_label(metrics, path):
    """Docs and spec traffic is counted under its own path label, not as unmatched."""
    c = client(build_app(metrics))
    c.get(path)

    assert any(f'path="{path}"' in s for s in label_sets(c))


def test_scraping_the_metrics_endpoint_records_nothing(metrics):
    """A Prometheus scrape does not count itself."""
    c = client(build_app(metrics))
    c.get("/")
    before = samples(c)
    after = samples(c)

    assert before == after


def test_scrape_records_nothing_even_with_no_configured_exclusions(metrics):
    """The metrics endpoint is excluded even when the caller excludes nothing."""
    c = client(build_app(metrics, excluded_paths=()))
    c.get("/")
    before = samples(c)

    assert samples(c) == before


def test_scrape_records_nothing_when_the_app_is_behind_a_root_path(metrics):
    """A scrape does not count itself when the app is served under a prefix."""
    app = build_app(metrics, app_kwargs={"root_path": "/prefix"})
    c = TestClient(app, root_path="/prefix", raise_server_exceptions=False)
    c.get("/prefix/")
    before = [
        line
        for line in c.get("/prefix/metrics").text.splitlines()
        if line.startswith(f"{COUNTER_NAME}_total{{")
    ]
    after = [
        line
        for line in c.get("/prefix/metrics").text.splitlines()
        if line.startswith(f"{COUNTER_NAME}_total{{")
    ]

    assert before == after


def test_excluded_path_is_not_counted(metrics):
    """A path in excluded_paths records nothing."""
    c = client(build_app(metrics))
    c.get("/_status")

    assert not any('path="/_status"' in s for s in label_sets(c))


def test_extra_label_from_provider_is_recorded(metrics):
    """A provider's value is recorded under its declared label name."""

    async def provider(request):
        return {"user_id": "someone"}

    c = client(
        build_app(metrics, extra_label_names=("user_id",), extra_labels=provider)
    )
    c.get("/")

    assert any('user_id="someone"' in s for s in label_sets(c))


def test_failing_provider_yields_unknown_and_leaves_the_response_alone(metrics):
    """A provider that raises does not affect the response and labels the request Unknown."""

    async def provider(request):
        raise RuntimeError("no idea")

    c = client(
        build_app(metrics, extra_label_names=("user_id",), extra_labels=provider)
    )
    response = c.get("/")

    assert response.status_code == 200
    assert any('user_id="Unknown"' in s for s in label_sets(c))


def test_provider_omitting_a_declared_name_yields_unknown(metrics):
    """A declared label the provider did not supply is recorded as Unknown."""

    async def provider(request):
        return {"user_id": "someone"}

    c = client(
        build_app(
            metrics,
            extra_label_names=("user_id", "tenant"),
            extra_labels=provider,
        )
    )
    c.get("/")

    assert any(
        'user_id="someone"' in s and 'tenant="Unknown"' in s for s in label_sets(c)
    )


def test_undeclared_name_from_provider_is_dropped(metrics):
    """A label the provider returns but did not declare does not reach the counter."""

    async def provider(request):
        return {"user_id": "someone", "sneaky": "value"}

    c = client(
        build_app(metrics, extra_label_names=("user_id",), extra_labels=provider)
    )
    c.get("/")

    assert not any("sneaky" in s for s in label_sets(c))


def test_label_values_stay_with_their_own_labels_across_requests(metrics):
    """Values are not swapped when the provider's dict iterates in a different order."""
    calls = {"n": 0}

    async def provider(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"first": "one", "second": "two"}
        return {"second": "two", "first": "one"}

    c = client(
        build_app(
            metrics,
            extra_label_names=("first", "second"),
            extra_labels=provider,
        )
    )
    c.get("/")
    c.get("/")

    recorded = label_sets(c)
    assert all('first="one"' in s and 'second="two"' in s for s in recorded)


def test_provider_reading_the_body_does_not_affect_the_response(metrics):
    """A provider that reaches for the request body fails without breaking the request."""

    async def provider(request):
        return {"user_id": (await request.body()).decode()}

    c = client(
        build_app(metrics, extra_label_names=("user_id",), extra_labels=provider)
    )
    response = c.get("/")

    assert response.status_code == 200
    assert any('user_id="Unknown"' in s for s in label_sets(c))


@pytest.mark.parametrize(
    "names,provider",
    [
        (("user_id",), None),
        ((), lambda request: {}),
        (("method",), lambda request: {}),
        (("path", "user_id"), lambda request: {}),
    ],
)
def test_invalid_label_configuration_is_rejected_at_install_time(
    metrics, names, provider
):
    """A mismatched or reserved label configuration raises when the middleware is added."""
    with pytest.raises(ValueError):
        build_app(metrics, extra_label_names=names, extra_labels=provider)


def test_unhandled_error_is_counted_as_a_server_error(metrics):
    """A route that raises is counted with status 500."""
    c = client(build_app(metrics))
    response = c.get("/boom")

    assert response.status_code == 500
    assert any('path="/boom"' in s and 'status_code="500"' in s for s in label_sets(c))


def test_streaming_response_is_counted_and_arrives_intact(metrics):
    """A streaming response is counted without its body being disturbed."""
    c = client(build_app(metrics))
    response = c.get("/stream")

    assert response.content == b"chunk-achunk-b"
    assert any('path="/stream"' in s for s in label_sets(c))


def test_response_is_passed_through_unchanged(metrics):
    """The middleware does not alter the status, body or headers of a response."""
    c = client(build_app(metrics))
    response = c.get("/things/abc")

    assert response.status_code == 200
    assert response.json() == {"thing_id": "abc"}
    assert response.headers["content-type"] == "application/json"


def test_disabled_metrics_client_installs_nothing():
    """A disabled client leaves requests working and creates no counter."""
    with tempfile.TemporaryDirectory() as prometheus_dir:
        disabled = BaseMetrics(enabled=False, prometheus_dir=prometheus_dir)
        app = FastAPI()

        @app.get("/")
        def root():
            return {"ok": True}

        add_request_metrics_middleware(app, disabled, counter_name=COUNTER_NAME)
        response = TestClient(app).get("/")

    assert response.status_code == 200
    assert disabled.prometheus_metrics == {}


def test_absent_metrics_client_installs_nothing():
    """A None client leaves requests working."""
    app = FastAPI()

    @app.get("/")
    def root():
        return {"ok": True}

    add_request_metrics_middleware(app, None, counter_name=COUNTER_NAME)

    assert TestClient(app).get("/").status_code == 200


def histogram_lines(test_client) -> list[str]:
    """Return the duration histogram's bucket lines from a scrape."""
    body = test_client.get("/metrics").text
    return [
        line
        for line in body.splitlines()
        if line.startswith(f"{HISTOGRAM_NAME}_bucket")
    ]


def test_request_duration_is_recorded_when_a_histogram_is_named(metrics):
    """A duration histogram is recorded alongside the counter when one is requested."""
    c = client(build_app(metrics, duration_histogram_name=HISTOGRAM_NAME))
    c.get("/things/abc")

    assert any('path="/things/{thing_id}"' in line for line in histogram_lines(c))
    assert any('path="/things/{thing_id}"' in s for s in label_sets(c))


def test_no_histogram_is_recorded_by_default(metrics):
    """Without a histogram name, only the counter is recorded."""
    c = client(build_app(metrics))
    c.get("/things/abc")

    assert histogram_lines(c) == []


def test_streaming_response_duration_covers_the_body(metrics):
    """A streamed response is timed to the last chunk, not to its headers."""
    c = client(build_app(metrics, duration_histogram_name=HISTOGRAM_NAME))
    c.get("/stream")

    observed = [
        sample.value
        for metric in metrics.prometheus_metrics[HISTOGRAM_NAME].collect()
        for sample in metric.samples
        if sample.name.endswith("_sum") and sample.labels["path"] == "/stream"
    ]
    assert observed and observed[0] > 0


def test_histogram_on_a_client_that_cannot_record_one_is_rejected(metrics):
    """Asking for a histogram from a client without the capability fails at install time."""

    class CounterOnlyMetrics:
        enabled = True

        def increment_counter(self, name, labels, description=""):
            """Record nothing."""

    with pytest.raises(ValueError):
        add_request_metrics_middleware(
            FastAPI(),
            CounterOnlyMetrics(),
            counter_name=COUNTER_NAME,
            duration_histogram_name=HISTOGRAM_NAME,
        )
