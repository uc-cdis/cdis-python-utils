# observability

Tracing, continuous profiling, and request metrics for Gen3 FastAPI services.

```bash
poetry add 'cdispyutils[observability]'
```

Four signals and how they leave the process:

| Signal   | Path out                                    | Configured by                                            |
| -------- | ------------------------------------------- | -------------------------------------------------------- |
| Traces   | OTLP to a collector, or the console         | `tracing.configure_tracing`                              |
| Profiles | Pyroscope ingest API                        | `continuous_profiling.configure_profiling`               |
| Metrics  | Scraped from an endpoint the service mounts | `request_metrics.add_request_metrics_middleware`         |
| Logs     | JSON on stdout, carrying the trace id       | `cdislogging`, correlated by the logging instrumentation |

Import the submodules directly. Importing them through the package would drag OpenTelemetry,
Pyroscope, and FastAPI in together even when only one is wanted.

## Wiring a service

Order matters: `configure_profiling` runs first, because `configure_tracing` only links spans to
profiles when it can see that an agent is already running.

```python
from cdispyutils.metrics import BaseMetrics
from cdispyutils.observability.continuous_profiling import configure_profiling
from cdispyutils.observability.request_metrics import add_request_metrics_middleware
from cdispyutils.observability.tracing import configure_tracing, instrument_class


def get_app() -> FastAPI:
    app = FastAPI()

    configure_profiling("my_service")
    configure_tracing(app, "my_service")

    instrument_class(DataAccessLayer)

    metrics = BaseMetrics(enabled=True)
    app.mount("/metrics", metrics.get_metrics_app(path="/var/tmp/prometheus_metrics"))
    add_request_metrics_middleware(
        app, metrics, counter_name="my_service_api_requests"
    )
    return app
```

Every setting has a keyword argument and an environment variable behind it. Leave the argument
out to take the environment's value; pass it to override. A service with its own config object
passes its values in explicitly.

### Choosing instrumentors

`configure_tracing` enables HTTPX, requests, and log correlation by default. Pass `instrumentors`
to change that - a service with no `requests` calls and a pile of boto3 ones wants a different
set, and database instrumentation is deliberately not in the default because the right one
differs per service:

```python
from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

from cdispyutils.observability.tracing import LoggingInstrumentorWithContext

configure_tracing(
    app,
    "my_service",
    instrumentors=[
        HTTPXClientInstrumentor(),
        BotocoreInstrumentor(),
        LoggingInstrumentorWithContext(),
    ],
)
```

Use `LoggingInstrumentorWithContext`, not a bare `LoggingInstrumentor()`. The latter does not
inject trace context, so logs carry no trace id and nothing joins them to spans.

## Configuration

| Variable                        | Default         | What it does                                                                                         |
| ------------------------------- | --------------- | ---------------------------------------------------------------------------------------------------- |
| `ENABLE_OPENTELEMETRY_TRACES`   | `true`          | Whether to install a tracer provider at all                                                          |
| `OTEL_EXPORTER_OTLP_ENDPOINT`   | `""`            | Collector base URL. Empty prints spans to the console                                                |
| `OTEL_EXPORTER_OTLP_PROTOCOL`   | `http/protobuf` | `grpc` or `http/protobuf`                                                                            |
| `FORCE_DISABLE_CUSTOM_TRACING`  | `false`         | Diagnostic switch turning off `@traced` and the instrument helpers while leaving request spans alone |
| `ENABLE_CONTINUOUS_PROFILING`   | `false`         | Whether to start the Pyroscope agent                                                                 |
| `PYROSCOPE_SERVER_ADDRESS`      | `""`            | Pyroscope ingest base URL. Empty leaves the agent stopped                                            |
| `PYROSCOPE_SAMPLE_RATE`         | `100`           | Samples per second                                                                                   |
| `PYROSCOPE_UPLOAD_INTERVAL`     | `10`            | Seconds between pushes                                                                               |
| `PROFILE_CPU`                   | `true`          | Collect CPU profiles                                                                                 |
| `PROFILE_MEMORY`                | `false`         | Collect memory profiles                                                                              |
| `PROFILE_ON_CPU_ONLY`           | `true`          | Measure CPU time rather than wall-clock time                                                         |
| `PYROSCOPE_BASIC_AUTH_USERNAME` | `""`            |                                                                                                      |
| `PYROSCOPE_BASIC_AUTH_PASSWORD` | `""`            |                                                                                                      |
| `PYROSCOPE_TENANT_ID`           | `""`            |                                                                                                      |

`FORCE_DISABLE_CUSTOM_TRACING` exists to answer "is our own instrumentation causing this?" in one
deploy. It is not a setting to leave on.

## Tracing your own functions

A few ways:

**`@traced`** on a definition, roughly 10µs per call:

```python
@traced
async def parse_and_auth_request(request: Request) -> None: ...
```

**`instrument_class(SomeClass)`** where the app is built, not at import. Traces the methods the
class itself defines, skipping inherited ones, dunders, and anything defined with
`@staticmethod`, `@classmethod`, or `@property` - the class dict holds a descriptor for those, so
there is no plain function to wrap. Decorate those where they are defined, with `@traced`
innermost.

**`get_tracer(__name__).start_as_current_span(...)`** when the span should cover part of a
function rather than all of it.

`configure_tracing(enabled=...)` gates `instrument_class` and `instrument_module`, which run from
the app factory after it. It cannot gate `@traced`: that runs when the decorated module is
imported, before any setup call, so only `ENABLE_OPENTELEMETRY_TRACES` in the environment reaches
it. `FORCE_DISABLE_CUSTOM_TRACING` turns off all three regardless.

`instrument_module(module)` exists too, but only calls that look the function up on the module are
affected. A caller that did `from x import work` holds the original and keeps calling it untraced,
so a module whose consumers import it that way needs `@traced` at each definition.

### What not to trace

Anything that runs per row or per loop iteration. A span costs more than the work it reports
there; mark it `@no_trace` so the class and module walks skip it.

Generators and async generators. A span around one ends when the generator object is created,
before any of the body runs, and wrapping hides the function's generator-ness from FastAPI's
dependency injection. `traced` raises `TypeError` rather than let that through, even when tracing
is disabled. Open a span inside the function instead.

## Request metrics

`add_request_metrics_middleware` counts every request, labelled with the route *template* that
matched it. That is the point of it: labelling with the URL would mint a Prometheus time series
per path parameter value, and a scanner walking the URL space would multiply that indefinitely.
Anything served without a matching route collapses to a single `<unmatched>` label.

The metrics endpoint is always excluded, whatever `excluded_paths` says, so a scrape can never
count itself.

Pass `duration_histogram_name` to record request latency as well:

```python
add_request_metrics_middleware(
    app,
    metrics,
    counter_name="my_service_api_requests",
    duration_histogram_name="my_service_api_request_duration_seconds",
)
```

The timing covers the whole response, including a streamed body, because the middleware is pure
ASGI and the downstream call returns only after the last body message. A histogram stores one
bucket series per label combination, so it multiplies the cost of every label far faster than a
counter - be sparing with `extra_label_names` when one is enabled. `duration_buckets` overrides
the defaults, which span 5ms to 10s.

Extra labels come from an async provider paired with the names it supplies:

```python
async def user_id_label(request: Request) -> dict[str, str]:
    return {"user_id": await get_user_id(request=request)}

add_request_metrics_middleware(
    app,
    metrics,
    counter_name="my_service_api_requests",
    extra_label_names=("user_id",),
    extra_labels=user_id_label,
)
```

The declared names are the canonical order, so a provider whose dict iterates differently cannot
swap values between labels. A name it omits, and every name if it raises, records as `Unknown`.
Each name multiplies the counter's cardinality, so declare them deliberately.

## Checking it locally

Spans, with no collector running:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT= python -m uvicorn my_service.main:app
```

Profiles:

```bash
docker run -p 4040:4040 grafana/pyroscope
ENABLE_CONTINUOUS_PROFILING=true PYROSCOPE_SERVER_ADDRESS=http://localhost:4040 \
    python -m uvicorn my_service.main:app
```

`PYROSCOPE_SERVER_ADDRESS` is Pyroscope's own ingest API, `POST /push.v1.PusherService/Push`, not
an OTLP receiver. Pointing it at 4317 or 4318 gets a 404 at push time, well after startup has
appeared to succeed.

One agent runs per process, started when the app is built. Running uvicorn with `--workers` forks
after that point and leaves the children unprofiled. So *****follow our guidelines of 1 uvicorn process per container!*****
