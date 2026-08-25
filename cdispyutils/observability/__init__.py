"""
Tracing, continuous profiling, and request metrics for Gen3 FastAPI services.

Requires the `observability` extra. Import the submodules directly rather than through this
package: each one pulls a different slice of that extra, and re-exporting here would make any
single import drag in OpenTelemetry, Pyroscope, and FastAPI together.
"""
