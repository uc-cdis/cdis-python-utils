"""
Continuous profiling with Pyroscope.

Requires the `observability` extra.
"""

import os
from collections.abc import Mapping

import pyroscope
from gen3logging import get_logger

from cdispyutils.observability._config import env_bool, env_int, env_str, resolve

logger = get_logger(__name__)

# Whether `configure_profiling` has started the agent in this process. The SDK holds one global
# agent, and a second `pyroscope.configure` only logs `Agent already running` and returns, so this
# is what keeps that error out of a test suite that builds the app repeatedly.
_agent_running = False


def configure_profiling(
    service_name: str,
    *,
    enabled: bool | None = None,
    server_address: str | None = None,
    sample_rate: int | None = None,
    upload_interval: int | None = None,
    profile_cpu: bool | None = None,
    profile_memory: bool | None = None,
    on_cpu_only: bool | None = None,
    basic_auth_username: str | None = None,
    basic_auth_password: str | None = None,
    tenant_id: str | None = None,
    tags: Mapping[str, str] | None = None,
) -> None:
    """
    Start the Pyroscope agent so this process pushes CPU and memory profiles.

    Does nothing when profiling is disabled, when no server address is configured, or when the
    agent is already running in this process. Call this before
    `cdispyutils.observability.tracing.configure_tracing`, which asks `profiling_active` whether
    to link spans to profiles.

    Every argument left as None is read from the environment variable named beside it below, so a
    service can configure this entirely through its deployment.

    Args:
        service_name (str): Pyroscope's application name, which is what the profiles are grouped
            and queried under.
        enabled (bool | None): Whether to start the agent at all.
            Env ENABLE_CONTINUOUS_PROFILING, default False.
        server_address (str | None): Base URL of the Pyroscope ingest API. Note this is
            Pyroscope's own `POST /push.v1.PusherService/Push` endpoint, not an OTLP receiver, so
            an OTLP port such as 4317 or 4318 fails at push time rather than here.
            Env PYROSCOPE_SERVER_ADDRESS, default "" (the agent is not started).
        sample_rate (int | None): Samples per second. Env PYROSCOPE_SAMPLE_RATE, default 100.
        upload_interval (int | None): Seconds between pushes.
            Env PYROSCOPE_UPLOAD_INTERVAL, default 10.
        profile_cpu (bool | None): Collect CPU profiles. Env PROFILE_CPU, default True.
        profile_memory (bool | None): Collect memory profiles. Env PROFILE_MEMORY, default False.
        on_cpu_only (bool | None): Measure CPU time rather than wall-clock time, so time spent
            awaiting I/O is left out of the flamegraph.
            Env PROFILE_ON_CPU_ONLY, default True.
        basic_auth_username (str | None): Env PYROSCOPE_BASIC_AUTH_USERNAME, default "".
        basic_auth_password (str | None): Env PYROSCOPE_BASIC_AUTH_PASSWORD, default "".
        tenant_id (str | None): Env PYROSCOPE_TENANT_ID, default "".
        tags (Mapping[str, str] | None): Extra tags, merged over the default `pod` tag.
    """
    global _agent_running

    if not resolve(enabled, "ENABLE_CONTINUOUS_PROFILING", False, env_bool):
        logger.info("Continuous profiling is disabled, skipping Pyroscope setup")
        return

    address = resolve(server_address, "PYROSCOPE_SERVER_ADDRESS", "", env_str)
    if not address:
        logger.warning(
            "Continuous profiling is enabled but no Pyroscope server address is configured, "
            "so the agent was not started"
        )
        return

    if _agent_running:
        logger.info(
            "The Pyroscope agent is already running in this process, leaving it alone"
        )
        return

    pyroscope.configure(
        application_name=service_name,
        server_address=address,
        sample_rate=resolve(sample_rate, "PYROSCOPE_SAMPLE_RATE", 100, env_int),
        upload_interval=resolve(
            upload_interval, "PYROSCOPE_UPLOAD_INTERVAL", 10, env_int
        ),
        cpu_enabled=resolve(profile_cpu, "PROFILE_CPU", True, env_bool),
        mem_enabled=resolve(profile_memory, "PROFILE_MEMORY", False, env_bool),
        oncpu=resolve(on_cpu_only, "PROFILE_ON_CPU_ONLY", True, env_bool),
        # Sample only the thread holding the GIL. Every request is handled on the one event loop
        # thread, so that is the thread doing the work; a service that pushed work into a
        # threadpool would need False to see any of it.
        gil_only=True,
        tags=_agent_tags(tags),
        report_pid=True,
        basic_auth_username=resolve(
            basic_auth_username, "PYROSCOPE_BASIC_AUTH_USERNAME", "", env_str
        ),
        basic_auth_password=resolve(
            basic_auth_password, "PYROSCOPE_BASIC_AUTH_PASSWORD", "", env_str
        ),
        tenant_id=resolve(tenant_id, "PYROSCOPE_TENANT_ID", "", env_str),
    )
    _agent_running = True

    logger.info(f"Pyroscope agent started for '{service_name}', pushing to {address}")


def profiling_active() -> bool:
    """
    Report whether the Pyroscope agent is running in this process.

    Returns:
        bool: True only after `configure_profiling` has started the agent. Distinct from the
            enabled setting, because the tagging that links traces to profiles is wasted work
            unless there is an agent to receive the tags.
    """
    return _agent_running


def stop_profiling() -> None:
    """
    Stop the agent and allow `configure_profiling` to start it again.

    Exists for tests, which would otherwise leak one process-wide agent into every test that
    follows the first one to enable profiling.
    """
    global _agent_running

    if not _agent_running:
        return

    pyroscope.shutdown()
    _agent_running = False


def _agent_tags(tags: Mapping[str, str] | None) -> dict[str, str]:
    """
    Build the tag set the agent reports profiles under.

    Args:
        tags (Mapping[str, str] | None): Caller-supplied tags, which win over the defaults.

    Returns:
        dict[str, str]: The merged tags. Kubernetes sets HOSTNAME to the pod name, which is the
            only thing distinguishing one replica's flamegraph from another's.
    """
    return {"pod": os.environ.get("HOSTNAME", ""), **(tags or {})}
