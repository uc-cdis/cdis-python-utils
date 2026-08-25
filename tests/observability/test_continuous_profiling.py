"""
Tests for the Pyroscope continuous-profiling lifecycle.
"""

import pytest

from cdispyutils.observability import continuous_profiling
from cdispyutils.observability.continuous_profiling import (
    configure_profiling,
    profiling_active,
    stop_profiling,
)

SERVICE_NAME = "test_service"
SERVER_ADDRESS = "http://pyroscope.test:4040"


class FakeAgent:
    """Stands in for the pyroscope SDK, recording what it was asked to do."""

    def __init__(self) -> None:
        self.configure_calls: list[dict] = []
        self.shutdown_calls = 0

    def configure(self, **kwargs) -> None:
        """Record a request to start the agent."""
        self.configure_calls.append(kwargs)

    def shutdown(self) -> None:
        """Record a request to stop the agent."""
        self.shutdown_calls += 1


@pytest.fixture(autouse=True)
def agent(monkeypatch):
    """Replace the SDK with a fake, and leave no agent running behind the test."""
    fake = FakeAgent()
    monkeypatch.setattr(continuous_profiling, "pyroscope", fake)
    yield fake
    stop_profiling()


@pytest.fixture
def profiling_on(monkeypatch):
    """Turn profiling on through the environment, as a deployment would."""
    monkeypatch.setenv("ENABLE_CONTINUOUS_PROFILING", "true")
    monkeypatch.setenv("PYROSCOPE_SERVER_ADDRESS", SERVER_ADDRESS)


def test_profiling_is_off_by_default(agent, monkeypatch):
    """With nothing configured, no agent is started."""
    monkeypatch.delenv("ENABLE_CONTINUOUS_PROFILING", raising=False)
    configure_profiling(SERVICE_NAME)

    assert agent.configure_calls == []
    assert not profiling_active()


def test_enabling_starts_the_agent_under_the_service_name(agent, profiling_on):
    """An enabled service starts the agent under its own name."""
    configure_profiling(SERVICE_NAME)

    assert profiling_active()
    assert agent.configure_calls[0]["application_name"] == SERVICE_NAME
    assert agent.configure_calls[0]["server_address"] == SERVER_ADDRESS


def test_cpu_is_profiled_and_memory_is_not_by_default(agent, profiling_on):
    """CPU profiling is on and memory profiling is off unless asked for."""
    configure_profiling(SERVICE_NAME)

    assert agent.configure_calls[0]["cpu_enabled"] is True
    assert agent.configure_calls[0]["mem_enabled"] is False


def test_memory_profiling_can_be_requested(agent, profiling_on):
    """Asking for memory profiling reaches the SDK."""
    configure_profiling(SERVICE_NAME, profile_memory=True)

    assert agent.configure_calls[0]["mem_enabled"] is True


def test_wall_clock_profiling_can_be_requested(agent, profiling_on):
    """Turning off on-CPU-only profiling reaches the SDK."""
    configure_profiling(SERVICE_NAME, on_cpu_only=False)

    assert agent.configure_calls[0]["oncpu"] is False


def test_explicit_argument_overrides_the_environment(agent, profiling_on):
    """An explicitly disabled service does not start the agent despite the environment."""
    configure_profiling(SERVICE_NAME, enabled=False)

    assert agent.configure_calls == []
    assert not profiling_active()


def test_missing_server_address_does_not_start_the_agent(agent, monkeypatch):
    """Profiling enabled with nowhere to push does not start the agent."""
    monkeypatch.setenv("ENABLE_CONTINUOUS_PROFILING", "true")
    monkeypatch.setenv("PYROSCOPE_SERVER_ADDRESS", "")
    configure_profiling(SERVICE_NAME)

    assert agent.configure_calls == []
    assert not profiling_active()


def test_caller_tags_are_merged_over_the_defaults(agent, profiling_on):
    """Caller-supplied tags reach the SDK alongside the default pod tag."""
    configure_profiling(SERVICE_NAME, tags={"region": "us-east-1"})

    tags = agent.configure_calls[0]["tags"]
    assert tags["region"] == "us-east-1"
    assert "pod" in tags


def test_configuring_twice_leaves_the_running_agent_alone(agent, profiling_on):
    """A second call does not start a second agent."""
    configure_profiling(SERVICE_NAME)
    configure_profiling(SERVICE_NAME)

    assert len(agent.configure_calls) == 1


def test_stopping_shuts_the_agent_down_and_allows_restarting(agent, profiling_on):
    """Stopping the agent reports it inactive and lets it be configured again."""
    configure_profiling(SERVICE_NAME)
    stop_profiling()

    assert agent.shutdown_calls == 1
    assert not profiling_active()

    configure_profiling(SERVICE_NAME)
    assert profiling_active()
    assert len(agent.configure_calls) == 2


def test_stopping_an_unstarted_agent_does_nothing(agent):
    """Stopping when nothing is running never reaches the SDK."""
    stop_profiling()

    assert agent.shutdown_calls == 0
