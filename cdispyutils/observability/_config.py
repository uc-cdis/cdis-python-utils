"""
Environment-variable fallbacks for the observability helpers' keyword arguments.
"""

import os
from collections.abc import Callable

# What `starlette.config.Config(cast=bool)` accepts, so a deployment that already sets
# ENABLE_OPENTELEMETRY_TRACES=false for a Starlette-configured service keeps the same meaning
# here.
_TRUE_VALUES = frozenset({"true", "1", "on", "yes", "y", "t"})
_FALSE_VALUES = frozenset({"false", "0", "off", "no", "n", "f", ""})


def env_bool(name: str, default: bool) -> bool:
    """
    Read a boolean setting from the environment.

    Args:
        name (str): The environment variable to read.
        default (bool): Returned when the variable is not set.

    Returns:
        bool: The parsed value, or `default`.

    Raises:
        ValueError: If the variable is set to something that is neither true-ish nor false-ish.
            Rejected rather than read as false, so a typo in a deployment's configuration turns
            observability off loudly instead of silently.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default

    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False

    raise ValueError(
        f"environment variable {name}={raw!r} is not a boolean; expected one of "
        f"{sorted(_TRUE_VALUES | _FALSE_VALUES)}"
    )


def env_str(name: str, default: str) -> str:
    """
    Read a string setting from the environment.

    Args:
        name (str): The environment variable to read.
        default (str): Returned when the variable is not set.

    Returns:
        str: The value, or `default`. An empty variable reads as the empty string, which the
            callers treat as "no endpoint configured" rather than falling back to `default`.
    """
    raw = os.environ.get(name)
    return default if raw is None else raw


def env_int(name: str, default: int) -> int:
    """
    Read an integer setting from the environment.

    Args:
        name (str): The environment variable to read.
        default (int): Returned when the variable is not set.

    Returns:
        int: The parsed value, or `default`.

    Raises:
        ValueError: If the variable is set to something that is not an integer.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default

    try:
        return int(raw.strip())
    except ValueError:
        raise ValueError(
            f"environment variable {name}={raw!r} is not an integer"
        ) from None


def resolve[
    Setting
](
    value: Setting | None,
    name: str,
    default: Setting,
    reader: Callable[[str, Setting], Setting],
) -> Setting:
    """
    Return an explicit argument, or the environment's value for it.

    Args:
        value (Setting | None): The argument as the caller passed it. Anything other than None is
            used as-is, so an explicit False or empty string overrides the environment.
        name (str): The environment variable to fall back to.
        default (Setting): Returned when the argument is None and the variable is not set.
        reader (Callable[[str, Setting], Setting]): One of `env_bool`, `env_str`, or `env_int`.

    Returns:
        Setting: The resolved setting, with the same type as `default`.
    """
    if value is not None:
        return value
    return reader(name, default)
