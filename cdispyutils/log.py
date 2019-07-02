"""Opinionated basic logging setup."""

import logging
import sys

LOGGERS = {}


def get_handler():
    """Return a stdout stream handler"""
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "[%(asctime)s][%(name)10s][%(levelname)7s] %(message)s"
    )
    handler.setFormatter(formatter)
    return handler


def get_logger(name):
    """Return an opinionated basic logger named `name` that logs to
    stdout."""
    if LOGGERS.get(name):
        return LOGGERS.get(name)
    else:
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        if not (
            len(logger.handlers) > 0
            and type(logger.handlers[0]) == logging.StreamHandler
        ):
            logger.addHandler(get_handler())
            logger.propagate = False
    return logger
