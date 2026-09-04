"""
Small helpers shared across armasec, replacing the `snick` dependency.
"""

from __future__ import annotations

from collections.abc import Callable
from traceback import format_tb
from typing import Any

from armasec_lite.exceptions import DoExceptParams


def noop(*args: Any, **kwargs: Any) -> None:
    """
    Do nothing. Used as the default `debug_logger` so callers need no None checks.
    """


def unwrap(text: str) -> str:
    """
    Collapse a wrapped, indented string literal into a single line.

    Args:
        text: The text to collapse.
    """
    return " ".join(text.split())


def log_error(logger: Callable[..., None], dep: DoExceptParams) -> None:
    """
    Log an error with its message, string representation and traceback.

    Does nothing when the supplied logger is `noop`, so that the default configuration
    performs no formatting work. Pass as a partial when using `handle_errors`::

        with AuthenticationError.handle_errors("Boom!", do_except=partial(log_error, log)):
            do_some_risky_stuff()

    Args:
        logger: A logging callable such as `logger.debug`.
        dep:    The parameters handed over by `handle_errors`.
    """
    if logger is noop:
        return

    trace = "\n".join(format_tb(dep.trace)) if dep.trace is not None else ""
    logger(f"{dep.final_message}\n\nError:\n______\n{dep.err}\n\nTraceback:\n----------\n{trace}")
