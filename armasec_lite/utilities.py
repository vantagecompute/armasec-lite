"""
Small helpers shared across armasec, replacing the `snick` dependency.

Three functions, none of them interesting on their own, but two carry a convention the rest
of the library relies on.

`noop` is the default `debug_logger` everywhere, which is why no call site in this codebase
guards a log call with `if self.debug_logger is not None`. It is a single shared function
object, not a fresh lambda per instance, so identity comparison against it is meaningful,
and `log_error` uses exactly that to skip formatting a traceback nobody will read. Anything
substituting a different do-nothing callable loses that optimization without changing
behavior.

`unwrap` collapses a wrapped, indented string literal onto one line. It exists so error and
debug messages can be written as indented triple-quoted strings that read well in the
source without the indentation leaking into the output. This is the one piece of `snick`
armasec used.
"""

from __future__ import annotations

from collections.abc import Callable
from traceback import format_tb
from typing import Any

from armasec_lite.exceptions import DoExceptParams


def noop(*args: Any, **kwargs: Any) -> None:
    """
    Do nothing. Used as the default `debug_logger` so callers need no None checks.

    Accepts and discards anything. Its identity matters: `log_error` compares against this
    exact function to skip formatting work, so substituting another do-nothing callable
    still works but costs a traceback format on every handled error.

    Args:
        args:   Ignored.
        kwargs: Ignored.
    """


def unwrap(text: str) -> str:
    """
    Collapse a wrapped, indented string literal into a single line.

    Lets a message be written as an indented triple-quoted string that reads well in the
    source without the indentation reaching the output.

    Args:
        text: The text to collapse.

    Returns:
        The text with every run of whitespace, newlines included, replaced by one space,
        and no leading or trailing whitespace. Deliberately crude: it splits on whitespace
        and rejoins, so intentional runs of spaces do not survive.
    """
    return " ".join(text.split())


def log_error(logger: Callable[..., None], dep: DoExceptParams) -> None:
    """
    Log an error with its message, string representation and traceback.

    Does nothing when the supplied logger is `noop`, so that the default configuration
    performs no formatting work. Pass as a partial when using `handle_errors`::

        with AuthenticationError.handle_errors("Boom!", do_except=partial(log_error, log)):
            do_some_risky_stuff()

    Everything it writes is internal detail: the composed message, the original exception
    and its traceback. None of it reaches the client, which sees only the error's `detail`.
    Point it at a logger whose output is not served to callers.

    Args:
        logger: A logging callable such as `logger.debug`. When it is `noop`, by identity,
                this returns immediately and formats nothing.
        dep:    The parameters handed over by `handle_errors`.
    """
    if logger is noop:
        return

    trace = "\n".join(format_tb(dep.trace)) if dep.trace is not None else ""
    logger(f"{dep.final_message}\n\nError:\n______\n{dep.err}\n\nTraceback:\n----------\n{trace}")
