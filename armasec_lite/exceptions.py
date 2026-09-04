"""
Exception types and the small assertion helpers armasec uses in place of py-buzz.

Only two py-buzz APIs are reimplemented here, because only two are used:
`require_condition` and `handle_errors`.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from types import TracebackType


@dataclass
class DoExceptParams:
    """
    The values handed to a `do_except` callback by `handle_errors`.

    Attributes:
        final_message: The composed message, including the original error text.
        err:           The original exception.
        trace:         The original traceback, suitable for `traceback.format_tb`.
    """

    final_message: str
    err: Exception
    trace: TracebackType | None


class ArmasecError(Exception):
    """
    Base error for armasec, used for checking conditions and wrapping other exceptions.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 400.
        detail:      The client-facing detail message. Set to "Bad request".
    """

    status_code: int = 400
    detail: str = "Bad request"

    @classmethod
    def require_condition(cls, expr: object, message: str) -> None:
        """
        Raise this error type with the supplied message when `expr` is falsey.

        Args:
            expr:    The expression to check for truthiness.
            message: The message to raise when the check fails.
        """
        if not expr:
            raise cls(message)

    @classmethod
    @contextmanager
    def handle_errors(
        cls,
        message: str,
        do_except: Callable[[DoExceptParams], None] | None = None,
    ) -> Iterator[None]:
        """
        Wrap any exception raised in the managed block into this error type.

        Errors that are already an `ArmasecError` pass through untouched, so a specific
        error type raised deep in a call stack is not flattened into a less specific one
        by an enclosing handler.

        Args:
            message:   The message to prefix onto the original error text.
            do_except: Optional callback invoked with a `DoExceptParams` before raising.
        """
        try:
            yield
        except ArmasecError:
            raise
        except Exception as err:
            final_message = f"{message} -- {type(err).__name__}: {err}"
            if do_except is not None:
                do_except(
                    DoExceptParams(
                        final_message=final_message,
                        err=err,
                        trace=sys.exc_info()[2],
                    )
                )
            raise cls(final_message) from err


class AuthenticationError(ArmasecError):
    """
    Indicates a failure to authenticate and decode a jwt.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 401.
    """

    status_code: int = 401
    detail: str = "Not authenticated"


class AuthorizationError(ArmasecError):
    """
    Indicates that the provided claims don't match the claims required for an endpoint.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 403.
    """

    status_code: int = 403
    detail: str = "Not authorized"


class PayloadMappingError(ArmasecError):
    """
    Indicates that the configured permission extractor did not match a path in the token.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 500.
    """

    status_code: int = 500
    detail: str = "Server error"
