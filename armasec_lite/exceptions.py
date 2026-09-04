"""
Exception types, and the assertion helpers used in place of py-buzz.

Every error type in the library descends from `ArmasecError`, and each one carries the
`status_code` and `detail` that `TokenSecurity` turns into the client's response. So the
exception a call raises decides the HTTP status a caller sees, which is why the class
hierarchy here is worth reading rather than skimming:

- `ArmasecError` is 400, the base and the fallback.
- `AuthenticationError` is 401: the token is absent, malformed, expired, or does not
  verify. `armasec_lite.jwt` subclasses this eight more times to name the specific check
  that failed.
- `AuthorizationError` is 403: the token verified, but it lacks a required permission or
  fails a domain's `match_keys`.
- `PayloadMappingError` is 500: a configured `permission_extractor` did not match the
  decoded token's shape. That is a server misconfiguration rather than a bad request, and
  answering 401 would tell the caller to fix a token that is perfectly fine.

A third party plugin raising its own `ArmasecError` subclass gets the same treatment, so a
plugin can answer 402 or any other status by declaring it on the error it raises.

## The two py-buzz replacements

Only two py-buzz APIs are reimplemented here, because only two are used.
`require_condition` raises when an expression is falsey. `handle_errors` is a context
manager that wraps anything raised inside it into the calling error type, with the
original attached as `__cause__`.

`handle_errors` differs from py-buzz in one deliberate way: an error that is already an
`ArmasecError` passes straight through, unwrapped. py-buzz re-wraps unconditionally, which
would flatten a specific `ExpiredSignatureError` (401) raised deep in a call stack into
whatever generic type the outermost handler happened to name, and a `PayloadMappingError`
(500) into a 401. The specific status is the useful one, so the inner error wins.
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

    A plain dataclass rather than a pydantic model: it is constructed once per failure, in
    an error path, and has nothing to validate. `log_error` in `armasec_lite.utilities` is
    the callback this exists for.

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

    The two class attributes are the whole contract with `TokenSecurity`: it reads them off
    whatever error reaches it and builds the response from them. Subclassing this and
    setting them is how a plugin chooses the status its refusal produces.

    `detail` is what the client sees, so it should stay generic. The exception's message,
    which is often specific about which check failed and why, goes to the `debug_logger`
    and is not sent to the caller.

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

        A classmethod, so it raises whichever subclass it is called on, and therefore
        chooses the resulting status: `AuthorizationError.require_condition(...)` produces
        a 403 where `AuthenticationError.require_condition(...)` produces a 401.

        Truthiness, not identity: an empty set or an empty string fails the check. Several
        call sites rely on that, passing a set difference or an intersection directly.

        Args:
            expr:    The expression to check for truthiness.
            message: The message to raise when the check fails. Goes to the debug logger,
                     not to the client, so it can be specific.

        Raises:
            ArmasecError: The class this was called on, when `expr` is falsey. The status
                a client sees is that class's `status_code`.
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
        by an enclosing handler. This is the one deliberate difference from py-buzz, which
        re-wraps unconditionally: without it, an `ExpiredSignatureError` inside a block
        guarded by `PayloadMappingError.handle_errors` would reach the client as a 500,
        and a `PayloadMappingError` inside an `AuthenticationError` block as a 401.

        The wrapped error is attached as `__cause__`, so the original traceback survives
        for anything reading it.

        Args:
            message:   The message to prefix onto the original error text.
            do_except: Optional callback invoked with a `DoExceptParams` before raising.
                       `log_error` is the intended one, usually bound with
                       `partial(log_error, self.debug_logger)`.

        Yields:
            Nothing. The managed block runs and its exceptions are translated.

        Raises:
            ArmasecError: The class this was called on, wrapping any non-`ArmasecError`
                exception raised in the block. The message is
                `"<message> -- <ExceptionType>: <original text>"`.
            Exception: Re-raised unchanged when it is already an `ArmasecError`, including
                every subclass in `armasec_lite.jwt`. `BaseException` subclasses such as
                `KeyboardInterrupt` are never caught.
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

    The most common error in the library, and the base for the eight specific decode
    failures in `armasec_lite.jwt`. It also covers the failures that are really the
    provider's fault rather than the caller's, such as an unreachable JWKS endpoint: from
    the route's point of view the token could not be verified, so 401 is still the honest
    answer.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 401.
        detail:      The client-facing detail message. Set to "Not authenticated".
    """

    status_code: int = 401
    detail: str = "Not authenticated"


class AuthorizationError(ArmasecError):
    """
    Indicates that the provided claims don't match the claims required for an endpoint.

    The token verified: whoever sent it is who they say they are, they are just not
    allowed to do this. Raised by the scope check, by `match_keys`, and typically by a
    plugin that denies a request. Retrying with the same token will not help, which is
    what distinguishes it from a 401.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 403.
        detail:      The client-facing detail message. Set to "Not authorized".
    """

    status_code: int = 403
    detail: str = "Not authorized"


class PayloadMappingError(ArmasecError):
    """
    Indicates that the configured permission extractor did not match a path in the token.

    Deliberately a 500 and not a 401. The token was decoded and verified; what failed was
    the `permission_extractor` this application configured, which expected a claim shape
    the provider does not actually produce. Answering 401 would tell the caller to go fix
    a token that is perfectly valid, and would hide a server misconfiguration behind an
    authentication failure.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 500.
        detail:      The client-facing detail message. Set to "Server error".
    """

    status_code: int = 500
    detail: str = "Server error"
