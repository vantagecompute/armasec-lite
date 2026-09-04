"""
The hook specification for armasec plugins.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

#: The one hook name armasec dispatches. Kept as a constant so the manager and the
#: documentation cannot disagree about it.
HOOK_NAME = "armasec_plugin_check"


def armasec_plugin_check(
    request: Any,
    token_payload: Any,
    debug_logger: Callable[..., None],
) -> None:
    """
    Check a token payload for validity against a request.

    If the check fails, raise an ArmasecError or a subclass of it. The raised error's
    `status_code` and `detail` become the response, so a plugin can answer with 402 or
    any other code it likes.

    An implementation receives only the arguments it declares, so a plugin that cares
    about nothing but the token can be written as
    `def armasec_plugin_check(token_payload): ...`.

    Args:
        request:       The original request made to the secured endpoint.
        token_payload: The contents of the auth token.
        debug_logger:  A callable such as `logger.debug`.
    """
