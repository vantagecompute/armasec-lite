"""
The hook specification for armasec plugins.

The contract a plugin author writes against. There is exactly one hook,
`armasec_plugin_check`, and the function below is its specification: it defines the
signature and documents the semantics, and its body is empty because nothing here is ever
called. `armasec_lite.pluggable` dispatches to implementations, not to this.

### Writing an implementation

Define a function named `armasec_plugin_check` in your plugin's module, decorate it with
`armasec_lite.pluggable.hookimpl`, and advertise the module under the `armasec` entry point
group in your package metadata. It is then registered automatically at import.

```python
from armasec_lite.exceptions import AuthorizationError
from armasec_lite.pluggable import hookimpl


@hookimpl
def armasec_plugin_check(token_payload):
    if not getattr(token_payload, "email_verified", False):
        raise AuthorizationError("Email address is not verified")
```

Declare only the parameters you want. An implementation is called with just the keyword
arguments it names, so the example above never sees `request` or `debug_logger`. An
implementation declaring `**kwargs` receives all three. Adding a parameter to this
specification is therefore not a breaking change for existing plugins.

### Denying a request

Return to allow, raise to deny. There is no truthy return value; a hook that returns False
has allowed the request.

The raised error decides the response. An `ArmasecError` subclass supplies its own
`status_code` and `detail`, so a plugin can answer 402, 451, or anything else it likes.
Anything other than an `ArmasecError` becomes a 403. The first implementation to raise ends
the check; later ones do not run.

Implementations run on the authenticated request path, once per request, after the token
has been verified and after the route's own scope check. So `token_payload` is trustworthy
by the time a plugin sees it. Keep the work cheap and do no blocking I/O: this is a
synchronous call inside an async handler, and a slow plugin stalls the event loop for every
other request in the process.

A route locked down with `skip_plugins=True` bypasses every implementation, so a plugin
cannot assume it runs on every secured route.

### The constants

`HOOK_NAME` is the single hook name, "armasec_plugin_check". `PluginManager` looks a
plugin's attribute up by it, so the constant, this specification and the implementations
cannot disagree about what the hook is called.
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

    A specification, not an implementation. It is never called; its body is empty on
    purpose. Write a function with this name and a subset of these parameters, mark it with
    `armasec_lite.pluggable.hookimpl`, and armasec will call yours.

    Return to allow the request. To deny it, raise an `ArmasecError` or a subclass. The
    raised error's `status_code` and `detail` become the response, so a plugin can answer
    with 402 or any other code it likes; anything that is not an `ArmasecError` becomes a
    403. There is no meaningful return value, so returning False allows the request.

    An implementation receives only the arguments it declares, so a plugin that cares
    about nothing but the token can be written as
    `def armasec_plugin_check(token_payload): ...`. Declaring `**kwargs` receives all of
    them.

    Called synchronously inside an async handler, after the token has verified and the
    route's scopes have been checked, so the payload is trustworthy but the event loop is
    blocked for the duration. Do no blocking I/O here.

    Args:
        request:       The original request made to the secured endpoint. A starlette
                       `Request`, untyped here so this module imports nothing. Its body has
                       not been read and reading it in a plugin will consume it.
        token_payload: The contents of the auth token, an
                       `armasec_lite.token_payload.TokenPayload`. Claims armasec does not
                       declare are still reachable as attributes, so read a provider
                       specific one with `getattr(token_payload, name, default)`.
        debug_logger:  A callable such as `logger.debug`. Defaults to a no-op in the
                       application, so a plugin's messages may go nowhere; do not rely on
                       it for an audit trail.

    Raises:
        ArmasecError: An implementation raises this, or a subclass, to deny the request
            with a chosen status. `AuthorizationError` (403) is the usual one.
        Exception: Anything else an implementation raises also denies the request, and
            `TokenSecurity` turns it into a 403.
    """
