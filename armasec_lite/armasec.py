"""
The factory that builds TokenSecurity instances for routes.

The entry point most consumers touch. An application builds one `Armasec` at module scope
and calls `lockdown()` on it in each route's `Depends()`, rather than constructing a
`TokenSecurity` per route and threading domain configuration and debug settings through
every declaration.

Using it is not essential. `TokenSecurity` works perfectly well on its own; this only
removes boilerplate.

## Memoization, and why it is not `lru_cache`

`lockdown()` caches on `(scopes, permission_mode, skip_plugins)` in a per-instance dict, so
ten routes requiring the same scopes share one `TokenSecurity` and therefore one set of
loaded managers. That is what keeps the provider fetch count at two per domain per process
instead of two per distinct lockdown.

The cache is a plain dict on the instance rather than `lru_cache` on the method, because
`lru_cache` keys on `self` in a process-global cache and would pin every `Armasec` ever
constructed for the life of the process. For the usual module-level singleton the behavior
is identical; for an application that builds them per test or per tenant it is not.

Note that the scopes tuple is used as given, so `lockdown("a", "b")` and `lockdown("b",
"a")` are different keys and produce two equivalent instances. Harmless, just slightly
wasteful.

## Construction is inert

Nothing here contacts a provider. `DomainConfig` validation happens at construction, so a
missing or empty domain is caught immediately, but the first network call waits for the
first request. An application therefore starts even when its OIDC provider is unreachable.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, status

from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_security import TokenSecurity
from armasec_lite.utilities import noop


class Armasec:
    """
    A factory for TokenSecurity instances.

    Using it is not essential to securing routes, but it removes the boilerplate of
    threading domain configuration and debug settings through every route declaration.

    Normally built once at module scope and shared by the whole application, so that every
    route locked down with the same scopes shares one `TokenSecurity` and one set of loaded
    provider keys.

    Attributes:
        domain_configs:   The OIDC domains every `TokenSecurity` built here will
                          authenticate against.
        debug_logger:     A callable such as `logger.debug`, passed to each instance.
        debug_exceptions: Passed to each instance. If True, they raise original exceptions
                          rather than translating them into HTTPExceptions. Testing and
                          debugging only.
    """

    def __init__(
        self,
        domain_configs: list[DomainConfig] | None = None,
        debug_logger: Callable[[str], None] | None = noop,
        debug_exceptions: bool = False,
        **kwargs: Any,
    ):
        """
        Store the settings every TokenSecurity built here will receive.

        Two mutually exclusive ways to configure a domain, kept for compatibility with
        upstream armasec. Pass `domain_configs` for one or more domains, or pass the
        `DomainConfig` fields directly as keyword arguments for the single-domain case.
        The keyword form wins when both are given.

        Args:
            domain_configs:   Domain configurations to authenticate tokens against.
            debug_logger:     A callable such as `logger.debug`.
            debug_exceptions: If True, raise original exceptions. Testing and debugging
                              only.
            kwargs:           Arguments for a single DomainConfig, such as `domain` and
                              `audience`. Only consulted when `domain` is among them and
                              is truthy.

        Raises:
            HTTPException: 422, when neither a truthy `domain` keyword nor
                `domain_configs` was supplied. Raised at construction, so an application
                misconfigured this way fails to start rather than failing per request.
                The presence of a domain is tested before a `DomainConfig` is built,
                deliberately: `DomainConfig` rejects an empty domain with a
                `ValidationError`, and this factory owes its caller the 422 instead.
            ValidationError: The keyword arguments are not a valid `DomainConfig`, for
                example an `algorithm` this library does not support.
        """
        # Tested before constructing, not after. `DomainConfig` now rejects an empty
        # domain outright, so building one from kwargs that carry no domain would raise a
        # ValidationError where this factory owes the caller its own 422.
        if kwargs.get("domain"):
            self.domain_configs = [DomainConfig(**kwargs)]
        elif domain_configs is not None:
            self.domain_configs = domain_configs
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="No domain was input.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        self.debug_logger = debug_logger
        self.debug_exceptions = debug_exceptions

        # A per-instance cache rather than lru_cache on the method. lru_cache keys on
        # `self` in a process-global cache, which pins every Armasec instance for the life
        # of the process. For the usual module-level singleton the behavior is identical.
        self._lockdowns: dict[tuple[tuple[str, ...], PermissionMode, bool], TokenSecurity] = {}

    def lockdown(
        self,
        *scopes: str,
        permission_mode: PermissionMode = PermissionMode.ALL,
        skip_plugins: bool = False,
    ) -> TokenSecurity:
        """
        Build a TokenSecurity to lock down a route, memoized on its arguments.

        The result goes in a route's `Depends()`. Calling it does no work beyond a dict
        lookup: the returned instance contacts the provider on the first request that
        reaches it, not here.

        Memoized so that every route asking for the same scopes shares one instance and
        therefore one set of loaded provider keys. The scopes tuple is the key as given, so
        the same scopes in a different order produce a second, equivalent instance.

        Called with no scopes, it requires a valid token and checks no permissions.

        Args:
            scopes:          The scopes needed to access the endpoint.
            permission_mode: If ALL, every listed scope is required. If SOME, one is.
            skip_plugins:    If True, do not evaluate plugin validators.

        Returns:
            The injectable. Declare it with `Depends()` and the route handler receives a
            `TokenPayload`.
        """
        key = (scopes, permission_mode, skip_plugins)
        security = self._lockdowns.get(key)
        if security is None:
            security = TokenSecurity(
                domain_configs=self.domain_configs,
                scopes=scopes,
                permission_mode=permission_mode,
                debug_logger=self.debug_logger,
                debug_exceptions=self.debug_exceptions,
                skip_plugins=skip_plugins,
            )
            self._lockdowns[key] = security
        return security

    def lockdown_all(self, *scopes: str, skip_plugins: bool = False) -> TokenSecurity:
        """
        Lock a route down, requiring every listed scope.

        A wrapper around `lockdown()` with the default permission mode, included for
        symmetry with `lockdown_some`.

        Args:
            scopes:       The scopes needed to access the endpoint. All are required.
            skip_plugins: If True, do not evaluate plugin validators.

        Returns:
            The injectable, memoized exactly as `lockdown()` memoizes it.
        """
        return self.lockdown(*scopes, permission_mode=PermissionMode.ALL, skip_plugins=skip_plugins)

    def lockdown_some(self, *scopes: str, skip_plugins: bool = False) -> TokenSecurity:
        """
        Lock a route down, requiring at least one of the listed scopes.

        A wrapper around `lockdown()` with `PermissionMode.SOME`.

        Args:
            scopes:       The scopes needed to access the endpoint. One is required.
            skip_plugins: If True, do not evaluate plugin validators.

        Returns:
            The injectable, memoized separately from the ALL-mode instance for the same
            scopes.
        """
        return self.lockdown(
            *scopes, permission_mode=PermissionMode.SOME, skip_plugins=skip_plugins
        )
