"""
The factory that builds TokenSecurity instances for routes.
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

        Args:
            domain_configs:   Domain configurations to authenticate tokens against.
            debug_logger:     A callable such as `logger.debug`.
            debug_exceptions: If True, raise original exceptions. Testing and debugging
                              only.
            kwargs:           Arguments for a single DomainConfig, such as `domain` and
                              `audience`.
        """
        primary_domain_config = DomainConfig(**kwargs)
        if primary_domain_config.domain:
            self.domain_configs = [primary_domain_config]
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

        Args:
            scopes:          The scopes needed to access the endpoint.
            permission_mode: If ALL, every listed scope is required. If SOME, one is.
            skip_plugins:    If True, do not evaluate plugin validators.
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
        """
        return self.lockdown(*scopes, permission_mode=PermissionMode.ALL, skip_plugins=skip_plugins)

    def lockdown_some(self, *scopes: str, skip_plugins: bool = False) -> TokenSecurity:
        """
        Lock a route down, requiring at least one of the listed scopes.

        Args:
            scopes:       The scopes needed to access the endpoint. One is required.
            skip_plugins: If True, do not evaluate plugin validators.
        """
        return self.lockdown(
            *scopes, permission_mode=PermissionMode.SOME, skip_plugins=skip_plugins
        )
