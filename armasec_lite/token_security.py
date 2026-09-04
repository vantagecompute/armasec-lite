"""
The FastAPI injectable that enforces authentication and authorization on a route.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from fastapi import HTTPException, status
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.api_key import APIKeyBase
from starlette.requests import Request

from armasec_lite.exceptions import AuthenticationError, AuthorizationError
from armasec_lite.openid_config_loader import OpenidConfigLoader
from armasec_lite.pluggable import plugin_manager
from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_decoder import TokenDecoder
from armasec_lite.token_manager import TokenManager
from armasec_lite.token_payload import TokenPayload
from armasec_lite.utilities import noop, unwrap


@dataclass
class ManagerConfig:
    """
    A TokenManager paired with the domain configuration it was built from.

    This stays a plain dataclass rather than a pydantic model: it is an internal pairing
    of two already-constructed objects, not a document that needs validating.

    Attributes:
        manager:       The TokenManager used to decode tokens for this domain.
        domain_config: The configuration for the openid server.
    """

    manager: TokenManager
    domain_config: DomainConfig


class TokenSecurity(APIKeyBase):
    """
    An injectable Security class that returns a TokenPayload when used with Depends().
    """

    def __init__(
        self,
        domain_configs: list[DomainConfig],
        scopes: Iterable[str] | None = None,
        permission_mode: PermissionMode = PermissionMode.ALL,
        debug_logger: Callable[..., None] | None = None,
        debug_exceptions: bool = False,
        skip_plugins: bool = False,
    ):
        """
        Initialize the TokenSecurity instance.

        Args:
            domain_configs:   Domain configurations to authenticate tokens against.
            scopes:           Optional permission scopes that should be checked.
            permission_mode:  How the scopes are matched. ALL or SOME.
            debug_logger:     A callable such as `logger.debug`.
            debug_exceptions: If True, raise original exceptions instead of translating
                              them into HTTPExceptions. Testing and debugging only.
            skip_plugins:     If True, do not evaluate plugin validators.
        """
        self.domain_configs = domain_configs
        self.scopes = scopes
        self.permission_mode = permission_mode

        self.debug_logger = debug_logger if debug_logger else noop
        self.debug_exceptions = debug_exceptions
        self.skip_plugins = skip_plugins

        self.model: APIKey = APIKey(
            **{"in": APIKeyIn.header},  # type: ignore[arg-type]
            name=TokenManager.header_key,
            description=self.__class__.__doc__,
        )
        self.scheme_name = self.__class__.__name__

        # Lazily populated on the first request that reaches this instance.
        self.managers: list[ManagerConfig] = []

    def _http_exception(self, err: Exception, default_status: int) -> HTTPException:
        """
        Translate an internal error into the response a client should see.

        Args:
            err:            The error raised during validation.
            default_status: The status to use when the error carries none.
        """
        return HTTPException(
            status_code=getattr(err, "status_code", default_status),
            detail=getattr(err, "detail", "Not authenticated"),
            headers={"WWW-Authenticate": "Bearer"},
        )

    async def __call__(self, request: Request) -> TokenPayload:
        """
        Validate a request, returning its token payload or raising an HTTPException.

        Called by FastAPI's dependency injection when this instance is injected with
        Depends(). The first call for a given domain loads the provider's configuration
        and keys. That load is synchronous network work, so it runs in an executor rather
        than on the event loop. Upstream armasec calls synchronous `httpx.get` directly
        inside this coroutine, which stalls every other request in the process, including
        ones that need no authentication at all.

        The executor hop happens only on that cold path. Once the managers are cached,
        everything below is pure in-memory work, so hopping again would add a scheduling
        round trip to every request for nothing.

        Args:
            request: The FastAPI request to check for secure access.
        """
        if not self.managers:
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(None, self._load_all_managers)
            except Exception as err:
                if self.debug_exceptions:
                    raise
                raise self._http_exception(err, status.HTTP_401_UNAUTHORIZED) from err

        try:
            token_payload = self._extract_token_payload_from_manager(request)
        except Exception as err:
            if self.debug_exceptions:
                raise
            raise self._http_exception(err, status.HTTP_401_UNAUTHORIZED) from err

        if self.scopes:
            try:
                self._check_scopes(token_payload)
            except Exception as err:
                if self.debug_exceptions:
                    raise
                raise self._http_exception(err, status.HTTP_403_FORBIDDEN) from err

        if not self.skip_plugins:
            self.debug_logger("Applying plugin checks")
            try:
                plugin_manager.hook.armasec_plugin_check(
                    request=request,
                    token_payload=token_payload,
                    debug_logger=self.debug_logger,
                )
            except Exception as err:
                if self.debug_exceptions:
                    raise
                raise self._http_exception(err, status.HTTP_403_FORBIDDEN) from err

        return token_payload

    def _check_scopes(self, token_payload: TokenPayload) -> None:
        """
        Compare the route's scopes against the token's permissions.

        Args:
            token_payload: The decoded token.
        """
        token_permissions = set(token_payload.permissions)
        my_permissions = set(self.scopes or ())

        self.debug_logger(
            unwrap(
                f"""
                Checking my permissions {my_permissions} against token_permissions
                {token_permissions} using PermissionMode {self.permission_mode}
                """
            )
        )

        if self.permission_mode == PermissionMode.ALL:
            AuthorizationError.require_condition(
                my_permissions - token_permissions == set(),
                unwrap(
                    f"""
                    Token permissions {token_permissions} missing some required permissions
                    {my_permissions - token_permissions}
                    """
                ),
            )
        elif self.permission_mode == PermissionMode.SOME:
            AuthorizationError.require_condition(
                token_permissions & my_permissions,
                unwrap(
                    f"""
                    Token permissions {token_permissions} missing at least
                    one required permissions {my_permissions}
                    """
                ),
            )
        else:
            raise AuthorizationError(f"Unknown permission_mode: {self.permission_mode}")

    def _load_all_managers(self) -> None:
        """
        Build a TokenManager for each configured domain, skipping ones that fail.
        """
        if self.managers:
            return

        for domain_config in self.domain_configs:
            try:
                self.managers.append(
                    ManagerConfig(
                        manager=self._load_manager(domain_config),
                        domain_config=domain_config,
                    )
                )
            except AuthenticationError:
                self.debug_logger(f"Failed to match JWK against domain {domain_config.domain}")
            # Deliberately broad: one unreachable or misconfigured provider must not take
            # down authentication against every other configured domain. The condition
            # below turns "all of them failed" into an error.
            except Exception as err:  # noqa: BLE001
                self.debug_logger(f"Exception caught: {err.__class__.__name__}")

        AuthenticationError.require_condition(
            len(self.managers) > 0,
            "Not authenticated: couldn't load any TokenManager instance",
        )

    def _load_manager(self, domain_config: DomainConfig) -> TokenManager:
        """
        Build one TokenManager from a shared, cached loader.

        Args:
            domain_config: The domain to build a manager for.
        """
        self.debug_logger(f"Lazy loading TokenManager for domain {domain_config.domain}")
        # The shared loader is what turns 2N HTTP calls for N lockdown scope sets into 2.
        loader = OpenidConfigLoader.get(
            domain_config.domain,
            use_https=domain_config.use_https,
            debug_logger=self.debug_logger,
        )
        decoder = TokenDecoder(
            loader.jwks,
            domain_config.algorithm,
            debug_logger=self.debug_logger,
            permission_extractor=domain_config.permission_extractor,
            jwks_refresher=loader.refresh_jwks,
        )
        return TokenManager(
            loader.config,
            decoder,
            audience=domain_config.audience,
            ignore_audience=domain_config.ignore_audience,
            verify_issuer=domain_config.verify_issuer,
            debug_logger=self.debug_logger,
        )

    def _check_match_keys(self, token_payload: TokenPayload, domain_config: DomainConfig) -> None:
        """
        Require the configured key/value pairs to be present in the token.

        Args:
            token_payload: The decoded token.
            domain_config: The domain whose match_keys should be enforced.
        """
        message = "Not authorized: token doesn't contain necessary key-value pairs"
        for key_to_match, value_to_match in domain_config.match_keys.items():
            actual = getattr(token_payload, key_to_match, None)
            if isinstance(value_to_match, bool):
                # Identity, not equality: `1 == True` in Python, and a token carrying 1
                # where True is required should not pass.
                AuthorizationError.require_condition(actual is value_to_match, message)
            elif isinstance(value_to_match, (str, int, float)):
                AuthorizationError.require_condition(actual == value_to_match, message)
            else:
                AuthorizationError.require_condition(
                    bool(set(actual or ()) & set(value_to_match)), message
                )

    def _extract_token_payload_from_manager(self, request: Request) -> TokenPayload:
        """
        Try each loaded manager until one decodes the request's token.

        The real decode error is preserved and re-raised. Upstream armasec swallows every
        manager's exception and then asserts the payload is not None, which surfaces to the
        caller as a bare AttributeError and says nothing about what actually went wrong.

        Args:
            request: The request whose headers carry the token.
        """
        self._load_all_managers()

        last_error: Exception | None = None
        for manager_config in self.managers:
            try:
                token_payload = manager_config.manager.extract_token_payload(request.headers)
            # Deliberately broad: a token that this manager cannot decode may still be
            # valid for the next configured domain. The error is kept, not discarded, so
            # that the last real failure is what the caller sees.
            except Exception as err:  # noqa: BLE001
                self.debug_logger(f"Exception caught: {err.__class__.__name__}")
                last_error = err
                continue

            self._check_match_keys(token_payload, manager_config.domain_config)
            return token_payload

        if last_error is not None:
            raise last_error
        raise AuthenticationError(
            "Not authenticated: could not find matching JWK with any input domain"
            " or token is malformed"
        )
