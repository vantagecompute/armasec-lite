"""
The FastAPI injectable that guards a route.

`TokenSecurity` is where a request actually meets this library. Everything else exists to
serve `TokenSecurity.__call__`, which FastAPI invokes through `Depends()` before the route
handler runs. It returns a `TokenPayload` on success and raises an `HTTPException` on
every failure, so a route handler that runs at all has already been authenticated and
authorized.

## Where it sits in the request path

`Armasec.lockdown()` builds and memoizes these; a route declares one as a dependency. On
the first request that reaches a given instance, `__call__` builds a `TokenManager` per
configured domain, each wrapping a `TokenDecoder` over a JWKS fetched by a shared
`OpenidConfigLoader`. From then on the instance holds those managers and does no network
work at all.

## The executor hop

That first load is synchronous network work, and it runs in an executor rather than on
the event loop. Upstream armasec calls synchronous `httpx.get` directly inside this
coroutine, which stalls every other request in the process for the duration, including
requests to routes that need no authentication whatsoever.

The hop happens only on that cold path. Once the managers are cached, the warm path is
pure in-memory work: unpack a header, verify a signature, compare some sets. Hopping to a
thread for that would add a scheduling round trip to every authenticated request and buy
nothing.

## What failure looks like

Each stage catches broadly and translates through `_http_exception`, which reads
`status_code` and `detail` off the error when it carries them. So an `AuthenticationError`
becomes 401, an `AuthorizationError` becomes 403, a `PayloadMappingError` becomes 500, and
a plugin's own `ArmasecError` subclass becomes whatever status it declares. Anything else
falls back to the stage's default. `WWW-Authenticate: Bearer` is set on all of them.

`debug_exceptions=True` re-raises the original error instead of translating it. It is a
development aid for seeing the real traceback, and it is developer supplied rather than
attacker reachable, but a production service running with it on leaks internal detail into
its responses.
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

    Subclasses FastAPI's `APIKeyBase` so the `Authorization` header shows up in the
    generated OpenAPI schema and the docs page grows an authorize button. That is the only
    reason for the base class; none of its behavior is used.

    Instances are effectively singletons per lockdown: `Armasec.lockdown()` memoizes on
    the scope set, so the manager cache below is shared by every request to every route
    declaring the same scopes.

    Attributes:
        domain_configs:   The OIDC domains a token may be authenticated against. A token
                          is accepted if any one of them can decode it.
        scopes:           Permissions the token must carry, or None to check none.
        permission_mode:  How `scopes` is matched. ALL requires every one, SOME requires
                          at least one.
        debug_logger:     A callable such as `logger.debug`. Defaults to `noop`, which
                          several call sites check for by identity to skip formatting
                          work entirely.
        debug_exceptions: If True, re-raise the original error rather than translating it
                          into an HTTPException. Testing and debugging only.
        skip_plugins:     If True, registered plugin checks are not evaluated for routes
                          guarded by this instance.
        model:            The FastAPI `APIKey` model that puts this scheme into the
                          OpenAPI document.
        scheme_name:      The name the scheme appears under in that document.
        managers:         The per-domain `ManagerConfig` list, empty until the first
                          request populates it. Its emptiness is the cold-path flag.
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
        Record the settings this instance will enforce. No network work happens here.

        Construction is deliberately inert: providers are contacted on the first request,
        not at import. An application that builds its `Armasec` at module scope therefore
        starts even when its OIDC provider is unreachable, and fails per request instead
        of failing to boot.

        Args:
            domain_configs:   Domain configurations to authenticate tokens against. A
                              token is accepted if any one of them decodes it.
            scopes:           Optional permission scopes that should be checked. When
                              empty or None, authentication is required but no permission
                              check is performed.
            permission_mode:  How the scopes are matched. ALL or SOME.
            debug_logger:     A callable such as `logger.debug`. Defaults to `noop`.
            debug_exceptions: If True, raise original exceptions instead of translating
                              them into HTTPExceptions. Testing and debugging only; it
                              leaks internal detail into responses.
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

        The error's own `status_code` and `detail` win when it has them, which is how an
        `ArmasecError` subclass, including one raised by a third party plugin, chooses the
        status a client sees. `default_status` covers everything else, so an unexpected
        error from deep in the stack still answers with the stage's intended status rather
        than leaking a 500.

        Args:
            err:            The error raised during validation.
            default_status: The status to use when the error carries none.

        Returns:
            The HTTPException to raise, always carrying `WWW-Authenticate: Bearer`.
        """
        return HTTPException(
            status_code=getattr(err, "status_code", default_status),
            detail=getattr(err, "detail", "Not authenticated"),
            headers={"WWW-Authenticate": "Bearer"},
        )

    async def __call__(self, request: Request) -> TokenPayload:
        """
        Validate a request, returning its token payload or raising an HTTPException.

        This is the method the whole library exists to serve. FastAPI's dependency
        injection calls it before the route handler runs, whenever this instance is
        declared with `Depends()` or `Security()`. If it returns, the request is
        authenticated, carries the required permissions, and has satisfied every
        registered plugin. If it raises, the handler never runs.

        Four stages, in order, each translating its failures to a different status:

        1. **Cold load**, only when `self.managers` is still empty. Fetches each domain's
           openid-configuration and JWKS and builds a `TokenManager` per domain. Failure
           is 401.
        2. **Decode.** Tries each manager in turn against the request's `Authorization`
           header and returns the first payload that decodes, then checks that domain's
           `match_keys`. Failure is 401 by default, but the real error's own status wins,
           so a `PayloadMappingError` from a bad `permission_extractor` surfaces as 500,
           which is correct: that is a server misconfiguration, not a bad request.
        3. **Scopes**, only when `self.scopes` is non-empty. Failure is 403.
        4. **Plugins**, unless `skip_plugins`. Every registered `armasec_plugin_check`
           implementation runs, and any exception denies the request. Failure defaults to
           403, but a plugin raising its own `ArmasecError` subclass chooses the status,
           so a plugin can answer 402 or anything else it likes.

        The cold load runs in an executor. It is synchronous network work, and running it
        inline would stall the event loop for the whole fetch, blocking every other
        request in the process including ones that need no authentication at all, which is
        what upstream armasec does by calling `httpx.get` directly inside this coroutine.

        The executor hop happens only on that cold path. The warm path below is pure
        in-memory work: read a header, verify a signature, compare some sets. Hopping to a
        thread for that would add a scheduling round trip to every authenticated request
        and buy nothing.

        The cold load is not itself the concurrency control. `OpenidConfigLoader` holds a
        `threading.Lock` and is shared process-wide, so N simultaneous first requests
        produce one fetch rather than N.

        Args:
            request: The FastAPI request to check for secure access. Only its headers are
                     read here; the whole object is passed on to plugin checks, which may
                     look at anything on it.

        Returns:
            The decoded, verified `TokenPayload`. FastAPI injects this into the route
            handler as the dependency's value, so a handler parameter annotated with it
            receives the caller's identity and permissions.

        Raises:
            HTTPException: Every failure, unless `debug_exceptions` is set. 401 when the
                token is absent, malformed, expired, or does not verify. 403 when it
                verifies but lacks the required scopes, fails a domain's `match_keys`, or
                is denied by a plugin. 500 when a configured `permission_extractor` does
                not match the token's shape. Whatever status a plugin's own error
                declares, otherwise. Every response carries
                `WWW-Authenticate: Bearer`.
            Exception: The original error, unwrapped, when `debug_exceptions` is True.
                Typically an `AuthenticationError`, `AuthorizationError` or
                `PayloadMappingError`. Testing and debugging only.
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

        Raises:
            AuthorizationError: The token is missing a required permission under ALL, or
                carries none of them under SOME, or `permission_mode` is a value neither
                branch recognizes. Maps to 403: the caller is authenticated, just not
                allowed.
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

        Idempotent, and cheap to call again: it returns immediately once anything is
        cached. A domain that fails to load is skipped rather than fatal, so one
        unreachable or misconfigured provider does not take down authentication against
        every other configured domain. Only "all of them failed" is an error.

        The skipped domain is not retried until the whole instance is reloaded, so a
        provider that was down at first-request time stays out of rotation for the life of
        the process. That is a known limitation, not an oversight.

        Raises:
            AuthenticationError: Every configured domain failed to load, so no token can
                be verified at all. Maps to 401, though the fault is nearly always
                configuration or provider availability rather than the request.
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

        Returns:
            A manager wired to a decoder over that domain's JWKS, with the loader's
            `refresh_jwks` attached so a provider key rotation can be recovered from
            without a restart.

        Raises:
            AuthenticationError: The provider's openid-configuration or JWKS could not be
                fetched or did not validate. The caller catches this per domain.
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

        How a value is matched depends on its type. A bool is compared by identity rather
        than equality, because `1 == True` in Python and a token carrying 1 where True is
        required should not pass. A str, int or float is compared by equality. Anything
        else is treated as a collection and matched if it intersects the token's value.

        Reads the claim with `getattr`, which works for arbitrary claims because
        `TokenPayload` sets `extra="allow"` and puts unknown members on the model itself.

        Args:
            token_payload: The decoded token.
            domain_config: The domain whose match_keys should be enforced.

        Raises:
            AuthorizationError: A configured key is absent from the token or does not
                match. Maps to 403: the token verified, it just is not for this caller.
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

        With one configured domain, which is the common case, "the last real failure" is
        simply the only failure, so the client sees the actual reason its token was
        rejected.

        Args:
            request: The request whose headers carry the token.

        Returns:
            The payload from the first manager that decoded the token and whose
            `match_keys` the payload satisfied.

        Raises:
            AuthenticationError: No manager could decode the token, and none of them
                raised anything more specific. Maps to 401.
            AuthorizationError: A manager decoded the token but its domain's `match_keys`
                were not satisfied. Maps to 403, and is not caught here: a token that
                verified against a domain but failed its match keys is a definite refusal,
                not a reason to try the next domain.
            Exception: The last error raised by any manager, re-raised unchanged so its
                own status and detail reach the client. Commonly an `AuthenticationError`
                subclass from `armasec_lite.jwt`, or a `PayloadMappingError` (500) when a
                `permission_extractor` did not match the token.
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
