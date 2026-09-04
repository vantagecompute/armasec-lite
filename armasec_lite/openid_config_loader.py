"""
Loads openid-configuration and JWKS documents from an OIDC provider.

Both documents are fetched lazily, on first access, and then held. `TokenSecurity` reaches
this module once per domain per process, on the first request that needs it, and after
that the request path touches nothing here except `refresh_jwks`.

Three things here are not in upstream armasec, and all three are invisible from the API.

### The loader cache is process-wide

Upstream builds one loader per `TokenSecurity`, so an app with ten distinct `lockdown()`
scope sets against one domain performs ten independent loads, or twenty HTTP requests.
Sharing by domain makes that two.

The cache is keyed on `(domain, use_https)` rather than on the domain alone. The two are
genuinely different providers as far as this library is concerned: they are fetched over
different schemes, and the https-only pin on `jwks_uri` is relaxed for one and not the
other, so collapsing them would let an http-configured domain seed the cache entry an
https-configured one then reads. `debug_logger` deliberately does not participate in the
key, so the first caller's logger is the one the shared loader keeps.

`clear_cache()` drops the whole mapping. A process-wide cache is a test-isolation hazard,
so the pytest extension calls it on entry to and exit from its mock provider.

### The cold fetch is guarded by a lock

Upstream has none, so N concurrent first requests all fetch simultaneously. The lock is a
`threading.Lock` and deliberately not an `asyncio.Lock`: an `asyncio.Lock` binds to the
loop that first awaits it and goes stale across test loops. Every path that takes this
lock, the cold load and the refresh alike, is driven from an executor thread by
`TokenSecurity`, so a worker holds it and the event loop thread is never blocked on it.
Both properties check inside the lock as well as outside it, so a thread that waited does
not repeat a fetch another thread already finished.

The lock is not reentrant, and `config` takes it. `jwks` and `refresh_jwks` therefore read
`self.config` before entering the lock rather than inside it. Moving either read in would
self-deadlock on the first request, so the ordering is load bearing and not stylistic.

### The JWKS is refetchable, within a rate limit

Upstream caches it for the process lifetime, so a provider key rotation returns 401 on
every request until someone restarts the service. `refresh_jwks` is wired into
`TokenDecoder.refresh_keys` and reached when a token presents a `kid` absent from the
cached set, which is exactly what a rotation looks like from here. `TokenSecurity` runs it
in an executor thread rather than on the event loop.

`JWKS_REFRESH_INTERVAL` is the minimum number of seconds between refetches for one domain.
It bounds refresh-to-refresh spacing, not the initial load; zero is the "never refreshed"
sentinel and always permits a refresh, so a rotation encountered shortly after startup
still recovers immediately.

The clock is stamped in a `finally`, so a failed refresh advances it just as a successful
one does. This is not tidiness, it closes a real hole. `kid` is read from the token's
unverified header, so an unauthenticated caller chooses it freely. If a failing provider
left the clock un-advanced, every token carrying an unknown `kid` would trigger another
outbound request, and anyone could turn one inbound request into one outbound request for
as long as they cared to keep sending them.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from armasec_lite import http
from armasec_lite.exceptions import AuthenticationError
from armasec_lite.schemas import JWKs, OpenidConfig
from armasec_lite.utilities import noop

#: Minimum seconds between JWKS refetches for one domain.
JWKS_REFRESH_INTERVAL = 300.0

#: Shared loaders, keyed by (domain, use_https), and the lock that guards the mapping.
_CACHE: dict[tuple[str, bool], OpenidConfigLoader] = {}
_CACHE_LOCK = threading.Lock()


def clear_cache() -> None:
    """
    Drop every shared loader.

    A process-wide cache leaks state between tests, so the pytest extension calls this
    around each test that stands up a mock provider: on entry, so a loader left over from
    an earlier test cannot answer from its own cache and never reach the mock, and on
    exit, so this test's loader cannot answer for the next one.

    Existing loader objects are not invalidated, only unreferenced by the cache. Anything
    still holding one, such as a `TokenSecurity` that has already built its managers, keeps
    using it. Clearing the cache is not a way to force a key refresh; that is what
    `refresh_jwks` is for.
    """
    with _CACHE_LOCK:
        _CACHE.clear()


class OpenidConfigLoader:
    """
    Lazily loads and caches the openid-configuration and JWKS for one OIDC domain.

    Construct these through `OpenidConfigLoader.get`, not by calling the class directly.
    `get` returns the process-wide shared instance for a domain, which is what turns 2N
    HTTP requests for N lockdown scope sets into 2. Constructing one directly is supported
    and is what the tests do, but it bypasses that sharing.

    Both documents are fetched on first access to `config` and `jwks` and then held for the
    life of the instance, except that `jwks` can be replaced by `refresh_jwks`.

    Attributes:
        domain:       The OIDC provider's domain, used to build the discovery URL.
        use_https:    Whether provider URLs use https. Also relaxes the https pin on the
                      published `jwks_uri` when False.
        debug_logger: A callable such as `logger.debug`, defaulting to `noop`.
    """

    def __init__(
        self,
        domain: str,
        use_https: bool = True,
        debug_logger: Callable[..., None] | None = None,
    ):
        """
        Set up a loader for one domain. Nothing is fetched until a property is read.

        Prefer `OpenidConfigLoader.get`, which returns the shared instance for a domain
        rather than a private one that will perform its own duplicate fetches.

        Args:
            domain:       The domain of the OIDC provider, used to build the discovery URL.
            use_https:    If falsey, use http instead of https.
            debug_logger: A callable such as `logger.debug`, or None for no logging.
        """
        self.domain = domain
        self.use_https = use_https
        self.debug_logger = debug_logger if debug_logger else noop

        self._config: OpenidConfig | None = None
        self._jwks: JWKs | None = None
        # Monotonic timestamp of the last REFRESH, not of the initial load. Zero is the
        # "never refreshed" sentinel and is treated as always allowed, so a rotation
        # encountered shortly after startup still recovers. The interval governs
        # refresh-to-refresh spacing, which is what stops unknown key ids becoming a
        # request flood.
        self._last_refresh_at = 0.0
        # A threading.Lock rather than an asyncio.Lock on purpose: an asyncio.Lock binds
        # to the loop that first awaits it and goes stale across test loops. Both the cold
        # load and the refresh run in an executor thread, so a worker holds this and the
        # event loop thread is never blocked on it.
        #
        # It is NOT reentrant, and `config` takes it. `jwks` and `refresh_jwks` must
        # therefore read `self.config` before entering the lock, never inside it.
        self._lock = threading.Lock()

    @classmethod
    def get(
        cls,
        domain: str,
        use_https: bool = True,
        debug_logger: Callable[..., None] | None = None,
    ) -> OpenidConfigLoader:
        """
        Return the shared loader for a domain, creating it on first use.

        The cache is keyed on `(domain, use_https)` and lives for the process. Two callers
        asking for the same pair get the same object, and therefore share one fetch of the
        openid-configuration and one of the JWKS.

        Args:
            domain:       The domain of the OIDC provider.
            use_https:    If falsey, use http instead of https. Part of the cache key, so
                          an http-configured domain and an https-configured one do not
                          share an entry.
            debug_logger: Applied only when the loader is created. A later caller passing
                          a different logger gets the existing loader with the original
                          logger still attached, since the loader is shared rather than
                          reconfigured.

        Returns:
            The shared loader. Nothing has been fetched yet; that happens on first access
            to `config` or `jwks`.
        """
        key = (domain, bool(use_https))
        with _CACHE_LOCK:
            loader = _CACHE.get(key)
            if loader is None:
                loader = cls(domain, use_https=use_https, debug_logger=debug_logger)
                _CACHE[key] = loader
            return loader

    @staticmethod
    def build_openid_config_url(domain: str, use_https: bool = True) -> str:
        """
        Build the discovery URL for a domain.

        Args:
            domain:    The domain of the OIDC provider.
            use_https: Use https by default. If falsey, use http.

        Returns:
            The RFC 8414 discovery URL, `<scheme>://<domain>/.well-known/openid-configuration`.
            The domain is interpolated as given and is not escaped or validated here;
            `DomainConfig` rejects an empty one at configuration time.
        """
        protocol = "https" if use_https else "http"
        return f"{protocol}://{domain}/.well-known/openid-configuration"

    def _load_openid_resource(self, url: str) -> dict[str, Any]:
        """
        Fetch and decode one openid resource, logging the attempt.

        The `http` module is referenced through the module object rather than by importing
        `get_json` directly, so that the lookup happens at call time. The pytest extension
        mocks a provider by patching `armasec_lite.http.get_json`, which a name bound at
        import time would silently defeat.

        Args:
            url: The URL to fetch.

        Returns:
            The decoded JSON object.

        Raises:
            AuthenticationError: The fetch failed, returned a non-200, exceeded
                `http.MAX_BODY_BYTES`, used a scheme other than http or https, or did not
                return a JSON object. See `armasec_lite.http.get_json`.
        """
        self.debug_logger(f"Attempting to fetch from openid resource '{url}'")
        return http.get_json(url)

    @property
    def config(self) -> OpenidConfig:
        """
        The provider's openid-configuration, fetched on first access.

        Held for the life of the loader once fetched. Unlike the JWKS there is no refresh
        path: an issuer or a `jwks_uri` changing is a provider migration, not a routine
        rotation, and it warrants a restart.

        Returns:
            The validated configuration, with `issuer` preserved exactly as published.

        Raises:
            AuthenticationError: The discovery document could not be fetched, or did not
                validate as an `OpenidConfig`. The most common validation failure is a
                `jwks_uri` published over http by a domain configured with
                `use_https=True`, which fails closed on purpose. Maps to 401.
        """
        if self._config is None:
            with self._lock:
                # Re-check inside the lock: another thread may have loaded it while this
                # one waited, and a second fetch would be pure waste.
                if self._config is None:
                    self.debug_logger("Fetching openid configuration")
                    with AuthenticationError.handle_errors(
                        f"Failed to load openid configuration for domain '{self.domain}'"
                    ):
                        data = self._load_openid_resource(
                            self.build_openid_config_url(self.domain, self.use_https)
                        )
                        # A `use_https=False` domain may legitimately publish an http
                        # jwks_uri; a normal one may not. The model fails closed when the
                        # context is absent, so this must be passed explicitly.
                        self._config = OpenidConfig.model_validate(
                            data,
                            context={"require_https": self.use_https},
                        )
        return self._config

    @property
    def jwks(self) -> JWKs:
        """
        The provider's JWKS, fetched on first access.

        Reads `config` first, outside the lock, since the JWKS URL comes from it and the
        lock is not reentrant.

        Returns:
            The validated key set. `refresh_jwks` may replace it later.

        Raises:
            AuthenticationError: The configuration could not be loaded, the JWKS could not
                be fetched, or the response did not validate as a `JWKs`. Maps to 401.
        """
        if self._jwks is None:
            # Read before taking the lock, never inside it: `config` takes the same
            # non-reentrant lock, so moving this line down self-deadlocks.
            config = self.config
            with self._lock:
                if self._jwks is None:
                    self.debug_logger("Fetching jwks")
                    with AuthenticationError.handle_errors(
                        f"Failed to load jwks for domain '{self.domain}'"
                    ):
                        data = self._load_openid_resource(str(config.jwks_uri))
                        self._jwks = JWKs.model_validate(data)
        return self._jwks

    def refresh_jwks(self) -> JWKs:
        """
        Refetch the JWKS, at most once per `JWKS_REFRESH_INTERVAL`.

        Wired into `TokenDecoder.refresh_keys` and reached when a token presents a key id
        absent from the cached set, which is what a provider key rotation looks like from
        here. `TokenSecurity` drives it from an executor thread, because it is blocking
        network work and `kid` is attacker chosen. A rate limited call returns the current
        JWKS unchanged rather than raising, so the caller simply fails to find the key and
        the request is refused as an ordinary 401.

        The rate limit is a security control, not a politeness measure. `kid` is read from
        the token's unverified header, so an unauthenticated caller picks it. The clock is
        therefore stamped in a `finally`, advancing even when the fetch fails: without
        that, a provider returning errors would leave the clock un-advanced and every
        unknown-kid token would trigger another outbound request, which is exactly the
        amplification this limit exists to stop.

        Returns:
            The refreshed JWKS, or the current one when the refresh was rate limited.

        Raises:
            AuthenticationError: The refresh was attempted and the fetch or validation
                failed. The clock is still stamped, so the next unknown `kid` within
                `JWKS_REFRESH_INTERVAL` will not retry. Maps to 401.
        """
        # Read before taking the lock, never inside it: `config` takes the same
        # non-reentrant lock, so moving this line down self-deadlocks the first request.
        config = self.config
        with self._lock:
            elapsed = time.monotonic() - self._last_refresh_at
            rate_limited = self._last_refresh_at > 0.0 and elapsed < JWKS_REFRESH_INTERVAL
            if self._jwks is not None and rate_limited:
                self.debug_logger(
                    f"Skipping jwks refresh: last refresh was {elapsed:.1f}s ago, "
                    f"minimum interval is {JWKS_REFRESH_INTERVAL}s"
                )
                return self._jwks

            self.debug_logger("Refreshing jwks")
            try:
                with AuthenticationError.handle_errors(
                    f"Failed to refresh jwks for domain '{self.domain}'"
                ):
                    data = self._load_openid_resource(str(config.jwks_uri))
                    refreshed = JWKs.model_validate(data)
                    self._jwks = refreshed
                    return refreshed
            finally:
                # Stamped even when the fetch fails. Otherwise a provider returning errors
                # leaves the clock un-advanced and every unknown-kid token triggers another
                # outbound request, which is the flood this limit exists to stop. `kid`
                # comes from the unverified header, so an unauthenticated caller drives it.
                self._last_refresh_at = time.monotonic()
