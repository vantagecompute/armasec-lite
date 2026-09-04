"""
Loads openid-configuration and JWKS documents from an OIDC provider.

Three things here are not in upstream armasec, and all three are invisible from the API.

The loader cache is process-wide. Upstream builds one loader per `TokenSecurity`, so an
app with ten distinct `lockdown()` scope sets against one domain performs ten independent
loads, or twenty HTTP requests. Sharing by domain makes that two.

The cold fetch is guarded by a lock. Upstream has none, so N concurrent first requests all
fetch simultaneously.

The JWKS is refetchable. Upstream caches it for the process lifetime, so a provider key
rotation returns 401 on every request until someone restarts the service. Refetching is
rate limited so that a flood of tokens carrying unknown key ids cannot be turned into a
flood of outbound requests.
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
    around each test that stands up a mock provider.
    """
    with _CACHE_LOCK:
        _CACHE.clear()


class OpenidConfigLoader:
    """
    Lazily loads and caches the openid-configuration and JWKS for one OIDC domain.
    """

    def __init__(
        self,
        domain: str,
        use_https: bool = True,
        debug_logger: Callable[..., None] | None = None,
    ):
        """
        Initialize a loader for one domain.

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
        # to the loop that first awaits it and goes stale across test loops. The cold load
        # already runs in an executor thread, so the worker holds this and the event loop
        # thread is never blocked on it.
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

        Args:
            domain:       The domain of the OIDC provider.
            use_https:    If falsey, use http instead of https.
            debug_logger: Applied only when the loader is created.
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
        """
        self.debug_logger(f"Attempting to fetch from openid resource '{url}'")
        return http.get_json(url)

    @property
    def config(self) -> OpenidConfig:
        """
        The provider's openid-configuration, fetched on first access.
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
        """
        if self._jwks is None:
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

        Called when a token presents a key id absent from the cached set, which is what a
        provider key rotation looks like from here. Returns the current JWKS either way,
        so a rate limited call is a no-op rather than an error.
        """
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
