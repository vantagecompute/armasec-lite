---
title: Caching
sidebar_position: 2
---

## The process-wide loader cache

`OpenidConfigLoader.get(domain, use_https, debug_logger)` returns a shared loader from a
module-level `dict` keyed by `(domain, use_https)`, guarded by a module-level
`threading.Lock`. Without this, an app with ten distinct `lockdown()` scope combinations
against one domain would perform ten independent loads, or twenty HTTP requests. With it,
two: one for the OIDC configuration document, one for the JWKS.

Because the cache is process-wide rather than private to each `Armasec` instance, it is
also a test-isolation hazard: two tests constructing an `Armasec` against the same domain
share a loader unless something clears it between them. `clear_cache()` is exported for
exactly this, and the `mock_openid_server` pytest fixture calls it automatically on entry
and exit.

## The per-loader fetch lock

Each loader holds its own `threading.Lock` around its cold config and JWKS fetches.
Upstream has no such lock, so N concurrent first requests to the same route all fetch
simultaneously. `armasec-lite`'s lock means only one of them performs the fetch; the rest
wait for it and reuse the result.

**Why `threading.Lock` and not `asyncio.Lock`.** An `asyncio.Lock` binds to the event loop
that first awaits it, and goes stale across test loops and multi-loop setups. Since the
cold path already runs in an executor thread (see
[Threading model](./threading-model.md)), the worker thread is what actually holds the
lock, and the event loop thread is never blocked on it. A `threading.Lock` is therefore
both the simpler primitive and the one that actually matches where the contention happens.

## Rate-limited JWKS refetch

`refresh_jwks()` refetches the JWKS when a token presents an unknown `kid`, but at most
once per `JWKS_REFRESH_INTERVAL` seconds (default 300), tracked with `time.monotonic()`.

Upstream caches the JWKS forever, so a provider key rotation causes every request to 401
until the process restarts. The rate limit is what lets `armasec-lite` recover within its
refetch interval instead: an unrecognized `kid` triggers one refetch, and a second unknown
`kid` within the interval triggers none, so a flood of tokens signed with an unknown key
cannot turn into a flood of outbound requests to the provider.
