---
title: Threading model
sidebar_position: 3
---

`TokenSecurity.__call__` is an `async def`. Upstream calls synchronous `httpx.get` directly
from inside it to fetch the OIDC configuration and JWKS on the cold path, which blocks the
event loop for the duration of that call. Every other request on the same process, whether
authenticated or not, waits behind it.

`armasec-lite` offloads that cold path to an executor:

```python
loop = asyncio.get_running_loop()
await loop.run_in_executor(None, self._load_all_managers)
```

## The other blocking path: a key rotation

The cold load is not the only synchronous network work a request can reach. A token whose
`kid` is absent from the cached JWKS means a provider key rotation, and recovering means
refetching the key set. `TokenDecoder` therefore does not perform that refetch itself: it
raises `UnknownKeyIdError`, and `__call__` answers by refreshing and retrying once, again
in an executor.

That path matters more than its rarity suggests. `kid` is read from the token's unverified
header, so an unauthenticated caller picks it. Refetching inline would hand anyone a
whole-process stall for the length of the fetch timeout, on demand, which is a worse
version of the upstream problem this page is about. The refresh is attempted at most once
per request, and the loader's own rate limit applies on top of that.

## Why only those two paths

`__call__` checks the warm cache first. When the managers for a request are already loaded
and the token's `kid` is one of the cached keys, it takes a fully synchronous path with
zero executor overhead: no thread handoff, no loop scheduling cost, just the verification
work described in [Request lifecycle](./request-lifecycle.md). The steady state pays for
no hop at all.

This is also why the per-loader fetch lock described in
[Caching](./caching.md) is a `threading.Lock`: every path that takes it runs on a worker
thread from the executor's thread pool, not on the event loop thread, so the lock that
guards it needs to work correctly from that thread and needs no relationship to any
particular event loop.

## What this fixes

Upstream's blocking cold load means a single cold authentication check can stall unrelated,
even unauthenticated, traffic on the same process for as long as the OIDC round trip takes.
`armasec-lite`'s executor hops keep every provider fetch off the event loop, the cold load
and the rotation refetch alike, so the rest of the application keeps serving requests while
they happen.
