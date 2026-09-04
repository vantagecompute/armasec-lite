---
title: Threading model
sidebar_position: 3
---

`TokenSecurity.__call__` is an `async def`. Upstream calls synchronous `httpx.get` directly
from inside it to fetch the OIDC configuration and JWKS on the cold path, which blocks the
event loop for the duration of that call. Every other request on the same process, whether
authenticated or not, waits behind it.

`armasec-lite` offloads exactly that cold path to an executor:

```python
loop = asyncio.get_running_loop()
await loop.run_in_executor(None, self._load_all_managers)
```

## Why only the cold path

`__call__` checks the warm cache first. When the managers for a request are already
loaded, it takes a fully synchronous path with zero executor overhead: no thread handoff,
no loop scheduling cost, just the verification work described in
[Request lifecycle](./request-lifecycle.md). Only the first request against a given
`Armasec` instance, the one that has to perform the OIDC configuration and JWKS fetch, pays
for the executor hop.

This is also why the per-loader fetch lock described in
[Caching](./caching.md) is a `threading.Lock`: the cold load runs on a worker thread from
the executor's thread pool, not on the event loop thread, so the lock that guards it needs
to work correctly from that thread and needs no relationship to any particular event loop.

## What this fixes

Upstream's blocking cold load means a single cold authentication check can stall unrelated,
even unauthenticated, traffic on the same process for as long as the OIDC round trip takes.
`armasec-lite`'s executor hop keeps that fetch off the event loop, so the rest of the
application keeps serving requests while it happens.
