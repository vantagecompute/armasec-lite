---
title: Request lifecycle
sidebar_position: 1
---

Every request through `Depends(armasec.lockdown(...))` runs the same sequence in
`TokenSecurity.__call__`:

1. **Lazy-load managers.** The first request against a given `Armasec` instance loads its
   `TokenManager` and the OIDC configuration it depends on. Later requests reuse what is
   already loaded. See [Caching](./caching.md) and
   [Threading model](./threading-model.md) for what happens on this path.
2. **Extract the token payload.** `TokenManager.extract_token_payload` unpacks the bearer
   token from the `Authorization` header, then `TokenDecoder.decode` verifies it and
   produces a `TokenPayload`.
3. **`match_keys` check.** If the domain config declares `match_keys`, every key must match
   the corresponding attribute on the token payload.
4. **Scope check.** The requested scopes are checked against the token's permissions,
   according to the domain's `PermissionMode` (`ALL` or `SOME`).
5. **Plugin hooks.** Any registered `armasec_plugin_check` hooks run last, in LIFO order.
   A hook that raises denies the request.

If every step passes, the dependency returns the `TokenPayload` to the route handler.

## Status codes

| Condition | Status |
| --- | --- |
| Missing, malformed, expired, or unverifiable token | 401 |
| Valid token, missing required scopes | 403 |
| Valid token, `match_keys` mismatch | 403 |
| Plugin check raised | plugin's `status_code`, default 403 |
| `permission_extractor` path missing from token | 500 |
| No domain configured at `Armasec()` construction | 422 |

Every error surfaced to a client is an `HTTPException` carrying a
`WWW-Authenticate: Bearer` header, translated from the underlying `ArmasecError` in
`TokenSecurity.__call__`. `debug_exceptions=True` re-raises the original error instead of
translating it, for use in tests.
