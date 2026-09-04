---
title: Migration
sidebar_position: 3
---

`armasec-lite` targets a drop-in migration from upstream armasec 3.0.3: `Armasec`,
`TokenSecurity`, and `DomainConfig` keep the same fields and the same method signatures.
Four things differ. Each is intentional and each has a documented fix.

## Prerequisite: you must already be on armasec 3.x

`armasec-lite` is a port of upstream armasec 3.x specifically. It does not cover, and was
not designed against, armasec 2.x. If you are still on 2.x, upgrade to 3.x first, confirm
your application still works, and only then swap the dependency. Migrating from 2.x
directly to `armasec-lite` is out of scope and untested.

This is worth checking explicitly rather than assuming: a dependency floor like
`armasec>=2.0.0` admits both major versions, so it is possible to be on 2.x without
realizing it. Check what actually resolved:

```bash
uv pip show armasec
```

## 1. Import name

Reusing upstream's `armasec` import path would make this a zero-edit drop-in, but two
distributions owning one import path lets `pip install` silently overwrite files with no
error and a half-merged package left on disk. So the import path changed along with the
distribution name.

**Fix:** one `sed` on your import lines.

```bash
grep -rl 'from armasec' . | xargs sed -i 's/from armasec/from armasec_lite/g'
grep -rl 'import armasec' . | xargs sed -i 's/import armasec/import armasec_lite/g'
```

Nothing else about the API changes; this is a mechanical rename.

## 2. `verify_issuer` defaults to `True`

Upstream loads `openid_config.issuer` from the provider's discovery document and never
checks it against the token's `iss` claim, so a token from any provider whose JWK happens
to match will pass. `armasec-lite` checks `iss` against the discovery document's `issuer`
by default.

This is the one difference most likely to turn a **working route into a 401** on upgrade.
The usual cause is a provider whose discovery `issuer` does not exactly match the `iss` it
mints into tokens, most commonly because one of the two carries a trailing slash and the
other does not. String equality is exact; a trailing slash is enough to fail it.

**Fix:** if your provider's `issuer` and `iss` genuinely disagree and you cannot correct
that at the provider, restore upstream's behavior for that domain:

```python
DomainConfig(
    domain="my-tenant.auth0.com",
    audience="https://my-api.example.com",
    algorithm="RS256",
    verify_issuer=False,
)
```

## 3. The OIDC loader cache is process-wide

Upstream's `OpenidConfigLoader` is private to whichever object constructs it. `armasec-lite`
keeps a module-level cache keyed by `(domain, use_https)`, shared across every `Armasec`
instance in the process: an app with ten distinct `lockdown()` scope sets against one
domain performs two HTTP requests total instead of twenty.

That sharing is a test-isolation hazard: two tests that each construct an `Armasec` against
the same domain, expecting independent state, now see each other's cached config and JWKS.

**Fix:** call `armasec_lite.openid_config_loader.clear_cache()` between tests, or use the
`mock_openid_server` pytest fixture from the `[test]` extra, which calls it automatically on
entry and exit.

## 4. `TokenDecoder` gained an optional `jwks_refresher` argument

Upstream's `TokenDecoder` receives a `JWKs` value at construction and has no way to ask
for a fresh one. When a token presents a `kid` the current JWKS does not contain, the
usual cause is a provider key rotation, and upstream has no path to recover: the process
must restart before it will accept tokens signed by the new key.

`armasec-lite`'s `TokenDecoder` gains an optional keyword argument,
`jwks_refresher: Callable[[], JWKs] | None = None`, and the library wires
`loader.refresh_jwks` into it internally. On an unknown `kid`, the decoder calls the
refresher and searches the refreshed JWKS once more before giving up, so a rotation
recovers without a process restart. This is rate limited to once per 300 seconds, so a
flood of tokens signed with an unrecognized key cannot become a flood of outbound requests
to the provider.

**Fix:** none required. This is purely additive: the first positional argument to
`TokenDecoder` is still `JWKs`, so every existing construction site is unaffected. Almost
nobody constructs `TokenDecoder` directly, since it is normally wired up internally by
`Armasec`, which is why this change ranks below the cache change in practical impact.

## What does not change

Everything else. `Armasec.lockdown`, `lockdown_all`, and `lockdown_some` keep identical
signatures. `TokenPayload` keeps `sub`, `permissions`, `expire`, `client_id`,
`original_token`, and arbitrary-claim attribute access through `extra`. Plugin discovery,
`match_keys`, and the `HTTPException` translation with `WWW-Authenticate: Bearer` are direct
ports.
