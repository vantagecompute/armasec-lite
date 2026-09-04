---
title: Migration
sidebar_position: 3
---

`armasec-lite` targets a drop-in migration from upstream armasec 3.0.3: `Armasec`,
`TokenSecurity`, and `DomainConfig` keep the same fields and the same method signatures.
Three things behave differently. Each is intentional and each has a documented fix.

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

## What does not change

Everything else. `Armasec.lockdown`, `lockdown_all`, and `lockdown_some` keep identical
signatures. `TokenPayload` keeps `sub`, `permissions`, `expire`, `client_id`,
`original_token`, and arbitrary-claim attribute access through `extra`. Plugin discovery,
`match_keys`, and the `HTTPException` translation with `WWW-Authenticate: Bearer` are direct
ports.
