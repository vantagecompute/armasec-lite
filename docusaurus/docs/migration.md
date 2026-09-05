---
title: Migration
sidebar_position: 3
---

`armasec-lite` targets a drop-in migration from upstream armasec 3.0.3: `Armasec`,
`TokenSecurity`, and `DomainConfig` keep the same fields and the same method signatures.
The list below is the complete, authoritative set of differences. Most require an action
on your part; a couple do not and are listed anyway so the API diff is complete.

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

**Fix:** a scoped `sed` on your own sources, run under a clean git tree so the change is
reviewable before you commit it:

```bash
git status --porcelain   # confirm a clean tree first
grep -rl --include='*.py' '\barmasec\b' src tests \
  | xargs sed -i -E 's/\barmasec\b/armasec_lite/g'
git diff                 # review before committing
```

Adjust `src tests` to your project's own source paths. Three things matter about this
form and are not optional: it names explicit paths rather than `.`, so it cannot recurse
into `.venv` or `site-packages`, where the real `armasec` package lives, and rewrite it in
place; it uses `\b` word boundaries, so it matches whole occurrences of `armasec` rather
than a substring of `from armasec_lite import ...`; and it is idempotent, so running it
twice does not turn `armasec_lite` into `armasec_lite_lite`. Nothing else about the API
changes; this is a mechanical rename.

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
from armasec_lite.schemas import DomainConfig

DomainConfig(
    domain="my-tenant.auth0.com",
    audience="https://my-api.example.com",
    algorithm="RS256",
    verify_issuer=False,
)
```

## 3. Errors no longer derive from py-buzz

Upstream's exception hierarchy derives from `py-buzz`'s `Buzz`. `armasec-lite` reimplements
the two `py-buzz` APIs armasec actually uses (`require_condition` and `handle_errors`)
directly on `armasec_lite.exceptions.ArmasecError`, which does not derive from `Buzz`.

**Fix:** if your code catches errors this library raises with `except buzz.Buzz:`, that
stops working. Catch `armasec_lite.exceptions.ArmasecError` instead.

## 4. The pytest fixtures live behind the `[test]` extra

Upstream forces `pytest` into every production install, so its fixtures are always
importable. `armasec-lite` moves `pytest` into a `[test]` extra instead (see
[Installation](./installation.md)), which means a ported test suite cannot import the
fixtures from a plain `armasec-lite` install.

**Fix:** depend on `armasec-lite[test]` wherever your tests run.

## 5. The OIDC loader cache is process-wide

Upstream's `OpenidConfigLoader` is private to whichever object constructs it. `armasec-lite`
keeps a module-level cache keyed by `(domain, use_https)`, shared across every `Armasec`
instance in the process: an app with four distinct `lockdown()` scope sets against one
domain performs two HTTP requests total instead of eight, and it stays at two however many
scope sets are added.

That sharing is a test-isolation hazard: two tests that each construct an `Armasec` against
the same domain, expecting independent state, now see each other's cached config and JWKS.

**Fix:** call `armasec_lite.openid_config_loader.clear_cache()` between tests, or use the
`mock_openid_server` pytest fixture from the `[test]` extra, which calls it automatically on
entry and exit.

## 6. The CLI is not included

Upstream's `armasec` console script (device-code login, token cache) is not part of this
project. It was already an extra upstream, it needs `typer`, `rich`, `loguru`, `pendulum`
and `pyperclip`, and a stdlib rewrite of it is roughly as much work as the rest of this
project combined. It may ship later as a separate `armasec-lite-cli` distribution.

**Fix:** none available yet. This is out of scope; keep the upstream `armasec` CLI
installed alongside `armasec-lite` if you rely on it, or wait for a future
`armasec-lite-cli`.

## Requires no action

A few more differences round out the API diff. None of them breaks anything migrating, so
none needs a fix; they are listed for completeness.

### `TokenDecoder` gained an optional `jwks_refresher` argument

Upstream's `TokenDecoder` receives a `JWKs` value at construction and has no way to ask
for a fresh one. When a token presents a `kid` the current JWKS does not contain, the
usual cause is a provider key rotation, and upstream has no path to recover: the process
must restart before it will accept tokens signed by the new key.

`armasec-lite`'s `TokenDecoder` gains an optional keyword argument,
`jwks_refresher: Callable[[], JWKs] | None = None`, and the library wires
`loader.refresh_jwks` into it internally. On an unknown `kid` the decoder raises
`UnknownKeyIdError`; `TokenSecurity` catches it, runs `TokenDecoder.refresh_keys` in an
executor thread, and searches the refreshed JWKS once more before giving up, so a rotation
recovers without a process restart. Refetching from a worker thread rather than inline
matters because `kid` comes from the unverified header: an inline fetch would let any
caller stall the event loop on demand. It is also rate limited to once per 300 seconds, so
a flood of tokens signed with an unrecognized key cannot become a flood of outbound
requests to the provider.

**Why it is safe:** this is purely additive. The first positional argument to
`TokenDecoder` is still `JWKs`, so every existing construction site is unaffected. Almost
nobody constructs `TokenDecoder` directly, since it is normally wired up internally by
`Armasec`.

### `JWK` no longer requires `n` and `e`

Upstream's `JWK` schema requires `alg`, `e`, `kid`, `kty`, and `n`, which is only correct
for RSA keys. `armasec-lite` requires only `kty` and `kid` unconditionally; the fields a
given key type actually needs (`n`/`e` for RSA, `crv`/`x`/`y` for EC, `k` for HMAC) are
validated per key type at use time in `jwt.py` instead.

**Why it is safe:** this is strictly more permissive than upstream, never less. A JWKS
document containing an EC or OKP key, which upstream's stricter schema rejects before the
key is ever used, now parses correctly under `armasec-lite`.

### `DomainConfig` validates `domain` and `algorithm` at construction

Upstream's `DomainConfig` defaults `domain` to the empty string and accepts any string as
`algorithm`. An empty domain builds the discovery URL
`https:///.well-known/openid-configuration`, and a mistyped algorithm configures a route
that refuses every token it is ever shown. Both failures arrive at request time, wearing a
message that names neither the domain nor the configuration.

`armasec-lite` requires `domain` and rejects one that is empty or whitespace, and checks
`algorithm` against the thirteen algorithms `jwt.py` supports.

**Why it is safe:** neither shape ever worked. A `DomainConfig` with no domain could not
load a provider, and a `DomainConfig` with an unsupported algorithm could not decode a
token. `Armasec()` with no domain at all still raises the same 422 it always did.

### `handle_errors` does not re-wrap an error that is already ours

py-buzz's `handle_errors` wraps every exception raised in its block, including one of its
own types. `armasec_lite.exceptions.handle_errors` re-raises an `ArmasecError` subclass
untouched and wraps everything else, so a specific error raised deep in a call stack is not
flattened by an enclosing handler.

**Why it is safe:** the wrapping contract holds for every error that is not already ours,
which is the case the handler exists for. The behavior it prevents is a real one: without
it, the `PayloadMappingError` block in `TokenDecoder.decode` would turn a genuine
authentication failure into a 500 instead of a 401.

## Summary

The tables below are the complete list; nothing above adds to or contradicts them.

**Requires action from an integrator:**

| Difference | What breaks | Fix |
| --- | --- | --- |
| Import name is `armasec_lite` | Every import line | A scoped `sed` over the project's own sources |
| `verify_issuer` defaults to `True` | Routes 401 when the provider's discovery `issuer` does not exactly match the `iss` it mints, most often over a trailing slash | Correct the provider, or `DomainConfig(verify_issuer=False)` |
| Errors no longer derive from py-buzz | `except buzz.Buzz` stops catching `ArmasecError` | Catch `armasec_lite.exceptions.ArmasecError` |
| The pytest fixtures live behind the `[test]` extra | A ported test suite cannot import the fixtures from a plain install, because upstream forced `pytest` into every install and this does not | Depend on `armasec-lite[test]` |
| The OIDC loader cache is process-wide | Tests that expect per-instance provider state now share it | `openid_config_loader.clear_cache()`, or the `mock_openid_server` fixture, which calls it automatically |
| The CLI is not included | `armasec` console script is gone | Out of scope; see [Security](./security/index.md#what-is-out-of-scope) |

**Requires no action, listed so the API diff is complete:**

| Difference | Why it is safe |
| --- | --- |
| `TokenDecoder` gained an optional `jwks_refresher` keyword argument | Purely additive; the first positional argument is still `JWKs`, so existing construction sites are unaffected |
| `JWK` no longer requires `n` and `e` | Strictly more permissive; an EC or OKP key that upstream rejected now parses |
| `DomainConfig` requires a non-empty `domain` and a supported `algorithm` | Neither shape ever worked; the failure just moved from request time to construction time. `Armasec()` with no domain still raises its own 422 |
| `handle_errors` re-raises an `ArmasecError` subclass unchanged | Everything that is not already ours is still wrapped. Re-wrapping would let the `PayloadMappingError` block turn a genuine 401 into a 500 |
