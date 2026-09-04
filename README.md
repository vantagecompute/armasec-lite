# armasec-lite

Injectable FastAPI authentication and authorization against OIDC providers, built almost
entirely on the Python standard library. `armasec-lite` is a dependency-minimal
reimplementation of [armasec](https://github.com/omnivector-solutions/armasec) 3.0.3 with
the same public API: it validates bearer tokens against your identity provider's JWKS,
checks scopes and issuer/audience claims, and plugs into a route with a single
`Depends()`, all with three runtime dependencies instead of upstream's ten.

## Quickstart

```bash
uv add armasec-lite
```

```python
"""Secure a single route against one OIDC domain."""

import os

from armasec_lite import Armasec
from fastapi import Depends, FastAPI

app = FastAPI()
armasec = Armasec(
    domain=os.environ.get("ARMASEC_DOMAIN"),
    audience=os.environ.get("ARMASEC_AUDIENCE"),
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return {"message": "Successfully authenticated!"}
```

More usage patterns, including multiple domains, `match_keys`, and the plugin system, are
in [`examples/`](examples/).

## Why

Upstream `armasec` carries ten runtime dependencies. Two of them (`pytest`, `respx`) are
test tools forced into every production install: `armasec==3.0.3` declares `pytest<9,>=6`
and `respx` as runtime requirements, which is exactly the kind of constraint that made this
project's own lockfile unsatisfiable when we tried to depend on upstream for benchmarking
against a `pytest>=9.1` toolchain. `armasec-lite` ships three runtime dependencies:
`fastapi`, `cryptography`, and `pydantic`. `pydantic` is kept rather than dropped because
`fastapi` requires it and imports it unconditionally, so it is installed and loaded in
every deployment regardless of what this project declares; keeping it as a direct
dependency preserves `model_dump()`, `response_model=`, and `except pydantic.ValidationError`
for anyone migrating from upstream, instead of breaking all three for a saving of zero
bytes.

| Upstream dependency | Replacement |
| --- | --- |
| `python-jose[cryptography]` | `jwt.py` (stdlib parsing, `cryptography` primitives) |
| `httpx` | `urllib.request` |
| `pydantic` | **kept** (see Decision 7): fastapi requires it, so it costs nothing |
| `py-buzz` | `exceptions.py` (~50 LOC) |
| `snick` | `textwrap` |
| `auto-name-enum` | `enum.Enum` |
| `pluggy` | `importlib.metadata` entry points (~55 LOC) |
| `respx` | monkeypatch of the internal HTTP layer |
| `pytest` (runtime) | moved to a `[test]` extra |
| `typer` | dropped with the CLI |
| `fastapi` | kept |
| (new) | `cryptography` |

## Migrating from armasec

This is the complete list of behavior differences from upstream armasec 3.x. Migrating
from 2.x is out of scope and untested; a 2.x consumer should upgrade to 3.x first and
confirm their application works there.

### Requires action from an integrator

| Difference | What breaks | Fix |
| --- | --- | --- |
| Import name is `armasec_lite` | Every import line | A scoped `sed` over the project's own sources |
| `verify_issuer` defaults to `True` | Routes 401 when the provider's discovery `issuer` does not exactly match the `iss` it mints, most often over a trailing slash | Correct the provider, or `DomainConfig(verify_issuer=False)` |
| Errors no longer derive from py-buzz | `except buzz.Buzz` stops catching `ArmasecError` | Catch `armasec_lite.exceptions.ArmasecError` |
| The pytest fixtures live behind the `[test]` extra | A ported test suite cannot import the fixtures from a plain install, because upstream forced `pytest` into every install and this does not | Depend on `armasec-lite[test]` |
| The OIDC loader cache is process-wide | Tests that expect per-instance provider state now share it | `openid_config_loader.clear_cache()`, or the `mock_openid_server` fixture, which calls it automatically |
| The CLI is not included | `armasec` console script is gone | Out of scope; see below |

### Requires no action, listed so the API diff is complete

| Difference | Why it is safe |
| --- | --- |
| `TokenDecoder` gained an optional `jwks_refresher` keyword argument | Purely additive; the first positional argument is still `JWKs`, so existing construction sites are unaffected |
| Models remain pydantic | `model_dump()`, `model_validate()`, `response_model=` and `pydantic.ValidationError` all keep working, as upstream |
| `JWK` no longer requires `n` and `e` | Strictly more permissive. Upstream fails to parse a JWKS document containing an EC or OKP key; this parses it |

## What is not included

The `armasec` CLI (device-code login, token cache) is not part of this package. It is
already shipped as an extra upstream, it needs `typer`, `rich`, `loguru`, `pendulum` and
`pyperclip`, and a stdlib rewrite of it is roughly as much work as the rest of this
project combined. This library validates tokens; it does not issue, refresh, or otherwise
participate in any OIDC client-side flow. A CLI can ship later as a separate distribution
if there is demand for one.

## Security

Signature verification delegates entirely to `cryptography`; nothing here hand-rolls RSA,
ECDSA, EdDSA, or HMAC primitives. The verification order implemented in
`armasec_lite/jwt.py` (algorithm allowlist check, JWK-type-versus-algorithm matching,
`crit` header validation, then signature verification, and only afterward claim
validation) is a security property, not an implementation detail, and is documented with
its rationale directly in that module. `tests/unit/test_jwt_attacks.py` is the
enumeration of what is defended: `alg: none`, algorithm confusion, disallowed algorithms,
`kid` mismatch, tampered headers and payloads, malformed ECDSA signature lengths,
unrecognized `crit` entries, expired and not-yet-valid tokens, and audience/issuer
mismatches.

## Documentation

Full docs, including architecture, the request lifecycle, the caching and threading
model, and the migration guide, are at
[https://docs.vantagecompute.ai/developer/armasec-lite/](https://docs.vantagecompute.ai/developer/armasec-lite/).
