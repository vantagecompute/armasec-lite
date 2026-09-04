# armasec-lite Design

Date: 2026-09-04
Status: Approved

## Purpose

`armasec-lite` is a dependency-minimal reimplementation of
[armasec](https://github.com/omnivector-solutions/armasec) 3.0.3. It provides injectable
FastAPI authentication against OIDC providers with the same public API, built almost
entirely on the Python standard library.

Upstream carries ten runtime dependencies. Two of them (`pytest`, `respx`) are test tools
forced into every production install. Four more (`snick`, `py-buzz`, `auto-name-enum`,
`pluggy`) provide small conveniences that the standard library covers directly.
`armasec-lite` ships two runtime dependencies.

### Dependency reduction

| Upstream dependency | Replacement |
| --- | --- |
| `python-jose[cryptography]` | `jwt.py` (stdlib parsing, `cryptography` primitives) |
| `httpx` | `urllib.request` |
| `pydantic` | `dataclasses` (`armasec_lite.schemas`) |
| `py-buzz` | `exceptions.py` (~50 LOC) |
| `snick` | `textwrap` |
| `auto-name-enum` | `enum.Enum` |
| `pluggy` | `importlib.metadata` entry points (~55 LOC) |
| `respx` | monkeypatch of the internal HTTP layer |
| `pytest` (runtime) | moved to a `[test]` extra |
| `typer` | dropped with the CLI |
| `fastapi` | kept |
| (new) | `cryptography` |

### Non-goals

- The `armasec` CLI (device-code login, token cache). It is already an extra upstream, it
  needs `typer`, `rich`, `loguru`, `pendulum` and `pyperclip`, and a stdlib rewrite is
  roughly as much work as the rest of this project combined. It can ship later as a
  separate `armasec-lite-cli` distribution.
- Token issuance, refresh, or any OIDC client-side flow. This library validates tokens.
- Backwards compatibility with armasec 2.x.

## Decisions

These were settled during design and are not open for reinterpretation during
implementation.

1. **Import name is `armasec_lite`, distribution name is `armasec-lite`.** Reusing the
   `armasec` import path would make this a zero-edit drop-in, but two distributions
   owning one import path lets `pip install` silently overwrite files with no error and a
   half-merged package on disk. Migration cost is one `sed` on import lines. The API is
   otherwise signature-identical to upstream.
2. **Signature verification uses `cryptography`, not hand-rolled RSA.** JWT libraries
   have a long CVE history precisely in signature verification (algorithm confusion,
   `alg: none`, PKCS#1 v1.5 padding forgery). A pure-stdlib path would also cap support
   at RS\* and HS\*, excluding ES256, which Auth0 and Keycloak both issue in common
   configurations. `python-jose[cryptography]` already installs `cryptography`, so the
   dependency count still drops from ten to two. Everything other than the primitive
   signature check is stdlib.
3. **`verify_issuer` defaults to `True`.** Upstream loads `openid_config.issuer` and then
   never checks it, so a token from any provider whose JWK happens to match will pass. The
   escape hatch is `DomainConfig(verify_issuer=False)`. This is the one intentional
   behavior difference from upstream and must be documented in the README migration notes.
4. **The OIDC loader cache is process-wide, keyed by `(domain, use_https)`**, guarded by a
   `threading.Lock`, with rate-limited JWKS refetch on unknown `kid`.

## Architecture

```
armasec_lite/
  __init__.py             public exports
  armasec.py              Armasec factory: lockdown / lockdown_all / lockdown_some
  token_security.py       TokenSecurity, the FastAPI injectable
  token_manager.py        header unpacking -> TokenPayload
  token_decoder.py        JWKs + token -> verified TokenPayload
  token_payload.py        TokenPayload
  openid_config_loader.py OpenidConfigLoader + process-wide cache
  schemas.py              JWK, JWKs, OpenidConfig, DomainConfig, PermissionMode
  exceptions.py           ArmasecError family, require_condition, handle_errors
  utilities.py            noop, log_error, unwrap
  jwt.py                  JWS/JWT encode and decode
  http.py                 get_json
  pluggable/
    __init__.py           PluginManager, hookimpl, plugin_manager singleton
    hookspecs.py          armasec_plugin_check signature and docs
  pytest_extension.py     pytest fixtures, shipped under the [test] extra
```

Request flow, unchanged from upstream:

```
FastAPI route
  Depends(armasec.lockdown("read:stuff"))
    TokenSecurity.__call__(request)
      1. lazy-load managers (cached, executor-offloaded on cold path)
      2. TokenManager.extract_token_payload(request.headers)
           unpack bearer token from Authorization header
           TokenDecoder.decode(token) -> TokenPayload
      3. match_keys check          -> AuthorizationError (403)
      4. scope check per PermissionMode -> AuthorizationError (403)
      5. plugin hooks              -> plugin-defined error
      returns TokenPayload
```

## Packaging

```toml
requires-python = ">=3.12"

dependencies = [
    "fastapi>=0.141.1,<1",
    "cryptography>=50.0.1,<51",
]

[project.optional-dependencies]
test = ["pytest>=9.1.1,<10"]

[dependency-groups]
dev = [
    "pytest>=9.1.1,<10",
    "pytest-asyncio",
    "pyjwt>=2.13.0,<3",
    "httpx",
    "mypy",
    "ruff",
]

[project.entry-points."pytest11"]
pytest_armasec_lite = "armasec_lite.pytest_extension"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

`cryptography` is capped below the next major because it ships compiled Rust and has
broken API across majors. `pyjwt` and `httpx` are development-only: `pyjwt` is the
cross-validation oracle described under Testing, `httpx` backs FastAPI's `TestClient`.
Neither reaches a production install.

## Components

### `jwt.py`

The only genuinely new code in the project, and the only security-critical code.

Public surface:

```python
def decode(
    token: str,
    jwk: JWK,
    algorithms: list[str],
    *,
    audience: str | None = None,
    issuer: str | None = None,
    options: dict | None = None,
    leeway: float = 0.0,
) -> dict: ...

def encode(claims: dict, key: bytes, algorithm: str, headers: dict | None = None) -> str: ...

def get_unverified_header(token: str) -> dict: ...
```

`encode` exists to serve the pytest extension's `build_rs256_token` fixture without a
second signing dependency. It is public, documented as a testing aid, and not part of the
request path.

**Verification order.** Steps 2 through 5 are the security core; the order is not an
implementation detail and must not be rearranged.

1. Split on `.`; require exactly three segments. Base64url-decode each with computed
   padding, rejecting lengths that cannot be valid base64url (`len % 4 == 1`).
2. Check `header["alg"]` against the caller-supplied `algorithms` allowlist. Never read
   the algorithm choice from the token itself. This is the `alg: none` and
   algorithm-confusion defense.
3. Check that the JWK's `kty` matches the algorithm family: `RS*`/`PS*` require `RSA`,
   `ES*` require `EC`, `EdDSA` requires `OKP`, `HS*` require `oct`. This blocks the
   classic forgery where an attacker signs with HS256 using the provider's RSA public key
   as the HMAC secret.
4. Reject any header listed in `crit` that is not recognized, per RFC 7515 section 4.1.11.
5. Verify the signature over the ASCII bytes of `f"{header_b64}.{payload_b64}"`, before
   parsing or trusting any claim.
6. Only after signature verification, validate claims: `exp`, `nbf`, `iat`, `aud`, `iss`,
   each honoring `leeway`.

**Algorithm support.**

| Algorithm | JWK fields | Verification |
| --- | --- | --- |
| RS256 / RS384 / RS512 | `n`, `e` | `RSAPublicNumbers(e, n).public_key()`, PKCS1v15 padding |
| PS256 / PS384 / PS512 | `n`, `e` | same key, PSS with MGF1, salt length equal to digest length |
| ES256 / ES384 / ES512 | `crv`, `x`, `y` | `EllipticCurvePublicNumbers`, P-256 / P-384 / P-521 |
| EdDSA | `crv=Ed25519`, `x` | `Ed25519PublicKey.from_public_bytes` |
| HS256 / HS384 / HS512 | `k` | `hmac.new(...).digest()` compared with `hmac.compare_digest` |

Big-endian integers come from `int.from_bytes(base64url_decode(field), "big")`.

**ECDSA signature encoding.** JWS carries ECDSA signatures as raw `r || s`;
`cryptography` expects DER. Convert with
`cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature`. The raw signature
length must equal exactly `2 * coord_bytes` or verification fails before any conversion,
which prevents short-signature manipulation. **The coordinate size is derived from the
algorithm name, never from the JWK's `crv` field**, so a hostile JWKS cannot substitute a
weaker curve than the algorithm implies.

**Claim validation.**

- `exp`: fail if `now > exp + leeway`. Error type `ExpiredSignatureError`.
- `nbf`: fail if `now < nbf - leeway`. Error type `ImmatureSignatureError`.
- `iat`: parsed for presence and type; not used to reject (matches jose).
- `aud`: the token claim may be a string or a list of strings. When `audience` is
  supplied, require membership. When `options={"verify_aud": False}`, skip entirely; this
  is the path `DomainConfig.ignore_audience` already uses upstream.
- `iss`: when `issuer` is supplied, require exact string equality.

All failures raise subclasses of `armasec_lite.exceptions.AuthenticationError` so the
existing `handle_errors` wrapping in `TokenDecoder` continues to work unchanged.

### `http.py`

```python
def get_json(url: str, *, timeout: float = 10.0) -> dict: ...
```

Built on `urllib.request`, with hardening upstream's `httpx.get` call does not have:

- An explicit `ssl.create_default_context()`, giving certificate and hostname verification.
- A custom `HTTPRedirectHandler` that refuses an `https` to `http` downgrade and caps the
  redirect count.
- A response body size cap. Read `MAX_BODY_BYTES + 1` and error if the body exceeds it,
  so a hostile or compromised JWKS endpoint cannot exhaust memory.
- `urllib.error.HTTPError` and `URLError` mapped onto `AuthenticationError`, preserving
  the status code in the message where one exists.

### `schemas.py`

Named `schemas` rather than `models` so that upstream's
`from armasec.schemas import DomainConfig` ports to
`from armasec_lite.schemas import DomainConfig` with only the package name changed. It is
a module, not a package, since it is four small types.

Plain `@dataclass` types, each with a `from_dict()` classmethod that validates required
fields and their types and ignores unknown keys, matching pydantic's `extra="allow"`
where upstream used it.

- `JWK`: `alg`, `e`, `kid`, `kty`, `n` required upstream. This is wrong for non-RSA keys,
  so in `armasec-lite` only `kty` and `kid` are unconditionally required; `n`/`e`,
  `crv`/`x`/`y`, and `k` are validated per key type at use time in `jwt.py`. Unknown
  members are retained in `extra`.
- `JWKs`: `keys: list[JWK]`.
- `OpenidConfig`: `issuer`, `jwks_uri`. These lose pydantic's `AnyHttpUrl` validation, so
  they are checked with `urllib.parse.urlparse` for a scheme in `("http", "https")` and a
  non-empty netloc. `jwks_uri` arrives inside a remote document that we then fetch, so its
  scheme is additionally pinned to match the domain's `use_https` setting.
- `DomainConfig`: `domain`, `audience`, `ignore_audience`, `algorithm`, `use_https`,
  `match_keys`, `permission_extractor`, plus the new `verify_issuer: bool = True`.
  Validated in `__post_init__`.

`PermissionMode` becomes `class PermissionMode(str, Enum)` with `ALL = "ALL"` and
`SOME = "SOME"`, preserving upstream's `AutoNameEnum` string values.

### `token_payload.py`

`TokenPayload` needs arbitrary-claim attribute access: `match_keys` does
`getattr(token_payload, key)`, and the documented plugin example reads `.email`. So it is
a dataclass with the known fields `sub`, `permissions`, `expire`, `client_id`,
`original_token`, plus `extra: dict`, and a `__getattr__` that falls through to `extra`
and raises `AttributeError` on a miss.

Alias handling moves out of pydantic field aliases into a `from_claims()` classmethod:
`exp` maps to `expire` (converted to an aware `datetime`), `azp` maps to `client_id`.
`to_dict()` is preserved for compatibility.

### `exceptions.py`

`ArmasecError(Exception)` carries `status_code` and `detail` class attributes and
reimplements the two py-buzz APIs armasec actually uses:

```python
@classmethod
def require_condition(cls, expr, message) -> None: ...

@classmethod
@contextmanager
def handle_errors(cls, message, do_except=None): ...
```

`handle_errors` wraps any raised exception into `cls` with the original attached, and
invokes `do_except(DoExceptParams(final_message, err, trace))` when supplied.
`DoExceptParams` is a small dataclass with the same three attributes py-buzz provides, so
`utilities.log_error` ports unchanged.

Subclasses keep upstream's status codes: `AuthenticationError` 401, `AuthorizationError`
403, `PayloadMappingError` 500. New `jwt.py` errors (`ExpiredSignatureError`,
`ImmatureSignatureError`, `InvalidAudienceError`, `InvalidIssuerError`,
`InvalidSignatureError`, `InvalidAlgorithmError`) all subclass `AuthenticationError`.

### `openid_config_loader.py`

`OpenidConfigLoader` keeps its upstream constructor and its lazy `config` and `jwks`
properties. Three additions:

**Process-wide cache.** A module-level `dict` keyed by `(domain, use_https)` returns a
shared loader via `OpenidConfigLoader.get(domain, use_https, debug_logger)`, guarded by a
module-level `threading.Lock`. Without this, an app with ten distinct `lockdown()` scope
combinations against one domain performs ten independent loads, or twenty HTTP requests.
With it, two.

**Per-loader fetch lock.** Each loader holds its own `threading.Lock` around the cold
config and JWKS fetches. Upstream has no lock, so N concurrent first requests to the same
route all fetch simultaneously. This is a `threading.Lock` rather than an `asyncio.Lock`
deliberately: an `asyncio.Lock` binds to the loop that first awaits it and goes stale
across test loops and multi-loop setups. Since the cold path already runs in an executor
thread (see `token_security.py`), the worker thread holds the lock and the event loop
thread is never blocked on it.

**Rate-limited JWKS refetch.** `refresh_jwks()` refetches the JWKS when a token presents
an unknown `kid`, but at most once per `JWKS_REFRESH_INTERVAL` seconds (default 300),
tracked with `time.monotonic()`. Upstream caches the JWKS forever, so a provider key
rotation 401s every request until the process restarts. The rate limit prevents a flood of
unknown-`kid` tokens from turning into a flood of outbound requests.

`clear_cache()` is exported for tests, and the `mock_openid_server` fixture calls it
automatically. A process-wide cache is a test-isolation hazard and this is the mitigation.

### `token_decoder.py`

Unchanged in shape from upstream, with one added constructor argument. Upstream's
`TokenDecoder` receives a `JWKs` value and therefore has no way to ask for a fresh one, so
it gains an optional keyword argument:

```python
jwks_refresher: Callable[[], JWKs] | None = None
```

`_load_manager` passes `loader.refresh_jwks`. The first positional argument stays `JWKs`,
so existing construction sites are unaffected.

`get_decode_key` searches `jwks.keys` for a matching `kid` and, on a miss, calls
`jwks_refresher()` when one is configured and searches the refreshed set once more before
raising. `decode` calls `armasec_lite.jwt.decode` in place of `jose.jwt.decode`, applies
`permission_extractor` when configured, and builds the `TokenPayload`.
`extract_keycloak_permissions` is carried over verbatim.

### `token_manager.py`

`unpack_token_from_header` drops `fastapi.security.utils.get_authorization_scheme_param`
in favor of a two-line `partition(" ")`, keeping identical behavior: require the header,
require both a scheme and a token, require the scheme to be `bearer` case-insensitively.
`extract_token_payload` passes `verify_issuer` and the openid config's `issuer` through to
the decoder alongside `audience`.

### `token_security.py`

Behavior matches upstream, with the async fix. `__call__` checks the warm cache first and
takes a fully synchronous path with zero executor overhead when managers are already
loaded. Only the cold path does:

```python
loop = asyncio.get_running_loop()
await loop.run_in_executor(None, self._load_all_managers)
```

Upstream calls sync `httpx.get` from inside `async def __call__`, blocking the event loop
on every cold load. This fixes that.

`ManagerConfig` becomes a plain dataclass. The rest of the class body, including
`match_keys` handling, `PermissionMode` evaluation, and the `HTTPException` translation
with `WWW-Authenticate: Bearer` headers, is a direct port.

### `armasec.py`

`Armasec` keeps `lockdown`, `lockdown_all` and `lockdown_some` with identical signatures.
The `@lru_cache` decorator on the `lockdown` method is replaced by a per-instance `dict`
keyed on `(scopes, permission_mode, skip_plugins)`. `lru_cache` on a method keys on `self`
in a process-global cache, which pins every `Armasec` instance for the process lifetime.
Semantics for the normal module-level-singleton usage are identical.

### `pluggable/`

A ~55 LOC `PluginManager` with `register()`, `unregister()`, `load_entry_points()`, and a
`hook.armasec_plugin_check(...)` relay. Third-party plugins are discovered through
`importlib.metadata.entry_points(group="armasec")`.

The one pluggy behavior armasec depends on must be preserved: implementations receive only
the keyword arguments they declare. The example plugin defines
`armasec_plugin_check(token_payload)` and must not be handed `request` and `debug_logger`.
This is `inspect.signature` filtering at registration time.

`hookimpl` becomes a decorator that sets a marker attribute; `register()` scans the given
module or object for callables carrying that marker. Call order is LIFO, matching pluggy.
Exceptions propagate, since raising is how a plugin signals denial.

### `pytest_extension.py`

Because the HTTP layer is now ours, the mock is a monkeypatch of
`armasec_lite.http.get_json` against a URL-to-payload routing table. No sockets, no
`respx`, no real server.

Fixtures carried over by name so upstream test suites port unchanged: `rs256_domain`,
`rs256_domain_config`, `rs256_iss`, `rs256_kid`, `rs256_sub`, `rs256_private_key`,
`rs256_public_key`, `rs256_jwk`, `rs256_jwks_uri`, `rs256_openid_config`,
`build_rs256_token`, `mock_openid_server`, plus `build_mock_openid_server`.

The same hardcoded PKCS#1 test key is reused so the existing `rs256_jwk` fixture values
still match. `cryptography.hazmat.primitives.serialization.load_pem_private_key` reads the
`BEGIN RSA PRIVATE KEY` PKCS#1 format directly.

The yielded object keeps `.call_count` and `.called` on its `openid_config_route` and
`jwks_route` members, so assertions written against respx's route API port as-is.
`mock_openid_server` calls `openid_config_loader.clear_cache()` on entry and exit.

## Error handling

Every error surfaced to a client is an `HTTPException` with a `WWW-Authenticate: Bearer`
header, translated in `TokenSecurity.__call__`:

| Condition | Status |
| --- | --- |
| Missing, malformed, expired, or unverifiable token | 401 |
| Valid token, missing required scopes | 403 |
| Valid token, `match_keys` mismatch | 403 |
| Plugin check raised | plugin's `status_code`, default 403 |
| `permission_extractor` path missing from token | 500 |
| No domain configured at `Armasec()` construction | 422 |

`debug_exceptions=True` re-raises the original error instead of translating, for testing.
`debug_logger` defaults to `noop` and is threaded through every component unchanged.

## Testing

Test-driven throughout. `jwt.py` gets its tests written first, since it is where the risk
is concentrated and everything else is straightforward by comparison.

**Ported suite.** Upstream's roughly 1400 lines of tests across `test_armasec.py`,
`test_token_security.py`, `test_token_manager.py`, `test_token_decoder.py`,
`test_openid_config_loader.py` and `test_token_payload.py` are the real behavioral
specification and are ported first, adjusted only for the import name and the
`verify_issuer` default.

**Attack tests**, which upstream has no reason to carry because it delegated to jose:

- `alg: none` is rejected.
- A token signed HS256 using the RSA public key as the HMAC secret is rejected
  (algorithm confusion).
- An algorithm outside the caller's allowlist is rejected even when the signature is valid.
- `kid` mismatch, tampered payload, tampered header.
- ECDSA signature of wrong length, both short and long.
- Unrecognized entry in the `crit` header.
- Expired `exp`, future `nbf`, wrong `aud`, wrong `iss`, missing `aud` when one is required.
- Non-canonical base64url padding.

**Per-algorithm round trips** for RS256/384/512, PS256/384/512, ES256/384/512, HS256/384/512
and EdDSA.

**Cross-validation against PyJWT.** Tokens signed by `armasec_lite.jwt.encode` must decode
under PyJWT, and tokens signed by PyJWT must decode under ours, including the negative
cases. This is the primary defense against spec drift in a hand-written decoder and is the
reason PyJWT is a development dependency despite the goal of removing such dependencies
from the runtime.

**Concurrency tests** for the new cache: N concurrent cold requests produce exactly one
config fetch and one JWKS fetch; ten distinct `lockdown()` scope sets against one domain
produce two HTTP calls total; a rotated `kid` triggers exactly one refetch and a second
unknown `kid` within the interval triggers none.

## Documentation

- `README.md`: the upstream quickstart, adjusted for the import name, plus a dependency
  comparison table and a migration section covering the two differences that can change
  behavior on upgrade (import name, `verify_issuer` default).
- `examples/`: `basic.py`, `two_domains.py`, `match_key_value_pairs.py` and `plugin.py`
  ported from upstream. The plugin example drops its `loguru` and `pydantic` imports.
- Docstrings on all public API, matching upstream's style, since they are the API
  reference.
