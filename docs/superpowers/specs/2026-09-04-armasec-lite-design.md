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
`armasec-lite` ships three runtime dependencies, one of which (`pydantic`) is a transitive dependency of `fastapi` and is therefore installed either way.

### Dependency reduction

| Upstream dependency | Replacement |
| --- | --- |
| `python-jose[cryptography]` | `jwt.py` (stdlib parsing, `cryptography` primitives) |
| `httpx` | `urllib.request` |
| `pydantic` | **kept** (see Decision 6): fastapi requires it, so it costs nothing |
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
   dependency count still drops from ten to three. Everything other than the primitive
   signature check is stdlib.
3. **`verify_issuer` defaults to `True`.** Upstream loads `openid_config.issuer` and then
   never checks it, so a token from any provider whose JWK happens to match will pass. The
   escape hatch is `DomainConfig(verify_issuer=False)`. It is the most consequential of the
   intentional behavior differences from upstream, since it is the one that can 401 a
   deployment that worked the day before, and it must be documented in the README migration
   notes. The full set of differences is the table under "Differences from upstream", which
   runs to several entries; this is not the only one.
4. **The OIDC loader cache is process-wide, keyed by `(domain, use_https)`**, guarded by a
   `threading.Lock`, with rate-limited JWKS refetch on unknown `kid`.
5. **No performance number is hand-authored.** Every figure in the documentation site is
   generated from a committed benchmark result file. See the Benchmarks section.
6. **`pydantic` is a declared runtime dependency, and the models stay pydantic models.**
   An earlier draft replaced them with dataclasses. That was wrong. `fastapi` requires
   `pydantic` and imports it unconditionally, so it is present in every install no matter
   what this project declares: dropping it saved zero bytes. What it cost was real, and
   was caught in review. Hand-rolled dataclasses break `TokenPayload.model_dump()`,
   `DomainConfig.model_validate()`, using either type as a FastAPI `response_model`, and
   `except pydantic.ValidationError`, for every consumer migrating from upstream. That was
   the single largest break in the migration table, traded for nothing. Declaring the
   dependency is honesty about what is already shipped, and it deletes roughly two hundred
   lines of hand-written validation, alias mapping and `__getattr__` fallthrough that would
   otherwise have to be kept correct forever. The dependency reduction that matters is
   untouched: `python-jose`, `py-buzz`, `snick`, `auto-name-enum`, `pluggy`, `respx` and
   runtime `pytest` all still go, and `jwt.py` is still written here.
7. **This repository contains no `infra/` directory and deploys no AWS resources.** The
   spoke deploy role is created by the `vantage-docs` hub stack from its own `spokes`
   context, so registering there is the whole of the infrastructure work. `vantage-mcp-infra`
   carries CDK because it deploys Lambdas, DynamoDB and a CloudFront distribution;
   `armasec-lite` is a library with no runtime AWS footprint, and PyPI publishing uses
   trusted publishing, which needs no AWS role. A CDK app here would deploy nothing.

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
      2a. on UnknownKeyIdError from every configured domain:
           executor hop -> refresh every manager's keys -> retry the extraction once
      3. match_keys check          -> AuthorizationError (403)
      4. scope check per PermissionMode -> AuthorizationError (403)
      5. plugin hooks              -> plugin-defined error
      returns TokenPayload
```

## Packaging

The block below is a dependency-relevant excerpt of `pyproject.toml`, not the whole file.
The shipped file additionally carries `[project.urls]`, the trove classifiers,
`[tool.pytest.ini_options]` (`minversion`, `testpaths`, `asyncio_mode = "auto"`, and the
`integration` marker), `[tool.ruff]` (`line-length = 100` and an `extend-exclude` covering
`docs/superpowers` and `.worktrees`, since ruff 0.16 lints fenced Python inside Markdown by
default and this spec is full of it), `[tool.mypy]` with
`strict = true`, and `[tool.hatch.build.targets.wheel]` naming the one package.

```toml
requires-python = ">=3.12"

dependencies = [
    "fastapi>=0.141.1,<1",
    "cryptography>=50.0.1,<51",
    "pydantic>=2.13.5,<3",
]

[project.optional-dependencies]
test = ["pytest>=9.1.1,<10"]

[dependency-groups]
dev = [
    "pytest>=9.1.1,<10",
    "pytest-asyncio>=1.4.0,<2",
    "pytest-cov>=7.1.0,<8",
    "pyjwt>=2.13.0,<3",
    "httpx2>=2.12.0,<3",
    "mypy>=2.3.1,<3",
    "ruff>=0.16.6,<1",
]
# Upstream armasec is deliberately NOT listed here. It declares pytest<9 and respx as
# RUNTIME dependencies, so adding it makes this project's lockfile unsatisfiable against
# pytest>=9.1. That constraint leaking into a consumer's environment is the exact defect
# armasec-lite exists to remove. The comparison harness installs upstream armasec into
# isolated uv venvs and Docker containers instead.
bench = [
    "plotly>=6,<7",
]

[project.entry-points."pytest11"]
pytest_armasec_lite = "armasec_lite.pytest_extension"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

`cryptography` is capped below the next major because it ships compiled Rust and has
broken API across majors. `pyjwt` and `httpx2` are development-only: `pyjwt` is the
cross-validation oracle described under Testing, `httpx2` backs FastAPI's `TestClient`
(Starlette 1.6 deprecates plain `httpx` for that use). Neither reaches a production install.

The `bench` group is separate from `dev` and exists only to build the chart specs. It
cannot contain upstream `armasec`: armasec 3.0.3 declares `pytest<9,>=6` and `respx` as
runtime dependencies, which is unsatisfiable against this project's `pytest>=9.1.1` in
uv's single universal lockfile. That is the defect this project exists to remove, so the
right answer is to keep upstream out of this dependency graph entirely rather than to
downgrade our own toolchain to accommodate it. `plotly` builds JSON only; there is no `kaleido` and no static image export,
because the site renders the specs client-side. Benchmarks that need isolated environments
shell out to `uv venv` rather than resolving anything into this project's environment.

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

def verify_signature(algorithm: str, jwk: JWK, signing_input: bytes, signature: bytes) -> None: ...

def split_token(token: str) -> tuple[str, str, str]: ...

def b64url_encode(data: bytes) -> str: ...

def b64url_decode(segment: str) -> bytes: ...

SUPPORTED_ALGORITHMS: frozenset[str]
```

`decode`, `encode` and `get_unverified_header` are the API the rest of the library calls.
The other four names and the frozenset are public because the tests import them directly:
`verify_signature` is where the attack suite aims most of its cases, and the base64url
helpers and `split_token` are how a test constructs a deliberately malformed token without
going through `encode`. `verify_signature` returns `None` on success and raises on failure,
never a boolean, so a caller cannot authenticate a token by ignoring a result.

`SUPPORTED_ALGORITHMS` is duplicated in `schemas.py` rather than imported from here,
because `schemas.py` cannot import `jwt.py`: `jwt.py` imports `JWK` from `schemas.py`, and
importing back would be circular. The two copies are held in sync by a test
(`tests/unit/test_schemas.py`) that asserts they are equal. That test is the only thing
preventing them from diverging, which is worth knowing before deleting it.

`encode` exists to serve the pytest extension's `build_rs256_token` fixture without a
second signing dependency. It is public, documented as a testing aid, and not part of the
request path. It builds its header as `{"typ": "JWT", **(headers or {}), "alg": algorithm}`,
placing `alg` last deliberately: a caller passing `headers={"alg": "none"}` must not be able
to mint a token whose header disagrees with the signature the function then produces.

**Verification order.** The order is not an implementation detail. Two orderings carry the
security of the module and neither may be relaxed: **the algorithm is decided from the
caller's allowlist before any key is touched**, and **nothing in the payload is read until
the signature has verified**. The numbering below describes the code; the two properties
are what a change has to preserve.

0. Refuse the RFC 7515 unsecured JWS shape, `"<header>.<payload>."` with an empty
   signature, as `InvalidAlgorithmError`. It is a structurally valid serialization that
   carries no signature at all, so it belongs to the algorithm rule rather than to generic
   malformed-token handling, and reporting it as such is what makes the `alg: none` family
   of attacks legible in a log.
1. Split on `.`; require exactly three segments. Base64url-decode each with computed
   padding, rejecting lengths that cannot be valid base64url (`len % 4 == 1`). JSON
   parsing of a segment additionally refuses `Infinity`, `-Infinity` and `NaN`, which
   Python's `json` accepts by default and which are not valid JSON.
2. Check `header["alg"]` against the caller-supplied `algorithms` allowlist. Never read
   the algorithm choice from the token itself. This is the `alg: none` and
   algorithm-confusion defense and it stays first.
3. Reject any header listed in `crit`, per RFC 7515 section 4.1.11. This module recognizes
   no critical extensions, so any `crit` entry at all is a refusal.
4. Verify the signature over the ASCII bytes of `f"{header_b64}.{payload_b64}"`, before
   parsing or trusting any claim. **The `kty` check lives inside `verify_signature`**, at
   `_check_kty`: the JWK's `kty` must match the algorithm family, `RS*`/`PS*` requiring
   `RSA`, `ES*` requiring `EC`, `EdDSA` requiring `OKP`, `HS*` requiring `oct`. That is
   what blocks the classic forgery where an attacker signs with HS256 using the provider's
   RSA public key as the HMAC secret. It sits inside `verify_signature` rather than in
   `decode` so that every caller of `verify_signature` gets it, including the tests that
   call it directly and any future caller that does not go through `decode`. Moving it out
   into `decode` would weaken the defense to a convention.
5. Only after signature verification, validate claims: `exp`, `nbf`, `iat`, `aud`, `iss`,
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

`exp`, `nbf` and `iat` go through one reader that refuses anything that is not a finite
number. `bool` is rejected explicitly, since it is an `int` subclass and a boolean
timestamp is always malformed. An integer beyond the float range, such as `10**400`, is
refused rather than allowed to raise `OverflowError`, which would escape the module as
something other than an `AuthenticationError` and break the contract every caller relies
on. Together with the `Infinity`/`NaN` refusal at the parser, this closes the token that
never expires: `{"exp": 1e400}` is ordinary JSON syntax that Python parses to a float
infinity, and upstream accepts it.

**Options.** `decode` takes a jose-shaped `options` dict merged over `_DEFAULT_OPTIONS`,
which is `verify_signature`, `verify_exp`, `verify_nbf`, `verify_aud` and `verify_iss`, all
defaulting to `True`. Unknown keys are ignored rather than rejected, matching the
permissiveness callers expect from that API shape. `verify_signature: False` is a testing
and debugging switch and nothing else: it accepts every token unconditionally, including
one with no valid signature at all. Nothing in the library sets it.

All failures raise subclasses of `armasec_lite.exceptions.AuthenticationError` so the
existing `handle_errors` wrapping in `TokenDecoder` continues to work unchanged.

### `http.py`

```python
def get_json(url: str, *, timeout: float = 10.0) -> dict: ...
```

Built on `urllib.request`, with hardening upstream's `httpx.get` call does not have:

- A scheme guard refusing anything that is not `http` or `https`. This is the one item on
  this list that looks redundant with the URL validation in `schemas.py` and is not.
  `urllib.request.build_opener()` installs `FileHandler` among its defaults, so an opener
  will happily read a `file://` URL and return its contents. `jwks_uri` arrives inside a
  document fetched from the network and is then fetched in turn, so a `file://` value
  reaching this call would turn a JWKS fetch into an arbitrary local file read whose
  contents become the key set deciding who is authenticated. The guard belongs here, at
  the call that actually opens the URL, in addition to the model that parses it.
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

Pydantic `BaseModel` types, as upstream has them (see Decision 6). Upstream's field
definitions are kept unless a change is called for below.

- `JWK`: upstream requires `alg`, `e`, `kid`, `kty`, `n`. That is wrong for non-RSA keys,
  which have no `n` or `e`, so a provider serving an EC or OKP key in its JWKS makes
  upstream fail to parse the document at all. Here only `kty` and `kid` are required;
  `n`/`e`, `crv`/`x`/`y` and `k` are optional and validated per key type at use time in
  `jwt.py`, where the algorithm is known. `model_config = ConfigDict(extra="allow")`.
- `JWKs`: `keys: list[JWK]`.
- `OpenidConfig`: `issuer` and `jwks_uri`. Only `jwks_uri` keeps upstream's `AnyHttpUrl`.
  **`issuer` is a plain `str`, deliberately not `AnyHttpUrl`**, validated by `urlparse`
  for an http or https scheme and a host and then returned byte-for-byte. Pydantic's URL
  type normalizes, and one of its normalizations appends a trailing slash to a bare-host
  URL, so a provider publishing `https://auth.example.com` as its issuer would be stored
  as `https://auth.example.com/` and would then fail the exact string comparison against
  the `iss` claim in every token it mints. That is the mechanism Decision 3 depends on:
  `verify_issuer=True` is only safe to default on if the value it compares survives
  unmodified. Anyone "fixing" this field back to `AnyHttpUrl` breaks real providers, and
  the failure looks like a provider problem rather than a library one.
  `jwks_uri` arrives inside a remote document that is then fetched, so a field validator
  pins its scheme. It **defaults to requiring https** and relaxes only when the validation
  context says otherwise: `openid_config_loader.py` passes `require_https=False` for a
  domain configured with `use_https=False`, and a caller that forgets the context gets the
  strict behavior rather than a silently accepted plaintext JWKS endpoint. Failing closed
  is the point. `extra="allow"`.
- `DomainConfig`: upstream's `domain`, `audience`, `ignore_audience`, `algorithm`,
  `use_https`, `match_keys` and `permission_extractor`, plus the new
  `verify_issuer: bool = True`. Two fields change from upstream. **`domain` is required**,
  with no default, and additionally rejects a whitespace-only value. Upstream defaults it
  to `""`, which builds the discovery URL `https:///.well-known/openid-configuration` and
  fails at request time with a message naming neither the domain nor the configuration. It
  has to be required rather than merely validated, because pydantic v2 does not run
  validators over field defaults: with a default present, `DomainConfig()` would still
  construct. `Armasec.__init__` checks for the keyword before constructing, so `Armasec()`
  with no domain still raises its own 422 rather than a `ValidationError`. **`algorithm` is
  checked against `SUPPORTED_ALGORITHMS` at construction**, so a typo fails where it was
  written instead of configuring a route that refuses every token it is ever shown with a
  message about the token.

`PermissionMode` becomes `class PermissionMode(str, Enum)` with `ALL = "ALL"` and
`SOME = "SOME"`, preserving upstream's `AutoNameEnum` string values. `auto-name-enum` is
still dropped; only the two-line enum replaces it.

### `token_payload.py`

A pydantic `BaseModel`, unchanged in shape from upstream: `sub`, `permissions`, `expire`,
`client_id`, `original_token`, with `model_config = ConfigDict(extra="allow")`.

`extra="allow"` is what gives arbitrary-claim attribute access, which the library depends
on in two places: `match_keys` does `getattr(token_payload, key)`, and the documented
plugin example reads `.email`. Upstream's `AliasChoices` handling is kept as it is, so
`exp` populates `expire` and `azp` populates `client_id`.

Because this is a pydantic model, `model_dump()`, `model_dump_json()` and use as a FastAPI
`response_model` all work exactly as they do upstream. `to_dict()` is preserved as well,
since upstream defines it and consumers may call it.

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
403, `PayloadMappingError` 500. The eight `jwt.py` errors (`InvalidTokenError`,
`InvalidSignatureError`, `InvalidAlgorithmError`, `InvalidKeyError`,
`ExpiredSignatureError`, `ImmatureSignatureError`, `InvalidAudienceError`,
`InvalidIssuerError`) all subclass `AuthenticationError`, so every way a token can fail
verification is a 401. `InvalidTokenError` covers the malformed shapes, and
`InvalidKeyError` covers a JWK missing a member its key type requires, which is a 401 whose
fault usually lies with the provider's JWKS rather than with the token.

`exceptions.py` adds one more: **`UnknownKeyIdError`, an `AuthenticationError` subclass
raised specifically to be caught.** It carries the same 401 as its parent, so nothing
changes for a client if it reaches the handler unhandled, but `TokenSecurity` catches it to
decide whether a JWKS refresh is worth attempting. It is public because a consumer writing
its own `except` clauses around the decoder will meet it. See `token_decoder.py` and
`token_security.py` below for the flow it drives.

### `openid_config_loader.py`

`OpenidConfigLoader` keeps its upstream constructor and its lazy `config` and `jwks`
properties. Three additions:

**Process-wide cache.** A module-level `dict` keyed by `(domain, use_https)` returns a
shared loader via `OpenidConfigLoader.get(domain, use_https, debug_logger)`, guarded by a
module-level `threading.Lock`. Without this, an app with four distinct `lockdown()` scope
combinations against one domain performs four independent loads, or eight HTTP requests.
With it, two, and it stays two however many scope sets are added.

**Per-loader fetch lock.** Each loader holds its own `threading.Lock` around the cold
config and JWKS fetches. Upstream has no lock, so N concurrent first requests to the same
route all fetch simultaneously. This is a `threading.Lock` rather than an `asyncio.Lock`
deliberately: an `asyncio.Lock` binds to the loop that first awaits it and goes stale
across test loops and multi-loop setups. Since every path that takes the lock, the cold
load and the JWKS refresh alike, runs in an executor thread (see `token_security.py`), the
worker thread holds the lock and the event loop thread is never blocked on it. The lock is
not reentrant and the `config` property takes it, so `jwks` and `refresh_jwks` read
`config` before entering the lock; moving either read inside would self-deadlock.

**Rate-limited JWKS refetch.** `refresh_jwks()` refetches the JWKS when a token presents
an unknown `kid`, but at most once per `JWKS_REFRESH_INTERVAL` seconds (default 300),
tracked with `time.monotonic()`. Upstream caches the JWKS forever, so a provider key
rotation 401s every request until the process restarts. The rate limit prevents a flood of
unknown-`kid` tokens from turning into a flood of outbound requests.

**The clock is stamped in a `finally`, so it advances even when the fetch fails.** This is
the only part of the rate limit that matters for the case it exists to defend. `kid` comes
from the token's unverified header, so it is attacker-chosen: an unauthenticated caller can
present an endless stream of tokens with distinct unknown `kid` values. If the clock were
stamped only on success, a provider returning errors would leave it un-advanced and every
one of those tokens would produce another outbound request, turning a provider outage into
an amplification vector aimed at the provider. Advancing on the failure path costs one
delayed recovery at worst, bounded by `JWKS_REFRESH_INTERVAL`.

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

**`get_decode_key` never refreshes. It reports.** It searches `jwks.keys` for a matching
`kid` and, on a miss, raises `UnknownKeyIdError` when a `jwks_refresher` is configured, or
a plain `AuthenticationError` when none is, since without a refresher there is nothing a
caller could do about it. It does not call the refresher itself, and this is the whole
point of the design: `get_decode_key` runs on the event loop, `kid` comes from the token's
unverified header, and a blocking refetch here would be a whole-process stall for the
length of the fetch timeout that any unauthenticated caller could trigger at will.

The refresh is a separate public method, `refresh_keys()`, which replaces the key set with
a freshly fetched one and is a no-op when no `jwks_refresher` was configured, so a caller
can invoke it unconditionally after an unknown `kid`. It does blocking network work and
must be run off the event loop. `TokenSecurity` is the caller and does exactly that, in an
executor; see `token_security.py`. A refetch failure raises out of `refresh_keys` and the
current key set is left untouched.

`decode` calls `armasec_lite.jwt.decode` in place of `jose.jwt.decode`, applies
`permission_extractor` when configured, and builds the `TokenPayload`.
`extract_keycloak_permissions` is carried over verbatim.

### `token_manager.py`

`unpack_token_from_header` drops `fastapi.security.utils.get_authorization_scheme_param`
in favor of a two-line `partition(" ")`, keeping identical behavior: require the header,
require both a scheme and a token, require the scheme to be `bearer` case-insensitively.
`extract_token_payload` passes `verify_issuer` and the openid config's `issuer` through to
the decoder alongside `audience`.

`__init__` gains `verify_issuer: bool = True` to carry Decision 3 down from `DomainConfig`.
It also still accepts upstream's `decode_options_override`, and stores it, but **never
consults it**. The decoder holds its own options and those are the ones that take effect.
The argument is kept only so an upstream construction site does not become a `TypeError`,
and it is called out here because a silently inert security-relevant argument is a trap:
someone passing `decode_options_override={"verify_aud": False}` here would get audience
checks anyway, with nothing to indicate the setting was ignored. Options belong on
`TokenDecoder`.

### `token_security.py`

Behavior matches upstream, with the async fix. `__call__` checks the warm cache first and
takes a fully synchronous path with zero executor overhead when the managers are already
loaded and the token's `kid` is one of the cached keys. The cold path does:

```python
loop = asyncio.get_running_loop()
await loop.run_in_executor(None, self._load_all_managers)
```

Upstream calls sync `httpx.get` from inside `async def __call__`, blocking the event loop
on every cold load. This fixes that.

The one other blocking path gets the same treatment, and it is the reason
`TokenDecoder.get_decode_key` reports an unknown `kid` rather than recovering from it.
`__call__` catches `UnknownKeyIdError` and drives `_refresh_and_retry` through the
executor, **once per request**. `_refresh_and_retry` calls `refresh_keys()` on every
manager's decoder, not only the ones that reported a miss: they all failed to decode the
token, so
none of their key sets is known good, and each loader's own rate limit bounds the outbound
traffic at one refetch per domain per `JWKS_REFRESH_INTERVAL` however often this runs. It
then retries the extraction exactly once. **The retry is not itself retried.** A second
`UnknownKeyIdError` propagates as an ordinary 401, so an attacker-chosen `kid` can never
drive a loop.

`_extract_token_payload_from_manager` decides which error the client sees, and the decision
is what makes the retry reachable at all when more than one domain is configured. It walks
the managers, and:

- an `UnknownKeyIdError` from any manager is remembered and wins over everything else, so a
  configuration where domain A cannot decode the token for an ordinary reason and domain B
  reports an unknown `kid` still reaches the refresh path rather than 401ing on A's error;
- any other decode error is remembered as the last real failure rather than discarded, and
  re-raised at the end so its own status and detail reach the client. A token that fails
  with a `PayloadMappingError` (500) should not be reported as a generic "no matching JWK";
- a `match_keys` refusal deliberately bypasses all of this. `_check_match_keys` runs
  outside the loop's `try`, after a manager has successfully decoded the token, so its
  `AuthorizationError` (403) propagates immediately instead of being demoted to a 401 by
  the fallthrough. The token verified; it simply is not for this caller, and those are
  different answers.

`_check_match_keys` compares booleans by identity, not equality. `1 == True` in Python, so
a token carrying `1` where a `match_keys` entry requires `True` would otherwise pass an
authorization check it should fail. Strings and numbers compare by equality, and anything
else is treated as a collection and checked for intersection.

`_load_all_managers` skips a domain whose manager fails to build rather than failing the
whole load, so one unreachable or misconfigured provider does not take down authentication
against every other configured domain. It errors only when every domain failed. The
consequence is worth stating because it is not obvious: managers are built once and cached
for the process lifetime, so **a provider that is down at first-request time stays out of
rotation until the process restarts**, even after it recovers. That is the deliberate trade
against the alternative, which is retrying the cold load on every request and handing an
unauthenticated caller a way to force it.

`_load_all_managers` also builds its list locally and assigns it in one statement.
Concurrent first requests all pass the empty-cache check in `__call__`, so appending in
place would leave N copies of every manager and would expose a half-built list to a
concurrent request.

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
config fetch and one JWKS fetch; four distinct `lockdown()` scope sets against one domain
produce two HTTP calls total; a rotated `kid` triggers exactly one refetch and a second
unknown `kid` within the interval triggers none. Four is what the end-to-end test actually
exercises, and the property it demonstrates is that the count is independent of the number
of scope sets, not that it holds at some particular number. Every place this claim is
repeated says four for that reason: a number that appears in prose but not in a test reads
as tested when it is not.

**Guard tests.** Two claims this spec makes are enforced by tests rather than by
convention, and the tests are the contract. `tests/unit/test_packaging.py` asserts the
runtime dependency list is exactly the three declared here and AST-walks every module under
`armasec_lite/` for banned imports (`jose`, `buzz`, `snick`, `auto_name_enum`, `pluggy`,
`respx`, `httpx`), so "three dependencies" is a checked invariant and not a claim that
decays the first time someone adds an import. `.github/workflows/deploy-docs.yml` similarly
cross-checks the module list in `docusaurus.config.ts` against the number of generated
reference pages, so the documented module list cannot silently drift from what the site
publishes. Deleting either guard deletes the enforcement of something this spec asserts as
fact.

## Differences from upstream

This is the authoritative list. The README's migration section and the docs site's
migration page both derive from it, and neither may add to it or contradict it.

An earlier draft of this spec claimed there were "two differences that can change behavior
on upgrade". That was wrong: review found several more, the largest being that replacing
pydantic with dataclasses would have broken `model_dump()`, `model_validate()`,
`response_model=TokenPayload` and `except pydantic.ValidationError` for every consumer.
That finding is what led to Decision 6, which keeps pydantic and removes that break
entirely. The table below is what remains after it.

**Requires action from an integrator:**

| Difference | What breaks | Fix |
| --- | --- | --- |
| Import name is `armasec_lite` | Every import line | A scoped `sed` over the project's own sources |
| `verify_issuer` defaults to `True` | Routes 401 when the provider's discovery `issuer` does not exactly match the `iss` it mints, most often over a trailing slash | Correct the provider, or `DomainConfig(verify_issuer=False)` |
| Errors no longer derive from py-buzz | `except buzz.Buzz` stops catching `ArmasecError` | Catch `armasec_lite.exceptions.ArmasecError` |
| The pytest fixtures live behind the `[test]` extra | A ported test suite cannot import the fixtures from a plain install, because upstream forced `pytest` into every install and this does not | Depend on `armasec-lite[test]` |
| The OIDC loader cache is process-wide | Tests that expect per-instance provider state now share it | `openid_config_loader.clear_cache()`, or the `mock_openid_server` fixture, which calls it automatically |
| The CLI is not included | `armasec` console script is gone | Out of scope; see Non-goals |
| `exp`, `nbf` and `iat` must be finite numbers, and JSON `Infinity`/`NaN` are refused outright | A token carrying `"exp": 1e400`, or a payload containing the non-standard JSON constants, was accepted upstream and is now a 401 | Nothing, unless a provider is minting such tokens, in which case fix the provider: an `exp` of infinity is a token that never expires |

**Requires no action, listed so the API diff is complete:**

| Difference | Why it is safe |
| --- | --- |
| `TokenDecoder` gained an optional `jwks_refresher` keyword argument | Purely additive; the first positional argument is still `JWKs`, so existing construction sites are unaffected |
| Models remain pydantic | `model_dump()`, `model_validate()`, `response_model=` and `pydantic.ValidationError` all keep working, as upstream (Decision 6) |
| `JWK` no longer requires `n` and `e` | Strictly more permissive. Upstream fails to parse a JWKS document containing an EC or OKP key; this parses it |
| `handle_errors` re-raises an `ArmasecError` subclass unchanged instead of re-wrapping it | Deliberate, and a deviation from py-buzz and from this spec's own prose above. Re-wrapping would let the `PayloadMappingError` block in `TokenDecoder.decode` swallow a genuine `AuthenticationError` and turn a 401 into a 500. The outermost handler still maps anything that is not an `ArmasecError` to the wrapper type, so the wrapping contract holds for every error that is not already ours |
| `DomainConfig.domain` is required and must be non-empty, where upstream defaults it to `""` | An empty domain builds the discovery URL `https:///.well-known/openid-configuration` and fails at request time with an error that names neither the domain nor the configuration. The only caller that relied on the empty default, `Armasec.__init__`, checks for the keyword before constructing, so `Armasec()` still raises its own 422 |
| `DomainConfig.algorithm` is checked against the supported set at construction | Strictly earlier failure. A typo previously configured a route that refused every token it was ever shown, with a message about the token |
| `UnknownKeyIdError` is a new public exception type | An `AuthenticationError` subclass carrying the same 401. Nothing that caught `AuthenticationError` stops catching it, and it exists so `TokenSecurity` can tell "no key matched" apart from every other 401 and refresh the JWKS in response |
| The RFC 7515 unsecured JWS shape returns `InvalidAlgorithmError` | Still a 401, still an `AuthenticationError` subclass. The status is unchanged; only the error type and message are more specific, which is what makes an `alg: none` attempt legible in a log rather than indistinguishable from a truncated token |

Upstream armasec **3.x** is the migration source. Migrating from 2.x is out of scope and
untested; a 2.x consumer should upgrade to 3.x first and confirm their application works.
Dependency floors of the form `armasec>=2.0.0` admit both majors, so a reader should check
what they actually resolved rather than trusting the floor.

## Documentation

- `README.md`: the upstream quickstart, adjusted for the import name, plus a dependency
  comparison table and a migration section covering the "Differences from upstream" table
  above.
- `examples/`: `basic.py`, `two_domains.py`, `match_key_value_pairs.py` and `plugin.py`
  ported from upstream. The plugin example drops its `loguru` and `pydantic` imports.
- Docstrings on all public API, matching upstream's style, since they are the API
  reference, and since the docs site generates its reference section from them.
- `docusaurus/`: the full documentation site, specified below.

## Benchmarks

### Ground rule

Every number that appears in the documentation site is produced by a script in
`benchmarks/` and read from a committed JSON result file. No figure is hand-authored. If a
benchmark shows `armasec-lite` losing on a dimension, the chart shows it losing. A
performance claim that cannot be regenerated by running `just bench` does not go in the
docs.

Each result file records provenance alongside its measurements: UTC timestamp, hostname,
CPU model, Python version, and the resolved versions of both packages under test. Charts
render that provenance as a caption, so a reader can tell what the numbers describe.

Request-model behavior is measured black-box, through Docker, by the integration
comparison harness specified in the next section. That is where cold-start latency,
event-loop blocking, OIDC request counts and rotation recovery come from. Measuring a
blocking event loop from outside the process is both more honest and more convincing than
instrumenting it from within, and it removes any question of the measurement perturbing
the thing measured.

The `benchmarks/` tree holds only what does not need two running services.

```
benchmarks/
  results/                  committed JSON, one file per benchmark
  bench/
    __init__.py
    provenance.py           machine/version metadata shared by all benchmarks
    footprint.py            dependency count, installed size, image size, source LOC
    warm_decode.py          steady-state token validations per second
    security_matrix.py      attack vectors run against both implementations
    charts.py               result JSON -> Plotly figure specs
```

`footprint.py` installs each package into its own throwaway `uv venv` and inspects it.
Comparing the two libraries inside one environment is not possible, since they resolve
incompatible dependency sets, and it would understate the difference anyway.

### Measurements

**Footprint.** Runtime distribution count, total transitive distribution count, installed
`site-packages` size in bytes, built container image size, and source lines of code. LOC
is counted as non-blank, non-comment lines via `tokenize`, reported both for the library
itself and for the library plus the dependencies unique to it, since "code you actually
ship" is the honest metric. Image size is read from `docker image inspect` on the two
application images the integration harness builds, which makes it a real deployment
number rather than a proxy for one.

**Warm decode.** Steady-state token validations per second on an already-loaded cache,
`armasec_lite.jwt` against `jose.jwt`, with warmup discarded and the median of repeated
runs reported. Expectation is rough parity, since both end up in the same `cryptography`
primitives. Whatever it measures is what ships, including a loss.

**Security matrix.** The attack suite from the Testing section run against both
implementations, producing a per-vector pass or fail. Several vectors will pass for both,
because jose does defend most of them. The honest story here is not that upstream is
insecure; it is that `armasec-lite` enforces `verify_issuer` and JWK-type-versus-algorithm
matching at its own boundary, and has explicit tests proving each defense rather than
inheriting them from a transitive dependency. The matrix presents it that way.

## Integration comparison harness

Two real FastAPI services under Docker Compose, one on upstream `armasec==3.0.3` and one
on `armasec-lite`, authenticating against **a real Keycloak** and driven by a load
generator. Everything about the request model is measured from the outside, over the
network, against running servers.

An earlier draft of this section specified a mock OIDC provider written for the harness.
That is superseded. A comparison against a provider we wrote ourselves proves less than a
comparison against the provider these libraries actually face, and Keycloak is what
`vantage-api`, `vantage-mcp-infra` and `slurm-mcp` authenticate against, so the harness
exercises the real migration path rather than an approximation of it.

```
legacy_comparison_compose/
  docker-compose.yaml
  Dockerfile.app            one image, parameterized by build arg
  Dockerfile.bench
  realm/
    armasec-realm.json      imported at Keycloak start
  app/
    main.py                 ONE app module, import selected by env var
  proxy/
    main.py                 counting and latency-injecting reverse proxy
  bench/
    run.py                  scenario driver
    scenarios.py
    report.py
  results/                  committed JSON
  test_parity.py            pytest: identical responses from both services
```

| Service | What it is |
| --- | --- |
| `keycloak` | `quay.io/keycloak/keycloak`, `start-dev --import-realm`, realm imported from `realm/armasec-realm.json` |
| `oidc-proxy` | A small asyncio reverse proxy in front of Keycloak. Counts requests per path, injects a configurable delay, and exposes `/__stats`, `/__latency` and `/__reset` |
| `app-legacy` | FastAPI on upstream `armasec==3.0.3` |
| `app-lite` | FastAPI on `armasec-lite` |
| `bench` | The load generator and scenario driver |

### Why a proxy sits in front of Keycloak

Three things the scenarios need that Keycloak cannot provide directly, and one trap.

**Exact request counting.** The headline caching claim is that N distinct `lockdown()`
scope sets against one domain cost 2 HTTP calls rather than 2N. That has to be counted at
the wire, not inferred. Keycloak has no per-path request counter, so the proxy keeps one.

**Injectable latency.** S5 sweeps provider latency to show how cold-start cost scales with
it, and S4's event-loop blocking is only visible when the provider is slow enough to
matter. A real Keycloak on the same host answers in single-digit milliseconds, which would
hide the effect being measured. The proxy adds a controlled delay.

**Fault injection.** The rate-limit fix depends on a failing provider still advancing the
refresh clock. The proxy can return 500s or hang on demand, which Keycloak will not do for
us.

**The trap: `KC_HOSTNAME` must point at the proxy.** Keycloak's discovery document
advertises absolute URLs, and its `jwks_uri` is one of them. Left at its default, Keycloak
would advertise its own address, the application would fetch the JWKS directly from
Keycloak, and every JWKS request would bypass the proxy and go uncounted. Setting
`KC_HOSTNAME` to the proxy's address makes discovery advertise proxy URLs, so both fetches
traverse the proxy. It also keeps `issuer` consistent between the discovery document and
the `iss` claim in minted tokens, which matters because `armasec-lite` verifies the issuer
by exact string equality and upstream does not.

That last point is worth stating plainly: **the harness is a live test of the most
consequential deliberate behavior difference between the two libraries.** A Keycloak behind
a proxy is exactly the deployment shape where issuer mismatches occur in practice.

### Realm

`realm/armasec-realm.json` defines realm `armasec` with:

- A confidential client `armasec-api` with service accounts and direct access grants
  enabled, so the bench can mint tokens by both client credentials and password grant.
- Client roles `read:stuff`, `write:stuff` and `admin:stuff`, assigned to a service account
  and to a test user, so scope checks have something real to check.
- An **audience mapper** putting `armasec-api` into `aud`. Keycloak's default audience is
  `account`, which would make the audience check vacuous.
- A second client `other-api` with its own audience, so a scenario can prove that a token
  minted for one API is rejected by the other.

Keycloak places client roles under `resource_access.<client>.roles`, not in a top-level
`permissions` claim, so both applications configure
`permission_extractor=extract_keycloak_permissions`. That is the realistic configuration
for a Keycloak deployment and it exercises a feature both libraries implement.

### Fairness

The comparison is only worth publishing if the sole difference between the two services is
the auth library. The harness enforces that:

- **One app module.** `app/main.py` is a single file. It selects its import at startup
  from an `ARMASEC_IMPL` environment variable and builds the identical route table either
  way. There is no second copy of the app to drift.
- **One Dockerfile**, parameterized by a build argument that picks which package to
  install. Same base image, same Python version, same uvicorn version and invocation, same
  worker count, same loop implementation.
- **Equal resource limits.** Identical `cpus` and `mem_limit` on both app services in
  `docker-compose.yaml`.
- **Interleaved trials.** Each scenario alternates legacy and lite runs rather than
  running all of one then all of the other, so machine drift, thermal throttling and
  noisy neighbors affect both arms equally.
- **Repeated trials with cold restarts.** Cold-start scenarios `docker compose restart`
  the app service between repetitions. Five repetitions by default; the median is
  reported and the spread is recorded in the result file.
- **Open-loop load generation.** The driver issues requests at a fixed arrival rate rather
  than waiting for each response before sending the next. A closed-loop generator stops
  sending while the server is stalled, which hides exactly the blocking behavior this
  harness exists to measure. This is the coordinated-omission problem and avoiding it is
  the difference between a meaningful latency number and a flattering one.

### Scenarios

| ID | Scenario | Measures |
| --- | --- | --- |
| S1 | Cold start, one route, concurrency 1 to 64 | p50, p95, max time to first response |
| S2 | Cold start, N distinct `lockdown()` scope sets, N in 1, 5, 10, 20 | OIDC requests counted at the proxy, wall time until all routes warm |
| S3 | Warm steady state, sustained open-loop load | requests per second, latency percentiles |
| S4 | Unauthenticated `/health` hammered *during* a cold auth load | `/health` latency, which exposes event-loop blocking entirely from outside the process |
| S5 | Provider latency sweep at 0, 50, 200, 500 ms | cold-start sensitivity to provider latency |
| S6 | Keycloak realm key rotation mid-run | error count after rotation, time to recovery |
| S7 | Malformed, expired, wrong-audience, wrong-issuer, insufficient-scope tokens | HTTP status from each service |
| S8 | Provider returning 500s while unknown-`kid` tokens arrive | outbound requests counted at the proxy |

S4 remains the central result. Upstream calls synchronous `httpx.get` from inside
`async def __call__`, so during a cold load the event loop cannot serve anything, including
routes that have no authentication at all. A client watching `/health` sees that directly.
No instrumentation, no profiler, no claim the reader has to take on faith.

S6 is a feature difference rather than a performance one and is labeled as such in the
docs. It now rotates **real Keycloak realm keys** through the admin API rather than
swapping a fixture, which is a materially stronger demonstration: upstream caches the JWKS
for the process lifetime and should 401 until restarted, while `armasec-lite` should
recover within its refetch interval.

S7 asserts **parity**: both services must return the same status for the same request,
except for the documented `verify_issuer` difference, which gets its own explicit case. Any
other divergence is a bug in `armasec-lite`.

S8 exists because the final review found a real vulnerability there: a failing provider
used to leave the refresh clock un-advanced, so every unknown-`kid` token produced another
outbound request, and `kid` is attacker-chosen. The scenario asserts the outbound count
stays bounded while the provider is failing, which is the property the fix introduced (see
`openid_config_loader.py` above) and which nothing outside the unit tests currently proves.

### Parity tests

`test_parity.py` runs S7 as ordinary pytest tests, marked `integration` and skipped when
the compose stack is not up. They assert response-code equality between the two services
across the malformed-token matrix. This is the strongest available evidence for the
drop-in claim, since it tests the shipped artifact over HTTP rather than testing an
import.

`pyproject.toml` sets `testpaths = ["tests/unit"]` so a plain `pytest` run never tries to
reach Docker. Integration tests run only when asked for.

### Results and provenance

Written to `legacy_comparison_compose/results/*.json` and committed. Each file records UTC
timestamp, hostname, CPU model, kernel, Docker version, container resource limits,
repetition count, the Keycloak image digest, and the resolved versions of both libraries.
`benchmarks/bench/charts.py` reads from both `benchmarks/results/` and
`legacy_comparison_compose/results/`.

Numbers from this harness describe one machine running Docker, and the docs say so. The
ratios between the two arms are the meaningful part, not the absolute milliseconds.

## Documentation site

`docusaurus/`, seeded from `vantage-mcp-infra/docusaurus` so it matches the other Vantage
spoke sites: `@vantagecompute/docusaurus-theme`, `@docusaurus/theme-mermaid`,
`docusaurus-plugin-llms`, and `@vantagecompute/docusaurus-plugin-pydoc` as an ordinary npm
dependency, pinned `^0.1.1` in `docusaurus/package.json`. An earlier draft vendored the
pydoc plugin as a git submodule under `docusaurus/vendor/`, matching what
`vantage-mcp-infra` did at the time. It is published to npm now, so there is no submodule,
no `.gitmodules`, and nothing for a CI checkout to authenticate against. The version pin is
load-bearing: 0.1.1 is the release that renders Google-style `Args:`, `Returns:` and
`Raises:` sections as lists rather than as run-on paragraphs.

Config changes from the seed: title `armasec-lite`, `baseUrl`
`/developer/armasec-lite/`, `organizationName`/`projectName` retargeted, a single pydoc
plugin instance pointed at the `armasec_lite` package, and navbar and footer links
rewritten. `getProjectVersion()` and `staticDir` come from the theme unchanged.

### Pages

```
docs/
  index.md                        Overview
  installation.md
  quickstart.md
  migration.md                    porting from armasec
  architecture/
    index.md
    request-lifecycle.md
    caching.md                    loader cache, locking, JWKS rotation
    threading-model.md            why the executor hop exists
  security/
    index.md
    jwt-verification.md           the verification order and its rationale
    threat-model.md               what is defended, what is out of scope
  benchmarks.md                   the charts
  comparison.md                   the legacy comparison harness and its scenarios
  testing.md                      generated test results
  api-reference/                  autogenerated by the pydoc plugin, not committed
  contributing.md
```

`index.md` states the project's purpose, the dependency reduction table, and the behavior
differences from upstream that require action from an integrator, then links onward to the
migration page for the complete list. It leads with what the project is, not with the
benchmark numbers.

### Charts

Figure specs are Plotly JSON written to `docusaurus/static/charts/*.json` by
`benchmarks/bench/charts.py`, which reads `benchmarks/results/*.json` and nothing else.
The generator fails loudly if a result file is missing rather than emitting a chart with
absent series.

Rendering uses a `src/components/PlotlyChart` React component wrapping
`react-plotly.js` in `@docusaurus/BrowserOnly`, since Plotly touches `window` and breaks
static rendering otherwise. The bundle is `plotly.js-cartesian-dist-min`, which covers bar,
scatter and heatmap at roughly a third the size of the full distribution. The component
reads `useColorMode()` and selects a light or dark template, so charts follow the site
theme rather than sitting on a white rectangle in dark mode.

Charts:

| Chart | Type | Source |
| --- | --- | --- |
| Dependency count and installed size | Grouped bar | `benchmarks/results/footprint.json` |
| Container image size | Bar | `benchmarks/results/footprint.json` |
| Source lines of code shipped | Grouped bar | `benchmarks/results/footprint.json` |
| Cold-start latency versus concurrency | Grouped bar, p50 and p95 | `legacy_comparison_compose/results/s1_cold_start.json` |
| OIDC requests per lockdown scope set | Bar | `legacy_comparison_compose/results/s2_scope_sets.json` |
| Warm steady-state throughput and latency | Grouped bar | `legacy_comparison_compose/results/s3_warm.json` |
| `/health` latency during cold auth load | Line over time | `legacy_comparison_compose/results/s4_loop_block.json` |
| Cold start versus provider latency | Line | `legacy_comparison_compose/results/s5_provider_latency.json` |
| Errors and recovery after key rotation | Line over time | `legacy_comparison_compose/results/s6_rotation.json` |
| Outbound requests while the provider is failing | Line over time | `legacy_comparison_compose/results/s8_failing_provider.json` |
| Security posture by attack vector | Heatmap | `benchmarks/results/security_matrix.json` |

The S4 chart is the headline. Plotting unauthenticated `/health` latency on a time axis,
with the cold auth load marked, shows the legacy service's unrelated route stalling for
the duration of its OIDC fetch while the lite service's does not. It is a black-box
measurement of event-loop blocking that needs no explanation of what an event loop is.

Warm decode microbenchmark results are reported as a table on `benchmarks.md` rather than
a chart. If the result is rough parity, a bar chart of two near-identical bars invites a
misreading that a table does not. S3, which measures end-to-end warm throughput through
the real services, does get a chart.

Response-code parity from S7 renders as a table, since every cell should read "identical"
and a chart of that would be theater.

Every chart caption carries the provenance line from its result file, and `benchmarks.md`
opens by stating how to regenerate the data.

### Task runner

A `justfile` at the repository root, following the convention in the sibling Vantage
repositories.

| Recipe | Action |
| --- | --- |
| `just test` | unit suite only, no Docker |
| `just test-cov` | the unit suite with coverage |
| `just lint` | `ruff check`, `ruff format --check` and `mypy` |
| `just compare-legacy` | the full legacy comparison, described below |
| `just bench` | the non-Docker microbenchmarks in `benchmarks/` |
| `just charts` | regenerate Plotly specs from committed results |
| `just docs-build` | build the Docusaurus site |
| `just docs-dev` | run the docs site with hot reload |
| `just docs-serve` | serve an already-built site locally |
| `just docs-sdk` | regenerate the API reference from docstrings |
| `just docs-diagrams` | render the Mermaid diagrams |
| `just docs-verify` | `docs-build` and `docs-diagrams` together |

`bench` and `charts` are the two recipes this spec calls for that the justfile does not
carry yet; everything else in the table exists.

`just compare-legacy` is the single command that produces the comparison:

1. Build both application images and the proxy and bench images, and pull the pinned
   Keycloak image.
2. Record image sizes into the footprint result.
3. `docker compose up -d`, wait for all health checks, including Keycloak's realm import.
4. Run scenarios S1 through S8, interleaving legacy and lite arms, restarting app
   containers between cold-start repetitions.
5. Run `test_parity.py` against the live stack.
6. Write result JSON into `legacy_comparison_compose/results/`.
7. `docker compose down -v`.
8. Regenerate the Plotly specs in `docusaurus/static/charts/`.
9. Print a summary table to the terminal, so the run is useful without opening the docs.

The recipe fails if any scenario fails, if a parity test fails, or if a result file would
be written with a missing series. A partially successful run must not silently publish a
partial chart.

### Hub registration

The docs site is a spoke under `docs.vantagecompute.ai/developer/armasec-lite/`, following
the arrangement `vantage-mcp-infra` uses. Registration is a pull request against
`vantage-docs`, not infrastructure in this repository.

**`vantage-docs/.developer-subsites`**: append `armasec-lite`. This excludes the subtree
from the hub's own `deploy-developer` sync, so the hub's `--delete` cannot remove spoke
content.

**`vantage-docs/infra/cdk.json`**: append to `context.config.spokes`:

```json
{ "name": "armasec-lite", "repo": "armasec-lite", "repo_id": "1357572183" }
```

The numeric `repo_id` is confirmed from the GitHub API for `vantagecompute/armasec-lite`.
GitHub is moving OIDC subjects from repository names to ids, so a role naming only the old
form is refused with an error that does not say which half mismatched.

`vantage-docs/infra/lambda/auth/config.json` also carries a `spoke_names` list, but it is
**generated** by `infra/stacks/docs_stack.py` from the `spokes` context above. Editing it by
hand would be overwritten on the next synth.

Adding those two entries is what brings the `vantage-docs-spoke-armasec-lite` deploy role
into existence, scoped to `developer/armasec-lite/*`. The hub stack creates it; this
repository deploys nothing.

### Deploy workflow

`.github/workflows/deploy-docs.yml`, ported from `vantage-mcp-infra`. Triggers on
`v[0-9]+.[0-9]+.[0-9]+` tags and `workflow_dispatch`. The pattern is deliberately not
`v*`: GitHub tag filters are glob-like rather than regular expressions, and `v*` also
matched pre-releases, so a release candidate silently replaced the published site. It
installs Node 24 and a Python 3.12 interpreter (the pydoc plugin parses the source with
`ast` and never imports it, so it needs no virtualenv and no `uv sync`), builds the
Docusaurus site, assumes `secrets.DOCS_SPOKE_ROLE_ARN` via OIDC, syncs to
`s3://$DOCS_BUCKET/developer/armasec-lite/` with `--delete`, and invalidates
`/developer/armasec-lite/*`.

`--delete` is safe here for the same reason it is safe for every other spoke: the hub
excludes this subtree from its own sync, so this repository owns it alone.

Required repository variables: `DOCS_BUCKET`, `DOCS_CF_DISTRIBUTION_ID`. Required secret:
`DOCS_SPOKE_ROLE_ARN`.

The workflow additionally fails the build if the generated API reference is incomplete,
counting generated pages against the module list declared in `docusaurus.config.ts`, so a
renamed or moved module cannot silently drop pages from the site.

### Test results page

`docs/testing.md` is generated by a script that reads the JUnit XML and coverage XML from
a `pytest` run: totals by outcome, per-module coverage, and the full list of attack-suite
test names with their outcomes, so the security matrix chart can be traced to named tests.
Generated content is written into a marked region of the page so the surrounding prose is
hand-maintained. The docs build regenerates it, so it cannot go stale silently.

## Release and CI

### `ci.yml`

Runs on every pull request and every push to `main`, with `cancel-in-progress` concurrency
so a superseded push does not hold a runner. It installs `uv` at a pinned version, syncs
all dependency groups, installs `just` from the official installer (the runner image ships
none), and runs `just lint` and `just test`. It deliberately calls the justfile rather than
`ruff` and `pytest` directly, so a contributor running the same two commands locally runs
exactly what CI runs.

### `release.yml`

Publishing to PyPI uses **trusted publishing over OIDC**, so there is no API token stored
in this repository to leak or rotate. It requires one-time setup on PyPI: a trusted
publisher for the project pointing at `vantagecompute/armasec-lite`, workflow
`release.yml`, environment `pypi`. The publish and release-creation jobs are gated on the
ref being a tag, so a `workflow_dispatch` run exercises the whole build and smoke test
without burning a version number.

The package is pure Python with no compiled extensions, so one universal `py3-none-any`
wheel covers every platform. There is no build matrix.

Four parts of the workflow are load-bearing and easy to break silently:

**The PEP 440 gate.** The tag's version is checked against a practical subset of the PEP
440 grammar before anything is built. A malformed version otherwise fails at upload time,
after the tag exists and after the docs deploy may already have run. If a legitimately
exotic version is ever rejected, relax the regex rather than work around it.

**The `sed` that rewrites `version` in `pyproject.toml`.** `armasec_lite.__version__` is
`importlib.metadata.version(...)`, read at import time, so the version lives in exactly one
place and only `pyproject.toml` needs rewriting. That coupling is the thing to preserve: a
future edit that hardcodes `__version__` in the source, or that moves or reformats the
`version` line in `pyproject.toml`, breaks the `sed` or the assertion downstream of it, and
does so without any local symptom.

**The clean-venv wheel smoke test.** The built wheel is installed into a throwaway `uv
venv`, not tested in the source tree, and the installed package is asked for its
`__version__` and for every name in `__all__`. A package can pass its own test suite and
still be unusable once built, if a module is missing from the wheel or a re-export does not
resolve. Testing the source tree cannot catch that; only installing the artifact can.

**The `pytest11` entry-point check.** The same clean venv installs `pytest` and asserts
that `armasec_lite.pytest_extension` appears in the `pytest11` entry-point group. That
entry point is resolved by pytest at startup, so a broken one breaks every consumer's test
run rather than failing quietly in ours.

On a tag, the workflow then publishes to PyPI under the `pypi` environment with
`id-token: write`, and creates a GitHub release carrying the built distributions.
