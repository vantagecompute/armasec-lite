---
title: JWT verification
sidebar_position: 1
---

This is the most important page in this documentation. `armasec_lite.jwt.decode` is the
one place in the library that does cryptography, and the order below is not an
implementation detail: it is the security core of the project.

Two orderings carry that security, and neither may be relaxed:

- **The algorithm is decided from the caller's allowlist before any key is touched.**
- **Nothing in the payload is read until the signature has verified.**

The numbered steps describe what the code does. Those two properties are what any change
has to preserve.

## The steps, in order

### 0. The unsecured JWS shape is refused

A token of the form `<header>.<payload>.` with an empty signature is the RFC 7515
unsecured JWS. It is a structurally valid serialization that carries no signature at all,
so it is rejected as an `InvalidAlgorithmError` rather than as a generic malformed token.

Reporting it under the algorithm rule is what makes an `alg: none` attempt legible in a
log, instead of indistinguishable from a truncated or corrupted token.

### 1. Structural validation

Refuse a token longer than `MAX_TOKEN_BYTES` (64 KiB). Then split it on `.`; require
exactly three segments. Base64url-decode each with computed padding, rejecting lengths
that cannot be valid base64url (`len % 4 == 1`).

The size cap comes first because a JSON segment cannot be measured until it has been
parsed, and parsing is where the cost is. Step 2 has to read `alg` to know what to verify
with, so the header is parsed before the signature is checked, by necessity, which puts a
JSON document under the control of an entirely unauthenticated caller. Unbounded array
nesting drives CPython's JSON scanner into recursion: a 267 KB token consumed 8 MB of
stack before raising. The cap is an order of magnitude above any real token, and in an
HTTP deployment the server's own header limit usually binds first, but `decode` is a
public function and does not get to assume it was reached over HTTP.

JSON parsing of a decoded segment additionally refuses `Infinity`, `-Infinity` and `NaN`,
which Python's `json` module accepts by default and which are not valid JSON.

This runs first because nothing past it is safe to do on malformed input. A token that
fails here is not a JWT at all, and every later step assumes it is looking at three
well-formed segments.

### 2. Algorithm allowlist check

Check `header["alg"]` against the caller-supplied `algorithms` allowlist. The algorithm
used to verify a signature is **never** read from the token itself.

This is the `alg: none` and algorithm-confusion defense, and it runs before any key
material is touched. A token that names an algorithm outside the allowlist is rejected
here, before the library has done any work with the key, regardless of whether the
signature would otherwise have been valid.

### 3. Unrecognized `crit` header rejection

Reject any header listed in `crit`, per RFC 7515 section 4.1.11. This library recognizes no
critical extensions, so any `crit` entry at all is a refusal.

`crit` exists so an extension can force a verifier to either understand it or refuse the
token outright, rather than silently ignoring a header that changes how the token should be
interpreted. This has to happen before the signature is trusted to mean what the rest of
the code assumes it means.

### 4. Signature verification, with the key-type check inside it

Verify the signature over the ASCII bytes of `f"{header_b64}.{payload_b64}"`, before
parsing or trusting any claim.

`verify_signature` begins by requiring that the JWK's `kty` matches the algorithm family:
`RS*`/`PS*` require `RSA`, `ES*` require `EC`, `EdDSA` requires `OKP`, `HS*` require `oct`.
That check is what blocks the classic forgery where an attacker signs a token with HS256,
using a provider's public RSA key (which is public, by design) as the HMAC secret. Without
it, a verifier that blindly hands whatever bytes it has to an HMAC function would accept
the forgery.

It lives **inside** `verify_signature` rather than in `decode` on purpose, so that every
caller of `verify_signature` gets it, including tests that call it directly and any future
caller that does not go through `decode`. Hoisting it into `decode` would turn a structural
guarantee into a convention, and conventions are what get dropped in a refactor.

This is the step everything before it exists to protect and everything after it depends
on. No claim value, including `exp`, `aud`, or `iss`, is read or trusted until the token is
confirmed to be signed by the key it claims to be signed by, under an algorithm the caller
actually allowed, with a key of the right type for that algorithm.

### 5. Claim validation

Only after signature verification succeeds, validate claims: `exp`, `nbf`, `iat`, `aud`,
`iss`, each honoring `leeway`.

Validating claims before the signature is checked would mean trusting attacker-controlled
data (the claims are inside the token an attacker sent) before establishing that the token
is genuine. Doing it last means every claim value the rest of the application ever sees has
already passed a real cryptographic check.

## Algorithm support

| Algorithm | JWK fields read | Verification |
| --- | --- | --- |
| RS256 / RS384 / RS512 | `n`, `e` | `RSAPublicNumbers(e, n).public_key()`, PKCS1v15 padding |
| PS256 / PS384 / PS512 | `n`, `e` | same key, PSS with MGF1, salt length equal to digest length |
| ES256 / ES384 / ES512 | `x`, `y` | `EllipticCurvePublicNumbers`, P-256 / P-384 / P-521 |
| EdDSA | `crv`, `x` | `Ed25519PublicKey.from_public_bytes`, `crv` required to be `Ed25519` |
| HS256 / HS384 / HS512 | `k` | `hmac.new(...).digest()` compared with `hmac.compare_digest` |

Big-endian integers come from `int.from_bytes(base64url_decode(field), "big")`.

The `crv` column is worth reading closely. For **ES** the field is not read at all: the
curve and the coordinate width come from the algorithm name, so a hostile JWKS cannot
substitute a weaker curve than the route agreed to accept. For **EdDSA** it is read and
checked, because there the algorithm name does not name a curve, and only `Ed25519` is
accepted.

### Key strength

An RSA modulus below `MIN_RSA_KEY_BITS` (2048) is refused, per RFC 7518 section 3.3. This
is not redundant with `cryptography`, which refuses to *generate* a key below 1024 bits
but reconstructs any size at all from public numbers. Without the check, a JWKS publishing
a 512 bit modulus was accepted and its signatures verified, and a modulus that small hands
the private half to anyone willing to spend an afternoon on it. It is the RSA half of the
same rule the ECDSA curve pin enforces.

### Key caching

Reconstructing a public key from its JWK members is an OpenSSL construction, and it used to
run on every request. The built keys are cached, keyed on the base64url members themselves
(and, for EC, on the algorithm, since that is what chooses the curve). Keying on the
material is the safety property: two JWKs holding the same members are the same key, and
two holding different members can never reach each other's entry. Keying on anything
looser, `kid` for instance, would let one key be verified against another's material,
which would be an authentication bypass rather than a performance bug.

## ECDSA signature encoding

JWS carries ECDSA signatures as raw `r || s`; `cryptography` expects DER. `armasec-lite`
converts with
`cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature`. The raw signature
length must equal exactly `2 * coord_bytes` or verification fails before any conversion is
attempted, which prevents short-signature manipulation.

The coordinate size is derived from the **algorithm name**, never from the JWK's `crv`
field, so a hostile JWKS document cannot substitute a weaker curve than the algorithm the
caller allowed implies.

## Claim validation details

- `exp`: fails if `now > exp + leeway`, raising `ExpiredSignatureError`.
- `nbf`: fails if `now < nbf - leeway`, raising `ImmatureSignatureError`.
- `iat`: parsed for presence and type; not used to reject, matching jose's behavior.
- `aud`: the token claim may be a string or a list of strings. When `audience` is supplied,
  membership is required. When `options={"verify_aud": False}`, the check is skipped
  entirely; this is the path `DomainConfig.ignore_audience` already uses upstream.
- `iss`: when `issuer` is supplied, exact string equality is required. See
  [Migration](../migration.md) for why this is on by default in `armasec-lite` and off by
  default upstream.

`exp`, `nbf` and `iat` all go through one reader that refuses anything which is not a
finite number. `bool` is rejected explicitly, since it is an `int` subclass and a boolean
timestamp is always malformed. An integer beyond the float range, such as `10**400`, is
refused rather than allowed to raise `OverflowError`, which would escape the module as
something other than an `AuthenticationError`. Together with the `Infinity`/`NaN` refusal
at the parser, this closes the token that never expires: `{"exp": 1e400}` is ordinary JSON
syntax that Python parses to a float infinity, and upstream accepts it.

All failures raise subclasses of `armasec_lite.exceptions.AuthenticationError`, so the
`handle_errors` wrapping in `TokenDecoder` continues to work unchanged.
