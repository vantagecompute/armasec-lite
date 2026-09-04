---
title: JWT verification
sidebar_position: 1
---

This is the most important page in this documentation. `armasec_lite.jwt.decode` is the
one place in the library that does cryptography, and the order below is not an
implementation detail: it is the security core of the project and must not be rearranged.

## The six steps, in order

### 1. Structural validation

Split the token on `.`; require exactly three segments. Base64url-decode each with
computed padding, rejecting lengths that cannot be valid base64url (`len % 4 == 1`).

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

### 3. Key-type-to-algorithm consistency

Check that the JWK's `kty` matches the algorithm family: `RS*`/`PS*` require `RSA`, `ES*`
require `EC`, `EdDSA` requires `OKP`, `HS*` require `oct`.

This runs before the signature is checked because it is what blocks the classic forgery
where an attacker signs a token with HS256, using a provider's public RSA key (which is
public, by design) as the HMAC secret. Without this check, a verifier that blindly hands
whatever bytes it has to an HMAC function would accept it. Checking `kty` against the
algorithm family closes that off structurally, not by hoping the caller chose HS256
correctly.

### 4. Unrecognized `crit` header rejection

Reject any header listed in `crit` that is not recognized, per RFC 7515 section 4.1.11.

`crit` exists so an extension can force a verifier to either understand it or refuse the
token outright, rather than silently ignoring a header that changes how the token should be
interpreted. This has to happen before the signature is trusted to mean what the rest of
the code assumes it means.

### 5. Signature verification

Verify the signature over the ASCII bytes of `f"{header_b64}.{payload_b64}"`, before
parsing or trusting any claim.

This is the step everything before it exists to protect and everything after it depends
on. No claim value, including `exp`, `aud`, or `iss`, is read or trusted until the token is
confirmed to be signed by the key it claims to be signed by, under an algorithm the caller
actually allowed, with a key of the right type for that algorithm.

### 6. Claim validation

Only after signature verification succeeds, validate claims: `exp`, `nbf`, `iat`, `aud`,
`iss`, each honoring `leeway`.

Validating claims before the signature is checked would mean trusting attacker-controlled
data (the claims are inside the token an attacker sent) before establishing that the token
is genuine. Doing it last means every claim value the rest of the application ever sees has
already passed a real cryptographic check.

## Algorithm support

| Algorithm | JWK fields | Verification |
| --- | --- | --- |
| RS256 / RS384 / RS512 | `n`, `e` | `RSAPublicNumbers(e, n).public_key()`, PKCS1v15 padding |
| PS256 / PS384 / PS512 | `n`, `e` | same key, PSS with MGF1, salt length equal to digest length |
| ES256 / ES384 / ES512 | `crv`, `x`, `y` | `EllipticCurvePublicNumbers`, P-256 / P-384 / P-521 |
| EdDSA | `crv=Ed25519`, `x` | `Ed25519PublicKey.from_public_bytes` |
| HS256 / HS384 / HS512 | `k` | `hmac.new(...).digest()` compared with `hmac.compare_digest` |

Big-endian integers come from `int.from_bytes(base64url_decode(field), "big")`.

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

All failures raise subclasses of `armasec_lite.exceptions.AuthenticationError`, so the
`handle_errors` wrapping in `TokenDecoder` continues to work unchanged.
