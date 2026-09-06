---
id: index
title: Security
sidebar_position: 0
---

`jwt.py` is the only genuinely new code in `armasec-lite`, and the only security-critical
code in it. Everything else in the request path (header unpacking, scope checks,
`match_keys`, plugin hooks) is a direct port of upstream's logic.

## What this library defends

- **Algorithm confusion and `alg: none`.** The algorithm used to verify a token is always
  the caller-supplied allowlist, never a value read from the token itself.
- **Key-type confusion.** A JWK's `kty` must match the algorithm family before it is used
  to verify a signature, which blocks the classic forgery of signing with HS256 using a
  provider's RSA public key as the HMAC secret.
- **Unrecognized critical header extensions**, per RFC 7515 section 4.1.11.
- **Key injection through the token header.** `jku`, `x5u` and an embedded `jwk` are never
  read. A token cannot nominate the key set, the certificate chain, or the key it would
  like to be verified against; the key comes from the configured provider's JWKS and
  nowhere else.
- **Weak key material in the JWKS.** An RSA modulus below 2048 bits is refused, as RFC 7518
  section 3.3 requires, and the ECDSA curve is taken from the algorithm rather than from
  the JWK's `crv`. Both exist for the same reason: strength is decided by what the route
  agreed to accept, never by what the key material asks for.
- **Oversized and deeply nested tokens.** A token is capped at 64 KiB before any segment is
  decoded. The header has to be parsed before the signature can be checked, since `alg`
  decides what to verify with, so an unauthenticated caller controls a JSON document this
  library parses, and unbounded array nesting drives the JSON parser into recursion.
- **Signature verification before claim parsing.** No claim is parsed or trusted until the
  signature over the token has been verified.
- **Standard claim checks** (`exp`, `nbf`, `aud`, `iss`) with leeway support, and, unlike
  upstream, a default-on `iss` check against the provider's discovery document (see
  [Migration](../migration.md)).
- **Transport hardening for the OIDC HTTP calls**: a scheme guard refusing anything that is
  not `http` or `https` (`urllib`'s default opener reads `file://` URLs, and `jwks_uri`
  arrives inside a document fetched from the network), explicit certificate and hostname
  verification, a redirect handler that refuses an `https`-to-`http` downgrade and caps
  the redirect count, and a response size cap so a hostile or compromised JWKS endpoint
  cannot exhaust memory.

See [JWT verification](./jwt-verification.md) for the full verification order and
[Threat model](./threat-model.md) for what is and is not attacker-controlled.

## What is out of scope

- **Token issuance, refresh, or any OIDC client-side flow.** This library validates
  tokens; it does not mint or refresh them.
- **The `armasec` CLI** (device-code login, token cache). It needs a stdlib rewrite of its
  own dependencies (`typer`, `rich`, `loguru`, `pendulum`, `pyperclip`) and can ship later
  as a separate distribution.
- **Backwards compatibility with armasec 2.x.**
