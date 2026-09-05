---
title: Threat model
sidebar_position: 2
---

## Trust boundaries

`armasec-lite` sits between an incoming HTTP request and the route handler it protects. It
trusts two things it should not, unless it verifies them itself: the token presented on the
request, and the JWKS document it fetches to check that token against.

### Attacker-controlled

- **The token itself.** Every field in the header and the payload is attacker-supplied,
  including `alg`, `kid`, `crit`, and every claim. None of it is trusted until the checks in
  [JWT verification](./jwt-verification.md) pass, and claims specifically are not read
  until after the signature is verified.
- **The `kid` in the token header.** It selects which key from the JWKS is used to verify
  the token, but selecting a key is not the same as trusting one: the key found by `kid`
  still has to pass the `kty`-to-algorithm consistency check, and the signature still has
  to verify under it.
- **The JWKS document's contents.** This has two layers of defense, for two different
  threats. Against a compromised or spoofed endpoint, `http.py`'s `get_json` hardens the
  fetch itself: an explicit `ssl.create_default_context()` for certificate and hostname
  verification, a custom `HTTPRedirectHandler` that refuses an `https`-to-`http` downgrade
  and caps the redirect count, and a response body size cap so a hostile or compromised
  endpoint cannot exhaust memory by serving an unbounded body. That protects the channel,
  not the contents: an authentic JWKS document from the real endpoint can still be hostile
  in what it contains, so the JWT verification layer defends the contents directly. The
  `kty`-to-algorithm-family check ([JWT verification](./jwt-verification.md)) means a JWKS
  entry cannot be substituted for a weaker key type than the algorithm demands, and the
  ECDSA coordinate size used to decode a signature is derived from the **algorithm name**,
  never from the JWK's `crv` field, so a hostile JWKS cannot substitute a weaker curve than
  the algorithm the caller allowed implies.
- **`jwks_uri`.** It arrives inside a fetched remote document (the OIDC discovery
  document) and determines where key material is fetched from next, so it belongs in this
  list alongside the token and the JWKS contents rather than with the fixed configuration
  below. Its scheme is pinned to match the domain's `use_https` setting for exactly this
  reason: an unpinned `jwks_uri` would let a compromised discovery document redirect key
  fetches to an `http` endpoint even when the domain is configured for `https`.

### Not attacker-controlled

- **The domain configuration.** `DomainConfig` (`domain`, `audience`, `algorithm`,
  `use_https`, `match_keys`, `verify_issuer`, and the rest) is set by the application owner
  at startup, not derived from anything in a request.
- **The algorithm allowlist.** `algorithms` is supplied by the caller, not read from the
  token; this is what makes the `alg: none` and algorithm-confusion defenses in
  [JWT verification](./jwt-verification.md) possible in the first place.
- **The TLS connection to the JWKS endpoint, when `use_https` is left at its default.**
  Given the hardening in `http.py` above, an attacker cannot pass off an untrusted
  certificate or downgrade the connection without that hardening flagging it. This
  protection is opt-out, not load-bearing by default: `DomainConfig(use_https=False)`
  removes TLS from the fetch entirely, and everything downstream of that choice is the
  application owner's decision, not this library's defense.

## What is out of scope

Everything upstream also does not cover, and everything explicitly outside this project's
purpose: token issuance, token refresh, and any OIDC client-side flow. `armasec-lite`
validates tokens that some other system already issued; it makes no claim about the
security of that issuance path, and it establishes no identity of its own beyond what a
verified token asserts.
