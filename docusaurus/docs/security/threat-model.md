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
- **The JWKS document's contents**, to the extent the endpoint serving it is compromised or
  spoofed. This is why `http.py`'s `get_json` hardens the fetch itself: an explicit
  `ssl.create_default_context()` for certificate and hostname verification, a custom
  `HTTPRedirectHandler` that refuses an `https`-to-`http` downgrade and caps the redirect
  count, and a response body size cap so a hostile or compromised endpoint cannot exhaust
  memory by serving an unbounded body.

### Not attacker-controlled

- **The domain configuration.** `DomainConfig` (`domain`, `audience`, `algorithm`,
  `use_https`, `match_keys`, `verify_issuer`, and the rest) is set by the application owner
  at startup, not derived from anything in a request.
- **The algorithm allowlist.** `algorithms` is supplied by the caller, not read from the
  token; this is what makes the `alg: none` and algorithm-confusion defenses in
  [JWT verification](./jwt-verification.md) possible in the first place.
- **The TLS connection to the JWKS endpoint**, given the hardening in `http.py` above: an
  attacker cannot pass off an untrusted certificate or downgrade the connection without
  that hardening flagging it.

## What is out of scope

Everything upstream also does not cover, and everything explicitly outside this project's
purpose: token issuance, token refresh, and any OIDC client-side flow. `armasec-lite`
validates tokens that some other system already issued; it makes no claim about the
security of that issuance path, and it establishes no identity of its own beyond what a
verified token asserts.
