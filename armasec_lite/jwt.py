"""
A minimal JWS/JWT implementation, replacing python-jose.

This is the only security-critical module in the library. A defect here is an
authentication bypass, not a bug. Everything except the signature primitive itself is
standard library. `cryptography` provides only the verify and sign operations, because
that is the part with a long CVE history and no business being hand written.

### The verification order in `decode`

The order of the seven steps below is a security property, not an implementation detail.
Each one exists to make a specific forgery impossible, and several of them only work
because of what has already been rejected by the time they run. Reordering them, or
moving work between them, reintroduces the attack the arrangement defends against.

1. **Structure.** The token is split into three segments and a malformed serialization is
   rejected before it can reach a cryptographic operation. The one shape singled out is
   `<header>.<payload>.` with an empty signature, the RFC 7515 unsecured JWS. It is
   structurally valid and carries no signature at all, so it is reported as an algorithm
   failure rather than as a generic malformed token.
2. **Algorithm allowlist.** The algorithm is checked against the list the CALLER passed,
   never against anything the token asks for. This is the `alg: none` and
   algorithm-confusion defense, and it must stay first among the semantic checks: every
   later step derives its behavior from this already-validated algorithm name.
3. **Critical headers.** RFC 7515 section 4.1.11 requires refusing a `crit` header naming
   an extension the verifier does not understand. This implementation understands none,
   so any `crit` entry at all is a refusal.
4. **The key.** The key is chosen from the header parsed in step 1 and from nothing else.
   `decode` takes a key directly; `decode_selecting_key`, which holds the implementation
   and is what `TokenDecoder` calls, asks a caller-supplied selector for one. The selector
   is handed the header this module parsed and returns a key: it never supplies the bytes
   that key is checked against, so a caller cannot present one header for key selection
   and a different one for the signature. That is why the selector is a callback rather
   than a pre-parsed header passed in, which would trade a structural guarantee for a
   convention. Selecting a key by the unverified `kid` is safe because the key still has
   to verify the signature in step 5; choosing the wrong one only means the token fails.
   This runs after step 2 so that a token naming an algorithm the route does not permit
   cannot reach a JWKS lookup at all, and it runs whether or not `verify_signature` is
   set, so that turning the signature check off does not also drop the `kid` requirement.
5. **Signature, and the key type behind it.** `verify_signature` requires the JWK's `kty`
   to match the algorithm family (see `_REQUIRED_KTY`) before any key material is read,
   which is what blocks the classic confusion attack of signing with HS256 while the
   server holds an RSA public key and uses it as the HMAC secret. For ECDSA, the curve
   and the coordinate size come from `_EC_CURVES`, keyed on the ALGORITHM name, and never
   from the JWK's own `crv`, so a hostile or compromised JWKS cannot substitute a weaker
   curve than the one the route agreed to accept. An RSA modulus below `MIN_RSA_KEY_BITS`
   is refused here too, for the same reason the curve is pinned.
6. **Claims, and only now.** The payload is not parsed until the signature has verified.
   Nothing an attacker writes into the payload is looked at, let alone trusted, before
   the key has vouched for the bytes that carry it.
7. **Registered claim checks.** `exp`, `nbf`, `aud` and `iss` are checked against the
   caller's requirements, with `leeway` applied to the two time-based ones.

### The constants

`SUPPORTED_ALGORITHMS` is every algorithm this module can verify: RS, PS, ES and HS at
256, 384 and 512, plus EdDSA. It bounds what `verify_signature` and `encode` will act on
at all. It is not itself an allowlist for a route: `decode` takes the permitted
algorithms from its caller, and `DomainConfig.algorithm` narrows a route to exactly one.

`MAX_TOKEN_BYTES` (64 KiB) caps a token before any segment is decoded. A JSON segment has
to be parsed before it can be measured, and the header in particular is parsed before the
signature is checked, because `alg` decides what to verify with. So an unauthenticated
caller controls a JSON document this module will parse. Deep array nesting drives
CPython's JSON scanner into recursion: a 267KB token consumed 8MB of stack before raising
`RecursionError`, an amplification of roughly thirty to one. The cap is an order of
magnitude above any real token, and in an HTTP deployment the server's own header limit is
usually the binding constraint anyway, but this module does not get to assume it was
reached over HTTP.

`KEY_CACHE_SIZE` (128) bounds how many reconstructed public keys are kept. Building an RSA
key from its numbers is an OpenSSL construction that cost about a tenth of a warm decode,
and a JWKS changes only on a rotation, so the keys are cached on the base64url members
themselves. Keying on the material rather than on `kid` is the safety property: two JWKs
with the same members are the same key, and two with different members can never reach
each other's entry.

`MIN_RSA_KEY_BITS` (2048) is the smallest RSA modulus `_rsa_public_key` will build a key
from. RFC 7518 section 3.3 requires it for the RS and PS families. It is not redundant
with `cryptography`, which refuses to GENERATE a key under 1024 bits but reconstructs any
size at all from public numbers, so a JWKS publishing a 512 bit modulus was accepted and
its signatures verified. That is the same threat the ECDSA curve pin addresses, from the
other direction: strength is decided by what the route agreed to accept, never by what the
key material asks for.

### Two switches worth knowing about

`_DEFAULT_OPTIONS` exposes `verify_signature`, a switch that turns the signature check
off, so `decode(..., options={"verify_signature": False})`, and therefore
`TokenDecoder(decode_options_override={"verify_signature": False})`, accepts any token at
all. Testing and debugging only, in the same sense as `debug_exceptions` on
`TokenSecurity`: it is developer supplied rather than attacker reachable, and it is kept
because python-jose exposes it and a migrating consumer may already pass it. Nothing in
this library sets it.

`encode` is a testing aid. It exists so the pytest extension can mint tokens without a
second signing library, and it is never called on the request path. Do not use it to mint
production tokens; this library is a validator, and it makes none of the guarantees about
key handling that a real issuer owes its users.

Every failure in this module raises an `AuthenticationError` subclass, so every one of
them maps to a 401. The specific subclass names which check failed and is worth reading
in a log, but it is not intended to be relayed to the client.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable
from functools import lru_cache
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.schemas import JWK


class InvalidTokenError(AuthenticationError):
    """
    The token is not a well formed JWS.

    Raised for a bad segment count, a segment that is not base64url or not JSON, a
    payload or header that is not a JSON object, an unsupported `crit` header, and a
    time claim that is not a number. Inherits 401 from `AuthenticationError`.
    """


class InvalidSignatureError(AuthenticationError):
    """
    The token's signature did not verify against the key.

    The ordinary forgery outcome, and also what a genuine token signed by a key this
    process does not hold looks like. Inherits 401 from `AuthenticationError`.
    """


class InvalidAlgorithmError(AuthenticationError):
    """
    The token's algorithm is not permitted, or does not match the key type.

    Carries the `alg: none` refusal, the unsecured-JWS refusal, and the
    algorithm-confusion refusal from `_check_kty`. Any of these appearing in a log means
    something deliberately tried a forgery, not that a client is misconfigured. Inherits
    401 from `AuthenticationError`.
    """


class InvalidKeyError(AuthenticationError):
    """
    The JWK is missing members required by its key type.

    Points at the provider's JWKS rather than at the token, but still answers 401,
    because from the route's point of view the token could not be verified. Inherits 401
    from `AuthenticationError`.
    """


class ExpiredSignatureError(AuthenticationError):
    """
    The token's `exp` claim is in the past.

    The one failure here that a well-behaved client should answer by refreshing its
    token. Inherits 401 from `AuthenticationError`.
    """


class ImmatureSignatureError(AuthenticationError):
    """
    The token's `nbf` claim is in the future.

    Usually clock skew between the issuer and this host. `decode` takes a `leeway`
    argument for exactly that. Inherits 401 from `AuthenticationError`.
    """


class InvalidAudienceError(AuthenticationError):
    """
    The token's `aud` claim does not contain the required audience.

    A valid token for a different API. Inherits 401 from `AuthenticationError`.
    """


class InvalidIssuerError(AuthenticationError):
    """
    The token's `iss` claim does not match the required issuer.

    Compared by exact string equality against what the provider published, so a trailing
    slash on one side and not the other is a mismatch. That strictness is why
    `OpenidConfig.issuer` is kept unnormalized. Inherits 401 from `AuthenticationError`.
    """


#: base64url alphabet, without padding. Anything else in a segment is a malformed token.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_encode(raw: bytes) -> str:
    """
    Encode bytes as unpadded base64url, the encoding JWS uses for every segment.

    Args:
        raw: The bytes to encode.

    Returns:
        The encoded text, with the `=` padding stripped as JWS requires.
    """
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(segment: str) -> bytes:
    """
    Decode an unpadded base64url segment.

    Rejects the standard base64 alphabet and embedded padding rather than silently
    tolerating them. A permissive decoder lets two different strings decode to the same
    bytes, which is exactly the sort of ambiguity that turns into a parser confusion bug.

    Args:
        segment: The base64url text to decode.

    Returns:
        The decoded bytes.

    Raises:
        InvalidTokenError: The segment contains a character outside the base64url
            alphabet, has a length no base64url string can have, or otherwise fails to
            decode. Maps to 401.
    """
    if not _B64URL_RE.match(segment):
        raise InvalidTokenError("Token segment contains a character outside base64url")

    # Named pad_len rather than padding, because `padding` at module scope is
    # cryptography's RSA padding module and shadowing it here would be a trap.
    pad_len = -len(segment) % 4
    if pad_len == 3:
        raise InvalidTokenError("Token segment has an impossible base64url length")

    try:
        return base64.urlsafe_b64decode(segment + "=" * pad_len)
    except (binascii.Error, ValueError) as err:
        raise InvalidTokenError(f"Token segment is not valid base64url: {err}") from err


def split_token(token: str) -> tuple[str, str, str]:
    """
    Split a compact JWS into its header, payload and signature segments.

    The segments are returned still base64url encoded and entirely unverified. Nothing
    here inspects their contents.

    The length cap is applied here rather than in `decode`, so that every entry point gets
    it: `get_unverified_header` reaches this function too, and it is called on the request
    path before anything has been verified.

    Args:
        token: The compact serialization to split.

    Returns:
        The header, payload and signature segments, in that order.

    Raises:
        InvalidTokenError: The value is not a string, is longer than `MAX_TOKEN_BYTES`,
            does not have exactly three segments, or has an empty segment. Maps to 401.
    """
    if not isinstance(token, str):
        raise InvalidTokenError("Token is not a string")

    # Checked before any segment is decoded or parsed. A JSON segment cannot be measured
    # until it has been parsed, and parsing is where the recursion this bounds happens.
    if len(token) > MAX_TOKEN_BYTES:
        raise InvalidTokenError(
            f"Token is too long: {len(token)} characters, limit is {MAX_TOKEN_BYTES}"
        )

    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError(f"Token has {len(parts)} segments, expected 3")
    if not all(parts):
        raise InvalidTokenError("Token has an empty segment")

    return (parts[0], parts[1], parts[2])


def _decode_json_segment(segment: str, label: str) -> dict[str, Any]:
    """
    Decode a base64url segment into a JSON object, rejecting non-objects.

    `Infinity`, `-Infinity` and `NaN` are refused. Python's parser accepts all three even
    though none is JSON, and an `exp` of `Infinity` or `NaN` is a token that never expires,
    since `now > inf` is False and every comparison against NaN is False. The same rule
    that makes this module reject non-canonical base64 applies here: a token has exactly
    one valid encoding, and an ambiguous one is refused rather than interpreted.

    Args:
        segment: The segment to decode.
        label:   The name used in error messages, such as "header" or "payload".

    Returns:
        The decoded JSON object.

    Raises:
        InvalidTokenError: The segment is not valid base64url, does not decode to valid
            JSON, carries a non-JSON numeric constant, or decodes to something other than
            a JSON object. Maps to 401.
    """

    def _reject_constant(name: str) -> Any:
        raise InvalidTokenError(f"Token {label} is not valid JSON: contains {name}")

    raw = b64url_decode(segment)
    try:
        value = json.loads(raw, parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise InvalidTokenError(f"Token {label} is not valid JSON: {err}") from err

    if not isinstance(value, dict):
        raise InvalidTokenError(f"Token {label} is not a JSON object")
    return value


def get_unverified_header(token: str) -> dict[str, Any]:
    """
    Read a token's header without verifying anything.

    Used to find the `kid` that selects a decode key. Every value in the returned mapping
    is attacker controlled: it has been through no signature check whatsoever. A `kid`
    from here may be used to look a key up and for nothing else, and an `alg` from here
    must never be allowed to choose the verification algorithm. `decode` reads the header
    again for itself and validates it against the caller's allowlist.

    Args:
        token: The token whose header should be read.

    Returns:
        The decoded, unverified JOSE header.

    Raises:
        InvalidTokenError: The token is not a well formed three-segment JWS, or its
            header segment is not a base64url-encoded JSON object. Maps to 401.
    """
    header_segment, _, _ = split_token(token)
    return _decode_json_segment(header_segment, "header")


#: Hash for each algorithm suffix. EdDSA carries its own hash internally.
_HASHES: dict[str, Any] = {
    "256": hashes.SHA256,
    "384": hashes.SHA384,
    "512": hashes.SHA512,
}

#: Curve and coordinate size for each ECDSA algorithm. Taken from the ALGORITHM, never
#: from the JWK's `crv`, so a hostile JWKS cannot substitute a weaker curve.
_EC_CURVES: dict[str, tuple[Any, int]] = {
    "ES256": (ec.SECP256R1, 32),
    "ES384": (ec.SECP384R1, 48),
    "ES512": (ec.SECP521R1, 66),
}

#: The key type each algorithm family requires. Enforcing this is what blocks signing
#: with HS256 using an RSA public key as the HMAC secret.
_REQUIRED_KTY: dict[str, str] = {
    "RS": "RSA",
    "PS": "RSA",
    "ES": "EC",
    "HS": "oct",
    "Ed": "OKP",
}

#: Cap on a whole compact serialization, before any segment is decoded. Bounds the JSON
#: parser's recursion depth, which is reachable by an unauthenticated caller through the
#: header. See the module docstring.
MAX_TOKEN_BYTES = 64 * 1024

#: How many reconstructed public keys are held. A JWKS carries a handful of keys and gains
#: a few more per rotation, so this is far above what any provider needs.
KEY_CACHE_SIZE = 128

#: Smallest RSA modulus a key will be built from, in bits. RFC 7518 section 3.3 requires
#: 2048 for RS and PS. `cryptography` will not generate below 1024 but reconstructs any
#: size from public numbers, so this is the only thing standing between a hostile JWKS and
#: a modulus that factors on a laptop.
MIN_RSA_KEY_BITS = 2048

SUPPORTED_ALGORITHMS: frozenset[str] = frozenset(
    [f"{family}{size}" for family in ("RS", "PS", "ES", "HS") for size in ("256", "384", "512")]
    + ["EdDSA"]
)


def _required_member(jwk: JWK, name: str) -> str:
    """
    Pull a required JWK member or raise naming it.

    Args:
        jwk:  The key to read.
        name: The member name, such as "n" or "crv".

    Returns:
        The member's value.

    Raises:
        InvalidKeyError: The member is absent, empty, or not a string. Maps to 401,
            though the fault is usually the provider's JWKS rather than the token.
    """
    value = getattr(jwk, name, None)
    if not isinstance(value, str) or value == "":
        raise InvalidKeyError(f"JWK of type {jwk.kty!r} is missing required member {name!r}")
    return value


def _b64url_int(jwk: JWK, name: str) -> int:
    """
    Decode a base64url big-endian integer member of a JWK.

    Args:
        jwk:  The key to read.
        name: The member name.

    Returns:
        The member decoded as a big-endian unsigned integer.

    Raises:
        InvalidKeyError: The member is absent, empty, or not a string.
        InvalidTokenError: The member is not valid base64url.
    """
    return int.from_bytes(b64url_decode(_required_member(jwk, name)), "big")


def _check_kty(algorithm: str, jwk: JWK) -> None:
    """
    Require the JWK's key type to match the algorithm family.

    This is the algorithm-confusion defense. Without it, a token asking for HS256 would be
    verified by treating an RSA public key, which is published and therefore known to
    everyone, as an HMAC secret, and anyone could mint a valid token.

    Args:
        algorithm: The algorithm named in the token header, already allowlisted.
        jwk:       The key selected by `kid`.

    Raises:
        InvalidAlgorithmError: The key's `kty` is not the one the algorithm family
            requires. Maps to 401.
    """
    required = _REQUIRED_KTY[algorithm[:2]]
    if jwk.kty != required:
        raise InvalidAlgorithmError(
            f"Algorithm {algorithm!r} requires a key with kty {required!r}, "
            f"but the JWK has kty {jwk.kty!r}"
        )


def _rsa_public_key(jwk: JWK) -> rsa.RSAPublicKey:
    """
    Build an RSA public key from a JWK's `n` and `e`, refusing an undersized modulus.

    The size check is the RSA counterpart of the curve pin in `_ec_public_key`. RFC 7518
    section 3.3 requires at least 2048 bits for RS and PS, and `cryptography` does not
    enforce it on this path: it refuses to generate a key below 1024 bits but reconstructs
    any size at all from public numbers. Without this, a JWKS publishing a 512 bit modulus
    would be accepted and its signatures would verify, and a modulus that small hands the
    private half to anyone who wants to spend an afternoon on it.

    Args:
        jwk: The key to read, already checked to have `kty` of "RSA".

    Returns:
        The reconstructed public key.

    Raises:
        InvalidKeyError: `n` or `e` is absent or empty, or the modulus is smaller than
            `MIN_RSA_KEY_BITS`. Maps to 401, though an undersized modulus points at the
            provider's JWKS rather than at the token.
        InvalidTokenError: `n` or `e` is not valid base64url.
        ValueError: `cryptography` rejected the numbers as an RSA key.
    """
    return _build_rsa_public_key(_required_member(jwk, "n"), _required_member(jwk, "e"))


@lru_cache(maxsize=KEY_CACHE_SIZE)
def _build_rsa_public_key(n: str, e: str) -> rsa.RSAPublicKey:
    """
    Build and cache an RSA public key from its encoded members.

    Cached on the members themselves, which is what makes the cache safe: two JWKs holding
    the same `n` and `e` are the same key, and two holding different material can never
    reach each other's entry. Keying on anything looser, such as `kid`, would let one key
    be verified against another's material, which is an authentication bypass rather than a
    performance bug.

    Args:
        n: The modulus, base64url encoded.
        e: The exponent, base64url encoded.

    Returns:
        The reconstructed public key, shared with every earlier caller that passed the same
        members.

    Raises:
        InvalidKeyError: The modulus is smaller than `MIN_RSA_KEY_BITS`. Not cached, since
            `lru_cache` stores return values and not exceptions, so a rejected key is
            rebuilt and rejected again on the next attempt.
        InvalidTokenError: A member is not valid base64url.
        ValueError: `cryptography` rejected the numbers as an RSA key.
    """
    key = rsa.RSAPublicNumbers(
        e=int.from_bytes(b64url_decode(e), "big"),
        n=int.from_bytes(b64url_decode(n), "big"),
    ).public_key()
    if key.key_size < MIN_RSA_KEY_BITS:
        raise InvalidKeyError(
            f"RSA key is {key.key_size} bits, but at least {MIN_RSA_KEY_BITS} are required"
        )
    return key


def _ec_public_key(algorithm: str, jwk: JWK) -> ec.EllipticCurvePublicKey:
    """
    Build an EC public key, taking the curve from the algorithm.

    The curve comes from `_EC_CURVES[algorithm]` and never from the JWK's own `crv`. That
    is deliberate: reading the curve from the key would let a hostile or compromised JWKS
    hand back a weaker curve than the route agreed to accept, and the signature would
    still verify against it.

    Args:
        algorithm: The ES algorithm in use, already allowlisted.
        jwk:       The key to read, already checked to have `kty` of "EC".

    Returns:
        The reconstructed public key, on the curve the algorithm names.

    Raises:
        InvalidKeyError: `x` or `y` is absent or empty.
        InvalidTokenError: `x` or `y` is not valid base64url.
        ValueError: The coordinates are not a point on the algorithm's curve, which is
            what a substituted key looks like from here.
    """
    return _build_ec_public_key(algorithm, _required_member(jwk, "x"), _required_member(jwk, "y"))


@lru_cache(maxsize=KEY_CACHE_SIZE)
def _build_ec_public_key(algorithm: str, x: str, y: str) -> ec.EllipticCurvePublicKey:
    """
    Build and cache an EC public key from its algorithm and encoded coordinates.

    The algorithm is part of the cache key, not merely an argument, because it is what
    chooses the curve. Leaving it out would let an ES256 key and an ES384 request share an
    entry, which would defeat the pin the caller's docstring describes.

    Args:
        algorithm: The ES algorithm in use, already allowlisted.
        x:         The x coordinate, base64url encoded.
        y:         The y coordinate, base64url encoded.

    Returns:
        The reconstructed public key, on the curve the algorithm names.

    Raises:
        InvalidTokenError: A coordinate is not valid base64url.
        ValueError: The coordinates are not a point on the algorithm's curve.
    """
    curve_cls, _ = _EC_CURVES[algorithm]
    return ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(b64url_decode(x), "big"),
        y=int.from_bytes(b64url_decode(y), "big"),
        curve=curve_cls(),
    ).public_key()


def verify_signature(
    algorithm: str,
    jwk: JWK,
    signing_input: bytes,
    signature: bytes,
) -> None:
    """
    Verify a JWS signature, raising on any failure.

    The caller must already have checked `algorithm` against its own allowlist. This
    function additionally requires the JWK's key type to match the algorithm family, so a
    key of the wrong kind cannot be pressed into service by a token that asks for it.

    Two details are load-bearing rather than incidental. For ECDSA, the curve and the
    coordinate size come from the algorithm name, never from the JWK's `crv`, and the raw
    r||s signature length is checked before decoding, which rejects DER-wrapped and
    truncated signatures outright. For EdDSA, only Ed25519 is accepted.

    Returns None on success. Verification failure is always an exception, never a False
    return, so a caller cannot accidentally authenticate a token by ignoring a result.

    Args:
        algorithm:     The algorithm from the token header, already allowlisted.
        jwk:           The key selected by the token's `kid`.
        signing_input: The ASCII bytes of "<header_b64>.<payload_b64>".
        signature:     The decoded signature bytes.

    Raises:
        InvalidAlgorithmError: The algorithm is not in `SUPPORTED_ALGORITHMS`, the JWK's
            `kty` does not match the algorithm family, or an EdDSA key names a curve
            other than Ed25519. Maps to 401.
        InvalidKeyError: The JWK is missing a member its key type requires, such as `n`
            and `e` for RSA or `x` and `y` for EC. Maps to 401, but the fault is usually
            the provider's JWKS rather than the token.
        InvalidSignatureError: The signature did not verify, or an ECDSA signature was
            not the exact raw r||s length the curve requires. Maps to 401. This is the
            ordinary "this token is a forgery, or was signed by a key we do not hold"
            outcome.
        InvalidTokenError: A JWK member that should be base64url is not.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise InvalidAlgorithmError(f"Algorithm {algorithm!r} is not supported")

    _check_kty(algorithm, jwk)

    if algorithm.startswith("HS"):
        digest = getattr(hashlib, f"sha{algorithm[2:]}")
        secret = b64url_decode(_required_member(jwk, "k"))
        expected = hmac.new(secret, signing_input, digest).digest()
        if not hmac.compare_digest(expected, signature):
            raise InvalidSignatureError("Token signature did not verify")
        return

    if algorithm == "EdDSA":
        crv = _required_member(jwk, "crv")
        if crv != "Ed25519":
            raise InvalidAlgorithmError(f"EdDSA curve {crv!r} is not supported")
        key = ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(_required_member(jwk, "x")))
        try:
            key.verify(signature, signing_input)
        except InvalidSignature as err:
            raise InvalidSignatureError("Token signature did not verify") from err
        return

    hash_alg = _HASHES[algorithm[2:]]()

    if algorithm.startswith("ES"):
        _, coord_bytes = _EC_CURVES[algorithm]
        # JWS carries ECDSA signatures as raw r||s. Checking the length before decoding
        # rejects both DER-wrapped and truncated signatures outright.
        if len(signature) != coord_bytes * 2:
            raise InvalidSignatureError(
                f"ECDSA signature has length {len(signature)}, expected {coord_bytes * 2}"
            )
        r = int.from_bytes(signature[:coord_bytes], "big")
        s = int.from_bytes(signature[coord_bytes:], "big")
        try:
            _ec_public_key(algorithm, jwk).verify(
                encode_dss_signature(r, s), signing_input, ec.ECDSA(hash_alg)
            )
        except InvalidSignature as err:
            raise InvalidSignatureError("Token signature did not verify") from err
        return

    pad: Any
    if algorithm.startswith("PS"):
        pad = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size)
    else:
        pad = padding.PKCS1v15()

    try:
        _rsa_public_key(jwk).verify(signature, signing_input, pad, hash_alg)
    except InvalidSignature as err:
        raise InvalidSignatureError("Token signature did not verify") from err


#: Options `decode` understands, with their defaults. Anything else is ignored, matching
#: the permissive behavior callers expect from a jose-shaped API. `verify_signature` is a
#: testing and debugging switch only: setting it False accepts every token. See the module
#: docstring.
_DEFAULT_OPTIONS: dict[str, bool] = {
    "verify_signature": True,
    "verify_exp": True,
    "verify_nbf": True,
    "verify_aud": True,
    "verify_iss": True,
}


def _numeric_claim(claims: dict[str, Any], name: str) -> float | None:
    """
    Read a NumericDate claim, rejecting values that are not numbers.

    A NumericDate is a finite number of seconds, so infinities and NaN are refused here as
    well as at the parser. The parser catches the JSON constants; this catches what it
    cannot, since `1e400` is ordinary JSON syntax that Python parses to a float infinity,
    and an `exp` of infinity or NaN is a token that never expires. Integers too large to
    become a float are refused rather than allowed to raise `OverflowError`, which would
    escape this module as something other than an `AuthenticationError`.

    Args:
        claims: The decoded payload.
        name:   The claim name.

    Returns:
        The claim as a finite float, or None when the claim is absent.

    Raises:
        InvalidTokenError: The claim is present but is not a number, is not finite, or is
            too large to represent as a float. `bool` is rejected explicitly, since it is
            an `int` subclass and a boolean timestamp is always a malformed token. Maps
            to 401.
    """
    if name not in claims:
        return None
    value = claims[name]
    # bool is an int subclass, and a boolean timestamp is always a malformed token.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidTokenError(f"Token claim {name!r} is not a number")

    try:
        number = float(value)
    except OverflowError as err:
        # An int beyond the float range, such as 10**400. Without this the OverflowError
        # escapes `decode`, breaking this module's contract that every failure is an
        # AuthenticationError subclass.
        raise InvalidTokenError(f"Token claim {name!r} is out of range") from err

    if not math.isfinite(number):
        raise InvalidTokenError(f"Token claim {name!r} is not a finite number")
    return number


def decode(
    token: str,
    jwk: JWK,
    algorithms: list[str],
    *,
    audience: str | None = None,
    issuer: str | None = None,
    options: dict[str, bool] | None = None,
    leeway: float = 0.0,
) -> dict[str, Any]:
    """
    Decode and fully validate a JWT, returning its claims.

    The order of operations below is a security property, not an implementation detail.
    In short: structure, then the algorithm from the CALLER's allowlist, then critical
    headers, then the signature (with the JWK's key type checked against the algorithm
    family and the ECDSA curve taken from the algorithm rather than from the key), and
    only then are any claims parsed or trusted. The module docstring sets out each step
    and the attack it forecloses. Read it before changing anything here.

    Nothing the token says about which algorithm to use is honored. `algorithms` is the
    authority, and callers in this library pass exactly one, from `DomainConfig`.

    This is the jose-shaped entry point, for a caller that has already picked a key.
    `decode_selecting_key` holds the implementation and is what `TokenDecoder` uses, so
    that a caller holding a whole JWKS does not have to parse the header a second time to
    find one.

    Args:
        token:      The compact serialization to decode.
        jwk:        The key to verify against, already selected by `kid`. Selecting it by
                    the unverified `kid` is safe precisely because that key still has to
                    verify the signature below.
        algorithms: The permitted algorithms. The token's own `alg` must appear here.
        audience:   Required audience. When None, `aud` is not checked.
        issuer:     Required issuer. When None, `iss` is not checked. Compared by exact
                    string equality against the value the provider published, which is
                    why `OpenidConfig.issuer` is never normalized.
        options:    Toggles for individual checks, such as `{"verify_aud": False}`. Only
                    the keys in `_DEFAULT_OPTIONS` are understood; anything else is
                    ignored, matching the permissive behavior of the jose-shaped API this
                    replaces. Setting `verify_signature` False accepts every token and is
                    a testing switch only.
        leeway:     Seconds of clock skew tolerated on `exp` and `nbf`.

    Returns:
        The verified claims, exactly as the payload carried them. No claim is renamed,
        coerced or added.

    Raises:
        InvalidTokenError: The token is not a well formed JWS, a segment is not valid
            base64url or valid JSON, a segment carries `Infinity`, `-Infinity` or `NaN`,
            the header carries a `crit` member, or `exp`, `nbf` or `iat` is present and is
            not a finite number in the float range. Maps to 401.
        InvalidAlgorithmError: The token is an unsecured JWS, carries no `alg`, names an
            algorithm absent from `algorithms`, or names one whose family does not match
            the JWK's `kty`. This is the `alg: none` and algorithm-confusion refusal.
            Maps to 401.
        InvalidKeyError: The JWK is missing a member its key type requires. Maps to 401,
            but points at the provider's JWKS rather than at the token.
        InvalidSignatureError: The signature did not verify against the key. Maps to 401.
        ExpiredSignatureError: `exp` is in the past, beyond `leeway`. Maps to 401, and is
            the one failure a well-behaved client should respond to by refreshing its
            token rather than by treating the request as rejected outright.
        ImmatureSignatureError: `nbf` is in the future, beyond `leeway`. Maps to 401.
        InvalidAudienceError: `audience` was required and the token's `aud` is missing or
            does not contain it. Maps to 401.
        InvalidIssuerError: `issuer` was required and the token's `iss` is missing or
            does not match it exactly. Maps to 401.
    """
    return decode_selecting_key(
        token,
        lambda _header: jwk,
        algorithms,
        audience=audience,
        issuer=issuer,
        options=options,
        leeway=leeway,
    )


def decode_selecting_key(
    token: str,
    select_key: Callable[[dict[str, Any]], JWK],
    algorithms: list[str],
    *,
    audience: str | None = None,
    issuer: str | None = None,
    options: dict[str, bool] | None = None,
    leeway: float = 0.0,
) -> dict[str, Any]:
    """
    Decode and fully validate a JWT, choosing the key once the header has been read.

    The implementation behind `decode`, and the only one: `decode` is this function with a
    selector that ignores the header and returns the key it was given.

    The selector exists so that a caller holding a whole JWKS does not have to parse the
    header itself to find `kid` and then hand the token back to be parsed a second time.
    It is handed the header THIS function parsed from the token's own bytes, and it returns
    a key. It never supplies the bytes that key is checked against, which is what keeps the
    arrangement safe: a caller cannot present one header for key selection and a different
    one for the signature.

    It is called after the algorithm allowlist and `crit` checks, not before. Key selection
    used to run ahead of every check, so a token naming `alg: none` and an unknown `kid`
    reported the missing key and drove an outbound JWKS refetch on behalf of a token that
    could never have verified. It runs whether or not `verify_signature` is set, so that
    turning the signature check off does not also turn off the `kid` requirement.

    The order of operations below is a security property, not an implementation detail.
    In short: structure, then the algorithm from the CALLER's allowlist, then critical
    headers, then the signature (with the JWK's key type checked against the algorithm
    family and the ECDSA curve taken from the algorithm rather than from the key), and
    only then are any claims parsed or trusted. The module docstring sets out each step
    and the attack it forecloses. Read it before changing anything here.

    Nothing the token says about which algorithm to use is honored. `algorithms` is the
    authority, and callers in this library pass exactly one, from `DomainConfig`.

    Args:
        token:      The compact serialization to decode.
        select_key: Called with the token's parsed but entirely unverified header, and
                    returns the key to verify with. Choosing a key by the unverified `kid`
                    is safe precisely because that key still has to verify the signature
                    below. Anything it raises propagates, which is how `TokenDecoder`
                    reports an unknown `kid`.
        algorithms: The permitted algorithms. The token's own `alg` must appear here.
        audience:   Required audience. When None, `aud` is not checked.
        issuer:     Required issuer. When None, `iss` is not checked. Compared by exact
                    string equality against the value the provider published, which is
                    why `OpenidConfig.issuer` is never normalized.
        options:    Toggles for individual checks, such as `{"verify_aud": False}`. Only
                    the keys in `_DEFAULT_OPTIONS` are understood; anything else is
                    ignored, matching the permissive behavior of the jose-shaped API this
                    replaces. Setting `verify_signature` False accepts every token and is
                    a testing switch only.
        leeway:     Seconds of clock skew tolerated on `exp` and `nbf`.

    Returns:
        The verified claims, exactly as the payload carried them. No claim is renamed,
        coerced or added.

    Raises:
        InvalidTokenError: The token is not a well formed JWS, a segment is not valid
            base64url or valid JSON, a segment carries `Infinity`, `-Infinity` or `NaN`,
            the header carries a `crit` member, or `exp`, `nbf` or `iat` is present and is
            not a finite number in the float range. Maps to 401.
        InvalidAlgorithmError: The token is an unsecured JWS, carries no `alg`, names an
            algorithm absent from `algorithms`, or names one whose family does not match
            the JWK's `kty`. This is the `alg: none` and algorithm-confusion refusal.
            Maps to 401.
        InvalidKeyError: The JWK is missing a member its key type requires. Maps to 401,
            but points at the provider's JWKS rather than at the token.
        InvalidSignatureError: The signature did not verify against the key. Maps to 401.
        ExpiredSignatureError: `exp` is in the past, beyond `leeway`. Maps to 401, and is
            the one failure a well-behaved client should respond to by refreshing its
            token rather than by treating the request as rejected outright.
        ImmatureSignatureError: `nbf` is in the future, beyond `leeway`. Maps to 401.
        InvalidAudienceError: `audience` was required and the token's `aud` is missing or
            does not contain it. Maps to 401.
        InvalidIssuerError: `issuer` was required and the token's `iss` is missing or
            does not match it exactly. Maps to 401.
    """
    opts = {**_DEFAULT_OPTIONS, **(options or {})}

    # 1. Structure. A malformed token never reaches a cryptographic operation.
    #    The one shape singled out here is "<header>.<payload>." with an empty signature,
    #    which is the RFC 7515 unsecured JWS. It is a structurally valid serialization
    #    carrying no signature at all, so it belongs to the algorithm rule in step 2 and
    #    is reported as such rather than as a generic malformed token.
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) == 3 and all(parts[:2]) and parts[2] == "":
        raise InvalidAlgorithmError("Unsecured JWS is not permitted for this route")

    header_b64, payload_b64, signature_b64 = split_token(token)
    header = _decode_json_segment(header_b64, "header")

    # 2. Algorithm allowlist. Read from the CALLER's list, never from the token. This is
    #    the `alg: none` and algorithm-confusion defense and it must stay first.
    algorithm = header.get("alg")
    if not isinstance(algorithm, str):
        raise InvalidAlgorithmError("Token header has no 'alg'")
    if algorithm not in algorithms:
        raise InvalidAlgorithmError(f"Algorithm {algorithm!r} is not permitted for this route")

    # 3. Unrecognized critical headers must be refused (RFC 7515 section 4.1.11). We
    #    understand none, so any `crit` entry at all is a refusal.
    crit = header.get("crit")
    if crit is not None:
        if not isinstance(crit, list):
            raise InvalidTokenError("Token header 'crit' is not a list")
        raise InvalidTokenError(f"Token header 'crit' names unsupported extensions: {crit}")

    # 4. The key, chosen from the header this function parsed and from nothing else. It
    #    comes after the allowlist check so that a token the route would never accept
    #    cannot reach a JWKS lookup, and before the `verify_signature` switch so that
    #    turning the signature check off does not also drop the `kid` requirement.
    jwk = select_key(header)

    # 5. Signature, before any claim is read. verify_signature also requires the JWK's kty
    #    to match the algorithm family.
    if opts["verify_signature"]:
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        verify_signature(algorithm, jwk, signing_input, b64url_decode(signature_b64))

    # 6. Only now are the claims worth reading.
    claims = _decode_json_segment(payload_b64, "payload")
    now = time.time()

    expire = _numeric_claim(claims, "exp")
    if opts["verify_exp"] and expire is not None and now > expire + leeway:
        raise ExpiredSignatureError("Token has expired")

    not_before = _numeric_claim(claims, "nbf")
    if opts["verify_nbf"] and not_before is not None and now < not_before - leeway:
        raise ImmatureSignatureError("Token is not yet valid")

    # Parsed for type validity even though it is not used to reject, matching jose.
    _numeric_claim(claims, "iat")

    if opts["verify_aud"] and audience is not None:
        raw_audience = claims.get("aud")
        if raw_audience is None:
            raise InvalidAudienceError("Token is missing the 'aud' claim")
        allowed = raw_audience if isinstance(raw_audience, list) else [raw_audience]
        if audience not in allowed:
            raise InvalidAudienceError(
                f"Token audience {raw_audience!r} does not match {audience!r}"
            )

    if opts["verify_iss"] and issuer is not None:
        token_issuer = claims.get("iss")
        if token_issuer is None:
            raise InvalidIssuerError("Token is missing the 'iss' claim")
        if token_issuer != issuer:
            raise InvalidIssuerError(f"Token issuer {token_issuer!r} does not match {issuer!r}")

    return claims


def _sign(algorithm: str, key: bytes | str, signing_input: bytes) -> bytes:
    """
    Produce a JWS signature. Used by `encode`, which is a testing aid.

    Args:
        algorithm:     The JWS algorithm to sign with.
        key:           PEM private key bytes, or raw secret bytes for HS algorithms.
        signing_input: The ASCII bytes of "<header_b64>.<payload_b64>".

    Returns:
        The raw signature bytes, r||s for ECDSA rather than DER.

    Raises:
        ValueError: The PEM could not be loaded, or the key does not match the algorithm.
        AssertionError: The loaded key is not of the type the algorithm needs. Asserting
            is acceptable here only because this is a testing aid, never reached by a
            request.
    """
    if algorithm.startswith("HS"):
        secret = key.encode() if isinstance(key, str) else key
        digest = getattr(hashlib, f"sha{algorithm[2:]}")
        return hmac.new(secret, signing_input, digest).digest()

    # Imported here rather than at module scope. This is the only place the library needs
    # it, `_sign` is a testing aid never reached by a request, and importing it eagerly
    # cost roughly 6.8ms of package import time while dragging in
    # `serialization.ssh` and its optional bcrypt path.
    from cryptography.hazmat.primitives import serialization

    pem = key.encode() if isinstance(key, str) else key
    private = serialization.load_pem_private_key(pem, password=None)

    if algorithm == "EdDSA":
        assert isinstance(private, ed25519.Ed25519PrivateKey)
        return private.sign(signing_input)

    hash_alg = _HASHES[algorithm[2:]]()

    if algorithm.startswith("ES"):
        assert isinstance(private, ec.EllipticCurvePrivateKey)
        _, coord_bytes = _EC_CURVES[algorithm]
        der = private.sign(signing_input, ec.ECDSA(hash_alg))
        r, s = decode_dss_signature(der)
        return r.to_bytes(coord_bytes, "big") + s.to_bytes(coord_bytes, "big")

    assert isinstance(private, rsa.RSAPrivateKey)
    if algorithm.startswith("PS"):
        pad: Any = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size)
    else:
        pad = padding.PKCS1v15()
    return private.sign(signing_input, pad, hash_alg)


def encode(
    claims: dict[str, Any],
    key: bytes | str,
    algorithm: str,
    headers: dict[str, Any] | None = None,
) -> str:
    """
    Sign a set of claims into a compact JWS.

    This is a testing aid. It exists so that the pytest extension can build tokens without
    pulling in a second signing library, and it is never used on the request path. Do not
    build production tokens with it; this library is a validator.

    Args:
        claims:    The payload to sign. Nothing is added to it: no `iat`, no `exp`, no
                   `iss`. A test that wants those must supply them.
        key:       PEM private key bytes, or the raw secret for an HS algorithm.
        algorithm: The JWS algorithm to sign with. Placed into the header last, so a
                   caller cannot override it through `headers` and produce a token whose
                   header disagrees with how it was actually signed.
        headers:   Additional header members, such as `kid`.

    Returns:
        The compact serialization, "<header>.<payload>.<signature>".

    Raises:
        InvalidAlgorithmError: The algorithm is not in `SUPPORTED_ALGORITHMS`.
        ValueError: The key could not be loaded, or does not match the algorithm.
        TypeError: The claims or headers are not JSON serializable.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise InvalidAlgorithmError(f"Algorithm {algorithm!r} is not supported")

    header = {"typ": "JWT", **(headers or {}), "alg": algorithm}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _sign(algorithm, key, signing_input)
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"
