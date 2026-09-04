"""
A minimal JWS/JWT implementation, replacing python-jose.

Everything except the signature primitive itself is standard library. `cryptography`
provides only the verify and sign operations, because that is the part with a long CVE
history and no business being hand written.

The verification order in `decode` is a security property, not an implementation detail.
Read the comments there before changing anything.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.schemas import JWK


class InvalidTokenError(AuthenticationError):
    """The token is not a well formed JWS."""


class InvalidSignatureError(AuthenticationError):
    """The token's signature did not verify against the key."""


class InvalidAlgorithmError(AuthenticationError):
    """The token's algorithm is not permitted, or does not match the key type."""


class InvalidKeyError(AuthenticationError):
    """The JWK is missing members required by its key type."""


class ExpiredSignatureError(AuthenticationError):
    """The token's `exp` claim is in the past."""


class ImmatureSignatureError(AuthenticationError):
    """The token's `nbf` claim is in the future."""


class InvalidAudienceError(AuthenticationError):
    """The token's `aud` claim does not contain the required audience."""


class InvalidIssuerError(AuthenticationError):
    """The token's `iss` claim does not match the required issuer."""


#: base64url alphabet, without padding. Anything else in a segment is a malformed token.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_encode(raw: bytes) -> str:
    """
    Encode bytes as unpadded base64url, the encoding JWS uses for every segment.

    Args:
        raw: The bytes to encode.
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

    Args:
        token: The compact serialization to split.
    """
    if not isinstance(token, str):
        raise InvalidTokenError("Token is not a string")

    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError(f"Token has {len(parts)} segments, expected 3")
    if not all(parts):
        raise InvalidTokenError("Token has an empty segment")

    return (parts[0], parts[1], parts[2])


def _decode_json_segment(segment: str, label: str) -> dict[str, Any]:
    """
    Decode a base64url segment into a JSON object, rejecting non-objects.

    Args:
        segment: The segment to decode.
        label:   The name used in error messages, such as "header" or "payload".
    """
    raw = b64url_decode(segment)
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise InvalidTokenError(f"Token {label} is not valid JSON: {err}") from err

    if not isinstance(value, dict):
        raise InvalidTokenError(f"Token {label} is not a JSON object")
    return value


def get_unverified_header(token: str) -> dict[str, Any]:
    """
    Read a token's header without verifying anything.

    Used to find the `kid` that selects a decode key. The value is attacker controlled,
    so it may be used to look a key up and for nothing else.

    Args:
        token: The token whose header should be read.
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
    """
    return int.from_bytes(b64url_decode(_required_member(jwk, name)), "big")


def _check_kty(algorithm: str, jwk: JWK) -> None:
    """
    Require the JWK's key type to match the algorithm family.

    Args:
        algorithm: The algorithm named in the token header, already allowlisted.
        jwk:       The key selected by `kid`.
    """
    required = _REQUIRED_KTY[algorithm[:2]]
    if jwk.kty != required:
        raise InvalidAlgorithmError(
            f"Algorithm {algorithm!r} requires a key with kty {required!r}, "
            f"but the JWK has kty {jwk.kty!r}"
        )


def _rsa_public_key(jwk: JWK) -> rsa.RSAPublicKey:
    """Build an RSA public key from a JWK's `n` and `e`."""
    return rsa.RSAPublicNumbers(e=_b64url_int(jwk, "e"), n=_b64url_int(jwk, "n")).public_key()


def _ec_public_key(algorithm: str, jwk: JWK) -> ec.EllipticCurvePublicKey:
    """Build an EC public key, taking the curve from the algorithm."""
    curve_cls, _ = _EC_CURVES[algorithm]
    x_raw = b64url_decode(_required_member(jwk, "x"))
    y_raw = b64url_decode(_required_member(jwk, "y"))
    return ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x_raw, "big"),
        y=int.from_bytes(y_raw, "big"),
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

    Args:
        algorithm:     The algorithm from the token header, already allowlisted.
        jwk:           The key selected by the token's `kid`.
        signing_input: The ASCII bytes of "<header_b64>.<payload_b64>".
        signature:     The decoded signature bytes.
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
#: the permissive behavior callers expect from a jose-shaped API.
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

    Args:
        claims: The decoded payload.
        name:   The claim name.
    """
    if name not in claims:
        return None
    value = claims[name]
    # bool is an int subclass, and a boolean timestamp is always a malformed token.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidTokenError(f"Token claim {name!r} is not a number")
    return float(value)


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

    The order of operations below is a security property. In particular the algorithm is
    taken from the caller's allowlist rather than from the token, the key type is checked
    against the algorithm, and the signature is verified before any claim is trusted.

    Args:
        token:      The compact serialization to decode.
        jwk:        The key to verify against, already selected by `kid`.
        algorithms: The permitted algorithms. The token's own `alg` must appear here.
        audience:   Required audience. When None, `aud` is not checked.
        issuer:     Required issuer. When None, `iss` is not checked.
        options:    Toggles for individual checks, such as `{"verify_aud": False}`.
        leeway:     Seconds of clock skew tolerated on `exp` and `nbf`.
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

    # 4. Signature, before any claim is read. Step 3 of verify_signature also requires the
    #    JWK's kty to match the algorithm family.
    if opts["verify_signature"]:
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        verify_signature(algorithm, jwk, signing_input, b64url_decode(signature_b64))

    # 5. Only now are the claims worth reading.
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
    """
    if algorithm.startswith("HS"):
        secret = key.encode() if isinstance(key, str) else key
        digest = getattr(hashlib, f"sha{algorithm[2:]}")
        return hmac.new(secret, signing_input, digest).digest()

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
        claims:    The payload to sign.
        key:       PEM private key bytes, or the raw secret for an HS algorithm.
        algorithm: The JWS algorithm to sign with.
        headers:   Additional header members, such as `kid`.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise InvalidAlgorithmError(f"Algorithm {algorithm!r} is not supported")

    header = {"typ": "JWT", **(headers or {}), "alg": algorithm}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _sign(algorithm, key, signing_input)
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"
