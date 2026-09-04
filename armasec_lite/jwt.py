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
import json
import re
from typing import Any

from armasec_lite.exceptions import AuthenticationError


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

    padding = -len(segment) % 4
    if padding == 3:
        raise InvalidTokenError("Token segment has an impossible base64url length")

    try:
        return base64.urlsafe_b64decode(segment + "=" * padding)
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
