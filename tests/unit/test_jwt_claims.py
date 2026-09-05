import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from armasec_lite.jwt import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    b64url_encode,
    decode,
)

ALGS = ["RS256"]


def _sign(rsa_private, claims: dict, header: dict | None = None) -> str:
    head = {"alg": "RS256", "typ": "JWT", "kid": "rsa-test", **(header or {})}
    head_b64 = b64url_encode(json.dumps(head).encode())
    body_b64 = b64url_encode(json.dumps(claims).encode())
    signing_input = f"{head_b64}.{body_b64}".encode("ascii")
    sig = rsa_private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{head_b64}.{body_b64}.{b64url_encode(sig)}"


def _sign_raw(rsa_private, payload_json: str) -> str:
    """Sign a payload written as raw JSON text, so literals `json.dumps` avoids survive."""
    head_b64 = b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "rsa-test"}).encode())
    body_b64 = b64url_encode(payload_json.encode())
    signing_input = f"{head_b64}.{body_b64}".encode("ascii")
    sig = rsa_private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{head_b64}.{body_b64}.{b64url_encode(sig)}"


@pytest.fixture
def now():
    return int(time.time())


def test_decode_returns_the_claims(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "custom": [1, 2]})
    claims = decode(token, rsa_jwk, ALGS)
    assert claims["sub"] == "abc"
    assert claims["custom"] == [1, 2]


def test_decode_rejects_an_algorithm_outside_the_allowlist(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    with pytest.raises(InvalidAlgorithmError, match="not permitted"):
        decode(token, rsa_jwk, ["ES256"])


def test_decode_rejects_alg_none(rsa_jwk, now):
    head = b64url_encode(json.dumps({"alg": "none", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 60}).encode())
    with pytest.raises(InvalidAlgorithmError):
        decode(f"{head}.{body}.", rsa_jwk, ALGS)


def test_decode_rejects_a_tampered_payload(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    head, _, sig = token.split(".")
    forged = b64url_encode(json.dumps({"sub": "admin", "exp": now + 60}).encode())
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{forged}.{sig}", rsa_jwk, ALGS)


def test_decode_rejects_an_unrecognized_crit_header(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60}, header={"crit": ["urn:novel"]})
    with pytest.raises(InvalidTokenError, match="crit"):
        decode(token, rsa_jwk, ALGS)


def test_decode_rejects_an_expired_token(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 10})
    with pytest.raises(ExpiredSignatureError):
        decode(token, rsa_jwk, ALGS)


def test_decode_accepts_an_expired_token_within_leeway(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 10})
    assert decode(token, rsa_jwk, ALGS, leeway=60)["sub"] == "abc"


def test_decode_can_skip_expiry_verification(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 10})
    assert decode(token, rsa_jwk, ALGS, options={"verify_exp": False})["sub"] == "abc"


def test_decode_rejects_a_token_not_yet_valid(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 600, "nbf": now + 300})
    with pytest.raises(ImmatureSignatureError):
        decode(token, rsa_jwk, ALGS)


def test_decode_rejects_a_non_numeric_exp(rsa_private, rsa_jwk):
    token = _sign(rsa_private, {"sub": "abc", "exp": "soon"})
    with pytest.raises(InvalidTokenError, match="exp"):
        decode(token, rsa_jwk, ALGS)


@pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
@pytest.mark.parametrize("literal", ["Infinity", "-Infinity", "NaN"])
def test_decode_rejects_a_non_json_numeric_constant(rsa_private, rsa_jwk, claim, literal):
    """
    `Infinity` and `NaN` are not JSON, and Python's parser accepts them anyway.

    An `exp` of either never expires: `now > inf` is False, and every comparison against
    NaN is False. The token still has to be signed by the issuer, so this is not a bypass,
    but this module rejects non-canonical base64 for exactly this reason and refusing
    ambiguous numbers is the same rule.
    """
    token = _sign_raw(rsa_private, f'{{"sub": "abc", "{claim}": {literal}}}')
    with pytest.raises(InvalidTokenError, match="JSON"):
        decode(token, rsa_jwk, ALGS)


@pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
def test_decode_rejects_a_numeric_claim_too_large_for_a_float(rsa_private, rsa_jwk, claim):
    """`float(10**400)` raises OverflowError, which is not an AuthenticationError."""
    token = _sign_raw(rsa_private, f'{{"sub": "abc", "{claim}": {10**400}}}')
    with pytest.raises(InvalidTokenError, match=claim):
        decode(token, rsa_jwk, ALGS)


@pytest.mark.parametrize("claim", ["exp", "nbf", "iat"])
def test_decode_rejects_a_numeric_claim_that_overflows_to_infinity(rsa_private, rsa_jwk, claim):
    """`1e400` needs no JSON constant: the parser hands back a float infinity directly."""
    token = _sign_raw(rsa_private, f'{{"sub": "abc", "{claim}": 1e400}}')
    with pytest.raises(InvalidTokenError, match=claim):
        decode(token, rsa_jwk, ALGS)


def test_decode_matches_a_string_audience(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "my-api"})
    assert decode(token, rsa_jwk, ALGS, audience="my-api")["aud"] == "my-api"


def test_decode_matches_an_audience_inside_a_list(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": ["other", "my-api"]})
    assert decode(token, rsa_jwk, ALGS, audience="my-api")["sub"] == "abc"


def test_decode_rejects_a_wrong_audience(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "other-api"})
    with pytest.raises(InvalidAudienceError):
        decode(token, rsa_jwk, ALGS, audience="my-api")


def test_decode_rejects_a_missing_audience_when_one_is_required(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    with pytest.raises(InvalidAudienceError, match="missing"):
        decode(token, rsa_jwk, ALGS, audience="my-api")


def test_decode_can_skip_audience_verification(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "other-api"})
    claims = decode(token, rsa_jwk, ALGS, audience="my-api", options={"verify_aud": False})
    assert claims["sub"] == "abc"


def test_decode_ignores_audience_when_none_is_required(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "anything"})
    assert decode(token, rsa_jwk, ALGS)["sub"] == "abc"


def test_decode_matches_the_issuer(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": "https://auth.example.com"})
    assert decode(token, rsa_jwk, ALGS, issuer="https://auth.example.com")["sub"] == "abc"


def test_decode_rejects_a_wrong_issuer(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": "https://evil.example.com"})
    with pytest.raises(InvalidIssuerError):
        decode(token, rsa_jwk, ALGS, issuer="https://auth.example.com")


def test_decode_rejects_a_missing_issuer_when_one_is_required(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    with pytest.raises(InvalidIssuerError, match="missing"):
        decode(token, rsa_jwk, ALGS, issuer="https://auth.example.com")


def test_decode_rejects_a_payload_that_is_not_an_object(rsa_private, rsa_jwk):
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": "rsa-test"}).encode())
    body = b64url_encode(b"[1,2,3]")
    signing_input = f"{head}.{body}".encode("ascii")
    sig = rsa_private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidTokenError, match="object"):
        decode(f"{head}.{body}.{b64url_encode(sig)}", rsa_jwk, ALGS)


def test_decode_verifies_signature_before_reading_claims(rsa_private, rsa_jwk, now):
    """An expired token with a bad signature must fail on the signature, not the clock."""
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 999})
    head, body, _ = token.split(".")
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{body}.{b64url_encode(b'garbage')}", rsa_jwk, ALGS)
