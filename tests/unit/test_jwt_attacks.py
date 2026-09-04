"""
The attack suite.

Every test here names one concrete forgery or malformed-input technique. The names are
consumed by the security matrix benchmark, so renaming one changes a published chart.
"""

import hashlib
import hmac as hmac_mod
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from armasec_lite.jwt import (
    InvalidAlgorithmError,
    InvalidSignatureError,
    InvalidTokenError,
    b64url_decode,
    b64url_encode,
    decode,
    encode,
)
from armasec_lite.schemas import JWK

ALGS = ["RS256"]


@pytest.fixture
def now():
    return int(time.time())


@pytest.fixture
def valid_token(rsa_private, now):
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64url_encode(sig)}"


def test_attack_alg_none_is_rejected(rsa_jwk, now):
    head = b64url_encode(json.dumps({"alg": "none", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    with pytest.raises(InvalidAlgorithmError):
        decode(f"{head}.{body}.", rsa_jwk, ALGS)


def test_attack_alg_none_with_empty_signature_and_none_allowlisted(rsa_jwk, now):
    """Even if a caller foolishly allowlists it, 'none' is not a supported algorithm."""
    head = b64url_encode(json.dumps({"alg": "none", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    with pytest.raises(InvalidAlgorithmError):
        decode(f"{head}.{body}.AA", rsa_jwk, ["none"])


def test_attack_unsecured_jws_with_none_allowlisted_is_rejected(rsa_jwk, now):
    """
    The genuinely empty third segment, with the caller allowlisting 'none'. `decode`
    recognizes the RFC 7515 unsecured-JWS shape before structural parsing and refuses it
    regardless of what the header claims and regardless of the caller's allowlist.
    """
    head = b64url_encode(json.dumps({"alg": "none", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    with pytest.raises(InvalidAlgorithmError, match="Unsecured JWS"):
        decode(f"{head}.{body}.", rsa_jwk, ["none"])


def test_attack_hmac_signed_with_the_rsa_public_key_is_rejected(rsa_jwk, now):
    """
    Algorithm confusion: the attacker knows the provider's PUBLIC key, signs HS256 using
    it as the HMAC secret, and hopes the verifier picks HMAC. Requiring kty to match the
    algorithm family stops it even when the caller allowlists HS256.
    """
    public_pem = b64url_decode(rsa_jwk.n or "")
    head = b64url_encode(json.dumps({"alg": "HS256", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    forged = hmac_mod.new(public_pem, f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        decode(f"{head}.{body}.{b64url_encode(forged)}", rsa_jwk, ["RS256", "HS256"])


def test_attack_hmac_confusion_against_a_jwk_carrying_k_is_rejected(rsa_jwk, now):
    """
    The same confusion attack against a JWK that also carries a `k` member, so that the
    HMAC branch would succeed outright if `_check_kty` were absent. Without this variant
    the test above can pass for the wrong reason: a plain RSA JWK has no `k`, so a
    defenseless implementation would raise InvalidKeyError and still look safe.
    """
    secret = b64url_decode(rsa_jwk.n or "")
    hostile = JWK.model_validate(
        {
            "kty": "RSA",
            "kid": "rsa-test",
            "alg": "RS256",
            "n": rsa_jwk.n,
            "e": rsa_jwk.e,
            "k": b64url_encode(secret),
        }
    )
    head = b64url_encode(json.dumps({"alg": "HS256", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    forged = hmac_mod.new(secret, f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        decode(f"{head}.{body}.{b64url_encode(forged)}", hostile, ["RS256", "HS256"])


def test_attack_algorithm_outside_the_allowlist_is_rejected(rsa_private, rsa_jwk, now):
    token = encode({"sub": "admin", "exp": now + 600}, b"secret" * 8, "HS256")
    with pytest.raises(InvalidAlgorithmError, match="not permitted"):
        decode(token, rsa_jwk, ALGS)


def test_attack_tampered_payload_is_rejected(valid_token, rsa_jwk, now):
    head, _, sig = valid_token.split(".")
    forged = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{forged}.{sig}", rsa_jwk, ALGS)


def test_attack_tampered_header_is_rejected(valid_token, rsa_jwk):
    _, body, sig = valid_token.split(".")
    forged = b64url_encode(json.dumps({"alg": "RS256", "kid": "rsa-test", "x": 1}).encode())
    with pytest.raises(InvalidSignatureError):
        decode(f"{forged}.{body}.{sig}", rsa_jwk, ALGS)


def test_attack_stripped_signature_is_rejected(valid_token, rsa_jwk):
    """
    Dropping the signature off an otherwise genuine RS256 token. `decode` classifies the
    resulting "<header>.<payload>." as the RFC 7515 unsecured JWS and refuses it as an
    algorithm failure, which is why this expects InvalidAlgorithmError rather than the
    generic InvalidTokenError that `split_token` would raise for an empty segment.
    """
    head, body, _ = valid_token.split(".")
    with pytest.raises(InvalidAlgorithmError, match="Unsecured JWS"):
        decode(f"{head}.{body}.", rsa_jwk, ALGS)


def test_attack_unrecognized_crit_header_is_rejected(rsa_private, rsa_jwk, now):
    head = b64url_encode(
        json.dumps({"alg": "RS256", "kid": "rsa-test", "crit": ["urn:x"]}).encode()
    )
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidTokenError, match="crit"):
        decode(f"{head}.{body}.{b64url_encode(sig)}", rsa_jwk, ALGS)


def test_attack_extra_segment_is_rejected(valid_token, rsa_jwk):
    with pytest.raises(InvalidTokenError):
        decode(f"{valid_token}.extra", rsa_jwk, ALGS)


def test_attack_standard_base64_alphabet_is_rejected(rsa_jwk):
    with pytest.raises(InvalidTokenError, match="character"):
        decode("ab+d.ab+d.ab+d", rsa_jwk, ALGS)


def test_attack_non_canonical_padding_is_rejected(rsa_jwk):
    with pytest.raises(InvalidTokenError, match="character"):
        decode("YQ==.YQ==.YQ==", rsa_jwk, ALGS)


def test_attack_ecdsa_der_signature_is_rejected(ec_private, ec_jwk, now):
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

    head = b64url_encode(json.dumps({"alg": "ES256", "kid": "ec-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    der = ec_private.sign(f"{head}.{body}".encode("ascii"), ec_mod.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignatureError, match="length"):
        decode(f"{head}.{body}.{b64url_encode(der)}", ec_jwk, ["ES256"])


def test_attack_ecdsa_truncated_signature_is_rejected(ec_private, ec_jwk, now):
    """
    A genuine raw r||s signature with its trailing bytes shaved off. The length check in
    front of the primitive is what refuses it, before any r or s is reconstructed from a
    short buffer.
    """
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    head = b64url_encode(json.dumps({"alg": "ES256", "kid": "ec-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    der = ec_private.sign(f"{head}.{body}".encode("ascii"), ec_mod.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    with pytest.raises(InvalidSignatureError, match="length"):
        decode(f"{head}.{body}.{b64url_encode(raw[:-8])}", ec_jwk, ["ES256"])


def test_attack_ecdsa_zero_signature_is_rejected(ec_jwk, now):
    """
    A correctly sized all-zero signature. It must fail on verification, not on the
    length check, so this exercises the primitive rather than the guard in front of it.
    """
    head = b64url_encode(json.dumps({"alg": "ES256", "kid": "ec-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    zero_sig = bytes(64)
    with pytest.raises(InvalidSignatureError) as info:
        decode(f"{head}.{body}.{b64url_encode(zero_sig)}", ec_jwk, ["ES256"])
    assert "length" not in str(info.value)
