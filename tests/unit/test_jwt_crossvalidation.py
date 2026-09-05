"""
Cross-validation against PyJWT.

A hand written JWT implementation drifts from the specification in ways its own tests
cannot see, because those tests encode the same misunderstanding as the implementation.
Checking both directions against an independent library is the defense: tokens we sign
must verify under PyJWT, and tokens PyJWT signs must verify under us.
"""

import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization

from armasec_lite.jwt import (
    ExpiredSignatureError,
    InvalidSignatureError,
    decode,
    encode,
)

from .conftest import ALL_ALGORITHMS, HS_SECRET


@pytest.fixture
def rsa_pem(rsa_private):
    return rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def rsa_pub_pem(rsa_private):
    return rsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_our_token_verifies_under_pyjwt(key_material, algorithm):
    """
    Every supported algorithm, not just the RSA family. This is the direction that pins
    the ES512 coordinate size deterministically: a wrong constant produces a signature of
    the wrong width, and an independent verifier refuses it every time rather than only
    when the integers happen not to fit.
    """
    material = key_material(algorithm)
    now = int(time.time())
    token = encode(
        {"sub": "abc", "exp": now + 60, "iss": "https://auth.example.com"},
        material.sign_key,
        algorithm,
        headers={"kid": material.jwk.kid},
    )
    claims = pyjwt.decode(
        token,
        material.verify_key,
        algorithms=[algorithm],
        issuer="https://auth.example.com",
        options={"verify_aud": False},
    )
    assert claims["sub"] == "abc"


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_pyjwt_token_verifies_under_us(key_material, algorithm):
    """The same coverage in the other direction, so neither side can drift alone."""
    material = key_material(algorithm)
    now = int(time.time())
    token = pyjwt.encode(
        {"sub": "abc", "exp": now + 60, "aud": "my-api", "iss": "https://auth.example.com"},
        material.sign_key,
        algorithm=algorithm,
        headers={"kid": material.jwk.kid},
    )
    claims = decode(
        token,
        material.jwk,
        [algorithm],
        audience="my-api",
        issuer="https://auth.example.com",
    )
    assert claims["sub"] == "abc"


def test_pyjwt_expired_token_is_rejected_by_us(rsa_pem, rsa_jwk):
    now = int(time.time())
    token = pyjwt.encode({"sub": "abc", "exp": now - 60}, rsa_pem, algorithm="RS256")
    with pytest.raises(ExpiredSignatureError):
        decode(token, rsa_jwk, ["RS256"])


def test_our_expired_token_is_rejected_by_pyjwt(rsa_pem, rsa_pub_pem):
    now = int(time.time())
    token = encode({"sub": "abc", "exp": now - 60}, rsa_pem, "RS256")
    with pytest.raises(pyjwt.ExpiredSignatureError):
        pyjwt.decode(token, rsa_pub_pem, algorithms=["RS256"], options={"verify_aud": False})


def test_our_tampered_token_is_rejected_by_pyjwt(rsa_pem, rsa_pub_pem):
    now = int(time.time())
    token = encode({"sub": "abc", "exp": now + 60}, rsa_pem, "RS256")
    head, body, sig = token.split(".")
    with pytest.raises(pyjwt.InvalidSignatureError):
        pyjwt.decode(
            f"{head}.{body}.{sig[:-4]}AAAA",
            rsa_pub_pem,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )


def test_pyjwt_tampered_token_is_rejected_by_us(rsa_pem, rsa_jwk):
    now = int(time.time())
    token = pyjwt.encode({"sub": "abc", "exp": now + 60}, rsa_pem, algorithm="RS256")
    head, body, sig = token.split(".")
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{body}.{sig[:-4]}AAAA", rsa_jwk, ["RS256"])


def test_es256_round_trips_through_pyjwt(ec_private, ec_jwk):
    pem = ec_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    now = int(time.time())
    token = pyjwt.encode({"sub": "abc", "exp": now + 60}, pem, algorithm="ES256")
    assert decode(token, ec_jwk, ["ES256"])["sub"] == "abc"


def test_eddsa_round_trips_through_pyjwt(ed_private, ed_jwk):
    pem = ed_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    now = int(time.time())
    token = pyjwt.encode({"sub": "abc", "exp": now + 60}, pem, algorithm="EdDSA")
    assert decode(token, ed_jwk, ["EdDSA"])["sub"] == "abc"


def test_our_es256_token_verifies_under_pyjwt(ec_private):
    """
    The direction that catches a mirrored bug: our _sign does DER to raw r||s and our
    verify does raw to DER, so a matched pair of errors round-trips cleanly through our
    own tests and fails only against an independent verifier.
    """
    private_pem = ec_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = ec_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = int(time.time())
    token = encode({"sub": "abc", "exp": now + 60}, private_pem, "ES256")
    claims = pyjwt.decode(token, public_pem, algorithms=["ES256"], options={"verify_aud": False})
    assert claims["sub"] == "abc"


def test_our_eddsa_token_verifies_under_pyjwt(ed_private):
    """Same argument as ES256, without the coordinate encoding."""
    private_pem = ed_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = ed_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = int(time.time())
    token = encode({"sub": "abc", "exp": now + 60}, private_pem, "EdDSA")
    claims = pyjwt.decode(token, public_pem, algorithms=["EdDSA"], options={"verify_aud": False})
    assert claims["sub"] == "abc"


def test_hs256_round_trips_through_pyjwt(oct_jwk):
    now = int(time.time())
    secret = HS_SECRET
    token = pyjwt.encode({"sub": "abc", "exp": now + 60}, secret, algorithm="HS256")
    assert decode(token, oct_jwk, ["HS256"])["sub"] == "abc"


def test_our_hs256_token_verifies_under_pyjwt():
    now = int(time.time())
    secret = HS_SECRET
    token = encode({"sub": "abc", "exp": now + 60}, secret, "HS256")
    assert pyjwt.decode(token, secret, algorithms=["HS256"])["sub"] == "abc"
