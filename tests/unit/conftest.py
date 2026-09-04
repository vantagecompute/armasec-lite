"""Key material shared across the jwt test modules."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from armasec_lite.jwt import b64url_encode
from armasec_lite.schemas import JWK


def _int_to_b64(value: int, length: int) -> str:
    return b64url_encode(value.to_bytes(length, "big"))


@pytest.fixture(scope="session")
def rsa_private():
    """A 2048 bit RSA private key, generated once per session."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_jwk(rsa_private):
    """The RSA public key as a JWK with kid 'rsa-test'."""
    numbers = rsa_private.public_key().public_numbers()
    return JWK.model_validate(
        {
            "kty": "RSA",
            "kid": "rsa-test",
            "alg": "RS256",
            "n": _int_to_b64(numbers.n, (numbers.n.bit_length() + 7) // 8),
            "e": _int_to_b64(numbers.e, (numbers.e.bit_length() + 7) // 8),
        }
    )


@pytest.fixture(scope="session")
def ec_private():
    """A P-256 private key, generated once per session."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def ec_jwk(ec_private):
    """The EC public key as a JWK with kid 'ec-test'."""
    numbers = ec_private.public_key().public_numbers()
    return JWK.model_validate(
        {
            "kty": "EC",
            "kid": "ec-test",
            "alg": "ES256",
            "crv": "P-256",
            "x": _int_to_b64(numbers.x, 32),
            "y": _int_to_b64(numbers.y, 32),
        }
    )


@pytest.fixture(scope="session")
def ed_private():
    """An Ed25519 private key, generated once per session."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def ed_jwk(ed_private):
    """The Ed25519 public key as a JWK with kid 'ed-test'."""
    from cryptography.hazmat.primitives import serialization

    raw = ed_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return JWK.model_validate(
        {"kty": "OKP", "kid": "ed-test", "alg": "EdDSA", "crv": "Ed25519", "x": b64url_encode(raw)}
    )


@pytest.fixture(scope="session")
def oct_jwk():
    """A symmetric key as a JWK with kid 'oct-test'."""
    return JWK.model_validate(
        {"kty": "oct", "kid": "oct-test", "alg": "HS256", "k": b64url_encode(b"s" * 32)}
    )
