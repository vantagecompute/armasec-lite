"""Key material shared across the jwt test modules."""

from collections import namedtuple

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from armasec_lite.jwt import b64url_encode
from armasec_lite.schemas import JWK

#: Every algorithm the library supports, in a stable order so that a parametrized test
#: reports the same ids from run to run. Kept as a literal rather than derived from
#: SUPPORTED_ALGORITHMS, so that dropping an algorithm from the implementation shows up
#: as a failure here rather than as a silently shrunken test matrix.
ALL_ALGORITHMS = [
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "HS256",
    "HS384",
    "HS512",
    "EdDSA",
]

#: The raw secret behind `oct_jwk`.
HS_SECRET = b"s" * 64

#: Everything a round trip for one algorithm needs. `sign_key` and `verify_key` are what
#: an outside library wants (PEM, or the raw secret for HMAC); `jwk` is what we want.
KeyMaterial = namedtuple("KeyMaterial", ["sign_key", "verify_key", "jwk"])


def _int_to_b64(value: int, length: int) -> str:
    return b64url_encode(value.to_bytes(length, "big"))


def _private_pem(private) -> bytes:
    return private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_pem(private) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


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
def attacker_rsa_private():
    """
    A second, unrelated 2048 bit RSA key, standing in for one an attacker controls.

    Needed to distinguish "the signature is wrong" from "the key is the wrong type": a
    forgery that names a legitimate `kid` has to be signed by something.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


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
def ec384_private():
    """A P-384 private key, generated once per session."""
    return ec.generate_private_key(ec.SECP384R1())


@pytest.fixture(scope="session")
def ec384_jwk(ec384_private):
    """The P-384 public key as a JWK with kid 'ec384-test'."""
    numbers = ec384_private.public_key().public_numbers()
    return JWK.model_validate(
        {
            "kty": "EC",
            "kid": "ec384-test",
            "alg": "ES384",
            "crv": "P-384",
            "x": _int_to_b64(numbers.x, 48),
            "y": _int_to_b64(numbers.y, 48),
        }
    )


@pytest.fixture(scope="session")
def ec521_private():
    """A P-521 private key, generated once per session."""
    return ec.generate_private_key(ec.SECP521R1())


@pytest.fixture(scope="session")
def ec521_jwk(ec521_private):
    """
    The P-521 public key as a JWK with kid 'ec521-test'.

    The coordinates are 66 bytes, not 64 or 65: P-521 is 521 bits, which is 65.125 bytes
    and therefore rounds up to 66. RFC 7518 requires the fixed-width encoding, so a
    shorter one is wrong even when the integer happens to fit.
    """
    numbers = ec521_private.public_key().public_numbers()
    return JWK.model_validate(
        {
            "kty": "EC",
            "kid": "ec521-test",
            "alg": "ES512",
            "crv": "P-521",
            "x": _int_to_b64(numbers.x, 66),
            "y": _int_to_b64(numbers.y, 66),
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
        {"kty": "oct", "kid": "oct-test", "alg": "HS256", "k": b64url_encode(HS_SECRET)}
    )


@pytest.fixture
def key_material(request):
    """
    Resolve the key material for any supported algorithm, as a `KeyMaterial`.

    One RSA key serves every RS and PS variant and one oct key serves every HS variant,
    since only the key type has to match the algorithm family. Each EC curve is pinned to
    its algorithm, which is the point: `decode` takes the curve from the algorithm rather
    than from the JWK, so ES384 and ES512 need real P-384 and P-521 keys to be exercised
    at all.

    Args:
        request: The pytest request, used to pull the per-algorithm key fixtures lazily.
    """

    def _resolve(algorithm: str) -> KeyMaterial:
        if algorithm.startswith("HS"):
            return KeyMaterial(HS_SECRET, HS_SECRET, request.getfixturevalue("oct_jwk"))

        if algorithm.startswith(("RS", "PS")):
            private_name, jwk_name = "rsa_private", "rsa_jwk"
        elif algorithm == "EdDSA":
            private_name, jwk_name = "ed_private", "ed_jwk"
        else:
            private_name, jwk_name = {
                "ES256": ("ec_private", "ec_jwk"),
                "ES384": ("ec384_private", "ec384_jwk"),
                "ES512": ("ec521_private", "ec521_jwk"),
            }[algorithm]

        private = request.getfixturevalue(private_name)
        return KeyMaterial(
            _private_pem(private),
            _public_pem(private),
            request.getfixturevalue(jwk_name),
        )

    return _resolve
