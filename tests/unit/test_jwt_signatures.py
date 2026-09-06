import hashlib
import hmac as hmac_mod
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from armasec_lite import jwt
from armasec_lite.jwt import (
    _EC_CURVES,
    SUPPORTED_ALGORITHMS,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    b64url_decode,
    b64url_encode,
    decode,
    encode,
    verify_signature,
)
from armasec_lite.schemas import JWK

from .conftest import ALL_ALGORITHMS, HS_SECRET

SIGNING_INPUT = b"header.payload"


def _rsa_sig(private, pad, hash_alg):
    return private.sign(SIGNING_INPUT, pad, hash_alg)


def _ec_raw_sig(private, hash_alg, coord_bytes):
    der = private.sign(SIGNING_INPUT, ec.ECDSA(hash_alg))
    r, s = decode_dss_signature(der)
    return r.to_bytes(coord_bytes, "big") + s.to_bytes(coord_bytes, "big")


def test_supported_algorithms_cover_the_spec():
    assert SUPPORTED_ALGORITHMS == frozenset(
        {
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
        }
    )


@pytest.mark.parametrize(
    ("algorithm", "expected_bytes"),
    [("ES256", 32), ("ES384", 48), ("ES512", 66)],
)
def test_ecdsa_coordinate_sizes_are_correct(algorithm, expected_bytes):
    """
    P-521 is 521 bits, which is 65.125 bytes and therefore 66, not 64 or 65. Getting this
    wrong produces signatures that fail verification everywhere except against our own
    matching mistake.
    """
    _, coord_bytes = _EC_CURVES[algorithm]
    assert coord_bytes == expected_bytes


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_every_supported_algorithm_round_trips(algorithm, key_material):
    """
    Sign and verify once per supported algorithm, so that a constant that is wrong only
    for one variant cannot hide behind the 256 bit members of its own family.
    """
    material = key_material(algorithm)
    now = int(time.time())
    token = encode(
        {"sub": "abc", "exp": now + 60},
        material.sign_key,
        algorithm,
        headers={"kid": material.jwk.kid},
    )
    assert decode(token, material.jwk, [algorithm])["sub"] == "abc"


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_every_supported_algorithm_rejects_a_tampered_signature(algorithm, key_material):
    """
    The other half of the round trip. An implementation that accepted everything would
    pass the test above for every algorithm at once.
    """
    material = key_material(algorithm)
    now = int(time.time())
    token = encode(
        {"sub": "abc", "exp": now + 60},
        material.sign_key,
        algorithm,
        headers={"kid": material.jwk.kid},
    )
    head, body, signature_b64 = token.split(".")
    # Flip a bit rather than truncating, so the signature keeps its length and the ECDSA
    # length guard does not answer for the primitive.
    tampered = bytearray(b64url_decode(signature_b64))
    tampered[-1] ^= 0xFF
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{body}.{b64url_encode(bytes(tampered))}", material.jwk, [algorithm])


def test_rs256_accepts_a_valid_signature(rsa_private, rsa_jwk):
    sig = _rsa_sig(rsa_private, padding.PKCS1v15(), hashes.SHA256())
    verify_signature("RS256", rsa_jwk, SIGNING_INPUT, sig)


def test_rs256_rejects_a_tampered_signature(rsa_private, rsa_jwk):
    sig = bytearray(_rsa_sig(rsa_private, padding.PKCS1v15(), hashes.SHA256()))
    sig[-1] ^= 0xFF
    with pytest.raises(InvalidSignatureError):
        verify_signature("RS256", rsa_jwk, SIGNING_INPUT, bytes(sig))


def test_rs256_rejects_a_signature_over_different_input(rsa_private, rsa_jwk):
    sig = _rsa_sig(rsa_private, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignatureError):
        verify_signature("RS256", rsa_jwk, b"different.input", sig)


def test_ps256_accepts_a_valid_signature(rsa_private, rsa_jwk):
    pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size)
    verify_signature("PS256", rsa_jwk, SIGNING_INPUT, _rsa_sig(rsa_private, pad, hashes.SHA256()))


def test_ps256_rejects_a_pkcs1v15_signature(rsa_private, rsa_jwk):
    sig = _rsa_sig(rsa_private, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignatureError):
        verify_signature("PS256", rsa_jwk, SIGNING_INPUT, sig)


def test_es256_accepts_a_valid_raw_signature(ec_private, ec_jwk):
    verify_signature("ES256", ec_jwk, SIGNING_INPUT, _ec_raw_sig(ec_private, hashes.SHA256(), 32))


def test_es256_rejects_a_der_encoded_signature(ec_private, ec_jwk):
    der = ec_private.sign(SIGNING_INPUT, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignatureError, match="length"):
        verify_signature("ES256", ec_jwk, SIGNING_INPUT, der)


def test_es256_rejects_a_short_signature(ec_private, ec_jwk):
    raw = _ec_raw_sig(ec_private, hashes.SHA256(), 32)
    with pytest.raises(InvalidSignatureError, match="length"):
        verify_signature("ES256", ec_jwk, SIGNING_INPUT, raw[:-1])


def test_es256_rejects_a_long_signature(ec_private, ec_jwk):
    raw = _ec_raw_sig(ec_private, hashes.SHA256(), 32)
    with pytest.raises(InvalidSignatureError, match="length"):
        verify_signature("ES256", ec_jwk, SIGNING_INPUT, raw + b"\x00")


def test_es256_uses_the_algorithm_curve_not_the_jwk_crv(ec_private, ec_jwk):
    """A hostile JWKS must not be able to name a weaker curve than the algorithm implies."""
    lying = JWK.model_validate(
        {
            "kty": "EC",
            "kid": ec_jwk.kid,
            "crv": "P-521",
            "x": ec_jwk.x,
            "y": ec_jwk.y,
        }
    )
    verify_signature("ES256", lying, SIGNING_INPUT, _ec_raw_sig(ec_private, hashes.SHA256(), 32))


def test_eddsa_accepts_a_valid_signature(ed_private, ed_jwk):
    verify_signature("EdDSA", ed_jwk, SIGNING_INPUT, ed_private.sign(SIGNING_INPUT))


def test_eddsa_rejects_a_tampered_signature(ed_private, ed_jwk):
    sig = bytearray(ed_private.sign(SIGNING_INPUT))
    sig[0] ^= 0xFF
    with pytest.raises(InvalidSignatureError):
        verify_signature("EdDSA", ed_jwk, SIGNING_INPUT, bytes(sig))


def test_hs256_accepts_a_valid_mac(oct_jwk):
    sig = hmac_mod.new(HS_SECRET, SIGNING_INPUT, hashlib.sha256).digest()
    verify_signature("HS256", oct_jwk, SIGNING_INPUT, sig)


def test_hs256_rejects_a_wrong_mac(oct_jwk):
    sig = hmac_mod.new(b"wrong-key", SIGNING_INPUT, hashlib.sha256).digest()
    with pytest.raises(InvalidSignatureError):
        verify_signature("HS256", oct_jwk, SIGNING_INPUT, sig)


def test_rsa_key_is_refused_for_an_hmac_algorithm(rsa_jwk):
    """
    The classic forgery: sign with HS256 using the provider's RSA public key as the
    HMAC secret. Enforcing kty against the algorithm family is what blocks it.
    """
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        verify_signature("HS256", rsa_jwk, SIGNING_INPUT, b"whatever")


def test_oct_key_is_refused_for_an_rsa_algorithm(oct_jwk):
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        verify_signature("RS256", oct_jwk, SIGNING_INPUT, b"whatever")


def test_ec_key_is_refused_for_an_rsa_algorithm(ec_jwk):
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        verify_signature("RS256", ec_jwk, SIGNING_INPUT, b"whatever")


def test_unknown_algorithm_is_refused(rsa_jwk):
    with pytest.raises(InvalidAlgorithmError, match="none"):
        verify_signature("none", rsa_jwk, SIGNING_INPUT, b"")


def test_rsa_jwk_missing_modulus_is_refused():
    jwk = JWK.model_validate({"kty": "RSA", "kid": "broken", "e": "AQAB"})
    with pytest.raises(InvalidKeyError, match="'n'"):
        verify_signature("RS256", jwk, SIGNING_INPUT, b"sig")


def test_ec_jwk_missing_y_is_refused():
    jwk = JWK.model_validate(
        {"kty": "EC", "kid": "broken", "crv": "P-256", "x": b64url_encode(b"\x01" * 32)}
    )
    with pytest.raises(InvalidKeyError, match="'y'"):
        verify_signature("ES256", jwk, SIGNING_INPUT, b"\x00" * 64)


def test_public_keys_are_built_once_per_distinct_key(rsa_jwk, ec_jwk):
    """
    Reconstructing a public key from JWK members is cached on the key material.

    Rebuilding an RSA key from its numbers cost roughly 10% of a warm decode, and a JWKS
    changes only on a rotation. The cache is keyed on the base64url members themselves, so
    two JWKs holding identical material are genuinely the same key and cannot alias each
    other by accident. For EC the algorithm is part of the key too, since the curve comes
    from the algorithm rather than from the JWK.
    """
    assert jwt._rsa_public_key(rsa_jwk) is jwt._rsa_public_key(rsa_jwk)
    assert jwt._ec_public_key("ES256", ec_jwk) is jwt._ec_public_key("ES256", ec_jwk)


def test_distinct_keys_do_not_share_a_cache_entry(rsa_jwk, attacker_rsa_private):
    """
    A second key with different material gets its own object, never the first one's.

    This is the property that makes the cache safe. If it were keyed on anything looser
    than the material, one JWK could be verified against another's key, which is an
    authentication bypass rather than a performance bug.
    """
    numbers = attacker_rsa_private.public_key().public_numbers()
    other = JWK.model_validate(
        {
            "kty": "RSA",
            "kid": "rsa-test",
            "n": b64url_encode(numbers.n.to_bytes(256, "big")),
            "e": b64url_encode(numbers.e.to_bytes(3, "big")),
        }
    )
    assert jwt._rsa_public_key(rsa_jwk) is not jwt._rsa_public_key(other)
    assert jwt._rsa_public_key(other).public_numbers().n == numbers.n
