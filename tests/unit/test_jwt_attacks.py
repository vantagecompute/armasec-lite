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

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.jwt import (
    MAX_TOKEN_BYTES,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    b64url_decode,
    b64url_encode,
    decode,
    encode,
)
from armasec_lite.schemas import JWK, JWKs
from armasec_lite.token_decoder import TokenDecoder

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


def test_attack_algorithm_outside_the_allowlist_is_rejected(key_material, now):
    """
    A genuinely valid RS384 token offered to a route that allows only RS256. The token is
    signed by the very key the verifier holds, so the signature is not what refuses it:
    the allowlist is. Proven by decoding the same token successfully with RS384 allowed.
    """
    material = key_material("RS384")
    token = encode(
        {"sub": "admin", "exp": now + 600},
        material.sign_key,
        "RS384",
        headers={"kid": material.jwk.kid},
    )
    assert decode(token, material.jwk, ["RS384"])["sub"] == "admin"

    with pytest.raises(InvalidAlgorithmError, match="not permitted"):
        decode(token, material.jwk, ALGS)


def test_attack_kid_mismatch_is_rejected(attacker_rsa_private, rsa_jwk, now):
    """
    `kid` is read from the unverified header, so the attacker chooses it. It may select a
    key and nothing else. Two shapes: a kid that is in no key set at all, and a kid
    naming a legitimate key over a token that key did not sign.
    """
    decoder = TokenDecoder(JWKs(keys=(rsa_jwk,)))

    def _forge(kid: str) -> str:
        head = b64url_encode(json.dumps({"alg": "RS256", "kid": kid}).encode())
        body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
        sig = attacker_rsa_private.sign(
            f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{head}.{body}.{b64url_encode(sig)}"

    with pytest.raises(AuthenticationError, match="matching jwk"):
        decoder.decode(_forge("no-such-kid"))

    with pytest.raises(InvalidSignatureError):
        decoder.decode(_forge(rsa_jwk.kid))


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
    """
    A segment of length 4n + 1 needs three padding characters, which no canonical base64
    encoding ever produces. Every character is in the base64url alphabet, so this reaches
    the length rule rather than the alphabet rule above it.
    """
    with pytest.raises(InvalidTokenError, match="length"):
        decode("QUJDR.QUJDR.QUJDR", rsa_jwk, ALGS)


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


def test_attack_weak_rsa_modulus_is_rejected(now):
    """
    A JWKS serving an undersized RSA key must not be usable, however well it signs.

    RFC 7518 section 3.3 requires a modulus of at least 2048 bits for the RS and PS
    families. `cryptography` refuses to GENERATE anything under 1024 bits but happily
    reconstructs any size at all from public numbers, so a JWKS publishing a 512 bit
    modulus was accepted and its signatures verified. A modulus that small factors on a
    laptop, which hands the private half to whoever wants it.

    This is the RSA counterpart of the curve pin in `_ec_public_key`: the algorithm, not
    the key material, decides what strength the route agreed to accept.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    numbers = weak.public_key().public_numbers()
    weak_jwk = JWK.model_validate(
        {
            "kty": "RSA",
            "kid": "rsa-test",
            "n": b64url_encode(numbers.n.to_bytes(128, "big")),
            "e": b64url_encode(numbers.e.to_bytes(3, "big")),
        }
    )
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    sig = weak.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    token = f"{head}.{body}.{b64url_encode(sig)}"

    with pytest.raises(InvalidKeyError, match="2048"):
        decode(token, weak_jwk, ALGS)


def test_attack_oversized_token_is_rejected(rsa_jwk):
    """
    A token past `MAX_TOKEN_BYTES` is refused before anything decodes it.

    The cap exists because a JSON segment is parsed before it is measured. A header of
    deeply nested arrays drives CPython's JSON scanner into recursion, and a 267KB token
    consumed 8MB of stack before raising, which is a memory amplification of roughly
    thirty to one from a single request.
    """
    oversized = "a" * (MAX_TOKEN_BYTES + 1) + ".b.c"
    with pytest.raises(InvalidTokenError, match="too long"):
        decode(oversized, rsa_jwk, ALGS)


def test_attack_deeply_nested_header_cannot_exhaust_the_stack(rsa_jwk):
    """
    The nesting that used to reach a RecursionError no longer fits inside the size cap.

    The header is parsed before the signature is checked, by necessity: `alg` has to be
    read to know what to verify with. So header nesting is reachable by an entirely
    unauthenticated caller, unlike payload nesting, which is only parsed after the
    signature verifies.
    """
    deep = '{"alg":"RS256","x":' + "[" * 100_000 + "]" * 100_000 + "}"
    token = f"{b64url_encode(deep.encode())}.{b64url_encode(b'{}')}.{b64url_encode(b'x')}"
    assert len(token) > MAX_TOKEN_BYTES
    with pytest.raises(InvalidTokenError, match="too long"):
        decode(token, rsa_jwk, ALGS)


def test_attack_jku_header_is_ignored(rsa_jwk, now, attacker_rsa_private):
    """
    A `jku` header naming an attacker's key set must not be fetched or honored.

    The classic key-injection attack: point the verifier at a JWKS the attacker controls
    and sign with the matching private key. `armasec_lite` never reads `jku`, so the token
    is verified against the configured key set and fails on the signature. Defended by
    construction rather than by a check, which is why it needs a test to stay true.
    """
    head = b64url_encode(
        json.dumps(
            {"alg": "RS256", "kid": "rsa-test", "jku": "https://attacker.example.com/jwks"}
        ).encode()
    )
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    sig = attacker_rsa_private.sign(
        f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{body}.{b64url_encode(sig)}", rsa_jwk, ALGS)


def test_attack_x5u_header_is_ignored(rsa_jwk, now, attacker_rsa_private):
    """The `x5u` variant of the same key-injection attack, over an X.509 chain URL."""
    head = b64url_encode(
        json.dumps(
            {"alg": "RS256", "kid": "rsa-test", "x5u": "https://attacker.example.com/chain.pem"}
        ).encode()
    )
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    sig = attacker_rsa_private.sign(
        f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{body}.{b64url_encode(sig)}", rsa_jwk, ALGS)


def test_attack_embedded_jwk_header_is_ignored(rsa_jwk, now, attacker_rsa_private):
    """
    A `jwk` header carrying the attacker's own public key must not be used to verify.

    The self-contained form of key injection: no fetch required, the key travels in the
    token. Refused for the same reason as `jku`, in that the header member is never read.
    """
    attacker_numbers = attacker_rsa_private.public_key().public_numbers()
    head = b64url_encode(
        json.dumps(
            {
                "alg": "RS256",
                "kid": "rsa-test",
                "jwk": {
                    "kty": "RSA",
                    "n": b64url_encode(attacker_numbers.n.to_bytes(256, "big")),
                    "e": b64url_encode(attacker_numbers.e.to_bytes(3, "big")),
                },
            }
        ).encode()
    )
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    sig = attacker_rsa_private.sign(
        f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{body}.{b64url_encode(sig)}", rsa_jwk, ALGS)


def test_attack_eddsa_curve_substitution_is_rejected(ed_jwk, ed_private):
    """
    An OKP key naming a curve other than Ed25519 is refused rather than guessed at.

    `verify_signature` accepts exactly one EdDSA curve. A JWKS substituting Ed448, or any
    other name, gets a refusal naming the algorithm rather than an attempt to read the key
    material as something it is not.
    """
    substituted = ed_jwk.model_copy(update={"crv": "Ed448"})
    token = encode({"sub": "abc"}, _ed_pem(ed_private), "EdDSA", {"kid": "ed-test"})
    with pytest.raises(InvalidAlgorithmError, match="Ed448"):
        decode(token, substituted, ["EdDSA"])


def _ed_pem(ed_private):
    from cryptography.hazmat.primitives import serialization

    return ed_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
