import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from starlette.datastructures import Headers

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.jwt import b64url_encode
from armasec_lite.schemas import JWKs, OpenidConfig
from armasec_lite.token_decoder import TokenDecoder
from armasec_lite.token_manager import TokenManager

ISSUER = "https://auth.example.com"


def _sign(rsa_private, claims, kid="rsa-test"):
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": kid}).encode())
    body = b64url_encode(json.dumps(claims).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64url_encode(sig)}"


@pytest.fixture
def openid_config():
    return OpenidConfig.model_validate(
        {"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks"}, context={"require_https": True}
    )


@pytest.fixture
def decoder(rsa_jwk):
    return TokenDecoder(JWKs(keys=(rsa_jwk,)))


@pytest.fixture
def now():
    return int(time.time())


def test_class_attributes_match_upstream():
    assert TokenManager.auth_scheme == "bearer"
    assert TokenManager.header_key == "Authorization"


def test_unpack_token_from_a_dict(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    assert (
        manager.unpack_token_from_header({"Authorization": "Bearer abc.def.ghi"}) == "abc.def.ghi"
    )


def test_unpack_token_from_starlette_headers(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    headers = Headers({"authorization": "Bearer abc.def.ghi"})
    assert manager.unpack_token_from_header(headers) == "abc.def.ghi"


def test_unpack_token_accepts_any_scheme_casing(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    assert manager.unpack_token_from_header({"Authorization": "bEaReR tok"}) == "tok"


def test_unpack_token_requires_the_header(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    with pytest.raises(AuthenticationError, match="Could not find auth header"):
        manager.unpack_token_from_header({})


def test_unpack_token_requires_a_scheme_and_a_token(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    with pytest.raises(AuthenticationError):
        manager.unpack_token_from_header({"Authorization": "Bearer"})
    with pytest.raises(AuthenticationError):
        manager.unpack_token_from_header({"Authorization": ""})


def test_unpack_token_rejects_a_wrong_scheme(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    with pytest.raises(AuthenticationError, match="Invalid auth scheme"):
        manager.unpack_token_from_header({"Authorization": "Basic abc"})


def test_extract_token_payload_decodes(openid_config, decoder, rsa_private, now):
    manager = TokenManager(openid_config, decoder)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": ISSUER})
    payload = manager.extract_token_payload({"Authorization": f"Bearer {token}"})
    assert payload.sub == "abc"


def test_extract_token_payload_verifies_the_issuer_by_default(
    openid_config, decoder, rsa_private, now
):
    manager = TokenManager(openid_config, decoder)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": "https://evil.example.com"})
    with pytest.raises(AuthenticationError):
        manager.extract_token_payload({"Authorization": f"Bearer {token}"})


def test_extract_token_payload_can_skip_issuer_verification(
    openid_config, decoder, rsa_private, now
):
    manager = TokenManager(openid_config, decoder, verify_issuer=False)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": "https://evil.example.com"})
    assert manager.extract_token_payload({"Authorization": f"Bearer {token}"}).sub == "abc"


def test_extract_token_payload_checks_the_audience(openid_config, decoder, rsa_private, now):
    manager = TokenManager(openid_config, decoder, audience="my-api")
    good = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": ISSUER, "aud": "my-api"})
    bad = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": ISSUER, "aud": "other"})
    assert manager.extract_token_payload({"Authorization": f"Bearer {good}"}).sub == "abc"
    with pytest.raises(AuthenticationError):
        manager.extract_token_payload({"Authorization": f"Bearer {bad}"})


def test_ignore_audience_skips_verification_when_no_audience_is_set(
    openid_config, decoder, rsa_private, now
):
    manager = TokenManager(openid_config, decoder, ignore_audience=True)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": ISSUER, "aud": "anything"})
    assert manager.extract_token_payload({"Authorization": f"Bearer {token}"}).sub == "abc"
