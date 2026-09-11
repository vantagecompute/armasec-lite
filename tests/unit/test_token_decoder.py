"""Tests for TokenDecoder: turning a compact JWT plus a JWKS into a TokenPayload."""

import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from armasec_lite.exceptions import AuthenticationError, PayloadMappingError, UnknownKeyIdError
from armasec_lite.jwt import b64url_encode
from armasec_lite.schemas import JWK, JWKs
from armasec_lite.token_decoder import TokenDecoder, extract_keycloak_permissions


def _sign(rsa_private, claims, kid="rsa-test"):
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": kid}).encode())
    body = b64url_encode(json.dumps(claims).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64url_encode(sig)}"


@pytest.fixture
def jwks(rsa_jwk):
    return JWKs(keys=(rsa_jwk,))


@pytest.fixture
def now():
    return int(time.time())


def test_get_decode_key_matches_on_kid(jwks, rsa_private, rsa_jwk, now):
    decoder = TokenDecoder(jwks)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    assert decoder.get_decode_key(token) is rsa_jwk


def test_get_decode_key_raises_without_a_kid(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks)
    head = b64url_encode(json.dumps({"alg": "RS256"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc"}).encode())
    with pytest.raises(AuthenticationError, match="kid"):
        decoder.get_decode_key(f"{head}.{body}.sig")


def test_get_decode_key_raises_on_an_unknown_kid(jwks, rsa_private, now):
    """Without a refresher there is nothing a caller could do, so this is a plain refusal."""
    decoder = TokenDecoder(jwks)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60}, kid="unknown")
    with pytest.raises(AuthenticationError, match="matching jwk") as info:
        decoder.get_decode_key(token)
    assert not isinstance(info.value, UnknownKeyIdError)


def test_get_decode_key_reports_an_unknown_kid_without_refreshing(rsa_private, rsa_jwk, now):
    """
    The decoder must never perform the refetch itself.

    `get_decode_key` is called from `TokenSecurity.__call__` on the event loop thread, and
    a blocking HTTP fetch there stalls every other request in the process. Reporting the
    miss lets the caller drive the refresh from a worker thread instead.
    """
    calls = []

    def _refresh():
        calls.append(1)
        return JWKs(keys=(rsa_jwk,))

    decoder = TokenDecoder(JWKs(keys=(rsa_jwk,)), jwks_refresher=_refresh)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60}, kid="never-there")
    with pytest.raises(UnknownKeyIdError, match="matching jwk"):
        decoder.get_decode_key(token)
    assert calls == []


def test_refresh_keys_recovers_a_rotated_kid(rsa_private, rsa_jwk, now):
    """A rotated kid recovers once the caller has run the refresher."""
    rotated = JWK.model_validate({"kty": "RSA", "kid": "rotated", "n": rsa_jwk.n, "e": rsa_jwk.e})
    calls = []

    def _refresh():
        calls.append(1)
        return JWKs(keys=(rotated,))

    decoder = TokenDecoder(JWKs(keys=(rsa_jwk,)), jwks_refresher=_refresh)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60}, kid="rotated")
    with pytest.raises(UnknownKeyIdError):
        decoder.get_decode_key(token)

    decoder.refresh_keys()
    assert decoder.get_decode_key(token).kid == "rotated"
    assert len(calls) == 1


def test_refresh_keys_does_nothing_without_a_refresher(jwks, rsa_jwk):
    decoder = TokenDecoder(jwks)
    decoder.refresh_keys()
    assert list(decoder.jwks.keys) == [rsa_jwk]


def test_decode_builds_a_token_payload(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "permissions": ["read:x"]})
    payload = decoder.decode(token)
    assert payload.sub == "abc"
    assert payload.permissions == {"read:x"}
    assert payload.original_token == token


def test_decode_survives_a_token_carrying_an_original_token_claim(jwks, rsa_private, now):
    """
    A claim named `original_token` used to collide with the keyword argument and raise
    TypeError, which surfaces as a 500 rather than a 401. The real token wins.
    """
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "original_token": "spoofed"})
    assert TokenDecoder(jwks).decode(token).original_token == token


def test_decode_applies_the_permission_extractor(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, permission_extractor=extract_keycloak_permissions)
    token = _sign(
        rsa_private,
        {
            "sub": "abc",
            "exp": now + 60,
            "azp": "my-client",
            "resource_access": {"my-client": {"roles": ["read:stuff"]}},
        },
    )
    assert decoder.decode(token).permissions == {"read:stuff"}


def test_decode_raises_payload_mapping_error_when_the_extractor_misses(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, permission_extractor=extract_keycloak_permissions)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "azp": "my-client"})
    with pytest.raises(PayloadMappingError):
        decoder.decode(token)


def test_decode_resolves_claim_locations_through_the_audience_placeholder(jwks, rsa_private, now):
    decoder = TokenDecoder(
        jwks,
        claim_locations={
            "permissions": ("resource_access", "{audience}", "permission_roles"),
            "application_roles": ("resource_access", "{audience}", "application_roles"),
        },
    )
    token = _sign(
        rsa_private,
        {
            "sub": "abc",
            "exp": now + 60,
            "aud": "my-cluster",
            "azp": "token-broker",
            "resource_access": {
                "my-cluster": {
                    "permission_roles": ["read:stuff"],
                    "application_roles": ["kubernetes:admin"],
                }
            },
        },
    )
    payload = decoder.decode(token, audience="my-cluster")
    assert payload.permissions == {"read:stuff"}
    # Undeclared on TokenPayload, reachable because the model allows extras.
    assert payload.application_roles == ["kubernetes:admin"]


def test_decode_resolves_claim_locations_through_the_azp_placeholder(jwks, rsa_private, now):
    decoder = TokenDecoder(
        jwks, claim_locations={"permissions": ("resource_access", "{azp}", "roles")}
    )
    token = _sign(
        rsa_private,
        {
            "sub": "abc",
            "exp": now + 60,
            "azp": "my-client",
            "resource_access": {"my-client": {"roles": ["read:stuff"]}},
        },
    )
    assert decoder.decode(token).permissions == {"read:stuff"}


def test_decode_leaves_an_unresolved_claim_location_at_its_default(jwks, rsa_private, now):
    decoder = TokenDecoder(
        jwks, claim_locations={"permissions": ("resource_access", "{audience}", "nope")}
    )
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "resource_access": {}})
    assert decoder.decode(token).permissions == set()


def test_decode_raises_payload_mapping_error_when_a_required_claim_misses(jwks, rsa_private, now):
    decoder = TokenDecoder(
        jwks,
        claim_locations={"permissions": ("resource_access", "{audience}", "permission_roles")},
        required_claims={"permissions"},
    )
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "my-cluster"})
    with pytest.raises(PayloadMappingError):
        decoder.decode(token, audience="my-cluster")


def test_decode_lets_the_permission_extractor_win_over_a_claim_location(jwks, rsa_private, now):
    decoder = TokenDecoder(
        jwks,
        claim_locations={"permissions": ("resource_access", "{audience}", "permission_roles")},
        permission_extractor=extract_keycloak_permissions,
    )
    token = _sign(
        rsa_private,
        {
            "sub": "abc",
            "exp": now + 60,
            "aud": "my-cluster",
            "azp": "my-client",
            "resource_access": {
                "my-client": {"roles": ["from:extractor"]},
                "my-cluster": {"permission_roles": ["from:location"]},
            },
        },
    )
    assert decoder.decode(token, audience="my-cluster").permissions == {"from:extractor"}


def test_decode_honors_the_options_override(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, decode_options_override={"verify_exp": False})
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 60})
    assert decoder.decode(token).sub == "abc"


def test_decode_merges_call_options_over_the_override(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, decode_options_override={"verify_exp": False})
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 60})
    with pytest.raises(AuthenticationError):
        decoder.decode(token, options={"verify_exp": True})


def test_decode_passes_audience_through(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "my-api"})
    assert decoder.decode(token, audience="my-api").sub == "abc"
    with pytest.raises(AuthenticationError):
        decoder.decode(token, audience="other-api")


def test_decode_restricts_the_algorithm_to_the_configured_one(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, algorithm="ES256")
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    with pytest.raises(AuthenticationError, match="not permitted"):
        decoder.decode(token)


def test_extract_keycloak_permissions_reads_the_nested_roles():
    decoded = {"azp": "my-client", "resource_access": {"my-client": {"roles": ["read:stuff"]}}}
    assert extract_keycloak_permissions(decoded) == {"read:stuff"}
