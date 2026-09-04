"""
Tests for the pydantic models describing data exchanged with an OIDC provider.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from armasec_lite.schemas import JWK, DomainConfig, JWKs, OpenidConfig, PermissionMode


def test_permission_mode_values_match_upstream():
    assert PermissionMode.ALL.value == "ALL"
    assert PermissionMode.SOME.value == "SOME"
    assert PermissionMode("ALL") is PermissionMode.ALL


def test_jwk_keeps_unknown_members_as_attributes():
    jwk = JWK.model_validate(
        {"kty": "RSA", "kid": "abc", "alg": "RS256", "n": "AAAA", "e": "AQAB", "novel": 1}
    )
    assert jwk.kty == "RSA"
    assert jwk.kid == "abc"
    assert jwk.n == "AAAA"
    # extra="allow" puts unknown members directly on the model, not in a nested dict.
    assert jwk.novel == 1  # type: ignore[attr-defined]
    assert jwk.model_extra == {"novel": 1}


def test_jwk_requires_kty_and_kid():
    with pytest.raises(ValidationError, match="kid"):
        JWK.model_validate({"kty": "RSA"})
    with pytest.raises(ValidationError, match="kty"):
        JWK.model_validate({"kid": "abc"})


def test_jwk_does_not_require_rsa_fields_for_ec_keys():
    jwk = JWK.model_validate({"kty": "EC", "kid": "ec1", "crv": "P-256", "x": "AA", "y": "BB"})
    assert jwk.n is None
    assert jwk.crv == "P-256"


def test_jwk_does_not_require_rsa_fields_for_okp_keys():
    jwk = JWK.model_validate({"kty": "OKP", "kid": "okp1", "crv": "Ed25519", "x": "AA"})
    assert jwk.n is None
    assert jwk.e is None
    assert jwk.crv == "Ed25519"


def test_jwks_builds_key_list():
    jwks = JWKs.model_validate(
        {"keys": [{"kty": "RSA", "kid": "one"}, {"kty": "RSA", "kid": "two"}]}
    )
    assert [k.kid for k in jwks.keys] == ["one", "two"]


def test_jwks_requires_keys_to_be_a_list():
    with pytest.raises(ValidationError, match="keys"):
        JWKs.model_validate({"keys": "not-a-list"})


def test_openid_config_accepts_https_urls():
    config = OpenidConfig.model_validate(
        {"issuer": "https://auth.example.com", "jwks_uri": "https://auth.example.com/jwks"}
    )
    # AnyHttpUrl normalizes a bare-host URL by appending a trailing slash. This matters
    # later: TokenManager compares str(issuer) against a token's `iss` claim for exact
    # equality, so a provider's `issuer` value that already omits the trailing slash
    # (the common case) will not round-trip byte-for-byte through this model.
    assert str(config.issuer) == "https://auth.example.com/"
    assert str(config.jwks_uri) == "https://auth.example.com/jwks"


def test_openid_config_rejects_non_http_scheme():
    with pytest.raises(ValidationError, match="scheme"):
        OpenidConfig.model_validate(
            {"issuer": "https://auth.example.com", "jwks_uri": "file:///etc/passwd"}
        )


def test_openid_config_rejects_url_without_host():
    with pytest.raises(ValidationError, match="host"):
        OpenidConfig.model_validate(
            {"issuer": "https://", "jwks_uri": "https://auth.example.com/jwks"}
        )


def test_openid_config_pins_jwks_scheme_to_https_when_required():
    with pytest.raises(ValidationError, match="https"):
        OpenidConfig.model_validate(
            {"issuer": "https://auth.example.com", "jwks_uri": "http://auth.example.com/jwks"},
            context={"require_https": True},
        )


def test_openid_config_allows_http_jwks_when_https_not_required():
    config = OpenidConfig.model_validate(
        {"issuer": "http://localhost:8080", "jwks_uri": "http://localhost:8080/jwks"},
        context={"require_https": False},
    )
    assert str(config.jwks_uri) == "http://localhost:8080/jwks"


def test_openid_config_retains_unknown_members():
    config = OpenidConfig.model_validate(
        {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/jwks",
            "authorization_endpoint": "https://auth.example.com/auth",
        }
    )
    assert config.model_extra == {"authorization_endpoint": "https://auth.example.com/auth"}


def test_domain_config_defaults_match_the_spec():
    config = DomainConfig(domain="auth.example.com")
    assert config.audience is None
    assert config.ignore_audience is False
    assert config.algorithm == "RS256"
    assert config.use_https is True
    assert config.verify_issuer is True
    assert config.match_keys == {}
    assert config.permission_extractor is None


def test_domain_config_rejects_a_non_string_domain():
    with pytest.raises(ValidationError, match="domain"):
        DomainConfig(domain=None)  # type: ignore[arg-type]


def test_domain_config_permission_extractor_accepts_a_callable():
    def extractor(claims: dict) -> list[str]:
        return list(claims.get("permissions", []))

    config = DomainConfig(domain="auth.example.com", permission_extractor=extractor)
    assert config.permission_extractor is extractor
    assert config.permission_extractor({"permissions": ["read"]}) == ["read"]


def test_token_manager_style_issuer_equality_is_exact_string_comparison():
    """
    Pin the normalization behavior that matters to TokenManager: comparing a token's
    `iss` claim against `str(config.issuer)` is a strict equality check, so a provider
    issuer without a trailing slash will not match unless the caller accounts for it.
    """
    config = OpenidConfig.model_validate(
        {"issuer": "https://auth.example.com", "jwks_uri": "https://auth.example.com/jwks"}
    )
    assert str(config.issuer) != "https://auth.example.com"
    assert str(config.issuer) == "https://auth.example.com/"
