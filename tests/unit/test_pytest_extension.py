"""
Exercises the shipped fixtures the way a downstream consumer would.

The extension is registered as a pytest11 entry point, so these fixtures are available
here without importing anything.
"""

from armasec_lite.jwt import decode, get_unverified_header
from armasec_lite.openid_config_loader import OpenidConfigLoader
from armasec_lite.pytest_extension import build_mock_openid_server
from armasec_lite.schemas import JWK, DomainConfig


def test_domain_fixtures_line_up(rs256_domain, rs256_iss, rs256_jwks_uri):
    assert rs256_iss == f"https://{rs256_domain}"
    assert rs256_jwks_uri == f"https://{rs256_domain}/.well-known/jwks.json"


def test_domain_config_fixture(rs256_domain_config, rs256_domain):
    assert isinstance(rs256_domain_config, DomainConfig)
    assert rs256_domain_config.domain == rs256_domain
    assert rs256_domain_config.audience == "https://this.api"


def test_the_shipped_jwk_matches_the_shipped_private_key(build_rs256_token, rs256_jwk, rs256_iss):
    """
    The JWK fixture is a hard coded dict and the private key is a hard coded PEM. If they
    ever drift apart, every downstream test suite breaks with an opaque signature error,
    so assert the pairing directly.
    """
    token = build_rs256_token()
    claims = decode(token, JWK.model_validate(rs256_jwk), ["RS256"], issuer=rs256_iss)
    assert claims["sub"] == "SAMPLE_SUB"
    assert claims["exp"] > claims["iat"]


def test_build_rs256_token_applies_claim_overrides(build_rs256_token, rs256_jwk):
    token = build_rs256_token(claim_overrides={"sub": "other", "permissions": ["read:x"]})
    claims = decode(token, JWK.model_validate(rs256_jwk), ["RS256"])
    assert claims["sub"] == "other"
    assert claims["permissions"] == ["read:x"]


def test_build_rs256_token_applies_header_overrides(build_rs256_token):
    token = build_rs256_token(headers_overrides={"kid": "other-kid"})
    assert get_unverified_header(token)["kid"] == "other-kid"


def test_build_rs256_token_can_format_for_keycloak(build_rs256_token, rs256_jwk):
    token = build_rs256_token(
        claim_overrides={"permissions": ["read:stuff"], "azp": "my-client"},
        format_keycloak=True,
    )
    claims = decode(token, JWK.model_validate(rs256_jwk), ["RS256"])
    assert "permissions" not in claims
    assert claims["resource_access"]["my-client"]["roles"] == ["read:stuff"]


def test_mock_openid_server_serves_the_config(mock_openid_server, rs256_domain, rs256_iss):
    loader = OpenidConfigLoader(rs256_domain)
    assert loader.config.issuer == rs256_iss
    assert mock_openid_server.openid_config_route.call_count == 1
    assert mock_openid_server.openid_config_route.called is True


def test_mock_openid_server_serves_the_jwks(mock_openid_server, rs256_domain, rs256_kid):
    loader = OpenidConfigLoader(rs256_domain)
    assert [k.kid for k in loader.jwks.keys] == [rs256_kid]
    assert mock_openid_server.jwks_route.call_count == 1


def test_mock_openid_server_routes_a_bare_host_jwks_uri(rs256_domain, rs256_iss, rs256_jwk):
    """
    A consumer may configure a bare-host `jwks_uri`. The loader fetches it after
    AnyHttpUrl parsing, which appends a "/", so a mock routing on the raw string would
    answer "Unmocked request" to a fixture that is entirely correct.
    """
    bare_uri = f"https://{rs256_domain}"
    builder = build_mock_openid_server(
        rs256_domain,
        {"issuer": rs256_iss, "jwks_uri": bare_uri},
        rs256_jwk,
        bare_uri,
    )
    with builder() as routes:
        loader = OpenidConfigLoader(rs256_domain)
        assert [k.kid for k in loader.jwks.keys] == [rs256_jwk["kid"]]
        assert routes.jwks_route.call_count == 1


def test_mock_openid_server_clears_the_loader_cache(mock_openid_server, rs256_domain):
    """A process-wide cache would otherwise leak a loader between tests."""
    first = OpenidConfigLoader.get(rs256_domain)
    _ = first.config
    assert mock_openid_server.openid_config_route.call_count == 1
