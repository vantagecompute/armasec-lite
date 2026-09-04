"""
Exercises the library the way an application does: through a real FastAPI app and a real
HTTP client, with routes declared exactly as the README shows.
"""

from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import armasec_lite
from armasec_lite import Armasec, TokenPayload


@pytest.fixture
def app(mock_openid_server, rs256_domain, rs256_domain_config):
    armasec = Armasec(domain=rs256_domain, audience="https://this.api")
    application = FastAPI()

    @application.get("/open")
    async def open_route():
        return {"message": "no auth needed"}

    @application.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
    async def read_stuff():
        return {"message": "Successfully authenticated!"}

    @application.get("/either", dependencies=[Depends(armasec.lockdown_some("a", "b"))])
    async def either():
        return {"message": "ok"}

    @application.get("/whoami")
    async def whoami(payload: Annotated[TokenPayload, Depends(armasec.lockdown())]):
        return {"sub": payload.sub}

    @application.get("/payload", response_model=TokenPayload)
    async def payload_route(payload: Annotated[TokenPayload, Depends(armasec.lockdown())]):
        return payload

    return application


@pytest.fixture
def client(app):
    return TestClient(app)


def test_public_exports_are_present():
    for name in (
        "Armasec",
        "TokenManager",
        "TokenSecurity",
        "TokenPayload",
        "TokenDecoder",
        "OpenidConfigLoader",
        "extract_keycloak_permissions",
        "PermissionMode",
        "DomainConfig",
    ):
        assert hasattr(armasec_lite, name), f"{name} is not exported"


def test_an_unprotected_route_needs_no_token(client):
    assert client.get("/open").status_code == 200


def test_a_valid_token_with_the_scope_is_allowed(client, build_rs256_token):
    token = build_rs256_token(
        claim_overrides={"permissions": ["read:stuff"], "aud": "https://this.api"}
    )
    response = client.get("/stuff", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"message": "Successfully authenticated!"}


def test_a_missing_token_is_401(client):
    response = client.get("/stuff")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_a_garbage_token_is_401(client):
    response = client.get("/stuff", headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401


def test_a_token_without_the_scope_is_403(client, build_rs256_token):
    token = build_rs256_token(
        claim_overrides={"permissions": ["read:other"], "aud": "https://this.api"}
    )
    response = client.get("/stuff", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_a_wrong_audience_is_401(client, build_rs256_token):
    token = build_rs256_token(claim_overrides={"permissions": ["read:stuff"], "aud": "other-api"})
    response = client.get("/stuff", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_a_wrong_issuer_is_401(client, build_rs256_token):
    """verify_issuer defaults to True, which is the one behavior change from upstream."""
    token = build_rs256_token(
        claim_overrides={
            "permissions": ["read:stuff"],
            "aud": "https://this.api",
            "iss": "https://evil.example.com",
        }
    )
    response = client.get("/stuff", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_lockdown_some_accepts_either_scope(client, build_rs256_token):
    for permission in ("a", "b"):
        token = build_rs256_token(
            claim_overrides={"permissions": [permission], "aud": "https://this.api"}
        )
        assert (
            client.get("/either", headers={"Authorization": f"Bearer {token}"}).status_code == 200
        )


def test_the_payload_is_injectable(client, build_rs256_token):
    token = build_rs256_token(claim_overrides={"aud": "https://this.api"})
    response = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.json() == {"sub": "SAMPLE_SUB"}


def test_the_payload_serves_as_a_response_model(client, build_rs256_token):
    """TokenPayload is a pydantic model, so it works directly as a response_model."""
    token = build_rs256_token(claim_overrides={"aud": "https://this.api"})
    response = client.get("/payload", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["sub"] == "SAMPLE_SUB"


def test_the_security_scheme_appears_in_the_openapi_document(client):
    schemes = client.get("/openapi.json").json()["components"]["securitySchemes"]
    assert "TokenSecurity" in schemes
    assert schemes["TokenSecurity"]["in"] == "header"
    assert schemes["TokenSecurity"]["name"] == "Authorization"


def test_four_lockdowns_against_one_domain_cost_two_http_calls(
    app, mock_openid_server, build_rs256_token
):
    """The headline caching fix, observed end to end."""
    client = TestClient(app)
    token = build_rs256_token(
        claim_overrides={"permissions": ["read:stuff", "a"], "aud": "https://this.api"}
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/stuff", headers=headers)
    client.get("/either", headers=headers)
    client.get("/whoami", headers=headers)

    assert mock_openid_server.openid_config_route.call_count == 1
    assert mock_openid_server.jwks_route.call_count == 1
