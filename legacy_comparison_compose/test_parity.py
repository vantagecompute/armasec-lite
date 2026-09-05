"""
Parity tests: both arms must answer the same request with the same status.

Everything here is marked `integration` and needs the docker compose stack in this
directory to be running. `pyproject.toml` sets `testpaths = ["tests/unit"]`, so a plain
`pytest` never collects this file, and `-m "not integration"` excludes it even when it is
pointed at directly. Nothing in this module is importable without the stack.

The matrix is the point. Six token conditions, four of which should be refused, one of
which should be refused with a different code, and one of which should be allowed. If the
two libraries agree on all six then a service can be migrated from one to the other without
its callers noticing, which is the claim the whole project rests on.

There is exactly one documented exception, and it gets its own test rather than a row in
the matrix: armasec-lite compares a token's `iss` claim to the provider's advertised issuer
by exact string equality, and upstream armasec loads the issuer and never checks it. Hiding
that in the parity matrix as a "known failure" would make it look like a defect. It is a
deliberate difference, so it is asserted directly, in both directions.

Tokens are minted from the real Keycloak through the proxy. The realm provides a distinct
client for each condition: `armasec-api` password grant for a token with `read:stuff`,
`armasec-api` client credentials for a service account holding only `write:stuff`,
`other-api` for a token whose audience is somebody else's, and `shortlived-api`, whose
access tokens live two seconds, for a token that is genuinely expired rather than forged.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

pytestmark = pytest.mark.integration

PROXY_URL = os.environ.get("HARNESS_PROXY_URL", "http://localhost:18080")
LEGACY_URL = os.environ.get("HARNESS_LEGACY_URL", "http://localhost:18001")
LITE_URL = os.environ.get("HARNESS_LITE_URL", "http://localhost:18002")
REALM_URL = f"{PROXY_URL}/realms/armasec"
TOKEN_URL = f"{REALM_URL}/protocol/openid-connect/token"
COMPOSE_DIR = os.path.dirname(os.path.abspath(__file__))

#: The condition name, the token fixture key, and the status both arms must return.
PARITY_CASES = [
    ("no-token", "none", 401),
    ("malformed-token", "malformed", 401),
    ("expired-token", "expired", 401),
    ("wrong-audience", "wrong_audience", 401),
    ("insufficient-scope", "insufficient", 403),
    ("valid-token", "valid", 200),
]


def http_get(url: str, token: str | None = None, timeout: float = 10.0) -> tuple[int, bytes]:
    """
    GET a URL, returning the status even when it is an error status.

    Args:
        url:     The URL to fetch.
        token:   A bearer token, or None to send no Authorization header.
        timeout: Seconds to wait.

    Returns:
        The status code and the response body.
    """
    request = urllib.request.Request(url)
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def mint(client_id: str, secret: str, **extra: str) -> str:
    """
    Ask Keycloak for an access token, through the proxy.

    Args:
        client_id: The client to mint for.
        secret:    That client's secret.
        extra:     Additional form fields. Supplying `username` and `password` selects the
                   password grant; without them a client credentials grant is used.

    Returns:
        The compact access token.

    Raises:
        AssertionError: Keycloak refused to mint, which means the realm import is wrong
            and no test in this module can be trusted.
    """
    grant = "password" if "username" in extra else "client_credentials"
    form = {"grant_type": grant, "client_id": client_id, "client_secret": secret, **extra}
    data = urllib.parse.urlencode(form).encode()
    try:
        with urllib.request.urlopen(TOKEN_URL, data=data, timeout=10) as response:
            return str(json.loads(response.read())["access_token"])
    except urllib.error.HTTPError as error:  # pragma: no cover - realm misconfiguration
        raise AssertionError(f"could not mint a token for {client_id}: {error.read()!r}") from error


def wait_healthy(url: str, timeout: float = 60.0) -> None:
    """
    Block until an application answers `/health`.

    Args:
        url:     The service base URL.
        timeout: Seconds to wait before giving up.

    Raises:
        AssertionError: The service did not become healthy in time.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if http_get(f"{url}/health", timeout=2)[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.5)
    raise AssertionError(f"{url} did not become healthy within {timeout}s")


def compose(*args: str) -> None:
    """
    Run a docker compose subcommand against this directory's stack.

    Args:
        args: The subcommand and its arguments.
    """
    subprocess.run(["docker", "compose", *args], cwd=COMPOSE_DIR, check=True, capture_output=True)


@pytest.fixture(scope="session", autouse=True)
def stack_is_up() -> None:
    """
    Skip the whole module unless all three HTTP services answer.

    A missing stack is a skip and not a failure, because these tests are opt in and a
    developer running them by accident should be told what is missing rather than shown a
    wall of connection errors.
    """
    for name, url in (
        ("oidc-proxy", f"{PROXY_URL}/__stats"),
        ("app-legacy", f"{LEGACY_URL}/health"),
        ("app-lite", f"{LITE_URL}/health"),
    ):
        try:
            status = http_get(url, timeout=3)[0]
        except OSError as error:
            pytest.skip(f"{name} is not reachable at {url} ({error}); run `docker compose up -d`")
        if status != 200:
            pytest.skip(f"{name} answered {status} at {url}; the stack is not ready")


@pytest.fixture(scope="session")
def tokens() -> dict[str, str | None]:
    """
    Mint one token per parity condition.

    The expired token is minted first and used last, so the two second lifespan configured
    on `shortlived-api` has elapsed by the time any test sends it. A sleep is still needed
    when the rest of the minting is fast, which it is.

    Returns:
        A mapping from condition name to token, with None for the no-token case.
    """
    expired = mint("shortlived-api", "shortlived-api-secret")
    minted: dict[str, str | None] = {
        "none": None,
        "malformed": "this.is.not-a-jwt",
        "valid": mint(
            "armasec-api",
            "armasec-api-secret",
            username="testuser",
            password="testuser-password",
        ),
        "insufficient": mint("armasec-api", "armasec-api-secret"),
        "wrong_audience": mint("other-api", "other-api-secret"),
        "expired": expired,
    }
    time.sleep(3)
    return minted


@pytest.mark.parametrize(
    ("condition", "key", "expected"), PARITY_CASES, ids=[c[0] for c in PARITY_CASES]
)
def test_stuff_parity(
    tokens: dict[str, str | None], condition: str, key: str, expected: int
) -> None:
    """
    Both arms answer `/stuff` identically, and with the status the condition calls for.

    Args:
        tokens:    The minted tokens.
        condition: The human readable name of the case, used as the test id.
        key:       The key into `tokens`.
        expected:  The status both services must return.
    """
    legacy_status, _ = http_get(f"{LEGACY_URL}/stuff", tokens[key])
    lite_status, _ = http_get(f"{LITE_URL}/stuff", tokens[key])
    assert legacy_status == lite_status, (
        f"{condition}: app-legacy returned {legacy_status} and app-lite returned {lite_status}"
    )
    assert lite_status == expected, f"{condition}: expected {expected}, both returned {lite_status}"


@pytest.mark.parametrize(
    ("condition", "key", "expected"), PARITY_CASES, ids=[c[0] for c in PARITY_CASES]
)
def test_either_parity(
    tokens: dict[str, str | None], condition: str, key: str, expected: int
) -> None:
    """
    The same matrix against the some-scopes route.

    `/either` requires `read:stuff` or `admin:stuff`. The service account token carries
    only `write:stuff`, so the insufficient-scope case is still a 403 here.

    Args:
        tokens:    The minted tokens.
        condition: The human readable name of the case.
        key:       The key into `tokens`.
        expected:  The status both services must return.
    """
    legacy_status, _ = http_get(f"{LEGACY_URL}/either", tokens[key])
    lite_status, _ = http_get(f"{LITE_URL}/either", tokens[key])
    assert legacy_status == lite_status, (
        f"{condition}: app-legacy returned {legacy_status} and app-lite returned {lite_status}"
    )
    assert lite_status == expected, f"{condition}: expected {expected}, both returned {lite_status}"


def test_health_needs_no_token() -> None:
    """Both arms serve `/health` unauthenticated, and each reports the library it loaded."""
    legacy_status, legacy_body = http_get(f"{LEGACY_URL}/health")
    lite_status, lite_body = http_get(f"{LITE_URL}/health")
    assert (legacy_status, lite_status) == (200, 200)
    assert json.loads(legacy_body)["lib"] == "legacy"
    assert json.loads(lite_body)["lib"] == "lite"


def test_whoami_payloads_are_identical(tokens: dict[str, str | None]) -> None:
    """
    The decoded payload has the same shape and the same values on both arms.

    Status parity alone would not catch a library that authenticated correctly and then
    handed the route a differently shaped payload, which is the kind of difference that
    breaks a migration one route at a time.

    Args:
        tokens: The minted tokens.
    """
    legacy_status, legacy_body = http_get(f"{LEGACY_URL}/whoami", tokens["valid"])
    lite_status, lite_body = http_get(f"{LITE_URL}/whoami", tokens["valid"])
    assert (legacy_status, lite_status) == (200, 200)
    assert json.loads(legacy_body) == json.loads(lite_body)


def test_keycloak_claims_are_shaped_as_the_harness_assumes(
    tokens: dict[str, str | None],
) -> None:
    """
    The audience mapper and the client roles are actually present in a minted token.

    Without this the audience and scope rows of the parity matrix could pass for the wrong
    reason: Keycloak's default audience is `account`, and a realm import that silently
    dropped the mapper would make every audience assertion vacuous.

    Args:
        tokens: The minted tokens.
    """
    segment = str(tokens["valid"]).split(".")[1]
    claims: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    )
    audience = claims["aud"]
    assert "armasec-api" in (audience if isinstance(audience, list) else [audience])
    assert claims["iss"] == "http://oidc-proxy:8080/realms/armasec"
    assert set(claims["resource_access"]["armasec-api"]["roles"]) == {"read:stuff", "write:stuff"}


def test_jwks_and_discovery_traverse_the_proxy() -> None:
    """
    Both OIDC fetches were counted at the proxy.

    A zero count on the certs path means `KC_HOSTNAME` is not pointing at the proxy, the
    applications are fetching the JWKS from Keycloak directly, and every request count the
    benchmark scenarios report is wrong. That failure is silent everywhere else.
    """
    status, body = http_get(f"{PROXY_URL}/__stats")
    assert status == 200
    counts = json.loads(body)["counts"]
    assert counts.get("/realms/armasec/.well-known/openid-configuration", 0) > 0
    assert counts.get("/realms/armasec/protocol/openid-connect/certs", 0) > 0, (
        "no JWKS fetch reached the proxy; KC_HOSTNAME is not pointing at oidc-proxy"
    )


@pytest.fixture
def rewritten_issuer() -> Iterator[str]:
    """
    Make the provider advertise an issuer that disagrees with its own tokens.

    Both libraries cache the discovery document for the life of the process, so the two
    application containers are restarted after the rewrite is in place and again after it
    is cleared. That is slow and unavoidable, and it is why this is one test rather than a
    row in the matrix.

    Yields:
        The bogus issuer that is now being advertised.
    """
    if shutil.which("docker") is None:  # pragma: no cover - depends on the host
        pytest.skip("docker is not on PATH, so the app containers cannot be restarted")
    bogus = "http://issuer-that-does-not-match.invalid/realms/armasec"
    try:
        http_get(f"{PROXY_URL}/__issuer?value={urllib.parse.quote(bogus)}")
        compose("restart", "app-legacy", "app-lite")
        wait_healthy(LEGACY_URL)
        wait_healthy(LITE_URL)
        yield bogus
    finally:
        http_get(f"{PROXY_URL}/__issuer?value=")
        compose("restart", "app-legacy", "app-lite")
        wait_healthy(LEGACY_URL)
        wait_healthy(LITE_URL)


def test_issuer_verification_is_the_documented_difference(
    tokens: dict[str, str | None], rewritten_issuer: str
) -> None:
    """
    With a mismatched issuer, armasec-lite refuses the token and upstream armasec does not.

    This is the only place the two arms are allowed to disagree, and it is asserted rather
    than tolerated: a run where both returned 200 would mean `verify_issuer` had stopped
    working, and a run where both returned 401 would mean upstream had started checking,
    which would make the difference undocumented rather than absent.

    A Keycloak behind a proxy is exactly the deployment shape where issuer mismatches
    happen in practice, which is why the harness reproduces it at the wire rather than by
    editing a fixture.

    Args:
        tokens:           The minted tokens. The valid one is used, unchanged.
        rewritten_issuer: The bogus issuer the proxy is advertising.
    """
    legacy_status, _ = http_get(f"{LEGACY_URL}/stuff", tokens["valid"])
    lite_status, _ = http_get(f"{LITE_URL}/stuff", tokens["valid"])
    assert legacy_status == 200, (
        f"upstream armasec does not verify the issuer and should have allowed this token, "
        f"but returned {legacy_status}"
    )
    assert lite_status == 401, (
        f"armasec-lite verifies the issuer by exact equality and should have refused a "
        f"token whose iss is not {rewritten_issuer!r}, but returned {lite_status}"
    )
