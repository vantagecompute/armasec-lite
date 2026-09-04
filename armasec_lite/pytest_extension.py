"""
A pytest plugin providing fixtures for testing armasec-secured applications.

Registered as a `pytest11` entry point, so installing `armasec-lite[test]` makes every
fixture here available without an import or a conftest entry. This is public surface: the
fixture names below are what a consumer's test suite is written against.

## How a consumer uses it

Two fixtures do the work. `mock_openid_server` stands in for the OIDC provider, and
`build_rs256_token` mints tokens the mocked provider's key will verify. A typical test
looks like:

```python
def test_secured_route(client, mock_openid_server, build_rs256_token):
    token = build_rs256_token(claim_overrides={"permissions": ["read:stuff"]})
    response = client.get("/secured", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
```

Point the application under test at the `rs256_domain` fixture's value, or build its
`DomainConfig` from `rs256_domain_config`. Everything else is derived from those: the
issuer, the key id, the JWKS URL and the discovery URL all agree because they come from the
same fixtures.

Each of the underlying values is its own fixture, so a test can override one by redefining
it. Overriding `rs256_kid`, for instance, changes the key id in both the minted token and
the mocked JWKS at once, which is usually what a test wants; to make them disagree, pass
`headers_overrides={"kid": "..."}` to `build_rs256_token` instead.

`build_mock_openid_server` is the underlying factory, exported for a consumer that needs a
second domain or a deliberately broken provider. It returns a context manager rather than a
fixture.

## How the mock works, and one hazard it handles

The mock replaces `armasec_lite.http.get_json` with a routing table rather than standing up
a server or intercepting sockets. armasec makes exactly two requests, both through that one
function, so there is nothing a heavier mock would additionally cover. A request to any
other URL raises `AssertionError` naming it, so an unexpected fetch fails loudly.

It clears the process-wide loader cache on both entry and exit. That cache is a genuine
test-isolation hazard: `OpenidConfigLoader.get` shares loaders across the process, so
without the clear on entry a loader left over from an earlier test would answer from its own
cached JWKS and never reach the mock at all, and without the clear on exit this test's
loader would do the same to the next one. The symptom is a test that passes alone and fails
in a suite, or worse, one that passes for the wrong reason.

The routes are keyed on `str(AnyHttpUrl(jwks_uri))` rather than on the raw string, because
the loader fetches the URL after pydantic parsing and that appends a trailing slash to a
bare-host URL. Routing on the raw string would miss, and a consumer whose fixture supplies
`https://host` would see an unexplained "Unmocked request" for a perfectly correct fixture.

The RSA key pair below is committed in the clear and is public knowledge. It exists so tests
are reproducible. Never use it for anything real.
"""

from __future__ import annotations

import textwrap
from collections import namedtuple
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import AnyHttpUrl

from armasec_lite import http, jwt
from armasec_lite.openid_config_loader import OpenidConfigLoader, clear_cache
from armasec_lite.schemas import DomainConfig

MockOpenidRoutes = namedtuple("MockOpenidRoutes", ["openid_config_route", "jwks_route"])


class _Route:
    """
    One mocked URL, counting the calls made to it.

    Exposes `called` and `call_count` so assertions written against respx's route API
    port over unchanged. A test asserting `mock_openid_server.jwks_route.call_count == 1`
    against upstream armasec keeps working here.

    Attributes:
        url:        The URL this route answers.
        payload:    The JSON body it returns, handed back by identity rather than copied,
                    so a test that mutates it changes what later calls receive.
        call_count: How many times the route has been requested.
    """

    def __init__(self, url: str, payload: dict[str, Any]):
        """
        Record the URL this route answers and the body it returns.

        Args:
            url:     The URL this route answers.
            payload: The JSON body to return.
        """
        self.url = url
        self.payload = payload
        self.call_count = 0

    @property
    def called(self) -> bool:
        """
        Whether this route was requested at least once.

        Returns:
            True once `call_count` is above zero. Named to match respx's route API.
        """
        return self.call_count > 0


@pytest.fixture()
def rs256_domain() -> str:
    """
    Provide a domain for use in other fixtures.

    The value has nothing to do with an actual domain name; nothing is ever resolved,
    because the mock intercepts the fetch. Every other fixture here derives from it, so
    overriding it moves the whole mocked provider to a new domain consistently.

    Returns:
        The domain to configure the application under test with.
    """
    return "armasec.dev"


@pytest.fixture()
def rs256_domain_config(rs256_domain: str) -> DomainConfig:
    """
    Provide the DomainConfig for the default rs256 domain.

    Ready to hand to `Armasec(domain_configs=[...])` or `TokenSecurity`. The audience it
    sets, "https://this.api", is also what `build_rs256_token` must be told to put in the
    token: pass `claim_overrides={"aud": "https://this.api"}`, or build a config of your
    own with `ignore_audience=True`.

    Args:
        rs256_domain: An implicit fixture parameter.

    Returns:
        A DomainConfig for the mocked provider, with an audience set.
    """
    return DomainConfig(domain=rs256_domain, audience="https://this.api")


@pytest.fixture()
def rs256_iss(rs256_domain: str) -> str:
    """
    Provide an issuer claim for use in other fixtures.

    Used in two places that must agree: the `issuer` the mocked discovery document
    publishes, and the `iss` claim `build_rs256_token` puts in every token. Issuer
    verification is on by default, so overriding only one of them makes every token fail.

    Args:
        rs256_domain: An implicit fixture parameter.

    Returns:
        The issuer, "https://" plus the domain.
    """
    return f"https://{rs256_domain}"


@pytest.fixture()
def rs256_kid() -> str:
    """
    Provide a KID header value for use in other fixtures.

    Shared by the mocked JWKS and by the `kid` header `build_rs256_token` sets, so they
    match by construction. To test a key-rotation or unknown-key path, leave this alone and
    pass `headers_overrides={"kid": "OTHER"}` to the token builder instead.

    Returns:
        The key id, "SAMPLE_KID".
    """
    return "SAMPLE_KID"


@pytest.fixture()
def rs256_sub() -> str:
    """
    Provide a sub claim for use in other fixtures.

    Becomes `TokenPayload.sub` on the decoded token, so a test asserting on the
    authenticated principal can compare against this fixture rather than a literal.

    Returns:
        The subject, "SAMPLE_SUB".
    """
    return "SAMPLE_SUB"


@pytest.fixture()
def rs256_private_key() -> bytes:
    """
    Provide a pre-generated private key for RS256 signing in other fixtures.

    This key is public knowledge, committed in the clear in this file. It exists only so
    that tests are reproducible. Never use it for anything real.

    Returns:
        The PEM-encoded private key, ready for `jwt.encode`.
    """
    return (
        textwrap.dedent(
            """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAw408+QDZ10idz4ytJtwFQE4YgmrjvCoEXjtTUWQ3H4nWAAYQ
        +oE9xpr/gosNiFMuyRburvXT+Rkq8ry8tWoUzN2zViaarot+Tt9I71sVlnIsbtDZ
        +XrteMvBwjARn/MEAQEwDLvVzrBnAZrOTwrIkznyJttZh7STrt6y5X91i2MMm3xu
        9QK90kpu3rymAyT5V+AEIRzZai/ZT4YfLDutXulOVlWPQ55Xww1mbheGQ99fUMo5
        LmkxM5Jsz8ulIVvq/G/8guiKwAPJN/8S34NbkgL5GoeXT8uNDkbhtkLh5+o2T4EL
        9/ODKHqx46pHgUmBiC6wNv6uJXdH7qpaqhPR3QIDAQABAoIBABeyl/788Wk7bZRn
        UdxxsVk3nZTAa1S0Ks9YlSI56MwzofFiys/wtZHJ2sjxHPS2T+cilk4xkDyRpjjA
        UoYRku+4tjDsgLZCRU49lNMc0KLotyW+vYuUMA8BcjucI6akhomwoSgJ40Em83So
        U/QUNHZTAVtgHZtqcLMyXa+eIJqBcfsMHFkCgSF8LSD/XkRBMm1SREswDw6KqQQ0
        sZ/8TVF9sJTi3/OG8m5OfI+44AYDaMH5wKoOBcR3FBln+dEutB6JuRjmpnEjQpIT
        DggULc+Dzb/c75yhT1qZSEL3Z99JQTbytPm6boNGKmzUE9HCoY84wKfnhUDocFKW
        jnHMmKkCgYEA7/gRAtLjbJW1rbxw8xN3cyOZEJsMFt4mXMmne6nDTttVKb0wUuXJ
        H8prKAXDOzadAZgPeGJXVSNgGoNeNtkmEKDtysrRiZbWiTRxYPE36MrHFGOywjTn
        tP8qMJHmHYkxS16nqrOl0znUWv6Q6/qwd59Utuu4IJF/CxqP3Z6HPssCgYEA0J2M
        1gRgGj8NnGoIKS58gc3Aa5RdqWKoeiyXeN/zRDfMCKpPsVykvZJb4cLcEdcwe9kC
        3xpgIPaTZCPwhJ1rYiZ0/Xr7oIf0E66IeEKs/bchKcT9+sSaWgc5/zQ7aQ/XpwzU
        nKCTTeMGFUyulCIkoe2tLEQ+Mw1OphIXv17fNPcCgYEAjWgVxh81ivgRjiZ8PJEd
        E4lHmmRzVEpmOslN225nO+G9ppHolwD3ardiO7xhllQRYy4S97KjmfT1ncoJy7Jc
        XvImDhlELprnIwT3RtP+STys4ZP6c7yvSZYPa32eJ4t/s9U8YjfooLb0LwbRqW0Z
        bfRC/GOdJfv27Dkjy8muEs8CgYEAo+oHDOonMLg2U54kh2cVQVCPTngnF76DLmv3
        IGym0gUddfmL4Iowjxt+wma/T+1LFSSwUuiAe6YCrX5nr2uZQmeBKOIG8F2idAyB
        Ai0xi7Dmh9FW1kDAHtjqwxEhVS2zfnhgXij1VQ96aiX0TkR9kBYWKV/9l1NvZqF0
        s1MyAoUCgYA0wfJrCTXdWitkyfxApcmoTxt0ljqUwO6F5fhojf8PU1ouglgkRXtm
        1rSDGp7YUfODhWNSsN2P/eaDybcZo+TGtLQJ5Bai3Qxqh8xPaKCsSZbcPRLRP0w5
        CbTvFEyj6EBEH+TJL/Loa4hKFuAk7ErBAtzMCw6LchTjB/OF+dUusA==
        -----END RSA PRIVATE KEY-----
        """
        )
        .strip()
        .encode("utf-8")
    )


@pytest.fixture()
def rs256_public_key() -> bytes:
    """
    Provide the matching pre-generated public key.

    Provided for completeness. The mocked JWKS serves `rs256_jwk` instead, which carries the
    same key as JWK members, so nothing in the normal path needs this PEM.

    Returns:
        The PEM-encoded public key matching `rs256_private_key`.
    """
    return (
        textwrap.dedent(
            """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAw408+QDZ10idz4ytJtwFQE4YgmrjvCoEXjtTUWQ3H4nWAAYQ+oE9
        xpr/gosNiFMuyRburvXT+Rkq8ry8tWoUzN2zViaarot+Tt9I71sVlnIsbtDZ+Xrt
        eMvBwjARn/MEAQEwDLvVzrBnAZrOTwrIkznyJttZh7STrt6y5X91i2MMm3xu9QK9
        0kpu3rymAyT5V+AEIRzZai/ZT4YfLDutXulOVlWPQ55Xww1mbheGQ99fUMo5Lmkx
        M5Jsz8ulIVvq/G/8guiKwAPJN/8S34NbkgL5GoeXT8uNDkbhtkLh5+o2T4EL9/OD
        KHqx46pHgUmBiC6wNv6uJXdH7qpaqhPR3QIDAQAB
        -----END RSA PUBLIC KEY-----
        """
        )
        .strip()
        .encode("utf-8")
    )


@pytest.fixture()
def rs256_jwk(rs256_kid: str) -> dict[str, Any]:
    """
    Provide the JWK matching the pre-generated key pair, as a plain dict.

    This is a plain dict rather than a `JWK` instance, deliberately: it is what a JWKS
    document actually contains, so it can be handed straight to the mock server and to
    `JWK.model_validate` alike.

    Args:
        rs256_kid: An implicit fixture parameter.

    Returns:
        The JWK, with `kty` "RSA", `alg` "RS256" and the modulus and exponent of
        `rs256_private_key`. Override it to test how the decoder behaves against a
        malformed or mismatched key.
    """
    modulus = (
        "w408-QDZ10idz4ytJtwFQE4YgmrjvCoEXjtTUWQ3H4nWAAYQ-oE9xpr_gosNiFMuyRburvXT-Rkq8ry8tWoU"
        "zN2zViaarot-Tt9I71sVlnIsbtDZ-XrteMvBwjARn_MEAQEwDLvVzrBnAZrOTwrIkznyJttZh7STrt6y5X91"
        "i2MMm3xu9QK90kpu3rymAyT5V-AEIRzZai_ZT4YfLDutXulOVlWPQ55Xww1mbheGQ99fUMo5LmkxM5Jsz8ul"
        "IVvq_G_8guiKwAPJN_8S34NbkgL5GoeXT8uNDkbhtkLh5-o2T4EL9_ODKHqx46pHgUmBiC6wNv6uJXdH7qpa"
        "qhPR3Q"
    )
    return {"alg": "RS256", "kty": "RSA", "kid": rs256_kid, "n": modulus, "e": "AQAB"}


@pytest.fixture
def rs256_jwks_uri(rs256_domain: str) -> str:
    """
    Provide a jwks uri for use in other fixtures.

    Appears in the mocked discovery document and is the second URL the mock routes. It must
    be https: `OpenidConfig` pins the scheme unless the domain is configured with
    `use_https=False`.

    Args:
        rs256_domain: An implicit fixture parameter.

    Returns:
        The JWKS URL for the mocked provider.
    """
    return f"https://{rs256_domain}/.well-known/jwks.json"


@pytest.fixture
def rs256_openid_config(rs256_iss: str, rs256_jwks_uri: str) -> dict[str, Any]:
    """
    Provide an openid configuration document for use in other fixtures.

    The body the mocked discovery route returns. Only `issuer` and `jwks_uri` are present,
    which is all armasec reads; a real provider publishes considerably more, and the extra
    members would be ignored.

    Args:
        rs256_iss:      An implicit fixture parameter.
        rs256_jwks_uri: An implicit fixture parameter.

    Returns:
        The openid-configuration document, as a plain dict.
    """
    return {"issuer": rs256_iss, "jwks_uri": rs256_jwks_uri}


@pytest.fixture
def build_rs256_token(
    rs256_private_key: bytes,
    rs256_iss: str,
    rs256_sub: str,
    rs256_kid: str,
) -> Callable[..., str]:
    """
    Provide a helper that builds a JWT signed with the pre-generated private key.

    The returned callable is what a test actually calls. It supplies sensible defaults
    (`iat` now, `exp` an hour out, the fixture issuer and subject, and the fixture `kid` in
    the header) and takes overrides for anything else, so a test names only the claim it
    cares about:

    ```python
    token = build_rs256_token(claim_overrides={"permissions": ["read:stuff"]})
    expired = build_rs256_token(claim_overrides={"exp": 0})
    ```

    Tokens are minted with `armasec_lite.jwt.encode`, which is a testing aid rather than an
    issuer. This is the reason it exists.

    Args:
        rs256_private_key: An implicit fixture parameter.
        rs256_iss:         An implicit fixture parameter.
        rs256_sub:         An implicit fixture parameter.
        rs256_kid:         An implicit fixture parameter.

    Returns:
        A callable taking `claim_overrides`, `headers_overrides` and `format_keycloak`, and
        returning a signed compact JWT.
    """
    base_claims = {"iss": rs256_iss, "sub": rs256_sub}
    base_headers = {"kid": rs256_kid}

    def _helper(
        claim_overrides: dict[str, Any] | None = None,
        headers_overrides: dict[str, Any] | None = None,
        format_keycloak: bool = False,
    ) -> str:
        """
        Encode a jwt with the default claims and headers, overridden by the arguments.

        Defaults are `iat` now, `exp` one hour out, the fixture issuer and subject, and the
        fixture `kid`. Overriding a default is how a test builds a token that should fail:
        `{"exp": 0}` for an expired one, `{"iss": "https://elsewhere"}` for a wrong issuer,
        `headers_overrides={"kid": "OTHER"}` for an unknown key.

        Args:
            claim_overrides:   Claims to add, overriding defaults on collision.
            headers_overrides: Headers to add, overriding defaults on collision. `alg` is
                               not overridable here; `jwt.encode` sets it last, so a token
                               cannot claim one algorithm and be signed with another.
            format_keycloak:   If set, move "permissions" from the claim overrides into
                               the position Keycloak uses, generating a random "azp"
                               client id when one is not supplied. Use it to exercise
                               `extract_keycloak_permissions`. Only has an effect when
                               "permissions" is among the claim overrides.

        Returns:
            The signed compact serialization, ready for an `Authorization: Bearer` header.
        """
        claim_overrides = dict(claim_overrides or {})
        headers_overrides = dict(headers_overrides or {})

        now = int(datetime.now(UTC).timestamp())

        if format_keycloak and "permissions" in claim_overrides:
            test_client = claim_overrides.get("azp", f"test-client-{uuid4()}")
            claim_overrides["azp"] = test_client
            claim_overrides["resource_access"] = {
                test_client: {"roles": claim_overrides.pop("permissions")}
            }

        return jwt.encode(
            {"iat": now, "exp": now + 60 * 60, **base_claims, **claim_overrides},
            rs256_private_key,
            "RS256",
            headers={**base_headers, **headers_overrides},
        )

    return _helper


def build_mock_openid_server(
    domain: str,
    openid_config: dict[str, Any],
    jwk: dict[str, Any],
    jwks_uri: str,
) -> Callable[..., Any]:
    """
    Build a context manager that mocks the openid routes armasec fetches.

    The factory behind `mock_openid_server`, exported for tests that need something the
    fixture does not give them: a second domain, a provider that publishes a mismatched
    issuer, or a JWKS carrying a different key. The arguments here become the context
    manager's defaults, and each can be overridden again at the point it is entered.

    ```python
    builder = build_mock_openid_server(domain, config, jwk, jwks_uri)
    with builder() as routes:
        ...
        assert routes.jwks_route.call_count == 1
    ```

    Entering it patches `armasec_lite.http.get_json` and clears the process-wide loader
    cache; leaving it restores the function and clears the cache again. Both clears matter:
    see the module docstring. Not reentrant, and not safe to nest for two different domains,
    since the inner one replaces the outer one's routing table entirely.

    Args:
        domain:        The domain of the openid server to mock.
        openid_config: The document returned from the discovery route.
        jwk:           The key returned from the jwks route. Wrapped as `{"keys": [jwk]}`,
                       so pass the key itself, not a JWKS document.
        jwks_uri:      The URL of the jwks route to mock. Normalized through `AnyHttpUrl`
                       before it becomes a route key, matching what the loader will
                       actually request.

    Returns:
        A context manager that, while active, mocks the openid routes and yields a
        `MockOpenidRoutes` pair whose `call_count` and `called` a test can assert on.

    Raises:
        AssertionError: Raised by the patched `get_json`, while the context manager is
            active, for any URL other than the two mocked routes. It names the URL, so an
            unexpected fetch fails loudly rather than silently returning nothing.
    """

    @contextmanager
    def _helper(
        domain: str = domain,
        openid_config: dict[str, Any] = openid_config,
        jwk: dict[str, Any] = jwk,
        jwks_uri: str = jwks_uri,
    ) -> Iterator[MockOpenidRoutes]:
        config_url = OpenidConfigLoader.build_openid_config_url(domain)
        # The loader fetches `str(config.jwks_uri)`, which is the value after AnyHttpUrl
        # parsing, and that appends a "/" to a bare-host URL. Routing on the raw string
        # would then miss, and a consumer whose fixture supplies "https://host" would see
        # an unexplained "Unmocked request" for a perfectly correct fixture.
        jwks_url = str(AnyHttpUrl(jwks_uri))
        config_route = _Route(config_url, openid_config)
        jwks_route = _Route(jwks_url, {"keys": [jwk]})
        routes = {config_url: config_route, jwks_url: jwks_route}

        original = http.get_json

        def _mocked(url: str, *, timeout: float = http.DEFAULT_TIMEOUT) -> dict[str, Any]:
            route = routes.get(url)
            if route is None:
                raise AssertionError(f"Unmocked request to {url}")
            route.call_count += 1
            return route.payload

        # The loader cache is process-wide, so a loader left over from another test would
        # answer from its own cache and never reach this mock.
        clear_cache()
        http.get_json = _mocked
        try:
            yield MockOpenidRoutes(config_route, jwks_route)
        finally:
            http.get_json = original
            clear_cache()

    return _helper


@pytest.fixture
def mock_openid_server(
    rs256_domain: str,
    rs256_openid_config: dict[str, Any],
    rs256_jwk: dict[str, Any],
    rs256_jwks_uri: str,
) -> Iterator[MockOpenidRoutes]:
    """
    Mock an openid server using the other fixtures in this extension.

    Request it from any test whose application authenticates against `rs256_domain`, and no
    real network call is made. Active for the duration of the test, with the loader cache
    cleared on both sides, so tests requesting it are isolated from each other.

    Args:
        rs256_domain:        An implicit fixture parameter.
        rs256_openid_config: An implicit fixture parameter.
        rs256_jwk:           An implicit fixture parameter.
        rs256_jwks_uri:      An implicit fixture parameter.

    Yields:
        A `MockOpenidRoutes` with `openid_config_route` and `jwks_route`. Each exposes
        `called` and `call_count`, which is how a test asserts that the provider was
        contacted exactly once rather than once per request.
    """
    builder = build_mock_openid_server(rs256_domain, rs256_openid_config, rs256_jwk, rs256_jwks_uri)
    with builder() as constructed:
        yield constructed
