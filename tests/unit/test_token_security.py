import asyncio
import json
import threading
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import HTTPException
from starlette.datastructures import Headers

from armasec_lite import openid_config_loader as loader_module
from armasec_lite.exceptions import ArmasecError
from armasec_lite.jwt import b64url_encode
from armasec_lite.openid_config_loader import clear_cache
from armasec_lite.pluggable import hookimpl, plugin_manager
from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_security import TokenSecurity

DOMAIN = "auth.example.com"
ISSUER = f"https://{DOMAIN}"
CONFIG_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/jwks"


class _Request:
    """The only parts of a starlette Request that TokenSecurity touches."""

    def __init__(self, headers: dict):
        self.headers = Headers(headers)


@pytest.fixture(autouse=True)
def reset_cache():
    clear_cache()
    yield
    clear_cache()


class _Calls(list):
    """The recorded fetch URLs, with the served documents hung off them.

    A plain list keeps every `fake_get.count(...)` assertion working, and `routes` lets a
    test rewrite what the provider serves next, which is how a key rotation is staged.
    """

    routes: dict


@pytest.fixture
def fake_get(monkeypatch, rsa_jwk):
    calls = _Calls()
    jwks_doc = {
        "keys": [{"kty": "RSA", "kid": rsa_jwk.kid, "alg": "RS256", "n": rsa_jwk.n, "e": rsa_jwk.e}]
    }
    routes = {CONFIG_URL: {"issuer": ISSUER, "jwks_uri": JWKS_URL}, JWKS_URL: jwks_doc}
    calls.routes = routes

    def _get(url, *, timeout=10.0):
        calls.append(url)
        return routes[url]

    monkeypatch.setattr(loader_module.http, "get_json", _get)
    return calls


@pytest.fixture
def make_token(rsa_private):
    def _make(kid="rsa-test", **overrides):
        claims = {
            "sub": "abc",
            "exp": int(time.time()) + 600,
            "iss": ISSUER,
            "permissions": [],
            **overrides,
        }
        head = b64url_encode(json.dumps({"alg": "RS256", "kid": kid}).encode())
        body = b64url_encode(json.dumps(claims).encode())
        sig = rsa_private.sign(
            f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{head}.{body}.{b64url_encode(sig)}"

    return _make


def _security(**kwargs):
    kwargs.setdefault("domain_configs", [DomainConfig(domain=DOMAIN)])
    kwargs.setdefault("skip_plugins", True)
    return TokenSecurity(**kwargs)


async def test_call_returns_the_token_payload(fake_get, make_token):
    security = _security()
    payload = await security(_Request({"Authorization": f"Bearer {make_token()}"}))
    assert payload.sub == "abc"


async def test_call_raises_401_without_a_token(fake_get):
    security = _security()
    with pytest.raises(HTTPException) as info:
        await security(_Request({}))
    assert info.value.status_code == 401
    assert info.value.headers["WWW-Authenticate"] == "Bearer"


async def test_call_raises_401_for_an_expired_token(fake_get, make_token):
    security = _security()
    token = make_token(exp=int(time.time()) - 60)
    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert info.value.status_code == 401


async def test_call_raises_403_when_a_required_scope_is_missing(fake_get, make_token):
    security = _security(scopes=["read:x", "write:x"])
    token = make_token(permissions=["read:x"])
    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert info.value.status_code == 403


async def test_permission_mode_all_requires_every_scope(fake_get, make_token):
    security = _security(scopes=["read:x", "write:x"], permission_mode=PermissionMode.ALL)
    token = make_token(permissions=["read:x", "write:x", "extra"])
    assert (await security(_Request({"Authorization": f"Bearer {token}"}))).sub == "abc"


async def test_permission_mode_some_requires_one_scope(fake_get, make_token):
    security = _security(scopes=["read:x", "write:x"], permission_mode=PermissionMode.SOME)
    token = make_token(permissions=["write:x"])
    assert (await security(_Request({"Authorization": f"Bearer {token}"}))).sub == "abc"


async def test_permission_mode_some_rejects_no_overlap(fake_get, make_token):
    security = _security(scopes=["read:x"], permission_mode=PermissionMode.SOME)
    token = make_token(permissions=["unrelated"])
    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert info.value.status_code == 403


async def test_match_keys_accepts_a_matching_scalar(fake_get, make_token):
    security = _security(domain_configs=[DomainConfig(domain=DOMAIN, match_keys={"tier": "gold"})])
    token = make_token(tier="gold")
    assert (await security(_Request({"Authorization": f"Bearer {token}"}))).sub == "abc"


async def test_match_keys_rejects_a_mismatched_scalar(fake_get, make_token):
    security = _security(domain_configs=[DomainConfig(domain=DOMAIN, match_keys={"tier": "gold"})])
    token = make_token(tier="bronze")
    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert info.value.status_code == 403


async def test_match_keys_handles_booleans_by_identity(fake_get, make_token):
    security = _security(
        domain_configs=[DomainConfig(domain=DOMAIN, match_keys={"verified": True})]
    )
    assert (
        await security(_Request({"Authorization": f"Bearer {make_token(verified=True)}"}))
    ).sub == "abc"
    with pytest.raises(HTTPException):
        await security(_Request({"Authorization": f"Bearer {make_token(verified=1)}"}))


async def test_match_keys_intersects_collections(fake_get, make_token):
    security = _security(
        domain_configs=[DomainConfig(domain=DOMAIN, match_keys={"groups": ["admins", "ops"]})]
    )
    token = make_token(groups=["ops", "other"])
    assert (await security(_Request({"Authorization": f"Bearer {token}"}))).sub == "abc"


async def test_debug_exceptions_reraises_the_original(fake_get, make_token):
    security = _security(debug_exceptions=True)
    with pytest.raises(ArmasecError):
        await security(_Request({}))


async def test_the_real_decode_error_is_preserved(fake_get, make_token):
    """
    The error that actually failed the decode must reach the caller.

    Upstream armasec swallows every manager's exception and then asserts the payload is
    not None, which surfaces as a bare AttributeError and says nothing useful.
    """
    security = _security(debug_exceptions=True)
    token = make_token(exp=int(time.time()) - 60)
    with pytest.raises(ArmasecError) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert "Token has expired" in str(info.value)
    assert "could not find matching JWK" not in str(info.value)


async def test_managers_are_loaded_once_across_calls(fake_get, make_token):
    security = _security()
    request = _Request({"Authorization": f"Bearer {make_token()}"})
    await security(request)
    await security(request)
    assert fake_get.count(CONFIG_URL) == 1
    assert fake_get.count(JWKS_URL) == 1


async def test_two_security_instances_share_the_loader_cache(fake_get, make_token):
    """This is the fix for upstream's 2N HTTP calls for N lockdown scope sets."""
    token = make_token(permissions=["a", "b"])
    request = _Request({"Authorization": f"Bearer {token}"})
    await _security(scopes=["a"])(request)
    await _security(scopes=["b"])(request)
    assert fake_get.count(CONFIG_URL) == 1
    assert fake_get.count(JWKS_URL) == 1


async def test_a_plugin_can_deny(fake_get, make_token):
    class Denier(ArmasecError):
        status_code = 402
        detail = "Payment required"

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            raise Denier("not subscribed")

    plugin = Plugin()
    plugin_manager.register(plugin)
    try:
        security = _security(skip_plugins=False)
        with pytest.raises(HTTPException) as info:
            await security(_Request({"Authorization": f"Bearer {make_token()}"}))
        assert info.value.status_code == 402
    finally:
        plugin_manager.unregister(plugin)


async def test_skip_plugins_bypasses_the_hook(fake_get, make_token):
    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            raise ArmasecError("should not run")

    plugin = Plugin()
    plugin_manager.register(plugin)
    try:
        security = _security(skip_plugins=True)
        assert (await security(_Request({"Authorization": f"Bearer {make_token()}"}))).sub == "abc"
    finally:
        plugin_manager.unregister(plugin)


@pytest.fixture
async def executor_calls(monkeypatch):
    """Record every `run_in_executor` hop made on the running event loop."""
    loop = asyncio.get_running_loop()
    recorded: list[str] = []
    original = loop.run_in_executor

    def _spy(executor, func, *args):
        recorded.append(getattr(func, "__name__", repr(func)))
        return original(executor, func, *args)

    monkeypatch.setattr(loop, "run_in_executor", _spy)
    return recorded


async def test_the_cold_load_runs_in_an_executor(fake_get, make_token, executor_calls):
    """
    The blocking OIDC fetches must not run on the event loop.

    Upstream armasec calls synchronous `httpx.get` inside `async def __call__`, stalling
    every other request in the process for the duration of both fetches.
    """
    security = _security()
    await security(_Request({"Authorization": f"Bearer {make_token()}"}))
    assert executor_calls == ["_load_all_managers"]


async def test_the_warm_path_makes_no_executor_hop(fake_get, make_token, executor_calls):
    """
    Once the managers are cached, the steady state must pay no thread hop at all.

    Hopping unconditionally would add a scheduling round trip to every single request.
    """
    security = _security()
    request = _Request({"Authorization": f"Bearer {make_token()}"})
    await security(request)
    executor_calls.clear()

    await security(request)
    await security(request)
    assert executor_calls == []


async def test_the_jwks_refresh_runs_in_an_executor(fake_get, make_token, executor_calls):
    """
    An unknown `kid` triggers a blocking refetch, and it must not run on the event loop.

    `kid` is read from the unverified header, so any unauthenticated caller chooses it. An
    inline refresh would let one invented key id stall the whole process for the fetch
    timeout, which is precisely the upstream behavior this library exists to fix.
    """
    security = _security()
    await security(_Request({"Authorization": f"Bearer {make_token()}"}))
    executor_calls.clear()

    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {make_token(kid='rotated')}"}))
    assert info.value.status_code == 401
    assert executor_calls == ["_refresh_and_retry"]


async def test_the_jwks_refresh_never_fetches_on_the_loop_thread(fake_get, make_token, monkeypatch):
    """The direct proof: no provider fetch happens on the thread running the event loop."""
    loop_thread = threading.get_ident()
    fetch_threads: list[int] = []
    served = loader_module.http.get_json

    def _watching_get(url, *, timeout=10.0):
        fetch_threads.append(threading.get_ident())
        return served(url, timeout=timeout)

    monkeypatch.setattr(loader_module.http, "get_json", _watching_get)

    security = _security()
    with pytest.raises(HTTPException):
        await security(_Request({"Authorization": f"Bearer {make_token(kid='rotated')}"}))

    assert fetch_threads, "no fetch was made, so the test proves nothing"
    assert loop_thread not in fetch_threads


async def test_the_refresh_is_attempted_at_most_once_per_request(fake_get, make_token):
    """One request buys one refetch. The loader's rate limit then applies on top."""
    security = _security()
    await security(_Request({"Authorization": f"Bearer {make_token()}"}))
    before = fake_get.count(JWKS_URL)

    with pytest.raises(HTTPException):
        await security(_Request({"Authorization": f"Bearer {make_token(kid='rotated')}"}))
    assert fake_get.count(JWKS_URL) == before + 1


async def test_a_rotated_kid_recovers_without_a_restart(fake_get, make_token):
    """
    The whole point of the refresh path: a provider key rotation heals itself.

    Upstream caches the JWKS for the life of the process, so a rotation 401s every request
    until someone restarts the service.
    """
    security = _security()
    await security(_Request({"Authorization": f"Bearer {make_token()}"}))

    fake_get.routes[JWKS_URL]["keys"][0]["kid"] = "rotated"
    payload = await security(_Request({"Authorization": f"Bearer {make_token(kid='rotated')}"}))
    assert payload.sub == "abc"


async def test_concurrent_cold_calls_do_not_duplicate_managers(fake_get, make_token, monkeypatch):
    """
    Every concurrent first request passes the empty-cache check, so the load must assign
    the finished list rather than append to the shared one. Otherwise N simultaneous cold
    requests leave N copies of every manager behind, and each duplicate re-runs the decode
    and the refresh for the rest of the process.
    """
    served = loader_module.http.get_json

    def _slow_get(url, *, timeout=10.0):
        # Slow enough that every worker is past the empty-cache guard before any finishes.
        time.sleep(0.05)
        return served(url, timeout=timeout)

    monkeypatch.setattr(loader_module.http, "get_json", _slow_get)

    security = _security()
    request = _Request({"Authorization": f"Bearer {make_token()}"})
    await asyncio.gather(*(security(request) for _ in range(5)))
    assert len(security.managers) == 1
