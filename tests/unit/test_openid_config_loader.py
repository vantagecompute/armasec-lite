import threading

import pytest

from armasec_lite import openid_config_loader as loader_module
from armasec_lite.exceptions import ArmasecError, AuthenticationError
from armasec_lite.openid_config_loader import OpenidConfigLoader, clear_cache

DOMAIN = "auth.example.com"
CONFIG_URL = f"https://{DOMAIN}/.well-known/openid-configuration"
JWKS_URL = f"https://{DOMAIN}/jwks"

CONFIG_DOC = {"issuer": f"https://{DOMAIN}", "jwks_uri": JWKS_URL}
JWKS_DOC = {"keys": [{"kty": "RSA", "kid": "one", "n": "AA", "e": "AQAB"}]}
ROTATED_DOC = {"keys": [{"kty": "RSA", "kid": "two", "n": "BB", "e": "AQAB"}]}


@pytest.fixture(autouse=True)
def reset_cache():
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def fake_get(monkeypatch):
    """Replace the HTTP layer with a counting router."""
    calls: list[str] = []
    routes = {CONFIG_URL: CONFIG_DOC, JWKS_URL: JWKS_DOC}

    def _get(url, *, timeout=10.0):
        calls.append(url)
        if url not in routes:
            raise AuthenticationError(f"no route for {url}")
        return routes[url]

    monkeypatch.setattr(loader_module.http, "get_json", _get)
    return calls, routes


def test_build_openid_config_url_uses_https_by_default():
    assert OpenidConfigLoader.build_openid_config_url(DOMAIN) == CONFIG_URL


def test_build_openid_config_url_can_use_http():
    assert OpenidConfigLoader.build_openid_config_url(DOMAIN, use_https=False) == (
        f"http://{DOMAIN}/.well-known/openid-configuration"
    )


def test_config_is_fetched_lazily_and_cached(fake_get):
    calls, _ = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    assert calls == []
    assert loader.config.issuer == f"https://{DOMAIN}"
    assert loader.config.issuer == f"https://{DOMAIN}"
    assert calls == [CONFIG_URL]


def test_jwks_fetch_pulls_the_config_first(fake_get):
    calls, _ = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    assert [k.kid for k in loader.jwks.keys] == ["one"]
    assert calls == [CONFIG_URL, JWKS_URL]


def test_invalid_config_document_raises(monkeypatch):
    monkeypatch.setattr(loader_module.http, "get_json", lambda url, timeout=10.0: {"nope": 1})
    with pytest.raises(ArmasecError, match="issuer"):
        _ = OpenidConfigLoader(DOMAIN).config


def test_get_returns_one_shared_loader_per_domain(fake_get):
    calls, _ = fake_get
    first = OpenidConfigLoader.get(DOMAIN)
    second = OpenidConfigLoader.get(DOMAIN)
    assert first is second
    _ = first.jwks
    _ = second.jwks
    assert calls == [CONFIG_URL, JWKS_URL]


def test_get_keys_the_cache_on_use_https(fake_get):
    assert OpenidConfigLoader.get(DOMAIN, use_https=True) is not OpenidConfigLoader.get(
        DOMAIN, use_https=False
    )


def test_clear_cache_drops_shared_loaders(fake_get):
    first = OpenidConfigLoader.get(DOMAIN)
    clear_cache()
    assert OpenidConfigLoader.get(DOMAIN) is not first


def test_concurrent_cold_loads_fetch_once(fake_get):
    """Ten threads racing a cold loader must produce one config fetch, not ten."""
    calls, _ = fake_get
    loader = OpenidConfigLoader.get(DOMAIN)
    barrier = threading.Barrier(10)

    def _work():
        barrier.wait()
        _ = loader.jwks

    threads = [threading.Thread(target=_work) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert calls.count(CONFIG_URL) == 1
    assert calls.count(JWKS_URL) == 1


def test_refresh_jwks_refetches_and_replaces(fake_get):
    calls, routes = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    assert [k.kid for k in loader.jwks.keys] == ["one"]

    routes[JWKS_URL] = ROTATED_DOC
    assert [k.kid for k in loader.refresh_jwks().keys] == ["two"]
    assert calls.count(JWKS_URL) == 2


def test_refresh_jwks_is_rate_limited(fake_get, monkeypatch):
    calls, routes = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    _ = loader.jwks
    routes[JWKS_URL] = ROTATED_DOC

    loader.refresh_jwks()
    loader.refresh_jwks()
    loader.refresh_jwks()

    # The first refresh reaches the network; the two inside the interval do not.
    assert calls.count(JWKS_URL) == 2


def test_refresh_jwks_allowed_again_after_the_interval(fake_get):
    calls, _ = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    _ = loader.jwks
    loader.refresh_jwks()
    loader.refresh_jwks()
    assert calls.count(JWKS_URL) == 2

    # Rewind the refresh clock rather than the wall clock, so the test does not sleep.
    loader._last_refresh_at -= loader_module.JWKS_REFRESH_INTERVAL * 2
    loader.refresh_jwks()

    assert calls.count(JWKS_URL) == 3


def test_refresh_jwks_rate_limit_holds_when_the_provider_is_failing(fake_get, monkeypatch):
    """
    A failing refetch must still advance the rate-limit clock. `kid` is attacker
    controlled, so if a failed refresh left the clock untouched, unknown-kid tokens would
    each trigger an outbound request against an already-degraded provider.
    """
    calls, _ = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    _ = loader.jwks
    before = calls.count(JWKS_URL)

    def _boom(url, *, timeout=10.0):
        calls.append(url)
        raise AuthenticationError("provider is down")

    monkeypatch.setattr(loader_module.http, "get_json", _boom)

    with pytest.raises(ArmasecError):
        loader.refresh_jwks()

    # The failed attempt stamped the clock, so these three are rate limited no-ops that
    # hand back the cached key set instead of reaching the network again.
    for _ in range(3):
        assert [k.kid for k in loader.refresh_jwks().keys] == ["one"]

    assert calls.count(JWKS_URL) == before + 1, (
        "a failing provider must not defeat the refresh rate limit"
    )


def test_first_refresh_is_never_rate_limited_by_the_initial_load(fake_get):
    """
    A rotation encountered shortly after startup must still recover. The interval governs
    refresh-to-refresh spacing, not the gap since the initial load.
    """
    _, routes = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    _ = loader.jwks
    routes[JWKS_URL] = ROTATED_DOC
    assert [k.kid for k in loader.refresh_jwks().keys] == ["two"]
