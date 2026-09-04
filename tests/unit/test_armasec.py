import pytest
from fastapi import HTTPException

from armasec_lite.armasec import Armasec
from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_security import TokenSecurity

DOMAIN = "auth.example.com"


def test_kwargs_build_a_single_domain_config():
    armasec = Armasec(domain=DOMAIN, audience="my-api")
    assert len(armasec.domain_configs) == 1
    assert armasec.domain_configs[0].domain == DOMAIN
    assert armasec.domain_configs[0].audience == "my-api"


def test_domain_configs_list_is_used_when_no_domain_kwarg():
    configs = [DomainConfig(domain="one.example.com"), DomainConfig(domain="two.example.com")]
    assert Armasec(domain_configs=configs).domain_configs == configs


def test_no_domain_raises_422():
    with pytest.raises(HTTPException) as info:
        Armasec()
    assert info.value.status_code == 422
    assert "No domain was input" in str(info.value.detail)


def test_lockdown_returns_a_token_security():
    security = Armasec(domain=DOMAIN).lockdown("read:x")
    assert isinstance(security, TokenSecurity)
    assert set(security.scopes) == {"read:x"}
    assert security.permission_mode is PermissionMode.ALL


def test_lockdown_is_memoized_on_its_arguments():
    armasec = Armasec(domain=DOMAIN)
    assert armasec.lockdown("read:x") is armasec.lockdown("read:x")
    assert armasec.lockdown("read:x") is not armasec.lockdown("write:x")


def test_lockdown_memoization_distinguishes_permission_mode():
    armasec = Armasec(domain=DOMAIN)
    assert armasec.lockdown_all("a") is not armasec.lockdown_some("a")


def test_lockdown_memoization_distinguishes_skip_plugins():
    armasec = Armasec(domain=DOMAIN)
    assert armasec.lockdown("a") is not armasec.lockdown("a", skip_plugins=True)


def test_lockdown_all_requires_every_scope():
    security = Armasec(domain=DOMAIN).lockdown_all("a", "b")
    assert security.permission_mode is PermissionMode.ALL


def test_lockdown_some_requires_one_scope():
    security = Armasec(domain=DOMAIN).lockdown_some("a", "b")
    assert security.permission_mode is PermissionMode.SOME


def test_debug_settings_are_passed_through():
    logged: list[str] = []
    logger = logged.append
    armasec = Armasec(domain=DOMAIN, debug_logger=logger, debug_exceptions=True)
    security = armasec.lockdown("read:x")
    assert security.debug_exceptions is True
    assert security.debug_logger is logger


def test_the_cache_is_per_instance_not_global():
    """
    Upstream decorates the method with lru_cache, which keys on self in a process-global
    cache and therefore pins every Armasec instance for the life of the process.
    """
    first = Armasec(domain=DOMAIN)
    second = Armasec(domain=DOMAIN)
    assert first.lockdown("read:x") is not second.lockdown("read:x")
