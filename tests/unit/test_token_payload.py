"""Tests for `armasec_lite.token_payload.TokenPayload`."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from armasec_lite.token_payload import TokenPayload


def test_construction_maps_upstream_aliases():
    """The `exp` and `azp` claim names alias onto `expire` and `client_id`."""
    payload = TokenPayload(
        sub="abc",
        exp=1735689600,
        azp="my-client",
        permissions=["read:x"],
        original_token="the-token",
    )
    assert payload.sub == "abc"
    assert payload.client_id == "my-client"
    assert payload.permissions == ["read:x"]
    assert payload.expire == datetime.fromtimestamp(1735689600, tz=UTC)
    assert payload.original_token == "the-token"


def test_construction_accepts_the_unaliased_names():
    """The armasec-native names `client_id` and `expire` also validate."""
    payload = TokenPayload(sub="abc", client_id="c", expire=1735689600)
    assert payload.client_id == "c"
    assert payload.expire is not None


def test_construction_defaults_permissions_to_empty():
    """`permissions` defaults to an empty list when the claim is absent."""
    assert TokenPayload(sub="abc").permissions == []


def test_construction_requires_sub():
    """A missing `sub` claim raises a pydantic `ValidationError`."""
    with pytest.raises(ValidationError, match="sub"):
        TokenPayload(exp=1735689600)


def test_extra_claims_are_reachable_as_attributes():
    """Claims that are not declared fields remain reachable as attributes."""
    payload = TokenPayload(sub="abc", email="a@b.c", is_admin=True)
    assert payload.email == "a@b.c"
    assert payload.is_admin is True


def test_unknown_attribute_raises_attribute_error():
    """An attribute that is neither a declared field nor an extra claim raises."""
    payload = TokenPayload(sub="abc")
    with pytest.raises(AttributeError, match="nope"):
        _ = payload.nope


def test_extra_does_not_shadow_declared_fields():
    """A declared field always wins over any same-named extra claim."""
    payload = TokenPayload(sub="abc", permissions=["a"])
    assert payload.permissions == ["a"]
    assert "permissions" not in (payload.model_extra or {})


def test_to_dict_matches_the_upstream_shape():
    """`to_dict` produces the flat shape upstream armasec's `to_dict` produced."""
    payload = TokenPayload(sub="abc", exp=1735689600, azp="my-client", permissions=["read:x"])
    assert payload.to_dict() == {
        "sub": "abc",
        "permissions": ["read:x"],
        "exp": 1735689600,
        "client_id": "my-client",
    }


def test_to_dict_without_an_expiry_omits_the_timestamp():
    """`to_dict` reports `None` for `exp` when no expiry claim was present."""
    payload = TokenPayload(sub="abc")
    assert payload.to_dict()["exp"] is None


def test_model_dump_round_trips_through_model_validate():
    """`model_dump` includes extra claims, and `model_validate` restores them.

    This is the capability the pydantic design exists for: hand-rolled dataclasses
    could not offer a lossless dump/reload cycle over arbitrary claims.
    """
    payload = TokenPayload(
        sub="abc",
        exp=1735689600,
        azp="my-client",
        permissions=["read:x"],
        original_token="the-token",
        email="a@b.c",
        is_admin=True,
    )

    dumped = payload.model_dump()

    assert dumped["sub"] == "abc"
    assert dumped["email"] == "a@b.c"
    assert dumped["is_admin"] is True

    restored = TokenPayload.model_validate(dumped)

    assert restored.sub == payload.sub
    assert restored.email == payload.email
    assert restored.is_admin == payload.is_admin
    assert restored.client_id == payload.client_id
    assert restored.expire == payload.expire
    assert restored.original_token == payload.original_token
