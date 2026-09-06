"""
Tests that the warm request path does no formatting work the default logger throws away.

`noop` is the default `debug_logger`, so on a normal deployment every debug message a
request builds is discarded. Building them is not free: a pydantic model interpolated into
an f-string costs several microseconds, and `TokenDecoder._find_key` used to pay that once
per key in the JWKS on every single request. Profiling a warm RS256 decode against a
six-key key set showed pydantic's repr machinery accounting for roughly 38% of the total,
against 14% for the RSA signature verification that is the actual work.

Each test here comes in a pair: one asserting nothing is formatted under `noop`, and one
asserting the same message really is produced when a logger is supplied. The second half
is what stops the guards from being "fixed" into silence, which would pass the first half
perfectly.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pydantic import BaseModel
from starlette.datastructures import Headers

from armasec_lite import token_security
from armasec_lite.jwt import b64url_encode
from armasec_lite.schemas import JWK, JWKs, OpenidConfig, PermissionMode
from armasec_lite.token_decoder import TokenDecoder
from armasec_lite.token_manager import TokenManager
from armasec_lite.token_payload import TokenPayload
from armasec_lite.token_security import TokenSecurity

ISSUER = "https://auth.example.com"


class FormatCounter:
    """
    Counts how many times a pydantic model was expanded into text.

    Attributes:
        count: The number of expansions seen so far.
    """

    def __init__(self) -> None:
        self.count = 0


@contextmanager
def counting_model_formats() -> Iterator[FormatCounter]:
    """
    Count every pydantic repr or str expansion performed inside the block.

    Hooks `BaseModel.__repr_args__`, which both `__repr__` and `__str__` route through, so
    an f-string, a `repr()` and a `str()` are all caught. That is the exact call the
    profile identified as the cost, so counting it measures the thing that matters rather
    than a proxy for it.

    Returns:
        A counter whose `count` is the number of expansions during the block.
    """
    counter = FormatCounter()
    original = BaseModel.__repr_args__

    def counted(self: BaseModel) -> Any:
        counter.count += 1
        return original(self)

    BaseModel.__repr_args__ = counted  # type: ignore[method-assign]
    try:
        yield counter
    finally:
        BaseModel.__repr_args__ = original  # type: ignore[method-assign]


def _sign(rsa_private: Any, claims: dict[str, Any], kid: str = "rsa-test") -> str:
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": kid}).encode())
    body = b64url_encode(json.dumps(claims).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64url_encode(sig)}"


@pytest.fixture
def jwks(rsa_jwk: JWK) -> JWKs:
    """A six key JWKS with the usable key last, so a linear scan visits every one."""
    decoys = [
        JWK.model_validate({"kty": "RSA", "kid": f"decoy-{i}", "n": rsa_jwk.n, "e": rsa_jwk.e})
        for i in range(5)
    ]
    return JWKs(keys=[*decoys, rsa_jwk])


@pytest.fixture
def token(rsa_private: Any) -> str:
    return _sign(rsa_private, {"sub": "test-user", "exp": int(time.time()) + 3600})


def test_warm_decode_formats_no_models_under_the_default_logger(jwks: JWKs, token: str) -> None:
    """A decode with the default `noop` logger expands no pydantic model at all."""
    decoder = TokenDecoder(jwks)
    with counting_model_formats() as counter:
        decoder.decode(token)
    assert counter.count == 0


def test_warm_decode_still_logs_the_key_scan_when_a_logger_is_supplied(
    jwks: JWKs, token: str
) -> None:
    """
    The guard must skip formatting, not skip logging.

    Without this the previous test passes just as well against a `_find_key` whose log
    line has simply been deleted.
    """
    messages: list[str] = []
    decoder = TokenDecoder(jwks, debug_logger=messages.append)
    decoder.decode(token)
    assert any("Checking key in jwk" in message for message in messages)
    assert any("Built token_payload" in message for message in messages)


class CountingHeaders(dict[str, str]):
    """
    A header mapping that counts how many times it is expanded into text.

    A pydantic counter cannot witness this path, since starlette's `Headers` is not a
    model. `unpack_token_from_header` accepts any mapping, so a dict that notices its own
    repr is the direct witness: the header mapping carries the `Authorization` header and
    any cookies, which makes it both the most expensive and the most sensitive value the
    request path used to interpolate unconditionally.

    Attributes:
        repr_count: The number of times this mapping has been rendered as text.
    """

    repr_count = 0

    def __repr__(self) -> str:
        type(self).repr_count += 1
        return super().__repr__()


def test_unpacking_a_header_does_not_render_the_header_map_under_the_default_logger(
    jwks: JWKs, token: str
) -> None:
    """Unpacking the bearer token never renders the header mapping into a message."""
    manager = TokenManager(
        OpenidConfig.model_validate(
            {"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks"}, context={"require_https": True}
        ),
        TokenDecoder(jwks),
    )
    headers = CountingHeaders({"Authorization": f"Bearer {token}"})
    CountingHeaders.repr_count = 0
    manager.unpack_token_from_header(headers)
    assert CountingHeaders.repr_count == 0


def test_unpacking_a_header_still_logs_when_a_logger_is_supplied(jwks: JWKs, token: str) -> None:
    """The header and the extracted token still reach a supplied logger."""
    messages: list[str] = []
    manager = TokenManager(
        OpenidConfig.model_validate(
            {"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks"}, context={"require_https": True}
        ),
        TokenDecoder(jwks),
        debug_logger=messages.append,
    )
    manager.unpack_token_from_header(Headers({"Authorization": f"Bearer {token}"}))
    assert any("Attempting to unpack token from headers" in message for message in messages)


def test_checking_scopes_does_not_build_its_debug_line_under_the_default_logger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A scope check under `noop` never composes its debug message.

    `_check_scopes` builds that line through `unwrap`, which splits and rejoins the whole
    string, so the discarded work here is more than an f-string. `unwrap` is still called
    once on this path, for the `require_condition` failure message, so the witness has to
    look at what is being unwrapped rather than merely counting calls.
    """
    unwrapped: list[str] = []
    original = token_security.unwrap

    def recording(text: str) -> str:
        unwrapped.append(text)
        return original(text)

    monkeypatch.setattr(token_security, "unwrap", recording)

    security = TokenSecurity(domain_configs=[], scopes=["read:stuff"])
    security._check_scopes(TokenPayload(sub="test-user", permissions=["read:stuff"]))
    assert not any("Checking my permissions" in text for text in unwrapped)


def test_checking_scopes_still_logs_when_a_logger_is_supplied() -> None:
    """The permission comparison still reaches a supplied logger."""
    messages: list[str] = []
    security = TokenSecurity(
        domain_configs=[],
        scopes=["read:stuff"],
        permission_mode=PermissionMode.ALL,
        debug_logger=messages.append,
    )
    security._check_scopes(TokenPayload(sub="test-user", permissions=["read:stuff"]))
    assert any("Checking my permissions" in message for message in messages)
