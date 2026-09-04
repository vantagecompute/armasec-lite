import base64
import json

import pytest

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.jwt import (
    InvalidTokenError,
    b64url_decode,
    b64url_encode,
    get_unverified_header,
    split_token,
)


def _seg(payload: dict) -> str:
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_b64url_round_trip():
    for raw in (b"", b"a", b"ab", b"abc", b"abcd", bytes(range(256))):
        assert b64url_decode(b64url_encode(raw)) == raw


def test_b64url_encode_strips_padding():
    assert "=" not in b64url_encode(b"a")


def test_b64url_decode_accepts_unpadded_input():
    assert b64url_decode("YQ") == b"a"


def test_b64url_decode_rejects_impossible_length():
    # A length of 4n+1 cannot be valid base64.
    with pytest.raises(InvalidTokenError, match="length"):
        b64url_decode("YQZZZ")


def test_b64url_decode_rejects_standard_base64_alphabet():
    # '+' and '/' belong to standard base64, not base64url.
    with pytest.raises(InvalidTokenError, match="character"):
        b64url_decode("ab+d")
    with pytest.raises(InvalidTokenError, match="character"):
        b64url_decode("ab/d")


def test_b64url_decode_rejects_embedded_padding():
    with pytest.raises(InvalidTokenError, match="character"):
        b64url_decode("YQ==")


def test_split_token_returns_three_segments():
    assert split_token("aaa.bbb.ccc") == ("aaa", "bbb", "ccc")


@pytest.mark.parametrize("bad", ["", "aaa", "aaa.bbb", "aaa.bbb.ccc.ddd", "..", "aaa..ccc"])
def test_split_token_rejects_malformed_tokens(bad):
    with pytest.raises(InvalidTokenError):
        split_token(bad)


def test_get_unverified_header_reads_the_header_segment():
    token = f"{_seg({'alg': 'RS256', 'kid': 'abc'})}.{_seg({'sub': 'x'})}.signature"
    assert get_unverified_header(token) == {"alg": "RS256", "kid": "abc"}


def test_get_unverified_header_rejects_non_object_header():
    token = f"{b64url_encode(b'[1,2,3]')}.{_seg({'sub': 'x'})}.sig"
    with pytest.raises(InvalidTokenError, match="object"):
        get_unverified_header(token)


def test_get_unverified_header_rejects_invalid_json():
    token = f"{b64url_encode(b'not json')}.{_seg({'sub': 'x'})}.sig"
    with pytest.raises(InvalidTokenError):
        get_unverified_header(token)


def test_jwt_errors_are_authentication_errors():
    assert issubclass(InvalidTokenError, AuthenticationError)
    assert InvalidTokenError.status_code == 401
