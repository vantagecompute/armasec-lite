import pytest

from armasec_lite.exceptions import (
    ArmasecError,
    AuthenticationError,
    AuthorizationError,
    DoExceptParams,
    PayloadMappingError,
)


def test_status_codes():
    assert ArmasecError.status_code == 400
    assert AuthenticationError.status_code == 401
    assert AuthorizationError.status_code == 403
    assert PayloadMappingError.status_code == 500


def test_require_condition_passes_on_truthy():
    AuthenticationError.require_condition(True, "should not raise")
    AuthenticationError.require_condition([1], "should not raise")


def test_require_condition_raises_on_falsey():
    with pytest.raises(AuthenticationError, match="nope"):
        AuthenticationError.require_condition(False, "nope")


def test_handle_errors_wraps_exception():
    with (
        pytest.raises(AuthenticationError) as info,
        AuthenticationError.handle_errors("outer message"),
    ):
        raise ValueError("inner message")
    assert "outer message" in str(info.value)
    assert "inner message" in str(info.value)


def test_handle_errors_does_not_wrap_on_success():
    with AuthenticationError.handle_errors("outer message"):
        pass


def test_handle_errors_invokes_do_except_with_params():
    captured: list[DoExceptParams] = []

    with (
        pytest.raises(AuthenticationError),
        AuthenticationError.handle_errors("boom", do_except=captured.append),
    ):
        raise ValueError("inner")

    assert len(captured) == 1
    assert captured[0].final_message.startswith("boom")
    assert isinstance(captured[0].err, ValueError)
    assert captured[0].trace is not None


def test_handle_errors_does_not_double_wrap_armasec_errors():
    with (
        pytest.raises(AuthorizationError, match="already typed"),
        AuthenticationError.handle_errors("outer"),
    ):
        raise AuthorizationError("already typed")
