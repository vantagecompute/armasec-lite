from armasec_lite.exceptions import DoExceptParams
from armasec_lite.utilities import log_error, noop, unwrap


def test_noop_accepts_anything_and_returns_none():
    assert noop() is None
    assert noop(1, 2, three=3) is None


def test_unwrap_joins_wrapped_lines_into_one():
    text = """
        this text is spread
        across several lines
    """
    assert unwrap(text) == "this text is spread across several lines"


def test_log_error_is_silent_when_logger_is_noop():
    log_error(noop, DoExceptParams("message", ValueError("boom"), None))


def test_log_error_writes_message_error_and_trace():
    lines: list[str] = []
    try:
        raise ValueError("boom")
    except ValueError as err:
        params = DoExceptParams("final message", err, err.__traceback__)

    log_error(lines.append, params)

    assert len(lines) == 1
    assert "final message" in lines[0]
    assert "boom" in lines[0]
    assert "Traceback" in lines[0]
