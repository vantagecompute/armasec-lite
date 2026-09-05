"""
Tests run against a real local HTTP server rather than a mocked urllib, because the
behavior under test is redirect handling, size limits and error mapping, all of which
live in urllib itself.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.http import MAX_BODY_BYTES, get_json


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        routes = self.server.routes  # type: ignore[attr-defined]
        if self.path not in routes:
            self.send_error(404)
            return
        status, headers, body = routes[self.path]
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.routes = {}  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    httpd.base = f"http://127.0.0.1:{httpd.server_address[1]}"  # type: ignore[attr-defined]
    yield httpd
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def _route(server, path, body, status=200, headers=None):
    server.routes[path] = (status, headers or {"Content-Type": "application/json"}, body)


def test_get_json_returns_a_decoded_object(server):
    _route(server, "/ok", json.dumps({"issuer": "https://x"}).encode())
    assert get_json(f"{server.base}/ok") == {"issuer": "https://x"}


def test_get_json_raises_on_a_non_200_status(server):
    _route(server, "/bad", b"{}", status=500)
    with pytest.raises(AuthenticationError, match="500"):
        get_json(f"{server.base}/bad")


def test_get_json_raises_on_invalid_json(server):
    _route(server, "/junk", b"not json")
    with pytest.raises(AuthenticationError, match="JSON"):
        get_json(f"{server.base}/junk")


def test_get_json_raises_when_the_body_is_not_an_object(server):
    _route(server, "/list", b"[1, 2, 3]")
    with pytest.raises(AuthenticationError, match="object"):
        get_json(f"{server.base}/list")


def test_get_json_rejects_an_oversized_body(server):
    _route(server, "/huge", b'{"pad": "' + b"x" * (MAX_BODY_BYTES + 10) + b'"}')
    with pytest.raises(AuthenticationError, match="too large"):
        get_json(f"{server.base}/huge")


def test_get_json_follows_a_same_scheme_redirect(server):
    _route(server, "/target", json.dumps({"ok": True}).encode())
    _route(
        server,
        "/from",
        b"",
        status=302,
        headers={"Location": f"{server.base}/target"},
    )
    assert get_json(f"{server.base}/from") == {"ok": True}


def test_get_json_refuses_an_https_to_http_downgrade():
    # No server needed: the handler refuses before any request is issued.
    from armasec_lite.http import _NoDowngradeRedirectHandler

    handler = _NoDowngradeRedirectHandler()

    class _FakeRequest:
        def get_full_url(self):
            return "https://secure.example.com/a"

    with pytest.raises(AuthenticationError, match="downgrade"):
        handler.redirect_request(
            _FakeRequest(), None, 302, "Found", {}, "http://secure.example.com/b"
        )


def test_get_json_refuses_a_redirect_off_http_and_https():
    """
    From an http origin, which a `use_https=False` domain has, the stdlib handler would
    still follow a redirect onto ftp. The destination scheme is pinned unconditionally.
    """
    from armasec_lite.http import _NoDowngradeRedirectHandler

    handler = _NoDowngradeRedirectHandler()

    class _FakeRequest:
        def get_full_url(self):
            return "http://plain.example.com/a"

    with pytest.raises(AuthenticationError, match="unsupported scheme"):
        handler.redirect_request(_FakeRequest(), None, 302, "Found", {}, "ftp://elsewhere/b")


def test_get_json_raises_on_an_unreachable_host():
    with pytest.raises(AuthenticationError):
        get_json("http://127.0.0.1:1/nothing", timeout=1.0)


def test_get_json_rejects_a_non_http_scheme():
    with pytest.raises(AuthenticationError, match="scheme"):
        get_json("file:///etc/passwd")
