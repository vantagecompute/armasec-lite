"""
The one place armasec talks to the network, replacing httpx with urllib.request.

armasec makes exactly two requests per domain per process: the discovery document and the
JWKS. There is nothing here for a connection pool to amortize, so the standard library is
not a compromise. What the standard library does not give for free is the hardening below.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from armasec_lite.exceptions import AuthenticationError

#: Cap on a response body. A compromised or hostile discovery endpoint should not be able
#: to exhaust memory in a process that is only expecting a few kilobytes of JSON.
MAX_BODY_BYTES = 1024 * 1024

#: Seconds before a request is abandoned.
DEFAULT_TIMEOUT = 10.0

#: Redirects followed before giving up.
MAX_REDIRECTS = 5


class _NoDowngradeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    A redirect handler that refuses to move from https to http.

    urllib follows redirects across schemes by default. A provider that is compromised, or
    merely misconfigured, could redirect a JWKS fetch onto plaintext, where the response
    can be rewritten in transit by anyone on the path. The keys that come back decide who
    is authenticated, so this is not a theoretical concern.
    """

    max_redirections = MAX_REDIRECTS

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        """Refuse a scheme downgrade, then defer to the standard behavior."""
        old_scheme = urlparse(req.get_full_url()).scheme
        new_scheme = urlparse(newurl).scheme
        if old_scheme == "https" and new_scheme != "https":
            raise AuthenticationError(
                f"Refusing redirect that would downgrade https to {new_scheme!r}: {newurl!r}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener() -> urllib.request.OpenerDirector:
    """
    Build an opener with certificate verification and the no-downgrade redirect handler.
    """
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _NoDowngradeRedirectHandler(),
    )


def get_json(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Fetch a URL and decode a JSON object from the response.

    Args:
        url:     The absolute http or https URL to fetch.
        timeout: Seconds to wait before abandoning the request.
    """
    scheme = urlparse(url).scheme
    # Not redundant with the schemas.py check: build_opener installs FileHandler among its
    # defaults, so an opener will happily read file:// URLs. jwks_uri arrives inside a
    # document fetched over the network and is then fetched in turn, so it gets two guards.
    if scheme not in ("http", "https"):
        raise AuthenticationError(f"Refusing to fetch URL with scheme {scheme!r}: {url!r}")

    opener = _build_opener()
    try:
        with opener.open(url, timeout=timeout) as response:
            if response.status != 200:
                raise AuthenticationError(
                    f"Didn't get a success status code from url {url}: {response.status}"
                )
            # Read one byte past the cap so an oversized body is detected rather than
            # silently truncated into a parse error that says nothing useful.
            body = response.read(MAX_BODY_BYTES + 1)
    except AuthenticationError:
        raise
    except urllib.error.HTTPError as err:
        raise AuthenticationError(
            f"Didn't get a success status code from url {url}: {err.code}"
        ) from err
    except (urllib.error.URLError, OSError) as err:
        raise AuthenticationError(f"Call to url {url} failed: {err}") from err

    if len(body) > MAX_BODY_BYTES:
        raise AuthenticationError(
            f"Response from url {url} is too large: over {MAX_BODY_BYTES} bytes"
        )

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise AuthenticationError(f"Response from url {url} is not valid JSON: {err}") from err

    if not isinstance(data, dict):
        raise AuthenticationError(f"Response from url {url} is not a JSON object")

    return data
