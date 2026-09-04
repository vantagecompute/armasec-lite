"""
The one place armasec talks to the network, replacing httpx.

Everything outbound goes through `get_json`, and only `openid_config_loader` calls it.
armasec makes exactly two requests per domain per process: the discovery document and the
JWKS. There is nothing here for a connection pool to amortize, so `urllib.request` from
the standard library is not a compromise. What the standard library does not give for free
is the hardening below.

Being the single choke point is also what makes the pytest extension's mock provider
possible: it swaps `armasec_lite.http.get_json` for a routing table, and there is nothing
else for it to intercept.

### The scheme guard is load-bearing

`urllib.request.build_opener()` installs `FileHandler` among its defaults, so an opener
will happily read a `file://` URL and hand back its contents. The check at the top of
`get_json` therefore is not redundant with the URL validation in `schemas.py`: without it,
a `jwks_uri` that reached here as a `file://` URL would turn a JWKS fetch into an
arbitrary local file read, and the file's contents would be parsed as the keys that decide
who is authenticated. `jwks_uri` arrives inside a document fetched over the network and is
then fetched in turn, so it gets both guards.

### Redirects

`_NoDowngradeRedirectHandler` refuses to follow a redirect from https to http, or off http
and https altogether. urllib crosses schemes freely by default. A provider that is
compromised, or merely misconfigured, could redirect a JWKS fetch onto plaintext, where
anyone on the path can rewrite the response. The destination scheme is pinned
unconditionally rather than only for an https origin, because a `use_https=False` domain
starts on http and the stdlib handler would otherwise follow a redirect from there onto
ftp or any other scheme it knows.

### The constants

`MAX_BODY_BYTES` (1 MiB) caps how much of a response is read. A compromised or hostile
discovery endpoint should not be able to exhaust memory in a process that expects a few
kilobytes of JSON. One byte past the cap is read deliberately, so an oversized body is
reported as oversized rather than silently truncated into a parse error that says nothing
useful.

`DEFAULT_TIMEOUT` (10 seconds) bounds a single request. It matters more than it looks:
this is the cold path a request waits on, so an unbounded fetch against a provider that
accepts a connection and then stalls would hold the request open indefinitely.

`MAX_REDIRECTS` (5) caps the redirect chain, which stops a redirect loop from becoming an
unbounded series of outbound requests.

Every failure here raises `AuthenticationError`, so every one maps to 401. That is right
from the route's point of view (the token could not be verified), even though the cause is
usually the provider rather than the caller.
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
    A redirect handler that refuses to move from https to http, or off http and https
    altogether.

    urllib follows redirects across schemes by default. A provider that is compromised, or
    merely misconfigured, could redirect a JWKS fetch onto plaintext, where the response
    can be rewritten in transit by anyone on the path. The keys that come back decide who
    is authenticated, so this is not a theoretical concern.

    The destination scheme is pinned unconditionally rather than only for an https origin.
    A `use_https=False` domain starts on http, and from there the stdlib handler would
    still follow a redirect onto ftp or any other scheme it knows.

    Attributes:
        max_redirections: How many redirects are followed before urllib gives up. Set from
                          `MAX_REDIRECTS`, which caps a redirect loop.
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
        """
        Refuse a scheme downgrade or change, then defer to the standard behavior.

        Called by urllib for each redirect. Everything except the scheme check is left to
        the stdlib handler, including the redirect count.

        Args:
            req:     The request that was redirected.
            fp:      The response file object.
            code:    The HTTP status of the redirect.
            msg:     The status message.
            headers: The response headers.
            newurl:  The redirect destination.

        Returns:
            The follow-up request, from the standard handler.

        Raises:
            AuthenticationError: The destination is not http or https, or the origin was
                https and the destination is not. Maps to 401.
        """
        old_scheme = urlparse(req.get_full_url()).scheme
        new_scheme = urlparse(newurl).scheme
        if new_scheme not in ("http", "https"):
            raise AuthenticationError(
                f"Refusing redirect to unsupported scheme {new_scheme!r}: {newurl!r}"
            )
        if old_scheme == "https" and new_scheme != "https":
            raise AuthenticationError(
                f"Refusing redirect that would downgrade https to {new_scheme!r}: {newurl!r}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener() -> urllib.request.OpenerDirector:
    """
    Build an opener with certificate verification and the no-downgrade redirect handler.

    Built per call rather than kept as a module-level singleton. armasec makes two requests
    per domain per process, so there is nothing to amortize, and a shared opener would be
    mutable state reachable from several threads.

    Passing an explicit `HTTPSHandler` with `ssl.create_default_context()` is what pins
    certificate verification on: the default context verifies certificates and checks
    hostnames, and stating it here means a caller cannot end up with an unverified
    connection through some ambient configuration.

    Returns:
        The configured opener. Note that `build_opener` still installs the stdlib defaults
        alongside these, `FileHandler` included, which is why `get_json` checks the scheme
        itself before opening anything.
    """
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _NoDowngradeRedirectHandler(),
    )


def get_json(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """
    Fetch a URL and decode a JSON object from the response.

    The only outbound call in the library. It is synchronous on purpose: `TokenSecurity`
    runs it in an executor rather than pretending it is async, and nothing else in the
    request path performs I/O at all.

    The scheme is checked before the opener is built, which is not redundant with the URL
    validation in `schemas.py`. `build_opener` installs `FileHandler` among its defaults,
    so without this check a `file://` URL reaching here would be read off disk and its
    contents parsed as JWKS keys.

    Args:
        url:     The absolute http or https URL to fetch.
        timeout: Seconds to wait before abandoning the request. Bounds one request, not
                 the whole redirect chain.

    Returns:
        The decoded JSON object. A JSON array or scalar is rejected rather than returned,
        since every document armasec fetches is an object.

    Raises:
        AuthenticationError: Every failure mode, all mapping to 401. The scheme is not
            http or https; the connection failed or timed out; the response status was not
            200; a redirect would have downgraded or changed scheme; the body exceeded
            `MAX_BODY_BYTES`; the body was not valid JSON; or the body was valid JSON but
            not an object. The message names the URL and the specific cause, which is what
            a `debug_logger` will show when a provider is misconfigured.
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
