"""
A counting, latency-injecting reverse proxy that sits in front of Keycloak.

The harness needs three things Keycloak will not do for it: an exact count of how many
HTTP requests each path received, a controllable amount of provider latency, and a way to
make the provider fail on demand. All three are properties of the wire, not of the
application, so they are measured and injected here rather than inferred from inside the
apps under test.

Everything is standard library. The proxy speaks HTTP/1.1 with `Connection: close` forced
on both legs, which costs a TCP handshake per request but removes every keep-alive and
response-framing edge case: the upstream response is relayed to the client as raw bytes
read until EOF, so chunked encoding, content lengths and trailers need no interpretation.
Only the OIDC discovery and JWKS paths traverse this proxy, never the benchmarked
application requests, so the extra handshake does not enter any measurement.

Control endpoints live under `/__` and are answered locally. They are never forwarded and
never counted, so a health check or a stats poll cannot pollute the numbers.

| Endpoint | Method | Effect |
| --- | --- | --- |
| `/__stats` | GET | JSON: per-path counts, total, and the current latency and fault settings |
| `/__latency?ms=N` | GET or POST | Set the delay injected before every forwarded request |
| `/__fault?status=N&count=M` | GET or POST | Answer the next M forwarded requests with `status` instead of proxying. `status=0` clears |
| `/__issuer?value=URL` | GET or POST | Rewrite the `issuer` field of the discovery document. An empty value clears it |
| `/__reset` | GET or POST | Zero the counters. Latency, fault and issuer settings are deliberately left alone |

`/__issuer` exists because the issuer is the one deliberate behavior difference between the
two libraries: armasec-lite compares a token's `iss` to the provider's advertised issuer by
exact string equality, and upstream armasec loads the issuer and never checks it. Keycloak
will not disagree with itself on demand, so the proxy does it instead. Both applications
cache the discovery document for the life of their process, so a rewrite only takes effect
for a process started after it was set.

Counting keys on the path with the query string stripped, so a JWKS fetch is one key
however the client decorates it.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import Counter
from typing import Any
from urllib.parse import parse_qs, urlsplit

LISTEN_HOST = os.environ.get("PROXY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROXY_LISTEN_PORT", "8080"))
UPSTREAM_HOST = os.environ.get("PROXY_UPSTREAM_HOST", "keycloak")
UPSTREAM_PORT = int(os.environ.get("PROXY_UPSTREAM_PORT", "8080"))

#: Hop by hop headers, which must not be relayed to the upstream.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
    }
)

STATE: dict[str, Any] = {
    "counts": Counter(),
    "total": 0,
    "latency_ms": 0,
    "fault_status": 0,
    "fault_remaining": 0,
    "issuer_override": "",
}

DISCOVERY_PATH_SUFFIX = "/.well-known/openid-configuration"


def _respond(status: int, payload: Any, content_type: str = "application/json") -> bytes:
    """
    Build a complete, self-terminating HTTP/1.1 response.

    Args:
        status:       The status code. Only the codes this proxy emits are named.
        payload:      A JSON-serializable object, or bytes to send verbatim.
        content_type: The Content-Type header value.

    Returns:
        The response as bytes, with `Connection: close` so the client stops reading at EOF.
    """
    reasons = {200: "OK", 400: "Bad Request", 404: "Not Found", 500: "Internal Server Error"}
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    head = (
        f"HTTP/1.1 {status} {reasons.get(status, 'Unknown')}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    return head + body


async def _read_head(reader: asyncio.StreamReader) -> tuple[bytes, dict[str, str], list[bytes]]:
    """
    Read the request line and headers.

    Args:
        reader: The client stream.

    Returns:
        A tuple of the request line, a lowercased header mapping, and the raw header lines
        as received, so they can be relayed without normalization.

    Raises:
        ConnectionError: The client closed before sending a request line.
    """
    request_line = await reader.readline()
    if not request_line:
        raise ConnectionError("client closed before sending a request line")
    raw: list[bytes] = []
    headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        raw.append(line)
        name, _, value = line.decode("latin-1").partition(":")
        headers[name.strip().lower()] = value.strip()
    return request_line, headers, raw


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
    """
    Read a request body, whether it is length-delimited or chunked.

    A chunked body is returned with its framing intact, because it is relayed together
    with the `Transfer-Encoding` header that describes it.

    Args:
        reader:  The client stream.
        headers: The lowercased request headers.

    Returns:
        The body bytes, empty when the request has none.
    """
    if "chunked" in headers.get("transfer-encoding", "").lower():
        parts: list[bytes] = []
        while True:
            line = await reader.readline()
            if not line:
                break
            parts.append(line)
            size = int(line.strip().split(b";")[0] or b"0", 16)
            if size == 0:
                while True:
                    trailer = await reader.readline()
                    parts.append(trailer)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                break
            parts.append(await reader.readexactly(size + 2))
        return b"".join(parts)
    length = int(headers.get("content-length") or 0)
    return await reader.readexactly(length) if length else b""


def _control(path: str, query: dict[str, list[str]], body: bytes) -> bytes | None:
    """
    Answer a control request locally.

    Args:
        path:  The request path with the query string removed.
        query: The parsed query string.
        body:  The request body, parsed as JSON when it is not empty, so the endpoints work
               from both `curl -X POST -d '{"ms": 200}'` and a bare query string.

    Returns:
        A complete response, or None when the path is not a control path and should be
        forwarded instead.
    """
    if not path.startswith("/__"):
        return None

    fields: dict[str, Any] = {k: v[0] for k, v in query.items()}
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                fields.update(parsed)
        except ValueError:
            return _respond(400, {"error": "body was not a JSON object"})

    if path == "/__stats":
        return _respond(
            200,
            {
                "counts": dict(STATE["counts"]),
                "total": STATE["total"],
                "latency_ms": STATE["latency_ms"],
                "fault_status": STATE["fault_status"],
                "fault_remaining": STATE["fault_remaining"],
                "issuer_override": STATE["issuer_override"],
                "upstream": f"{UPSTREAM_HOST}:{UPSTREAM_PORT}",
            },
        )
    if path == "/__latency":
        try:
            STATE["latency_ms"] = max(0, int(fields.get("ms", 0)))
        except (TypeError, ValueError):
            return _respond(400, {"error": "ms must be an integer"})
        return _respond(200, {"latency_ms": STATE["latency_ms"]})
    if path == "/__fault":
        try:
            STATE["fault_status"] = int(fields.get("status", 0))
            STATE["fault_remaining"] = int(fields.get("count", 0)) if STATE["fault_status"] else 0
        except (TypeError, ValueError):
            return _respond(400, {"error": "status and count must be integers"})
        return _respond(
            200,
            {"fault_status": STATE["fault_status"], "fault_remaining": STATE["fault_remaining"]},
        )
    if path == "/__issuer":
        STATE["issuer_override"] = str(fields.get("value", "") or "")
        return _respond(200, {"issuer_override": STATE["issuer_override"]})
    if path == "/__reset":
        STATE["counts"] = Counter()
        STATE["total"] = 0
        return _respond(200, {"counts": {}, "total": 0, "latency_ms": STATE["latency_ms"]})
    return _respond(404, {"error": f"no such control endpoint: {path}"})


def _rewrite_issuer(response: bytes, issuer: str) -> bytes:
    """
    Replace the `issuer` field of a discovery document in a complete raw response.

    The response is rebuilt rather than patched in place, because changing the body length
    invalidates both `Content-Length` and any chunked framing. Emitting a fresh
    length-delimited response sidesteps both.

    Args:
        response: The upstream response as raw bytes, headers included.
        issuer:   The issuer string to advertise instead.

    Returns:
        The rewritten response, or the original bytes unchanged when it was not a 200 with
        a JSON object body, which is the only case worth rewriting.
    """
    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator or b" 200 " not in head.split(b"\r\n", 1)[0]:
        return response
    if b"chunked" in head.lower():
        # A chunked discovery document is possible but Keycloak does not send one, and
        # de-chunking here would add framing code with no test to exercise it.
        return response
    try:
        document = json.loads(body)
    except ValueError:
        return response
    if not isinstance(document, dict) or "issuer" not in document:
        return response
    document["issuer"] = issuer
    return _respond(200, document)


async def _forward(request_line: bytes, raw_headers: list[bytes], body: bytes) -> bytes:
    """
    Relay one request to Keycloak and return its response bytes.

    Args:
        request_line: The client's request line, passed through unchanged.
        raw_headers:  The client's header lines, minus hop by hop headers.
        body:         The request body, already framed as the headers describe.

    Returns:
        The upstream response as raw bytes, or a 500 when the upstream is unreachable.
    """
    keep = [
        line
        for line in raw_headers
        if line.decode("latin-1").partition(":")[0].strip().lower() not in HOP_BY_HOP
    ]
    payload = request_line + b"".join(keep) + b"Connection: close\r\n\r\n" + body
    try:
        reader, writer = await asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT)
    except OSError as exc:
        return _respond(500, {"error": f"upstream unreachable: {exc}"})
    try:
        writer.write(payload)
        await writer.drain()
        return await reader.read()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Serve one client connection: one request, one response, then close.

    Args:
        reader: The client stream.
        writer: The client stream.
    """
    try:
        request_line, headers, raw_headers = await _read_head(reader)
        body = await _read_body(reader, headers)
        target = request_line.decode("latin-1").split(" ")[1] if b" " in request_line else "/"
        split = urlsplit(target)

        response = _control(split.path, parse_qs(split.query), body)
        if response is None:
            STATE["counts"][split.path] += 1
            STATE["total"] += 1
            if STATE["latency_ms"]:
                await asyncio.sleep(STATE["latency_ms"] / 1000.0)
            if STATE["fault_remaining"] > 0:
                STATE["fault_remaining"] -= 1
                response = _respond(STATE["fault_status"], {"error": "injected fault"})
            else:
                response = await _forward(request_line, raw_headers, body)
                if STATE["issuer_override"] and split.path.endswith(DISCOVERY_PATH_SUFFIX):
                    response = _rewrite_issuer(response, STATE["issuer_override"])

        writer.write(response)
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, IndexError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def main() -> None:
    """Serve until cancelled."""
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    print(
        f"oidc-proxy listening on {LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM_HOST}:{UPSTREAM_PORT}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
