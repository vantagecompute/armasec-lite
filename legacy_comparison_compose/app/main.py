"""
One FastAPI application, built against either armasec-lite or upstream armasec.

The library is chosen by the `ARMASEC_LIB` environment variable and nothing else differs.
That single-module rule is what makes the comparison honest: two copies of this file, one
per arm, would drift, and every measured difference would then be arguable. Whatever route
table, response shape and dependency graph one arm gets, the other gets the same, because
they are the same lines of code.

The two libraries expose the same names, so the import is the only branch. `DomainConfig`
takes one extra keyword on the lite side, `verify_issuer`, which upstream does not have;
that is the one deliberate behavior difference between them and it is passed only where it
exists rather than being smuggled through `**kwargs`.

Both arms configure `permission_extractor=extract_keycloak_permissions`, because Keycloak
puts client roles under `resource_access.<azp>.roles` and not in a top level `permissions`
claim. Without it every scope check in the harness would read an empty permission list and
`/stuff` would 403 for reasons having nothing to do with the token.

### Routes

| Route | Auth |
| --- | --- |
| `GET /health` | none, so it can be hammered during a cold authenticated load |
| `GET /stuff` | requires `read:stuff` |
| `GET /either` | requires `read:stuff` or `admin:stuff` |
| `GET /whoami` | requires only a valid token, and returns its payload |

`/health` also reports which library is loaded and at what version, which is how the
parity tests confirm they are talking to the arm they think they are.

`HARNESS_SCOPE_ROUTES` additionally registers that many routes, each locked down behind a
scope set no token in the realm holds. Scenario S2 counts OIDC fetches against the number
of distinct `lockdown()` calls exercised, so it needs distinct scope sets it can reach one
at a time. They answer 403, which is fine and deliberate: a scope check happens after the
token is decoded, so the OIDC configuration has already been loaded by the time the request
is refused, which is the thing being counted.

### The sampling profiler

`GET /__profile/start` runs a daemon thread that wakes every few milliseconds, calls
`sys._current_frames()` and tallies one stack signature per thread. It is off until
started, so it costs nothing in the runs that do not ask for it.

Sampling rather than instrumenting is the point. `cProfile` distorts the timings the
harness exists to measure, and it cannot say what a process was doing while it was blocked,
because a blocked call is a single event with no returns until it finishes. A sampler can:
a thread stuck in a socket read still has a stack, and it appears in every sample taken
while it is stuck. Tagging the event loop thread separately therefore gives a direct view
of scenario S4 from the inside: samples landing in socket reads **on the loop thread** are
an event loop that is not running anything else.
"""

from __future__ import annotations

import collections
import os
import sys
import threading
import time
from typing import Annotated, Any

from fastapi import Depends, FastAPI

ARMASEC_LIB = os.environ.get("ARMASEC_LIB", "lite").strip().lower()
DOMAIN = os.environ.get("ARMASEC_DOMAIN", "oidc-proxy:8080/realms/armasec")
AUDIENCE = os.environ.get("ARMASEC_AUDIENCE", "armasec-api")
USE_HTTPS = os.environ.get("ARMASEC_USE_HTTPS", "false").strip().lower() in ("1", "true", "yes")
VERIFY_ISSUER = os.environ.get("ARMASEC_VERIFY_ISSUER", "true").strip().lower() in (
    "1",
    "true",
    "yes",
)
#: How many extra scope-locked routes to register, for scenario S2.
SCOPE_ROUTES = int(os.environ.get("HARNESS_SCOPE_ROUTES", "0") or "0")

if ARMASEC_LIB == "lite":
    from armasec_lite import (  # type: ignore[import-not-found]
        Armasec,
        DomainConfig,
        TokenPayload,
        extract_keycloak_permissions,
    )
    from armasec_lite import (
        __version__ as LIB_VERSION,
    )
elif ARMASEC_LIB == "legacy":
    from importlib.metadata import version as _dist_version

    from armasec import (  # type: ignore[import-not-found,no-redef]
        Armasec,
        TokenPayload,
        extract_keycloak_permissions,
    )
    from armasec.schemas import DomainConfig  # type: ignore[import-not-found,no-redef]

    LIB_VERSION = _dist_version("armasec")
else:
    raise RuntimeError(f"ARMASEC_LIB must be 'lite' or 'legacy', got {ARMASEC_LIB!r}")

domain_kwargs: dict[str, Any] = {
    "domain": DOMAIN,
    "audience": AUDIENCE,
    "use_https": USE_HTTPS,
    "permission_extractor": extract_keycloak_permissions,
}
if ARMASEC_LIB == "lite":
    # Upstream has no such field and would either reject it or silently ignore it. Passing
    # it only where it exists keeps the difference explicit rather than incidental.
    domain_kwargs["verify_issuer"] = VERIFY_ISSUER

armasec = Armasec(domain_configs=[DomainConfig(**domain_kwargs)], debug_exceptions=False)

app = FastAPI(title=f"armasec comparison harness ({ARMASEC_LIB})")


def payload_dict(payload: TokenPayload) -> dict[str, Any]:
    """
    Render a decoded token payload as the same JSON shape on both arms.

    `to_dict()` exists on both libraries' `TokenPayload` and emits the same four keys, so
    a parity test can compare response bodies and not only status codes.

    Args:
        payload: The verified payload injected by the route's security dependency.

    Returns:
        The payload as a plain dictionary. `original_token` is excluded, because echoing a
        caller's bearer token back over the wire is a bad habit even in a harness.
    """
    return dict(payload.to_dict())


@app.get("/health")
async def health() -> dict[str, Any]:
    """
    Report liveness and which library this process is running.

    Unauthenticated on purpose: scenario S4 hammers it during a cold authenticated load,
    where its latency exposes event loop blocking from outside the process.

    Returns:
        The arm name and the resolved version of the library it loaded.
    """
    return {"status": "ok", "lib": ARMASEC_LIB, "version": LIB_VERSION, "domain": DOMAIN}


@app.get("/stuff")
async def get_stuff(
    payload: Annotated[TokenPayload, Depends(armasec.lockdown("read:stuff"))],
) -> Any:
    """
    Require `read:stuff`.

    Args:
        payload: Injected by the security dependency once the token verifies.

    Returns:
        The permissions the token carried, so a caller can see why it was allowed.
    """
    return {"stuff": "read", "permissions": payload.permissions}


@app.get("/either")
async def get_either(
    payload: Annotated[TokenPayload, Depends(armasec.lockdown_some("read:stuff", "admin:stuff"))],
) -> Any:
    """
    Require at least one of `read:stuff` and `admin:stuff`.

    Exercises the SOME permission mode, which is memoized separately from the ALL mode
    instance for the same scopes and therefore counts as a distinct lockdown.

    Args:
        payload: Injected by the security dependency once the token verifies.

    Returns:
        The permissions the token carried.
    """
    return {"stuff": "either", "permissions": payload.permissions}


@app.get("/whoami")
async def whoami(payload: Annotated[TokenPayload, Depends(armasec.lockdown())]) -> Any:
    """
    Require a valid token and check no permissions.

    Args:
        payload: Injected by the security dependency once the token verifies.

    Returns:
        The decoded payload, minus the original token.
    """
    return payload_dict(payload)


def scope_route(index: int) -> Any:
    """
    Build a route handler locked behind a scope set belonging to nobody.

    The dependency is a local name, and `from __future__ import annotations` turns every
    annotation into a string that FastAPI later resolves against module globals. An
    `Annotated[..., Depends(dependency)]` annotation would therefore fail to resolve, so
    the dependency is passed as a default value instead, which FastAPI reads directly.

    Args:
        index: Distinguishes this route's scope set from every other one.

    Returns:
        An async handler ready to be registered.
    """
    dependency = armasec.lockdown(f"harness:scope-{index}")

    async def route(payload: TokenPayload = Depends(dependency)) -> Any:  # noqa: B008
        return {"scope_set": index, "permissions": payload.permissions}

    return route


for _index in range(SCOPE_ROUTES):
    app.get(f"/scope/{_index}")(scope_route(_index))


#: Stack signature counts, keyed by (thread label, signature). Read under `PROFILE_LOCK`.
PROFILE_COUNTS: collections.Counter[tuple[str, str]] = collections.Counter()
PROFILE_LOCK = threading.Lock()
PROFILE_STATE: dict[str, Any] = {"running": False, "interval_ms": 5.0, "samples": 0, "loop": 0}


def thread_label(thread_id: int) -> str:
    """
    Name a thread for the profile report, calling out the event loop.

    The distinction is the whole point of the measurement: work on the loop thread blocks
    every other request in the process, and the same work on a worker thread does not.

    Args:
        thread_id: The identifier `sys._current_frames()` keyed the stack under.

    Returns:
        `loop` for the thread running the asyncio event loop, otherwise the thread's name
        with its identifier, so worker threads stay distinguishable from each other.
    """
    if thread_id == PROFILE_STATE["loop"]:
        return "loop"
    for thread in threading.enumerate():
        if thread.ident == thread_id:
            return f"{thread.name}({thread_id})"
    return f"unknown({thread_id})"


def stack_signature(frame: Any, depth: int = 12) -> str:
    """
    Render a stack as a leaf-first, semicolon separated signature.

    Leaf first because the innermost frame is what the thread is actually doing, and a
    truncated signature should lose the uninformative uvicorn and asyncio scaffolding at
    the bottom rather than the socket read at the top.

    Args:
        frame: The innermost frame, as `sys._current_frames()` returns it.
        depth: How many frames to keep.

    Returns:
        Frames as `module:function:line`, innermost first.
    """
    parts: list[str] = []
    current = frame
    while current is not None and len(parts) < depth:
        code = current.f_code
        module = code.co_filename.rsplit("/", 1)[-1]
        parts.append(f"{module}:{code.co_name}:{current.f_lineno}")
        current = current.f_back
    return ";".join(parts)


def sampler() -> None:
    """Sample every live stack until `PROFILE_STATE['running']` goes false."""
    while PROFILE_STATE["running"]:
        frames = sys._current_frames()
        own = threading.get_ident()
        with PROFILE_LOCK:
            for thread_id, frame in frames.items():
                if thread_id == own:
                    continue
                PROFILE_COUNTS[(thread_label(thread_id), stack_signature(frame))] += 1
            PROFILE_STATE["samples"] += 1
        time.sleep(PROFILE_STATE["interval_ms"] / 1000.0)


@app.get("/__profile/start")
async def profile_start(interval_ms: float = 5.0) -> dict[str, Any]:
    """
    Start the sampling profiler, recording which thread is the event loop.

    The loop thread is identified from inside this handler, which runs on it. Nothing else
    in the process can say so reliably: uvicorn's loop thread has no distinguishing name.

    Args:
        interval_ms: Milliseconds between samples.

    Returns:
        The profiler state after starting.
    """
    PROFILE_STATE["loop"] = threading.get_ident()
    PROFILE_STATE["interval_ms"] = max(1.0, interval_ms)
    if not PROFILE_STATE["running"]:
        PROFILE_STATE["running"] = True
        threading.Thread(target=sampler, name="pmp-sampler", daemon=True).start()
    return {k: v for k, v in PROFILE_STATE.items()}


@app.get("/__profile/stop")
async def profile_stop() -> dict[str, Any]:
    """
    Stop the sampling profiler.

    Returns:
        The profiler state after stopping.
    """
    PROFILE_STATE["running"] = False
    return {k: v for k, v in PROFILE_STATE.items()}


@app.get("/__profile/reset")
async def profile_reset() -> dict[str, Any]:
    """
    Drop every accumulated sample without stopping the profiler.

    Returns:
        The profiler state after clearing.
    """
    with PROFILE_LOCK:
        PROFILE_COUNTS.clear()
        PROFILE_STATE["samples"] = 0
    return {k: v for k, v in PROFILE_STATE.items()}


@app.get("/__profile")
async def profile_read(top: int = 25) -> dict[str, Any]:
    """
    Report the most frequently sampled stack signatures, grouped by thread.

    Args:
        top: How many signatures to return per thread.

    Returns:
        The profiler state, the per-thread sample totals, and the top signatures for each
        thread with their sample counts.
    """
    with PROFILE_LOCK:
        snapshot = list(PROFILE_COUNTS.items())
        state = {k: v for k, v in PROFILE_STATE.items()}
    per_thread: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for (label, signature), count in snapshot:
        per_thread[label][signature] += count
    return {
        "state": state,
        "lib": ARMASEC_LIB,
        "totals": {label: sum(counts.values()) for label, counts in per_thread.items()},
        "top": {
            label: [
                {"samples": count, "signature": signature}
                for signature, count in counts.most_common(top)
            ]
            for label, counts in per_thread.items()
        },
    }
