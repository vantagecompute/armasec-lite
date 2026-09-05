"""
In-image probes: import cost, installed distributions, call counts, static call graph.

Baked into the application image and run with `docker exec`, because each of these is a
property of the environment the library lives in rather than of a running server, and
because a fresh interpreter is the only place import cost can be measured at all. One
module for both arms, chosen by `ARMASEC_LIB`, for the same reason `main.py` is one module:
two copies would drift and every measured difference would then be arguable.

Every subcommand prints a single JSON object on stdout and nothing else, so the caller can
parse the output of `docker exec` without stripping banners.

| Subcommand | What it measures |
| --- | --- |
| `import-cost` | `ru_maxrss` delta and `sys.modules` growth from importing the arm's library into a bare interpreter |
| `distributions` | Every installed distribution's name and version, from `importlib.metadata` |
| `callcounts` | Function calls, by owning package, for one warm and one cold authenticated request, plus the deepest stack reached |
| `static` | Call sites and shortest static path from the FastAPI dependency to signature verification |

### Why `sys.setprofile` and not `cProfile`

`callcounts` wants call counts, not timings, and `sys.setprofile` gives exactly that with
one hook and no pstats round trip. It is also the only one of the two that can be extended
to threads the request dispatches work onto: `threading.setprofile` installs the same hook
on every thread started afterwards, which matters because `armasec_lite` runs its cold OIDC
load in an executor thread and a current-thread-only profiler would report that work as
free.

Timing questions are answered by the sampling profiler in `main.py` and by the load
generator, neither of which instruments a call.
"""

from __future__ import annotations

import ast
import asyncio
import collections
import json
import os
import resource
import sys
import threading
import urllib.parse
import urllib.request
from typing import Any

ARMASEC_LIB = os.environ.get("ARMASEC_LIB", "lite").strip().lower()
PROXY_URL = os.environ.get("HARNESS_PROXY_URL", "http://oidc-proxy:8080")
TOKEN_URL = f"{PROXY_URL}/realms/armasec/protocol/openid-connect/token"

#: Function names that mean "check the signature", for the static path search. Upstream
#: reaches signature verification inside python-jose, which spells it with a leading
#: underscore in `jose.jws` and as a plain method on its backend key classes.
VERIFY_NAMES = frozenset({"verify_signature", "_verify_signature", "verify"})


def emit(payload: dict[str, Any]) -> None:
    """
    Print one JSON object and nothing else.

    Args:
        payload: The object to print.
    """
    print(json.dumps(payload))


def package_of(filename: str) -> str:
    """
    Attribute a source file to the thing that ships it.

    Args:
        filename: A code object's `co_filename`.

    Returns:
        The distribution-ish package name for a file under `site-packages`, `harness-app`
        for this harness's own modules, `stdlib` for anything else under the Python
        installation, and `other` when none of those match.
    """
    marker = "site-packages/"
    if marker in filename:
        tail = filename.split(marker, 1)[1]
        return tail.split("/", 1)[0].removesuffix(".py")
    if filename.startswith("/srv/app"):
        return "harness-app"
    if "/lib/python3" in filename or filename.startswith("<"):
        return "stdlib"
    return "other"


def import_cost() -> None:
    """
    Measure what importing the arm's library costs a bare interpreter.

    `ru_maxrss` is a high water mark rather than a current reading, so the delta is a lower
    bound on the peak the import reached and can never be negative. The module count is the
    more interesting half: it says how much of the interpreter the library populates, which
    is the thing that scales with a dependency list.
    """
    before_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    before_modules = set(sys.modules)
    if ARMASEC_LIB == "lite":
        import armasec_lite  # noqa: F401
    else:
        import armasec  # noqa: F401
    after_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    after_modules = set(sys.modules)
    added = sorted(after_modules - before_modules)
    emit(
        {
            "lib": ARMASEC_LIB,
            "rss_delta_kib": after_rss - before_rss,
            "rss_after_kib": after_rss,
            "modules_before": len(before_modules),
            "modules_after": len(after_modules),
            "modules_added": len(added),
            "top_level_packages_added": sorted({name.split(".")[0] for name in added}),
        }
    )


def distributions() -> None:
    """Report every installed distribution's name and version."""
    from importlib.metadata import distributions as installed

    found: dict[str, str] = {}
    for dist in installed():
        name = dist.metadata["Name"]
        if name:
            found[name.lower()] = dist.version
    emit({"lib": ARMASEC_LIB, "count": len(found), "distributions": found})


def mint_token() -> str:
    """
    Get a real access token from Keycloak, through the proxy.

    Returns:
        The compact access token.
    """
    form = {
        "grant_type": "password",
        "client_id": "armasec-api",
        "client_secret": "armasec-api-secret",
        "username": "testuser",
        "password": "testuser-password",
    }
    data = urllib.parse.urlencode(form).encode()
    with urllib.request.urlopen(TOKEN_URL, data=data, timeout=30) as response:
        return str(json.loads(response.read())["access_token"])


def build_security() -> Any:
    """
    Build the same security dependency `main.py` builds, without starting a server.

    Returns:
        The `lockdown("read:stuff")` dependency for the configured arm.
    """
    if ARMASEC_LIB == "lite":
        from armasec_lite import Armasec, DomainConfig, extract_keycloak_permissions

        config = DomainConfig(
            domain=os.environ.get("ARMASEC_DOMAIN", "oidc-proxy:8080/realms/armasec"),
            audience=os.environ.get("ARMASEC_AUDIENCE", "armasec-api"),
            use_https=False,
            permission_extractor=extract_keycloak_permissions,
            verify_issuer=True,
        )
    else:
        from armasec import Armasec, extract_keycloak_permissions
        from armasec.schemas import DomainConfig

        config = DomainConfig(
            domain=os.environ.get("ARMASEC_DOMAIN", "oidc-proxy:8080/realms/armasec"),
            audience=os.environ.get("ARMASEC_AUDIENCE", "armasec-api"),
            use_https=False,
            permission_extractor=extract_keycloak_permissions,
        )
    return Armasec(domain_configs=[config], debug_exceptions=False).lockdown("read:stuff")


def fake_request(token: str) -> Any:
    """
    Build the minimum Starlette request both libraries will accept.

    Args:
        token: The bearer token to present.

    Returns:
        A `Request` carrying an Authorization header and nothing else of consequence.
    """
    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/stuff",
            "raw_path": b"/stuff",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 8000),
        }
    )


class CallCounter:
    """
    A `sys.setprofile` hook that counts calls per package and tracks stack depth.

    Attributes:
        by_package: Call counts keyed by the package owning the called code.
        by_module:  Call counts keyed by package and source file. This is what separates
                    armasec-lite's JWT layer from the rest of it: `armasec_lite.jwt` is a
                    module inside the package it is being distinguished from, whereas
                    upstream's JWT layer is a separate distribution and falls out of
                    `by_package` for free. Comparing the two needs the finer key.
        calls:      Total calls seen, Python and C together.
        max_depth:  The deepest stack reached, counted from where profiling started.
    """

    def __init__(self) -> None:
        """Start with no samples and every thread at depth zero."""
        self.by_package: collections.Counter[str] = collections.Counter()
        self.by_module: collections.Counter[str] = collections.Counter()
        self.calls = 0
        self.max_depth = 0
        self._depth: dict[int, int] = collections.defaultdict(int)

    def hook(self, frame: Any, event: str, arg: Any) -> None:
        """
        Record one profile event.

        Args:
            frame: The frame the event happened in.
            event: One of the `sys.setprofile` event names.
            arg:   The C function object for `c_call`, otherwise unused.
        """
        thread = threading.get_ident()
        if event == "call":
            self.calls += 1
            filename = frame.f_code.co_filename
            package = package_of(filename)
            self.by_package[package] += 1
            if package not in ("stdlib", "other"):
                self.by_module[f"{package}:{filename.rsplit('/', 1)[-1]}"] += 1
            self._depth[thread] += 1
            self.max_depth = max(self.max_depth, self._depth[thread])
        elif event == "c_call":
            self.calls += 1
            module = getattr(arg, "__module__", None) or "builtins"
            self.by_package[f"c:{module.split('.')[0]}"] += 1
        elif event in ("return", "exception"):
            self._depth[thread] = max(0, self._depth[thread] - 1)


def profile_once(security: Any, request: Any) -> dict[str, Any]:
    """
    Drive one request through the security dependency with the profiler on.

    `threading.setprofile` is installed alongside `sys.setprofile` because armasec-lite
    dispatches its cold OIDC load to an executor thread. Profiling only the calling thread
    would report that work as costing nothing, which is the opposite of true.

    Args:
        security: The dependency to call.
        request:  The request to pass it.

    Returns:
        The call counts, the per-package breakdown, the deepest stack, and whether the call
        succeeded.
    """
    counter = CallCounter()

    async def drive() -> Any:
        return await security(request)

    threading.setprofile(counter.hook)
    sys.setprofile(counter.hook)
    failure: str | None = None
    try:
        asyncio.run(drive())
    except Exception as error:  # noqa: BLE001 - a refused request is a result, not a crash
        failure = f"{type(error).__name__}: {error}"
    finally:
        sys.setprofile(None)
        threading.setprofile(None)
    return {
        "ok": failure is None,
        "failure": failure,
        "total_calls": counter.calls,
        "max_depth": counter.max_depth,
        "by_package": dict(counter.by_package.most_common()),
        "by_module": dict(counter.by_module.most_common()),
    }


def callcounts() -> None:
    """
    Count the calls one authenticated request costs, cold and then warm.

    The cold request is measured first and includes the OIDC discovery and JWKS fetches, so
    its counts are dominated by HTTP and TLS machinery. The warm request is the steady state
    number and is the one worth comparing between arms.
    """
    token = mint_token()
    security = build_security()
    request = fake_request(token)
    cold = profile_once(security, request)
    # A fresh Request each time: both libraries read the header off the request object and
    # reusing a consumed one would measure a different code path.
    warm = profile_once(security, fake_request(token))
    warm2 = profile_once(security, fake_request(token))
    emit({"lib": ARMASEC_LIB, "cold": cold, "warm": warm, "warm_repeat": warm2})


def collect_functions(roots: list[str]) -> tuple[dict[str, set[str]], int, int]:
    """
    Build a name-level call graph over every function defined under the given roots.

    Resolution is by bare function name, not by import. That is coarse: two functions with
    the same name in different modules collapse into one node. It is also the only thing
    available without importing the code, and the question being asked (how many frames
    from the dependency to signature verification) is about shape rather than identity.

    Args:
        roots: Directories to walk.

    Returns:
        The call graph as name to called names, the number of functions defined, and the
        number of call sites whose target is a function defined under the roots.
    """
    sources: list[tuple[str, ast.Module]] = []
    for root in roots:
        for directory, _, files in os.walk(root):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(directory, name)
                try:
                    with open(path, encoding="utf-8") as handle:
                        sources.append((path, ast.parse(handle.read())))
                except (SyntaxError, UnicodeDecodeError, OSError):
                    continue

    defined: set[str] = set()
    for _, tree in sources:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(node.name)

    graph: dict[str, set[str]] = collections.defaultdict(set)
    internal_sites = 0
    for _, tree in sources:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                target = inner.func
                name = (
                    target.attr
                    if isinstance(target, ast.Attribute)
                    else target.id
                    if isinstance(target, ast.Name)
                    else None
                )
                if name and name in defined:
                    graph[node.name].add(name)
                    internal_sites += 1
    return graph, len(defined), internal_sites


def static() -> None:
    """
    Report the static shape of the request path for this arm.

    The shortest path from `__call__` to a signature-verification function is reported in
    frames, counting both endpoints, so a direct call reads as 2.
    """
    if ARMASEC_LIB == "lite":
        import armasec_lite

        roots = [os.path.dirname(armasec_lite.__file__)]
    else:
        import armasec
        import jose

        roots = [os.path.dirname(armasec.__file__), os.path.dirname(jose.__file__)]

    graph, defined, sites = collect_functions(roots)

    queue: list[tuple[str, int]] = [("__call__", 1)]
    seen = {"__call__"}
    shortest: int | None = None
    while queue:
        name, depth = queue.pop(0)
        if name in VERIFY_NAMES and depth > 1:
            shortest = depth
            break
        for target in sorted(graph.get(name, ())):
            if target not in seen:
                seen.add(target)
                queue.append((target, depth + 1))
    emit(
        {
            "lib": ARMASEC_LIB,
            "roots": roots,
            "functions_defined": defined,
            "internal_call_sites": sites,
            "reachable_from_call": len(seen),
            "frames_call_to_verify": shortest,
        }
    )


COMMANDS = {
    "import-cost": import_cost,
    "distributions": distributions,
    "callcounts": callcounts,
    "static": static,
}


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        print(f"usage: probe.py [{'|'.join(COMMANDS)}]", file=sys.stderr)
        raise SystemExit(2)
    COMMANDS[sys.argv[1]]()
