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
"""

from __future__ import annotations

import os
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
