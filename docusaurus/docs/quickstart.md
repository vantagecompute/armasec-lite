---
title: Quickstart
sidebar_position: 2
---

`armasec-lite` keeps upstream armasec's public API: `Armasec`, `TokenSecurity`, and
`DomainConfig` carry the same fields and the same signatures. Porting an existing
application is mechanical; see the [migration guide](./migration.md) for the handful of
places behavior differs.

## Basic: one domain, one scope

`Armasec` accepts `domain` and `audience` directly for the single-domain case; they are
forwarded into one `DomainConfig` internally, so there is no need to construct one by hand:

```python
import os

from armasec_lite import Armasec
from fastapi import Depends, FastAPI

app = FastAPI()
armasec = Armasec(
    domain=os.environ.get("ARMASEC_DOMAIN"),
    audience=os.environ.get("ARMASEC_AUDIENCE"),
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return dict(message="Successfully authenticated!")
```

`armasec.lockdown("read:stuff")` returns a FastAPI dependency. On each request it extracts
the bearer token from the `Authorization` header, verifies it against the domain's OIDC
provider, and confirms the token carries the `read:stuff` scope. A missing or invalid token
produces a `401`; a valid token missing the scope produces a `403`. See
[Architecture → Request lifecycle](./architecture/request-lifecycle.md) for the full status
code table.

When the handler needs the verified token's claims rather than just the access check,
`Depends(armasec.lockdown(...))` also works as an ordinary parameter dependency and injects
the `TokenPayload`:

```python
@app.get("/stuff")
async def get_stuff(token_payload=Depends(armasec.lockdown("read:stuff"))):
    return {"sub": token_payload.sub}
```

Constructing `Armasec()` with neither `domain` nor `domain_configs` supplied is a
configuration error: it raises a `422` `HTTPException` rather than accepting requests it
can never actually verify.

## Two domains

An application that accepts tokens from more than one issuer, such as a staging and a
production tenant, lists more than one `DomainConfig`:

```python
from armasec_lite.schemas import DomainConfig

armasec = Armasec(
    domain_configs=[
        DomainConfig(
            domain="my-tenant.auth0.com",
            audience="https://my-api.example.com",
            algorithm="RS256",
        ),
        DomainConfig(
            domain="my-tenant-staging.auth0.com",
            audience="https://my-api.example.com",
            algorithm="RS256",
        ),
    ],
)
```

`TokenSecurity` tries each configured domain in turn until one of them successfully
verifies the token. Each domain gets its own entry in the process-wide OIDC loader cache,
keyed by `(domain, use_https)`, so two domains cost at most two cold OIDC fetches no matter
how many distinct `lockdown()` scope sets are declared against them; see
[Architecture → Caching](./architecture/caching.md).

## Match keys

`match_keys` restricts a route to tokens whose claims match specific values, in addition to
the scope check. It is read with `getattr(token_payload, key)`, so it can match any known
`TokenPayload` field or any claim carried in `extra`:

```python
from armasec_lite.schemas import DomainConfig

armasec = Armasec(
    domain_configs=[
        DomainConfig(
            domain="my-tenant.auth0.com",
            audience="https://my-api.example.com",
            algorithm="RS256",
            match_keys={"client_id": "my-trusted-client"},
        ),
    ],
)


@app.get("/stuff")
async def get_stuff(token_payload=Depends(armasec.lockdown("read:stuff"))):
    return {"sub": token_payload.sub}
```

A token that carries `read:stuff` but a different `client_id` still fails with a `403`,
the same status a missing scope produces.
