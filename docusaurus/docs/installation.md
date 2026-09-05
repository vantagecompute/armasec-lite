---
title: Installation
sidebar_position: 1
---

## Requirements

Python 3.12 or newer.

## Install

```bash
uv add armasec-lite
```

This installs the three direct runtime dependencies: `fastapi`, `cryptography` and
`pydantic`. There is no `python-jose`, `httpx`, `respx`, `pytest`, `py-buzz`, `snick`,
`auto-name-enum` or `pluggy`.

## The `test` extra

```bash
uv add "armasec-lite[test]" --group dev
```

The `test` extra adds `pytest` and registers `armasec_lite.pytest_extension` as a
`pytest11` plugin, which ships a set of pytest fixtures for exercising code that depends on
`armasec-lite` without a real OIDC provider: `rs256_domain`, `rs256_domain_config`,
`rs256_iss`, `rs256_kid`, `rs256_sub`, `rs256_private_key`, `rs256_public_key`, `rs256_jwk`,
`rs256_jwks_uri`, `rs256_openid_config`, `build_rs256_token`, `mock_openid_server`, and
`build_mock_openid_server`.

`mock_openid_server` monkeypatches `armasec_lite.http.get_json` against a URL-to-payload
routing table, so tests written against it need no sockets, no real server, and no
`respx`. It also calls `armasec_lite.openid_config_loader.clear_cache()` on entry and exit,
which matters because the loader cache is process-wide; see
[Architecture → Caching](./architecture/caching.md).

`pytest` itself is not a runtime dependency of `armasec-lite`. It lives only in this extra,
so installing `armasec-lite` for production use never pulls in a test framework.
