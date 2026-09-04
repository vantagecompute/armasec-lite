---
id: index
title: Architecture
sidebar_position: 0
---

`armasec_lite` is one package, flat except for a small `pluggable/` subpackage:

| Module | Purpose |
| --- | --- |
| `__init__.py` | public exports |
| `armasec.py` | `Armasec` factory: `lockdown` / `lockdown_all` / `lockdown_some` |
| `token_security.py` | `TokenSecurity`, the FastAPI injectable |
| `token_manager.py` | header unpacking to `TokenPayload` |
| `token_decoder.py` | JWKs + token to verified `TokenPayload` |
| `token_payload.py` | `TokenPayload` |
| `openid_config_loader.py` | `OpenidConfigLoader` and the process-wide cache |
| `schemas.py` | `JWK`, `JWKs`, `OpenidConfig`, `DomainConfig`, `PermissionMode` |
| `exceptions.py` | `ArmasecError` family, `require_condition`, `handle_errors` |
| `utilities.py` | `noop`, `log_error`, `unwrap` |
| `jwt.py` | JWS/JWT encode and decode |
| `http.py` | `get_json` |
| `pluggable/__init__.py` | `PluginManager`, `hookimpl`, `plugin_manager` singleton |
| `pluggable/hookspecs.py` | `armasec_plugin_check` signature and docs |
| `pytest_extension.py` | pytest fixtures, shipped under the `[test]` extra |

## Request flow

Unchanged from upstream:

```mermaid
graph TD
    A["FastAPI route<br/>Depends(armasec.lockdown(&quot;read:stuff&quot;))"] --> B["TokenSecurity.__call__(request)"]
    B --> C["1. lazy-load managers<br/>(cached, executor-offloaded on cold path)"]
    C --> D["2. TokenManager.extract_token_payload(request.headers)"]
    D --> D1["unpack bearer token from Authorization header"]
    D1 --> D2["TokenDecoder.decode(token) -> TokenPayload"]
    D2 --> E["3. match_keys check"]
    E -->|"mismatch"| E1["AuthorizationError (403)"]
    E --> F["4. scope check per PermissionMode"]
    F -->|"missing scope"| F1["AuthorizationError (403)"]
    F --> G["5. plugin hooks"]
    G -->|"raised"| G1["plugin-defined error"]
    G --> H["returns TokenPayload"]
```

See [Request lifecycle](./request-lifecycle.md) for the status code produced by each
failure, [Caching](./caching.md) for what "cached" means at step 1, and
[Threading model](./threading-model.md) for why the cold path is the only one that touches
an executor.
