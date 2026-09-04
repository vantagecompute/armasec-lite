# armasec-lite Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `armasec-lite`, a dependency-minimal reimplementation of armasec 3.0.3 that provides injectable FastAPI OIDC authentication with two runtime dependencies instead of ten.

**Architecture:** A stdlib-first port of upstream armasec. `python-jose` is replaced by a hand-written `jwt.py` that parses and validates with the standard library and delegates only the signature primitive to `cryptography`. `httpx` becomes `urllib.request`, `pydantic` becomes `dataclasses`, `py-buzz`/`snick`/`auto-name-enum` become small local equivalents, and `pluggy` becomes `importlib.metadata` entry points. Three behavioral improvements ride along behind an unchanged API: a process-wide OIDC loader cache, rate-limited JWKS refetch on key rotation, and an executor hop so the cold load stops blocking the event loop.

**Tech Stack:** Python 3.12+, FastAPI, cryptography, pytest, uv, ruff, mypy.

**Spec:** `docs/superpowers/specs/2026-09-04-armasec-lite-design.md`

## Global Constraints

- `requires-python = ">=3.12"`.
- Runtime dependencies are exactly `fastapi>=0.141.1,<1` and `cryptography>=50.0.1,<51`. Adding a third runtime dependency is a plan violation.
- `pytest>=9.1.1,<10` lives in the `test` extra, never in `dependencies`.
- Dev-only: `pytest`, `pytest-asyncio`, `pyjwt>=2.13.0,<3`, `httpx`, `mypy`, `ruff`.
- Import package is `armasec_lite`; distribution is `armasec-lite`.
- Never import `jose`, `buzz`, `snick`, `auto_name_enum`, `pluggy`, `respx`, or `pydantic` from `armasec_lite/`.
- Never use the em-dash (U+2014) or en-dash (U+2013) character in any file. Use commas, colons, parentheses, or separate sentences.
- `ruff` line length is 100.
- `testpaths = ["tests/unit"]` so a bare `pytest` never reaches Docker.
- Public API names and signatures match upstream armasec 3.0.3 exactly, except for the three documented differences: import name, `DomainConfig.verify_issuer` defaulting to `True`, and `TokenDecoder`'s new optional `jwks_refresher` keyword argument.
- Every public callable carries a docstring in upstream's style. The docs site generates its API reference from them.
- TDD throughout: the failing test is written and observed failing before the implementation.

## File Structure

| File | Responsibility |
| --- | --- |
| `pyproject.toml` | Packaging, dependency pins, pytest/ruff/mypy config |
| `justfile` | `test`, `lint`, `bench`, `compare-legacy`, `charts`, `docs` recipes |
| `armasec_lite/__init__.py` | Public exports |
| `armasec_lite/exceptions.py` | `ArmasecError` family, `require_condition`, `handle_errors`, `DoExceptParams` |
| `armasec_lite/utilities.py` | `noop`, `log_error`, `unwrap` |
| `armasec_lite/schemas.py` | `JWK`, `JWKs`, `OpenidConfig`, `DomainConfig`, `PermissionMode` |
| `armasec_lite/jwt.py` | JWS/JWT encode and decode; the only security-critical module |
| `armasec_lite/http.py` | `get_json`, hardened `urllib.request` wrapper |
| `armasec_lite/token_payload.py` | `TokenPayload` with extra-claim attribute access |
| `armasec_lite/openid_config_loader.py` | `OpenidConfigLoader`, process-wide cache, locking, JWKS refetch |
| `armasec_lite/token_decoder.py` | JWKs plus token to verified `TokenPayload` |
| `armasec_lite/token_manager.py` | Bearer header unpacking |
| `armasec_lite/token_security.py` | `TokenSecurity`, the FastAPI injectable |
| `armasec_lite/armasec.py` | `Armasec` factory |
| `armasec_lite/pluggable/__init__.py` | `PluginManager`, `hookimpl`, `plugin_manager` |
| `armasec_lite/pluggable/hookspecs.py` | `armasec_plugin_check` signature and docs |
| `armasec_lite/pytest_extension.py` | pytest fixtures, `[test]` extra |
| `tests/unit/` | Ported upstream suite, attack suite, cross-validation |

---

### Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `justfile`
- Create: `armasec_lite/__init__.py`
- Create: `tests/unit/__init__.py`
- Create: `tests/unit/test_packaging.py`
- Create: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: an installable package importable as `armasec_lite`, exposing `__version__: str`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_packaging.py`:

```python
"""Guard rails on the packaging contract that the rest of the project depends on."""

import importlib.metadata

import armasec_lite


BANNED_RUNTIME_IMPORTS = {
    "jose",
    "buzz",
    "snick",
    "auto_name_enum",
    "pluggy",
    "respx",
    "pydantic",
    "httpx",
}


def test_version_is_exposed():
    assert armasec_lite.__version__ == importlib.metadata.version("armasec-lite")


def test_runtime_dependencies_are_exactly_two():
    requires = importlib.metadata.requires("armasec-lite") or []
    runtime = [r for r in requires if "extra ==" not in r]
    names = sorted(r.split(" ")[0].split(">")[0].split("<")[0].split("=")[0] for r in runtime)
    assert names == ["cryptography", "fastapi"]


def test_no_banned_dependency_is_imported_at_runtime(monkeypatch):
    import sys

    for banned in BANNED_RUNTIME_IMPORTS:
        assert banned not in sys.modules or banned == "httpx", (
            f"{banned} was imported by armasec_lite"
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_packaging.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite'`

- [ ] **Step 3: Write `pyproject.toml`**

```toml
[project]
name = "armasec-lite"
version = "0.1.0"
description = "Injectable FastAPI auth via OIDC, with two dependencies"
authors = [{name = "Vantage Compute", email = "info@vantagecompute.ai"}]
license = {text = "MIT"}
readme = "README.md"
requires-python = ">=3.12"
keywords = ["fastapi", "auth", "oidc", "oauth2", "security", "jwt"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Framework :: FastAPI",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: Security",
]
dependencies = [
    "fastapi>=0.141.1,<1",
    "cryptography>=50.0.1,<51",
]

[project.urls]
Homepage = "https://github.com/vantagecompute/armasec-lite"
Repository = "https://github.com/vantagecompute/armasec-lite"

[project.optional-dependencies]
test = ["pytest>=9.1.1,<10"]

[project.entry-points."pytest11"]
pytest_armasec_lite = "armasec_lite.pytest_extension"

[dependency-groups]
dev = [
    "pytest>=9.1.1,<10",
    "pytest-asyncio>=1.2.0",
    "pyjwt>=2.13.0,<3",
    "httpx>=0.28.1,<1",
    "mypy>=1.18.1,<2",
    "ruff>=0.13.0,<1",
]
bench = [
    "plotly>=6,<7",
    "armasec==3.0.3",
]

[tool.pytest.ini_options]
minversion = "9.0"
testpaths = ["tests/unit"]
asyncio_mode = "auto"
markers = [
    "integration: requires the docker compose comparison stack to be running",
]

[tool.ruff]
line-length = 100

[tool.mypy]
python_version = "3.12"
strict = true

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["armasec_lite"]
```

- [ ] **Step 4: Write `armasec_lite/__init__.py`**

Task 18 replaces this file with the full export list. Until then it only needs to exist
and carry a version, so that the packaging test can import it:

```python
"""Injectable FastAPI auth via OIDC, built on the standard library."""

import importlib.metadata

__version__ = importlib.metadata.version("armasec-lite")

__all__ = ["__version__"]
```

- [ ] **Step 5: Write `.gitignore`**

```gitignore
__pycache__/
*.py[cod]
.venv/
.pytest_cache/
.ruff_cache/
.mypy_cache/
dist/
build/
*.egg-info/
.coverage
coverage.xml
junit.xml
```

- [ ] **Step 6: Write `justfile`**

```just
# armasec-lite task runner

default:
    @just --list

# Run the unit suite. Never touches Docker.
test *ARGS:
    uv run pytest tests/unit {{ARGS}}

# Run the unit suite with coverage, emitting the XML the docs site reads.
test-cov:
    uv run pytest tests/unit --cov=armasec_lite --cov-report=xml --junitxml=junit.xml

# Lint and type-check.
lint:
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy armasec_lite

# Auto-fix what ruff can fix.
fmt:
    uv run ruff check --fix .
    uv run ruff format .
```

- [ ] **Step 7: Create empty `tests/unit/__init__.py`**

```python
```

- [ ] **Step 8: Sync and run the test**

Run: `uv sync --all-groups && uv run pytest tests/unit/test_packaging.py -v`
Expected: PASS, 3 tests

- [ ] **Step 9: Verify lint passes**

Run: `just lint`
Expected: no errors

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml justfile .gitignore armasec_lite/ tests/
git commit -m "feat: scaffold armasec-lite package

Two runtime dependencies, enforced by a packaging test."
```

---

### Task 2: Exceptions and utilities

**Files:**
- Create: `armasec_lite/exceptions.py`
- Create: `armasec_lite/utilities.py`
- Create: `tests/unit/test_exceptions.py`
- Create: `tests/unit/test_utilities.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `ArmasecError(Exception)` with class attributes `status_code: int = 400`, `detail: str = "Bad request"`, classmethods `require_condition(expr: object, message: str) -> None` and `handle_errors(message: str, do_except: Callable[[DoExceptParams], None] | None = None)` (a context manager).
  - `AuthenticationError` (401), `AuthorizationError` (403), `PayloadMappingError` (500).
  - `DoExceptParams` dataclass with `final_message: str`, `err: Exception`, `trace: TracebackType | None`.
  - `noop(*args, **kwargs) -> None`, `log_error(logger, dep: DoExceptParams) -> None`, `unwrap(text: str) -> str`.

- [ ] **Step 1: Write the failing test for exceptions**

Create `tests/unit/test_exceptions.py`:

```python
import pytest

from armasec_lite.exceptions import (
    ArmasecError,
    AuthenticationError,
    AuthorizationError,
    DoExceptParams,
    PayloadMappingError,
)


def test_status_codes():
    assert ArmasecError.status_code == 400
    assert AuthenticationError.status_code == 401
    assert AuthorizationError.status_code == 403
    assert PayloadMappingError.status_code == 500


def test_require_condition_passes_on_truthy():
    AuthenticationError.require_condition(True, "should not raise")
    AuthenticationError.require_condition([1], "should not raise")


def test_require_condition_raises_on_falsey():
    with pytest.raises(AuthenticationError, match="nope"):
        AuthenticationError.require_condition(False, "nope")


def test_handle_errors_wraps_exception():
    with pytest.raises(AuthenticationError) as info:
        with AuthenticationError.handle_errors("outer message"):
            raise ValueError("inner message")
    assert "outer message" in str(info.value)
    assert "inner message" in str(info.value)


def test_handle_errors_does_not_wrap_on_success():
    with AuthenticationError.handle_errors("outer message"):
        pass


def test_handle_errors_invokes_do_except_with_params():
    captured: list[DoExceptParams] = []

    with pytest.raises(AuthenticationError):
        with AuthenticationError.handle_errors("boom", do_except=captured.append):
            raise ValueError("inner")

    assert len(captured) == 1
    assert captured[0].final_message.startswith("boom")
    assert isinstance(captured[0].err, ValueError)
    assert captured[0].trace is not None


def test_handle_errors_does_not_double_wrap_armasec_errors():
    with pytest.raises(AuthorizationError, match="already typed"):
        with AuthenticationError.handle_errors("outer"):
            raise AuthorizationError("already typed")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_exceptions.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.exceptions'`

- [ ] **Step 3: Write `armasec_lite/exceptions.py`**

```python
"""
Exception types and the small assertion helpers armasec uses in place of py-buzz.

Only two py-buzz APIs are reimplemented here, because only two are used:
`require_condition` and `handle_errors`.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from dataclasses import dataclass
from types import TracebackType
from typing import Callable, Iterator


@dataclass
class DoExceptParams:
    """
    The values handed to a `do_except` callback by `handle_errors`.

    Attributes:
        final_message: The composed message, including the original error text.
        err:           The original exception.
        trace:         The original traceback, suitable for `traceback.format_tb`.
    """

    final_message: str
    err: Exception
    trace: TracebackType | None


class ArmasecError(Exception):
    """
    Base error for armasec, used for checking conditions and wrapping other exceptions.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 400.
        detail:      The client-facing detail message. Set to "Bad request".
    """

    status_code: int = 400
    detail: str = "Bad request"

    @classmethod
    def require_condition(cls, expr: object, message: str) -> None:
        """
        Raise this error type with the supplied message when `expr` is falsey.

        Args:
            expr:    The expression to check for truthiness.
            message: The message to raise when the check fails.
        """
        if not expr:
            raise cls(message)

    @classmethod
    @contextmanager
    def handle_errors(
        cls,
        message: str,
        do_except: Callable[[DoExceptParams], None] | None = None,
    ) -> Iterator[None]:
        """
        Wrap any exception raised in the managed block into this error type.

        Errors that are already an `ArmasecError` pass through untouched, so a specific
        error type raised deep in a call stack is not flattened into a less specific one
        by an enclosing handler.

        Args:
            message:   The message to prefix onto the original error text.
            do_except: Optional callback invoked with a `DoExceptParams` before raising.
        """
        try:
            yield
        except ArmasecError:
            raise
        except Exception as err:
            final_message = f"{message} -- {type(err).__name__}: {err}"
            if do_except is not None:
                do_except(
                    DoExceptParams(
                        final_message=final_message,
                        err=err,
                        trace=sys.exc_info()[2],
                    )
                )
            raise cls(final_message) from err


class AuthenticationError(ArmasecError):
    """
    Indicates a failure to authenticate and decode a jwt.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 401.
    """

    status_code: int = 401
    detail: str = "Not authenticated"


class AuthorizationError(ArmasecError):
    """
    Indicates that the provided claims don't match the claims required for an endpoint.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 403.
    """

    status_code: int = 403
    detail: str = "Not authorized"


class PayloadMappingError(ArmasecError):
    """
    Indicates that the configured permission extractor did not match a path in the token.

    Attributes:
        status_code: The HTTP status code indicated by the error. Set to 500.
    """

    status_code: int = 500
    detail: str = "Server error"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_exceptions.py -v`
Expected: PASS, 7 tests

- [ ] **Step 5: Write the failing test for utilities**

Create `tests/unit/test_utilities.py`:

```python
from armasec_lite.exceptions import DoExceptParams
from armasec_lite.utilities import log_error, noop, unwrap


def test_noop_accepts_anything_and_returns_none():
    assert noop() is None
    assert noop(1, 2, three=3) is None


def test_unwrap_joins_wrapped_lines_into_one():
    text = """
        this text is spread
        across several lines
    """
    assert unwrap(text) == "this text is spread across several lines"


def test_log_error_is_silent_when_logger_is_noop():
    log_error(noop, DoExceptParams("message", ValueError("boom"), None))


def test_log_error_writes_message_error_and_trace():
    lines: list[str] = []
    try:
        raise ValueError("boom")
    except ValueError as err:
        params = DoExceptParams("final message", err, err.__traceback__)

    log_error(lines.append, params)

    assert len(lines) == 1
    assert "final message" in lines[0]
    assert "boom" in lines[0]
    assert "Traceback" in lines[0]
```

- [ ] **Step 6: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_utilities.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.utilities'`

- [ ] **Step 7: Write `armasec_lite/utilities.py`**

```python
"""
Small helpers shared across armasec, replacing the `snick` dependency.
"""

from __future__ import annotations

from traceback import format_tb
from typing import Any, Callable

from armasec_lite.exceptions import DoExceptParams


def noop(*args: Any, **kwargs: Any) -> None:
    """
    Do nothing. Used as the default `debug_logger` so callers need no None checks.
    """


def unwrap(text: str) -> str:
    """
    Collapse a wrapped, indented string literal into a single line.

    Args:
        text: The text to collapse.
    """
    return " ".join(text.split())


def log_error(logger: Callable[..., None], dep: DoExceptParams) -> None:
    """
    Log an error with its message, string representation and traceback.

    Does nothing when the supplied logger is `noop`, so that the default configuration
    performs no formatting work. Pass as a partial when using `handle_errors`::

        with AuthenticationError.handle_errors("Boom!", do_except=partial(log_error, log)):
            do_some_risky_stuff()

    Args:
        logger: A logging callable such as `logger.debug`.
        dep:    The parameters handed over by `handle_errors`.
    """
    if logger is noop:
        return

    trace = "\n".join(format_tb(dep.trace)) if dep.trace is not None else ""
    logger(
        f"{dep.final_message}\n"
        f"\n"
        f"Error:\n"
        f"______\n"
        f"{dep.err}\n"
        f"\n"
        f"Traceback:\n"
        f"----------\n"
        f"{trace}"
    )
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `uv run pytest tests/unit -v`
Expected: PASS, 14 tests

- [ ] **Step 9: Verify lint passes**

Run: `just lint`
Expected: no errors

- [ ] **Step 10: Commit**

```bash
git add armasec_lite/exceptions.py armasec_lite/utilities.py tests/unit/
git commit -m "feat: add exceptions and utilities

Replaces py-buzz and snick with local equivalents. handle_errors does not
re-wrap ArmasecError subclasses, so a specific error raised deep in the
stack is not flattened by an enclosing handler."
```

---

### Task 3: Schemas

**Files:**
- Create: `armasec_lite/schemas.py`
- Create: `tests/unit/test_schemas.py`

**Interfaces:**
- Consumes: `armasec_lite.exceptions.ArmasecError`.
- Produces:
  - `PermissionMode(str, Enum)` with members `ALL` and `SOME`, values `"ALL"` and `"SOME"`.
  - `JWK` dataclass: required `kty: str`, `kid: str`; optional `alg`, `n`, `e`, `crv`, `x`, `y`, `k`, `use`, `x5c`, `x5t`, all defaulting to `None`; `extra: dict[str, Any]`. Classmethod `from_dict(data: dict) -> JWK`.
  - `JWKs` dataclass: `keys: list[JWK]`. Classmethod `from_dict(data: dict) -> JWKs`.
  - `OpenidConfig` dataclass: `issuer: str`, `jwks_uri: str`, `extra: dict`. Classmethod `from_dict(data: dict, *, require_https: bool = True) -> OpenidConfig`.
  - `DomainConfig` dataclass with fields `domain: str = ""`, `audience: str | None = None`, `ignore_audience: bool = False`, `algorithm: str = "RS256"`, `use_https: bool = True`, `verify_issuer: bool = True`, `match_keys: dict[str, Any]`, `permission_extractor: Callable[[dict], list[str]] | None = None`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_schemas.py`:

```python
import pytest

from armasec_lite.exceptions import ArmasecError
from armasec_lite.schemas import JWK, JWKs, DomainConfig, OpenidConfig, PermissionMode


def test_permission_mode_values_match_upstream():
    assert PermissionMode.ALL.value == "ALL"
    assert PermissionMode.SOME.value == "SOME"
    assert PermissionMode("ALL") is PermissionMode.ALL


def test_jwk_from_dict_keeps_unknown_members_in_extra():
    jwk = JWK.from_dict(
        {"kty": "RSA", "kid": "abc", "alg": "RS256", "n": "AAAA", "e": "AQAB", "novel": 1}
    )
    assert jwk.kty == "RSA"
    assert jwk.kid == "abc"
    assert jwk.n == "AAAA"
    assert jwk.extra_dict == {"novel": 1}


def test_jwk_from_dict_requires_kty_and_kid():
    with pytest.raises(ArmasecError, match="kid"):
        JWK.from_dict({"kty": "RSA"})
    with pytest.raises(ArmasecError, match="kty"):
        JWK.from_dict({"kid": "abc"})


def test_jwk_does_not_require_rsa_fields_for_ec_keys():
    jwk = JWK.from_dict({"kty": "EC", "kid": "ec1", "crv": "P-256", "x": "AA", "y": "BB"})
    assert jwk.n is None
    assert jwk.crv == "P-256"


def test_jwks_from_dict_builds_key_list():
    jwks = JWKs.from_dict({"keys": [{"kty": "RSA", "kid": "one"}, {"kty": "RSA", "kid": "two"}]})
    assert [k.kid for k in jwks.keys] == ["one", "two"]


def test_jwks_from_dict_requires_keys_to_be_a_list():
    with pytest.raises(ArmasecError, match="keys"):
        JWKs.from_dict({"keys": "not-a-list"})


def test_openid_config_from_dict_accepts_https_urls():
    config = OpenidConfig.from_dict(
        {"issuer": "https://auth.example.com", "jwks_uri": "https://auth.example.com/jwks"}
    )
    assert config.issuer == "https://auth.example.com"
    assert config.jwks_uri == "https://auth.example.com/jwks"


def test_openid_config_rejects_non_http_scheme():
    with pytest.raises(ArmasecError, match="scheme"):
        OpenidConfig.from_dict(
            {"issuer": "https://auth.example.com", "jwks_uri": "file:///etc/passwd"}
        )


def test_openid_config_rejects_url_without_host():
    with pytest.raises(ArmasecError, match="host"):
        OpenidConfig.from_dict({"issuer": "https://", "jwks_uri": "https://auth.example.com/jwks"})


def test_openid_config_pins_jwks_scheme_to_https_when_required():
    with pytest.raises(ArmasecError, match="https"):
        OpenidConfig.from_dict(
            {"issuer": "https://auth.example.com", "jwks_uri": "http://auth.example.com/jwks"},
            require_https=True,
        )


def test_openid_config_allows_http_jwks_when_https_not_required():
    config = OpenidConfig.from_dict(
        {"issuer": "http://localhost:8080", "jwks_uri": "http://localhost:8080/jwks"},
        require_https=False,
    )
    assert config.jwks_uri == "http://localhost:8080/jwks"


def test_domain_config_defaults_match_the_spec():
    config = DomainConfig(domain="auth.example.com")
    assert config.audience is None
    assert config.ignore_audience is False
    assert config.algorithm == "RS256"
    assert config.use_https is True
    assert config.verify_issuer is True
    assert config.match_keys == {}
    assert config.permission_extractor is None


def test_domain_config_rejects_a_non_string_domain():
    with pytest.raises(ArmasecError, match="domain"):
        DomainConfig(domain=None)  # type: ignore[arg-type]


def test_domain_config_is_hashable_for_use_as_a_cache_key():
    config = DomainConfig(domain="auth.example.com")
    assert isinstance(hash(config), int)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_schemas.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.schemas'`

- [ ] **Step 3: Write `armasec_lite/schemas.py`**

```python
"""
Dataclass models for the data armasec exchanges with an OIDC provider.

These replace the pydantic models upstream uses. Each `from_dict` validates the fields
armasec actually depends on and retains everything else in `extra`, which is the behavior
`model_config = ConfigDict(extra="allow")` gave upstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
from urllib.parse import urlparse

from armasec_lite.exceptions import ArmasecError

#: Members of a JWK that armasec understands. Anything else lands in `JWK.extra`.
_JWK_KNOWN = ("alg", "kty", "kid", "n", "e", "crv", "x", "y", "k", "use", "x5c", "x5t")


class PermissionMode(str, Enum):
    """
    How a route's scopes are matched against a token's permissions.

    Attributes:
        ALL:  Require every listed permission.
        SOME: Require at least one of the listed permissions.
    """

    ALL = "ALL"
    SOME = "SOME"


def _require_str(data: dict[str, Any], key: str, context: str) -> str:
    """
    Pull a required string out of a mapping or raise with a message naming the field.
    """
    value = data.get(key)
    ArmasecError.require_condition(
        isinstance(value, str) and value != "",
        f"{context} is missing a valid '{key}'",
    )
    return str(value)


def _validate_url(url: str, label: str, *, require_https: bool) -> str:
    """
    Check that a URL is an absolute http or https URL with a host.

    Replaces pydantic's `AnyHttpUrl`. `jwks_uri` arrives inside a document fetched from
    the network and is then fetched in turn, so its scheme is pinned rather than merely
    checked for plausibility.
    """
    parsed = urlparse(url)
    ArmasecError.require_condition(
        parsed.scheme in ("http", "https"),
        f"{label} has an unsupported scheme {parsed.scheme!r}: expected http or https",
    )
    ArmasecError.require_condition(
        bool(parsed.netloc),
        f"{label} has no host: {url!r}",
    )
    if require_https:
        ArmasecError.require_condition(
            parsed.scheme == "https",
            f"{label} must use https: {url!r}",
        )
    return url


@dataclass(frozen=True)
class JWK:
    """
    One JSON Web Key from an OIDC provider's JWKS document.

    Only `kty` and `kid` are required. The members a particular key type needs, such as
    `n` and `e` for RSA or `crv`, `x` and `y` for EC, are validated at use time by
    `armasec_lite.jwt`, since which ones are required depends on the algorithm.

    Attributes:
        alg: The algorithm the key is intended for.
        kty: The key type: RSA, EC, OKP or oct.
        kid: The key id, matched against a token's `kid` header.
        n:   RSA modulus, base64url encoded.
        e:   RSA exponent, base64url encoded.
        crv: EC or OKP curve name.
        x:   EC x coordinate or OKP public key, base64url encoded.
        y:   EC y coordinate, base64url encoded.
        k:   Symmetric key material, base64url encoded.
        use: The intended use of the key.
        x5c: The X.509 certificate chain.
        x5t: The X.509 certificate SHA-1 thumbprint.
        extra: Members not listed above, retained verbatim.
    """

    kty: str
    kid: str
    alg: str | None = None
    n: str | None = None
    e: str | None = None
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    k: str | None = None
    use: str | None = None
    x5c: tuple[str, ...] | None = None
    x5t: str | None = None
    extra: tuple[tuple[str, Any], ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JWK:
        """
        Build a JWK from a decoded JWKS entry, retaining unknown members.

        Args:
            data: One entry from a provider's `keys` array.
        """
        ArmasecError.require_condition(isinstance(data, dict), "jwk entry is not an object")
        kty = _require_str(data, "kty", "jwk")
        kid = _require_str(data, "kid", "jwk")
        x5c = data.get("x5c")
        return cls(
            kty=kty,
            kid=kid,
            alg=data.get("alg"),
            n=data.get("n"),
            e=data.get("e"),
            crv=data.get("crv"),
            x=data.get("x"),
            y=data.get("y"),
            k=data.get("k"),
            use=data.get("use"),
            x5c=tuple(x5c) if isinstance(x5c, list) else None,
            x5t=data.get("x5t"),
            extra=tuple((k, v) for k, v in data.items() if k not in _JWK_KNOWN),
        )
```

`extra` is a tuple of pairs rather than a dict so that `JWK` can stay `frozen=True` and
therefore hashable, which matters because `JWKs` is cached and compared. Callers that want
a mapping use the `extra_dict` property. Add it as the last member of the `JWK` class,
inside the class body:

```python
    @property
    def extra_dict(self) -> dict[str, Any]:
        """
        Unknown JWK members as a mapping.
        """
        return dict(self.extra)
```

Continue the module at top level:

```python
@dataclass(frozen=True)
class JWKs:
    """
    The container object retrieved from an OIDC provider's JWKS endpoint.

    Attributes:
        keys: The JWKs contained within.
    """

    keys: tuple[JWK, ...]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JWKs:
        """
        Build a JWKs from a decoded JWKS document.

        Args:
            data: The decoded document, expected to carry a `keys` array.
        """
        ArmasecError.require_condition(isinstance(data, dict), "jwks document is not an object")
        raw = data.get("keys")
        ArmasecError.require_condition(
            isinstance(raw, list),
            "jwks document 'keys' is missing or is not a list",
        )
        assert isinstance(raw, list)
        return cls(keys=tuple(JWK.from_dict(entry) for entry in raw))


@dataclass(frozen=True)
class OpenidConfig:
    """
    The subset of an openid-configuration document that armasec uses.

    Attributes:
        issuer:   The URL of the issuer of the tokens.
        jwks_uri: The URI where JWKs can be found on the OpenID server.
        extra:    Members not listed above, retained verbatim.
    """

    issuer: str
    jwks_uri: str
    extra: tuple[tuple[str, Any], ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, require_https: bool = True) -> OpenidConfig:
        """
        Build an OpenidConfig from a decoded discovery document.

        Args:
            data:          The decoded openid-configuration document.
            require_https: Pin both URLs to https. False only when the domain is
                           configured with `use_https=False`, which is a local
                           development affordance.
        """
        ArmasecError.require_condition(isinstance(data, dict), "openid config is not an object")
        issuer = _validate_url(
            _require_str(data, "issuer", "openid config"),
            "openid config 'issuer'",
            require_https=require_https,
        )
        jwks_uri = _validate_url(
            _require_str(data, "jwks_uri", "openid config"),
            "openid config 'jwks_uri'",
            require_https=require_https,
        )
        known = ("issuer", "jwks_uri")
        return cls(
            issuer=issuer,
            jwks_uri=jwks_uri,
            extra=tuple((k, v) for k, v in data.items() if k not in known),
        )


@dataclass(frozen=True)
class DomainConfig:
    """
    Configuration for one OIDC domain to authenticate tokens against.

    Attributes:
        domain:               The OIDC domain from which resources are loaded.
        audience:             Optional designation of the token audience.
        ignore_audience:      If true and audience is None, skip audience verification.
        algorithm:            The algorithm to use for decoding. Defaults to RS256.
        use_https:            If falsey, use http instead of https for provider URLs.
        verify_issuer:        Check the token's `iss` claim against the provider's
                              configured issuer. Defaults to True. Upstream armasec loads
                              the issuer and never checks it; set this False for exact
                              upstream behavior.
        match_keys:           Key/value pairs that must be present in a decoded token.
                              A mismatch raises 403.
        permission_extractor: Optional function that extracts permissions from the decoded
                              token when they are not a top level claim.
    """

    domain: str = ""
    audience: str | None = None
    ignore_audience: bool = False
    algorithm: str = "RS256"
    use_https: bool = True
    verify_issuer: bool = True
    match_keys: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    permission_extractor: Callable[[dict[str, Any]], list[str]] | None = field(
        default=None, hash=False, compare=False
    )

    def __post_init__(self) -> None:
        """Validate field types that a caller could plausibly get wrong."""
        ArmasecError.require_condition(
            isinstance(self.domain, str),
            "DomainConfig 'domain' must be a string",
        )
        ArmasecError.require_condition(
            isinstance(self.algorithm, str) and self.algorithm != "",
            "DomainConfig 'algorithm' must be a non-empty string",
        )
        ArmasecError.require_condition(
            isinstance(self.match_keys, dict),
            "DomainConfig 'match_keys' must be a dict",
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_schemas.py -v`
Expected: PASS, 14 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/schemas.py tests/unit/test_schemas.py
git commit -m "feat: add dataclass schemas

Replaces pydantic. JWK requires only kty and kid, because which members a
key needs depends on its algorithm, which jwt.py validates at use time.
OpenidConfig pins jwks_uri's scheme, since it arrives in a fetched document
and is then fetched in turn."
```

---

### Task 4: JWT segment parsing and base64url

**Files:**
- Create: `armasec_lite/jwt.py`
- Create: `tests/unit/test_jwt_parsing.py`

**Interfaces:**
- Consumes: `armasec_lite.exceptions.AuthenticationError`.
- Produces:
  - `InvalidTokenError`, `InvalidSignatureError`, `InvalidAlgorithmError`, `ExpiredSignatureError`, `ImmatureSignatureError`, `InvalidAudienceError`, `InvalidIssuerError`, all subclassing `AuthenticationError`.
  - `b64url_decode(segment: str) -> bytes`
  - `b64url_encode(raw: bytes) -> str`
  - `split_token(token: str) -> tuple[str, str, str]`
  - `get_unverified_header(token: str) -> dict[str, Any]`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_jwt_parsing.py`:

```python
import base64
import json

import pytest

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.jwt import (
    InvalidTokenError,
    b64url_decode,
    b64url_encode,
    get_unverified_header,
    split_token,
)


def _seg(payload: dict) -> str:
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_b64url_round_trip():
    for raw in (b"", b"a", b"ab", b"abc", b"abcd", bytes(range(256))):
        assert b64url_decode(b64url_encode(raw)) == raw


def test_b64url_encode_strips_padding():
    assert "=" not in b64url_encode(b"a")


def test_b64url_decode_accepts_unpadded_input():
    assert b64url_decode("YQ") == b"a"


def test_b64url_decode_rejects_impossible_length():
    # A length of 4n+1 cannot be valid base64.
    with pytest.raises(InvalidTokenError, match="length"):
        b64url_decode("YQZZZ")


def test_b64url_decode_rejects_standard_base64_alphabet():
    # '+' and '/' belong to standard base64, not base64url.
    with pytest.raises(InvalidTokenError, match="character"):
        b64url_decode("ab+d")
    with pytest.raises(InvalidTokenError, match="character"):
        b64url_decode("ab/d")


def test_b64url_decode_rejects_embedded_padding():
    with pytest.raises(InvalidTokenError, match="character"):
        b64url_decode("YQ==")


def test_split_token_returns_three_segments():
    assert split_token("aaa.bbb.ccc") == ("aaa", "bbb", "ccc")


@pytest.mark.parametrize("bad", ["", "aaa", "aaa.bbb", "aaa.bbb.ccc.ddd", "..", "aaa..ccc"])
def test_split_token_rejects_malformed_tokens(bad):
    with pytest.raises(InvalidTokenError):
        split_token(bad)


def test_get_unverified_header_reads_the_header_segment():
    token = f"{_seg({'alg': 'RS256', 'kid': 'abc'})}.{_seg({'sub': 'x'})}.signature"
    assert get_unverified_header(token) == {"alg": "RS256", "kid": "abc"}


def test_get_unverified_header_rejects_non_object_header():
    token = f"{b64url_encode(b'[1,2,3]')}.{_seg({'sub': 'x'})}.sig"
    with pytest.raises(InvalidTokenError, match="object"):
        get_unverified_header(token)


def test_get_unverified_header_rejects_invalid_json():
    token = f"{b64url_encode(b'not json')}.{_seg({'sub': 'x'})}.sig"
    with pytest.raises(InvalidTokenError):
        get_unverified_header(token)


def test_jwt_errors_are_authentication_errors():
    assert issubclass(InvalidTokenError, AuthenticationError)
    assert InvalidTokenError.status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_jwt_parsing.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.jwt'`

- [ ] **Step 3: Write the first section of `armasec_lite/jwt.py`**

```python
"""
A minimal JWS/JWT implementation, replacing python-jose.

Everything except the signature primitive itself is standard library. `cryptography`
provides only the verify and sign operations, because that is the part with a long CVE
history and no business being hand written.

The verification order in `decode` is a security property, not an implementation detail.
Read the comments there before changing anything.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from armasec_lite.exceptions import AuthenticationError


class InvalidTokenError(AuthenticationError):
    """The token is not a well formed JWS."""


class InvalidSignatureError(AuthenticationError):
    """The token's signature did not verify against the key."""


class InvalidAlgorithmError(AuthenticationError):
    """The token's algorithm is not permitted, or does not match the key type."""


class InvalidKeyError(AuthenticationError):
    """The JWK is missing members required by its key type."""


class ExpiredSignatureError(AuthenticationError):
    """The token's `exp` claim is in the past."""


class ImmatureSignatureError(AuthenticationError):
    """The token's `nbf` claim is in the future."""


class InvalidAudienceError(AuthenticationError):
    """The token's `aud` claim does not contain the required audience."""


class InvalidIssuerError(AuthenticationError):
    """The token's `iss` claim does not match the required issuer."""


#: base64url alphabet, without padding. Anything else in a segment is a malformed token.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_encode(raw: bytes) -> str:
    """
    Encode bytes as unpadded base64url, the encoding JWS uses for every segment.

    Args:
        raw: The bytes to encode.
    """
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(segment: str) -> bytes:
    """
    Decode an unpadded base64url segment.

    Rejects the standard base64 alphabet and embedded padding rather than silently
    tolerating them. A permissive decoder lets two different strings decode to the same
    bytes, which is exactly the sort of ambiguity that turns into a parser confusion bug.

    Args:
        segment: The base64url text to decode.
    """
    if not _B64URL_RE.match(segment):
        raise InvalidTokenError("Token segment contains a character outside base64url")

    padding = -len(segment) % 4
    if padding == 3:
        raise InvalidTokenError("Token segment has an impossible base64url length")

    try:
        return base64.urlsafe_b64decode(segment + "=" * padding)
    except (binascii.Error, ValueError) as err:
        raise InvalidTokenError(f"Token segment is not valid base64url: {err}") from err


def split_token(token: str) -> tuple[str, str, str]:
    """
    Split a compact JWS into its header, payload and signature segments.

    Args:
        token: The compact serialization to split.
    """
    if not isinstance(token, str):
        raise InvalidTokenError("Token is not a string")

    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError(f"Token has {len(parts)} segments, expected 3")
    if not all(parts):
        raise InvalidTokenError("Token has an empty segment")

    return (parts[0], parts[1], parts[2])


def _decode_json_segment(segment: str, label: str) -> dict[str, Any]:
    """
    Decode a base64url segment into a JSON object, rejecting non-objects.

    Args:
        segment: The segment to decode.
        label:   The name used in error messages, such as "header" or "payload".
    """
    raw = b64url_decode(segment)
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise InvalidTokenError(f"Token {label} is not valid JSON: {err}") from err

    if not isinstance(value, dict):
        raise InvalidTokenError(f"Token {label} is not a JSON object")
    return value


def get_unverified_header(token: str) -> dict[str, Any]:
    """
    Read a token's header without verifying anything.

    Used to find the `kid` that selects a decode key. The value is attacker controlled,
    so it may be used to look a key up and for nothing else.

    Args:
        token: The token whose header should be read.
    """
    header_segment, _, _ = split_token(token)
    return _decode_json_segment(header_segment, "header")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_jwt_parsing.py -v`
Expected: PASS, 17 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/jwt.py tests/unit/test_jwt_parsing.py
git commit -m "feat: add JWT segment parsing and strict base64url

The decoder rejects the standard base64 alphabet, embedded padding and
impossible segment lengths. A permissive decoder lets two different strings
decode to the same bytes, which is where parser confusion bugs come from."
```

---

### Task 5: Algorithm registry and signature verification

**Files:**
- Modify: `armasec_lite/jwt.py` (append)
- Create: `tests/unit/test_jwt_signatures.py`
- Create: `tests/unit/conftest.py`

**Interfaces:**
- Consumes: `split_token`, `b64url_decode`, `b64url_encode`, the error types from Task 4; `armasec_lite.schemas.JWK`.
- Produces:
  - `SUPPORTED_ALGORITHMS: frozenset[str]` covering RS256/384/512, PS256/384/512, ES256/384/512, HS256/384/512, EdDSA.
  - `verify_signature(algorithm: str, jwk: JWK, signing_input: bytes, signature: bytes) -> None`, raising `InvalidSignatureError` on mismatch, `InvalidAlgorithmError` on a key-type mismatch, `InvalidKeyError` on a JWK missing required members.

- [ ] **Step 1: Write the shared key fixtures**

Create `tests/unit/conftest.py`:

```python
"""Key material shared across the jwt test modules."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from armasec_lite.jwt import b64url_encode
from armasec_lite.schemas import JWK


def _int_to_b64(value: int, length: int) -> str:
    return b64url_encode(value.to_bytes(length, "big"))


@pytest.fixture(scope="session")
def rsa_private():
    """A 2048 bit RSA private key, generated once per session."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_jwk(rsa_private):
    """The RSA public key as a JWK with kid 'rsa-test'."""
    numbers = rsa_private.public_key().public_numbers()
    return JWK.from_dict(
        {
            "kty": "RSA",
            "kid": "rsa-test",
            "alg": "RS256",
            "n": _int_to_b64(numbers.n, (numbers.n.bit_length() + 7) // 8),
            "e": _int_to_b64(numbers.e, (numbers.e.bit_length() + 7) // 8),
        }
    )


@pytest.fixture(scope="session")
def ec_private():
    """A P-256 private key, generated once per session."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def ec_jwk(ec_private):
    """The EC public key as a JWK with kid 'ec-test'."""
    numbers = ec_private.public_key().public_numbers()
    return JWK.from_dict(
        {
            "kty": "EC",
            "kid": "ec-test",
            "alg": "ES256",
            "crv": "P-256",
            "x": _int_to_b64(numbers.x, 32),
            "y": _int_to_b64(numbers.y, 32),
        }
    )


@pytest.fixture(scope="session")
def ed_private():
    """An Ed25519 private key, generated once per session."""
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def ed_jwk(ed_private):
    """The Ed25519 public key as a JWK with kid 'ed-test'."""
    from cryptography.hazmat.primitives import serialization

    raw = ed_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return JWK.from_dict(
        {"kty": "OKP", "kid": "ed-test", "alg": "EdDSA", "crv": "Ed25519", "x": b64url_encode(raw)}
    )


@pytest.fixture(scope="session")
def oct_jwk():
    """A symmetric key as a JWK with kid 'oct-test'."""
    return JWK.from_dict({"kty": "oct", "kid": "oct-test", "alg": "HS256", "k": b64url_encode(b"s" * 32)})
```

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_jwt_signatures.py`:

```python
import hashlib
import hmac as hmac_mod

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from armasec_lite.jwt import (
    SUPPORTED_ALGORITHMS,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    b64url_encode,
    verify_signature,
)
from armasec_lite.schemas import JWK

SIGNING_INPUT = b"header.payload"


def _rsa_sig(private, pad, hash_alg):
    return private.sign(SIGNING_INPUT, pad, hash_alg)


def _ec_raw_sig(private, hash_alg, coord_bytes):
    der = private.sign(SIGNING_INPUT, ec.ECDSA(hash_alg))
    r, s = decode_dss_signature(der)
    return r.to_bytes(coord_bytes, "big") + s.to_bytes(coord_bytes, "big")


def test_supported_algorithms_cover_the_spec():
    assert SUPPORTED_ALGORITHMS == frozenset(
        {
            "RS256", "RS384", "RS512",
            "PS256", "PS384", "PS512",
            "ES256", "ES384", "ES512",
            "HS256", "HS384", "HS512",
            "EdDSA",
        }
    )


def test_rs256_accepts_a_valid_signature(rsa_private, rsa_jwk):
    sig = _rsa_sig(rsa_private, padding.PKCS1v15(), hashes.SHA256())
    verify_signature("RS256", rsa_jwk, SIGNING_INPUT, sig)


def test_rs256_rejects_a_tampered_signature(rsa_private, rsa_jwk):
    sig = bytearray(_rsa_sig(rsa_private, padding.PKCS1v15(), hashes.SHA256()))
    sig[-1] ^= 0xFF
    with pytest.raises(InvalidSignatureError):
        verify_signature("RS256", rsa_jwk, SIGNING_INPUT, bytes(sig))


def test_rs256_rejects_a_signature_over_different_input(rsa_private, rsa_jwk):
    sig = _rsa_sig(rsa_private, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignatureError):
        verify_signature("RS256", rsa_jwk, b"different.input", sig)


def test_ps256_accepts_a_valid_signature(rsa_private, rsa_jwk):
    pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size)
    verify_signature("PS256", rsa_jwk, SIGNING_INPUT, _rsa_sig(rsa_private, pad, hashes.SHA256()))


def test_ps256_rejects_a_pkcs1v15_signature(rsa_private, rsa_jwk):
    sig = _rsa_sig(rsa_private, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignatureError):
        verify_signature("PS256", rsa_jwk, SIGNING_INPUT, sig)


def test_es256_accepts_a_valid_raw_signature(ec_private, ec_jwk):
    verify_signature("ES256", ec_jwk, SIGNING_INPUT, _ec_raw_sig(ec_private, hashes.SHA256(), 32))


def test_es256_rejects_a_der_encoded_signature(ec_private, ec_jwk):
    der = ec_private.sign(SIGNING_INPUT, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignatureError, match="length"):
        verify_signature("ES256", ec_jwk, SIGNING_INPUT, der)


def test_es256_rejects_a_short_signature(ec_private, ec_jwk):
    raw = _ec_raw_sig(ec_private, hashes.SHA256(), 32)
    with pytest.raises(InvalidSignatureError, match="length"):
        verify_signature("ES256", ec_jwk, SIGNING_INPUT, raw[:-1])


def test_es256_rejects_a_long_signature(ec_private, ec_jwk):
    raw = _ec_raw_sig(ec_private, hashes.SHA256(), 32)
    with pytest.raises(InvalidSignatureError, match="length"):
        verify_signature("ES256", ec_jwk, SIGNING_INPUT, raw + b"\x00")


def test_es256_uses_the_algorithm_curve_not_the_jwk_crv(ec_private, ec_jwk):
    """A hostile JWKS must not be able to name a weaker curve than the algorithm implies."""
    lying = JWK.from_dict(
        {
            "kty": "EC",
            "kid": ec_jwk.kid,
            "crv": "P-521",
            "x": ec_jwk.x,
            "y": ec_jwk.y,
        }
    )
    verify_signature("ES256", lying, SIGNING_INPUT, _ec_raw_sig(ec_private, hashes.SHA256(), 32))


def test_eddsa_accepts_a_valid_signature(ed_private, ed_jwk):
    verify_signature("EdDSA", ed_jwk, SIGNING_INPUT, ed_private.sign(SIGNING_INPUT))


def test_eddsa_rejects_a_tampered_signature(ed_private, ed_jwk):
    sig = bytearray(ed_private.sign(SIGNING_INPUT))
    sig[0] ^= 0xFF
    with pytest.raises(InvalidSignatureError):
        verify_signature("EdDSA", ed_jwk, SIGNING_INPUT, bytes(sig))


def test_hs256_accepts_a_valid_mac(oct_jwk):
    sig = hmac_mod.new(b"s" * 32, SIGNING_INPUT, hashlib.sha256).digest()
    verify_signature("HS256", oct_jwk, SIGNING_INPUT, sig)


def test_hs256_rejects_a_wrong_mac(oct_jwk):
    sig = hmac_mod.new(b"wrong-key", SIGNING_INPUT, hashlib.sha256).digest()
    with pytest.raises(InvalidSignatureError):
        verify_signature("HS256", oct_jwk, SIGNING_INPUT, sig)


def test_rsa_key_is_refused_for_an_hmac_algorithm(rsa_jwk):
    """
    The classic forgery: sign with HS256 using the provider's RSA public key as the
    HMAC secret. Enforcing kty against the algorithm family is what blocks it.
    """
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        verify_signature("HS256", rsa_jwk, SIGNING_INPUT, b"whatever")


def test_oct_key_is_refused_for_an_rsa_algorithm(oct_jwk):
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        verify_signature("RS256", oct_jwk, SIGNING_INPUT, b"whatever")


def test_ec_key_is_refused_for_an_rsa_algorithm(ec_jwk):
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        verify_signature("RS256", ec_jwk, SIGNING_INPUT, b"whatever")


def test_unknown_algorithm_is_refused(rsa_jwk):
    with pytest.raises(InvalidAlgorithmError, match="none"):
        verify_signature("none", rsa_jwk, SIGNING_INPUT, b"")


def test_rsa_jwk_missing_modulus_is_refused():
    jwk = JWK.from_dict({"kty": "RSA", "kid": "broken", "e": "AQAB"})
    with pytest.raises(InvalidKeyError, match="'n'"):
        verify_signature("RS256", jwk, SIGNING_INPUT, b"sig")


def test_ec_jwk_missing_y_is_refused():
    jwk = JWK.from_dict({"kty": "EC", "kid": "broken", "crv": "P-256", "x": b64url_encode(b"\x01" * 32)})
    with pytest.raises(InvalidKeyError, match="'y'"):
        verify_signature("ES256", jwk, SIGNING_INPUT, b"\x00" * 64)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_jwt_signatures.py -v`
Expected: FAIL with `ImportError: cannot import name 'verify_signature'`

- [ ] **Step 4: Append the algorithm registry to `armasec_lite/jwt.py`**

Extend the standard library imports at the top of the module with `hashlib` and `hmac`, so
that block reads:

```python
import base64
import binascii
import hashlib
import hmac
import json
import re
from typing import Any
```

Then add the third party and local imports beneath them:

```python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.schemas import JWK
```

Import only what this task uses. `serialization` and `decode_dss_signature` arrive in
Task 7, `time` in Task 6. Adding them early leaves `ruff` failing on F401 at the end of
this task.

Then append:

```python
#: Hash for each algorithm suffix. EdDSA carries its own hash internally.
_HASHES: dict[str, Any] = {
    "256": hashes.SHA256,
    "384": hashes.SHA384,
    "512": hashes.SHA512,
}

#: Curve and coordinate size for each ECDSA algorithm. Taken from the ALGORITHM, never
#: from the JWK's `crv`, so a hostile JWKS cannot substitute a weaker curve.
_EC_CURVES: dict[str, tuple[Any, int]] = {
    "ES256": (ec.SECP256R1, 32),
    "ES384": (ec.SECP384R1, 48),
    "ES512": (ec.SECP521R1, 66),
}

#: The key type each algorithm family requires. Enforcing this is what blocks signing
#: with HS256 using an RSA public key as the HMAC secret.
_REQUIRED_KTY: dict[str, str] = {
    "RS": "RSA",
    "PS": "RSA",
    "ES": "EC",
    "HS": "oct",
    "Ed": "OKP",
}

SUPPORTED_ALGORITHMS: frozenset[str] = frozenset(
    [f"{family}{size}" for family in ("RS", "PS", "ES", "HS") for size in ("256", "384", "512")]
    + ["EdDSA"]
)


def _required_member(jwk: JWK, name: str) -> str:
    """
    Pull a required JWK member or raise naming it.

    Args:
        jwk:  The key to read.
        name: The member name, such as "n" or "crv".
    """
    value = getattr(jwk, name, None)
    if not isinstance(value, str) or value == "":
        raise InvalidKeyError(f"JWK of type {jwk.kty!r} is missing required member {name!r}")
    return value


def _b64url_int(jwk: JWK, name: str) -> int:
    """
    Decode a base64url big-endian integer member of a JWK.

    Args:
        jwk:  The key to read.
        name: The member name.
    """
    return int.from_bytes(b64url_decode(_required_member(jwk, name)), "big")


def _check_kty(algorithm: str, jwk: JWK) -> None:
    """
    Require the JWK's key type to match the algorithm family.

    Args:
        algorithm: The algorithm named in the token header, already allowlisted.
        jwk:       The key selected by `kid`.
    """
    required = _REQUIRED_KTY[algorithm[:2]]
    if jwk.kty != required:
        raise InvalidAlgorithmError(
            f"Algorithm {algorithm!r} requires a key with kty {required!r}, "
            f"but the JWK has kty {jwk.kty!r}"
        )


def _rsa_public_key(jwk: JWK) -> rsa.RSAPublicKey:
    """Build an RSA public key from a JWK's `n` and `e`."""
    return rsa.RSAPublicNumbers(e=_b64url_int(jwk, "e"), n=_b64url_int(jwk, "n")).public_key()


def _ec_public_key(algorithm: str, jwk: JWK) -> ec.EllipticCurvePublicKey:
    """Build an EC public key, taking the curve from the algorithm."""
    curve_cls, coord_bytes = _EC_CURVES[algorithm]
    x_raw = b64url_decode(_required_member(jwk, "x"))
    y_raw = b64url_decode(_required_member(jwk, "y"))
    return ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x_raw, "big"),
        y=int.from_bytes(y_raw, "big"),
        curve=curve_cls(),
    ).public_key()


def verify_signature(
    algorithm: str,
    jwk: JWK,
    signing_input: bytes,
    signature: bytes,
) -> None:
    """
    Verify a JWS signature, raising on any failure.

    The caller must already have checked `algorithm` against its own allowlist. This
    function additionally requires the JWK's key type to match the algorithm family, so a
    key of the wrong kind cannot be pressed into service by a token that asks for it.

    Args:
        algorithm:     The algorithm from the token header, already allowlisted.
        jwk:           The key selected by the token's `kid`.
        signing_input: The ASCII bytes of "<header_b64>.<payload_b64>".
        signature:     The decoded signature bytes.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise InvalidAlgorithmError(f"Algorithm {algorithm!r} is not supported")

    _check_kty(algorithm, jwk)

    if algorithm.startswith("HS"):
        digest = getattr(hashlib, f"sha{algorithm[2:]}")
        secret = b64url_decode(_required_member(jwk, "k"))
        expected = hmac.new(secret, signing_input, digest).digest()
        if not hmac.compare_digest(expected, signature):
            raise InvalidSignatureError("Token signature did not verify")
        return

    if algorithm == "EdDSA":
        crv = _required_member(jwk, "crv")
        if crv != "Ed25519":
            raise InvalidAlgorithmError(f"EdDSA curve {crv!r} is not supported")
        key = ed25519.Ed25519PublicKey.from_public_bytes(
            b64url_decode(_required_member(jwk, "x"))
        )
        try:
            key.verify(signature, signing_input)
        except InvalidSignature as err:
            raise InvalidSignatureError("Token signature did not verify") from err
        return

    hash_alg = _HASHES[algorithm[2:]]()

    if algorithm.startswith("ES"):
        _, coord_bytes = _EC_CURVES[algorithm]
        # JWS carries ECDSA signatures as raw r||s. Checking the length before decoding
        # rejects both DER-wrapped and truncated signatures outright.
        if len(signature) != coord_bytes * 2:
            raise InvalidSignatureError(
                f"ECDSA signature has length {len(signature)}, expected {coord_bytes * 2}"
            )
        r = int.from_bytes(signature[:coord_bytes], "big")
        s = int.from_bytes(signature[coord_bytes:], "big")
        try:
            _ec_public_key(algorithm, jwk).verify(
                encode_dss_signature(r, s), signing_input, ec.ECDSA(hash_alg)
            )
        except InvalidSignature as err:
            raise InvalidSignatureError("Token signature did not verify") from err
        return

    pad: Any
    if algorithm.startswith("PS"):
        pad = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size)
    else:
        pad = padding.PKCS1v15()

    try:
        _rsa_public_key(jwk).verify(signature, signing_input, pad, hash_alg)
    except InvalidSignature as err:
        raise InvalidSignatureError("Token signature did not verify") from err
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_jwt_signatures.py -v`
Expected: PASS, 21 tests

- [ ] **Step 6: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 7: Commit**

```bash
git add armasec_lite/jwt.py tests/unit/test_jwt_signatures.py tests/unit/conftest.py
git commit -m "feat: add algorithm registry and signature verification

Key type is checked against the algorithm family, which blocks signing with
HS256 using an RSA public key as the HMAC secret. ECDSA curve and signature
length come from the algorithm name, never from the JWK's crv, so a hostile
JWKS cannot name a weaker curve than the algorithm implies."
```

---

### Task 6: Claim validation and `decode`

**Files:**
- Modify: `armasec_lite/jwt.py` (append)
- Create: `tests/unit/test_jwt_claims.py`

**Interfaces:**
- Consumes: everything from Tasks 4 and 5.
- Produces: `decode(token, jwk, algorithms, *, audience=None, issuer=None, options=None, leeway=0.0) -> dict[str, Any]`.
  - `options` keys honored: `verify_signature`, `verify_exp`, `verify_nbf`, `verify_aud`, `verify_iss`, all defaulting to `True`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_jwt_claims.py`:

```python
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from armasec_lite.jwt import (
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    b64url_encode,
    decode,
)

ALGS = ["RS256"]


def _sign(rsa_private, claims: dict, header: dict | None = None) -> str:
    head = {"alg": "RS256", "typ": "JWT", "kid": "rsa-test", **(header or {})}
    head_b64 = b64url_encode(json.dumps(head).encode())
    body_b64 = b64url_encode(json.dumps(claims).encode())
    signing_input = f"{head_b64}.{body_b64}".encode("ascii")
    sig = rsa_private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{head_b64}.{body_b64}.{b64url_encode(sig)}"


@pytest.fixture
def now():
    return int(time.time())


def test_decode_returns_the_claims(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "custom": [1, 2]})
    claims = decode(token, rsa_jwk, ALGS)
    assert claims["sub"] == "abc"
    assert claims["custom"] == [1, 2]


def test_decode_rejects_an_algorithm_outside_the_allowlist(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    with pytest.raises(InvalidAlgorithmError, match="not permitted"):
        decode(token, rsa_jwk, ["ES256"])


def test_decode_rejects_alg_none(rsa_jwk, now):
    head = b64url_encode(json.dumps({"alg": "none", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 60}).encode())
    with pytest.raises(InvalidAlgorithmError):
        decode(f"{head}.{body}.", rsa_jwk, ALGS)


def test_decode_rejects_a_tampered_payload(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    head, _, sig = token.split(".")
    forged = b64url_encode(json.dumps({"sub": "admin", "exp": now + 60}).encode())
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{forged}.{sig}", rsa_jwk, ALGS)


def test_decode_rejects_an_unrecognized_crit_header(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60}, header={"crit": ["urn:novel"]})
    with pytest.raises(InvalidTokenError, match="crit"):
        decode(token, rsa_jwk, ALGS)


def test_decode_rejects_an_expired_token(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 10})
    with pytest.raises(ExpiredSignatureError):
        decode(token, rsa_jwk, ALGS)


def test_decode_accepts_an_expired_token_within_leeway(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 10})
    assert decode(token, rsa_jwk, ALGS, leeway=60)["sub"] == "abc"


def test_decode_can_skip_expiry_verification(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 10})
    assert decode(token, rsa_jwk, ALGS, options={"verify_exp": False})["sub"] == "abc"


def test_decode_rejects_a_token_not_yet_valid(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 600, "nbf": now + 300})
    with pytest.raises(ImmatureSignatureError):
        decode(token, rsa_jwk, ALGS)


def test_decode_rejects_a_non_numeric_exp(rsa_private, rsa_jwk):
    token = _sign(rsa_private, {"sub": "abc", "exp": "soon"})
    with pytest.raises(InvalidTokenError, match="exp"):
        decode(token, rsa_jwk, ALGS)


def test_decode_matches_a_string_audience(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "my-api"})
    assert decode(token, rsa_jwk, ALGS, audience="my-api")["aud"] == "my-api"


def test_decode_matches_an_audience_inside_a_list(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": ["other", "my-api"]})
    assert decode(token, rsa_jwk, ALGS, audience="my-api")["sub"] == "abc"


def test_decode_rejects_a_wrong_audience(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "other-api"})
    with pytest.raises(InvalidAudienceError):
        decode(token, rsa_jwk, ALGS, audience="my-api")


def test_decode_rejects_a_missing_audience_when_one_is_required(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    with pytest.raises(InvalidAudienceError, match="missing"):
        decode(token, rsa_jwk, ALGS, audience="my-api")


def test_decode_can_skip_audience_verification(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "other-api"})
    claims = decode(token, rsa_jwk, ALGS, audience="my-api", options={"verify_aud": False})
    assert claims["sub"] == "abc"


def test_decode_ignores_audience_when_none_is_required(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "anything"})
    assert decode(token, rsa_jwk, ALGS)["sub"] == "abc"


def test_decode_matches_the_issuer(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": "https://auth.example.com"})
    assert decode(token, rsa_jwk, ALGS, issuer="https://auth.example.com")["sub"] == "abc"


def test_decode_rejects_a_wrong_issuer(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": "https://evil.example.com"})
    with pytest.raises(InvalidIssuerError):
        decode(token, rsa_jwk, ALGS, issuer="https://auth.example.com")


def test_decode_rejects_a_missing_issuer_when_one_is_required(rsa_private, rsa_jwk, now):
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    with pytest.raises(InvalidIssuerError, match="missing"):
        decode(token, rsa_jwk, ALGS, issuer="https://auth.example.com")


def test_decode_rejects_a_payload_that_is_not_an_object(rsa_private, rsa_jwk):
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": "rsa-test"}).encode())
    body = b64url_encode(b"[1,2,3]")
    signing_input = f"{head}.{body}".encode("ascii")
    sig = rsa_private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidTokenError, match="object"):
        decode(f"{head}.{body}.{b64url_encode(sig)}", rsa_jwk, ALGS)


def test_decode_verifies_signature_before_reading_claims(rsa_private, rsa_jwk, now):
    """An expired token with a bad signature must fail on the signature, not the clock."""
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 999})
    head, body, _ = token.split(".")
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{body}.{b64url_encode(b'garbage')}", rsa_jwk, ALGS)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_jwt_claims.py -v`
Expected: FAIL with `ImportError: cannot import name 'decode'`

- [ ] **Step 3: Append `decode` to `armasec_lite/jwt.py`**

Add `import time` to the standard library import block first; this task is the first to
use it.

```python
#: Options `decode` understands, with their defaults. Anything else is ignored, matching
#: the permissive behavior callers expect from a jose-shaped API.
_DEFAULT_OPTIONS: dict[str, bool] = {
    "verify_signature": True,
    "verify_exp": True,
    "verify_nbf": True,
    "verify_aud": True,
    "verify_iss": True,
}


def _numeric_claim(claims: dict[str, Any], name: str) -> float | None:
    """
    Read a NumericDate claim, rejecting values that are not numbers.

    Args:
        claims: The decoded payload.
        name:   The claim name.
    """
    if name not in claims:
        return None
    value = claims[name]
    # bool is an int subclass, and a boolean timestamp is always a malformed token.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidTokenError(f"Token claim {name!r} is not a number")
    return float(value)


def decode(
    token: str,
    jwk: JWK,
    algorithms: list[str],
    *,
    audience: str | None = None,
    issuer: str | None = None,
    options: dict[str, bool] | None = None,
    leeway: float = 0.0,
) -> dict[str, Any]:
    """
    Decode and fully validate a JWT, returning its claims.

    The order of operations below is a security property. In particular the algorithm is
    taken from the caller's allowlist rather than from the token, the key type is checked
    against the algorithm, and the signature is verified before any claim is trusted.

    Args:
        token:      The compact serialization to decode.
        jwk:        The key to verify against, already selected by `kid`.
        algorithms: The permitted algorithms. The token's own `alg` must appear here.
        audience:   Required audience. When None, `aud` is not checked.
        issuer:     Required issuer. When None, `iss` is not checked.
        options:    Toggles for individual checks, such as `{"verify_aud": False}`.
        leeway:     Seconds of clock skew tolerated on `exp` and `nbf`.
    """
    opts = {**_DEFAULT_OPTIONS, **(options or {})}

    # 1. Structure. A malformed token never reaches a cryptographic operation.
    header_b64, payload_b64, signature_b64 = split_token(token)
    header = _decode_json_segment(header_b64, "header")

    # 2. Algorithm allowlist. Read from the CALLER's list, never from the token. This is
    #    the `alg: none` and algorithm-confusion defense and it must stay first.
    algorithm = header.get("alg")
    if not isinstance(algorithm, str):
        raise InvalidAlgorithmError("Token header has no 'alg'")
    if algorithm not in algorithms:
        raise InvalidAlgorithmError(f"Algorithm {algorithm!r} is not permitted for this route")

    # 3. Unrecognized critical headers must be refused (RFC 7515 section 4.1.11). We
    #    understand none, so any `crit` entry at all is a refusal.
    crit = header.get("crit")
    if crit is not None:
        if not isinstance(crit, list):
            raise InvalidTokenError("Token header 'crit' is not a list")
        raise InvalidTokenError(f"Token header 'crit' names unsupported extensions: {crit}")

    # 4. Signature, before any claim is read. Step 3 of verify_signature also requires the
    #    JWK's kty to match the algorithm family.
    if opts["verify_signature"]:
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        verify_signature(algorithm, jwk, signing_input, b64url_decode(signature_b64))

    # 5. Only now are the claims worth reading.
    claims = _decode_json_segment(payload_b64, "payload")
    now = time.time()

    expire = _numeric_claim(claims, "exp")
    if opts["verify_exp"] and expire is not None and now > expire + leeway:
        raise ExpiredSignatureError("Token has expired")

    not_before = _numeric_claim(claims, "nbf")
    if opts["verify_nbf"] and not_before is not None and now < not_before - leeway:
        raise ImmatureSignatureError("Token is not yet valid")

    # Parsed for type validity even though it is not used to reject, matching jose.
    _numeric_claim(claims, "iat")

    if opts["verify_aud"] and audience is not None:
        raw_audience = claims.get("aud")
        if raw_audience is None:
            raise InvalidAudienceError("Token is missing the 'aud' claim")
        allowed = raw_audience if isinstance(raw_audience, list) else [raw_audience]
        if audience not in allowed:
            raise InvalidAudienceError(f"Token audience {raw_audience!r} does not match {audience!r}")

    if opts["verify_iss"] and issuer is not None:
        token_issuer = claims.get("iss")
        if token_issuer is None:
            raise InvalidIssuerError("Token is missing the 'iss' claim")
        if token_issuer != issuer:
            raise InvalidIssuerError(f"Token issuer {token_issuer!r} does not match {issuer!r}")

    return claims
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_jwt_claims.py -v`
Expected: PASS, 21 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/jwt.py tests/unit/test_jwt_claims.py
git commit -m "feat: add JWT claim validation and decode

The algorithm comes from the caller's allowlist, never from the token, and
the signature is verified before any claim is read. Unrecognized crit
headers are refused per RFC 7515 4.1.11."
```

---

### Task 7: `encode` and PyJWT cross-validation

**Files:**
- Modify: `armasec_lite/jwt.py` (append)
- Create: `tests/unit/test_jwt_crossvalidation.py`

**Interfaces:**
- Consumes: everything from Tasks 4 through 6.
- Produces: `encode(claims: dict, key: bytes | str, algorithm: str, headers: dict | None = None) -> str`.

`encode` exists so the pytest extension can build test tokens without a second signing
dependency. It is a testing aid, documented as such, and never used on the request path.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_jwt_crossvalidation.py`:

```python
"""
Cross-validation against PyJWT.

A hand written JWT implementation drifts from the specification in ways its own tests
cannot see, because those tests encode the same misunderstanding as the implementation.
Checking both directions against an independent library is the defense: tokens we sign
must verify under PyJWT, and tokens PyJWT signs must verify under us.
"""

import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization

from armasec_lite.jwt import (
    ExpiredSignatureError,
    InvalidSignatureError,
    decode,
    encode,
)

RSA_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]


@pytest.fixture
def rsa_pem(rsa_private):
    return rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def rsa_pub_pem(rsa_private):
    return rsa_private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.mark.parametrize("algorithm", RSA_ALGS)
def test_our_token_verifies_under_pyjwt(rsa_pem, rsa_pub_pem, algorithm):
    now = int(time.time())
    token = encode(
        {"sub": "abc", "exp": now + 60, "iss": "https://auth.example.com"},
        rsa_pem,
        algorithm,
        headers={"kid": "rsa-test"},
    )
    claims = pyjwt.decode(
        token,
        rsa_pub_pem,
        algorithms=[algorithm],
        issuer="https://auth.example.com",
        options={"verify_aud": False},
    )
    assert claims["sub"] == "abc"


@pytest.mark.parametrize("algorithm", RSA_ALGS)
def test_pyjwt_token_verifies_under_us(rsa_pem, rsa_jwk, algorithm):
    now = int(time.time())
    token = pyjwt.encode(
        {"sub": "abc", "exp": now + 60, "aud": "my-api", "iss": "https://auth.example.com"},
        rsa_pem,
        algorithm=algorithm,
        headers={"kid": "rsa-test"},
    )
    claims = decode(
        token,
        rsa_jwk,
        [algorithm],
        audience="my-api",
        issuer="https://auth.example.com",
    )
    assert claims["sub"] == "abc"


def test_pyjwt_expired_token_is_rejected_by_us(rsa_pem, rsa_jwk):
    now = int(time.time())
    token = pyjwt.encode({"sub": "abc", "exp": now - 60}, rsa_pem, algorithm="RS256")
    with pytest.raises(ExpiredSignatureError):
        decode(token, rsa_jwk, ["RS256"])


def test_our_expired_token_is_rejected_by_pyjwt(rsa_pem, rsa_pub_pem):
    now = int(time.time())
    token = encode({"sub": "abc", "exp": now - 60}, rsa_pem, "RS256")
    with pytest.raises(pyjwt.ExpiredSignatureError):
        pyjwt.decode(token, rsa_pub_pem, algorithms=["RS256"], options={"verify_aud": False})


def test_our_tampered_token_is_rejected_by_pyjwt(rsa_pem, rsa_pub_pem):
    now = int(time.time())
    token = encode({"sub": "abc", "exp": now + 60}, rsa_pem, "RS256")
    head, body, sig = token.split(".")
    with pytest.raises(pyjwt.InvalidSignatureError):
        pyjwt.decode(
            f"{head}.{body}.{sig[:-4]}AAAA",
            rsa_pub_pem,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )


def test_pyjwt_tampered_token_is_rejected_by_us(rsa_pem, rsa_jwk):
    now = int(time.time())
    token = pyjwt.encode({"sub": "abc", "exp": now + 60}, rsa_pem, algorithm="RS256")
    head, body, sig = token.split(".")
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{body}.{sig[:-4]}AAAA", rsa_jwk, ["RS256"])


def test_es256_round_trips_through_pyjwt(ec_private, ec_jwk):
    pem = ec_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    now = int(time.time())
    token = pyjwt.encode({"sub": "abc", "exp": now + 60}, pem, algorithm="ES256")
    assert decode(token, ec_jwk, ["ES256"])["sub"] == "abc"


def test_eddsa_round_trips_through_pyjwt(ed_private, ed_jwk):
    pem = ed_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    now = int(time.time())
    token = pyjwt.encode({"sub": "abc", "exp": now + 60}, pem, algorithm="EdDSA")
    assert decode(token, ed_jwk, ["EdDSA"])["sub"] == "abc"


def test_hs256_round_trips_through_pyjwt(oct_jwk):
    now = int(time.time())
    secret = b"s" * 32
    token = pyjwt.encode({"sub": "abc", "exp": now + 60}, secret, algorithm="HS256")
    assert decode(token, oct_jwk, ["HS256"])["sub"] == "abc"


def test_our_hs256_token_verifies_under_pyjwt():
    now = int(time.time())
    secret = b"s" * 32
    token = encode({"sub": "abc", "exp": now + 60}, secret, "HS256")
    assert pyjwt.decode(token, secret, algorithms=["HS256"])["sub"] == "abc"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_jwt_crossvalidation.py -v`
Expected: FAIL with `ImportError: cannot import name 'encode'`

- [ ] **Step 3: Append `encode` to `armasec_lite/jwt.py`**

```python
def _sign(algorithm: str, key: bytes | str, signing_input: bytes) -> bytes:
    """
    Produce a JWS signature. Used by `encode`, which is a testing aid.

    Args:
        algorithm:     The JWS algorithm to sign with.
        key:           PEM private key bytes, or raw secret bytes for HS algorithms.
        signing_input: The ASCII bytes of "<header_b64>.<payload_b64>".
    """
    if algorithm.startswith("HS"):
        secret = key.encode() if isinstance(key, str) else key
        digest = getattr(hashlib, f"sha{algorithm[2:]}")
        return hmac.new(secret, signing_input, digest).digest()

    pem = key.encode() if isinstance(key, str) else key
    private = serialization.load_pem_private_key(pem, password=None)

    if algorithm == "EdDSA":
        assert isinstance(private, ed25519.Ed25519PrivateKey)
        return private.sign(signing_input)

    hash_alg = _HASHES[algorithm[2:]]()

    if algorithm.startswith("ES"):
        assert isinstance(private, ec.EllipticCurvePrivateKey)
        _, coord_bytes = _EC_CURVES[algorithm]
        der = private.sign(signing_input, ec.ECDSA(hash_alg))
        r, s = decode_dss_signature(der)
        return r.to_bytes(coord_bytes, "big") + s.to_bytes(coord_bytes, "big")

    assert isinstance(private, rsa.RSAPrivateKey)
    if algorithm.startswith("PS"):
        pad: Any = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size)
    else:
        pad = padding.PKCS1v15()
    return private.sign(signing_input, pad, hash_alg)


def encode(
    claims: dict[str, Any],
    key: bytes | str,
    algorithm: str,
    headers: dict[str, Any] | None = None,
) -> str:
    """
    Sign a set of claims into a compact JWS.

    This is a testing aid. It exists so that the pytest extension can build tokens without
    pulling in a second signing library, and it is never used on the request path. Do not
    build production tokens with it; this library is a validator.

    Args:
        claims:    The payload to sign.
        key:       PEM private key bytes, or the raw secret for an HS algorithm.
        algorithm: The JWS algorithm to sign with.
        headers:   Additional header members, such as `kid`.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise InvalidAlgorithmError(f"Algorithm {algorithm!r} is not supported")

    header = {"typ": "JWT", **(headers or {}), "alg": algorithm}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _sign(algorithm, key, signing_input)
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"
```

Two imports at the top of the module need extending for this task. `serialization` is new,
and `decode_dss_signature` joins the existing utils import:

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_jwt_crossvalidation.py -v`
Expected: PASS, 22 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/jwt.py tests/unit/test_jwt_crossvalidation.py
git commit -m "feat: add JWT encode and cross-validate against PyJWT

Tokens we sign verify under PyJWT and tokens PyJWT signs verify under us,
in both the positive and negative cases. A hand written implementation
cannot catch its own spec drift, because its tests encode the same
misunderstanding as the code."
```

---

### Task 8: The attack suite

**Files:**
- Create: `tests/unit/test_jwt_attacks.py`

**Interfaces:**
- Consumes: everything from Tasks 4 through 7.
- Produces: no code. Named tests that `benchmarks/bench/security_matrix.py` reads to build the security posture chart, so the test names are part of the contract and must not be renamed casually.

- [ ] **Step 1: Write the attack tests**

Create `tests/unit/test_jwt_attacks.py`:

```python
"""
The attack suite.

Every test here names one concrete forgery or malformed-input technique. The names are
consumed by the security matrix benchmark, so renaming one changes a published chart.
"""

import hashlib
import hmac as hmac_mod
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from armasec_lite.jwt import (
    InvalidAlgorithmError,
    InvalidSignatureError,
    InvalidTokenError,
    b64url_decode,
    b64url_encode,
    decode,
    encode,
)

ALGS = ["RS256"]


@pytest.fixture
def now():
    return int(time.time())


@pytest.fixture
def valid_token(rsa_private, now):
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64url_encode(sig)}"


def test_attack_alg_none_is_rejected(rsa_jwk, now):
    head = b64url_encode(json.dumps({"alg": "none", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    with pytest.raises(InvalidAlgorithmError):
        decode(f"{head}.{body}.", rsa_jwk, ALGS)


def test_attack_alg_none_with_empty_signature_and_none_allowlisted(rsa_jwk, now):
    """Even if a caller foolishly allowlists it, 'none' is not a supported algorithm."""
    head = b64url_encode(json.dumps({"alg": "none", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    with pytest.raises(InvalidAlgorithmError):
        decode(f"{head}.{body}.AA", rsa_jwk, ["none"])


def test_attack_hmac_signed_with_the_rsa_public_key_is_rejected(rsa_jwk, now):
    """
    Algorithm confusion: the attacker knows the provider's PUBLIC key, signs HS256 using
    it as the HMAC secret, and hopes the verifier picks HMAC. Requiring kty to match the
    algorithm family stops it even when the caller allowlists HS256.
    """
    public_pem = b64url_decode(rsa_jwk.n or "")
    head = b64url_encode(json.dumps({"alg": "HS256", "kid": "rsa-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    forged = hmac_mod.new(public_pem, f"{head}.{body}".encode("ascii"), hashlib.sha256).digest()
    with pytest.raises(InvalidAlgorithmError, match="kty"):
        decode(f"{head}.{body}.{b64url_encode(forged)}", rsa_jwk, ["RS256", "HS256"])


def test_attack_algorithm_outside_the_allowlist_is_rejected(rsa_private, rsa_jwk, now):
    token = encode({"sub": "admin", "exp": now + 600}, b"secret" * 8, "HS256")
    with pytest.raises(InvalidAlgorithmError, match="not permitted"):
        decode(token, rsa_jwk, ALGS)


def test_attack_tampered_payload_is_rejected(valid_token, rsa_jwk, now):
    head, _, sig = valid_token.split(".")
    forged = b64url_encode(json.dumps({"sub": "admin", "exp": now + 600}).encode())
    with pytest.raises(InvalidSignatureError):
        decode(f"{head}.{forged}.{sig}", rsa_jwk, ALGS)


def test_attack_tampered_header_is_rejected(valid_token, rsa_jwk):
    _, body, sig = valid_token.split(".")
    forged = b64url_encode(json.dumps({"alg": "RS256", "kid": "rsa-test", "x": 1}).encode())
    with pytest.raises(InvalidSignatureError):
        decode(f"{forged}.{body}.{sig}", rsa_jwk, ALGS)


def test_attack_stripped_signature_is_rejected(valid_token, rsa_jwk):
    head, body, _ = valid_token.split(".")
    with pytest.raises(InvalidTokenError):
        decode(f"{head}.{body}.", rsa_jwk, ALGS)


def test_attack_unrecognized_crit_header_is_rejected(rsa_private, rsa_jwk, now):
    head = b64url_encode(
        json.dumps({"alg": "RS256", "kid": "rsa-test", "crit": ["urn:x"]}).encode()
    )
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidTokenError, match="crit"):
        decode(f"{head}.{body}.{b64url_encode(sig)}", rsa_jwk, ALGS)


def test_attack_extra_segment_is_rejected(valid_token, rsa_jwk):
    with pytest.raises(InvalidTokenError):
        decode(f"{valid_token}.extra", rsa_jwk, ALGS)


def test_attack_standard_base64_alphabet_is_rejected(rsa_jwk):
    with pytest.raises(InvalidTokenError, match="character"):
        decode("ab+d.ab+d.ab+d", rsa_jwk, ALGS)


def test_attack_non_canonical_padding_is_rejected(rsa_jwk):
    with pytest.raises(InvalidTokenError, match="character"):
        decode("YQ==.YQ==.YQ==", rsa_jwk, ALGS)


def test_attack_ecdsa_der_signature_is_rejected(ec_private, ec_jwk, now):
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

    head = b64url_encode(json.dumps({"alg": "ES256", "kid": "ec-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    der = ec_private.sign(f"{head}.{body}".encode("ascii"), ec_mod.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignatureError, match="length"):
        decode(f"{head}.{body}.{b64url_encode(der)}", ec_jwk, ["ES256"])


def test_attack_ecdsa_zero_signature_is_rejected(ec_jwk, now):
    """
    A correctly sized all-zero signature. It must fail on verification, not on the
    length check, so this exercises the primitive rather than the guard in front of it.
    """
    head = b64url_encode(json.dumps({"alg": "ES256", "kid": "ec-test"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc", "exp": now + 600}).encode())
    zero_sig = bytes(64)
    with pytest.raises(InvalidSignatureError) as info:
        decode(f"{head}.{body}.{b64url_encode(zero_sig)}", ec_jwk, ["ES256"])
    assert "length" not in str(info.value)
```

- [ ] **Step 2: Run the attack suite**

Run: `uv run pytest tests/unit/test_jwt_attacks.py -v`
Expected: PASS, 13 tests. Every one should pass against the implementation from Tasks 4
through 7 without any change. If one fails, that is a real defect in `jwt.py`, not a bad
test. Fix `jwt.py`, not the test.

- [ ] **Step 3: Confirm the suite fails without the defenses**

Temporarily comment out the `_check_kty(algorithm, jwk)` call in `verify_signature` and run:

Run: `uv run pytest tests/unit/test_jwt_attacks.py::test_attack_hmac_signed_with_the_rsa_public_key_is_rejected -v`
Expected: FAIL. This confirms the test actually exercises the defense rather than passing
for an unrelated reason. Restore the line afterwards and re-run to confirm PASS.

- [ ] **Step 4: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_jwt_attacks.py
git commit -m "test: add the JWT attack suite

Names are consumed by the security matrix benchmark, so renaming one
changes a published chart."
```

---

### Task 9: Hardened HTTP fetch

**Files:**
- Create: `armasec_lite/http.py`
- Create: `tests/unit/test_http.py`

**Interfaces:**
- Consumes: `armasec_lite.exceptions.AuthenticationError`.
- Produces:
  - `MAX_BODY_BYTES: int` (1 MiB), `DEFAULT_TIMEOUT: float` (10.0), `MAX_REDIRECTS: int` (5).
  - `get_json(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_http.py`:

```python
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
    def log_message(self, *args):  # noqa: D102 - silence the default stderr logging
        pass

    def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
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


def test_get_json_raises_on_an_unreachable_host():
    with pytest.raises(AuthenticationError):
        get_json("http://127.0.0.1:1/nothing", timeout=1.0)


def test_get_json_rejects_a_non_http_scheme():
    with pytest.raises(AuthenticationError, match="scheme"):
        get_json("file:///etc/passwd")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_http.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.http'`

- [ ] **Step 3: Write `armasec_lite/http.py`**

```python
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
        raise AuthenticationError(f"Response from url {url} is too large: over {MAX_BODY_BYTES} bytes")

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as err:
        raise AuthenticationError(f"Response from url {url} is not valid JSON: {err}") from err

    if not isinstance(data, dict):
        raise AuthenticationError(f"Response from url {url} is not a JSON object")

    return data
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_http.py -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/http.py tests/unit/test_http.py
git commit -m "feat: add hardened HTTP fetch

Replaces httpx. Adds an explicit TLS context, a redirect handler that
refuses an https to http downgrade, and a response size cap. The keys that
come back from a JWKS fetch decide who is authenticated, so a redirect onto
plaintext is not a theoretical concern."
```

---

### Task 10: TokenPayload

**Files:**
- Create: `armasec_lite/token_payload.py`
- Create: `tests/unit/test_token_payload.py`

**Interfaces:**
- Consumes: nothing beyond the standard library.
- Produces: `TokenPayload` dataclass with `sub: str`, `permissions: list[str]`, `expire: datetime | None`, `client_id: str | None`, `original_token: str | None`, `extra: dict[str, Any]`; classmethod `from_claims(claims: dict, original_token: str | None = None) -> TokenPayload`; method `to_dict() -> dict`; attribute fallthrough to `extra` via `__getattr__`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_token_payload.py`:

```python
from datetime import datetime, timezone

import pytest

from armasec_lite.token_payload import TokenPayload


def test_from_claims_maps_upstream_aliases():
    payload = TokenPayload.from_claims(
        {"sub": "abc", "exp": 1735689600, "azp": "my-client", "permissions": ["read:x"]},
        original_token="the-token",
    )
    assert payload.sub == "abc"
    assert payload.client_id == "my-client"
    assert payload.permissions == ["read:x"]
    assert payload.expire == datetime.fromtimestamp(1735689600, tz=timezone.utc)
    assert payload.original_token == "the-token"


def test_from_claims_accepts_the_unaliased_names():
    payload = TokenPayload.from_claims({"sub": "abc", "client_id": "c", "expire": 1735689600})
    assert payload.client_id == "c"
    assert payload.expire is not None


def test_from_claims_defaults_permissions_to_empty():
    assert TokenPayload.from_claims({"sub": "abc"}).permissions == []


def test_from_claims_requires_sub():
    with pytest.raises(Exception, match="sub"):
        TokenPayload.from_claims({"exp": 1735689600})


def test_extra_claims_are_reachable_as_attributes():
    payload = TokenPayload.from_claims({"sub": "abc", "email": "a@b.c", "is_admin": True})
    assert payload.email == "a@b.c"
    assert payload.is_admin is True


def test_unknown_attribute_raises_attribute_error():
    payload = TokenPayload.from_claims({"sub": "abc"})
    with pytest.raises(AttributeError, match="nope"):
        payload.nope


def test_extra_does_not_shadow_declared_fields():
    payload = TokenPayload.from_claims({"sub": "abc", "permissions": ["a"]})
    assert payload.permissions == ["a"]
    assert "permissions" not in payload.extra


def test_to_dict_matches_the_upstream_shape():
    payload = TokenPayload.from_claims(
        {"sub": "abc", "exp": 1735689600, "azp": "my-client", "permissions": ["read:x"]}
    )
    assert payload.to_dict() == {
        "sub": "abc",
        "permissions": ["read:x"],
        "exp": 1735689600,
        "client_id": "my-client",
    }


def test_to_dict_without_an_expiry_omits_the_timestamp():
    payload = TokenPayload.from_claims({"sub": "abc"})
    assert payload.to_dict()["exp"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_token_payload.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.token_payload'`

- [ ] **Step 3: Write `armasec_lite/token_payload.py`**

```python
"""
The decoded contents of a JWT, in the shape armasec's consumers expect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from armasec_lite.exceptions import ArmasecError

#: Claims that map onto declared fields, under either their JWT name or armasec's name.
_CLAIMED = {"sub", "permissions", "exp", "expire", "azp", "client_id", "original_token"}


@dataclass
class TokenPayload:
    """
    A convenience class for accessing parts of a decoded jwt.

    Claims that are not declared fields remain reachable as attributes, because
    `match_keys` and plugin checks read arbitrary claims off this object.

    Attributes:
        sub:            The "sub" claim from a JWT.
        permissions:    The permissions claims extracted from a JWT.
        expire:         The "exp" claim, as an aware datetime.
        client_id:      The "azp" claim from a JWT.
        original_token: The original token value.
        extra:          Every other claim, verbatim.
    """

    sub: str
    permissions: list[str] = field(default_factory=list)
    expire: datetime | None = None
    client_id: str | None = None
    original_token: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __getattr__(self, name: str) -> Any:
        """
        Fall through to undeclared claims so `getattr(payload, "email")` works.

        Only called when normal attribute lookup fails, so declared fields always win.
        """
        try:
            return self.__dict__["extra"][name]
        except KeyError:
            raise AttributeError(
                f"{type(self).__name__!r} object has no attribute or claim {name!r}"
            ) from None

    @classmethod
    def from_claims(
        cls,
        claims: dict[str, Any],
        original_token: str | None = None,
    ) -> TokenPayload:
        """
        Build a TokenPayload from a decoded claim set.

        Args:
            claims:         The decoded JWT payload.
            original_token: The compact token the claims came from.
        """
        sub = claims.get("sub")
        ArmasecError.require_condition(
            isinstance(sub, str) and sub != "",
            "Token payload is missing a valid 'sub' claim",
        )

        raw_expire = claims.get("exp", claims.get("expire"))
        expire = (
            datetime.fromtimestamp(float(raw_expire), tz=timezone.utc)
            if isinstance(raw_expire, (int, float)) and not isinstance(raw_expire, bool)
            else None
        )

        permissions = claims.get("permissions") or []
        ArmasecError.require_condition(
            isinstance(permissions, list),
            "Token payload 'permissions' is not a list",
        )

        return cls(
            sub=str(sub),
            permissions=list(permissions),
            expire=expire,
            client_id=claims.get("azp", claims.get("client_id")),
            original_token=original_token,
            extra={k: v for k, v in claims.items() if k not in _CLAIMED},
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to the dictionary shape upstream armasec's `to_dict` produced.
        """
        return {
            "sub": self.sub,
            "permissions": self.permissions,
            "exp": int(self.expire.timestamp()) if self.expire is not None else None,
            "client_id": self.client_id,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_token_payload.py -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/token_payload.py tests/unit/test_token_payload.py
git commit -m "feat: add TokenPayload

Undeclared claims stay reachable as attributes via __getattr__, because
match_keys and plugin checks read arbitrary claims off this object."
```

---

### Task 11: OpenidConfigLoader with the process-wide cache

**Files:**
- Create: `armasec_lite/openid_config_loader.py`
- Create: `tests/unit/test_openid_config_loader.py`

**Interfaces:**
- Consumes: `armasec_lite.http.get_json`, `armasec_lite.schemas.{JWKs, OpenidConfig}`, `armasec_lite.exceptions.AuthenticationError`, `armasec_lite.utilities.noop`.
- Produces:
  - `JWKS_REFRESH_INTERVAL: float` (300.0).
  - `OpenidConfigLoader(domain, use_https=True, debug_logger=None)` with properties `config -> OpenidConfig` and `jwks -> JWKs`, method `refresh_jwks() -> JWKs`, and staticmethod `build_openid_config_url(domain, use_https=True) -> str`.
  - Classmethod `OpenidConfigLoader.get(domain, use_https=True, debug_logger=None) -> OpenidConfigLoader`, returning the shared instance for that domain.
  - `clear_cache() -> None`, for tests.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_openid_config_loader.py`:

```python
import threading

import pytest

from armasec_lite import openid_config_loader as loader_module
from armasec_lite.exceptions import ArmasecError, AuthenticationError
from armasec_lite.openid_config_loader import OpenidConfigLoader, clear_cache

DOMAIN = "auth.example.com"
CONFIG_URL = f"https://{DOMAIN}/.well-known/openid-configuration"
JWKS_URL = f"https://{DOMAIN}/jwks"

CONFIG_DOC = {"issuer": f"https://{DOMAIN}", "jwks_uri": JWKS_URL}
JWKS_DOC = {"keys": [{"kty": "RSA", "kid": "one", "n": "AA", "e": "AQAB"}]}
ROTATED_DOC = {"keys": [{"kty": "RSA", "kid": "two", "n": "BB", "e": "AQAB"}]}


@pytest.fixture(autouse=True)
def reset_cache():
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def fake_get(monkeypatch):
    """Replace the HTTP layer with a counting router."""
    calls: list[str] = []
    routes = {CONFIG_URL: CONFIG_DOC, JWKS_URL: JWKS_DOC}

    def _get(url, *, timeout=10.0):
        calls.append(url)
        if url not in routes:
            raise AuthenticationError(f"no route for {url}")
        return routes[url]

    monkeypatch.setattr(loader_module.http, "get_json", _get)
    return calls, routes


def test_build_openid_config_url_uses_https_by_default():
    assert OpenidConfigLoader.build_openid_config_url(DOMAIN) == CONFIG_URL


def test_build_openid_config_url_can_use_http():
    assert OpenidConfigLoader.build_openid_config_url(DOMAIN, use_https=False) == (
        f"http://{DOMAIN}/.well-known/openid-configuration"
    )


def test_config_is_fetched_lazily_and_cached(fake_get):
    calls, _ = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    assert calls == []
    assert loader.config.issuer == f"https://{DOMAIN}"
    assert loader.config.issuer == f"https://{DOMAIN}"
    assert calls == [CONFIG_URL]


def test_jwks_fetch_pulls_the_config_first(fake_get):
    calls, _ = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    assert [k.kid for k in loader.jwks.keys] == ["one"]
    assert calls == [CONFIG_URL, JWKS_URL]


def test_invalid_config_document_raises(monkeypatch):
    monkeypatch.setattr(loader_module.http, "get_json", lambda url, timeout=10.0: {"nope": 1})
    with pytest.raises(ArmasecError, match="issuer"):
        OpenidConfigLoader(DOMAIN).config


def test_get_returns_one_shared_loader_per_domain(fake_get):
    calls, _ = fake_get
    first = OpenidConfigLoader.get(DOMAIN)
    second = OpenidConfigLoader.get(DOMAIN)
    assert first is second
    first.jwks
    second.jwks
    assert calls == [CONFIG_URL, JWKS_URL]


def test_get_keys_the_cache_on_use_https(fake_get):
    assert OpenidConfigLoader.get(DOMAIN, use_https=True) is not OpenidConfigLoader.get(
        DOMAIN, use_https=False
    )


def test_clear_cache_drops_shared_loaders(fake_get):
    first = OpenidConfigLoader.get(DOMAIN)
    clear_cache()
    assert OpenidConfigLoader.get(DOMAIN) is not first


def test_concurrent_cold_loads_fetch_once(fake_get):
    """Ten threads racing a cold loader must produce one config fetch, not ten."""
    calls, _ = fake_get
    loader = OpenidConfigLoader.get(DOMAIN)
    barrier = threading.Barrier(10)

    def _work():
        barrier.wait()
        loader.jwks

    threads = [threading.Thread(target=_work) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert calls.count(CONFIG_URL) == 1
    assert calls.count(JWKS_URL) == 1


def test_refresh_jwks_refetches_and_replaces(fake_get):
    calls, routes = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    assert [k.kid for k in loader.jwks.keys] == ["one"]

    routes[JWKS_URL] = ROTATED_DOC
    assert [k.kid for k in loader.refresh_jwks().keys] == ["two"]
    assert calls.count(JWKS_URL) == 2


def test_refresh_jwks_is_rate_limited(fake_get, monkeypatch):
    calls, routes = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    loader.jwks
    routes[JWKS_URL] = ROTATED_DOC

    loader.refresh_jwks()
    loader.refresh_jwks()
    loader.refresh_jwks()

    # The first refresh reaches the network; the two inside the interval do not.
    assert calls.count(JWKS_URL) == 2


def test_refresh_jwks_allowed_again_after_the_interval(fake_get):
    calls, routes = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    loader.jwks
    loader.refresh_jwks()
    loader.refresh_jwks()
    assert calls.count(JWKS_URL) == 2

    # Rewind the refresh clock rather than the wall clock, so the test does not sleep.
    loader._last_refresh_at -= loader_module.JWKS_REFRESH_INTERVAL * 2
    loader.refresh_jwks()

    assert calls.count(JWKS_URL) == 3


def test_first_refresh_is_never_rate_limited_by_the_initial_load(fake_get):
    """
    A rotation encountered shortly after startup must still recover. The interval governs
    refresh-to-refresh spacing, not the gap since the initial load.
    """
    calls, routes = fake_get
    loader = OpenidConfigLoader(DOMAIN)
    loader.jwks
    routes[JWKS_URL] = ROTATED_DOC
    assert [k.kid for k in loader.refresh_jwks().keys] == ["two"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_openid_config_loader.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.openid_config_loader'`

- [ ] **Step 3: Write `armasec_lite/openid_config_loader.py`**

```python
"""
Loads openid-configuration and JWKS documents from an OIDC provider.

Two things here are not in upstream armasec, and both are invisible from the API.

The loader cache is process-wide. Upstream builds one loader per `TokenSecurity`, so an
app with ten distinct `lockdown()` scope sets against one domain performs ten independent
loads, or twenty HTTP requests. Sharing by domain makes that two.

The JWKS is refetchable. Upstream caches it for the process lifetime, so a provider key
rotation returns 401 on every request until someone restarts the service. Refetching is
rate limited so that a flood of tokens carrying unknown key ids cannot be turned into a
flood of outbound requests.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from armasec_lite import http
from armasec_lite.exceptions import AuthenticationError
from armasec_lite.schemas import JWKs, OpenidConfig
from armasec_lite.utilities import noop

#: Minimum seconds between JWKS refetches for one domain.
JWKS_REFRESH_INTERVAL = 300.0

#: Shared loaders, keyed by (domain, use_https), and the lock that guards the mapping.
_CACHE: dict[tuple[str, bool], "OpenidConfigLoader"] = {}
_CACHE_LOCK = threading.Lock()


def clear_cache() -> None:
    """
    Drop every shared loader.

    A process-wide cache leaks state between tests, so the pytest extension calls this
    around each test that stands up a mock provider.
    """
    with _CACHE_LOCK:
        _CACHE.clear()


class OpenidConfigLoader:
    """
    Lazily loads and caches the openid-configuration and JWKS for one OIDC domain.
    """

    def __init__(
        self,
        domain: str,
        use_https: bool = True,
        debug_logger: Callable[..., None] | None = None,
    ):
        """
        Initialize a loader for one domain.

        Args:
            domain:       The domain of the OIDC provider, used to build the discovery URL.
            use_https:    If falsey, use http instead of https.
            debug_logger: A callable such as `logger.debug`, or None for no logging.
        """
        self.domain = domain
        self.use_https = use_https
        self.debug_logger = debug_logger if debug_logger else noop

        self._config: OpenidConfig | None = None
        self._jwks: JWKs | None = None
        # Monotonic timestamp of the last REFRESH, not of the initial load. Starting at
        # zero means the first refresh is always allowed, so a rotation encountered
        # shortly after startup still recovers. The interval governs refresh-to-refresh
        # spacing, which is what stops unknown key ids becoming a request flood.
        self._last_refresh_at = 0.0
        # A threading.Lock rather than an asyncio.Lock on purpose: an asyncio.Lock binds
        # to the loop that first awaits it and goes stale across test loops. The cold load
        # already runs in an executor thread, so the worker holds this and the event loop
        # thread is never blocked on it.
        self._lock = threading.Lock()

    @classmethod
    def get(
        cls,
        domain: str,
        use_https: bool = True,
        debug_logger: Callable[..., None] | None = None,
    ) -> OpenidConfigLoader:
        """
        Return the shared loader for a domain, creating it on first use.

        Args:
            domain:       The domain of the OIDC provider.
            use_https:    If falsey, use http instead of https.
            debug_logger: Applied only when the loader is created.
        """
        key = (domain, bool(use_https))
        with _CACHE_LOCK:
            loader = _CACHE.get(key)
            if loader is None:
                loader = cls(domain, use_https=use_https, debug_logger=debug_logger)
                _CACHE[key] = loader
            return loader

    @staticmethod
    def build_openid_config_url(domain: str, use_https: bool = True) -> str:
        """
        Build the discovery URL for a domain.

        Args:
            domain:    The domain of the OIDC provider.
            use_https: Use https by default. If falsey, use http.
        """
        protocol = "https" if use_https else "http"
        return f"{protocol}://{domain}/.well-known/openid-configuration"

    def _load_openid_resource(self, url: str) -> dict:
        """
        Fetch and decode one openid resource, logging the attempt.

        Args:
            url: The URL to fetch.
        """
        self.debug_logger(f"Attempting to fetch from openid resource '{url}'")
        return http.get_json(url)

    @property
    def config(self) -> OpenidConfig:
        """
        The provider's openid-configuration, fetched on first access.
        """
        if self._config is None:
            with self._lock:
                # Re-check inside the lock: another thread may have loaded it while this
                # one waited, and a second fetch would be pure waste.
                if self._config is None:
                    self.debug_logger("Fetching openid configuration")
                    data = self._load_openid_resource(
                        self.build_openid_config_url(self.domain, self.use_https)
                    )
                    self._config = OpenidConfig.from_dict(data, require_https=self.use_https)
        return self._config

    @property
    def jwks(self) -> JWKs:
        """
        The provider's JWKS, fetched on first access.
        """
        if self._jwks is None:
            config = self.config
            with self._lock:
                if self._jwks is None:
                    self.debug_logger("Fetching jwks")
                    data = self._load_openid_resource(config.jwks_uri)
                    self._jwks = JWKs.from_dict(data)
        return self._jwks

    def refresh_jwks(self) -> JWKs:
        """
        Refetch the JWKS, at most once per `JWKS_REFRESH_INTERVAL`.

        Called when a token presents a key id absent from the cached set, which is what a
        provider key rotation looks like from here. Returns the current JWKS either way,
        so a rate limited call is a no-op rather than an error.
        """
        config = self.config
        with self._lock:
            elapsed = time.monotonic() - self._last_refresh_at
            if self._jwks is not None and elapsed < JWKS_REFRESH_INTERVAL:
                self.debug_logger(
                    f"Skipping jwks refresh: last fetch was {elapsed:.1f}s ago, "
                    f"minimum interval is {JWKS_REFRESH_INTERVAL}s"
                )
                return self._jwks

            self.debug_logger("Refreshing jwks")
            data = self._load_openid_resource(config.jwks_uri)
            self._jwks = JWKs.from_dict(data)
            self._last_refresh_at = time.monotonic()
            return self._jwks
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_openid_config_loader.py -v`
Expected: PASS, 13 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/openid_config_loader.py tests/unit/test_openid_config_loader.py
git commit -m "feat: add OpenidConfigLoader with a process-wide cache

Sharing loaders by domain turns 2N HTTP calls for N lockdown scope sets
into 2. A per-loader threading.Lock collapses concurrent cold loads into
one fetch. JWKS refetch on an unknown kid recovers from key rotation
without a restart, rate limited so unknown kids cannot become a request
flood."
```

---

### Task 12: TokenDecoder

**Files:**
- Create: `armasec_lite/token_decoder.py`
- Create: `tests/unit/test_token_decoder.py`

**Interfaces:**
- Consumes: `armasec_lite.jwt.{decode, get_unverified_header}`, `armasec_lite.schemas.{JWK, JWKs}`, `armasec_lite.token_payload.TokenPayload`, `armasec_lite.exceptions.{AuthenticationError, PayloadMappingError}`, `armasec_lite.utilities.{log_error, noop}`.
- Produces:
  - `TokenDecoder(jwks, algorithm="RS256", debug_logger=None, decode_options_override=None, permission_extractor=None, jwks_refresher=None)`.
  - `get_decode_key(token: str) -> JWK`
  - `decode(token: str, **claims) -> TokenPayload`
  - `extract_keycloak_permissions(decoded_token: dict) -> list[str]`

`jwks_refresher` is the only signature change from upstream: upstream receives a `JWKs`
value and so has no way to ask for a fresh one.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_token_decoder.py`:

```python
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from armasec_lite.exceptions import AuthenticationError, PayloadMappingError
from armasec_lite.jwt import b64url_encode
from armasec_lite.schemas import JWK, JWKs
from armasec_lite.token_decoder import TokenDecoder, extract_keycloak_permissions


def _sign(rsa_private, claims, kid="rsa-test"):
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": kid}).encode())
    body = b64url_encode(json.dumps(claims).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64url_encode(sig)}"


@pytest.fixture
def jwks(rsa_jwk):
    return JWKs(keys=(rsa_jwk,))


@pytest.fixture
def now():
    return int(time.time())


def test_get_decode_key_matches_on_kid(jwks, rsa_private, rsa_jwk, now):
    decoder = TokenDecoder(jwks)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    assert decoder.get_decode_key(token) is rsa_jwk


def test_get_decode_key_raises_without_a_kid(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks)
    head = b64url_encode(json.dumps({"alg": "RS256"}).encode())
    body = b64url_encode(json.dumps({"sub": "abc"}).encode())
    with pytest.raises(AuthenticationError, match="kid"):
        decoder.get_decode_key(f"{head}.{body}.sig")


def test_get_decode_key_raises_on_an_unknown_kid(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60}, kid="unknown")
    with pytest.raises(AuthenticationError, match="matching jwk"):
        decoder.get_decode_key(token)


def test_get_decode_key_retries_through_the_refresher(rsa_private, rsa_jwk, now):
    """A rotated kid recovers when a refresher is wired in."""
    rotated = JWK.from_dict({"kty": "RSA", "kid": "rotated", "n": rsa_jwk.n, "e": rsa_jwk.e})
    calls = []

    def _refresh():
        calls.append(1)
        return JWKs(keys=(rotated,))

    decoder = TokenDecoder(JWKs(keys=(rsa_jwk,)), jwks_refresher=_refresh)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60}, kid="rotated")
    assert decoder.get_decode_key(token).kid == "rotated"
    assert len(calls) == 1


def test_get_decode_key_refresher_is_tried_only_once(rsa_private, rsa_jwk, now):
    calls = []

    def _refresh():
        calls.append(1)
        return JWKs(keys=(rsa_jwk,))

    decoder = TokenDecoder(JWKs(keys=(rsa_jwk,)), jwks_refresher=_refresh)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60}, kid="never-there")
    with pytest.raises(AuthenticationError, match="matching jwk"):
        decoder.get_decode_key(token)
    assert len(calls) == 1


def test_decode_builds_a_token_payload(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "permissions": ["read:x"]})
    payload = decoder.decode(token)
    assert payload.sub == "abc"
    assert payload.permissions == ["read:x"]
    assert payload.original_token == token


def test_decode_applies_the_permission_extractor(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, permission_extractor=extract_keycloak_permissions)
    token = _sign(
        rsa_private,
        {
            "sub": "abc",
            "exp": now + 60,
            "azp": "my-client",
            "resource_access": {"my-client": {"roles": ["read:stuff"]}},
        },
    )
    assert decoder.decode(token).permissions == ["read:stuff"]


def test_decode_raises_payload_mapping_error_when_the_extractor_misses(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, permission_extractor=extract_keycloak_permissions)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "azp": "my-client"})
    with pytest.raises(PayloadMappingError):
        decoder.decode(token)


def test_decode_honors_the_options_override(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, decode_options_override={"verify_exp": False})
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 60})
    assert decoder.decode(token).sub == "abc"


def test_decode_merges_call_options_over_the_override(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, decode_options_override={"verify_exp": False})
    token = _sign(rsa_private, {"sub": "abc", "exp": now - 60})
    with pytest.raises(AuthenticationError):
        decoder.decode(token, options={"verify_exp": True})


def test_decode_passes_audience_through(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "aud": "my-api"})
    assert decoder.decode(token, audience="my-api").sub == "abc"
    with pytest.raises(AuthenticationError):
        decoder.decode(token, audience="other-api")


def test_decode_restricts_the_algorithm_to_the_configured_one(jwks, rsa_private, now):
    decoder = TokenDecoder(jwks, algorithm="ES256")
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60})
    with pytest.raises(AuthenticationError, match="not permitted"):
        decoder.decode(token)


def test_extract_keycloak_permissions_reads_the_nested_roles():
    decoded = {"azp": "my-client", "resource_access": {"my-client": {"roles": ["read:stuff"]}}}
    assert extract_keycloak_permissions(decoded) == ["read:stuff"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_token_decoder.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.token_decoder'`

- [ ] **Step 3: Write `armasec_lite/token_decoder.py`**

```python
"""
Turns a compact JWT plus a JWKS into a verified TokenPayload.
"""

from __future__ import annotations

from functools import partial
from typing import Any, Callable

from armasec_lite import jwt
from armasec_lite.exceptions import AuthenticationError, PayloadMappingError
from armasec_lite.schemas import JWK, JWKs
from armasec_lite.token_payload import TokenPayload
from armasec_lite.utilities import log_error, noop


class TokenDecoder:
    """
    Decodes tokens against a set of JSON web keys.
    """

    def __init__(
        self,
        jwks: JWKs,
        algorithm: str = "RS256",
        debug_logger: Callable[..., None] | None = None,
        decode_options_override: dict[str, Any] | None = None,
        permission_extractor: Callable[[dict[str, Any]], list[str]] | None = None,
        jwks_refresher: Callable[[], JWKs] | None = None,
    ):
        """
        Initialize a TokenDecoder.

        Args:
            jwks:                    The public keys available for decoding.
            algorithm:               The only algorithm accepted. Defaults to RS256.
            debug_logger:            A callable such as `logger.debug`.
            decode_options_override: Options overriding the default decode behavior, for
                                     example `{"verify_exp": False}`.
            permission_extractor:    Optional function that extracts permissions from the
                                     decoded token when they are not a top level claim.

                                     Consider the example token:

                                     ```
                                     {
                                       "exp": 1728627701,
                                       "sub": "dfa64115-40b5-46ab-924c-c376e73f631d",
                                       "azp": "my-client",
                                       "resource_access": {
                                         "my-client": {"roles": ["read:stuff"]}
                                       }
                                     }
                                     ```

                                     Permissions live at `resource_access.my-client.roles`,
                                     so an extractor would be:

                                     ```
                                     def my_extractor(decoded_token: dict) -> list[str]:
                                         resource_key = decoded_token["azp"]
                                         return decoded_token["resource_access"][resource_key]["roles"]
                                     ```
            jwks_refresher:          Optional callable returning a freshly fetched JWKs.
                                     Consulted once when a token's `kid` is absent from the
                                     current set, which is what a provider key rotation
                                     looks like from here.
        """
        self.algorithm = algorithm
        self.jwks = jwks
        self.debug_logger = debug_logger if debug_logger else noop
        self.decode_options_override = decode_options_override if decode_options_override else {}
        self.permission_extractor = permission_extractor
        self.jwks_refresher = jwks_refresher

    def _find_key(self, kid: str) -> JWK | None:
        """
        Search the current JWKS for a key with the given id.

        Args:
            kid: The key id from the token's unverified header.
        """
        for jwk in self.jwks.keys:
            self.debug_logger(f"Checking key in jwk: {jwk}")
            if jwk.kid == kid:
                self.debug_logger("Key matches unverified header. Using as decode key.")
                return jwk
        return None

    def get_decode_key(self, token: str) -> JWK:
        """
        Find the public key matching a token's `kid`.

        The `kid` is read from the unverified header, so it is attacker controlled. It is
        used to select a key and for nothing else; the key then has to actually verify the
        signature.

        Args:
            token: The token whose key should be found.
        """
        self.debug_logger("Getting decode key from JWKs")
        unverified_header = jwt.get_unverified_header(token)
        self.debug_logger(f"Extracted unverified header: {unverified_header}")
        kid = unverified_header.get("kid")
        AuthenticationError.require_condition(
            kid,
            "Unverified header doesn't contain 'kid'...not sure how this happened",
        )

        jwk = self._find_key(str(kid))
        if jwk is not None:
            return jwk

        # An unknown kid is what a provider key rotation looks like from here, so try
        # once for a fresh key set before giving up. The refresher is rate limited, so
        # this cannot become a request flood.
        if self.jwks_refresher is not None:
            self.debug_logger(f"No key matched kid {kid!r}; refreshing jwks")
            self.jwks = self.jwks_refresher()
            jwk = self._find_key(str(kid))
            if jwk is not None:
                return jwk

        raise AuthenticationError("Could not find a matching jwk")

    def decode(self, token: str, **claims: Any) -> TokenPayload:
        """
        Decode a JWT into a TokenPayload, checking signatures and claims.

        Args:
            token:  The token to decode.
            claims: Additional constraints, such as `audience` or `issuer`. May include an
                    `options` dict merged over `decode_options_override`.
        """
        self.debug_logger(f"Attempting to decode '{token}'")
        self.debug_logger(f"  checking claims: {claims}")

        options = {**self.decode_options_override, **claims.pop("options", {})}

        with AuthenticationError.handle_errors(
            "Failed to decode token string",
            do_except=partial(log_error, self.debug_logger),
        ):
            payload_dict = jwt.decode(
                token,
                self.get_decode_key(token),
                [self.algorithm],
                options=options,
                **claims,
            )
            self.debug_logger(f"Raw payload dictionary is {payload_dict}")

        with PayloadMappingError.handle_errors(
            "Failed to map decoded token to TokenPayload",
            do_except=partial(log_error, self.debug_logger),
        ):
            if self.permission_extractor is not None:
                self.debug_logger("Attempting to extract permissions.")
                payload_dict = {
                    **payload_dict,
                    "permissions": self.permission_extractor(payload_dict),
                }
                self.debug_logger(f"Payload dictionary with extracted permissions is {payload_dict}")

            self.debug_logger("Attempting to convert to TokenPayload")
            token_payload = TokenPayload.from_claims(payload_dict, original_token=token)
            self.debug_logger(f"Built token_payload as {token_payload}")
            return token_payload


def extract_keycloak_permissions(decoded_token: dict[str, Any]) -> list[str]:
    """
    Extract permissions from a Keycloak token.

    Keycloak nests a client's roles inside the "resource_access" claim rather than
    exposing them as a top level claim. Given this token:

    ```
    {
      "exp": 1728627701,
      "sub": "dfa64115-40b5-46ab-924c-c376e73f631d",
      "azp": "my-client",
      "resource_access": {
        "my-client": {"roles": ["read:stuff"]}
      }
    }
    ```

    this extractor returns `["read:stuff"]`.

    Args:
        decoded_token: The decoded token dictionary.
    """
    resource_key = decoded_token["azp"]
    return list(decoded_token["resource_access"][resource_key]["roles"])
```

Note that `AuthenticationError.handle_errors` does not re-wrap `ArmasecError` subclasses,
so the specific error types from `jwt.py` (`ExpiredSignatureError`, `InvalidAudienceError`
and the rest) propagate intact and keep their 401 status.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_token_decoder.py -v`
Expected: PASS, 13 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/token_decoder.py tests/unit/test_token_decoder.py
git commit -m "feat: add TokenDecoder

Adds jwks_refresher, the one signature change from upstream: upstream takes
a JWKs value and so cannot ask for a fresh one when a kid is unknown."
```

---

### Task 13: TokenManager

**Files:**
- Create: `armasec_lite/token_manager.py`
- Create: `tests/unit/test_token_manager.py`

**Interfaces:**
- Consumes: `armasec_lite.token_decoder.TokenDecoder`, `armasec_lite.schemas.OpenidConfig`, `armasec_lite.token_payload.TokenPayload`, `armasec_lite.exceptions.AuthenticationError`, `armasec_lite.utilities.noop`.
- Produces: `TokenManager(openid_config, token_decoder, audience=None, ignore_audience=False, verify_issuer=True, debug_logger=None, decode_options_override=None)` with class attributes `auth_scheme = "bearer"` and `header_key = "Authorization"`, methods `unpack_token_from_header(headers) -> str` and `extract_token_payload(headers) -> TokenPayload`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_token_manager.py`:

```python
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from starlette.datastructures import Headers

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.jwt import b64url_encode
from armasec_lite.schemas import JWKs, OpenidConfig
from armasec_lite.token_decoder import TokenDecoder
from armasec_lite.token_manager import TokenManager

ISSUER = "https://auth.example.com"


def _sign(rsa_private, claims, kid="rsa-test"):
    head = b64url_encode(json.dumps({"alg": "RS256", "kid": kid}).encode())
    body = b64url_encode(json.dumps(claims).encode())
    sig = rsa_private.sign(f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64url_encode(sig)}"


@pytest.fixture
def openid_config():
    return OpenidConfig.from_dict({"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks"})


@pytest.fixture
def decoder(rsa_jwk):
    return TokenDecoder(JWKs(keys=(rsa_jwk,)))


@pytest.fixture
def now():
    return int(time.time())


def test_class_attributes_match_upstream():
    assert TokenManager.auth_scheme == "bearer"
    assert TokenManager.header_key == "Authorization"


def test_unpack_token_from_a_dict(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    assert manager.unpack_token_from_header({"Authorization": "Bearer abc.def.ghi"}) == "abc.def.ghi"


def test_unpack_token_from_starlette_headers(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    headers = Headers({"authorization": "Bearer abc.def.ghi"})
    assert manager.unpack_token_from_header(headers) == "abc.def.ghi"


def test_unpack_token_accepts_any_scheme_casing(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    assert manager.unpack_token_from_header({"Authorization": "bEaReR tok"}) == "tok"


def test_unpack_token_requires_the_header(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    with pytest.raises(AuthenticationError, match="Could not find auth header"):
        manager.unpack_token_from_header({})


def test_unpack_token_requires_a_scheme_and_a_token(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    with pytest.raises(AuthenticationError):
        manager.unpack_token_from_header({"Authorization": "Bearer"})
    with pytest.raises(AuthenticationError):
        manager.unpack_token_from_header({"Authorization": ""})


def test_unpack_token_rejects_a_wrong_scheme(openid_config, decoder):
    manager = TokenManager(openid_config, decoder)
    with pytest.raises(AuthenticationError, match="Invalid auth scheme"):
        manager.unpack_token_from_header({"Authorization": "Basic abc"})


def test_extract_token_payload_decodes(openid_config, decoder, rsa_private, now):
    manager = TokenManager(openid_config, decoder)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": ISSUER})
    payload = manager.extract_token_payload({"Authorization": f"Bearer {token}"})
    assert payload.sub == "abc"


def test_extract_token_payload_verifies_the_issuer_by_default(openid_config, decoder, rsa_private, now):
    manager = TokenManager(openid_config, decoder)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": "https://evil.example.com"})
    with pytest.raises(AuthenticationError):
        manager.extract_token_payload({"Authorization": f"Bearer {token}"})


def test_extract_token_payload_can_skip_issuer_verification(openid_config, decoder, rsa_private, now):
    manager = TokenManager(openid_config, decoder, verify_issuer=False)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": "https://evil.example.com"})
    assert manager.extract_token_payload({"Authorization": f"Bearer {token}"}).sub == "abc"


def test_extract_token_payload_checks_the_audience(openid_config, decoder, rsa_private, now):
    manager = TokenManager(openid_config, decoder, audience="my-api")
    good = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": ISSUER, "aud": "my-api"})
    bad = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": ISSUER, "aud": "other"})
    assert manager.extract_token_payload({"Authorization": f"Bearer {good}"}).sub == "abc"
    with pytest.raises(AuthenticationError):
        manager.extract_token_payload({"Authorization": f"Bearer {bad}"})


def test_ignore_audience_skips_verification_when_no_audience_is_set(openid_config, decoder, rsa_private, now):
    manager = TokenManager(openid_config, decoder, ignore_audience=True)
    token = _sign(rsa_private, {"sub": "abc", "exp": now + 60, "iss": ISSUER, "aud": "anything"})
    assert manager.extract_token_payload({"Authorization": f"Bearer {token}"}).sub == "abc"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_token_manager.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.token_manager'`

- [ ] **Step 3: Write `armasec_lite/token_manager.py`**

```python
"""
Extracts a bearer token from request headers and decodes it.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.schemas import OpenidConfig
from armasec_lite.token_decoder import TokenDecoder
from armasec_lite.token_payload import TokenPayload
from armasec_lite.utilities import noop


class TokenManager:
    """
    Unpacks a JWT from request headers and hands it to a TokenDecoder.
    """

    auth_scheme = "bearer"
    header_key = "Authorization"

    def __init__(
        self,
        openid_config: OpenidConfig,
        token_decoder: TokenDecoder,
        audience: str | None = None,
        ignore_audience: bool = False,
        verify_issuer: bool = True,
        debug_logger: Callable[..., None] | None = None,
        decode_options_override: dict[str, Any] | None = None,
    ):
        """
        Initialize a TokenManager.

        Args:
            openid_config:           The provider's configuration, used for the issuer.
            token_decoder:           The decoder used to verify jwts.
            audience:                An optional audience to check in decoded tokens.
            ignore_audience:         If true and audience is None, skip audience checks.
            verify_issuer:           Check the token's `iss` against the provider's issuer.
                                     Upstream armasec never performed this check; pass
                                     False for exact upstream behavior.
            debug_logger:            A callable such as `logger.debug`.
            decode_options_override: Options overriding the default decode behavior.
        """
        self.audience = audience
        self.ignore_audience = ignore_audience
        self.verify_issuer = verify_issuer
        self.debug_logger = debug_logger if debug_logger else noop
        self.decode_options_override = decode_options_override if decode_options_override else {}

        self.openid_config = openid_config
        self.token_decoder = token_decoder

    def unpack_token_from_header(self, headers: Mapping[str, str]) -> str:
        """
        Pull the bearer token out of a request's headers.

        Args:
            headers: The headers to read. Any case-insensitive mapping works, which covers
                     both a plain dict and starlette's Headers.
        """
        self.debug_logger(f"Attempting to unpack token from headers {headers}")
        auth_str = headers.get(self.header_key)
        if auth_str is None:
            # A plain dict is case sensitive, unlike starlette's Headers, so fall back to
            # a scan rather than making callers match our capitalization.
            lowered = self.header_key.lower()
            auth_str = next(
                (value for key, value in headers.items() if key.lower() == lowered), None
            )
        self.debug_logger(f"Got {auth_str} using header key {self.header_key}")
        AuthenticationError.require_condition(
            auth_str,
            f"Could not find auth header at {self.header_key}",
        )
        auth_str = str(auth_str)

        self.debug_logger("Attempting to get authorization scheme")
        scheme, _, token = auth_str.partition(" ")
        token = token.strip()
        AuthenticationError.require_condition(
            scheme and token,
            f"Could not extract scheme ('{self.auth_scheme}') from token '{token}'",
        )
        AuthenticationError.require_condition(
            scheme.lower() == self.auth_scheme,
            f"Invalid auth scheme '{scheme}': expected '{self.auth_scheme}'",
        )
        return token

    def extract_token_payload(self, headers: Mapping[str, str]) -> TokenPayload:
        """
        Retrieve a token from request headers and decode it into a TokenPayload.

        Args:
            headers: The headers to read the token from.
        """
        token = self.unpack_token_from_header(headers)
        issuer = self.openid_config.issuer if self.verify_issuer else None

        if self.ignore_audience and self.audience is None:
            self.debug_logger(
                "Bypassing audience verification (ignore_audience=True, audience=None)"
            )
            return self.token_decoder.decode(
                token,
                issuer=issuer,
                options={"verify_aud": False},
            )

        return self.token_decoder.decode(token, audience=self.audience, issuer=issuer)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_token_manager.py -v`
Expected: PASS, 12 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/token_manager.py tests/unit/test_token_manager.py
git commit -m "feat: add TokenManager

Drops fastapi.security.utils.get_authorization_scheme_param for a partition,
and threads the provider's issuer through to the decoder, which upstream
loaded but never checked."
```

---

### Task 14: The plugin system

**Files:**
- Create: `armasec_lite/pluggable/__init__.py`
- Create: `armasec_lite/pluggable/hookspecs.py`
- Create: `tests/unit/test_pluggable.py`

**Interfaces:**
- Consumes: nothing beyond the standard library.
- Produces:
  - `hookimpl(func)` decorator, setting the marker attribute `_armasec_hookimpl`.
  - `PluginManager()` with `register(plugin, name=None)`, `unregister(plugin)`, `load_entry_points(group="armasec")`, `get_plugins()`, and a `hook` relay exposing `armasec_plugin_check(**kwargs)`.
  - `plugin_manager`, the module-level singleton, with entry points already loaded.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_pluggable.py`:

```python
import pytest

from armasec_lite.exceptions import ArmasecError
from armasec_lite.pluggable import PluginManager, hookimpl


class _Sentinel:
    pass


def test_hookimpl_marks_a_function():
    @hookimpl
    def armasec_plugin_check():
        pass

    assert getattr(armasec_plugin_check, "_armasec_hookimpl", False) is True


def test_registered_hook_is_called():
    calls = []

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            calls.append(token_payload)

    manager = PluginManager()
    manager.register(Plugin())
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == ["p"]


def test_only_declared_keyword_arguments_are_passed():
    """
    pluggy passes an implementation only the arguments it declares. The documented
    example plugin declares just token_payload, so passing it request and debug_logger
    would be a TypeError.
    """
    seen = {}

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, request, token_payload):
            seen["request"] = request
            seen["token_payload"] = token_payload

    manager = PluginManager()
    manager.register(Plugin())
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert seen == {"request": "r", "token_payload": "p"}


def test_an_implementation_taking_kwargs_receives_everything():
    seen = {}

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, **kwargs):
            seen.update(kwargs)

    manager = PluginManager()
    manager.register(Plugin())
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert set(seen) == {"request", "token_payload", "debug_logger"}


def test_a_module_can_be_registered():
    import types

    module = types.ModuleType("fake_plugin")
    calls = []

    @hookimpl
    def armasec_plugin_check(token_payload):
        calls.append(token_payload)

    module.armasec_plugin_check = armasec_plugin_check

    manager = PluginManager()
    manager.register(module)
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == ["p"]


def test_unmarked_callables_are_not_registered():
    calls = []

    class Plugin:
        def armasec_plugin_check(self, token_payload):
            calls.append(token_payload)

    manager = PluginManager()
    manager.register(Plugin())
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == []


def test_exceptions_propagate_because_raising_is_how_a_plugin_denies():
    class Denier:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            raise ArmasecError("denied")

    manager = PluginManager()
    manager.register(Denier())
    with pytest.raises(ArmasecError, match="denied"):
        manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)


def test_hooks_are_called_in_lifo_order():
    order = []

    def _make(name):
        class Plugin:
            @hookimpl
            def armasec_plugin_check(self, token_payload):
                order.append(name)

        return Plugin()

    manager = PluginManager()
    manager.register(_make("first"))
    manager.register(_make("second"))
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert order == ["second", "first"]


def test_unregister_removes_a_plugin():
    calls = []

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            calls.append(token_payload)

    plugin = Plugin()
    manager = PluginManager()
    manager.register(plugin)
    manager.unregister(plugin)
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == []


def test_registering_the_same_plugin_twice_is_idempotent():
    calls = []

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            calls.append(1)

    plugin = Plugin()
    manager = PluginManager()
    manager.register(plugin)
    manager.register(plugin)
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == [1]


def test_no_plugins_is_a_no_op():
    PluginManager().hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_pluggable.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.pluggable'`

- [ ] **Step 3: Write `armasec_lite/pluggable/hookspecs.py`**

```python
"""
The hook specification for armasec plugins.
"""

from __future__ import annotations

from typing import Any, Callable

#: The one hook name armasec dispatches. Kept as a constant so the manager and the
#: documentation cannot disagree about it.
HOOK_NAME = "armasec_plugin_check"


def armasec_plugin_check(
    request: Any,
    token_payload: Any,
    debug_logger: Callable[..., None],
) -> None:
    """
    Check a token payload for validity against a request.

    If the check fails, raise an ArmasecError or a subclass of it. The raised error's
    `status_code` and `detail` become the response, so a plugin can answer with 402 or
    any other code it likes.

    An implementation receives only the arguments it declares, so a plugin that cares
    about nothing but the token can be written as
    `def armasec_plugin_check(token_payload): ...`.

    Args:
        request:       The original request made to the secured endpoint.
        token_payload: The contents of the auth token.
        debug_logger:  A callable such as `logger.debug`.
    """
```

- [ ] **Step 4: Write `armasec_lite/pluggable/__init__.py`**

```python
"""
A small plugin system, replacing pluggy.

Only one hook exists and only one dispatch strategy is needed, so the fifty lines here
cover what armasec used pluggy for: a marker decorator, registration by module or object,
discovery through entry points, and calling each implementation with just the arguments
it declares.
"""

from __future__ import annotations

import inspect
from importlib.metadata import entry_points
from typing import Any, Callable

from armasec_lite.pluggable.hookspecs import HOOK_NAME, armasec_plugin_check

#: Attribute set on a function by `hookimpl` to mark it as an implementation.
_MARKER = "_armasec_hookimpl"


def hookimpl(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Mark a function as an armasec hook implementation.

    Args:
        func: The function to mark.
    """
    setattr(func, _MARKER, True)
    return func


class _HookRelay:
    """
    Dispatches a hook call to every registered implementation.
    """

    def __init__(self, manager: PluginManager):
        """
        Bind the relay to its manager.

        Args:
            manager: The manager whose implementations should be called.
        """
        self._manager = manager

    def armasec_plugin_check(self, **kwargs: Any) -> None:
        """
        Call every registered `armasec_plugin_check` implementation.

        Implementations are called most recently registered first, matching pluggy, and
        each receives only the keyword arguments it declares. Exceptions propagate,
        because raising is how a plugin denies a request.

        Args:
            kwargs: The full argument set from the hook specification.
        """
        for implementation in self._manager.implementations():
            implementation(**_filter_kwargs(implementation, kwargs))


def _filter_kwargs(func: Callable[..., Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    """
    Reduce a keyword argument set to what a callable actually declares.

    This is the one pluggy behavior armasec depends on. The documented example plugin
    declares only `token_payload`, so handing it `request` and `debug_logger` would be a
    TypeError rather than a working plugin.

    Args:
        func:   The implementation about to be called.
        kwargs: The full argument set.
    """
    signature = inspect.signature(func)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return kwargs
    return {name: value for name, value in kwargs.items() if name in signature.parameters}


class PluginManager:
    """
    Holds registered plugins and dispatches hooks to them.
    """

    def __init__(self) -> None:
        """Create an empty manager."""
        self._plugins: list[Any] = []
        self.hook = _HookRelay(self)

    def register(self, plugin: Any, name: str | None = None) -> None:
        """
        Register a module or object carrying marked hook implementations.

        Registering the same plugin twice is a no-op, so an import executed more than once
        does not double every check.

        Args:
            plugin: The module or object to register.
            name:   Accepted for compatibility with pluggy's signature. Unused.
        """
        if plugin not in self._plugins:
            self._plugins.append(plugin)

    def unregister(self, plugin: Any) -> None:
        """
        Remove a previously registered plugin.

        Args:
            plugin: The module or object to remove.
        """
        if plugin in self._plugins:
            self._plugins.remove(plugin)

    def get_plugins(self) -> list[Any]:
        """Return the registered plugins, in registration order."""
        return list(self._plugins)

    def implementations(self) -> list[Callable[..., Any]]:
        """
        Collect every marked implementation, most recently registered first.
        """
        found: list[Callable[..., Any]] = []
        for plugin in reversed(self._plugins):
            candidate = getattr(plugin, HOOK_NAME, None)
            if candidate is None or not callable(candidate):
                continue
            # A bound method carries the marker on its underlying function.
            target = getattr(candidate, "__func__", candidate)
            if getattr(target, _MARKER, False):
                found.append(candidate)
        return found

    def load_entry_points(self, group: str = "armasec") -> None:
        """
        Register every plugin advertised under an entry point group.

        Args:
            group: The entry point group to search. Defaults to "armasec".
        """
        for entry_point in entry_points(group=group):
            self.register(entry_point.load())


#: The manager armasec dispatches through. Third party plugins are discovered at import.
plugin_manager = PluginManager()
plugin_manager.load_entry_points()

__all__ = ["PluginManager", "armasec_plugin_check", "hookimpl", "plugin_manager"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_pluggable.py -v`
Expected: PASS, 11 tests

- [ ] **Step 6: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 7: Commit**

```bash
git add armasec_lite/pluggable/ tests/unit/test_pluggable.py
git commit -m "feat: add the plugin system

Replaces pluggy with importlib.metadata entry points. Preserves the one
pluggy behavior armasec relies on: an implementation receives only the
keyword arguments it declares, so a plugin taking just token_payload keeps
working."
```

---

### Task 15: TokenSecurity

**Files:**
- Create: `armasec_lite/token_security.py`
- Create: `tests/unit/test_token_security.py`

**Interfaces:**
- Consumes: everything from Tasks 2, 3, 10 through 14.
- Produces:
  - `ManagerConfig` dataclass with `manager: TokenManager` and `domain_config: DomainConfig`.
  - `TokenSecurity(APIKeyBase)` with `__init__(domain_configs, scopes=None, permission_mode=PermissionMode.ALL, debug_logger=None, debug_exceptions=False, skip_plugins=False)` and `async __call__(request) -> TokenPayload`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_token_security.py`:

```python
import json
import time

import pytest
from starlette.datastructures import Headers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import HTTPException

from armasec_lite import openid_config_loader as loader_module
from armasec_lite.exceptions import ArmasecError
from armasec_lite.jwt import b64url_encode
from armasec_lite.openid_config_loader import clear_cache
from armasec_lite.pluggable import hookimpl, plugin_manager
from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_security import TokenSecurity

DOMAIN = "auth.example.com"
ISSUER = f"https://{DOMAIN}"
CONFIG_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/jwks"


class _Request:
    """The only parts of a starlette Request that TokenSecurity touches."""

    def __init__(self, headers: dict):
        self.headers = Headers(headers)


@pytest.fixture(autouse=True)
def reset_cache():
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def fake_get(monkeypatch, rsa_jwk):
    calls: list[str] = []
    jwks_doc = {
        "keys": [
            {"kty": "RSA", "kid": rsa_jwk.kid, "alg": "RS256", "n": rsa_jwk.n, "e": rsa_jwk.e}
        ]
    }
    routes = {CONFIG_URL: {"issuer": ISSUER, "jwks_uri": JWKS_URL}, JWKS_URL: jwks_doc}

    def _get(url, *, timeout=10.0):
        calls.append(url)
        return routes[url]

    monkeypatch.setattr(loader_module.http, "get_json", _get)
    return calls


@pytest.fixture
def make_token(rsa_private):
    def _make(**overrides):
        claims = {
            "sub": "abc",
            "exp": int(time.time()) + 600,
            "iss": ISSUER,
            "permissions": [],
            **overrides,
        }
        head = b64url_encode(json.dumps({"alg": "RS256", "kid": "rsa-test"}).encode())
        body = b64url_encode(json.dumps(claims).encode())
        sig = rsa_private.sign(
            f"{head}.{body}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{head}.{body}.{b64url_encode(sig)}"

    return _make


def _security(**kwargs):
    kwargs.setdefault("domain_configs", [DomainConfig(domain=DOMAIN)])
    kwargs.setdefault("skip_plugins", True)
    return TokenSecurity(**kwargs)


async def test_call_returns_the_token_payload(fake_get, make_token):
    security = _security()
    payload = await security(_Request({"Authorization": f"Bearer {make_token()}"}))
    assert payload.sub == "abc"


async def test_call_raises_401_without_a_token(fake_get):
    security = _security()
    with pytest.raises(HTTPException) as info:
        await security(_Request({}))
    assert info.value.status_code == 401
    assert info.value.headers["WWW-Authenticate"] == "Bearer"


async def test_call_raises_401_for_an_expired_token(fake_get, make_token):
    security = _security()
    token = make_token(exp=int(time.time()) - 60)
    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert info.value.status_code == 401


async def test_call_raises_403_when_a_required_scope_is_missing(fake_get, make_token):
    security = _security(scopes=["read:x", "write:x"])
    token = make_token(permissions=["read:x"])
    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert info.value.status_code == 403


async def test_permission_mode_all_requires_every_scope(fake_get, make_token):
    security = _security(scopes=["read:x", "write:x"], permission_mode=PermissionMode.ALL)
    token = make_token(permissions=["read:x", "write:x", "extra"])
    assert (await security(_Request({"Authorization": f"Bearer {token}"}))).sub == "abc"


async def test_permission_mode_some_requires_one_scope(fake_get, make_token):
    security = _security(scopes=["read:x", "write:x"], permission_mode=PermissionMode.SOME)
    token = make_token(permissions=["write:x"])
    assert (await security(_Request({"Authorization": f"Bearer {token}"}))).sub == "abc"


async def test_permission_mode_some_rejects_no_overlap(fake_get, make_token):
    security = _security(scopes=["read:x"], permission_mode=PermissionMode.SOME)
    token = make_token(permissions=["unrelated"])
    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert info.value.status_code == 403


async def test_match_keys_accepts_a_matching_scalar(fake_get, make_token):
    security = _security(domain_configs=[DomainConfig(domain=DOMAIN, match_keys={"tier": "gold"})])
    token = make_token(tier="gold")
    assert (await security(_Request({"Authorization": f"Bearer {token}"}))).sub == "abc"


async def test_match_keys_rejects_a_mismatched_scalar(fake_get, make_token):
    security = _security(domain_configs=[DomainConfig(domain=DOMAIN, match_keys={"tier": "gold"})])
    token = make_token(tier="bronze")
    with pytest.raises(HTTPException) as info:
        await security(_Request({"Authorization": f"Bearer {token}"}))
    assert info.value.status_code == 403


async def test_match_keys_handles_booleans_by_identity(fake_get, make_token):
    security = _security(
        domain_configs=[DomainConfig(domain=DOMAIN, match_keys={"verified": True})]
    )
    assert (
        await security(_Request({"Authorization": f"Bearer {make_token(verified=True)}"}))
    ).sub == "abc"
    with pytest.raises(HTTPException):
        await security(_Request({"Authorization": f"Bearer {make_token(verified=1)}"}))


async def test_match_keys_intersects_collections(fake_get, make_token):
    security = _security(
        domain_configs=[DomainConfig(domain=DOMAIN, match_keys={"groups": ["admins", "ops"]})]
    )
    token = make_token(groups=["ops", "other"])
    assert (await security(_Request({"Authorization": f"Bearer {token}"}))).sub == "abc"


async def test_debug_exceptions_reraises_the_original(fake_get, make_token):
    security = _security(debug_exceptions=True)
    with pytest.raises(ArmasecError):
        await security(_Request({}))


async def test_managers_are_loaded_once_across_calls(fake_get, make_token):
    security = _security()
    request = _Request({"Authorization": f"Bearer {make_token()}"})
    await security(request)
    await security(request)
    assert fake_get.count(CONFIG_URL) == 1
    assert fake_get.count(JWKS_URL) == 1


async def test_two_security_instances_share_the_loader_cache(fake_get, make_token):
    """This is the fix for upstream's 2N HTTP calls for N lockdown scope sets."""
    request = _Request({"Authorization": f"Bearer {make_token()}"})
    await _security(scopes=["a"])(request)
    await _security(scopes=["b"])(request)
    assert fake_get.count(CONFIG_URL) == 1
    assert fake_get.count(JWKS_URL) == 1


async def test_a_plugin_can_deny(fake_get, make_token):
    class Denier(ArmasecError):
        status_code = 402
        detail = "Payment required"

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            raise Denier("not subscribed")

    plugin = Plugin()
    plugin_manager.register(plugin)
    try:
        security = _security(skip_plugins=False)
        with pytest.raises(HTTPException) as info:
            await security(_Request({"Authorization": f"Bearer {make_token()}"}))
        assert info.value.status_code == 402
    finally:
        plugin_manager.unregister(plugin)


async def test_skip_plugins_bypasses_the_hook(fake_get, make_token):
    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            raise ArmasecError("should not run")

    plugin = Plugin()
    plugin_manager.register(plugin)
    try:
        security = _security(skip_plugins=True)
        assert (
            await security(_Request({"Authorization": f"Bearer {make_token()}"}))
        ).sub == "abc"
    finally:
        plugin_manager.unregister(plugin)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_token_security.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.token_security'`

- [ ] **Step 3: Write `armasec_lite/token_security.py`**

```python
"""
The FastAPI injectable that enforces authentication and authorization on a route.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from fastapi import HTTPException, status
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.api_key import APIKeyBase
from starlette.requests import Request

from armasec_lite.exceptions import AuthenticationError, AuthorizationError
from armasec_lite.openid_config_loader import OpenidConfigLoader
from armasec_lite.pluggable import plugin_manager
from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_decoder import TokenDecoder
from armasec_lite.token_manager import TokenManager
from armasec_lite.token_payload import TokenPayload
from armasec_lite.utilities import noop, unwrap


@dataclass
class ManagerConfig:
    """
    A TokenManager paired with the domain configuration it was built from.

    Attributes:
        manager:       The TokenManager used to decode tokens for this domain.
        domain_config: The configuration for the openid server.
    """

    manager: TokenManager
    domain_config: DomainConfig


class TokenSecurity(APIKeyBase):
    """
    An injectable Security class that returns a TokenPayload when used with Depends().
    """

    def __init__(
        self,
        domain_configs: list[DomainConfig],
        scopes: Iterable[str] | None = None,
        permission_mode: PermissionMode = PermissionMode.ALL,
        debug_logger: Callable[..., None] | None = None,
        debug_exceptions: bool = False,
        skip_plugins: bool = False,
    ):
        """
        Initialize the TokenSecurity instance.

        Args:
            domain_configs:   Domain configurations to authenticate tokens against.
            scopes:           Optional permission scopes that should be checked.
            permission_mode:  How the scopes are matched. ALL or SOME.
            debug_logger:     A callable such as `logger.debug`.
            debug_exceptions: If True, raise original exceptions instead of translating
                              them into HTTPExceptions. Testing and debugging only.
            skip_plugins:     If True, do not evaluate plugin validators.
        """
        self.domain_configs = domain_configs
        self.scopes = scopes
        self.permission_mode = permission_mode

        self.debug_logger = debug_logger if debug_logger else noop
        self.debug_exceptions = debug_exceptions
        self.skip_plugins = skip_plugins

        self.model: APIKey = APIKey(
            **{"in": APIKeyIn.header},  # type: ignore[arg-type]
            name=TokenManager.header_key,
            description=self.__class__.__doc__,
        )
        self.scheme_name = self.__class__.__name__

        # Lazily populated on the first request that reaches this instance.
        self.managers: list[ManagerConfig] = []

    def _http_exception(self, err: Exception, default_status: int) -> HTTPException:
        """
        Translate an internal error into the response a client should see.

        Args:
            err:            The error raised during validation.
            default_status: The status to use when the error carries none.
        """
        return HTTPException(
            status_code=getattr(err, "status_code", default_status),
            detail=getattr(err, "detail", "Not authenticated"),
            headers={"WWW-Authenticate": "Bearer"},
        )

    async def __call__(self, request: Request) -> TokenPayload:
        """
        Validate a request, returning its token payload or raising an HTTPException.

        Called by FastAPI's dependency injection when this instance is injected with
        Depends(). The first call for a given domain loads the provider's configuration
        and keys. That load is synchronous network work, so it runs in an executor rather
        than on the event loop. Upstream armasec calls synchronous `httpx.get` directly
        inside this coroutine, which stalls every other request in the process, including
        ones that need no authentication at all.

        Args:
            request: The FastAPI request to check for secure access.
        """
        if not self.managers:
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(None, self._load_all_managers)
            except Exception as err:
                if self.debug_exceptions:
                    raise
                raise self._http_exception(err, status.HTTP_401_UNAUTHORIZED) from err

        try:
            token_payload = self._extract_token_payload_from_manager(request)
        except Exception as err:
            if self.debug_exceptions:
                raise
            raise self._http_exception(err, status.HTTP_401_UNAUTHORIZED) from err

        if self.scopes:
            try:
                self._check_scopes(token_payload)
            except Exception as err:
                if self.debug_exceptions:
                    raise
                raise self._http_exception(err, status.HTTP_403_FORBIDDEN) from err

        if not self.skip_plugins:
            self.debug_logger("Applying plugin checks")
            try:
                plugin_manager.hook.armasec_plugin_check(
                    request=request,
                    token_payload=token_payload,
                    debug_logger=self.debug_logger,
                )
            except Exception as err:
                if self.debug_exceptions:
                    raise
                raise self._http_exception(err, status.HTTP_403_FORBIDDEN) from err

        return token_payload

    def _check_scopes(self, token_payload: TokenPayload) -> None:
        """
        Compare the route's scopes against the token's permissions.

        Args:
            token_payload: The decoded token.
        """
        token_permissions = set(token_payload.permissions)
        my_permissions = set(self.scopes or ())

        self.debug_logger(
            unwrap(
                f"""
                Checking my permissions {my_permissions} against token_permissions
                {token_permissions} using PermissionMode {self.permission_mode}
                """
            )
        )

        if self.permission_mode == PermissionMode.ALL:
            AuthorizationError.require_condition(
                my_permissions - token_permissions == set(),
                unwrap(
                    f"""
                    Token permissions {token_permissions} missing some required permissions
                    {my_permissions - token_permissions}
                    """
                ),
            )
        elif self.permission_mode == PermissionMode.SOME:
            AuthorizationError.require_condition(
                token_permissions & my_permissions,
                unwrap(
                    f"""
                    Token permissions {token_permissions} missing at least
                    one required permissions {my_permissions}
                    """
                ),
            )
        else:
            raise AuthorizationError(f"Unknown permission_mode: {self.permission_mode}")

    def _load_all_managers(self) -> None:
        """
        Build a TokenManager for each configured domain, skipping ones that fail.
        """
        if self.managers:
            return

        for domain_config in self.domain_configs:
            try:
                self.managers.append(
                    ManagerConfig(
                        manager=self._load_manager(domain_config),
                        domain_config=domain_config,
                    )
                )
            except AuthenticationError:
                self.debug_logger(f"Failed to match JWK against domain {domain_config.domain}")
            except Exception as err:
                self.debug_logger(f"Exception caught: {err.__class__.__name__}")

        AuthenticationError.require_condition(
            len(self.managers) > 0,
            "Not authenticated: couldn't load any TokenManager instance",
        )

    def _load_manager(self, domain_config: DomainConfig) -> TokenManager:
        """
        Build one TokenManager from a shared, cached loader.

        Args:
            domain_config: The domain to build a manager for.
        """
        self.debug_logger(f"Lazy loading TokenManager for domain {domain_config.domain}")
        # The shared loader is what turns 2N HTTP calls for N lockdown scope sets into 2.
        loader = OpenidConfigLoader.get(
            domain_config.domain,
            use_https=domain_config.use_https,
            debug_logger=self.debug_logger,
        )
        decoder = TokenDecoder(
            loader.jwks,
            domain_config.algorithm,
            debug_logger=self.debug_logger,
            permission_extractor=domain_config.permission_extractor,
            jwks_refresher=loader.refresh_jwks,
        )
        return TokenManager(
            loader.config,
            decoder,
            audience=domain_config.audience,
            ignore_audience=domain_config.ignore_audience,
            verify_issuer=domain_config.verify_issuer,
            debug_logger=self.debug_logger,
        )

    def _check_match_keys(self, token_payload: TokenPayload, domain_config: DomainConfig) -> None:
        """
        Require the configured key/value pairs to be present in the token.

        Args:
            token_payload: The decoded token.
            domain_config: The domain whose match_keys should be enforced.
        """
        message = "Not authorized: token doesn't contain necessary key-value pairs"
        for key_to_match, value_to_match in domain_config.match_keys.items():
            actual = getattr(token_payload, key_to_match, None)
            if isinstance(value_to_match, bool):
                # Identity, not equality: `1 == True` in Python, and a token carrying 1
                # where True is required should not pass.
                AuthorizationError.require_condition(actual is value_to_match, message)
            elif isinstance(value_to_match, (str, int, float)):
                AuthorizationError.require_condition(actual == value_to_match, message)
            else:
                AuthorizationError.require_condition(
                    bool(set(actual or ()) & set(value_to_match)), message
                )

    def _extract_token_payload_from_manager(self, request: Request) -> TokenPayload:
        """
        Try each loaded manager until one decodes the request's token.

        Args:
            request: The request whose headers carry the token.
        """
        self._load_all_managers()

        last_error: Exception | None = None
        for manager_config in self.managers:
            try:
                token_payload = manager_config.manager.extract_token_payload(request.headers)
            except Exception as err:
                self.debug_logger(f"Exception caught: {err.__class__.__name__}")
                last_error = err
                continue

            self._check_match_keys(token_payload, manager_config.domain_config)
            return token_payload

        if last_error is not None:
            raise last_error
        raise AuthenticationError(
            "Not authenticated: could not find matching JWK with any input domain"
            " or token is malformed"
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_token_security.py -v`
Expected: PASS, 16 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/token_security.py tests/unit/test_token_security.py
git commit -m "feat: add TokenSecurity

The cold load runs in an executor instead of on the event loop. Upstream
calls synchronous httpx.get inside this coroutine, which stalls every other
request in the process, including ones needing no authentication.

Also propagates the real decode error rather than losing it: upstream
swallows every manager's exception and then asserts the payload is not None,
which surfaces as a bare AttributeError."
```

---

### Task 16: The Armasec factory

**Files:**
- Create: `armasec_lite/armasec.py`
- Create: `tests/unit/test_armasec.py`

**Interfaces:**
- Consumes: `armasec_lite.schemas.{DomainConfig, PermissionMode}`, `armasec_lite.token_security.TokenSecurity`, `armasec_lite.utilities.noop`.
- Produces: `Armasec(domain_configs=None, debug_logger=noop, debug_exceptions=False, **kwargs)` with `lockdown(*scopes, permission_mode=PermissionMode.ALL, skip_plugins=False)`, `lockdown_all(*scopes, skip_plugins=False)`, `lockdown_some(*scopes, skip_plugins=False)`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_armasec.py`:

```python
import pytest
from fastapi import HTTPException

from armasec_lite.armasec import Armasec
from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_security import TokenSecurity

DOMAIN = "auth.example.com"


def test_kwargs_build_a_single_domain_config():
    armasec = Armasec(domain=DOMAIN, audience="my-api")
    assert len(armasec.domain_configs) == 1
    assert armasec.domain_configs[0].domain == DOMAIN
    assert armasec.domain_configs[0].audience == "my-api"


def test_domain_configs_list_is_used_when_no_domain_kwarg():
    configs = [DomainConfig(domain="one.example.com"), DomainConfig(domain="two.example.com")]
    assert Armasec(domain_configs=configs).domain_configs == configs


def test_no_domain_raises_422():
    with pytest.raises(HTTPException) as info:
        Armasec()
    assert info.value.status_code == 422
    assert "No domain was input" in str(info.value.detail)


def test_lockdown_returns_a_token_security():
    security = Armasec(domain=DOMAIN).lockdown("read:x")
    assert isinstance(security, TokenSecurity)
    assert set(security.scopes) == {"read:x"}
    assert security.permission_mode is PermissionMode.ALL


def test_lockdown_is_memoized_on_its_arguments():
    armasec = Armasec(domain=DOMAIN)
    assert armasec.lockdown("read:x") is armasec.lockdown("read:x")
    assert armasec.lockdown("read:x") is not armasec.lockdown("write:x")


def test_lockdown_memoization_distinguishes_permission_mode():
    armasec = Armasec(domain=DOMAIN)
    assert armasec.lockdown_all("a") is not armasec.lockdown_some("a")


def test_lockdown_memoization_distinguishes_skip_plugins():
    armasec = Armasec(domain=DOMAIN)
    assert armasec.lockdown("a") is not armasec.lockdown("a", skip_plugins=True)


def test_lockdown_all_requires_every_scope():
    security = Armasec(domain=DOMAIN).lockdown_all("a", "b")
    assert security.permission_mode is PermissionMode.ALL


def test_lockdown_some_requires_one_scope():
    security = Armasec(domain=DOMAIN).lockdown_some("a", "b")
    assert security.permission_mode is PermissionMode.SOME


def test_debug_settings_are_passed_through():
    logged: list[str] = []
    armasec = Armasec(domain=DOMAIN, debug_logger=logged.append, debug_exceptions=True)
    security = armasec.lockdown("read:x")
    assert security.debug_exceptions is True
    assert security.debug_logger is logged.append


def test_the_cache_is_per_instance_not_global():
    """
    Upstream decorates the method with lru_cache, which keys on self in a process-global
    cache and therefore pins every Armasec instance for the life of the process.
    """
    first = Armasec(domain=DOMAIN)
    second = Armasec(domain=DOMAIN)
    assert first.lockdown("read:x") is not second.lockdown("read:x")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_armasec.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'armasec_lite.armasec'`

- [ ] **Step 3: Write `armasec_lite/armasec.py`**

```python
"""
The factory that builds TokenSecurity instances for routes.
"""

from __future__ import annotations

from typing import Any, Callable

from fastapi import HTTPException, status

from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_security import TokenSecurity
from armasec_lite.utilities import noop


class Armasec:
    """
    A factory for TokenSecurity instances.

    Using it is not essential to securing routes, but it removes the boilerplate of
    threading domain configuration and debug settings through every route declaration.
    """

    def __init__(
        self,
        domain_configs: list[DomainConfig] | None = None,
        debug_logger: Callable[[str], None] | None = noop,
        debug_exceptions: bool = False,
        **kwargs: Any,
    ):
        """
        Store the settings every TokenSecurity built here will receive.

        Args:
            domain_configs:   Domain configurations to authenticate tokens against.
            debug_logger:     A callable such as `logger.debug`.
            debug_exceptions: If True, raise original exceptions. Testing and debugging
                              only.
            kwargs:           Arguments for a single DomainConfig, such as `domain` and
                              `audience`.
        """
        primary_domain_config = DomainConfig(**kwargs)
        if primary_domain_config.domain:
            self.domain_configs = [primary_domain_config]
        elif domain_configs is not None:
            self.domain_configs = domain_configs
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="No domain was input.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        self.debug_logger = debug_logger
        self.debug_exceptions = debug_exceptions

        # A per-instance cache rather than lru_cache on the method. lru_cache keys on
        # `self` in a process-global cache, which pins every Armasec instance for the life
        # of the process. For the usual module-level singleton the behavior is identical.
        self._lockdowns: dict[tuple[tuple[str, ...], PermissionMode, bool], TokenSecurity] = {}

    def lockdown(
        self,
        *scopes: str,
        permission_mode: PermissionMode = PermissionMode.ALL,
        skip_plugins: bool = False,
    ) -> TokenSecurity:
        """
        Build a TokenSecurity to lock down a route, memoized on its arguments.

        Args:
            scopes:          The scopes needed to access the endpoint.
            permission_mode: If ALL, every listed scope is required. If SOME, one is.
            skip_plugins:    If True, do not evaluate plugin validators.
        """
        key = (scopes, permission_mode, skip_plugins)
        security = self._lockdowns.get(key)
        if security is None:
            security = TokenSecurity(
                domain_configs=self.domain_configs,
                scopes=scopes,
                permission_mode=permission_mode,
                debug_logger=self.debug_logger,
                debug_exceptions=self.debug_exceptions,
                skip_plugins=skip_plugins,
            )
            self._lockdowns[key] = security
        return security

    def lockdown_all(self, *scopes: str, skip_plugins: bool = False) -> TokenSecurity:
        """
        Lock a route down, requiring every listed scope.

        A wrapper around `lockdown()` with the default permission mode, included for
        symmetry with `lockdown_some`.

        Args:
            scopes:       The scopes needed to access the endpoint. All are required.
            skip_plugins: If True, do not evaluate plugin validators.
        """
        return self.lockdown(*scopes, permission_mode=PermissionMode.ALL, skip_plugins=skip_plugins)

    def lockdown_some(self, *scopes: str, skip_plugins: bool = False) -> TokenSecurity:
        """
        Lock a route down, requiring at least one of the listed scopes.

        Args:
            scopes:       The scopes needed to access the endpoint. One is required.
            skip_plugins: If True, do not evaluate plugin validators.
        """
        return self.lockdown(
            *scopes, permission_mode=PermissionMode.SOME, skip_plugins=skip_plugins
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_armasec.py -v`
Expected: PASS, 11 tests

- [ ] **Step 5: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 6: Commit**

```bash
git add armasec_lite/armasec.py tests/unit/test_armasec.py
git commit -m "feat: add the Armasec factory

Memoizes lockdown in a per-instance dict rather than lru_cache on the
method, which keys on self in a process-global cache and pins every
instance for the life of the process."
```

---

### Task 17: The pytest extension

**Files:**
- Create: `armasec_lite/pytest_extension.py`
- Create: `tests/unit/test_pytest_extension.py`

**Interfaces:**
- Consumes: `armasec_lite.jwt.encode`, `armasec_lite.openid_config_loader.{OpenidConfigLoader, clear_cache}`, `armasec_lite.schemas.DomainConfig`, `armasec_lite.http`.
- Produces the fixtures upstream ships, by the same names: `rs256_domain`, `rs256_domain_config`, `rs256_iss`, `rs256_kid`, `rs256_sub`, `rs256_private_key`, `rs256_public_key`, `rs256_jwk`, `rs256_jwks_uri`, `rs256_openid_config`, `build_rs256_token`, `mock_openid_server`, plus `build_mock_openid_server`.

Because the HTTP layer is ours, the mock is a monkeypatch of `armasec_lite.http.get_json`
against a URL routing table. No sockets, no server, no respx.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_pytest_extension.py`:

```python
"""
Exercises the shipped fixtures the way a downstream consumer would.

The extension is registered as a pytest11 entry point, so these fixtures are available
here without importing anything.
"""

import pytest

from armasec_lite.jwt import decode, get_unverified_header
from armasec_lite.openid_config_loader import OpenidConfigLoader
from armasec_lite.schemas import JWK, DomainConfig


def test_domain_fixtures_line_up(rs256_domain, rs256_iss, rs256_jwks_uri):
    assert rs256_iss == f"https://{rs256_domain}"
    assert rs256_jwks_uri == f"https://{rs256_domain}/.well-known/jwks.json"


def test_domain_config_fixture(rs256_domain_config, rs256_domain):
    assert isinstance(rs256_domain_config, DomainConfig)
    assert rs256_domain_config.domain == rs256_domain
    assert rs256_domain_config.audience == "https://this.api"


def test_the_shipped_jwk_matches_the_shipped_private_key(build_rs256_token, rs256_jwk, rs256_iss):
    """
    The JWK fixture is a hard coded dict and the private key is a hard coded PEM. If they
    ever drift apart, every downstream test suite breaks with an opaque signature error,
    so assert the pairing directly.
    """
    token = build_rs256_token()
    claims = decode(token, JWK.from_dict(rs256_jwk), ["RS256"], issuer=rs256_iss)
    assert claims["sub"] == "SAMPLE_SUB"
    assert claims["exp"] > claims["iat"]


def test_build_rs256_token_applies_claim_overrides(build_rs256_token, rs256_jwk):
    token = build_rs256_token(claim_overrides={"sub": "other", "permissions": ["read:x"]})
    claims = decode(token, JWK.from_dict(rs256_jwk), ["RS256"])
    assert claims["sub"] == "other"
    assert claims["permissions"] == ["read:x"]


def test_build_rs256_token_applies_header_overrides(build_rs256_token):
    token = build_rs256_token(headers_overrides={"kid": "other-kid"})
    assert get_unverified_header(token)["kid"] == "other-kid"


def test_build_rs256_token_can_format_for_keycloak(build_rs256_token, rs256_jwk):
    token = build_rs256_token(
        claim_overrides={"permissions": ["read:stuff"], "azp": "my-client"},
        format_keycloak=True,
    )
    claims = decode(token, JWK.from_dict(rs256_jwk), ["RS256"])
    assert "permissions" not in claims
    assert claims["resource_access"]["my-client"]["roles"] == ["read:stuff"]


def test_mock_openid_server_serves_the_config(mock_openid_server, rs256_domain, rs256_iss):
    loader = OpenidConfigLoader(rs256_domain)
    assert loader.config.issuer == rs256_iss
    assert mock_openid_server.openid_config_route.call_count == 1
    assert mock_openid_server.openid_config_route.called is True


def test_mock_openid_server_serves_the_jwks(mock_openid_server, rs256_domain, rs256_kid):
    loader = OpenidConfigLoader(rs256_domain)
    assert [k.kid for k in loader.jwks.keys] == [rs256_kid]
    assert mock_openid_server.jwks_route.call_count == 1


def test_mock_openid_server_clears_the_loader_cache(mock_openid_server, rs256_domain):
    """A process-wide cache would otherwise leak a loader between tests."""
    first = OpenidConfigLoader.get(rs256_domain)
    first.config
    assert mock_openid_server.openid_config_route.call_count == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_pytest_extension.py -v`
Expected: FAIL with `fixture 'rs256_domain' not found`

- [ ] **Step 3: Write `armasec_lite/pytest_extension.py`**

```python
"""
A pytest plugin providing fixtures for testing armasec-secured applications.

Registered as a `pytest11` entry point, so installing `armasec-lite[test]` makes every
fixture here available without an import or a conftest entry.

The mock provider replaces `armasec_lite.http.get_json` with a routing table rather than
standing up a server or intercepting sockets. armasec makes exactly two requests, both
through that one function, so there is nothing a heavier mock would additionally cover.
"""

from __future__ import annotations

import textwrap
from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Iterator
from uuid import uuid4

import pytest

from armasec_lite import http, jwt
from armasec_lite.openid_config_loader import OpenidConfigLoader, clear_cache
from armasec_lite.schemas import DomainConfig

MockOpenidRoutes = namedtuple("MockOpenidRoutes", ["openid_config_route", "jwks_route"])


class _Route:
    """
    One mocked URL, counting the calls made to it.

    Exposes `called` and `call_count` so assertions written against respx's route API
    port over unchanged.
    """

    def __init__(self, url: str, payload: dict[str, Any]):
        """
        Args:
            url:     The URL this route answers.
            payload: The JSON body to return.
        """
        self.url = url
        self.payload = payload
        self.call_count = 0

    @property
    def called(self) -> bool:
        """Whether this route was requested at least once."""
        return self.call_count > 0


@pytest.fixture()
def rs256_domain() -> str:
    """
    Provide a domain for use in other fixtures.

    The value has nothing to do with an actual domain name.
    """
    return "armasec.dev"


@pytest.fixture()
def rs256_domain_config(rs256_domain: str) -> DomainConfig:
    """
    Provide the DomainConfig for the default rs256 domain.

    Args:
        rs256_domain: An implicit fixture parameter.
    """
    return DomainConfig(domain=rs256_domain, audience="https://this.api")


@pytest.fixture()
def rs256_iss(rs256_domain: str) -> str:
    """
    Provide an issuer claim for use in other fixtures.

    Args:
        rs256_domain: An implicit fixture parameter.
    """
    return f"https://{rs256_domain}"


@pytest.fixture()
def rs256_kid() -> str:
    """Provide a KID header value for use in other fixtures."""
    return "SAMPLE_KID"


@pytest.fixture()
def rs256_sub() -> str:
    """Provide a sub claim for use in other fixtures."""
    return "SAMPLE_SUB"


@pytest.fixture()
def rs256_private_key() -> bytes:
    """
    Provide a pre-generated private key for RS256 signing in other fixtures.

    This key is public knowledge and exists only so that tests are reproducible. Never
    use it for anything real.
    """
    return textwrap.dedent(
        """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAw408+QDZ10idz4ytJtwFQE4YgmrjvCoEXjtTUWQ3H4nWAAYQ
        +oE9xpr/gosNiFMuyRburvXT+Rkq8ry8tWoUzN2zViaarot+Tt9I71sVlnIsbtDZ
        +XrteMvBwjARn/MEAQEwDLvVzrBnAZrOTwrIkznyJttZh7STrt6y5X91i2MMm3xu
        9QK90kpu3rymAyT5V+AEIRzZai/ZT4YfLDutXulOVlWPQ55Xww1mbheGQ99fUMo5
        LmkxM5Jsz8ulIVvq/G/8guiKwAPJN/8S34NbkgL5GoeXT8uNDkbhtkLh5+o2T4EL
        9/ODKHqx46pHgUmBiC6wNv6uJXdH7qpaqhPR3QIDAQABAoIBABeyl/788Wk7bZRn
        UdxxsVk3nZTAa1S0Ks9YlSI56MwzofFiys/wtZHJ2sjxHPS2T+cilk4xkDyRpjjA
        UoYRku+4tjDsgLZCRU49lNMc0KLotyW+vYuUMA8BcjucI6akhomwoSgJ40Em83So
        U/QUNHZTAVtgHZtqcLMyXa+eIJqBcfsMHFkCgSF8LSD/XkRBMm1SREswDw6KqQQ0
        sZ/8TVF9sJTi3/OG8m5OfI+44AYDaMH5wKoOBcR3FBln+dEutB6JuRjmpnEjQpIT
        DggULc+Dzb/c75yhT1qZSEL3Z99JQTbytPm6boNGKmzUE9HCoY84wKfnhUDocFKW
        jnHMmKkCgYEA7/gRAtLjbJW1rbxw8xN3cyOZEJsMFt4mXMmne6nDTttVKb0wUuXJ
        H8prKAXDOzadAZgPeGJXVSNgGoNeNtkmEKDtysrRiZbWiTRxYPE36MrHFGOywjTn
        tP8qMJHmHYkxS16nqrOl0znUWv6Q6/qwd59Utuu4IJF/CxqP3Z6HPssCgYEA0J2M
        1gRgGj8NnGoIKS58gc3Aa5RdqWKoeiyXeN/zRDfMCKpPsVykvZJb4cLcEdcwe9kC
        3xpgIPaTZCPwhJ1rYiZ0/Xr7oIf0E66IeEKs/bchKcT9+sSaWgc5/zQ7aQ/XpwzU
        nKCTTeMGFUyulCIkoe2tLEQ+Mw1OphIXv17fNPcCgYEAjWgVxh81ivgRjiZ8PJEd
        E4lHmmRzVEpmOslN225nO+G9ppHolwD3ardiO7xhllQRYy4S97KjmfT1ncoJy7Jc
        XvImDhlELprnIwT3RtP+STys4ZP6c7yvSZYPa32eJ4t/s9U8YjfooLb0LwbRqW0Z
        bfRC/GOdJfv27Dkjy8muEs8CgYEAo+oHDOonMLg2U54kh2cVQVCPTngnF76DLmv3
        IGym0gUddfmL4Iowjxt+wma/T+1LFSSwUuiAe6YCrX5nr2uZQmeBKOIG8F2idAyB
        Ai0xi7Dmh9FW1kDAHtjqwxEhVS2zfnhgXij1VQ96aiX0TkR9kBYWKV/9l1NvZqF0
        s1MyAoUCgYA0wfJrCTXdWitkyfxApcmoTxt0ljqUwO6F5fhojf8PU1ouglgkRXtm
        1rSDGp7YUfODhWNSsN2P/eaDybcZo+TGtLQJ5Bai3Qxqh8xPaKCsSZbcPRLRP0w5
        CbTvFEyj6EBEH+TJL/Loa4hKFuAk7ErBAtzMCw6LchTjB/OF+dUusA==
        -----END RSA PRIVATE KEY-----
        """
    ).strip().encode("utf-8")


@pytest.fixture()
def rs256_public_key() -> bytes:
    """
    Provide the matching pre-generated public key.
    """
    return textwrap.dedent(
        """
        -----BEGIN RSA PUBLIC KEY-----
        MIIBCgKCAQEAw408+QDZ10idz4ytJtwFQE4YgmrjvCoEXjtTUWQ3H4nWAAYQ+oE9
        xpr/gosNiFMuyRburvXT+Rkq8ry8tWoUzN2zViaarot+Tt9I71sVlnIsbtDZ+Xrt
        eMvBwjARn/MEAQEwDLvVzrBnAZrOTwrIkznyJttZh7STrt6y5X91i2MMm3xu9QK9
        0kpu3rymAyT5V+AEIRzZai/ZT4YfLDutXulOVlWPQ55Xww1mbheGQ99fUMo5Lmkx
        M5Jsz8ulIVvq/G/8guiKwAPJN/8S34NbkgL5GoeXT8uNDkbhtkLh5+o2T4EL9/OD
        KHqx46pHgUmBiC6wNv6uJXdH7qpaqhPR3QIDAQAB
        -----END RSA PUBLIC KEY-----
        """
    ).strip().encode("utf-8")


@pytest.fixture()
def rs256_jwk(rs256_kid: str) -> dict[str, Any]:
    """
    Provide the JWK matching the pre-generated key pair, as a plain dict.

    Args:
        rs256_kid: An implicit fixture parameter.
    """
    modulus = "".join(
        """
        w408-QDZ10idz4ytJtwFQE4YgmrjvCoEXjtTUWQ3H4nWAAYQ-oE9xpr_gosNiFMuyRburvXT-Rkq8ry8tWoU
        zN2zViaarot-Tt9I71sVlnIsbtDZ-XrteMvBwjARn_MEAQEwDLvVzrBnAZrOTwrIkznyJttZh7STrt6y5X91
        i2MMm3xu9QK90kpu3rymAyT5V-AEIRzZai_ZT4YfLDutXulOVlWPQ55Xww1mbheGQ99fUMo5LmkxM5Jsz8ul
        IVvq_G_8guiKwAPJN_8S34NbkgL5GoeXT8uNDkbhtkLh5-o2T4EL9_ODKHqx46pHgUmBiC6wNv6uJXdH7qpa
        qhPR3Q
        """.split()
    )
    return {"alg": "RS256", "kty": "RSA", "kid": rs256_kid, "n": modulus, "e": "AQAB"}


@pytest.fixture
def rs256_jwks_uri(rs256_domain: str) -> str:
    """
    Provide a jwks uri for use in other fixtures.

    Args:
        rs256_domain: An implicit fixture parameter.
    """
    return f"https://{rs256_domain}/.well-known/jwks.json"


@pytest.fixture
def rs256_openid_config(rs256_iss: str, rs256_jwks_uri: str) -> dict[str, Any]:
    """
    Provide an openid configuration document for use in other fixtures.

    Args:
        rs256_iss:      An implicit fixture parameter.
        rs256_jwks_uri: An implicit fixture parameter.
    """
    return {"issuer": rs256_iss, "jwks_uri": rs256_jwks_uri}


@pytest.fixture
def build_rs256_token(
    rs256_private_key: bytes,
    rs256_iss: str,
    rs256_sub: str,
    rs256_kid: str,
) -> Callable[..., str]:
    """
    Provide a helper that builds a JWT signed with the pre-generated private key.

    Args:
        rs256_private_key: An implicit fixture parameter.
        rs256_iss:         An implicit fixture parameter.
        rs256_sub:         An implicit fixture parameter.
        rs256_kid:         An implicit fixture parameter.
    """
    base_claims = {"iss": rs256_iss, "sub": rs256_sub}
    base_headers = {"kid": rs256_kid}

    def _helper(
        claim_overrides: dict[str, Any] | None = None,
        headers_overrides: dict[str, Any] | None = None,
        format_keycloak: bool = False,
    ) -> str:
        """
        Encode a jwt with the default claims and headers, overridden by the arguments.

        Args:
            claim_overrides:   Claims to add, overriding defaults on collision.
            headers_overrides: Headers to add, overriding defaults on collision.
            format_keycloak:   If set, move "permissions" from the claim overrides into
                               the position Keycloak uses, generating a random "azp"
                               client id when one is not supplied.
        """
        claim_overrides = dict(claim_overrides or {})
        headers_overrides = dict(headers_overrides or {})

        now = int(datetime.now(timezone.utc).timestamp())

        if format_keycloak and "permissions" in claim_overrides:
            test_client = claim_overrides.get("azp", f"test-client-{uuid4()}")
            claim_overrides["azp"] = test_client
            claim_overrides["resource_access"] = {
                test_client: {"roles": claim_overrides.pop("permissions")}
            }

        return jwt.encode(
            {"iat": now, "exp": now + 60 * 60, **base_claims, **claim_overrides},
            rs256_private_key,
            "RS256",
            headers={**base_headers, **headers_overrides},
        )

    return _helper


def build_mock_openid_server(
    domain: str,
    openid_config: dict[str, Any],
    jwk: dict[str, Any],
    jwks_uri: str,
) -> Callable[..., Any]:
    """
    Build a context manager that mocks the openid routes armasec fetches.

    Args:
        domain:        The domain of the openid server to mock.
        openid_config: The document returned from the discovery route.
        jwk:           The key returned from the jwks route.
        jwks_uri:      The URL of the jwks route to mock.

    Returns:
        A context manager that, while active, mocks the openid routes.
    """

    @contextmanager
    def _helper(
        domain: str = domain,
        openid_config: dict[str, Any] = openid_config,
        jwk: dict[str, Any] = jwk,
        jwks_uri: str = jwks_uri,
    ) -> Iterator[MockOpenidRoutes]:
        config_url = OpenidConfigLoader.build_openid_config_url(domain)
        config_route = _Route(config_url, openid_config)
        jwks_route = _Route(jwks_uri, {"keys": [jwk]})
        routes = {config_url: config_route, jwks_uri: jwks_route}

        original = http.get_json

        def _mocked(url: str, *, timeout: float = http.DEFAULT_TIMEOUT) -> dict[str, Any]:
            route = routes.get(url)
            if route is None:
                raise AssertionError(f"Unmocked request to {url}")
            route.call_count += 1
            return route.payload

        # The loader cache is process-wide, so a loader left over from another test would
        # answer from its own cache and never reach this mock.
        clear_cache()
        http.get_json = _mocked  # type: ignore[assignment]
        try:
            yield MockOpenidRoutes(config_route, jwks_route)
        finally:
            http.get_json = original  # type: ignore[assignment]
            clear_cache()

    return _helper


@pytest.fixture
def mock_openid_server(
    rs256_domain: str,
    rs256_openid_config: dict[str, Any],
    rs256_jwk: dict[str, Any],
    rs256_jwks_uri: str,
) -> Iterator[MockOpenidRoutes]:
    """
    Mock an openid server using the other fixtures in this extension.

    Args:
        rs256_domain:        An implicit fixture parameter.
        rs256_openid_config: An implicit fixture parameter.
        rs256_jwk:           An implicit fixture parameter.
        rs256_jwks_uri:      An implicit fixture parameter.
    """
    builder = build_mock_openid_server(
        rs256_domain, rs256_openid_config, rs256_jwk, rs256_jwks_uri
    )
    with builder() as constructed:
        yield constructed
```

Note that `rs256_jwk` is a plain dict rather than a `JWK` instance. That is deliberate: it
is what a JWKS document actually contains, so it can be handed straight to the mock server
and to `JWK.from_dict` alike. Upstream's fixture returned a pydantic model, but nothing
downstream depended on that.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_pytest_extension.py -v`
Expected: PASS, 9 tests

- [ ] **Step 5: Verify the entry point resolves from an installed wheel**

Run: `uv run python -c "from importlib.metadata import entry_points; print([e.value for e in entry_points(group='pytest11')])"`
Expected: the output includes `armasec_lite.pytest_extension`

- [ ] **Step 6: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 7: Commit**

```bash
git add armasec_lite/pytest_extension.py tests/unit/test_pytest_extension.py
git commit -m "feat: add the pytest extension

Mocks the provider by monkeypatching our own get_json rather than pulling
in respx. Keeps respx's called/call_count surface so existing assertions
port unchanged, and clears the process-wide loader cache on entry and exit
so a leftover loader cannot answer from its own cache."
```

---

### Task 18: Public exports and end-to-end FastAPI tests

**Files:**
- Modify: `armasec_lite/__init__.py`
- Create: `tests/unit/test_end_to_end.py`

**Interfaces:**
- Consumes: every module built so far.
- Produces: the public API surface. `armasec_lite` exports `Armasec`, `TokenManager`, `TokenSecurity`, `TokenPayload`, `TokenDecoder`, `OpenidConfigLoader`, `extract_keycloak_permissions`, `PermissionMode`, `DomainConfig`, `__version__`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_end_to_end.py`:

```python
"""
Exercises the library the way an application does: through a real FastAPI app and a real
HTTP client, with routes declared exactly as the README shows.
"""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import armasec_lite
from armasec_lite import Armasec, TokenPayload
from armasec_lite.schemas import JWK


@pytest.fixture
def app(mock_openid_server, rs256_domain, rs256_domain_config):
    armasec = Armasec(domain=rs256_domain, audience="https://this.api")
    application = FastAPI()

    @application.get("/open")
    async def open_route():
        return {"message": "no auth needed"}

    @application.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
    async def read_stuff():
        return {"message": "Successfully authenticated!"}

    @application.get("/either", dependencies=[Depends(armasec.lockdown_some("a", "b"))])
    async def either():
        return {"message": "ok"}

    @application.get("/whoami")
    async def whoami(payload: TokenPayload = Depends(armasec.lockdown())):
        return {"sub": payload.sub}

    return application


@pytest.fixture
def client(app):
    return TestClient(app)


def test_public_exports_are_present():
    for name in (
        "Armasec",
        "TokenManager",
        "TokenSecurity",
        "TokenPayload",
        "TokenDecoder",
        "OpenidConfigLoader",
        "extract_keycloak_permissions",
        "PermissionMode",
        "DomainConfig",
    ):
        assert hasattr(armasec_lite, name), f"{name} is not exported"


def test_an_unprotected_route_needs_no_token(client):
    assert client.get("/open").status_code == 200


def test_a_valid_token_with_the_scope_is_allowed(client, build_rs256_token):
    token = build_rs256_token(claim_overrides={"permissions": ["read:stuff"], "aud": "https://this.api"})
    response = client.get("/stuff", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"message": "Successfully authenticated!"}


def test_a_missing_token_is_401(client):
    response = client.get("/stuff")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_a_garbage_token_is_401(client):
    response = client.get("/stuff", headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401


def test_a_token_without_the_scope_is_403(client, build_rs256_token):
    token = build_rs256_token(claim_overrides={"permissions": ["read:other"], "aud": "https://this.api"})
    response = client.get("/stuff", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_a_wrong_audience_is_401(client, build_rs256_token):
    token = build_rs256_token(claim_overrides={"permissions": ["read:stuff"], "aud": "other-api"})
    response = client.get("/stuff", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_a_wrong_issuer_is_401(client, build_rs256_token):
    """verify_issuer defaults to True, which is the one behavior change from upstream."""
    token = build_rs256_token(
        claim_overrides={
            "permissions": ["read:stuff"],
            "aud": "https://this.api",
            "iss": "https://evil.example.com",
        }
    )
    response = client.get("/stuff", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_lockdown_some_accepts_either_scope(client, build_rs256_token):
    for permission in ("a", "b"):
        token = build_rs256_token(
            claim_overrides={"permissions": [permission], "aud": "https://this.api"}
        )
        assert client.get("/either", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_the_payload_is_injectable(client, build_rs256_token):
    token = build_rs256_token(claim_overrides={"aud": "https://this.api"})
    response = client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.json() == {"sub": "SAMPLE_SUB"}


def test_the_security_scheme_appears_in_the_openapi_document(client):
    schemes = client.get("/openapi.json").json()["components"]["securitySchemes"]
    assert "TokenSecurity" in schemes
    assert schemes["TokenSecurity"]["in"] == "header"
    assert schemes["TokenSecurity"]["name"] == "Authorization"


def test_four_lockdowns_against_one_domain_cost_two_http_calls(app, mock_openid_server, build_rs256_token):
    """The headline caching fix, observed end to end."""
    client = TestClient(app)
    token = build_rs256_token(
        claim_overrides={"permissions": ["read:stuff", "a"], "aud": "https://this.api"}
    )
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/stuff", headers=headers)
    client.get("/either", headers=headers)
    client.get("/whoami", headers=headers)

    assert mock_openid_server.openid_config_route.call_count == 1
    assert mock_openid_server.jwks_route.call_count == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_end_to_end.py -v`
Expected: FAIL with `ImportError: cannot import name 'Armasec' from 'armasec_lite'`

- [ ] **Step 3: Write `armasec_lite/__init__.py`**

```python
"""
Injectable FastAPI auth via OIDC, built on the standard library.

A dependency-minimal reimplementation of armasec. The public API matches upstream, with
three documented differences: the import name is `armasec_lite`,
`DomainConfig.verify_issuer` defaults to True, and `TokenDecoder` accepts an optional
`jwks_refresher`.
"""

import importlib.metadata

from armasec_lite.armasec import Armasec
from armasec_lite.openid_config_loader import OpenidConfigLoader
from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_decoder import TokenDecoder, extract_keycloak_permissions
from armasec_lite.token_manager import TokenManager
from armasec_lite.token_payload import TokenPayload
from armasec_lite.token_security import TokenSecurity

__version__ = importlib.metadata.version("armasec-lite")

__all__ = [
    "Armasec",
    "DomainConfig",
    "OpenidConfigLoader",
    "PermissionMode",
    "TokenDecoder",
    "TokenManager",
    "TokenPayload",
    "TokenSecurity",
    "__version__",
    "extract_keycloak_permissions",
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/test_end_to_end.py -v`
Expected: PASS, 12 tests

- [ ] **Step 5: Run the whole suite**

Run: `uv run pytest tests/unit -v`
Expected: PASS, roughly 200 tests, zero failures

- [ ] **Step 6: Confirm no banned dependency is importable at runtime**

Run: `uv run python -c "import armasec_lite, sys; banned={'jose','buzz','snick','auto_name_enum','pluggy','respx','pydantic','httpx'} & set(sys.modules); print('LEAKED:', banned) if banned else print('clean')"`
Expected: `clean`. FastAPI does import pydantic, so if this reports a leak, confirm it came
from FastAPI rather than from `armasec_lite` before treating it as a failure. The
packaging test in Task 1 is the authoritative check on declared dependencies.

- [ ] **Step 7: Lint and type-check**

Run: `just lint`
Expected: no errors

- [ ] **Step 8: Commit**

```bash
git add armasec_lite/__init__.py tests/unit/test_end_to_end.py
git commit -m "feat: add public exports and end-to-end tests

Exercises the library through a real FastAPI app and TestClient, including
the OpenAPI security scheme and the caching fix observed end to end: three
lockdowns against one domain cost two HTTP calls, not six."
```

---

### Task 19: Examples and README

**Files:**
- Create: `README.md`
- Create: `examples/basic.py`
- Create: `examples/two_domains.py`
- Create: `examples/match_key_value_pairs.py`
- Create: `examples/plugin.py`
- Create: `tests/unit/test_examples.py`
- Create: `LICENSE`

**Interfaces:**
- Consumes: the full public API.
- Produces: no importable code. The examples are documentation that is checked for syntax and imports.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_examples.py`:

```python
"""
The examples are documentation, and documentation that does not run is a liability. These
tests import each one so a rename in the library breaks the build rather than a reader.
"""

import importlib.util
import pathlib

import pytest

EXAMPLES = sorted((pathlib.Path(__file__).parents[2] / "examples").glob("*.py"))


def test_examples_directory_is_not_empty():
    assert [p.name for p in EXAMPLES] == [
        "basic.py",
        "match_key_value_pairs.py",
        "plugin.py",
        "two_domains.py",
    ]


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_imports_cleanly(path, monkeypatch):
    monkeypatch.setenv("ARMASEC_DOMAIN", "auth.example.com")
    monkeypatch.setenv("ARMASEC_AUDIENCE", "https://this.api")
    monkeypatch.setenv("ARMASEC_DOMAIN_1", "one.example.com")
    monkeypatch.setenv("ARMASEC_AUDIENCE_1", "https://one.api")
    monkeypatch.setenv("ARMASEC_DOMAIN_2", "two.example.com")
    monkeypatch.setenv("ARMASEC_AUDIENCE_2", "https://two.api")

    spec = importlib.util.spec_from_file_location(f"example_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert hasattr(module, "app")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_examples.py -v`
Expected: FAIL, the examples directory does not exist

- [ ] **Step 3: Write `examples/basic.py`**

```python
"""Secure a single route against one OIDC domain."""

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

- [ ] **Step 4: Write `examples/two_domains.py`**

```python
"""Accept tokens issued by either of two OIDC domains."""

import os

from armasec_lite import Armasec
from armasec_lite.schemas import DomainConfig
from fastapi import Depends, FastAPI

app = FastAPI()
armasec = Armasec(
    domain_configs=[
        DomainConfig(
            domain=os.environ.get("ARMASEC_DOMAIN_1", ""),
            audience=os.environ.get("ARMASEC_AUDIENCE_1"),
        ),
        DomainConfig(
            domain=os.environ.get("ARMASEC_DOMAIN_2", ""),
            audience=os.environ.get("ARMASEC_AUDIENCE_2"),
        ),
    ],
    debug_exceptions=True,
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return dict(message="Successfully authenticated!")
```

- [ ] **Step 5: Write `examples/match_key_value_pairs.py`**

```python
"""Require specific key/value pairs to be present in the token."""

import os

from armasec_lite import Armasec
from armasec_lite.schemas import DomainConfig
from fastapi import Depends, FastAPI

app = FastAPI()
armasec = Armasec(
    domain_configs=[
        DomainConfig(
            domain=os.environ.get("ARMASEC_DOMAIN_1", ""),
            audience=os.environ.get("ARMASEC_AUDIENCE_1"),
            match_keys={"dummy-key": "this value must be in the token"},
        ),
        DomainConfig(
            domain=os.environ.get("ARMASEC_DOMAIN_2", ""),
            audience=os.environ.get("ARMASEC_AUDIENCE_2"),
        ),
    ],
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return dict(message="Successfully authenticated!")
```

- [ ] **Step 6: Write `examples/plugin.py`**

Upstream's version imports `loguru` and `pydantic`. Neither is a dependency here, so this
uses `logging` and a dataclass instead.

```python
"""Add a custom authorization check through the plugin system."""

import logging
import os
import sys
from dataclasses import dataclass

from armasec_lite import Armasec, TokenPayload
from armasec_lite.exceptions import ArmasecError
from armasec_lite.pluggable import hookimpl, plugin_manager
from fastapi import Depends, FastAPI

logger = logging.getLogger(__name__)

# Local data store of "subscribers" for this demo.
subscribers: set[str] = set()


@dataclass
class Subscriber:
    email: str


class PluginError(ArmasecError):
    """Raised when the authenticated user is not a subscriber."""

    status_code = 402
    detail = "User is not subscribed."


@hookimpl
def armasec_plugin_check(token_payload: TokenPayload):
    """Reject any token whose email is not in the subscriber set."""
    logger.debug("Applying check from example plugin")
    PluginError.require_condition(
        getattr(token_payload, "email", None) in subscribers,
        "User is not subscribed!",
    )


plugin_manager.register(sys.modules[__name__])


app = FastAPI()
armasec = Armasec(
    domain=os.environ.get("ARMASEC_DOMAIN"),
    audience=os.environ.get("ARMASEC_AUDIENCE"),
    use_https=False,
    debug_logger=logger.debug,
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return dict(message="Successfully authenticated!")


@app.post("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff", skip_plugins=True))])
async def add_subscriber(subscriber: Subscriber):
    subscribers.add(subscriber.email)
    return dict(message=f"Added subscriber {subscriber.email}!")
```

- [ ] **Step 7: Run the example tests**

Run: `uv run pytest tests/unit/test_examples.py -v`
Expected: PASS, 5 tests

- [ ] **Step 8: Write `LICENSE`**

Use the MIT license text, copyright `2026 Vantage Compute Corporation`, matching the
`license` field in `pyproject.toml`.

- [ ] **Step 9: Write `README.md`**

The README must contain, in this order:

1. A one-paragraph description: injectable FastAPI auth via OIDC, with two dependencies.
2. **Quickstart**, the contents of `examples/basic.py` with an `uv add armasec-lite` line
   above it.
3. **Why**, containing the dependency comparison table copied verbatim from the spec's
   "Dependency reduction" section, plus the sentence that upstream ships `pytest` and
   `respx` in every production install.
4. **Migrating from armasec**, listing exactly three differences, each with the fix:
   - Import name: `armasec` becomes `armasec_lite`, `armasec.schemas` becomes
     `armasec_lite.schemas`. One `sed` over import lines.
   - `DomainConfig.verify_issuer` defaults to `True`. Upstream loads the provider's issuer
     and never checks it. If your provider's discovery `issuer` does not exactly match the
     `iss` claim it mints (a trailing slash is the usual culprit), routes that worked will
     start returning 401. Set `verify_issuer=False` for exact upstream behavior.
   - `TokenDecoder` takes an optional `jwks_refresher`. Additive; existing construction
     sites are unaffected.
5. **What is not included**: the `armasec` CLI, and why.
6. A **Security** section stating that signature verification delegates to `cryptography`,
   that the verification order in `armasec_lite/jwt.py` is a security property documented
   in that module, and pointing at `tests/unit/test_jwt_attacks.py` as the enumeration of
   what is defended.
7. A link to the docs site at `https://docs.vantagecompute.ai/developer/armasec-lite/`.

Do not include benchmark numbers in the README. Those come from the comparison harness and
live on the docs site, where they carry their provenance.

- [ ] **Step 10: Run the whole suite and lint**

Run: `uv run pytest tests/unit -v && just lint`
Expected: PASS, no lint errors

- [ ] **Step 11: Verify the package builds**

Run: `uv build`
Expected: a wheel and an sdist in `dist/`, no warnings about missing files

- [ ] **Step 12: Commit**

```bash
git add README.md LICENSE examples/ tests/unit/test_examples.py
git commit -m "docs: add README, license and examples

Examples are imported by the test suite, so a rename in the library breaks
the build rather than a reader. The plugin example drops upstream's loguru
and pydantic imports, neither of which is a dependency here."
```

---

## Definition of Done

The library plan is complete when all of the following hold:

- `uv run pytest tests/unit` passes with zero failures.
- `just lint` reports no errors from `ruff check`, `ruff format --check`, or `mypy`.
- `uv build` produces a wheel and an sdist.
- `importlib.metadata.requires("armasec-lite")` lists exactly `fastapi` and `cryptography`
  outside of extras, as asserted by `tests/unit/test_packaging.py`.
- Every test in `tests/unit/test_jwt_attacks.py` passes, and each was observed to fail when
  its corresponding defense was temporarily removed.
- The PyJWT cross-validation suite passes in both directions.
- No file in `armasec_lite/` imports `jose`, `buzz`, `snick`, `auto_name_enum`, `pluggy`,
  `respx`, `pydantic`, or `httpx`.
- No file contains the em-dash or en-dash character.

## Follow-on plans

Two plans follow this one, in order, each written once its input exists:

1. **`legacy_comparison_compose/`**, the Docker Compose harness comparing this library
   against upstream `armasec==3.0.3` across the seven scenarios in the spec, driven by
   `just compare-legacy`. Written after this plan lands, because its containers install
   the artifact this plan produces.
2. **`docusaurus/`**, the documentation site and its Plotly charts. Written after the
   harness runs, because the charts read committed result files and there is nothing to
   plot until those exist.
