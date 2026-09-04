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

Exports are filled in by Task 16. For now:

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
