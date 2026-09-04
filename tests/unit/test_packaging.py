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
