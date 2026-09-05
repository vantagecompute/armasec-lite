"""
The examples are documentation, and documentation that does not run is a liability. These
tests import each one so a rename in the library breaks the build rather than a reader.
"""

import importlib.util
import pathlib
import sys

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
    # The plugin example does `plugin_manager.register(sys.modules[__name__])`, which
    # requires the module to already be registered under its own name, exactly as the
    # normal import machinery would do.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    assert hasattr(module, "app")
