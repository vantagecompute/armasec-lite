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
    "httpx",
}


def test_version_is_exposed():
    assert armasec_lite.__version__ == importlib.metadata.version("armasec-lite")


def test_runtime_dependencies_are_exactly_three():
    """
    Guard rail against dependency creep.

    The runtime dependency count is fixed at three: fastapi, cryptography, and
    pydantic (declared because fastapi imports it unconditionally in every install
    regardless of what this project declares). This test is what stops a future task
    from quietly adding a fourth, which is the exact failure mode armasec-lite exists
    to prevent.
    """
    requires = importlib.metadata.requires("armasec-lite") or []
    runtime = [r for r in requires if "extra ==" not in r]
    names = sorted(r.split(" ")[0].split(">")[0].split("<")[0].split("=")[0] for r in runtime)
    assert names == ["cryptography", "fastapi", "pydantic"]


def test_armasec_lite_source_imports_no_banned_module():
    """
    The package's own source must not import any dependency this project removed.

    Checked by parsing the source rather than by inspecting sys.modules, because
    sys.modules is polluted by pytest (which imports pluggy) and by fastapi (which
    imports pydantic). Neither says anything about what armasec_lite itself imports.
    """
    import ast
    import pathlib

    package = pathlib.Path(armasec_lite.__file__).parent
    offenders = []
    for path in package.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                root = name.split(".")[0]
                if root in BANNED_RUNTIME_IMPORTS:
                    offenders.append(f"{path.relative_to(package)}:{node.lineno} imports {name}")

    assert offenders == [], "armasec_lite imports removed dependencies: " + "; ".join(offenders)


def test_importing_armasec_lite_does_not_load_banned_modules():
    """
    Importing the package in a clean interpreter must not pull in a removed dependency.

    Runs in a subprocess because this test process already has pytest's own imports
    loaded.
    """
    import subprocess
    import sys

    banned = sorted(BANNED_RUNTIME_IMPORTS)
    code = (
        "import sys, json, armasec_lite; "
        f"print(json.dumps([m for m in {banned!r} if m in sys.modules]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]", f"armasec_lite loaded: {result.stdout.strip()}"
