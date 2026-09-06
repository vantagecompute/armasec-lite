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


def test_importing_armasec_lite_does_not_load_pem_serialization():
    """
    The production import path must not pull in `cryptography`'s serialization machinery.

    `jwt.py` needs `serialization.load_pem_private_key` at exactly one place: `_sign`,
    which backs `encode`, which is a testing aid never reached by a request. Importing it
    at module scope cost roughly 6.8ms of the package's import time and dragged in
    `serialization.ssh`, which in turn reaches for `bcrypt` when it is installed. None of
    that belongs in a validator's startup path, so the import lives inside `_sign`.

    Runs in a subprocess: this test process has already imported serialization through
    conftest's key fixtures.
    """
    import subprocess
    import sys

    code = (
        "import sys, armasec_lite; "
        "print('cryptography.hazmat.primitives.serialization' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "False"


def test_distribution_metadata_carries_the_pypi_project_page_fields():
    """
    The published metadata must fill in every field PyPI renders on a project page.

    PyPI builds its sidebar from installed metadata, not from the repository, so a field
    left out of `pyproject.toml` shows up as a missing link or an empty Meta section on
    the release page rather than as a build failure. This test is what makes that
    omission visible here instead of after an upload.

    `License-Expression` rather than a `License ::` classifier is deliberate: PEP 639
    metadata (2.4) rejects a distribution that carries both, so the classifier was
    removed when the SPDX expression was added.
    """
    metadata = importlib.metadata.metadata("armasec-lite")

    assert metadata["Summary"]
    assert metadata.get("Author") or metadata.get("Author-email")
    assert metadata["Requires-Python"]
    assert metadata["Description-Content-Type"] == "text/markdown"

    urls = {
        value.split(",", 1)[0].strip(): value.split(",", 1)[1].strip()
        for value in metadata.get_all("Project-URL") or []
    }
    assert {"Homepage", "Documentation", "Repository", "Issues", "Changelog"} <= urls.keys()

    classifiers = set(metadata.get_all("Classifier") or [])
    assert "Typing :: Typed" in classifiers
    assert "Framework :: FastAPI" in classifiers
    assert "Framework :: Pytest" in classifiers
    assert not [c for c in classifiers if c.startswith("License ::")]


def test_the_package_ships_a_py_typed_marker():
    """
    Without `py.typed`, PEP 561 tells a consumer's type checker to ignore the package.

    Every signature in `armasec_lite` is annotated and the project runs mypy in strict
    mode, so the annotations are known good. The marker is what lets a downstream
    project actually see them: mypy and pyright both skip an installed package that has
    no marker, silently, and treat every symbol it exports as `Any`.
    """
    import pathlib

    marker = pathlib.Path(armasec_lite.__file__).parent / "py.typed"
    assert marker.is_file()


def test_the_sdist_ships_an_explicit_allow_list():
    """
    The source distribution must name what it contains rather than take hatchling's default.

    Hatchling's default sdist is "everything the root `.gitignore` does not exclude", and
    it does not read nested ignore files. `docusaurus/node_modules` is ignored by
    `docusaurus/.gitignore`, so the default swept in 574MB of it and produced a 115.7MB
    tarball, over PyPI's 100MB per-file limit. The failure surfaces at upload, after a
    tag has been pushed.

    This checks the declaration rather than building a tarball, so it stays a
    millisecond-scale unit test. It cannot prove the build output is small; it catches
    the regression that would make it large again, which is someone deleting the section
    or adding a directory of harness data to it.
    """
    import pathlib
    import tomllib

    pyproject = pathlib.Path(__file__).parents[2] / "pyproject.toml"
    config = tomllib.loads(pyproject.read_text())
    sdist = config["tool"]["hatch"]["build"]["targets"]["sdist"]

    assert sdist["include"], "an empty include list means hatchling falls back to its default"
    assert "armasec_lite" in sdist["include"]
    assert not [e for e in sdist["include"] if e.startswith(("docusaurus", "legacy_"))]

    # The include list alone does not do it: hatchling matches README* and LICEN[CS]E*
    # recursively, which caught 1888 of them under docusaurus/node_modules even with
    # only the two root files named above.
    assert {"docusaurus", "legacy_comparison_compose"} <= set(sdist["exclude"])
