# armasec-lite: injectable FastAPI auth via OIDC, with two dependencies.
# `just` with no arguments lists every recipe.

set dotenv-load := false

# Docusaurus's conventional port. Commonly taken by something else -- pass a port
# argument or export DOCS_PORT rather than letting the dev server prompt.
export DOCS_PORT := env_var_or_default("DOCS_PORT", "3000")

default:
    @just --list

# --- tests -----------------------------------------------------------------------------

# Run the unit suite. Never touches Docker.
test *ARGS:
    uv run pytest tests/unit {{ARGS}}

# Run the unit suite with coverage, emitting the XML the docs site reads.
test-cov:
    uv run pytest tests/unit --cov=armasec_lite --cov-report=xml --junitxml=junit.xml

# --- quality -------------------------------------------------------------------------

# Lint and type-check.
lint:
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy armasec_lite

# Auto-fix what ruff can fix.
fmt:
    uv run ruff check --fix .
    uv run ruff format .

# --- comparison ------------------------------------------------------------------------

# Not implemented yet. Reserves the name so a future recipe here cannot be mistaken for a
# no-op: an empty recipe with this name would silently "pass" instead of saying so.
compare-legacy:
    #!/usr/bin/env bash
    echo "compare-legacy: the legacy comparison harness is not implemented yet." >&2
    exit 1

# --- documentation -------------------------------------------------------------------

# Docusaurus dev server with live reload. `just docs-dev 3100` to pick a port.
docs-dev PORT=DOCS_PORT:
    cd docusaurus && npm install && npm run start -- --port {{PORT}}

# The API reference is regenerated as part of this: the pydoc plugin writes it from
# docstrings at build time and it is not committed, so a build is the only way it exists.

# Build the static site into docusaurus/build.
docs-build:
    cd docusaurus && npm install && npm run build

# Useful when checking that a renamed module still appears. The plugin parses the source
# with `ast` and imports nothing, so this needs no virtualenv and no dependencies.

# Regenerate the API reference alone, without building the site.
docs-sdk:
    cd docusaurus && npm install && npm run gen-sdk-docs

# Serve the built site locally. Takes a port for the same reason as docs-dev.
docs-serve PORT=DOCS_PORT:
    cd docusaurus && npm run serve -- --port {{PORT}}

# Type-check the Docusaurus config and sidebars.
docs-typecheck:
    cd docusaurus && npm install && npm run typecheck

# Docusaurus renders mermaid in the browser, so `docs-build` cannot fail on a malformed
# diagram: the reader gets a blank box instead. This parses every diagram with mermaid's
# own grammar, which is the only place a syntax error is catchable before a human sees it.

# Fail if any mermaid diagram in the docs does not parse.
docs-diagrams:
    cd docusaurus && node ./mmdcheck.mjs $(find docs -name '*.md' -not -path 'docs/api-reference/*')

# Fail if the built API reference is missing any module in the config.
docs-verify: docs-build docs-diagrams
    #!/usr/bin/env bash
    set -euo pipefail
    cd docusaurus
    declared=$(grep -cE "^\s+\{module: " docusaurus.config.ts)
    # One index page per instance, which is not a module.
    instances=$(grep -cE "^\s+id: '" docusaurus.config.ts)
    generated=$(( $(find docs/api-reference -mindepth 1 -name '*.md' | wc -l) - instances ))
    if [ "$generated" -ne "$declared" ]; then
        echo "API reference is incomplete: $declared modules declared, $generated pages generated."
        echo "Likely cause: a module was renamed or moved without updating the plugin's"
        echo "module list in docusaurus/docusaurus.config.ts."
        exit 1
    fi
    echo "API reference OK: $generated pages for $declared declared modules"
