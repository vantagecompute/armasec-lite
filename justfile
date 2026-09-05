# Vantage AI serverless stack.
# `just` with no arguments lists every recipe.

set dotenv-load := false

# This project's port block. Deliberately clear of 8000-8002 and 4566, which
# pianus-backend uses, so both stacks can run at the same time.
# Every cdk recipe needs credentials for the vantage-runtimes account. Without a profile
# the CLI has none, and CDK reports it as "SSM parameter /cdk-bootstrap/... not found. Has
# the environment been bootstrapped?" -- which sends you off bootstrapping an account that
# was already bootstrapped. Override by exporting AWS_PROFILE yourself.
export AWS_PROFILE := env_var_or_default("AWS_PROFILE", "vantage-runtimes")

export MINISTACK_PORT := env_var_or_default("MINISTACK_PORT", "4567")
export KEYCLOAK_PORT := env_var_or_default("KEYCLOAK_PORT", "8081")
export STUB_PORT := env_var_or_default("STUB_PORT", "8500")
export CHAT_PORT := env_var_or_default("CHAT_PORT", "8501")
export API_PORT := env_var_or_default("API_PORT", "8502")
export MCP_PORT := env_var_or_default("MCP_PORT", "8503")
export GATEWAY_PORT := env_var_or_default("GATEWAY_PORT", "8504")
export DOCS_MCP_PORT := env_var_or_default("DOCS_MCP_PORT", "8505")
export AWS_MCP_PORT := env_var_or_default("AWS_MCP_PORT", "8506")
export GCP_MCP_PORT := env_var_or_default("GCP_MCP_PORT", "8507")
export AZURE_MCP_PORT := env_var_or_default("AZURE_MCP_PORT", "8508")
# Docusaurus's conventional port. Commonly taken by something else -- pass a port
# argument or export DOCS_PORT rather than letting the dev server prompt.
export DOCS_PORT := env_var_or_default("DOCS_PORT", "3000")
# NOT exported. AWS_ENDPOINT_URL is a global endpoint override honoured by every AWS
# SDK, so exporting it sends real AWS calls to ministack. That is what made `cdk`
# report "SSM parameter /cdk-bootstrap/... not found. Has the environment been
# bootstrapped?" -- it was asking ministack, which has no such parameter. Passed
# explicitly to the recipes that actually talk to the local stack.
LOCAL_AWS_ENDPOINT := env_var_or_default("AWS_ENDPOINT_URL", "http://localhost:" + MINISTACK_PORT)
LOCAL_AWS_REGION := env_var_or_default("AWS_DEFAULT_REGION", "us-east-1")

COMPOSE := "docker compose -p vantage-ai -f docker/docker-compose.ministack.yml"

default:
    @just --list

# --- setup ---------------------------------------------------------------------------

# Sync the uv workspace with every dev dependency.
install:
    uv sync

# Install the git hooks.
pre-commit-install:
    uv run pre-commit install --install-hooks
    uv run pre-commit install --hook-type commit-msg

# --- quality -------------------------------------------------------------------------

# Auto-fix formatting and lint issues.
fmt:
    uv run ruff format .
    uv run ruff check --fix .

# Lint without fixing.
lint:
    uv run ruff check .
    uv run ruff format --check .
    uv run mypy armasec_lite

# Run the unit suite with coverage, emitting the XML the docs site reads.
test-cov:
    uv run pytest tests/unit --cov=armasec_lite --cov-report=xml --junitxml=junit.xml

# The comparison harness recipes live under "comparison harness" further down, next to
# each other, because they share a compose stack and are only ever used together.

# Type-check the workspace.
typecheck:
    uv run mypy armasec_lite

# Everything the "check" CI job runs, plus the synth and catalog jobs it does not share
# a runner with. Not everything CI runs: commitlint needs the PR's base and head shas,
# which only exist in CI's checkout.
check: lint typecheck test-unit test-functional infra-test catalog-check

# --- tests ---------------------------------------------------------------------------

# Fast, hermetic. No network, no AWS, no Vantage stage.
test-unit:
    uv run pytest tests/unit -q

# Runs against the stub vantage-api built from the committed SDL.
test-functional:
    uv run pytest tests/functional -q

# Requires a real Vantage stage: set VANTAGE_API_URL and VANTAGE_TOKEN.
test-integration:
    uv run pytest tests/integration -q -m integration

# Run the unit suite. Never touches Docker.
test *ARGS:
    uv run pytest tests/unit {{ARGS}}

# --- catalog -------------------------------------------------------------------------

# Rebuild the catalog from the committed schema sources. Offline.
catalog-build:
    uv run python -m catalog_build.cli --from-dir catalog/sources --stage dev

# Re-capture the schema sources from a live stage, then rebuild.
# Review the diff under catalog/sources before committing: it is a vantage-api change.
catalog-refresh URL TOKEN="":
    uv run python -m catalog_build.cli --url {{URL}} --token "{{TOKEN}}" --stage dev

# Mirrors the "catalog is in sync" CI job: rebuilding from the committed schema sources
# must be a no-op. A dirty result here means the artifact was hand-edited or the sources
# were refreshed without rebuilding -- run `catalog-build` and commit the diff.
catalog-check: catalog-build
    #!/usr/bin/env bash
    set -euo pipefail
    if ! git diff --quiet -- catalog/vantage-catalog.json; then
        echo "catalog/vantage-catalog.json is stale. Run 'just catalog-build' and commit it."
        git diff --stat -- catalog/vantage-catalog.json
        exit 1
    fi

# --- metrics reference ---------------------------------------------------------------

# Audit which label carries the subject of each metric family, against a live Prometheus.
# Exits non-zero when catalog/metrics-subjects.json has drifted, because filtering a
# metric by the wrong label draws an empty panel rather than raising. Port-forward first:
#   kubectl -n vantage-prometheus port-forward svc/kube-prometheus-stack-prometheus 9090
metrics-audit URL="http://127.0.0.1:9090":
    uv run python -m metrics_audit.cli {{URL}}

# Accept the cluster as truth and rewrite the reference. Review the diff: a change here
# means the agent's guidance about which label to filter on may be wrong.
metrics-accept URL="http://127.0.0.1:9090":
    uv run python -m metrics_audit.cli {{URL}} --write

# --- local stack ---------------------------------------------------------------------

# Everything at once: containers, the table, and all four services, supervised in one
# terminal. Ctrl-C stops the services; containers keep running.
up:
    uv run python scripts/dev_stack.py

# Stop the containers.
down:
    {{COMPOSE}} down

# ministack (AWS surface) + Keycloak (real OIDC), then create the table.
ministack-up:
    {{COMPOSE}} up -d --wait
    AWS_ENDPOINT_URL={{LOCAL_AWS_ENDPOINT}} AWS_DEFAULT_REGION={{LOCAL_AWS_REGION}} \
    AWS_ACCESS_KEY_ID=local AWS_SECRET_ACCESS_KEY=local \
    uv run python docker/bootstrap.py
    @echo ""
    @echo "  ministack   http://localhost:$MINISTACK_PORT"
    @echo "  keycloak    http://localhost:$KEYCLOAK_PORT  (admin/admin, realm 'vantage')"
    @echo ""
    @echo "  Next: just local-stub, then just local-chat"

ministack-down:
    {{COMPOSE}} down

# Also removes volumes.
ministack-nuke:
    {{COMPOSE}} down -v

# Sign in to Vantage and print an access token. Pass --write to store it in .env.
vantage-login *ARGS:
    @uv run python scripts/vantage_login.py {{ARGS}}

# Send one turn to the deployed stack (CHAT_URL overrides the target). Handles the token
# expiry check, the required body hash, and SSE rendering.
chat PROMPT="How many clusters are there in this organization?":
    @uv run python scripts/chat.py "{{PROMPT}}"

# Render a stored conversation, or list recent ones when given no id.
show ID="":
    @uv run python scripts/show_conversation.py "{{ID}}"

# Run one agent turn end to end in a single process. Needs only GEMINI_API_KEY.
try PROMPT="How many clusters are there in this organization?":
    uv run python scripts/try_agent.py "{{PROMPT}}"

# Offline stand-in for vantage-api, served from the committed SDL.
local-stub:
    PORT=$STUB_PORT uv run python docker/stub_vantage_api.py

# The services read .env, so configuration lives in exactly one place. Point .env at a
# real Vantage stage for live tokens, or set AUTH_BYPASS_SUB plus a stub URL for offline
# work -- see .env.example.

# The api service.
local-api:
    uv run uvicorn vantage_api.app:app --reload --port $API_PORT

# The chat service (SSE).
local-chat:
    uv run uvicorn vantage_chat.app:app --reload --port $CHAT_PORT

# The MCP service, for Claude Desktop / Cursor / any MCP client.
local-mcp:
    uv run uvicorn vantage_mcp.app:app --reload --port $MCP_PORT

# Start local-mcp and local-docs-mcp first; an unreachable one is reported, not fatal.
# The gateway: one MCP endpoint over every configured server.
local-gateway:
    uv run uvicorn vantage_gateway.app:app --reload --port $GATEWAY_PORT

# Serves nothing without DOCS_INDEX_BUCKET; a deployment with no index degrades, not fails.
# The documentation MCP service (semantic search over the published index).
local-docs-mcp:
    uv run uvicorn vantage_docs_mcp.app:app --reload --port $DOCS_MCP_PORT

# The AWS MCP service (AWS list prices, from the upstream awslabs server).
local-aws-mcp:
    uv run uvicorn vantage_aws_mcp.app:app --reload --port $AWS_MCP_PORT

# The GCP MCP service (Google Cloud list prices, proxied to Google's own server).
local-gcp-mcp:
    uv run uvicorn vantage_gcp_mcp.app:app --reload --port $GCP_MCP_PORT

# The Azure MCP service (Azure retail prices, proxied to Microsoft's own server).
local-azure-mcp:
    uv run uvicorn vantage_azure_mcp.app:app --reload --port $AZURE_MCP_PORT

# Mint a real Keycloak token for the local test user.
local-token:
    @curl -s -X POST http://localhost:$KEYCLOAK_PORT/realms/vantage/protocol/openid-connect/token \
        -d grant_type=password -d client_id=vantage-ui \
        -d username=engineer -d password=engineer | uv run python -c "import json,sys; print(json.load(sys.stdin)['access_token'])"

# --- documentation -------------------------------------------------------------------

# Docusaurus dev server with live reload. `just docs-dev 3100` to pick a port.
docs-dev PORT=DOCS_PORT:
    cd docusaurus && npm install && npm run start -- --port {{PORT}}

# The SDK reference and the benchmark pages are both regenerated as part of this: the pydoc
# plugin writes the reference from docstrings and npm's `prebuild` hook runs
# scripts/generate_benchmarks.py over the committed results. Neither is committed, so a
# build is the only way either exists.

# Build the static site into docusaurus/build.
docs-build:
    cd docusaurus && npm install && PYDOC_PYTHON="$(uv python find 3.14)" npm run build

# Useful when checking that a renamed module still appears. The plugin parses the source
# with `ast` and imports nothing, so this needs no virtualenv and no dependencies.

# Regenerate the SDK reference alone, without building the site.
docs-sdk:
    cd docusaurus && npm install && PYDOC_PYTHON="$(uv python find 3.14)" npm run gen-sdk-docs

# The benchmark pages and their figure specs are generated the same way the SDK reference
# is: written at build time from committed data, never committed themselves. The data is
# the JSON under legacy_comparison_compose/results/, and the generator reads that and
# nothing else. It fails rather than emitting a page with a scenario missing, so a broken
# results tree stops the docs build instead of quietly publishing a shorter page.

# Regenerate the benchmark pages and Plotly figure specs from the committed results.
charts:
    python3 docusaurus/scripts/generate_benchmarks.py

# Validate the results tree and build every figure without writing anything.
charts-check:
    python3 docusaurus/scripts/generate_benchmarks.py --check

# The plugin fails outright when introspection fails, and when every requested module
# documents nothing. This catches the case neither covers: a partial generation, where some
# modules landed and others silently did not. It compares the generated pages against the
# module list in the config, so a module added to the site cannot be forgotten here.

# Docusaurus renders mermaid in the browser, so `docs-build` cannot fail on a malformed
# diagram: the reader gets a blank box instead. This parses every diagram with mermaid's
# own grammar, which is the only place a syntax error is catchable before a human sees it.

# Fail if any mermaid diagram in the docs does not parse.
docs-diagrams:
    cd docusaurus && node ./mmdcheck.mjs $(find docs -name '*.md' -not -path 'docs/sdk-reference/*')

# Fail if the built SDK reference is missing any module in the config.
docs-verify: docs-build docs-diagrams
    #!/usr/bin/env bash
    set -euo pipefail
    cd docusaurus
    declared=$(grep -cE "^\s+\{module: " docusaurus.config.ts)
    # One index page per instance, which is not a module.
    instances=$(grep -cE "^\s+id: '" docusaurus.config.ts)
    generated=$(( $(find docs/sdk-reference -mindepth 2 -name '*.md' | wc -l) - instances ))
    if [ "$generated" -ne "$declared" ]; then
        echo "SDK reference is incomplete: $declared modules declared, $generated pages generated."
        echo "Likely cause: a module was renamed or moved without updating the plugin's"
        echo "module list in docusaurus/docusaurus.config.ts."
        exit 1
    fi
    echo "SDK reference OK: $generated pages for $declared declared modules"

    # Same check for the benchmark pages: one per committed run, plus the summary. Counted
    # against the results tree rather than a number written here, so committing a run
    # cannot be forgotten in the check.
    committed=$(find ../legacy_comparison_compose/results -mindepth 2 -maxdepth 2 -type d | wc -l)
    pages=$(find docs/benchmarks -name '*.mdx' | wc -l)
    if [ "$pages" -ne "$(( committed + 1 ))" ]; then
        echo "Benchmark pages are incomplete: $committed runs committed, $pages pages generated."
        echo "Expected one page per run plus one summary."
        exit 1
    fi
    echo "Benchmark pages OK: $pages pages for $committed committed runs"

# Serve the built site locally. Takes a port for the same reason as docs-dev.
docs-serve PORT=DOCS_PORT:
    cd docusaurus && npm run serve -- --port {{PORT}}

# Type-check the Docusaurus config and sidebars.
docs-typecheck:
    cd docusaurus && npm install && npm run typecheck

# --- comparison harness --------------------------------------------------------------

# Bring the four-service stack up and leave it running, for poking at by hand.
compare-legacy-up:
    cd legacy_comparison_compose && docker compose up -d --wait

# Tear the stack down, dropping the Keycloak volume so the realm reimports next time.
compare-legacy-down:
    cd legacy_comparison_compose && docker compose down -v

# The parity matrix. Needs the stack up.
compare-legacy-parity:
    uv run pytest legacy_comparison_compose/test_parity.py -v

# Measure armasec-lite against upstream armasec, end to end, and write the result files.
#
# Builds both application images and the bench image, brings the stack up on health checks
# rather than sleeps, runs every scenario, writes one JSON file per scenario into a fresh
# per-run directory under legacy_comparison_compose/results/v<version>/, rebuilds
# results/index.json from the whole tree, prints a summary and tears the stack down. Takes
# roughly an hour at the default five repetitions.
#
# Nothing is overwritten: every run keeps its own directory, named from its own provenance,
# and every run is meant to be committed. Two runs of the same version tell you how much
# noise a single number carries; two runs of different versions tell you what a change did.
#
# Nothing here is a shortcut around the ground rule: every number in the docs comes out of
# one of the files this writes. Pass REPS=1 SCENARIOS=s4 QUICK=--quick to check that the
# harness works without pretending the output is a measurement.
compare-legacy REPS="5" SCENARIOS="s4,s10,s3,s9,s1,s2,s8,s11,footprint,memory,callgraph,profile" QUICK="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd legacy_comparison_compose
    echo "==> building"
    docker compose build
    docker compose --profile bench build bench
    echo "==> up"
    docker compose up -d --wait
    status=0
    docker compose run --rm bench \
        --reps {{REPS}} --scenarios {{SCENARIOS}} {{QUICK}} || status=$?
    echo "==> down"
    docker compose down -v
    echo
    echo "==> result files"
    find results -name '*.json' -printf '%10s  %p\n' | sort -k2
    exit $status

# --- infrastructure ------------------------------------------------------------------

# Synthesise every stack with bundling stubbed. No Docker, no AWS credentials.
infra-test:
    cd infra && uv run --quiet python test_synth.py

# Environments: dev | staging | prod. Config lives in infra/environments.py.

# The selector deliberately excludes VantageAiCicd: an application deploy must never be
# able to rewrite the roles that authorise it.

cdk-synth ENV="dev":
    cd infra && uv run npx -y aws-cdk@2 synth 'VantageAi*-{{ENV}}' -c env={{ENV}}

cdk-diff ENV="dev":
    cd infra && uv run npx -y aws-cdk@2 diff 'VantageAi*-{{ENV}}' -c env={{ENV}}

cdk-deploy ENV="dev":
    # --require-approval never matches deploy.yml. Without it CDK stops for an
    # interactive confirmation on any IAM change and simply fails where there is no
    # TTY, so a security-relevant change becomes the one kind you cannot deploy
    # locally. `just cdk-diff ENV` is the review step; run it first.
    cd infra && uv run npx -y aws-cdk@2 deploy 'VantageAi*-{{ENV}}' -c env={{ENV}} \
        --require-approval never

# One-time bootstrap: creates the GitHub Actions OIDC deploy roles. Run this by hand with
# the vantage-runtimes profile -- it is what makes keyless CI deploys possible, so CI
# cannot create it. Prints the role ARNs to put in each GitHub environment.
cdk-deploy-cicd:
    # Same reason as cdk-deploy: this stack is nothing but IAM, so CDK always stops
    # for a confirmation it cannot get without a TTY. `just cdk-diff-cicd` is the
    # review step.
    cd infra && uv run npx -y aws-cdk@2 deploy VantageAiCicd --exclusively \
        --require-approval never

# What the deploy role is allowed to do, for review before creating it.
cdk-diff-cicd:
    cd infra && uv run npx -y aws-cdk@2 diff VantageAiCicd --exclusively


# --- release -------------------------------------------------------------------------

# Mirrors `just release` in the v8x repository, with one deliberate difference: that one
# commits to main and pushes a tag, because its CI publishes from the tag. Nothing here
# publishes from a tag except the docs site, and the version lives in twenty-four places
# across fifteen Python projects, a docs site and eight service constructors. So this cuts
# a branch for review instead, and the tag is created after it merges, from main. A tag on
# an unmerged branch names a commit that may never reach main.
#
# Note the grammar below accepts a pre-release such as 1.2.3rc1, while deploy-docs.yml
# publishes only on a plain vX.Y.Z tag. That split is deliberate: a release candidate gets
# a version and a tag without replacing the published documentation.
#
# Cut a release branch and bump every version in the workspace.
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION="{{version}}"
    BRANCH="release/v${VERSION}"

    # The same grammar v8x validates, and narrowed the same way: no trailing local-version
    # segment, because a version typed here becomes a real release identifier and `+abc123`
    # is meaningless as one.
    PEP440_RE='^[0-9]+\.[0-9]+\.[0-9]+([.-]?(a|b|c|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?$'
    if [[ ! "${VERSION}" =~ ${PEP440_RE} ]]; then
        echo "Version '${VERSION}' is not a valid PEP 440 release version." >&2
        echo "Use a form like '1.2.3', '1.2.3rc1', or '1.2.3.post1'." >&2
        exit 1
    fi

    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "Working tree is not clean. Commit or stash before releasing." >&2
        exit 1
    fi

    # A release cut from a stale main silently omits whatever landed since the last fetch,
    # and the omission is invisible in the diff because the branch looks complete.
    git fetch --quiet origin main
    if [[ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]]; then
        echo "HEAD is not origin/main. Check out main and pull before releasing." >&2
        exit 1
    fi

    if git rev-parse --verify --quiet "${BRANCH}" >/dev/null \
       || git ls-remote --exit-code --heads origin "${BRANCH}" >/dev/null 2>&1; then
        echo "Branch ${BRANCH} already exists locally or on origin." >&2
        exit 1
    fi

    git switch --quiet --create "${BRANCH}"

    # Every edit is asserted rather than attempted. A regex that silently matches nothing
    # would leave one component behind at the old version, and a half-bumped workspace is
    # worse than an unbumped one because it looks done.
    VERSION="${VERSION}" uv run python - <<'PY'
    import json, os, pathlib, re, sys

    version = os.environ["VERSION"]
    changed, failed = [], []

    def sub(path: pathlib.Path, pattern: str, repl: str) -> None:
        text = path.read_text()
        new, n = re.subn(pattern, repl, text, count=1, flags=re.M)
        if n != 1:
            failed.append(f"{path}: no match for {pattern!r}")
            return
        path.write_text(new)
        changed.append(str(path))

    skip = (".venv", "node_modules", "cdk.out")
    for p in sorted(pathlib.Path(".").rglob("pyproject.toml")):
        if any(s in str(p) for s in skip):
            continue
        sub(p, r'^version = "[^"]+"', f'version = "{version}"')

    for p in sorted(pathlib.Path("services").rglob("app.py")):
        if 'version="' not in p.read_text():
            continue
        sub(p, r'version="[0-9][^"]*"', f'version="{version}"')

    # npm rejects a PEP 440 pre-release, so the marker is rewritten into semver's form.
    # The docs site is unpublished and its version is cosmetic, but leaving it behind
    # would make it the one component that disagrees, which is exactly the confusion
    # this recipe exists to prevent.
    npm = re.sub(r"^(\d+\.\d+\.\d+)[.-]?(a|b|c|rc|post|dev)(\d+)$", r"\1-\2.\3", version)
    pkg = pathlib.Path("docusaurus/package.json")
    data = json.loads(pkg.read_text())
    if "version" not in data:
        failed.append(f"{pkg}: no version field")
    else:
        data["version"] = npm
        pkg.write_text(json.dumps(data, indent=2) + "\n")
        changed.append(str(pkg))

    if failed:
        print("Version bump failed, nothing committed:", file=sys.stderr)
        for f in failed:
            print(f"  {f}", file=sys.stderr)
        raise SystemExit(1)

    print(f"  bumped {len(changed)} files to {version} (npm form: {npm})")
    PY

    (cd docusaurus && npm install --package-lock-only --silent >/dev/null 2>&1) || true

    # Verify before committing, the same reason v8x builds before it tags: a release branch
    # that does not pass its own gates wastes a review cycle to discover it.
    echo "Verifying the workspace before committing the bump..."
    just check

    git add -A
    git commit --quiet -m "release: bump every version to ${VERSION}"
    git push --quiet --set-upstream origin "${BRANCH}"

    echo ""
    echo "Cut ${BRANCH} at ${VERSION}."
    echo "  gh pr create --base main --head ${BRANCH} --title 'release: ${VERSION}'"
    echo "  after it merges, tag main:  git tag -a v${VERSION} -m 'Release ${VERSION}' && git push origin v${VERSION}"
