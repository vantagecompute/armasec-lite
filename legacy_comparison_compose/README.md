# The armasec-lite versus armasec comparison harness

Two FastAPI applications, identical except for the authentication library they import,
authenticating real tokens from a real Keycloak. This directory is the foundation the
benchmark scenarios are built on; the scenarios themselves are not here yet.

Nothing in this directory is imported by `armasec_lite`, and none of it participates in
this repository's dependency resolution. Upstream `armasec==3.0.3` declares `pytest<9` and
`respx` as **runtime** dependencies, which is the defect armasec-lite exists to remove and
which makes upstream unsatisfiable against this repository's lockfile. The legacy arm
therefore resolves its own dependencies inside its own Docker image and upstream armasec is
deliberately absent from `pyproject.toml`.

## Services

| Service | Host port | What it is |
| --- | --- | --- |
| `keycloak` | 18081 | `quay.io/keycloak/keycloak:26.4`, `start-dev --import-realm`, realm from `realm/armasec-realm.json` |
| `oidc-proxy` | 18080 | A standard-library asyncio reverse proxy that counts requests per path, injects latency and faults, and can rewrite the advertised issuer |
| `app-legacy` | 18001 | `app/main.py` on upstream `armasec==3.0.3` |
| `app-lite` | 18002 | The same `app/main.py` on `armasec-lite` |

Every port is bound to `127.0.0.1`. Both app services get identical `cpus` and `mem_limit`,
set once through a YAML anchor so they cannot drift apart.

### Why the proxy is there

Three things the benchmark scenarios need and Keycloak will not give them: an exact count
of OIDC requests taken at the wire rather than inferred, a controllable amount of provider
latency (a local Keycloak answers in single-digit milliseconds, which would hide the effect
being measured), and a provider that fails on demand.

**`KC_HOSTNAME` must point at the proxy, and this is the trap.** Keycloak's discovery
document advertises absolute URLs, `jwks_uri` among them. At its default Keycloak would
advertise its own address, both apps would fetch the JWKS directly, and every JWKS request
would bypass the proxy uncounted while everything still appeared to work. Setting
`KC_HOSTNAME: http://oidc-proxy:8080` makes discovery advertise proxy URLs, so both fetches
traverse the proxy, and it keeps the discovery document's `issuer` equal to the `iss` claim
of minted tokens. That second effect matters because armasec-lite compares them by exact
string equality and upstream armasec does not.

If `/__stats` ever shows a zero count for the `certs` path, `KC_HOSTNAME` is wrong and no
number the harness produces means anything. `test_jwks_and_discovery_traverse_the_proxy`
asserts it.

## Bringing it up

```bash
cd legacy_comparison_compose
docker compose up -d          # blocks on health checks, not sleeps; Keycloak takes ~40s
docker compose ps             # all four should read (healthy)
```

## Getting a token by hand

The realm gives each parity condition its own client, so no token has to be forged.

```bash
# A valid token with read:stuff and write:stuff.
TOKEN=$(curl -s -X POST http://localhost:18080/realms/armasec/protocol/openid-connect/token \
  -d grant_type=password -d client_id=armasec-api -d client_secret=armasec-api-secret \
  -d username=testuser -d password=testuser-password | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s -o /dev/null -w '%{http_code}\n' http://localhost:18001/stuff -H "Authorization: Bearer $TOKEN"  # legacy
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:18002/stuff -H "Authorization: Bearer $TOKEN"  # lite
```

Decode it with any base64 tool. The claims that matter are `iss`
(`http://oidc-proxy:8080/realms/armasec`), `aud` (`armasec-api`, put there by an audience
mapper because Keycloak's default audience is `account` and would make every audience
assertion vacuous) and `resource_access.armasec-api.roles`, which is where Keycloak puts
client roles and why both apps configure `permission_extractor=extract_keycloak_permissions`.

| Grant | Token it produces |
| --- | --- |
| `armasec-api` password grant as `testuser` | valid, holds `read:stuff` and `write:stuff` |
| `armasec-api` client credentials | valid, service account holds only `write:stuff`, so 403 on `/stuff` |
| `other-api` client credentials | audience is `other-api`, so 401 |
| `shortlived-api` client credentials | correct audience, two second lifespan, so 401 once it lapses |

## Routes

`app/main.py` is one module, selecting its library from `ARMASEC_LIB` and building the same
route table either way. Two copies would drift and every measured difference would then be
arguable.

| Route | Auth |
| --- | --- |
| `GET /health` | none |
| `GET /stuff` | `read:stuff` |
| `GET /either` | `read:stuff` or `admin:stuff` |
| `GET /whoami` | any valid token; returns the decoded payload |

## Proxy control endpoints

| Endpoint | Effect |
| --- | --- |
| `GET /__stats` | Per-path request counts, total, and the current latency, fault and issuer settings |
| `GET /__latency?ms=200` | Delay every forwarded request by 200ms |
| `GET /__fault?status=500&count=10` | Answer the next 10 forwarded requests with 500. `status=0` clears |
| `GET /__issuer?value=URL` | Advertise a different `issuer` in the discovery document. Empty clears |
| `GET /__reset` | Zero the counters. Latency, fault and issuer settings are left alone |

Control paths are answered locally, never forwarded and never counted, so polling `/__stats`
or running a health check cannot pollute the numbers. Both libraries cache the discovery
document for the life of the process, so `/__issuer` only takes effect for an app process
started after it was set; restart the two app services.

## Tests

```bash
uv run pytest legacy_comparison_compose/test_parity.py -v   # needs the stack running
uv run pytest                                               # unit suite only, never touches Docker
```

`pyproject.toml` sets `testpaths = ["tests/unit"]` and every test in `test_parity.py` is
marked `integration`, so a plain `pytest` run never reaches Docker. The tests skip rather
than fail when the stack is not up.

The parity matrix asserts both services return the same status for no token, a malformed
token, an expired token, a wrong-audience token, an insufficient-scope token and a valid
token, across both `/stuff` and `/either`. The one documented difference,
`verify_issuer`, gets its own test: it uses `/__issuer` to make Keycloak disagree with its
own tokens, restarts both app services, and asserts upstream returns 200 while armasec-lite
returns 401. Asserting it in both directions means the test fails if either library changes
its mind.

## Tearing down

```bash
docker compose down -v        # -v also drops the Keycloak volume, so the realm reimports
```

## Rebuilding after a change

The build context is the repository root, because the lite arm installs `armasec-lite` from
the local source tree. `Dockerfile.app.dockerignore` keeps the context small without putting
a `.dockerignore` at the repository root.

```bash
docker compose build          # both arms, one Dockerfile, one build arg apart
docker compose up -d --build
```

`app/main.py` and `proxy/main.py` are bind-mounted or copied differently: the proxy is
mounted read-only from the host, so editing it needs only `docker compose restart
oidc-proxy`, while the app module is baked into the image and needs a rebuild.
