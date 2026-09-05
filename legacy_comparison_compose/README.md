# The armasec-lite versus armasec comparison harness

Two FastAPI applications, identical except for the authentication library they import,
authenticating real tokens from a real Keycloak, driven by an open-loop load generator that
writes its findings to committed JSON.

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
| `bench` | none | The load generator. Behind a compose profile, so `up` does not start it |

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
| `GET /scope/0` .. `/scope/19` | a distinct scope set nobody holds, for S2 |
| `GET /__profile`, `/__profile/start`, `/__profile/stop`, `/__profile/reset` | none; the sampling profiler |

The twenty `/scope/N` routes exist so scenario S2 can exercise N distinct `lockdown()` scope
sets and count the OIDC fetches they cost. They answer 403, deliberately: a scope check
happens after the token has been decoded, so the OIDC configuration has already been loaded
by the time the request is refused, which is the thing being counted. A route that is never
called never builds a loader, so registering all twenty costs the N=5 sweep point nothing.

`/__profile/start` runs a daemon thread that wakes every few milliseconds, calls
`sys._current_frames()` and tallies one stack signature per thread, tagging the event loop
thread separately. It is off until started. It is how the headline result is corroborated
from inside the process by a method independent of the load generator outside it.

## Proxy control endpoints

| Endpoint | Effect |
| --- | --- |
| `GET /__stats` | Per-path request counts, total, and the current latency, fault and issuer settings |
| `GET /__latency?ms=200` | Delay every forwarded request by 200ms |
| `GET /__fault?status=500&count=10&path=certs` | Answer the next 10 forwarded requests whose path contains `certs` with 500. `status=0` clears, an empty `path` faults everything |
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

## Benchmarks

```bash
just compare-legacy                                  # everything, five repetitions, ~35 minutes
just compare-legacy REPS=1 SCENARIOS=s4 QUICK=--quick  # check the harness, do not cite the output
```

The recipe builds both application images and the bench image, brings the stack up on
health checks, runs the scenarios, writes one JSON file per scenario into `results/`, prints
a summary and tears the stack down.

**Every number published about this project comes out of one of those files.** No figure is
hand-authored. Where a scenario shows no difference, the file says so and the difference is
not claimed; where upstream wins, the file records that it won.

| File | Scenario | Measures |
| --- | --- | --- |
| `s4_event_loop_blocking.json` | S4 | `/health` latency while a cold authentication load runs, as a time series |
| `s3_warm_flood.json` | S3 | Throughput and latency percentiles at four arrival rates against a warm cache |
| `s1_cold_start.json` | S1 | Time to first response after a restart, at concurrency 1 to 64 |
| `s2_request_amplification.json` | S2 | OIDC fetches counted at the proxy for N distinct `lockdown()` scope sets |
| `s8_failing_provider.json` | S8 | Outbound JWKS fetches while the provider fails and unknown key ids arrive |
| `footprint.json` | | Installed distributions per arm, read from the running containers |
| `memory.json` | | Container RSS idle, warm and under load, plus per-library import cost |
| `call_graph.json` | | Static call sites and per-request call counts on the authentication path |
| `profile_sampling.json` | | Sampled stacks per thread during the S4 workload |

S7, the status parity matrix, is `test_parity.py` rather than a result file, because its
output is a pass or a fail rather than a number.

**Two scenarios from the design are not built.** S5, the provider latency sweep at 0, 50,
200 and 500ms, and S6, real Keycloak realm key rotation mid-run. No result file claims
either, and nothing in the documentation may cite them. The proxy already carries the
latency knob S5 needs.

### S4 is the headline

An unauthenticated `/health` route is hammered at a fixed arrival rate while a single cold
authenticated request lands mid-stream, with 500ms of provider latency injected so the two
OIDC fetches cost about a second. `/health` touches neither library, so every millisecond it
gains is the event loop being unavailable. The measurement needs no instrumentation inside
either process and cannot be confounded by the cost of authentication itself, because the
requests being timed are not authenticated.

`profile_sampling.json` corroborates it from inside by a different method, and the two agree.

### Methodology

**Open loop.** Arrivals are scheduled on a fixed timetable from the start of a run and
dispatched whether or not earlier requests have finished. Latency is measured from a
request's scheduled arrival, so time spent queued behind a stalled server counts against it.
A closed-loop generator stops offering load while the server is stalled and would hide
precisely the stall S4 exists to measure. That is coordinated omission and it would
invalidate the headline result. Every result records `schedule_error_ms` so a reader can see
whether the generator kept to its timetable.

**One connection per request.** Sharing connections would serialize requests behind each
other inside the client and reintroduce, in the generator, the head-of-line blocking the
scenarios exist to detect in the server. The bench container widens its ephemeral port range
and enables `tcp_tw_reuse` for the same reason; without them a sustained flood exhausts the
port range and connection failures look identical to the server refusing requests.

**Interleaved arms.** Which arm goes first alternates on every repetition, so thermal drift
and noisy neighbours land on both.

**Repetition and spread.** Five repetitions, median reported, every individual value kept.
Two arms are called different only when their observed ranges do not overlap, which is a
deliberately blunt test that errs toward calling things noise.

**Restarts, not assumptions.** Cold-start repetitions restart the container rather than
assuming the cache is empty. Steady-state measurements discard a warmup.

**Identical limits.** `report.provenance` reads both application containers' CPU and memory
limits from the Docker daemon and refuses to run if they differ. An unfair comparison is
worse than no comparison, and a warning in a log is not a control.

### Provenance

Every result file carries the same block: UTC timestamp, hostname, CPU model, core count,
kernel, Docker version, both containers' CPU and memory limits, repetition count, the
Keycloak image and its digest, and the resolved version of both libraries. Absolute numbers
describe one machine running Docker. The ratio between the two arms is the transferable part.

### The bench container

It sits on the compose network and addresses services by name, so its requests do not
traverse the host's published ports. It gets the Docker socket for two reasons and no
others: three scenarios restart application containers between repetitions, and provenance
reads container limits and image digests from the daemon. It is standard library only and
imports neither library under test.

`app/probe.py` is baked into the application image and run with `docker exec`. It measures
the things that are properties of an environment rather than of a running server: import
cost in a bare interpreter, installed distributions, per-request call counts under
`sys.setprofile`, and a static call graph parsed with `ast`.

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
