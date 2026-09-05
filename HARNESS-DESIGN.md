# Replacement for the spec's "Integration comparison harness" section

Supersedes the mock-OIDC-provider design. The harness runs a **real Keycloak**, because a
comparison against a provider we wrote ourselves proves less than a comparison against the
provider these libraries actually face. Keycloak is also what `vantage-api`,
`vantage-mcp-infra` and `slurm-mcp` authenticate against, so the harness exercises the real
migration path rather than an approximation of it.

## Services

```
legacy_comparison_compose/
  docker-compose.yaml
  Dockerfile.app            one image, parameterized by build arg
  Dockerfile.bench
  realm/
    armasec-realm.json      imported at Keycloak start
  app/
    main.py                 ONE app module, import selected by env var
  proxy/
    main.py                 counting and latency-injecting reverse proxy
  bench/
    run.py                  scenario driver
    scenarios.py
    report.py
  results/                  committed JSON
  test_parity.py            pytest: identical responses from both services
```

| Service | What it is |
| --- | --- |
| `keycloak` | `quay.io/keycloak/keycloak`, `start-dev --import-realm`, realm imported from `realm/armasec-realm.json` |
| `oidc-proxy` | A small asyncio reverse proxy in front of Keycloak. Counts requests per path, injects a configurable delay, and exposes `/__stats`, `/__latency` and `/__reset` |
| `app-legacy` | FastAPI on upstream `armasec==3.0.3` |
| `app-lite` | FastAPI on `armasec-lite` |
| `bench` | The load generator and scenario driver |

## Why a proxy sits in front of Keycloak

Three things the scenarios need that Keycloak cannot provide directly, and one trap.

**Exact request counting.** The headline caching claim is that N distinct `lockdown()` scope
sets against one domain cost 2 HTTP calls rather than 2N. That has to be counted at the
wire, not inferred. Keycloak has no per-path request counter, so the proxy keeps one.

**Injectable latency.** Scenario S5 sweeps provider latency to show how cold-start cost
scales with it, and S4's event-loop blocking is only visible when the provider is slow
enough to matter. A real Keycloak on the same host answers in single-digit milliseconds,
which would hide the effect being measured. The proxy adds a controlled delay.

**Fault injection.** The rate-limit fix depends on a failing provider still advancing the
refresh clock. The proxy can return 500s or hang on demand, which Keycloak will not do for
us.

**The trap: `KC_HOSTNAME` must point at the proxy.** Keycloak's discovery document
advertises absolute URLs, and its `jwks_uri` is one of them. Left at its default, Keycloak
would advertise its own address, the application would fetch the JWKS directly from
Keycloak, and every JWKS request would bypass the proxy and go uncounted. Setting
`KC_HOSTNAME` to the proxy's address makes discovery advertise proxy URLs, so both fetches
traverse the proxy. It also keeps `issuer` consistent between the discovery document and the
`iss` claim in minted tokens, which matters because `armasec-lite` verifies the issuer by
exact string equality and upstream does not.

That last point is worth stating plainly: **the harness is a live test of the one deliberate
behavior difference between the two libraries.** A Keycloak behind a proxy is exactly the
deployment shape where issuer mismatches occur in practice.

## Realm

`realm/armasec-realm.json` defines realm `armasec` with:

- A confidential client `armasec-api` with service accounts and direct access grants
  enabled, so the bench can mint tokens by both client credentials and password grant.
- Client roles `read:stuff`, `write:stuff` and `admin:stuff`, assigned to a service account
  and to a test user, so scope checks have something real to check.
- An **audience mapper** putting `armasec-api` into `aud`. Keycloak's default audience is
  `account`, which would make the audience check vacuous.
- A second client `other-api` with its own audience, so a scenario can prove that a token
  minted for one API is rejected by the other.

Keycloak places client roles under `resource_access.<client>.roles`, not in a top-level
`permissions` claim, so both applications configure
`permission_extractor=extract_keycloak_permissions`. That is the realistic configuration for
a Keycloak deployment and it exercises a feature both libraries implement.

## Fairness

Unchanged from the previous design and still the thing that makes the comparison worth
publishing: one app module selecting its import from an environment variable, one
Dockerfile parameterized by build arg, identical `cpus` and `mem_limit`, trials interleaved
rather than run in blocks, five repetitions with container restarts between cold-start runs,
and an open-loop load generator so a stalled server does not slow the offered load and hide
its own stall.

## Scenarios

| ID | Scenario | Measures |
| --- | --- | --- |
| S1 | Cold start, one route, concurrency 1 to 64 | p50, p95, max time to first response |
| S2 | Cold start, N distinct `lockdown()` scope sets, N in 1, 5, 10, 20 | OIDC requests counted at the proxy, wall time until all routes warm |
| S3 | Warm steady state, sustained open-loop load | requests per second, latency percentiles |
| S4 | Unauthenticated `/health` hammered during a cold auth load | `/health` latency, which exposes event-loop blocking from outside the process |
| S5 | Provider latency sweep at 0, 50, 200, 500 ms | cold-start sensitivity to provider latency |
| S6 | Keycloak realm key rotation mid-run | error count after rotation, time to recovery |
| S7 | Malformed, expired, wrong-audience, wrong-issuer, insufficient-scope tokens | HTTP status from each service |
| S8 | Provider returning 500s while unknown-`kid` tokens arrive | outbound requests counted at the proxy |
| S9 | Warm steady state at the S3 rate ladder | CPU microseconds and memory per request, from cgroup v2 |
| S10 | The S4 workload with both containers' CPU sampled at 50ms | whether the stall is a blocked process or a saturated one |
| S11 | Both containers idle, no traffic | CPU consumed at rest, expected to be approximately zero |

S4 remains the central result.

S9, S10 and S11 were added because call counts and latency are both proxies for work and
neither is the work itself. S9 answers the "does one library do more" question with the
quantity that actually settles it, and it is built to be able to return a flat result, which
would say the latency difference is not compute. S10 is the sharper use: a process blocked in
a socket read and a process saturating its core look identical in a latency chart, and CPU
separates them, so it says whether S4's stall is idle waiting or overload. S11 is a null
result by design.

Building them turned up a defect in the harness itself. The application health probe was
`python -c 'import urllib.request; urllib.request.urlopen(...)'` on a three second interval,
which costs 287ms of CPU per probe and which Docker charges to the container it probes: 9.6%
of one core, burned continuously, in both arms. It never biased the latency comparison, since
the two arms carry the identical probe, and it is invisible in a latency measurement. It is
not invisible in a CPU one. The probe is now a bare socket check on a sixty second interval
with a one second start interval, and idle CPU fell to 0.15% of a core. S6 now rotates **real Keycloak realm keys** through the admin
API rather than swapping a fixture, which is a materially stronger demonstration: upstream
caches the JWKS for the process lifetime and should 401 until restarted, while
`armasec-lite` should recover within its refetch interval.

S8 is new, and it exists because the final review found a real vulnerability there: a
failing provider used to leave the refresh clock un-advanced, so every unknown-`kid` token
produced another outbound request. `kid` is attacker-chosen. The scenario asserts the
outbound count stays bounded while the provider is failing, which is the property the fix
introduced and which nothing outside the unit tests currently proves.

S7 asserts **parity**: both services must return the same status for the same request,
except for the documented `verify_issuer` difference, which gets its own explicit case.

## Results

Written to `legacy_comparison_compose/results/v<version>/<UTC timestamp>/*.json` and
committed, with
one entry per run in `results/index.json`, each file carrying provenance: UTC timestamp,
hostname, CPU model, kernel, Docker version, container resource limits, repetition count, the
Keycloak image digest, the cgroup version and mount point, and the resolved version of both
libraries. Numbers describe one machine running Docker, and the documentation says so. The
ratio between the two arms is the meaningful part, not the absolute milliseconds.
