"""
The load generator and the scenarios it drives against the two application arms.

Everything here talks to the running services over the network from outside their
processes. Nothing imports either library under test, and neither library is installed in
this image. A measurement taken from inside a process cannot distinguish the cost of the
thing being measured from the cost of measuring it, and the headline result depends on
exactly that distinction.

### Why the generator is open loop

A closed-loop generator sends a request, waits for the response, and sends the next. When
the server stalls, it stops offering load. The stall then shows up as a handful of slow
requests rather than as the pile of delayed arrivals it actually caused, and the recorded
latency distribution understates the damage by however long the stall lasted. That is
coordinated omission, and it would erase scenario S4, whose entire subject is a server that
stops answering for a second.

So arrivals are scheduled on a fixed timetable from the start of the run and dispatched
whether or not earlier requests have finished. Latency is measured from a request's
**scheduled** arrival, not from when a socket was opened for it, so time spent queued
behind a stalled server is counted against it. `schedule_error_ms` in every result records
how far the generator itself drifted from its timetable, so a reader can see whether the
generator was keeping up.

Each request opens its own TCP connection. Sharing connections would serialize requests
behind each other inside the client and reintroduce, in the generator, exactly the
head-of-line blocking the scenarios exist to detect in the server. The extra handshake is
sub-millisecond on a container bridge network and it lands on both arms equally.

### Fairness

Arms alternate: the arm that goes first swaps on every repetition, so thermal drift, page
cache warming and noisy neighbours land on both. Application containers are restarted
between cold-start repetitions rather than being assumed cold. Warmup traffic is discarded
before steady-state measurement. The two arms carry identical CPU and memory limits, which
`report.provenance` verifies and refuses to run without.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from bench import report

PROXY_HOST = os.environ.get("HARNESS_PROXY_HOST", "oidc-proxy")
PROXY_PORT = int(os.environ.get("HARNESS_PROXY_PORT", "8080"))
PROXY_URL = f"http://{PROXY_HOST}:{PROXY_PORT}"
REALM_URL = f"{PROXY_URL}/realms/armasec"
TOKEN_URL = f"{REALM_URL}/protocol/openid-connect/token"
APP_PORT = int(os.environ.get("HARNESS_APP_PORT", "8000"))

#: The discovery and JWKS path keys the proxy counts under, spelled as Keycloak serves them.
DISCOVERY_PATH = "/realms/armasec/.well-known/openid-configuration"
JWKS_PATH = "/realms/armasec/protocol/openid-connect/certs"


@dataclass(frozen=True)
class Arm:
    """
    One side of the comparison.

    Attributes:
        name:    `legacy` or `lite`, used as the key in every result file.
        service: The compose service name, for restarts and container inspection.
        host:    The hostname the bench container reaches it on.
        port:    The port it serves on.
    """

    name: str
    service: str
    host: str
    port: int = APP_PORT


ARMS = (
    Arm("legacy", "app-legacy", os.environ.get("HARNESS_LEGACY_HOST", "app-legacy")),
    Arm("lite", "app-lite", os.environ.get("HARNESS_LITE_HOST", "app-lite")),
)


@dataclass
class Sample:
    """
    One request, timed from when it was supposed to happen.

    Attributes:
        scheduled: Seconds from the start of the run at which this request was due.
        sent:      Seconds at which the generator actually began it.
        done:      Seconds at which its response completed.
        status:    The HTTP status, or 0 when the request failed outright.
        error:     The failure, or None.
    """

    scheduled: float
    sent: float
    done: float
    status: int
    error: str | None = None

    @property
    def latency_ms(self) -> float:
        """Milliseconds from scheduled arrival to completed response."""
        return (self.done - self.scheduled) * 1000.0

    @property
    def service_ms(self) -> float:
        """Milliseconds the request itself took, generator scheduling excluded."""
        return (self.done - self.sent) * 1000.0

    @property
    def schedule_error_ms(self) -> float:
        """Milliseconds by which the generator missed this request's scheduled arrival."""
        return (self.sent - self.scheduled) * 1000.0


async def fetch(
    host: str, port: int, path: str, token: str | None = None, timeout: float = 30.0
) -> tuple[int, bytes]:
    """
    Make one HTTP/1.1 GET over a fresh connection.

    Written by hand rather than with a client library so that connection reuse, retries and
    pooling cannot silently become part of a measurement. `Connection: close` means the
    body is whatever arrives before EOF, which needs no chunked-encoding or content-length
    interpretation.

    Args:
        host:    The server hostname.
        port:    The server port.
        path:    The request path.
        token:   A bearer token, or None to send no Authorization header.
        timeout: Seconds before the whole exchange is abandoned.

    Returns:
        The status code and the response body. A status of 0 means the request never
        completed.
    """
    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            head = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n"
            if token is not None:
                head += f"Authorization: Bearer {token}\r\n"
            writer.write((head + "\r\n").encode())
            await writer.drain()
            status_line = await reader.readline()
            body = await reader.read()
    except (TimeoutError, OSError, asyncio.IncompleteReadError):
        return 0, b""
    finally:
        if writer is not None:
            writer.close()
    parts = status_line.split(b" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return status, body.partition(b"\r\n\r\n")[2]


async def open_loop(
    arm: Arm,
    path: str,
    *,
    rate: float,
    duration: float,
    token: str | None = None,
    on_start: Any = None,
) -> list[Sample]:
    """
    Offer load at a fixed arrival rate, regardless of whether the server is keeping up.

    Requests due at the same instant are all dispatched before the loop sleeps again, so a
    scheduler hiccup in the generator produces a burst that catches up rather than a
    permanently thinned load. Nothing waits for a response before scheduling the next
    arrival.

    Args:
        arm:      The service to load.
        path:     The path to request.
        rate:     Arrivals per second.
        duration: Seconds of arrivals to schedule.
        token:    A bearer token, or None.
        on_start: An optional coroutine function, awaited nothing and launched as a task at
                  t=0, used by S4 to fire its cold authentication load partway through.

    Returns:
        One `Sample` per scheduled arrival, in completion order.
    """
    samples: list[Sample] = []
    tasks: list[asyncio.Task[None]] = []
    total = int(rate * duration)
    started = time.perf_counter()

    async def one(scheduled: float) -> None:
        sent = time.perf_counter() - started
        status, _ = await fetch(arm.host, arm.port, path, token)
        done = time.perf_counter() - started
        samples.append(Sample(scheduled, sent, done, status))

    if on_start is not None:
        tasks.append(asyncio.create_task(on_start()))

    index = 0
    while index < total:
        now = time.perf_counter() - started
        due = min(total, int(now * rate) + 1)
        while index < due:
            tasks.append(asyncio.create_task(one(index / rate)))
            index += 1
        if index < total:
            ahead = index / rate - (time.perf_counter() - started)
            if ahead > 0:
                await asyncio.sleep(ahead)
    await asyncio.gather(*tasks, return_exceptions=True)
    return samples


def sample_stats(samples: list[Sample]) -> dict[str, Any]:
    """
    Reduce a set of samples to the numbers a result file should carry.

    Args:
        samples: The samples to reduce.

    Returns:
        Latency percentiles measured from scheduled arrival, the same for service time, the
        status distribution, the achieved rate, and the generator's own scheduling drift.
    """
    ok = [s for s in samples if 200 <= s.status < 400]
    statuses: dict[str, int] = {}
    for sample in samples:
        statuses[str(sample.status)] = statuses.get(str(sample.status), 0) + 1
    span = max((s.done for s in samples), default=0.0)
    return {
        "requests": len(samples),
        "successful": len(ok),
        "achieved_rps": len(samples) / span if span else 0.0,
        "statuses": statuses,
        "latency_ms": report.summarize([s.latency_ms for s in samples]),
        "service_ms": report.summarize([s.service_ms for s in samples]),
        "schedule_error_ms": report.summarize([s.schedule_error_ms for s in samples]),
    }


def http_json(url: str, timeout: float = 30.0) -> Any:
    """
    GET a URL and parse the result as JSON.

    Args:
        url:     The URL to fetch.
        timeout: Seconds to wait.

    Returns:
        The parsed object.
    """
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def proxy_stats() -> dict[str, Any]:
    """
    Read the proxy's request counters.

    Returns:
        The `/__stats` document.
    """
    return dict(http_json(f"{PROXY_URL}/__stats"))


def proxy_reset() -> None:
    """Zero the proxy's request counters."""
    http_json(f"{PROXY_URL}/__reset")


def proxy_latency(milliseconds: int) -> None:
    """
    Set the delay the proxy injects before every forwarded request.

    Args:
        milliseconds: The delay. Zero clears it.
    """
    http_json(f"{PROXY_URL}/__latency?ms={milliseconds}")


def proxy_fault(status: int, count: int = 0, path: str = "") -> None:
    """
    Arm or clear the proxy's fault injector.

    Args:
        status: The status to answer with. Zero clears the fault.
        count:  How many forwarded requests to fault.
        path:   Fault only paths containing this substring. Empty faults every path.
    """
    query = urllib.parse.urlencode({"status": status, "count": count, "path": path})
    http_json(f"{PROXY_URL}/__fault?{query}")


def oidc_counts(stats: dict[str, Any]) -> dict[str, int]:
    """
    Pull the two OIDC path counts out of a proxy stats document.

    Args:
        stats: A `/__stats` document.

    Returns:
        The discovery and JWKS counts, and their sum.
    """
    counts = stats.get("counts", {})
    discovery = int(counts.get(DISCOVERY_PATH, 0))
    jwks = int(counts.get(JWKS_PATH, 0))
    return {"discovery": discovery, "jwks": jwks, "total_oidc": discovery + jwks}


class Minter:
    """
    Mints and re-mints real Keycloak access tokens.

    Keycloak's default access token lifespan is five minutes and a full run is longer than
    that, so a token minted once at the start would expire mid-run and turn every
    subsequent 200 into a 401. The cache is refreshed well inside that window.

    Attributes:
        ttl: Seconds a minted token is reused for before another is requested.
    """

    def __init__(self, ttl: float = 120.0) -> None:
        """
        Args:
            ttl: Seconds to reuse a token for.
        """
        self.ttl = ttl
        self._token = ""
        self._minted_at = 0.0

    def mint(self) -> str:
        """
        Ask Keycloak for a fresh access token with `read:stuff`.

        Returns:
            The compact access token.

        Raises:
            RuntimeError: Keycloak refused, which means the realm import is wrong and no
                number this harness produces would mean anything.
        """
        form = {
            "grant_type": "password",
            "client_id": "armasec-api",
            "client_secret": "armasec-api-secret",
            "username": "testuser",
            "password": "testuser-password",
        }
        data = urllib.parse.urlencode(form).encode()
        try:
            with urllib.request.urlopen(TOKEN_URL, data=data, timeout=30) as response:
                return str(json.loads(response.read())["access_token"])
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"Keycloak refused to mint a token: {error.read()!r}") from error

    @property
    def token(self) -> str:
        """The current token, re-minted when it is older than `ttl`."""
        if not self._token or time.monotonic() - self._minted_at > self.ttl:
            self._token = self.mint()
            self._minted_at = time.monotonic()
        return self._token


def forge_unknown_kid(token: str) -> str:
    """
    Rewrite a token's `kid` header to a value no key in the JWKS carries.

    Only the header is changed, so the token still parses, still carries valid claims, and
    still fails at key lookup, which is exactly what a provider key rotation and an attacker
    probing for one look like from the server's side. `kid` is read from the unverified
    header, so this needs no signing key and an unauthenticated caller can do it too. That
    is the whole point of scenario S8.

    Args:
        token: A real compact JWT to base the forgery on.

    Returns:
        The token with an unknown `kid`.
    """
    head, _, rest = token.partition(".")
    padded = head + "=" * (-len(head) % 4)
    header = json.loads(base64.urlsafe_b64decode(padded))
    header["kid"] = "".join(random.choices("0123456789abcdef", k=32))
    reissued = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    return f"{reissued}.{rest}"


@dataclass
class Context:
    """
    Everything a scenario needs to run.

    Attributes:
        docker:  The Docker API client, for restarts and container inspection.
        minter:  The token source.
        reps:    Repetitions per measurement point.
        quick:   True to shorten every duration, for a smoke run.
        verbose: True to log each step as it happens.
    """

    docker: report.Docker
    minter: Minter
    reps: int = 5
    quick: bool = False
    verbose: bool = True
    log_lines: list[str] = field(default_factory=list)

    def log(self, message: str) -> None:
        """
        Record and optionally print one progress line.

        Args:
            message: What just happened.
        """
        self.log_lines.append(message)
        if self.verbose:
            print(f"  {message}", flush=True)

    def scale(self, seconds: float) -> float:
        """
        Shorten a duration for a smoke run.

        Args:
            seconds: The full-run duration.

        Returns:
            The duration to actually use.
        """
        return max(1.0, seconds / 5.0) if self.quick else seconds

    def order(self, repetition: int) -> tuple[Arm, ...]:
        """
        Choose which arm goes first, alternating by repetition.

        Args:
            repetition: The zero-based repetition index.

        Returns:
            The arms in the order they should be measured this repetition.
        """
        return ARMS if repetition % 2 == 0 else tuple(reversed(ARMS))


def wait_healthy(arm: Arm, timeout: float = 90.0) -> float:
    """
    Block until an arm answers `/health`.

    Args:
        arm:     The service to wait for.
        timeout: Seconds before giving up.

    Returns:
        Seconds waited.

    Raises:
        RuntimeError: The service never came back, which invalidates the repetition rather
            than being something to measure around.
    """
    started = time.perf_counter()
    while time.perf_counter() - started < timeout:
        try:
            with urllib.request.urlopen(
                f"http://{arm.host}:{arm.port}/health", timeout=2
            ) as response:
                if response.status == 200:
                    return time.perf_counter() - started
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(0.05)
    raise RuntimeError(f"{arm.name} did not become healthy within {timeout}s")


def restart(context: Context, arm: Arm) -> float:
    """
    Restart an arm's container and wait for it to serve again.

    Args:
        context: The run context.
        arm:     The arm to restart.

    Returns:
        Seconds from the restart call to the first successful `/health`.
    """
    started = time.perf_counter()
    context.docker.restart(arm.service)
    wait_healthy(arm)
    return time.perf_counter() - started


def library_versions() -> dict[str, str]:
    """
    Read the resolved library version each arm actually loaded.

    Returns:
        The version string for each arm, keyed by arm name.
    """
    versions: dict[str, str] = {}
    for arm in ARMS:
        document = http_json(f"http://{arm.host}:{arm.port}/health")
        versions[arm.name] = f"{document['lib']} {document['version']}"
    return versions


# --------------------------------------------------------------------------------------
# S4: event loop blocking, the headline
# --------------------------------------------------------------------------------------

#: Provider latency injected during S4. Two OIDC fetches at this delay is roughly a second
#: of network wait, which is long enough to see from outside and short enough that five
#: repetitions of both arms stay inside a few minutes.
S4_LATENCY_MS = 500
S4_RATE = 40.0
S4_DURATION = 8.0
#: Shortened for a smoke run, but never below the point where the cold load and the stall it
#: may cause both fit inside the window. A shorter run would fire the authenticated request
#: after the `/health` stream had already finished and would measure nothing at all, which
#: is a mistake this harness made once.
S4_QUICK_DURATION = 6.0
#: The cold load fires a quarter of the way in, leaving a clean baseline before it and room
#: for two injected provider delays plus recovery after it.
S4_TRIGGER_FRACTION = 0.25


def s4_duration(context: Context) -> tuple[float, float]:
    """
    Choose the S4 window and the point inside it where the cold load fires.

    Args:
        context: The run context.

    Returns:
        The `/health` stream duration and the offset at which the authenticated request is
        launched.
    """
    duration = S4_QUICK_DURATION if context.quick else S4_DURATION
    return duration, duration * S4_TRIGGER_FRACTION


async def s4_one_run(
    arm: Arm, token: str, duration: float, trigger_at: float
) -> tuple[list[Sample], float, int]:
    """
    Hammer `/health` on one arm while a single cold authenticated request lands mid-stream.

    `/health` requires no token and touches neither library, so every millisecond of latency
    it gains is the event loop being unavailable to serve it. That is the measurement: it
    needs no instrumentation inside either process and cannot be confounded by the cost of
    authentication itself, because the requests being timed are not authenticated.

    Args:
        arm:        The arm to load. Must have been restarted, so its OIDC cache is empty.
        token:      A valid token for the cold authenticated request.
        duration:   Seconds of `/health` load.
        trigger_at: Seconds into the stream at which the cold authenticated request fires.

    Returns:
        The `/health` samples, how many milliseconds the cold authenticated request took,
        and the status it returned.
    """
    auth: dict[str, Any] = {"ms": 0.0, "status": 0}

    async def trigger() -> None:
        await asyncio.sleep(trigger_at)
        started = time.perf_counter()
        status, _ = await fetch(arm.host, arm.port, "/stuff", token, timeout=60.0)
        auth["ms"] = (time.perf_counter() - started) * 1000.0
        auth["status"] = status

    samples = await open_loop(arm, "/health", rate=S4_RATE, duration=duration, on_start=trigger)
    return samples, float(auth["ms"]), int(auth["status"])


def s4_event_loop_blocking(context: Context) -> dict[str, Any]:
    """
    Scenario S4: does a cold authentication load stop the process answering anything else?

    Upstream armasec fetches the OIDC discovery document and the JWKS with a synchronous
    HTTP client called from inside an async dependency, so the fetch runs on the event loop
    thread and nothing else in the process runs until it returns. armasec-lite does the same
    fetches on an executor thread. The difference should appear as a stall in an
    unauthenticated route's latency, and it is measured from outside the process by a
    generator that keeps offering load throughout.

    Args:
        context: The run context.

    Returns:
        The scenario document, including the full `/health` latency time series for every
        repetition, which is what makes the result plottable.
    """
    duration, trigger_at = s4_duration(context)
    window_end = trigger_at + (2 * S4_LATENCY_MS / 1000.0) + 1.5
    per_arm: dict[str, list[dict[str, Any]]] = {"legacy": [], "lite": []}

    for repetition in range(context.reps):
        for arm in context.order(repetition):
            proxy_latency(0)
            restart_seconds = restart(context, arm)
            proxy_latency(S4_LATENCY_MS)
            token = context.minter.token
            samples, auth_ms, auth_status = asyncio.run(
                s4_one_run(arm, token, duration, trigger_at)
            )
            proxy_latency(0)

            before = [s.latency_ms for s in samples if s.scheduled < trigger_at - 0.2]
            during = [s.latency_ms for s in samples if trigger_at - 0.2 <= s.scheduled < window_end]
            baseline_p50 = report.percentile(before, 0.50)
            per_arm[arm.name].append(
                {
                    "restart_seconds": restart_seconds,
                    "auth_request_ms": auth_ms,
                    "auth_status": auth_status,
                    "health_baseline": report.summarize(before),
                    "health_during_cold_load": report.summarize(during),
                    "health_overall": sample_stats(samples),
                    "stalled_over_100ms": sum(1 for s in samples if s.latency_ms > 100.0),
                    "stalled_over_250ms": sum(1 for s in samples if s.latency_ms > 250.0),
                    "worst_health_ms": max((s.latency_ms for s in samples), default=0.0),
                    "baseline_p50_ms": baseline_p50,
                    "series": [
                        {
                            "t": round(s.scheduled, 4),
                            "latency_ms": round(s.latency_ms, 3),
                            "status": s.status,
                        }
                        for s in sorted(samples, key=lambda s: s.scheduled)
                    ],
                }
            )
            context.log(
                f"S4 rep {repetition + 1} {arm.name}: worst /health "
                f"{per_arm[arm.name][-1]['worst_health_ms']:.1f}ms, "
                f"{per_arm[arm.name][-1]['stalled_over_100ms']} over 100ms, "
                f"cold auth {auth_ms:.0f}ms -> {auth_status}"
            )

    worst = {arm: [rep["worst_health_ms"] for rep in reps] for arm, reps in per_arm.items()}
    stalled = {arm: [rep["stalled_over_100ms"] for rep in reps] for arm, reps in per_arm.items()}
    baseline = {arm: [rep["baseline_p50_ms"] for rep in reps] for arm, reps in per_arm.items()}
    during_p99 = {
        arm: [rep["health_during_cold_load"].get("p99", 0.0) for rep in reps]
        for arm, reps in per_arm.items()
    }

    return {
        "scenario": "S4",
        "title": "Unauthenticated /health latency during a cold authentication load",
        "question": (
            "Does the cold OIDC load block the event loop, and therefore every other "
            "request the process is serving?"
        ),
        "config": {
            "health_rate_per_second": S4_RATE,
            "duration_seconds": duration,
            "cold_auth_triggered_at_seconds": trigger_at,
            "injected_provider_latency_ms": S4_LATENCY_MS,
            "expected_cold_fetch_cost_ms": 2 * S4_LATENCY_MS,
            "open_loop": True,
            "restart_before_each_repetition": True,
        },
        "measurements": {
            "worst_health_latency_ms": {
                arm: report.across_reps(values) for arm, values in worst.items()
            },
            "health_requests_over_100ms": {
                arm: report.across_reps([float(v) for v in values])
                for arm, values in stalled.items()
            },
            "health_p99_during_cold_load_ms": {
                arm: report.across_reps(values) for arm, values in during_p99.items()
            },
            "health_baseline_p50_ms": {
                arm: report.across_reps(values) for arm, values in baseline.items()
            },
            "repetitions": per_arm,
        },
        "verdicts": {
            "worst_health_latency": report.verdict(worst["legacy"], worst["lite"]),
            "health_requests_over_100ms": report.verdict(
                [float(v) for v in stalled["legacy"]], [float(v) for v in stalled["lite"]]
            ),
            "baseline_p50": report.verdict(baseline["legacy"], baseline["lite"]),
        },
        "summary_rows": [
            [
                "S4 worst /health latency (ms)",
                f"{report.across_reps(worst['legacy'])['median']:.1f}",
                f"{report.across_reps(worst['lite'])['median']:.1f}",
                report.verdict(worst["legacy"], worst["lite"]),
            ],
            [
                "S4 /health requests over 100ms",
                f"{report.across_reps([float(v) for v in stalled['legacy']])['median']:.0f}",
                f"{report.across_reps([float(v) for v in stalled['lite']])['median']:.0f}",
                report.verdict(
                    [float(v) for v in stalled["legacy"]], [float(v) for v in stalled["lite"]]
                ),
            ],
        ],
    }


# --------------------------------------------------------------------------------------
# S3: the flood
# --------------------------------------------------------------------------------------

S3_RATES = (100.0, 300.0, 600.0, 900.0)
S3_WARMUP = 2.0
S3_DURATION = 10.0


def s3_flood(context: Context) -> dict[str, Any]:
    """
    Scenario S3: sustained open-loop load on an authenticated route against a warm cache.

    On the warm path both libraries verify a signature against a cached key and do
    essentially the same work, so the expectation is parity and a flat result is the correct
    outcome. The rate ladder exists so the answer is not one number at one arrival rate: a
    difference that only appears at saturation is a different claim from one that appears
    everywhere, and a ladder shows which it is.

    Args:
        context: The run context.

    Returns:
        The scenario document.
    """
    proxy_latency(0)
    duration = context.scale(S3_DURATION)
    warmup = context.scale(S3_WARMUP)
    rates = S3_RATES if not context.quick else S3_RATES[:2]
    results: dict[str, dict[str, list[dict[str, Any]]]] = {
        f"{rate:.0f}": {"legacy": [], "lite": []} for rate in rates
    }

    for arm in ARMS:
        wait_healthy(arm)
        asyncio.run(fetch(arm.host, arm.port, "/stuff", context.minter.token))

    for repetition in range(context.reps):
        for rate in rates:
            for arm in context.order(repetition):
                token = context.minter.token
                asyncio.run(open_loop(arm, "/stuff", rate=rate, duration=warmup, token=token))
                samples = asyncio.run(
                    open_loop(arm, "/stuff", rate=rate, duration=duration, token=token)
                )
                stats = sample_stats(samples)
                results[f"{rate:.0f}"][arm.name].append(stats)
                context.log(
                    f"S3 rep {repetition + 1} {arm.name} @{rate:.0f}rps: "
                    f"achieved {stats['achieved_rps']:.0f}rps, "
                    f"p50 {stats['latency_ms']['p50']:.1f}ms, "
                    f"p99 {stats['latency_ms']['p99']:.1f}ms, "
                    f"{stats['successful']}/{stats['requests']} ok"
                )

    measurements: dict[str, Any] = {}
    verdicts: dict[str, str] = {}
    rows: list[list[str]] = []
    for rate in rates:
        key = f"{rate:.0f}"
        per_arm = results[key]
        block: dict[str, Any] = {}
        for metric, extract in (
            ("achieved_rps", lambda s: s["achieved_rps"]),
            ("p50_ms", lambda s: s["latency_ms"]["p50"]),
            ("p95_ms", lambda s: s["latency_ms"]["p95"]),
            ("p99_ms", lambda s: s["latency_ms"]["p99"]),
            ("max_ms", lambda s: s["latency_ms"]["max"]),
            ("schedule_error_p99_ms", lambda s: s["schedule_error_ms"]["p99"]),
        ):
            block[metric] = {
                arm: report.across_reps([extract(s) for s in per_arm[arm]]) for arm in per_arm
            }
        block["success_rate"] = {
            arm: report.across_reps(
                [s["successful"] / s["requests"] if s["requests"] else 0.0 for s in per_arm[arm]]
            )
            for arm in per_arm
        }
        block["repetitions"] = per_arm
        measurements[f"target_{key}_rps"] = block
        for metric, lower_better in (("p50_ms", True), ("p99_ms", True), ("achieved_rps", False)):
            verdicts[f"{key}rps_{metric}"] = report.verdict(
                block[metric]["legacy"]["values"],
                block[metric]["lite"]["values"],
                lower_is_better=lower_better,
            )
        rows.append(
            [
                f"S3 @{key}rps p99 latency (ms)",
                f"{block['p99_ms']['legacy']['median']:.1f}",
                f"{block['p99_ms']['lite']['median']:.1f}",
                verdicts[f"{key}rps_p99_ms"],
            ]
        )

    return {
        "scenario": "S3",
        "title": "Warm steady state, sustained open-loop load on an authenticated route",
        "question": "Does either library cost more per request once its key cache is warm?",
        "config": {
            "path": "/stuff",
            "target_rates_per_second": list(rates),
            "warmup_seconds_discarded": warmup,
            "measured_seconds": duration,
            "open_loop": True,
            "injected_provider_latency_ms": 0,
        },
        "measurements": measurements,
        "verdicts": verdicts,
        "summary_rows": rows,
    }


# --------------------------------------------------------------------------------------
# S1: cold start
# --------------------------------------------------------------------------------------

S1_CONCURRENCIES = (1, 2, 4, 8, 16, 32, 64)


async def s1_burst(arm: Arm, token: str, concurrency: int) -> list[tuple[float, int]]:
    """
    Fire a burst of authenticated requests at a cold process and time each one.

    Args:
        arm:         The arm to hit.
        token:       A valid token.
        concurrency: How many requests to launch at once.

    Returns:
        Milliseconds from launch to completion and the status returned, one pair per
        request, in completion order.
    """
    started = time.perf_counter()
    results: list[tuple[float, int]] = []

    async def one() -> None:
        status, _ = await fetch(arm.host, arm.port, "/stuff", token, timeout=60.0)
        results.append(((time.perf_counter() - started) * 1000.0, status))

    await asyncio.gather(*[one() for _ in range(concurrency)])
    return results


def s1_cold_start(context: Context) -> dict[str, Any]:
    """
    Scenario S1: how long does the first authenticated request take on a fresh process?

    Every repetition restarts the container, so the OIDC cache really is empty rather than
    assumed to be. The concurrency sweep matters because the two libraries reach the same
    cache by different routes: a synchronous fetch on the event loop serializes every
    concurrent arrival behind it by construction, while an executor-thread fetch needs a
    lock to achieve the same thing. The OIDC request counts recorded alongside the latencies
    say which happened.

    Args:
        context: The run context.

    Returns:
        The scenario document.
    """
    proxy_latency(0)
    per_level: dict[str, dict[str, list[dict[str, Any]]]] = {
        str(c): {"legacy": [], "lite": []} for c in S1_CONCURRENCIES
    }
    levels = S1_CONCURRENCIES if not context.quick else (1, 8, 64)

    for repetition in range(context.reps):
        for concurrency in levels:
            for arm in context.order(repetition):
                proxy_reset()
                restart(context, arm)
                token = context.minter.token
                before = oidc_counts(proxy_stats())
                burst = asyncio.run(s1_burst(arm, token, concurrency))
                after = oidc_counts(proxy_stats())
                times = [elapsed for elapsed, _ in burst]
                statuses: dict[str, int] = {}
                for _, status in burst:
                    statuses[str(status)] = statuses.get(str(status), 0) + 1
                per_level[str(concurrency)][arm.name].append(
                    {
                        "first_response_ms": min(times) if times else 0.0,
                        "last_response_ms": max(times) if times else 0.0,
                        "latency_ms": report.summarize(times),
                        "statuses": statuses,
                        "oidc_requests": {key: after[key] - before[key] for key in after},
                    }
                )
        context.log(f"S1 repetition {repetition + 1} of {context.reps} done")

    measurements: dict[str, Any] = {}
    rows: list[list[str]] = []
    verdicts: dict[str, str] = {}
    for concurrency in levels:
        key = str(concurrency)
        per_arm = per_level[key]
        block = {
            metric: {
                arm: report.across_reps([float(rep[metric]) for rep in per_arm[arm]])
                for arm in per_arm
            }
            for metric in ("first_response_ms", "last_response_ms")
        }
        block["p95_ms"] = {
            arm: report.across_reps([rep["latency_ms"]["p95"] for rep in per_arm[arm]])
            for arm in per_arm
        }
        block["max_ms"] = {
            arm: report.across_reps([rep["latency_ms"]["max"] for rep in per_arm[arm]])
            for arm in per_arm
        }
        block["oidc_requests_total"] = {
            arm: report.across_reps(
                [float(rep["oidc_requests"]["total_oidc"]) for rep in per_arm[arm]]
            )
            for arm in per_arm
        }
        block["repetitions"] = per_arm
        measurements[f"concurrency_{key}"] = block
        verdicts[f"c{key}_first_response"] = report.verdict(
            block["first_response_ms"]["legacy"]["values"],
            block["first_response_ms"]["lite"]["values"],
        )
        verdicts[f"c{key}_last_response"] = report.verdict(
            block["last_response_ms"]["legacy"]["values"],
            block["last_response_ms"]["lite"]["values"],
        )
        rows.append(
            [
                f"S1 c={key} time to first response (ms)",
                f"{block['first_response_ms']['legacy']['median']:.1f}",
                f"{block['first_response_ms']['lite']['median']:.1f}",
                verdicts[f"c{key}_first_response"],
            ]
        )

    return {
        "scenario": "S1",
        "title": "Cold start: time to first response after a container restart",
        "question": "What does the first authenticated request cost on a fresh process?",
        "config": {
            "concurrencies": list(levels),
            "path": "/stuff",
            "injected_provider_latency_ms": 0,
            "restart_before_each_repetition": True,
        },
        "measurements": measurements,
        "verdicts": verdicts,
        "summary_rows": rows,
    }


# --------------------------------------------------------------------------------------
# S2: request amplification
# --------------------------------------------------------------------------------------

S2_SCOPE_SETS = (0, 1, 5, 10, 20)


def s2_amplification(context: Context) -> dict[str, Any]:
    """
    Scenario S2: how many OIDC fetches do N distinct `lockdown()` scope sets cost?

    Counted at the wire by the proxy, never inferred. The counters are reset before the
    restart rather than after it, so anything the process fetches during startup is counted
    too and a library that loads its configuration eagerly cannot hide behind the reset.

    Each `/scope/i` route is locked behind a scope no token in the realm holds, so the
    requests are answered 403. That is deliberate and it does not weaken the count: a scope
    check happens after the token has been decoded, so the OIDC configuration and JWKS have
    already been loaded by the time the request is refused.

    Args:
        context: The run context.

    Returns:
        The scenario document.
    """
    proxy_latency(0)
    per_level: dict[str, dict[str, list[dict[str, Any]]]] = {
        str(n): {"legacy": [], "lite": []} for n in S2_SCOPE_SETS
    }

    for repetition in range(context.reps):
        for scope_sets in S2_SCOPE_SETS:
            for arm in context.order(repetition):
                token = context.minter.token
                proxy_reset()
                restart(context, arm)
                started = time.perf_counter()
                statuses: list[int] = []
                for index in range(scope_sets):
                    status, _ = asyncio.run(
                        fetch(arm.host, arm.port, f"/scope/{index}", token, timeout=60.0)
                    )
                    statuses.append(status)
                elapsed = (time.perf_counter() - started) * 1000.0
                counts = oidc_counts(proxy_stats())
                per_level[str(scope_sets)][arm.name].append(
                    {
                        "oidc_requests": counts,
                        "wall_ms": elapsed,
                        "statuses": sorted(set(statuses)),
                    }
                )
        context.log(f"S2 repetition {repetition + 1} of {context.reps} done")

    measurements: dict[str, Any] = {}
    rows: list[list[str]] = []
    verdicts: dict[str, str] = {}
    for scope_sets in S2_SCOPE_SETS:
        key = str(scope_sets)
        per_arm = per_level[key]
        block = {
            metric: {
                arm: report.across_reps(
                    [float(rep["oidc_requests"][metric]) for rep in per_arm[arm]]
                )
                for arm in per_arm
            }
            for metric in ("discovery", "jwks", "total_oidc")
        }
        block["wall_ms"] = {
            arm: report.across_reps([rep["wall_ms"] for rep in per_arm[arm]]) for arm in per_arm
        }
        block["repetitions"] = per_arm
        measurements[f"scope_sets_{key}"] = block
        verdicts[f"n{key}_total_oidc"] = report.verdict(
            block["total_oidc"]["legacy"]["values"], block["total_oidc"]["lite"]["values"]
        )
        rows.append(
            [
                f"S2 N={key} OIDC fetches at the proxy",
                f"{block['total_oidc']['legacy']['median']:.0f}",
                f"{block['total_oidc']['lite']['median']:.0f}",
                verdicts[f"n{key}_total_oidc"],
            ]
        )

    return {
        "scenario": "S2",
        "title": "Request amplification: OIDC fetches per distinct lockdown() scope set",
        "question": (
            "Does each distinct lockdown() scope set build its own OIDC loader and fetch "
            "the provider again?"
        ),
        "config": {
            "scope_set_counts": list(S2_SCOPE_SETS),
            "counted_at": "the proxy, per path, with counters reset before the restart",
            "expected_statuses": "403, since no token in the realm holds these scopes",
            "injected_provider_latency_ms": 0,
        },
        "measurements": measurements,
        "verdicts": verdicts,
        "summary_rows": rows,
    }


# --------------------------------------------------------------------------------------
# S8: failing provider
# --------------------------------------------------------------------------------------

S8_UNKNOWN_KID_REQUESTS = 60


def s8_failing_provider(context: Context) -> dict[str, Any]:
    """
    Scenario S8: does a failing provider plus attacker-chosen `kid` values amplify traffic?

    `kid` is read from a token's unverified header, so an unauthenticated caller picks it.
    If an unknown `kid` triggers a JWKS refetch and a failed refetch leaves the refresh
    clock un-advanced, then every forged token produces another outbound request and the
    application becomes an amplifier pointed at its own identity provider. That was a real
    defect and its fix is the property this scenario tests.

    Only the JWKS path is faulted. Faulting everything would stop discovery too, and the
    application would never reach the point where an unknown key id is noticed, so the
    scenario would measure a broken provider rather than the refresh rate limit.

    Args:
        context: The run context.

    Returns:
        The scenario document.
    """
    proxy_latency(0)
    per_arm: dict[str, list[dict[str, Any]]] = {"legacy": [], "lite": []}
    attempts = S8_UNKNOWN_KID_REQUESTS if not context.quick else 15

    for repetition in range(context.reps):
        for arm in context.order(repetition):
            token = context.minter.token
            proxy_fault(0)
            proxy_reset()
            restart(context, arm)

            warm_status, _ = asyncio.run(fetch(arm.host, arm.port, "/stuff", token, timeout=60.0))
            warm_counts = oidc_counts(proxy_stats())

            proxy_fault(500, count=100_000, path="certs")
            statuses: list[int] = []
            for _ in range(attempts):
                forged = forge_unknown_kid(token)
                status, _ = asyncio.run(fetch(arm.host, arm.port, "/stuff", forged, timeout=60.0))
                statuses.append(status)
            after = oidc_counts(proxy_stats())
            proxy_fault(0)

            distribution: dict[str, int] = {}
            for status in statuses:
                distribution[str(status)] = distribution.get(str(status), 0) + 1
            per_arm[arm.name].append(
                {
                    "warm_status": warm_status,
                    "oidc_after_warmup": warm_counts,
                    "unknown_kid_requests": attempts,
                    "jwks_fetches_during_flood": after["jwks"] - warm_counts["jwks"],
                    "discovery_fetches_during_flood": after["discovery"] - warm_counts["discovery"],
                    "statuses": distribution,
                }
            )
            context.log(
                f"S8 rep {repetition + 1} {arm.name}: {attempts} unknown-kid requests caused "
                f"{per_arm[arm.name][-1]['jwks_fetches_during_flood']} JWKS fetches, "
                f"statuses {distribution}"
            )

    fetches = {
        arm: [float(rep["jwks_fetches_during_flood"]) for rep in reps]
        for arm, reps in per_arm.items()
    }
    return {
        "scenario": "S8",
        "title": "Failing provider with attacker-chosen unknown key ids",
        "question": (
            "While the JWKS endpoint is failing, does each unknown kid produce another "
            "outbound request?"
        ),
        "config": {
            "unknown_kid_requests_per_repetition": attempts,
            "fault": "500 on any path containing 'certs', discovery left working",
            "counted_at": "the proxy, JWKS path only, measured from after a successful warmup",
            "amplification_factor_if_unbounded": attempts,
        },
        "measurements": {
            "jwks_fetches_during_flood": {
                arm: report.across_reps(values) for arm, values in fetches.items()
            },
            "amplification_ratio": {
                arm: report.across_reps([v / attempts for v in values])
                for arm, values in fetches.items()
            },
            "repetitions": per_arm,
        },
        "verdicts": {"jwks_fetches": report.verdict(fetches["legacy"], fetches["lite"])},
        "summary_rows": [
            [
                f"S8 JWKS fetches for {attempts} unknown kids",
                f"{report.across_reps(fetches['legacy'])['median']:.0f}",
                f"{report.across_reps(fetches['lite'])['median']:.0f}",
                report.verdict(fetches["legacy"], fetches["lite"]),
            ]
        ],
    }


# --------------------------------------------------------------------------------------
# Footprint
# --------------------------------------------------------------------------------------

#: The dependencies the design set out to remove, plus the two the harness is asked about.
WATCHED = ("pytest", "respx", "python-jose", "py-buzz", "snick", "auto-name-enum", "pluggy")

#: Installed in both images by the harness itself, so excluding them gives a like-for-like
#: count of what each library actually drags in.
HARNESS_OVERHEAD = ("pip", "setuptools", "wheel", "uvicorn", "click", "h11")


def footprint(context: Context) -> dict[str, Any]:
    """
    Count what each arm actually has installed, read from the running containers.

    The raw count is every distribution `importlib.metadata` can see, which is the honest
    "what is in this image" number and includes pip and the harness's own uvicorn. The
    adjusted count removes the handful of things the harness installs into both images
    identically, so the remainder is attributable to the library under test.

    Args:
        context: The run context.

    Returns:
        The result document.
    """
    measurements: dict[str, Any] = {}
    for arm in ARMS:
        found = context.docker.exec_json(
            arm.service, ["python", "/srv/app/probe.py", "distributions"]
        )
        names = dict(found["distributions"])
        adjusted = {k: v for k, v in names.items() if k not in HARNESS_OVERHEAD}
        measurements[arm.name] = {
            "distribution_count": found["count"],
            "distribution_count_excluding_harness_overhead": len(adjusted),
            "watched_packages": {name: names.get(name) for name in WATCHED},
            "watched_present": sorted(name for name in WATCHED if name in names),
            "distributions": dict(sorted(names.items())),
        }
        context.log(
            f"footprint {arm.name}: {found['count']} distributions, "
            f"{len(adjusted)} excluding harness overhead, "
            f"watched present: {measurements[arm.name]['watched_present']}"
        )

    return {
        "scenario": "footprint",
        "title": "Installed distributions per arm, measured inside the running containers",
        "question": "How many distributions does each arm actually install?",
        "config": {
            "measured_with": "importlib.metadata.distributions() inside each app container",
            "harness_overhead_excluded_from_adjusted_count": list(HARNESS_OVERHEAD),
            "watched_packages": list(WATCHED),
        },
        "measurements": measurements,
        "verdicts": {
            "distribution_count": (
                f"upstream {measurements['legacy']['distribution_count']} vs "
                f"armasec-lite {measurements['lite']['distribution_count']}"
            )
        },
        "summary_rows": [
            [
                "Installed distributions",
                str(measurements["legacy"]["distribution_count"]),
                str(measurements["lite"]["distribution_count"]),
                "counted in the running container",
            ],
            [
                "Distributions excluding harness overhead",
                str(measurements["legacy"]["distribution_count_excluding_harness_overhead"]),
                str(measurements["lite"]["distribution_count_excluding_harness_overhead"]),
                f"excludes {', '.join(HARNESS_OVERHEAD)}",
            ],
        ],
    }


# --------------------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------------------

MEMORY_WARM_REQUESTS = 200
MEMORY_LOAD_RATE = 300.0
MEMORY_LOAD_SECONDS = 20.0
MEMORY_SAMPLE_SECONDS = 2.0


def container_rss(docker: report.Docker, arm: Arm) -> dict[str, Any]:
    """
    Read one container's memory usage from the Docker daemon.

    Taken from outside the process on purpose: reading a process's own memory allocates, and
    doing it inside only one arm's code path would not be a comparison at all.

    Args:
        docker: The API client.
        arm:    The arm to sample.

    Returns:
        The cgroup usage in bytes, the anonymous set when the daemon reports one, and the
        limit.
    """
    stats = docker.stats(arm.service)
    memory = stats.get("memory_stats", {})
    detail = memory.get("stats", {}) or {}
    anon = detail.get("anon", detail.get("rss"))
    return {
        "usage_bytes": memory.get("usage"),
        "anon_bytes": anon,
        "file_bytes": detail.get("file", detail.get("cache")),
        "limit_bytes": memory.get("limit"),
    }


def settled_rss(docker: report.Docker, arm: Arm, samples: int = 3) -> dict[str, Any]:
    """
    Take several memory samples and report their median.

    A single reading taken moments after a process starts catches it mid-churn: the first
    measurements taken this way had upstream's idle baseline reading higher than its warm
    figure, because the baseline landed before the import-time garbage had been collected.
    A median of a few samples a second apart removes that artefact without hiding a real
    difference.

    Args:
        docker:  The API client.
        arm:     The arm to sample.
        samples: How many readings to take.

    Returns:
        The median usage and anonymous set, and every reading taken.
    """
    readings = []
    for index in range(samples):
        if index:
            time.sleep(1.0)
        readings.append(container_rss(docker, arm))
    usage = sorted(r["usage_bytes"] for r in readings if r["usage_bytes"])
    anon = sorted(r["anon_bytes"] for r in readings if r["anon_bytes"])
    return {
        "usage_bytes": usage[len(usage) // 2] if usage else None,
        "anon_bytes": anon[len(anon) // 2] if anon else None,
        "limit_bytes": readings[0]["limit_bytes"],
        "readings": readings,
    }


def memory_footprint(context: Context) -> dict[str, Any]:
    """
    Measure resident memory at three points and the cost of importing each library.

    Baseline is what the process costs to exist, which is what matters to anyone running
    many replicas. Warm is after the OIDC cache is populated and the request path has been
    exercised. Under load is sampled during a sustained flood, which answers a different
    question: whether anything accumulates over a fixed workload.

    This runs as its own pass with the load generator otherwise idle, because sampling the
    daemon takes about a second per call and the latency scenarios must not carry that.

    Args:
        context: The run context.

    Returns:
        The result document.
    """
    proxy_latency(0)
    measurements: dict[str, Any] = {}
    load_seconds = context.scale(MEMORY_LOAD_SECONDS)

    for arm in ARMS:
        restart(context, arm)
        time.sleep(5.0)
        baseline = settled_rss(context.docker, arm)

        token = context.minter.token
        warm_rate, warm_seconds = 50.0, MEMORY_WARM_REQUESTS / 50.0
        asyncio.run(open_loop(arm, "/stuff", rate=warm_rate, duration=warm_seconds, token=token))
        warm = settled_rss(context.docker, arm)

        samples: list[dict[str, Any]] = []
        stop = threading.Event()

        def poll(
            target: Arm = arm,
            collected: list[dict[str, Any]] = samples,
            done: threading.Event = stop,
        ) -> None:
            while not done.is_set():
                collected.append({"t": time.time(), **container_rss(context.docker, target)})
                done.wait(MEMORY_SAMPLE_SECONDS)

        sampler = threading.Thread(target=poll, daemon=True)
        sampler.start()
        asyncio.run(
            open_loop(arm, "/stuff", rate=MEMORY_LOAD_RATE, duration=load_seconds, token=token)
        )
        stop.set()
        sampler.join(timeout=10.0)
        after = settled_rss(context.docker, arm)

        usages = [s["usage_bytes"] for s in samples if s.get("usage_bytes")]
        climb = (usages[-1] - usages[0]) if len(usages) >= 2 else 0
        import_cost = context.docker.exec_json(
            arm.service, ["python", "/srv/app/probe.py", "import-cost"]
        )
        measurements[arm.name] = {
            "baseline_idle": baseline,
            "warm": warm,
            "warm_requests_issued": int(warm_rate * warm_seconds),
            "under_load": {
                "rate_per_second": MEMORY_LOAD_RATE,
                "seconds": load_seconds,
                "samples": samples,
                "peak_usage_bytes": max(usages) if usages else None,
                "first_usage_bytes": usages[0] if usages else None,
                "last_usage_bytes": usages[-1] if usages else None,
                "climb_bytes": climb,
                "climb_pct": (climb / usages[0] * 100.0) if usages and usages[0] else None,
            },
            "after_load": after,
            "import_cost": import_cost,
        }
        context.log(
            f"memory {arm.name}: baseline {baseline['usage_bytes'] / 1e6:.1f}MB, "
            f"warm {warm['usage_bytes'] / 1e6:.1f}MB, "
            f"peak {(max(usages) if usages else 0) / 1e6:.1f}MB, "
            f"import +{import_cost['rss_delta_kib'] / 1024:.1f}MB / "
            f"{import_cost['modules_added']} modules"
        )

    def mb(value: Any) -> str:
        return f"{value / 1e6:.1f}" if value else "n/a"

    return {
        "scenario": "memory",
        "title": "Resident memory idle, warm and under load, plus per-library import cost",
        "question": "What does each arm cost to run, and does anything accumulate?",
        "config": {
            "measured_with": "the Docker daemon's container stats, never from inside the process",
            "warm_requests": MEMORY_WARM_REQUESTS,
            "load_rate_per_second": MEMORY_LOAD_RATE,
            "load_seconds": load_seconds,
            "sample_interval_seconds": MEMORY_SAMPLE_SECONDS,
            "separate_pass": "run with the latency scenarios idle, so sampling perturbs nothing",
        },
        "measurements": measurements,
        "verdicts": {
            "baseline": (
                f"upstream {mb(measurements['legacy']['baseline_idle']['usage_bytes'])}MB vs "
                f"armasec-lite {mb(measurements['lite']['baseline_idle']['usage_bytes'])}MB"
            )
        },
        "summary_rows": [
            [
                "Container RSS idle (MB)",
                mb(measurements["legacy"]["baseline_idle"]["usage_bytes"]),
                mb(measurements["lite"]["baseline_idle"]["usage_bytes"]),
                "median of three samples, one run",
            ],
            [
                "Container RSS warm (MB)",
                mb(measurements["legacy"]["warm"]["usage_bytes"]),
                mb(measurements["lite"]["warm"]["usage_bytes"]),
                f"after {MEMORY_WARM_REQUESTS} authenticated requests",
            ],
            [
                "Container RSS peak under load (MB)",
                mb(measurements["legacy"]["under_load"]["peak_usage_bytes"]),
                mb(measurements["lite"]["under_load"]["peak_usage_bytes"]),
                f"{MEMORY_LOAD_RATE:.0f}rps for {load_seconds:.0f}s",
            ],
            [
                "Import RSS delta (MB)",
                f"{measurements['legacy']['import_cost']['rss_delta_kib'] / 1024:.1f}",
                f"{measurements['lite']['import_cost']['rss_delta_kib'] / 1024:.1f}",
                "bare interpreter, ru_maxrss",
            ],
            [
                "Modules added by import",
                str(measurements["legacy"]["import_cost"]["modules_added"]),
                str(measurements["lite"]["import_cost"]["modules_added"]),
                "bare interpreter, sys.modules",
            ],
        ],
    }


# --------------------------------------------------------------------------------------
# Call graph: static shape and per-request call counts
# --------------------------------------------------------------------------------------


def call_graph(context: Context) -> dict[str, Any]:
    """
    Count the work each library does per request in call-graph terms rather than wall clock.

    The static half parses each library's own source with `ast` and reports how many call
    sites reach its own functions and how many frames separate the FastAPI dependency from
    signature verification. The dynamic half drives exactly one request through the
    dependency under `sys.setprofile` and reports the calls it cost, attributed to the
    package that owns each frame.

    Neither half is a timing measurement and neither runs while anything else is being
    timed. `sys.setprofile` roughly doubles the cost of a call, which is fine when the
    quantity being reported is a count.

    Args:
        context: The run context.

    Returns:
        The result document.
    """
    measurements: dict[str, Any] = {}
    for arm in ARMS:
        wait_healthy(arm)
        static = context.docker.exec_json(arm.service, ["python", "/srv/app/probe.py", "static"])
        dynamic = context.docker.exec_json(
            arm.service, ["python", "/srv/app/probe.py", "callcounts"]
        )
        warm = dynamic["warm_repeat"]
        if arm.name == "legacy":
            # Upstream's JWT layer is a separate distribution, so the package key isolates
            # it. `buzz`, `snick`, `pluggy` and `auto_name_enum` are counted with the auth
            # library because upstream calls them from its own request path and
            # armasec-lite's equivalents are lines inside armasec_lite itself. Excluding
            # them would credit upstream for work armasec-lite is being charged for.
            jwt_calls = warm["by_package"].get("jose", 0)
            library_calls = sum(
                warm["by_package"].get(name, 0)
                for name in ("armasec", "buzz", "snick", "pluggy", "auto_name_enum")
            )
        else:
            # armasec_lite.jwt is a module inside the package it must be distinguished
            # from, so the split needs the per-file counter rather than the package one.
            jwt_calls = warm["by_module"].get("armasec_lite:jwt.py", 0)
            library_calls = warm["by_package"].get("armasec_lite", 0) - jwt_calls
        measurements[arm.name] = {
            "static": static,
            "dynamic": dynamic,
            "warm_total_calls": warm["total_calls"],
            "warm_max_depth": warm["max_depth"],
            "warm_calls_auth_library": library_calls,
            "warm_calls_jwt_layer": jwt_calls,
            "warm_calls_library_and_jwt": library_calls + jwt_calls,
            "warm_calls_framework": sum(
                warm["by_package"].get(name, 0)
                for name in ("fastapi", "starlette", "pydantic", "pydantic_core")
            ),
            "cold_total_calls": dynamic["cold"]["total_calls"],
            "cold_max_depth": dynamic["cold"]["max_depth"],
        }
        context.log(
            f"call graph {arm.name}: warm {warm['total_calls']} calls, "
            f"depth {warm['max_depth']}, auth library "
            f"{measurements[arm.name]['warm_calls_auth_library']}, "
            f"jwt layer {measurements[arm.name]['warm_calls_jwt_layer']}"
        )

    def row(label: str, key: str, note: str) -> list[str]:
        return [label, str(measurements["legacy"][key]), str(measurements["lite"][key]), note]

    return {
        "scenario": "call_graph",
        "title": "Static call sites and per-request call counts on the authentication path",
        "question": "Does either library do materially more work per request?",
        "config": {
            "dynamic_method": "sys.setprofile plus threading.setprofile around one request",
            "warm_measurement": "the second repeat request, so the cache and code paths are hot",
            "jwt_layer": {"legacy": "jose", "lite": "armasec_lite.jwt"},
            "single_request": True,
            "not_a_timing_measurement": True,
        },
        "measurements": measurements,
        "verdicts": {
            "warm_total_calls": (
                f"upstream {measurements['legacy']['warm_total_calls']} vs "
                f"armasec-lite {measurements['lite']['warm_total_calls']} per warm request"
            )
        },
        "summary_rows": [
            row("Calls per warm request (total)", "warm_total_calls", "one request, setprofile"),
            row(
                "Calls in the auth library (JWT layer excluded)",
                "warm_calls_auth_library",
                "upstream includes buzz, snick, pluggy, auto_name_enum",
            ),
            row("Calls in the JWT layer", "warm_calls_jwt_layer", "jose vs armasec_lite.jwt"),
            row("Calls in library plus JWT layer", "warm_calls_library_and_jwt", "warm request"),
            row("Deepest stack on a warm request", "warm_max_depth", "frames"),
            row("Calls per cold request (total)", "cold_total_calls", "includes the OIDC load"),
            row("Deepest stack on a cold request", "cold_max_depth", "frames"),
        ],
    }


# --------------------------------------------------------------------------------------
# Sampling profiler: S4 corroborated from inside the process
# --------------------------------------------------------------------------------------

PROFILE_INTERVAL_MS = 5.0

#: A stack whose innermost frame is the selector is an event loop with nothing to do. Any
#: other leaf on the loop thread is work that no other request in the process can proceed
#: past.
IDLE_MARKER = "selectors.py:select"

#: Frames belonging to a blocking HTTP client. `sync.py`, `http11.py` and `connection_pool`
#: are httpcore, which is what upstream armasec reaches through httpx; `client.py` and
#: `request.py` are `http.client` and `urllib.request`, which is what armasec-lite uses.
#: Finding any of these on the loop thread is the defect. Finding them on a worker thread
#: is the fix.
HTTP_CLIENT_MARKERS = (
    "sync.py:read",
    "http11.py:",
    "connection_pool.py:",
    "client.py:getresponse",
    "client.py:_read_status",
    "request.py:do_open",
)


def profile_pass(context: Context) -> dict[str, Any]:
    """
    Repeat S4 with each application's own sampling profiler running, and read the stacks.

    This is a second, independent line of evidence for the headline result, taken by a
    different method. S4 says from outside that the process stopped answering. The sampler
    says from inside which thread was busy and what it was busy with. If a stall is caused
    by network I/O on the event loop thread, samples land on the loop thread inside a socket
    read; if the same work has been moved to an executor, the loop thread sits in the
    selector and the samples land on a worker instead.

    It runs as a separate pass at the same arrival rate as S4 rather than during it, because
    a sampling thread taking the GIL every few milliseconds is a small perturbation and the
    headline latency numbers should not carry it.

    Args:
        context: The run context.

    Returns:
        The result document, with the top stack signatures reported verbatim.
    """
    duration, trigger_at = s4_duration(context)
    measurements: dict[str, Any] = {}

    for arm in ARMS:
        proxy_latency(0)
        restart(context, arm)
        http_json(f"http://{arm.host}:{arm.port}/__profile/start?interval_ms={PROFILE_INTERVAL_MS}")
        http_json(f"http://{arm.host}:{arm.port}/__profile/reset")
        proxy_latency(S4_LATENCY_MS)
        samples, auth_ms, auth_status = asyncio.run(
            s4_one_run(arm, context.minter.token, duration, trigger_at)
        )
        proxy_latency(0)
        profile = http_json(f"http://{arm.host}:{arm.port}/__profile?top=15")
        http_json(f"http://{arm.host}:{arm.port}/__profile/stop")

        loop_top = profile["top"].get("loop", [])
        loop_total = profile["totals"].get("loop", 0)
        idle = sum(
            entry["samples"] for entry in loop_top if entry["signature"].startswith(IDLE_MARKER)
        )
        loop_blocked = sum(
            entry["samples"]
            for entry in loop_top
            if any(marker in entry["signature"] for marker in HTTP_CLIENT_MARKERS)
        )
        worker_blocked = sum(
            entry["samples"]
            for label, entries in profile["top"].items()
            if label != "loop"
            for entry in entries
            if any(marker in entry["signature"] for marker in HTTP_CLIENT_MARKERS)
        )
        measurements[arm.name] = {
            "profiler": profile["state"],
            "samples_per_thread": profile["totals"],
            "loop_thread_samples": loop_total,
            "loop_thread_samples_idle_in_selector": idle,
            "loop_thread_samples_busy": loop_total - idle,
            "loop_thread_samples_in_blocking_http_client": loop_blocked,
            "loop_thread_blocked_share": (loop_blocked / loop_total) if loop_total else 0.0,
            "worker_thread_samples_in_blocking_http_client": worker_blocked,
            "threads_seen": sorted(profile["totals"]),
            "cold_auth_request_ms": auth_ms,
            "cold_auth_status": auth_status,
            "worst_health_ms": max((s.latency_ms for s in samples), default=0.0),
            "top_signatures": profile["top"],
        }
        context.log(
            f"profile {arm.name}: loop-thread samples {loop_total} "
            f"({idle} idle in the selector), {loop_blocked} inside a blocking HTTP client "
            f"({measurements[arm.name]['loop_thread_blocked_share'] * 100:.1f}%), "
            f"{worker_blocked} on worker threads, threads {sorted(profile['totals'])}"
        )

    return {
        "scenario": "profile",
        "title": "Poor man's profiler: where each arm's event loop thread was during a cold load",
        "question": "Does the cold OIDC load run on the event loop thread or off it?",
        "config": {
            "method": "sys._current_frames() sampled by a daemon thread inside each app",
            "interval_ms": PROFILE_INTERVAL_MS,
            "workload": "the S4 workload repeated, not measured concurrently with it",
            "health_rate_per_second": S4_RATE,
            "injected_provider_latency_ms": S4_LATENCY_MS,
            "idle_marker": IDLE_MARKER,
            "http_client_markers": list(HTTP_CLIENT_MARKERS),
        },
        "measurements": measurements,
        "verdicts": {
            "loop_thread_blocked_share": (
                f"upstream {measurements['legacy']['loop_thread_blocked_share'] * 100:.1f}% vs "
                f"armasec-lite {measurements['lite']['loop_thread_blocked_share'] * 100:.1f}% "
                "of loop-thread samples inside a blocking HTTP client"
            )
        },
        "summary_rows": [
            [
                "Loop-thread samples in a blocking HTTP client (%)",
                f"{measurements['legacy']['loop_thread_blocked_share'] * 100:.1f}",
                f"{measurements['lite']['loop_thread_blocked_share'] * 100:.1f}",
                "one pass per arm, sampled at 5ms",
            ],
            [
                "Worker-thread samples in a blocking HTTP client",
                str(measurements["legacy"]["worker_thread_samples_in_blocking_http_client"]),
                str(measurements["lite"]["worker_thread_samples_in_blocking_http_client"]),
                "where the fetch went instead",
            ],
        ],
    }


SCENARIOS = {
    "s4": s4_event_loop_blocking,
    "s3": s3_flood,
    "s1": s1_cold_start,
    "s2": s2_amplification,
    "s8": s8_failing_provider,
    "footprint": footprint,
    "memory": memory_footprint,
    "callgraph": call_graph,
    "profile": profile_pass,
}

#: Result file basenames, so a reader can find a scenario by name rather than by number.
FILENAMES = {
    "s1": "s1_cold_start",
    "s2": "s2_request_amplification",
    "s3": "s3_warm_flood",
    "s4": "s4_event_loop_blocking",
    "s8": "s8_failing_provider",
    "footprint": "footprint",
    "memory": "memory",
    "callgraph": "call_graph",
    "profile": "profile_sampling",
}
