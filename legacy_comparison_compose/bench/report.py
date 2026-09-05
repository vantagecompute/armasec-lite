"""
Provenance, statistics and result files: everything that describes a run rather than drives it.

A number with no provenance describes nothing. Every result file this module writes carries
the same block: when the run happened, on what machine, under which kernel and Docker
daemon, with what CPU and memory limits on the two application containers, how many
repetitions were taken, which Keycloak image was running, and the resolved version of both
libraries. The ratio between the two arms is the transferable part; the absolute
milliseconds describe one machine running Docker and the documentation says so.

This module also owns the Docker API client, because collecting provenance is most of what
the harness uses Docker for. The scenarios borrow it to restart application containers,
which is the other part.

### Reporting spread

`across_reps` reports the median of the repetitions and keeps every individual value.
`verdict` then compares two arms by whether their observed ranges overlap. That is a
deliberately blunt, non-parametric test and it errs toward calling things noise: five
repetitions cannot support anything finer, and a harness that reports a difference the data
does not carry is worse than one that reports none.

Percentiles are linearly interpolated between the two nearest ranks, which is what `numpy`
does by default. For a p99 over a few hundred samples the difference against nearest-rank
is under one sample either way.
"""

from __future__ import annotations

import datetime
import http.client
import json
import os
import socket
from typing import Any


class UnixHTTPConnection(http.client.HTTPConnection):
    """
    An `http.client` connection that speaks to a Unix domain socket.

    The Docker daemon's API is ordinary HTTP over `/var/run/docker.sock`. Nothing else is
    needed to talk to it, so nothing else is used.

    Attributes:
        socket_path: The filesystem path of the daemon socket.
    """

    def __init__(self, socket_path: str, timeout: float = 120.0) -> None:
        """
        Args:
            socket_path: The daemon socket to connect to.
            timeout:     Seconds before a read or connect gives up.
        """
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        """Open the Unix socket in place of a TCP connection."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class Docker:
    """
    The slice of the Docker Engine API this harness needs.

    Attributes:
        socket_path: The daemon socket.
        project:     The compose project name used to find the stack's containers.
    """

    def __init__(self, socket_path: str = "/var/run/docker.sock", project: str = "") -> None:
        """
        Args:
            socket_path: The daemon socket.
            project:     The compose project whose containers are in scope.
        """
        self.socket_path = socket_path
        self.project = project
        self._ids: dict[str, str] = {}

    def call(self, method: str, path: str, body: Any = None, timeout: float = 120.0) -> Any:
        """
        Make one API call.

        Args:
            method:  The HTTP method.
            path:    The API path, query string included.
            body:    A JSON-serializable request body, or None.
            timeout: Seconds before giving up.

        Returns:
            The parsed JSON response, the raw text when it is not JSON, or None for an
            empty response.

        Raises:
            RuntimeError: The daemon answered with a status of 400 or above.
        """
        connection = UnixHTTPConnection(self.socket_path, timeout=timeout)
        try:
            payload = json.dumps(body).encode() if body is not None else None
            headers = {"Content-Type": "application/json"} if payload else {}
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            if response.status >= 400:
                raise RuntimeError(f"docker {method} {path} -> {response.status}: {raw!r}")
            if not raw:
                return None
            try:
                return json.loads(raw)
            except ValueError:
                return raw.decode("utf-8", "replace")
        finally:
            connection.close()

    def container_id(self, service: str) -> str:
        """
        Find a compose service's container.

        Args:
            service: The compose service name, such as `app-lite`.

        Returns:
            The container's full identifier.

        Raises:
            RuntimeError: No running container carries that service label, which means the
                stack is not up and no measurement taken against it would mean anything.
        """
        if service in self._ids:
            return self._ids[service]
        query = json.dumps(
            {
                "label": [
                    f"com.docker.compose.project={self.project}",
                    f"com.docker.compose.service={service}",
                ]
            }
        )
        found = self.call("GET", f"/containers/json?filters={_quote(query)}")
        if not found:
            raise RuntimeError(f"no running container for compose service {service!r}")
        self._ids[service] = str(found[0]["Id"])
        return self._ids[service]

    def inspect(self, service: str) -> Any:
        """
        Inspect a compose service's container.

        Args:
            service: The compose service name.

        Returns:
            The full inspection document.
        """
        return self.call("GET", f"/containers/{self.container_id(service)}/json")

    def restart(self, service: str, stop_seconds: int = 2) -> None:
        """
        Restart a compose service's container.

        Args:
            service:      The compose service name.
            stop_seconds: How long to wait after SIGTERM before SIGKILL. Uvicorn exits on
                          SIGTERM promptly, so a short grace period only shortens the gap
                          between repetitions.
        """
        self.call("POST", f"/containers/{self.container_id(service)}/restart?t={stop_seconds}")

    def stats(self, service: str) -> Any:
        """
        Take one non-streaming resource sample for a compose service.

        Args:
            service: The compose service name.

        Returns:
            The daemon's stats document.
        """
        return self.call("GET", f"/containers/{self.container_id(service)}/stats?stream=false")

    def raw_post(self, path: str, body: Any, timeout: float = 180.0) -> bytes:
        """
        POST to the daemon over a raw socket and read everything it sends back.

        `http.client` cannot be used for `/exec/{id}/start`. The daemon answers it with
        `Content-Type: application/vnd.docker.raw-stream` and neither a `Content-Length`
        nor a chunked encoding, because the connection is hijacked into a bidirectional
        stream, and `http.client` returns an empty body rather than reading to EOF. Reading
        the socket directly is the whole fix.

        Args:
            path:    The API path.
            body:    A JSON-serializable request body.
            timeout: Seconds before giving up.

        Returns:
            The response body, headers stripped.
        """
        payload = json.dumps(body).encode()
        request = (
            f"POST {path} HTTP/1.1\r\n"
            "Host: docker\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + payload
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(self.socket_path)
        chunks: list[bytes] = []
        try:
            sock.sendall(request)
            while True:
                received = sock.recv(65536)
                if not received:
                    break
                chunks.append(received)
        finally:
            sock.close()
        return b"".join(chunks).partition(b"\r\n\r\n")[2]

    def exec_run(self, service: str, command: list[str], timeout: float = 300.0) -> str:
        """
        Run a command inside a compose service's container and collect its output.

        `Tty` is set so the daemon returns a raw stream rather than the multiplexed
        stdout/stderr framing, which would otherwise have to be de-framed by hand for no
        benefit: every probe prints one JSON object and nothing else.

        Args:
            service: The compose service name.
            command: The command and its arguments.
            timeout: Seconds before giving up.

        Returns:
            Everything the command wrote, decoded as UTF-8.
        """
        created = json.loads(
            self.raw_post(
                f"/containers/{self.container_id(service)}/exec",
                {"AttachStdout": True, "AttachStderr": True, "Tty": True, "Cmd": command},
            )
        )
        output = self.raw_post(
            f"/exec/{created['Id']}/start", {"Detach": False, "Tty": True}, timeout
        )
        return output.decode("utf-8", "replace")

    def exec_json(self, service: str, command: list[str]) -> Any:
        """
        Run a command that prints one JSON object and parse it.

        Args:
            service: The compose service name.
            command: The command and its arguments.

        Returns:
            The parsed object.

        Raises:
            RuntimeError: The command printed nothing parseable, which is reported with the
                raw output because that output is the diagnosis.
        """
        raw = self.exec_run(service, command)
        for line in reversed(raw.strip().splitlines()):
            stripped = line.strip()
            if stripped.startswith("{"):
                try:
                    return json.loads(stripped)
                except ValueError:
                    continue
        raise RuntimeError(f"no JSON object in output of {command!r}: {raw!r}")


def _quote(value: str) -> str:
    """
    Percent-encode a filter document for a query string.

    Args:
        value: The raw string.

    Returns:
        The encoded string.
    """
    import urllib.parse

    return urllib.parse.quote(value, safe="")


def container_limits(docker: Docker, service: str) -> dict[str, Any]:
    """
    Read a container's configured CPU and memory limits.

    Args:
        docker:  The API client.
        service: The compose service name.

    Returns:
        The CPU limit in cores, the memory limit in bytes, and the image the container was
        started from.
    """
    document = docker.inspect(service)
    host = document["HostConfig"]
    return {
        "cpus": host.get("NanoCpus", 0) / 1_000_000_000 if host.get("NanoCpus") else None,
        "cpu_quota": host.get("CpuQuota") or None,
        "cpu_period": host.get("CpuPeriod") or None,
        "mem_limit_bytes": host.get("Memory") or None,
        "memswap_limit_bytes": host.get("MemorySwap") or None,
        "image": document["Config"]["Image"],
        "image_id": document["Image"],
    }


def provenance(docker: Docker, versions: dict[str, str], reps: int) -> dict[str, Any]:
    """
    Collect everything needed to say what a set of numbers describes.

    Host facts come from the daemon rather than from inside the bench container, which sees
    its own hostname and a CPU count filtered through its own cgroup. The CPU model is read
    from `/proc/cpuinfo`, which a container shares with its host unmodified.

    Args:
        docker:   The API client.
        versions: The resolved library version for each arm, keyed `legacy` and `lite`.
        reps:     How many repetitions the run took.

    Returns:
        The provenance block written into every result file.

    Raises:
        RuntimeError: The two application containers do not carry identical CPU and memory
            limits. An unfair comparison is worse than no comparison, so this stops the run
            rather than recording the numbers with a warning attached.
    """
    info = docker.call("GET", "/info")
    version = docker.call("GET", "/version")

    model = ""
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                    break
    except OSError:  # pragma: no cover - /proc is always present under Linux
        model = "unknown"

    legacy_limits = container_limits(docker, "app-legacy")
    lite_limits = container_limits(docker, "app-lite")
    comparable = ("cpus", "cpu_quota", "cpu_period", "mem_limit_bytes", "memswap_limit_bytes")
    mismatched = {
        key: [legacy_limits[key], lite_limits[key]]
        for key in comparable
        if legacy_limits[key] != lite_limits[key]
    }
    if mismatched:
        raise RuntimeError(
            "the two application containers have different resource limits, so no "
            f"comparison between them is meaningful: {mismatched}"
        )

    keycloak = docker.inspect("keycloak")
    image = docker.call("GET", f"/images/{_quote(keycloak['Image'])}/json")

    return {
        "timestamp_utc": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "hostname": info.get("Name"),
        "cpu_model": model,
        "cpu_count": info.get("NCPU"),
        "memory_total_bytes": info.get("MemTotal"),
        "kernel": info.get("KernelVersion"),
        "operating_system": info.get("OperatingSystem"),
        "docker_version": version.get("Version"),
        "docker_api_version": version.get("ApiVersion"),
        "repetitions": reps,
        "keycloak_image": keycloak["Config"]["Image"],
        "keycloak_image_id": keycloak["Image"],
        "keycloak_repo_digests": image.get("RepoDigests", []),
        "library_versions": versions,
        "app_container_limits": {"identical": True, "legacy": legacy_limits, "lite": lite_limits},
    }


def percentile(values: list[float], quantile: float) -> float:
    """
    Interpolate a percentile from a sample.

    Args:
        values:   The sample. Not modified.
        quantile: The percentile as a fraction, so 0.99 for p99.

    Returns:
        The interpolated value, or 0.0 for an empty sample.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = quantile * (len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def summarize(values: list[float]) -> dict[str, float]:
    """
    Reduce a latency sample to the percentiles worth reporting.

    Args:
        values: The sample, in milliseconds.

    Returns:
        Count, mean, and the p50, p90, p95, p99, min and max.
    """
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "mean": sum(values) / len(values),
        "min": min(values),
        "p50": percentile(values, 0.50),
        "p90": percentile(values, 0.90),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values),
    }


def across_reps(values: list[float]) -> dict[str, Any]:
    """
    Report the median of a set of repetitions and keep the spread.

    Args:
        values: One number per repetition.

    Returns:
        The median, the observed range, the relative spread as a percentage of the median,
        and every individual value, because a single number with no spread is not a
        measurement.
    """
    if not values:
        return {"median": None, "min": None, "max": None, "values": []}
    ordered = sorted(values)
    middle = len(ordered) // 2
    median = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2
    span = ordered[-1] - ordered[0]
    return {
        "median": median,
        "min": ordered[0],
        "max": ordered[-1],
        "spread_pct_of_median": (span / median * 100.0) if median else None,
        "values": values,
    }


def verdict(legacy: list[float], lite: list[float], lower_is_better: bool = True) -> str:
    """
    Say whether a difference between two arms is real or within noise.

    Overlapping ranges are called noise. With five repetitions nothing finer is supportable,
    and a harness that reports a difference its data does not carry is worse than one that
    reports none.

    Args:
        legacy:          One value per repetition for the upstream arm.
        lite:            One value per repetition for the armasec-lite arm.
        lower_is_better: True for latencies and counts, False for throughput.

    Returns:
        A sentence naming the winner and the ratio, or saying the ranges overlap.
    """
    if not legacy or not lite:
        return "not measured"
    legacy_stats = across_reps(legacy)
    lite_stats = across_reps(lite)
    if min(len(legacy), len(lite)) < 3:
        # One or two values have no meaningful range, so an overlap test on them would
        # report every difference as real. Say how many there were instead of pretending.
        return f"only {min(len(legacy), len(lite))} repetition(s), no spread to judge against"
    overlap = legacy_stats["min"] <= lite_stats["max"] and lite_stats["min"] <= legacy_stats["max"]
    if overlap:
        return "within noise (repetition ranges overlap)"
    high, low = legacy_stats["median"], lite_stats["median"]
    if high == 0 or low == 0:
        winner = "lite" if (low < high) == lower_is_better else "legacy"
        return f"{winner} wins, ranges disjoint (one median is zero, no ratio)"
    ratio = high / low if high > low else low / high
    better_is_lite = (low < high) == lower_is_better
    winner = "armasec-lite" if better_is_lite else "upstream armasec"
    direction = "lower" if lower_is_better else "higher"
    return f"{winner} {ratio:.2f}x {direction}, ranges disjoint"


def write_result(path: str, document: dict[str, Any]) -> str:
    """
    Write one result file.

    Args:
        path:     The file to write.
        document: The result, provenance included.

    Returns:
        The path written, for logging.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return path


def print_summary(rows: list[list[str]]) -> None:
    """
    Print the run summary as an aligned table.

    Args:
        rows: The header row followed by the data rows.
    """
    if not rows:
        return
    widths = [max(len(str(row[column])) for row in rows) for column in range(len(rows[0]))]
    for index, row in enumerate(rows):
        rendered = "  ".join(str(cell).ljust(widths[column]) for column, cell in enumerate(row))
        print(rendered.rstrip())
        if index == 0:
            print("  ".join("-" * width for width in widths))
