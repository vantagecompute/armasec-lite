"""
Reading a container's cgroup v2 CPU and memory counters without perturbing the container.

Call counts are a proxy for work. CPU time is the work itself, and the kernel already keeps
it: under cgroup v2 every container has a `cpu.stat` carrying `usage_usec`, `user_usec` and
`system_usec` since the cgroup was created, and a `memory.current` plus `memory.peak`
alongside it. Those counters are monotonic, so the CPU consumed by a measurement window is
the difference between a reading taken at each end of it, and nothing has to be sampled fast
enough to catch a rate.

### Why the host cgroup filesystem is bind-mounted rather than read over `docker exec`

The obvious way to read these files is `docker exec <container> cat /sys/fs/cgroup/cpu.stat`.
It is also wrong for this measurement. An exec'd process joins the target container's
cgroup, so the interpreter or shell it starts charges its own CPU to the very counter being
read. At the rates in the S3 ladder an application container spends a few hundred
milliseconds of CPU per window, and a process spawn costs single-digit milliseconds, so
reading the counter that way would inflate it by a few percent, in the arm being sampled
and not in the other one. Reading the same files through a read-only bind mount of the
host's `/sys/fs/cgroup` costs the container nothing at all: the reader is a thread in the
bench container and the bytes come from the kernel.

The Docker daemon's `/containers/{id}/stats` endpoint is derived from these same counters
and is equally unperturbing, and the existing memory scenario uses it. It is not used here
for two reasons: it does not expose `memory.peak`, and a non-streaming stats call takes
about a second to answer, which is too coarse to sample the one-second stall that scenario
S10 exists to characterise.

### Locating a container's cgroup

Docker's systemd cgroup driver puts a container at
`system.slice/docker-<full id>.scope`; the cgroupfs driver puts it at `docker/<full id>`;
Kubernetes and rootless layouts put it somewhere else again. `find` tries the two common
shapes by name and falls back to a bounded walk looking for a directory whose name contains
the container id, so a layout this file has never seen still resolves.

`memory.peak` became resettable by writing to it in Linux 6.11. On an older kernel it is the
high-water mark since the cgroup was created and cannot be zeroed, so `Reader.reset_peak`
reports whether the reset actually took and callers that need a per-window peak take it from
their own samples instead of trusting the file.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

#: Where the host's cgroup v2 hierarchy is bind-mounted inside the bench container.
CGROUP_ROOT = os.environ.get("HARNESS_CGROUP_ROOT", "/host/sys/fs/cgroup")

#: The `cpu.stat` keys worth carrying into a result file. `nr_throttled` and
#: `throttled_usec` matter as much as the usage counters: both application containers are
#: capped at one CPU, and a window in which one arm was throttled and the other was not is
#: not a comparison of how much work they did.
CPU_KEYS = (
    "usage_usec",
    "user_usec",
    "system_usec",
    "nr_periods",
    "nr_throttled",
    "throttled_usec",
)

#: The `memory.stat` keys worth carrying. `memory.current` is the whole charge and includes
#: page cache, so two containers that have read different amounts of their own image differ
#: in it for reasons having nothing to do with the libraries they run. `anon` is the
#: anonymous set, which is the number a reader means by "how much memory does this process
#: use", and `inactive_file` is what the Docker daemon subtracts from `memory.current` to
#: produce the figure the existing memory scenario reports, so carrying it keeps the two
#: scenarios comparable.
MEMORY_KEYS = ("anon", "file", "inactive_file", "active_file", "slab", "sock", "kernel_stack")


def cgroup_version(root: str = CGROUP_ROOT) -> str:
    """
    Say which cgroup hierarchy is mounted at a path.

    Args:
        root: The mount point to inspect.

    Returns:
        `v2` when the unified hierarchy is there, `v1` when a legacy hierarchy is, and
        `absent` when nothing is mounted at that path.
    """
    if not os.path.isdir(root):
        return "absent"
    if os.path.exists(os.path.join(root, "cgroup.controllers")):
        return "v2"
    return "v1"


def find(container_id: str, root: str = CGROUP_ROOT) -> str:
    """
    Locate one container's cgroup v2 directory.

    Args:
        container_id: The container's full identifier.
        root:         The cgroup v2 mount point.

    Returns:
        The absolute path of the container's cgroup directory.

    Raises:
        RuntimeError: No directory under `root` belongs to that container. There is no
            partial answer to fall back on: a CPU measurement read from the wrong cgroup
            would be a plausible-looking number describing something else.
    """
    candidates = (
        os.path.join(root, "system.slice", f"docker-{container_id}.scope"),
        os.path.join(root, "docker", container_id),
        os.path.join(root, f"docker-{container_id}.scope"),
    )
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    for directory, subdirectories, _ in os.walk(root):
        for name in subdirectories:
            if container_id in name:
                return os.path.join(directory, name)
    raise RuntimeError(
        f"no cgroup directory for container {container_id[:12]} under {root!r}; "
        "is the host cgroup filesystem bind-mounted into the bench container?"
    )


def _read(path: str) -> str:
    """
    Read a small pseudo-file, returning an empty string when it is not there.

    Args:
        path: The file to read.

    Returns:
        The file's contents, or an empty string.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


@dataclass
class Snapshot:
    """
    One reading of a container's CPU and memory counters.

    Attributes:
        t:            `time.monotonic()` at the moment of the reading, so two snapshots
                      define a window whose length is known to better than a millisecond.
        wall:         Unix time, for aligning a series against anything timestamped outside
                      this process.
        cpu:          The `cpu.stat` counters named in `CPU_KEYS`, in microseconds or
                      counts, cumulative since the cgroup was created.
        memory_bytes: `memory.current`, the cgroup's whole charge, page cache included.
        peak_bytes:   `memory.peak`, its high-water mark, or None where the kernel does not
                      publish one.
        memory:       The `memory.stat` keys named in `MEMORY_KEYS`.
    """

    t: float
    wall: float
    cpu: dict[str, int]
    memory_bytes: int | None
    peak_bytes: int | None
    memory: dict[str, int] = field(default_factory=dict)

    @property
    def anon_bytes(self) -> int | None:
        """The anonymous set, which is what a reader means by the process's memory."""
        return self.memory.get("anon")

    @property
    def working_set_bytes(self) -> int | None:
        """
        `memory.current` less reclaimable page cache, the figure the Docker daemon reports.

        Returns:
            The working set, or None when either input is missing.
        """
        if self.memory_bytes is None or "inactive_file" not in self.memory:
            return None
        return max(0, self.memory_bytes - self.memory["inactive_file"])

    def as_dict(self) -> dict[str, Any]:
        """
        Render the snapshot for a result file.

        Returns:
            A JSON-serializable copy.
        """
        return {
            "t": round(self.t, 4),
            "wall": round(self.wall, 4),
            "cpu": dict(self.cpu),
            "memory_bytes": self.memory_bytes,
            "anon_bytes": self.anon_bytes,
            "working_set_bytes": self.working_set_bytes,
            "peak_bytes": self.peak_bytes,
            "memory_stat": dict(self.memory),
        }


class Reader:
    """
    A handle on one container's cgroup, able to snapshot it and to difference two snapshots.

    Attributes:
        path: The container's cgroup directory.
    """

    def __init__(self, container_id: str, root: str = CGROUP_ROOT) -> None:
        """
        Args:
            container_id: The container's full identifier.
            root:         The cgroup v2 mount point.
        """
        self.path = find(container_id, root)

    def snapshot(self) -> Snapshot:
        """
        Read every counter once.

        The monotonic clock is read between the CPU file and the memory files rather than
        before both, so the timestamp sits in the middle of the reading rather than at one
        end of it. The whole read is tens of microseconds, so this is a detail, but it costs
        nothing to get right.

        Returns:
            The reading.
        """
        raw = _read(os.path.join(self.path, "cpu.stat"))
        now = time.monotonic()
        wall = time.time()
        cpu: dict[str, int] = {}
        for line in raw.splitlines():
            key, _, value = line.partition(" ")
            if key in CPU_KEYS and value.strip().isdigit():
                cpu[key] = int(value)
        current = _read(os.path.join(self.path, "memory.current")).strip()
        peak = _read(os.path.join(self.path, "memory.peak")).strip()
        memory: dict[str, int] = {}
        for line in _read(os.path.join(self.path, "memory.stat")).splitlines():
            key, _, value = line.partition(" ")
            if key in MEMORY_KEYS and value.strip().isdigit():
                memory[key] = int(value)
        return Snapshot(
            t=now,
            wall=wall,
            cpu=cpu,
            memory_bytes=int(current) if current.isdigit() else None,
            peak_bytes=int(peak) if peak.isdigit() else None,
            memory=memory,
        )

    def reset_peak(self) -> bool:
        """
        Try to zero `memory.peak`, which Linux 6.11 and later allow.

        Returns:
            True when the reset took effect, False on a kernel that publishes the counter
            read-only. A caller that gets False must derive a per-window peak from its own
            samples rather than from the file.
        """
        target = os.path.join(self.path, "memory.peak")
        before = _read(target).strip()
        try:
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("0")
        except OSError:
            return False
        after = _read(target).strip()
        return after.isdigit() and before.isdigit() and int(after) <= int(before)


def delta(start: Snapshot, end: Snapshot) -> dict[str, Any]:
    """
    Difference two snapshots into the CPU a window actually cost.

    Args:
        start: The reading taken as the window opened.
        end:   The reading taken as it closed.

    Returns:
        The window length, the CPU microseconds consumed split user and system, the same
        figure as milliseconds and as a fraction of one core, and the throttling counters,
        which say whether the window was capped rather than merely busy.
    """
    seconds = end.t - start.t
    consumed = {key: end.cpu.get(key, 0) - start.cpu.get(key, 0) for key in CPU_KEYS}
    usage = consumed.get("usage_usec", 0)
    return {
        "window_seconds": round(seconds, 4),
        "usage_usec": usage,
        "user_usec": consumed.get("user_usec", 0),
        "system_usec": consumed.get("system_usec", 0),
        "cpu_ms": usage / 1000.0,
        "user_ms": consumed.get("user_usec", 0) / 1000.0,
        "system_ms": consumed.get("system_usec", 0) / 1000.0,
        "cores_used": (usage / 1e6 / seconds) if seconds > 0 else 0.0,
        "nr_periods": consumed.get("nr_periods", 0),
        "nr_throttled": consumed.get("nr_throttled", 0),
        "throttled_usec": consumed.get("throttled_usec", 0),
    }


@dataclass
class Series:
    """
    A background sampler that reads one container's counters on a fixed interval.

    Sampling is what turns a total into a shape. The per-request CPU figures only need the
    two ends of a window, but scenario S10 has to say what the CPU was doing during a
    particular second of a run, and memory has to be watched through a window rather than
    at the end of it, because a figure that plateaus and a figure that is still climbing
    when the load stops are different findings.

    Attributes:
        reader:   The cgroup to sample.
        interval: Seconds between samples.
        samples:  Every reading taken, in order.
    """

    reader: Reader
    interval: float = 0.1
    samples: list[Snapshot] = field(default_factory=list)

    def collect(self, stop: Any) -> None:
        """
        Sample until an event is set. Intended as a thread target.

        Args:
            stop: A `threading.Event` that ends the loop.
        """
        while not stop.is_set():
            self.samples.append(self.reader.snapshot())
            stop.wait(self.interval)
        self.samples.append(self.reader.snapshot())

    def rates(self) -> list[dict[str, Any]]:
        """
        Turn the samples into a per-interval CPU rate and memory series.

        Returns:
            One entry per gap between consecutive samples, carrying the interval's midpoint,
            the fraction of a core used across it, and the memory charge at its end.
        """
        series: list[dict[str, Any]] = []
        for previous, current in zip(self.samples, self.samples[1:], strict=False):
            seconds = current.t - previous.t
            if seconds <= 0:
                continue
            used = current.cpu.get("usage_usec", 0) - previous.cpu.get("usage_usec", 0)
            series.append(
                {
                    "t": round((current.t + previous.t) / 2.0, 4),
                    "cores_used": round(used / 1e6 / seconds, 5),
                    "cpu_ms": round(used / 1000.0, 3),
                    "memory_bytes": current.memory_bytes,
                    "anon_bytes": current.anon_bytes,
                    "working_set_bytes": current.working_set_bytes,
                }
            )
        return series

    def memory_bytes(self) -> list[int]:
        """
        Every non-null `memory.current` reading, in order.

        Returns:
            The series.
        """
        return [s.memory_bytes for s in self.samples if s.memory_bytes is not None]

    def anon_bytes(self) -> list[int]:
        """
        Every non-null anonymous-set reading, in order.

        This is the series to judge accumulation by. `memory.current` moves with page cache
        the kernel is free to reclaim, so a container that has read more of its own image
        reads higher without any process having allocated anything.

        Returns:
            The series.
        """
        return [s.anon_bytes for s in self.samples if s.anon_bytes is not None]
