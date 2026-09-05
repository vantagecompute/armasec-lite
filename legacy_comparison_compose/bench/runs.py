"""
Where a run's result files live, and the index that lets a reader find them.

Results used to be nine files in one directory, which meant the next run destroyed the
previous one. A benchmark you cannot compare against its own history is a screenshot, not a
measurement, so the layout is now a directory per run under a directory per version of the
library being measured:

```
results/
  index.json
  v0.1.0/
    2026-09-05T01-55-12Z/
      s1_cold_start.json
      ...
    <another run of the same version>/
  v0.2.0/
    ...
```

The version axis is the one that matters. Two runs of the same version differ only by
machine and by noise, so comparing them says how far to trust any single number. Two runs
of different versions say what a change actually did. Flattening both into one list of runs
loses that distinction, and a reader chasing a regression wants the second question.

Both the version and the run id come from the run's own provenance block, never from the
working tree. `pyproject.toml` can move on after a measurement is taken; the file records
what was actually running.

The run id is a UTC timestamp and nothing else. The host is not in the path: it is recorded
in every result file's provenance block, which is where the generated pages read it from and
where a reader comparing two machines will look for it.

`index.json` is derived, in full, from the result files under it, every time it is built.
Nothing is hand-copied into it. An index that carried its own numbers would be a second
source of truth, free to drift from the results it claims to summarise, and the first
regression it hid would be the last time anyone believed it.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from typing import Any

#: The scenario files a complete run writes, in scenario order. A run holding a file that is
#: not listed here is a run whose results the pages would silently omit, so the page
#: generator refuses to build until the two agree.
SCENARIO_FILES = (
    "s1_cold_start",
    "s2_request_amplification",
    "s3_warm_flood",
    "s4_event_loop_blocking",
    "s8_failing_provider",
    "s9_cpu_per_request",
    "s10_cpu_during_cold_load",
    "s11_idle_cpu",
    "footprint",
    "memory",
    "call_graph",
    "profile_sampling",
)


def library_version(provenance: dict[str, Any]) -> str:
    """
    Read the measured armasec-lite version out of a provenance block.

    The block records the version each arm's container reported over `/health` at run time,
    formatted `"lite 0.1.0"`. That string, not the working tree, is the authority on what
    was measured.

    Args:
        provenance: The provenance block from any result file of the run.

    Returns:
        The bare version, for example `"0.1.0"`.

    Raises:
        ValueError: The block carries no usable armasec-lite version.
    """
    raw = str(provenance.get("library_versions", {}).get("lite", "")).strip()
    parts = raw.split()
    if not parts:
        raise ValueError("provenance carries no library_versions.lite, so the run has no version")
    candidate = parts[-1]
    if not re.fullmatch(r"[0-9][0-9A-Za-z_.+-]*", candidate):
        raise ValueError(f"library_versions.lite is not a version: {raw!r}")
    return candidate


def version_directory(provenance: dict[str, Any]) -> str:
    """
    Name the version directory a run belongs in.

    Args:
        provenance: The provenance block from any result file of the run.

    Returns:
        The directory name, for example `"v0.1.0"`.
    """
    return f"v{library_version(provenance)}"


def run_id(provenance: dict[str, Any]) -> str:
    """
    Derive a run's identifier from what the run itself recorded.

    A UTC timestamp to the second, and nothing else. It is deliberately not a random id: a
    reader should be able to look at a directory name and know when the run was taken.

    The host used to be part of this, because it is what made a run unique across machines.
    A path is a poor place to keep it: it leaks machine names into the repository tree and it
    is noise to every reader who is not comparing two hosts. The host is still recorded in
    every result file's provenance block, which is where the generated pages read it from, so
    nothing is lost by taking it out of the path. Second precision is what replaces it: two
    runs starting inside the same second on one machine is not a case worth engineering for,
    and `allocate_run_directory` handles it anyway.

    The colons an ISO timestamp would carry are written as hyphens, because a colon in a path
    name is legal on Linux and a nuisance everywhere else.

    Args:
        provenance: The provenance block from any result file of the run.

    Returns:
        An identifier of the shape `2026-09-05T01-55-12Z`.

    Raises:
        ValueError: The block carries no parseable timestamp.
    """
    raw = str(provenance.get("timestamp_utc", "")).strip()
    if not raw:
        raise ValueError("provenance carries no timestamp_utc, so the run cannot be dated")
    moment = datetime.datetime.fromisoformat(raw)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.UTC)
    moment = moment.astimezone(datetime.UTC)
    return moment.strftime("%Y-%m-%dT%H-%M-%SZ")


def allocate_run_directory(results_root: str, provenance: dict[str, Any]) -> str:
    """
    Choose, and create, the directory this run's files belong in.

    The run id is a timestamp, so two runs starting inside the same second would otherwise
    collide and the second would overwrite the first. When the derived name is taken, a
    numeric suffix is appended until it is not. Nothing existing is ever written into.

    Args:
        results_root: The `results/` directory.
        provenance:   The provenance block the run collected.

    Returns:
        The absolute path of a freshly created, empty run directory.
    """
    parent = os.path.join(results_root, version_directory(provenance))
    base = run_id(provenance)
    candidate = base
    suffix = 2
    while os.path.exists(os.path.join(parent, candidate)):
        candidate = f"{base}-{suffix}"
        suffix += 1
    path = os.path.join(parent, candidate)
    os.makedirs(path)
    return path


# --------------------------------------------------------------------------------------
# Summaries, derived from the result files and from nowhere else
# --------------------------------------------------------------------------------------


def _median(document: dict[str, Any], *path: str) -> Any:
    """
    Follow a path of keys into a result document and return the median it ends at.

    Args:
        document: A parsed result file.
        path:     Keys to follow, ending at an `across_reps` block.

    Returns:
        The median, or `None` when any step of the path is absent.
    """
    node: Any = document
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    if isinstance(node, dict):
        return node.get("median")
    return None


def _arm_pair(document: dict[str, Any], *path: str) -> dict[str, Any] | None:
    """
    Read one measurement's median for both arms.

    Args:
        document: A parsed result file.
        path:     Keys to follow to the measurement, arm name excluded.

    Returns:
        A `{"legacy": ..., "lite": ...}` mapping, or `None` when neither arm is present.
    """
    legacy = _median(document, *path, "legacy")
    lite = _median(document, *path, "lite")
    if legacy is None and lite is None:
        return None
    return {"legacy": legacy, "lite": lite}


def _summarize_s4(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise the event loop blocking scenario.

    Args:
        document: The parsed `s4_event_loop_blocking.json`.

    Returns:
        The headline medians for both arms.
    """
    return {
        key: value
        for key, value in {
            "worst_health_latency_ms": _arm_pair(
                document, "measurements", "worst_health_latency_ms"
            ),
            "health_p99_during_cold_load_ms": _arm_pair(
                document, "measurements", "health_p99_during_cold_load_ms"
            ),
            "health_requests_over_100ms": _arm_pair(
                document, "measurements", "health_requests_over_100ms"
            ),
            "health_baseline_p50_ms": _arm_pair(document, "measurements", "health_baseline_p50_ms"),
        }.items()
        if value is not None
    }


def _summarize_s3(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise the warm flood scenario, one entry per offered rate.

    Args:
        document: The parsed `s3_warm_flood.json`.

    Returns:
        Per-rate medians for the achieved rate and the latency percentiles.
    """
    out: dict[str, Any] = {}
    for name, block in document.get("measurements", {}).items():
        if not name.startswith("target_") or not isinstance(block, dict):
            continue
        rate = name.removeprefix("target_").removesuffix("_rps")
        out[rate] = {
            key: _arm_pair(document, "measurements", name, key)
            for key in ("achieved_rps", "p50_ms", "p95_ms", "p99_ms")
        }
    return out


def _summarize_s2(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise request amplification, one entry per scope set count.

    Args:
        document: The parsed `s2_request_amplification.json`.

    Returns:
        Per-scope-set-count OIDC fetch medians.
    """
    out: dict[str, Any] = {}
    for name, block in document.get("measurements", {}).items():
        if not name.startswith("scope_sets_") or not isinstance(block, dict):
            continue
        count = name.removeprefix("scope_sets_")
        out[count] = {
            key: _arm_pair(document, "measurements", name, key)
            for key in ("discovery", "jwks", "total_oidc")
        }
    return out


def _summarize_s1(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise cold start, one entry per concurrency level.

    Args:
        document: The parsed `s1_cold_start.json`.

    Returns:
        Per-concurrency first and last response medians.
    """
    out: dict[str, Any] = {}
    for name, block in document.get("measurements", {}).items():
        if not name.startswith("concurrency_") or not isinstance(block, dict):
            continue
        level = name.removeprefix("concurrency_")
        out[level] = {
            key: _arm_pair(document, "measurements", name, key)
            for key in ("first_response_ms", "last_response_ms", "p95_ms", "oidc_requests_total")
        }
    return out


def _summarize_s8(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise the failing provider scenario.

    Args:
        document: The parsed `s8_failing_provider.json`.

    Returns:
        The JWKS fetch medians for both arms.
    """
    return {
        "jwks_fetches_during_flood": _arm_pair(
            document, "measurements", "jwks_fetches_during_flood"
        ),
        "unknown_kid_requests_per_repetition": document.get("config", {}).get(
            "unknown_kid_requests_per_repetition"
        ),
    }


def _summarize_memory(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise resident memory and import cost.

    Args:
        document: The parsed `memory.json`.

    Returns:
        Idle and warm resident bytes plus the module and RSS cost of importing each library.
    """
    out: dict[str, Any] = {}
    for field, source in (
        ("baseline_idle_bytes", "baseline_idle"),
        ("warm_bytes", "warm"),
    ):
        out[field] = {
            arm: document.get("measurements", {}).get(arm, {}).get(source, {}).get("usage_bytes")
            for arm in ("legacy", "lite")
        }
    out["import_modules_added"] = {
        arm: document.get("measurements", {})
        .get(arm, {})
        .get("import_cost", {})
        .get("modules_added")
        for arm in ("legacy", "lite")
    }
    out["import_rss_delta_kib"] = {
        arm: document.get("measurements", {})
        .get(arm, {})
        .get("import_cost", {})
        .get("rss_delta_kib")
        for arm in ("legacy", "lite")
    }
    return out


def _summarize_footprint(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise installed distributions.

    Args:
        document: The parsed `footprint.json`.

    Returns:
        Distribution counts and which watched packages each arm actually ships.
    """
    return {
        "distribution_count": {
            arm: document.get("measurements", {}).get(arm, {}).get("distribution_count")
            for arm in ("legacy", "lite")
        },
        "distribution_count_excluding_harness_overhead": {
            arm: document.get("measurements", {})
            .get(arm, {})
            .get("distribution_count_excluding_harness_overhead")
            for arm in ("legacy", "lite")
        },
        "watched_present": {
            arm: document.get("measurements", {}).get(arm, {}).get("watched_present", [])
            for arm in ("legacy", "lite")
        },
    }


def _summarize_call_graph(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise the call counting pass.

    Args:
        document: The parsed `call_graph.json`.

    Returns:
        Warm call counts, call depth and the static reachable-function count.
    """
    out: dict[str, Any] = {}
    for field in (
        "warm_total_calls",
        "warm_max_depth",
        "warm_calls_auth_library",
        "warm_calls_jwt_layer",
        "warm_calls_library_and_jwt",
        "warm_calls_framework",
        "cold_total_calls",
    ):
        out[field] = {
            arm: document.get("measurements", {}).get(arm, {}).get(field)
            for arm in ("legacy", "lite")
        }
    out["reachable_from_call"] = {
        arm: document.get("measurements", {})
        .get(arm, {})
        .get("static", {})
        .get("reachable_from_call")
        for arm in ("legacy", "lite")
    }
    return out


def _summarize_profile(document: dict[str, Any]) -> dict[str, Any]:
    """
    Summarise the sampling profiler pass.

    Args:
        document: The parsed `profile_sampling.json`.

    Returns:
        Loop-thread sample counts and the worst `/health` latency seen during the pass.
    """
    out: dict[str, Any] = {}
    for field in (
        "loop_thread_samples",
        "loop_thread_samples_idle_in_selector",
        "loop_thread_samples_busy",
        "loop_thread_samples_in_blocking_http_client",
        "worker_thread_samples_in_blocking_http_client",
        "worst_health_ms",
        "cold_auth_request_ms",
    ):
        out[field] = {
            arm: document.get("measurements", {}).get(arm, {}).get(field)
            for arm in ("legacy", "lite")
        }
    return out


#: Which summariser to run for which result file. A file with no entry here is still listed
#: in the index's `scenarios`, it just contributes no headline numbers.
_SUMMARIZERS = {
    "s1_cold_start": _summarize_s1,
    "s2_request_amplification": _summarize_s2,
    "s3_warm_flood": _summarize_s3,
    "s4_event_loop_blocking": _summarize_s4,
    "s8_failing_provider": _summarize_s8,
    "footprint": _summarize_footprint,
    "memory": _summarize_memory,
    "call_graph": _summarize_call_graph,
    "profile_sampling": _summarize_profile,
}


def summarize_run(run_directory: str) -> dict[str, Any]:
    """
    Read one run directory and derive its index entry.

    Every number in the entry is computed here, from the run's own files. Nothing is copied
    in from a caller.

    Args:
        run_directory: A directory holding one run's result files.

    Returns:
        The run's index entry, provenance and derived summary included.

    Raises:
        ValueError: The directory holds no result files at all.
    """
    present: list[str] = []
    summary: dict[str, Any] = {}
    provenance: dict[str, Any] = {}
    verdicts: dict[str, Any] = {}
    for name in SCENARIO_FILES:
        path = os.path.join(run_directory, f"{name}.json")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        present.append(name)
        if not provenance and isinstance(document.get("provenance"), dict):
            provenance = document["provenance"]
        if isinstance(document.get("verdicts"), dict):
            verdicts[name] = document["verdicts"]
        summariser = _SUMMARIZERS.get(name)
        if summariser is not None:
            summary[name] = summariser(document)

    if not present:
        raise ValueError(f"{run_directory} holds none of the expected result files")

    return {
        "run_id": os.path.basename(run_directory.rstrip("/")),
        "path": os.path.relpath(run_directory, os.path.dirname(os.path.dirname(run_directory))),
        "complete": len(present) == len(SCENARIO_FILES),
        "scenarios": present,
        "missing": [name for name in SCENARIO_FILES if name not in present],
        "provenance": provenance,
        "verdicts": verdicts,
        "summary": summary,
    }


def _version_sort_key(version: str) -> tuple[Any, ...]:
    """
    Order versions newest first, numerically where the parts are numeric.

    Args:
        version: A bare version such as `"0.10.0"`.

    Returns:
        A sort key. Numeric components compare as integers so 0.10 sorts above 0.9.
    """
    parts: list[Any] = []
    for chunk in re.split(r"[._-]", version):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return tuple(parts)


def build_index(results_root: str) -> dict[str, Any]:
    """
    Walk the results tree and derive the whole index from it.

    Args:
        results_root: The `results/` directory.

    Returns:
        The index document: versions newest first, runs newest first inside each.
    """
    versions: list[dict[str, Any]] = []
    for entry in sorted(os.listdir(results_root)):
        directory = os.path.join(results_root, entry)
        if not entry.startswith("v") or not os.path.isdir(directory):
            continue
        runs: list[dict[str, Any]] = []
        for run_name in sorted(os.listdir(directory)):
            run_directory = os.path.join(directory, run_name)
            if not os.path.isdir(run_directory):
                continue
            try:
                runs.append(summarize_run(run_directory))
            except ValueError:
                continue
        if not runs:
            continue
        runs.sort(key=lambda run: str(run["provenance"].get("timestamp_utc", "")), reverse=True)
        versions.append(
            {
                "version": entry.removeprefix("v"),
                "directory": entry,
                "run_count": len(runs),
                "runs": runs,
            }
        )
    versions.sort(key=lambda block: _version_sort_key(block["version"]), reverse=True)

    return {
        "schema": "armasec-lite-comparison-index/1",
        "generated_utc": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "note": (
            "Derived in full from the result files under this directory. Every number here "
            "is recomputed from those files whenever the index is rebuilt, so the index is "
            "never a second source of truth."
        ),
        "scenario_files": list(SCENARIO_FILES),
        "version_count": len(versions),
        "run_count": sum(len(block["runs"]) for block in versions),
        "versions": versions,
    }


def write_index(results_root: str) -> str:
    """
    Rebuild `index.json` from the results tree and write it.

    Args:
        results_root: The `results/` directory.

    Returns:
        The path written.
    """
    path = os.path.join(results_root, "index.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(build_index(results_root), handle, indent=2, sort_keys=False)
        handle.write("\n")
    return path


if __name__ == "__main__":  # pragma: no cover - a hand-run maintenance entry point
    import sys

    root = sys.argv[1] if len(sys.argv) > 1 else "results"
    print(write_index(os.path.abspath(root)))
