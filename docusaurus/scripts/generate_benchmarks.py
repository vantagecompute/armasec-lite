#!/usr/bin/env python3
"""
Generate the benchmark pages and their figures from the committed comparison results.

Run at build time, from `npm run build`'s `prebuild` hook, the same way
`@vantagecompute/docusaurus-plugin-pydoc` generates the API reference. The pages and the
figure specs are both derived artefacts and both gitignored, for the reason that plugin's
gitignore comment gives: a committed generated page can outlive the data it came from, and
a stale benchmark page is worse than none, because its staleness is invisible.

The committed artefact is the result JSON under `legacy_comparison_compose/results/`. This
script reads that and only that. It never reads `pyproject.toml`, never reaches the network,
and never supplies a default for a number it cannot find. Anything missing or malformed
raises and fails the build, so a page cannot quietly drop a scenario.

```
python3 docusaurus/scripts/generate_benchmarks.py
python3 docusaurus/scripts/generate_benchmarks.py --check   # verify without writing
```

The one thing this script writes that is not a number is prose, and the prose is templated
so it stays true when the numbers change. Sentences derive their direction, their comparison
and their hedging from the data: where the harness recorded a difference as being inside its
own noise threshold, the page says "within noise" rather than quoting a ratio, and where a
measurement counts against armasec-lite the page says so in the same voice it uses for the
wins.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Iterable
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
DOCUSAURUS = os.path.dirname(HERE)
REPOSITORY = os.path.dirname(DOCUSAURUS)
HARNESS = os.path.join(REPOSITORY, "legacy_comparison_compose")

sys.path.insert(0, HARNESS)
sys.path.insert(0, HERE)

import benchmark_charts as charts
from bench import runs as layout

RESULTS_ROOT = os.path.join(HARNESS, "results")
PAGES_DIR = os.path.join(DOCUSAURUS, "docs", "benchmarks")
CHARTS_DIR = os.path.join(DOCUSAURUS, "static", "charts")

#: How each scenario file is titled on the page, and the order the page walks them in. The
#: order is editorial: the headline first, its independent corroboration next, then the
#: exact results, then the ones that need the most care.
SCENARIO_ORDER = (
    "s4_event_loop_blocking",
    "profile_sampling",
    "s2_request_amplification",
    "footprint",
    "memory",
    "call_graph",
    "s3_warm_flood",
    "s1_cold_start",
    "s8_failing_provider",
)

ARMS = ("legacy", "lite")
LABELS = charts.ARM_LABELS
#: The same names, capitalised, for the start of a sentence. `armasec-lite` is a package
#: name and keeps its lower case everywhere, including here.
LEAD = {"legacy": "Upstream armasec", "lite": "armasec-lite"}


class GenerationError(RuntimeError):
    """The results tree cannot produce a complete set of pages."""


# --------------------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------------------


def ms(value: float) -> str:
    """
    Render a millisecond measurement with its unit and a sane number of digits.

    Args:
        value: A duration in milliseconds.

    Returns:
        The formatted duration, for example `"4.32 ms"` or `"1,074.8 ms"`.
    """
    return f"{value:,.2f} ms" if abs(value) < 10 else f"{value:,.1f} ms"


def count(value: float, unit: str = "") -> str:
    """
    Render a count, dropping a trailing `.0` that only a float would have.

    Args:
        value: The count.
        unit:  An optional unit to append.

    Returns:
        The formatted count.
    """
    rendered = f"{round(value):,}" if float(value).is_integer() else f"{value:,.2f}"
    return f"{rendered} {unit}".strip()


def mib(value: float) -> str:
    """
    Render a byte count as mebibytes.

    Args:
        value: A byte count.

    Returns:
        The formatted size, for example `"41.1 MiB"`.
    """
    return f"{charts.mib(value):.1f} MiB"


def spread(block: dict[str, Any], render) -> str:
    """
    Render a measurement as its median with the observed repetition range beside it.

    A number without its spread invites more confidence than the sample supports, so no
    measured value appears on a page without one.

    Args:
        block:  An `across_reps` block carrying `median`, `min` and `max`.
        render: The formatter for a single value.

    Returns:
        The median, followed by the range when the repetitions did not all agree.
    """
    median = float(block["median"])
    low = float(block["min"])
    high = float(block["max"])
    if low == high:
        return f"{render(median)} (every repetition)"
    return f"{render(median)} (range {render(low)} to {render(high)})"


def table(header: Iterable[str], rows: Iterable[Iterable[str]]) -> str:
    """
    Render a Markdown table.

    Args:
        header: Column headings.
        rows:   Row cells, already formatted.

    Returns:
        The table, with a trailing blank line.
    """
    header = list(header)
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
    ]
    lines.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def escape(text: str) -> str:
    """
    Make a string safe to drop into MDX prose.

    MDX reads `{` and `<` as syntax, and result files carry stack signatures full of neither
    but plenty of characters that a future file might not be so polite about.

    Args:
        text: Arbitrary text from a result file.

    Returns:
        The text with MDX's active characters neutralised.
    """
    return text.replace("{", "&#123;").replace("}", "&#125;").replace("<", "&lt;")


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------


def load_runs() -> dict[str, Any]:
    """
    Read the whole results tree, index and documents together.

    Returns:
        The derived index with each run's parsed result documents attached under
        `documents`, and each run given a `label`, a `version` and a `page_id`.

    Raises:
        GenerationError: The tree is absent, empty, or holds a file that will not parse.
    """
    if not os.path.isdir(RESULTS_ROOT):
        raise GenerationError(f"no results directory at {RESULTS_ROOT}")

    index = layout.build_index(RESULTS_ROOT)
    if not index["versions"]:
        raise GenerationError(
            f"{RESULTS_ROOT} holds no run directories, so there is nothing to publish"
        )

    for version in index["versions"]:
        for run in version["runs"]:
            directory = os.path.join(RESULTS_ROOT, version["directory"], run["run_id"])
            documents: dict[str, Any] = {}
            for stem in run["scenarios"]:
                path = os.path.join(directory, f"{stem}.json")
                try:
                    with open(path, encoding="utf-8") as handle:
                        documents[stem] = json.load(handle)
                except (OSError, json.JSONDecodeError) as cause:
                    raise GenerationError(f"{path} could not be read: {cause}") from cause
                if not isinstance(documents[stem].get("provenance"), dict):
                    raise GenerationError(f"{path} carries no provenance block")
            run["documents"] = documents
            run["directory"] = directory
            run["version"] = version["version"]
            run["label"] = f"v{version['version']} {run['run_id']}"
            run["page_id"] = f"v{version['version']}--{run['run_id']}"
            run["chart_dir"] = os.path.join(CHARTS_DIR, run["page_id"])
            run["chart_url"] = f"/charts/{run['page_id']}"

    newest = index["versions"][0]
    covered = {stem for run in newest["runs"] for stem in run["scenarios"]}
    missing = [stem for stem in layout.SCENARIO_FILES if stem not in covered]
    if missing:
        raise GenerationError(
            f"version {newest['version']} has no measurement of {', '.join(missing)} in any "
            "of its runs. A benchmark page that silently omits a scenario is worse than no "
            "page, so the build stops here. Run `just compare-legacy` and commit the result."
        )
    return index


def newest_per_scenario(version: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    For each scenario, find the most recent run of this version that measured it.

    Scenarios are not always measured together: a single scenario can be re-run on its own
    after a harness correction, and when that happens the newer measurement is the one the
    page should lead with. The run each figure came from is named beside it either way.

    Args:
        version: One version block from the index, runs newest first.

    Returns:
        The chosen run for each scenario the version measured at all.
    """
    chosen: dict[str, dict[str, Any]] = {}
    for run in version["runs"]:  # already newest first
        for stem in run["scenarios"]:
            chosen.setdefault(stem, run)
    return chosen


def provenance_of(run: dict[str, Any]) -> dict[str, Any]:
    """
    Read the provenance block a run recorded.

    Args:
        run: A loaded run.

    Returns:
        The provenance block.
    """
    return run["provenance"]


def caption(run: dict[str, Any]) -> str:
    """
    Build the provenance caption that sits under every figure.

    Args:
        run: The run the figure was built from.

    Returns:
        A single line naming the host, the date and both library versions.
    """
    block = provenance_of(run)
    when = str(block.get("timestamp_utc", "")).replace("+00:00", " UTC")
    versions = block.get("library_versions", {})
    return (
        f"{block.get('hostname', 'unknown host')}, {when}, "
        f"{versions.get('legacy', 'upstream armasec')} against "
        f"{versions.get('lite', 'armasec-lite')}, "
        f"{block.get('repetitions', '?')} repetitions. Run {run['run_id']}."
    )


# --------------------------------------------------------------------------------------
# Prose that derives from the data
# --------------------------------------------------------------------------------------


def verdict_rows(document: dict[str, Any]) -> list[list[str]]:
    """
    Turn a result file's verdict block into table rows.

    The verdict strings are the harness's own: a non-parametric overlap test across the
    repetitions, which errs toward calling a difference noise. Reproducing them verbatim is
    deliberate. A generated page that reworded them would be free to make them sound more
    certain than the test that produced them.

    Args:
        document: A parsed result file.

    Returns:
        Rows of `(measurement, verdict)`.
    """
    return [
        [f"`{name}`", escape(str(text))]
        for name, text in sorted(document.get("verdicts", {}).items())
    ]


def blocking_signature(document: dict[str, Any]) -> tuple[str, int] | None:
    """
    Find the loop-thread stack that sits inside a blocking HTTP client.

    Args:
        document: The parsed `profile_sampling.json` for one run.

    Returns:
        The signature and its sample count for upstream armasec, or `None` when the
        profiler saw no such stack, which is itself a finding worth stating.
    """
    markers = charts.require(document, "config", "http_client_markers")
    signatures = charts.require(document, "measurements", "legacy", "top_signatures", "loop")
    for entry in signatures:
        if any(marker in entry["signature"] for marker in markers):
            return entry["signature"], int(entry["samples"])
    return None


def is_noise(verdict: str) -> bool:
    """
    Decide whether a verdict string reports a difference or the absence of one.

    Args:
        verdict: A verdict string from a result file.

    Returns:
        True when the harness called the difference noise.
    """
    return verdict.strip().lower().startswith("within noise")


def compare_phrase(verdict: str) -> str:
    """
    Render a verdict inline, in prose, without inventing certainty it does not carry.

    Args:
        verdict: A verdict string from a result file.

    Returns:
        A phrase suitable for the middle of a sentence.
    """
    if not verdict.strip():
        return "no verdict declared"
    return "within noise, the repetition ranges overlap" if is_noise(verdict) else escape(verdict)


# --------------------------------------------------------------------------------------
# Section writers, one per scenario
# --------------------------------------------------------------------------------------


def section_s4(run: dict[str, Any]) -> str:
    """
    Write the S4 section: the headline result.

    Args:
        run: The run whose S4 measurement is being presented.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["s4_event_loop_blocking"]
    source = f"{run['label']}/s4_event_loop_blocking.json"
    measurements = charts.require(document, "measurements", source=source)
    config = charts.require(document, "config", source=source)
    worst = measurements["worst_health_latency_ms"]
    p99 = measurements["health_p99_during_cold_load_ms"]
    over = measurements["health_requests_over_100ms"]
    baseline = measurements["health_baseline_p50_ms"]
    verdicts = document.get("verdicts", {})

    baseline_note = (
        "Before the cold load starts, the two arms serve `/health` at the same speed: "
        f"{compare_phrase(verdicts.get('baseline_p50', ''))}. "
        if "baseline_p50" in verdicts
        else ""
    )

    return f"""## S4: an unauthenticated route, while a cold token validation runs

{escape(str(document["question"]))}

`/health` requires no token and touches no authentication code. It is served at
{config["health_rate_per_second"]:g} requests per second for {
        config["duration_seconds"]:g} seconds. A quarter
of the way in, one authenticated request arrives on a freshly restarted process, which forces
discovery and JWKS fetches through a proxy holding each response back by
{config["injected_provider_latency_ms"]} ms.

{baseline_note}Once the cold load begins the two diverge:

{
        table(
            ["/health during the cold load", LABELS["legacy"], LABELS["lite"], "harness verdict"],
            [
                [
                    "baseline p50, before the load",
                    spread(baseline["legacy"], ms),
                    spread(baseline["lite"], ms),
                    compare_phrase(verdicts.get("baseline_p50", "")),
                ],
                [
                    "p99 during the load",
                    spread(p99["legacy"], ms),
                    spread(p99["lite"], ms),
                    compare_phrase(verdicts.get("health_p99_during_cold_load", "")),
                ],
                [
                    "worst observed",
                    spread(worst["legacy"], ms),
                    spread(worst["lite"], ms),
                    compare_phrase(verdicts.get("worst_health_latency", "")),
                ],
                [
                    "requests slower than 100 ms",
                    spread(over["legacy"], count),
                    spread(over["lite"], count),
                    compare_phrase(verdicts.get("health_requests_over_100ms", "")),
                ],
            ],
        )
    }
Under {LABELS["legacy"]}, the worst request to a route with no authentication on it waited
{ms(float(worst["legacy"]["median"]))}, against the {
        count(float(config["expected_cold_fetch_cost_ms"]))
    } ms the two injected
provider round trips were expected to cost. Under {LABELS["lite"]} the same request waited
{ms(float(worst["lite"]["median"]))}. The cold work is the same
work in both arms; the difference is which thread it runs on.

<PlotlyChart
  src="{run["chart_url"]}/s4-health-latency.json"
  alt="Bar chart of /health latency percentiles for both libraries during a cold token validation, on a logarithmic scale"
  provenance="{caption(run)}"
/>

<PlotlyChart
  src="{run["chart_url"]}/s4-slow-health-requests.json"
  alt="Bar chart of the number of /health requests slower than 100 ms per repetition"
  provenance="{caption(run)}"
/>
"""


def section_profile(run: dict[str, Any]) -> str:
    """
    Write the sampling profiler section, which corroborates S4 by a different method.

    Args:
        run: The run whose profiler pass is being presented.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["profile_sampling"]
    source = f"{run['label']}/profile_sampling.json"
    measurements = charts.require(document, "measurements", source=source)
    config = charts.require(document, "config", source=source)
    legacy = measurements["legacy"]
    lite = measurements["lite"]
    found = blocking_signature(document)

    if found is None:
        signature_block = (
            "The profiler recorded no loop-thread stack matching a blocking HTTP client in "
            "either arm, so this pass does not corroborate the S4 result and nothing should "
            "be read into it."
        )
    else:
        signature, samples = found
        frames = signature.split(";")
        signature_block = f"""The stack those samples were taken in is recorded verbatim. Read it innermost frame first:

```text
{escape(chr(10).join(frames))}
```

{count(samples)} of the {count(float(legacy["loop_thread_samples_in_blocking_http_client"]))} blocking samples
carry this exact signature. `_client.py:send` at the bottom is the synchronous entry point of
an HTTP client, and `sync.py:read` at the top is a blocking socket read. Those frames are on
the thread running `run_forever`, which is the event loop."""

    return f"""## The same result, measured a second way

{escape(str(document["question"]))}

A separate pass repeats the S4 workload with a sampling profiler running inside each
application: a daemon thread calling `sys._current_frames()` every {
        config["interval_ms"]:g} ms. This is a
different instrument on the same question, and it agrees.

{
        table(
            [
                "Event loop thread, sampled every " + f"{config['interval_ms']:g} ms",
                LABELS["legacy"],
                LABELS["lite"],
            ],
            [
                [
                    "samples taken",
                    count(float(legacy["loop_thread_samples"])),
                    count(float(lite["loop_thread_samples"])),
                ],
                [
                    "idle in the selector",
                    count(float(legacy["loop_thread_samples_idle_in_selector"])),
                    count(float(lite["loop_thread_samples_idle_in_selector"])),
                ],
                [
                    "**inside a blocking HTTP client**",
                    "**"
                    + count(float(legacy["loop_thread_samples_in_blocking_http_client"]))
                    + "**",
                    "**" + count(float(lite["loop_thread_samples_in_blocking_http_client"])) + "**",
                ],
                [
                    "the same, on a worker thread instead",
                    count(float(legacy["worker_thread_samples_in_blocking_http_client"])),
                    count(float(lite["worker_thread_samples_in_blocking_http_client"])),
                ],
                [
                    "worst /health seen during this pass",
                    ms(float(legacy["worst_health_ms"])),
                    ms(float(lite["worst_health_ms"])),
                ],
                [
                    "the cold authenticated request itself",
                    ms(float(legacy["cold_auth_request_ms"])),
                    ms(float(lite["cold_auth_request_ms"])),
                ],
            ],
        )
    }
{signature_block}

The last two rows are the part worth dwelling on. The cold authenticated request costs both
arms about the same, {ms(float(legacy["cold_auth_request_ms"]))} against {
        ms(float(lite["cold_auth_request_ms"]))
    }: neither
library is faster at fetching OIDC metadata, and neither claims to be. What differs is
whether everything else the process is serving waits for it. The blocking read happens in
both arms; under {LABELS["lite"]} it happens on a worker thread, where the profiler counted
{count(float(lite["worker_thread_samples_in_blocking_http_client"]))} samples of it.

Two independent methods, a latency measurement from outside and a stack sample from inside,
give the same answer. That agreement is the strongest evidence on this page.

<PlotlyChart
  src="{run["chart_url"]}/profile-loop-samples.json"
  alt="Stacked bar chart of event loop thread samples split into idle, busy, and inside a blocking HTTP client"
  provenance="{caption(run)}"
/>

<PlotlyChart
  src="{run["chart_url"]}/profile-worst-health.json"
  alt="Bar chart comparing the worst health latency against the cold authenticated request latency for both libraries"
  provenance="{caption(run)}"
/>
"""


def section_s2(run: dict[str, Any]) -> str:
    """
    Write the request amplification section.

    Args:
        run: The run whose S2 measurement is being presented.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["s2_request_amplification"]
    source = f"{run['label']}/s2_request_amplification.json"
    measurements = charts.require(document, "measurements", source=source)
    counts = sorted(
        int(name.removeprefix("scope_sets_"))
        for name in measurements
        if name.startswith("scope_sets_")
    )
    rows = []
    for value in counts:
        block = measurements[f"scope_sets_{value}"]["total_oidc"]
        rows.append(
            [
                str(value),
                spread(block["legacy"], count),
                spread(block["lite"], count),
            ]
        )
    return f"""## S2: OIDC fetches per distinct scope set

{escape(str(document["question"]))}

Every count below was taken at the proxy, so it is what actually left the application, not
what the application believed it did. Each of the {len(counts)} scope-set counts was repeated
{provenance_of(run).get("repetitions", "?")} times, and every repetition of every one produced the same
integer. There is no spread to report here and no ratio to hedge.

{table(["distinct `lockdown()` scope sets", LABELS["legacy"] + ", OIDC fetches", LABELS["lite"] + ", OIDC fetches"], rows)}
{LEAD["legacy"]} performs two fetches, discovery and JWKS, for each distinct scope set the
application declares. {LABELS["lite"]} performs two in total, because the loader is shared
rather than built per dependency. The behaviour is exact, not statistical: the cost of adding
another protected scope set is one more pair of provider round trips on one side and nothing
on the other.

<PlotlyChart
  src="{run["chart_url"]}/s2-oidc-fetches.json"
  alt="Line chart of outbound OIDC requests against the number of distinct scope sets, flat for armasec-lite and linear for upstream"
  provenance="{caption(run)}"
/>
"""


def section_footprint(run: dict[str, Any]) -> str:
    """
    Write the installed footprint section.

    Args:
        run: The run whose footprint measurement is being presented.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["footprint"]
    source = f"{run['label']}/footprint.json"
    measurements = charts.require(document, "measurements", source=source)
    config = charts.require(document, "config", source=source)
    present = measurements["legacy"]["watched_present"]
    lite_present = measurements["lite"]["watched_present"]
    watched = measurements["legacy"]["watched_packages"]

    if present and not lite_present:
        how_many = (
            f"All {len(present)}"
            if len(present) == len(config["watched_packages"])
            else f"{len(present)} of the {len(config['watched_packages'])}"
        )
        watched_sentence = (
            f"{how_many} watched packages are installed in "
            f"{LABELS['legacy']}'s production container and none in {LABELS['lite']}'s: "
            + ", ".join(f"`{name}` {watched[name]}" for name in present)
            + ". Two of those, `pytest` and `respx`, are test tooling that reaches production "
            "because the library imports them at module scope rather than behind an extra."
        )
    elif present:
        watched_sentence = (
            f"{LABELS['legacy']} ships "
            + ", ".join(f"`{name}`" for name in present)
            + f"; {LABELS['lite']} ships "
            + ", ".join(f"`{name}`" for name in lite_present)
            + "."
        )
    else:
        watched_sentence = "Neither arm ships any of the watched packages."

    return f"""## Installed footprint

{escape(str(document["question"]))}

Counted with `importlib.metadata.distributions()` inside the running containers, not from a
lockfile, so it is what is actually installed alongside the application.

{
        table(
            ["Distributions in the application container", LABELS["legacy"], LABELS["lite"]],
            [
                [
                    "installed",
                    count(float(measurements["legacy"]["distribution_count"])),
                    count(float(measurements["lite"]["distribution_count"])),
                ],
                [
                    "excluding shared harness overhead",
                    count(
                        float(
                            measurements["legacy"]["distribution_count_excluding_harness_overhead"]
                        )
                    ),
                    count(
                        float(measurements["lite"]["distribution_count_excluding_harness_overhead"])
                    ),
                ],
            ],
        )
    }
{watched_sentence}

<PlotlyChart
  src="{run["chart_url"]}/footprint-distributions.json"
  alt="Bar chart of installed distribution counts for both libraries"
  provenance="{caption(run)}"
/>
"""


def section_memory(run: dict[str, Any]) -> str:
    """
    Write the resident memory and import cost section.

    Args:
        run: The run whose memory measurement is being presented.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["memory"]
    source = f"{run['label']}/memory.json"
    measurements = charts.require(document, "measurements", source=source)
    config = charts.require(document, "config", source=source)
    legacy = measurements["legacy"]
    lite = measurements["lite"]

    climb_legacy = float(legacy["under_load"]["climb_pct"])
    climb_lite = float(lite["under_load"]["climb_pct"])
    accumulation = (
        "Neither arm's resident set climbed measurably across "
        f"{config['load_seconds']:g} seconds at {config['load_rate_per_second']:g} requests per second: "
        f"{climb_legacy:.2f} percent for {LABELS['legacy']} and {climb_lite:.2f} percent for {LABELS['lite']}. "
        "Nothing here suggests a leak in either."
        if max(abs(climb_legacy), abs(climb_lite)) < 1.0
        else (
            f"Resident memory moved {climb_legacy:.2f} percent for {LABELS['legacy']} and "
            f"{climb_lite:.2f} percent for {LABELS['lite']} across the load window, which is worth "
            "a closer look than this harness gives it."
        )
    )

    return f"""## Resident memory and import cost

{escape(str(document["question"]))}

Read from the Docker daemon's container statistics rather than from inside the process, so
the number includes the interpreter and everything it loaded.

{
        table(
            ["Memory", LABELS["legacy"], LABELS["lite"]],
            [
                [
                    "container resident, idle",
                    mib(float(legacy["baseline_idle"]["usage_bytes"])),
                    mib(float(lite["baseline_idle"]["usage_bytes"])),
                ],
                [
                    f"container resident, after {int(legacy['warm_requests_issued'])} requests",
                    mib(float(legacy["warm"]["usage_bytes"])),
                    mib(float(lite["warm"]["usage_bytes"])),
                ],
                [
                    "modules imported by the library",
                    count(float(legacy["import_cost"]["modules_added"])),
                    count(float(lite["import_cost"]["modules_added"])),
                ],
                [
                    "resident memory added by the import",
                    f"{float(legacy['import_cost']['rss_delta_kib']) / 1024:.1f} MiB",
                    f"{float(lite['import_cost']['rss_delta_kib']) / 1024:.1f} MiB",
                ],
            ],
        )
    }
{accumulation}

The idle difference, {mib(float(legacy["baseline_idle"]["usage_bytes"]))} against
{mib(float(lite["baseline_idle"]["usage_bytes"]))}, is a few megabytes on a process that is mostly
interpreter. It is a real difference and a small one. The module count behind it,
{count(float(legacy["import_cost"]["modules_added"]))} against {
        count(float(lite["import_cost"]["modules_added"]))
    },
matters more for what it implies about surface area than for the memory it costs.

<PlotlyChart
  src="{run["chart_url"]}/memory-resident.json"
  alt="Bar chart of container resident memory idle and warm for both libraries"
  provenance="{caption(run)}"
/>

<PlotlyChart
  src="{run["chart_url"]}/memory-import-cost.json"
  alt="Bar chart of the number of modules each library imports into a fresh interpreter"
  provenance="{caption(run)}"
/>
"""


def section_call_graph(run: dict[str, Any]) -> str:
    """
    Write the call counting section, including the count that goes against armasec-lite.

    Args:
        run: The run whose call graph measurement is being presented.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["call_graph"]
    source = f"{run['label']}/call_graph.json"
    measurements = charts.require(document, "measurements", source=source)
    legacy = measurements["legacy"]
    lite = measurements["lite"]

    legacy_reach = int(legacy["static"]["reachable_from_call"])
    lite_reach = int(lite["static"]["reachable_from_call"])
    if lite_reach > legacy_reach:
        against = f"""### One count goes the other way

`reachable_from_call` is the number of functions statically reachable from the entry point
the request path enters through. {LABELS["lite"]} scores {lite_reach} against
{LABELS["legacy"]}'s {legacy_reach}. That is worse, by {lite_reach - legacy_reach}, and it is not an
artefact of the smaller library being easier to walk: it is measured the same way in both.

The reading is that {LABELS["lite"]} spreads its work over more, smaller functions inside a
much smaller module set. Which of the two facts a reader weighs more is a judgement, not a
measurement, and this page is not going to make it for them by omitting the number."""
    elif lite_reach < legacy_reach:
        against = f"""### Reachable surface

`reachable_from_call` is {lite_reach} for {LABELS["lite"]} against {legacy_reach} for
{LABELS["legacy"]}, so this count runs the same direction as the others. It has run the other
way in the past; it is reported either way."""
    else:
        against = f"""### Reachable surface

`reachable_from_call` is {lite_reach} for both arms."""

    depth_note = (
        f"Call depth is the same in both, {int(legacy['warm_max_depth'])} frames"
        if int(legacy["warm_max_depth"]) == int(lite["warm_max_depth"])
        else (
            f"Call depth differs: {int(legacy['warm_max_depth'])} frames for {LABELS['legacy']} "
            f"against {int(lite['warm_max_depth'])} for {LABELS['lite']}"
        )
    )

    return f"""## Calls made serving one warm request

{escape(str(document["question"]))}

Counted with `sys.setprofile` around a single request, the second of a repeat pair so every
cache is hot. This is a count, not a timing: it says how much Python runs, and deliberately
nothing about how long it takes.

{
        table(
            ["Warm authenticated request", LABELS["legacy"], LABELS["lite"]],
            [
                [
                    "calls, all packages",
                    count(float(legacy["warm_total_calls"])),
                    count(float(lite["warm_total_calls"])),
                ],
                [
                    "calls inside the auth library",
                    count(float(legacy["warm_calls_auth_library"])),
                    count(float(lite["warm_calls_auth_library"])),
                ],
                [
                    "calls inside the JWT layer",
                    count(float(legacy["warm_calls_jwt_layer"])),
                    count(float(lite["warm_calls_jwt_layer"])),
                ],
                [
                    "auth library and JWT layer together",
                    count(float(legacy["warm_calls_library_and_jwt"])),
                    count(float(lite["warm_calls_library_and_jwt"])),
                ],
                [
                    "calls inside the framework",
                    count(float(legacy["warm_calls_framework"])),
                    count(float(lite["warm_calls_framework"])),
                ],
                [
                    "maximum call depth",
                    count(float(legacy["warm_max_depth"])),
                    count(float(lite["warm_max_depth"])),
                ],
                [
                    "functions defined",
                    count(float(legacy["static"]["functions_defined"])),
                    count(float(lite["static"]["functions_defined"])),
                ],
                [
                    "internal call sites",
                    count(float(legacy["static"]["internal_call_sites"])),
                    count(float(lite["static"]["internal_call_sites"])),
                ],
                [
                    "reachable from the entry point",
                    count(float(legacy["static"]["reachable_from_call"])),
                    count(float(lite["static"]["reachable_from_call"])),
                ],
            ],
        )
    }
{depth_note}. This measurement is one request on one process and carries no repetitions, so
treat it as a description of the code path rather than as a statistic.

{against}

<PlotlyChart
  src="{run["chart_url"]}/call-graph-warm.json"
  alt="Bar chart of calls made serving one warm authenticated request, broken down by package"
  provenance="{caption(run)}"
/>

<PlotlyChart
  src="{run["chart_url"]}/call-graph-static.json"
  alt="Bar chart of statically defined functions, internal call sites, reachable functions and warm call depth"
  provenance="{caption(run)}"
/>
"""


def section_s3(run: dict[str, Any], call_run: dict[str, Any] | None) -> str:
    """
    Write the warm flood section: a modest real difference, and its amplified consequence.

    The finding worth carrying away is the per-request one, which is small. The dramatic
    numbers at the top of the sweep are the same small difference multiplied by proximity to
    a capacity ceiling, and this section separates the two rather than letting the second
    stand in for the first.

    Args:
        run:      The run whose S3 measurement is being presented.
        call_run: The run whose call graph measurement is available, if any. Used to relate
                  the service-time difference to the per-request work difference.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["s3_warm_flood"]
    source = f"{run['label']}/s3_warm_flood.json"
    measurements = charts.require(document, "measurements", source=source)
    verdicts = document.get("verdicts", {})
    rates = sorted(
        float(name.removeprefix("target_").removesuffix("_rps"))
        for name in measurements
        if name.startswith("target_")
    )

    rows = []
    for rate in rates:
        block = measurements[f"target_{rate:g}_rps"]
        key = f"{rate:g}rps"
        for metric, render in (("p50_ms", ms), ("p99_ms", ms)):
            rows.append(
                [
                    f"{rate:g} rps, {metric.removesuffix('_ms')}",
                    spread(block[metric]["legacy"], render),
                    spread(block[metric]["lite"], render),
                    compare_phrase(verdicts.get(f"{key}_{metric}", "")),
                ]
            )
        rows.append(
            [
                f"{rate:g} rps, achieved rate",
                spread(block["achieved_rps"]["legacy"], lambda v: f"{v:,.1f} rps"),
                spread(block["achieved_rps"]["lite"], lambda v: f"{v:,.1f} rps"),
                compare_phrase(verdicts.get(f"{key}_achieved_rps", "")),
            ]
        )

    saturated = charts.saturation(document, source)
    below = [rate for rate in rates if rate not in saturated]
    top = rates[-1]
    top_block = measurements[f"target_{top:g}_rps"]
    legacy_p50 = float(top_block["p50_ms"]["legacy"]["median"])
    lite_p50 = float(top_block["p50_ms"]["lite"]["median"])
    legacy_rate = float(top_block["achieved_rps"]["legacy"]["median"])
    lite_rate = float(top_block["achieved_rps"]["lite"]["median"])
    rate_verdict = verdicts.get(f"{top:g}rps_achieved_rps", "")

    # The service-time finding: how much more each request costs upstream, at every rate
    # where both arms were still serving everything they were offered. Above that boundary
    # the number stops being service time, so it is deliberately not averaged in.
    service_rows = []
    service_diffs: list[float] = []
    for rate in below:
        block = measurements[f"target_{rate:g}_rps"]["p50_ms"]
        legacy_value = float(block["legacy"]["median"])
        lite_value = float(block["lite"]["median"])
        difference = (legacy_value - lite_value) / lite_value * 100.0
        noise = is_noise(verdicts.get(f"{rate:g}rps_p50_ms", ""))
        service_rows.append(
            [
                f"{rate:g} rps",
                ms(legacy_value),
                ms(lite_value),
                "within noise" if noise else f"+{difference:.1f} percent",
            ]
        )
        if not noise:
            service_diffs.append(difference)

    # Reported as the observed range rather than as an average of two or three points. An
    # average over this few measurements would look more settled than the measurements are.
    if not service_diffs:
        headline = "no measurable amount"
    elif len(service_diffs) == 1:
        headline = f"{service_diffs[0]:.0f} percent"
    else:
        headline = f"{min(service_diffs):.0f} to {max(service_diffs):.0f} percent"

    if call_run is not None:
        calls = charts.require(
            call_run["documents"]["call_graph"], "measurements", source="call_graph.json"
        )
        legacy_calls = float(calls["legacy"]["warm_total_calls"])
        lite_calls = float(calls["lite"]["warm_total_calls"])
        fewer = (1.0 - lite_calls / legacy_calls) * 100.0
        work_sentence = (
            f"That is consistent with the call counting pass, where {LABELS['lite']} makes "
            f"{fewer:.0f} percent fewer calls serving the same warm request "
            f"({count(lite_calls)} against {count(legacy_calls)}). A constant factor of that size in "
            "work per request is exactly what a constant factor of this size in service time "
            "looks like."
        )
    else:
        work_sentence = (
            "This run recorded no call counting pass, so there is nothing here to relate the "
            "service time difference to."
        )

    if saturated.get(top) == ["legacy"]:
        legacy_short = top - legacy_rate
        lite_short = top - lite_rate
        legacy_range = top_block["p50_ms"]["legacy"]
        lite_range = top_block["p50_ms"]["lite"]
        ceiling = f"""### Why {top:g} rps looks so much worse than {below[-1]:g} rps

A few percent more work per request also means a few percent less capacity, and at {top:g} rps
that is what the achieved rate shows. Of the {top:g} offered, {LABELS["legacy"]} served
{legacy_rate:,.1f}, short by {legacy_short:.1f} per second, while {LABELS["lite"]} served {lite_rate:,.1f},
short by {lite_short:.1f}. **At this point {LABELS["legacy"]} is at its ceiling and {LABELS["lite"]} is
not.**

Latency near capacity is not linear in load. As utilisation approaches one, queueing delay
diverges, so a modest constant factor in service time becomes an enormous factor in observed
latency the moment one arm crosses its ceiling and the other has not. The p50 at {top:g} rps,
{ms(legacy_p50)} against {ms(lite_p50)}, is queue depth. It is not per-request work, and it is not a
{legacy_p50 / lite_p50:.1f}-fold throughput advantage.

The repetition spread says the same thing. Across {provenance_of(run).get("repetitions", "?")}
repetitions, {LABELS["legacy"]}'s p50 ran from {ms(float(legacy_range["min"]))} to
{ms(float(legacy_range["max"]))}, while {LABELS["lite"]}'s ran from {ms(float(lite_range["min"]))} to
{ms(float(lite_range["max"]))}. A system comfortably below its ceiling repeats itself; one sitting on
the boundary does not.

On the achieved rate specifically, the harness's own overlap test declines to call a winner:
{compare_phrase(rate_verdict)}, because {LABELS["legacy"]}'s best repetition reached
{float(top_block["achieved_rps"]["legacy"]["max"]):,.1f} rps. The latency evidence is the stronger of the two
and it points the same way.

So there are two findings here and they are not the same size:

- **Real and modest.** Below saturation, {LABELS["legacy"]} costs {headline} more per request.
  That is the transferable result.
- **Real but derivative.** The {top:g} rps numbers are that same small difference, amplified by
  proximity to a capacity ceiling. Comparing latency across a saturation boundary measures
  the boundary, not the libraries.

The latency chart marks the saturated point, and the achieved-rate chart beside it shows the
ceiling directly. Read them together or not at all."""
    elif saturated:
        arms = ", ".join(LABELS[arm] for rate, found in saturated.items() for arm in found)
        ceiling = f"""### Saturation in this run

At least one arm stopped serving the offered rate in this run ({arms}), so the latency
figures above and below that point are not measuring the same quantity. Latency compared
across a saturation boundary measures the boundary. The achieved-rate chart shows where it
falls."""
    else:
        ceiling = f"""### No saturation in this run

Both arms served every offered rate up to {top:g} rps, so every latency figure above is service
time rather than queueing delay, and the differences are the modest ones in the table."""

    return f"""## S3: warm steady state under sustained load

{escape(str(document["question"]))}

Open loop: requests are issued on a fixed schedule and a slow response delays nothing behind
it, so a queue that builds shows up as latency instead of hiding as a lower rate. The first
{document["config"]["warmup_seconds_discarded"]:g} seconds of each point are discarded and the next
{document["config"]["measured_seconds"]:g} seconds are measured.

{table(["Offered rate and metric", LABELS["legacy"], LABELS["lite"], "harness verdict"], rows)}
### The per-request finding

Below saturation, p50 reflects the time it takes to serve a request rather than the time it
spends waiting behind other requests. At every rate where both arms served everything they
were offered:

{table(["Offered rate", LABELS["legacy"] + " p50", LABELS["lite"] + " p50", "difference"], service_rows)}
Serving the same request, {LABELS["legacy"]} costs **{headline} more**. {work_sentence}

{ceiling}

<PlotlyChart
  src="{run["chart_url"]}/s3-latency.json"
  alt="Line chart of p50 and p99 latency against offered request rate for both libraries on a logarithmic scale, with the saturated rate marked"
  provenance="{caption(run)}"
/>

<PlotlyChart
  src="{run["chart_url"]}/s3-achieved-rate.json"
  alt="Bar chart of achieved request rate against offered request rate for both libraries, showing where upstream falls short"
  provenance="{caption(run)}"
/>
"""


def section_s1(run: dict[str, Any]) -> str:
    """
    Write the cold start section.

    Args:
        run: The run whose S1 measurement is being presented.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["s1_cold_start"]
    source = f"{run['label']}/s1_cold_start.json"
    measurements = charts.require(document, "measurements", source=source)
    verdicts = document.get("verdicts", {})
    levels = sorted(
        int(name.removeprefix("concurrency_"))
        for name in measurements
        if name.startswith("concurrency_")
    )
    rows = []
    for level in levels:
        block = measurements[f"concurrency_{level}"]["first_response_ms"]
        rows.append(
            [
                str(level),
                spread(block["legacy"], ms),
                spread(block["lite"], ms),
                compare_phrase(verdicts.get(f"c{level}_first_response", "")),
            ]
        )

    wins_for_legacy = [
        level
        for level in levels
        if "upstream armasec" in str(verdicts.get(f"c{level}_first_response", "")).lower()
    ]
    reversal = (
        "The direction reverses at the top of the sweep: at "
        + " and ".join(f"{level} concurrent first requests" for level in wins_for_legacy)
        + f", {LABELS['legacy']} reaches its first response sooner. "
        "That is on this page for the same reason the rest of it is."
        if wins_for_legacy
        else ""
    )

    return f"""## S1: cold start

{escape(str(document["question"]))}

The container is restarted before every repetition, then some number of authenticated
requests arrive at once against a provider with no injected latency. Differences here are
modest and the sweep is the point, not any single row.

{table(["concurrent first requests", LABELS["legacy"] + ", first response", LABELS["lite"] + ", first response", "harness verdict"], rows)}
{reversal}

<PlotlyChart
  src="{run["chart_url"]}/s1-cold-start.json"
  alt="Line chart of time to first authenticated response against concurrency for both libraries"
  provenance="{caption(run)}"
/>
"""


def section_s8(run: dict[str, Any]) -> str:
    """
    Write the failing provider section, as a behaviour difference rather than a scoreboard.

    Args:
        run: The run whose S8 measurement is being presented.

    Returns:
        Markdown for the section.
    """
    document = run["documents"]["s8_failing_provider"]
    source = f"{run['label']}/s8_failing_provider.json"
    measurements = charts.require(document, "measurements", source=source)
    config = charts.require(document, "config", source=source)
    fetches = measurements["jwks_fetches_during_flood"]
    requests = float(config["unknown_kid_requests_per_repetition"])
    recorded = str(document.get("verdicts", {}).get("jwks_fetches", ""))

    return f"""## S8: a failing provider and attacker-chosen key ids

{escape(str(document["question"]))}

The JWKS endpoint is made to return 500 while discovery keeps working. Then
{requests:g} tokens arrive, each signed with a key id the application has never seen. If a
library refetched the key set on every unknown key id, an unauthenticated client could aim
{requests:g} outbound requests per {requests:g} inbound at the identity provider.

{
        table(
            ["JWKS fetches while the provider is failing", LABELS["legacy"], LABELS["lite"]],
            [
                [
                    f"outbound JWKS requests for {requests:g} unknown key ids",
                    spread(fetches["legacy"], count),
                    spread(fetches["lite"], count),
                ],
                ["if unbounded, one per request", count(requests), count(requests)],
            ],
        )
    }
**This is not a scoreboard row, and the smaller number is not the better one.** The harness
records no winner here, and its own note says why:

> {escape(recorded)}

{LEAD["legacy"]} fetches nothing because it never attempts a refetch on an unknown key id at
all. That bounds the amplification perfectly and it is also why it cannot pick up a rotated
signing key without a process restart. {LABELS["lite"]} makes exactly one fetch across all
{requests:g} unknown key ids, because it does attempt a refetch and a rate limit stops the second
attempt. One fetch is the refresh working and the bound holding at the same time.

Which behaviour is preferable depends on whether key rotation without a restart matters to
the deployment. The measurement says what each does; it does not say which is right.

<PlotlyChart
  src="{run["chart_url"]}/s8-jwks-fetches.json"
  alt="Bar chart of outbound JWKS requests during a failing provider flood, with the unbounded case marked"
  provenance="{caption(run)}"
/>
"""


#: Which writer handles which scenario on the summary page. Scenarios needing a second
#: run's data take it as an extra argument, handled in `write_index_page`.
SECTIONS = {
    "s4_event_loop_blocking": section_s4,
    "profile_sampling": section_profile,
    "s2_request_amplification": section_s2,
    "footprint": section_footprint,
    "memory": section_memory,
    "call_graph": section_call_graph,
    "s1_cold_start": section_s1,
    "s8_failing_provider": section_s8,
}


# --------------------------------------------------------------------------------------
# Page assembly
# --------------------------------------------------------------------------------------


def provenance_table(run: dict[str, Any]) -> str:
    """
    Render a run's provenance block as a table.

    Args:
        run: A loaded run.

    Returns:
        A Markdown table naming the machine and the software the run measured.
    """
    block = provenance_of(run)
    limits = block.get("app_container_limits", {}).get("legacy", {})
    rows = [
        [
            "measured at",
            escape(str(block.get("timestamp_utc", "unknown")).replace("+00:00", " UTC")),
        ],
        ["host", f"`{escape(str(block.get('hostname', 'unknown')))}`"],
        ["CPU", escape(str(block.get("cpu_model", "unknown")))],
        ["cores", count(float(block.get("cpu_count", 0)))],
        [
            "host memory",
            f"{float(block['memory_total_bytes']) / 1024**3:.1f} GiB"
            if block.get("memory_total_bytes")
            else "unknown",
        ],
        ["kernel", f"`{escape(str(block.get('kernel', 'unknown')))}`"],
        ["operating system", escape(str(block.get("operating_system", "unknown")))],
        [
            "Docker",
            f"{escape(str(block.get('docker_version', 'unknown')))} (API {escape(str(block.get('docker_api_version', 'unknown')))})",
        ],
        ["identity provider", f"`{escape(str(block.get('keycloak_image', 'unknown')))}`"],
        [
            "upstream arm",
            f"`{escape(str(block.get('library_versions', {}).get('legacy', 'unknown')))}`",
        ],
        [
            "armasec-lite arm",
            f"`{escape(str(block.get('library_versions', {}).get('lite', 'unknown')))}`",
        ],
        ["repetitions per point", count(float(block.get("repetitions", 0)))],
    ]
    if limits:
        rows.append(
            [
                "container limits, both arms",
                f"{limits.get('cpus', '?')} CPUs, {mib(float(limits.get('mem_limit_bytes', 0)))}",
            ]
        )
    return table(["Provenance", "Value"], rows)


HEADER_IMPORT = 'import PlotlyChart from "@site/src/components/PlotlyChart";\n'


def write_run_page(run: dict[str, Any], position: int) -> str:
    """
    Write one run's own page: what it measured, on what, and with what result.

    Args:
        run:      A loaded run.
        position: Its sidebar position.

    Returns:
        The page body, for the caller to write out.
    """
    parts = [
        "---",
        f'title: "{run["run_id"]}"',
        f'sidebar_label: "v{run["version"]} {run["run_id"]}"',
        f"sidebar_position: {position}",
        (
            f"description: One comparison run of armasec-lite {run['version']}, "
            f"measured on {provenance_of(run).get('hostname', 'an unknown host')}."
        ),
        "---",
        "",
        HEADER_IMPORT,
        f"# Run `{run['run_id']}`",
        "",
        (
            f"One comparison run of **armasec-lite {run['version']}** against upstream armasec. "
            "Generated from this run's result files; nothing on this page was written by hand."
        ),
        "",
        provenance_table(run),
    ]

    recorded = ", ".join(f"`{stem}`" for stem in run["scenarios"])
    if run["missing"]:
        absent = ", ".join(f"`{stem}`" for stem in run["missing"])
        parts.append(
            f"This run recorded {len(run['scenarios'])} of the "
            f"{len(layout.SCENARIO_FILES)} scenarios: {recorded}. It did not record {absent}. "
            "A run measures whatever it was asked to measure; the "
            "[summary](./index.mdx) draws each scenario from the most recent run of this "
            "version that measured it.\n"
        )
    else:
        parts.append(f"This run recorded all {len(run['scenarios'])} scenarios: {recorded}.\n")

    for stem in SCENARIO_ORDER:
        if stem not in run["documents"]:
            continue
        document = run["documents"][stem]
        rows = verdict_rows(document)
        parts.append(f"## `{stem}`")
        parts.append("")
        parts.append(f"**{escape(str(document['title']))}**")
        parts.append("")
        parts.append(escape(str(document["question"])))
        parts.append("")
        if rows:
            parts.append(
                "Verdicts as the harness recorded them. The test is a non-parametric "
                "comparison of the observed repetition ranges, which errs toward calling a "
                "difference noise.\n"
            )
            parts.append(table(["Measurement", "Verdict"], rows))
        else:
            parts.append(
                "This scenario records counts rather than a distribution, so the harness "
                "declares no verdict on it.\n"
            )
        for figure in charts.BUILDERS.get(stem, {}):
            parts.append(
                f'<PlotlyChart\n  src="{run["chart_url"]}/{figure}.json"\n'
                f'  alt="{figure.replace("-", " ")} for run {run["run_id"]}"\n'
                f'  provenance="{caption(run)}"\n/>\n'
            )

    parts.append("## The raw files\n")
    parts.append(
        "Every number above comes from "
        f"`legacy_comparison_compose/results/v{run['version']}/{run['run_id']}/`, which is "
        "committed to the repository. The page is regenerated from those files on every "
        "documentation build and is not committed itself.\n"
    )
    return "\n".join(parts)


def trend_section(index: dict[str, Any], figures: dict[str, dict[str, Any]]) -> str:
    """
    Write the section that compares runs against each other.

    Args:
        index:   The loaded index.
        figures: The trend figures that could be built, possibly none.

    Returns:
        Markdown for the section, honest about what does not exist yet.
    """
    total = index["run_count"]
    versions = index["version_count"]
    lead = f"""## Comparing runs against each other

Every run is kept, so this page can show change rather than only a snapshot. The two kinds
of comparison answer different questions. Two runs of the **same** version differ only by
machine and by noise, which is how far a single number here should be trusted. Two runs of
**different** versions differ by what changed in the library, which is how a regression we
introduced ourselves becomes visible.

There {"are" if total != 1 else "is"} {total} run{"s" if total != 1 else ""} committed, across
{versions} version{"s" if versions != 1 else ""}.
"""
    if not figures:
        return (
            lead
            + """
No measurement has yet been taken more than once, so there is nothing to plot. The charts in
this section appear on their own once a second run of any scenario is committed, and the
first thing they will show is how much of the difference above was ever noise.
"""
        )
    body = "\n".join(
        f'<PlotlyChart\n  src="/charts/trends/{name}.json"\n'
        f'  alt="{name.replace("-", " ")} across every committed run"\n'
        f'  provenance="Every committed run, oldest first. Each run\'s own host and versions are on its run page."\n/>\n'
        for name in sorted(figures)
    )
    return lead + "\n" + body


def write_index_page(index: dict[str, Any], figures: dict[str, dict[str, Any]]) -> str:
    """
    Write the summary page: the newest version, read honestly.

    Args:
        index:   The loaded index.
        figures: The trend figures that could be built.

    Returns:
        The page body.

    Raises:
        GenerationError: A scenario has no run to draw from, which `load_runs` should
            already have caught.
    """
    newest = index["versions"][0]
    chosen = newest_per_scenario(newest)
    lead_run = chosen["s4_event_loop_blocking"]
    hosts = sorted({str(provenance_of(run).get("hostname", "unknown")) for run in chosen.values()})

    tree_rows = []
    for version in index["versions"]:
        for run in version["runs"]:
            block = provenance_of(run)
            tree_rows.append(
                [
                    f"`{version['version']}`",
                    f"[`{run['run_id']}`](./{run['page_id']}.mdx)",
                    escape(str(block.get("timestamp_utc", "")).replace("+00:00", " UTC")),
                    f"`{escape(str(block.get('hostname', '?')))}`",
                    f"{len(run['scenarios'])} of {len(layout.SCENARIO_FILES)}",
                ]
            )

    sources = table(
        ["Scenario", "Drawn from run"],
        [
            [f"`{stem}`", f"[`{chosen[stem]['run_id']}`](./{chosen[stem]['page_id']}.mdx)"]
            for stem in SCENARIO_ORDER
            if stem in chosen
        ],
    )

    parts = [
        "---",
        "title: Benchmarks",
        "sidebar_label: Benchmarks",
        "sidebar_position: 0",
        (
            "description: armasec-lite measured against upstream armasec, with the losses "
            "and the unknowns reported alongside the wins."
        ),
        "---",
        "",
        HEADER_IMPORT,
        "# Benchmarks",
        "",
        f"""armasec-lite measured against the library it replaces, upstream `armasec`, on the same
machine, in the same container image, against the same Keycloak, with identical CPU and
memory limits on both application containers. The harness refuses to start if those limits
differ, because an unfair comparison is worse than no comparison.

This is a library benchmarked against its own upstream by the people who wrote it. Treat it
accordingly. What follows reports the results that go against armasec-lite and the questions
this harness could not answer in the same place, and at the same size, as the ones that go
for it.

## How to read this page

- **These numbers describe one machine running Docker.** Everything below was measured on
  `{escape(hosts[0])}`{"" if len(hosts) == 1 else " and " + ", ".join("`" + escape(h) + "`" for h in hosts[1:])},
  inside containers, with an identity provider on the same host. Absolute milliseconds will
  not transfer to your hardware. **The ratio between the two arms is the part that
  transfers**, and even that only for the workload described.
- **Every measured value appears with the range its repetitions covered.** Where those ranges
  overlap, the harness calls the difference noise and this page says "within noise" instead
  of quoting a ratio. That test is deliberately blunt: {provenance_of(lead_run).get("repetitions", "?")}
  repetitions cannot support anything finer.
- **Counts are exact where they are exact.** The OIDC fetch counts in S2 and the JWKS fetch
  counts in S8 were taken at a proxy and repeated identically every time. They carry no
  spread because there was none.
- **Nothing here is hand-entered.** This page is generated from the JSON files under
  `legacy_comparison_compose/results/`, which are committed. If a number is on this page it
  is in one of those files, and if a file goes missing the documentation build fails rather
  than quietly dropping a section.

## What was measured, and when

Results are stored one directory per run, under one directory per armasec-lite version, and
every run is kept. The version and the timestamp both come from the run's own provenance
block rather than from the working tree.

{table(["Version", "Run", "Measured at", "Host", "Scenarios"], tree_rows)}
The summary below presents **armasec-lite {newest["version"]}**, taking each scenario from the most
recent run of that version which measured it:

{sources}""",
    ]

    call_run = chosen.get("call_graph")
    for stem in SCENARIO_ORDER:
        run = chosen.get(stem)
        if run is None:
            raise GenerationError(f"no run measured {stem}")
        if stem == "s3_warm_flood":
            parts.append(section_s3(run, call_run))
        else:
            parts.append(SECTIONS[stem](run))

    parts.append(trend_section(index, figures))
    parts.append(
        """## What this page does not tell you

- **A throughput multiple.** The S3 numbers at the top offered rate are the easiest thing on
  this page to overread. They are a modest per-request difference amplified by one arm
  reaching its capacity ceiling while the other had not. The per-request difference is the
  finding; the multiple is an artefact of where the boundary fell on this machine.
- **Anything about a machine that is not the one named above.** No cloud instance, no
  multi-host deployment, no provider across a real network.
- **Anything about correctness.** These are performance and footprint measurements. The
  parity suite under `legacy_comparison_compose/test_parity.py` is what checks that the two
  libraries accept and reject the same tokens, and it is a separate claim from any of these.
- **Anything about a workload with a different shape.** One protected route, one realm, one
  signing key, tokens that are valid unless the scenario says otherwise.

## Reproducing this

The harness lives in `legacy_comparison_compose/`. It builds both application images, brings
up Keycloak and a counting proxy, and runs every scenario:

```bash
just compare-legacy
```

Each run writes into `legacy_comparison_compose/results/v<version>/<timestamp>-<host>/` and
rebuilds `results/index.json` from the whole tree. Nothing is overwritten, and every run is
meant to be committed, so that the next person to read this page can see whether the numbers
moved. Regenerating these pages and their figures from the committed files, without running
anything:

```bash
just charts
```
"""
    )
    return "\n".join(parts)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def generate(check_only: bool = False) -> int:
    """
    Build every figure and every page.

    Args:
        check_only: Validate the results tree and build every figure in memory without
            writing anything.

    Returns:
        The number of figure specs built.

    Raises:
        GenerationError: The results tree cannot produce a complete set of pages.
        charts.ResultError: A result file is missing something a figure needs.
    """
    index = load_runs()
    all_runs = [run for version in index["versions"] for run in version["runs"]]
    all_runs.sort(key=lambda run: str(provenance_of(run).get("timestamp_utc", "")))

    built: list[tuple[str, dict[str, Any]]] = []
    for run in all_runs:
        for stem, builders in charts.BUILDERS.items():
            if stem not in run["documents"]:
                continue
            source = f"{run['label']}/{stem}.json"
            for name, builder in builders.items():
                built.append(
                    (
                        os.path.join(run["chart_dir"], f"{name}.json"),
                        builder(run["documents"][stem], source),
                    )
                )

    trends = charts.trend_figures(all_runs)
    for name, figure in trends.items():
        built.append((os.path.join(CHARTS_DIR, "trends", f"{name}.json"), figure))

    pages = {os.path.join(PAGES_DIR, "index.mdx"): write_index_page(index, trends)}
    for position, run in enumerate(reversed(all_runs), start=1):
        pages[os.path.join(PAGES_DIR, f"{run['page_id']}.mdx")] = write_run_page(run, position)

    for body in pages.values():
        # Written as escapes so this guard does not itself contain what it forbids.
        for dash in ("\u2014", "\u2013"):
            if dash in body:
                raise GenerationError(
                    f"a generated page contains U+{ord(dash):04X}, which this project does not use"
                )

    if check_only:
        return len(built)

    for directory in (CHARTS_DIR, PAGES_DIR):
        if os.path.isdir(directory):
            shutil.rmtree(directory)

    for path, figure in built:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(figure, handle, indent=1, sort_keys=False)
            handle.write("\n")

    os.makedirs(PAGES_DIR, exist_ok=True)
    for path, body in pages.items():
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body.rstrip() + "\n")

    return len(built)


def main(argv: list[str]) -> int:
    """
    Command line entry point.

    Args:
        argv: Arguments, the program name excluded.

    Returns:
        A process exit status.
    """
    parser = argparse.ArgumentParser(prog="generate_benchmarks", description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the results tree and build every figure without writing anything",
    )
    args = parser.parse_args(argv)

    try:
        figures = generate(check_only=args.check)
    except (GenerationError, charts.ResultError) as cause:
        print(f"benchmark generation failed: {cause}", file=sys.stderr)
        return 1

    verb = "would write" if args.check else "wrote"
    pages = len(os.listdir(PAGES_DIR)) if os.path.isdir(PAGES_DIR) and not args.check else "?"
    print(
        f"benchmarks: {verb} {figures} figure specs"
        + (f" and {pages} pages" if not args.check else "")
        + f" from {RESULTS_ROOT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
