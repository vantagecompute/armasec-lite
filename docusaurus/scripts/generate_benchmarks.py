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
import re
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
#: order is editorial: the headline first, the second instrument on the same question next,
#: then the exact results, then the ones that need the most care.
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

#: The order a run's own page walks its scenarios in: the editorial order above, then
#: everything else the harness writes. A run page reports what one run measured, so a
#: scenario that has no hand-written section on the summary page still gets its title, its
#: question and its verdict table here rather than being dropped from the page of the only
#: run that measured it.
RUN_PAGE_ORDER = (
    *SCENARIO_ORDER,
    *(stem for stem in layout.SCENARIO_FILES if stem not in SCENARIO_ORDER),
)

ARMS = ("legacy", "lite")
LABELS = charts.ARM_LABELS
#: The same names, capitalised, for the start of a sentence. `armasec-lite` is a package
#: name and keeps its lower case everywhere, including here.
LEAD = {"legacy": "Upstream armasec", "lite": "armasec-lite"}

#: Scenarios that take one observation of one process rather than a set of repetitions.
#: Their numbers carry no spread, and a number without a spread must not be set beside
#: numbers with one and left to read as equally solid. Every page element that would
#: otherwise imply repetitions for these, the figure captions included, says otherwise.
SINGLE_OBSERVATION = ("profile_sampling", "call_graph")

#: Matches a multiplier the harness put in a verdict string, such as `137.04x`. Used to
#: find the places a bare ratio would otherwise be published.
RATIO = re.compile(r"\d+(?:\.\d+)?x\b")


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


def validate_run(run: dict[str, Any], directory: str) -> None:
    """
    Check one run against the scenario set a complete run writes, and record the gap.

    The build's own completeness check counts generated pages, so a run directory missing a
    scenario file produces a page and passes. This is the check that sees it. It does not
    fail the build: re-running one scenario after a harness correction is a supported and
    deliberate workflow, `newest_per_scenario` exists to serve it, and the committed tree is
    in exactly that state, so failing here would break the build on the repository's own
    current contents for something that is not a defect. What it does instead is set
    `missing` from the authoritative scenario list rather than from the index's bookkeeping,
    so the run page can render the gap as a gap. The case that really does leave a hole, a
    scenario absent from every run of the newest version, still fails the build in
    `load_runs`.

    Args:
        run:       A loaded run, its `documents` already attached.
        directory: The run's directory, for the error message.

    Raises:
        GenerationError: The run holds a result file that is not a known scenario, which
            means the scenario list and the harness have drifted apart and the page would
            silently omit whatever the new file holds.
    """
    recorded = set(run["documents"])
    unexpected = sorted(recorded - set(layout.SCENARIO_FILES))
    if unexpected:
        raise GenerationError(
            f"{directory} holds result files this page does not know how to present: "
            f"{', '.join(unexpected)}. Add them to bench/runs.py's SCENARIO_FILES and give "
            "them a section, or the page will publish a run while omitting part of it."
        )
    run["missing"] = [stem for stem in layout.SCENARIO_FILES if stem not in recorded]
    run["complete"] = not run["missing"]


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
            validate_run(run, directory)
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


def caption(run: dict[str, Any], stem: str | None = None) -> str:
    """
    Build the provenance caption that sits under every figure.

    The repetition count in a run's provenance block is the harness's setting, not a
    promise that every scenario used it. The profiler and call counting passes take one
    observation each, so their captions say so rather than inheriting a repetition count
    that never applied to them.

    Args:
        run:  The run the figure was built from.
        stem: The scenario the figure came from, when the caller knows it.

    Returns:
        A single line naming the host, the date, both library versions and the sample size.
    """
    block = provenance_of(run)
    when = str(block.get("timestamp_utc", "")).replace("+00:00", " UTC")
    versions = block.get("library_versions", {})
    sample = (
        "a single observation, no repetitions"
        if stem in SINGLE_OBSERVATION
        else f"{block.get('repetitions', '?')} repetitions"
    )
    return (
        f"Run {run['run_id']} on host {block.get('hostname', 'unknown')}, {when}. "
        f"{versions.get('legacy', 'upstream armasec')} against "
        f"{versions.get('lite', 'armasec-lite')}, {sample}."
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

    The one thing added to a verdict is the injected provider delay, where the verdict
    quotes a multiplier and the scenario injected one. That is not a rewording: the
    multiplier is a function of the delay, and publishing it without the delay publishes a
    parameter of this harness as though it were a characteristic of the libraries.

    Args:
        document: A parsed result file.

    Returns:
        Rows of `(measurement, verdict)`.
    """
    config = document.get("config", {})
    return [
        [f"`{name}`", annotate_injection(escape(str(text)), config)]
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


def injected_latency(config: dict[str, Any]) -> tuple[float, float | None] | None:
    """
    Read the provider delay a scenario injected, and how many fetches paid it.

    The fetch count is derived from the total cold cost the scenario recorded, and is
    `None` when the scenario did not record one. It is deliberately not defaulted: a made-up
    fetch count would turn into a made-up sentence on the page, which is the failure mode
    this whole generator exists to avoid.

    Args:
        config: A result file's `config` block.

    Returns:
        The injected delay in milliseconds and the number of fetches charged for it, or
        `None` when the scenario injected nothing.
    """
    raw = config.get("injected_provider_latency_ms")
    if raw is None:
        return None
    delay = float(raw)
    if delay <= 0:
        return None
    total = config.get("expected_cold_fetch_cost_ms")
    return delay, (float(total) / delay if total is not None else None)


def annotate_injection(rendered: str, config: dict[str, Any]) -> str:
    """
    Attach a ratio's dependency to it, inside the same cell that quotes it.

    A ratio between an arm that waits out an injected provider delay and an arm that does
    not is a function of that delay. It is not a property of either library, and the
    harness's verdict string states it bare. A bare multiplier is the number a reader
    carries away, so every place one is published it is published with the delay it was
    measured under standing next to it.

    Args:
        rendered: An already-rendered verdict, escaped and ready for the page.
        config:   The `config` block of the file the verdict came from.

    Returns:
        The verdict, with the injected delay named beside any multiplier it contains.
    """
    injection = injected_latency(config)
    if injection is None or not RATIO.search(rendered):
        return rendered
    delay, _ = injection
    return f"{rendered}, with {count(delay)} ms injected per provider fetch"


def with_injection(verdict: str, config: dict[str, Any]) -> str:
    """
    Render a verdict for prose, with any multiplier's dependency attached.

    Args:
        verdict: A verdict string from a result file.
        config:  The same file's `config` block.

    Returns:
        A phrase suitable for a table cell or the middle of a sentence.
    """
    return annotate_injection(compare_phrase(verdict), config)


def scaling_note(config: dict[str, Any], legacy_worst: float, lite_worst: float) -> str:
    """
    Say, in the reader's line of sight, that the headline ratio is a dial and not a finding.

    The upstream arm's worst case tracks the injected delay because it waits for the whole
    cold fetch; the armasec-lite arm's does not move with it at all. So the ratio between
    them is close to linear in a parameter this harness picked. The two extrapolations
    below are computed from this run's own measured values under exactly that model, and
    the sentence says they are extrapolations rather than presenting them as measurements.

    Args:
        config:       The S4 `config` block.
        legacy_worst: The upstream arm's measured worst `/health` latency, in milliseconds.
        lite_worst:   The armasec-lite arm's measured worst `/health` latency.

    Returns:
        Markdown for the paragraph that follows the headline comparison.
    """
    injection = injected_latency(config)
    if injection is None or lite_worst <= 0:
        return ""
    delay, fetches = injection
    if fetches is None:
        return (
            "**The ratio between those two numbers is not a property of either library.** "
            f"The upstream arm waits out the {count(delay)} ms this harness injects at the "
            "provider and the armasec-lite arm does not, so the multiple is a function of "
            "that injected delay and scales with it. It would be a different number against "
            "a provider with different latency, with neither library behaving any "
            "differently."
        )

    # What upstream's worst case would be at a different injected delay, holding everything
    # this run measured fixed except the delay itself.
    fixed = legacy_worst - fetches * delay

    def projected(candidate: float) -> str:
        return f"{(fixed + fetches * candidate) / lite_worst:,.0f}x"

    lower = delay / 5.0
    upper = delay * 4.0
    return f"""**The ratio between those two numbers is not a property of either library.** It is the
relationship above divided by a delay this harness chose: {count(delay)} ms held back per
provider fetch across {count(fetches)} fetch{"" if fetches == 1 else "es"}, so {
        count(float(config["expected_cold_fetch_cost_ms"]))
    } ms of
deliberately injected waiting. The numerator scales with that delay and the denominator does
not, so the multiple scales with it too. Extrapolating this run's own numbers linearly in the
injected delay, the same measurement would report roughly {projected(lower)} at {count(lower)} ms
per fetch and roughly {projected(upper)} at {count(upper)} ms per fetch, with neither library
behaving any differently. A reader quoting the multiple is quoting the harness's dial. The
invariant in the paragraph above is the part that survives a change of provider."""


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
                    with_injection(verdicts.get("worst_health_latency", ""), config),
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
**The invariant is the finding.** Under {LABELS["legacy"]}, the worst request to a route with
no authentication on it waited {ms(float(worst["legacy"]["median"]))}, against the {
        count(float(config["expected_cold_fetch_cost_ms"]))
    } ms
the {
        count(
            float(config["expected_cold_fetch_cost_ms"])
            / float(config["injected_provider_latency_ms"])
        )
    } injected
provider round trips were expected to cost. Upstream's worst case on an unrelated,
unauthenticated route is approximately the full cold OIDC fetch cost, so it inherits whatever
latency the identity provider happens to have. Under {LABELS["lite"]} the same request waited
{ms(float(worst["lite"]["median"]))}, which is its baseline: it does not move with the provider
at all. The cold work is the same work in both arms; the difference is which thread it runs
on, and that difference is what transfers to another provider and another machine.

{scaling_note(config, float(worst["legacy"]["median"]), float(worst["lite"]["median"]))}

<PlotlyChart
  src="{run["chart_url"]}/s4-health-latency.json"
  alt="Bar chart of /health latency percentiles for both libraries during a cold token validation, on a logarithmic scale"
  provenance="{caption(run, "s4_event_loop_blocking")}"
/>

<PlotlyChart
  src="{run["chart_url"]}/s4-slow-health-requests.json"
  alt="Bar chart of the number of /health requests slower than 100 ms per repetition"
  provenance="{caption(run, "s4_event_loop_blocking")}"
/>
"""


def section_profile(run: dict[str, Any]) -> str:
    """
    Write the sampling profiler section: the same question, asked with a second instrument.

    The two instruments are independent methods and not independent experiments, and this
    section says so. They ran in one harness, on one machine, in one process, from one run,
    so a common-mode error in the harness would move both together. The section also states
    that this pass carries no repetitions, because its headline count is the most quotable
    number on the page and sits beside numbers that do have a spread.

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

:::caution[This pass is a single observation]

Unlike every scenario with a repetition range beside it, the profiler pass ran once, on one
process, and carries no repetitions and therefore no spread. The
{count(float(legacy["loop_thread_samples_in_blocking_http_client"]))} loop-thread samples against
{count(float(lite["loop_thread_samples_in_blocking_http_client"]))} is the most quotable figure on
this page and it has the least statistical support behind it. Read the counts below as a
description of where the work runs, not as a statistic. Nothing here says how much these
counts would move on a second run, because there was no second run.

:::

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

Two different measurement techniques, a latency measurement taken from outside the process
and a stack sample taken from inside it, give the same answer. They are independent
**methods**. They are not independent **experiments**: both were taken in the same harness,
on the same machine, against the same workload, in the same process, so a common-mode error
in the harness would move both together and their agreement would not reveal it. This is not
corroboration by an independent party, and it is not two chances at being wrong reduced to
one. It is two instruments on one bench agreeing, which is the strongest evidence on this
page and still evidence of exactly that kind.

<PlotlyChart
  src="{run["chart_url"]}/profile-loop-samples.json"
  alt="Stacked bar chart of event loop thread samples split into idle, busy, and inside a blocking HTTP client"
  provenance="{caption(run, "profile_sampling")}"
/>

<PlotlyChart
  src="{run["chart_url"]}/profile-worst-health.json"
  alt="Bar chart comparing the worst health latency against the cold authenticated request latency for both libraries"
  provenance="{caption(run, "profile_sampling")}"
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
  provenance="{caption(run, "call_graph")}"
/>

<PlotlyChart
  src="{run["chart_url"]}/call-graph-static.json"
  alt="Bar chart of statically defined functions, internal call sites, reachable functions and warm call depth"
  provenance="{caption(run, "call_graph")}"
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
    Write one run's own page: what it measured, on what machine, and with what result.

    The host is named in the title, in the first line of prose and in the sidebar, not only
    in the provenance table. Every number on the page is a property of that machine as much
    as of the libraries, the run directory does not have to carry the hostname, and two runs
    disagreeing because they ran on different machines is a thing a reader should be able to
    notice without reading a table.

    A run that recorded only some of the scenarios says so in a banner and in a table
    covering all of them, so a partial run is visibly partial rather than merely shorter
    than the others.

    Args:
        run:      A loaded run.
        position: Its sidebar position.

    Returns:
        The page body, for the caller to write out.
    """
    block = provenance_of(run)
    host = str(block.get("hostname", "an unknown host"))
    when = str(block.get("timestamp_utc", "an unrecorded time")).replace("+00:00", " UTC")
    parts = [
        "---",
        f'title: "{run["run_id"]} on {host}"',
        f'sidebar_label: "v{run["version"]} {run["run_id"]} ({host})"',
        f"sidebar_position: {position}",
        (f"description: One comparison run of armasec-lite {run['version']}, measured on {host}."),
        "---",
        "",
        HEADER_IMPORT,
        f"# Run `{run['run_id']}` on `{escape(host)}`",
        "",
        (
            f"One comparison run of **armasec-lite {run['version']}** against upstream armasec, "
            f"measured on **`{escape(host)}`** at {escape(when)}. "
            "Generated from this run's result files; nothing on this page was written by hand."
        ),
        "",
        (
            "**Every number below is a property of that machine as much as of the two "
            "libraries.** Two runs can disagree because they ran on different hosts and for "
            "no other reason, so check the host before setting this run against another one. "
            "The run identifier is a timestamp and carries no machine name; this line and the "
            "table below are where the machine is recorded.\n"
        ),
        provenance_table(run),
    ]

    if run["missing"]:
        parts.append(
            ":::warning[This run is partial]\n\n"
            f"It recorded {len(run['scenarios'])} of the {len(layout.SCENARIO_FILES)} scenarios "
            "a complete run writes. The absent ones were not measured on this host at this "
            "time, so this page carries no result for them and neither does any comparison "
            "drawn against this run. The [summary](./index.mdx) takes each scenario from the "
            "most recent run of this version that measured it, which for the scenarios absent "
            "here is a different run, possibly on a different machine.\n\n"
            ":::\n"
        )
    else:
        parts.append(
            f"This run recorded all {len(layout.SCENARIO_FILES)} scenarios a complete run writes.\n"
        )

    parts.append(
        table(
            ["Scenario", "Recorded by this run"],
            [
                [
                    f"`{stem}`",
                    "yes" if stem in run["documents"] else "**no, not measured in this run**",
                ]
                for stem in layout.SCENARIO_FILES
            ],
        )
    )

    for stem in RUN_PAGE_ORDER:
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
        if stem in SINGLE_OBSERVATION:
            parts.append(
                "**One observation, no repetitions.** This scenario measures a single "
                "process once, so its numbers carry no range and nothing here says how far "
                "they would move on a second run.\n"
            )
        injection = injected_latency(document.get("config", {}))
        if injection is not None:
            delay, fetches = injection
            charged = (
                ""
                if fetches is None
                else f", charged {count(fetches)} time{'' if fetches == 1 else 's'}"
            )
            parts.append(
                f"**This scenario injects latency at the provider:** {count(delay)} ms held "
                f"back per fetch{charged}. Any latency or multiplier below that reflects a "
                "cold fetch is a function of that injected delay and scales with it. It "
                "describes this harness setting as much as it describes either library, and "
                "it would be a different number against a provider with different latency.\n"
            )
        if rows:
            parts.append(
                "Verdicts as the harness recorded them, reworded nowhere.\n"
                if stem in SINGLE_OBSERVATION
                else (
                    "Verdicts as the harness recorded them. The test is a non-parametric "
                    "comparison of the observed repetition ranges, which errs toward calling "
                    "a difference noise.\n"
                )
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
                f'  provenance="{caption(run, stem)}"\n/>\n'
            )

    parts.append("## The raw files\n")
    parts.append(
        "Every number above comes from "
        f"`legacy_comparison_compose/results/v{run['version']}/{run['run_id']}/`, which is "
        "committed to the repository. The page is regenerated from those files on every "
        "documentation build and is not committed itself. The directory name is an opaque "
        "run identifier: the version, the timestamp and the host all come from the "
        f"provenance block inside the files, which is why this page can say `{escape(host)}` "
        "whatever the directory happens to be called.\n"
    )
    return "\n".join(parts)


def trend_section(index: dict[str, Any], figures: dict[str, dict[str, Any]]) -> str:
    """
    Write the section that compares runs against each other, when there is one to write.

    The full section describes two kinds of comparison and carries the charts that make
    them. Neither exists until some scenario has been measured twice, so until then the
    section is a single paragraph saying it is empty rather than a description of a
    capability the reader cannot exercise. A page that explains a feature nobody can use
    reads as a page hiding how little data it has.

    Args:
        index:   The loaded index.
        figures: The trend figures that could be built, possibly none.

    Returns:
        Markdown for the section, or for its absence.
    """
    total = index["run_count"]
    versions = index["version_count"]
    runs_phrase = f"{total} run{'s' if total != 1 else ''}"
    versions_phrase = f"{versions} version{'s' if versions != 1 else ''}"

    if not figures:
        repeated = [
            stem
            for stem in layout.SCENARIO_FILES
            if sum(
                1
                for version in index["versions"]
                for run in version["runs"]
                if stem in run["scenarios"]
            )
            > 1
        ]
        also = (
            (
                " The scenarios measured by more than one run ("
                + ", ".join(f"`{stem}`" for stem in repeated)
                + ") record nothing this page tracks across runs, so they add no comparison "
                "either."
            )
            if repeated
            else ""
        )
        return f"""## Comparing runs against each other

**There is nothing to compare yet, and this section is empty until there is.** The results
tree holds {runs_phrase} across {versions_phrase}, and no measurement on this page has been
taken by two runs that a reader could set against each other.{also}

Every run is kept, so this section will fill in on its own the first time a scenario is
measured twice, and it will describe what those comparisons show at that point rather than
before. Until then, treat every number above as one measurement on one machine, with only
its own repetition range to say how far it would move.
"""

    lead = f"""## Comparing runs against each other

Every run is kept, so this page can show change rather than only a snapshot. The two kinds
of comparison answer different questions. Two runs of the **same** version differ only by
machine and by noise, which is how far a single number here should be trusted. Two runs of
**different** versions differ by what changed in the library, which is how a regression we
introduced ourselves becomes visible.

There {"are" if total != 1 else "is"} {runs_phrase} committed, across {versions_phrase}.
"""
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
    partial = 0
    for version in index["versions"]:
        for run in version["runs"]:
            block = provenance_of(run)
            total = len(layout.SCENARIO_FILES)
            coverage = f"{len(run['scenarios'])} of {total}"
            if run["missing"]:
                partial += 1
                coverage = f"**{coverage}, partial**"
            tree_rows.append(
                [
                    f"`{version['version']}`",
                    f"[`{run['run_id']}`](./{run['page_id']}.mdx)",
                    escape(str(block.get("timestamp_utc", "")).replace("+00:00", " UTC")),
                    f"`{escape(str(block.get('hostname', '?')))}`",
                    coverage,
                ]
            )

    if partial == len(tree_rows):
        how_many = "Every run above" if partial > 1 else "That run"
    else:
        how_many = f"{partial} of those {len(tree_rows)} runs"
    partial_note = (
        (
            f"\n{how_many} recorded only some of the "
            f"{len(layout.SCENARIO_FILES)} scenarios a complete run writes, which is marked "
            "above and stated again on the run's own page. A partial run is normal: a single "
            "scenario is sometimes re-run on its own after a harness correction. It matters "
            "because a scenario absent from a run is absent from any comparison drawn against "
            "that run.\n"
        )
        if partial
        else ""
    )

    host_note = (
        ""
        if len(hosts) == 1
        else (
            "\nThe scenarios below were not all measured on the same machine. Two of these "
            "numbers can differ because their runs used different hosts and for no other "
            "reason, so the table above and each run page name the host.\n"
        )
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
  not transfer to your hardware.
- **Not every ratio transfers either.** Where a scenario injects a delay at the identity
  provider, the ratio between the two arms is a function of the delay this harness chose,
  and it is published with that delay named beside it every place it appears. What transfers
  is the described relationship between each arm and the work: which thread it runs on,
  whether the rest of the process waits for it, how many fetches it costs. Read those, not
  the multipliers.
- **Every repeated measurement appears with the range its repetitions covered.** Where those
  ranges overlap, the harness calls the difference noise and this page says "within noise"
  instead of quoting a ratio. That test is deliberately blunt: {provenance_of(lead_run).get("repetitions", "?")}
  repetitions cannot support anything finer.
- **Counts are exact where they are exact.** The OIDC fetch counts in S2 and the JWKS fetch
  counts in S8 were taken at a proxy and repeated identically every time. They carry no
  spread because there was none.
- **Some measurements have no repetitions at all.** The profiler pass and the call counting
  pass each observe one process once. They are labelled where they appear, and a count with
  no spread should not be read as firmly as one with a range beside it, however quotable it
  is.
- **Nothing here is hand-entered.** This page is generated from the JSON files under
  `legacy_comparison_compose/results/`, which are committed. If a number is on this page it
  is in one of those files. A scenario with no measurement in any run of this version fails
  the documentation build rather than quietly dropping a section, and a run that measured
  only some of them is marked partial here and on its own page.

## What was measured, and when

Results are stored one directory per run, under one directory per armasec-lite version, and
every run is kept. The directory name is an opaque run identifier. The version, the
timestamp and the host all come from the run's own provenance block rather than from the
directory name or the working tree, which is why the host has a column of its own here and a
line at the top of every run page.

{table(["Version", "Run", "Measured at", "Host", "Scenarios"], tree_rows)}{partial_note}
The summary below presents **armasec-lite {newest["version"]}**, taking each scenario from the most
recent run of that version which measured it:

{sources}{host_note}""",
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
- **A latency multiple you can quote.** The S4 ratio between the two arms is the second
  easiest thing here to overread. It is a function of the provider delay this harness
  injected, it scales with that delay, and it would be a different number on a provider with
  different latency. The transferable finding in S4 is that upstream's worst case on an
  unauthenticated route tracks the full cold fetch cost while armasec-lite's stays at its
  baseline. That is the sentence to carry away, not the multiplier.
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

Each run writes into `legacy_comparison_compose/results/v<version>/<run id>/` and rebuilds
`results/index.json` from the whole tree. Nothing is overwritten, and every run is meant to
be committed, so that the next person to read this page can see whether the numbers moved.
The run id is a timestamp and nothing else has to be read out of it: these pages take the
version, the date and the host from each run's provenance block. Regenerating these pages
and their figures from the committed files, without running anything:

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
