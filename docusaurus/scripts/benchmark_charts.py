"""
Plotly figure specs, built from the committed comparison result files and from nothing else.

Every builder in this module reads a parsed result document and returns a `{"data": ...,
"layout": ...}` figure. There is no fallback path, no default value and no placeholder: a
missing key raises, because a benchmark chart that silently substitutes a zero is a lie with
a legend on it. `require` is the only accessor used.

Two conversions happen here and they are the only arithmetic performed on a measured value:
bytes are divided by 1024 twice to be shown as MiB, and the min and max across repetitions
are turned into the offsets Plotly wants for an error bar. Both are unit changes. No ratio,
average or rescaling is computed for a chart; where the page states a ratio it comes from
the verdict string the harness itself recorded.

Series colors carry meaning and are fixed across every figure: upstream armasec is blue,
armasec-lite is orange. Only the chrome follows the site theme, in `PlotlyChart`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

#: Upstream armasec. Fixed across every figure on the site.
LEGACY_COLOR = "#4c78a8"
#: armasec-lite. Fixed across every figure on the site.
LITE_COLOR = "#f58518"

#: How each arm is named in prose and in a legend. The result files key them `legacy` and
#: `lite`, which is an implementation detail no reader should have to learn.
ARM_LABELS = {"legacy": "upstream armasec", "lite": "armasec-lite"}
ARM_COLORS = {"legacy": LEGACY_COLOR, "lite": LITE_COLOR}
ARMS = ("legacy", "lite")


class ResultError(RuntimeError):
    """A result file is missing something a figure needs, or holds something unusable."""


def require(document: Any, *path: str, source: str = "result file") -> Any:
    """
    Follow a path of keys, failing loudly rather than defaulting.

    Args:
        document: The parsed result document, or any node within it.
        path:     Keys to follow, in order.
        source:   What to name in the error, usually the file path.

    Returns:
        The value at the end of the path.

    Raises:
        ResultError: Any step of the path is absent, or a step is not a mapping.
    """
    node = document
    walked: list[str] = []
    for key in path:
        if not isinstance(node, dict):
            raise ResultError(f"{source}: {'.'.join(walked) or '<root>'} is not an object")
        if key not in node:
            raise ResultError(
                f"{source}: missing {'.'.join([*walked, key])}, so the figure that needs it "
                "cannot be built"
            )
        node = node[key]
        walked.append(key)
    if node is None:
        raise ResultError(f"{source}: {'.'.join(walked)} is null")
    return node


def mib(value: float) -> float:
    """
    Convert bytes to mebibytes.

    Args:
        value: A byte count from a result file.

    Returns:
        The same quantity in MiB.
    """
    return value / 1024.0 / 1024.0


def _spread(block: dict[str, Any]) -> tuple[float, float]:
    """
    Turn an `across_reps` block into the two offsets Plotly wants for an error bar.

    Args:
        block: A block carrying `median`, `min` and `max`.

    Returns:
        The distance up to the maximum and the distance down to the minimum.
    """
    median = float(block["median"])
    return max(0.0, float(block["max"]) - median), max(0.0, median - float(block["min"]))


def _bars_with_spread(
    document: dict[str, Any],
    source: str,
    categories: Iterable[tuple[str, tuple[str, ...]]],
) -> list[dict[str, Any]]:
    """
    Build one grouped bar trace per arm, with error bars taken from the repetition range.

    Args:
        document:   The parsed result file.
        source:     The file path, for error messages.
        categories: `(label, key path)` pairs; the path ends just above the arm name.

    Returns:
        Two Plotly bar traces, upstream first.
    """
    labels = [label for label, _ in categories]
    traces: list[dict[str, Any]] = []
    for arm in ARMS:
        values: list[float] = []
        plus: list[float] = []
        minus: list[float] = []
        for _, path in categories:
            block = require(document, *path, arm, source=source)
            values.append(float(require(block, "median", source=source)))
            up, down = _spread(block)
            plus.append(up)
            minus.append(down)
        traces.append(
            {
                "type": "bar",
                "name": ARM_LABELS[arm],
                "x": labels,
                "y": values,
                "marker": {"color": ARM_COLORS[arm]},
                "error_y": {
                    "type": "data",
                    "symmetric": False,
                    "array": plus,
                    "arrayminus": minus,
                    "color": ARM_COLORS[arm],
                    "thickness": 1.4,
                    "width": 5,
                },
            }
        )
    return traces


def _plain_bars(
    labels: list[str], per_arm: dict[str, list[float]], suffix: str = ""
) -> list[dict[str, Any]]:
    """
    Build one grouped bar trace per arm from values that carry no repetition spread.

    Args:
        labels:  The category labels.
        per_arm: Values per arm, in the same order as `labels`.
        suffix:  Unit suffix for the hover template, for example `" MiB"`.

    Returns:
        Two Plotly bar traces, upstream first.
    """
    return [
        {
            "type": "bar",
            "name": ARM_LABELS[arm],
            "x": labels,
            "y": per_arm[arm],
            "marker": {"color": ARM_COLORS[arm]},
            "hovertemplate": f"%{{x}}<br>%{{y}}{suffix}<extra>{ARM_LABELS[arm]}</extra>",
        }
        for arm in ARMS
    ]


# --------------------------------------------------------------------------------------
# S4 and the profiler: the headline, measured two independent ways
# --------------------------------------------------------------------------------------


def s4_health_latency(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Latency of the unauthenticated `/health` route while a cold token validation runs.

    Args:
        document: The parsed `s4_event_loop_blocking.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure on a log axis, since the two arms differ by orders of
        magnitude and a linear axis would render one of them as a flat line.
    """
    categories = [
        ("baseline p50", ("measurements", "health_baseline_p50_ms")),
        ("p99 during cold load", ("measurements", "health_p99_during_cold_load_ms")),
        ("worst observed", ("measurements", "worst_health_latency_ms")),
    ]
    return {
        "data": _bars_with_spread(document, source, categories),
        "layout": {
            "title": "S4: /health latency during a cold token validation",
            "barmode": "group",
            "yaxis": {"title": "milliseconds (log scale)", "type": "log"},
            "xaxis": {"title": ""},
        },
    }


def s4_slow_health_requests(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    How many `/health` requests took longer than 100 ms during the cold load.

    Args:
        document: The parsed `s4_event_loop_blocking.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure on a linear axis; one arm's median is zero, which a log axis
        cannot show.
    """
    return {
        "data": _bars_with_spread(
            document,
            source,
            [("requests over 100 ms", ("measurements", "health_requests_over_100ms"))],
        ),
        "layout": {
            "title": "S4: /health requests slower than 100 ms per repetition",
            "barmode": "group",
            "yaxis": {"title": "requests", "rangemode": "tozero"},
            "xaxis": {"title": ""},
        },
    }


def profile_loop_samples(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Where each arm's event loop thread was, sampled every 5 ms through the same workload.

    Args:
        document: The parsed `profile_sampling.json`.
        source:   The file path, for error messages.

    Returns:
        A stacked bar figure splitting loop-thread samples into idle, busy elsewhere, and
        inside a blocking HTTP client.
    """
    blocking = [
        float(
            require(
                document,
                "measurements",
                arm,
                "loop_thread_samples_in_blocking_http_client",
                source=source,
            )
        )
        for arm in ARMS
    ]
    idle = [
        float(
            require(
                document,
                "measurements",
                arm,
                "loop_thread_samples_idle_in_selector",
                source=source,
            )
        )
        for arm in ARMS
    ]
    busy = [
        float(require(document, "measurements", arm, "loop_thread_samples_busy", source=source))
        - blocked
        for arm, blocked in zip(ARMS, blocking)
    ]
    labels = [ARM_LABELS[arm] for arm in ARMS]
    return {
        "data": [
            {
                "type": "bar",
                "name": "idle in the selector",
                "x": labels,
                "y": idle,
                "marker": {"color": "#9ecae9"},
            },
            {
                "type": "bar",
                "name": "busy, not in an HTTP client",
                "x": labels,
                "y": busy,
                "marker": {"color": "#8c8c8c"},
            },
            {
                "type": "bar",
                "name": "inside a blocking HTTP client",
                "x": labels,
                "y": blocking,
                "marker": {"color": "#d62728"},
            },
        ],
        "layout": {
            "title": "Event loop thread samples, 5 ms interval, during the same cold load",
            "barmode": "stack",
            "yaxis": {"title": "samples", "rangemode": "tozero"},
            "xaxis": {"title": ""},
        },
    }


def profile_worst_health(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    The worst `/health` latency observed during the profiled pass.

    This is the same quantity S4 measures, taken from a separate pass with the sampling
    profiler running. Two independent methods on the same question is the point of showing
    it.

    Args:
        document: The parsed `profile_sampling.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure on a log axis.
    """
    labels = ["worst /health", "cold authenticated request"]
    per_arm = {
        arm: [
            float(require(document, "measurements", arm, "worst_health_ms", source=source)),
            float(require(document, "measurements", arm, "cold_auth_request_ms", source=source)),
        ]
        for arm in ARMS
    }
    return {
        "data": _plain_bars(labels, per_arm, " ms"),
        "layout": {
            "title": "Profiled pass: worst /health latency against the cold request itself",
            "barmode": "group",
            "yaxis": {"title": "milliseconds (log scale)", "type": "log"},
            "xaxis": {"title": ""},
        },
    }


# --------------------------------------------------------------------------------------
# S2, S1, S3, S8
# --------------------------------------------------------------------------------------


def s2_oidc_fetches(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Outbound OIDC requests against the number of distinct `lockdown()` scope sets.

    Args:
        document: The parsed `s2_request_amplification.json`.
        source:   The file path, for error messages.

    Returns:
        A line figure, one trace per arm, counted at the proxy.
    """
    counts = sorted(
        int(name.removeprefix("scope_sets_"))
        for name in require(document, "measurements", source=source)
        if name.startswith("scope_sets_")
    )
    traces = []
    for arm in ARMS:
        traces.append(
            {
                "type": "scatter",
                "mode": "lines+markers",
                "name": ARM_LABELS[arm],
                "x": counts,
                "y": [
                    float(
                        require(
                            document,
                            "measurements",
                            f"scope_sets_{count}",
                            "total_oidc",
                            arm,
                            "median",
                            source=source,
                        )
                    )
                    for count in counts
                ],
                "line": {"color": ARM_COLORS[arm], "width": 2.5},
                "marker": {"color": ARM_COLORS[arm], "size": 8},
            }
        )
    return {
        "data": traces,
        "layout": {
            "title": "S2: OIDC fetches per distinct lockdown() scope set",
            "yaxis": {"title": "outbound OIDC requests", "rangemode": "tozero"},
            "xaxis": {"title": "distinct scope sets protected by the application"},
        },
    }


def s1_cold_start(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Time to the first authenticated response after a container restart.

    Args:
        document: The parsed `s1_cold_start.json`.
        source:   The file path, for error messages.

    Returns:
        A line figure over the concurrency levels the scenario swept.
    """
    levels = sorted(
        int(name.removeprefix("concurrency_"))
        for name in require(document, "measurements", source=source)
        if name.startswith("concurrency_")
    )
    traces = []
    for arm in ARMS:
        medians: list[float] = []
        plus: list[float] = []
        minus: list[float] = []
        for level in levels:
            block = require(
                document,
                "measurements",
                f"concurrency_{level}",
                "first_response_ms",
                arm,
                source=source,
            )
            medians.append(float(require(block, "median", source=source)))
            up, down = _spread(block)
            plus.append(up)
            minus.append(down)
        traces.append(
            {
                "type": "scatter",
                "mode": "lines+markers",
                "name": ARM_LABELS[arm],
                "x": levels,
                "y": medians,
                "line": {"color": ARM_COLORS[arm], "width": 2.5},
                "marker": {"color": ARM_COLORS[arm], "size": 7},
                "error_y": {
                    "type": "data",
                    "symmetric": False,
                    "array": plus,
                    "arrayminus": minus,
                    "color": ARM_COLORS[arm],
                    "thickness": 1.2,
                    "width": 4,
                },
            }
        )
    return {
        "data": traces,
        "layout": {
            "title": "S1: time to first authenticated response after a restart",
            "yaxis": {"title": "milliseconds", "rangemode": "tozero"},
            "xaxis": {"title": "concurrent first requests", "type": "log", "dtick": 0.30103},
        },
    }


#: An arm counts as having stopped keeping up when the rate it actually served falls this
#: far short of the rate offered, as a percentage. Above this the latency it reports is
#: queueing delay rather than service time, and the two must not be compared as though they
#: measured the same thing.
SATURATION_SHORTFALL_PCT = 0.25


def saturation(document: dict[str, Any], source: str) -> dict[float, list[str]]:
    """
    Find, per offered rate, which arms failed to serve it.

    Args:
        document: The parsed `s3_warm_flood.json`.
        source:   The file path, for error messages.

    Returns:
        The arms that fell short, keyed by the offered rate. Rates where both arms kept up
        are absent.
    """
    measurements = require(document, "measurements", source=source)
    rates = sorted(
        float(name.removeprefix("target_").removesuffix("_rps"))
        for name in measurements
        if name.startswith("target_")
    )
    found: dict[float, list[str]] = {}
    for rate in rates:
        short = []
        for arm in ARMS:
            achieved = float(
                require(
                    document,
                    "measurements",
                    f"target_{rate:g}_rps",
                    "achieved_rps",
                    arm,
                    "median",
                    source=source,
                )
            )
            if (rate - achieved) / rate * 100.0 > SATURATION_SHORTFALL_PCT:
                short.append(arm)
        if short:
            found[rate] = short
    return found


def s3_latency(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Warm-path latency percentiles against the offered request rate.

    Any rate at which an arm stopped serving the offered load is annotated on the figure.
    Latency measured on one side of a saturation boundary and latency measured on the other
    are not the same quantity, and a chart that does not say so invites the wrong reading.

    Args:
        document: The parsed `s3_warm_flood.json`.
        source:   The file path, for error messages.

    Returns:
        A figure with a solid p50 line and a dashed p99 line per arm, on a log latency axis.
    """
    rates = sorted(
        float(name.removeprefix("target_").removesuffix("_rps"))
        for name in require(document, "measurements", source=source)
        if name.startswith("target_")
    )
    traces = []
    for percentile, dash in (("p50_ms", "solid"), ("p99_ms", "dot")):
        for arm in ARMS:
            traces.append(
                {
                    "type": "scatter",
                    "mode": "lines+markers",
                    "name": f"{ARM_LABELS[arm]} {percentile.removesuffix('_ms')}",
                    "x": rates,
                    "y": [
                        float(
                            require(
                                document,
                                "measurements",
                                f"target_{rate:g}_rps",
                                percentile,
                                arm,
                                "median",
                                source=source,
                            )
                        )
                        for rate in rates
                    ],
                    "line": {"color": ARM_COLORS[arm], "width": 2.5, "dash": dash},
                    "marker": {"color": ARM_COLORS[arm], "size": 7},
                }
            )
    annotations = []
    shapes = []
    for rate, arms in saturation(document, source).items():
        annotations.append(
            {
                "x": rate,
                "y": 1.06,
                "xref": "x",
                "yref": "paper",
                "text": ", ".join(ARM_LABELS[arm] for arm in arms) + " saturated",
                "showarrow": False,
                "xanchor": "right",
                "xshift": -6,
                "font": {"size": 11, "color": "#d62728"},
            }
        )
        shapes.append(
            {
                "type": "line",
                "x0": rate,
                "x1": rate,
                "y0": 0,
                "y1": 1,
                "yref": "paper",
                "line": {"color": "#d62728", "width": 1, "dash": "dot"},
            }
        )

    return {
        "data": traces,
        "layout": {
            "title": "S3: warm authenticated latency against offered rate",
            "yaxis": {"title": "milliseconds (log scale)", "type": "log"},
            "xaxis": {"title": "offered requests per second"},
            "annotations": annotations,
            "shapes": shapes,
            "margin": {"t": 62},
        },
    }


def s3_achieved_rate(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    The rate each arm actually served against the rate the generator offered.

    Args:
        document: The parsed `s3_warm_flood.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure with the offered rate drawn as a reference line.
    """
    rates = sorted(
        float(name.removeprefix("target_").removesuffix("_rps"))
        for name in require(document, "measurements", source=source)
        if name.startswith("target_")
    )
    labels = [f"{rate:g} rps offered" for rate in rates]
    traces = _bars_with_spread(
        document,
        source,
        [
            (label, ("measurements", f"target_{rate:g}_rps", "achieved_rps"))
            for label, rate in zip(labels, rates)
        ],
    )
    traces.append(
        {
            "type": "scatter",
            "mode": "lines+markers",
            "name": "offered rate",
            "x": labels,
            "y": rates,
            "line": {"color": "#8c8c8c", "width": 1.5, "dash": "dot"},
            "marker": {"color": "#8c8c8c", "size": 6},
        }
    )
    return {
        "data": traces,
        "layout": {
            "title": "S3: achieved rate against offered rate",
            "barmode": "group",
            "yaxis": {"title": "requests per second served", "rangemode": "tozero"},
            "xaxis": {"title": ""},
        },
    }


def s8_jwks_fetches(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Outbound JWKS fetches while the provider is failing and every key id is unknown.

    Args:
        document: The parsed `s8_failing_provider.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure with the unbounded case drawn as a reference line, so the
        reader can see that neither arm is anywhere near it.
    """
    requests = float(
        require(document, "config", "unknown_kid_requests_per_repetition", source=source)
    )
    traces = _bars_with_spread(
        document,
        source,
        [("JWKS fetches", ("measurements", "jwks_fetches_during_flood"))],
    )
    traces.append(
        {
            "type": "scatter",
            "mode": "lines",
            "name": f"one fetch per request ({requests:g})",
            "x": ["JWKS fetches"],
            "y": [requests],
            "line": {"color": "#8c8c8c", "width": 1.5, "dash": "dot"},
        }
    )
    return {
        "data": traces,
        "layout": {
            "title": f"S8: JWKS fetches for {requests:g} attacker-chosen unknown key ids",
            "barmode": "group",
            "yaxis": {"title": "outbound JWKS requests", "rangemode": "tozero"},
            "xaxis": {"title": ""},
        },
    }


# --------------------------------------------------------------------------------------
# Footprint, memory and call counts
# --------------------------------------------------------------------------------------


def memory_resident(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Resident memory of each application container, read from the Docker daemon.

    Args:
        document: The parsed `memory.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure in MiB, idle and warm.
    """
    labels = ["idle", "warm, after 200 requests"]
    per_arm = {
        arm: [
            mib(float(require(document, "measurements", arm, phase, "usage_bytes", source=source)))
            for phase in ("baseline_idle", "warm")
        ]
        for arm in ARMS
    }
    return {
        "data": _plain_bars(labels, per_arm, " MiB"),
        "layout": {
            "title": "Container resident memory",
            "barmode": "group",
            "yaxis": {"title": "MiB", "rangemode": "tozero"},
            "xaxis": {"title": ""},
        },
    }


def memory_import_cost(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    How many modules importing each library pulls into a fresh interpreter.

    Modules only. An earlier version of this figure put modules on a left axis and the
    resident memory the import costs on a right axis, which drew two bars of similar height
    from two unrelated scales and invited the reader to compare them. The resident figure
    is in the table beside this chart, in MiB, where it cannot be misread as a proportion.

    Args:
        document: The parsed `memory.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure of modules added by the import.
    """
    modules = {
        arm: [
            float(
                require(
                    document, "measurements", arm, "import_cost", "modules_added", source=source
                )
            )
        ]
        for arm in ARMS
    }
    return {
        "data": _plain_bars(["modules imported by the library"], modules, " modules"),
        "layout": {
            "title": "Modules the library imports into a fresh interpreter",
            "barmode": "group",
            "yaxis": {"title": "modules", "rangemode": "tozero"},
            "xaxis": {"title": ""},
        },
    }


def footprint_distributions(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Installed distributions inside each application container.

    Args:
        document: The parsed `footprint.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure of the total and of the total less shared harness overhead.
    """
    labels = ["installed distributions", "excluding shared harness overhead"]
    per_arm = {
        arm: [
            float(require(document, "measurements", arm, field, source=source))
            for field in (
                "distribution_count",
                "distribution_count_excluding_harness_overhead",
            )
        ]
        for arm in ARMS
    }
    return {
        "data": _plain_bars(labels, per_arm),
        "layout": {
            "title": "Distributions installed in the application container",
            "barmode": "group",
            "yaxis": {"title": "distributions", "rangemode": "tozero"},
            "xaxis": {"title": ""},
        },
    }


def call_graph_warm(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Python-level calls made while serving one warm authenticated request.

    Args:
        document: The parsed `call_graph.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure of total calls and of the calls attributable to each library.
    """
    fields = [
        ("all calls", "warm_total_calls"),
        ("auth library", "warm_calls_auth_library"),
        ("JWT layer", "warm_calls_jwt_layer"),
        ("auth library and JWT layer", "warm_calls_library_and_jwt"),
        ("framework", "warm_calls_framework"),
    ]
    per_arm = {
        arm: [
            float(require(document, "measurements", arm, field, source=source))
            for _, field in fields
        ]
        for arm in ARMS
    }
    return {
        "data": _plain_bars([label for label, _ in fields], per_arm, " calls"),
        "layout": {
            "title": "Calls made while serving one warm authenticated request",
            "barmode": "group",
            "yaxis": {"title": "calls (log scale)", "type": "log"},
            "xaxis": {"title": ""},
        },
    }


def call_graph_static(document: dict[str, Any], source: str) -> dict[str, Any]:
    """
    Static surface of each library, and the call depth reached at run time.

    `reachable_from_call` is the count armasec-lite is higher on, and it is charted beside
    the counts it is lower on rather than tucked somewhere the reader will not look.

    Args:
        document: The parsed `call_graph.json`.
        source:   The file path, for error messages.

    Returns:
        A grouped bar figure of the static counts and the warm call depth.
    """
    fields = [
        ("functions defined", ("static", "functions_defined")),
        ("internal call sites", ("static", "internal_call_sites")),
        ("reachable from the entry point", ("static", "reachable_from_call")),
        ("warm call depth", ("warm_max_depth",)),
    ]
    per_arm = {
        arm: [
            float(require(document, "measurements", arm, *path, source=source))
            for _, path in fields
        ]
        for arm in ARMS
    }
    return {
        "data": _plain_bars([label for label, _ in fields], per_arm),
        "layout": {
            "title": "Static surface on the authentication path, and warm call depth",
            "barmode": "group",
            "yaxis": {"title": "count", "rangemode": "tozero"},
            "xaxis": {"title": ""},
        },
    }


#: Which figures each result file yields. The key is the file's stem, the value maps a
#: figure name to its builder. A run only produces figures for the files it actually holds.
BUILDERS: dict[str, dict[str, Callable[[dict[str, Any], str], dict[str, Any]]]] = {
    "s4_event_loop_blocking": {
        "s4-health-latency": s4_health_latency,
        "s4-slow-health-requests": s4_slow_health_requests,
    },
    "profile_sampling": {
        "profile-loop-samples": profile_loop_samples,
        "profile-worst-health": profile_worst_health,
    },
    "s2_request_amplification": {"s2-oidc-fetches": s2_oidc_fetches},
    "s1_cold_start": {"s1-cold-start": s1_cold_start},
    "s3_warm_flood": {"s3-latency": s3_latency, "s3-achieved-rate": s3_achieved_rate},
    "s8_failing_provider": {"s8-jwks-fetches": s8_jwks_fetches},
    "memory": {"memory-resident": memory_resident, "memory-import-cost": memory_import_cost},
    "footprint": {"footprint-distributions": footprint_distributions},
    "call_graph": {
        "call-graph-warm": call_graph_warm,
        "call-graph-static": call_graph_static,
    },
}


# --------------------------------------------------------------------------------------
# Comparing runs against each other
# --------------------------------------------------------------------------------------

#: The measurements worth tracking across runs, as `(figure name, title, y axis title, log
#: axis, key path within a result file)`. The path is resolved per run; a run that lacks it
#: contributes no point rather than a zero.
TRACKED = (
    (
        "trend-s4-worst-health",
        "S4: worst /health latency during a cold token validation",
        "milliseconds (log scale)",
        True,
        ("s4_event_loop_blocking", ("measurements", "worst_health_latency_ms")),
    ),
    (
        "trend-s3-p99-600rps",
        "S3: p99 latency at 600 requests per second offered",
        "milliseconds",
        False,
        ("s3_warm_flood", ("measurements", "target_600_rps", "p99_ms")),
    ),
    (
        "trend-s3-p50-600rps",
        "S3: p50 service time at 600 requests per second offered, below saturation",
        "milliseconds",
        False,
        ("s3_warm_flood", ("measurements", "target_600_rps", "p50_ms")),
    ),
    (
        "trend-s3-achieved-900rps",
        "S3: rate actually served when 900 per second were offered",
        "requests per second",
        False,
        ("s3_warm_flood", ("measurements", "target_900_rps", "achieved_rps")),
    ),
)


def trend_figures(runs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Build the figures that put several runs side by side.

    A point is only plotted for a run that actually measured the quantity. When fewer than
    two runs measured it there is nothing to compare, so no figure is emitted at all rather
    than a single lonely point pretending to be a trend.

    Args:
        runs: Loaded runs, oldest first, each a mapping with `label` and `documents`.

    Returns:
        Figure specs by name, possibly empty.

    Raises:
        ResultError: A run holds the file but not the measurement inside it.
    """
    figures: dict[str, dict[str, Any]] = {}
    for name, title, y_title, log_axis, (stem, path) in TRACKED:
        points = [run for run in runs if stem in run["documents"]]
        if len(points) < 2:
            continue
        labels = [run["label"] for run in points]
        traces = []
        for arm in ARMS:
            medians: list[float] = []
            plus: list[float] = []
            minus: list[float] = []
            for run in points:
                block = require(
                    run["documents"][stem], *path, arm, source=f"{run['label']}/{stem}.json"
                )
                medians.append(float(block["median"]))
                up, down = _spread(block)
                plus.append(up)
                minus.append(down)
            traces.append(
                {
                    "type": "scatter",
                    "mode": "lines+markers",
                    "name": ARM_LABELS[arm],
                    "x": labels,
                    "y": medians,
                    "line": {"color": ARM_COLORS[arm], "width": 2.5},
                    "marker": {"color": ARM_COLORS[arm], "size": 9},
                    "error_y": {
                        "type": "data",
                        "symmetric": False,
                        "array": plus,
                        "arrayminus": minus,
                        "color": ARM_COLORS[arm],
                        "thickness": 1.2,
                        "width": 5,
                    },
                }
            )
        figures[name] = {
            "data": traces,
            "layout": {
                "title": title,
                "yaxis": {
                    "title": y_title,
                    **({"type": "log"} if log_axis else {"rangemode": "tozero"}),
                },
                "xaxis": {"title": "run, oldest first"},
                "margin": {"b": 130},
            },
        }
    return figures
