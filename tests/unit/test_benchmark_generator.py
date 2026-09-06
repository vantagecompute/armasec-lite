"""
Tests for the benchmark page generator's run-to-run comparison.

The generator is a build-time script and its usual gate is the docs build, which catches a
page that fails to render but says nothing about whether a number on it is the right one.
The arithmetic below decides what the run pages claim about a change, so it is worth a test
that does not need Docker, a results tree, or an hour.

The property under test throughout is that the two comparisons a run page makes stay
separate. Against upstream armasec is a ratio between the arms. Against the previous run is
armasec-lite's own number moving. A ratio can improve because the upstream arm got slower,
which is not an improvement in this library, and conflating the two would publish that as
one.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import pytest

REPOSITORY = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPOSITORY, "docusaurus", "scripts"))
sys.path.insert(0, os.path.join(REPOSITORY, "legacy_comparison_compose"))

import generate_benchmarks as gen


def make_run(
    page_id: str,
    timestamp: str,
    *,
    lite: float,
    legacy: float,
    git: dict[str, Any] | None = None,
    hostname: str = "test-host",
    stem: str = "s9_cpu_per_request",
) -> dict[str, Any]:
    """
    Build the smallest run shape the comparison functions read.

    The path matches the first entry of `REPRODUCIBILITY`, so a run built here contributes
    exactly one comparable row and the assertions stay about the arithmetic rather than
    about which of twenty-eight quantities moved.

    Args:
        page_id:   The run's page identifier, which is what identity is matched on.
        timestamp: The run's recorded UTC timestamp, which is what runs are ordered by.
        lite:      The armasec-lite value to record.
        legacy:    The upstream value to record.
        git:       The git block, or None for a run that recorded none.
        hostname:  The host to record.
        stem:      The scenario file to record it under.

    Returns:
        A run dictionary shaped as `load_runs` leaves them.
    """
    provenance = {"timestamp_utc": timestamp, "hostname": hostname, "git": git}
    document = {
        "provenance": provenance,
        "measurements": {
            "target_100_rps": {"cpu_ms_per_request": {"legacy": legacy, "lite": lite}}
        },
    }
    return {
        "page_id": page_id,
        "run_id": page_id,
        "label": page_id,
        "version": "0.1.3",
        "provenance": provenance,
        "documents": {stem: document},
        "scenarios": [stem],
    }


def index_of(*runs: dict[str, Any]) -> dict[str, Any]:
    """Wrap runs in the index shape, newest first inside one version, as the loader does."""
    ordered = sorted(runs, key=lambda run: run["provenance"]["timestamp_utc"], reverse=True)
    return {"versions": [{"version": "0.1.3", "runs": ordered}]}


GIT_A = {"describe": "v0.1.3-4-gaaaaaaa", "commit": "a" * 40, "branch": "main", "dirty": False}
GIT_B = {"describe": "v0.1.3-9-gbbbbbbb", "commit": "b" * 40, "branch": "work", "dirty": False}


def test_previous_run_is_the_one_before_it_in_time() -> None:
    """Runs are compared in the order they were taken, not the order the index groups them."""
    first = make_run("first", "2026-09-05T01:00:00+00:00", lite=1.0, legacy=2.0)
    second = make_run("second", "2026-09-05T02:00:00+00:00", lite=1.0, legacy=2.0)
    third = make_run("third", "2026-09-05T03:00:00+00:00", lite=1.0, legacy=2.0)
    index = index_of(first, second, third)

    assert gen.previous_run_of(index, third)["page_id"] == "second"
    assert gen.previous_run_of(index, second)["page_id"] == "first"


def test_the_oldest_run_has_no_previous_run() -> None:
    """The oldest run reports no predecessor rather than comparing against itself."""
    first = make_run("first", "2026-09-05T01:00:00+00:00", lite=1.0, legacy=2.0)
    second = make_run("second", "2026-09-05T02:00:00+00:00", lite=1.0, legacy=2.0)
    assert gen.previous_run_of(index_of(first, second), first) is None


def test_previous_run_crosses_a_version_boundary() -> None:
    """
    The run before a version's first run is the last run of the version before it.

    That is the comparison that matters most, and the index's own grouping hides it: runs
    are nested under versions there, so the neighbour inside the group is the wrong one.
    """
    older = make_run("old", "2026-09-05T01:00:00+00:00", lite=1.0, legacy=2.0)
    newer = make_run("new", "2026-09-06T01:00:00+00:00", lite=1.0, legacy=2.0)
    index = {
        "versions": [
            {"version": "0.1.3", "runs": [newer]},
            {"version": "0.1.0", "runs": [older]},
        ]
    }
    assert gen.previous_run_of(index, newer)["page_id"] == "old"


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (GIT_A, GIT_A, True),
        (GIT_A, GIT_B, False),
        (GIT_A, None, None),
        (None, None, None),
    ],
)
def test_same_code_answers_or_declines_to_answer(
    left: dict[str, Any] | None, right: dict[str, Any] | None, expected: bool | None
) -> None:
    """
    Whether two runs measured the same code, or None when a run did not record it.

    None matters as much as the two booleans. The four runs already committed predate the
    git block, so guessing here would put a confident claim on a page that has no basis for
    one.
    """
    first = make_run("a", "2026-09-05T01:00:00+00:00", lite=1.0, legacy=2.0, git=left)
    second = make_run("b", "2026-09-05T02:00:00+00:00", lite=1.0, legacy=2.0, git=right)
    assert gen.same_code(first, second) is expected


def test_a_dirty_tree_is_not_the_same_code_as_the_commit_it_sits_on() -> None:
    """A dirty tree carries a marker, so it cannot be mistaken for the clean commit."""
    clean = make_run("clean", "2026-09-05T01:00:00+00:00", lite=1.0, legacy=2.0, git=GIT_A)
    dirty = make_run(
        "dirty", "2026-09-05T02:00:00+00:00", lite=1.0, legacy=2.0, git={**GIT_A, "dirty": True}
    )
    assert gen.same_code(clean, dirty) is False


def test_comparison_separates_our_own_movement_from_the_ratio() -> None:
    """
    The two columns answer different questions and are computed from different numbers.

    The case built here is the one that makes the separation matter: armasec-lite did not
    move at all, and the ratio against upstream doubled because the upstream arm got slower.
    Reporting the ratio alone would publish that as an improvement we made.
    """
    earlier = make_run("earlier", "2026-09-05T01:00:00+00:00", lite=10.0, legacy=20.0)
    later = make_run("later", "2026-09-05T02:00:00+00:00", lite=10.0, legacy=40.0)

    rows, uncompared = gen.comparison_rows(later, earlier)
    assert uncompared == [label for label, _, _, _ in gen.REPRODUCIBILITY[1:]]
    assert len(rows) == 1
    row = rows[0]
    assert row["lite_now"] == 10.0
    assert row["lite_before"] == 10.0
    assert row["change_pct"] == 0.0
    assert row["moved"] is False
    assert row["ratio_now"] == pytest.approx(4.0)


def test_comparison_reports_a_real_improvement_as_one() -> None:
    """armasec-lite halving its own number is a fall of 50 percent, and counts as movement."""
    earlier = make_run("earlier", "2026-09-05T01:00:00+00:00", lite=10.0, legacy=20.0)
    later = make_run("later", "2026-09-05T02:00:00+00:00", lite=5.0, legacy=20.0)

    row = gen.comparison_rows(later, earlier)[0][0]
    assert row["change_pct"] == pytest.approx(-50.0)
    assert row["moved"] is True
    assert "better" in gen.change_cell(row)


def test_comparison_reports_a_regression_as_one() -> None:
    """
    A number growing is reported as worse, in the same voice as a win.

    Every quantity tracked here is one where less is better: CPU, calls, fetches, bytes,
    latency. A page that only knows how to describe improvements is a page nobody should
    trust about a regression.
    """
    earlier = make_run("earlier", "2026-09-05T01:00:00+00:00", lite=10.0, legacy=20.0)
    later = make_run("later", "2026-09-05T02:00:00+00:00", lite=15.0, legacy=20.0)

    row = gen.comparison_rows(later, earlier)[0][0]
    assert row["change_pct"] == pytest.approx(50.0)
    assert "worse" in gen.change_cell(row)


def test_a_small_movement_is_called_noise_rather_than_a_result() -> None:
    """Inside the reproduction threshold the cell says so instead of quoting a direction."""
    earlier = make_run("earlier", "2026-09-05T01:00:00+00:00", lite=100.0, legacy=200.0)
    later = make_run("later", "2026-09-05T02:00:00+00:00", lite=105.0, legacy=200.0)

    row = gen.comparison_rows(later, earlier)[0][0]
    assert row["moved"] is False
    cell = gen.change_cell(row)
    assert "within noise" in cell
    assert "better" not in cell and "worse" not in cell


def test_a_scenario_only_one_run_measured_is_listed_not_dropped() -> None:
    """
    A quantity the earlier run never measured is named as uncompared.

    Showing it as unchanged would be a fabrication, and dropping it silently would let a
    page lose a measurement without saying so.
    """
    earlier = make_run(
        "earlier", "2026-09-05T01:00:00+00:00", lite=1.0, legacy=2.0, stem="call_graph"
    )
    later = make_run("later", "2026-09-05T02:00:00+00:00", lite=1.0, legacy=2.0)

    rows, uncompared = gen.comparison_rows(later, earlier)
    assert rows == []
    assert "CPU per request, 100 rps offered" in uncompared


def test_arm_quantity_reads_a_median_and_a_bare_number() -> None:
    """Distributions contribute their median; plain numbers contribute themselves."""
    document = {
        "measurements": {
            "spread": {"lite": {"median": 7.5, "p99": 90.0}},
            "flat": {"lite": 3},
        }
    }
    assert gen.arm_quantity(document, ("measurements", "spread", "{arm}"), "lite", "x") == 7.5
    assert gen.arm_quantity(document, ("measurements", "flat", "{arm}"), "lite", "x") == 3.0
    assert gen.arm_quantity(document, ("measurements", "absent", "{arm}"), "lite", "x") is None


def test_arm_quantity_refuses_a_value_that_is_not_a_number() -> None:
    """
    A path resolving to a non-number fails the build rather than being coerced.

    It means the harness and the tracked list have drifted apart, and a page that quietly
    published whatever it found there would be publishing something nobody chose.
    """
    document = {"measurements": {"broken": {"lite": "fast"}}}
    with pytest.raises(gen.GenerationError):
        gen.arm_quantity(document, ("measurements", "broken", "{arm}"), "lite", "x")
