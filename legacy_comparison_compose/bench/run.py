"""
The scenario driver: pick scenarios, run them, write result files, print a summary.

Run inside the `bench` container, which sits on the compose network and reaches the two
application arms by service name. It needs the Docker socket for two reasons and no others:
three scenarios restart application containers between repetitions, and the provenance block
reads container resource limits and the Keycloak image digest from the daemon.

```
docker compose run --rm bench --reps 5
docker compose run --rm bench --scenarios s4 --reps 1 --quick
```

Scenario order is deliberate. S4 is the headline and runs first, while the machine is in
whatever state the rest of the run will inherit rather than after twenty minutes of load.
The measurement passes that instrument the applications (`memory`, `callgraph`, `profile`)
run last, so nothing they perturb is still being timed.

The run refuses to start if the two application containers do not carry identical CPU and
memory limits, which `report.provenance` checks. An unfair comparison is worse than no
comparison, and a warning in a log file is not a control.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import traceback

from bench import report, scenarios

#: Runs in this order for the reasons given in the module docstring.
DEFAULT_ORDER = ("s4", "s3", "s1", "s2", "s8", "footprint", "memory", "callgraph", "profile")


def parse_args(argv: list[str]) -> argparse.Namespace:
    """
    Parse the driver's command line.

    Args:
        argv: Arguments, the program name excluded.

    Returns:
        The parsed namespace.
    """
    parser = argparse.ArgumentParser(prog="bench.run", description=__doc__)
    parser.add_argument(
        "--scenarios",
        default=",".join(DEFAULT_ORDER),
        help=f"comma separated, from {', '.join(DEFAULT_ORDER)}",
    )
    parser.add_argument("--reps", type=int, default=5, help="repetitions per measurement point")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="shorten every duration, for checking the harness rather than measuring with it",
    )
    parser.add_argument(
        "--out",
        default=os.environ.get("HARNESS_RESULTS_DIR", "/results"),
        help="directory to write result files into",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """
    Run the requested scenarios and write their results.

    Args:
        argv: Arguments, the program name excluded.

    Returns:
        A process exit status: 0 when every requested scenario completed, 1 otherwise.
    """
    args = parse_args(argv)
    requested = [name.strip() for name in args.scenarios.split(",") if name.strip()]
    unknown = [name for name in requested if name not in scenarios.SCENARIOS]
    if unknown:
        print(f"unknown scenarios: {unknown}", file=sys.stderr)
        return 2

    docker = report.Docker(project=os.environ.get("HARNESS_COMPOSE_PROJECT", "armasec-comparison"))
    minter = scenarios.Minter()
    context = scenarios.Context(docker=docker, minter=minter, reps=args.reps, quick=args.quick)

    for arm in scenarios.ARMS:
        scenarios.wait_healthy(arm)
    versions = scenarios.library_versions()
    provenance = report.provenance(docker, versions, args.reps)

    print("armasec-lite comparison harness")
    print(f"  host          {provenance['hostname']} ({provenance['cpu_count']} cores)")
    print(f"  cpu           {provenance['cpu_model']}")
    print(f"  kernel        {provenance['kernel']}")
    print(f"  docker        {provenance['docker_version']}")
    print(f"  keycloak      {provenance['keycloak_image']}")
    print(f"  legacy arm    {versions['legacy']}")
    print(f"  lite arm      {versions['lite']}")
    limits = provenance["app_container_limits"]["legacy"]
    print(f"  app limits    {limits['cpus']} cpus, {limits['mem_limit_bytes'] / 1e6:.0f}MB (both)")
    print(f"  repetitions   {args.reps}{' (quick mode)' if args.quick else ''}")
    print()

    summary: list[list[str]] = [["Measurement", "upstream armasec", "armasec-lite", "verdict"]]
    failures: list[str] = []

    for name in requested:
        print(f"[{name}] starting", flush=True)
        started = time.perf_counter()
        try:
            document = scenarios.SCENARIOS[name](context)
        except Exception:  # noqa: BLE001 - one broken scenario must not lose the others
            failures.append(name)
            print(f"[{name}] FAILED\n{traceback.format_exc()}", file=sys.stderr, flush=True)
            continue
        elapsed = time.perf_counter() - started
        rows = document.pop("summary_rows", [])
        document["provenance"] = provenance
        document["elapsed_seconds"] = round(elapsed, 1)
        path = os.path.join(args.out, f"{scenarios.FILENAMES[name]}.json")
        report.write_result(path, document)
        summary.extend(rows)
        print(f"[{name}] done in {elapsed:.0f}s -> {path}\n", flush=True)

    print()
    print("=" * 100)
    print("SUMMARY")
    print("=" * 100)
    report.print_summary(summary)
    print()
    print(
        "Absolute numbers describe one machine running Docker. The ratio between the two "
        "arms is the transferable part."
    )
    if failures:
        print(f"\nFAILED SCENARIOS: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


def _fix_result_ownership(directory: str) -> None:
    """
    Hand the result files to whoever owns the directory they were written into.

    The bench container runs as root because that is what reading the Docker socket
    requires, so without this every result file lands root-owned on the host and cannot be
    committed without an escalation. The bind-mounted directory already carries the right
    owner, so it is the answer rather than an environment variable that could drift.

    Args:
        directory: The results directory.
    """
    try:
        stat = os.stat(directory)
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                os.chown(path, stat.st_uid, stat.st_gid)
    except OSError:
        pass


if __name__ == "__main__":
    status = main(sys.argv[1:])
    _fix_result_ownership(os.environ.get("HARNESS_RESULTS_DIR", "/results"))
    raise SystemExit(status)
