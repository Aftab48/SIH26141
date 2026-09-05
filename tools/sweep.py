"""Run the Phase 5 sweep, and reduce whatever is on disk into tables.

Two subcommands, separable on purpose:

.. code-block:: text

    python tools/sweep.py run honest --trials 30 --workers 20
    python tools/sweep.py reduce honest --format markdown

``run`` executes trials and writes one file per trial as it completes.
``reduce`` reads the files and regenerates every table, as many times as anyone
likes, without re-running anything. The long sweep happens once, whenever the
human wants; the tables are cheap. A table that could only be produced by a
fourteen-hour run is a table nobody will check, and D9 is the rule that says a
reviewer must be able to.

There is a third, ``perf``, which measures this machine rather than the
protocol: session throughput against key length, the achieved parallel speedup
curve, detector latency and memory. It is a separate subcommand because those
numbers are about the harness and belong in a performance section, not in a
results table.

Everything the run needs to be reproducible goes into a manifest beside the
results: the commit, the exact command line, the seed derivation, the worker
count, the machine, and the start and end times.

Examples
--------
.. code-block:: text

    # what would run, without running it
    python tools/sweep.py run smoke --dry-run

    # a real sweep, resumable -- rerun the same line after a hibernation
    python tools/sweep.py run honest --trials 30 --workers 20

    # one cell only, e.g. after adding it
    python tools/sweep.py run noise --cells p010 --trials 30 --workers 20

    # tables, from whatever is on disk
    python tools/sweep.py reduce honest
    python tools/sweep.py reduce honest --out docs/tables

    # this machine's numbers
    python tools/sweep.py perf --speedup --workers 1,4,20
    python tools/sweep.py perf --session-scaling --key-lengths 96,192,768
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sih141.eval.experiments import EXPERIMENTS, experiment  # noqa: E402
from sih141.eval.manifest import RunManifest, command_line  # noqa: E402
from sih141.eval.perf import (  # noqa: E402
    detector_latency,
    measure_memory,
    measure_scaling,
    measure_small_end,
    speedup_table,
)
from sih141.eval.reduce import EXTRA_CHARTS, reduce_experiment  # noqa: E402
from sih141.eval.runner import (  # noqa: E402
    pin_blas_threads,
    plan_trials,
    probe_pool,
    run_experiment,
)
from sih141.eval.store import DEFAULT_RESULTS_ROOT, ResultStore  # noqa: E402


def _int_list(text: str) -> list[int]:
    """Parse a comma-separated list of positive integers.

    Parameters
    ----------
    text : str
        For example ``"1,4,20"``.

    Returns
    -------
    list of int

    Raises
    ------
    argparse.ArgumentTypeError
        If any element is not a positive integer.
    """
    values: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit() or int(part) <= 0:
            raise argparse.ArgumentTypeError(
                f"expected a comma-separated list of positive integers, "
                f"got {text!r}"
            )
        values.append(int(part))
    if not values:
        raise argparse.ArgumentTypeError(f"no values in {text!r}")
    return values


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser.

    Returns
    -------
    argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="tools/sweep.py",
        description=(
            "Run the Phase 5 evaluation sweep, or reduce its results to "
            "tables. The two are separable: reduce reads what is on disk and "
            "re-runs nothing."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="execute trials and write one file each")
    run.add_argument("experiment", choices=sorted(EXPERIMENTS))
    run.add_argument(
        "--trials",
        type=int,
        default=None,
        help="trials per cell; default is the experiment's own",
    )
    run.add_argument(
        "--cells",
        default=None,
        help="comma-separated cell names; default is every cell",
    )
    run.add_argument(
        "--workers",
        type=int,
        default=20,
        help=(
            "pool size (default 20: this machine has 20 physical cores and "
            "eight logical threads are left free so it stays usable)"
        ),
    )
    run.add_argument(
        "--chunk",
        type=int,
        default=1,
        help="trials handed over per message (default 1, for load balance)",
    )
    run.add_argument(
        "--results",
        type=Path,
        default=DEFAULT_RESULTS_ROOT,
        help=f"results directory (default {DEFAULT_RESULTS_ROOT}, outside the repo)",
    )
    run.add_argument(
        "--retain-transcripts",
        action="store_true",
        help=(
            "keep the full transcript on every record: 25.4 MiB per trial at "
            "L=115200, so for a named handful of worked examples only"
        ),
    )
    run.add_argument(
        "--in-process",
        action="store_true",
        help="bypass the pool entirely; for debugging, never for a timing",
    )
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="list the trials that would run, and stop",
    )
    run.add_argument("--quiet", action="store_true", help="no progress output")

    reduce_cmd = sub.add_parser(
        "reduce", help="regenerate every table from the results on disk"
    )
    reduce_cmd.add_argument("experiment", choices=sorted(EXPERIMENTS))
    reduce_cmd.add_argument(
        "--results", type=Path, default=DEFAULT_RESULTS_ROOT, help="results directory"
    )
    reduce_cmd.add_argument(
        "--cells", default=None, help="comma-separated cell names"
    )
    reduce_cmd.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="output format (default markdown)",
    )
    reduce_cmd.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write to this directory instead of stdout",
    )
    reduce_cmd.add_argument(
        "--charts",
        type=Path,
        default=None,
        help=(
            "also render this experiment's charts into this directory, "
            "for experiments that register one"
        ),
    )

    perf = sub.add_parser("perf", help="measure this machine, not the protocol")
    perf.add_argument(
        "--speedup",
        action="store_true",
        help="run the same reduced sweep at each worker count and report the curve",
    )
    perf.add_argument(
        "--session-scaling",
        action="store_true",
        help="time one session at each key length",
    )
    perf.add_argument(
        "--detector-latency",
        action="store_true",
        help="time the detector alone, separately from session generation",
    )
    perf.add_argument(
        "--memory",
        action="store_true",
        help="peak resident set against key length, read from an OS counter",
    )
    perf.add_argument(
        "--small-end",
        action="store_true",
        help=(
            "probe the key lengths too small to carry a security claim: "
            "floors, honest-run aborts, and which families are evaluable"
        ),
    )
    perf.add_argument(
        "--small-end-lengths",
        type=_int_list,
        default=[3, 6, 12, 24, 96, 180, 183, 384],
        help="key lengths for --small-end (default 3,6,12,24,96,180,183,384)",
    )
    perf.add_argument("--probe", action="store_true", help="report what workers see")
    perf.add_argument(
        "--experiment",
        choices=sorted(EXPERIMENTS),
        default="scaling",
        help="experiment the speedup curve runs (default scaling)",
    )
    perf.add_argument(
        "--speedup-cell",
        default="l768",
        help="cell the speedup curve runs (default l768)",
    )
    perf.add_argument(
        "--workers", type=_int_list, default=[1, 4, 20], help="worker counts to time"
    )
    perf.add_argument(
        "--key-lengths",
        type=_int_list,
        default=[96, 192, 384, 768],
        help="key lengths to time",
    )
    perf.add_argument(
        "--trials",
        type=int,
        default=40,
        help="trials in the reduced sweep used for the speedup curve",
    )
    perf.add_argument(
        "--results",
        type=Path,
        default=None,
        help="scratch directory for the speedup sweep (default: a temp dir)",
    )
    perf.add_argument(
        "--json", action="store_true", help="emit JSON instead of a table"
    )
    return parser


def command_run(args: argparse.Namespace) -> int:
    """Execute the ``run`` subcommand.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed arguments.

    Returns
    -------
    int
        Process exit status. Non-zero if any trial failed or if a trial moved
        a global random state.
    """
    # Before the pool exists, so every spawned worker inherits the limit at
    # interpreter start rather than after numpy has sized its own pool.
    blas = pin_blas_threads(1)

    exp = experiment(args.experiment)
    cells = None if args.cells is None else [c.strip() for c in args.cells.split(",")]
    store = ResultStore(args.results)
    trials = exp.trials if args.trials is None else args.trials

    planned = plan_trials(exp, store, trials=trials, cells=cells)
    if args.dry_run:
        print(f"{len(planned)} trial(s) would run into {store.root}:")
        for spec in planned:
            print(f"  {spec.experiment}/{spec.cell}#{spec.index}")
        return 0

    manifest = RunManifest.begin(
        experiment=exp.name,
        cells=tuple(c.name for c in exp.cells) if cells is None else tuple(cells),
        trials=trials,
        workers=args.workers,
        results_root=str(store.root),
        eps=exp.cells[0].eps,
        command_line=command_line(),
    )
    opening = manifest.to_dict()
    # Every cell in full, because "eps" above is a single float and the cells
    # may not agree on one. A reviewer re-running this needs the parameter set,
    # the scenario, its options and both nulls per cell, not a representative.
    opening["cell_definitions"] = [
        cell.to_dict()
        for cell in exp.cells
        if cells is None or cell.name in set(cells)
    ]
    manifest_path = store.write_manifest(exp.name, manifest.filename(), opening)
    if not args.quiet:
        print(f"[sweep] manifest {manifest_path}", file=sys.stderr)

    summary = run_experiment(
        exp,
        store,
        trials=trials,
        cells=cells,
        workers=args.workers,
        chunk=args.chunk,
        in_process=args.in_process,
        retain_transcript=args.retain_transcripts or None,
        quiet=args.quiet,
    )
    done = manifest.finish(
        ran=summary["ran"],
        skipped=summary["skipped"],
        failed=summary["failed"],
        wall_clock_seconds=summary["wall_clock_seconds"],
    )
    payload = done.to_dict()
    payload["cell_definitions"] = opening["cell_definitions"]
    payload["blas"] = blas
    payload["outcomes"] = summary["outcomes"]
    payload["errors"] = summary["errors"]
    payload["global_rng_touched"] = summary["global_rng_touched"]
    if not args.in_process:
        # Measured, not assumed: what a real worker saw in its own environment.
        payload["worker_probe"] = probe_pool(min(args.workers, 2))
    store.write_manifest(exp.name, done.filename(), payload)

    print(
        f"[sweep] {exp.name}: ran {summary['ran']}, skipped "
        f"{summary['skipped']}, failed {summary['failed']} in "
        f"{summary['wall_clock_seconds']:.1f} s",
        file=sys.stderr,
    )
    for line in summary["errors"]:
        print(f"[sweep] FAILED {line}", file=sys.stderr)
    if summary["global_rng_touched"]:
        print(
            "[sweep] D3 VIOLATION -- these trials moved a global random "
            "state and are not reproducible from their seeds: "
            + ", ".join(summary["global_rng_touched"]),
            file=sys.stderr,
        )
        return 2
    return 1 if summary["failed"] else 0


def command_reduce(args: argparse.Namespace) -> int:
    """Execute the ``reduce`` subcommand.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed arguments.

    Returns
    -------
    int
        Process exit status.
    """
    store = ResultStore(args.results)
    cells = None if args.cells is None else [c.strip() for c in args.cells.split(",")]
    # shlex.quote, exactly as `command_line` does on the run side. D9's claim is
    # that a reviewer can re-run the printed command, and an unquoted path with
    # a space in it prints a command that argparse rejects with "unrecognized
    # arguments" -- a table that looks reproducible and is not.
    regenerate = (
        f"python tools/sweep.py reduce {args.experiment} "
        f"--results {shlex.quote(str(args.results))}"
    )
    tables = reduce_experiment(
        store, args.experiment, command=regenerate, cells=cells
    )

    if args.charts is not None:
        _write_charts(store, args.experiment, cells, args.charts, regenerate)

    manifests = store.manifests(args.experiment)
    provenance = _provenance(manifests)
    if args.format == "json":
        payload: dict[str, Any] = {
            "experiment": args.experiment,
            "provenance": provenance,
            "tables": [table.to_dict() for table in tables],
        }
        text = json.dumps(payload, indent=2, sort_keys=True)
        blocks = {f"{args.experiment}-tables.json": text}
    else:
        parts = [f"## {args.experiment}", "", _provenance_markdown(provenance), ""]
        for table in tables:
            parts.append(table.to_markdown())
            parts.append("")
        text = "\n".join(parts)
        blocks = {f"{args.experiment}.md": text}

    if args.out is None:
        print(text)
    else:
        args.out.mkdir(parents=True, exist_ok=True)
        for name, body in blocks.items():
            path = args.out / name
            path.write_text(body, encoding="utf-8")
            print(f"wrote {path}", file=sys.stderr)
    return 0


def _write_charts(
    store: ResultStore,
    experiment_name: str,
    cells: Sequence[str] | None,
    destination: Path,
    command: str,
) -> None:
    """Render an experiment's registered charts into a directory.

    Parameters
    ----------
    store : ResultStore
        Where results live.
    experiment_name : str
        Which experiment.
    cells : Sequence of str or None
        Restrict to these cells, as ``reduce`` does.
    destination : Path
        Directory to write into; created if absent.
    command : str
        The regenerating command, handed to the renderer so the figure can
        carry it (D9).

    Notes
    -----
    Says so loudly when an experiment registers no chart. Writing nothing and
    exiting zero would be indistinguishable from a renderer that silently
    produced an empty figure.
    """
    renderer = EXTRA_CHARTS.get(experiment_name)
    if renderer is None:
        print(
            f"no chart is registered for {experiment_name!r}; nothing written "
            f"to {destination}",
            file=sys.stderr,
        )
        return
    wanted = None if cells is None else set(cells)
    records = [
        record
        for record in store.read_experiment(experiment_name)
        if wanted is None or record.cell in wanted
    ]
    order = None
    registered = EXPERIMENTS.get(experiment_name)
    if registered is not None:
        order = registered.cell_names
    destination.mkdir(parents=True, exist_ok=True)
    for name, body in renderer(
        records,
        command=f"{command} --charts {shlex.quote(str(destination))}",
        cell_order=order,
    ).items():
        path = destination / name
        path.write_text(body, encoding="utf-8")
        print(f"wrote {path}", file=sys.stderr)


def _provenance(manifest_paths: Sequence[Path]) -> dict[str, Any]:
    """Summarise the manifests behind a set of results.

    Parameters
    ----------
    manifest_paths : Sequence of pathlib.Path
        Manifest files, oldest first.

    Returns
    -------
    dict
        The commits, whether any tree was dirty, the worker counts and the
        commands. A reduction whose results came from two different commits
        says so; a table drawn across a code change is a table with two
        meanings.
    """
    commits: list[str] = []
    commands: list[str] = []
    workers: list[int] = []
    dirty = False
    unfinished = 0
    for path in manifest_paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        git = data.get("git") or {}
        if git.get("commit"):
            commits.append(str(git["commit"])[:12])
        dirty = dirty or bool(git.get("dirty"))
        command = data.get("command_line")
        if command and str(command) not in commands:
            # Two passes over one cell run the same line twice; printing it
            # twice says nothing the manifest list does not already say.
            commands.append(str(command))
        if data.get("workers") is not None:
            workers.append(int(data["workers"]))
        if data.get("finished_at") is None:
            unfinished += 1
    return {
        "manifests": [p.name for p in manifest_paths],
        "commits": sorted(set(commits)),
        "tree_was_dirty": dirty,
        "worker_counts": sorted(set(workers)),
        "commands": commands,
        "unfinished_manifests": unfinished,
    }


def _provenance_markdown(provenance: dict[str, Any]) -> str:
    """Render the provenance block that sits above the tables.

    Parameters
    ----------
    provenance : dict
        As :func:`_provenance`.

    Returns
    -------
    str
        Markdown. The dirty-tree and multiple-commit cases are stated loudly,
        because both mean the results were not all produced by one committed
        version and D9's claim is exactly that they were.
    """
    lines = ["**Provenance.**", ""]
    commits = provenance["commits"]
    if not commits:
        lines.append("- commit: **not recorded** -- these results are not traceable")
    elif len(commits) == 1:
        lines.append(f"- commit: `{commits[0]}`")
    else:
        lines.append(
            "- commit: **" + ", ".join(f"`{c}`" for c in commits) + "** -- these "
            "results span more than one commit, so the table has more than one "
            "meaning"
        )
    if provenance["tree_was_dirty"]:
        lines.append(
            "- **the working tree was dirty for at least one run**, so the "
            "commit above does not fully describe the code that ran"
        )
    if provenance["unfinished_manifests"]:
        lines.append(
            f"- {provenance['unfinished_manifests']} manifest(s) have no finish "
            "time: a run was interrupted and these cells may be partial"
        )
    lines.append(f"- worker counts: {provenance['worker_counts']}")
    for command in provenance["commands"]:
        lines.append(f"- produced by: `{command}`")
    return "\n".join(lines)


def command_perf(args: argparse.Namespace) -> int:
    """Execute the ``perf`` subcommand.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed arguments.

    Returns
    -------
    int
        Process exit status.
    """
    import tempfile
    import time

    pin_blas_threads(1)
    report: dict[str, Any] = {}
    nothing_asked = not any(
        (
            args.speedup,
            args.session_scaling,
            args.detector_latency,
            args.memory,
            args.small_end,
            args.probe,
        )
    )

    if args.probe or nothing_asked:
        report["worker_probe"] = probe_pool(2)

    if args.session_scaling or nothing_asked:
        rows = measure_scaling(args.key_lengths)
        report["session_scaling"] = rows
        if not args.json:
            print("| L | seconds | ms/position | positions/s | KiB/position |")
            print("| --- | --- | --- | --- | --- |")
            for row in rows:
                print(
                    f"| {row['key_length']} | {row['seconds']:.3f} | "
                    f"{row['ms_per_position']:.3f} | "
                    f"{row['positions_per_second']:.1f} | "
                    f"{row['kb_per_position']:.3f} |"
                )
            print()

    if args.detector_latency or nothing_asked:
        rows = [detector_latency(L, seed=11 + L) for L in args.key_lengths]
        report["detector_latency"] = rows
        if not args.json:
            print("| L | JSON bytes | detect s (min) | detect s (mean) | MiB/s |")
            print("| --- | --- | --- | --- | --- |")
            for row in rows:
                print(
                    f"| {row['key_length']} | {row['json_bytes']} | "
                    f"{row['min_seconds']:.4f} | {row['mean_seconds']:.4f} | "
                    f"{row['mb_per_second']:.1f} |"
                )
            print()

    if args.memory or nothing_asked:
        rows = measure_memory(sorted(args.key_lengths))
        report["memory"] = rows
        if not args.json:
            print("| L | peak RSS MiB | rise MiB | transcript MiB |")
            print("| --- | --- | --- | --- |")
            for row in rows:
                print(
                    f"| {row['key_length']} | {row['peak_rss_mb']:.1f} | "
                    f"{row['delta_mb']:+.1f} | {row['json_mb']:.2f} |"
                )
            print()

    if args.small_end or nothing_asked:
        rows = measure_small_end(args.small_end_lengths)
        report["small_end"] = rows
        if not args.json:
            print(
                "| L | signing length | m_min | M_min | aborts / trials | "
                "security claim | families withheld |"
            )
            print("| --- | --- | --- | --- | --- | --- | --- |")
            for row in rows:
                if row["refused"]:
                    # A refused parameter set is a ROW. A length missing from
                    # the table reads as one nobody tried.
                    print(
                        f"| {row['key_length']} | parameter set **refused** "
                        f"| - | - | - | - | - |"
                    )
                    continue
                lo, hi = row["withheld_min"], row["withheld_max"]
                span = str(lo) if lo == hi else f"{lo}-{hi}"
                claim = (
                    "varies"
                    if row["security_claim_varies"]
                    else ("yes" if row["security_claim"] else "no")
                )
                print(
                    f"| {row['key_length']} | {row['signing_length']} | "
                    f"{row['m_min']} | {row['M_min']} | "
                    f"{row['aborts']} / {row['trials']} | "
                    f"{claim} | {span} |"
                )
            print()

    if args.speedup:
        scratch = args.results
        temporary = None
        if scratch is None:
            temporary = tempfile.TemporaryDirectory()
            scratch = Path(temporary.name)
        try:
            measurements = []
            exp = experiment(args.experiment)
            cells = [args.speedup_cell]
            exp.cell(args.speedup_cell)
            for workers in args.workers:
                # A fresh directory per point: a resumed sweep would skip the
                # trials and time an empty run, which is exactly the shape of
                # "an arm reporting zero that never acted".
                store = ResultStore(Path(scratch) / f"w{workers}")
                started = time.perf_counter()
                summary = run_experiment(
                    exp,
                    store,
                    trials=args.trials,
                    cells=cells,
                    workers=workers,
                    quiet=True,
                )
                elapsed = time.perf_counter() - started
                if summary["ran"] != args.trials:
                    raise RuntimeError(
                        f"speedup point at {workers} workers ran "
                        f"{summary['ran']} trials, not {args.trials}. A point "
                        f"that skipped its work would time an empty run."
                    )
                measurements.append(
                    {
                        "workers": workers,
                        "seconds": elapsed,
                        "ran": summary["ran"],
                        "trial_seconds_total": sum(
                            o["seconds"] for o in summary["outcomes"]
                        ),
                    }
                )
        finally:
            if temporary is not None:
                temporary.cleanup()
        curve = speedup_table(measurements)
        for row, measured in zip(curve, measurements):
            row["ran"] = measured["ran"]
            row["trial_seconds_total"] = measured["trial_seconds_total"]
            row["aggregate_speedup"] = (
                measured["trial_seconds_total"] / measured["seconds"]
            )
        report["speedup"] = curve
        if not args.json:
            print(
                "| workers | wall s | speedup | efficiency | sum of trial s | "
                "aggregate speedup |"
            )
            print("| --- | --- | --- | --- | --- | --- |")
            for row in curve:
                print(
                    f"| {row['workers']} | {row['seconds']:.2f} | "
                    f"{row['speedup']:.2f} | {row['efficiency']:.2f} | "
                    f"{row['trial_seconds_total']:.2f} | "
                    f"{row['aggregate_speedup']:.2f} |"
                )
            print()

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and dispatch.

    Parameters
    ----------
    argv : Sequence of str or None, optional
        Defaults to :data:`sys.argv`.

    Returns
    -------
    int
        Process exit status.
    """
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return command_run(args)
    if args.command == "reduce":
        return command_reduce(args)
    return command_perf(args)


if __name__ == "__main__":
    # Required, not decorative. Windows uses spawn: without this guard every
    # worker re-executes this module as __main__, starts its own sweep, and
    # forks a fork bomb.
    raise SystemExit(main())
