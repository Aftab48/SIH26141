"""The parallel runner: a persistent pool, pinned BLAS, and a resumable sweep.

Three things about running this protocol in parallel are easy to get wrong, and
each of them fails quietly rather than loudly.

.. _blas-oversubscription:

1. BLAS oversubscription
------------------------
numpy spawns its own OpenMP pool inside every process that imports it. Twenty
workers each spawning twenty BLAS threads is four hundred threads over
twenty-eight logical cores, and the result is a parallel run **slower than the
serial one** -- the cores spend their time context-switching rather than
computing. The fix is ``OMP_NUM_THREADS=1`` and friends, and the trap is that
setting them has no effect once numpy has been imported: the pool is already
sized.

So :func:`pin_blas_threads` sets them **in the parent, before the pool is
created**. Windows uses spawn, and a spawned child gets a copy of the parent's
environment at interpreter start -- before any import -- so the limit is in
place in every worker by construction rather than by an initializer racing the
import. The parent's own numpy is already up and unpinned, which does not
matter because the parent does no numerics while the sweep runs; that fact is
recorded rather than hidden, in ``numpy_already_imported``.

And it is then **measured** rather than assumed: :func:`worker_probe` runs in a
worker and reports what that worker actually sees, and the achieved speedup
curve -- which is what the mistake would show up in -- is a deliverable of this
phase rather than a footnote.

.. _spawn-not-fork:

2. Windows uses spawn, not fork
-------------------------------
Every worker re-imports Qiskit from scratch, which costs about 0.75 s. A
process per trial would pay that per trial; at ``L = 96`` that is more than the
trial itself. So the pool is created once and lives for the whole sweep, work
is handed to it a trial at a time, and the entry point is guarded with
``if __name__ == "__main__"`` in ``tools/sweep.py`` -- without that guard a
spawned child re-executes the sweep and forks a fork bomb.

Chunk size defaults to one. That is not the same question as "a process per
trial": the pool is persistent either way, and a chunk is only how many tasks
are handed over in one message. One keeps the load balanced when cells have
different key lengths -- and a static split would leave nineteen workers idle
while one finishes the long cell -- at an IPC cost of well under a millisecond
against a trial that takes at least a fifth of a second.

.. _resumable:

3. Hibernation
--------------
This has already destroyed one long run in this project, and baked
``"<no summary line>"`` into ``docs/METRICS.md``. Each worker writes its own
trial's file the moment that trial finishes, atomically, named from the trial's
identity; :func:`plan_trials` skips what is already on disk. So an interruption
costs the trials in flight and not the run, and re-running a single cell later
does not mean redoing the sweep.

Examples
--------
>>> import tempfile
>>> from pathlib import Path
>>> from sih141.eval.experiments import experiment
>>> from sih141.eval.runner import plan_trials, run_experiment
>>> from sih141.eval.store import ResultStore
>>> with tempfile.TemporaryDirectory() as tmp:
...     store = ResultStore(Path(tmp))
...     smoke = experiment("smoke")
...     first = plan_trials(smoke, store, trials=3)
...     summary = run_experiment(smoke, store, trials=3, workers=1,
...                              in_process=True, quiet=True)
...     second = plan_trials(smoke, store, trials=3)
...     [spec.index for spec in first]
...     (summary["ran"], summary["skipped"], summary["failed"])
...     [spec.index for spec in second]
[0, 1, 2]
(3, 0, 0)
[]

Nothing left to do is not an error -- it is what a resumed sweep looks like:

>>> with tempfile.TemporaryDirectory() as tmp:
...     store = ResultStore(Path(tmp))
...     smoke = experiment("smoke")
...     _ = run_experiment(smoke, store, trials=2, workers=1,
...                        in_process=True, quiet=True)
...     again = run_experiment(smoke, store, trials=2, workers=1,
...                            in_process=True, quiet=True)
...     (again["ran"], again["skipped"])
(0, 2)
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Sequence

from .experiments import Experiment, all_cells, experiment, run_trial
from .store import ResultStore

__all__ = [
    "BLAS_ENV_VARS",
    "TrialOutcome",
    "TrialSpec",
    "global_rng_fingerprint",
    "default_results_root",
    "pin_blas_threads",
    "plan_trials",
    "probe_pool",
    "run_experiment",
    "worker_probe",
]

BLAS_ENV_VARS: Final[tuple[str, ...]] = (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
)
"""tuple of str: Every thread-limit variable a numpy build might read.

All five, not just ``OMP_NUM_THREADS``, because which one bites depends on
which BLAS the wheel was built against and getting it wrong costs a factor
rather than a percent. See :ref:`blas-oversubscription`.
"""


def pin_blas_threads(threads: int = 1) -> dict[str, Any]:
    """Limit every worker's BLAS pool, and report whether it can have worked.

    Parameters
    ----------
    threads : int, optional
        Threads per process. ``1`` is right for this workload: the protocol is
        pure Python over two- and three-qubit states, so there is no matrix
        large enough for a BLAS thread to earn its scheduling.

    Returns
    -------
    dict
        ``threads``, the ``values`` now in the environment, and
        ``numpy_already_imported`` -- which is ``True`` in the parent almost
        always, and is the field that says the parent's own pool was sized
        before this call and is therefore not what was pinned. The children
        inherit the environment at interpreter start, so theirs is.

    Raises
    ------
    ValueError
        If ``threads`` is not positive.

    Examples
    --------
    >>> from sih141.eval.runner import pin_blas_threads
    >>> report = pin_blas_threads(1)
    >>> report["threads"], report["values"]["OMP_NUM_THREADS"]
    (1, '1')
    >>> sorted(report)
    ['numpy_already_imported', 'threads', 'values']
    """
    if isinstance(threads, bool) or not isinstance(threads, int) or threads < 1:
        raise ValueError(f"threads must be a positive int, got {threads!r}")
    for name in BLAS_ENV_VARS:
        os.environ[name] = str(threads)
    return {
        "threads": threads,
        "values": {name: os.environ.get(name) for name in BLAS_ENV_VARS},
        "numpy_already_imported": "numpy" in sys.modules,
    }


def global_rng_fingerprint() -> str:
    """Return a digest of the two global random states D3 forbids touching.

    Returns
    -------
    str
        Sixteen hex characters over :func:`numpy.random.get_state` and
        :func:`random.getstate`. Reading a state does not advance it, so this
        can be called on both sides of a trial.

    Notes
    -----
    This is how "no worker touches global ``numpy.random`` or stdlib
    ``random``" is *measured* rather than asserted. A scenario that drew from
    either would move the digest, the worker would report
    ``touched_global_rng``, and the sweep would say so. A test that merely
    grepped the sources for ``np.random.`` would pass on a call made three
    libraries down.
    """
    import random as _random

    import numpy as _np

    state = _np.random.get_state()
    keys = _np.asarray(state[1]).tobytes()
    payload = repr((state[0], state[2], state[3], state[4], _random.getstate()))
    digest = hashlib.sha256(keys + payload.encode("utf-8")).hexdigest()
    return digest[:16]


def worker_probe() -> dict[str, Any]:
    """Report what one worker process actually sees. Runs inside the pool.

    Returns
    -------
    dict
        The process id, the BLAS environment as the worker reads it, whether
        numpy was already imported when the worker started, and the global RNG
        fingerprint.

    Notes
    -----
    The point of this function is that :ref:`blas-oversubscription` is a
    silent failure. A comment saying the variables are set proves nothing; a
    worker reporting what is in its own environment is an observation that
    would differ if the setting had not reached it.
    """
    return {
        "pid": os.getpid(),
        "blas_env": {name: os.environ.get(name) for name in BLAS_ENV_VARS},
        "numpy_imported_at_start": "numpy" in sys.modules,
        "global_rng": global_rng_fingerprint(),
    }


@dataclass(frozen=True)
class TrialSpec:
    """One unit of work: which trial, and where to put it.

    Small and picklable on purpose. The worker rebuilds the
    :class:`~sih141.eval.experiments.Experiment` from the registry by name
    rather than being sent one, so nothing about the cell -- and in particular
    nothing about its ground-truth label -- travels as pickled state that could
    diverge between parent and worker.

    Attributes
    ----------
    experiment : str
        Experiment name.
    cell : str
        Cell name.
    index : int
        Trial index.
    results_root : str
        Where to write.
    retain_transcript : bool or None
        Overrides the cell's own setting.
    """

    experiment: str
    cell: str
    index: int
    results_root: str
    retain_transcript: bool | None = None


@dataclass(frozen=True)
class TrialOutcome:
    """What a worker reports back once a trial is on disk.

    The record itself is **not** sent back: at ``L = 115200`` with transcripts
    retained it would be 26.7 MB through a pipe, per trial. The worker writes
    the file and returns this.

    Attributes
    ----------
    experiment, cell : str
        Identity.
    index : int
        Trial index.
    fingerprint : str or None
        :meth:`~sih141.eval.records.TrialRecord.fingerprint`, or ``None`` if the
        trial failed. This is what the determinism test compares across worker
        counts.
    seconds : float
        Wall clock for the trial, in the worker.
    pid : int
        Which process ran it.
    touched_global_rng : bool
        Whether the global numpy or stdlib random state moved while this trial
        ran. Always ``False`` if D3 holds, and the sweep reports it loudly if
        it is ever ``True``.
    error : str or None
        The exception, as ``type: message``, if the trial failed. A failed
        trial does not stop the sweep -- it is counted, named, and left absent
        from disk so a later pass retries it.
    """

    experiment: str
    cell: str
    index: int
    fingerprint: str | None
    seconds: float
    pid: int
    touched_global_rng: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "experiment": self.experiment,
            "cell": self.cell,
            "index": self.index,
            "fingerprint": self.fingerprint,
            "seconds": self.seconds,
            "pid": self.pid,
            "touched_global_rng": self.touched_global_rng,
            "error": self.error,
        }


def _execute(spec: TrialSpec) -> TrialOutcome:
    """Run one trial in whatever process picks it up, and write it.

    Module-level and taking a single picklable argument, because that is what
    :meth:`concurrent.futures.ProcessPoolExecutor.map` requires.

    Parameters
    ----------
    spec : TrialSpec
        The unit of work.

    Returns
    -------
    TrialOutcome
        Never raises for a failed trial: an exception is caught, named and
        counted, so one bad cell does not cost a fourteen-hour sweep.
    """
    started = time.perf_counter()
    before = global_rng_fingerprint()
    try:
        exp = experiment(spec.experiment)
        record = run_trial(
            exp, spec.cell, spec.index, retain_transcript=spec.retain_transcript
        )
        ResultStore(spec.results_root).write(record)
        fingerprint: str | None = record.fingerprint()
        error: str | None = None
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        fingerprint = None
        error = f"{type(exc).__name__}: {exc}"
    return TrialOutcome(
        experiment=spec.experiment,
        cell=spec.cell,
        index=spec.index,
        fingerprint=fingerprint,
        seconds=time.perf_counter() - started,
        pid=os.getpid(),
        touched_global_rng=global_rng_fingerprint() != before,
        error=error,
    )


def plan_trials(
    exp: Experiment,
    store: ResultStore,
    *,
    trials: int | None = None,
    cells: Sequence[str] | None = None,
    retain_transcript: bool | None = None,
) -> list[TrialSpec]:
    """Return the work still to do, skipping what is already on disk.

    Parameters
    ----------
    exp : Experiment
        The experiment.
    store : ResultStore
        Where results live.
    trials : int or None, optional
        Keyword-only. Trials per cell; ``None`` uses the experiment's own
        default.
    cells : Sequence of str or None, optional
        Keyword-only. Restrict to these cells.
    retain_transcript : bool or None, optional
        Keyword-only. Override every cell's transcript-retention setting.

    Returns
    -------
    list of TrialSpec
        In cell order then index order, which is deterministic and is what
        makes two runs of the same command hand out the same work -- though
        the *results* would be identical either way, since a trial's seed
        comes from its identity and not from its position in this list.

    Raises
    ------
    KeyError
        If ``cells`` names a cell the experiment does not have.
    ValueError
        If ``trials`` is not positive. Zero is refused rather than treated as
        "run nothing", because a sweep that silently does nothing and reports
        success is indistinguishable from one that worked.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.runner import plan_trials
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     specs = plan_trials(experiment("honest"), ResultStore(Path(tmp)),
    ...                         trials=2, cells=["l192", "l384"])
    ...     [(s.cell, s.index) for s in specs]
    [('l192', 0), ('l192', 1), ('l384', 0), ('l384', 1)]
    """
    count = exp.trials if trials is None else int(trials)
    if count <= 0:
        raise ValueError(f"trials must be positive, got {count}")
    specs: list[TrialSpec] = []
    for cell in all_cells(exp, cells):
        for index in range(count):
            if store.has(exp.name, cell.name, index):
                continue
            specs.append(
                TrialSpec(
                    experiment=exp.name,
                    cell=cell.name,
                    index=index,
                    results_root=str(store.root),
                    retain_transcript=retain_transcript,
                )
            )
    return specs


def _report(message: str, quiet: bool) -> None:
    """Write a progress line to stderr.

    Parameters
    ----------
    message : str
        The line.
    quiet : bool
        Suppress output.
    """
    if not quiet:
        print(message, file=sys.stderr, flush=True)


def run_experiment(
    exp: Experiment,
    store: ResultStore,
    *,
    trials: int | None = None,
    cells: Sequence[str] | None = None,
    workers: int = 1,
    chunk: int = 1,
    in_process: bool = False,
    retain_transcript: bool | None = None,
    quiet: bool = False,
    progress_every: int = 1,
) -> dict[str, Any]:
    """Run every outstanding trial of one experiment and return what happened.

    Parameters
    ----------
    exp : Experiment
        The experiment.
    store : ResultStore
        Where results go.
    trials : int or None, optional
        Keyword-only. Trials per cell.
    cells : Sequence of str or None, optional
        Keyword-only. Restrict to these cells.
    workers : int, optional
        Keyword-only. Pool size. ``1`` still uses a pool of one, so that the
        one-worker baseline of a speedup curve runs the same code in the same
        kind of process as the twenty-worker point. Comparing an in-parent
        serial run against pooled workers would compare two environments and
        call the difference a speedup.
    chunk : int, optional
        Keyword-only. Tasks handed over per message; see :ref:`spawn-not-fork`
        for why the default is one.
    in_process : bool, optional
        Keyword-only. Bypass the pool entirely and run in this process. For
        tests and debugging; never for a published timing.
    retain_transcript : bool or None, optional
        Keyword-only. Override the cells' transcript retention.
    quiet : bool, optional
        Keyword-only. Suppress progress output.
    progress_every : int, optional
        Keyword-only. Print a progress line every this many completions.

    Returns
    -------
    dict
        ``ran``, ``skipped``, ``failed``, ``wall_clock_seconds``,
        ``outcomes`` (a list of :meth:`TrialOutcome.to_dict`), ``errors``, and
        ``global_rng_touched`` -- the identities of any trial that moved a
        global random state, which must be empty (D3).

    Raises
    ------
    ValueError
        If ``workers`` or ``chunk`` is not positive.

    Notes
    -----
    A trial that raises is counted and named, and its file is not written, so
    the next pass retries it. That is the right behaviour for a sweep measured
    in hours: one bad cell should cost that cell.
    """
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError(f"workers must be a positive int, got {workers!r}")
    if isinstance(chunk, bool) or not isinstance(chunk, int) or chunk < 1:
        raise ValueError(f"chunk must be a positive int, got {chunk!r}")

    requested = exp.trials if trials is None else int(trials)
    planned = plan_trials(
        exp,
        store,
        trials=requested,
        cells=cells,
        retain_transcript=retain_transcript,
    )
    selected = all_cells(exp, cells)
    skipped = requested * len(selected) - len(planned)

    outcomes: list[TrialOutcome] = []
    started = time.perf_counter()
    total = len(planned)
    if total:
        _report(
            f"[sweep] {exp.name}: {total} trials to run, {skipped} already on "
            f"disk, {workers} worker(s)"
            + (" (in-process)" if in_process else ""),
            quiet,
        )

    def note(done: int, outcome: TrialOutcome) -> None:
        if done % max(1, progress_every) and done != total:
            return
        elapsed = time.perf_counter() - started
        rate = done / elapsed if elapsed > 0 else 0.0
        remaining = (total - done) / rate if rate > 0 else float("nan")
        _report(
            f"[sweep] {done}/{total} {outcome.cell}#{outcome.index} "
            f"{outcome.seconds:.2f}s pid={outcome.pid} "
            f"| {rate:.2f} trial/s, ~{remaining / 60:.1f} min left",
            quiet,
        )

    try:
        if in_process or not planned:
            for done, spec in enumerate(planned, start=1):
                outcome = _execute(spec)
                outcomes.append(outcome)
                note(done, outcome)
        else:
            with ProcessPoolExecutor(max_workers=workers) as pool:
                for done, outcome in enumerate(
                    pool.map(_execute, planned, chunksize=chunk), start=1
                ):
                    outcomes.append(outcome)
                    note(done, outcome)
    except KeyboardInterrupt:
        _report(
            f"[sweep] interrupted after {len(outcomes)}/{total}; every "
            f"finished trial is on disk and the next run resumes from there.",
            quiet,
        )
        raise

    wall = time.perf_counter() - started
    failed = [o for o in outcomes if o.error is not None]
    touched = [o for o in outcomes if o.touched_global_rng]
    if touched:
        _report(
            f"[sweep] D3 VIOLATION: {len(touched)} trial(s) moved a global "
            f"random state. Results are not reproducible from their seeds.",
            quiet,
        )
    return {
        "ran": len(outcomes) - len(failed),
        "skipped": skipped,
        "failed": len(failed),
        "wall_clock_seconds": wall,
        "outcomes": [o.to_dict() for o in outcomes],
        "errors": [f"{o.cell}#{o.index}: {o.error}" for o in failed],
        "global_rng_touched": [f"{o.cell}#{o.index}" for o in touched],
    }


def probe_pool(workers: int = 1) -> list[dict[str, Any]]:
    """Ask each of ``workers`` processes what its environment looks like.

    Parameters
    ----------
    workers : int, optional
        Pool size.

    Returns
    -------
    list of dict
        One :func:`worker_probe` report per task submitted. Distinct ``pid``
        values confirm the pool really is several processes; the ``blas_env``
        values confirm the pinning reached them.

    Raises
    ------
    ValueError
        If ``workers`` is not a positive integer.

    Notes
    -----
    Tasks are not pinned to workers, so ``workers`` reports may come from
    fewer than ``workers`` processes on a fast probe. What the probe answers
    is "did the environment arrive", which is the same for every worker in the
    pool; the speedup curve is what answers "are they really running at once".
    """
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError(f"workers must be a positive int, got {workers!r}")
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_probe_task, range(workers * 2)))


def _probe_task(_: int) -> dict[str, Any]:
    """Run :func:`worker_probe` in a pool worker.

    Parameters
    ----------
    _ : int
        Ignored; :meth:`~concurrent.futures.Executor.map` needs an argument.

    Returns
    -------
    dict
    """
    time.sleep(0.02)
    return worker_probe()



def default_results_root() -> Path:
    """Return the results directory a sweep writes to when none is given.

    Returns
    -------
    pathlib.Path
        :data:`~sih141.eval.store.DEFAULT_RESULTS_ROOT`, which is outside the
        repository.
    """
    from .store import DEFAULT_RESULTS_ROOT

    return DEFAULT_RESULTS_ROOT

