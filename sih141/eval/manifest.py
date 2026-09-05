"""The file that makes D9 checkable rather than aspirational.

D9 says every published figure must be derivable by running one committed
command against recorded seeds. A manifest is what turns that from a promise
into something a reviewer can act on without asking anyone a question: it
records the commit the code was at, the command that was typed, the seed
derivation the trials ran under, the worker count, the machine, and when the
run started and stopped.

The fields that are easy to leave out and expensive to lack:

``git_commit`` **and** ``git_dirty``
    A commit alone is a claim about code that may not have been the code that
    ran. If the tree was dirty the manifest says so, and the figure it produced
    is not reproducible until the tree is committed. Better a manifest that
    admits it than one that implies otherwise.
``command_line``
    Reconstructed from :data:`sys.argv` with shell quoting applied, so it can
    be pasted rather than paraphrased. This is the "committed command" half of
    D9; without it the seeds alone do not say what was run against them.
``seed_derivation``
    Not the seeds -- there may be thousands -- but the rule, quoted from
    :mod:`sih141.eval.seeds`, plus the domain string and the pattern names must
    match. Every individual seed is on its own trial's record anyway.
``machine["blas_env"]``
    The classic parallel own-goal is numpy spawning an OpenMP pool inside every
    worker: twenty workers each spawning twenty BLAS threads is four hundred
    threads over twenty-eight logical cores, and the parallel run comes out
    slower than the serial one. The manifest records the thread limits as this
    process reads them, and ``tools/sweep.py`` adds what a *worker* reported
    seeing -- because setting the variables after numpy is imported is a no-op
    that looks identical from the outside, so only the worker's own report
    settles it.

Examples
--------
>>> from sih141.eval.manifest import RunManifest, machine_facts
>>> facts = machine_facts()
>>> sorted(facts)
['blas_env', 'cpu_count_logical', 'machine', 'numpy', 'platform', 'processor', 'python']
>>> manifest = RunManifest.begin(
...     experiment="honest",
...     cells=("l192",),
...     trials=4,
...     workers=1,
...     results_root="/tmp/results",
...     eps=1e-9,
...     command_line="python tools/sweep.py run honest --trials 4",
... )
>>> manifest.finished_at is None
True
>>> done = manifest.finish(ran=4, skipped=0, failed=0, wall_clock_seconds=1.5)
>>> done.finished_at is None
False
>>> done.to_dict()["trials_ran"], done.to_dict()["trials_skipped"]
(4, 0)
>>> done.to_dict()["seed_derivation"]["domain"]
'sih141/eval/seed/v1'
"""

from __future__ import annotations

import os
import platform
import shlex
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Sequence

from .seeds import ADVERSARY_ROLE, NAME_PATTERN, SEED_DOMAIN, SEED_PERSON, SESSION_ROLE

__all__ = [
    "HARNESS_VERSION",
    "MANIFEST_SCHEMA",
    "RunManifest",
    "command_line",
    "git_state",
    "machine_facts",
    "seed_derivation",
    "utc_now",
]

HARNESS_VERSION: Final[str] = "1.0.0"
"""str: Version of the evaluation harness itself, recorded in every manifest."""

MANIFEST_SCHEMA: Final[str] = "sih141/eval/manifest/v1"
"""str: Schema tag, so a reader can refuse a manifest it does not understand."""

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix.

    Returns
    -------
    str
        Second resolution. Used for manifest timestamps and manifest
        filenames, so it must not contain a colon on Windows -- see
        :meth:`RunManifest.filename`.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def git_state(root: Path | None = None) -> dict[str, Any]:
    """Return the commit the code is at and whether the tree was dirty.

    Parameters
    ----------
    root : pathlib.Path or None, optional
        Repository root. Defaults to this package's repository.

    Returns
    -------
    dict
        ``commit``, ``dirty`` and ``branch``. Every value is ``None`` if git is
        unavailable or the directory is not a repository, which is reported
        rather than raised: a sweep must still run from a source tarball, it
        just cannot claim reproducibility from a commit it does not have.

    Notes
    -----
    ``dirty`` being ``True`` is not an error here, but it is a caveat on every
    number the run produces, and the reduction prints it next to the table.
    """
    directory = Path(root) if root is not None else _REPO_ROOT
    state: dict[str, Any] = {"commit": None, "dirty": None, "branch": None}

    def ask(*args: str) -> str | None:
        try:
            done = subprocess.run(
                ["git", *args],
                cwd=str(directory),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if done.returncode != 0:
            return None
        return done.stdout.strip()

    state["commit"] = ask("rev-parse", "HEAD")
    state["branch"] = ask("rev-parse", "--abbrev-ref", "HEAD")
    status = ask("status", "--porcelain")
    if status is not None:
        state["dirty"] = status != ""
    return state


def machine_facts() -> dict[str, Any]:
    """Return what the run was executed on.

    Returns
    -------
    dict
        Platform, processor, logical CPU count, Python and numpy versions, and
        the BLAS thread-limit environment as it stands in this process.

    Notes
    -----
    ``cpu_count_logical`` is :func:`os.cpu_count`, which on this machine's
    i7-14700HX reports 28 -- eight P-cores with SMT plus twelve E-cores, for
    twenty physical. There is no portable stdlib call for the physical count,
    so it is not claimed here; the achieved speedup curve is what actually
    answers the question anyway.
    """
    import numpy as np

    return {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "cpu_count_logical": os.cpu_count(),
        "python": sys.version.split()[0],
        "numpy": np.__version__,
        "blas_env": {
            name: os.environ.get(name)
            for name in (
                "OMP_NUM_THREADS",
                "MKL_NUM_THREADS",
                "OPENBLAS_NUM_THREADS",
                "NUMEXPR_NUM_THREADS",
                "VECLIB_MAXIMUM_THREADS",
            )
        },
    }


def seed_derivation() -> dict[str, Any]:
    """Return the seed rule in a form a reviewer can re-implement.

    Returns
    -------
    dict
        The domain string, the BLAKE2b personalisation, the digest size, the
        role names and the name pattern -- everything
        :func:`~sih141.eval.seeds.trial_seed` reads. The prose version is in
        that module's docstring under :ref:`seed-derivation`.
    """
    return {
        "function": "sih141.eval.seeds.trial_seed",
        "domain": SEED_DOMAIN.decode("ascii"),
        "person": SEED_PERSON.decode("ascii"),
        "hash": "blake2b",
        "digest_size_bytes": 8,
        "separator": "0x00",
        "material": (
            "domain || 0x00 || utf8(experiment) || 0x00 || utf8(cell) || 0x00 "
            "|| utf8(role) || 0x00 || ascii(decimal(index))"
        ),
        "roles": [SESSION_ROLE, ADVERSARY_ROLE],
        "name_pattern": NAME_PATTERN.pattern,
    }


def command_line(argv: Sequence[str] | None = None) -> str:
    """Return the command that started this process, quoted for a shell.

    Parameters
    ----------
    argv : Sequence of str or None, optional
        Defaults to :data:`sys.argv`.

    Returns
    -------
    str
        ``python <argv...>``, with each element quoted so a path containing a
        space -- which this repository's own path does -- survives a
        copy-paste.

    Examples
    --------
    >>> from sih141.eval.manifest import command_line
    >>> command_line(["tools/sweep.py", "run", "honest", "--trials", "4"])
    'python tools/sweep.py run honest --trials 4'
    >>> command_line(["a b/sweep.py", "run"])
    "python 'a b/sweep.py' run"
    """
    parts = list(sys.argv if argv is None else argv)
    return "python " + " ".join(shlex.quote(part) for part in parts)


_default_command_line = command_line
"""Module-level alias, because ``RunManifest.begin`` has a parameter of the
same name and a shadowed function is the kind of thing that silently becomes a
``TypeError: str object is not callable`` on a path nothing exercises."""


@dataclass(frozen=True)
class RunManifest:
    """Everything needed to re-run a sweep, written before and after it.

    Built by :meth:`begin` at the top of a run and rewritten by :meth:`finish`
    at the bottom. The first write is not a formality: a run that dies leaves a
    manifest whose ``finished_at`` is ``None``, which is how a later reader
    knows the cell is partial rather than complete-and-small.

    Attributes
    ----------
    schema : str
        :data:`MANIFEST_SCHEMA`.
    harness_version : str
        :data:`HARNESS_VERSION`.
    experiment : str
        Which experiment ran.
    cells : tuple of str
        Which cells were asked for.
    trials : int
        Trials requested per cell.
    workers : int
        Process count. ``1`` means the pool was bypassed entirely.
    results_root : str
        Where the per-trial files went.
    eps : float
        Detector budget every trial was scored at.
    command_line : str
        The command, quoted.
    git : dict
        As :func:`git_state`.
    machine : dict
        As :func:`machine_facts`.
    seed_derivation : dict
        As :func:`seed_derivation`.
    started_at : str
        UTC, ISO-8601.
    finished_at : str or None
        UTC, or ``None`` while the run is in flight or was interrupted.
    trials_ran, trials_skipped, trials_failed : int
        What the run actually did. ``skipped`` are trials already on disk.
    wall_clock_seconds : float or None
        End to end, including the pool's startup.
    notes : str
        Free text.
    """

    schema: str
    harness_version: str
    experiment: str
    cells: tuple[str, ...]
    trials: int
    workers: int
    results_root: str
    eps: float
    command_line: str
    git: dict[str, Any]
    machine: dict[str, Any]
    seed_derivation: dict[str, Any]
    started_at: str
    finished_at: str | None = None
    trials_ran: int = 0
    trials_skipped: int = 0
    trials_failed: int = 0
    wall_clock_seconds: float | None = None
    notes: str = ""

    @classmethod
    def begin(
        cls,
        *,
        experiment: str,
        cells: Sequence[str],
        trials: int,
        workers: int,
        results_root: Path | str,
        eps: float,
        command_line: str | None = None,
        notes: str = "",
    ) -> RunManifest:
        """Open a manifest at the start of a run.

        Parameters
        ----------
        experiment : str
            Experiment name.
        cells : Sequence of str
            Cell names being run.
        trials : int
            Trials per cell.
        workers : int
            Process count.
        results_root : pathlib.Path or str
            Results directory.
        eps : float
            Detector budget.
        command_line : str or None, optional
            Defaults to the real one, from :data:`sys.argv`.
        notes : str, optional
            Free text.

        Returns
        -------
        RunManifest
            With ``finished_at`` ``None``.
        """
        return cls(
            schema=MANIFEST_SCHEMA,
            harness_version=HARNESS_VERSION,
            experiment=experiment,
            cells=tuple(cells),
            trials=int(trials),
            workers=int(workers),
            results_root=str(results_root),
            eps=float(eps),
            command_line=(
                _default_command_line() if command_line is None else command_line
            ),
            git=git_state(),
            machine=machine_facts(),
            seed_derivation=seed_derivation(),
            started_at=utc_now(),
            notes=notes,
        )

    def finish(
        self,
        *,
        ran: int,
        skipped: int,
        failed: int,
        wall_clock_seconds: float,
    ) -> RunManifest:
        """Return a closed copy of this manifest.

        Parameters
        ----------
        ran : int
            Trials executed this pass.
        skipped : int
            Trials already on disk and left alone.
        failed : int
            Trials that raised.
        wall_clock_seconds : float
            End to end.

        Returns
        -------
        RunManifest
            A new manifest; the original is frozen and unchanged.
        """
        return replace(
            self,
            finished_at=utc_now(),
            trials_ran=int(ran),
            trials_skipped=int(skipped),
            trials_failed=int(failed),
            wall_clock_seconds=float(wall_clock_seconds),
        )

    def filename(self) -> str:
        """Return the stem this manifest should be stored under.

        Returns
        -------
        str
            ``manifest-<start time>``, with the ISO timestamp's colons removed
            because Windows forbids them in filenames. Two passes over the same
            experiment therefore leave two manifests rather than one
            overwriting the other, and the pair is the record of what each pass
            did.

        Examples
        --------
        >>> from sih141.eval.manifest import RunManifest
        >>> manifest = RunManifest.begin(
        ...     experiment="honest", cells=("l192",), trials=1, workers=1,
        ...     results_root=".", eps=1e-9, command_line="python x",
        ... )
        >>> manifest.filename().startswith("manifest-")
        True
        >>> ":" in manifest.filename()
        False
        """
        stamp = self.started_at.replace(":", "").replace("-", "")
        return f"manifest-{stamp}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "schema": self.schema,
            "harness_version": self.harness_version,
            "experiment": self.experiment,
            "cells": list(self.cells),
            "trials": self.trials,
            "workers": self.workers,
            "results_root": self.results_root,
            "eps": self.eps,
            "command_line": self.command_line,
            "git": self.git,
            "machine": self.machine,
            "seed_derivation": self.seed_derivation,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "trials_ran": self.trials_ran,
            "trials_skipped": self.trials_skipped,
            "trials_failed": self.trials_failed,
            "wall_clock_seconds": self.wall_clock_seconds,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunManifest:
        """Rebuild from :meth:`to_dict` output.

        Parameters
        ----------
        data : dict
            As produced by :meth:`to_dict`.

        Returns
        -------
        RunManifest

        Raises
        ------
        ValueError
            If the schema tag is not :data:`MANIFEST_SCHEMA`.
        """
        if data.get("schema") != MANIFEST_SCHEMA:
            raise ValueError(
                f"manifest schema {data.get('schema')!r} is not "
                f"{MANIFEST_SCHEMA!r}"
            )
        return cls(
            schema=str(data["schema"]),
            harness_version=str(data["harness_version"]),
            experiment=str(data["experiment"]),
            cells=tuple(data["cells"]),
            trials=int(data["trials"]),
            workers=int(data["workers"]),
            results_root=str(data["results_root"]),
            eps=float(data["eps"]),
            command_line=str(data["command_line"]),
            git=dict(data["git"]),
            machine=dict(data["machine"]),
            seed_derivation=dict(data["seed_derivation"]),
            started_at=str(data["started_at"]),
            finished_at=data.get("finished_at"),
            trials_ran=int(data.get("trials_ran", 0)),
            trials_skipped=int(data.get("trials_skipped", 0)),
            trials_failed=int(data.get("trials_failed", 0)),
            wall_clock_seconds=data.get("wall_clock_seconds"),
            notes=str(data.get("notes", "")),
        )
