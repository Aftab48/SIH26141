"""One file per trial, on disk, named from the trial's identity.

A sweep at production parameters is measured in hours, and this machine
hibernates. That has already cost this project one long run -- it baked
``"<no summary line>"`` into ``docs/METRICS.md`` -- so the storage layer is
built around the assumption that the process will die mid-sweep:

* **One file per trial**, written the moment that trial finishes, by the worker
  that finished it. Nothing is held in memory until the end and nothing is
  batched, so an interruption costs the trial in flight and not the run.
* **Named from identity**, ``<root>/<experiment>/<cell>/trial-000042.json``,
  where the identity is exactly what
  :func:`~sih141.eval.seeds.trial_seed` hashes. So :meth:`ResultStore.has`
  answers "already done?" from the filename alone, without opening anything,
  and a resumed sweep skips what is there.
* **Written atomically.** A partial file is worse than a missing one, because
  the filename says "done" while the contents say nothing. Every write goes to
  a temporary name in the same directory and is then :func:`os.replace`\\ d,
  which is atomic on Windows and POSIX alike.

.. _outside-the-repo:

Where results go
----------------
:data:`DEFAULT_RESULTS_ROOT` is **outside the repository**, under the user's
home directory, because raw per-trial files are never committed -- only reduced
tables are. Committing them would be a mistake of a familiar shape: a reviewer
seeing 200 JSON files in the tree would take them for the evidence, when the
evidence is the seed plus the command, and the files are just a cache of a
computation anyone can redo. ``.gitignore`` also carries the in-tree names in
case someone points ``--results`` at the working copy.

Examples
--------
>>> import tempfile
>>> from pathlib import Path
>>> from sih141.eval.store import ResultStore
>>> with tempfile.TemporaryDirectory() as tmp:
...     store = ResultStore(Path(tmp) / "results")
...     store.has("honest", "l192", 0)
...     store.path_for("honest", "l192", 42).name
False
'trial-000042.json'
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

from .records import TrialRecord
from .seeds import check_name

__all__ = [
    "DEFAULT_RESULTS_ROOT",
    "MANIFEST_GLOB",
    "ResultStore",
    "TRIAL_GLOB",
]

DEFAULT_RESULTS_ROOT: Final[Path] = Path.home() / ".sih141" / "results"
"""pathlib.Path: Where a sweep writes when ``--results`` is not given.

Outside the repository on purpose; see :ref:`outside-the-repo`.
"""

TRIAL_GLOB: Final[str] = "trial-*.json"
"""str: How a cell directory's trial files are found."""

MANIFEST_GLOB: Final[str] = "manifest-*.json"
"""str: How an experiment directory's run manifests are found."""


class ResultStore:
    """A results directory, addressed by trial identity.

    Parameters
    ----------
    root : pathlib.Path or str
        The results root. Created on demand; nothing is created by the
        constructor, so building a store to *read* an absent directory is not
        an error and reports zero trials.

    Raises
    ------
    TypeError
        If ``root`` is not a path or string.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp) / "absent")
    ...     list(store.experiments()), list(store.cells("nothing"))
    ([], [])
    """

    def __init__(self, root: Path | str) -> None:
        if not isinstance(root, (Path, str)):
            raise TypeError(f"root must be a Path or str, got {type(root).__name__}")
        self._root = Path(root)

    @property
    def root(self) -> Path:
        """pathlib.Path: The results root."""
        return self._root

    def __repr__(self) -> str:
        """Return a debugging representation.

        Returns
        -------
        str
        """
        return f"ResultStore({str(self._root)!r})"

    def cell_dir(self, experiment: str, cell: str) -> Path:
        """Return the directory holding one cell's trials.

        Parameters
        ----------
        experiment : str
            Experiment name.
        cell : str
            Cell name.

        Returns
        -------
        pathlib.Path

        Raises
        ------
        ValueError
            If either name is not a legal identity component. That check is
            what keeps a name from escaping the results root.
        """
        check_name(experiment, what="experiment")
        check_name(cell, what="cell")
        return self._root / experiment / cell

    def path_for(self, experiment: str, cell: str, index: int) -> Path:
        """Return the file one trial's record lives at.

        Parameters
        ----------
        experiment : str
            Experiment name.
        cell : str
            Cell name.
        index : int
            Trial index.

        Returns
        -------
        pathlib.Path

        Raises
        ------
        TypeError
            If ``index`` is not an integer.
        ValueError
            If ``index`` is negative, or a name is illegal.

        Notes
        -----
        Six zero-padded digits, so a directory listing sorts in trial order and
        a million trials per cell fit before the padding gives out. Beyond that
        the name simply grows and sorting by name stops matching sorting by
        index -- which is why every reader here sorts by the parsed index
        instead.
        """
        if isinstance(index, bool) or not isinstance(index, int):
            raise TypeError(f"index must be an int, got {type(index).__name__}")
        if index < 0:
            raise ValueError(f"index must be non-negative, got {index}")
        return self.cell_dir(experiment, cell) / f"trial-{index:06d}.json"

    def has(self, experiment: str, cell: str, index: int) -> bool:
        """Return whether this trial is already on disk.

        Parameters
        ----------
        experiment : str
            Experiment name.
        cell : str
            Cell name.
        index : int
            Trial index.

        Returns
        -------
        bool
            Whether the file exists. Because writes are atomic, existence
            means the record is complete: there is no state in which the name
            is present and the contents are half a record.
        """
        return self.path_for(experiment, cell, index).is_file()

    def write(self, record: TrialRecord) -> Path:
        """Write one record atomically and return where it went.

        Parameters
        ----------
        record : TrialRecord
            The finished trial.

        Returns
        -------
        pathlib.Path
            The record's final path.

        Raises
        ------
        TypeError
            If ``record`` is not a :class:`~sih141.eval.records.TrialRecord`.

        Notes
        -----
        The temporary file is created in the destination directory rather than
        the system temp directory, because :func:`os.replace` is only atomic
        within a filesystem and the two are routinely on different drives on
        Windows.
        """
        if not isinstance(record, TrialRecord):
            raise TypeError(
                f"record must be a TrialRecord, got {type(record).__name__}"
            )
        destination = self.path_for(*record.identity)
        destination.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(
            dir=str(destination.parent), prefix=".trial-", suffix=".tmp"
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(record.to_dict(), stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return destination

    def read(self, experiment: str, cell: str, index: int) -> TrialRecord:
        """Read one record back.

        Parameters
        ----------
        experiment : str
            Experiment name.
        cell : str
            Cell name.
        index : int
            Trial index.

        Returns
        -------
        TrialRecord

        Raises
        ------
        FileNotFoundError
            If the trial is not on disk.
        ValueError
            If the file is not a record of the current schema.
        """
        path = self.path_for(experiment, cell, index)
        with path.open("r", encoding="utf-8") as stream:
            return TrialRecord.from_dict(json.load(stream))

    def experiments(self) -> list[str]:
        """Return the experiment names present, sorted.

        Returns
        -------
        list of str
        """
        if not self._root.is_dir():
            return []
        return sorted(p.name for p in self._root.iterdir() if p.is_dir())

    def cells(self, experiment: str) -> list[str]:
        """Return one experiment's cell names, sorted.

        Parameters
        ----------
        experiment : str
            Experiment name.

        Returns
        -------
        list of str
            Empty if the experiment is not on disk.
        """
        directory = self._root / experiment
        if not directory.is_dir():
            return []
        return sorted(p.name for p in directory.iterdir() if p.is_dir())

    def indices(self, experiment: str, cell: str) -> list[int]:
        """Return the trial indices present in one cell, sorted numerically.

        Parameters
        ----------
        experiment : str
            Experiment name.
        cell : str
            Cell name.

        Returns
        -------
        list of int
            Sorted by index, not by filename, so the order is stable past six
            digits. A file whose stem does not parse as an index is skipped
            rather than raising: the sweep must survive junk in its own output
            directory.
        """
        directory = self.cell_dir(experiment, cell)
        if not directory.is_dir():
            return []
        found: list[int] = []
        for path in directory.glob(TRIAL_GLOB):
            stem = path.stem.removeprefix("trial-")
            if stem.isdigit():
                found.append(int(stem))
        return sorted(found)

    def read_cell(self, experiment: str, cell: str) -> list[TrialRecord]:
        """Read one cell's records, in trial-index order.

        Parameters
        ----------
        experiment : str
            Experiment name.
        cell : str
            Cell name.

        Returns
        -------
        list of TrialRecord
            Ordered by :attr:`~sih141.eval.records.TrialRecord.index`, never by
            completion order or by directory order -- that is what makes a
            reduction independent of the order twenty workers happened to
            finish in.
        """
        return [
            self.read(experiment, cell, index)
            for index in self.indices(experiment, cell)
        ]

    def read_experiment(self, experiment: str) -> Iterator[TrialRecord]:
        """Yield every record in one experiment, cell by cell, index by index.

        Parameters
        ----------
        experiment : str
            Experiment name.

        Yields
        ------
        TrialRecord
        """
        for cell in self.cells(experiment):
            yield from self.read_cell(experiment, cell)

    def count(self, experiment: str, cell: str | None = None) -> int:
        """Return how many trials are on disk.

        Parameters
        ----------
        experiment : str
            Experiment name.
        cell : str or None, optional
            One cell, or ``None`` for the whole experiment.

        Returns
        -------
        int
        """
        if cell is not None:
            return len(self.indices(experiment, cell))
        return sum(len(self.indices(experiment, c)) for c in self.cells(experiment))

    def write_manifest(self, experiment: str, name: str, payload: Any) -> Path:
        """Write a run manifest into the experiment's directory.

        Parameters
        ----------
        experiment : str
            Experiment name.
        name : str
            Filename stem, normally ``manifest-<utc timestamp>``. Manifests are
            never overwritten by a later run, so a resumed sweep leaves two and
            the pair records what each pass actually did.
        payload : object
            JSON-serialisable manifest content.

        Returns
        -------
        pathlib.Path

        Raises
        ------
        TypeError
            If ``experiment`` is not a string.
        ValueError
            If ``experiment`` is not a legal identity component.
        """
        check_name(experiment, what="experiment")
        directory = self._root / experiment
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{name}.json"
        handle, temporary = tempfile.mkstemp(
            dir=str(directory), prefix=".manifest-", suffix=".tmp"
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, sort_keys=True, default=str)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return path

    def manifests(self, experiment: str) -> list[Path]:
        """Return one experiment's manifest files, oldest name first.

        Parameters
        ----------
        experiment : str
            Experiment name.

        Returns
        -------
        list of pathlib.Path
        """
        directory = self._root / experiment
        if not directory.is_dir():
            return []
        return sorted(directory.glob(MANIFEST_GLOB))
