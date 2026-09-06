"""Records to tables, with every way a Phase 5 table can quietly lie closed off.

Reduction is a separate command from running for a practical reason and a
methodological one. Practically, the sweep is measured in hours and the tables
are redrawn constantly; nobody would re-check a table that costs fourteen hours
to regenerate. Methodologically, a reduction that can only run inside the sweep
cannot be re-run by a reviewer against the same files, and D9 is exactly the
claim that it can.

What the reduction refuses to do
--------------------------------
These come out of the Phase 3 and Phase 4 audits and are constraints on the
*table*, not just the code that fills it. Each is enforced here rather than
documented and hoped for.

**A no-verdict is not a rejection.** :func:`outcome_table` counts through
:class:`~sih141.detect.thresholds_structural.OutcomeTally`, which has no field
summing a rejection with a refusal and whose two no-verdict counts raise if
added to an ``int``. A row reading "detection 92%" with 8% silently aborted is a
false claim, so every rate here prints its denominator and the aborts appear as
their own column.

**The two count orderings are never pooled.** ``count_exchange_timing`` is part
of the grouping key of every table, so one cell can become two rows; it is never
averaged over. The two orderings give different answers to the same attack, and
a merged row averages a forgery rate with a denial-of-service rate.

**Measured is not proven.** A detection rate is a measurement with a sample
size and a Wilson interval, and the column says ``measured``. A false-positive
bound is proven under the honest null, and that column says ``proven``. There is
no false-negative bound and there cannot be one from a transcript, so nothing
here ever prints one.

**An unevaluated family is not a passed one.** ``Detection.withheld`` names the
families that could not be scored -- with no check rounds the whole channel
family is unevaluable -- and those appear as ``not evaluated``.

**A hypothesis ruled out by assumption is named, not blank.** A cell whose
ground truth says ``detectable=False`` prints
:data:`~sih141.eval.records.UNDETECTABLE_BY_CONSTRUCTION`. A missing row reads
as a hypothesis that was ruled out; a zero reads as one we tried and failed to
catch.

**A null that was not the truth is a column.** ``null_is_noiseless`` rides on
every detection row, because a mismatch-rate detection under a noiseless null on
a genuinely noisy link is arithmetically correct and still a false claim once
the null goes unstated.

Examples
--------
>>> import tempfile
>>> from pathlib import Path
>>> from sih141.eval.experiments import experiment
>>> from sih141.eval.reduce import outcome_table, reduce_experiment
>>> from sih141.eval.runner import run_experiment
>>> from sih141.eval.store import ResultStore
>>> with tempfile.TemporaryDirectory() as tmp:
...     store = ResultStore(Path(tmp))
...     _ = run_experiment(experiment("smoke"), store, trials=3, workers=1,
...                        in_process=True, quiet=True)
...     records = list(store.read_experiment("smoke"))
...     table = outcome_table(records)
...     len(records)
...     table.columns
...     table.rows[0][:6]
3
('cell', 'count_exchange_timing', 'runs', 'parties', 'accepted', 'rejected', 'refused', 'not_asked')
('tiny', 'before-forwarding', 3, 6, 6, 0)

Reduction is a pure function of what is on disk, so it gives the same tables
however many workers wrote them:

>>> with tempfile.TemporaryDirectory() as tmp:
...     store = ResultStore(Path(tmp))
...     _ = run_experiment(experiment("smoke"), store, trials=3, workers=1,
...                        in_process=True, quiet=True)
...     tables = reduce_experiment(store, "smoke")
...     [t.slug for t in tables]
['outcomes', 'detection', 'timing']
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Final, Iterable, Mapping, Sequence

from sih141.detect.statistics import wilson_interval
from sih141.detect.thresholds_structural import NoVerdictCount, OutcomeTally

from .experiments import EXPERIMENTS
from .records import (
    UNDETECTABLE_ASSUMPTION,
    UNDETECTABLE_BY_CONSTRUCTION,
    TrialRecord,
)
from .store import ResultStore

__all__ = [
    "CONFIDENCE",
    "EXTRA_CHARTS",
    "EXTRA_REDUCTIONS",
    "NOT_EVALUATED",
    "VARIANT_MARKERS",
    "Table",
    "completeness_note",
    "detection_table",
    "escape_xml",
    "expected_trials",
    "group_records",
    "measured_rate",
    "outcome_table",
    "reduce_experiment",
    "refused_run",
    "tally_from_record",
    "timing_table",
]

EXTRA_REDUCTIONS: Final[dict[str, Any]] = {}
"""dict: Per-experiment reductions, appended after the three standard tables.

An experiment family that needs a table of its own registers here, keyed by
experiment name, with a callable taking
``(records, *, command, cell_order, expected)`` and returning a list of
:class:`Table`. ``expected`` is :func:`expected_trials` for this store -- the
per-cell trial count the sweep was *asked* for -- because a family building its
own completeness footnote without it can only check for interior gaps, and the
note it then writes has to say so. :func:`reduce_experiment` consults it,
so ``python tools/sweep.py reduce <name>`` picks the extra tables up with no
change to the command line and no second reduction path for a reviewer to miss.

Empty here on purpose: the three standard tables are what every experiment
supports, and a family that needs more says so from its own module.
"""

EXTRA_CHARTS: Final[dict[str, Any]] = {}
"""dict: Per-experiment chart renderers, keyed by experiment name.

Same shape as :data:`EXTRA_REDUCTIONS` but returning a mapping of filename to
document text, which ``tools/sweep.py reduce --charts DIR`` writes. A chart is
a published figure and D9 applies to it exactly as it does to a table, so a
renderer is handed the same ``command`` string and is expected to print it.
"""

CONFIDENCE: Final[float] = 0.99
"""float: Confidence level for every measured rate's interval.

Ninety-nine percent, not ninety-five, because these samples are small -- tens of
trials, not thousands -- and a narrow-looking interval on thirty trials is the
kind of figure that gets quoted without its ``n``.
"""

NOT_EVALUATED: Final[str] = "not evaluated"
"""str: What a withheld detector family prints. Never ``passed``, never blank."""


@dataclass(frozen=True)
class Table:
    """One results table, with the command that regenerates it attached.

    D9 says a figure must be derivable by running one committed command, and
    that the command must be printed next to the table it produced. So the
    command is a field of the table rather than something a writer is trusted
    to remember: :meth:`to_markdown` prints it, and a table built without one
    prints a line saying it is not reproducible, which is louder than silence.

    Attributes
    ----------
    slug : str
        Short identifier, used as a filename stem.
    title : str
        Human-readable title.
    columns : tuple of str
        Column headers.
    rows : tuple of tuple
        Row data, already formatted or raw -- :meth:`to_markdown` stringifies.
    command : str
        The exact command that regenerates this table.
    notes : tuple of str
        Footnotes. This is where a denominator, a withheld family or an
        assumption goes; a table whose caveat lives only in a docstring has no
        caveat.

    Examples
    --------
    >>> from sih141.eval.reduce import Table
    >>> table = Table(
    ...     slug="demo", title="Demo", columns=("a", "b"),
    ...     rows=((1, 2), (3, 4)),
    ...     command="python tools/sweep.py reduce demo",
    ...     notes=("n = 2 rows",),
    ... )
    >>> print(table.to_markdown())
    ### Demo
    <BLANKLINE>
    | a | b |
    | --- | --- |
    | 1 | 2 |
    | 3 | 4 |
    <BLANKLINE>
    Regenerate: `python tools/sweep.py reduce demo`
    <BLANKLINE>
    - n = 2 rows
    """

    slug: str
    title: str
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]
    command: str = ""
    notes: tuple[str, ...] = ()

    def to_markdown(self) -> str:
        """Render as a GitHub-flavoured markdown table.

        Returns
        -------
        str
            Title, table, the regenerating command, then the notes.
        """
        lines = [f"### {self.title}", ""]
        lines.append("| " + " | ".join(self.columns) + " |")
        lines.append("| " + " | ".join("---" for _ in self.columns) + " |")
        for row in self.rows:
            lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
        lines.append("")
        if self.command:
            lines.append(f"Regenerate: `{self.command}`")
        else:
            lines.append(
                "Regenerate: **no command recorded -- this table is not "
                "reproducible and must not be published (D9)**"
            )
        if self.notes:
            lines.append("")
            for note in self.notes:
                lines.append(f"- {note}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "slug": self.slug,
            "title": self.title,
            "columns": list(self.columns),
            "rows": [list(row) for row in self.rows],
            "command": self.command,
            "notes": list(self.notes),
        }


VARIANT_MARKERS: Final[tuple[str, ...]] = (
    "count_exchange_timing",
    "symmetrised",
    "counts_exchanged",
    "signer_saw_recipient_logs",
    "security_claim",
)
"""tuple of str: The names of ``Detection.grouping_key``'s five elements.

Phase 4 froze that key with "Group by this; never average over it"
(:class:`~sih141.detect.detector.Detection`). Only the first element reaches
the grouping here, because the other four are functions of a cell's parameters
and so are constant inside a cell -- which is an *invariant*, not a
coincidence, and :func:`_refuse_mixed_variant_markers` is where it is checked
rather than assumed.
"""


def _refuse_mixed_variant_markers(
    grouped: Mapping[tuple[str, str], Sequence[TrialRecord]],
) -> None:
    """Refuse to hand back a group that averages over a variant marker.

    ``Detection.grouping_key``'s first element is the count-exchange ordering
    and is part of the group key. The other four --
    ``symmetrised``, ``counts_exchanged``, ``signer_saw_recipient_logs``,
    ``security_claim`` -- are not, because today they are fixed by a cell's
    parameters. If one of them ever varies inside a cell, every table built on
    this grouping would average two different protocols into one row, silently.
    ``signer_saw_recipient_logs`` is the case Phase 4 carried the marker for:
    a run where the signer saw the recipient's logs is not the shipped scheme,
    and no table may quote it as if it were.

    Parameters
    ----------
    grouped : Mapping
        The groups, keyed as :func:`group_records` keys them.

    Raises
    ------
    ValueError
        If a group holds two values of one marker. Records with no
        ``grouping_key`` in their detection payload are skipped: a stand-in
        record in a test is not evidence of a mixed group.
    """
    for (cell, timing), group in grouped.items():
        seen: dict[str, set[Any]] = {}
        for record in group:
            key = record.detection.get("grouping_key")
            if not isinstance(key, (list, tuple)) or len(key) != len(
                VARIANT_MARKERS
            ):
                continue
            for name, value in zip(VARIANT_MARKERS[1:], tuple(key)[1:]):
                seen.setdefault(name, set()).add(value)
        mixed = sorted(name for name, values in seen.items() if len(values) > 1)
        if mixed:
            raise ValueError(
                f"cell {cell!r} ({timing}) mixes two values of "
                + ", ".join(mixed)
                + ": these are grouping_key markers and a table must not "
                "average over them. Split the cell, or widen the group key."
            )


def group_records(
    records: Iterable[TrialRecord],
    *,
    cell_order: Sequence[str] | None = None,
) -> dict[tuple[str, str], list[TrialRecord]]:
    """Group records by ``(cell, count_exchange_timing)``.

    Parameters
    ----------
    records : Iterable of TrialRecord
        Any order; the grouping sorts.
    cell_order : Sequence of str or None, optional
        Keyword-only. Cell names in the order the experiment declares them.
        Without it the rows come out alphabetically, which for a throughput
        table reads ``l12288, l192, l3072, l768`` -- correct, deterministic,
        and useless to a reader looking for a trend. Cells not named here sort
        after the ones that are, so a record whose cell has since left the
        registry still appears.

    Returns
    -------
    dict
        Keyed by cell name and count ordering, in table order, values in
        trial-index order. Two orderings inside one cell become two groups,
        which is the point: the timing is a column, never a thing averaged
        over.

    Raises
    ------
    ValueError
        If a group mixes two values of one of the four ``grouping_key``
        markers that are *not* in the key -- see
        :func:`_refuse_mixed_variant_markers`. Every caller routes through
        here, so the invariant is checked once rather than in each table.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.reduce import group_records
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("smoke"), store, trials=2, workers=1,
    ...                        in_process=True, quiet=True)
    ...     sorted(group_records(store.read_experiment("smoke")))
    [('tiny', 'before-forwarding')]
    """
    grouped: dict[tuple[str, str], list[TrialRecord]] = {}
    for record in records:
        key = (record.cell, record.count_exchange_timing)
        grouped.setdefault(key, []).append(record)
    _refuse_mixed_variant_markers(grouped)
    for group in grouped.values():
        group.sort(key=lambda r: r.index)
    rank = {name: i for i, name in enumerate(cell_order or ())}
    unknown = len(rank)
    return dict(
        sorted(
            grouped.items(),
            key=lambda item: (
                rank.get(item[0][0], unknown),
                item[0][0],
                item[0][1],
            ),
        )
    )


def tally_from_record(record: TrialRecord) -> OutcomeTally:
    """Build one run's outcome tally from its transcript summary.

    Parameters
    ----------
    record : TrialRecord
        One trial.

    Returns
    -------
    OutcomeTally
        With ``runs = 1``. ``not_asked`` counts the verifiers absent from the
        summary entirely, which is a third thing again: a party never asked did
        not refuse, and folding the two together would turn a protocol
        ordering into an apparent refusal rate.

    Notes
    -----
    Built from ``transcript_summary["verdicts"]``, which is written by
    :func:`~sih141.eval.records.transcript_summary` straight off the
    transcript's own results and aborts. The detector reaches the same
    conclusion by a different route and records it as ``detection["outcomes"]``,
    and ``tests/test_eval_harness.py`` asserts the two agree on every record --
    a cross-check that would be vacuous if both columns came from one field.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.reduce import tally_from_record
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("smoke"), store, trials=1, workers=1,
    ...                        in_process=True, quiet=True)
    ...     tally = tally_from_record(store.read("smoke", "tiny", 0))
    ...     (tally.accepted, tally.rejected, tally.refused, tally.not_asked)
    (2, 0, 0, 0)
    """
    verdicts: Mapping[str, str] = record.transcript_summary["verdicts"]
    accepted = sum(1 for v in verdicts.values() if v == "accepted")
    rejected = sum(1 for v in verdicts.values() if v == "rejected")
    refused = sum(1 for v in verdicts.values() if v == "refused")
    not_asked = 2 - len(verdicts)
    return OutcomeTally(
        accepted=accepted,
        rejected=rejected,
        refused=NoVerdictCount(refused),
        not_asked=NoVerdictCount(max(0, not_asked)),
        count_exchange_timing=record.count_exchange_timing,
        runs=1,
    )


def outcome_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> Table:
    """Tabulate what actually happened to each run, aborts kept apart.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. The command that regenerates this table.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order; see :func:`group_records`.

    Returns
    -------
    Table
        One row per ``(cell, count_exchange_timing)``. ``parties`` is the
        denominator for the verdict columns and is printed rather than
        implied: two verifiers per run, always, whatever became of them.

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.reduce import outcome_table
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("smoke"), store, trials=2, workers=1,
    ...                        in_process=True, quiet=True)
    ...     table = outcome_table(list(store.read_experiment("smoke")))
    ...     table.rows
    (('tiny', 'before-forwarding', 2, 4, 4, 0, 0, 0),)
    """
    if not records:
        raise ValueError("outcome_table needs at least one record")
    rows: list[tuple[Any, ...]] = []
    for (cell, timing), group in group_records(
        records, cell_order=cell_order
    ).items():
        tally = tally_from_record(group[0])
        for record in group[1:]:
            tally = tally.merge(tally_from_record(record))
        rows.append(
            (
                cell,
                timing,
                tally.runs,
                tally.verdicts + int(tally.no_verdicts),
                tally.accepted,
                tally.rejected,
                int(tally.refused),
                int(tally.not_asked),
            )
        )
    return Table(
        slug="outcomes",
        title="Run outcomes, by cell and count ordering",
        columns=(
            "cell",
            "count_exchange_timing",
            "runs",
            "parties",
            "accepted",
            "rejected",
            "refused",
            "not_asked",
        ),
        rows=tuple(rows),
        command=command,
        notes=(
            "`parties` is the denominator, and it is two verifiers per run "
            "-- every run has a Bob and a Charlie whatever became of them. "
            "accepted + rejected + refused + not_asked = parties, exactly. "
            "`not_asked` is a party the protocol never put the question to, "
            "which is a third thing again from a refusal.",
            "`refused` is a no-verdict, not a rejection. A run where a "
            "verifier could not score the declaration is neither an "
            "acceptance nor a detection, and it is never folded into either.",
            "`count_exchange_timing` is a column, never averaged over: the "
            "two orderings give different answers to the same attack.",
        ),
    )


def measured_rate(successes: int, trials: int, *, places: int = 3) -> str:
    """Format a measured rate with its interval, or say why there is none.

    The one formatter every Phase 5 table uses for a measured rate. Three
    copies of it existed when the families were written in parallel, differing
    only in ``places``; that is a parameter now, because the thing worth
    single-sourcing is the empty-denominator rule and the interval, not the
    column width.

    Parameters
    ----------
    successes : int
        Numerator.
    trials : int
        Denominator.
    places : int, optional
        Keyword-only. Decimal places for the rate and both endpoints. Three by
        default; the security curves pass four, where the rates being compared
        against a closed form are small.

    Returns
    -------
    str
        ``k/n = p [lo, hi]``, or ``no trials`` when ``n`` is zero -- never
        ``0.0``, which would read as a measurement that found nothing rather
        than as an absence of measurement.

    Examples
    --------
    >>> from sih141.eval.reduce import measured_rate
    >>> measured_rate(0, 40)
    '0/40 = 0.000 [0.000, 0.142]'

    An empty denominator is an absence, not a zero:

    >>> measured_rate(0, 0)
    'no trials'

    ``places`` moves the width and nothing else -- the same sample, printed
    finer:

    >>> measured_rate(1, 400, places=4)
    '1/400 = 0.0025 [0.0003, 0.0209]'
    """
    if trials <= 0:
        return "no trials"
    interval = wilson_interval(successes, trials, confidence=CONFIDENCE)
    rate = successes / trials
    return (
        f"{successes}/{trials} = {rate:.{places}f} "
        f"[{interval.low:.{places}f}, {interval.high:.{places}f}]"
    )


def refused_run(record: TrialRecord) -> bool:
    """Say whether any verifier reached no verdict on this run.

    The single route every Phase 5 table counts refusals by. Phase 3
    constraint 1 -- a no-verdict is not a rejection -- is only enforceable if
    every table agrees on what a refusal *is*, and the tempting shortcut,
    ``transcript_summary["aborted"]``, is a different question: it is true of a
    run that aborted for any reason, including one where the question was
    never put to a verifier at all.

    Parameters
    ----------
    record : TrialRecord
        One trial.

    Returns
    -------
    bool
        True when at least one verifier's recorded verdict is ``refused``.

    Examples
    --------
    >>> from sih141.eval.reduce import refused_run
    >>> class Fake:
    ...     def __init__(self, verdicts):
    ...         self.transcript_summary = {"verdicts": verdicts}
    >>> refused_run(Fake({"Bob": "accepted", "Charlie": "refused"}))
    True
    >>> refused_run(Fake({"Bob": "accepted", "Charlie": "rejected"}))
    False

    A rejection is not a refusal, and neither is a party who was never asked:

    >>> refused_run(Fake({"Bob": "rejected", "Charlie": "not_asked"}))
    False
    """
    verdicts = record.transcript_summary.get("verdicts") or {}
    return any(str(v) == "refused" for v in verdicts.values())


def expected_trials(
    store: ResultStore, experiment_name: str
) -> dict[str, int]:
    """Return how many trials per cell the sweep was actually asked for.

    Read from the manifests the runs wrote, not from the registry, because the
    registry says what the *default* is and a manifest says what *this store*
    was asked for. Where a store has several manifests -- which is what a
    resumed sweep leaves -- the largest request wins, since a cell asked for
    400 trials once is short at 380 however many smaller runs also touched it.

    Parameters
    ----------
    store : ResultStore
        Where results live.
    experiment_name : str
        Which experiment.

    Returns
    -------
    dict
        Cell name to expected trial count. Empty when no manifest records a
        count, in which case completeness cannot be checked against anything
        and :func:`completeness_note` says so rather than guessing.
    """
    wanted: dict[str, int] = {}
    for path in store.manifests(experiment_name):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        count = payload.get("trials")
        if not isinstance(count, int) or count <= 0:
            continue
        for cell in payload.get("cells") or ():
            wanted[str(cell)] = max(wanted.get(str(cell), 0), count)
    return wanted


def completeness_note(
    records: Sequence[TrialRecord], expected: Mapping[str, int]
) -> str:
    """Say whether every trial the sweep asked for is on disk.

    The single most likely way the human's long run goes quietly wrong. Every
    rate in every table is computed over the records that are present, which is
    arithmetically correct and still a false claim if the denominator shrank
    without saying so: a cell that was asked for 400 trials and has 380 prints
    ``k/380`` and looks finished.

    Two ways a trial goes missing, and they need different checks:

    - **An interior gap.** A trial whose scenario raised leaves no file at all,
      so index 7 can be absent with 8 and 9 present.
    - **A short tail.** An interrupted run leaves the *highest* indices
      missing, and that is the common case rather than the exotic one. A check
      that only looks for gaps below the highest index present reports a short
      cell as complete -- which is false reassurance, and worse than saying
      nothing.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Every record being reduced.
    expected : Mapping
        Cell name to the trial count the sweep asked for, from
        :func:`expected_trials`. An empty mapping means no manifest recorded a
        count, and the note says only what it could check. A mapping that
        covers *some* cells is the same problem in miniature -- a manifest that
        would not parse leaves its cells out -- and the uncovered cells are
        named rather than counted as complete.

    Returns
    -------
    str
        A footnote for the outcome table. Loud when something is missing.

    Examples
    --------
    A cell short by its last trial is caught, and the note names the shortfall
    rather than the index, because after an interruption the indices present
    are scattered:

    >>> from sih141.eval.reduce import completeness_note
    >>> class Fake:
    ...     def __init__(self, cell, index):
    ...         self.cell, self.index = cell, index
    >>> got = [Fake("a", 0), Fake("a", 1), Fake("b", 0)]
    >>> print(completeness_note(got, {"a": 2, "b": 2}))
    ... # doctest: +NORMALIZE_WHITESPACE
    **INCOMPLETE** -- the denominators above are smaller than the sweep asked
    for, so every rate here is over a shrunken sample: b has 1 of 2 trials.

    With nothing missing it says so, and says what it checked against:

    >>> print(completeness_note(got, {"a": 2, "b": 1}))
    ... # doctest: +NORMALIZE_WHITESPACE
    Complete: every cell has all the trials its manifest asked for, and no
    trial index is missing below the highest present. A trial whose scenario
    raised would leave no file, so this is checked rather than assumed.

    A cell no manifest covers is not folded into the affirmative, because it
    was checked against nothing -- which is what happens whenever
    :func:`expected_trials` skips an unreadable manifest:

    >>> print(completeness_note(got, {"a": 2}))
    ... # doctest: +NORMALIZE_WHITESPACE
    Partly checked: every cell a manifest covers has all the trials it asked
    for, and no trial index is missing below the highest present. No manifest
    recorded a trial count for b, so that cell was checked for interior gaps
    only and may be short of what was asked for.

    With no manifest to check against it does not claim completeness:

    >>> print(completeness_note(got, {}))
    ... # doctest: +NORMALIZE_WHITESPACE
    No manifest recorded a trial count for this store, so completeness could
    not be checked; only interior gaps were, and there are none. The row
    counts above may be short of what was asked for.
    """
    by_cell: dict[str, set[int]] = {}
    for record in records:
        by_cell.setdefault(record.cell, set()).add(record.index)

    short: list[str] = []
    gaps: list[str] = []
    for cell in sorted(by_cell):
        seen = by_cell[cell]
        absent = sorted(set(range(max(seen) + 1)) - seen)
        if absent:
            gaps.append(f"{cell} is missing index {absent}")
        want = expected.get(cell)
        if want is not None and len(seen) < want:
            short.append(f"{cell} has {len(seen)} of {want} trials")
    for cell in sorted(expected):
        if cell not in by_cell:
            short.append(f"{cell} has no records at all")

    # A cell with records that no manifest covers was never checked against a
    # count, only for interior gaps. Saying "every cell has all the trials its
    # manifest asked for" over it is the false affirmative this function
    # exists to remove, so the cells are named.
    unchecked = [cell for cell in sorted(by_cell) if cell not in expected]
    caveat = (
        " No manifest recorded a trial count for "
        + ", ".join(unchecked)
        + ", so "
        + ("that cell was" if len(unchecked) == 1 else "those cells were")
        + " checked for interior gaps only and may be short of what was "
        "asked for."
        if expected and unchecked
        else ""
    )

    if short or gaps:
        return (
            "**INCOMPLETE** -- the denominators above are smaller than the "
            "sweep asked for, so every rate here is over a shrunken sample: "
            + "; ".join(short + gaps)
            + "."
            + caveat
        )
    if caveat:
        return (
            "Partly checked: every cell a manifest covers has all the trials "
            "it asked for, and no trial index is missing below the highest "
            "present." + caveat
        )
    if not expected:
        return (
            "No manifest recorded a trial count for this store, so "
            "completeness could not be checked; only interior gaps were, and "
            "there are none. The row counts above may be short of what was "
            "asked for."
        )
    return (
        "Complete: every cell has all the trials its manifest asked for, and "
        "no trial index is missing below the highest present. A trial whose "
        "scenario raised would leave no file, so this is checked rather than "
        "assumed."
    )


def escape_xml(text: str) -> str:
    """Escape the five XML metacharacters, for a chart renderer.

    Shared by every family's SVG chart, so an experiment name carrying an
    ampersand cannot produce a document one renderer escapes and another does
    not.

    Parameters
    ----------
    text : str
        Raw text.

    Returns
    -------
    str
        ``text`` with ``&``, ``<``, ``>``, ``"`` and ``'`` replaced by their
        entities. The ampersand goes first, or the entities the later
        replacements introduce would be escaped a second time.

    Examples
    --------
    >>> from sih141.eval.reduce import escape_xml
    >>> escape_xml('a & b <c> "d"')
    'a &amp; b &lt;c&gt; &quot;d&quot;'
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def detection_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> Table:
    """Tabulate what the detector flagged, measured apart from proven.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. The regenerating command.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order; see :func:`group_records`.

    Returns
    -------
    Table
        One row per ``(cell, count_exchange_timing)``. The ``flagged
        (measured)`` column carries a Wilson interval at
        :data:`CONFIDENCE` and the word is on the header; ``max proven FP
        bound`` is the largest
        :attr:`~sih141.detect.detector.Detection.false_positive_bound` over the
        group and is a proof under the honest null. The two are never merged.

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Notes
    -----
    ``attacked`` is the count of runs whose adversary actually engaged, read
    off the adversary's own log. It is the denominator a detection rate belongs
    over; the untargeted runs in an attack cell are honest runs and are shown
    separately rather than counted as misses.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.reduce import detection_table
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("smoke"), store, trials=2, workers=1,
    ...                        in_process=True, quiet=True)
    ...     table = detection_table(list(store.read_experiment("smoke")))
    ...     table.columns[:5]
    ...     row = table.rows[0]
    ...     row[0], row[2], row[3], row[4]
    ...     table.columns[7], row[7]
    ...     row[10].startswith("not evaluated")
    ('cell', 'count_exchange_timing', 'hypothesis', 'runs', 'attacked')
    ('tiny', 'honest', 2, 0)
    ('refusals (any party)', 0)
    True
    """
    if not records:
        raise ValueError("detection_table needs at least one record")
    rows: list[tuple[Any, ...]] = []
    withheld_seen: set[str] = set()
    for (cell, timing), group in group_records(
        records, cell_order=cell_order
    ).items():
        # Per group, not accumulated across the table: a family withheld in one
        # cell says nothing about another, and a column that went to
        # "not evaluated" for every row as soon as any row withheld would
        # understate what the detector actually managed to score.
        withheld_here: set[str] = set()
        runs = len(group)
        attacked = [r for r in group if r.truth.attacked]
        clean = [r for r in group if not r.truth.attacked]
        detectable = all(r.truth.detectable for r in group)
        hypotheses = sorted({r.truth.hypothesis for r in group})
        bounds = [
            float(r.detection["false_positive_bound"])
            for r in group
            if r.detection.get("false_positive_bound") is not None
        ]
        # Phase 3 constraint 1, on the one table every experiment gets. A
        # refusal is not a rejection, and a `flagged 400/400` row over a cell
        # where every verifier reached no verdict is a denial of transfer
        # dressed as a caught attack. The count is its own column and is added
        # to neither denominator: the detector returned on every run.
        refusals = sum(1 for r in group if refused_run(r))
        for record in group:
            withheld_here.update(str(w) for w in record.detection.get("withheld", ()))
        withheld_seen.update(withheld_here)

        # The assumption excludes detection of the *attack*. It says nothing
        # about the runs the adversary left alone, which are honest runs whose
        # false-positive rate is as measurable as any other -- so only the
        # attacked column carries the phrase, and putting it in both would
        # withhold a measurement that was made.
        flagged_cell: Any = (
            UNDETECTABLE_BY_CONSTRUCTION
            if not detectable
            else measured_rate(sum(1 for r in attacked if r.flagged), len(attacked))
        )
        clean_cell = measured_rate(sum(1 for r in clean if r.flagged), len(clean))

        nulls = {r.null_is_noiseless for r in group}
        null_cell = (
            "yes" if nulls == {True} else "no" if nulls == {False} else "mixed"
        )
        rows.append(
            (
                cell,
                timing,
                ", ".join(hypotheses),
                runs,
                len(attacked),
                flagged_cell,
                clean_cell,
                refusals,
                f"{max(bounds):.3e}" if bounds else NOT_EVALUATED,
                null_cell,
                f"{NOT_EVALUATED} ({len(withheld_here)})" if withheld_here else "-",
            )
        )
    notes = [
        "`flagged on attacked (measured)` and `flagged on clean (measured)` "
        "are MEASUREMENTS with a sample size, shown as k/n with a "
        f"{CONFIDENCE:.0%} Wilson interval. There is no false-negative bound "
        "and there cannot be one from a transcript.",
        "`max proven FP bound` is PROVEN under the honest null -- the largest "
        "Detection.false_positive_bound in the group. It shares no column "
        "with a measured rate.",
        "`attacked` counts runs whose adversary engaged, read off the "
        "adversary's own log. An untargeted run is byte-identical to an "
        "honest one and is scored as one.",
        "`refusals (any party)` counts runs where AT LEAST ONE verifier "
        "reached no verdict. It is shown beside the rates and added to "
        "neither denominator: a refusal is not a rejection, and it is not a "
        "miss either -- the detector scored every run in both denominators, "
        "refusal or not. A row whose count equals its `runs` did not "
        "necessarily deny transfer, and this is where an experiment's own "
        "per-party table earns its place: at L = 96 the recipient forger "
        "refuses on all 400 runs under either ordering, but before forwarding "
        "it is CHARLIE who reaches no verdict (a denial of transfer) and "
        "after forwarding it is BOB, while Charlie returns a real 120/400 "
        "acceptance. Same count, opposite reading, which is why the column is "
        "named for what it actually counts.",
        "`null_is_noiseless` says whether the detector was given a noiseless "
        "null. On a genuinely noisy link that null is not the truth, honest "
        "runs depart from it, and the mismatch members fire correctly -- so a "
        "`yes` here is a caveat on the row, not a detail.",
        f"`{UNDETECTABLE_BY_CONSTRUCTION}` means an assumption rules "
        f"detection out for that hypothesis -- {UNDETECTABLE_ASSUMPTION}. It "
        "is never a blank, a dash or a zero.",
    ]
    if withheld_seen:
        notes.append(
            "Families withheld on at least one run in this table, reported as "
            f"`{NOT_EVALUATED}` and never as passed: "
            + ", ".join(sorted(withheld_seen))
            + "."
        )
    return Table(
        slug="detection",
        title="Detector signals, measured rates apart from proven bounds",
        columns=(
            "cell",
            "count_exchange_timing",
            "hypothesis",
            "runs",
            "attacked",
            "flagged on attacked (measured)",
            "flagged on clean (measured)",
            "refusals (any party)",
            "max proven FP bound",
            "null_is_noiseless",
            "withheld families",
        ),
        rows=tuple(rows),
        command=command,
        notes=tuple(notes),
    )


def timing_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> Table:
    """Tabulate what the trials cost, so the manifest can be checked against it.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. The regenerating command.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order; see :func:`group_records`.

    Returns
    -------
    Table
        Per cell: key length, trials, total and mean session seconds, mean
        detector seconds, and milliseconds per position.

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Notes
    -----
    This is the sanity check on the runner. The sum of these per-trial timings
    against the manifest's wall clock says whether the pool was really running
    trials in parallel: if aggregate throughput disagrees with the manifest,
    one of the two is wrong and finding out which is part of the job.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.experiments import experiment
    >>> from sih141.eval.reduce import timing_table
    >>> from sih141.eval.runner import run_experiment
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     store = ResultStore(Path(tmp))
    ...     _ = run_experiment(experiment("smoke"), store, trials=2, workers=1,
    ...                        in_process=True, quiet=True)
    ...     table = timing_table(list(store.read_experiment("smoke")))
    ...     table.columns
    ...     table.rows[0][0], table.rows[0][1], table.rows[0][2]
    ('cell', 'key_length', 'trials', 'session s (total)', 'session s (mean)', 'detect s (mean)', 'ms/position')
    ('tiny', 96, 2)
    """
    if not records:
        raise ValueError("timing_table needs at least one record")
    by_cell: dict[str, list[TrialRecord]] = {}
    for (cell, _timing), group in group_records(
        records, cell_order=cell_order
    ).items():
        by_cell.setdefault(cell, []).extend(group)
    rows: list[tuple[Any, ...]] = []
    for cell, group in by_cell.items():
        length = int(group[0].params["key_length"])
        session = [float(r.wall_clock.get("session_seconds", 0.0)) for r in group]
        detect_s = [float(r.wall_clock.get("detect_seconds", 0.0)) for r in group]
        mean_session = sum(session) / len(session)
        rows.append(
            (
                cell,
                length,
                len(group),
                f"{sum(session):.2f}",
                f"{mean_session:.3f}",
                f"{sum(detect_s) / len(detect_s):.4f}",
                f"{1000.0 * mean_session / length:.3f}",
            )
        )
    return Table(
        slug="timing",
        title="Per-trial cost, by cell",
        columns=(
            "cell",
            "key_length",
            "trials",
            "session s (total)",
            "session s (mean)",
            "detect s (mean)",
            "ms/position",
        ),
        rows=tuple(rows),
        command=command,
        notes=(
            "Timings are wall clock inside the worker, so at N workers the "
            "sum of `session s (total)` exceeds the sweep's own wall clock by "
            "roughly the achieved speedup. That comparison is the check on "
            "the runner: if it does not, one of the two numbers is wrong.",
            "**`ms/position` HERE IS NOT THE PROTOCOL'S COST.** It carries the "
            "contention of whatever worker count produced these records -- see "
            "`worker counts` in the provenance above. Measured on this machine, "
            "a trial takes 1.61x longer at twenty workers than at one at "
            "L = 384, and 2.53x at L = 768, because the cores share an all-core "
            "turbo budget and an L3. The single-threaded reference is "
            "`sih141.eval.perf.REFERENCE_MS_PER_POSITION`; regenerate it with "
            "`python tools/sweep.py perf`. Multiplying the figure below by a "
            "key length to project a production run overstates it by that "
            "factor.",
            "Timings are excluded from a record's fingerprint, so they cannot "
            "affect the reproducibility claim -- and every other table here "
            "is byte-identical at one worker and at twenty.",
        ),
    )


def reduce_experiment(
    store: ResultStore,
    experiment_name: str,
    *,
    command: str = "",
    cells: Sequence[str] | None = None,
) -> list[Table]:
    """Read one experiment off disk and return every table it supports.

    Parameters
    ----------
    store : ResultStore
        Where results live.
    experiment_name : str
        Which experiment.
    command : str, optional
        Keyword-only. The regenerating command, stamped on every table.
    cells : Sequence of str or None, optional
        Keyword-only. Restrict to these cells.

    Returns
    -------
    list of Table
        Outcomes, detection, timing -- in that order -- followed by whatever
        this experiment registered in :data:`EXTRA_REDUCTIONS`.

    Raises
    ------
    FileNotFoundError
        If the experiment has no records on disk. Reducing nothing into an
        empty table would publish a table that looks like a measurement of
        zero.

    Examples
    --------
    >>> import tempfile
    >>> from pathlib import Path
    >>> from sih141.eval.reduce import reduce_experiment
    >>> from sih141.eval.store import ResultStore
    >>> with tempfile.TemporaryDirectory() as tmp:
    ...     reduce_experiment(ResultStore(Path(tmp)), "smoke")
    Traceback (most recent call last):
        ...
    FileNotFoundError: no records for experiment 'smoke' under ...
    """
    wanted = None if cells is None else set(cells)
    records = [
        record
        for record in store.read_experiment(experiment_name)
        if wanted is None or record.cell in wanted
    ]
    if not records:
        raise FileNotFoundError(
            f"no records for experiment {experiment_name!r} under "
            f"{store.root}. Run the sweep first: "
            f"python tools/sweep.py run {experiment_name}"
        )
    order: Sequence[str] | None = None
    registered = EXPERIMENTS.get(experiment_name)
    if registered is not None:
        order = registered.cell_names
    expected = {
        cell: count
        for cell, count in expected_trials(store, experiment_name).items()
        if wanted is None or cell in wanted
    }
    complete = completeness_note(records, expected)
    outcomes = outcome_table(records, command=command, cell_order=order)
    # Prepended, not appended: if the sample is short, that is the first thing
    # a reader needs and not a footnote after three about the denominators.
    outcomes = replace(outcomes, notes=(complete, *outcomes.notes))
    tables = [
        outcomes,
        detection_table(records, command=command, cell_order=order),
        timing_table(records, command=command, cell_order=order),
    ]
    extra = EXTRA_REDUCTIONS.get(experiment_name)
    if extra is not None:
        # `expected` goes through so a family's own completeness footnote can
        # check the count against the manifest rather than only looking for
        # interior gaps. Without it the ROC grid printed "No manifest recorded
        # a trial count for this store" while the outcome table three sections
        # above said "Complete: every cell has all the trials its manifest
        # asked for" -- one of the two was false about the same store, in the
        # same file.
        tables.extend(
            extra(
                records,
                command=command,
                cell_order=order,
                expected=expected,
            )
        )
    return tables
