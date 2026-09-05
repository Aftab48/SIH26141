"""The ROC family: detection against a swept budget, every point derived.

The question this family answers, in one sentence: **as the detector's
false-positive budget ``eps`` is swept over a committed ladder, what detection
rate does the Phase 4 detector achieve against each adversary, with every
operating point obtained by passing that ``eps`` to the shipped
:func:`~sih141.detect.detector.detect` rather than by moving a cut by hand?**

Phase 4 published one column of this surface -- 19 arms at ``eps = 1e-9``, 40
runs each (``docs/PHASE4.md`` section 5). This family adds the second axis. It
is the axis that turns a table of rates into a receiver operating
characteristic, and the only one on which the phrase "derived, not tuned" can be
checked rather than asserted: :ref:`D7 <d7>` says a threshold comes from a
stated null and a concentration inequality, and the visible consequence of that
is that ``eps`` is the *only* knob, so a whole curve falls out of one argument.

.. _roc-axes:

The two axes are different kinds of number, and the table says so
-----------------------------------------------------------------
Phase 3 constraint 6. There is no false-negative bound and there cannot be one
from a transcript, so:

* the **horizontal** axis is :attr:`~sih141.detect.detector.Detection.false_positive_bound`
  -- **proven**, under the honest null, for every run that will ever be scored;
* the **vertical** axis is a **measured** detection rate with a sample size and
  a 99% Wilson interval, over a denominator this module prints rather than
  implies.

They never share a column, the words ``proven`` and ``measured`` are on the
headers, and :func:`roc_chart_svg` puts them on the axis labels of the chart so
the distinction survives being screenshotted out of the document.

.. _roc-paired:

Why the ladder is a reduce-time axis
------------------------------------
Every point on one curve is scored on **the same runs**. That is not an
optimisation; it is what makes a wobble in the curve a finding.

A trial's seed is a pure function of ``(experiment, cell, index)``
(:mod:`~sih141.eval.seeds`), so making ``eps`` a cell dimension would give each
operating point a *different* sample of runs. At ``n = 40`` a five-percent
difference between two such points is sampling noise, and a family whose
headline claim is "if the curve goes non-monotonic that is a finding about a
threshold" cannot afford a curve whose wobbles are explained by the sample.
Scoring one transcript at every budget removes the sample as an explanation:
at run level the set of budgets a run fires at must be an up-set, and
:func:`monotonicity_violations` checks exactly that, per run, not per rate.

So the cells retain their transcripts and the ladder is applied by the
reduction. Measured at ``L = 384``, ``check_fraction = 0.25``: a session is
798 ms, its JSON is 125 KiB, re-reading that JSON is 7 ms and one
:func:`~sih141.detect.detector.detect` call is 2.6 ms. Fifteen budgets is 5% of
one session, and the reduction pays it instead of the sweep -- which buys
something better than the saving: **the ladder is not frozen at run time.** A
reviewer who wants an operating point between two of ours re-reduces; nobody
re-runs. What it costs is disk and a slower reduction: 154 KiB per record,
90 MiB for the production family (measured on the production store: 153.8 and
90.1), and about 35 s to redraw every table (measured: one
ladder pass over 60 records is 3.05 s). If this family is ever taken to
``L = 115200``, where a transcript is 37 MiB, that trade reverses and the ladder
belongs on the record instead.

.. _roc-crosscheck:

The cross-check that would fail if the reduction were wrong
-----------------------------------------------------------
Every ROC cell runs at ``eps = 1e-9``, which is **on** the ladder. So each
record carries a :class:`~sih141.detect.detector.Detection` computed at run
time, in a worker process, from a live
:class:`~sih141.detect.statistics.TranscriptStatistics`; and the reduction
recomputes that same point from the stored JSON in a different process at a
different time. :func:`reconciliation` compares the two and
:func:`roc_reduction` raises if they ever disagree. A test that merely asserted
the ROC table had rows would pass just as happily with the ladder wired to a
constant.

Examples
--------
The ladder is a committed constant, not an argument someone chose per figure:

>>> from sih141.eval.roc import EPS_LADDER, DEFAULT_EPS
>>> len(EPS_LADDER), EPS_LADDER[0], EPS_LADDER[-1]
(15, 0.5, 1e-30)
>>> DEFAULT_EPS in EPS_LADDER            # the anchor Phase 4 published at
True
>>> all(a > b for a, b in zip(EPS_LADDER, EPS_LADDER[1:]))
True

The tolerated-null arm's two nulls are one physical statement, converted once
and written down, rather than two numbers that could drift apart:

>>> from sih141.eval.roc import TOLERATED_DEPOLARISING, TOLERATED_ERROR_RATE
>>> TOLERATED_DEPOLARISING, TOLERATED_ERROR_RATE
(0.05, 0.025)

The cells, in table order:

>>> from sih141.eval.experiments import experiment
>>> roc = experiment("roc")
>>> len(roc.cells), roc.trials
(15, 40)
>>> roc.cell("impersonation-full").detectable
False
>>> roc.cell("honest-unchecked").params.has_check_rounds
False

Every cell keeps its transcript, because the ladder is applied afterwards. A
whole record is 154 KiB measured -- the 125 KiB transcript plus the verdict,
the summary and JSON escaping -- so the production family is about **90 MiB**
on disk. Kibibytes throughout, because every other size in this package is
``len(...) / 1024``:

>>> all(cell.retain_transcript for cell in roc.cells)
True

Every cell also runs at the anchor budget, so every record cross-checks the
reduction (:ref:`roc-crosscheck`):

>>> {cell.eps for cell in roc.cells} == {DEFAULT_EPS}
True
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Final, Mapping, Sequence

from sih141.attacks.forgery import OutsideForger, RecipientForger
from sih141.attacks.impersonation import (
    ImpersonationScope,
    Impersonator,
    impersonation_seams,
)
from sih141.attacks.replay import ReplayingForwarder, replay_capture
from sih141.attacks.starvation import CountStarver
from sih141.detect.detector import detect
from sih141.detect.statistics import TranscriptStatistics, wilson_interval
from sih141.detect.thresholds_rate import dominance_noise_level
from sih141.protocol.analysis import depolarising_error_rate
from sih141.protocol.params import ProtocolParams
from sih141.protocol.session import (
    COUNTS_AFTER_FORWARDING,
    COUNTS_BEFORE_FORWARDING,
    QDSSession,
    SessionTranscript,
)
from sih141.protocol.verify import MatchedSetTooSmall

from . import reduce as reduce_module
from .experiments import (
    DEFAULT_EPS,
    EXPERIMENTS,
    SCENARIO_PROBE_OPTIONS,
    SCENARIOS,
    Cell,
    Experiment,
    claim,
)
from .records import UNDETECTABLE_BY_CONSTRUCTION, GroundTruth, TrialRecord
from .reduce import (
    CONFIDENCE,
    NOT_EVALUATED,
    Table,
    completeness_note,
    escape_xml,
    group_records,
    measured_rate,
    refused_run,
)
from .seeds import TrialSeeds

__all__ = [
    "EPS_LADDER",
    "PROTOTYPE_ARMS",
    "ROC_PROBE_OPTIONS",
    "PROTOTYPE_FALSE_ALARMS",
    "ROC_CHECK_FRACTION",
    "ROC_KEY_LENGTH",
    "ROC_SCENARIOS",
    "ROC_TRIALS",
    "TOLERATED_DEPOLARISING",
    "TOLERATED_ERROR_RATE",
    "OperatingPoint",
    "RocPoint",
    "impersonation_scenario",
    "monotonicity_violations",
    "outside_forgery_scenario",
    "recipient_forgery_scenario",
    "reconciliation",
    "register",
    "replay_scenario",
    "roc_chart_svg",
    "roc_envelope_table",
    "roc_points",
    "roc_prototype_table",
    "roc_reduction",
    "roc_table",
    "score_ladder",
    "starvation_scenario",
]


# --------------------------------------------------------------------------- #
# The committed constants: the ladder, the configuration, the prototype
# --------------------------------------------------------------------------- #

EPS_LADDER: Final[tuple[float, ...]] = (
    5e-1,
    1e-1,
    1e-2,
    1e-3,
    1e-4,
    1e-5,
    1e-6,
    1e-7,
    1e-8,
    1e-9,
    1e-12,
    1e-15,
    1e-18,
    1e-24,
    1e-30,
)
"""tuple of float: The operating points, loosest first.

Committed rather than passed, because D9's promise is that a published figure
is reproducible from a recorded seed and a committed command, and an axis
chosen per chart is neither. Fifteen budgets over thirty decades.

The ends are chosen against measured behaviour rather than for tidiness.
``5e-1`` is the loosest budget Phase 4's own tests use, and it is where a
proven bound is large enough that an honest run really can trip something --
without it the measured false-alarm column is ``0/n`` everywhere and says
nothing.

The tight end is past the point where the structural family loses an
admissible operating point. On the checked honest cell ``structural:
evidence-abort`` is scored at ``1e-18`` and **withheld** at ``1e-24``; bisecting
between them puts the crossover at ``eps`` about ``4.9e-19``, identically on
every run, so it is a property of the parameters rather than of a realisation.
That number is worth carrying: it sits *above* ``2**-64``, about ``5.42e-20``,
which is the smallest budget this project quotes -- so at the tightest budget
anyone here would actually ask for, that member has no operating point and the
table says ``not evaluated`` rather than ``passed``. A withheld check is not a
passed check, and this is the sweep finding the boundary rather than a reader
being asked to take ``can_fire`` on trust.
``tests/test_eval_roc.py`` pins both ends of that bracket.

Below roughly ``1e-310`` :func:`~sih141.detect.detector.family_budget` refuses
to split at all, and it says so in the exception rather than returning a share
of zero.
"""

ROC_KEY_LENGTH: Final[int] = 384
"""int: Nominal key length for every ROC cell. Phase 4 section 5's length.

At ``check_fraction = 0.25`` this sifts to 288, which clears the per-verifier
floor at 273, so an abort on an honest run is the rare event the derivation
says it is rather than a routine outcome that would eat the denominator.
"""

ROC_CHECK_FRACTION: Final[float] = 0.25
"""float: Check-round fraction. The only arrangement in which the channel
family is evaluable at all -- all four links publish, and
:attr:`~sih141.detect.detector.Detection.withheld` is empty. One cell
deliberately runs at ``0.0`` so the table has a row where a family really is
withheld and prints ``not evaluated`` rather than ``passed`` (constraint 8).
"""

ROC_TRIALS: Final[int] = 40
"""int: Runs per cell. Forty, matching Phase 4 section 5 exactly, so the
``eps = 1e-9`` row of this family and the published Phase 4 row are the same
measurement at a different seed set and their Wilson intervals are directly
comparable.
"""

TOLERATED_DEPOLARISING: Final[float] = 0.05
"""float: ``p0`` for the tolerated-null arm, as a Werner strength.

Constraint 9 says a table either passes the link's true error rate or carries
``null_is_noiseless`` as a column. This family does **both**, in different
cells, because the two configurations answer different questions: under the
noiseless null the detector sees every adversary and the curve is flat, and it
is only when the link's own noise is admitted into the null that the ROC has a
shape at all.
"""

TOLERATED_ERROR_RATE: Final[float] = depolarising_error_rate(TOLERATED_DEPOLARISING)
"""float: ``p_e`` for the tolerated-null arm: ``p0 / 2``.

Derived through :func:`~sih141.protocol.analysis.depolarising_error_rate` and
not written out, because ``channel_error_rate`` and ``tolerated_depolarising``
are two parameterisations of one physical statement and a transcription error
between them would state a null nobody chose.

>>> from sih141.eval.roc import TOLERATED_DEPOLARISING, TOLERATED_ERROR_RATE
>>> TOLERATED_ERROR_RATE == TOLERATED_DEPOLARISING / 2
True
"""

PROTOTYPE_ARMS: Final[str] = "4 of 5 adversaries at 100%"
"""str: What the Phase 3 prototype separated, quoted from ``docs/PHASE3.md``."""

PROTOTYPE_FALSE_ALARMS: Final[str] = "0/80"
"""str: The prototype's false-alarm **observation**. Not a bound; that is the
whole point of the comparison this family draws (:func:`roc_prototype_table`).
"""

_CAPTURE_SEED: Final[int] = 20260905
"""int: Seed for the declaration the replaying forwarder is holding.

Fixed per cell rather than per trial, and that is the attack rather than a
shortcut: a replaying adversary holds *one* copy of something that was public
and re-presents it. Making it vary per trial would model an adversary who
captures a fresh round before every replay, which is a different threat.
Constant also means :func:`~sih141.attacks.replay.replay_capture`'s cache is
hit after the first trial in each worker, so the arm costs one extra session
per worker rather than one per trial.
"""


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #


def _run(
    cell: Cell, seeds: TrialSeeds, **seams: Any
) -> SessionTranscript:
    """Run one session and keep the transcript even when a verifier refuses.

    Parameters
    ----------
    cell : Cell
        The cell. ``scenario_options["count_exchange_timing"]`` is honoured
        here so every adversary in this module can be run under either
        ordering without five copies of the same argument handling.
    seeds : TrialSeeds
        The trial's seeds. Only the session's is drawn on here; each scenario
        hands the adversary's to its own adversary and nothing else (D3, D6).
    **seams : object
        Passed straight to :class:`~sih141.protocol.session.QDSSession`.

    Returns
    -------
    SessionTranscript
        Complete, or carrying the abort that stopped it.

    Raises
    ------
    ValueError
        If ``count_exchange_timing`` names neither ordering.

    Notes
    -----
    The :exc:`~sih141.protocol.verify.MatchedSetTooSmall` guard is
    **defensive, and deliberately kept**. The shipped
    :meth:`~sih141.protocol.session.QDSSession.run` already catches that
    exception at each of the two Phase C steps and carries the refusal into
    the transcript, so on every configuration this module ships it never
    escapes -- measured, not assumed. What it does not wrap is the phases
    before Phase C, and Phase 4's own corpus builder carries the same guard for
    the same reason.

    The reason it is worth keeping over an exception that has not been
    observed is what escaping would cost. A raise inside a scenario is caught
    by :func:`~sih141.eval.runner._execute`, counted as a failed trial, and
    leaves **no file on disk**; the reduction would then average a cell of 37
    records without anything in the table to say that three runs had gone.
    That is Phase 3 constraint 1 defeated by the back door, and there would be
    no abort column to give it away -- so this catches, and
    :func:`_missing_note` checks the index sequence as well.
    """
    timing = str(
        cell.scenario_options.get("count_exchange_timing", COUNTS_BEFORE_FORWARDING)
    )
    if timing not in (COUNTS_BEFORE_FORWARDING, COUNTS_AFTER_FORWARDING):
        raise ValueError(
            f"cell {cell.name!r} names count_exchange_timing {timing!r}; the "
            f"two orderings are {COUNTS_BEFORE_FORWARDING!r} and "
            f"{COUNTS_AFTER_FORWARDING!r}"
        )
    session = QDSSession(
        cell.params,
        rng=seeds.session_rng(),
        count_exchange_timing=timing,
        **seams,
    )
    try:
        return session.run(cell.message_bit)
    except MatchedSetTooSmall:
        return session.transcript()


def outside_forgery_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """Eve on the signer seam: a fresh key, declared, holding nothing.

    Parameters
    ----------
    cell : Cell
        The cell.
    seeds : TrialSeeds
        The trial's seeds. The forger is built from
        :meth:`~sih141.eval.seeds.TrialSeeds.adversary_rng` and never sees the
        session's (D6).

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)
        ``engaged_count`` is :attr:`~sih141.attacks.forgery.OutsideForger.calls`
        -- her own tally of declarations made, not the cell's intent.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell
    >>> from sih141.eval.roc import outside_forgery_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> from sih141.protocol.params import ProtocolParams
    >>> cell = Cell(name="f", params=ProtocolParams(key_length=96),
    ...             scenario="roc-outside-forgery")
    >>> run, truth = outside_forgery_scenario(cell, trial_seeds("d", "f", 0))
    >>> truth.engaged, truth.engaged_count
    (True, 1)
    >>> [r.accepted for r in run.results_by_party.values()]
    [False, False]
    """
    forger = OutsideForger(rng=seeds.adversary_rng())
    transcript = _run(cell, seeds, signer=forger)
    return transcript, _truth(cell, engaged_count=int(forger.calls))


def recipient_forgery_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """Bob forging to Charlie on the forwarding hop.

    Parameters
    ----------
    cell : Cell
        ``scenario_options`` takes ``guess_probability`` (default ``0.0``, the
        optimal forger) and ``count_exchange_timing``.
    seeds : TrialSeeds
        The trial's seeds.

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)
        ``engaged_count`` is
        :attr:`~sih141.attacks.forgery.RecipientForger.calls`.

    Notes
    -----
    The ordering is a **column, never averaged over** (constraint 2), and this
    adversary is why the rule exists in this family. Under the shipped
    ``before-forwarding`` rule a substituted declaration leaves Charlie with no
    verdict at all -- a denial of transfer, a refusal, not a detection -- while
    under ``after-forwarding`` he scores it and rejects. Pooling the two would
    average a forgery rate with a denial-of-service rate.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell
    >>> from sih141.eval.roc import recipient_forgery_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> from sih141.protocol.params import ProtocolParams
    >>> cell = Cell(name="rf", params=ProtocolParams(key_length=96),
    ...             scenario="roc-recipient-forgery")
    >>> run, truth = recipient_forgery_scenario(cell, trial_seeds("d", "rf", 0))
    >>> truth.engaged_count
    1
    >>> run.count_exchange_timing
    'before-forwarding'
    """
    forger = RecipientForger(
        rng=seeds.adversary_rng(),
        guess_probability=float(cell.scenario_options.get("guess_probability", 0.0)),
    )
    transcript = _run(cell, seeds, forwarder=forger)
    return transcript, _truth(cell, engaged_count=int(forger.calls))


def replay_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """A forwarder re-presenting a declaration captured from a finished round.

    Parameters
    ----------
    cell : Cell
        ``scenario_options`` takes ``replay_probability`` (default ``1.0``),
        ``relabel`` (default ``True``), ``capture_seed`` (default
        :data:`_CAPTURE_SEED`) and ``count_exchange_timing``.
    seeds : TrialSeeds
        The trial's seeds.

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)
        ``engaged_count`` is
        :attr:`~sih141.attacks.replay.ReplayingForwarder.replays` -- calls that
        actually substituted. At a ``replay_probability`` below one some trials
        forward honestly and are labelled ``engaged=False``, which is correct:
        such a run is byte-identical to an honest one and a table that scored
        it as a miss would report a rate against a denominator counting runs
        where nothing happened.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell
    >>> from sih141.eval.roc import replay_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> from sih141.protocol.params import ProtocolParams
    >>> cell = Cell(name="rp", params=ProtocolParams(key_length=96),
    ...             scenario="roc-replay",
    ...             scenario_options={"replay_probability": 0.0})
    >>> _, truth = replay_scenario(cell, trial_seeds("d", "rp", 0))
    >>> truth.engaged, truth.engaged_count
    (False, 0)
    """
    options = dict(cell.scenario_options)
    capture = replay_capture(
        cell.params,
        message_bit=cell.message_bit,
        seed=int(options.get("capture_seed", _CAPTURE_SEED)),
    )
    attack = ReplayingForwarder(
        rng=seeds.adversary_rng(),
        captures=[capture.signature],
        replay_probability=float(options.get("replay_probability", 1.0)),
        relabel=bool(options.get("relabel", True)),
    )
    transcript = _run(cell, seeds, forwarder=attack)
    return transcript, _truth(cell, engaged_count=int(attack.replays))


def starvation_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """A verifier under-reporting his Phase C' count to deny the other's verdict.

    Parameters
    ----------
    cell : Cell
        ``scenario_options`` takes ``denial_probability`` (default ``1.0``),
        ``party`` (default Charlie, the transferee) and
        ``count_exchange_timing``.
    seeds : TrialSeeds
        The trial's seeds.

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)
        ``engaged_count`` counts the entries in
        :attr:`~sih141.attacks.starvation.CountStarver.log` whose ``starved``
        flag is set -- exchanges on which the coin actually came up denial. A
        selective starver leaves most runs alone and those runs are honest
        runs; scoring them as misses is Phase 3 constraint 4 broken, and it is
        broken silently because such a run is byte-identical to an honest one.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell
    >>> from sih141.eval.roc import starvation_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> from sih141.protocol.params import ProtocolParams
    >>> cell = Cell(name="st", params=ProtocolParams(key_length=600),
    ...             scenario="roc-count-starvation")
    >>> run, truth = starvation_scenario(cell, trial_seeds("d", "st", 0))
    >>> truth.engaged, truth.engaged_count
    (True, 1)

    The denial is a refusal, and the transcript keeps it in the field that
    cannot be added to a rejection:

    >>> [(a.party.value, str(a.reason)) for a in run.aborts]
    [('Bob', 'counterpart-matched-count-below-floor')]
    """
    options = dict(cell.scenario_options)
    starver = CountStarver(
        rng=seeds.adversary_rng(),
        denial_probability=float(options.get("denial_probability", 1.0)),
        **({"party": options["party"]} if "party" in options else {}),
    )
    transcript = _run(cell, seeds, count_exchange=starver)
    starved = sum(1 for decision in starver.log if decision.starved)
    return transcript, _truth(cell, engaged_count=starved)


def impersonation_scenario(
    cell: Cell, seeds: TrialSeeds
) -> tuple[SessionTranscript, GroundTruth]:
    """Mallory holding one or both of Alice's seams.

    Parameters
    ----------
    cell : Cell
        ``scenario_options["scope"]`` is required and names an
        :class:`~sih141.attacks.impersonation.ImpersonationScope`. There is no
        default: ``"none"`` is a legal scope that seizes nothing, so a typo
        defaulted to it would run an honest session under an attack label and
        report a detector that found nothing.
    seeds : TrialSeeds
        The trial's seeds.

    Returns
    -------
    tuple of (SessionTranscript, GroundTruth)
        ``engaged_count`` is how many keys Mallory drew, off her own cache.
        Zero for :attr:`~sih141.attacks.impersonation.ImpersonationScope.NONE`,
        because a seam she does not hold is never called.

    Raises
    ------
    KeyError
        If ``scope`` is absent.

    Notes
    -----
    ``FULL`` is out of model by assumption **(AUTH)** and its cell carries
    ``detectable=False``, so the reduction prints
    :data:`~sih141.eval.records.UNDETECTABLE_BY_CONSTRUCTION` rather than the
    ``0/40`` it would otherwise measure (constraint 5). The zero is real and it
    is not a miss.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell
    >>> from sih141.eval.roc import impersonation_scenario
    >>> from sih141.eval.seeds import trial_seeds
    >>> from sih141.protocol.params import ProtocolParams
    >>> cell = Cell(name="im", params=ProtocolParams(key_length=96),
    ...             scenario="roc-impersonation",
    ...             scenario_options={"scope": "signing"})
    >>> run, truth = impersonation_scenario(cell, trial_seeds("d", "im", 0))
    >>> truth.engaged, truth.engaged_count
    (True, 1)
    >>> [r.accepted for r in run.results_by_party.values()]
    [False, False]
    """
    options = dict(cell.scenario_options)
    if "scope" not in options:
        raise KeyError(
            f"cell {cell.name!r} uses the impersonation scenario but names no "
            f"'scope' in scenario_options. There is no default: "
            f"ImpersonationScope.NONE seizes nothing, so a defaulted typo "
            f"would run an honest session under an attack label."
        )
    scope = ImpersonationScope(str(options["scope"]))
    mallory = Impersonator(rng=seeds.adversary_rng())
    transcript = _run(cell, seeds, **impersonation_seams(mallory, scope))
    return transcript, _truth(cell, engaged_count=len(mallory.keys))


def _truth(cell: Cell, *, engaged_count: int) -> GroundTruth:
    """Build the harness's label from the adversary's own tally.

    Parameters
    ----------
    cell : Cell
        The cell, for the hypothesis, the detectability flag and the note.
    engaged_count : int
        Keyword-only. What the adversary's own log says it did. ``engaged``
        follows from it and is never asserted independently.

    Returns
    -------
    GroundTruth
    """
    return GroundTruth(
        hypothesis=cell.truth_hypothesis,
        engaged=engaged_count > 0,
        engaged_count=engaged_count,
        targeted_link=(
            None
            if cell.scenario_options.get("target") is None
            else str(cell.scenario_options["target"])
        ),
        detectable=cell.detectable,
        notes=cell.notes,
    )


ROC_SCENARIOS: Final[dict[str, Any]] = {
    "roc-outside-forgery": outside_forgery_scenario,
    "roc-recipient-forgery": recipient_forgery_scenario,
    "roc-replay": replay_scenario,
    "roc-count-starvation": starvation_scenario,
    "roc-impersonation": impersonation_scenario,
}
"""dict: The five scenarios this family adds, under prefixed keys.

Prefixed because :data:`~sih141.eval.experiments.SCENARIOS` is a flat registry
shared by every Phase 5 family and two families registering ``outside-forgery``
would silently give whichever imported last. :func:`register` refuses to
overwrite a key it does not own rather than trusting the prefix.
"""

ROC_PROBE_OPTIONS: Final[dict[str, dict[str, Any]]] = {
    "roc-impersonation": {"scope": "signing"},
}
"""dict: The smallest options each of this family's scenarios needs to run.

Registered into
:data:`~sih141.eval.experiments.SCENARIO_PROBE_OPTIONS` so that the harness's
contract test -- which runs every registered scenario twice and compares -- can
construct them. Only :func:`impersonation_scenario` appears: the other four
default every option they take, and ``scope`` is the one this family refuses to
default, because ``ImpersonationScope.NONE`` seizes nothing and a defaulted
typo would run an honest session under an attack label.
"""


# --------------------------------------------------------------------------- #
# Cells
# --------------------------------------------------------------------------- #


def _checked() -> ProtocolParams:
    """Return the checked parameter set every ROC cell but one runs at.

    Returns
    -------
    ProtocolParams
    """
    return ProtocolParams(
        key_length=ROC_KEY_LENGTH, check_fraction=ROC_CHECK_FRACTION
    )


def _roc_cells() -> tuple[Cell, ...]:
    """Build the ROC roster, in table order.

    Returns
    -------
    tuple of Cell
        Fifteen cells in two groups. The first eleven score against the
        **noiseless** null and reproduce Phase 4 section 5's arm list; the last
        four score against a link whose true error rate is admitted into the
        null, which is the only configuration in which this detector's ROC has
        a shape rather than a ceiling.
    """
    checked = _checked()
    tolerated = {
        "channel_error_rate": TOLERATED_ERROR_RATE,
        "tolerated_depolarising": TOLERATED_DEPOLARISING,
    }
    return (
        Cell(
            retain_transcript=True,
            name="honest",
            params=checked,
            notes="honest, noiseless link, noiseless null: the false-alarm arm",
        ),
        Cell(
            retain_transcript=True,
            name="honest-unchecked",
            params=ProtocolParams(key_length=ROC_KEY_LENGTH),
            notes=(
                "honest with no check rounds: the channel family is "
                "unevaluable and is withheld, never passed"
            ),
        ),
        Cell(
            retain_transcript=True,
            name="outside-forgery",
            params=checked,
            scenario="roc-outside-forgery",
            truth_hypothesis="outside-forgery",
            notes="Eve on the signer seam, holding nothing",
        ),
        Cell(
            retain_transcript=True,
            name="recipient-forgery",
            params=checked,
            scenario="roc-recipient-forgery",
            truth_hypothesis="recipient-forgery",
            notes=(
                "Bob forging to Charlie under the shipped ordering: Charlie "
                "reaches no verdict, which is a denial of transfer"
            ),
        ),
        Cell(
            retain_transcript=True,
            name="recipient-forgery-after",
            params=checked,
            scenario="roc-recipient-forgery",
            scenario_options={"count_exchange_timing": COUNTS_AFTER_FORWARDING},
            truth_hypothesis="recipient-forgery",
            notes=(
                "the same forger under the other ordering, where Charlie "
                "scores the substitution instead of refusing it"
            ),
        ),
        Cell(
            retain_transcript=True,
            name="replay",
            params=checked,
            scenario="roc-replay",
            truth_hypothesis="replay",
            notes="a stale declaration re-presented on the forwarding hop",
        ),
        Cell(
            retain_transcript=True,
            name="starvation",
            params=checked,
            scenario="roc-count-starvation",
            truth_hypothesis="count-starvation",
            notes="Charlie under-reporting his count on every exchange",
        ),
        Cell(
            retain_transcript=True,
            name="starvation-selective",
            params=checked,
            scenario="roc-count-starvation",
            scenario_options={"denial_probability": 0.5},
            truth_hypothesis="count-starvation",
            notes=(
                "the same starver denying half the runs: the untargeted half "
                "are honest runs and are scored as such"
            ),
        ),
        Cell(
            retain_transcript=True,
            name="impersonation-signing",
            params=checked,
            scenario="roc-impersonation",
            scenario_options={"scope": "signing"},
            truth_hypothesis="impersonation-signing-seam",
            notes="Mallory holding Phase B only: in model",
        ),
        Cell(
            retain_transcript=True,
            name="impersonation-full",
            params=checked,
            scenario="roc-impersonation",
            scenario_options={"scope": "full"},
            truth_hypothesis="impersonation-full",
            detectable=False,
            notes="both seams: out of model by assumption (AUTH)",
        ),
        Cell(
            retain_transcript=True,
            name="channel-bob",
            params=checked,
            scenario="depolarising",
            scenario_options={"strength": 0.10, "target": "Bob"},
            truth_hypothesis="channel-manipulation",
            notes="a depolariser on Bob's link only, scored noiseless",
        ),
        Cell(
            retain_transcript=True,
            name="tol-honest",
            params=checked,
            scenario="depolarising",
            scenario_options={"strength": 0.0, "target": "Bob"},
            truth_hypothesis="channel-manipulation",
            notes=(
                "the tolerated-null control: the attack engages on nothing, "
                "so every run here is an honest run and is scored as one"
            ),
            **tolerated,
        ),
        Cell(
            retain_transcript=True,
            name="tol-p05",
            params=checked,
            scenario="depolarising",
            scenario_options={"strength": TOLERATED_DEPOLARISING, "target": "Bob"},
            truth_hypothesis="channel-manipulation",
            notes="an adversary sitting exactly at the tolerated noise level",
            **tolerated,
        ),
        Cell(
            retain_transcript=True,
            name="tol-p20",
            params=checked,
            scenario="depolarising",
            scenario_options={"strength": 0.20, "target": "Bob"},
            truth_hypothesis="channel-manipulation",
            notes="four times the tolerated level",
            **tolerated,
        ),
        Cell(
            retain_transcript=True,
            name="tol-p35",
            params=checked,
            scenario="depolarising",
            scenario_options={"strength": 0.35, "target": "Bob"},
            truth_hypothesis="channel-manipulation",
            notes="seven times the tolerated level: the arm with a real curve",
            **tolerated,
        ),
    )


def _roc_experiment() -> Experiment:
    """Build the ROC experiment.

    Returns
    -------
    Experiment
    """
    return Experiment(
        name="roc",
        description=(
            "Detection against a swept false-positive budget, per adversary. "
            "Every operating point is a threshold derived by passing that "
            "budget to the shipped detector; nothing here is tuned."
        ),
        trials=ROC_TRIALS,
        cells=_roc_cells(),
    )


_SINGLETON: dict[str, Experiment] = {}
"""dict: Holds the one :class:`Experiment` object this family registers."""


def _singleton_experiment() -> Experiment:
    """Return the ROC experiment, built once and reused ever after.

    Returns
    -------
    Experiment

    Notes
    -----
    Lazy rather than a module-level constant, because
    :meth:`~sih141.eval.experiments.Cell.__post_init__` validates that a cell's
    scenario is in :data:`~sih141.eval.experiments.SCENARIOS` -- and this
    family's scenarios are not there until :func:`register` has put them there.
    Building the cells at import time therefore fails on the first cell that
    names one.

    Reused rather than rebuilt so :func:`register` can decide by **identity**
    whether the ``roc`` slot is this family's or somebody else's. Rebuilding
    would make an equal-but-distinct object and the collision check would fire
    on the second call.
    """
    made = _SINGLETON.get("roc")
    if made is None:
        made = _roc_experiment()
        _SINGLETON["roc"] = made
    return made


# --------------------------------------------------------------------------- #
# Scoring the ladder
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class OperatingPoint:
    """One run scored at one budget.

    Attributes
    ----------
    eps : float
        The budget.
    detected : bool
        Whether a **detection** signal fired.
    false_positive_bound : float
        Proven under the honest null.
    bound_is_unconditional : bool
        ``False`` where a positive ``channel_error_rate`` made the rate
        family's mismatch members conditional on this run's matched counts.
        Carried per point because the tolerated-null cells make it ``False``
        and the noiseless ones make it ``True``, in the same table.
    null_is_noiseless : bool
    security_claim : bool
    withheld : tuple of str
        Families and members with no admissible operating point at this
        budget. Grows as ``eps`` tightens, and that is the ROC's own view of
        ``can_fire``.
    kinds : tuple of str
        Which kinds of signal fired.
    """

    eps: float
    detected: bool
    false_positive_bound: float
    bound_is_unconditional: bool
    null_is_noiseless: bool
    security_claim: bool
    withheld: tuple[str, ...]
    kinds: tuple[str, ...]


_LADDER_CACHE: dict[tuple[Any, ...], tuple[OperatingPoint, ...]] = {}
"""dict: Ladders already computed, keyed by everything they depend on.

Three tables and a chart all want the same grid, and without this the reduction
scores every transcript five times. The key is the record's identity **and its
fingerprint** and the nulls and the ladder, so a record that changed gets a
fresh entry rather than a stale one; the fingerprint is what makes the cache a
memo of a pure function instead of a guess that the file has not moved.
"""

_LADDER_CACHE_LIMIT: Final[int] = 8192
"""int: Entries kept before the memo is dropped wholesale.

Room for the production family (15 cells at 40 trials, one ladder) many times
over. Cleared rather than evicted one at a time because the access pattern is a
reduction pass, not a working set.
"""


def score_ladder(
    record: TrialRecord, *, eps_values: Sequence[float] = EPS_LADDER
) -> tuple[OperatingPoint, ...]:
    """Score one stored run at every budget on the ladder.

    Every point is produced by handing ``eps`` to
    :func:`~sih141.detect.detector.detect` and reading what came back. No
    threshold is recomputed here, interpolated, or cached between budgets;
    :ref:`D7 <d7>` is a property of this function being three lines long.

    Parameters
    ----------
    record : TrialRecord
        Must carry its transcript. ROC cells set ``retain_transcript``, so a
        record without one came from a sweep run with the flag overridden.
    eps_values : Sequence of float, optional
        Keyword-only. Defaults to :data:`EPS_LADDER`.

    Returns
    -------
    tuple of OperatingPoint
        In the order given.

    Raises
    ------
    ValueError
        If the record has no transcript, naming the flag that would fix it. A
        silent empty result here would produce a ROC table of ``no trials``
        that looked like a measurement rather than a missing input.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell, run_trial, Experiment
    >>> from sih141.eval.roc import score_ladder
    >>> from sih141.protocol.params import ProtocolParams
    >>> tiny = Experiment(
    ...     name="rocdemo", trials=1,
    ...     cells=(Cell(name="f", params=ProtocolParams(key_length=96),
    ...                 scenario="roc-outside-forgery",
    ...                 truth_hypothesis="outside-forgery",
    ...                 retain_transcript=True),),
    ... )
    >>> record = run_trial(tiny, "f", 0)
    >>> points = score_ladder(record, eps_values=(1e-3, 1e-9))
    >>> [(p.eps, p.detected) for p in points]
    [(0.001, True), (1e-09, True)]

    The bound follows the budget rather than a constant:

    >>> points[0].false_positive_bound > points[1].false_positive_bound
    True
    """
    text = record.transcript_json
    if not text:
        raise ValueError(
            f"trial {record.identity} carries no transcript, so its ROC "
            f"ladder cannot be scored. The ROC cells set "
            f"retain_transcript=True; re-run the sweep without "
            f"--no-transcripts, or with --retain-transcripts."
        )
    noise = float(record.detection["channel_error_rate"])
    tolerated = _tolerated_of(record)
    key = (
        record.identity,
        record.fingerprint(),
        noise,
        tolerated,
        tuple(float(value) for value in eps_values),
    )
    cached = _LADDER_CACHE.get(key)
    if cached is not None:
        return cached
    # Parsed once, then handed to every budget. detect() re-reads JSON text on
    # every call, and at L = 384 that parse is 7 ms against a 3 ms detection --
    # so a fifteen-rung ladder would spend two thirds of its time reading the
    # same 125 KiB fifteen times. The detector's own doctest pins that the three
    # doors agree byte for byte, so this is the same computation and not a
    # shortcut past one.
    stats = TranscriptStatistics.from_json(text)
    points: list[OperatingPoint] = []
    for eps in eps_values:
        verdict = detect(
            stats,
            eps=float(eps),
            channel_error_rate=noise,
            tolerated_depolarising=tolerated,
        )
        points.append(
            OperatingPoint(
                eps=float(eps),
                detected=bool(verdict.detected),
                false_positive_bound=float(verdict.false_positive_bound),
                bound_is_unconditional=bool(verdict.bound_is_unconditional),
                null_is_noiseless=bool(verdict.null_is_noiseless),
                security_claim=bool(verdict.security_claim),
                withheld=tuple(str(item) for item in verdict.withheld),
                kinds=tuple(str(kind) for kind in verdict.kinds),
            )
        )
    if len(_LADDER_CACHE) >= _LADDER_CACHE_LIMIT:
        _LADDER_CACHE.clear()
    _LADDER_CACHE[key] = tuple(points)
    return tuple(points)


def _tolerated_of(record: TrialRecord) -> float:
    """Return the channel family's null this record was scored against.

    Parameters
    ----------
    record : TrialRecord
        One trial.

    Returns
    -------
    float
        ``p0``, read off the cell the record came from. The value is not on
        the record -- :class:`~sih141.detect.detector.Detection` carries
        ``channel_error_rate`` but not ``tolerated_depolarising`` -- so it is
        looked up in the registry, and a record whose cell has left the
        registry falls back to the noiseless ``0.0`` rather than guessing.

    Notes
    -----
    A registry that moved after the sweep ran would make this the wrong null,
    and what catches that is an observation rather than a convention:
    :func:`reconciliation` recomputes the anchor budget from the stored
    transcript and compares it with the verdict the worker stored, so a changed
    ``p0`` surfaces as a disagreement on ``false_positive_bound`` and
    :func:`roc_reduction` refuses to publish anything at all.
    """
    registered = EXPERIMENTS.get(record.experiment)
    if registered is None:
        return 0.0
    try:
        return float(registered.cell(record.cell).tolerated_depolarising)
    except KeyError:
        return 0.0


def reconciliation(
    records: Sequence[TrialRecord], *, eps_values: Sequence[float] = EPS_LADDER
) -> tuple[str, ...]:
    """Compare each record's run-time verdict against the reduction's own.

    Every ROC cell runs at :data:`~sih141.eval.experiments.DEFAULT_EPS`, which
    is on the ladder, so each record's stored
    :class:`~sih141.detect.detector.Detection` and this module's recomputation
    of the same point are two independent routes to one answer -- different
    process, different time, one from a live
    :class:`~sih141.detect.statistics.TranscriptStatistics` and one from the
    stored JSON. See :ref:`roc-crosscheck`.

    Parameters
    ----------
    records : Sequence of TrialRecord
        The records to check.
    eps_values : Sequence of float, optional
        Keyword-only. The ladder actually used. A record whose ``eps`` is not
        on it is skipped, and the skip is reported rather than passed over.

    Returns
    -------
    tuple of str
        One line per disagreement, empty when the two routes agree. A record
        that could not be checked at all produces a line saying so: "checked
        nothing" and "checked everything and found nothing" must not look
        alike.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell, Experiment, run_trial
    >>> from sih141.eval.roc import reconciliation
    >>> from sih141.protocol.params import ProtocolParams
    >>> tiny = Experiment(
    ...     name="rocdemo2", trials=1,
    ...     cells=(Cell(name="h", params=ProtocolParams(key_length=96),
    ...                 retain_transcript=True),),
    ... )
    >>> reconciliation([run_trial(tiny, "h", 0)], eps_values=(1e-9,))
    ()
    """
    problems: list[str] = []
    ladder = [float(value) for value in eps_values]
    for record in records:
        eps = float(record.eps)
        if eps not in ladder:
            problems.append(
                f"{record.identity}: run at eps={eps!r}, which is not on the "
                f"ladder {ladder}, so its stored verdict cross-checks nothing"
            )
            continue
        point = score_ladder(record, eps_values=(eps,))[0]
        stored = record.detection
        for label, mine, theirs in (
            ("detected", point.detected, bool(stored["detected"])),
            (
                "false_positive_bound",
                point.false_positive_bound,
                float(stored["false_positive_bound"]),
            ),
            (
                "withheld",
                point.withheld,
                tuple(str(item) for item in stored["withheld"]),
            ),
        ):
            if mine != theirs:
                problems.append(
                    f"{record.identity}: at eps={eps:g} the reduction says "
                    f"{label}={mine!r} and the record says {theirs!r}"
                )
    return tuple(problems)


def monotonicity_violations(
    records: Sequence[TrialRecord], *, eps_values: Sequence[float] = EPS_LADDER
) -> tuple[str, ...]:
    """Find runs that fire at a tighter budget but not at a looser one.

    The sharp form of "the curve must not go non-monotonic", checked per
    **run** rather than per rate. Because every budget scores the same
    transcripts (:ref:`roc-paired`), the set of budgets a given run fires at
    must be an up-set: a threshold derived at a looser ``eps`` is at or below
    the one derived at a tighter ``eps``, so anything that fires under the
    tighter cut fires under the looser one. A violation is therefore a
    statement about a threshold and not about the sample, and it is not
    something to smooth over or drop.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Records carrying transcripts.
    eps_values : Sequence of float, optional
        Keyword-only, **loosest first**. Defaults to :data:`EPS_LADDER`.

    Returns
    -------
    tuple of str
        One line per offending run, naming the two budgets.

    Raises
    ------
    ValueError
        If ``eps_values`` is not strictly decreasing, since the up-set claim
        is stated relative to that order.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell, Experiment, run_trial
    >>> from sih141.eval.roc import monotonicity_violations
    >>> from sih141.protocol.params import ProtocolParams
    >>> tiny = Experiment(
    ...     name="rocdemo3", trials=1,
    ...     cells=(Cell(name="f", params=ProtocolParams(key_length=96),
    ...                 scenario="roc-outside-forgery",
    ...                 truth_hypothesis="outside-forgery",
    ...                 retain_transcript=True),),
    ... )
    >>> monotonicity_violations([run_trial(tiny, "f", 0)],
    ...                         eps_values=(1e-1, 1e-6, 1e-12))
    ()
    """
    return tuple(
        f"{record.identity}: fires at eps={tighter:g} but not at the looser "
        f"eps={looser:g}"
        for record, looser, tighter in _up_set_failures(records, eps_values)
    )


def _up_set_failures(
    records: Sequence[TrialRecord], eps_values: Sequence[float]
) -> tuple[tuple[TrialRecord, float, float], ...]:
    """Return every adjacent pair of budgets a run fires on out of order.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Records carrying transcripts.
    eps_values : Sequence of float
        Loosest first.

    Returns
    -------
    tuple
        ``(record, looser_eps, tighter_eps)`` triples. Structured rather than
        formatted, so a table can ask which cells are affected without parsing
        a sentence back apart.

    Raises
    ------
    ValueError
        If ``eps_values`` is not strictly decreasing.
    """
    ladder = [float(value) for value in eps_values]
    if any(a <= b for a, b in zip(ladder, ladder[1:])):
        raise ValueError(
            f"eps_values must be strictly decreasing (loosest first), got "
            f"{ladder}. The up-set claim this function checks is stated "
            f"relative to that order."
        )
    out: list[tuple[TrialRecord, float, float]] = []
    for record in records:
        fired = [point.detected for point in score_ladder(record, eps_values=ladder)]
        for i in range(len(fired) - 1):
            if fired[i + 1] and not fired[i]:
                out.append((record, ladder[i], ladder[i + 1]))
    return tuple(out)


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RocPoint:
    """One cell, one ordering, one budget: the row a ROC chart plots.

    Attributes
    ----------
    cell, count_exchange_timing, hypothesis : str
        Identity. The ordering is part of it and is never averaged over.
    eps : float
        The budget.
    proven_bound : float
        The largest :attr:`~sih141.detect.detector.Detection.false_positive_bound`
        in the group. **Proven**, under the honest null.
    attacked, detected : int
        Denominator and numerator of the measured detection rate. ``attacked``
        counts runs whose adversary engaged, read off its own log.
    clean, false_alarms : int
        Denominator and numerator of the measured false-alarm rate: runs on
        which no adversary acted, including the untargeted runs of a selective
        attack cell.
    refusals : int
        Runs on which at least one verifier reached no verdict. Reported
        beside the rates and added to neither: a refusal is not a rejection
        and it is not a miss either.
    detectable : bool
        ``False`` where an assumption rules detection out.
    null_is_noiseless : bool or None
        ``None`` if the group somehow mixes the two, which would be a bug.
    bound_is_unconditional : bool
        ``False`` if any run's bound was conditioned on its matched counts.
    security_claims : int
        How many runs in the group carried a non-degenerate floor.
    withheld : tuple of str
        Everything withheld on at least one run at this budget.
    dominance_noise_level : float or None
        The link error rate above which the mismatch member stops adding
        anything over the verifier's own cut, at this budget and this group's
        median matched count. Published beside the rate because a detector
        that only fires on runs the verifier already rejected has marginal
        information zero, and that is a property of the noise level rather
        than of the detector.
    """

    cell: str
    count_exchange_timing: str
    hypothesis: str
    eps: float
    proven_bound: float
    attacked: int
    detected: int
    clean: int
    false_alarms: int
    refusals: int
    detectable: bool
    null_is_noiseless: bool | None
    bound_is_unconditional: bool
    security_claims: int
    withheld: tuple[str, ...]
    dominance_noise_level: float | None

    @property
    def detection_rate(self) -> float | None:
        """float or None: Measured, over ``attacked``. ``None`` with no
        attacked runs -- never ``0.0``, which would read as a detector that
        tried and failed."""
        return None if self.attacked == 0 else self.detected / self.attacked

    @property
    def false_alarm_rate(self) -> float | None:
        """float or None: Measured, over ``clean``."""
        return None if self.clean == 0 else self.false_alarms / self.clean


def _median_matched(group: Sequence[TrialRecord]) -> int | None:
    """Return the group's median matched count over both verifiers.

    Parameters
    ----------
    group : Sequence of TrialRecord
        One cell's runs.

    Returns
    -------
    int or None
        ``None`` when no verifier in the group reached a verdict, or when the
        median count is zero. Either way there is no matched count to state a
        dominance level over, and a starved cell where every verifier refused
        is exactly the case that would otherwise ask
        :func:`~sih141.detect.thresholds_rate.dominance_noise_level` for a
        threshold over an empty sample.
    """
    counts = sorted(
        int(value)
        for record in group
        for value in record.transcript_summary["matched"].values()
    )
    if not counts:
        return None
    median = counts[len(counts) // 2]
    return median if median >= 1 else None


def roc_points(
    records: Sequence[TrialRecord],
    *,
    eps_values: Sequence[float] = EPS_LADDER,
    cell_order: Sequence[str] | None = None,
) -> tuple[RocPoint, ...]:
    """Reduce records to the ROC grid: one point per cell, ordering and budget.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    eps_values : Sequence of float, optional
        Keyword-only. The ladder.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order; see
        :func:`~sih141.eval.reduce.group_records`.

    Returns
    -------
    tuple of RocPoint

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell, Experiment, run_trial
    >>> from sih141.eval.roc import roc_points
    >>> from sih141.protocol.params import ProtocolParams
    >>> tiny = Experiment(
    ...     name="rocdemo4", trials=2,
    ...     cells=(Cell(name="f", params=ProtocolParams(key_length=96),
    ...                 scenario="roc-outside-forgery",
    ...                 truth_hypothesis="outside-forgery",
    ...                 retain_transcript=True),),
    ... )
    >>> made = [run_trial(tiny, "f", i) for i in range(2)]
    >>> points = roc_points(made, eps_values=(1e-3, 1e-9))
    >>> [(p.eps, p.attacked, p.detected, p.clean) for p in points]
    [(0.001, 2, 2, 0), (1e-09, 2, 2, 0)]
    >>> points[0].detection_rate, points[0].false_alarm_rate
    (1.0, None)
    """
    if not records:
        raise ValueError("roc_points needs at least one record")
    grouped = group_records(records, cell_order=cell_order)
    ladders = {
        record.identity: score_ladder(record, eps_values=eps_values)
        for record in records
    }
    out: list[RocPoint] = []
    for (cell, timing), group in grouped.items():
        hypotheses = ", ".join(sorted({r.truth.hypothesis for r in group}))
        detectable = all(r.truth.detectable for r in group)
        attacked = [r for r in group if r.truth.attacked]
        clean = [r for r in group if not r.truth.attacked]
        # Through the shared predicate, so this family and the standard
        # detection table cannot drift apart on what a refusal is. The second
        # clause this used to carry -- fewer than two recorded verdicts --
        # is a *not-asked* party in the outcome table's taxonomy, which that
        # table is explicit is "a third thing again from a refusal"; it was
        # dead on every record ever produced (all 12,494 of the production
        # sweep carry exactly two) and folding it in here contradicted the
        # table three sections above.
        refusals = sum(1 for r in group if refused_run(r))
        matched = _median_matched(group)
        cut = float(group[0].params["s_a"])
        for position, eps in enumerate(eps_values):
            points = {r.identity: ladders[r.identity][position] for r in group}
            nulls = {points[r.identity].null_is_noiseless for r in group}
            withheld: set[str] = set()
            for record in group:
                withheld.update(points[record.identity].withheld)
            out.append(
                RocPoint(
                    cell=cell,
                    count_exchange_timing=timing,
                    hypothesis=hypotheses,
                    eps=float(eps),
                    proven_bound=max(
                        points[r.identity].false_positive_bound for r in group
                    ),
                    attacked=len(attacked),
                    detected=sum(1 for r in attacked if points[r.identity].detected),
                    clean=len(clean),
                    false_alarms=sum(
                        1 for r in clean if points[r.identity].detected
                    ),
                    refusals=refusals,
                    detectable=detectable,
                    null_is_noiseless=(
                        nulls.pop() if len(nulls) == 1 else None
                    ),
                    bound_is_unconditional=all(
                        points[r.identity].bound_is_unconditional for r in group
                    ),
                    security_claims=sum(
                        1 for r in group if points[r.identity].security_claim
                    ),
                    withheld=tuple(sorted(withheld)),
                    dominance_noise_level=(
                        None
                        if matched is None
                        else dominance_noise_level(matched, cut, eps=float(eps))
                    ),
                )
            )
    return tuple(out)


def _missing_note(
    records: Sequence[TrialRecord],
    expected: Mapping[str, int] | None = None,
) -> str:
    """Say whether every trial the sweep asked for is on disk.

    Parameters
    ----------
    records : Sequence of TrialRecord
        All records for the experiment.
    expected : Mapping or None, optional
        Per-cell trial counts from the store's manifests, handed down the
        :data:`~sih141.eval.reduce.EXTRA_REDUCTIONS` contract. ``None`` or
        empty means the caller had no manifest to check against, and the note
        then says only what it could check.

    Returns
    -------
    str
        A footnote. A trial whose scenario raised leaves **no file on disk**,
        so a reduction that only counted what it found would publish a rate
        over a denominator that had quietly shrunk.

    Notes
    -----
    This delegates to :func:`~sih141.eval.reduce.completeness_note` and is kept
    only because this family's ROC table wants the footnote on its own table
    rather than only on the outcome table.

    It used to be a second implementation, and the difference mattered: it
    looked for gaps *below the highest index present*, which catches a scenario
    that raised and misses the case an interrupted sweep actually leaves -- a
    short tail. A cell asked for 400 trials with 380 on disk reported "no trial
    index is missing from any cell", which is false reassurance rather than
    silence. The shared version checks the count against the manifest as well.

    It then made the opposite mistake for one release: called with no expected
    counts at all, it printed "No manifest recorded a trial count for this
    store" onto a grid whose own outcome table, three sections up the same
    file, said "Complete: every cell has all the trials its manifest asked
    for". Both cannot be true of one store, and a reader has no way to tell
    which. The counts now come down the reduction hook, so the two notes are
    computed from the same mapping.
    """
    return completeness_note(records, dict(expected or {}))


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #


def _roc_notes(points: Sequence[RocPoint]) -> list[str]:
    """Build the footnotes every ROC table carries.

    Parameters
    ----------
    points : Sequence of RocPoint
        The grid.

    Returns
    -------
    list of str
    """
    withheld = sorted({item for point in points for item in point.withheld})
    notes = [
        "**The two axes are different kinds of number.** `proven FP bound` is "
        "Detection.false_positive_bound: a union bound under the honest null, "
        "true of every run that will ever be scored. `detected (measured)` "
        "and `false alarms (measured)` are MEASUREMENTS with a sample size, "
        f"shown as k/n with a {CONFIDENCE:.0%} Wilson interval. There is no "
        "false-negative bound and there cannot be one from a transcript, so "
        "the two never share a column.",
        "**Denominators.** `detected` is over `attacked`: runs whose "
        "adversary engaged, counted off the adversary's own log and never "
        "off the cell's intent. `false alarms` is over `clean`: runs on "
        "which no adversary acted, which includes the untargeted runs of a "
        "selective cell -- such a run is byte-identical to an honest one and "
        "is scored as one.",
        "**Aborts are neither.** `refusals` counts runs where a verifier "
        "reached no verdict. They are shown in their own column and are added "
        "to nothing: a refusal is not a rejection, and it is not a miss "
        "either. The detector returned a verdict on every run in the "
        "denominators above, refusal or not, so no run has been dropped.",
        "**`count_exchange_timing` is a column, never averaged over.** The "
        "two orderings give different answers to the same attack; the "
        "recipient-forgery rows are the case in point, where one ordering "
        "produces a rejection and the other a denial of transfer.",
        f"**`{UNDETECTABLE_BY_CONSTRUCTION}`** means an assumption rules "
        "detection out for that hypothesis -- full impersonation under "
        "(AUTH). It is never a blank, a dash or a zero. The clean column on "
        "such a row is still a measurement, because the assumption is about "
        "the attack and not about the runs it left alone.",
        "**`null_is_noiseless`** says whether the mismatch members were "
        "scored against a link on which a matched position never disagrees. "
        "On a genuinely noisy link that null is not the truth, honest runs "
        "depart from it, and the mismatch members fire correctly -- so `yes` "
        "on an attacked row is a caveat on the row, not a detail. The `tol-` "
        "cells are the same physics scored against the link's true error "
        f"rate ({TOLERATED_ERROR_RATE}), and they are the only cells here "
        "whose curve has a shape.",
        "**`dominance p_e`** is dominance_noise_level() at this budget and "
        "this group's median matched count, against the party cut s_a. Above "
        "that link error rate every run the mismatch member flags is a run "
        "the verifier has already rejected, and its marginal information is "
        "zero. Published beside the rate rather than in a footnote because "
        "the design noise level 2*s_a is larger than it at the default "
        "parameters.",
        "**Every point is derived.** The only argument that moves between "
        "rows of one cell is `eps`, handed to the shipped detect(). No "
        "threshold was fitted, chosen or nudged on attack data (D7).",
    ]
    if withheld:
        notes.append(
            f"Withheld somewhere in this table, reported as `{NOT_EVALUATED}` "
            "and never as passed: " + ", ".join(withheld) + "."
        )
    return notes


def roc_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
    eps_values: Sequence[float] = EPS_LADDER,
    expected: Mapping[str, int] | None = None,
) -> Table:
    """The ROC grid: one row per cell, ordering and budget.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. The regenerating command.
    cell_order : Sequence of str or None, optional
        Keyword-only. Row order.
    eps_values : Sequence of float, optional
        Keyword-only. The ladder.
    expected : Mapping or None, optional
        Keyword-only. Per-cell trial counts the sweep asked for, so the
        completeness footnote can check the count and not only the index
        sequence. See :func:`_missing_note`.

    Returns
    -------
    Table

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell, Experiment, run_trial
    >>> from sih141.eval.roc import roc_table
    >>> from sih141.protocol.params import ProtocolParams
    >>> tiny = Experiment(
    ...     name="rocdemo5", trials=1,
    ...     cells=(Cell(name="f", params=ProtocolParams(key_length=96),
    ...                 scenario="roc-outside-forgery",
    ...                 truth_hypothesis="outside-forgery",
    ...                 retain_transcript=True),),
    ... )
    >>> table = roc_table([run_trial(tiny, "f", 0)], eps_values=(1e-9,))
    >>> table.columns[:6]
    ('cell', 'count_exchange_timing', 'hypothesis', 'eps', 'proven FP bound', 'attacked')
    >>> table.rows[0][3], table.rows[0][5], table.rows[0][6]
    ('1e-09', 1, '1/1 = 1.000 [0.131, 1.000]')
    """
    points = roc_points(records, eps_values=eps_values, cell_order=cell_order)
    rows = tuple(
        (
            point.cell,
            point.count_exchange_timing,
            point.hypothesis,
            f"{point.eps:.0e}",
            f"{point.proven_bound:.4e}",
            point.attacked,
            (
                UNDETECTABLE_BY_CONSTRUCTION
                if not point.detectable
                else measured_rate(point.detected, point.attacked)
            ),
            point.clean,
            measured_rate(point.false_alarms, point.clean),
            point.refusals,
            (
                "yes"
                if point.null_is_noiseless
                else "no"
                if point.null_is_noiseless is not None
                else "mixed"
            ),
            "yes" if point.bound_is_unconditional else "no",
            (
                "-"
                if point.dominance_noise_level is None
                else f"{point.dominance_noise_level:.6f}"
            ),
            (
                f"{NOT_EVALUATED} ({len(point.withheld)})"
                if point.withheld
                else "-"
            ),
        )
        for point in points
    )
    return Table(
        slug="roc",
        title=(
            "ROC grid: measured detection against a proven false-positive "
            "bound, per adversary, per derived operating point"
        ),
        columns=(
            "cell",
            "count_exchange_timing",
            "hypothesis",
            "eps",
            "proven FP bound",
            "attacked",
            "detected (measured)",
            "clean",
            "false alarms (measured)",
            "refusals",
            "null_is_noiseless",
            "bound unconditional",
            "dominance p_e",
            "withheld",
        ),
        rows=rows,
        command=command,
        notes=tuple(_roc_notes(points) + [_missing_note(records, expected)]),
    )


def _breaks_at(
    group: Sequence[RocPoint], ladder: Sequence[float], *, detectable: bool
) -> str:
    """Say where on the ladder this cell's measured rate leaves the ceiling.

    Parameters
    ----------
    group : Sequence of RocPoint
        One cell's points, loosest budget first.
    ladder : Sequence of float
        The budgets, loosest first.
    detectable : bool
        Keyword-only. ``False`` where an assumption rules detection out.

    Returns
    -------
    str
        One of five answers, all of them stated rather than implied. A cell
        with no attacked runs has no curve to break; a hypothesis excluded by
        assumption has no curve at all; and a cell already below the ceiling
        at the loosest budget never reached it, which is a different fact from
        "it fell off at 5e-01" and reads very differently in a table.
    """
    if not detectable:
        return UNDETECTABLE_BY_CONSTRUCTION
    if group[0].attacked == 0:
        return "no attacked runs"
    below = [
        point
        for point in group
        if point.detection_rate is not None and point.detection_rate < 1.0
    ]
    if not below:
        return "never below 1.0"
    if below[0].eps == float(ladder[0]):
        return "below 1.0 at every budget on the ladder"
    return f"{below[0].eps:.0e}"


def roc_envelope_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
    eps_values: Sequence[float] = EPS_LADDER,
) -> Table:
    """One row per adversary: where on the ladder the curve actually moves.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only.
    cell_order : Sequence of str or None, optional
        Keyword-only.
    eps_values : Sequence of float, optional
        Keyword-only.

    Returns
    -------
    Table
        Per cell and ordering: the detection rate at the loosest budget, at
        ``1e-9`` (Phase 4's published column) and at the tightest, the budget
        at which the measured rate first falls below one, and whether the
        run-level up-set property held.

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Notes
    -----
    The ``breaks at`` column is the ROC's shape in one number. A cell that
    never breaks is a curve that is flat at ``1.0`` over thirty decades of
    budget, which is a real result about the separation the adversary
    produces, not a missing measurement.
    """
    points = roc_points(records, eps_values=eps_values, cell_order=cell_order)
    ladder = [float(value) for value in eps_values]
    by_group: dict[tuple[str, str], list[RocPoint]] = {}
    for point in points:
        by_group.setdefault((point.cell, point.count_exchange_timing), []).append(
            point
        )
    failures = _up_set_failures(records, ladder)
    violations = monotonicity_violations(records, eps_values=ladder)
    offenders = {
        (record.cell, record.count_exchange_timing) for record, _, _ in failures
    }
    rows: list[tuple[Any, ...]] = []
    for (cell, timing), group in by_group.items():
        at = {point.eps: point for point in group}
        loosest, tightest = at[ladder[0]], at[ladder[-1]]
        anchor = at.get(DEFAULT_EPS)
        detectable = loosest.detectable

        def rate_cell(point: RocPoint | None) -> str:
            """Format one budget's measured rate for this row."""
            if not detectable:
                return UNDETECTABLE_BY_CONSTRUCTION
            if point is None:
                return f"{NOT_EVALUATED} (budget not on the ladder)"
            return measured_rate(point.detected, point.attacked)

        rows.append(
            (
                cell,
                timing,
                loosest.hypothesis,
                loosest.attacked,
                loosest.clean,
                rate_cell(loosest),
                rate_cell(anchor),
                rate_cell(tightest),
                _breaks_at(group, ladder, detectable=detectable),
                "no" if (cell, timing) in offenders else "yes",
            )
        )
    notes = [
        "`breaks at` is the loosest budget at which the measured detection "
        "rate first falls below 1.0. `never below 1.0` means the curve is "
        "flat at the ceiling across the whole ladder -- a result about how "
        "large the separation is, not a measurement that failed. `below 1.0 "
        "at every budget` means it never reached the ceiling, which is a "
        "different fact and is not abbreviated to a budget value.",
        "`up-set holds` is checked per RUN, not per rate: because every "
        "budget scores the same transcripts, a run that fires at a tighter "
        "eps must fire at every looser one. A `no` here is a finding about a "
        "threshold and is not smoothed over.",
        f"The `at eps=1e-09` column is the one Phase 4 section 5 published, "
        f"at the same n = {ROC_TRIALS} and the same key length, so the two "
        "are directly comparable.",
        "ABORTS: every rate here is over `attacked` or `clean`, and a run "
        "where a verifier reached no verdict stays in whichever of the two it "
        "belongs to -- a refusal is not a rejection and it is not a miss. The "
        "grid above carries the per-cell `refusals` count, and the "
        "recipient-forgery rows are the case worth reading there: one "
        "ordering is a denial of transfer and the other a forgery rate.",
    ]
    if violations:
        notes.append(
            "**Up-set violations, verbatim:** " + "; ".join(violations)
        )
    return Table(
        slug="roc-envelope",
        title="Where each adversary's curve moves, and whether it is monotone",
        columns=(
            "cell",
            "count_exchange_timing",
            "hypothesis",
            "attacked",
            "clean",
            f"at eps={ladder[0]:.0e} (measured)",
            "at eps=1e-09 (measured)",
            f"at eps={ladder[-1]:.0e} (measured)",
            "breaks at",
            "up-set holds",
        ),
        rows=tuple(rows),
        command=command,
        notes=tuple(notes),
    )


def roc_prototype_table(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
    eps_values: Sequence[float] = EPS_LADDER,
) -> Table:
    """The comparison against the Phase 3 prototype, with the two axes kept apart.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only.
    cell_order : Sequence of str or None, optional
        Keyword-only.
    eps_values : Sequence of float, optional
        Keyword-only.

    Returns
    -------
    Table
        Two rows -- the prototype and this detector -- against the same four
        questions.

    Notes
    -----
    The prototype separated *four of five adversaries at 100% with ``0/80``
    false alarms*, on thresholds that were not derived from a stated null. The
    honest way to read the comparison is not rate against rate. ``0/80`` and a
    modern ``0/n`` are both **observations**, and both are consistent with a
    true false-alarm rate of a few percent; the derived detector replaces that
    observation with a **proven** bound that holds for every run that will ever
    be scored, and the sample size is what the derivation makes irrelevant.

    **A lower detection rate from a derived threshold is a better result than a
    higher rate from a tuned one, and it must be presented as such** -- in
    those words, because the alternative reading ("the new detector is worse")
    is the one a reader reaches for. What a tuned threshold buys is power on
    the runs it was tuned on and nothing at all on the next hundred thousand.
    """
    points = roc_points(records, eps_values=eps_values, cell_order=cell_order)
    anchored = [p for p in points if p.eps == DEFAULT_EPS]
    rows: list[tuple[Any, ...]] = [
        (
            "Phase 3 prototype (thresholds not derived)",
            PROTOTYPE_ARMS,
            f"{PROTOTYPE_FALSE_ALARMS} observed",
            "none -- there is no null to invert",
            "tuned on the runs in front of it",
        )
    ]
    # Split by null rather than pooled. The two halves of this family were
    # scored against different nulls, and a single headline over both would
    # average a detector that saw everything with one that was asked to ignore
    # the noise the attack was hiding in -- the same pooling error the timing
    # column exists to prevent, one axis over.
    if not anchored:
        # The comparison is stated at one budget, and if that budget was not
        # scored there is nothing to compare. Returning the prototype's row
        # alone would read as a detector that had been measured and found
        # wanting.
        rows.append(
            (
                "Phase 4 detector",
                f"{NOT_EVALUATED}: eps={DEFAULT_EPS:g} is not on the ladder "
                f"this reduction was given",
                NOT_EVALUATED,
                NOT_EVALUATED,
                "derived from a stated null and a concentration inequality (D7)",
            )
        )
    for noiseless, label in ((True, "noiseless null"), (False, "true rate as null")):
        group = [p for p in anchored if p.null_is_noiseless is noiseless]
        if not group:
            continue
        attack_rows = [p for p in group if p.attacked > 0 and p.detectable]
        perfect = sum(
            1
            for p in attack_rows
            if p.detection_rate is not None and p.detection_rate >= 1.0
        )
        undetectable = sum(1 for p in group if not p.detectable)
        clean_alarms = sum(p.false_alarms for p in group)
        clean_runs = sum(p.clean for p in group)
        bounds = [p.proven_bound for p in group]
        rows.append(
            (
                f"Phase 4 detector at eps=1e-09, {label}",
                f"{perfect} of {len(attack_rows)} attacked arms at 100%"
                + (
                    f"; {undetectable} arm {UNDETECTABLE_BY_CONSTRUCTION}"
                    if undetectable
                    else ""
                ),
                f"{measured_rate(clean_alarms, clean_runs)} observed",
                f"{max(bounds):.4e} proven, per run, under the honest null"
                if bounds
                else NOT_EVALUATED,
                "derived from a stated null and a concentration inequality (D7)",
            )
        )
    return Table(
        slug="roc-prototype",
        title="Against the Phase 3 prototype: what the derivation cost",
        columns=(
            "detector",
            "attacked arms separated",
            "false alarms (measured)",
            "false-alarm bound (proven)",
            "how the threshold was chosen",
        ),
        rows=tuple(rows),
        command=command,
        notes=(
            "The two false-alarm columns are not the same kind of statement "
            "and must not be read as a like-for-like improvement. "
            f"`{PROTOTYPE_FALSE_ALARMS}` and the observed column here are both "
            "OBSERVATIONS, and both are consistent with a true false-alarm "
            "rate of a few percent. The proven column is a statement about "
            "every run that will ever be scored. The sample size is what the "
            "derivation makes irrelevant.",
            "The two experiments share no parameter set, seed set or arm "
            "list, so the sensible reading is `the derivation did not cost "
            "detection`, not `the derived detector is better`.",
            "**A lower detection rate from a derived threshold is a better "
            "result than a higher rate from a tuned one.** Where a rate here "
            "is below the prototype's, that is the correct trade and not a "
            "regression: a tuned cut buys power on the runs it was tuned on "
            "and says nothing about the next hundred thousand. This family "
            "reports the rate it measures and does not move a threshold to "
            "improve it (D7).",
            "The `tol-` cells are where the derived detector does give ground, "
            "and the reason is stated rather than tuned away: once the link's "
            "own error rate is admitted into the null, an adversary at or near "
            "that level is inside the noise the protocol already tolerates. "
            "That is a result about the protocol's observability.",
            "DENOMINATORS AND ABORTS: `false alarms (measured)` is over the "
            "clean runs of the arms in that row's null -- the untargeted runs "
            "of a selective cell included, since such a run is byte-identical "
            "to an honest one -- and the count is printed rather than implied. "
            "None of those runs reached a no-verdict; where an arm does refuse "
            "it is counted in the grid's own `refusals` column and is added to "
            "neither denominator.",
        ),
    )


# --------------------------------------------------------------------------- #
# The chart
# --------------------------------------------------------------------------- #

_CHART_WIDTH: Final[int] = 980
_CHART_HEIGHT: Final[int] = 560
_CHART_LEFT: Final[int] = 96
#: Reserved for the legend. Wide enough for the longest label this family
#: produces -- ``recipient-forgery-after [after-forwarding] (n=40)`` -- beside
#: its colour swatch, at the legend's own font size. A test estimates the
#: rendered width and fails if a longer cell name is added without widening it.
_CHART_RIGHT: Final[int] = 344
_CHART_TOP: Final[int] = 64
_CHART_BOTTOM: Final[int] = 96
_SERIES_COLOURS: Final[tuple[str, ...]] = (
    "#1b4f72",
    "#b03a2e",
    "#1e8449",
    "#7d3c98",
    "#b9770e",
    "#117a8b",
    "#5d6d7e",
    "#943126",
)


def _chart_x(bound: float, lo: float, hi: float) -> float:
    """Map a proven bound to a horizontal pixel on a log axis.

    Parameters
    ----------
    bound : float
        The proven false-positive bound.
    lo, hi : float
        Axis ends, as base-ten logarithms.

    Returns
    -------
    float
    """
    span = _CHART_WIDTH - _CHART_LEFT - _CHART_RIGHT
    value = math.log10(bound) if bound > 0.0 else lo
    fraction = 0.0 if hi == lo else (value - lo) / (hi - lo)
    return _CHART_LEFT + span * min(1.0, max(0.0, fraction))


def _chart_y(rate: float) -> float:
    """Map a rate in ``[0, 1]`` to a vertical pixel.

    Parameters
    ----------
    rate : float
        The measured rate.

    Returns
    -------
    float
    """
    span = _CHART_HEIGHT - _CHART_TOP - _CHART_BOTTOM
    return _CHART_TOP + span * (1.0 - min(1.0, max(0.0, rate)))


def roc_chart_svg(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
    eps_values: Sequence[float] = EPS_LADDER,
) -> str:
    """Render the ROC as an SVG whose axes say what kind of number each is.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Any order.
    command : str, optional
        Keyword-only. Printed inside the chart, because a figure separated
        from the command that made it is not reproducible (D9).
    cell_order : Sequence of str or None, optional
        Keyword-only.
    eps_values : Sequence of float, optional
        Keyword-only.

    Returns
    -------
    str
        A standalone SVG document. Deterministic: the same records give the
        same bytes.

    Raises
    ------
    ValueError
        If ``records`` is empty.

    Notes
    -----
    Constraint 6 is a constraint on the **chart**, not only on the table: the
    horizontal axis is proven and the vertical is measured, and a screenshot
    of the plot has to carry that. So the words are in the axis labels rather
    than in a caption, each measured point carries its 99% Wilson interval as
    a vertical bar, and an arm ruled out by assumption is drawn as a labelled
    band rather than as a line along zero.

    Examples
    --------
    >>> from sih141.eval.experiments import Cell, Experiment, run_trial
    >>> from sih141.eval.roc import roc_chart_svg
    >>> from sih141.protocol.params import ProtocolParams
    >>> tiny = Experiment(
    ...     name="rocdemo6", trials=1,
    ...     cells=(Cell(name="f", params=ProtocolParams(key_length=96),
    ...                 scenario="roc-outside-forgery",
    ...                 truth_hypothesis="outside-forgery",
    ...                 retain_transcript=True),),
    ... )
    >>> svg = roc_chart_svg([run_trial(tiny, "f", 0)], eps_values=(1e-3, 1e-9))
    >>> svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    True
    >>> "PROVEN" in svg and "MEASURED" in svg
    True
    """
    points = roc_points(records, eps_values=eps_values, cell_order=cell_order)
    bounds = [p.proven_bound for p in points if p.proven_bound > 0.0]
    if not bounds:
        raise ValueError("roc_chart_svg found no positive proven bound to plot")
    lo = math.floor(math.log10(min(bounds)))
    hi = math.ceil(math.log10(max(bounds)))
    if hi == lo:
        hi = lo + 1

    by_group: dict[tuple[str, str], list[RocPoint]] = {}
    for point in points:
        by_group.setdefault((point.cell, point.count_exchange_timing), []).append(
            point
        )

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{_CHART_WIDTH}" '
        f'height="{_CHART_HEIGHT}" viewBox="0 0 {_CHART_WIDTH} '
        f'{_CHART_HEIGHT}" font-family="Georgia, serif" font-size="12">',
        f'<rect width="{_CHART_WIDTH}" height="{_CHART_HEIGHT}" fill="#ffffff"/>',
        f'<text x="{_CHART_LEFT}" y="28" font-size="16" font-weight="bold">'
        "Detection against a derived operating point</text>",
        f'<text x="{_CHART_LEFT}" y="46" fill="#555555">'
        "one curve per adversary; every point is a threshold derived by "
        "passing eps to the shipped detector</text>",
    ]

    # Axes and gridlines.
    plot_bottom = _CHART_HEIGHT - _CHART_BOTTOM
    plot_right = _CHART_WIDTH - _CHART_RIGHT
    for decade in range(lo, hi + 1):
        x = _chart_x(10.0**decade, lo, hi)
        parts.append(
            f'<line x1="{x:.1f}" y1="{_CHART_TOP}" x2="{x:.1f}" '
            f'y2="{plot_bottom}" stroke="#e2e2e2"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{plot_bottom + 16}" text-anchor="middle" '
            f'fill="#555555">1e{decade}</text>'
        )
    for tick in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = _chart_y(tick)
        parts.append(
            f'<line x1="{_CHART_LEFT}" y1="{y:.1f}" x2="{plot_right}" '
            f'y2="{y:.1f}" stroke="#e2e2e2"/>'
        )
        parts.append(
            f'<text x="{_CHART_LEFT - 8}" y="{y + 4:.1f}" text-anchor="end" '
            f'fill="#555555">{tick:.2f}</text>'
        )
    parts.append(
        f'<line x1="{_CHART_LEFT}" y1="{plot_bottom}" x2="{plot_right}" '
        f'y2="{plot_bottom}" stroke="#333333"/>'
    )
    parts.append(
        f'<line x1="{_CHART_LEFT}" y1="{_CHART_TOP}" x2="{_CHART_LEFT}" '
        f'y2="{plot_bottom}" stroke="#333333"/>'
    )
    parts.append(
        f'<text x="{(_CHART_LEFT + plot_right) / 2:.0f}" '
        f'y="{plot_bottom + 42}" text-anchor="middle" font-weight="bold">'
        "PROVEN false-positive bound (union bound under the honest null)"
        "</text>"
    )
    parts.append(
        f'<text x="{(_CHART_LEFT + plot_right) / 2:.0f}" '
        f'y="{plot_bottom + 60}" text-anchor="middle" fill="#555555">'
        "smaller is a stronger guarantee; the budget eps runs from "
        f"{eps_values[0]:.0e} at the right to {eps_values[-1]:.0e} at the left"
        "</text>"
    )
    parts.append(
        f'<text transform="translate(24,{(_CHART_TOP + plot_bottom) / 2:.0f}) '
        'rotate(-90)" text-anchor="middle" font-weight="bold">'
        f"MEASURED detection rate ({CONFIDENCE:.0%} Wilson interval)</text>"
    )

    # Series.
    legend_y = _CHART_TOP
    drawn = 0
    for (cell, timing), group in sorted(by_group.items()):
        # Counted over the series that actually get a line, not over every
        # group: three of this family's cells have no attacked runs and appear
        # in the legend as text only, and letting them consume a colour would
        # push two real adversaries onto the same one.
        colour = _SERIES_COLOURS[drawn % len(_SERIES_COLOURS)]
        dashes = (
            ""
            if drawn < len(_SERIES_COLOURS)
            else ' stroke-dasharray="6 3"'
            if drawn < 2 * len(_SERIES_COLOURS)
            else ' stroke-dasharray="2 3"'
        )
        label = cell if timing == COUNTS_BEFORE_FORWARDING else f"{cell} [{timing}]"
        if not group[0].detectable:
            parts.append(
                f'<text x="{plot_right + 16}" y="{legend_y + 4}" fill="#777777" '
                f'font-size="11">{escape_xml(label)}: '
                f"{UNDETECTABLE_BY_CONSTRUCTION}</text>"
            )
            legend_y += 18
            continue
        plotted = [p for p in group if p.detection_rate is not None]
        if not plotted:
            parts.append(
                f'<text x="{plot_right + 16}" y="{legend_y + 4}" fill="#777777" '
                f'font-size="11">{escape_xml(label)}: no attacked runs</text>'
            )
            legend_y += 18
            continue
        coords = [
            (
                _chart_x(p.proven_bound, lo, hi),
                _chart_y(p.detection_rate or 0.0),
            )
            for p in plotted
        ]
        path = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
        parts.append(
            f'<polyline points="{path}" fill="none" stroke="{colour}" '
            f'stroke-width="1.6"{dashes}/>'
        )
        for point, (x, y) in zip(plotted, coords):
            interval = wilson_interval(
                point.detected, point.attacked, confidence=CONFIDENCE
            )
            parts.append(
                f'<line x1="{x:.1f}" y1="{_chart_y(interval.low):.1f}" '
                f'x2="{x:.1f}" y2="{_chart_y(interval.high):.1f}" '
                f'stroke="{colour}" stroke-width="1" opacity="0.45"/>'
            )
            parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{colour}"/>'
            )
        parts.append(
            f'<line x1="{plot_right + 16}" y1="{legend_y}" '
            f'x2="{plot_right + 40}" y2="{legend_y}" stroke="{colour}" '
            f'stroke-width="1.6"{dashes}/>'
        )
        parts.append(
            f'<text x="{plot_right + 46}" y="{legend_y + 4}" fill="{colour}" '
            f'font-size="11">{escape_xml(label)} '
            f"(n={plotted[0].attacked})</text>"
        )
        legend_y += 18
        drawn += 1

    parts.append(
        f'<text x="{_CHART_LEFT}" y="{_CHART_HEIGHT - 12}" fill="#777777" '
        f'font-size="10">Regenerate: '
        f'{escape_xml(command or "NO COMMAND RECORDED -- not reproducible (D9)")}'
        "</text>"
    )
    parts.append("</svg>")
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Wiring into the sweep
# --------------------------------------------------------------------------- #


def roc_reduction(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
    expected: Mapping[str, int] | None = None,
) -> list[Table]:
    """Turn ROC result files into the published tables.

    The entry point :data:`~sih141.eval.reduce.EXTRA_REDUCTIONS` calls, so
    ``python tools/sweep.py reduce roc`` regenerates every ROC figure from what
    is on disk without re-running a session.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Every record for the experiment.
    command : str, optional
        Keyword-only. Stamped on each table.
    cell_order : Sequence of str or None, optional
        Keyword-only.
    expected : Mapping or None, optional
        Keyword-only. Per-cell trial counts the sweep asked for, handed down
        by :func:`~sih141.eval.reduce.reduce_experiment` so the grid's
        completeness footnote checks the same mapping the outcome table does.

    Returns
    -------
    list of Table
        The grid, the envelope, and the prototype comparison.

    Raises
    ------
    RuntimeError
        If the reduction's own recomputation of the anchor budget disagrees
        with the verdict the worker stored. See :ref:`roc-crosscheck`; a
        disagreement means one of the two routes is wrong and neither number
        may be published until it is known which.
    """
    problems = reconciliation(records, eps_values=EPS_LADDER)
    if problems:
        raise RuntimeError(
            "the ROC reduction disagrees with the verdicts the sweep stored, "
            "so the ladder cannot be trusted and nothing here may be "
            "published: " + "; ".join(problems[:5])
        )
    return [
        roc_table(
            records,
            command=command,
            cell_order=cell_order,
            expected=expected,
        ),
        roc_envelope_table(records, command=command, cell_order=cell_order),
        roc_prototype_table(records, command=command, cell_order=cell_order),
    ]


def roc_charts(
    records: Sequence[TrialRecord],
    *,
    command: str = "",
    cell_order: Sequence[str] | None = None,
) -> dict[str, str]:
    """Return the ROC charts, keyed by filename.

    The entry point :data:`~sih141.eval.reduce.EXTRA_CHARTS` calls.

    Parameters
    ----------
    records : Sequence of TrialRecord
        Every record for the experiment.
    command : str, optional
        Keyword-only.
    cell_order : Sequence of str or None, optional
        Keyword-only.

    Returns
    -------
    dict
        Filename to SVG text.
    """
    return {
        "roc.svg": roc_chart_svg(
            records, command=command, cell_order=cell_order
        )
    }


def register(
    *,
    scenarios: dict[str, Any] | None = None,
    experiments: dict[str, Experiment] | None = None,
) -> None:
    """Add this family's scenarios, experiment and reductions to the registries.

    Called once at import. Idempotent, and it **refuses to overwrite a name it
    does not already own**: two Phase 5 families registering one scenario key
    would otherwise give whichever imported last, silently, and the losing
    family's cells would run the winner's adversary under the losing family's
    label.

    Parameters
    ----------
    scenarios : dict or None, optional
        Keyword-only. Defaults to
        :data:`~sih141.eval.experiments.SCENARIOS`.
    experiments : dict or None, optional
        Keyword-only. Defaults to
        :data:`~sih141.eval.experiments.EXPERIMENTS`.

    Raises
    ------
    RuntimeError
        If a name is taken by something else.

    Examples
    --------
    >>> from sih141.eval.roc import register
    >>> register()                      # already done at import; a no-op
    >>> register(scenarios={"roc-replay": len}, experiments={})
    Traceback (most recent call last):
        ...
    RuntimeError: scenario 'roc-replay' is already registered...

    An experiment name taken by another family is a collision in the other
    direction, and it raises too rather than quietly leaving this family
    registered nowhere:

    >>> register(scenarios={}, experiments={"roc": "someone else's"})
    Traceback (most recent call last):
        ...
    RuntimeError: experiment 'roc' is already registered...
    """
    target_scenarios = SCENARIOS if scenarios is None else scenarios
    target_experiments = EXPERIMENTS if experiments is None else experiments
    for name, function in ROC_SCENARIOS.items():
        claim(target_scenarios, name, function, "scenario")
    for name, options in ROC_PROBE_OPTIONS.items():
        claim(SCENARIO_PROBE_OPTIONS, name, options, "probe options")
    # After the scenarios, never before: building the cells validates each
    # one's scenario against the live registry.
    claim(target_experiments, "roc", _singleton_experiment(), "experiment")
    claim(reduce_module.EXTRA_REDUCTIONS, "roc", roc_reduction, "reduction")
    claim(reduce_module.EXTRA_CHARTS, "roc", roc_charts, "chart renderer")


register()
