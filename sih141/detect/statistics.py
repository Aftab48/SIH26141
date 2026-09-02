"""Phase 4, layer one: everything a detector may legitimately read.

This module is a **boundary**, and the boundary is the point. It takes one
:class:`~sih141.protocol.session.SessionTranscript` that has been round-tripped
through JSON, it returns numbers, and it can reach nothing else -- not the
session object, not the adversary, not any harness state. Every later Phase 4
module is expected to read :class:`TranscriptStatistics` and never the
transcript, so that "our detector spotted it" is a claim about a file on disk
rather than about privileged access to the experiment that produced it.

.. _the-boundary:

Why the boundary is drawn here and not one function further out
---------------------------------------------------------------
A detection rate measured by a detector that can see the adversary's log is not
a detection rate, it is a restatement of the ground truth. Phase 3 established
this the expensive way (:mod:`sih141.attacks.isolation`, convention **D6**) and
its prototype threshold detector adopted the same rule voluntarily. Two
mechanical consequences are worth stating because they are what make the rule
enforceable rather than aspirational:

1. :meth:`TranscriptStatistics.from_transcript` **serialises and re-reads**
   even when it is handed a live transcript object. Anything that does not
   survive :meth:`~sih141.protocol.session.SessionTranscript.to_json` is gone
   by construction, and no reviewer has to take that on trust: the two entry
   points are one line apart and one of them is defined in terms of the other.
2. This module imports from :mod:`sih141.protocol` and from nothing else in the
   package. In particular it does **not** import :mod:`sih141.attacks`, even
   for the binomial-interval arithmetic that already lives there
   (:mod:`sih141.attacks.statistics`). A static import edge from the detector
   to the adversary suite would mean the shipped detector could not be built
   without the attacks, which is the dependency this phase exists to not have.
   The cost is one more copy of the Wilson closed form;
   :func:`wilson_interval` carries the note, a doctest that pins it against the
   protocol's own copy, and the one endpoint where the two deliberately
   differ.

.. _nulls:

Every statistic here carries its null, because Phase 4 derives its thresholds
-----------------------------------------------------------------------------
Convention **D7**: a threshold must come from a stated null distribution and a
concentration inequality applied to it, never from a number that separated the
attack data somebody happened to have. A statistic whose null cannot be written
down therefore cannot carry a derived threshold, and saying so is part of this
module's job rather than a gap in it. The table, with ``n`` the *sifted* key
length :attr:`~sih141.protocol.params.ProtocolParams.signing_length` and ``p =
1/|B|`` the match probability:

============================== ======================================= =========
statistic                      null on an honest run                   closed?
============================== ======================================= =========
``|M_R|`` matched count        ``Binomial(n, p)``, per verifier        exact
``M = m_B + m_C`` pooled       ``Binomial(2n, p)``                     exact
``e_R`` mismatches             point mass at ``0`` (noiseless link)    exact
``r_R = e_R / |M_R|``          point mass at ``0`` (noiseless link)    exact
declared count (Phase C')      ``Binomial(n, p)``, honest declaration  exact
unmatched agreements           ``Binomial(n - |M_R|, 1/2)``            exact
declared basis frequency       ``Multinomial(n, uniform)``             exact
declared eigenvalue balance    ``Binomial(n, 1/2)``                    exact
record basis frequency         ``Multinomial(n, uniform)``             exact
record eigenvalue balance      ``Binomial(n, 1/2)``                    exact
check-round QBER errors        point mass at ``0`` (noiseless link)    exact
check-round CHSH ``S``         normal, ``Var(S) = sum 1/(2 n_c)``      asymptotic
resource summaries (five)      point mass at ``1``; wings at ``0.5``   exact
abort counts, structural       point mass at ``0``                     exact
abort counts, evidence         ``<= 2**-64`` per verifier (Chernoff)   bound
replay refusals                point mass at ``0``                     exact
spent rounds                   point mass at ``2`` on a complete run   exact
============================== ======================================= =========

Only the CHSH row is asymptotic, and it does not have to be believed on its
own: :attr:`LinkStatistics.chsh_bound` and :attr:`LinkStatistics.qber_bound`
carry the **distribution-free** Hoeffding forms of both check-round statistics,
whose coverage is at least the stated level at every sample size. Read the
calibrated interval to report a number and the bound to derive a threshold, and
never mix the two in one table without saying which is which.

Seven of those seventeen rows are **degenerate** -- a point mass, and the word
appears in each of them -- and that is a feature, not a defect of the
modelling. On a noiseless honest run a verifier's mismatch
count is ``0`` with probability exactly one, so any detector that fires on
``e_R > 0`` has a false-positive probability of exactly zero *under that null*,
and the honest thing to report is the zero rather than a fitted band. What such
a threshold buys is stated in :class:`CountStatistic.tail_bound`, and what it
costs is stated here: it is a claim about a noiseless link, and a run over a
genuinely noisy honest channel violates it. On a run with check rounds the
transcript carries its own estimate of that link's error rate and the two can
be compared (:class:`LinkStatistics`); on a run without them it does not, which
is :ref:`finding 2 <findings>`.

.. _derivations:

The two derivations everything else leans on
--------------------------------------------
**(a) The matched count survives symmetrisation.** Alice draws each declared
basis uniformly from ``B`` and independently across positions; each recipient
draws his measurement basis the same way and independently of her. So the raw
per-position matched indicators ``(X_i, Y_i)`` for the two recipients are
i.i.d. ``Bernoulli(p)``. Phase A'
(:mod:`sih141.protocol.symmetrise`) tosses a fair coin per position and either
keeps the pair or swaps it. A swap is a permutation of an *exchangeable* pair,
so the post-exchange pair has the same joint law as the raw one:

.. code-block:: text

    (m_B,i , m_C,i)  =  (X_i , Y_i)      with probability 1/2
                     =  (Y_i , X_i)      with probability 1/2
    and (X_i, Y_i) i.i.d.  =>  both cases have the same joint law

Hence, unconditionally, ``m_B ~ Binomial(n, p)`` and ``m_C ~ Binomial(n, p)``
and the two are independent.

**One verifier's honest mean is ``n/|B|``, and it is the pooled total whose
mean is ``2n/|B|``.** Worth saying flatly because the two get swapped: at
:data:`~sih141.protocol.params.DEFAULT_PARAMS` the per-verifier mean is
``38400`` against a floor ``m_min = 36555``, and the pooled mean is ``76800``
against ``M_min = 74190``. Separately, ``2n/|B|`` *is* the honest mean of a
single verifier's matched count under a **recipient forgery** -- the forger
supplied half the evidence himself, so his declaration is matched there with
probability one and the count moves from ``n/3`` to ``n(1 + 1/3)/2 = 2n/3``
(:attr:`~sih141.protocol.params.ProtocolParams.forger_scored_fraction`). The
same fraction, two entirely different quantities; a threshold that took one for
the other would be off by a factor of two at every key length.

**The word "unconditionally" is load-bearing.**
*Given the raw records* the coins only move entries between the two verifiers,
so ``m_C = M - m_B`` exactly and the two are perfectly negatively dependent;
``tests/test_protocol_tally.py`` opens with that trap. A per-verifier threshold
uses the unconditional law and is fine. A threshold on the *pair* must not
assume independence, and does not need to: ``M = m_B + m_C`` is coin-invariant
and is a sum of ``2n`` i.i.d. indicators, so ``M ~ Binomial(2n, p)`` exactly.

**(b) An unmatched position is a fair coin.** ``X``, ``Y`` and ``Z`` pairwise
anticommute, so measuring a Pauli other than the declared one on an eigenstate
of the declared one yields ``+1`` and ``-1`` with probability ``1/2`` each,
independently of the declared eigenvalue. Conditional on ``|M_R|``, the number
of unmatched positions whose recorded sign nevertheless agrees with the
declaration is therefore ``Binomial(n - |M_R|, 1/2)``, exactly. This is the
statistic that catches a *fabricated* record -- one copied off the declaration
reads ``1.0`` -- and it is deliberately **not** a channel statistic: a
depolarising channel leaves it at ``1/2``.

.. _not-signals:

What this module refuses to expose, and why
-------------------------------------------
``wings_agree``
    Excluded outright; see :func:`why_wings_agree_is_absent`. No
    trace-preserving map on one half of a maximally entangled pair can change
    only that half's marginal, so every channel adversary in
    :mod:`sih141.attacks.channel` leaves it ``True`` on every round. Zero
    detection power against that whole family, measured.
Pooled per-link check statistics
    Not computed by default, ever. Symmetrisation smears the *records* but
    never the *check logs*, so per-link QBER is the only statistic that both
    detects a party-targeted channel attack and attributes it, and pooling two
    links reports the average of two channels and detects neither.
    :func:`pooled_check_qber` exists, requires ``pool=True`` spelled out, and
    says in its own docstring what the caller is giving up.
Aborts folded into verdicts
    :class:`AbortStatistics` is a separate field of a separate type from
    :class:`VerifierStatistics`, and no member of this module ever sums across
    the two. A refusal to score is not a rejection; averaging them reports a
    detection that never happened.
Anything keyed on ``count_exchange_timing``
    Recorded (:attr:`TranscriptStatistics.count_exchange_timing`) and never
    aggregated. The two orderings give different answers to the same attack, so
    a Phase 5 table that pooled them would be averaging a forgery rate with a
    denial-of-service rate. Group by it; do not average over it.

.. _no-timing:

Assumption (NO-TIMING), which two of these statistics are conditioned on
------------------------------------------------------------------------
Every *check-round* statistic here -- :class:`LinkStatistics`' QBER and CHSH,
and the :class:`ResourceStatistics` rows behind them -- is conditioned on the
adversary being unable to infer the check set from timing. If he can, he spares
the watched rounds and the sample stops describing the link. Statistics that
read the **key** rather than the sample -- the verifier mismatch rate, the
matched counts, the declared-count z-score, the abort reasons -- do not depend
on it, and the Phase 3 prototype separated four of five adversaries on the rate
alone. It is check-round *attribution*, which link was touched, that leans on
the assumption. Anything published from :class:`LinkStatistics` must cite it.

.. _findings:

What a detector wants that the transcript does not expose
---------------------------------------------------------
Reported rather than reached for. Each of these is a statistic somebody will
ask for; none of them is obtainable from a JSON transcript, and the answer is
to say so.

1. **Which link Eve touched, and which runs a selective starver targeted.**
   Ground truth, and it lives on the adversary's log. An untargeted run is
   byte-identical to an honest one, which is correct. Score false-positive
   rates against a labelled harness instead of trying to recover the label.
2. **The link's true error rate on a run without check rounds.** With
   ``check_fraction = 0`` the transcript carries no independent estimate of the
   channel, so the only defensible null for ``r_R`` is the noiseless one and
   every claim from it is a claim about a noiseless link.
   :attr:`TranscriptStatistics.has_check_rounds` says which kind of run this
   is, and :attr:`VerifierStatistics.mismatch` says so again in its own null.
3. **The raw, pre-symmetrisation records and the coins.** Only post-Phase-A'
   records reach the transcript, by design -- Alice must not see the coins
   either. So the *conditional* law of ``m_B`` given the records is
   unavailable and only the unconditional one may be used; see
   :ref:`derivations`.
4. **Any timing or ordering information.** There are no timestamps anywhere in
   a transcript. A timing side channel is invisible to a transcript-only
   detector, which is exactly why (NO-TIMING) is an assumption and not a check.
5. **The resource on the positions that carried key.**
   :attr:`~sih141.protocol.session.SessionTranscript.channel` holds check
   positions only, and
   :meth:`~sih141.protocol.session.SessionTranscript.from_dict` refuses a file
   that claims otherwise. Every channel number here is an estimate over a
   sample, never a census over the key.
6. **A replay** *rate*. :attr:`ReplayStatistics.refusals_by_party` counts
   refusals, but the transcript records no denominator -- how many times each
   verifier was *asked* -- so only a count is computable, never a rate.
7. **Alice's own behaviour, directly.** She reaches no verdict and holds no
   record, and full impersonation is inseparable by assumption (AUTH). Do not
   invent a detector for it; state the assumption.
8. **Anything inside a channel monitor's** ``extra`` **blob.**
   :attr:`ResourceStatistics.extra_keys` reports which keys a monitor wrote and
   nothing else. That mapping is free-form JSON produced by a *seam*, so a
   statistic keyed on its contents would be reading harness state through a
   hole in the boundary rather than reading the protocol.
9. **A matched set for the message bit that was not signed.** The transcript
   carries both distributions' records but only one declaration, so the
   unsigned bit has no matched set, no mismatch rate and no pooled count --
   only the frequency statistics on :class:`RecordStatistics`. That half of the
   run is real evidence and half of it is unusable, which is worth knowing
   before a Phase 5 table tries to double its sample size.
10. **Which recipient sent which Phase C' message, and in what order.**
    :attr:`~sih141.protocol.session.SessionTranscript.pooled` carries the two
    counts, the two floors and the declaration digest, but not the two
    :class:`~sih141.protocol.tally.MatchedCountMessage` objects, so the
    exchange's own ordering is not recoverable.

One adjacent finding that is not a transcript gap: the Wilson lower endpoint
inside :func:`~sih141.protocol.checkrounds.estimate_qber` still carries the
floating-point dust that :mod:`sih141.attacks.statistics` was written to
remove, so a clean link reports ``interval.low == 6.9e-18`` rather than ``0.0``
at some sample sizes. :func:`wilson_interval` explains it, this phase does not
own the file, and ``tests/test_detect_statistics.py`` pins the divergence so it
cannot be fixed silently or forgotten quietly.

Notes
-----
Determinism (D3)
    Nothing in this module draws randomness. It has no ``rng`` argument because
    it has nothing to draw for: it is a pure function of one JSON document.
No machine learning (D4)
    Counting, four closed forms and two concentration inequalities. There is no
    fitted quantity anywhere in this file, and there is no place to put one:
    every ``null_probability`` is either ``1/|B|``, ``1/2``, ``0`` or a value
    the caller derived from the protocol's own parameters.

Examples
--------
The whole layer, from one honest run:

>>> import numpy as np
>>> from sih141.detect.statistics import TranscriptStatistics
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> transcript = QDSSession(
...     ProtocolParams(key_length=192), rng=np.random.default_rng(7)
... ).run(0)
>>> stats = TranscriptStatistics.from_transcript(transcript)
>>> stats.key_length, stats.match_probability
(192, 0.3333333333333333)
>>> bob = stats.verifier("Bob")
>>> bob.matched.count, bob.mismatch.count, bob.mismatch_rate
(59, 0, 0.0)
>>> f"{bob.matched.z_score:.4f}"
'-0.7655'

The pooled count is a statistic in its own right, with its own exact null over
``2n`` trials:

>>> stats.pooled.pooled.count, f"{stats.pooled.pooled.z_score:.4f}"
(117, '-1.1908')

Nothing was refused, replayed or aborted, and the module keeps those three
answers apart from the verdicts:

>>> stats.aborts.total, stats.replay.total_refusals, stats.replay.spent_rounds
(0, 0, 2)
>>> stats.transferable, stats.repudiated
(True, False)
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sih141.protocol.checkrounds import (
    CHECK_CONFIDENCE,
    IDEAL_CHSH,
    CheckLog,
    CheckRole,
    ChshEstimate,
    Interval,
    QberEstimate,
    QberObservation,
    estimate_chsh,
    estimate_qber,
    normal_quantile,
)
from sih141.protocol.params import Party, ProtocolParams
from sih141.protocol.records import RecipientRecord
from sih141.protocol.session import ChannelSample, SessionTranscript
from sih141.protocol.signature import Signature
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    AbortReason,
)
from sih141.protocol.verify import (
    enforced_repudiation_bound as _enforced_repudiation_bound,
)
from sih141.protocol.verify import (
    VerificationResult,
    matched_positions,
    minimum_matched_count,
    minimum_pooled_matched_count,
    mismatch_positions,
)

__all__ = [
    "EVIDENCE_ABORT_REASONS",
    "IDEAL_TOLERANCE",
    "STRUCTURAL_ABORT_REASONS",
    "AbortStatistics",
    "CountStatistic",
    "DeclarationStatistics",
    "LinkStatistics",
    "PooledStatistics",
    "RecordStatistics",
    "ReplayStatistics",
    "ResourceStatistics",
    "TranscriptStatistics",
    "VerifierStatistics",
    "chernoff_deviation_bound",
    "evidence_abort_probability_bound",
    "floor_shortfall_bound",
    "pooled_check_qber",
    "why_wings_agree_is_absent",
    "wilson_interval",
]


#: Abort reasons that **cannot** occur on an honest run at any key length, so
#: that a detector firing on one of them has a false-positive probability of
#: exactly zero under the honest null. Two of them say the declaration and the
#: record are not the same transaction at all; two say the counterpart's count
#: named a different declaration or named none. None of the four is a statement
#: about how much evidence a run produced, so none has a tail to bound.
STRUCTURAL_ABORT_REASONS: Final[frozenset[AbortReason]] = frozenset(
    {
        AbortReason.SESSION_MISMATCH,
        AbortReason.RECORD_ALREADY_VERIFIED,
        AbortReason.COUNT_OF_UNRECORDED_PROVENANCE,
        AbortReason.COUNTS_FROM_TWO_DECLARATIONS,
    }
)

#: Abort reasons that *are* statements about how much evidence a run produced,
#: and therefore do have an honest-run probability: each of the two floors was
#: derived from a Chernoff lower tail at :data:`HONEST_ABORT_BUDGET`, so an
#: honest verifier trips one with probability at most ``2**-64`` and an honest
#: run with probability at most ``2 * 2**-64``. Reported separately from the
#: structural four because the provable bound is different -- exactly zero
#: against ``2**-64`` -- and a table that summed them would quote the weaker
#: one for both.
EVIDENCE_ABORT_REASONS: Final[frozenset[AbortReason]] = frozenset(
    {
        AbortReason.EMPTY_MATCHED_SET,
        AbortReason.BELOW_FLOOR,
        AbortReason.POOLED_BELOW_FLOOR,
        AbortReason.COUNTERPART_BELOW_FLOOR,
    }
)

#: Tolerance at which a channel summary counts as sitting on its ideal value.
#: The same ``1e-9`` :attr:`~sih141.protocol.session.ChannelSample.is_ideal`
#: uses, and for the same reason: these are point-mass nulls disturbed only by
#: floating-point arithmetic on a four-by-four matrix, not by sampling.
IDEAL_TOLERANCE: Final[float] = 1e-9


def why_wings_agree_is_absent() -> str:
    """Return the reason ``wings_agree`` is not a statistic in this module.

    A function rather than a comment so that the reason is importable, testable
    and impossible to delete by accident while re-adding the statistic.

    :attr:`sih141.protocol.session.ChannelSample.wings_agree` asks whether the
    two halves of a check-round pair are equally disturbed. It is **not an
    eavesdropper detector and Phase 3 measured that it is not.** No
    trace-preserving map acting on one half of a maximally entangled pair can
    change only that half's marginal -- the reduced state of either half of a
    Bell pair is already maximally mixed, and a channel acting on one wing
    leaves it maximally mixed. All three adversaries in
    :mod:`sih141.attacks.channel` act on exactly one leg, and every one of them
    leaves ``wings_agree`` ``True`` on every round: a per-hop depolariser, an
    intercept-resend, and an eavesdropper who keeps a share. Zero detection
    power against that whole family.

    The statistics that *do* see them are on
    :class:`ResourceStatistics` -- :attr:`~ResourceStatistics.mean_fidelity`
    and :attr:`~ResourceStatistics.mean_concurrence` for all three,
    :attr:`~ResourceStatistics.mean_purity` for a kept share -- and above all
    the per-link check-round QBER of :class:`LinkStatistics`.

    Returns
    -------
    str
        One paragraph, suitable for pasting into a report that has to explain
        why an obvious-looking signal is missing.

    Examples
    --------
    >>> from sih141.detect.statistics import why_wings_agree_is_absent
    >>> "no detection power" in why_wings_agree_is_absent()
    True
    """
    return (
        "wings_agree is excluded from the Phase 4 statistics layer on "
        "purpose. No trace-preserving map on one half of a maximally "
        "entangled pair can change only that half's marginal, so every "
        "channel adversary in the threat model leaves it True on every "
        "round: it has no detection power against that family, as Phase 3 "
        "measured. Read per-link check-round QBER, fidelity and concurrence "
        "instead."
    )


# --------------------------------------------------------------------------- #
# Arithmetic: one interval and one tail bound, both with their algebra shown
# --------------------------------------------------------------------------- #


def _as_count(value: Any, name: str) -> int:
    """Coerce a non-negative integer count, refusing booleans.

    Parameters
    ----------
    value : int
        The candidate.
    name : str
        Argument name quoted in the error message.

    Returns
    -------
    int

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not an integer.
    ValueError
        If ``value`` is negative.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{name} must be an int, got {type(value).__name__}. Counts of "
            f"trials are integers; a float here is usually a rate that has "
            f"already been divided once."
        )
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _as_probability(value: Any, name: str) -> float:
    """Coerce a probability in the closed unit interval, refusing booleans.

    Parameters
    ----------
    value : float
        The candidate.
    name : str
        Argument name quoted in the error message.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not a real number.
    ValueError
        If ``value`` is not finite or lies outside ``[0, 1]``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be a real number, got {type(value).__name__}"
        )
    probability = float(value)
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError(
            f"{name} must be a finite probability in [0, 1], got "
            f"{probability!r}. It is the null's parameter, not a count."
        )
    return probability


def wilson_interval(
    successes: int, trials: int, *, confidence: float = CHECK_CONFIDENCE
) -> Interval:
    """Return the Wilson score interval for a binomial proportion.

    ``(k + z^2/2) / (n + z^2)  +-  z/(n + z^2) sqrt(k(n-k)/n + z^2/4)``, the
    exact inversion of the score test. Wilson rather than Wald because nearly
    every proportion in this project sits at or beside an endpoint, where the
    Wald interval collapses to the point it was measured at and claims
    certainty from a finite experiment.

    Parameters
    ----------
    successes : int
        ``0 <= successes <= trials``.
    trials : int
        At least ``1``.
    confidence : float, optional
        Keyword-only two-sided coverage, strictly inside ``(0, 1)``. Defaults
        to :data:`~sih141.protocol.checkrounds.CHECK_CONFIDENCE`, the level the
        protocol's own check-round estimates use, so that an interval from this
        module and one from :func:`~sih141.protocol.checkrounds.estimate_qber`
        are comparable without a footnote.

    Returns
    -------
    Interval
        The protocol's own interval type, tagged ``method="wilson"``. Exactly
        ``0.0`` at zero successes and exactly ``1.0`` at ``successes ==
        trials``: both endpoints are exact in the closed form and inexact in
        IEEE 754, and every defended result in this project is ``0`` successes
        out of ``N``, so the dust would land on precisely the numbers a reader
        most needs to read plainly.

    Raises
    ------
    TypeError
        If a count is not an integer or ``confidence`` is not a real number.
    ValueError
        If ``trials < 1``, ``successes`` is outside ``[0, trials]``, or
        ``confidence`` is not strictly inside ``(0, 1)``.

    Notes
    -----
    **This is the project's third copy of this closed form**, after
    :func:`sih141.attacks.statistics.wilson_bounds` and
    :func:`sih141.protocol.checkrounds.estimate_qber`'s private helper, and the
    duplication is deliberate rather than careless: importing the first would
    give :mod:`sih141.detect` a static dependency on :mod:`sih141.attacks`,
    which is the one edge this phase exists not to have (:ref:`the-boundary`),
    and the second is private to its module. What keeps the copies from
    drifting is the last example below, which pins this implementation against
    the protocol's. If a future phase promotes the arithmetic to a neutral
    module, all three should delegate to it.

    They now agree bit for bit, endpoints included, and the endpoints are the
    part that had to be fixed rather than documented. At zero successes the
    Wilson lower bound is the difference of two expressions that are equal in
    exact arithmetic and differ by about ``1e-18`` in IEEE 754, so a
    ``max(0.0, centre - spread)`` returns ``6.938893903907228e-18`` rather than
    ``0.0`` for some ``n``. Both copies clamp *by case* and return the exact
    ``0.0``. Every defended result in this project is ``0`` successes out of
    ``N``, so that endpoint is the one a published table quotes.

    When this module was written the protocol's copy still carried the dust and
    the divergence was pinned by a test rather than fixed, because the fix
    belonged to a module this layer does not own. The Phase 4 reconciliation
    made it, and ``tests/test_detect_reconciliation.py`` now pins the two
    against each other at both endpoints over a grid of sample sizes.

    Examples
    --------
    >>> from sih141.detect.statistics import wilson_interval
    >>> interval = wilson_interval(0, 400)
    >>> interval.low, f"{interval.high:.6f}"
    (0.0, '0.016317')
    >>> wilson_interval(400, 400).high
    1.0

    Agreement with the protocol's own Wilson interval, computed from the same
    counts through a completely separate code path:

    >>> from sih141.core.paulis import PauliBasis
    >>> from sih141.protocol.checkrounds import QberObservation, estimate_qber
    >>> sample = [
    ...     QberObservation(i, PauliBasis.Z, 1, 1 if i < 7 else -1)
    ...     for i in range(50)
    ... ]
    >>> theirs = estimate_qber(sample)
    >>> theirs.errors, theirs.rounds
    (43, 50)
    >>> ours = wilson_interval(theirs.errors, theirs.rounds)
    >>> (ours.low, ours.high) == (theirs.interval.low, theirs.interval.high)
    True
    """
    total = _as_count(trials, "trials")
    hits = _as_count(successes, "successes")
    if total < 1:
        raise ValueError(
            f"trials must be at least 1, got {total}. A proportion measured "
            f"over no trials is not a wide interval, it is the absence of a "
            f"measurement; report the trial count instead."
        )
    if hits > total:
        raise ValueError(
            f"successes ({hits}) exceeds trials ({total}); a proportion above "
            f"one is a counting error upstream, not a rate."
        )
    level = _as_probability(confidence, "confidence")
    if not 0.0 < level < 1.0:
        raise ValueError(
            f"confidence must lie strictly inside (0, 1), got {level}. It is "
            f"a coverage probability, not a percentage: pass 0.99, not 99."
        )

    z = normal_quantile(0.5 + level / 2.0)
    z_squared = z * z
    denominator = total + z_squared
    centre = (hits + z_squared / 2.0) / denominator
    spread = (
        z
        / denominator
        * math.sqrt(hits * (total - hits) / total + z_squared / 4.0)
    )
    low = 0.0 if hits == 0 else max(0.0, centre - spread)
    high = 1.0 if hits == total else min(1.0, centre + spread)
    return Interval(low=low, high=high, confidence=level, method="wilson")


#: The three sides :func:`chernoff_deviation_bound` will bound.
_SIDES: Final[frozenset[str]] = frozenset({"two-sided", "lower", "upper"})

_LOG_FLOOR_BUDGET: Final[float] = math.log(1.0 / HONEST_ABORT_BUDGET)
"""``ln(1/eps0)`` with ``eps0 = 2**-64``, the budget both matched-count floors
were derived at. Named because it appears in the applicability test of
:func:`floor_shortfall_bound` as well as in the deviation itself."""


def evidence_abort_probability_bound(
    params: ProtocolParams, *, counts_exchanged: bool = True
) -> float:
    """Bound P(an honest run records an evidence abort), as a function of ``n``.

    **This replaces a constant that was not proven.** The field it feeds,
    :attr:`AbortStatistics.honest_bound`, used to be the fixed
    ``2 * HONEST_ABORT_BUDGET``. That was wrong in both directions. The
    run-level union is over **three** events, not two -- both per-verifier
    floors *and* the pooled floor -- and
    :mod:`sih141.protocol.verify` derives ``3 * eps0`` itself, with
    ``tests/test_protocol_reconciliation.py`` asserting ``<= 3 * eps``. So two
    terms was smaller than the union bound its own derivation supports, i.e.
    optimistic. And a constant is wrong at the short end regardless: at
    ``n = 24`` the honest probability is ``1.19e-04``, five thousand million
    million times larger than ``2 * 2**-64``.

    The derivation, which is the one
    :func:`~sih141.protocol.verify.minimum_matched_count` already made and is
    reused rather than restated. Write ``n`` for the sifted key length,
    ``p = 1/|B|``, and let ``m_min`` and ``M_min`` be the two floors. An
    evidence abort implies one of

    .. code-block:: text

        E_B = {m_B < m_min},  E_C = {m_C < m_min},  E_M = {M < M_min}

    with ``m_B, m_C ~ Binomial(n, p)`` and ``M ~ Binomial(2n, p)`` -- the last
    exactly, by conservation of the pooled count under the symmetrisation
    coins rather than by independence. The union bound gives

    .. code-block:: text

        P(evidence > 0)  <=  2 b(n, m_min) + b(2n, M_min)

    and each term is answered in one of two exact regimes:

    * **floor > 1.** Since ``ceil(x) - 1 < x``, ``{m < m_min}`` is contained in
      ``{m <= (1 - d0) mu}`` with ``d0 = sqrt(2 ln(1/eps0) / mu)``, so the
      multiplicative Chernoff lower tail gives ``exp(-d0^2 mu / 2) = eps0``
      exactly -- the same inequality at the same budget the floor was derived
      from.
    * **floor == 1.** The event is ``{m = 0}``, whose probability is exactly
      ``(1 - p)**n``. No inequality is needed, and the smaller of the two is
      taken wherever both apply.

    Without the count exchange there is no pooled floor and the third term is
    dropped.

    Parameters
    ----------
    params : ProtocolParams
        The run's **sifted** parameter set -- ``TranscriptStatistics.params``,
        never the nominal one. A null stated over ``L`` where the truth is
        ``n`` claims more evidence than the run has.
    counts_exchanged : bool, optional
        Keyword-only. ``False`` drops the pooled term for a run that did not
        exchange counts.

    Returns
    -------
    float
        The bound, in ``[0, 1]``.

    See Also
    --------
    sih141.detect.thresholds_structural.evidence_abort_bound : The threshold
        family's own copy, which computes the same quantity for its own use and
        never reads this field. The two are pinned against each other in
        ``tests/test_detect_reconciliation.py``.

    Examples
    --------
    Not monotone in ``n``, and that is the derivation showing through: each
    time a floor stops being ``1`` an exact term is replaced by the looser
    Chernoff one.

    >>> from sih141.detect.statistics import evidence_abort_probability_bound
    >>> from sih141.protocol.params import ProtocolParams
    >>> for length in (24, 96, 136, 137, 273, 115200):
    ...     bound = evidence_abort_probability_bound(
    ...         ProtocolParams(key_length=length))
    ...     print(f"{length:6d}  {bound:.4e}")
        24  1.1881e-04
        96  2.4904e-17
       136  2.2523e-24
       137  5.4212e-20
       273  1.6263e-19
    115200  1.6263e-19

    It settles on three times the floors' own budget, never two:

    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> evidence_abort_probability_bound(DEFAULT_PARAMS) == 3 * 2.0 ** -64
    True
    >>> evidence_abort_probability_bound(
    ...     DEFAULT_PARAMS, counts_exchanged=False) == 2 * 2.0 ** -64
    True
    """
    length = int(params.key_length)
    probability = float(params.match_probability)
    bound = 2.0 * floor_shortfall_bound(
        length, probability, minimum_matched_count(params)
    )
    if counts_exchanged:
        bound += floor_shortfall_bound(
            2 * length, probability, minimum_pooled_matched_count(params)
        )
    return min(1.0, bound)


def floor_shortfall_bound(trials: int, probability: float, floor: int) -> float:
    """Bound ``P(Binomial(trials, probability) < floor)`` in its two exact regimes.

    The per-floor term of :func:`evidence_abort_probability_bound`, and the one
    implementation of it in the tree: the structural threshold family's
    ``_floor_bound`` delegates here for its inequality path rather than keeping
    a second copy, so the two cannot report different bounds for one run.

    Two regimes, and the tighter of the two wherever both apply:

    * ``floor <= 1`` -- the event is ``{count == 0}`` and its probability is
      exactly ``(1 - probability) ** trials``. No inequality is needed, and it
      is sometimes far tighter than the Chernoff term: at ``trials = 267`` the
      floor is still ``1`` while Chernoff already applies, and ``(2/3)**267``
      is ``9.6302e-48`` against ``eps0 = 5.4210e-20``.
    * ``2 ln(1/eps0) < trials * probability`` -- the regime
      :func:`~sih141.protocol.verify.minimum_matched_count` derived the floor
      in. Since ``ceil(x) - 1 < x``, the event is contained in
      ``{count <= (1 - d0) mu}`` with ``d0 = sqrt(2 ln(1/eps0) / mu)``, and the
      multiplicative Chernoff lower tail ``exp(-d0^2 mu / 2)`` is exactly
      ``eps0``.

    When neither applies the honest answer is ``1.0``: the sample is too small
    for the Chernoff form to have any power and the floor is too high for the
    event to be ``{count == 0}``, so nothing better than the trivial bound has
    been proven. Returning ``eps0`` there would be asserting a bound rather
    than proving one, which is the whole failure mode D7 exists to prevent.

    Parameters
    ----------
    trials : int
        ``n`` for a per-verifier floor, ``2n`` for the pooled one.
    probability : float
        ``p = 1/|B|``.
    floor : int
        The floor as the protocol derives it.

    Returns
    -------
    float
        The bound, in ``[0, 1]``.

    Examples
    --------
    >>> from sih141.detect.statistics import floor_shortfall_bound
    >>> f"{floor_shortfall_bound(115200, 1 / 3, 36555):.4e}"
    '5.4210e-20'
    >>> f"{floor_shortfall_bound(267, 1 / 3, 1):.4e}"
    '9.6302e-48'
    >>> floor_shortfall_bound(24, 1 / 3, 3)
    1.0
    """
    candidates: list[float] = []
    if floor <= 1:
        candidates.append((1.0 - probability) ** trials)
    if 2.0 * _LOG_FLOOR_BUDGET < trials * probability:
        candidates.append(HONEST_ABORT_BUDGET)
    if not candidates:
        return 1.0
    return min(candidates)


def chernoff_deviation_bound(
    count: int, trials: int, probability: float, *, side: str = "two-sided"
) -> float:
    """Bound the null probability of a deviation at least as large as observed.

    **The sentence convention D7 asks for, as a number**: for ``S ~
    Binomial(trials, probability)`` with mean ``mu``, this returns an upper
    bound on the probability that ``S`` lands at least as far from ``mu`` as
    ``count`` did. A threshold agent picks a false-positive budget and inverts
    it; nothing here chooses a threshold, and nothing here has seen any attack
    data.

    The two multiplicative Chernoff bounds, applied at the *observed* relative
    deviation ``d = |count - mu| / mu``:

    .. code-block:: text

        P(S <= (1 - d) mu)  <=  exp(-d^2 mu / 2)          for 0 < d <= 1
        P(S >= (1 + d) mu)  <=  exp(-d^2 mu / (2 + d))    for d > 0

    ``side="two-sided"`` sums them and clips at ``1``. The lower term is
    dropped when ``d > 1``, where ``(1 - d) mu`` is negative and the event is
    empty.

    Parameters
    ----------
    count : int
        The observed count, ``0 <= count <= trials``.
    trials : int
        Trials, at least ``0``.
    probability : float
        The null's success probability, in ``[0, 1]``.
    side : {'two-sided', 'lower', 'upper'}, optional
        Keyword-only. Which event to bound. ``'lower'`` bounds
        ``P(S <= count)`` and ``'upper'`` bounds ``P(S >= count)``; each
        returns ``1.0`` when the observation sits on the wrong side of the
        mean for that tail to be a tail. **Prefer a one-sided bound where the
        detector is one-sided**, which is most of them: count starvation only
        ever under-reports, and the two-sided bound at a starved count is
        dominated by an upper tail nobody is testing -- ``5.4e-10`` against the
        ``1.3e-14`` the lower tail actually gives, a factor of forty thousand
        thrown away for symmetry nobody asked for.

    Returns
    -------
    float
        A number in ``[0, 1]``. ``1.0`` when nothing was observed, when the
        observation lands exactly on the mean, or when the null is degenerate
        and the observation is the value it puts all its mass on; ``0.0`` when
        the null is degenerate and the observation contradicts it outright.

    Raises
    ------
    TypeError
        If a count is not an integer or ``probability`` is not a real number.
    ValueError
        If a count is negative, ``count > trials``, ``probability`` is outside
        ``[0, 1]``, or ``side`` names no tail.

    Notes
    -----
    A *bound*, not a p-value: the true tail is smaller, usually by orders of
    magnitude. That direction is the safe one -- a threshold derived from this
    over-states its own false-positive rate -- and it is the direction a
    security claim has to err in.

    The degenerate cases are exact rather than bounded. At ``probability = 0``
    the null is a point mass at ``0``, so any positive count has probability
    exactly zero under it, and at ``probability = 1`` the mirror holds. Those
    are the nulls of the mismatch count and of the check-round error count on a
    noiseless link (:ref:`nulls`), which is why they are worth the two lines.

    Examples
    --------
    >>> from sih141.detect.statistics import chernoff_deviation_bound
    >>> f"{chernoff_deviation_bound(64, 192, 1 / 3):.4f}"      # on the mean
    '1.0000'
    >>> f"{chernoff_deviation_bound(32, 192, 1 / 3):.6f}"      # half the mean
    '0.001997'

    A starved run, two-sided and then on the tail a starvation detector is
    actually testing:

    >>> f"{chernoff_deviation_bound(0, 192, 1 / 3):.3e}"
    '5.433e-10'
    >>> f"{chernoff_deviation_bound(0, 192, 1 / 3, side='lower'):.3e}"
    '1.266e-14'
    >>> chernoff_deviation_bound(0, 192, 1 / 3, side="upper")
    1.0

    A point-mass null answers exactly, in both directions:

    >>> chernoff_deviation_bound(0, 5000, 0.0)
    1.0
    >>> chernoff_deviation_bound(1, 5000, 0.0)
    0.0
    """
    total = _as_count(trials, "trials")
    hits = _as_count(count, "count")
    if hits > total:
        raise ValueError(
            f"count ({hits}) exceeds trials ({total}); a count above its own "
            f"denominator is a counting error upstream, not a deviation."
        )
    p = _as_probability(probability, "probability")
    if not isinstance(side, str) or side not in _SIDES:
        raise ValueError(
            f"side must be one of {sorted(_SIDES)}, got {side!r}. A one-sided "
            f"detector should ask for the tail it tests; a two-sided bound "
            f"charges it for a tail it never looks at."
        )

    if p == 0.0:
        if hits == 0:
            return 1.0
        return 0.0 if side in ("two-sided", "upper") else 1.0
    if p == 1.0:
        if hits == total:
            return 1.0
        return 0.0 if side in ("two-sided", "lower") else 1.0
    mean = total * p
    if mean == 0.0:
        return 1.0
    deviation = abs(hits - mean)
    if deviation == 0.0:
        return 1.0
    relative = deviation / mean
    lower = (
        math.exp(-relative * relative * mean / 2.0) if relative <= 1.0 else 0.0
    )
    upper = math.exp(-relative * relative * mean / (2.0 + relative))
    if side == "lower":
        return 1.0 if hits > mean else min(1.0, lower)
    if side == "upper":
        return 1.0 if hits < mean else min(1.0, upper)
    return min(1.0, lower + upper)


# --------------------------------------------------------------------------- #
# The workhorse carrier
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CountStatistic:
    """One count, the null it is read against, and what that null permits.

    Every counting statistic in this module has the same four-field shape, so
    that a downstream threshold agent never has to ask which distribution a
    number came from: it is on the object. The derived views are the three a
    derived threshold needs -- the standardised deviation, a provable tail
    bound and a confidence interval on the underlying rate.

    Parameters
    ----------
    name : str
        What was counted, for reports. Free text; nothing keys on it.
    count : int
        The observation, ``0 <= count <= trials``.
    trials : int
        The denominator the null is stated over. May be ``0``, which is the
        honest representation of "this run produced no trials of this kind";
        the derived views then say so rather than dividing.
    null_probability : float
        The per-trial success probability under the honest-run null, in
        ``[0, 1]``. ``0.0`` and ``1.0`` are point-mass nulls and are handled
        exactly rather than approximated; see
        :func:`chernoff_deviation_bound`.
    null : str
        One sentence naming the distribution, written out so that a table
        rendered from these objects carries its own derivation. Required, not
        optional: a statistic whose null nobody wrote down cannot carry a
        derived threshold, and leaving the field blank would hide that.

    Raises
    ------
    TypeError
        If ``count`` or ``trials`` is not an integer, or ``null_probability``
        is not a real number, or ``name``/``null`` is not a string.
    ValueError
        If a count is negative, ``count > trials``, ``null_probability`` is
        outside ``[0, 1]``, or ``null`` is empty.

    Examples
    --------
    >>> from sih141.detect.statistics import CountStatistic
    >>> matched = CountStatistic(
    ...     name="matched_count",
    ...     count=59,
    ...     trials=192,
    ...     null_probability=1 / 3,
    ...     null="Binomial(192, 1/3)",
    ... )
    >>> matched.expected, f"{matched.z_score:.4f}"
    (64.0, '-0.7655')
    >>> f"{matched.tail_bound:.4f}", f"{matched.lower_tail_bound:.4f}"
    ('1.0000', '0.8226')

    A point-mass null is exact in both directions, and the interval still
    reports what the *observation* alone supports:

    >>> clean = CountStatistic("mismatches", 0, 59, 0.0, "point mass at 0")
    >>> clean.z_score, clean.tail_bound
    (0.0, 1.0)
    >>> dirty = CountStatistic("mismatches", 3, 59, 0.0, "point mass at 0")
    >>> dirty.z_score, dirty.tail_bound
    (inf, 0.0)
    """

    name: str
    count: int
    trials: int
    null_probability: float
    null: str

    def __post_init__(self) -> None:
        """Coerce the counts and check the observation fits its denominator."""
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "count", _as_count(self.count, "count"))
        object.__setattr__(self, "trials", _as_count(self.trials, "trials"))
        object.__setattr__(
            self,
            "null_probability",
            _as_probability(self.null_probability, "null_probability"),
        )
        object.__setattr__(self, "null", str(self.null))
        if self.count > self.trials:
            raise ValueError(
                f"{self.name}: count ({self.count}) exceeds trials "
                f"({self.trials}). A statistic whose observation is larger "
                f"than its own denominator is a wiring error, and reporting a "
                f"rate above one would hide it."
            )
        if not self.null:
            raise ValueError(
                f"{self.name}: null must be a non-empty sentence naming the "
                f"distribution this count is read against. Convention D7: a "
                f"statistic with no written-down null cannot carry a derived "
                f"threshold, and an empty string would let one be attached "
                f"anyway."
            )

    # -- derived views ------------------------------------------------------ #

    @property
    def rate(self) -> float | None:
        """float or None: ``count / trials``; ``None`` when ``trials == 0``.

        ``None`` rather than ``0.0`` deliberately: a rate over no trials is not
        zero, it is undefined, and the same distinction
        :func:`sih141.protocol.verify.verify` enforces on an empty matched set
        applies here.
        """
        if self.trials == 0:
            return None
        return self.count / self.trials

    @property
    def expected(self) -> float:
        """float: ``trials * null_probability``, the null's mean."""
        return self.trials * self.null_probability

    @property
    def variance(self) -> float:
        """float: ``trials * p * (1 - p)``, the null's variance."""
        return self.trials * self.null_probability * (1.0 - self.null_probability)

    @property
    def standard_deviation(self) -> float:
        """float: The square root of :attr:`variance`."""
        return math.sqrt(self.variance)

    @property
    def z_score(self) -> float:
        """float: Standard deviations between the observation and the null mean.

        ``(count - expected) / sd``. When the null has zero variance -- a point
        mass, or no trials -- this is ``0.0`` if the observation lands on the
        mass and a signed :data:`math.inf` if it does not: an outcome the null
        forbids outright is infinitely surprising under it, and saying so is
        more useful than dividing by zero.
        """
        deviation = self.count - self.expected
        spread = self.standard_deviation
        if spread == 0.0:
            return 0.0 if deviation == 0.0 else math.copysign(math.inf, deviation)
        return deviation / spread

    @property
    def tail_bound(self) -> float:
        """float: Upper bound on the null probability of a deviation this large.

        :func:`chernoff_deviation_bound` at this object's numbers, two-sided.
        **This is the field a derived threshold is built from**, and the reason
        every statistic in this module carries its null as data rather than as
        prose. Where the detector is one-sided -- and most of them are -- read
        :attr:`lower_tail_bound` or :attr:`upper_tail_bound` instead: they are
        tighter by orders of magnitude and are what the derivation actually
        needs.
        """
        return chernoff_deviation_bound(
            self.count, self.trials, self.null_probability
        )

    @property
    def lower_tail_bound(self) -> float:
        """float: Upper bound on ``P(S <= count)`` under the null.

        The tail a starvation or under-report detector tests. ``1.0`` when the
        observation sits above the mean, where "at most this many" is not a
        tail at all.
        """
        return chernoff_deviation_bound(
            self.count, self.trials, self.null_probability, side="lower"
        )

    @property
    def upper_tail_bound(self) -> float:
        """float: Upper bound on ``P(S >= count)`` under the null.

        The tail a mismatch or error-inflation detector tests. ``1.0`` when the
        observation sits below the mean.
        """
        return chernoff_deviation_bound(
            self.count, self.trials, self.null_probability, side="upper"
        )

    def interval(
        self, *, confidence: float = CHECK_CONFIDENCE
    ) -> Interval | None:
        """Return the Wilson interval on the underlying rate.

        Parameters
        ----------
        confidence : float, optional
            Keyword-only two-sided coverage. Defaults to
            :data:`~sih141.protocol.checkrounds.CHECK_CONFIDENCE`.

        Returns
        -------
        Interval or None
            ``None`` when ``trials == 0``, for the reason :attr:`rate` gives.

        Examples
        --------
        >>> from sih141.detect.statistics import CountStatistic
        >>> stat = CountStatistic("e", 0, 59, 0.0, "point mass at 0")
        >>> f"{stat.interval().high:.6f}"
        '0.101088'
        """
        if self.trials == 0:
            return None
        return wilson_interval(self.count, self.trials, confidence=confidence)

    def summary(self) -> str:
        """Return a one-line account naming every number behind it.

        Returns
        -------
        str

        Examples
        --------
        >>> from sih141.detect.statistics import CountStatistic
        >>> print(
        ...     CountStatistic(
        ...         "matched_count", 59, 192, 1 / 3, "Binomial(192, 1/3)"
        ...     ).summary()
        ... )
        matched_count: 59/192 = 0.307292 vs null Binomial(192, 1/3) mean 64.000000 (z = -0.77, P(|dev| >= this) <= 1.00e+00)
        """
        rate = "undefined" if self.rate is None else f"{self.rate:.6f}"
        return (
            f"{self.name}: {self.count}/{self.trials} = {rate} vs null "
            f"{self.null} mean {self.expected:.6f} "
            f"(z = {self.z_score:.2f}, "
            f"P(|dev| >= this) <= {self.tail_bound:.2e})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
            Keys ``"name"``, ``"count"``, ``"trials"``, ``"null_probability"``,
            ``"null"``, ``"rate"``, ``"expected"``, ``"z_score"`` and
            ``"tail_bound"``. ``"z_score"`` is ``None`` rather than ``Infinity``
            where the null forbids the observation, because ``Infinity`` is not
            JSON and :func:`json.dumps` writing it anyway is how a downstream
            parser gets a surprise.
        """
        z = self.z_score
        return {
            "name": self.name,
            "count": self.count,
            "trials": self.trials,
            "null_probability": self.null_probability,
            "null": self.null,
            "rate": self.rate,
            "expected": self.expected,
            "z_score": None if math.isinf(z) else z,
            "tail_bound": self.tail_bound,
            "lower_tail_bound": self.lower_tail_bound,
            "upper_tail_bound": self.upper_tail_bound,
        }


# --------------------------------------------------------------------------- #
# Per-verifier statistics: the strongest and cheapest channel signal
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VerifierStatistics:
    """One verifier's verdict reduced to counts, each against its own null.

    Built only for a party who reached a **verdict**. A party who refused to
    score appears in :class:`AbortStatistics` instead and never here, so that
    no statistic in this module can average a refusal into a rejection.

    Attributes
    ----------
    party : Party
        Bob or Charlie.
    accepted : bool
        The verdict as recorded.
    threshold : float
        The cut this verifier was scored against, ``s_a`` or ``s_v``.
    margin : float
        ``threshold - rate``; non-negative exactly when the run was accepted.
        On a noiseless honest run this equals ``threshold`` exactly, because
        the rate is exactly zero.
    matched : CountStatistic
        ``|M_R|`` against ``Binomial(n, 1/|B|)``. **The null is unconditional**
        -- see :ref:`derivations` for why the conditional one is different and
        why only this one is usable from a transcript.
    mismatch : CountStatistic
        ``e_R`` against a point mass at ``0``: on a noiseless honest run every
        matched position reproduces the declared eigenvalue with probability
        one. The denominator is ``|M_R|``, not ``n`` -- counting unmatched
        positions into a mismatch rate is the classic bug of this protocol
        family and would put an honest run at ``(1 - 1/|B|)/2``.
    unmatched_agreement : CountStatistic
        Unmatched positions whose recorded sign agrees with the declaration
        anyway, against ``Binomial(n - |M_R|, 1/2)`` -- exact, by the
        anticommutation argument in :ref:`derivations`. Reads ``1.0`` for a
        record copied off the declaration and ``1/2`` for everything honest,
        including a depolarised link; it is a *fabrication* statistic and not a
        channel one.
    recomputed : bool
        Whether the matched and mismatch counts were recomputed from this
        transcript's own record and declaration rather than read off the
        verdict. ``False`` when the record and the declaration have different
        lengths, which no run this package produces does, but which a
        hand-assembled transcript can.
    reported_matched, reported_mismatches : int
        What the verdict *claimed*, always, whether or not recomputation was
        possible.
    consistent : bool
        Whether the recomputation agreed with the claim. ``True`` when no
        recomputation was possible, since nothing then disagrees. A ``False``
        is not a probabilistic event: it means the transcript contradicts
        itself, which no adversary in the Phase 3 threat model can cause and
        which is therefore a plumbing finding rather than a detection.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> charlie = stats.verifier("Charlie")
    >>> charlie.accepted, charlie.matched.count, charlie.mismatch.count
    (True, 58, 0)
    >>> charlie.margin == charlie.threshold
    True
    >>> charlie.consistent, charlie.recomputed
    (True, True)
    >>> f"{charlie.unmatched_agreement.z_score:.4f}"
    '0.5183'
    """

    party: Party
    accepted: bool
    threshold: float
    margin: float
    matched: CountStatistic
    mismatch: CountStatistic
    unmatched_agreement: CountStatistic
    recomputed: bool
    reported_matched: int
    reported_mismatches: int
    consistent: bool

    @property
    def mismatch_rate(self) -> float | None:
        """float or None: ``r_R = e_R / |M_R|``, the quantity the cut applies to.

        ``None`` only where the matched set is empty, which
        :func:`sih141.protocol.verify.verify` refuses to score at all, so in
        practice never on an object built from a verdict.
        """
        return self.mismatch.rate

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "party": str(self.party),
            "accepted": self.accepted,
            "threshold": self.threshold,
            "margin": self.margin,
            "mismatch_rate": self.mismatch_rate,
            "matched": self.matched.to_dict(),
            "mismatch": self.mismatch.to_dict(),
            "unmatched_agreement": self.unmatched_agreement.to_dict(),
            "recomputed": self.recomputed,
            "reported_matched": self.reported_matched,
            "reported_mismatches": self.reported_mismatches,
            "consistent": self.consistent,
        }


# --------------------------------------------------------------------------- #
# Pooled evidence
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PooledStatistics:
    """The evidence base of the whole run, and what Phase C' put on the wire.

    Two different things live here and they must not be confused, which is why
    they are separate fields with separate nulls:

    * the **verdict counts**, ``m_B`` and ``m_C`` as each verifier's
      :class:`~sih141.protocol.verify.VerificationResult` records them, summed
      into :attr:`pooled`; and
    * the **declared counts**, the integers each recipient put on the wire in
      Phase C' (:mod:`sih141.protocol.tally`).

    On an honest run they are equal. Under count starvation they are not, and
    the gap is the whole attack: a recipient understates his own count to deny
    the other a verdict. :attr:`declaration_gap` is that gap, and
    :attr:`declared_bob`/:attr:`declared_charlie` carry the z-score a Phase 3
    finding named as the signal to key on -- the quietest denying declaration
    sits about ``-11.54`` honest standard deviations below the mean at every
    key length, which is why starvation does not get cheaper as ``L`` grows.

    Attributes
    ----------
    pooled : CountStatistic or None
        ``M = m_B + m_C`` from the verdicts, against ``Binomial(2n, 1/|B|)``,
        which is **exact**: the symmetrisation coins re-assign a fixed multiset
        of ``2n`` entries and cannot move the total (:ref:`derivations`).
        ``None`` unless both verifiers reached a verdict, since a refusal has
        no matched count to contribute and counting it as zero would flatter
        the bound.
    declared_bob, declared_charlie : CountStatistic or None
        The wire counts against ``Binomial(n, 1/|B|)``. ``None`` on a run whose
        recipients did not exchange counts at all -- the pre-pooled variant,
        which has no unconditional non-repudiation guarantee below ``1/2`` and
        which :attr:`counts_exchanged` flags.
    declared_pooled : CountStatistic or None
        Their total, against ``Binomial(2n, 1/|B|)``.
    counts_exchanged : bool
        Whether Phase C' ran at all.
    minimum_matched, minimum_pooled : int or None
        The two floors the run was scored under, as the run recorded them --
        not as recomputed now. A transcript on disk has to say what the rule
        *was*.
    meets_pooled_floor, meets_every_floor : bool or None
        As the exchange recorded them; ``None`` without an exchange.
    declaration_digest_present : bool
        Whether the exchange named the declaration its counts were computed
        against. Mandatory in the shipped code; ``False`` marks a transcript
        from before the binding, or one built by a seam that declined to supply
        provenance.
    matched_floor_bound : float
        The honest-run probability that a single verifier's count falls below
        :attr:`minimum_matched`, as the floor's own derivation bounds it: at
        most :data:`~sih141.protocol.verify.HONEST_ABORT_BUDGET`. Carried so a
        report can quote the false-positive cost of the floor without
        re-deriving it.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> pooled = stats.pooled
    >>> pooled.counts_exchanged, pooled.declaration_gap
    (True, 0)
    >>> pooled.pooled.count, pooled.pooled.trials
    (117, 384)
    >>> f"{pooled.declared_bob.z_score:.4f}"
    '-0.7655'
    """

    pooled: CountStatistic | None
    declared_bob: CountStatistic | None
    declared_charlie: CountStatistic | None
    declared_pooled: CountStatistic | None
    counts_exchanged: bool
    minimum_matched: int | None
    minimum_pooled: int | None
    meets_pooled_floor: bool | None
    meets_every_floor: bool | None
    declaration_digest_present: bool
    matched_floor_bound: float

    @property
    def declaration_gap(self) -> int | None:
        """int or None: Declared pooled total minus the verdicts' pooled total.

        ``0`` on every honest run, and on every run in which each verifier
        declared the count he then scored. Non-zero is not a probabilistic
        event under any null: it means the integers a recipient put on the wire
        were not the integers his own log supports, which is what count
        starvation *is*. ``None`` when either total is unavailable.
        """
        if self.declared_pooled is None or self.pooled is None:
            return None
        return self.declared_pooled.count - self.pooled.count

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "pooled": None if self.pooled is None else self.pooled.to_dict(),
            "declared_bob": (
                None if self.declared_bob is None else self.declared_bob.to_dict()
            ),
            "declared_charlie": (
                None
                if self.declared_charlie is None
                else self.declared_charlie.to_dict()
            ),
            "declared_pooled": (
                None
                if self.declared_pooled is None
                else self.declared_pooled.to_dict()
            ),
            "counts_exchanged": self.counts_exchanged,
            "minimum_matched": self.minimum_matched,
            "minimum_pooled": self.minimum_pooled,
            "meets_pooled_floor": self.meets_pooled_floor,
            "meets_every_floor": self.meets_every_floor,
            "declaration_digest_present": self.declaration_digest_present,
            "matched_floor_bound": self.matched_floor_bound,
            "declaration_gap": self.declaration_gap,
        }


# --------------------------------------------------------------------------- #
# Per-link check-round statistics -- never pooled by default
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ResourceStatistics:
    """What the entanglement resource looked like on one link's check rounds.

    The resource side of a check round, summarised from
    :attr:`~sih141.protocol.session.SessionTranscript.channel`. Every field has
    a **point-mass null**: on an ideal :math:`|\\Phi^{+}\\rangle` the fidelity,
    purity and concurrence are ``1`` and each wing's purity is ``0.5``, exactly,
    up to the floating-point dust of a four-by-four matrix. So a detector that
    fires on ``mean_fidelity < 1 - 1e-9`` has a false-positive probability of
    exactly zero *against a run whose honest resource is ideal*, and the caveat
    is the whole content of the claim: a deployment whose honest pairs are
    already noisy needs its null re-stated at that noise level, and the
    transcript cannot tell you what that level is.

    ``wings_agree`` is deliberately absent; see
    :func:`why_wings_agree_is_absent`.

    Attributes
    ----------
    samples : int
        How many check rounds on this link were monitored. ``0`` is possible on
        a checked run: an impersonator who substitutes his own states consumes
        no entanglement, and an empty channel log says so rather than reporting
        a clean channel. **Every summary below is then** ``None``, not ``0.0``
        and not ``nan``: an unmonitored link has no fidelity, a zero would read
        as a maximally broken channel, and ``nan`` is not JSON -- writing it
        would hand a Phase 6 dashboard a document its parser rejects.
    qber_samples, chsh_samples : int
        The split by arm.
    mean_fidelity, min_fidelity : float or None
        :math:`\\langle\\Phi^{+}|\\rho|\\Phi^{+}\\rangle`, mean and worst over
        the sample. ``1.0`` ideally.
    mean_purity, min_purity : float or None
        :math:`\\mathrm{Tr}(\\rho^2)`. ``1.0`` ideally. Separates a *mixing*
        attack from a *unitary* one: a rotated pair is still pure and still
        wrong.
    mean_concurrence, min_concurrence : float or None
        Entanglement of the pair. ``1.0`` ideally, ``0.0`` for anything
        separable.
    mean_alice_purity, mean_recipient_purity : float or None
        :math:`\\mathrm{Tr}(\\rho_A^2)` and its counterpart for the travelling
        half. Both ``0.5`` ideally, because each half of a maximally entangled
        pair is maximally mixed on its own. Reported as two numbers because a
        channel that damps only the leg in flight moves one and not the other;
        reported as *numbers* rather than as the boolean that compares them,
        for the reason :func:`why_wings_agree_is_absent` gives.
    ideal_samples : CountStatistic
        How many of the rounds sat on every ideal value at once, against a
        point mass at all of them. On an unmonitored link this has ``trials =
        0`` and says so.
    extra_keys : tuple of str
        Which keys a ``channel_monitor`` seam wrote into ``extra``, sorted.
        **The keys only**: the values are free-form JSON written by a seam, so
        a statistic keyed on their contents would be reading harness state
        through a hole in the boundary. Reported so that a reviewer can see a
        monitor was attached, and so that :ref:`finding 8 <findings>` is
        visible rather than silent.
    """

    samples: int
    qber_samples: int
    chsh_samples: int
    mean_fidelity: float | None
    min_fidelity: float | None
    mean_purity: float | None
    min_purity: float | None
    mean_concurrence: float | None
    min_concurrence: float | None
    mean_alice_purity: float | None
    mean_recipient_purity: float | None
    ideal_samples: CountStatistic
    extra_keys: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "samples": self.samples,
            "qber_samples": self.qber_samples,
            "chsh_samples": self.chsh_samples,
            "mean_fidelity": self.mean_fidelity,
            "min_fidelity": self.min_fidelity,
            "mean_purity": self.mean_purity,
            "min_purity": self.min_purity,
            "mean_concurrence": self.mean_concurrence,
            "min_concurrence": self.min_concurrence,
            "mean_alice_purity": self.mean_alice_purity,
            "mean_recipient_purity": self.mean_recipient_purity,
            "ideal_samples": self.ideal_samples.to_dict(),
            "extra_keys": list(self.extra_keys),
        }


@dataclass(frozen=True)
class LinkStatistics:
    """One recipient's link on one message bit, estimated from its own sample.

    **Per link and per message bit, never pooled.** Symmetrisation smears the
    records but never the check logs, so per-link QBER is the only statistic
    that both detects a party-targeted channel attack *and* attributes it;
    pooling two links reports the average of two channels and detects neither,
    which is the exact shape of a one-sided attack. :func:`pooled_check_qber`
    exists for a caller who has decided the two links really are one channel,
    and makes that decision visible at the call site.

    Everything on this object is conditioned on (NO-TIMING); see
    :ref:`no-timing`. Cite it wherever these numbers are published.

    Attributes
    ----------
    party : Party
        Whose link.
    message_bit : int
        Which distribution.
    errors : CountStatistic
        Check-round QBER errors against a point mass at ``0``: on a noiseless
        link every QBER round reproduces the ideal two-wing correlation. The
        denominator is the number of QBER rounds actually observed. Under an
        honest depolarising channel of strength ``p`` the null becomes
        ``Binomial(n_qber, q)`` with ``q`` from
        :func:`~sih141.protocol.analysis.depolarising_error_rate`; the
        transcript does not carry ``p``, so a noise-tolerant threshold has to
        be handed one.
    qber : QberEstimate or None
        The protocol's own estimate, interval included, recomputed here from
        the published observations so that it is auditable rather than
        asserted. The interval is **Wilson**: calibrated, coverage close to
        nominal, and the right thing to *report*. ``None`` when the link
        published no QBER rounds.
    qber_bound : Interval or None
        The same rate's **Hoeffding** interval,
        ``q +- sqrt(ln(2/alpha) / (2n))``: distribution-free, coverage *at
        least* the stated level at every ``n``, and therefore the one a
        security claim is entitled to quote. Carried beside the calibrated one
        rather than instead of it, because a report that mixes the two without
        saying which is which is not reporting a confidence level at all. A
        threshold derived under D7 should take this one.
    chsh : ChshEstimate or None
        The Bell-test arm, with the **normal** plug-in interval. ``None`` when
        the link published no CHSH rounds **or** when one of the four
        correlator cells came out empty, which is not a failure but a sample
        too small to compute ``S`` from; a correlator with no rounds behind it
        is undefined, and treating it as zero would report a two-setting
        experiment as a Bell test.
    chsh_bound : Interval or None
        The same ``S``, bounded distribution-free: a per-cell half-width
        ``sqrt(2 ln(8/alpha) / n_c)`` summed over the four cells, where the
        ``8`` is a union bound over four cells and two tails. Coverage at least
        the stated level at every ``n``. The counterpart of :attr:`qber_bound`,
        and for the same reason.
    chsh_unavailable : str or None
        Why :attr:`chsh` is ``None``, when it is. Carried so that "no Bell test
        here" and "a Bell test that failed" can never be confused in a table.
    resource : ResourceStatistics
        The channel-monitor summaries for the same rounds.

    Notes
    -----
    The CHSH null is the one **asymptotic** entry in this module's table. Each
    cell correlator is a mean of ``+-1`` products, so on an ideal pair
    ``|E_c| = 1/sqrt(2)`` and ``Var(E_c) = (1 - 1/2)/n_c``; the four cells are
    disjoint sets of rounds and hence independent, so under the ideal null

    .. code-block:: text

        Var(S) = sum_c (1 - E_c^2) / n_c  =  sum_c 1 / (2 n_c)  =  8 / N

    for ``N`` rounds split evenly. :attr:`chsh_z` standardises the observed
    ``S`` by *that* variance -- the null's own, computed from
    ``|E_c| = 1/sqrt(2)`` -- and not by the plug-in variance
    :func:`~sih141.protocol.checkrounds.estimate_chsh` uses for its reporting
    interval. The distinction is the one :mod:`sih141.attacks.statistics` makes
    about tolerances: the hypothesis under test is that the ideal analysis is
    right, and an estimator's own value has no business setting the width of
    its own acceptance band.

    All of that is a central-limit statement rather than an exact one, which is
    why :attr:`chsh_bound` is carried beside it.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192, check_fraction=0.25),
    ...         rng=np.random.default_rng(7),
    ...     ).run(0)
    ... )
    >>> link = stats.link("Bob", 0)
    >>> link.errors.count, link.errors.trials
    (0, 12)
    >>> f"{link.qber.interval.high:.6f}"
    '0.356047'
    >>> link.resource.samples, link.resource.mean_fidelity
    (24, 1.0)
    >>> round(link.resource.mean_alice_purity, 9)
    0.5

    The calibrated interval and the distribution-free bound are both carried,
    labelled, and never the same number: a bound that is not wider than the
    interval it bounds is not a bound.

    >>> link.qber.interval.method, link.qber_bound.method
    ('wilson', 'hoeffding')
    >>> link.qber_bound.high > link.qber.interval.high
    True
    >>> link.chsh_bound.method, link.chsh.interval.method
    ('hoeffding', 'normal')
    """

    party: Party
    message_bit: int
    errors: CountStatistic
    qber: QberEstimate | None
    qber_bound: Interval | None
    chsh: ChshEstimate | None
    chsh_bound: Interval | None
    chsh_unavailable: str | None
    resource: ResourceStatistics

    @property
    def qber_rounds(self) -> int:
        """int: How many QBER rounds this link published."""
        return self.errors.trials

    @property
    def chsh_statistic(self) -> float | None:
        """float or None: ``S``, or ``None`` when the arm produced no estimate."""
        return None if self.chsh is None else self.chsh.statistic

    @property
    def chsh_z(self) -> float | None:
        """float or None: ``S - 2 sqrt(2)`` in units of the ideal null's sd.

        The standardised deviation from an ideal resource, using the **null's**
        variance ``sum_c 1 / (2 n_c)`` rather than the measured correlators'.
        ``None`` when no estimate exists. Negative on a disturbed link, since
        every channel that touches the pair lowers ``S``.
        """
        if self.chsh is None:
            return None
        variance = sum(1.0 / (2.0 * count) for count in self.chsh.counts)
        deviation = self.chsh.statistic - IDEAL_CHSH
        if variance == 0.0:
            return 0.0 if deviation == 0.0 else math.copysign(
                math.inf, deviation
            )
        return deviation / math.sqrt(variance)

    @property
    def violates_classical_bound(self) -> bool | None:
        """bool or None: Whether the ``S`` interval sits strictly above ``2``.

        The claim "the resource was entangled when it arrived", stated so that
        sampling error counts against it. ``None`` where no estimate exists --
        which is *not* the same as ``False`` and must not be rendered as one.
        """
        if self.chsh is None:
            return None
        return self.chsh.violates_classical_bound

    @property
    def consistent_with_ideal(self) -> bool | None:
        """bool or None: Whether the ``S`` interval covers ``2 sqrt(2)``.

        The honest-channel test. ``False`` says the deviation from
        :data:`~sih141.protocol.checkrounds.IDEAL_CHSH` is larger than sampling
        noise explains. ``None`` where no estimate exists.
        """
        if self.chsh is None:
            return None
        return self.chsh.consistent_with_ideal

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "party": str(self.party),
            "message_bit": self.message_bit,
            "errors": self.errors.to_dict(),
            "qber": None if self.qber is None else self.qber.to_dict(),
            "qber_bound": (
                None if self.qber_bound is None else self.qber_bound.to_dict()
            ),
            "chsh": None if self.chsh is None else self.chsh.to_dict(),
            "chsh_bound": (
                None if self.chsh_bound is None else self.chsh_bound.to_dict()
            ),
            "chsh_z": self.chsh_z,
            "chsh_unavailable": self.chsh_unavailable,
            "violates_classical_bound": self.violates_classical_bound,
            "consistent_with_ideal": self.consistent_with_ideal,
            "resource": self.resource.to_dict(),
        }


def pooled_check_qber(
    logs: Iterable[CheckLog], *, pool: bool, confidence: float = CHECK_CONFIDENCE
) -> QberEstimate:
    """Estimate one QBER over several links' check logs, if you really mean to.

    **Pooling is a deliberate opt-in and this function refuses to do it
    silently.** Phase 3 established the rule: symmetrisation smears the records
    but never the check logs, so per-link QBER is the only statistic that both
    detects a party-targeted channel attack and attributes it. A rate pooled
    over Bob's link and Charlie's link is the average of two channels; if one
    of them is under attack and the other is clean, the average is half the
    disturbance and the attribution is gone entirely. Use
    :meth:`TranscriptStatistics.link` unless the two links are known to be one
    physical channel -- a shared fibre, say -- in which case pooling doubles the
    sample legitimately and this function is how to say so out loud.

    Parameters
    ----------
    logs : iterable of CheckLog
        The logs to pool.
    pool : bool
        Keyword-only and mandatory. Must be ``True``. It exists only to make
        the decision appear at the call site, where a reviewer sees it.
    confidence : float, optional
        Keyword-only two-sided level, defaulting to
        :data:`~sih141.protocol.checkrounds.CHECK_CONFIDENCE`.

    Returns
    -------
    QberEstimate
        Over every QBER observation in every supplied log.

    Raises
    ------
    ValueError
        If ``pool`` is not ``True``, or if the pooled sample is empty -- a rate
        needs a denominator.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import pooled_check_qber
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession, SessionTranscript
    >>> transcript = SessionTranscript.from_json(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192, check_fraction=0.25),
    ...         rng=np.random.default_rng(7),
    ...     ).run(0).to_json()
    ... )
    >>> estimate = pooled_check_qber(transcript.check_logs, pool=True)
    >>> estimate.errors, estimate.rounds
    (0, 48)

    Declining to say so is refused rather than defaulted:

    >>> pooled_check_qber(transcript.check_logs, pool=False)
    Traceback (most recent call last):
        ...
    ValueError: pooling two links' check logs is a deliberate choice, ...
    """
    if pool is not True:
        raise ValueError(
            "pooling two links' check logs is a deliberate choice, so pass "
            "pool=True to make it. Per-link QBER is the only statistic that "
            "both detects a party-targeted channel attack and attributes it; "
            "a pooled rate is the average of two channels and detects "
            "neither. Use TranscriptStatistics.link(party, message_bit) for "
            "the default."
        )
    observations: list[QberObservation] = []
    for log in logs:
        observations.extend(log.qber)
    if not observations:
        raise ValueError(
            "the pooled sample holds no QBER rounds, so there is no rate to "
            "estimate: a rate needs a denominator. This is what a run with "
            "check_fraction = 0 looks like, and the honest report is that it "
            "published no channel statistics."
        )
    return estimate_qber(observations, confidence=confidence)


# --------------------------------------------------------------------------- #
# Aborts, replay, declarations and records
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AbortStatistics:
    """Refusals to score, counted by reason -- and never mixed with verdicts.

    A refusal is not a rejection. Aborts are a separate transcript field of a
    separate type precisely so that no statistic can average a refusal into a
    rejection, and this class is the same separation one layer up: nothing here
    is ever summed with anything on :class:`VerifierStatistics`. Folding them
    together would report a detection that never happened, which is the single
    most likely way for a Phase 5 table to be wrong.

    Attributes
    ----------
    total : int
        How many verifiers reached no verdict. ``0`` on a healthy run, ``2`` at
        most.
    by_reason : mapping of str to int
        Counts keyed by :class:`~sih141.protocol.verify.AbortReason` value.
        Only reasons that occurred appear.
    by_party : mapping of str to str
        Which reason each refusing party recorded.
    structural : int
        Refusals whose reason is in :data:`STRUCTURAL_ABORT_REASONS`. **These
        cannot happen on an honest run at any key length**, so a detector
        firing on ``structural > 0`` has a false-positive probability of
        exactly zero under the honest null. That is the strongest provable
        bound in this module and it costs nothing.
    evidence : int
        Refusals whose reason is in :data:`EVIDENCE_ABORT_REASONS`, i.e. one of
        the two matched-count floors. Each floor was derived from a Chernoff
        lower tail at :data:`~sih141.protocol.verify.HONEST_ABORT_BUDGET`, so
        an honest verifier trips one with probability at most ``2**-64`` and an
        honest run with probability at most :attr:`honest_bound`.
    honest_bound : float or None
        The run-level bound on ``evidence > 0`` under the honest null,
        **computed from this run's own sifted parameters**, or ``None`` when no
        parameter set was supplied and the bound therefore cannot be stated.
        See :func:`evidence_abort_probability_bound` for the derivation and for
        what this field used to be.
    shortfalls : mapping of str to int
        Each refusing party's distance below whichever floor it failed, as the
        run recorded it. ``0`` for the structural reasons, which name no floor.

    Examples
    --------
    An abort tally with no parameter set behind it states no bound, because the
    bound is a function of the key length and there is no honest number to put
    there:

    >>> from sih141.detect.statistics import AbortStatistics
    >>> empty = AbortStatistics.empty()
    >>> empty.total, empty.structural, empty.evidence
    (0, 0, 0)
    >>> empty.honest_bound is None
    True

    Given the parameters it is a function of ``n``, and it is not monotone in
    it -- an exact ``(1 - p)**n`` term is replaced by the looser Chernoff term
    each time a floor starts to bite:

    >>> from sih141.protocol.params import ProtocolParams
    >>> for length in (24, 96, 273, 115200):
    ...     bound = AbortStatistics.empty(
    ...         ProtocolParams(key_length=length)
    ...     ).honest_bound
    ...     print(f"n = {length:6d}   {bound:.4e}")
    n =     24   1.1881e-04
    n =     96   2.4904e-17
    n =    273   1.6263e-19
    n = 115200   1.6263e-19
    """

    total: int
    by_reason: Mapping[str, int]
    by_party: Mapping[str, str]
    structural: int
    evidence: int
    honest_bound: float | None
    shortfalls: Mapping[str, int]

    @classmethod
    def empty(cls, params: ProtocolParams | None = None) -> AbortStatistics:
        """Return the statistics of a run in which nobody refused to score.

        Parameters
        ----------
        params : ProtocolParams or None, optional
            The run's **sifted** parameter set, used only to state
            :attr:`honest_bound`. ``None`` leaves that bound unstated rather
            than guessing one, because it is a function of the key length.

        Returns
        -------
        AbortStatistics
        """
        return cls(
            total=0,
            by_reason={},
            by_party={},
            structural=0,
            evidence=0,
            honest_bound=(
                None
                if params is None
                else evidence_abort_probability_bound(params)
            ),
            shortfalls={},
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "total": self.total,
            "by_reason": dict(self.by_reason),
            "by_party": dict(self.by_party),
            "structural": self.structural,
            "evidence": self.evidence,
            "honest_bound": self.honest_bound,
            "shortfalls": dict(self.shortfalls),
        }


@dataclass(frozen=True)
class ReplayStatistics:
    """The replay defence's own record: refusals counted, rounds spent.

    Both nulls here are **point masses**, which makes them the cheapest
    provable statements in the module and the easiest to misread as trivial.
    An honest run asks each verifier exactly once, so a refusal to re-decide a
    spent round happens exactly zero times; and a complete honest run leaves
    exactly two spent rounds, one per verifier, naming one session identifier
    and one message bit. Neither is a rate and neither has sampling error: a
    non-zero refusal count is a replay, full stop.

    Attributes
    ----------
    total_refusals : int
        How many times a verifier was asked to decide a round he had already
        decided. Point-mass null at ``0``.
    refusals_by_party : mapping of str to int
        The same, split by verifier. A replay against a live session leaves no
        other trace, which is why the count exists at all.
    spent_rounds : int
        How many ``(party, session_id, message_bit)`` triples the two ledgers
        held at the end. ``2`` on a complete honest run, fewer on a run
        abandoned part-way.
    distinct_sessions : int
        How many distinct session identifiers appear among them. ``1`` on any
        single-round run; more than one means the transcript's ledgers span
        rounds, which a single session does not produce.
    distinct_message_bits : int
        Likewise for the bit. ``1`` on a run that signed one bit.
    parties_with_spent_rounds : tuple of str
        Sorted, so two runs of one seed compare equal.

    Notes
    -----
    There is **no replay rate here and there cannot be**: the transcript
    records refusals but not the number of times each verifier was *asked*, so
    the denominator does not exist. See :ref:`finding 6 <findings>`. A Phase 5
    table wanting a rate has to supply the attempt count from its own harness,
    and must say that it did.

    Examples
    --------
    >>> from sih141.detect.statistics import ReplayStatistics
    >>> quiet = ReplayStatistics(0, {}, 2, 1, 1, ("Bob", "Charlie"))
    >>> quiet.total_refusals, quiet.spent_rounds
    (0, 2)
    """

    total_refusals: int
    refusals_by_party: Mapping[str, int]
    spent_rounds: int
    distinct_sessions: int
    distinct_message_bits: int
    parties_with_spent_rounds: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "total_refusals": self.total_refusals,
            "refusals_by_party": dict(self.refusals_by_party),
            "spent_rounds": self.spent_rounds,
            "distinct_sessions": self.distinct_sessions,
            "distinct_message_bits": self.distinct_message_bits,
            "parties_with_spent_rounds": list(self.parties_with_spent_rounds),
        }


@dataclass(frozen=True)
class DeclarationStatistics:
    """The declared key read as a random string, and its binding.

    Alice draws each key element's basis uniformly from ``B`` and its
    eigenvalue uniformly from ``{+1, -1}``, independently across elements
    (:func:`~sih141.protocol.keys.generate_private_key`). Both nulls follow
    directly and neither needs an approximation.

    Attributes
    ----------
    party : str
        Which verifier scored this declaration -- ``"Bob"``, or ``"Charlie"``
        where the forwarding hop handed him a different one. The two are
        separate objects because a run in which the verifiers scored different
        declarations is otherwise unrepresentable.
    length : int
        The declared key length, which is the *sifted* length on a checked run.
    basis_counts : mapping of str to CountStatistic
        One statistic per alphabet symbol, each against ``Binomial(length,
        1/|B|)``. The joint law is ``Multinomial(length, uniform)``; the
        marginals are what a threshold can be derived from without a
        multivariate tail bound, and a union bound over ``|B|`` of them costs a
        factor of three.
    off_alphabet : int
        Declared bases outside ``params.bases``. Zero on anything the protocol
        produces; a positive count is a malformed declaration, not a deviation.
    positive_eigenvalues : CountStatistic
        ``+1`` outcomes against ``Binomial(length, 1/2)``.
    bound : bool
        Whether the declaration names a distribution round at all.
    session_id : str or None
        The round it names.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> declaration = stats.declarations["Bob"]
    >>> declaration.length, declaration.bound, declaration.off_alphabet
    (192, True, 0)
    >>> sorted(declaration.basis_counts)
    ['X', 'Y', 'Z']
    >>> sum(stat.count for stat in declaration.basis_counts.values())
    192
    """

    party: str
    length: int
    basis_counts: Mapping[str, CountStatistic]
    off_alphabet: int
    positive_eigenvalues: CountStatistic
    bound: bool
    session_id: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "party": self.party,
            "length": self.length,
            "basis_counts": {
                name: stat.to_dict() for name, stat in self.basis_counts.items()
            },
            "off_alphabet": self.off_alphabet,
            "positive_eigenvalues": self.positive_eigenvalues.to_dict(),
            "bound": self.bound,
            "session_id": self.session_id,
        }


@dataclass(frozen=True)
class RecordStatistics:
    """One recipient's log for one message bit, read as a random string.

    Present for **both** message bits, because the transcript carries both
    distributions and hiding one would be an editorial choice rather than an
    extraction. Only the signed bit's records have a declaration to be scored
    against, though, so the matched-set statistics live on
    :class:`VerifierStatistics` and this class carries the frequency statistics
    that need no declaration.

    Attributes
    ----------
    party : Party
    message_bit : int
    length : int
    symmetrised : bool
        Whether this log went through Phase A'. ``False`` marks a run of the
        insecure variant, which supports no non-repudiation claim at any key
        length. Provenance, not data: the difference is invisible in the two
        columns and worth an entire security property.
    session_id : str or None
        Which distribution round the log names, as Alice announced it before
        any declaration existed. The anchor of the replay defence, and the one
        end of the comparison no signer can reach.
    basis_counts : mapping of str to CountStatistic
        Against ``Binomial(length, 1/|B|)`` per symbol, for the same reason and
        with the same union-bound caveat as
        :attr:`DeclarationStatistics.basis_counts`. A recipient draws his
        measurement basis freely and uniformly, and Phase A' swaps whole
        entries between two logs drawn the same way, so the law survives the
        exchange.
    off_alphabet : int
        Bases outside ``params.bases``. Zero on anything the protocol produces.
    positive_eigenvalues : CountStatistic
        Against ``Binomial(length, 1/2)``: a recipient's recorded sign is
        uniform whether or not his basis matched, so this null needs no
        conditioning on the matched set.
    signed_bit : bool
        Whether this is the distribution the run actually signed.
    """

    party: Party
    message_bit: int
    length: int
    symmetrised: bool
    session_id: str | None
    basis_counts: Mapping[str, CountStatistic]
    off_alphabet: int
    positive_eigenvalues: CountStatistic
    signed_bit: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "party": str(self.party),
            "message_bit": self.message_bit,
            "length": self.length,
            "symmetrised": self.symmetrised,
            "session_id": self.session_id,
            "basis_counts": {
                name: stat.to_dict() for name, stat in self.basis_counts.items()
            },
            "off_alphabet": self.off_alphabet,
            "positive_eigenvalues": self.positive_eigenvalues.to_dict(),
            "signed_bit": self.signed_bit,
        }


# --------------------------------------------------------------------------- #
# Extraction helpers
# --------------------------------------------------------------------------- #


def _basis_statistics(
    bases: Sequence[Any], params: ProtocolParams, prefix: str
) -> tuple[dict[str, CountStatistic], int]:
    """Count basis symbols against the uniform-alphabet null.

    Parameters
    ----------
    bases : sequence
        The declared or recorded bases, in key order.
    params : ProtocolParams
        Supplies the alphabet and hence the null's ``1/|B|``.
    prefix : str
        Prepended to each statistic's name.

    Returns
    -------
    tuple
        ``(statistics_by_symbol, off_alphabet_count)``.
    """
    alphabet = [str(basis) for basis in params.bases]
    length = len(bases)
    probability = params.match_probability
    observed = [str(basis) for basis in bases]
    counts = {symbol: observed.count(symbol) for symbol in alphabet}
    off = length - sum(counts.values())
    null = f"Binomial({length}, 1/{len(alphabet)})"
    return (
        {
            symbol: CountStatistic(
                name=f"{prefix}.basis[{symbol}]",
                count=count,
                trials=length,
                null_probability=probability,
                null=null,
            )
            for symbol, count in counts.items()
        },
        off,
    )


def _eigenvalue_statistic(
    eigenvalues: Sequence[int], name: str
) -> CountStatistic:
    """Count ``+1`` outcomes against the fair-coin null.

    Parameters
    ----------
    eigenvalues : sequence of int
        ``+1``/``-1`` outcomes.
    name : str
        The statistic's name.

    Returns
    -------
    CountStatistic
    """
    length = len(eigenvalues)
    return CountStatistic(
        name=name,
        count=sum(1 for value in eigenvalues if value == 1),
        trials=length,
        null_probability=0.5,
        null=f"Binomial({length}, 1/2)",
    )


def _resource_statistics(
    samples: Sequence[ChannelSample],
) -> ResourceStatistics:
    """Summarise one link's channel samples.

    Parameters
    ----------
    samples : sequence of ChannelSample
        Possibly empty.

    Returns
    -------
    ResourceStatistics
    """
    total = len(samples)
    if total == 0:
        zero = CountStatistic(
            name="ideal_samples",
            count=0,
            trials=0,
            null_probability=1.0,
            null="point mass at every ideal value (no samples observed)",
        )
        # None rather than nan: an unmonitored link has no fidelity, and
        # json.dumps writes nan as the bare token ``NaN``, which is not JSON
        # and which a strict downstream parser refuses.
        return ResourceStatistics(
            samples=0,
            qber_samples=0,
            chsh_samples=0,
            mean_fidelity=None,
            min_fidelity=None,
            mean_purity=None,
            min_purity=None,
            mean_concurrence=None,
            min_concurrence=None,
            mean_alice_purity=None,
            mean_recipient_purity=None,
            ideal_samples=zero,
            extra_keys=(),
        )

    def mean(values: Iterable[float]) -> float:
        collected = list(values)
        return sum(collected) / len(collected)

    ideal = sum(
        1
        for sample in samples
        if sample.is_ideal
        and abs(sample.alice_purity - 0.5) <= IDEAL_TOLERANCE
        and abs(sample.recipient_purity - 0.5) <= IDEAL_TOLERANCE
    )
    extra_keys: set[str] = set()
    for sample in samples:
        extra_keys.update(str(key) for key in sample.extra)
    return ResourceStatistics(
        samples=total,
        qber_samples=sum(
            1 for sample in samples if sample.role is CheckRole.QBER
        ),
        chsh_samples=sum(
            1 for sample in samples if sample.role is CheckRole.CHSH
        ),
        mean_fidelity=mean(sample.fidelity for sample in samples),
        min_fidelity=min(sample.fidelity for sample in samples),
        mean_purity=mean(sample.purity for sample in samples),
        min_purity=min(sample.purity for sample in samples),
        mean_concurrence=mean(sample.concurrence for sample in samples),
        min_concurrence=min(sample.concurrence for sample in samples),
        mean_alice_purity=mean(sample.alice_purity for sample in samples),
        mean_recipient_purity=mean(
            sample.recipient_purity for sample in samples
        ),
        ideal_samples=CountStatistic(
            name="ideal_samples",
            count=ideal,
            trials=total,
            null_probability=1.0,
            null=(
                "point mass: an ideal Phi+ resource has fidelity, purity and "
                "concurrence 1 and both wing purities 1/2"
            ),
        ),
        extra_keys=tuple(sorted(extra_keys)),
    )


def _link_statistics(
    log: CheckLog, samples: Sequence[ChannelSample]
) -> LinkStatistics:
    """Build one link's statistics from its published log and samples.

    Parameters
    ----------
    log : CheckLog
        The published observations for one ``(party, message_bit)``.
    samples : sequence of ChannelSample
        The resource summaries for the same rounds.

    Returns
    -------
    LinkStatistics
    """
    qber_rounds = len(log.qber)
    errors = CountStatistic(
        name=f"qber_errors[{log.party.value},{log.message_bit}]",
        count=sum(1 for entry in log.qber if entry.is_error),
        trials=qber_rounds,
        null_probability=0.0,
        null=(
            "point mass at 0 on a noiseless link; "
            f"Binomial({qber_rounds}, p/2) under depolarising strength p"
        ),
    )
    qber = estimate_qber(log.qber) if qber_rounds else None
    qber_bound = (
        estimate_qber(log.qber, method="hoeffding").interval
        if qber_rounds
        else None
    )

    chsh: ChshEstimate | None = None
    chsh_bound: Interval | None = None
    unavailable: str | None = None
    if not log.chsh:
        unavailable = "this link published no CHSH rounds"
    else:
        cells = [0, 0, 0, 0]
        for entry in log.chsh:
            cells[entry.cell] += 1
        empty = [index for index, count in enumerate(cells) if count == 0]
        if empty:
            unavailable = (
                f"CHSH cell(s) {empty} hold no rounds out of "
                f"{len(log.chsh)}, so their correlators are undefined; "
                f"treating an empty cell as 0 would report a two-setting "
                f"experiment as a Bell test"
            )
        else:
            chsh = estimate_chsh(log.chsh)
            chsh_bound = estimate_chsh(log.chsh, method="hoeffding").interval

    return LinkStatistics(
        party=log.party,
        message_bit=log.message_bit,
        errors=errors,
        qber=qber,
        qber_bound=qber_bound,
        chsh=chsh,
        chsh_bound=chsh_bound,
        chsh_unavailable=unavailable,
        resource=_resource_statistics(samples),
    )


def _matched_null(trials: int, alphabet: int) -> str:
    """Return the written-out matched-count null.

    Parameters
    ----------
    trials : int
        The number of Bernoulli trials the null is stated over.
    alphabet : int
        ``|B|``.

    Returns
    -------
    str
    """
    return f"Binomial({trials}, 1/{alphabet})"


def _verifier_statistics(
    result: VerificationResult,
    record: RecipientRecord | None,
    declaration: Signature,
    scored: ProtocolParams,
) -> VerifierStatistics:
    """Build one verifier's statistics, recomputing the counts where possible.

    Recomputation needs the record, the declaration and the parameter set to
    agree on one length. They do on everything this package produces; a
    hand-assembled transcript can disagree, and there the reported counts are
    carried through with ``recomputed=False`` rather than being scored against
    a null whose trial count is a guess.

    Parameters
    ----------
    result : VerificationResult
        The verdict as recorded.
    record : RecipientRecord or None
        This verifier's log for the signed bit, if the transcript carries one.
    declaration : Signature
        The declaration *this* verifier scored -- which is not always the one
        Bob scored.
    scored : ProtocolParams
        The sifted parameter set, supplying ``n`` and the alphabet.

    Returns
    -------
    VerifierStatistics
    """
    signing_length = scored.key_length
    alphabet = len(scored.bases)
    recomputed = (
        record is not None
        and len(record) == signing_length
        and declaration.length == signing_length
    )
    matched_count = result.matched_count
    mismatch_count = result.mismatches
    unmatched_agreements = 0
    unmatched_trials = 0

    if recomputed:
        matched = matched_positions(declaration, record)
        matched_count = len(matched)
        mismatch_count = len(mismatch_positions(declaration, record))
        matched_set = set(matched)
        declared = declaration.eigenvalues
        measured = record.eigenvalues
        unmatched_trials = signing_length - matched_count
        unmatched_agreements = sum(
            1
            for index in range(signing_length)
            if index not in matched_set and measured[index] == declared[index]
        )

    consistent = (
        matched_count == result.matched_count
        and mismatch_count == result.mismatches
    )
    return VerifierStatistics(
        party=result.party,
        accepted=result.accepted,
        threshold=result.threshold,
        margin=result.margin,
        matched=CountStatistic(
            name=f"matched_count[{result.party.value}]",
            count=matched_count,
            trials=signing_length,
            null_probability=scored.match_probability,
            null=_matched_null(signing_length, alphabet),
        ),
        mismatch=CountStatistic(
            name=f"mismatches[{result.party.value}]",
            count=mismatch_count,
            trials=matched_count,
            null_probability=0.0,
            null=(
                "point mass at 0 on a noiseless honest link; "
                f"Binomial({matched_count}, p/2) under depolarising strength p"
            ),
        ),
        unmatched_agreement=CountStatistic(
            name=f"unmatched_agreements[{result.party.value}]",
            count=unmatched_agreements,
            trials=unmatched_trials,
            null_probability=0.5,
            null=f"Binomial({unmatched_trials}, 1/2)",
        ),
        recomputed=recomputed,
        reported_matched=result.matched_count,
        reported_mismatches=result.mismatches,
        consistent=consistent,
    )


# --------------------------------------------------------------------------- #
# The layer
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TranscriptStatistics:
    """Everything a Phase 4 detector may read, and nothing else.

    Built by :meth:`from_json` from JSON text, or by :meth:`from_transcript`,
    which serialises the object it is given and reads it straight back. There
    is no third door, and that is the boundary: a statistic that is not on this
    object was not reachable from a transcript, and reaching further for it is
    a finding to report rather than a step to take (:ref:`the-boundary`).

    Attributes
    ----------
    params : ProtocolParams
        The **sifted** parameter set the verdicts were reached under, so that
        ``params.key_length`` is ``n``, the number of positions that carried
        key. On a run with no check rounds it is the run's own parameter set.
    nominal_key_length : int
        ``L`` before sifting, from the run's own parameters. Different from
        :attr:`key_length` exactly on a run with check rounds, and carried so
        that the difference is visible instead of inferred.
    message_bit : int
        The bit that was signed.
    verifiers : mapping of str to VerifierStatistics
        Only the parties who reached a verdict.
    aborts : AbortStatistics
        Only the parties who did not. Never summed with the above.
    pooled : PooledStatistics
    replay : ReplayStatistics
    links : mapping of tuple to LinkStatistics
        Keyed by ``(party, message_bit)`` -- per link, per distribution, never
        pooled.
    declarations : mapping of str to DeclarationStatistics
        Keyed by the verifier who scored it. Two entries only on a run whose
        forwarding hop altered the declaration.
    records : mapping of tuple to RecordStatistics
        Keyed by ``(party, message_bit)``, for both bits.
    symmetrised, counts_exchanged, channel_monitored : bool
        Which protocol this run actually was. Each marks a variant with a
        different security claim, and a table that pooled runs across any of
        them would be averaging different experiments.
    signer_saw_recipient_logs : bool
        ``True`` marks an insecure-arm run whose signer seam was shown both
        recipients' raw logs -- more than any single adversary in the threat
        model holds. Carried so no Phase 5 table can quote such a run as if it
        described the shipped scheme.
    count_exchange_timing : str
        Which declaration Phase C' counted against. **Group by this; never
        average over it.** The two orderings give different answers to the same
        attack, so a table mixing them averages a forgery rate with a
        denial-of-service rate.
    forwarding_altered_signature, session_coherent, is_complete, aborted : bool
    transferable, repudiated : bool
        The run's own two headline outcomes, as the transcript computes them.
        :attr:`repudiated` is carried, and carries a warning:
        **it cannot distinguish signer misbehaviour from channel noise or from
        recipient forgery.** Phase 3 measured plain depolarising noise at
        ``p = 0.10`` producing ``repudiated == True`` with a completely honest
        Alice. The discriminator that works is Charlie's matched count -- see
        :attr:`PooledStatistics.pooled` -- which separates recipient forgery
        from noise at about ``9.8`` standard deviations at ``L = 192``.
    repudiation_guarantee : float or None
        The per-run bound the run is entitled to quote, from its own observed
        ``M``. ``None`` where the run is not a repudiation experiment at all.
    enforced_repudiation_bound : float
        The a-priori bound the floors enforce, evaluated on the sifted set.
    run_id : str or None
    has_check_rounds : bool
        Whether the run published any channel statistics at all. ``False``
        means the transcript carries no independent estimate of the link's
        error rate, so the only defensible null for ``r_R`` is the noiseless
        one (:ref:`finding 2 <findings>`).
    security_claim : bool
        Whether *either* matched-count floor is non-degenerate at this run's
        sifted length. ``False`` when both collapse to ``1``, where the run
        carries no security claim at all and every number in this object
        nevertheless computes cheerfully -- which is exactly why it needs a
        field rather than a footnote. The crossover is at a sifted length of
        ``137``, where the pooled floor first bites; the per-verifier floor
        does not bite until ``273``. A ``True`` here says a rule was in force,
        not that the run was long enough for any particular bound.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> transcript = QDSSession(
    ...     ProtocolParams(key_length=192), rng=np.random.default_rng(7)
    ... ).run(0)
    >>> stats = TranscriptStatistics.from_transcript(transcript)

    The two doors are one line apart, and agree:

    >>> stats == TranscriptStatistics.from_json(transcript.to_json())
    True

    Everything it holds survives :func:`json.dumps` unchanged, which is what a
    Phase 5 aggregator and a Phase 6 dashboard both need:

    >>> import json
    >>> json.loads(json.dumps(stats.to_dict()))["message_bit"]
    0
    >>> stats.security_claim, stats.has_check_rounds
    (True, False)
    """

    params: ProtocolParams
    nominal_key_length: int
    message_bit: int
    verifiers: Mapping[str, VerifierStatistics]
    aborts: AbortStatistics
    pooled: PooledStatistics
    replay: ReplayStatistics
    links: Mapping[tuple[str, int], LinkStatistics]
    declarations: Mapping[str, DeclarationStatistics]
    records: Mapping[tuple[str, int], RecordStatistics]
    symmetrised: bool
    counts_exchanged: bool
    channel_monitored: bool
    signer_saw_recipient_logs: bool
    count_exchange_timing: str
    forwarding_altered_signature: bool
    session_coherent: bool
    is_complete: bool
    aborted: bool
    transferable: bool
    repudiated: bool
    repudiation_guarantee: float | None
    enforced_repudiation_bound: float
    run_id: str | None
    has_check_rounds: bool
    security_claim: bool = True

    # -- construction ------------------------------------------------------- #

    @classmethod
    def from_json(cls, text: str) -> TranscriptStatistics:
        """Extract the statistics from JSON transcript text.

        **The canonical door.** Every other way in is defined in terms of this
        one, so the contract "the detector reads a JSON round-tripped
        transcript and nothing else" is a property of the code rather than of a
        convention somebody remembers.

        Parameters
        ----------
        text : str
            :meth:`~sih141.protocol.session.SessionTranscript.to_json` output.

        Returns
        -------
        TranscriptStatistics

        Raises
        ------
        TypeError
            If ``text`` is not a string.
        ValueError
            Propagated from
            :meth:`~sih141.protocol.session.SessionTranscript.from_json` if the
            document does not describe a self-consistent run. Refusing there
            rather than here is deliberate: a transcript whose Bob verdict
            carries Charlie's threshold is internally consistent and reports
            ``transferable=True`` for a run Bob rejected, and no statistic
            computed downstream of it would be worth anything.
        """
        if not isinstance(text, str):
            raise TypeError(
                f"text must be JSON transcript text, got "
                f"{type(text).__name__}. Pass transcript.to_json(), or use "
                f"TranscriptStatistics.from_transcript(transcript), which "
                f"does the round trip for you."
            )
        return cls._extract(SessionTranscript.from_json(text))

    @classmethod
    def from_transcript(
        cls, transcript: SessionTranscript
    ) -> TranscriptStatistics:
        """Extract the statistics from a transcript object, via JSON.

        Serialises and re-reads rather than reading the object directly, so
        that anything not representable in a transcript file is gone by
        construction and no reviewer has to check that this module did not
        peek. It is exactly ``from_json(transcript.to_json())``, and the
        example on the class asserts the two agree.

        Parameters
        ----------
        transcript : SessionTranscript
            The run to read.

        Returns
        -------
        TranscriptStatistics

        Raises
        ------
        TypeError
            If ``transcript`` is not a
            :class:`~sih141.protocol.session.SessionTranscript`. Not
            duck-typed: the round trip is the guarantee, and an object that
            merely quacks like a transcript would skip it.
        """
        if not isinstance(transcript, SessionTranscript):
            raise TypeError(
                f"transcript must be a SessionTranscript, got "
                f"{type(transcript).__name__}. The round trip through JSON is "
                f"what makes a measured detection rate mean something, so a "
                f"stand-in that cannot be serialised is refused rather than "
                f"read directly."
            )
        return cls.from_json(transcript.to_json())

    @classmethod
    def _extract(cls, transcript: SessionTranscript) -> TranscriptStatistics:
        """Do the extraction, from an already round-tripped transcript.

        Parameters
        ----------
        transcript : SessionTranscript
            Restored from JSON by :meth:`from_json`.

        Returns
        -------
        TranscriptStatistics
        """
        scored = transcript.params.sifted()
        records_for_bit = transcript.records_for(transcript.message_bit)
        verifiers: dict[str, VerifierStatistics] = {}
        for result in transcript.results:
            verifiers[result.party.value] = _verifier_statistics(
                result=result,
                record=records_for_bit.get(result.party),
                declaration=transcript.signature_for(result.party),
                scored=scored,
            )

        by_reason: dict[str, int] = {}
        by_party: dict[str, str] = {}
        shortfalls: dict[str, int] = {}
        structural = 0
        evidence = 0
        for abort in transcript.aborts:
            reason = str(abort.reason)
            by_reason[reason] = by_reason.get(reason, 0) + 1
            by_party[abort.party.value] = reason
            shortfalls[abort.party.value] = abort.shortfall
            if abort.reason in STRUCTURAL_ABORT_REASONS:
                structural += 1
            else:
                evidence += 1
        aborts = AbortStatistics(
            total=len(transcript.aborts),
            by_reason=by_reason,
            by_party=by_party,
            structural=structural,
            evidence=evidence,
            # From THIS run's own sifted parameters and THIS run's own
            # configuration, never a constant: the bound is a function of n
            # (see evidence_abort_probability_bound), and a run that did not
            # exchange counts has no pooled floor and so no third term.
            honest_bound=evidence_abort_probability_bound(
                scored, counts_exchanged=transcript.counts_exchanged
            ),
            shortfalls=shortfalls,
        )

        pooled = cls._pooled_statistics(transcript, scored)
        replay = cls._replay_statistics(transcript)

        samples_by_link: dict[tuple[Party, int], list[ChannelSample]] = {}
        for sample in transcript.channel:
            samples_by_link.setdefault(
                (sample.party, sample.message_bit), []
            ).append(sample)
        links = {
            (log.party.value, log.message_bit): _link_statistics(
                log, samples_by_link.get((log.party, log.message_bit), [])
            )
            for log in transcript.check_logs
        }

        declarations: dict[str, DeclarationStatistics] = {}
        # Charlie gets his own entry only where the forwarding hop altered the
        # declaration: on an honest run the two verifiers scored one
        # declaration, and a second identical entry would invite a table to
        # count it twice.
        scoring = [Party.BOB]
        if transcript.forwarding_altered_signature:
            scoring.append(Party.CHARLIE)
        for party in scoring:
            declarations[party.value] = cls._declaration_statistics(
                transcript.signature_for(party), scored, party.value
            )

        records: dict[tuple[str, int], RecordStatistics] = {}
        for record in transcript.records:
            counts, off = _basis_statistics(
                record.bases,
                scored,
                f"record[{record.party.value},{record.message_bit}]",
            )
            records[(record.party.value, record.message_bit)] = RecordStatistics(
                party=record.party,
                message_bit=record.message_bit,
                length=len(record),
                symmetrised=record.symmetrised,
                session_id=record.session_id,
                basis_counts=counts,
                off_alphabet=off,
                positive_eigenvalues=_eigenvalue_statistic(
                    record.eigenvalues,
                    f"record[{record.party.value},"
                    f"{record.message_bit}].positive",
                ),
                signed_bit=record.message_bit == transcript.message_bit,
            )

        floor = minimum_matched_count(scored)
        pooled_floor = minimum_pooled_matched_count(scored)
        return cls(
            params=scored,
            nominal_key_length=transcript.params.key_length,
            message_bit=transcript.message_bit,
            verifiers=verifiers,
            aborts=aborts,
            pooled=pooled,
            replay=replay,
            links=links,
            declarations=declarations,
            records=records,
            symmetrised=transcript.symmetrised,
            counts_exchanged=transcript.counts_exchanged,
            channel_monitored=transcript.channel_monitored,
            signer_saw_recipient_logs=transcript.signer_saw_recipient_logs,
            count_exchange_timing=transcript.count_exchange_timing,
            forwarding_altered_signature=(
                transcript.forwarding_altered_signature
            ),
            session_coherent=transcript.session_coherent,
            is_complete=transcript.is_complete,
            aborted=transcript.aborted,
            transferable=transcript.transferable,
            repudiated=transcript.repudiated,
            repudiation_guarantee=transcript.repudiation_guarantee,
            enforced_repudiation_bound=_enforced_repudiation_bound(scored),
            run_id=transcript.run_id,
            has_check_rounds=bool(transcript.check_logs),
            security_claim=floor > 1 or pooled_floor > 1,
        )

    @staticmethod
    def _pooled_statistics(
        transcript: SessionTranscript, scored: ProtocolParams
    ) -> PooledStatistics:
        """Build the pooled-evidence statistics.

        Parameters
        ----------
        transcript : SessionTranscript
            The round-tripped run.
        scored : ProtocolParams
            The sifted parameter set, supplying ``n`` and the alphabet.

        Returns
        -------
        PooledStatistics
        """
        signing_length = scored.key_length
        probability = scored.match_probability
        alphabet = len(scored.bases)
        one = _matched_null(signing_length, alphabet)
        both = _matched_null(2 * signing_length, alphabet)

        pooled_count = transcript.pooled_matched_count
        pooled_stat = (
            None
            if pooled_count is None
            else CountStatistic(
                name="pooled_matched_count",
                count=pooled_count,
                trials=2 * signing_length,
                null_probability=probability,
                null=both,
            )
        )
        exchange = transcript.pooled
        declared_bob = declared_charlie = declared_pooled = None
        if exchange is not None:
            declared_bob = CountStatistic(
                name="declared_matched_count[Bob]",
                count=exchange.bob_count,
                trials=signing_length,
                null_probability=probability,
                null=one,
            )
            declared_charlie = CountStatistic(
                name="declared_matched_count[Charlie]",
                count=exchange.charlie_count,
                trials=signing_length,
                null_probability=probability,
                null=one,
            )
            declared_pooled = CountStatistic(
                name="declared_pooled_matched_count",
                count=exchange.pooled,
                trials=2 * signing_length,
                null_probability=probability,
                null=both,
            )
        return PooledStatistics(
            pooled=pooled_stat,
            declared_bob=declared_bob,
            declared_charlie=declared_charlie,
            declared_pooled=declared_pooled,
            counts_exchanged=exchange is not None,
            minimum_matched=(
                None if exchange is None else exchange.minimum_matched
            ),
            minimum_pooled=(
                None if exchange is None else exchange.minimum_pooled
            ),
            meets_pooled_floor=(
                None if exchange is None else exchange.meets_pooled_floor
            ),
            meets_every_floor=(
                None if exchange is None else exchange.meets_every_floor
            ),
            declaration_digest_present=(
                exchange is not None and bool(exchange.declaration_digest)
            ),
            matched_floor_bound=HONEST_ABORT_BUDGET,
        )

    @staticmethod
    def _replay_statistics(transcript: SessionTranscript) -> ReplayStatistics:
        """Build the replay statistics.

        Parameters
        ----------
        transcript : SessionTranscript

        Returns
        -------
        ReplayStatistics
        """
        refusals = {party: count for party, count in transcript.replay_refusals}
        return ReplayStatistics(
            total_refusals=sum(refusals.values()),
            refusals_by_party=refusals,
            spent_rounds=len(transcript.spent_rounds),
            distinct_sessions=len(
                {session for _, session, _ in transcript.spent_rounds}
            ),
            distinct_message_bits=len(
                {bit for _, _, bit in transcript.spent_rounds}
            ),
            parties_with_spent_rounds=tuple(
                sorted({party for party, _, _ in transcript.spent_rounds})
            ),
        )

    @staticmethod
    def _declaration_statistics(
        declaration: Signature, scored: ProtocolParams, party: str
    ) -> DeclarationStatistics:
        """Build one declaration's frequency statistics.

        Parameters
        ----------
        declaration : Signature
        scored : ProtocolParams
            The sifted parameter set, supplying the alphabet.
        party : str
            The verifier who scored this declaration.

        Returns
        -------
        DeclarationStatistics
        """
        counts, off = _basis_statistics(
            declaration.bases, scored, f"declaration[{party}]"
        )
        return DeclarationStatistics(
            party=party,
            length=declaration.length,
            basis_counts=counts,
            off_alphabet=off,
            positive_eigenvalues=_eigenvalue_statistic(
                declaration.eigenvalues, f"declaration[{party}].positive"
            ),
            bound=declaration.session_id is not None,
            session_id=declaration.session_id,
        )

    # -- lookups ------------------------------------------------------------ #

    @property
    def key_length(self) -> int:
        """int: ``n``, the sifted key length every null here is stated over."""
        return self.params.key_length

    @property
    def match_probability(self) -> float:
        """float: ``1/|B|``, the per-position match probability."""
        return self.params.match_probability

    def verifier(self, party: Party | str) -> VerifierStatistics:
        """Return one verifier's statistics.

        Parameters
        ----------
        party : Party or str
            Bob or Charlie.

        Returns
        -------
        VerifierStatistics

        Raises
        ------
        KeyError
            If that party reached no verdict in this run. Deliberately not a
            ``None``: "rejected", "never asked" and "asked and refused to
            score" are three different things, and only :attr:`aborts` can tell
            you which of the last two happened.
        """
        name = str(party)
        if name not in self.verifiers:
            refusal = self.aborts.by_party.get(name)
            because = (
                f" He was asked and refused to score: {refusal}."
                if refusal is not None
                else " He reached no verdict; read aborts and is_complete."
            )
            raise KeyError(
                f"{name} has no verdict statistics in this run.{because} This "
                f"is not a rejection: no decision was made, and counting it as "
                f"one would report a detection that never happened."
            )
        return self.verifiers[name]

    def link(self, party: Party | str, message_bit: int) -> LinkStatistics:
        """Return one link's check-round statistics, for one message bit.

        Parameters
        ----------
        party : Party or str
            The recipient whose link is wanted. Alice holds none: a check round
            is a statement about one link and she is at the far end of both.
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        LinkStatistics

        Raises
        ------
        KeyError
            If the run published no check log for that link and bit, which is
            every run of a parameter set with ``check_fraction = 0``.
        """
        key = (str(party), int(message_bit))
        if key not in self.links:
            raise KeyError(
                f"no check log for {key[0]} on message bit {key[1]}. A run "
                f"with check_fraction = 0 publishes none, which is the honest "
                f"representation of 'this run published no channel "
                f"statistics'; read has_check_rounds before asking."
            )
        return self.links[key]

    def record(self, party: Party | str, message_bit: int) -> RecordStatistics:
        """Return one recipient's log statistics, for one message bit.

        Parameters
        ----------
        party : Party or str
        message_bit : int

        Returns
        -------
        RecordStatistics

        Raises
        ------
        KeyError
            If the transcript carries no such record.
        """
        return self.records[(str(party), int(message_bit))]

    def summary(self) -> str:
        """Return a short account of every statistic that has a verdict behind it.

        Returns
        -------
        str
            One line per verifier, then the pooled line, then one line each for
            aborts and replay. Refusals are on their own line and are never
            folded into a verdict count.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.detect.statistics import TranscriptStatistics
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> stats = TranscriptStatistics.from_transcript(
        ...     QDSSession(
        ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
        ...     ).run(0)
        ... )
        >>> print(stats.summary().splitlines()[0])
        Bob: accepted, r_R = 0.000000 vs threshold 0.015625, |M_R| = 59 (z = -0.77)
        >>> print(stats.summary().splitlines()[-1])
        replay: 0 refusal(s), 2 spent round(s) over 1 session(s)
        """
        lines: list[str] = []
        for name in sorted(self.verifiers):
            stat = self.verifiers[name]
            rate = stat.mismatch_rate
            shown = "undefined" if rate is None else f"{rate:.6f}"
            lines.append(
                f"{name}: {'accepted' if stat.accepted else 'rejected'}, "
                f"r_R = {shown} vs threshold {stat.threshold:.6f}, "
                f"|M_R| = {stat.matched.count} "
                f"(z = {stat.matched.z_score:.2f})"
            )
        if self.pooled.pooled is not None:
            lines.append(f"pooled: {self.pooled.pooled.summary()}")
        else:
            lines.append("pooled: no pooled matched count (not a full run)")
        lines.append(
            f"aborts: {self.aborts.total} refusal(s), "
            f"{self.aborts.structural} structural, "
            f"{self.aborts.evidence} evidence"
        )
        lines.append(
            f"replay: {self.replay.total_refusals} refusal(s), "
            f"{self.replay.spent_rounds} spent round(s) over "
            f"{self.replay.distinct_sessions} session(s)"
        )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of every statistic extracted.

        The hand-off to Phase 5 and Phase 6. Mapping keys that are tuples in
        Python -- ``links`` and ``records`` -- are joined with ``"|"``, because
        JSON object keys are strings and a silently stringified tuple is how a
        downstream parser gets ``"('Bob', 0)"``.

        Returns
        -------
        dict
            Passes to :func:`json.dumps` unchanged.
        """
        return {
            "params": self.params.to_dict(),
            "nominal_key_length": self.nominal_key_length,
            "key_length": self.key_length,
            "match_probability": self.match_probability,
            "message_bit": self.message_bit,
            "verifiers": {
                name: stat.to_dict() for name, stat in self.verifiers.items()
            },
            "aborts": self.aborts.to_dict(),
            "pooled": self.pooled.to_dict(),
            "replay": self.replay.to_dict(),
            "links": {
                f"{party}|{bit}": stat.to_dict()
                for (party, bit), stat in self.links.items()
            },
            "declarations": {
                name: stat.to_dict() for name, stat in self.declarations.items()
            },
            "records": {
                f"{party}|{bit}": stat.to_dict()
                for (party, bit), stat in self.records.items()
            },
            "symmetrised": self.symmetrised,
            "counts_exchanged": self.counts_exchanged,
            "channel_monitored": self.channel_monitored,
            "signer_saw_recipient_logs": self.signer_saw_recipient_logs,
            "count_exchange_timing": self.count_exchange_timing,
            "forwarding_altered_signature": self.forwarding_altered_signature,
            "session_coherent": self.session_coherent,
            "is_complete": self.is_complete,
            "aborted": self.aborted,
            "transferable": self.transferable,
            "repudiated": self.repudiated,
            "repudiation_guarantee": self.repudiation_guarantee,
            "enforced_repudiation_bound": self.enforced_repudiation_bound,
            "run_id": self.run_id,
            "has_check_rounds": self.has_check_rounds,
            "security_claim": self.security_claim,
        }
