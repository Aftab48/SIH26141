"""Phase 4, layer two: derived thresholds for the **structural** signals.

Aborts, refusals and the shape of a run. These are not sample statistics that
need a new concentration argument: every one of them is an *event* whose
honest-run probability was already derived somewhere in the protocol, and this
module's job is to wire each one to that existing proven bound rather than to
invent a second one. Where the derivation is elsewhere, it is cited by name;
where the last step is missing, it is done here and the algebra is written out.

Convention **D7** in one sentence: a threshold comes from a stated null and an
inequality applied to it, carries a provable false-positive bound, and is never
a number that separated the attack data somebody happened to have. Every public
function here takes a false-positive budget ``eps`` and *derives* an operating
point from it, so that a Phase 5 ROC curve is a sweep over budgets rather than
a sweep over knobs. When no operating point exists inside a budget, the answer
is ``None`` and a stated reason -- never a lowered bar.

.. _structural-summary:

The four checks, their nulls and their bounds
----------------------------------------------
``n`` is the **sifted** key length (:attr:`TranscriptStatistics.key_length`),
``p = 1/|B|`` the per-position match probability, ``eps0 = 2**-64`` the
honest-abort budget the protocol's floors were calibrated to
(:data:`~sih141.protocol.verify.HONEST_ABORT_BUDGET`).

===================== ============================== ==================== =========================
check                 statistic                      honest-run null      proven false-positive
===================== ============================== ==================== =========================
structural abort      ``aborts.structural``          point mass at ``0``  **exactly 0**
replay refusal        ``replay.total_refusals``      point mass at ``0``  **exactly 0**
run shape             six equalities, below          point mass at ``0``  **exactly 0**
evidence abort        ``aborts.evidence``            union of three tails :func:`evidence_abort_bound`
===================== ============================== ==================== =========================

Three of the four cost nothing at all: their honest-run probability is zero
because the event is **outside the honest run's outcome space**, not because a
tail happens to be small. The fourth is the only one with a number, and that
number is ``1.626e-19`` at every key length where both matched-count floors
bite -- twelve orders of magnitude looser than the exact tail, which
:func:`evidence_abort_bound` will compute on request (``8.015e-31`` at
:data:`~sih141.protocol.params.DEFAULT_PARAMS`).

.. _measured:

Measured, as a check on the derivation and never as a source of one
--------------------------------------------------------------------
D7's corollary: honest data may *check* a derived threshold, attack data may not
*choose* one. Every number below was read after the thresholds were fixed, and
each is asserted in ``tests/test_detect_structural.py`` -- prose is the one
thing ``--doctest-modules`` cannot check, so nothing here is load-bearing on its
own.

.. code-block:: text

    arm                                   alarms   check that fired
    ------------------------------------  -------  ----------------------------
    honest, L = 192 / 384 / 600, each run
      scored at four budgets from 1e-3
      down to 1e-20                         0/60   -- (evidence withheld at
                                                      1e-20, and the answer is
                                                      the same either way)
    count starvation, before-forwarding    40/40   evidence-abort
    count starvation, after-forwarding     40/40   evidence-abort
    recipient forgery, before-forwarding   40/40   structural-abort
    recipient forgery, after-forwarding    40/40   structural-abort
    outside forgery (signer seam)           0/20   -- (the run is *rejected*)
    depolariser 0.60 on Bob's link          0/20   --
    intercept-resend on Bob's link          0/20   --
    impersonation, all three scopes         0/20   --

A wider honest control of ``100`` runs at ``L = 192`` also raised ``0`` alarms
and ``0`` run-shape violations. That one is **not** in the suite -- it costs
forty seconds and says nothing the sixty in it do not -- so it is recorded here
with its provenance rather than quoted as if a test guarded it.

Two of those deserve a sentence each. **Recipient forgery is caught here at a
false-positive probability of exactly zero** -- a substituted declaration makes
the two Phase C' counts describe two declarations, which is a *structural*
refusal -- and that is a second, cheaper route to an adversary Phase 3 caught on
Charlie's matched count. **The channel adversaries are silent, correctly**: the
matched set is decided by basis agreement and a channel attack corrupts
eigenvalues, so no floor moves and nothing structural can see it. A structural
alarm on a depolariser would mean this module had found a way to read a channel
through a bookkeeping statistic, which is not a thing it should be able to do.

.. _structural-null:

Derivation 1: the structural aborts, and why the bound is exactly zero
-----------------------------------------------------------------------
:data:`~sih141.detect.statistics.STRUCTURAL_ABORT_REASONS` holds the five
refusals that make no claim about how much evidence a run produced. Four are
decided by an **equality test on data the honest protocol fixes** and the fifth
by set membership on an argument the caller supplies; in none of them does
randomness enter, so there is no tail to bound:

``SESSION_MISMATCH``
    The declaration and the record are stamped with the same session identifier
    by the same :class:`~sih141.protocol.session.QDSSession`; the check compares
    two copies of one string.
``RECORD_ALREADY_VERIFIED``
    An honest run asks each verifier once per ``(session, bit)``. The ledger key
    is that pair (:class:`~sih141.protocol.verify.ConsumedRecords`) and the
    check is set membership.
``COUNT_OF_UNRECORDED_PROVENANCE``
    The shipped exchange always fills the provenance slot
    (:mod:`sih141.protocol.tally`, ``binding-is-mandatory``); an empty slot is
    unreachable from it.
``COUNTS_FROM_TWO_DECLARATIONS``
    One declaration exists on an honest run, so the two digests are two hashes
    of one object.
``UNAUTHORISED_VERIFIER``
    An honest run authorises the recipients it distributed to, and the check is
    set membership on the party the record names
    (:class:`~sih141.protocol.verify.AbortReason`). It is also off unless the
    caller passes ``authorised``, so on the shipped session it never runs at
    all. This is the one member whose zero is conditional on something outside
    the protocol: a caller who names a set omitting a recipient the signer
    distributed to refuses him on every run, honest or not, and the refusal is
    counted here as structural. The set is checked to hold parties, and an empty
    one is refused outright (:func:`~sih141.protocol.verify.verify`), which
    closes the wiring mistakes but not a set that is well-formed and wrong.

None of the five is a function of the key material, the bases, the eigenvalues
or the channel. The honest run's outcome space does not contain
``aborts.structural >= 1`` at all, so

.. code-block:: text

    P_null[ aborts.structural >= 1 ] = 0                    (exactly)

and the derived operating point is ``fire iff count >= 1`` for **every** budget
``eps`` in ``[0, 1)``: it is the smallest ``k >= 1`` whose tail is inside the
budget, and ``k = 0`` is excluded because a rule that fires on every run is not
a detector. (Markov gives the same answer with an inequality attached:
``P[X >= 1] <= E[X] = 0``. The point mass is the shorter road.)

The same argument, verbatim, covers :func:`replay_refusal_threshold` -- a
refusal to re-decide a spent round is an equality test on a ledger -- and
:func:`run_shape_threshold`, whose six equalities are listed on
:func:`run_shape_violations`.

.. _evidence-null:

Derivation 2: the evidence aborts, where the only real number is
-----------------------------------------------------------------
:data:`~sih141.detect.statistics.EVIDENCE_ABORT_REASONS` holds the four
refusals that *are* statements about how much evidence a run produced. Under
honest operation Alice draws each declared basis uniformly from ``B`` and
independently across positions, and each recipient draws his measurement basis
the same way and independently of her, so

.. code-block:: text

    m_B ~ Binomial(n, p)      m_C ~ Binomial(n, p)      M = m_B + m_C ~ Binomial(2n, p)

the last one **exactly**, by conservation under the symmetrisation coins rather
than by independence -- given the records ``m_C = M - m_B`` and the two are
perfectly negatively dependent (:ref:`sih141.protocol.verify <pooled-floor>`).
The union bound below never needs them independent.

Every one of the four reasons is implied by one of three events:

.. code-block:: text

    E_B = {m_B < m_min}     E_C = {m_C < m_min}     E_M = {M < M_min}

    EMPTY_MATCHED_SET(R)        subset of  E_R      (m_min >= 1 always)
    BELOW_FLOOR(R)              equals     E_R
    COUNTERPART_BELOW_FLOOR(R)  equals     E_(other R)
    POOLED_BELOW_FLOOR(R)       equals     E_M

so ``{evidence >= 1}`` is contained in ``E_B ∪ E_C ∪ E_M`` and

.. code-block:: text

    P[ evidence >= 1 ] <= P[E_B] + P[E_C] + P[E_M]          (union bound)

**Three terms, not two.** The layer below used to report ``2 * eps0`` for this
event, which is smaller than the union bound its own derivation supports. It
now computes the same quantity this section derives, and the two share one
implementation (:func:`~sih141.detect.statistics.floor_shortfall_bound`), so a
run cannot be handed two different bounds for one event. See :ref:`findings`.

Each term, in closed form. :func:`~sih141.protocol.verify.minimum_matched_count`
sets ``m_min = max(1, ceil((1 - d0) mu))`` with ``d0 = sqrt(2 ln(1/eps0) / mu)``
and ``mu = n p``. Two regimes, and both are exact rather than approximated:

.. code-block:: text

    (i)  floor > 1, so d0 < 1 and ceil(x) - 1 < x:
           {m < m_min}  subset of  {m <= (1 - d0) mu}
           P <= exp(-d0^2 mu / 2) = exp(-ln(1/eps0)) = eps0
                                              (multiplicative Chernoff, lower)

    (ii) floor = 1, so the event is {m = 0}:
           P = (1 - p)^n                                    (exactly; no bound)

Both are available whenever the floor is ``1`` and the Chernoff form is not
vacuous, and :func:`_floor_bound` takes the smaller -- which matters: at
``n = 267`` the floor is still ``1`` while the Chernoff form already applies, and
``(2/3)**267 = 5.4e-48`` against ``eps0 = 5.4e-20``.

So, writing ``b(trials, floor)`` for that per-check bound,

.. code-block:: text

    B_evid(n) = 2 b(n, m_min) + b(2n, M_min)      with the count exchange
              = 2 b(n, m_min)                     without it: no pooled check,
                                                  and no counterpart check

which is :func:`evidence_abort_bound`. It is **not monotone in n**, and the
non-monotonicity is the honest shape of the thing rather than a defect: the
exact ``(1 - p)^n`` term falls away as ``n`` grows until a floor starts to bite,
at which point the much looser Chernoff term ``eps0`` replaces it. The pooled
floor first exceeds ``1`` at ``n = 137`` and the per-verifier floor at
``n = 273``, so ``B_evid`` steps *up* at each of those.

.. _no-lower-budget:

Consequence: there is a budget below which this check cannot be operated
------------------------------------------------------------------------
``B_evid(n)`` tends to ``3 eps0 = 1.626e-19`` from below and stays there, so no
key length buys a tighter closed-form bound and

.. code-block:: text

    eps < 3 eps0   =>   no admissible operating point at any n

:func:`minimum_sifted_length` returns ``None`` there rather than firing anyway,
and :func:`evidence_abort_threshold` reports the check **withheld**. That is a
genuine ROC point -- the detector's true-positive rate at such a budget is zero,
by derivation -- and it is the reason ``eps`` is an argument and not a constant.
Asking for the exact tails (``exact=True``) moves the asymptote to
``8.015e-31`` and the same statement holds one budget lower down.

.. _shortfall:

Derivation 3: how far below the floor, and what that is worth
---------------------------------------------------------------
An abort naming a floor also records the distance
(:attr:`~sih141.protocol.verify.VerificationAbort.shortfall`), and the distance
has its own tail. With ``s`` the shortfall and ``c = floor - s`` the count that
produced it, ``{shortfall >= s} = {count <= c}``, so inverting the same Chernoff
lower tail at a budget ``eps`` gives the derived operating point

.. code-block:: text

    P[count <= c] <= exp(-(mu - c)^2 / (2 mu)) <= eps
      <=>  mu - c >= sqrt(2 mu ln(1/eps))
      <=>  c      <= mu - sqrt(2 mu ln(1/eps))

    c(eps) = floor( mu - sqrt(2 mu ln(1/eps)) )      s(eps) = max(1, floor - c(eps))

:func:`shortfall_threshold`. And here is what it says, which is worth more than
the threshold itself: **for every eps at or above eps0 it returns 1.** The
floors were calibrated at ``2**-64`` and therefore already spend the whole of
any practical budget, so the abort *is* the threshold and its magnitude adds no
detection power. The knob only starts to turn below ``2**-64``, where it asks
for a shortfall of ``258`` records at
:data:`~sih141.protocol.params.DEFAULT_PARAMS` and ``eps = 1e-25``. Shipped
because it is the derived answer and Phase 5 sweeps the whole range; reported as
a collapse because pretending it separates anything at a usable budget would be
the sort of claim this phase exists not to make.

.. _induced:

"Evidence was thin" against "somebody made it thin"
-----------------------------------------------------
The distinction the problem asks for **resolves, and the resolution is the
bound**. On a run whose floors bite, an honest evidence abort has probability at
most ``1.626e-19``; so an evidence abort is somebody's doing, at that
false-positive cost, and no further statistic is needed to say so. What is still
open afterwards is *whose*, and that is attribution rather than detection:
:func:`attribute_aborts` reads it off the reason and the shortfall, which is all
the transcript carries and all it needs to.

**How strong, per reason**, is :func:`abort_reason_bound`: five of the nine are
exactly zero, one is the exact ``(1 - p)^n`` of an empty matched set, and the
remaining three are the two floor tails seen from three sides. Note what may
*not* be done with them: ``COUNTERPART_BELOW_FLOOR`` at Bob and ``BELOW_FLOOR``
at Charlie are the **same event**, so the nine are not a partition and totalling
them over-counts. The run-level bound is the union over the three *events*,
which is :func:`evidence_abort_bound`; the per-reason numbers are for saying how
strong one observed refusal is.

.. code-block:: text

    reason                          whose count was short   who can force it
    ------------------------------  ----------------------  ---------------------------
    EMPTY_MATCHED_SET               the refusing verifier    a signer choosing the
    BELOW_FLOOR                     the refusing verifier      declaration from his log
    POOLED_BELOW_FLOOR              the pair, jointly        a signer aiming a low total
    COUNTERPART_BELOW_FLOOR         the *other* verifier     that other verifier
    SESSION_MISMATCH                nobody -- no count       a replayed pairing
    RECORD_ALREADY_VERIFIED         nobody -- no count       anyone who can make a
                                                              verifier spend the round
    COUNT_OF_UNRECORDED_PROVENANCE  nobody -- no count       the counterpart, by omission
    COUNTS_FROM_TWO_DECLARATIONS    nobody -- no count       the forwarding hop
    UNAUTHORISED_VERIFIER           nobody -- no count       nobody: the caller names
                                                              the authorised set

That table is a reading of the protocol's own control flow -- which check sits
where, and which party supplies its input -- not a summary of measurements, and
nothing in this module was chosen from it.

**Induced at will, and deterministically.** Two of the nine cost their
adversary no probability whatever. A recipient denies his counterpart by
declaring any count below the headroom
(:ref:`sih141.attacks.starvation <starvation-headroom>`), which forces
``COUNTERPART_BELOW_FLOOR`` with probability one; and a forwarding hop that
substitutes a declaration forces ``COUNTS_FROM_TWO_DECLARATIONS`` with
probability one under either count ordering. Both are measured in
``tests/test_detect_structural.py`` at ``L = 384``: ``40/40`` for the starver,
and ``40/40`` again under *each* count ordering for the forwarding hop -- which
refuses at Charlie under
:data:`~sih141.protocol.session.COUNTS_BEFORE_FORWARDING` and at Bob under
:data:`~sih141.protocol.session.COUNTS_AFTER_FORWARDING`, so the two are
reported as two groups and never averaged. **A denial of service is not a
forgery**, and this module's whole answer to either is an alarm plus a
:class:`RunOutcome` of :attr:`~RunOutcome.REFUSED` -- never a rejection.

.. _no-verdict:

The no-verdict outcome, and why the API fights back
-----------------------------------------------------
Phase 3's constraint, and the single most likely way for a Phase 5 table to be
wrong: **a refusal is not a rejection.** Documenting that is not enough, so the
types here are built to make the wrong thing fail rather than merely be
discouraged.

* :class:`RunOutcome` has four members and **no truth value**: ``bool(outcome)``
  raises :exc:`TypeError`. ``if outcome:`` and ``if not accepted:`` are the two
  shapes that silently turn a refusal into a rejection, and both now stop.
* :class:`NoVerdictCount` is an :class:`int` that **refuses to be added to
  anything but another** :class:`NoVerdictCount`. ``tally.rejected +
  tally.refused`` raises, and so does :func:`sum` over a mixed list, because
  :func:`sum` starts at ``0``. Totalling refusals on purpose is
  :meth:`NoVerdictCount.total`, which is four keystrokes and a decision.
* :class:`OutcomeTally` carries no summed field at all, and its
  :meth:`~OutcomeTally.merge` refuses two tallies whose
  ``count_exchange_timing`` differs -- Phase 3's other pooling rule, enforced
  the same way.

.. _findings:

Findings, reported rather than worked around
----------------------------------------------
1. **The layer below understated a proven bound. FIXED in the Phase 4
   reconciliation; kept here because the shape of the mistake is worth
   remembering.** :attr:`sih141.detect.statistics.AbortStatistics.honest_bound`
   was ``2 * HONEST_ABORT_BUDGET``, described as the run-level bound on
   ``evidence > 0``. The run-level union is over **three** events -- both
   per-verifier floors and the pooled floor -- and
   :mod:`sih141.protocol.verify` derives ``3 eps`` for exactly that reason, with
   ``tests/test_protocol_reconciliation.py`` asserting ``<= 3 * eps``. ``2 eps``
   was smaller than the union bound its own derivation supports, so it was not
   proven -- and being a *constant* it was also wrong at the short end, where
   the truth is ``1.19e-04`` at ``n = 24``. The repair was not ``2.0 -> 3.0``
   but the function of ``n`` this section derives. This module computes
   :func:`evidence_abort_bound` itself and never
   reads that field; ``test_detect_structural.py`` now pins the **agreement**,
   and ``test_detect_reconciliation.py`` pins that the two are one
   implementation.
2. **The same field was a constant where the truth is a function of ``n``**
   -- the other half of finding 1, and the half that decided the repair. At
   ``n = 96`` both floors are ``1``, the only reachable evidence reason is an
   empty matched set, and the honest probability is ``2.49e-17`` -- *above*
   ``2 * eps0``, so the constant was optimistic there too. At ``n = 24`` it is
   ``1.19e-04``. A detector that fires on an abort at a demonstration key length
   is not making a ``2**-64`` claim, and :func:`evidence_abort_threshold`
   withholds itself rather than letting one be made.
3. **The transcript cannot tell "no ledger" from "an empty ledger".**
   :meth:`~sih141.protocol.session.SessionTranscript.from_dict` defaults
   ``spent_rounds`` to ``()``, so a file written before the replay ledger
   existed is byte-indistinguishable from one whose verifiers reached verdicts
   without spending a round. :func:`run_shape_violations` therefore reports the
   spent-round conservation check as a statement about the **file**, and
   :func:`structural_report` never counts a run-shape alarm as a detection of
   any adversary in the threat model. Measured: it fires on none of the five
   adversary families, the replay arm -- the only one that touches a ledger at
   all -- included, because a refusal spends nothing.
4. **No replay rate exists, and a replay can leave no abort.** Refusals are
   counted but attempts are not (:ref:`sih141.detect.statistics <findings>`,
   finding 6), and the ledger denial-of-service route burns a round through a
   *rejection*, which is a verdict -- so ``replay.total_refusals == 0`` is not
   evidence that no replay was attempted. The check is sound in one direction
   only, and says so.

Notes
-----
Determinism (D3)
    Nothing here draws randomness; it has no ``rng`` argument because it has
    nothing to draw for.
No machine learning (D4)
    Two closed forms, one union bound and a table of equality tests. There is no
    fitted quantity in this file and nowhere to put one: every threshold is a
    function of ``(eps, n, |B|)`` alone, and none of them has seen an attack.
Assumption (NO-TIMING)
    **Not required by anything here.** Every statistic this module reads is a
    property of the key or of the run's own bookkeeping, never of the check-round
    sample, so nothing in this family is conditioned on the adversary being
    unable to infer the check set. That is worth stating because the check-round
    statistics of :class:`~sih141.detect.statistics.LinkStatistics` are.

Examples
--------
An honest run trips nothing, at any budget:

>>> import numpy as np
>>> from sih141.detect.statistics import TranscriptStatistics
>>> from sih141.detect.thresholds_structural import structural_report
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> stats = TranscriptStatistics.from_transcript(
...     QDSSession(
...         ProtocolParams(key_length=384), rng=np.random.default_rng(7)
...     ).run(0)
... )
>>> report = structural_report(stats, eps=1e-9)
>>> report.alarm_raised, len(report.alarms)
(False, 0)

and the price of watching for one is stated as a number, not as an observation:

>>> f"{report.false_positive_bound:.4e}"
'1.6263e-19'
>>> report.outcomes["Bob"], report.outcomes["Charlie"]
(<RunOutcome.ACCEPTED: 'accepted'>, <RunOutcome.ACCEPTED: 'accepted'>)

The three point-mass checks cost nothing at all, and say so:

>>> for threshold in report.thresholds:
...     print(f"{threshold.check:20s} {threshold.false_positive_bound:.4e}")
structural-abort     0.0000e+00
evidence-abort       1.6263e-19
replay-refusal       0.0000e+00
run-shape            0.0000e+00
"""

from __future__ import annotations

import enum
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from sih141.detect.statistics import (
    EVIDENCE_ABORT_REASONS,
    STRUCTURAL_ABORT_REASONS,
    TranscriptStatistics,
    chernoff_deviation_bound,
    floor_shortfall_bound,
)
from sih141.protocol.analysis import matched_shortfall_probability
from sih141.protocol.params import DEFAULT_BASES, Party, ProtocolParams
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    AbortReason,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

__all__ = [
    "FLOOR_BUDGET",
    "STRUCTURAL_CHECKS",
    "AbortAttribution",
    "NoVerdictCount",
    "OutcomeTally",
    "RunOutcome",
    "StructuralAlarm",
    "StructuralCheck",
    "StructuralReport",
    "StructuralThreshold",
    "abort_reason_bound",
    "attribute_aborts",
    "chernoff_lower_tail_count",
    "evidence_abort_bound",
    "evidence_abort_threshold",
    "minimum_sifted_length",
    "outcome_of",
    "outcomes",
    "point_mass_threshold",
    "replay_refusal_threshold",
    "run_shape_threshold",
    "run_shape_violations",
    "shortfall_threshold",
    "structural_abort_threshold",
    "structural_report",
    "tally_outcomes",
]


#: The budget the protocol's two matched-count floors were derived at,
#: ``2**-64``. Re-exported under a name that says what it *is* rather than what
#: it bounds, because this module's own ``eps`` arguments are different numbers
#: with the same units and confusing the two would be easy.
FLOOR_BUDGET: Final[float] = HONEST_ABORT_BUDGET

#: ``ln(1/eps0)``, the constant every floor derivation in the protocol is
#: written in terms of. ``44.3614...``.
_LOG_FLOOR_BUDGET: Final[float] = -math.log(HONEST_ABORT_BUDGET)

#: Largest sifted length :func:`minimum_sifted_length` searches before falling
#: back on the asymptote. Both floors are non-degenerate well below it -- the
#: per-verifier one from ``273`` -- so ``B_evid`` is constant above it and the
#: search is exhaustive rather than truncated. See :ref:`evidence-null`.
_SEARCH_CEILING: Final[int] = 400


class StructuralCheck(enum.StrEnum):
    """Which structural check a threshold, alarm or withholding is about.

    A :class:`enum.StrEnum` so it passes through :func:`json.dumps` into a Phase
    5 table unchanged, like
    :class:`~sih141.protocol.verify.AbortReason` beside it.

    Attributes
    ----------
    STRUCTURAL_ABORT
        A refusal whose reason is in
        :data:`~sih141.detect.statistics.STRUCTURAL_ABORT_REASONS`. Point-mass
        null, false-positive probability exactly zero (:ref:`structural-null`).
        Four of the five reasons are equality tests on data the honest protocol
        fixes; the fifth is unreachable unless a caller names an authorised
        recipient set, and its zero holds only for a set containing the
        recipients the signer distributed to.
    EVIDENCE_ABORT
        A refusal whose reason is in
        :data:`~sih141.detect.statistics.EVIDENCE_ABORT_REASONS`. The only check
        in the family with a number attached (:ref:`evidence-null`).
    REPLAY_REFUSAL
        A verifier asked to decide a round he had already decided. Point-mass
        null; sound in one direction only, see :ref:`finding 4 <findings>`.
    RUN_SHAPE
        One of the six equalities on :func:`run_shape_violations`. Point-mass
        null; a statement about the transcript file rather than about any
        adversary in the threat model, see :ref:`finding 3 <findings>`.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import StructuralCheck
    >>> StructuralCheck.EVIDENCE_ABORT
    <StructuralCheck.EVIDENCE_ABORT: 'evidence-abort'>
    >>> f"{StructuralCheck.RUN_SHAPE}"
    'run-shape'
    """

    STRUCTURAL_ABORT = "structural-abort"
    EVIDENCE_ABORT = "evidence-abort"
    REPLAY_REFUSAL = "replay-refusal"
    RUN_SHAPE = "run-shape"


#: The family, in the order :func:`structural_report` applies it. Written out
#: rather than derived from the enum so that adding a member upstream without
#: deciding where it belongs fails a test instead of silently disappearing from
#: every report.
STRUCTURAL_CHECKS: Final[tuple[StructuralCheck, ...]] = (
    StructuralCheck.STRUCTURAL_ABORT,
    StructuralCheck.EVIDENCE_ABORT,
    StructuralCheck.REPLAY_REFUSAL,
    StructuralCheck.RUN_SHAPE,
)


# --------------------------------------------------------------------------- #
# Refusals are not verdicts, enforced by type
# --------------------------------------------------------------------------- #


class RunOutcome(enum.StrEnum):
    """What one party did, with **no truth value** so it cannot be misread.

    Four outcomes, and the third and fourth are the ones this class exists for.
    "Accepted", "rejected", "asked and refused to score" and "never asked" are
    four different things; a :class:`bool` can hold two of them, which is how a
    refusal becomes a rejection in a table.

    ``bool(outcome)`` raises :exc:`TypeError`. That is deliberate and it is the
    whole point: ``if outcome:`` and ``if not verdict:`` are the two shapes that
    silently fold a no-verdict into a rejection, and both now stop with a
    message rather than producing a plausible wrong answer. Everything else a
    :class:`enum.StrEnum` does still works -- equality, ordering, dict keys,
    formatting and :func:`json.dumps`.

    Attributes
    ----------
    ACCEPTED
        The party reached a verdict and it was an acceptance.
    REJECTED
        The party reached a verdict and it was a rejection. **The only member
        that may be counted as a detection of a bad signature.**
    REFUSED
        The party was asked and returned no verdict, recording a
        :class:`~sih141.protocol.verify.VerificationAbort`. Not a rejection: he
        learned nothing about the signature.
    NOT_ASKED
        The party appears in neither the verdicts nor the refusals. A run that
        ended before he was asked, which is again not a rejection.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import RunOutcome
    >>> RunOutcome.REFUSED == "refused-to-score"
    True
    >>> sorted(RunOutcome)[0]
    <RunOutcome.ACCEPTED: 'accepted'>

    The guard, which is the reason the class is not a pair of booleans:

    >>> if RunOutcome.REFUSED:
    ...     print("counted as a rejection")
    Traceback (most recent call last):
        ...
    TypeError: RunOutcome has no truth value: 'refused-to-score' is neither an
    acceptance nor a rejection, and a no-verdict counted as one reports a
    detection that never happened. Compare against the member you mean, e.g.
    `outcome is RunOutcome.REJECTED`.
    """

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    REFUSED = "refused-to-score"
    NOT_ASKED = "not-asked"

    def __bool__(self) -> bool:
        """Refuse to have a truth value.

        Returns
        -------
        bool
            Never returns.

        Raises
        ------
        TypeError
            Always.
        """
        raise TypeError(
            f"RunOutcome has no truth value: {self.value!r} is neither an\n"
            f"acceptance nor a rejection, and a no-verdict counted as one "
            f"reports a\ndetection that never happened. Compare against the "
            f"member you mean, e.g.\n`outcome is RunOutcome.REJECTED`."
        )


#: The two members that mean "this party reached no verdict". A frozenset so a
#: caller can ask the question without spelling out a disjunction that is easy
#: to get one member wrong in.
_NO_VERDICT_OUTCOMES: Final[frozenset[RunOutcome]] = frozenset(
    {RunOutcome.REFUSED, RunOutcome.NOT_ASKED}
)


class NoVerdictCount(int):
    """A count of no-verdicts that refuses to be added to anything else.

    An :class:`int` in every respect that matters -- it compares, formats,
    indexes and serialises as the number it is -- with one behaviour removed:
    ``+`` accepts only another :class:`NoVerdictCount`. Adding a refusal count
    to a rejection count is the arithmetic form of the mistake
    :class:`RunOutcome` guards the boolean form of, and :func:`sum` walks into
    it by construction because it starts from ``0``.

    Totalling refusals *on purpose* is :meth:`total`, which cannot be reached by
    accident.

    Parameters
    ----------
    value : int
        The count.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import NoVerdictCount
    >>> refusals = NoVerdictCount(2)
    >>> refusals, refusals == 2, int(refusals) + 1
    (2, True, 3)
    >>> refusals + NoVerdictCount(3)
    5

    The two shapes it stops:

    >>> refusals + 1
    Traceback (most recent call last):
        ...
    TypeError: a no-verdict count may only be added to another no-verdict
    count. A refusal is not a rejection, and summing the two reports a
    detection that never happened -- use NoVerdictCount.total(...) for a
    deliberate total of refusals, or int(...) if you really mean plain
    arithmetic.
    >>> sum([NoVerdictCount(1), NoVerdictCount(1)])
    Traceback (most recent call last):
        ...
    TypeError: a no-verdict count may only be added to another no-verdict
    count. A refusal is not a rejection, and summing the two reports a
    detection that never happened -- use NoVerdictCount.total(...) for a
    deliberate total of refusals, or int(...) if you really mean plain
    arithmetic.
    >>> NoVerdictCount.total([NoVerdictCount(1), NoVerdictCount(1)])
    2
    """

    __slots__ = ()

    def __add__(self, other: Any) -> NoVerdictCount:
        """Add another :class:`NoVerdictCount`, and nothing else.

        Parameters
        ----------
        other : NoVerdictCount
            The other count.

        Returns
        -------
        NoVerdictCount

        Raises
        ------
        TypeError
            If ``other`` is not a :class:`NoVerdictCount`.
        """
        if isinstance(other, NoVerdictCount):
            return NoVerdictCount(int(self) + int(other))
        raise TypeError(
            "a no-verdict count may only be added to another no-verdict\n"
            "count. A refusal is not a rejection, and summing the two reports "
            "a\ndetection that never happened -- use NoVerdictCount.total(...) "
            "for a\ndeliberate total of refusals, or int(...) if you really "
            "mean plain\narithmetic."
        )

    __radd__ = __add__

    @classmethod
    def total(cls, counts: Iterable[NoVerdictCount]) -> NoVerdictCount:
        """Return the deliberate total of several no-verdict counts.

        Parameters
        ----------
        counts : iterable of NoVerdictCount
            The counts to total.

        Returns
        -------
        NoVerdictCount

        Raises
        ------
        TypeError
            If any element is not a :class:`NoVerdictCount`.
        """
        running = cls(0)
        for count in counts:
            running = running + count
        return running


def outcome_of(stats: TranscriptStatistics, party: Party | str) -> RunOutcome:
    """Return what one party did, as an outcome that cannot be read as a bool.

    The safe replacement for ``stats.verifier(party).accepted``, which raises
    :exc:`KeyError` for a party who reached no verdict -- correct, and awkward
    at a call site that wants an answer for every party. This returns the answer
    for every party and makes the two no-verdict cases distinguishable and
    unmistakable for a rejection.

    Parameters
    ----------
    stats : TranscriptStatistics
        The run.
    party : Party or str
        Bob or Charlie. Alice reaches no verdict at all and is refused, in line
        with :class:`~sih141.protocol.verify.VerificationAbort`.

    Returns
    -------
    RunOutcome

    Raises
    ------
    TypeError
        If ``stats`` is not a
        :class:`~sih141.detect.statistics.TranscriptStatistics`.
    ValueError
        If ``party`` is Alice or names no party.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_structural import outcome_of
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=384), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> outcome_of(stats, "Bob")
    <RunOutcome.ACCEPTED: 'accepted'>
    >>> outcome_of(stats, "Alice")
    Traceback (most recent call last):
        ...
    ValueError: Alice reaches no verdict: she signs, holds no record and has no
    acceptance threshold. Ask about Party.BOB or Party.CHARLIE.
    """
    resolved = _as_verifier(party)
    if not isinstance(stats, TranscriptStatistics):
        raise TypeError(
            f"stats must be a TranscriptStatistics, got "
            f"{type(stats).__name__}. Build one with "
            f"TranscriptStatistics.from_transcript(transcript); the round trip "
            f"through JSON is what makes a detection rate mean something."
        )
    if resolved in stats.verifiers:
        verdict = stats.verifiers[resolved]
        return RunOutcome.ACCEPTED if verdict.accepted else RunOutcome.REJECTED
    if resolved in stats.aborts.by_party:
        return RunOutcome.REFUSED
    return RunOutcome.NOT_ASKED


def outcomes(stats: TranscriptStatistics) -> dict[str, RunOutcome]:
    """Return both verifiers' outcomes, keyed by party name.

    Parameters
    ----------
    stats : TranscriptStatistics
        The run.

    Returns
    -------
    dict of str to RunOutcome
        Always exactly two entries, ``"Bob"`` and ``"Charlie"``, because a party
        who was never asked has an outcome too and leaving him out is how he
        gets counted as something else later.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_structural import outcomes
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=384), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> sorted(outcomes(stats).items())
    [('Bob', <RunOutcome.ACCEPTED: 'accepted'>), ('Charlie', <RunOutcome.ACCEPTED: 'accepted'>)]
    """
    return {
        party.value: outcome_of(stats, party)
        for party in (Party.BOB, Party.CHARLIE)
    }


@dataclass(frozen=True)
class OutcomeTally:
    """Verdicts and no-verdicts counted apart, with no field that sums them.

    The aggregation type Phase 5 needs, built so that the two mistakes Phase 3
    named cannot be made quietly:

    * there is **no** ``not_accepted``, ``failures`` or ``rejected_or_aborted``
      field, and the two no-verdict counts are :class:`NoVerdictCount`, so
      writing the sum by hand raises rather than returning a number; and
    * the tally carries the ``count_exchange_timing`` it was built under and
      :meth:`merge` refuses two tallies that disagree, because the two orderings
      give different answers to the same attack and a table mixing them averages
      a forgery rate with a denial-of-service rate.

    Attributes
    ----------
    accepted : int
        Verdicts that were acceptances.
    rejected : int
        Verdicts that were rejections. The only field a "detected" column may be
        drawn from.
    refused : NoVerdictCount
        Parties asked who returned no verdict.
    not_asked : NoVerdictCount
        Parties never asked.
    count_exchange_timing : str
        The ordering every run in this tally was produced under.
    runs : int
        How many runs were folded in. ``1`` from :func:`tally_outcomes`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_structural import tally_outcomes
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=384), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> tally = tally_outcomes(stats)
    >>> tally.accepted, tally.rejected, tally.refused, tally.not_asked
    (2, 0, 0, 0)
    >>> tally.merge(tally).accepted
    4

    And the guard, which is the reason the counts are not four plain ints:

    >>> tally.rejected + tally.refused
    Traceback (most recent call last):
        ...
    TypeError: a no-verdict count may only be added to another no-verdict
    count. A refusal is not a rejection, and summing the two reports a
    detection that never happened -- use NoVerdictCount.total(...) for a
    deliberate total of refusals, or int(...) if you really mean plain
    arithmetic.
    """

    accepted: int
    rejected: int
    refused: NoVerdictCount
    not_asked: NoVerdictCount
    count_exchange_timing: str
    runs: int = 1

    def __post_init__(self) -> None:
        """Coerce the two no-verdict counts and refuse a negative tally.

        Raises
        ------
        TypeError
            If a count is not an integer or the timing is not a string.
        ValueError
            If a count is negative.
        """
        for name in ("accepted", "rejected", "refused", "not_asked", "runs"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(
                    f"{name} must be an int, got {type(value).__name__}"
                )
            if value < 0:
                raise ValueError(f"{name} must be non-negative, got {value}")
        if not isinstance(self.count_exchange_timing, str):
            raise TypeError(
                f"count_exchange_timing must be a string, got "
                f"{type(self.count_exchange_timing).__name__}. It is the "
                f"grouping key, and a tally that does not know its own group "
                f"can be merged with the wrong one."
            )
        object.__setattr__(self, "refused", NoVerdictCount(self.refused))
        object.__setattr__(self, "not_asked", NoVerdictCount(self.not_asked))

    @property
    def verdicts(self) -> int:
        """int: Acceptances plus rejections. Never includes a no-verdict."""
        return self.accepted + self.rejected

    @property
    def no_verdicts(self) -> NoVerdictCount:
        """NoVerdictCount: Refusals plus never-askeds, kept off the verdicts."""
        return self.refused + self.not_asked

    def merge(self, other: OutcomeTally) -> OutcomeTally:
        """Return the tally of both, refusing to pool two count orderings.

        Parameters
        ----------
        other : OutcomeTally
            The tally to fold in.

        Returns
        -------
        OutcomeTally

        Raises
        ------
        TypeError
            If ``other`` is not an :class:`OutcomeTally`.
        ValueError
            If the two were produced under different ``count_exchange_timing``
            values. The two orderings answer the same attack differently, so a
            merged tally would average a forgery rate with a denial-of-service
            rate -- group by the timing and report the groups.

        Examples
        --------
        >>> from sih141.detect.thresholds_structural import (
        ...     NoVerdictCount, OutcomeTally
        ... )
        >>> zero = NoVerdictCount(0)
        >>> before = OutcomeTally(2, 0, zero, zero, "before-forwarding")
        >>> after = OutcomeTally(0, 2, zero, zero, "after-forwarding")
        >>> before.merge(after)
        Traceback (most recent call last):
            ...
        ValueError: refusing to merge tallies from two count orderings:
        'before-forwarding' and 'after-forwarding'. The two give different
        answers to the same attack, so a merged tally would average a forgery
        rate with a denial-of-service rate. Group by count_exchange_timing and
        report the groups.
        """
        if not isinstance(other, OutcomeTally):
            raise TypeError(
                f"other must be an OutcomeTally, got {type(other).__name__}"
            )
        if self.count_exchange_timing != other.count_exchange_timing:
            raise ValueError(
                f"refusing to merge tallies from two count orderings:\n"
                f"{self.count_exchange_timing!r} and "
                f"{other.count_exchange_timing!r}. The two give different\n"
                f"answers to the same attack, so a merged tally would average "
                f"a forgery\nrate with a denial-of-service rate. Group by "
                f"count_exchange_timing and\nreport the groups."
            )
        return OutcomeTally(
            accepted=self.accepted + other.accepted,
            rejected=self.rejected + other.rejected,
            refused=self.refused + other.refused,
            not_asked=self.not_asked + other.not_asked,
            count_exchange_timing=self.count_exchange_timing,
            runs=self.runs + other.runs,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
            The four counts stay four counts; nothing here sums two of them.
        """
        return {
            "accepted": self.accepted,
            "rejected": self.rejected,
            "refused": int(self.refused),
            "not_asked": int(self.not_asked),
            "count_exchange_timing": self.count_exchange_timing,
            "runs": self.runs,
        }


def tally_outcomes(stats: TranscriptStatistics) -> OutcomeTally:
    """Tally one run's two outcomes, keeping refusals off the verdicts.

    Parameters
    ----------
    stats : TranscriptStatistics
        The run.

    Returns
    -------
    OutcomeTally
        With ``runs == 1`` and the run's own ``count_exchange_timing``, so that
        merging two tallies across orderings raises instead of averaging.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_structural import tally_outcomes
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=384), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> tally_outcomes(stats).to_dict()["count_exchange_timing"]
    'before-forwarding'
    """
    seen = outcomes(stats)
    counts = {outcome: 0 for outcome in RunOutcome}
    for outcome in seen.values():
        counts[outcome] += 1
    return OutcomeTally(
        accepted=counts[RunOutcome.ACCEPTED],
        rejected=counts[RunOutcome.REJECTED],
        refused=NoVerdictCount(counts[RunOutcome.REFUSED]),
        not_asked=NoVerdictCount(counts[RunOutcome.NOT_ASKED]),
        count_exchange_timing=stats.count_exchange_timing,
        runs=1,
    )


# --------------------------------------------------------------------------- #
# The arithmetic: one inversion, one union bound
# --------------------------------------------------------------------------- #


def _as_budget(value: Any, name: str = "eps") -> float:
    """Coerce a false-positive budget in ``(0, 1)``.

    Parameters
    ----------
    value : float
        The candidate.
    name : str, optional
        Argument name quoted in the error message.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not a real number.
    ValueError
        If ``value`` is not finite or is outside ``(0, 1)``. Zero is refused
        rather than clamped: no threshold in this module can achieve a
        false-positive probability of zero *by choice of budget*, and the three
        that achieve it do so from their null and would be unaffected. One is
        refused because a rule that fires on every run is not a detector.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be a real number, got {type(value).__name__}. It is "
            f"a false-positive budget, not a count."
        )
    budget = float(value)
    if not math.isfinite(budget) or not 0.0 < budget < 1.0:
        raise ValueError(
            f"{name} must be a finite budget strictly inside (0, 1), got "
            f"{budget!r}. Sweep it to build a ROC curve; each value is an "
            f"operating point that has to be derivable, and 0 and 1 are not."
        )
    return budget


def _as_verifier(party: Party | str) -> str:
    """Coerce a verifier's name, refusing Alice.

    Parameters
    ----------
    party : Party or str
        Bob or Charlie.

    Returns
    -------
    str
        ``"Bob"`` or ``"Charlie"``.

    Raises
    ------
    ValueError
        If ``party`` is Alice or names no party.
    """
    name = str(party)
    if name == Party.ALICE.value:
        raise ValueError(
            "Alice reaches no verdict: she signs, holds no record and has no\n"
            "acceptance threshold. Ask about Party.BOB or Party.CHARLIE."
        )
    if name not in (Party.BOB.value, Party.CHARLIE.value):
        raise ValueError(
            f"{name!r} names no party in this protocol; expected "
            f"{Party.BOB.value!r} or {Party.CHARLIE.value!r}."
        )
    return name


def _counterpart(party: str) -> str:
    """Return the other verifier's name.

    Parameters
    ----------
    party : str
        ``"Bob"`` or ``"Charlie"``.

    Returns
    -------
    str
    """
    return (
        Party.CHARLIE.value if party == Party.BOB.value else Party.BOB.value
    )


def chernoff_lower_tail_count(
    trials: int, probability: float, eps: float
) -> int | None:
    """Return the largest count whose lower tail is inside a budget.

    The inversion the whole family's non-degenerate arithmetic rests on. For
    ``S ~ Binomial(trials, probability)`` with mean ``mu``, the multiplicative
    Chernoff lower tail says ``P[S <= (1 - d) mu] <= exp(-d^2 mu / 2)`` for
    ``0 < d <= 1``; writing the threshold as ``c = (1 - d) mu`` and asking for
    the bound to be at most ``eps``,

    .. code-block:: text

        exp(-(mu - c)^2 / (2 mu)) <= eps
          <=>  (mu - c)^2 >= 2 mu ln(1/eps)
          <=>  c <= mu - sqrt(2 mu ln(1/eps))

        c(eps) = floor( mu - sqrt(2 mu ln(1/eps)) )

    so ``P[S <= c(eps)] <= eps``, provably, by that inequality alone. This is
    the same algebra :func:`~sih141.protocol.verify.minimum_matched_count` runs
    at ``eps = 2**-64``, with a floor rather than a ceiling because the protocol
    wants ``P[S < m_min]`` and this wants ``P[S <= c]``.

    Parameters
    ----------
    trials : int
        Trials, at least ``0``.
    probability : float
        The null's success probability, in ``[0, 1]``.
    eps : float
        The false-positive budget, in ``(0, 1)``.

    Returns
    -------
    int or None
        The largest admissible count, or ``None`` when the Chernoff form is
        vacuous at this budget -- ``c(eps) < 0``, i.e.
        ``mu < 2 ln(1/eps)`` -- which is the honest answer that this sample is
        too small to spend that budget on. It is **not** ``0``: firing on
        ``S <= 0`` at such a sample size has a false-positive probability of
        ``(1 - p)^trials``, which is not inside ``eps``, and returning ``0``
        would smuggle that claim in.

    Raises
    ------
    TypeError
        If ``trials`` is not an integer or a probability is not a real number.
    ValueError
        If ``trials`` is negative, ``probability`` is outside ``[0, 1]``, or
        ``eps`` is outside ``(0, 1)``.

    See Also
    --------
    sih141.detect.statistics.chernoff_deviation_bound : The forward direction.
    shortfall_threshold : The one caller that inverts a *floor* with it.

    Examples
    --------
    At :data:`~sih141.protocol.params.DEFAULT_PARAMS`' per-verifier count,
    ``mu = 38400``:

    >>> from sih141.detect.thresholds_structural import (
    ...     chernoff_lower_tail_count
    ... )
    >>> chernoff_lower_tail_count(115200, 1 / 3, 2.0**-64)
    36554
    >>> chernoff_lower_tail_count(115200, 1 / 3, 1e-9)
    37138

    and the floor the protocol derives from the same budget sits one above the
    first of those, as it must:

    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> from sih141.protocol.verify import minimum_matched_count
    >>> minimum_matched_count(DEFAULT_PARAMS)
    36555

    Vacuous rather than zero, on a sample too small for the budget:

    >>> chernoff_lower_tail_count(24, 1 / 3, 1e-9) is None
    True
    """
    total = _as_count(trials, "trials")
    p = _as_unit(probability, "probability")
    budget = _as_budget(eps)
    mean = total * p
    if mean <= 0.0:
        return None
    spread = math.sqrt(2.0 * mean * -math.log(budget))
    if spread > mean:
        return None
    return int(math.floor(mean - spread))


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
            f"{name} must be an int, got {type(value).__name__}"
        )
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _as_unit(value: Any, name: str) -> float:
    """Coerce a probability in ``[0, 1]``, refusing booleans.

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
            f"{probability!r}"
        )
    return probability


def _as_params(value: Any) -> ProtocolParams:
    """Coerce a parameter set.

    Parameters
    ----------
    value : ProtocolParams
        The candidate. Must already be the **sifted** set: every null in this
        module is stated over ``n``, the positions that carried key.

    Returns
    -------
    ProtocolParams

    Raises
    ------
    TypeError
        If ``value`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.
    """
    if not isinstance(value, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(value).__name__}. "
            f"Pass the sifted set -- TranscriptStatistics.params already is "
            f"one -- because every null here is stated over the positions that "
            f"carried key, not over the nominal L."
        )
    return value


def _floor_bound(
    trials: int,
    probability: float,
    floor: int,
    bases: tuple[Any, ...],
    *,
    exact: bool,
) -> float:
    """Bound the honest probability of falling under one matched-count floor.

    The per-check term of :func:`evidence_abort_bound`, in the two regimes
    :ref:`evidence-null` sets out.

    Parameters
    ----------
    trials : int
        ``n`` for a per-verifier floor, ``2n`` for the pooled one.
    probability : float
        ``p = 1/|B|``.
    floor : int
        The floor as the protocol derives it.
    bases : tuple
        The alphabet, carried so the exact branch states the same null the
        closed-form one does rather than the shipped three-basis default.
    exact : bool
        Keyword-only at every public call site. ``True`` sums the binomial lower
        tail exactly rather than bounding it -- tighter by orders of magnitude,
        and ``O(floor)`` rather than ``O(1)``.

    Returns
    -------
    float
        A probability in ``[0, 1]``.
    """
    if exact:
        return matched_shortfall_probability(
            ProtocolParams(key_length=trials, bases=bases),
            minimum_matched=max(1, floor),
        )
    # The inequality path is NOT reimplemented here. It lives one layer down,
    # in sih141.detect.statistics.floor_shortfall_bound, and both this family
    # and AbortStatistics.honest_bound call it -- so a run cannot be handed two
    # different bounds for one event by two modules that were written apart.
    # Consolidated in the Phase 4 reconciliation; the two regimes and why the
    # third answer is 1.0 rather than eps0 are documented there.
    return floor_shortfall_bound(trials, probability, floor)


def evidence_abort_bound(
    params: ProtocolParams, *, counts_exchanged: bool = True, exact: bool = False
) -> float:
    """Bound the honest-run probability that any evidence abort occurs.

    The one number in this family, derived in :ref:`evidence-null`: a union
    bound over the three floor events, each term either an exact point-mass
    probability or the Chernoff lower tail the floor was calibrated to.

    .. code-block:: text

        B_evid(n) = 2 b(n, m_min) + b(2n, M_min)     with the count exchange
                  = 2 b(n, m_min)                    without it

    Parameters
    ----------
    params : ProtocolParams
        The **sifted** parameter set -- ``params.key_length`` is ``n``. Pass
        :attr:`~sih141.detect.statistics.TranscriptStatistics.params`, which
        already is one.
    counts_exchanged : bool, optional
        Keyword-only. ``False`` on the pre-pooled variant, where Phase C' did
        not run: there is then no pooled check and no counterpart check, so the
        union is over two events rather than three.
    exact : bool, optional
        Keyword-only. ``True`` sums the binomial lower tails exactly
        (:func:`~sih141.protocol.analysis.matched_shortfall_probability`)
        instead of bounding them. Twelve orders of magnitude tighter at
        :data:`~sih141.protocol.params.DEFAULT_PARAMS` and about forty
        milliseconds slower; both answers are proven, and a report should say
        which it quoted.

    Returns
    -------
    float
        A probability in ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams` or a flag is not a
        :class:`bool`.

    Notes
    -----
    **Three terms, not two.** The union is over both per-verifier floors *and*
    the pooled floor, and :mod:`sih141.protocol.verify` derives ``3 eps`` for
    exactly that reason.
    :attr:`sih141.detect.statistics.AbortStatistics.honest_bound` reported
    ``2 * eps0`` for the same event until the Phase 4 reconciliation; the two
    now agree by construction. See :ref:`finding 1 <findings>`.

    The value is **not monotone in ``n``**, because an exact term is replaced by
    a much looser Chernoff term each time a floor starts to bite. It steps up at
    ``n = 137`` (the pooled floor) and again at ``n = 273`` (the per-verifier
    floor), and is constant above that.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import evidence_abort_bound
    >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
    >>> f"{evidence_abort_bound(DEFAULT_PARAMS):.4e}"
    '1.6263e-19'
    >>> f"{evidence_abort_bound(DEFAULT_PARAMS, exact=True):.4e}"
    '8.0154e-31'

    Without the count exchange the union is over two events, and the run has no
    unconditional non-repudiation guarantee either:

    >>> f"{evidence_abort_bound(DEFAULT_PARAMS, counts_exchanged=False):.4e}"
    '1.0842e-19'

    The two steps, and the regime below them where an abort is not rare at all:

    >>> for length in (24, 96, 136, 137, 272, 273):
    ...     bound = evidence_abort_bound(ProtocolParams(key_length=length))
    ...     print(f"{length:4d}  {bound:.4e}")
      24  1.1881e-04
      96  2.4904e-17
     136  2.2523e-24
     137  5.4212e-20
     272  5.4210e-20
     273  1.6263e-19
    """
    scored = _as_params(params)
    if not isinstance(counts_exchanged, bool):
        raise TypeError(
            f"counts_exchanged must be a bool, got "
            f"{type(counts_exchanged).__name__}"
        )
    if not isinstance(exact, bool):
        raise TypeError(f"exact must be a bool, got {type(exact).__name__}")
    trials = scored.key_length
    probability = scored.match_probability
    own = _floor_bound(
        trials,
        probability,
        minimum_matched_count(scored),
        scored.bases,
        exact=exact,
    )
    total = 2.0 * own
    if counts_exchanged:
        total += _floor_bound(
            2 * trials,
            probability,
            minimum_pooled_matched_count(scored),
            scored.bases,
            exact=exact,
        )
    return min(1.0, total)


def abort_reason_bound(
    params: ProtocolParams,
    reason: AbortReason | str,
    *,
    exact: bool = False,
) -> float:
    """Bound the honest-run probability of **one** abort reason.

    "How strong is an abort?" has nine answers, not one, and summing them would
    quote the weakest for all nine. Each reason is bounded as tightly as its
    own event allows:

    .. code-block:: text

        the five structural reasons     0            exactly; outside the
                                                     honest outcome space
        EMPTY_MATCHED_SET               (1 - p)^n    exactly; the event is
                                                     {count = 0}
        BELOW_FLOOR                     b(n, m_min)  Chernoff, or exact where
        COUNTERPART_BELOW_FLOOR         b(n, m_min)    the floor degenerates
        POOLED_BELOW_FLOOR              b(2n, M_min)

    ``b`` is the same per-check term :func:`evidence_abort_bound` sums, so the
    run-level union is the sum of the three *events* and not of the nine
    reasons -- five of which are zero and three of which describe the same two
    events from different sides.

    Parameters
    ----------
    params : ProtocolParams
        The **sifted** parameter set.
    reason : AbortReason or str
        The reason to bound.
    exact : bool, optional
        Keyword-only. Sum the tail exactly rather than bounding it. Has no
        effect on the six reasons whose answer is already exact.

    Returns
    -------
    float
        A probability in ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams` or ``exact`` is not a
        :class:`bool`.
    ValueError
        If ``reason`` names no :class:`~sih141.protocol.verify.AbortReason`, or
        one with no attribution entry here.

    Notes
    -----
    ``EMPTY_MATCHED_SET`` **underflows to** ``0.0`` **at long keys**, and the
    zero is a float artefact rather than a support argument: ``(2/3)**115200``
    is about ``1e-20303``, which no double holds. It is reported as it computes
    because the alternative -- a special case returning a made-up floor -- would
    be a worse lie, and because the two zeros are told apart by the reason:
    :data:`~sih141.detect.statistics.STRUCTURAL_ABORT_REASONS` is zero because
    the event cannot happen, and this one is zero because the number is smaller
    than arithmetic. A report quoting one should say which.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import abort_reason_bound
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> from sih141.protocol.verify import AbortReason
    >>> for reason in AbortReason:
    ...     bound = abort_reason_bound(DEFAULT_PARAMS, reason)
    ...     print(f"{reason.value:44s} {bound:.4e}")
    session-identifier-mismatch                  0.0000e+00
    records-already-verified                     0.0000e+00
    empty-matched-set                            0.0000e+00
    matched-count-below-floor                    5.4210e-20
    counterpart-count-of-unrecorded-provenance   0.0000e+00
    counts-from-two-declarations                 0.0000e+00
    pooled-matched-count-below-floor             5.4210e-20
    counterpart-matched-count-below-floor        5.4210e-20
    unauthorised-verifier                        0.0000e+00

    The empty matched set reads ``0`` there only because ``(2/3)**115200``
    underflows a float; at a length where it does not, it is exact and far
    tighter than the floor's own budget:

    >>> from sih141.protocol.params import ProtocolParams
    >>> f"{abort_reason_bound(ProtocolParams(key_length=96), AbortReason.EMPTY_MATCHED_SET):.4e}"
    '1.2452e-17'
    >>> f"{(2 / 3) ** 96:.4e}"
    '1.2452e-17'
    """
    scored = _as_params(params)
    if not isinstance(exact, bool):
        raise TypeError(f"exact must be a bool, got {type(exact).__name__}")
    resolved = _as_reason(str(reason))
    if resolved in STRUCTURAL_ABORT_REASONS:
        return 0.0
    probability = scored.match_probability
    if resolved is AbortReason.EMPTY_MATCHED_SET:
        return (1.0 - probability) ** scored.key_length
    if resolved is AbortReason.POOLED_BELOW_FLOOR:
        return _floor_bound(
            2 * scored.key_length,
            probability,
            minimum_pooled_matched_count(scored),
            scored.bases,
            exact=exact,
        )
    return _floor_bound(
        scored.key_length,
        probability,
        minimum_matched_count(scored),
        scored.bases,
        exact=exact,
    )


def minimum_sifted_length(
    eps: float, *, alphabet: int = 3, counts_exchanged: bool = True
) -> int | None:
    """Return the shortest sifted key at which an evidence abort fits a budget.

    The ROC-relevant inverse of :func:`evidence_abort_bound`: the smallest ``n``
    such that ``B_evid(m) <= eps`` for **every** ``m >= n``. The "every" is
    load-bearing -- ``B_evid`` is not monotone (:ref:`evidence-null`), so the
    first ``n`` that fits the budget is not necessarily the point past which it
    keeps fitting, and a Phase 5 sweep that took it for one would claim a bound
    that a longer key violates.

    Parameters
    ----------
    eps : float
        The false-positive budget, in ``(0, 1)``.
    alphabet : int, optional
        Keyword-only. ``|B|``, at least ``2``. ``3`` is the shipped six-state
        alphabet.
    counts_exchanged : bool, optional
        Keyword-only. Whether Phase C' runs; see :func:`evidence_abort_bound`.

    Returns
    -------
    int or None
        ``None`` when the budget is below what the floors themselves spend --
        ``3 * 2**-64`` with the exchange, ``2 * 2**-64`` without -- because no
        key length reaches it and firing anyway would be a claim the derivation
        does not support (:ref:`no-lower-budget`).

    Raises
    ------
    TypeError
        If ``eps`` is not a real number, ``alphabet`` is not an integer or
        ``counts_exchanged`` is not a :class:`bool`.
    ValueError
        If ``eps`` is outside ``(0, 1)`` or ``alphabet < 2``.

    Notes
    -----
    **There is deliberately no** ``exact`` **option here, and the reason is the
    quantifier.** The closed-form bound is eventually the constant ``3 eps0``
    (:ref:`no-lower-budget`), so "for every ``m >= n``" can be settled by a
    finite search plus a proven asymptote. The exact tail has neither: it
    *increases* with key length -- ``4.1e-37`` at ``L = 600`` against
    ``2.5e-31`` at :data:`~sih141.protocol.params.DEFAULT_PARAMS`, because the
    floor sits a fixed number of standard deviations below the mean -- and its
    limit has no closed form here, so no finite search can certify the
    quantifier. :func:`evidence_abort_bound` still takes ``exact`` because a
    per-run bound quantifies over nothing.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import minimum_sifted_length
    >>> for budget in (1e-3, 1e-6, 1e-9, 1e-15, 1e-18):
    ...     print(f"{budget:.0e}  {minimum_sifted_length(budget)}")
    1e-03  19
    1e-06  36
    1e-09  53
    1e-15  87
    1e-18  104

    Below the floors' own budget there is no such length, and the honest answer
    is to say so rather than to fire:

    >>> minimum_sifted_length(1e-19) is None
    True
    >>> f"{3 * 2.0**-64:.4e}"
    '1.6263e-19'
    >>> minimum_sifted_length(1.7e-19)
    109

    Dropping the pooled check removes one term from the union and one from the
    asymptote, so a slightly tighter budget becomes reachable:

    >>> minimum_sifted_length(1.2e-19, counts_exchanged=False)
    110
    >>> minimum_sifted_length(1.2e-19) is None
    True
    """
    budget = _as_budget(eps)
    if isinstance(alphabet, bool) or not isinstance(alphabet, int):
        raise TypeError(
            f"alphabet must be an int, got {type(alphabet).__name__}"
        )
    if alphabet < 2:
        raise ValueError(
            f"alphabet must be at least 2, got {alphabet}; one basis is not a "
            f"basis choice and the match probability would be 1."
        )
    if not isinstance(counts_exchanged, bool):
        raise TypeError(
            f"counts_exchanged must be a bool, got "
            f"{type(counts_exchanged).__name__}"
        )

    bases = _bases_of_size(alphabet)
    values = [
        evidence_abort_bound(
            ProtocolParams(key_length=length, bases=bases),
            counts_exchanged=counts_exchanged,
        )
        for length in range(1, _SEARCH_CEILING + 1)
    ]
    asymptote = values[-1]
    if asymptote > budget:
        return None
    answer: int | None = None
    running = asymptote
    for index in range(_SEARCH_CEILING - 1, -1, -1):
        running = max(running, values[index])
        if running <= budget:
            answer = index + 1
    return answer


def _bases_of_size(alphabet: int) -> tuple[Any, ...]:
    """Return an alphabet of the requested size, from the shipped Pauli bases.

    Parameters
    ----------
    alphabet : int
        ``2`` or ``3``.

    Returns
    -------
    tuple
        A prefix of :data:`~sih141.protocol.params.DEFAULT_BASES`.

    Raises
    ------
    ValueError
        If ``alphabet`` exceeds the number of Pauli bases there are.
    """
    if alphabet > len(DEFAULT_BASES):
        raise ValueError(
            f"alphabet must be at most {len(DEFAULT_BASES)}, got {alphabet}: "
            f"there are three mutually unbiased Pauli bases and no fourth."
        )
    return DEFAULT_BASES[:alphabet]


# --------------------------------------------------------------------------- #
# Thresholds
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class StructuralThreshold:
    """One derived operating point, with the four things D7 asks for on it.

    A threshold that cannot say what null it was derived against, which
    inequality was applied and what its false-positive probability provably is
    has not been derived, it has been chosen. All four are fields here, and
    :attr:`derivation` names the section of a docstring that shows the algebra.

    Attributes
    ----------
    check : StructuralCheck
        Which check this is the threshold for.
    statistic : str
        The attribute path on
        :class:`~sih141.detect.statistics.TranscriptStatistics` this reads.
    null : str
        The honest-run law, stated exactly.
    inequality : str
        The named inequality applied to it, or ``"none -- point mass"`` where
        the null is degenerate and the answer is exact.
    budget : float
        The ``eps`` this operating point was derived for.
    fires_at : int or None
        The smallest observed count that fires. ``None`` means **no admissible
        operating point exists at this budget**, and the check must be withheld
        rather than fired at a bar the derivation does not reach.
    false_positive_bound : float
        The proven bound on the probability that an honest run fires this,
        *at this operating point*. Often far below :attr:`budget`, and reported
        as what is proven rather than as what was asked for.
    detail : str
        One line naming the derivation, for a report that has to be read by a
        person.
    derivation : str
        Where the algebra is written down.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import (
    ...     structural_abort_threshold
    ... )
    >>> threshold = structural_abort_threshold(1e-9)
    >>> threshold.fires_at, threshold.false_positive_bound
    (1, 0.0)
    >>> threshold.admissible, threshold.fires(0), threshold.fires(1)
    (True, False, True)
    >>> threshold.inequality
    'none -- point mass at 0'
    """

    check: StructuralCheck
    statistic: str
    null: str
    inequality: str
    budget: float
    fires_at: int | None
    false_positive_bound: float
    detail: str
    derivation: str

    @property
    def admissible(self) -> bool:
        """bool: Whether an operating point exists inside :attr:`budget`."""
        return self.fires_at is not None

    def fires(self, count: int) -> bool:
        """Whether an observed count trips this threshold.

        Parameters
        ----------
        count : int
            The observed statistic.

        Returns
        -------
        bool
            ``False`` for every count when the threshold is not admissible: a
            withheld check does not fire, it abstains, and the difference is
            visible on :attr:`admissible`.

        Raises
        ------
        TypeError
            If ``count`` is not an integer.
        ValueError
            If ``count`` is negative.
        """
        observed = _as_count(count, "count")
        if self.fires_at is None:
            return False
        return observed >= self.fires_at

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "check": str(self.check),
            "statistic": self.statistic,
            "null": self.null,
            "inequality": self.inequality,
            "budget": self.budget,
            "fires_at": self.fires_at,
            "false_positive_bound": self.false_positive_bound,
            "admissible": self.admissible,
            "detail": self.detail,
            "derivation": self.derivation,
        }


def point_mass_threshold(
    check: StructuralCheck,
    eps: float,
    *,
    statistic: str,
    null: str,
    detail: str,
    derivation: str,
) -> StructuralThreshold:
    """Return the derived threshold for a statistic whose null is a point mass.

    Shared by the three checks whose honest-run probability is zero, so that the
    argument is made once instead of three times. The derivation is two lines:
    we want the smallest ``k >= 1`` with ``P_null[X >= k] <= eps``; the null puts
    all its mass on ``0``, so ``P_null[X >= 1] = 0 <= eps`` for every budget and
    ``k = 1``. ``k = 0`` is excluded because ``P[X >= 0] = 1``, and a rule that
    fires on every run is not a detector.

    Parameters
    ----------
    check : StructuralCheck
        Which check this is.
    eps : float
        The budget, in ``(0, 1)``. Recorded; the answer does not depend on it,
        which is itself the result rather than an oversight.
    statistic, null, detail, derivation : str
        Keyword-only. Carried onto the threshold; see
        :class:`StructuralThreshold`.

    Returns
    -------
    StructuralThreshold
        With ``fires_at = 1`` and ``false_positive_bound = 0.0`` at every
        budget.

    Raises
    ------
    TypeError
        If ``check`` is not a :class:`StructuralCheck`, ``eps`` is not a real
        number, or a text field is not a string.
    ValueError
        If ``eps`` is outside ``(0, 1)``.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import (
    ...     StructuralCheck, point_mass_threshold
    ... )
    >>> threshold = point_mass_threshold(
    ...     StructuralCheck.REPLAY_REFUSAL,
    ...     1e-30,
    ...     statistic="replay.total_refusals",
    ...     null="point mass at 0",
    ...     detail="an honest run asks each verifier once",
    ...     derivation="structural-null",
    ... )
    >>> threshold.fires_at, threshold.false_positive_bound
    (1, 0.0)
    """
    if not isinstance(check, StructuralCheck):
        raise TypeError(
            f"check must be a StructuralCheck, got {type(check).__name__}"
        )
    budget = _as_budget(eps)
    for name, value in (
        ("statistic", statistic),
        ("null", null),
        ("detail", detail),
        ("derivation", derivation),
    ):
        if not isinstance(value, str):
            raise TypeError(
                f"{name} must be a string, got {type(value).__name__}"
            )
    return StructuralThreshold(
        check=check,
        statistic=statistic,
        null=null,
        inequality="none -- point mass at 0",
        budget=budget,
        fires_at=1,
        false_positive_bound=0.0,
        detail=detail,
        derivation=derivation,
    )


def structural_abort_threshold(eps: float) -> StructuralThreshold:
    """Return the derived threshold on structural aborts.

    Null: point mass at ``0``. Four of the five reasons in
    :data:`~sih141.detect.statistics.STRUCTURAL_ABORT_REASONS` are decided by an
    equality test on data the honest protocol fixes, and the fifth by set
    membership on an authorised recipient set the caller supplies; no randomness
    enters any of them, so the event is outside the honest run's outcome space
    and its probability is exactly zero -- not small, zero. The fifth carries
    that zero only for a set containing the recipients the signer distributed
    to, and is unreachable on a call that names no set at all.
    :ref:`structural-null` names the five tests.

    Parameters
    ----------
    eps : float
        The budget, in ``(0, 1)``. Recorded and not used: the strongest bound in
        the family is also the one no budget can improve or spoil.

    Returns
    -------
    StructuralThreshold
        ``fires_at = 1``, ``false_positive_bound = 0.0``.

    Raises
    ------
    TypeError
        If ``eps`` is not a real number.
    ValueError
        If ``eps`` is outside ``(0, 1)``.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import (
    ...     structural_abort_threshold
    ... )
    >>> loose = structural_abort_threshold(0.5)
    >>> tight = structural_abort_threshold(1e-300)
    >>> (loose.fires_at, loose.false_positive_bound) == (
    ...     tight.fires_at, tight.false_positive_bound
    ... )
    True
    >>> loose.false_positive_bound
    0.0
    """
    # The null below is quoted verbatim in the recorded transcripts under
    # sih141/web/static/data/recorded/ and in the Phase 4 table, so a reword
    # here is a re-record there: python tools/phase6_fixtures.py.
    return point_mass_threshold(
        StructuralCheck.STRUCTURAL_ABORT,
        eps,
        statistic="aborts.structural",
        null=(
            "point mass at 0: each of the five structural reasons is decided "
            "without a random draw, four by an equality test on data the "
            "honest protocol fixes and the fifth by set membership on an "
            "authorised set the caller supplies"
        ),
        detail=(
            "a session mismatch, a re-presented round, a count with no "
            "provenance and two counts from two declarations cannot occur on "
            "an honest run at any key length, and neither can a verifier "
            "outside the authorised set once that set names the recipients "
            "the signer distributed to"
        ),
        derivation="sih141.detect.thresholds_structural, structural-null",
    )


def replay_refusal_threshold(eps: float) -> StructuralThreshold:
    """Return the derived threshold on replay refusals.

    Null: point mass at ``0``. An honest run asks each verifier exactly once per
    ``(session, message bit)``, the ledger key is that pair, and the refusal is
    set membership -- no randomness, no tail.

    Sound in **one direction only**, which the returned
    :attr:`~StructuralThreshold.detail` says: the ledger denial-of-service route
    burns a round through a *rejection*, which is a verdict, so a replay can
    happen and leave this statistic at ``0``. There is also no rate to be had --
    refusals are counted but attempts are not. See :ref:`finding 4 <findings>`.

    Parameters
    ----------
    eps : float
        The budget, in ``(0, 1)``. Recorded and not used.

    Returns
    -------
    StructuralThreshold
        ``fires_at = 1``, ``false_positive_bound = 0.0``.

    Raises
    ------
    TypeError
        If ``eps`` is not a real number.
    ValueError
        If ``eps`` is outside ``(0, 1)``.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import (
    ...     replay_refusal_threshold
    ... )
    >>> threshold = replay_refusal_threshold(1e-9)
    >>> threshold.fires_at, threshold.false_positive_bound
    (1, 0.0)
    >>> "one direction" in threshold.detail
    True
    """
    return point_mass_threshold(
        StructuralCheck.REPLAY_REFUSAL,
        eps,
        statistic="replay.total_refusals",
        null=(
            "point mass at 0: an honest run asks each verifier once per "
            "(session, bit) and the ledger check is set membership"
        ),
        detail=(
            "a non-zero refusal count is a replay outright; zero is not "
            "evidence of none, because the ledger denial-of-service route "
            "burns a round through a rejection, which is a verdict -- sound "
            "in one direction only, and there is no denominator for a rate"
        ),
        derivation="sih141.detect.thresholds_structural, structural-null",
    )


def run_shape_threshold(eps: float) -> StructuralThreshold:
    """Return the derived threshold on run-shape violations.

    Null: point mass at ``0``. The six equalities on
    :func:`run_shape_violations` are properties of the shipped
    :class:`~sih141.protocol.session.QDSSession` -- one fresh ledger per
    verifier per session, one bit signed, a verdict spends a round, a refusal
    spends nothing -- so a violation is not improbable, it is unreachable.

    **It is a statement about the file, not about an adversary.** No adversary
    in the Phase 3 threat model produces one, measured; what produces one is a
    transcript that did not come from the shipped session, including one written
    before the replay ledger existed (:ref:`finding 3 <findings>`).
    :func:`structural_report` keeps it out of the detection count for that
    reason.

    Parameters
    ----------
    eps : float
        The budget, in ``(0, 1)``. Recorded and not used.

    Returns
    -------
    StructuralThreshold
        ``fires_at = 1``, ``false_positive_bound = 0.0``.

    Raises
    ------
    TypeError
        If ``eps`` is not a real number.
    ValueError
        If ``eps`` is outside ``(0, 1)``.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import run_shape_threshold
    >>> run_shape_threshold(1e-9).false_positive_bound
    0.0
    """
    return point_mass_threshold(
        StructuralCheck.RUN_SHAPE,
        eps,
        statistic="run_shape_violations(stats)",
        null=(
            "point mass at 0: six equalities the shipped session satisfies by "
            "construction, none of them a function of any random draw"
        ),
        detail=(
            "a violation says the transcript did not come from the shipped "
            "session -- a provenance finding about the file, not a detection "
            "of any adversary in the threat model"
        ),
        derivation="sih141.detect.thresholds_structural, structural-null",
    )


def evidence_abort_threshold(
    params: ProtocolParams,
    eps: float,
    *,
    counts_exchanged: bool = True,
    exact: bool = False,
) -> StructuralThreshold:
    """Return the derived threshold on evidence aborts.

    Null: ``{evidence >= 1}`` is contained in the union of the three floor
    events, each bounded exactly or by the multiplicative Chernoff lower tail
    the floor was calibrated to; :func:`evidence_abort_bound` is the union and
    :ref:`evidence-null` is the algebra.

    The operating point is ``fire iff evidence >= 1`` **when the bound fits the
    budget**, and no operating point at all when it does not -- there is no
    higher bar to retreat to, since the statistic is at most ``2`` and its tail
    at ``2`` is bounded by the same union. A budget below ``3 * 2**-64`` admits
    no key length at all (:ref:`no-lower-budget`).

    Parameters
    ----------
    params : ProtocolParams
        The **sifted** parameter set.
    eps : float
        The budget, in ``(0, 1)``.
    counts_exchanged : bool, optional
        Keyword-only. Whether Phase C' ran; two floor events instead of three.
    exact : bool, optional
        Keyword-only. Whether to sum the tails exactly.

    Returns
    -------
    StructuralThreshold
        ``fires_at = 1`` and ``false_positive_bound`` the union bound, or
        ``fires_at = None`` with the same bound recorded, so a report can say
        *why* the check was withheld.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, ``eps`` is not a real
        number, or a flag is not a :class:`bool`.
    ValueError
        If ``eps`` is outside ``(0, 1)``.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import (
    ...     evidence_abort_threshold
    ... )
    >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
    >>> threshold = evidence_abort_threshold(DEFAULT_PARAMS, 1e-9)
    >>> threshold.fires_at, f"{threshold.false_positive_bound:.4e}"
    (1, '1.6263e-19')

    The bound is what is proven, not what was asked for: a run at
    ``eps = 1e-9`` fires a check that is ten orders of magnitude better than the
    budget. Below the floors' own budget the check is withheld instead:

    >>> tight = evidence_abort_threshold(DEFAULT_PARAMS, 1e-20)
    >>> tight.admissible, tight.fires(2)
    (False, False)

    And at a demonstration key length the same budget buys nothing, which is the
    honest answer rather than a footnote:

    >>> demo = evidence_abort_threshold(ProtocolParams(key_length=24), 1e-9)
    >>> demo.admissible, f"{demo.false_positive_bound:.4e}"
    (False, '1.1881e-04')
    """
    scored = _as_params(params)
    budget = _as_budget(eps)
    bound = evidence_abort_bound(
        scored, counts_exchanged=counts_exchanged, exact=exact
    )
    admissible = bound <= budget
    checks = "three" if counts_exchanged else "two"
    return StructuralThreshold(
        check=StructuralCheck.EVIDENCE_ABORT,
        statistic="aborts.evidence",
        null=(
            f"union of {checks} binomial lower tails: "
            f"m_B, m_C ~ Binomial(n, p) and M ~ Binomial(2n, p) with "
            f"n = {scored.key_length}, p = 1/{len(scored.bases)}"
        ),
        inequality=(
            "multiplicative Chernoff lower tail at eps0 = 2**-64, exact point "
            "mass where a floor degenerates, union bound over the "
            f"{checks} floor events"
        )
        if not exact
        else (
            "exact binomial lower tail per floor, union bound over the "
            f"{checks} floor events"
        ),
        budget=budget,
        fires_at=1 if admissible else None,
        false_positive_bound=bound,
        detail=(
            "an evidence abort on an honest run needs one of the three floor "
            "events; the floors were derived from that same tail at 2**-64, so "
            "the abort itself is the threshold"
        )
        if admissible
        else (
            f"withheld: the proven bound {bound:.3e} exceeds the budget "
            f"{budget:.3e}, so no operating point on this statistic is "
            f"derivable at this key length -- lengthen the key or loosen the "
            f"budget, do not lower the bar"
        ),
        derivation="sih141.detect.thresholds_structural, evidence-null",
    )


def shortfall_threshold(
    params: ProtocolParams, eps: float, *, pooled: bool = False
) -> StructuralThreshold:
    """Return the derived threshold on how far below a floor a run fell.

    Null: the count behind the shortfall is ``Binomial(n, p)`` for a
    per-verifier floor and ``Binomial(2n, p)`` for the pooled one, so
    ``{shortfall >= s} = {count <= floor - s}`` and the same Chernoff lower tail
    inverts to a shortfall (:ref:`shortfall`).

    **It collapses at every practical budget, and that is the result.** The
    floors are calibrated at ``2**-64``, so for any ``eps`` at or above that the
    derived shortfall is ``1`` -- the abort itself -- and the magnitude carries
    no further detection power. The knob turns only below ``2**-64``.

    Parameters
    ----------
    params : ProtocolParams
        The **sifted** parameter set.
    eps : float
        The budget, in ``(0, 1)``.
    pooled : bool, optional
        Keyword-only. ``True`` for
        :attr:`~sih141.protocol.verify.AbortReason.POOLED_BELOW_FLOOR`, whose
        count is over ``2n`` trials against the pooled floor.

    Returns
    -------
    StructuralThreshold
        ``fires_at`` is the smallest shortfall inside the budget, or ``None``
        where the sample is too small to spend it.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, ``eps`` is not a real
        number, or ``pooled`` is not a :class:`bool`.
    ValueError
        If ``eps`` is outside ``(0, 1)``.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import shortfall_threshold
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> for budget in (1e-3, 1e-9, 2.0**-64, 1e-25, 1e-40):
    ...     threshold = shortfall_threshold(DEFAULT_PARAMS, budget)
    ...     print(f"{budget:.2e}  {threshold.fires_at}")
    1.00e-03  1
    1.00e-09  1
    5.42e-20  1
    1.00e-25  258
    1.00e-40  815

    The bound reported is the one proven at the operating point, which at the
    collapsed threshold is the floor's own budget rather than the budget asked
    for -- and a shade under it, because ``m_min`` is a *ceiling* and the tail
    at ``m_min - 1`` is therefore slightly inside ``2**-64``:

    >>> threshold = shortfall_threshold(DEFAULT_PARAMS, 1e-3)
    >>> f"{threshold.false_positive_bound:.4e}", f"{2.0**-64:.4e}"
    ('5.3677e-20', '5.4210e-20')
    """
    scored = _as_params(params)
    budget = _as_budget(eps)
    if not isinstance(pooled, bool):
        raise TypeError(f"pooled must be a bool, got {type(pooled).__name__}")
    trials = 2 * scored.key_length if pooled else scored.key_length
    probability = scored.match_probability
    floor = (
        minimum_pooled_matched_count(scored)
        if pooled
        else minimum_matched_count(scored)
    )
    largest = chernoff_lower_tail_count(trials, probability, budget)
    if largest is None:
        fires_at: int | None = None
        bound = 1.0
    else:
        fires_at = max(1, floor - largest)
        bound = chernoff_deviation_bound(
            max(0, floor - fires_at), trials, probability, side="lower"
        )
    which = "pooled" if pooled else "per-verifier"
    return StructuralThreshold(
        check=StructuralCheck.EVIDENCE_ABORT,
        statistic=f"aborts.shortfalls[party] ({which} floor)",
        null=(
            f"the count behind the shortfall is Binomial({trials}, "
            f"1/{len(scored.bases)}); "
            f"{{shortfall >= s}} = {{count <= {floor} - s}}"
        ),
        inequality="multiplicative Chernoff lower tail, inverted",
        budget=budget,
        fires_at=fires_at,
        false_positive_bound=bound,
        detail=(
            f"the {which} floor is {floor}; at every budget at or above "
            f"2**-64 this collapses to 1, because the floor already spends "
            f"that budget and the abort is itself the threshold"
        ),
        derivation="sih141.detect.thresholds_structural, shortfall",
    )


# --------------------------------------------------------------------------- #
# Run shape
# --------------------------------------------------------------------------- #


def run_shape_violations(stats: TranscriptStatistics) -> tuple[str, ...]:
    """Return the run-shape equalities this transcript breaks.

    Six properties of the shipped :class:`~sih141.protocol.session.QDSSession`,
    each satisfied by construction and none of them a function of a random draw:

    1. ``spent_rounds <= 2`` -- one ledger entry per verifier per
       ``(session, bit)``, and there are two verifiers.
    2. ``spent_rounds >= |verdicts|`` -- reaching a verdict spends the round,
       and a refusal spends nothing.
    3. ``distinct_sessions <= 1`` -- the session builds one fresh ledger per
       verifier, so its ledgers span one round.
    4. ``distinct_message_bits <= 1`` -- one run signs one bit.
    5. Every party holding a spent round is a verifier.
    6. No party appears both among the verdicts and among the refusals -- each
       verifier holds exactly one current outcome.

    Parameters
    ----------
    stats : TranscriptStatistics
        The run.

    Returns
    -------
    tuple of str
        One line per violation, empty on a well-formed transcript. Sorted, so
        two readings of one file compare equal.

    Raises
    ------
    TypeError
        If ``stats`` is not a
        :class:`~sih141.detect.statistics.TranscriptStatistics`.

    Notes
    -----
    Check 2 is the one with a caveat, and :ref:`finding 3 <findings>` states it:
    :meth:`~sih141.protocol.session.SessionTranscript.from_dict` defaults
    ``spent_rounds`` to ``()``, so a transcript written before the replay ledger
    existed trips it. That is a true statement about the file -- it did not come
    from the shipped session -- and it is why nothing here is reported as a
    detection of an adversary.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_structural import run_shape_violations
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=384), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> run_shape_violations(stats)
    ()
    """
    if not isinstance(stats, TranscriptStatistics):
        raise TypeError(
            f"stats must be a TranscriptStatistics, got "
            f"{type(stats).__name__}"
        )
    replay = stats.replay
    verdicts = set(stats.verifiers)
    refusals = set(stats.aborts.by_party)
    found: list[str] = []
    if replay.spent_rounds > 2:
        found.append(
            f"spent_rounds is {replay.spent_rounds}; one ledger entry per "
            f"verifier per (session, bit) caps it at 2"
        )
    if replay.spent_rounds < len(verdicts):
        found.append(
            f"spent_rounds is {replay.spent_rounds} against "
            f"{len(verdicts)} verdict(s); reaching a verdict spends the round"
        )
    if replay.distinct_sessions > 1:
        found.append(
            f"the ledgers name {replay.distinct_sessions} sessions; one run "
            f"builds one fresh ledger per verifier"
        )
    if replay.distinct_message_bits > 1:
        found.append(
            f"the ledgers name {replay.distinct_message_bits} message bits; "
            f"one run signs one bit"
        )
    strangers = sorted(
        party
        for party in replay.parties_with_spent_rounds
        if party not in (Party.BOB.value, Party.CHARLIE.value)
    )
    if strangers:
        found.append(
            f"{', '.join(strangers)} hold(s) a spent round without being a "
            f"verifier"
        )
    both = sorted(verdicts & refusals)
    if both:
        found.append(
            f"{', '.join(both)} appear(s) among both the verdicts and the "
            f"refusals; each verifier holds exactly one current outcome"
        )
    return tuple(sorted(found))


# --------------------------------------------------------------------------- #
# Attribution
# --------------------------------------------------------------------------- #

#: Which party's count each abort reason is a statement about, as a function of
#: the refusing party. ``None`` marks a reason that names no count at all -- the
#: five structural ones and the pooled one, which is about the pair. Read off
#: the protocol's own control flow (:class:`~sih141.protocol.verify.AbortReason`
#: and :attr:`~sih141.protocol.verify.VerificationAbort.shortfall`), not off any
#: measurement.
_SHORT_PARTY: Final[Mapping[AbortReason, str]] = {
    AbortReason.EMPTY_MATCHED_SET: "self",
    AbortReason.BELOW_FLOOR: "self",
    AbortReason.COUNTERPART_BELOW_FLOOR: "counterpart",
    AbortReason.POOLED_BELOW_FLOOR: "pair",
    AbortReason.SESSION_MISMATCH: "none",
    AbortReason.RECORD_ALREADY_VERIFIED: "none",
    AbortReason.COUNT_OF_UNRECORDED_PROVENANCE: "none",
    AbortReason.COUNTS_FROM_TWO_DECLARATIONS: "none",
    AbortReason.UNAUTHORISED_VERIFIER: "none",
}

#: Which position in the threat model can force each reason, and whether it can
#: do so deterministically. A reading of where each check sits and who supplies
#: its input -- see :ref:`induced`. Nothing in this module was chosen from it,
#: and it holds no numbers.
_FORCED_BY: Final[Mapping[AbortReason, str]] = {
    AbortReason.EMPTY_MATCHED_SET: (
        "a signer who chooses the declaration against this verifier's log; "
        "also an honest run at a key length too short for the floors"
    ),
    AbortReason.BELOW_FLOOR: (
        "a signer who chooses the declaration against this verifier's log"
    ),
    AbortReason.POOLED_BELOW_FLOOR: (
        "a signer aiming the pooled total low -- the split-coin route the "
        "pooled floor closes"
    ),
    AbortReason.COUNTERPART_BELOW_FLOOR: (
        "the counterpart himself, with one integer and probability 1: any "
        "declaration at or below the denial headroom"
    ),
    AbortReason.SESSION_MISMATCH: (
        "anyone who can pair a declaration with another round's record"
    ),
    AbortReason.RECORD_ALREADY_VERIFIED: (
        "anyone who can make this verifier reach a verdict twice, including "
        "the ledger denial-of-service route on the forwarding hop"
    ),
    AbortReason.COUNT_OF_UNRECORDED_PROVENANCE: (
        "the counterpart, by declining to say which declaration he counted"
    ),
    AbortReason.COUNTS_FROM_TWO_DECLARATIONS: (
        "the forwarding hop, with probability 1: a substituted declaration "
        "makes the two counts describe two declarations"
    ),
    AbortReason.UNAUTHORISED_VERIFIER: (
        "nobody in the threat model: the authorised set is the caller's, the "
        "check is off unless he names one, and a party holding a leaked record "
        "passes it under its owner's name"
    ),
}


@dataclass(frozen=True)
class AbortAttribution:
    """One refusal, read for what it says about who made the evidence thin.

    Detection is finished before this object exists: an evidence abort on a run
    whose floors bite is somebody's doing at a false-positive cost of
    :func:`evidence_abort_bound`. What remains is *whose*, and the transcript
    answers it through the reason and the shortfall and through nothing else.

    Attributes
    ----------
    party : str
        The verifier who refused.
    reason : str
        The :class:`~sih141.protocol.verify.AbortReason` value.
    group : str
        ``"structural"`` or ``"evidence"``. The two carry different provable
        bounds and are never summed.
    short_party : str or None
        Whose count was short: the refusing party for the two own-count
        reasons, the *other* verifier for
        :attr:`~sih141.protocol.verify.AbortReason.COUNTERPART_BELOW_FLOOR`,
        and ``None`` for the pooled reason -- which is about the pair -- and for
        the five structural reasons, which name no count.
    shortfall : int
        Distance below the floor the reason names, as the run recorded it.
        ``0`` on every reason that names no floor.
    false_positive_bound : float
        The proven bound on an honest run producing *this* refusal:
        ``0.0`` for a structural reason, and the Chernoff lower tail at the
        observed count for a reason that names a floor -- which is at or below
        the floor's own ``2**-64``, and tighter the deeper the shortfall. One
        of the structural zeros carries a precondition:
        :attr:`~sih141.protocol.verify.AbortReason.UNAUTHORISED_VERIFIER` is
        unreachable unless a caller names an authorised recipient set, and its
        zero holds for a set containing the recipients the signer distributed
        to. A caller who names some other set refuses an honest verifier, and
        that refusal is filed here under ``"structural"`` like any other. See
        :class:`StructuralCheck` and ``forced_by``.
    forced_by : str
        Which position in the threat model can force this reason, from
        :ref:`induced`. A reading of the protocol, not a measurement.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import AbortAttribution
    >>> AbortAttribution(
    ...     party="Bob",
    ...     reason="counterpart-matched-count-below-floor",
    ...     group="evidence",
    ...     short_party="Charlie",
    ...     shortfall=9,
    ...     false_positive_bound=1.2e-21,
    ...     forced_by="the counterpart himself",
    ... ).short_party
    'Charlie'
    """

    party: str
    reason: str
    group: str
    short_party: str | None
    shortfall: int
    false_positive_bound: float
    forced_by: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "party": self.party,
            "reason": self.reason,
            "group": self.group,
            "short_party": self.short_party,
            "shortfall": self.shortfall,
            "false_positive_bound": self.false_positive_bound,
            "forced_by": self.forced_by,
        }


def attribute_aborts(
    stats: TranscriptStatistics,
) -> tuple[AbortAttribution, ...]:
    """Read every refusal in a run for whose evidence was short.

    Parameters
    ----------
    stats : TranscriptStatistics
        The run.

    Returns
    -------
    tuple of AbortAttribution
        One per refusing party, sorted by party name. Empty on a run in which
        everybody reached a verdict.

    Raises
    ------
    TypeError
        If ``stats`` is not a
        :class:`~sih141.detect.statistics.TranscriptStatistics`.
    ValueError
        If the transcript names an abort reason this module has no entry for,
        which means a reason was added upstream without deciding where it
        belongs. Refused loudly rather than filed under the weaker bound.

    Examples
    --------
    A run whose counterpart starved the count: Bob refuses, and the refusal
    names Charlie.

    >>> import numpy as np
    >>> from sih141.attacks.starvation import CountStarver
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_structural import attribute_aborts
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> from sih141.protocol.verify import MatchedSetTooSmall
    >>> session = QDSSession(
    ...     ProtocolParams(key_length=384),
    ...     rng=np.random.default_rng(700000),
    ...     count_exchange=CountStarver(rng=np.random.default_rng(9001)),
    ... )
    >>> try:
    ...     transcript = session.run(0)
    ... except MatchedSetTooSmall:
    ...     transcript = session.transcript()
    >>> found = attribute_aborts(
    ...     TranscriptStatistics.from_transcript(transcript)
    ... )
    >>> found[0].party, found[0].short_party, found[0].shortfall
    ('Bob', 'Charlie', 9)
    >>> found[0].group, f"{found[0].false_positive_bound:.3e}"
    ('evidence', '3.667e-23')
    """
    if not isinstance(stats, TranscriptStatistics):
        raise TypeError(
            f"stats must be a TranscriptStatistics, got "
            f"{type(stats).__name__}"
        )
    scored = stats.params
    probability = scored.match_probability
    floor = minimum_matched_count(scored)
    pooled_floor = minimum_pooled_matched_count(scored)
    found: list[AbortAttribution] = []
    for party in sorted(stats.aborts.by_party):
        raw = stats.aborts.by_party[party]
        reason = _as_reason(raw)
        shortfall = int(stats.aborts.shortfalls.get(party, 0))
        role = _SHORT_PARTY[reason]
        if role == "self":
            short_party: str | None = party
            trials, base = scored.key_length, floor
        elif role == "counterpart":
            short_party = _counterpart(party)
            trials, base = scored.key_length, floor
        elif role == "pair":
            short_party = None
            trials, base = 2 * scored.key_length, pooled_floor
        else:
            short_party = None
            trials, base = 0, 0
        if reason in STRUCTURAL_ABORT_REASONS:
            group, bound = "structural", 0.0
        else:
            group = "evidence"
            bound = chernoff_deviation_bound(
                max(0, base - shortfall), trials, probability, side="lower"
            )
        found.append(
            AbortAttribution(
                party=party,
                reason=str(reason),
                group=group,
                short_party=short_party,
                shortfall=shortfall,
                false_positive_bound=bound,
                forced_by=_FORCED_BY[reason],
            )
        )
    return tuple(found)


def _as_reason(value: str) -> AbortReason:
    """Coerce a recorded abort reason, refusing an unknown one.

    Parameters
    ----------
    value : str
        The reason as the transcript recorded it.

    Returns
    -------
    AbortReason

    Raises
    ------
    ValueError
        If the value names no known reason, or names one this module has no
        attribution entry for.
    """
    try:
        reason = AbortReason(value)
    except ValueError as unknown:
        raise ValueError(
            f"{value!r} names no AbortReason. A transcript carrying one was "
            f"not produced by this protocol."
        ) from unknown
    if reason not in _SHORT_PARTY or reason not in _FORCED_BY:
        raise ValueError(
            f"{reason!r} has no attribution entry in "
            f"sih141.detect.thresholds_structural. A reason added upstream "
            f"must be placed deliberately: the two abort groups carry "
            f"different provable bounds and must not be summed."
        )
    if reason not in STRUCTURAL_ABORT_REASONS | EVIDENCE_ABORT_REASONS:
        raise ValueError(
            f"{reason!r} belongs to neither abort group. The two carry "
            f"different provable bounds -- exactly zero against 2**-64 -- so a "
            f"reason in neither cannot be reported without inventing one."
        )
    return reason


# --------------------------------------------------------------------------- #
# The family, applied
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class StructuralAlarm:
    """One check that fired, and what firing it costs in false positives.

    Attributes
    ----------
    check : StructuralCheck
        Which check.
    count : int
        The observed statistic.
    threshold : StructuralThreshold
        The operating point it tripped, carrying the null and the bound.
    detail : str
        What tripped, in a line a person can read.

    Notes
    -----
    **An alarm is not a rejection.** It says a structural signal fired, and on
    three of the four checks the run reached no verdict at all -- which is
    exactly the outcome that must never be counted as a rejection. Read
    :attr:`StructuralReport.outcomes` for what each verifier actually did; there
    is no ``accepted`` field here and there will not be one.

    Examples
    --------
    >>> from sih141.detect.thresholds_structural import (
    ...     StructuralAlarm, structural_abort_threshold
    ... )
    >>> alarm = StructuralAlarm(
    ...     check=structural_abort_threshold(1e-9).check,
    ...     count=1,
    ...     threshold=structural_abort_threshold(1e-9),
    ...     detail="Charlie: counts-from-two-declarations",
    ... )
    >>> alarm.false_positive_bound
    0.0
    """

    check: StructuralCheck
    count: int
    threshold: StructuralThreshold
    detail: str

    @property
    def false_positive_bound(self) -> float:
        """float: The proven bound carried by the threshold that fired."""
        return self.threshold.false_positive_bound

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "check": str(self.check),
            "count": self.count,
            "detail": self.detail,
            "false_positive_bound": self.false_positive_bound,
            "threshold": self.threshold.to_dict(),
        }


@dataclass(frozen=True)
class StructuralReport:
    """Everything the structural family has to say about one run.

    Attributes
    ----------
    budget : float
        The ``eps`` every threshold in it was derived at.
    thresholds : tuple of StructuralThreshold
        All four, in :data:`STRUCTURAL_CHECKS` order, whether or not they fired
        and whether or not they were admissible.
    alarms : tuple of StructuralAlarm
        Those that fired.
    withheld : tuple of StructuralCheck
        Those with no admissible operating point at this budget and key length.
        A withheld check is not a passed check, and keeping the two apart is why
        this field exists.
    false_positive_bound : float
        Union bound over the checks that were **applied**: the probability that
        an honest run raises any alarm at all. The three point-mass checks
        contribute exactly zero, so this is
        :func:`evidence_abort_bound` whenever that check is admissible and
        ``0.0`` when it is withheld.
    outcomes : mapping of str to RunOutcome
        What each verifier did. Four-valued and with no truth value, so a
        refusal cannot be read as a rejection.
    attributions : tuple of AbortAttribution
        One per refusal.
    count_exchange_timing : str
        Carried so that a Phase 5 table groups by it and never averages over it.
    key_length : int
        The **sifted** length every null was stated over.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_structural import structural_report
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=384), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> report = structural_report(stats, eps=1e-9)
    >>> report.alarm_raised, report.withheld
    (False, ())
    >>> print(report.summary())
    structural: no alarm at eps = 1.000e-09 (false positives <= 1.6263e-19)
    outcomes: Bob accepted, Charlie accepted
    """

    budget: float
    thresholds: tuple[StructuralThreshold, ...]
    alarms: tuple[StructuralAlarm, ...]
    withheld: tuple[StructuralCheck, ...]
    false_positive_bound: float
    outcomes: Mapping[str, RunOutcome]
    attributions: tuple[AbortAttribution, ...]
    count_exchange_timing: str
    key_length: int

    @property
    def alarm_raised(self) -> bool:
        """bool: Whether any structural check fired.

        A **detection** flag and never a verdict: three of the four checks fire
        on runs that reached no verdict at all, and
        :attr:`~StructuralReport.outcomes` is where the verdicts are.
        """
        return bool(self.alarms)

    @property
    def detection_alarms(self) -> tuple[StructuralAlarm, ...]:
        """tuple of StructuralAlarm: The alarms that are about an adversary.

        Everything except :attr:`StructuralCheck.RUN_SHAPE`, which is a
        statement about the transcript file rather than about anybody's
        behaviour (:ref:`finding 3 <findings>`) and would inflate a Phase 5
        detection column if it were counted as one.
        """
        return tuple(
            alarm
            for alarm in self.alarms
            if alarm.check is not StructuralCheck.RUN_SHAPE
        )

    def summary(self) -> str:
        """Return a short account, with refusals on their own line.

        Returns
        -------
        str
            One line for the family's verdict, one per alarm, then the
            outcomes. Refusals are never folded into a rejection count.
        """
        lines: list[str] = []
        if self.alarms:
            lines.append(
                f"structural: {len(self.alarms)} alarm(s) at eps = "
                f"{self.budget:.3e} "
                f"(false positives <= {self.false_positive_bound:.4e})"
            )
            lines.extend(
                f"  {alarm.check}: {alarm.detail} "
                f"[<= {alarm.false_positive_bound:.4e}]"
                for alarm in self.alarms
            )
        else:
            lines.append(
                f"structural: no alarm at eps = {self.budget:.3e} "
                f"(false positives <= {self.false_positive_bound:.4e})"
            )
        if self.withheld:
            lines.append(
                "withheld (no derivable operating point at this budget): "
                + ", ".join(str(check) for check in sorted(self.withheld))
            )
        lines.append(
            "outcomes: "
            + ", ".join(
                f"{party} {self.outcomes[party].value}"
                for party in sorted(self.outcomes)
            )
        )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "budget": self.budget,
            "thresholds": [
                threshold.to_dict() for threshold in self.thresholds
            ],
            "alarms": [alarm.to_dict() for alarm in self.alarms],
            "withheld": [str(check) for check in self.withheld],
            "false_positive_bound": self.false_positive_bound,
            "outcomes": {
                party: outcome.value
                for party, outcome in self.outcomes.items()
            },
            "attributions": [
                attribution.to_dict() for attribution in self.attributions
            ],
            "count_exchange_timing": self.count_exchange_timing,
            "key_length": self.key_length,
            "alarm_raised": self.alarm_raised,
            "detections": len(self.detection_alarms),
        }


def structural_report(
    stats: TranscriptStatistics, *, eps: float, exact: bool = False
) -> StructuralReport:
    """Apply the whole structural family to one run at one budget.

    Parameters
    ----------
    stats : TranscriptStatistics
        The run, extracted from a JSON round-tripped transcript. Nothing else
        is read, and nothing else can be.
    eps : float
        Keyword-only. The false-positive budget, in ``(0, 1)``. Sweep it to
        build a ROC curve; every point is a derived operating point.
    exact : bool, optional
        Keyword-only. Whether the evidence-abort bound is the exact tail sum
        rather than the closed form. See :func:`evidence_abort_bound`.

    Returns
    -------
    StructuralReport

    Raises
    ------
    TypeError
        If ``stats`` is not a
        :class:`~sih141.detect.statistics.TranscriptStatistics`, ``eps`` is not
        a real number, or ``exact`` is not a :class:`bool`.
    ValueError
        If ``eps`` is outside ``(0, 1)``.

    Examples
    --------
    A recipient forgery on the forwarding hop, which forces
    ``COUNTS_FROM_TWO_DECLARATIONS`` -- a structural reason, so the alarm's
    false-positive probability is exactly zero:

    >>> import numpy as np
    >>> from sih141.attacks.forgery import RecipientForger
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_structural import structural_report
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> from sih141.protocol.verify import MatchedSetTooSmall
    >>> session = QDSSession(
    ...     ProtocolParams(key_length=384),
    ...     rng=np.random.default_rng(800000),
    ...     forwarder=RecipientForger(rng=np.random.default_rng(4242)),
    ... )
    >>> try:
    ...     transcript = session.run(0)
    ... except MatchedSetTooSmall:
    ...     transcript = session.transcript()
    >>> report = structural_report(
    ...     TranscriptStatistics.from_transcript(transcript), eps=1e-9
    ... )
    >>> print(report.summary())
    structural: 1 alarm(s) at eps = 1.000e-09 (false positives <= 1.6263e-19)
      structural-abort: Charlie refused: counts-from-two-declarations [<= 0.0000e+00]
    outcomes: Bob accepted, Charlie refused-to-score

    Charlie refused; he did **not** reject, and the report will not let a table
    say he did:

    >>> report.outcomes["Charlie"] is RunOutcome.REFUSED
    True
    >>> report.outcomes["Charlie"] is RunOutcome.REJECTED
    False
    """
    if not isinstance(stats, TranscriptStatistics):
        raise TypeError(
            f"stats must be a TranscriptStatistics, got "
            f"{type(stats).__name__}. Build one with "
            f"TranscriptStatistics.from_transcript(transcript)."
        )
    budget = _as_budget(eps)
    if not isinstance(exact, bool):
        raise TypeError(f"exact must be a bool, got {type(exact).__name__}")

    thresholds = {
        StructuralCheck.STRUCTURAL_ABORT: structural_abort_threshold(budget),
        StructuralCheck.EVIDENCE_ABORT: evidence_abort_threshold(
            stats.params,
            budget,
            counts_exchanged=stats.counts_exchanged,
            exact=exact,
        ),
        StructuralCheck.REPLAY_REFUSAL: replay_refusal_threshold(budget),
        StructuralCheck.RUN_SHAPE: run_shape_threshold(budget),
    }
    shape = run_shape_violations(stats)
    counts = {
        StructuralCheck.STRUCTURAL_ABORT: stats.aborts.structural,
        StructuralCheck.EVIDENCE_ABORT: stats.aborts.evidence,
        StructuralCheck.REPLAY_REFUSAL: stats.replay.total_refusals,
        StructuralCheck.RUN_SHAPE: len(shape),
    }
    attributions = attribute_aborts(stats)
    details = {
        StructuralCheck.STRUCTURAL_ABORT: "; ".join(
            f"{item.party} refused: {item.reason}"
            for item in attributions
            if item.group == "structural"
        ),
        StructuralCheck.EVIDENCE_ABORT: "; ".join(
            f"{item.party} refused: {item.reason}"
            + (
                f", {item.short_party} short by {item.shortfall}"
                if item.short_party is not None
                else f", short by {item.shortfall}"
            )
            for item in attributions
            if item.group == "evidence"
        ),
        StructuralCheck.REPLAY_REFUSAL: "; ".join(
            f"{party} asked to re-decide a spent round {count} time(s)"
            for party, count in sorted(stats.replay.refusals_by_party.items())
        ),
        StructuralCheck.RUN_SHAPE: "; ".join(shape),
    }

    alarms: list[StructuralAlarm] = []
    withheld: list[StructuralCheck] = []
    bound = 0.0
    for check in STRUCTURAL_CHECKS:
        threshold = thresholds[check]
        if not threshold.admissible:
            withheld.append(check)
            continue
        bound += threshold.false_positive_bound
        if threshold.fires(counts[check]):
            alarms.append(
                StructuralAlarm(
                    check=check,
                    count=counts[check],
                    threshold=threshold,
                    detail=details[check] or "(no detail recorded)",
                )
            )
    return StructuralReport(
        budget=budget,
        thresholds=tuple(thresholds[check] for check in STRUCTURAL_CHECKS),
        alarms=tuple(alarms),
        withheld=tuple(withheld),
        false_positive_bound=min(1.0, bound),
        outcomes=outcomes(stats),
        attributions=attributions,
        count_exchange_timing=stats.count_exchange_timing,
        key_length=stats.key_length,
    )
