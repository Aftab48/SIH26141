"""Phase 4, layer three: the composite rule, and the error rate of the family.

Three families of derived thresholds exist below this one --
:mod:`sih141.detect.thresholds_rate`, :mod:`sih141.detect.thresholds_structural`
and :mod:`sih141.detect.thresholds_channel` -- and each is individually sound.
Firing when **any** of them fires is not. Running many tests inflates the
family-wise error rate, and a naive OR of individually-correct thresholds is
exactly how a detector ends up crying wolf on honest runs while every component
still looks right under inspection. This module is the correction, and the
number it proves is the number the submission quotes.

Convention **D7** applies here with no softening: the correction is *derived*,
its allocation is a choice made before any run exists, and its slack is stated
rather than absorbed. Nothing in this file was chosen because it separated
attack data, and there is no argument through which attack data could reach it
-- :func:`detect` is a pure function of ``(stats, eps, the two null noise
levels)`` and the deduction table of :ref:`C-5 <c5>` is written from the
protocol's mechanics.

.. _c1:

(C-1) The correction: a union bound, and why not something cleverer
-------------------------------------------------------------------
The composite fires iff any member of any family fires, so

.. code-block:: text

    P(detect | honest)  =  P(union of member events)
                        <= sum over members of P(member fires | honest)
                        <= sum over members of (that member's proven bound)

which needs no independence and gets none. The three families are dependent by
construction: the rate family and the structural family both read the matched
counts (``matched_count_low`` and the evidence-abort floors are two readings of
the same integer), and every channel screen on a run shares the symmetrisation
coins with every rate member. So:

* **Sidak** -- ``1 - (1 - eps)**(1/m)`` -- is sharper than Bonferroni by a
  factor of about ``1 + eps/2`` and needs the tests to be **independent**. They
  are not, the gain at ``eps = 1e-9`` is in the eleventh significant figure,
  and buying it would cost an assumption this scheme does not make anywhere
  else.
* **Holm** and **Simes** need ``p``-values. A derived threshold does not have
  one: it has a *bound* on a tail, which is an inequality rather than an
  equality, and a step-down procedure fed upper bounds in place of ``p``-values
  is not the procedure whose level was proven. There is nowhere to get the
  ``p``-values from either -- four of the members are point masses whose only
  attainable ``p`` is ``0`` or ``1``.
* **Choosing fewer tests** would be sharper still and is the one route that is
  forbidden outright: dropping the members that stayed quiet on the runs we
  have is fitting, and dropping members whose *null* is degenerate is already
  done, inside each family, before this layer sees them.

So the correction is the union bound. Its slack is real and is stated in
:ref:`C-4 <c4>` rather than hidden.

.. _c2:

(C-2) The allocation, and why it is not three equal thirds
-----------------------------------------------------------
A union bound constrains only that the shares **sum** to ``eps``; how they are
divided is free, and the division is made before any data exists, which is what
keeps it on the right side of D7. Dividing evenly is the reflex, and here it is
provably wasteful in one place.

The structural family's proven bound **does not depend on its share.** Three of
its four checks are point masses whose false-positive probability is exactly
zero at every budget; the fourth, evidence-abort, has bound ``B_evid(n)``, a
function of the sifted length and of whether Phase C' ran, and of nothing else
(:func:`~sih141.detect.thresholds_structural.evidence_abort_bound`). Its share
decides one thing only: whether that check is **admissible**, which it is iff
``B_evid(n) <= share``. Handing the family more than ``B_evid(n)`` therefore
buys nothing at all, while taking that budget away from the two families whose
thresholds *do* move with it costs sensitivity.

.. code-block:: text

    eps_struct = min(B_evid(n), eps / 3)
    eps_rate   = eps_chan = (eps - eps_struct) / 2

    sum = eps_struct + 2 (eps - eps_struct) / 2 = eps            (exact)

The cap at ``eps / 3`` is what makes this never worse than the even split: the
structural share is at most a third, so each of the other two receives at least
``(eps - eps/3)/2 = eps/3``. At :data:`~sih141.protocol.params.DEFAULT_PARAMS`
``B_evid = 1.6263e-19``, so at any budget a report would use the structural
family is free to four significant figures and the split is a half each.

.. _c3:

(C-3) Four links, and a roster fixed rather than sized to the run
------------------------------------------------------------------
The channel share is divided again, evenly over
:data:`LINK_ROSTER` -- two recipients times two message bits --
by :func:`~sih141.detect.thresholds_channel.divide_budget`, and each screen
then divides its own share over the members that run's check plan makes
evaluable (:func:`~sih141.detect.thresholds_channel.screen_link` argues that
step).

The roster is **four whether or not the run publishes four**, for the reason
:ref:`D-4 <sih141.detect.thresholds_rate:d4>` fixes the rate roster at twelve:
a roster sized to the run makes each member's budget a function of the data. A
run that publishes fewer links -- every run with ``check_fraction = 0``
publishes none -- simply has members that cannot fire, and a union bound over a
superset of the events is still a bound. The cost is that on a run with no
check rounds **half the composite budget is unspendable**, which shows up in
:ref:`C-4 <c4>` as extra slack and is reported rather than reclaimed.

.. _c4:

(C-4) The slack, measured and stated
-------------------------------------
The composite proves the **sum of what its members prove**, which is not
``eps``. At ``L = 384`` with ``check_fraction = 0.25`` and ``eps = 1e-9``:

============================ =============== ==============================
part                          proven bound    where it goes
============================ =============== ==============================
rate family (12 members)      ``2.3964e-10``  10 live members at ``eps/24``
structural family (4)         ``1.6263e-19``  1 live member, 3 point masses
channel family (4 screens)    ``1.0000e-10``  1 live member per screen
**composite**                 ``3.3964e-10``  against a budget of ``1e-9``
============================ =============== ==============================

a slack factor of ``2.944``. Three things spend it, and all three are
point-mass nulls that cost nothing and prove nothing:

* the two ``mismatch_rate`` members are exactly zero under the noiseless null;
* three of the four structural checks and the free ``declaration_gap`` test are
  exactly zero at every budget;
* four of the five members of every channel screen are point masses, so a
  screen costs what CHSH alone costs -- one fifth of its share.

Quoting ``eps`` where the composite proves ``3.3964e-10`` would overstate the
detector's own false-positive rate by a factor of three. Both numbers are on
:class:`Detection`; :attr:`Detection.false_positive_bound` is the proven one
and the one a ROC point belongs at.

**And the number that says the correction is not decoration.** Score the same
three families with no correction at all -- every member at the full ``eps``,
which is exactly what an OR of individually-sound thresholds is -- and the same
run proves ``1.3442e-09`` against a budget of ``1e-9``. It overspends by a
third; every component still looks correct under inspection, and nothing inside
any of them would ever say so. The comparison is doctested below.

.. _c5:

(C-5) Discrimination: a deduction table, not a classifier
----------------------------------------------------------
Detection says *something was wrong*. Phase 3's constraint 5 is that
``transcript.repudiated`` cannot say **what**: plain depolarising noise at
``p = 0.10`` produced ``repudiated == True`` with a completely honest Alice.
The discriminator that works is Charlie's matched count, and this layer
generalises that observation into a table -- with the emphasis on *table*.
:data:`HYPOTHESIS_TABLE` **contains no numbers**, every row carries the
mechanism it was read off, and each of those mechanisms is a sentence in a
module this file does not own. What that buys is the thing D7 is about: there is
no quantity here that attack data could have chosen, because there is no
quantity here at all. (Two rows *were* wrong when first written, and the arms
found them; both fixes are in the journal, both changed the shape of a deduction
rather than a number, and both are justified by a quotable sentence in the
module the mechanism lives in.)

Three relations per hypothesis, and the second is the load-bearing one:

**predicts.** Signal kinds this position in the threat model produces by
construction. A hypothesis with a fired signal it predicts, and none it leaves
intact, is reported ``SUPPORTED``.

**leaves intact.** Signal kinds whose *null this position does not disturb*.
This is deliberately a stronger and more checkable claim than "cannot cause".
If hypothesis ``H`` leaves signal ``S``'s null intact, then ``P(S fires | H)``
is bounded by the same ``b_S`` that bounds it under the honest null -- so
observing ``S`` **excludes** ``H``, and excludes it wrongly with probability at
most ``b_S``. An exclusion in this module therefore carries a derived
confidence, computed from the thresholds that did the excluding, rather than an
assertion.

**requires.** A subset of *predicts*: kinds this position produces with
probability essentially one. A run on which one of them was **evaluated and did
not fire** is a run this position does not explain, and the hypothesis is
reported ``UNSUPPORTED`` -- withheld, never ``EXCLUDED``, because a signal that
did not fire carries no bound, only a false-negative statement nothing in this
project derives. Only two rows have a requirement, both definitional; a
requirement read off a particular adversary *object's* parameters would be that
object's behaviour wearing a derivation's clothes, and there is none. The clause
is waived entirely on a run where some verifier reached no verdict
(:func:`_requirement_kinds`).

The mechanics behind the table, each a reading of code this module does not
own:

1. **The matched set is decided by basis agreement**, between Alice's declared
   bases and the recipient's recorded ones
   (:mod:`sih141.protocol.keys`). A trace-preserving map on the entanglement
   resource acts on the teleported *eigenstate*. It cannot move a basis, so it
   cannot move a matched count, a declared count, a pooled count, a floor or
   any bookkeeping equality. **Every channel adversary leaves all of those
   nulls intact.** (This is the same fact that makes ``wings_agree`` a
   non-signal -- Phase 3's constraint 2.)
2. **A declaration drawn independently of the records leaves the matched
   count's law exactly ``Binomial(n, 1/|B|)``.** An outside forger draws a
   fresh key and knows nothing (:class:`~sih141.attacks.forgery.OutsideForger`
   is built that way on purpose); a seam impersonator declares her own key. So
   both leave every count null intact and disturb only the eigenvalues at
   positions that do match.
3. **A recipient forging on the forwarding hop declares from his own raw log**,
   which after Phase A' is roughly half of what the receiving verifier now
   holds, so the receiving verifier's matched count moves from ``n/3`` to
   ``2n/3`` -- ``9.80`` honest standard deviations at ``n = 192`` and ``240``
   at :data:`~sih141.protocol.params.DEFAULT_PARAMS`
   (:func:`~sih141.detect.thresholds_rate.forgery_separation_sigma`). That is
   Phase 3's constraint 5, as a prediction rather than as an observation.
4. **A count starver lies about one integer on the wire** and about nothing
   else: his own scored matched count is untouched, so the wire integer and the
   scored one part company, and the direction is downward by construction.
5. **The ledger records a re-ask and nothing else does.** A replay refusal or a
   ``session-identifier-mismatch`` needs a round to be presented twice, which
   no other seam in the model does. It is **predicted and not required**: the
   structural family's finding 4 says the ledger check is sound in one
   direction only, and
   :class:`~sih141.attacks.replay.ReplayingForwarder` says the session rebinds
   whatever a forwarder returns to the live round, so a replayed declaration
   can reach a verifier with no ledger entry spent at all.
6. **Two refusal reasons implicate two different seams, and the table keeps
   them apart.** :mod:`sih141.protocol.verify` draws the line itself: of
   ``counterpart-count-of-unrecorded-provenance`` it says *the party who
   supplies that count is an adversary in this threat model*, and of
   ``counts-from-two-declarations`` it says *the adversary here is Bob -- or
   whoever holds the Bob-to-Charlie hop*. So the first is
   :attr:`SignalKind.DECLARATION_CONFLICT`, a count-exchange seam, and the
   second is :attr:`SignalKind.FORWARDING_TAMPER`, a forwarding hop; a count
   starver leaves the second's null intact and a forging recipient produces it.
   Lumping the two into one kind would leave those two positions unable to
   exclude each other on the one signal that separates them.

**And one thing the table deliberately does not do.** ``MISMATCH`` and
``CHANNEL`` never appear in any *leaves intact* set except the **null's own**,
because a merely **noisy honest link** produces both -- finding F6 of the rate
family measured six of twelve honest runs at ``p = 0.03`` firing the
noiseless-null mismatch threshold while both verifiers accepted. A table that
excluded an *adversary* hypothesis on those two kinds would be excluding it on
the channel's noise level, and
:class:`HypothesisPredicate` refuses to be constructed that way. For the null
itself the exception is required and is the point: a mismatch firing *is* the
departure the threshold was built to bound, and excluding the honest hypothesis
on it -- with that threshold's own proven bound -- is what the word "detection"
means here.

.. _c6:

(C-6) What cannot be discriminated, said rather than guessed
-------------------------------------------------------------
**Full impersonation is undetectable by construction.** Mallory runs the
protocol correctly with a key pair of her own, so every statistic on the
transcript is drawn from the honest law and no derived threshold can fire.
:attr:`Hypothesis.IMPERSONATION_FULL` is therefore reported with status
:attr:`Support.UNDETECTABLE` on **every** run -- never supported, never
excluded -- carrying assumption **(AUTH)** in its rationale. That is Phase 3's
constraint 7, kept as an entry in the report rather than as a hole in it: a
hypothesis that is silently missing from a table reads as a hypothesis that was
ruled out.

**Three hypotheses share one signature and are not separable.** An outside
forger, a signing-seam impersonator and a distribution-seam impersonator all
present as *a declaration that disagrees with the records at matched positions,
with every count null intact*. This is not an accident of our implementation:
:class:`~sih141.attacks.impersonation.ImpersonationScope` says in its own
docstring that the signing scope **is** the external forger of
:mod:`sih141.protocol.analysis` section 3, reached by seizing a seam rather
than by guessing. :attr:`Attribution.indistinguishable_from` names the group on
every one of them, so a Phase 5 table cannot report one of the three as if the
transcript had picked it out.

**An exclusion is bounded; an attribution is not.** ``P(S fires | H)`` has a
null and therefore a bound, which is what makes *excluding* a hypothesis a
derived act. "Adversary A rather than adversary B" has no null, so there is no
inequality to invert and no honest number to quote. What
:attr:`Attribution.false_positive_bound` reports on a **supported** hypothesis
is a statement against the *honest* null only -- an honest run trips all of
this evidence with probability at most this -- and its docstring says so in
those words, because a reader who took it for ``P(wrong adversary)`` would be
quoting a number nothing in this project derives.

.. _c7:

(C-7) A run-shape violation is not a detection
-----------------------------------------------
:attr:`~sih141.detect.thresholds_structural.StructuralCheck.RUN_SHAPE` fires on
a transcript *file* that the shipped session could not have written -- a
default-valued ``spent_rounds`` on a file older than the replay ledger, say.
:attr:`~sih141.detect.thresholds_structural.StructuralReport.detection_alarms`
excludes it for that reason and so does this layer:
:attr:`Signal.is_detection` is ``False`` on it, it is left out of
:attr:`Detection.detected` and out of the deduction table, and it is still
listed on :attr:`Detection.signals` so it cannot be lost. Its bound is exactly
zero, so keeping it inside the union bound costs nothing.

.. _findings:

Findings
--------
**G1. Half the budget is unspendable on a run with no check rounds**, and the
roster is not resized to reclaim it (:ref:`C-3 <c3>`). The composite then
proves the rate family's union bound and nothing else -- ``2.6499e-10`` at
``L = 192``, ``eps = 1e-9``, a slack factor of ``3.77`` against the ``2.944``
of the checked run in :ref:`C-4 <c4>`; both are doctested below. The
alternative is a budget split that is a function of the run's configuration,
and while that configuration is a constant *under the null*, it is not a
constant under an adversary: a distributor who suppressed the check plan would
be choosing the detector's own allocation. Fixing the roster costs about a
third in the reported slack and removes that route entirely.

**G2. Two of the eight in-model positions are named alone; the rest are named
in groups, and the groups are structural rather than accidental.** Measured on
twenty runs per arm at ``L = 384``, ``eps = 1e-9``, once every threshold and
every row was frozen:

* **count starvation** is named alone, 20/20. A count in the lower tail plus an
  evidence abort is out of reach of every position except the count-exchange
  seam.
* **recipient forgery under COUNTS_AFTER_FORWARDING** is named alone, 20/20 --
  Phase 3's constraint 5 restated as a property of the detector, and the arm
  where it earns its keep is the *channel* one: a depolariser is never named a
  recipient forgery, because that row requires an inflated count and a channel
  adversary moves no basis.
* **recipient forgery under COUNTS_BEFORE_FORWARDING** and the **replaying
  forwarder** are named together, 20/20 each. Both hold the Bob-to-Charlie hop
  and the only evidence is that the hop produced a second declaration; from a
  transcript there is nothing further to say.
* **outside forgery, signing-seam impersonation, distribution-seam
  impersonation and channel manipulation** are one group of five (replay joins
  it), 20/20 each. The first three are one signature by construction
  (:ref:`C-6 <c6>`); channel manipulation is separated from them only in the
  direction that *fires* -- a clear channel screen never excludes a channel
  adversary, because this module bounds false positives and never false
  negatives, and a noisy honest link fires the same members.
* **full impersonation** is 0/20, correctly, and is reported as an assumption.

The group of five is where a fitted detector would have shown a better table,
and where this one declines to. What separates its members is the *amount* of
evidence, not a null: with check rounds a depolariser backs channel
manipulation with five signals and a signer-seam forger backs it with one.
:attr:`Attribution.supporting` carries that; a score built from it would be a
classifier, and no such field exists.

**G3. There is no false-negative bound anywhere in this layer, and there cannot
be one from a transcript.** Every bound here is under the honest null. A
detection rate against a named adversary is a *measurement*, reported with its
sample size and grouped by ``count_exchange_timing``
(:ref:`constraint 6 <sih141.detect.thresholds_rate:findings>`), and it is not a
guarantee. Where a rate disappoints, that is a finding about the protocol's
observability and not a licence to move a threshold.

Notes
-----
Determinism (D3)
    Nothing here draws randomness; there is no ``rng`` argument because there is
    nothing to draw for.
No machine learning (D4)
    A union bound, one division, and a static table of implications read off the
    protocol. There is no fitted quantity in this file and no place to put one.
Reads (the boundary)
    A :class:`~sih141.protocol.session.SessionTranscript` **round-tripped
    through JSON**, via :class:`~sih141.detect.statistics.TranscriptStatistics`.
    Never a session, never an adversary, never any harness state.

Examples
--------
An honest run, scored at a budget rather than at a pile of constants:

>>> import numpy as np
>>> from sih141.detect.detector import detect
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> transcript = QDSSession(
...     ProtocolParams(key_length=384, check_fraction=0.25),
...     rng=np.random.default_rng(7),
... ).run(0)
>>> result = detect(transcript, eps=1e-9)
>>> result.detected, result.signals
(False, ())
>>> f"{result.false_positive_bound:.4e}"
'3.3964e-10'

The proven bound is what the members prove; the budget is what they were
allowed to spend, and the gap between the two is :ref:`C-4 <c4>`:

>>> f"{result.slack_factor:.3f}"
'2.944'

The three parts of that bound, which is the :ref:`C-4 <c4>` table:

>>> import math
>>> from sih141.detect.statistics import TranscriptStatistics
>>> from sih141.detect.thresholds_channel import screen_link
>>> from sih141.detect.thresholds_rate import RateCountThresholds
>>> from sih141.detect.thresholds_structural import structural_report
>>> stats = TranscriptStatistics.from_transcript(transcript)
>>> split = result.budget
>>> family = RateCountThresholds.for_transcript(stats, eps=split.rate)
>>> f"{family.per_test_budget:.4e}"
'4.1667e-11'
>>> family.per_test_budget == split.rate / 12 and split.rate < 1e-9 / 2
True
>>> f"{family.evaluate(stats).false_positive_bound:.4e}"
'2.3964e-10'
>>> f"{structural_report(stats, eps=split.structural).false_positive_bound:.4e}"
'1.6263e-19'
>>> screens = [
...     screen_link(link, epsilon=split.per_link)
...     for link in stats.links.values()
... ]
>>> f"{math.fsum(s.false_positive_bound for s in screens):.4e}", len(screens)
('1.0000e-10', 4)

The corrected composite against the uncorrected OR of the same members, on the
same run -- as arithmetic rather than as a warning:

>>> naive = math.fsum(
...     (
...         RateCountThresholds.for_transcript(stats, eps=1e-9)
...         .evaluate(stats)
...         .false_positive_bound,
...         structural_report(stats, eps=1e-9).false_positive_bound,
...         *(
...             screen_link(link, epsilon=1e-9).false_positive_bound
...             for link in stats.links.values()
...         ),
...     )
... )
>>> f"{naive:.4e}", naive > 1e-9
('1.3442e-09', True)

On a run with no check rounds the whole channel half of the budget is
unspendable, and the slack widens to match (finding G1):

>>> bare = detect(
...     QDSSession(
...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
...     ).run(0),
...     eps=1e-9,
... )
>>> f"{bare.false_positive_bound:.4e}", f"{bare.slack_factor:.2f}"
('2.6499e-10', '3.77')

Which hypothesis the run is consistent with, and the one that is never named
either way:

>>> result.named
(<Hypothesis.HONEST: 'honest'>,)
>>> result.attribution(Hypothesis.IMPERSONATION_FULL).status
<Support.UNDETECTABLE: 'undetectable-by-construction'>
"""

from __future__ import annotations

import enum
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from sih141.detect.statistics import TranscriptStatistics
from sih141.detect.thresholds_channel import (
    ChannelScreen,
    divide_budget,
    screen_link,
)
from sih141.detect.thresholds_rate import (
    RATE_COUNT_FREE_TESTS,
    RateCountThresholds,
    RateCountVerdict,
)
from sih141.detect.thresholds_structural import (
    RunOutcome,
    StructuralCheck,
    StructuralReport,
    evidence_abort_bound,
    structural_report,
)
from sih141.protocol.params import ProtocolParams
from sih141.protocol.session import SessionTranscript
from sih141.protocol.verify import AbortReason

__all__ = [
    "DETECTOR_FAMILIES",
    "HYPOTHESES",
    "HYPOTHESIS_TABLE",
    "LINK_ROSTER",
    "SIGNATURE_SUBSTITUTION_GROUP",
    "Attribution",
    "Detection",
    "FamilyBudget",
    "Hypothesis",
    "HypothesisPredicate",
    "Signal",
    "SignalKind",
    "Support",
    "detect",
    "family_budget",
]


#: The three families the composite is a union over, in the order a report
#: lists them. Fixed as a constant so that a family added below without a
#: budget of its own fails a test instead of being summed into
#: :attr:`Detection.false_positive_bound` for free.
DETECTOR_FAMILIES: Final[tuple[str, ...]] = ("rate", "structural", "channel")

#: The channel family's roster: two recipients times two message bits. **Fixed
#: at four whether or not the run publishes four** -- see :ref:`C-3 <c3>`. A
#: run with no check rounds publishes none of them, which only shrinks the
#: event the union bound is taken over.
LINK_ROSTER: Final[tuple[tuple[str, int], ...]] = (
    ("Bob", 0),
    ("Bob", 1),
    ("Charlie", 0),
    ("Charlie", 1),
)

#: Relative tolerance allowed when checking that the composite's proven bound
#: has not exceeded its budget. Not a threshold and not tunable: it exists
#: because the three family bounds are summed in floating point and a sum of
#: ten terms can land one unit in the last place above a budget it provably
#: does not exceed. A real excess is orders of magnitude, not ulps.
_BOUND_SLACK: Final[float] = 1e-12


class SignalKind(enum.StrEnum):
    """What a fired threshold says, in the vocabulary the table is written in.

    Seven kinds, chosen so that each one names a *mechanism* rather than a
    module: the deduction table of :ref:`C-5 <c5>` reasons about what an
    adversary can reach, and "the verifier's mismatch count is in the upper
    tail" is reachable from three different families' worth of thresholds.

    Attributes
    ----------
    MISMATCH
        A verifier's mismatch count ``e_R`` in the upper tail. Produced by any
        adversary who disturbs the eigenvalues at matched positions -- **and by
        a merely noisy honest link**, which is why it never excludes anything.
    COUNT_HIGH
        A matched, declared or pooled count in the **upper** tail. The
        recipient-forgery tail (constraint 5), and the one signal that
        separates a forging recipient from channel noise.
    COUNT_LOW
        A matched, declared or pooled count in the **lower** tail. The
        evidence-denial tail.
    EVIDENCE_SHORTFALL
        A refusal whose reason names a matched-count floor.
    DECLARATION_CONFLICT
        The Phase C' wire count and the count a verdict scored do not agree, or
        a count arrived without saying which declaration it was computed
        against. Both are acts of the **count-exchange seam**, which
        :mod:`sih141.protocol.verify` names as the adversary that supplies the
        count.
    FORWARDING_TAMPER
        A counterpart's count was computed against a *different declaration*
        from the one this verifier is scoring
        (:attr:`~sih141.protocol.verify.AbortReason.COUNTS_FROM_TWO_DECLARATIONS`).
        Two declarations existed in one run, which takes the **forwarding
        hop**: :mod:`sih141.protocol.verify` says so in as many words -- the
        adversary there is Bob, or whoever holds the Bob-to-Charlie hop.
    LEDGER
        A round presented twice: a replay refusal, a session identifier that
        does not bind, or a record already verified.
    CHANNEL
        Any member of the per-link channel screen -- QBER, CHSH, fidelity,
        purity, concurrence. **Also produced by a noisy honest link**, so like
        ``MISMATCH`` it supports and never excludes.
    FILE_SHAPE
        A run-shape violation: a statement about the transcript *file* and not
        about an adversary (:ref:`C-7 <c7>`). Carried, never counted as a
        detection, and absent from the table.

    Examples
    --------
    >>> from sih141.detect.detector import SignalKind
    >>> SignalKind.COUNT_HIGH
    <SignalKind.COUNT_HIGH: 'count-high'>
    >>> f"{SignalKind.LEDGER}"
    'ledger'
    """

    MISMATCH = "mismatch"
    COUNT_HIGH = "count-high"
    COUNT_LOW = "count-low"
    EVIDENCE_SHORTFALL = "evidence-shortfall"
    DECLARATION_CONFLICT = "declaration-conflict"
    FORWARDING_TAMPER = "forwarding-tamper"
    LEDGER = "ledger"
    CHANNEL = "channel"
    FILE_SHAPE = "file-shape"


#: The two kinds a noisy honest link produces on its own, and which therefore
#: never appear in any hypothesis's *leaves intact* set (:ref:`C-5 <c5>`). Named
#: rather than remembered, because the table is checked against this set by a
#: test: a future kind added to a *leaves intact* set by mistake would turn the
#: channel's noise level into an exclusion.
_NOISE_REACHABLE: Final[frozenset[SignalKind]] = frozenset(
    {SignalKind.MISMATCH, SignalKind.CHANNEL}
)

#: The kind that is not about an adversary at all (:ref:`C-7 <c7>`).
_NOT_A_DETECTION: Final[frozenset[SignalKind]] = frozenset(
    {SignalKind.FILE_SHAPE}
)


class Hypothesis(enum.StrEnum):
    """One position in the threat model, plus the honest one.

    A :class:`enum.StrEnum` so a hypothesis drops into a Phase 5 table and
    through :func:`json.dumps` without an encoder, like
    :class:`~sih141.detect.thresholds_structural.RunOutcome` beside it.

    Attributes
    ----------
    HONEST
        The run is the run the nulls describe. Excluded by any detection
        signal, and the exclusion carries the bound that makes it a detection.
    OUTSIDE_FORGERY
        Eve on the signer seam: a fresh key, declared, knowing nothing.
    IMPERSONATION_SIGNING
        Mallory holding Phase B only. **The same signature as
        ``OUTSIDE_FORGERY``** -- :ref:`C-6 <c6>`.
    IMPERSONATION_DISTRIBUTION
        Mallory holding Phase A only. Same signature again.
    IMPERSONATION_FULL
        Mallory holding both seams. Out of model by assumption **(AUTH)** and
        reported :attr:`Support.UNDETECTABLE` on every run.
    RECIPIENT_FORGERY
        A recipient forging on the forwarding hop, from his own raw log.
    COUNT_STARVATION
        A recipient understating the integer he puts on the wire in Phase C'.
    REPLAY
        A forwarder re-presenting a declaration into a round already decided.
    CHANNEL_MANIPULATION
        An adversary acting on the entanglement resource or the payload line.

    Examples
    --------
    >>> from sih141.detect.detector import Hypothesis
    >>> Hypothesis.RECIPIENT_FORGERY
    <Hypothesis.RECIPIENT_FORGERY: 'recipient-forgery'>
    >>> f"{Hypothesis.IMPERSONATION_FULL}"
    'impersonation-full'
    """

    HONEST = "honest"
    OUTSIDE_FORGERY = "outside-forgery"
    IMPERSONATION_SIGNING = "impersonation-signing-seam"
    IMPERSONATION_DISTRIBUTION = "impersonation-distribution-seam"
    IMPERSONATION_FULL = "impersonation-full"
    RECIPIENT_FORGERY = "recipient-forgery"
    COUNT_STARVATION = "count-starvation"
    REPLAY = "replay"
    CHANNEL_MANIPULATION = "channel-manipulation"


#: The order a report lists hypotheses in. Written out rather than derived from
#: the enum so that a member added upstream without a row in
#: :data:`HYPOTHESIS_TABLE` fails a test rather than disappearing from every
#: report -- the same trade
#: :data:`~sih141.detect.thresholds_structural.STRUCTURAL_CHECKS` makes.
HYPOTHESES: Final[tuple[Hypothesis, ...]] = (
    Hypothesis.HONEST,
    Hypothesis.OUTSIDE_FORGERY,
    Hypothesis.IMPERSONATION_SIGNING,
    Hypothesis.IMPERSONATION_DISTRIBUTION,
    Hypothesis.IMPERSONATION_FULL,
    Hypothesis.RECIPIENT_FORGERY,
    Hypothesis.COUNT_STARVATION,
    Hypothesis.REPLAY,
    Hypothesis.CHANNEL_MANIPULATION,
)

#: The three hypotheses that present identically from a transcript
#: (:ref:`C-6 <c6>`). Named as a constant so that
#: :attr:`Attribution.indistinguishable_from` is one lookup rather than three
#: places to get out of step.
SIGNATURE_SUBSTITUTION_GROUP: Final[tuple[Hypothesis, ...]] = (
    Hypothesis.OUTSIDE_FORGERY,
    Hypothesis.IMPERSONATION_SIGNING,
    Hypothesis.IMPERSONATION_DISTRIBUTION,
)


class Support(enum.StrEnum):
    """What the observed signals say about one hypothesis.

    Four values, and the difference between the second and the third is the
    whole reason this is not a boolean. "Nothing supports it" and "the evidence
    rules it out" are different statements with different bounds behind them,
    and a detector that reported them with one flag would be claiming the
    second every time it meant the first.

    Attributes
    ----------
    SUPPORTED
        At least one fired signal is one this hypothesis predicts, and no fired
        signal is one whose null it leaves intact.
    UNSUPPORTED
        Nothing fired that it predicts, and nothing fired that excludes it.
        **Not a rejection of the hypothesis.**
    EXCLUDED
        A signal fired whose null this hypothesis leaves intact, so under the
        hypothesis that signal fires with probability at most its own proven
        bound -- which is
        :attr:`Attribution.false_positive_bound` on this attribution.
    UNDETECTABLE
        Reserved for :attr:`Hypothesis.IMPERSONATION_FULL`, which assumption
        **(AUTH)** puts out of model. Never supported and never excluded, on
        any run (:ref:`C-6 <c6>`).

    Examples
    --------
    >>> from sih141.detect.detector import Support
    >>> Support.EXCLUDED
    <Support.EXCLUDED: 'excluded'>
    >>> f"{Support.UNDETECTABLE}"
    'undetectable-by-construction'
    """

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    EXCLUDED = "excluded"
    UNDETECTABLE = "undetectable-by-construction"


@dataclass(frozen=True)
class HypothesisPredicate:
    """One row of the deduction table: what a position produces, and what not.

    Attributes
    ----------
    predicts : frozenset of SignalKind
        Kinds this position produces by construction.
    requires : frozenset of SignalKind
        Kinds this position produces **with probability essentially one**, so
        that a run on which one of them was evaluated and did not fire is a run
        this position does not explain. A subset of :attr:`predicts`, and kept
        deliberately small: only requirements that follow from the *definition*
        of the position go in, never one read off a particular adversary
        object's parameters, which would be that object's behaviour wearing a
        derivation's clothes. Enforced only when every verifier reached a
        verdict -- see :attr:`Detection.requirements_enforced`.
    leaves_intact : frozenset of SignalKind
        Kinds whose **null this position does not disturb**. Observing one of
        them excludes the hypothesis, wrongly with probability at most that
        signal's own proven bound. Never contains ``MISMATCH`` or ``CHANNEL``:
        a noisy honest link produces both, so excluding on either would be
        excluding on the channel's noise level (:ref:`C-5 <c5>`).
    mechanism : str
        Why, in one sentence, read off the protocol rather than off any run.
    detectable : bool
        ``False`` only for :attr:`Hypothesis.IMPERSONATION_FULL`.
    is_null : bool
        ``True`` only on :attr:`Hypothesis.HONEST`, which **is** the null every
        threshold was derived against. The null row is the one row allowed to
        be excluded on ``MISMATCH`` and ``CHANNEL``: for an adversary
        hypothesis, excluding on those would be excluding on the link's noise
        level, but for the null itself a mismatch firing *is* the departure the
        threshold was built to bound, and it is excluded with exactly that
        threshold's proven bound. Where the null was mis-stated -- a noiseless
        null over a genuinely noisy honest link -- that exclusion is a false
        positive, which is finding F6 of the rate family and is reported rather
        than prevented.

    Raises
    ------
    ValueError
        If ``predicts`` and ``leaves_intact`` overlap -- a kind cannot be both
        produced and left alone -- if ``requires`` is not a subset of
        ``predicts``, if ``leaves_intact`` names a kind a noisy honest link
        reaches on a row that is not the null, or if ``mechanism`` is empty.

    Examples
    --------
    >>> from sih141.detect.detector import HYPOTHESIS_TABLE, Hypothesis
    >>> row = HYPOTHESIS_TABLE[Hypothesis.CHANNEL_MANIPULATION]
    >>> sorted(str(kind) for kind in row.predicts)
    ['channel', 'mismatch']
    >>> 'count-high' in {str(kind) for kind in row.leaves_intact}
    True
    """

    predicts: frozenset[SignalKind]
    leaves_intact: frozenset[SignalKind]
    mechanism: str
    requires: frozenset[SignalKind] = frozenset()
    detectable: bool = True
    is_null: bool = False

    def __post_init__(self) -> None:
        """Refuse a row that contradicts itself or excludes on noise."""
        object.__setattr__(self, "predicts", frozenset(self.predicts))
        object.__setattr__(
            self, "leaves_intact", frozenset(self.leaves_intact)
        )
        object.__setattr__(self, "requires", frozenset(self.requires))
        object.__setattr__(self, "mechanism", str(self.mechanism))
        object.__setattr__(self, "detectable", bool(self.detectable))
        object.__setattr__(self, "is_null", bool(self.is_null))
        both = self.predicts & self.leaves_intact
        if both:
            raise ValueError(
                f"a hypothesis cannot both produce and leave intact "
                f"{sorted(str(kind) for kind in both)}: the first says the "
                f"signal is evidence for it and the second says the signal "
                f"excludes it."
            )
        unpredicted = self.requires - self.predicts
        if unpredicted:
            raise ValueError(
                f"requires must be a subset of predicts, and "
                f"{sorted(str(kind) for kind in unpredicted)} is not: a kind "
                f"a position produces with probability one is a kind it "
                f"produces."
            )
        noisy = self.leaves_intact & _NOISE_REACHABLE
        if noisy and not self.is_null:
            raise ValueError(
                f"{sorted(str(kind) for kind in noisy)} cannot be in a "
                f"leaves_intact set on a row that is not the null: a "
                f"merely noisy honest link produces them, so excluding an "
                f"adversary hypothesis on one would be excluding it on the "
                f"channel's noise level. The null row itself may -- that "
                f"exclusion is the detection. See C-5, and finding F6 of the "
                f"rate family."
            )
        if not self.mechanism:
            raise ValueError(
                "a row of the deduction table must carry the mechanism it was "
                "read off, or it is a rule somebody chose (D7)."
            )


#: Every count and bookkeeping kind -- the ones a channel adversary and a
#: signature substitution both leave alone. Assembled once so the two rows that
#: use it cannot drift apart.
_CLASSICAL_KINDS: Final[frozenset[SignalKind]] = frozenset(
    {
        SignalKind.COUNT_HIGH,
        SignalKind.COUNT_LOW,
        SignalKind.EVIDENCE_SHORTFALL,
        SignalKind.DECLARATION_CONFLICT,
        SignalKind.FORWARDING_TAMPER,
        SignalKind.LEDGER,
    }
)

_SUBSTITUTION_ROW: Final[HypothesisPredicate] = HypothesisPredicate(
    predicts=frozenset({SignalKind.MISMATCH}),
    requires=frozenset({SignalKind.MISMATCH}),
    leaves_intact=_CLASSICAL_KINDS,
    mechanism=(
        "a declaration drawn independently of the recipients' records leaves "
        "the matched count's law exactly Binomial(n, 1/|B|) and touches no "
        "wire integer, no forwarding hop and no ledger; only the eigenvalues "
        "at positions that do match are disturbed, and each of those survives "
        "with probability 1/2 "
        "(sih141.protocol.analysis.FORGER_MATCHED_MISMATCH_PROBABILITY), so "
        "the mismatch count is zero with probability 2**-|M_R| and the "
        "signal is required rather than merely predicted"
    ),
)

#: The deduction table of :ref:`C-5 <c5>`. **No numbers, and no row was
#: adjusted after an arm was run.** Each entry is a reading of the protocol's
#: mechanics, and the mechanism is carried on the row so a reviewer can check
#: it against the module it was read from.
HYPOTHESIS_TABLE: Final[Mapping[Hypothesis, HypothesisPredicate]] = {
    Hypothesis.HONEST: HypothesisPredicate(
        predicts=frozenset(),
        leaves_intact=frozenset(SignalKind) - _NOT_A_DETECTION,
        is_null=True,
        mechanism=(
            "the honest run is the run every null in this package describes, "
            "so every threshold fires on it with at most its own proven "
            "bound; this is the one row that may be excluded on a mismatch or "
            "a channel signal, because for the null itself those are the "
            "departure the threshold was built to bound rather than the "
            "channel's noise level"
        ),
    ),
    Hypothesis.OUTSIDE_FORGERY: _SUBSTITUTION_ROW,
    Hypothesis.IMPERSONATION_SIGNING: _SUBSTITUTION_ROW,
    Hypothesis.IMPERSONATION_DISTRIBUTION: _SUBSTITUTION_ROW,
    Hypothesis.IMPERSONATION_FULL: HypothesisPredicate(
        predicts=frozenset(),
        leaves_intact=frozenset(),
        detectable=False,
        mechanism=(
            "Mallory runs the protocol correctly with a key pair of her own, "
            "so every statistic on the transcript is drawn from the honest "
            "law; assumption (AUTH) puts this position out of model rather "
            "than pretending a detector reaches it"
        ),
    ),
    Hypothesis.RECIPIENT_FORGERY: HypothesisPredicate(
        predicts=frozenset(
            {
                SignalKind.COUNT_HIGH,
                SignalKind.FORWARDING_TAMPER,
                SignalKind.MISMATCH,
            }
        ),
        requires=frozenset({SignalKind.COUNT_HIGH, SignalKind.MISMATCH}),
        leaves_intact=frozenset({SignalKind.LEDGER}),
        mechanism=(
            "he forwards a declaration built from his own raw log, which "
            "after Phase A' is roughly half of what the receiving verifier "
            "holds, so that verifier's matched count moves from n/3 to 2n/3 "
            "-- sqrt(n/2) standard deviations of the null, 9.80 at n = 192 "
            "and 240 at DEFAULT_PARAMS, with the derived upper-tail threshold "
            "strictly between the two means, which is what makes COUNT_HIGH a "
            "requirement and not a hope; his forwarded declaration is not "
            "Alice's, so the pair's counts name two declarations; he presents "
            "it into a fresh round, so no ledger entry is spent twice"
        ),
    ),
    Hypothesis.COUNT_STARVATION: HypothesisPredicate(
        predicts=frozenset(
            {
                SignalKind.COUNT_LOW,
                SignalKind.EVIDENCE_SHORTFALL,
                SignalKind.DECLARATION_CONFLICT,
            }
        ),
        leaves_intact=frozenset(
            {
                SignalKind.COUNT_HIGH,
                SignalKind.FORWARDING_TAMPER,
                SignalKind.LEDGER,
            }
        ),
        mechanism=(
            "he understates one integer on the Phase C' wire and nothing "
            "else: his own scored matched count is untouched, so the two part "
            "company, and the lie is downward by construction -- an upper "
            "tail, a second declaration on the forwarding hop and a spent "
            "round are all three out of a count-exchange seam's reach"
        ),
    ),
    Hypothesis.REPLAY: HypothesisPredicate(
        predicts=frozenset(
            {
                SignalKind.LEDGER,
                SignalKind.FORWARDING_TAMPER,
                SignalKind.MISMATCH,
            }
        ),
        leaves_intact=frozenset(
            {
                SignalKind.COUNT_HIGH,
                SignalKind.COUNT_LOW,
                SignalKind.EVIDENCE_SHORTFALL,
            }
        ),
        mechanism=(
            "he re-presents a captured declaration, which the consumed-records "
            "ledger and the session binding both record, and which is not the "
            "declaration Alice sent this run; that declaration was drawn "
            "independently of the receiving verifier's current record, so "
            "every count null is left exactly where it was while the "
            "eigenvalues at matched positions disagree. LEDGER is predicted "
            "and NOT required: the ledger check is sound in one direction "
            "only -- a replay that burns its round through a rejection leaves "
            "the refusal count at zero (finding 4 of the structural family)"
        ),
    ),
    Hypothesis.CHANNEL_MANIPULATION: HypothesisPredicate(
        predicts=frozenset({SignalKind.CHANNEL, SignalKind.MISMATCH}),
        leaves_intact=_CLASSICAL_KINDS,
        mechanism=(
            "the matched set is decided by basis agreement, and a "
            "trace-preserving map on the entanglement resource acts on the "
            "teleported eigenstate; it cannot move a basis, so it cannot move "
            "a count, a floor, a declaration or a bookkeeping equality. "
            "CHANNEL is predicted and NOT required: a weak enough deviation "
            "clears a short check sample, and this layer bounds false "
            "positives and never false negatives"
        ),
    ),
}


# --------------------------------------------------------------------------- #
# Argument checking, in the house style: refuse, and say what to pass instead
# --------------------------------------------------------------------------- #


def _as_budget(value: Any, name: str = "eps") -> float:
    """Coerce a false-positive budget strictly inside ``(0, 1)``.

    Parameters
    ----------
    value : Any
        The candidate.
    name : str, optional
        Name to quote in an error.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``value`` is not a real number.
    ValueError
        If ``value`` is not finite or lies outside ``(0, 1)``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be a real number in (0, 1), got "
            f"{type(value).__name__}. It is a false-positive budget, not a "
            f"threshold: sweep it to build a ROC curve."
        )
    budget = float(value)
    if not math.isfinite(budget) or not 0.0 < budget < 1.0:
        raise ValueError(
            f"{name} must lie strictly inside (0, 1), got {budget!r}. A "
            f"budget of 0 admits no test and a budget of 1 admits every one."
        )
    return budget


def _as_probability(value: Any, name: str) -> float:
    """Coerce a probability in ``[0, 1]``.

    Parameters
    ----------
    value : Any
        The candidate.
    name : str
        Name to quote in an error.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``value`` is not a real number.
    ValueError
        If ``value`` is not finite or lies outside ``[0, 1]``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be a real number in [0, 1], got "
            f"{type(value).__name__}"
        )
    probability = float(value)
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise ValueError(
            f"{name} must lie in [0, 1], got {probability!r}"
        )
    return probability


# --------------------------------------------------------------------------- #
# The budget split
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FamilyBudget:
    """How ``eps`` was divided over the three families, with the algebra on it.

    :ref:`C-2 <c2>` derives the split. The object exists so that the division
    is data a reviewer can check rather than a step buried in a function: a
    composite whose allocation cannot be printed is a composite whose
    family-wise bound cannot be audited.

    Attributes
    ----------
    eps : float
        The budget for the **whole detector**.
    rate : float
        The rate-and-count family's share, itself divided by twelve inside
        :class:`~sih141.detect.thresholds_rate.RateCountThresholds`.
    structural : float
        The structural family's share: ``min(B_evid(n), eps/3)``, which is
        everything that family can prove and never more than the even third.
    channel : float
        The channel family's share, divided again over :data:`LINK_ROSTER`.
    per_link : float
        ``channel / 4``, what one screen is held to.
    evidence_bound : float
        ``B_evid(n)``, the structural family's whole proven bound, carried so
        that ``structural < evidence_bound`` -- the case where the evidence
        check is withheld -- is visible rather than inferred.
    derivation : str
        The algebra with this object's numbers in it.

    Raises
    ------
    ValueError
        If the three shares do not sum to :attr:`eps`. That would mean the
        union bound of :ref:`C-1 <c1>` is over a different budget from the one
        reported, and it is refused at construction rather than published.

    Examples
    --------
    >>> from sih141.detect.detector import family_budget
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> split = family_budget(DEFAULT_PARAMS, eps=1e-9)
    >>> f"{split.rate:.4e}", f"{split.structural:.4e}"
    ('5.0000e-10', '1.6263e-19')
    >>> split.rate + split.structural + split.channel == split.eps
    True
    >>> f"{split.per_link:.4e}"
    '1.2500e-10'

    At a budget below what the structural family can prove, the cap binds and
    the split is the plain even third -- and the evidence check is then
    withheld, which the family says for itself:

    >>> tight = family_budget(DEFAULT_PARAMS, eps=1e-19)
    >>> f"{tight.structural:.4e}", tight.structural < tight.evidence_bound
    ('3.3333e-20', True)
    """

    eps: float
    rate: float
    structural: float
    channel: float
    evidence_bound: float
    derivation: str

    def __post_init__(self) -> None:
        """Coerce the shares and refuse a split that does not sum to ``eps``."""
        object.__setattr__(self, "eps", _as_budget(self.eps))
        for field in ("rate", "structural", "channel"):
            try:
                object.__setattr__(
                    self, field, _as_budget(getattr(self, field), field)
                )
            except ValueError as exc:
                # A share is derived, never passed. If one is out of range the
                # caller's eps is what is wrong, and naming the internal field
                # sends them looking for an argument they never supplied --
                # Phase 4 audit finding A2-1, hit by any ROC sweep walking eps
                # down a decade ladder.
                raise ValueError(
                    f"eps={self.eps!r} is too small to divide into family "
                    f"shares: the {field} share came out as "
                    f"{getattr(self, field)!r}, which is outside (0, 1). "
                    f"The smallest budget this project quotes is 2**-64, "
                    f"about 5.42e-20, and the split stays representable to "
                    f"roughly 1e-310; below that a share underflows and no "
                    f"bound can be proven from it. Sweep no lower rather "
                    f"than reading this as a defect in the split."
                ) from exc
        object.__setattr__(
            self,
            "evidence_bound",
            _as_probability(self.evidence_bound, "evidence_bound"),
        )
        object.__setattr__(self, "derivation", str(self.derivation))
        total = math.fsum((self.rate, self.structural, self.channel))
        if not math.isclose(total, self.eps, rel_tol=_BOUND_SLACK):
            raise ValueError(
                f"eps={self.eps!r}: the shares sum to {total!r} instead. "
                f"The union bound of C-1 is only a bound on eps when the "
                f"shares sum to it, so a split that does not is refused here "
                f"rather than reported as if it did. Below roughly 1e-313 "
                f"the shares carry subnormal rounding dust and stop summing "
                f"to the budget, which is a limit of binary floating point "
                f"and not a statement about the detector -- refusing is the "
                f"safe direction, and the region is far below any usable "
                f"budget (Phase 4 audit finding A3-2)."
            )

    @property
    def per_link(self) -> float:
        """float: One screen's budget, ``channel / len(LINK_ROSTER)``."""
        return divide_budget(self.channel, len(LINK_ROSTER))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "eps": self.eps,
            "rate": self.rate,
            "structural": self.structural,
            "channel": self.channel,
            "per_link": self.per_link,
            "evidence_bound": self.evidence_bound,
            "link_roster": [list(link) for link in LINK_ROSTER],
            "derivation": self.derivation,
        }


def family_budget(
    params: ProtocolParams, *, eps: float, counts_exchanged: bool = True
) -> FamilyBudget:
    """Derive the split of ``eps`` over the three families.

    The whole of :ref:`C-2 <c2>`, in one place, so the allocation is written
    down once instead of guessed at three call sites.

    Parameters
    ----------
    params : ProtocolParams
        The **sifted** parameter set. Pass
        :attr:`~sih141.detect.statistics.TranscriptStatistics.params`, which is
        already sifted; a null stated over ``L`` on a checked run would claim
        evidence the run does not have.
    eps : float
        Keyword-only. The budget for the whole detector, inside ``(0, 1)``.
    counts_exchanged : bool, optional
        Keyword-only. Whether Phase C' ran, which decides whether
        ``B_evid(n)`` is a union over three floor events or two.

    Returns
    -------
    FamilyBudget

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, ``eps`` is not a real
        number, or ``counts_exchanged`` is not a :class:`bool`.
    ValueError
        If ``eps`` lies outside ``(0, 1)``.

    Examples
    --------
    The structural family is charged what it can prove and nothing more, so at
    any usable budget the other two split the rest in half:

    >>> from sih141.detect.detector import family_budget
    >>> from sih141.protocol.params import ProtocolParams
    >>> split = family_budget(ProtocolParams(key_length=384), eps=1e-9)
    >>> f"{split.structural:.4e}"
    '1.6263e-19'
    >>> f"{split.rate:.6e}", f"{split.channel:.6e}"
    ('5.000000e-10', '5.000000e-10')

    Neither of the two ever receives less than the even third, because the
    structural share is capped there:

    >>> all(
    ...     family_budget(ProtocolParams(key_length=384), eps=e).rate
    ...     >= e / 3
    ...     for e in (1e-30, 1e-19, 1e-9, 1e-3, 0.5)
    ... )
    True

    Without the count exchange the structural bound is a union over two floor
    events rather than three, and the split says so:

    >>> pooled_off = family_budget(
    ...     ProtocolParams(key_length=384), eps=1e-9, counts_exchanged=False
    ... )
    >>> f"{pooled_off.structural:.4e}"
    '1.0842e-19'
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}. "
            f"Pass TranscriptStatistics.params, which is already sifted."
        )
    if not isinstance(counts_exchanged, bool):
        raise TypeError(
            f"counts_exchanged must be a bool, got "
            f"{type(counts_exchanged).__name__}"
        )
    budget = _as_budget(eps)
    evidence = evidence_abort_bound(params, counts_exchanged=counts_exchanged)
    even = budget / len(DETECTOR_FAMILIES)
    if evidence >= even:
        # The cap binds, and this is the plain even three-way split. Written as
        # `even` rather than as `(budget - even) / 2` -- the same number in real
        # arithmetic and one unit in the last place smaller in floating point,
        # which would make "never worse than the even split" false by an ulp.
        structural = even
        rest = even
    else:
        structural = evidence
        rest = (budget - structural) / 2.0
    return FamilyBudget(
        eps=budget,
        rate=rest,
        structural=structural,
        channel=rest,
        evidence_bound=evidence,
        derivation=(
            f"eps_struct = min(B_evid, eps/3) = min({evidence:.4e}, "
            f"{even:.4e}) = {structural:.4e}; "
            f"eps_rate = eps_chan = (eps - eps_struct)/2 = {rest:.4e}; "
            f"sum = eps = {budget:.4e}. The structural family's proven bound "
            f"is B_evid(n) whatever its share, so a larger share buys it "
            f"nothing (C-2); the cap at eps/3 keeps the split from ever being "
            f"worse than the even one."
        ),
    )


# --------------------------------------------------------------------------- #
# What fired
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Signal:
    """One threshold that fired, with the proof that let it.

    A detector that says only "attack" is useless in a demonstration and
    unfalsifiable in a review. This is the unit of what it says instead.

    Attributes
    ----------
    name : str
        Qualified and stable: ``"rate:<roster name>"``,
        ``"structural:<check>"``, ``"structural:<check>:<party>:<reason>"`` or
        ``"channel:<party>/<bit>:<statistic>"``. A Phase 5 table groups on it.
    family : str
        One of :data:`DETECTOR_FAMILIES`.
    kind : SignalKind
        What it says, in the vocabulary the deduction table reasons in.
    statistic : str
        The quantity compared, in words.
    observed : float or None
        What was seen. ``None`` where the signal is a refusal reason rather
        than a number.
    critical : float or None
        The derived operating point it crossed.
    false_positive_bound : float
        The bound the threshold behind this signal proves. **Signals from one
        threshold share one bound**, and the composite counts it once: two
        refusal reasons from a single structural check are two signals and one
        term in :attr:`Detection.false_positive_bound`.
    is_detection : bool
        ``False`` only on a :attr:`SignalKind.FILE_SHAPE` signal, which is a
        statement about the transcript file rather than about an adversary
        (:ref:`C-7 <c7>`).
    claim : str
        The sentence D7 requires, from the threshold that fired.

    Examples
    --------
    >>> from sih141.detect.detector import Signal, SignalKind
    >>> signal = Signal(
    ...     name="rate:matched_count_high:Charlie",
    ...     family="rate",
    ...     kind=SignalKind.COUNT_HIGH,
    ...     statistic="|M_R|",
    ...     observed=128.0,
    ...     critical=108.0,
    ...     false_positive_bound=6.2367e-11,
    ...     claim="...",
    ... )
    >>> signal.is_detection, f"{signal.false_positive_bound:.3e}"
    (True, '6.237e-11')
    """

    name: str
    family: str
    kind: SignalKind
    statistic: str
    observed: float | None
    critical: float | None
    false_positive_bound: float
    claim: str
    is_detection: bool = True

    def __post_init__(self) -> None:
        """Coerce the fields and refuse a family that is not on the roster."""
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "family", str(self.family))
        object.__setattr__(self, "kind", SignalKind(self.kind))
        object.__setattr__(self, "statistic", str(self.statistic))
        if self.observed is not None:
            object.__setattr__(self, "observed", float(self.observed))
        if self.critical is not None:
            object.__setattr__(self, "critical", float(self.critical))
        object.__setattr__(
            self,
            "false_positive_bound",
            _as_probability(self.false_positive_bound, "false_positive_bound"),
        )
        object.__setattr__(self, "claim", str(self.claim))
        object.__setattr__(self, "is_detection", bool(self.is_detection))
        if self.family not in DETECTOR_FAMILIES:
            raise ValueError(
                f"family must be one of {list(DETECTOR_FAMILIES)}, got "
                f"{self.family!r}. A family off the roster would be summed "
                f"into the composite bound without a share of the budget."
            )
        if (self.kind in _NOT_A_DETECTION) == self.is_detection:
            raise ValueError(
                f"{self.name}: kind {str(self.kind)!r} and is_detection="
                f"{self.is_detection} disagree. Only a file-shape signal is "
                f"not a detection, and it never is one (C-7)."
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "name": self.name,
            "family": self.family,
            "kind": str(self.kind),
            "statistic": self.statistic,
            "observed": self.observed,
            "critical": self.critical,
            "false_positive_bound": self.false_positive_bound,
            "is_detection": self.is_detection,
            "claim": self.claim,
        }


@dataclass(frozen=True)
class Attribution:
    """What the observed signals say about one hypothesis, and how surely.

    Attributes
    ----------
    hypothesis : Hypothesis
    status : Support
    supporting : tuple of str
        Signal names that this hypothesis predicts and that fired.
    excluding : tuple of str
        Signal names whose null this hypothesis leaves intact and that fired.
    missing_requirements : tuple of SignalKind
        Kinds this position produces with probability essentially one that
        **were evaluated on this run and did not fire**. Non-empty means
        ``UNSUPPORTED`` rather than ``EXCLUDED``, and the difference is the
        point: a missing signal has no bound behind it, only a false-negative
        statement this project never makes, so it withholds support without
        claiming a refutation.
    false_positive_bound : float or None
        Read it differently depending on :attr:`status`, and the two readings
        are not interchangeable:

        ``EXCLUDED``
            **A bound on being wrong.** Under this hypothesis each excluding
            signal fires with probability at most its own proven bound, so the
            exclusion is mistaken with probability at most the smallest of
            them. This is a derived number.
        ``SUPPORTED``
            **A bound against the honest null only.** An honest run trips all
            of the supporting evidence with probability at most this. It is
            *not* ``P(the named adversary is the wrong one)``: "adversary A
            rather than adversary B" has no null, so there is no inequality to
            invert and nothing in this project derives such a number
            (:ref:`C-6 <c6>`).
        ``UNSUPPORTED`` / ``UNDETECTABLE``
            ``None``. There is no evidence to bound.
    indistinguishable_from : tuple of Hypothesis
        Other hypotheses that present identically from a transcript. Non-empty
        for the three members of :data:`SIGNATURE_SUBSTITUTION_GROUP`, so a
        table cannot report one of them as if the transcript had picked it out.
    rationale : str
        The mechanism this row was read off, plus what the observed signals did
        to it.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.detector import Hypothesis, detect
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> result = detect(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
    ...     ).run(0),
    ...     eps=1e-9,
    ... )
    >>> result.attribution(Hypothesis.HONEST).status
    <Support.SUPPORTED: 'supported'>
    >>> result.attribution(Hypothesis.REPLAY).status
    <Support.UNSUPPORTED: 'unsupported'>
    """

    hypothesis: Hypothesis
    status: Support
    supporting: tuple[str, ...]
    excluding: tuple[str, ...]
    missing_requirements: tuple[SignalKind, ...]
    false_positive_bound: float | None
    indistinguishable_from: tuple[Hypothesis, ...]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "hypothesis": str(self.hypothesis),
            "status": str(self.status),
            "supporting": list(self.supporting),
            "excluding": list(self.excluding),
            "missing_requirements": [
                str(kind) for kind in self.missing_requirements
            ],
            "false_positive_bound": self.false_positive_bound,
            "indistinguishable_from": [
                str(other) for other in self.indistinguishable_from
            ],
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class Detection:
    """The composite verdict on one run: what fired, what it costs, what it says.

    **Not a rejection.** The run's own verdicts are on :attr:`outcomes`, in a
    type with no truth value, and nothing here touches them. A flag says the
    run departed from a stated null; the verifiers say whether the signature was
    acceptable. Phase 3's constraint 4 one layer further out.

    Attributes
    ----------
    eps : float
        The budget the whole detector was given.
    detected : bool
        Whether any **detection** signal fired -- so a file-shape violation
        alone leaves this ``False`` (:ref:`C-7 <c7>`).
    signals : tuple of Signal
        Everything that fired, sorted by name, file-shape signals included.
    false_positive_bound : float
        **The number the submission quotes.** The union bound of
        :ref:`C-1 <c1>`: the probability that an honest run trips anything at
        all is at most this. At or below :attr:`eps`, and normally well below
        it -- see :attr:`slack_factor`.
    channel_error_rate : float
        The link error rate the rate family's mismatch members were given as
        their null -- the value passed to :func:`detect`, defaulting to
        ``0.0``. **Read this before tabulating :attr:`detected`.** At ``0.0``
        the null is that a matched position never disagrees, so an honest run
        over a *noisy* link departs from it and is correctly reported as a
        detection: the arithmetic is right and the row is still a false claim
        if the table does not say which null it was scored against. Measured
        by the Phase 5 ``noise`` experiment at ``L = 384``,
        ``check_fraction = 0.25``, depolarising noise on the wire only,
        six levels and 30 runs per level, regenerated with
        ``python tools/sweep.py run noise &&
        python tools/sweep.py reduce noise``: ``0.0`` fires ``0/30``,
        ``0.0025`` fires ``14/30``, ``0.005`` fires ``23/30``, ``0.01``
        fires ``28/30``, and from ``0.015`` up -- including the design noise
        level ``2 s_a = 0.03125`` -- ``30/30``. The denominator is every run
        at the level, NOT only the runs both verifiers accepted: at
        ``0.03125`` sixteen of the sixty verifier verdicts are rejections,
        because a link that noisy also moves the signature. Passing the true
        rate gives ``0/30`` at every level. See also :attr:`null_is_noiseless` and
        :func:`sih141.detect.thresholds_rate.dominance_noise_level`.

        Phase 4's audit raised this as finding A3-1: the behaviour was
        disclosed in prose while the machine-readable output carried nothing,
        which is why the value now ships on the verdict itself.
    bound_is_unconditional : bool
        ``False`` when a positive ``channel_error_rate`` made the rate family's
        mismatch members conditional on this run's matched counts. The sum is
        still a correct bound then, but on ``P(fire | the matched counts)``, and
        :attr:`eps` is what remains unconditionally true. Mirrors
        :attr:`RateCountThresholds.bound_is_unconditional
        <sih141.detect.thresholds_rate.RateCountThresholds>`, which is where
        the tower-rule argument lives.
    evidence_bound : float or None
        For the set of signals that actually fired, a bound on an honest run
        tripping **all** of them: the smallest of their individual bounds.
        ``None`` when nothing fired. **Post hoc**: the set was chosen by the
        data, so this is a statement about that fixed set evaluated after the
        fact, and :attr:`false_positive_bound` is the unconditional guarantee.
        Kept because "the strongest single thing that fired here is a
        ``6e-11`` event under the honest null" is the sentence a demonstration
        needs, and quoting it as the *detector's* error rate is the mistake
        keeping it in a separate field exists to make hard.
    budget : FamilyBudget
        How ``eps`` was divided (:ref:`C-2 <c2>`).
    attributions : tuple of Attribution
        One per member of :data:`HYPOTHESES`, in that order. Complete: a
        hypothesis missing from a report reads as one that was ruled out.
    outcomes : mapping of str to RunOutcome
        What each verifier did. Four-valued and with no truth value, so a
        refusal cannot be read as a rejection.
    not_scored : tuple of str
        Verifiers who reached no verdict. Never counted as a rejection or as a
        non-detection.
    withheld : tuple of str
        Checks with no admissible operating point at this budget, and channel
        statistics this run could not evaluate. **A withheld check is not a
        passed check**, which is why it is a field.
    grouping_key : tuple
        The run's variant markers. **Group by this; never average over it.**
    requirements_enforced : bool
        Whether a hypothesis's ``requires`` clause was checked at all.
        ``False`` on any run where a verifier reached no verdict, because a
        required signal may then simply never have been looked for
        (:func:`_requirement_kinds`). Carried so a report can say why a
        hypothesis survived rather than leaving a reader to wonder.
    security_claim : bool
        Whether the run's own floors were non-degenerate. ``False`` marks a run
        that carries no security claim at all, on which every number here still
        computes cheerfully.
    key_length : int
        The **sifted** length every null was stated over.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.detector import detect
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> result = detect(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
    ...     ).run(0),
    ...     eps=1e-9,
    ... )
    >>> result.detected, result.evidence_bound
    (False, None)
    >>> f"{result.false_positive_bound:.4e}"
    '2.6499e-10'
    >>> for line in result.summary().splitlines()[:2]:
    ...     print(line)
    detect: nothing fired at eps = 1.000e-09
      P(any signal | honest) <= 2.6499e-10, a factor of 3.77 inside the budget
    >>> print(result.summary().splitlines()[2])
      consistent with: honest
    >>> print(result.summary().splitlines()[-1])
      outcomes: Bob accepted, Charlie accepted
    """

    eps: float
    detected: bool
    signals: tuple[Signal, ...]
    false_positive_bound: float
    bound_is_unconditional: bool
    evidence_bound: float | None
    budget: FamilyBudget
    attributions: tuple[Attribution, ...]
    outcomes: Mapping[str, RunOutcome]
    not_scored: tuple[str, ...]
    withheld: tuple[str, ...]
    grouping_key: tuple[Any, ...]
    requirements_enforced: bool
    security_claim: bool
    key_length: int
    channel_error_rate: float

    # -- derived views ------------------------------------------------------ #

    @property
    def null_is_noiseless(self) -> bool:
        """bool: whether the mismatch members were scored against a
        noiseless link.

        ``True`` exactly when :attr:`channel_error_rate` is ``0.0``, which is
        :func:`detect`'s default. It is a statement about the **null**, not
        about the caller: a run scored this way over a noisy link can report
        :attr:`detected` with a proven bound and still not be evidence of an
        adversary. One field to filter a results table on.

        >>> from sih141.detect import detect
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> import numpy as np
        >>> t = QDSSession(ProtocolParams(key_length=96),
        ...                rng=np.random.default_rng(4)).run(0)
        >>> detect(t, eps=1e-9).null_is_noiseless
        True
        >>> detect(t, eps=1e-9, channel_error_rate=0.01).null_is_noiseless
        False
        """
        return self.channel_error_rate == 0.0

    @property
    def slack_factor(self) -> float:
        """float: ``eps`` over what the composite actually proves.

        The slack of :ref:`C-4 <c4>`, as one number. ``1.0`` would mean every
        member spent its whole share; anything above it is budget the family's
        point-mass members could not spend, and quoting ``eps`` in its place
        would overstate the detector's own false-positive rate by exactly this
        factor.
        """
        if self.false_positive_bound == 0.0:
            return math.inf
        return self.eps / self.false_positive_bound

    @property
    def detection_signals(self) -> tuple[Signal, ...]:
        """tuple of Signal: The signals that are about an adversary.

        Everything except :attr:`SignalKind.FILE_SHAPE` (:ref:`C-7 <c7>`).
        """
        return tuple(signal for signal in self.signals if signal.is_detection)

    @property
    def kinds(self) -> tuple[SignalKind, ...]:
        """tuple of SignalKind: Which kinds fired, sorted and deduplicated."""
        return tuple(
            sorted({signal.kind for signal in self.detection_signals})
        )

    @property
    def named(self) -> tuple[Hypothesis, ...]:
        """tuple of Hypothesis: The hypotheses the evidence supports.

        Empty when the pattern supports nothing in the model, which is a
        legitimate outcome and is reported rather than resolved by guessing:
        every in-model position can be excluded at once, and a detector that
        picked a survivor anyway would be inventing an attribution.
        """
        return tuple(
            attribution.hypothesis
            for attribution in self.attributions
            if attribution.status is Support.SUPPORTED
        )

    @property
    def excluded(self) -> tuple[Hypothesis, ...]:
        """tuple of Hypothesis: The hypotheses this run's evidence rules out.

        The half of the discrimination that carries a derived bound: each of
        these leaves some fired signal's null intact, so under it that signal
        fires with probability at most its own proven bound, and
        :attr:`Attribution.false_positive_bound` is that number
        (:ref:`C-5 <c5>`). On an honest run the tuple is empty; on any detected
        run it contains at least :attr:`Hypothesis.HONEST`.
        """
        return tuple(
            attribution.hypothesis
            for attribution in self.attributions
            if attribution.status is Support.EXCLUDED
        )

    def attribution(self, hypothesis: Hypothesis | str) -> Attribution:
        """Return this run's attribution for one hypothesis.

        Parameters
        ----------
        hypothesis : Hypothesis or str
            A member of :class:`Hypothesis`, or its value.

        Returns
        -------
        Attribution

        Raises
        ------
        KeyError
            If ``hypothesis`` names nothing on :data:`HYPOTHESES`.
        """
        try:
            wanted = Hypothesis(hypothesis)
        except ValueError as error:
            raise KeyError(
                f"{hypothesis!r} is not a hypothesis. The roster is "
                f"{[str(item) for item in HYPOTHESES]}."
            ) from error
        for attribution in self.attributions:
            if attribution.hypothesis is wanted:
                return attribution
        raise KeyError(  # pragma: no cover - HYPOTHESES is complete
            f"{wanted!r} has no attribution on this Detection."
        )

    def signal(self, name: str) -> Signal:
        """Return one fired signal by name.

        Parameters
        ----------
        name : str
            The qualified signal name.

        Returns
        -------
        Signal

        Raises
        ------
        KeyError
            If no signal of that name fired on this run.
        """
        for item in self.signals:
            if item.name == name:
                return item
        raise KeyError(
            f"{name!r} did not fire on this run. What did: "
            f"{[item.name for item in self.signals]}."
        )

    def summary(self) -> str:
        """Return the whole verdict as a few readable lines.

        Returns
        -------
        str
            The headline, the proven bound and its slack, one line per fired
            signal, what the evidence is consistent with, what it rules out and
            how surely, what it cannot separate, and the outcomes -- which are
            never folded into the detection.

        Examples
        --------
        A count starver, which the deduction table names alone because a wire
        integer in its lower tail is out of reach of every other position in the
        model:

        >>> import numpy as np
        >>> from sih141.attacks.starvation import CountStarver
        >>> from sih141.detect.detector import detect
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> from sih141.protocol.verify import MatchedSetTooSmall
        >>> session = QDSSession(
        ...     ProtocolParams(key_length=384),
        ...     rng=np.random.default_rng(500001),
        ...     count_exchange=CountStarver(rng=np.random.default_rng(9001)),
        ... )
        >>> try:
        ...     transcript = session.run(0)
        ... except MatchedSetTooSmall:
        ...     transcript = session.transcript()
        >>> lines = detect(transcript, eps=1e-9).summary().splitlines()
        >>> print(lines[0])
        detect: 2 signal(s) at eps = 1.000e-09
        >>> print(lines[4])
          consistent with: count-starvation
        >>> print(lines[-1])
          outcomes: Bob refused-to-score, Charlie accepted

        The refusal on that last line is **not** a rejection, and the type it is
        carried in refuses to pretend otherwise:

        >>> from sih141.detect.thresholds_structural import RunOutcome
        >>> detect(transcript, eps=1e-9).outcomes["Bob"] is RunOutcome.REFUSED
        True
        """
        lines: list[str] = []
        if self.detected:
            lines.append(
                f"detect: {len(self.detection_signals)} signal(s) at eps = "
                f"{self.eps:.3e}"
            )
        else:
            lines.append(f"detect: nothing fired at eps = {self.eps:.3e}")
        lines.append(
            f"  P(any signal | honest) <= "
            f"{self.false_positive_bound:.4e}, a factor of "
            f"{self.slack_factor:.2f} inside the budget"
        )
        for signal in self.signals:
            shown = "n/a" if signal.observed is None else f"{signal.observed:g}"
            mark = "" if signal.is_detection else "  [not a detection, C-7]"
            lines.append(
                f"  {signal.name}: {signal.statistic} = {shown} "
                f"[<= {signal.false_positive_bound:.4e}]{mark}"
            )
        named = self.named
        if named:
            lines.append(
                "  consistent with: "
                + ", ".join(str(item) for item in named)
            )
        else:
            lines.append(
                "  consistent with: nothing in the model -- every in-model "
                "position is excluded by some signal, and no survivor is "
                "invented to fill the row"
            )
        ruled_out = self.excluded
        if ruled_out:
            worst = max(
                self.attribution(item).false_positive_bound or 0.0
                for item in ruled_out
            )
            lines.append(
                "  ruled out: "
                + ", ".join(str(item) for item in ruled_out)
                + f" (each wrongly with probability at most {worst:.4e})"
            )
        if named and not self.requirements_enforced:
            lines.append(
                "  requirements waived: a verifier reached no verdict, so a "
                "signal a position produces with probability one may never "
                "have been looked for"
            )
        group = {
            other
            for item in named
            for other in self.attribution(item).indistinguishable_from
        }
        if group:
            lines.append(
                "  not separable: "
                + ", ".join(sorted(str(other) for other in group))
                + " present identically from a transcript"
            )
        lines.append(
            "  not separable: impersonation-full is undetectable by "
            "construction (AUTH)"
        )
        if self.withheld:
            lines.append("  withheld: " + ", ".join(self.withheld))
        if self.not_scored:
            lines.append(
                "  reached no verdict: " + ", ".join(self.not_scored)
            )
        lines.append(
            "  outcomes: "
            + ", ".join(
                f"{party} {self.outcomes[party].value}"
                for party in sorted(self.outcomes)
            )
        )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the whole verdict.

        Returns
        -------
        dict
            Passes to :func:`json.dumps` unchanged. ``"grouping_key"`` becomes
            a list, since JSON has no tuple, and keeps its order.
        """
        return {
            "eps": self.eps,
            "detected": self.detected,
            "signals": [signal.to_dict() for signal in self.signals],
            "false_positive_bound": self.false_positive_bound,
            "bound_is_unconditional": self.bound_is_unconditional,
            "channel_error_rate": self.channel_error_rate,
            "null_is_noiseless": self.null_is_noiseless,
            "evidence_bound": self.evidence_bound,
            "slack_factor": self.slack_factor,
            "budget": self.budget.to_dict(),
            "attributions": [
                attribution.to_dict() for attribution in self.attributions
            ],
            "named": [str(item) for item in self.named],
            "kinds": [str(kind) for kind in self.kinds],
            "outcomes": {
                party: outcome.value
                for party, outcome in self.outcomes.items()
            },
            "not_scored": list(self.not_scored),
            "withheld": list(self.withheld),
            "grouping_key": list(self.grouping_key),
            "requirements_enforced": self.requirements_enforced,
            "security_claim": self.security_claim,
            "key_length": self.key_length,
            "summary": self.summary(),
        }


# --------------------------------------------------------------------------- #
# Reading the three families into signals
# --------------------------------------------------------------------------- #

#: Which kind each rate-family roster name reports, derived from the tail it
#: tests rather than from a table of exceptions. Keyed by the part of the name
#: before the party.
_RATE_KINDS: Final[Mapping[str, SignalKind]] = {
    "mismatch_rate": SignalKind.MISMATCH,
    "matched_count_low": SignalKind.COUNT_LOW,
    "matched_count_high": SignalKind.COUNT_HIGH,
    "declared_count_low": SignalKind.COUNT_LOW,
    "declared_count_high": SignalKind.COUNT_HIGH,
    "pooled_count_low": SignalKind.COUNT_LOW,
    "pooled_count_high": SignalKind.COUNT_HIGH,
    "declaration_gap": SignalKind.DECLARATION_CONFLICT,
}

#: Which kind each abort reason reports. Total over
#: :class:`~sih141.protocol.verify.AbortReason`, and checked to be, so a reason
#: added upstream fails a test instead of arriving as a kind nobody chose.
_REASON_KINDS: Final[Mapping[AbortReason, SignalKind]] = {
    AbortReason.SESSION_MISMATCH: SignalKind.LEDGER,
    AbortReason.RECORD_ALREADY_VERIFIED: SignalKind.LEDGER,
    AbortReason.COUNT_OF_UNRECORDED_PROVENANCE: (
        SignalKind.DECLARATION_CONFLICT
    ),
    AbortReason.COUNTS_FROM_TWO_DECLARATIONS: SignalKind.FORWARDING_TAMPER,
    AbortReason.EMPTY_MATCHED_SET: SignalKind.EVIDENCE_SHORTFALL,
    AbortReason.BELOW_FLOOR: SignalKind.EVIDENCE_SHORTFALL,
    AbortReason.POOLED_BELOW_FLOOR: SignalKind.EVIDENCE_SHORTFALL,
    AbortReason.COUNTERPART_BELOW_FLOOR: SignalKind.EVIDENCE_SHORTFALL,
}


def _rate_signals(
    family: RateCountThresholds, verdict: RateCountVerdict
) -> list[Signal]:
    """Turn the rate family's verdict into signals.

    Parameters
    ----------
    family : RateCountThresholds
        The family that was evaluated, for the thresholds behind each name.
    verdict : RateCountVerdict
        What it saw.

    Returns
    -------
    list of Signal
    """
    signals: list[Signal] = []
    for name in verdict.fired:
        base = name.partition(":")[0]
        observed = verdict.observations.get(name)
        if name in RATE_COUNT_FREE_TESTS:
            # Charged nothing because its bound is exactly zero: two integers
            # that must be equal being unequal is not a deviation under any
            # null (RATE_COUNT_FREE_TESTS).
            signals.append(
                Signal(
                    name=f"rate:{name}",
                    family="rate",
                    kind=_RATE_KINDS[base],
                    statistic="declared pooled count - scored pooled count",
                    observed=observed,
                    critical=0.0,
                    false_positive_bound=0.0,
                    claim=(
                        "declaration_gap: fires when the two Phase C' wire "
                        "integers do not sum to the count the two verdicts "
                        "scored; under every null this fires with probability "
                        "exactly 0, because it compares two integers that are "
                        "equal by construction on an honest run."
                    ),
                )
            )
            continue
        threshold = family.threshold(name)
        signals.append(
            Signal(
                name=f"rate:{name}",
                family="rate",
                kind=_RATE_KINDS[base],
                statistic=threshold.statistic,
                observed=observed,
                critical=float(threshold.critical_count),
                false_positive_bound=threshold.false_positive_bound,
                claim=threshold.claim(),
            )
        )
    return signals


def _structural_signals(report: StructuralReport) -> list[Signal]:
    """Turn the structural report's alarms into signals, one per refusal reason.

    An abort check that fired on two refusals for two different reasons is two
    signals, because the reasons point at different positions in the threat
    model -- ``counts-from-two-declarations`` is a forwarding hop and
    ``session-identifier-mismatch`` is a ledger. Both carry the **same**
    threshold bound, and :func:`detect` counts that bound once, from the
    family's own union, rather than once per signal.

    Parameters
    ----------
    report : StructuralReport
        The structural family's verdict on this run.

    Returns
    -------
    list of Signal
    """
    signals: list[Signal] = []
    reasons: dict[StructuralCheck, list[str]] = {}
    for attribution in report.attributions:
        check = (
            StructuralCheck.STRUCTURAL_ABORT
            if attribution.group == "structural"
            else StructuralCheck.EVIDENCE_ABORT
        )
        reasons.setdefault(check, []).append(
            f"{attribution.party}:{attribution.reason}"
        )
    for alarm in report.alarms:
        threshold = alarm.threshold
        claim = (
            f"{alarm.check}: fires when {threshold.statistic} >= "
            f"{threshold.fires_at}; under {threshold.null}, this fires with "
            f"probability at most {threshold.false_positive_bound:.4e}, by "
            f"{threshold.inequality}."
        )
        if alarm.check in (
            StructuralCheck.STRUCTURAL_ABORT,
            StructuralCheck.EVIDENCE_ABORT,
        ):
            tags = sorted(reasons.get(alarm.check, ()))
            if tags:
                for tag in tags:
                    party, _, reason = tag.partition(":")
                    signals.append(
                        Signal(
                            # The party is in the name as well as the reason:
                            # two verifiers can refuse for the same reason, and
                            # two signals sharing a name would make one of them
                            # unreachable through Detection.signal.
                            name=(
                                f"structural:{alarm.check}:{party}:{reason}"
                            ),
                            family="structural",
                            kind=_REASON_KINDS[AbortReason(reason)],
                            statistic=f"{party} refused: {reason}",
                            observed=None,
                            critical=float(threshold.fires_at or 1),
                            false_positive_bound=(
                                threshold.false_positive_bound
                            ),
                            claim=claim,
                        )
                    )
                continue
            # An abort alarm with no attribution behind it should be
            # unreachable -- attribute_aborts covers every refusal the
            # statistics carry. If it ever happens, emit the alarm rather than
            # dropping it: a detection lost here would be invisible, which is
            # the one failure mode this layer must not have.
            signals.append(
                Signal(
                    name=f"structural:{alarm.check}",
                    family="structural",
                    kind=(
                        SignalKind.EVIDENCE_SHORTFALL
                        if alarm.check is StructuralCheck.EVIDENCE_ABORT
                        else SignalKind.DECLARATION_CONFLICT
                    ),
                    statistic=alarm.detail or threshold.statistic,
                    observed=float(alarm.count),
                    critical=float(threshold.fires_at or 1),
                    false_positive_bound=threshold.false_positive_bound,
                    claim=claim,
                )
            )
            continue
        kind = (
            SignalKind.FILE_SHAPE
            if alarm.check is StructuralCheck.RUN_SHAPE
            else SignalKind.LEDGER
        )
        signals.append(
            Signal(
                name=f"structural:{alarm.check}",
                family="structural",
                kind=kind,
                statistic=alarm.detail or threshold.statistic,
                observed=float(alarm.count),
                critical=float(threshold.fires_at or 1),
                false_positive_bound=threshold.false_positive_bound,
                claim=claim,
                is_detection=kind is not SignalKind.FILE_SHAPE,
            )
        )
    return signals


def _channel_signals(
    screens: Mapping[tuple[str, int], ChannelScreen],
) -> list[Signal]:
    """Turn the per-link channel screens into signals.

    Parameters
    ----------
    screens : mapping
        One :class:`~sih141.detect.thresholds_channel.ChannelScreen` per link
        the run published, keyed by ``(party, message bit)``.

    Returns
    -------
    list of Signal
    """
    signals: list[Signal] = []
    for (party, bit), screen in sorted(screens.items()):
        for name in screen.fired:
            threshold = screen.thresholds[name]
            signals.append(
                Signal(
                    name=f"channel:{party}/{bit}:{name}",
                    family="channel",
                    kind=SignalKind.CHANNEL,
                    statistic=threshold.statistic,
                    observed=screen.observed[name],
                    critical=threshold.critical_value,
                    false_positive_bound=threshold.false_positive_bound,
                    claim=threshold.summary(),
                )
            )
    return signals


# --------------------------------------------------------------------------- #
# The deduction
# --------------------------------------------------------------------------- #


def _requirement_kinds(
    rate_verdict: RateCountVerdict,
    report: StructuralReport,
    screens: Mapping[tuple[str, int], ChannelScreen],
) -> frozenset[SignalKind]:
    """Return the kinds a ``requires`` clause may be checked against.

    A required signal that was **never looked for** must not count against a
    hypothesis: "we could not look" read as "we looked and it was fine" is the
    mistake the channel screen keeps a whole field for, and it is the same
    mistake here. So a kind counts only when at least one threshold of that
    kind was actually applied to this run.

    **And the whole check is waived when any verifier reached no verdict.** A
    required count or mismatch signal lives on one verifier's statistics, and
    this layer cannot say which verifier a hypothesis is about -- a recipient
    forgery requires an inflated count *at the verifier who received the forged
    declaration*, and in the count-exchange ordering where that verifier
    refuses, the signal was never evaluated for him even though it was
    evaluated for the other one. Waiving is the conservative direction: it can
    leave a hypothesis supported that a sharper rule would withhold, and it can
    never withhold support the evidence deserves.

    Parameters
    ----------
    rate_verdict : RateCountVerdict
        The rate family's verdict, whose ``observations`` name exactly the
        members that were evaluated.
    report : StructuralReport
        The structural family's report, whose thresholds say which checks had
        an admissible operating point.
    screens : mapping
        The channel screens that were built.

    Returns
    -------
    frozenset of SignalKind
    """
    if rate_verdict.not_scored:
        return frozenset()
    kinds: set[SignalKind] = set()
    for name in rate_verdict.observations:
        kinds.add(_RATE_KINDS[name.partition(":")[0]])
    for threshold in report.thresholds:
        if not threshold.admissible:
            continue
        if threshold.check is StructuralCheck.EVIDENCE_ABORT:
            kinds.add(SignalKind.EVIDENCE_SHORTFALL)
        elif threshold.check is StructuralCheck.STRUCTURAL_ABORT:
            kinds.update(
                (
                    SignalKind.LEDGER,
                    SignalKind.DECLARATION_CONFLICT,
                    SignalKind.FORWARDING_TAMPER,
                )
            )
        elif threshold.check is StructuralCheck.REPLAY_REFUSAL:
            kinds.add(SignalKind.LEDGER)
    if any(screen.thresholds for screen in screens.values()):
        kinds.add(SignalKind.CHANNEL)
    return frozenset(kinds)


def _attribute(
    signals: Mapping[SignalKind, list[Signal]],
    evaluated: frozenset[SignalKind],
) -> tuple[Attribution, ...]:
    """Apply the deduction table of :ref:`C-5 <c5>` to the fired kinds.

    Parameters
    ----------
    signals : mapping of SignalKind to list of Signal
        The detection signals that fired, grouped by kind. File-shape signals
        are absent by construction: they are not about an adversary
        (:ref:`C-7 <c7>`).
    evaluated : frozenset of SignalKind
        Kinds for which at least one threshold was actually applied on this
        run, and against which a row's ``requires`` is checked. Empty when the
        requirements are waived -- see :func:`_requirement_kinds`.

    Returns
    -------
    tuple of Attribution
        One per member of :data:`HYPOTHESES`, in that order.
    """
    built: list[Attribution] = []
    for hypothesis in HYPOTHESES:
        row = HYPOTHESIS_TABLE[hypothesis]
        supporting = tuple(
            sorted(
                signal.name
                for kind in row.predicts
                for signal in signals.get(kind, ())
            )
        )
        excluding = tuple(
            sorted(
                signal.name
                for kind in row.leaves_intact
                for signal in signals.get(kind, ())
            )
        )
        missing = tuple(
            sorted(
                kind
                for kind in row.requires
                if kind in evaluated and not signals.get(kind)
            )
        )
        group = (
            tuple(
                other
                for other in SIGNATURE_SUBSTITUTION_GROUP
                if other is not hypothesis
            )
            if hypothesis in SIGNATURE_SUBSTITUTION_GROUP
            else ()
        )

        if not row.detectable:
            status = Support.UNDETECTABLE
            bound: float | None = None
            note = (
                "never named and never ruled out: assumption (AUTH) puts this "
                "position out of model, and a hypothesis silently missing "
                "from a table reads as one that was excluded"
            )
        elif excluding:
            status = Support.EXCLUDED
            bound = min(
                signal.false_positive_bound
                for kind in row.leaves_intact
                for signal in signals.get(kind, ())
            )
            note = (
                f"excluded by {list(excluding)}, whose nulls this position "
                f"leaves intact; the exclusion is mistaken with probability "
                f"at most {bound:.4e}"
            )
        elif missing:
            status = Support.UNSUPPORTED
            bound = None
            note = (
                f"not supported: this position produces "
                f"{[str(kind) for kind in missing]} with probability "
                f"essentially one, and on this run that was evaluated and did "
                f"not fire. Withheld rather than refuted -- a signal that did "
                f"not fire carries no bound, only a false-negative statement "
                f"nothing here derives"
            )
        elif supporting:
            status = Support.SUPPORTED
            bound = min(
                signal.false_positive_bound
                for kind in row.predicts
                for signal in signals.get(kind, ())
            )
            note = (
                f"supported by {list(supporting)}; an honest run trips all of "
                f"that evidence with probability at most {bound:.4e}, which "
                f"is a bound against the honest null and not a bound on "
                f"having named the wrong adversary (C-6)"
            )
        elif row.is_null:
            # Reached only when nothing fired at all: the null row leaves every
            # detection kind intact, so any signal takes the branch above.
            status = Support.SUPPORTED
            bound = None
            note = (
                "nothing fired, so nothing departs from the nulls; the "
                "detector's own false-positive bound is the number that says "
                "how much that is worth"
            )
        else:
            status = Support.UNSUPPORTED
            bound = None
            note = (
                "nothing fired that this position predicts, and nothing that "
                "excludes it -- an absence of evidence, which is not evidence "
                "of absence and is not reported as one"
            )
        built.append(
            Attribution(
                hypothesis=hypothesis,
                status=status,
                supporting=supporting,
                excluding=excluding,
                missing_requirements=missing,
                false_positive_bound=bound,
                indistinguishable_from=group,
                rationale=f"{row.mechanism}. {note}.",
            )
        )
    return tuple(built)


# --------------------------------------------------------------------------- #
# The detector
# --------------------------------------------------------------------------- #


def _as_statistics(source: Any) -> TranscriptStatistics:
    """Coerce the detector's one input, keeping the JSON boundary intact.

    Parameters
    ----------
    source : SessionTranscript or TranscriptStatistics or str
        A transcript, its JSON text, or layer one's extraction of one. Every
        route goes through
        :meth:`~sih141.detect.statistics.TranscriptStatistics.from_json`, which
        is what makes "reads a JSON round-tripped transcript and nothing else"
        a property of the code.

    Returns
    -------
    TranscriptStatistics

    Raises
    ------
    TypeError
        If ``source`` is none of the three.
    """
    if isinstance(source, TranscriptStatistics):
        return source
    if isinstance(source, SessionTranscript):
        return TranscriptStatistics.from_transcript(source)
    if isinstance(source, str):
        return TranscriptStatistics.from_json(source)
    raise TypeError(
        f"transcript must be a SessionTranscript, its JSON text, or a "
        f"TranscriptStatistics, got {type(source).__name__}. The detector "
        f"reads a JSON round-tripped transcript and nothing else -- not the "
        f"session, not the adversary, not any harness state."
    )


def detect(
    transcript: SessionTranscript | TranscriptStatistics | str,
    *,
    eps: float,
    channel_error_rate: float = 0.0,
    tolerated_depolarising: float = 0.0,
    method: str = "sharpest",
    qber_method: str = "exact",
) -> Detection:
    """Score one run against every derived threshold, at one budget.

    The whole detector. It takes a **false-positive budget** rather than a pile
    of constants, so Phase 5 sweeps ``eps`` to produce a ROC curve on which
    every operating point is derived rather than tuned, and it returns which
    signals fired and what each one proves rather than a boolean.

    Parameters
    ----------
    transcript : SessionTranscript or str or TranscriptStatistics
        The run. A transcript object is serialised and re-read; JSON text is
        read; a :class:`~sih141.detect.statistics.TranscriptStatistics` came
        through one of those two doors already.
    eps : float
        Keyword-only. The budget for the **whole detector**, inside ``(0, 1)``.
        The guarantee is that an honest run trips at least one signal with
        probability at most this; the number actually proven is
        :attr:`Detection.false_positive_bound` and is normally well below it.
    channel_error_rate : float, optional
        Keyword-only. ``p_e``, the rate family's null for the verifier mismatch
        count. Defaults to the noiseless ``0.0``, which is the strongest bound
        in the family and a claim about a **noiseless link**: on an honest but
        genuinely noisy link the mismatch members fire, correctly, and finding
        F6 of the rate family measures how often. Not read off the run -- a
        transcript with no check rounds carries no estimate of it.
    tolerated_depolarising : float, optional
        Keyword-only. ``p0``, the channel family's null, as a Werner strength.
        Defaults to ``0.0``. **Deliberately a separate argument from**
        ``channel_error_rate``: the two are different parameterisations of the
        same physics and
        :func:`~sih141.protocol.analysis.depolarising_error_rate` converts one
        into the other, but doing that conversion silently would state a null
        the caller did not ask for.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
        Keyword-only. Which proofs the rate family consults. Selection is over
        proofs, never over data (:ref:`D-5
        <sih141.detect.thresholds_rate:d5>`).
    qber_method : {'exact', 'chernoff', 'hoeffding'}, optional
        Keyword-only. Which inversion each channel screen's QBER threshold
        uses.

    Returns
    -------
    Detection

    Raises
    ------
    TypeError
        If ``transcript`` is not one of the three accepted forms, or an
        argument has the wrong type.
    ValueError
        If ``eps`` lies outside ``(0, 1)``, a noise level lies outside
        ``[0, 1]``, or -- and this one would be a bug in this module rather
        than a property of the run -- the composite's proven bound exceeds its
        own budget.

    Notes
    -----
    **A flag is not a rejection.** The verdicts are on
    :attr:`Detection.outcomes`, in a type with no truth value; a run can be
    accepted and flagged at once, and under the noiseless null every run with a
    single mismatch is. Folding one into the other would report a detection
    that never happened.

    **No false-negative bound exists here.** Every number is under the honest
    null. A detection rate against a named adversary is a measurement, reported
    with its sample size and grouped by ``count_exchange_timing``, never a
    guarantee (:ref:`finding G3 <findings>`).

    Examples
    --------
    An honest run, at three budgets four orders of magnitude apart. Nothing
    fires at any of them, and the proven bound moves with the budget while no
    threshold is touched by hand:

    >>> import numpy as np
    >>> from sih141.detect.detector import detect
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> transcript = QDSSession(
    ...     ProtocolParams(key_length=384, check_fraction=0.25),
    ...     rng=np.random.default_rng(11),
    ... ).run(0)
    >>> [
    ...     detect(transcript, eps=e).detected
    ...     for e in (1e-3, 1e-6, 1e-9)
    ... ]
    [False, False, False]
    >>> f"{detect(transcript, eps=1e-3).false_positive_bound:.4e}"
    '4.0167e-04'

    The JSON boundary is the contract, and all three doors agree:

    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> text = transcript.to_json()
    >>> a = detect(transcript, eps=1e-9)
    >>> b = detect(text, eps=1e-9)
    >>> c = detect(TranscriptStatistics.from_json(text), eps=1e-9)
    >>> a.to_dict() == b.to_dict() == c.to_dict()
    True
    """
    stats = _as_statistics(transcript)
    budget = _as_budget(eps)
    noise = _as_probability(channel_error_rate, "channel_error_rate")
    strength = _as_probability(
        tolerated_depolarising, "tolerated_depolarising"
    )
    split = family_budget(
        stats.params, eps=budget, counts_exchanged=stats.counts_exchanged
    )

    rate_family = RateCountThresholds.for_transcript(
        stats, eps=split.rate, channel_error_rate=noise, method=method
    )
    rate_verdict = rate_family.evaluate(stats)
    report = structural_report(stats, eps=split.structural)
    per_link = split.per_link
    screens = {
        link: screen_link(
            stats.links[link],
            epsilon=per_link,
            tolerated_depolarising=strength,
            qber_method=qber_method,
        )
        for link in LINK_ROSTER
        if link in stats.links
    }

    signals = tuple(
        sorted(
            _rate_signals(rate_family, rate_verdict)
            + _structural_signals(report)
            + _channel_signals(screens),
            key=lambda signal: signal.name,
        )
    )

    # Counted once per *threshold*, from each family's own union bound, so two
    # refusal reasons out of one structural check do not appear as two terms.
    bound = min(
        1.0,
        math.fsum(
            (
                rate_verdict.false_positive_bound,
                report.false_positive_bound,
                *(screen.false_positive_bound for screen in screens.values()),
            )
        ),
    )
    if bound > budget * (1.0 + _BOUND_SLACK):
        raise ValueError(  # pragma: no cover - an arithmetic error here
            f"the composite proves {bound!r} against a budget of {budget!r}. "
            f"The union bound of C-1 and the allocation of C-2 disagree, "
            f"which is a bug in this module and not a property of the run."
        )

    evaluated = _requirement_kinds(rate_verdict, report, screens)
    by_kind: dict[SignalKind, list[Signal]] = {}
    for signal in signals:
        if signal.is_detection:
            by_kind.setdefault(signal.kind, []).append(signal)
    detection_signals = [signal for signal in signals if signal.is_detection]

    withheld = [
        f"structural:{check}" for check in sorted(report.withheld)
    ] + [
        f"channel:{party}/{bit}:{name}"
        for (party, bit), screen in sorted(screens.items())
        for name in sorted(screen.unavailable)
    ]
    if not screens:
        withheld.append(
            "channel: this run published no check rounds, so the whole "
            "channel family is unevaluable -- an unmonitored link is not a "
            "clean one"
        )

    return Detection(
        eps=budget,
        detected=bool(detection_signals),
        signals=signals,
        false_positive_bound=bound,
        bound_is_unconditional=rate_family.bound_is_unconditional,
        channel_error_rate=noise,
        evidence_bound=(
            min(signal.false_positive_bound for signal in detection_signals)
            if detection_signals
            else None
        ),
        budget=split,
        attributions=_attribute(by_kind, evaluated),
        outcomes=report.outcomes,
        not_scored=rate_verdict.not_scored,
        withheld=tuple(withheld),
        grouping_key=rate_verdict.grouping_key,
        requirements_enforced=not rate_verdict.not_scored,
        security_claim=stats.security_claim,
        key_length=stats.key_length,
    )
