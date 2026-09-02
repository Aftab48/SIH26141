"""Phase 4, layer two: derived thresholds for the rate and count statistics.

The strongest and cheapest family. Phase 3 measured that the verifier mismatch
rate separates four of five adversaries on its own, needs no check rounds and
reads straight off a JSON transcript; this module turns that observation into
thresholds that carry **proofs** rather than measured separations.

Convention **D7** in one sentence: every number here comes from a written-down
null distribution and a named inequality applied to it, and every threshold
carries a sentence of the form *under the null this fires with probability at
most X, and here is why*. No number in this file was chosen because it
separated attack data. There is no place to put one: each threshold is a pure
function of ``(trials, null probability, eps)`` and the only run data any of
them touches is a **conditioning variable**, which :ref:`D-3 <d3>` shows is a
different thing.

Every threshold is a function of a false-positive budget ``eps``, never a
constant. Phase 5 sweeps ``eps`` to build a ROC curve, and each point on that
curve is a derived operating point rather than a knob turned until the picture
improved.

.. _the-nulls:

The three nulls, and where they come from
-----------------------------------------
All three are stated in :mod:`sih141.detect.statistics` and are restated here
because a threshold module that did not carry its own nulls would be a table of
constants. Throughout, ``n`` is the **sifted** key length
(:attr:`~sih141.detect.statistics.TranscriptStatistics.key_length`, which is
:attr:`~sih141.protocol.params.ProtocolParams.signing_length`, *not* the
nominal ``L``) and ``p = 1/|B|`` is the per-position match probability.

``|M_R| ~ Binomial(n, p)``, per verifier, **unconditionally**
    Alice draws each declared basis uniformly and independently; each recipient
    draws his own the same way. Phase A' then tosses a fair coin per position
    and either keeps or swaps an *exchangeable* pair, which leaves the joint
    law alone. Conditionally on the records the two counts are perfectly
    negatively dependent (``m_C = M - m_B``), which is why only the
    unconditional law may be used from a transcript.

``M = m_B + m_C ~ Binomial(2n, p)``, **exactly, by conservation**
    The coins re-assign a fixed multiset of ``2n`` entries, so ``M`` is
    coin-invariant and is a sum of ``2n`` i.i.d. indicators. This is *not*
    derived by convolving the two marginals -- given the records they are not
    independent -- even though that route lands on the same answer. See
    :mod:`sih141.protocol.tally` and ``:ref:`pooled-floor``` in
    :mod:`sih141.protocol.verify`.

``e_R | |M_R| = m  ~  Binomial(m, p_e)``
    ``p_e`` is the link's true error rate. On a noiseless link it is ``0`` and
    the null is a **point mass at zero**, under which any detector firing on
    ``e_R >= 1`` has a false-positive probability of exactly zero. The cost of
    that free bound is stated with it: it is a claim about a noiseless link,
    and a transcript with ``check_fraction = 0`` carries no estimate of ``p_e``
    at all (:mod:`sih141.detect.statistics`, finding 2). So ``p_e`` is a
    **keyword argument this module refuses to invent**, defaulting to the
    noiseless ``0.0`` and saying so on every object it produces.

.. _d1:

(D-1) The lower-tail critical count
-----------------------------------
Wanted: the largest integer ``k`` for which ``P(S <= k) <= eps`` is *provable*,
for ``S ~ Binomial(N, q)`` with mean ``mu = N q``. Fire iff ``S <= k``. This is
the starvation / evidence-denial tail.

**Multiplicative Chernoff.** For ``0 < d <= 1``,

.. code-block:: text

    P(S <= (1 - d) mu)  <=  exp(-d^2 mu / 2)

Setting the right-hand side to ``eps`` and solving for ``d``:

.. code-block:: text

    d^2 mu / 2 = ln(1/eps)
    d          = sqrt(2 ln(1/eps) / mu)
    k_lo       = floor((1 - d) mu)

``k_lo <= (1 - d) mu``, so ``{S <= k_lo}`` is contained in
``{S <= (1 - d) mu}`` and inherits its bound. The form needs ``d <= 1``, i.e.
``mu >= 2 ln(1/eps)``; below that ``(1 - d) mu`` is negative, the event is
empty and the inequality certifies nothing at this budget. The derived detector
is then **silent** -- it never fires, its false-positive probability is exactly
zero, and it is flagged :attr:`~DerivedThreshold.vacuous` rather than quietly
clamped to something that looks like a threshold.

This is the protocol's own floor arithmetic, deliberately:
:func:`~sih141.protocol.verify.minimum_matched_count` computes
``m_min = max(1, ceil((1 - d) mu))`` at
``eps =`` :data:`~sih141.protocol.verify.HONEST_ABORT_BUDGET` and aborts iff
``|M_R| < m_min``, that is iff ``|M_R| <= m_min - 1``. Since
``ceil(x) - 1 <= floor(x)``, the derived detector at the same budget fires on
every count the protocol's floor aborts on, and at both shipped parameter sets
the two coincide to the integer (pinned in :func:`matched_count_threshold` and
:func:`pooled_count_threshold`).

**Hoeffding**, distribution-free, for ``S`` a sum of ``N`` independent
variables in ``[0, 1]``:

.. code-block:: text

    P(S <= mu - t)  <=  exp(-2 t^2 / N)
    t     = sqrt(N ln(1/eps) / 2)
    k_lo  = floor(mu - t)

No side condition, valid at every ``N``, and -- see :ref:`F1 <findings>` --
sharper than the multiplicative form at ``q = 1/3`` wherever either has any
power at all. **The ordering is not universal and that is why both are kept**:
the multiplicative form is tuned for small ``q`` and wins by an order of
magnitude on the mismatch null, where ``q = p_e`` is a per-cent-scale error
rate rather than ``1/3``. ``method="sharpest"`` does not have to know which is
which.

**Exact.** ``P(S <= k)`` is the binomial cdf, monotone in ``k``, so the largest
admissible ``k`` is found by bisection. An equality rather than an inequality,
hence the tightest certified threshold that exists.

.. _d2:

(D-2) The upper-tail critical count
-----------------------------------
Wanted: the smallest ``k`` for which ``P(S >= k) <= eps`` is provable. Fire iff
``S >= k``. This is the recipient-forgery / error-inflation tail.

**Multiplicative Chernoff.** For ``d > 0``,

.. code-block:: text

    P(S >= (1 + d) mu)  <=  exp(-d^2 mu / (2 + d))

Setting the right-hand side to ``eps`` gives a quadratic in ``d``, which is the
one piece of algebra in this module worth writing out in full:

.. code-block:: text

    d^2 mu / (2 + d) = ln(1/eps)                       write  a = ln(1/eps)
    d^2 mu           = a (2 + d)
    mu d^2 - a d - 2 a = 0
    d = ( a + sqrt(a^2 + 8 mu a) ) / (2 mu)            positive root
    k_hi = ceil((1 + d) mu)

``k_hi >= (1 + d) mu``, so ``{S >= k_hi}`` is contained in
``{S >= (1 + d) mu}`` and inherits its bound. Unlike the lower form this one
has no side condition: ``d`` is positive for every ``mu > 0``.

**Hoeffding** and **exact** mirror :ref:`D-1 <d1>` with ``k_hi = ceil(mu + t)``
and a bisection on the upper tail.

.. _d3:

(D-3) Conditioning on ``|M_R|`` is not fitting
----------------------------------------------
The mismatch threshold is a function of the observed matched count, which is
run data, and that deserves the paragraph rather than a shrug. It is
**conditioning**, and the bound survives it by the tower rule: the inner bound
holds for *every* value of the conditioning variable, so

.. code-block:: text

    P(fire) = E[ P(e_R >= k(|M_R|) | |M_R|) ]  <=  E[eps]  =  eps

What would make it fitting is a dependence on the statistic being *tested* or
on any observation of an attack, and there is neither: ``k`` is a function of
``|M_R|``, ``p_e`` and ``eps`` alone. The same argument licenses no other
reach -- in particular it does **not** license reading ``p_e`` off the run
whose ``e_R`` is being tested, which is why ``p_e`` arrives as an argument.

**And it licenses nothing across runs**, which is the half that could have gone
wrong quietly. A threshold conditioned on ``|M_R| = 200`` and applied to a run
holding ``|M_R| = 69`` bounds nothing, while every number still computes;
:meth:`RateCountThresholds.evaluate` refuses that combination outright at a
positive ``p_e``. At ``p_e = 0`` the threshold is ``e_R >= 1`` for every
possible matched count, so there is nothing to condition on and nothing to
refuse -- the guard appears exactly where the derivation needs it.

.. _d4:

(D-4) The family budget, and why the roster is fixed
----------------------------------------------------
:class:`RateCountThresholds` fires when **any** member fires, so its
false-positive probability is bounded by the sum of its members' bounds -- a
union bound, which needs no independence and gets none (the matched-count test
and the mismatch test share ``|M_R|`` by construction).

The roster is a **constant of the module**, :data:`RATE_COUNT_ROSTER`, twelve
budgeted names long, and each member is allocated ``eps / 12``:

.. code-block:: text

    P(any member fires | honest)  <=  sum over members of bound_i
                                  <=  12 * (eps / 12)  =  eps

Fixing the roster rather than sizing it to the run is what makes that line
true without a second thought. A run in which a party reached no verdict simply
has members that cannot fire, and a union bound over a superset of the events
is still a bound; sizing the split to the run would instead make the per-member
budget a function of the data.

:data:`RATE_COUNT_FREE_TESTS` is charged nothing because its bound is
**exactly zero**: a declared count that disagrees with the count its own
verifier then scored is not a deviation under any null, it is two integers that
must be equal being unequal. That is the strongest bound in the family and the
cheapest, exactly as the structural aborts are in layer one.

**One half of the union bound is conditional, and the object says which.**
:attr:`RateCountThresholds.false_positive_bound` reports the sum of what the
members actually prove, which is tighter than ``eps`` because a threshold is an
integer and a budget is not. Ten of the twelve members have thresholds that are
functions of the parameter set alone, so those terms are constants. The two
mismatch members are functions of the observed ``|M_R|``, so at a positive
noise level their terms -- and hence the sum -- are bounds on
``P(fire | the matched counts)``. The *unconditional* guarantee is ``eps``, by
the same tower rule as :ref:`D-3 <d3>`, and
:attr:`RateCountThresholds.bound_is_unconditional` says which of the two a
report may quote. At the default ``channel_error_rate = 0`` the mismatch terms
are exactly zero for every possible ``|M_R|``, the flag is ``True`` and the
distinction does not arise; it is stated because a Phase 5 ROC plotted at the
wrong one of those two numbers would be wrong in a way nothing would flag.

.. _d5:

(D-5) Choosing among proofs is not choosing among separations
-------------------------------------------------------------
``method="sharpest"``, the default, evaluates every applicable inequality at
the same ``eps`` and keeps the most sensitive threshold any of them certifies,
recording which one won in :attr:`DerivedThreshold.inequality`. This is the one
form of "pick the best number" convention D7 permits, and the reason is that
each candidate is admissible **on its own, before any data exists**: they are
three proofs of statements about the same null, not three fits to the same
sample. Selection happens over proofs; nothing in the selection can see a
transcript. ``"sharpest"`` picks ``"exact"`` whenever the exact tail is
computable, which is the honest description of what it does.

.. _relative:

What it means to flag a run the protocol accepted
-------------------------------------------------
``s_a = 1/64`` and ``s_v = 1/16`` are **not** false-positive budgets and must
not be read as thresholds of the kind this module derives. ``s_a`` is a noise
budget -- the depolarising rate ``2 s_a = 3.125%`` the resource is allowed to
carry -- and ``s_v`` is placed at ``0.75`` of the recipient-forger floor
``1/12`` to buy an unforgeability exponent. Neither carries a stated honest-run
firing probability and neither is a function of ``eps``. So the verifier and
the detector are answering different questions:

* the **verifier** asks *is this signature acceptable under the scheme's noise
  and forgery budgets*;
* the **detector** asks *is this link the link the null describes*.

A run can be accepted and flagged at once, and under the noiseless null every
run with a single mismatch is. **That flag is not a rejection.** The verdict
stands; the flag says the channel departed from the null it was scored against.
Folding one into the other would report a detection that never happened, which
is constraint 4 of Phase 3 applied one layer further out, and
:class:`RateCountVerdict` keeps them in separate fields with separate types for
the same reason layer one keeps aborts out of verdicts.

The quantity that says whether the detector adds anything over the verifier is
the **dominance crossover** (:func:`dominance_noise_level`): the largest link
error rate at which the derived threshold still sits at or below the party's
own cut. Above it, every run the detector flags the verifier has already
rejected and the detector's marginal information is zero. At
:data:`~sih141.protocol.params.DEFAULT_PARAMS` with ``m = 38400`` and
``eps = 1e-9`` the crossover is ``p_e = 0.012119`` against ``s_a = 0.015625``,
and the design noise level ``2 s_a = 0.03125`` sits **above** it. So on a link
running at the noise ``s_a`` was sized for, the ``r_R`` detector at that budget
is dominated by Bob's own acceptance test, and all of its power comes from
assuming the link is quieter than the protocol assumes.

The crossover is a property of the **cut**, not of the detector, which is why
it is computed per party: against Charlie's looser ``s_v = 1/16`` it moves to
``0.055355``, on the far side of the design noise level with a factor of about
``1.8`` in hand, so against *him* the detector does still add information
there. The tighter cut is the one that squeezes the detector out. Report the
crossover next to the threshold, per party; a Phase 5 table quoting one without
the other is quoting a detection rate whose denominator is an assumption.

.. _findings:

Findings, reported rather than reached around
---------------------------------------------
**F1. The protocol's own matched-count floors use the loosest of the three
inequalities.** At ``q = 1/3`` the multiplicative Chernoff lower tail is
dominated by the exact tail at every key length, and by Hoeffding at every key
length where either of the two closed forms has any power at all -- so a floor
derived from either would be strictly higher at the *same* ``2**-64`` budget:

Every entry below is a **critical count** -- the largest count that trips the
rule -- so the protocol's floors appear as ``m_min - 1`` and ``M_min - 1``,
which is what ``|M_R| < m_min`` actually means. Mixing a floor and a critical
count in one table would be off by one in the column a reader compares:

============ ============= ============ ============ ==============
``L``        protocol      Hoeffding    exact        exact, pooled
============ ============= ============ ============ ==============
``192``      ``0``         ``-1``       ``11``       ``49``
``360``      ``16``        ``30``       ``44``       ``130``
``600``      ``66``        ``84``       ``100``      ``256``
``115200``   ``36554``     ``36801``    ``36951``    ``74749``
============ ============= ============ ============ ==============

(the ``-1`` is this module's unreachable count: at ``L = 192`` neither closed
form certifies anything at this budget, so both are silent, and the protocol's
``0`` is its floor having clamped to "abort only on an empty matched set". The
numbers are computed in :func:`floor_comparison`, which is doctested, so the
table cannot drift, and ``tests/test_detect_rate.py`` pins it whole.)

This is not a defect --- a looser floor aborts honest runs *less* often and
every bound the protocol quotes is still valid --- but the margin
``M_min - 2 m_min`` that closes the split-coin route of ``:ref:`pooled-floor```
is bought at the loosest available exchange rate, and at ``L = 192`` the
shipped per-verifier floor degenerates while the exact tail at the same budget
certifies a real one. The fix belongs in :mod:`sih141.protocol.verify`, which
this module does not own, and it is not a one-line change:
:func:`~sih141.protocol.verify.enforced_repudiation_bound` and the
``(2 - sqrt 2) A`` margin argument are both stated in the Chernoff form.

**F2. Pooling costs a factor of ``sqrt(2)`` against a party-localised
deviation.** A recipient forgery moves one verifier's count from ``n/3`` to
``2n/3``, a shift of ``n/3`` against a null spread of ``sqrt(2n)/3``, i.e.
``sqrt(n/2)`` standard deviations -- concretely ``9.80`` honest standard
deviations at ``n = 192`` and ``240`` at
:data:`~sih141.protocol.params.DEFAULT_PARAMS`, confirming Phase 3's constraint
5. The same forgery moves the *pooled* count by exactly ``1/sqrt(2)`` as many
standard deviations, ``6.93`` and ``169.71``, because the deviation is
unchanged while the null's spread grows like ``sqrt(2n)``
(:func:`forgery_separation_sigma`). So the pooled count is the weaker
discriminator for anything one party does alone, and it is kept because it is
the statistic every repudiation bound is exponential in and the one that sees a
shortfall in the *total* evidence base. Neither is pooled into the other, for
the same reason layer one refuses to pool the two links' check logs.

**F3. The ``r_R`` detector is dominated at the design noise level**, above.

**F4. ``p_e`` is not obtainable from a transcript with no check rounds.** Layer
one's finding 2, inherited. This module's answer is to make the noise level an
argument with a noiseless default and to carry
:attr:`DerivedThreshold.null` saying which was used, so that no report can
quote a noiseless bound over a noisy link without the sentence appearing beside
it.

**F5. The mismatch rate detects a party-targeted channel attack and cannot
attribute it -- and unlike the check logs, it cannot be un-pooled.** Phase 3's
constraint 3 forbids pooling the two links' *check logs*, on the grounds that
per-link QBER is the only statistic that both detects a party-targeted channel
attack and attributes it. The mismatch rate is a different case and a worse
one: it is **already** pooled, by the protocol itself, and no option restores
the attribution. Phase A' swaps records between the two recipients, so a record
damaged on Bob's link is held by Charlie half the time, while the check logs
are never swapped. Measured with a depolariser at strength ``0.30`` aimed at
Bob's link alone (``L = 384``, ``check_fraction = 0.25``): the check-round QBER
names the link on every run -- Bob three to seven errors out of twenty-four,
Charlie zero out of twenty-four, every run -- while the two mismatch counts are
scrambled across the recipients, and on some runs *Charlie's is the larger of
the two*. So the party in a roster name like ``mismatch_rate:Bob`` names the
**verifier who scored**, never the link that was touched, and a Phase 5 table
that read it as an attribution would be reporting which recipient the
symmetrisation coins happened to hand a damaged record to. Attribution lives in
the check-round family and is conditioned on (NO-TIMING).
``tests/test_detect_rate.py`` pins it.

**F6. At the noise level the scheme was designed to tolerate, the
noiseless-null detector flags runs both verifiers accept.** F3's crossover, as
a measurement rather than as an argument. Depolarising noise at ``p = 0.03``,
just inside the ``2 s_a = 0.03125`` budget ``s_a`` was sized for: six of twelve
runs were accepted by **both** verifiers and flagged by the noiseless-null
mismatch threshold. Every one of those flags is a true statement -- the link is
not the noiseless link the null describes -- and not one of them is a
rejection. It is the concrete reason ``channel_error_rate`` is an argument, and
the concrete reason :func:`dominance_noise_level` belongs beside every rate
threshold that gets published. (The six is a sample, not a rate;
``tests/test_detect_rate.py`` pins only that the count is positive over those
twelve seeds, because that is the part of it that is a claim.)

**F7. The two count-exchange orderings answer differently, and this family
measures how differently.** Constraint 6 says never to pool runs across
``count_exchange_timing``; here is what pooling would average. A recipient
forgery at ``L = 600``, twenty runs per ordering, ``eps = 1e-9``: under
``COUNTS_AFTER_FORWARDING`` Bob refuses and Charlie reaches a verdict that this
family flags on all three of his members, twenty runs out of twenty. Under
``COUNTS_BEFORE_FORWARDING`` it is Charlie who refuses, Bob reaches a verdict
whose numbers are indistinguishable from honest, and the family flags **zero**
out of twenty -- correctly, because in that arm the attack is a denial of
service against Charlie and not a forgery that reached anybody. A table
averaging the two would publish a ``50%`` detection rate for an experiment that
is a hundred per cent detection in one arm and a hundred per cent
denial-of-service in the other. :attr:`RateCountVerdict.grouping_key` carries
the ordering so the grouping is mechanical rather than remembered. (Provenance:
the twenty-run figures come from a measurement over seeds ``100..119`` and
``200..219``; ``tests/test_detect_rate.py`` pins the same *shape* at six runs
per ordering -- every run flagged in one arm, none in the other, and which
party refuses in each -- which is where a regression would show up.)

Notes
-----
Determinism (D3)
    Nothing here draws randomness; there is no ``rng`` argument because there
    is nothing to draw for. Every function is a pure function of its arguments.
No machine learning (D4)
    Three concentration arguments, one exact cdf, one union bound and one
    bisection. There is no fitted quantity in this file.
Reads (the boundary)
    :class:`~sih141.detect.statistics.TranscriptStatistics` and
    :mod:`sih141.protocol`. Never a transcript, never a session, never an
    adversary, never a harness.

Examples
--------
The derived lower-tail threshold at the protocol's own budget reproduces the
protocol's own floor, through completely separate code:

>>> from sih141.detect.thresholds_rate import matched_count_threshold
>>> from sih141.protocol.params import DEFAULT_PARAMS
>>> from sih141.protocol.verify import (
...     HONEST_ABORT_BUDGET, minimum_matched_count
... )
>>> low = matched_count_threshold(
...     DEFAULT_PARAMS.signing_length,
...     DEFAULT_PARAMS.match_probability,
...     eps=HONEST_ABORT_BUDGET,
...     side="lower",
...     method="chernoff",
... )
>>> low.critical_count, minimum_matched_count(DEFAULT_PARAMS) - 1
(36554, 36554)

Sharpen the same threshold by changing only the *proof*, at the same budget:

>>> sharp = matched_count_threshold(
...     DEFAULT_PARAMS.signing_length,
...     DEFAULT_PARAMS.match_probability,
...     eps=HONEST_ABORT_BUDGET,
...     side="lower",
... )
>>> sharp.critical_count, sharp.inequality
(36951, 'exact binomial tail')
>>> sharp.false_positive_bound <= HONEST_ABORT_BUDGET
True

``eps`` is the argument, so the operating point moves with the budget and
nothing else:

>>> [
...     matched_count_threshold(
...         192, 1 / 3, eps=e, side="upper"
...     ).critical_count
...     for e in (1e-3, 1e-6, 1e-9)
... ]
[86, 97, 106]

The whole family over one honest run, with its own proven bound:

>>> import numpy as np
>>> from sih141.detect.statistics import TranscriptStatistics
>>> from sih141.detect.thresholds_rate import RateCountThresholds
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> stats = TranscriptStatistics.from_transcript(
...     QDSSession(
...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
...     ).run(0)
... )
>>> family = RateCountThresholds.for_transcript(stats, eps=1e-9)
>>> verdict = family.evaluate(stats)
>>> verdict.flagged, verdict.fired
(False, ())
>>> f"{family.false_positive_bound:.3e}"
'4.804e-10'
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from sih141.detect.statistics import CountStatistic, TranscriptStatistics
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams
from sih141.protocol.verify import (
    HONEST_ABORT_BUDGET,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

__all__ = [
    "EXACT_TRIALS_LIMIT",
    "INEQUALITIES",
    "RATE_COUNT_FREE_TESTS",
    "RATE_COUNT_ROSTER",
    "DerivedThreshold",
    "RateCountThresholds",
    "RateCountVerdict",
    "binomial_tail_bound",
    "critical_count",
    "declared_count_threshold",
    "dominance_noise_level",
    "floor_comparison",
    "forgery_separation_sigma",
    "matched_count_threshold",
    "mismatch_rate_threshold",
    "pooled_count_threshold",
]


#: The inequalities this module will invert, in the order ``"sharpest"``
#: consults them. ``"exact"`` is first because it dominates the other two by
#: construction -- it inverts the cdf itself rather than a bound on it -- so a
#: tie is reported as the exact tail, which is the honest attribution.
INEQUALITIES: Final[tuple[str, ...]] = ("exact", "hoeffding", "chernoff")

#: Human-readable names, so a :class:`DerivedThreshold` prints the proof that
#: produced it rather than a slug.
_INEQUALITY_NAMES: Final[Mapping[str, str]] = {
    "exact": "exact binomial tail",
    "hoeffding": "Hoeffding",
    "chernoff": "multiplicative Chernoff",
}

#: Above this many trials the exact tail is not attempted by ``"sharpest"``,
#: which falls back to the sharpest closed form and says so in
#: :attr:`DerivedThreshold.inequality`. The bisection costs a few tens of
#: milliseconds at :data:`~sih141.protocol.params.DEFAULT_PARAMS` and grows
#: like ``sqrt(N)`` per evaluation, so the cap exists to keep a Phase 5 sweep
#: over thousands of runs from silently becoming the slow part; it is a
#: performance guard and changing it changes no bound. Asking for
#: ``method="exact"`` explicitly ignores it.
EXACT_TRIALS_LIMIT: Final[int] = 4_000_000

#: The twelve budgeted members of the family, fixed as a constant of the module
#: rather than sized to a run. :ref:`D-4 <d4>` explains why: the union bound
#: over a fixed roster is a sentence a reader can check, and a roster sized to
#: the run would make each member's budget a function of the data. Members that
#: cannot evaluate on a given run never fire, which only shrinks the event.
RATE_COUNT_ROSTER: Final[tuple[str, ...]] = (
    "mismatch_rate:Bob",
    "mismatch_rate:Charlie",
    "matched_count_low:Bob",
    "matched_count_low:Charlie",
    "matched_count_high:Bob",
    "matched_count_high:Charlie",
    "declared_count_low:Bob",
    "declared_count_low:Charlie",
    "declared_count_high:Bob",
    "declared_count_high:Charlie",
    "pooled_count_low",
    "pooled_count_high",
)

#: Members charged nothing, because their false-positive probability is exactly
#: zero rather than merely small. ``declaration_gap`` compares the integers a
#: recipient put on the wire in Phase C' with the count his own verdict scored;
#: on an honest run those are the same integer by construction, so a non-zero
#: gap is not a deviation under any null. The strongest bound in the family and
#: it costs no budget -- the same trade
#: :data:`~sih141.detect.statistics.STRUCTURAL_ABORT_REASONS` makes in layer
#: one.
RATE_COUNT_FREE_TESTS: Final[tuple[str, ...]] = ("declaration_gap",)

_SIDES: Final[frozenset[str]] = frozenset({"lower", "upper"})
_METHODS: Final[frozenset[str]] = frozenset(INEQUALITIES) | {"sharpest"}

#: Relative slack at which the rigorous geometric remainder of a binomial tail
#: is folded in and the summation stops. Not a tuned constant: the remainder is
#: *added* to the sum, so the returned tail is an upper bound whatever this is,
#: and the only thing it buys is that the loop stops after a few hundred terms
#: instead of ``N``.
_TAIL_SLACK: Final[float] = 1e-18


# --------------------------------------------------------------------------- #
# Argument checking, in the house style: refuse, and say what to pass instead
# --------------------------------------------------------------------------- #


def _as_count(value: Any, name: str) -> int:
    """Coerce a non-negative integer count.

    Parameters
    ----------
    value : Any
        The candidate.
    name : str
        Field name, quoted in error messages.

    Returns
    -------
    int

    Raises
    ------
    TypeError
        If ``value`` is not an integer.
    ValueError
        If ``value`` is negative.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{name} must be an int, got {type(value).__name__}. Counts here "
            f"are numbers of positions, and a float count would silently make "
            f"an integer threshold non-integer."
        )
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}.")
    return value


def _as_probability(value: Any, name: str) -> float:
    """Coerce a probability in ``[0, 1]``.

    Parameters
    ----------
    value : Any
        The candidate.
    name : str
        Field name, quoted in error messages.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``value`` is not a real number.
    ValueError
        If ``value`` lies outside ``[0, 1]`` or is not finite.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be a real number, got {type(value).__name__}."
        )
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(
            f"{name} must lie in [0, 1], got {number}. It is a probability, "
            f"not a percentage: pass 0.01, not 1."
        )
    return number


def _as_budget(value: Any, name: str = "eps") -> float:
    """Coerce a false-positive budget in the open interval ``(0, 1)``.

    Parameters
    ----------
    value : Any
        The candidate.
    name : str, optional
        Field name, quoted in error messages.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``value`` is not a real number.
    ValueError
        If ``value`` is not strictly inside ``(0, 1)``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be a real number, got {type(value).__name__}."
        )
    number = float(value)
    if not math.isfinite(number) or not 0.0 < number < 1.0:
        raise ValueError(
            f"{name} must lie strictly inside (0, 1), got {number}. It is a "
            f"false-positive budget: a budget of 0 buys a detector that never "
            f"fires and a budget of 1 buys one that fires on everything, and "
            f"neither is a threshold."
        )
    return number


def _check_side(side: Any) -> str:
    """Validate the tail name.

    Parameters
    ----------
    side : Any
        ``'lower'`` or ``'upper'``.

    Returns
    -------
    str

    Raises
    ------
    ValueError
        If ``side`` names no tail.
    """
    if not isinstance(side, str) or side not in _SIDES:
        raise ValueError(
            f"side must be one of {sorted(_SIDES)}, got {side!r}. A one-sided "
            f"detector must name the tail it tests; a two-sided threshold "
            f"would spend half its budget on a tail nobody looks at."
        )
    return side


def _check_method(method: Any) -> str:
    """Validate the inequality selector.

    Parameters
    ----------
    method : Any
        One of :data:`INEQUALITIES` or ``'sharpest'``.

    Returns
    -------
    str

    Raises
    ------
    ValueError
        If ``method`` names no inequality.
    """
    if not isinstance(method, str) or method not in _METHODS:
        raise ValueError(
            f"method must be one of {sorted(_METHODS)}, got {method!r}. "
            f"'sharpest' consults every inequality at the same eps and keeps "
            f"the most sensitive threshold any of them proves; see D-5."
        )
    return method


# --------------------------------------------------------------------------- #
# The tails
# --------------------------------------------------------------------------- #


def _log_pmf(successes: int, trials: int, probability: float) -> float:
    """Return ``log P(S = successes)`` for ``S ~ Binomial(trials, probability)``.

    Through :func:`math.lgamma` rather than :func:`math.comb`, because the
    binomial coefficient at ``N = 230400`` is an integer with about seventy
    thousand digits and the ratio it appears in is an ordinary float.

    Parameters
    ----------
    successes : int
        ``0 <= successes <= trials``.
    trials : int
        At least ``1``.
    probability : float
        Strictly inside ``(0, 1)``; the degenerate cases are handled by the
        callers, exactly.

    Returns
    -------
    float
    """
    return (
        math.lgamma(trials + 1.0)
        - math.lgamma(successes + 1.0)
        - math.lgamma(trials - successes + 1.0)
        + successes * math.log(probability)
        + (trials - successes) * math.log1p(-probability)
    )


def _upper_tail(count: int, trials: int, probability: float) -> float:
    """Return an upper bound on ``P(S >= count)``, tight to rounding.

    Sums the exact terms outward from ``count`` and stops once a **rigorous**
    geometric bound on everything left is negligible beside what has been
    accumulated. The remainder is added rather than dropped, so the result is
    never below the true tail -- which is the direction a security claim has to
    err in.

    The ratio ``t[j+1]/t[j] = ((N - j) / (j + 1)) (p / (1 - p))`` decreases in
    ``j``, so once it is below one at some ``J`` it stays below, and

    .. code-block:: text

        sum over j > J of t[j]  <=  t[J] * r_J / (1 - r_J)

    Parameters
    ----------
    count : int
        The tail's left endpoint, included.
    trials : int
        At least ``1``.
    probability : float
        Strictly inside ``(0, 1)``.

    Returns
    -------
    float
    """
    if count <= 0:
        return 1.0
    if count > trials:
        return 0.0
    odds = probability / (1.0 - probability)
    total = 0.0
    index = count
    while index <= trials:
        term = math.exp(_log_pmf(index, trials, probability))
        total += term
        if index < trials:
            ratio = ((trials - index) / (index + 1.0)) * odds
            if ratio < 1.0:
                remainder = term * ratio / (1.0 - ratio)
                if remainder <= _TAIL_SLACK * max(total, 5e-324):
                    total += remainder
                    break
        index += 1
    return min(1.0, total)


def _lower_tail(count: int, trials: int, probability: float) -> float:
    """Return an upper bound on ``P(S <= count)``, tight to rounding.

    The mirror of :func:`_upper_tail`, walking down from ``count``. The ratio
    ``t[j-1]/t[j] = (j / (N - j + 1)) ((1 - p) / p)`` decreases as ``j``
    decreases, so the same geometric remainder applies.

    Parameters
    ----------
    count : int
        The tail's right endpoint, included.
    trials : int
        At least ``1``.
    probability : float
        Strictly inside ``(0, 1)``.

    Returns
    -------
    float
    """
    if count < 0:
        return 0.0
    if count >= trials:
        return 1.0
    odds = (1.0 - probability) / probability
    total = 0.0
    index = count
    while index >= 0:
        term = math.exp(_log_pmf(index, trials, probability))
        total += term
        if index > 0:
            ratio = (index / (trials - index + 1.0)) * odds
            if ratio < 1.0:
                remainder = term * ratio / (1.0 - ratio)
                if remainder <= _TAIL_SLACK * max(total, 5e-324):
                    total += remainder
                    break
        index -= 1
    return min(1.0, total)


def binomial_tail_bound(
    count: int,
    trials: int,
    probability: float,
    *,
    side: str,
    method: str = "sharpest",
) -> float:
    """Bound the one-sided null probability of the observed count.

    ``side="lower"`` bounds ``P(S <= count)`` and ``side="upper"`` bounds
    ``P(S >= count)``, for ``S ~ Binomial(trials, probability)``. This is the
    forward direction; :func:`critical_count` inverts it.

    Parameters
    ----------
    count : int
        ``0 <= count <= trials``.
    trials : int
        At least ``0``.
    probability : float
        The null's per-trial success probability, in ``[0, 1]``. The two
        endpoints are point-mass nulls and are answered exactly.
    side : {'lower', 'upper'}
        Keyword-only. Which tail.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
        Keyword-only. Which inequality to apply; ``'sharpest'`` returns the
        smallest bound any of them proves (:ref:`D-5 <d5>`).

    Returns
    -------
    float
        A number in ``[0, 1]``, always an upper bound on the true tail.

    Raises
    ------
    TypeError
        If a count is not an integer or ``probability`` is not a real number.
    ValueError
        If ``count > trials``, ``probability`` is outside ``[0, 1]``, or
        ``side``/``method`` names nothing.

    Notes
    -----
    The multiplicative Chernoff forms are stated for a deviation *away from the
    mean*, so each returns ``1.0`` when the observation sits on the wrong side
    of the mean for that tail to be a tail. The exact form has no such caveat
    and is simply the cdf.

    **What "exact" means here, precisely.** The exact tail is summed in IEEE
    754 doubles through :func:`math.lgamma`, and the summation stops early with
    a *rigorous* geometric bound on the remainder folded in rather than
    dropped. Against exact rational arithmetic at ``n = 192``, swept over every
    count and over ``p`` in {1/3, 1/2, 1/12, 1/64} on both tails, the agreement
    is to a relative ``3e-13`` or better wherever the tail is representable in
    double precision; the worst case measured is ``2.624e-13`` at ``p = 1/12``
    on the upper tail. The residue is ordinary floating-point error in
    ``lgamma``, not the truncation -- ``tests/test_detect_rate.py`` pins that
    comparison. So a threshold sits at its budget to within a relative
    ``3e-13``, which is many orders finer than any budget this project quotes
    and is stated rather than glossed: "exact" names the *law* being inverted,
    not the arithmetic inverting it.

    The one place that agreement fails is where no double could hold it:
    below roughly ``1e-316`` the tail underflows, so the returned value and
    any double representation are both ``0.0`` while the rational is merely
    tiny. Every such count sits about 296 orders of magnitude below
    ``2**-64``, the smallest budget this project quotes, and so can never
    select a threshold. That is why the figures above are qualified by the
    representable range rather than stated across ``the range`` flatly -- an
    earlier draft said ``1.4e-13`` ``across the range``, which was in fact the
    maximum over the nine counts the pinning test parametrises. Audit 1 of
    Phase 4 caught it; the sweep behind the numbers now quoted is wider.

    Examples
    --------
    >>> from sih141.detect.thresholds_rate import binomial_tail_bound
    >>> f"{binomial_tail_bound(0, 192, 1 / 3, side='lower'):.3e}"
    '1.551e-34'
    >>> f"{binomial_tail_bound(0, 192, 1/3, side='lower', method='chernoff'):.3e}"
    '1.266e-14'

    The Chernoff form is the loosest of the three by a wide margin, which is
    :ref:`F1 <findings>` in one line:

    >>> counts = [
    ...     binomial_tail_bound(128, 192, 1 / 3, side="upper", method=m)
    ...     for m in ("exact", "hoeffding", "chernoff")
    ... ]
    >>> [f"{c:.2e}" for c in counts]
    ['4.39e-21', '2.95e-19', '5.43e-10']

    A point-mass null answers exactly, in both directions:

    >>> binomial_tail_bound(1, 5000, 0.0, side="upper")
    0.0
    >>> binomial_tail_bound(0, 5000, 0.0, side="upper")
    1.0
    """
    total = _as_count(trials, "trials")
    hits = _as_count(count, "count")
    if hits > total:
        raise ValueError(
            f"count ({hits}) exceeds trials ({total}); a count above its own "
            f"denominator is a counting error upstream, not a deviation."
        )
    chance = _as_probability(probability, "probability")
    tail = _check_side(side)
    how = _check_method(method)

    if total == 0:
        return 1.0
    if chance == 0.0:
        if tail == "upper":
            return 0.0 if hits >= 1 else 1.0
        return 1.0
    if chance == 1.0:
        if tail == "lower":
            return 0.0 if hits <= total - 1 else 1.0
        return 1.0

    candidates = INEQUALITIES if how == "sharpest" else (how,)
    best = 1.0
    for name in candidates:
        if name == "exact" and how == "sharpest" and total > EXACT_TRIALS_LIMIT:
            continue
        best = min(best, _one_tail_bound(hits, total, chance, tail, name))
    return best


def _one_tail_bound(
    count: int, trials: int, probability: float, side: str, method: str
) -> float:
    """Apply one named inequality to one tail.

    Parameters
    ----------
    count : int
        The observation.
    trials : int
        At least ``1``.
    probability : float
        Strictly inside ``(0, 1)``.
    side : {'lower', 'upper'}
        Which tail.
    method : {'exact', 'hoeffding', 'chernoff'}
        Which inequality.

    Returns
    -------
    float
    """
    mean = trials * probability
    if method == "exact":
        if side == "lower":
            return _lower_tail(count, trials, probability)
        return _upper_tail(count, trials, probability)
    if method == "hoeffding":
        gap = mean - count if side == "lower" else count - mean
        if gap <= 0.0:
            return 1.0
        return min(1.0, math.exp(-2.0 * gap * gap / trials))
    deviation = abs(count - mean) / mean
    if side == "lower":
        if count >= mean:
            return 1.0
        if deviation > 1.0:
            return 0.0
        return min(1.0, math.exp(-deviation * deviation * mean / 2.0))
    if count <= mean:
        return 1.0
    return min(
        1.0, math.exp(-deviation * deviation * mean / (2.0 + deviation))
    )


# --------------------------------------------------------------------------- #
# The inversion: eps in, a critical count out
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Critical:
    """One inverted threshold: the count, the proof and the realised bound."""

    count: int
    method: str
    bound: float
    vacuous: bool


def _chernoff_critical(
    trials: int, probability: float, eps: float, side: str
) -> int:
    """Invert the multiplicative Chernoff bound at ``eps``.

    :ref:`D-1 <d1>` and :ref:`D-2 <d2>` carry the algebra; this is those two
    closed forms and nothing else.

    Parameters
    ----------
    trials : int
        At least ``1``.
    probability : float
        Strictly inside ``(0, 1)``.
    eps : float
        Strictly inside ``(0, 1)``.
    side : {'lower', 'upper'}
        Which tail.

    Returns
    -------
    int
        ``-1`` for a lower tail the form cannot certify at this budget, where
        the derived detector is silent rather than clamped.
    """
    mean = trials * probability
    log_inverse = -math.log(eps)
    if side == "lower":
        slack = 2.0 * log_inverse
        if slack >= mean:
            return -1
        deviation = math.sqrt(slack / mean)
        return math.floor((1.0 - deviation) * mean)
    deviation = (
        log_inverse
        + math.sqrt(log_inverse * log_inverse + 8.0 * mean * log_inverse)
    ) / (2.0 * mean)
    return math.ceil((1.0 + deviation) * mean)


def _hoeffding_critical(
    trials: int, probability: float, eps: float, side: str
) -> int:
    """Invert the Hoeffding bound at ``eps``.

    Parameters
    ----------
    trials : int
        At least ``1``.
    probability : float
        Strictly inside ``(0, 1)``.
    eps : float
        Strictly inside ``(0, 1)``.
    side : {'lower', 'upper'}
        Which tail.

    Returns
    -------
    int
        May be negative for a lower tail, which the caller reads as "silent".
    """
    mean = trials * probability
    spread = math.sqrt(trials * -math.log(eps) / 2.0)
    if side == "lower":
        return math.floor(mean - spread)
    return math.ceil(mean + spread)


def _exact_critical(
    trials: int, probability: float, eps: float, side: str
) -> int:
    """Invert the exact binomial tail at ``eps``, by bisection.

    Both tails are monotone in the critical count, so bisection finds the
    extreme admissible one in ``log2(trials)`` tail evaluations.

    Parameters
    ----------
    trials : int
        At least ``1``.
    probability : float
        Strictly inside ``(0, 1)``.
    eps : float
        Strictly inside ``(0, 1)``.
    side : {'lower', 'upper'}
        Which tail.

    Returns
    -------
    int
    """
    if side == "lower":
        if _lower_tail(0, trials, probability) > eps:
            return -1
        low, high = 0, trials - 1
        while low < high:
            middle = (low + high + 1) // 2
            if _lower_tail(middle, trials, probability) <= eps:
                low = middle
            else:
                high = middle - 1
        return low
    low, high = 1, trials + 1
    while low < high:
        middle = (low + high) // 2
        if _upper_tail(middle, trials, probability) <= eps:
            high = middle
        else:
            low = middle + 1
    return low


def _invert(
    trials: int, probability: float, eps: float, side: str, method: str
) -> _Critical:
    """Return the sharpest critical count the requested proofs certify.

    Parameters
    ----------
    trials : int
        At least ``0``.
    probability : float
        In ``[0, 1]``.
    eps : float
        Strictly inside ``(0, 1)``.
    side : {'lower', 'upper'}
        Which tail.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}
        Which proofs to consult.

    Returns
    -------
    _Critical
    """
    named = _INEQUALITY_NAMES.get(method, method)
    silent_low = _Critical(-1, named, 0.0, True)
    silent_high = _Critical(trials + 1, named, 0.0, True)
    if trials == 0:
        # No trials is not a small sample, it is the absence of one. Both
        # thresholds are unreachable and the "inequality" that produced them is
        # named for what it is rather than for a proof nobody applied.
        empty = "no trials (the null has no denominator)"
        if side == "lower":
            return _Critical(-1, empty, 0.0, True)
        return _Critical(1, empty, 0.0, True)
    if probability == 0.0:
        if side == "upper":
            return _Critical(1, "point mass at 0", 0.0, False)
        return _Critical(-1, "point mass at 0", 0.0, True)
    if probability == 1.0:
        if side == "lower":
            return _Critical(trials - 1, "point mass at N", 0.0, False)
        return _Critical(trials + 1, "point mass at N", 0.0, True)

    candidates = INEQUALITIES if method == "sharpest" else (method,)
    # Start from the silent threshold on this side, so the loop only ever
    # improves on "never fires" and there is no None to guard afterwards.
    best = silent_low if side == "lower" else silent_high
    for name in candidates:
        if (
            name == "exact"
            and method == "sharpest"
            and trials > EXACT_TRIALS_LIMIT
        ):
            continue
        if name == "exact":
            found = _exact_critical(trials, probability, eps, side)
        elif name == "hoeffding":
            found = _hoeffding_critical(trials, probability, eps, side)
        else:
            found = _chernoff_critical(trials, probability, eps, side)
        if side == "lower":
            found = max(found, -1)
            if found <= best.count and not best.vacuous:
                continue
        else:
            found = min(found, trials + 1)
            if found >= best.count and not best.vacuous:
                continue
        vacuous = found < 0 if side == "lower" else found > trials
        if vacuous:
            continue
        best = _Critical(
            found,
            _INEQUALITY_NAMES[name],
            _one_tail_bound(found, trials, probability, side, name),
            False,
        )
    return best


def critical_count(
    trials: int,
    probability: float,
    *,
    eps: float,
    side: str,
    method: str = "sharpest",
) -> int:
    """Return the extreme count a false-positive budget of ``eps`` certifies.

    For ``side="lower"``: the **largest** ``k`` for which ``P(S <= k) <= eps``
    is provable by the requested inequality. For ``side="upper"``: the
    **smallest** ``k`` for which ``P(S >= k) <= eps`` is provable. Fire iff the
    observed count is at or beyond ``k`` on that side.

    Parameters
    ----------
    trials : int
        The null's denominator, at least ``0``.
    probability : float
        The null's per-trial success probability, in ``[0, 1]``.
    eps : float
        Keyword-only false-positive budget, strictly inside ``(0, 1)``.
    side : {'lower', 'upper'}
        Keyword-only.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
        Keyword-only. Which proofs to consult (:ref:`D-5 <d5>`).

    Returns
    -------
    int
        ``-1`` on a lower tail, or ``trials + 1`` on an upper tail, when the
        requested proof certifies nothing at this budget. Both are counts no
        observation can reach, so the derived detector is **silent**: it never
        fires, and its false-positive probability is exactly zero. Reported as
        an unreachable count rather than as a clamped one so that a silent
        detector cannot be mistaken for a working threshold.

    Raises
    ------
    TypeError
        If a count is not an integer or a probability is not a real number.
    ValueError
        If ``probability`` or ``eps`` is out of range, or ``side``/``method``
        names nothing.

    See Also
    --------
    binomial_tail_bound : The forward direction this inverts.
    matched_count_threshold : The same inversion, wrapped with its null.

    Examples
    --------
    >>> from sih141.detect.thresholds_rate import critical_count
    >>> critical_count(192, 1 / 3, eps=1e-9, side="lower")
    26
    >>> critical_count(192, 1 / 3, eps=1e-9, side="upper")
    106

    A tighter budget buys a less sensitive threshold, monotonically, which is
    what makes ``eps`` a ROC knob rather than a dial:

    >>> [
    ...     critical_count(192, 1 / 3, eps=e, side="lower")
    ...     for e in (1e-2, 1e-4, 1e-8, 1e-16)
    ... ]
    [48, 40, 29, 15]

    The multiplicative Chernoff form is vacuous at short key lengths, and says
    so with an unreachable count rather than a clamp:

    >>> critical_count(192, 1 / 3, eps=2.0**-64, side="lower", method="chernoff")
    -1
    >>> critical_count(192, 1 / 3, eps=2.0**-64, side="lower", method="exact")
    11
    """
    total = _as_count(trials, "trials")
    chance = _as_probability(probability, "probability")
    budget = _as_budget(eps)
    tail = _check_side(side)
    how = _check_method(method)
    return _invert(total, chance, budget, tail, how).count


# --------------------------------------------------------------------------- #
# The carrier
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DerivedThreshold:
    """One threshold, its null, the proof behind it and what it costs.

    The object convention **D7** asks for, made into data: every field a
    reviewer needs to check the derivation is on it, so a Phase 5 table
    rendered from these carries its own justification and a threshold that lost
    its derivation cannot be constructed.

    Attributes
    ----------
    name : str
        Roster name, e.g. ``"matched_count_low:Bob"``. Free text to the family;
        :data:`RATE_COUNT_ROSTER` is the list that matters.
    statistic : str
        What is compared against :attr:`critical_count`, in words.
    null : str
        The honest-run distribution, written out, including the assumption it
        rests on where there is one ("noiseless link").
    inequality : str
        Which concentration argument certified this threshold. One of the
        values of :data:`INEQUALITIES`, spelled out, or the name of a
        point-mass null where the answer is exact rather than bounded.
    side : {'lower', 'upper'}
        ``'lower'`` fires on ``count <= critical_count``, ``'upper'`` on
        ``count >= critical_count``.
    budget : float
        The ``eps`` this threshold was derived at -- its **share** of a family
        budget, not the family's.
    trials : int
        The null's denominator.
    null_probability : float
        The null's per-trial success probability.
    critical_count : int
        The threshold, as a count.
    false_positive_bound : float
        **The proven bound.** The probability, under the null, that this
        threshold fires on an honest run -- as the same inequality bounds it at
        the realised :attr:`critical_count`. Always at most :attr:`budget`, and
        usually far below it, because a threshold is an integer and the budget
        is not.
    derivation : str
        The algebra, with this object's numbers substituted, so the object can
        print its own proof.
    vacuous : bool
        ``True`` when :attr:`critical_count` is unreachable and the detector is
        silent. A silent detector has a false-positive probability of exactly
        zero and no power at all; both halves of that need saying.

    Raises
    ------
    TypeError
        If a count is not an integer or a probability is not a real number.
        ``critical_count`` in particular is checked rather than coerced: a
        threshold silently truncated from ``5.7`` to ``5`` is a different rule
        with a different false-positive probability.
    ValueError
        If ``side`` names no tail, ``null``/``derivation`` is empty, or
        :attr:`false_positive_bound` exceeds :attr:`budget` -- which would mean
        the derivation and the arithmetic disagree, and is refused at
        construction rather than reported downstream.

    Examples
    --------
    >>> from sih141.detect.thresholds_rate import matched_count_threshold
    >>> threshold = matched_count_threshold(192, 1 / 3, eps=1e-9, side="upper")
    >>> threshold.critical_count, threshold.inequality
    (106, 'exact binomial tail')
    >>> f"{threshold.false_positive_bound:.3e}"
    '4.048e-10'
    >>> threshold.fires(128), threshold.fires(64)
    (True, False)
    >>> print(threshold.claim())
    matched_count_high [Bob]: fires when |M_R| >= 106 out of 192; under Binomial(192, 1/3), the honest law of a verifier's matched count, this fires with probability at most 4.048e-10, by the exact binomial tail at a budget of 1.000e-09.
    """

    name: str
    statistic: str
    null: str
    inequality: str
    side: str
    budget: float
    trials: int
    null_probability: float
    critical_count: int
    false_positive_bound: float
    derivation: str
    vacuous: bool

    def __post_init__(self) -> None:
        """Coerce the fields and refuse a bound that exceeds its own budget."""
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "statistic", str(self.statistic))
        object.__setattr__(self, "null", str(self.null))
        object.__setattr__(self, "inequality", str(self.inequality))
        object.__setattr__(self, "side", _check_side(self.side))
        object.__setattr__(self, "budget", _as_budget(self.budget, "budget"))
        object.__setattr__(self, "trials", _as_count(self.trials, "trials"))
        object.__setattr__(
            self,
            "null_probability",
            _as_probability(self.null_probability, "null_probability"),
        )
        if isinstance(self.critical_count, bool) or not isinstance(
            self.critical_count, int
        ):
            raise TypeError(
                f"{self.name}: critical_count must be an int, got "
                f"{type(self.critical_count).__name__}. Not coerced: a "
                f"threshold silently truncated from 5.7 to 5 is a different "
                f"rule with a different false-positive probability, and "
                f"nothing downstream would say so."
            )
        object.__setattr__(
            self,
            "false_positive_bound",
            _as_probability(
                self.false_positive_bound, "false_positive_bound"
            ),
        )
        object.__setattr__(self, "derivation", str(self.derivation))
        object.__setattr__(self, "vacuous", bool(self.vacuous))
        if not self.null or not self.derivation:
            raise ValueError(
                f"{self.name}: a threshold must carry both its null and its "
                f"derivation. Convention D7: a number with neither is a "
                f"constant somebody chose, and there is no way to tell it "
                f"apart from one afterwards."
            )
        if self.false_positive_bound > self.budget:
            raise ValueError(
                f"{self.name}: proven false-positive bound "
                f"{self.false_positive_bound!r} exceeds its budget "
                f"{self.budget!r}. The inversion and the forward bound "
                f"disagree, which is an arithmetic error in this module and "
                f"not a property of the run."
            )

    # -- derived views ------------------------------------------------------ #

    @property
    def critical_rate(self) -> float | None:
        """float or None: :attr:`critical_count` as a rate; ``None`` at no trials.

        ``None`` rather than ``0.0`` for the reason
        :attr:`sih141.detect.statistics.CountStatistic.rate` gives: a rate over
        no trials is undefined, not zero.
        """
        if self.trials == 0:
            return None
        return self.critical_count / self.trials

    @property
    def expected(self) -> float:
        """float: ``trials * null_probability``, the null's mean."""
        return self.trials * self.null_probability

    def fires(self, count: int) -> bool:
        """Return whether an observed count trips this threshold.

        Parameters
        ----------
        count : int
            The observation, non-negative.

        Returns
        -------
        bool
            ``count <= critical_count`` on a lower tail, ``count >=
            critical_count`` on an upper one. Always ``False`` for a
            :attr:`vacuous` threshold, whose critical count no observation
            reaches.

        Raises
        ------
        TypeError
            If ``count`` is not an integer.
        ValueError
            If ``count`` is negative.
        """
        observed = _as_count(count, "count")
        if self.side == "lower":
            return observed <= self.critical_count
        return observed >= self.critical_count

    def claim(self) -> str:
        """Return the sentence convention D7 requires, as one line.

        Returns
        -------
        str
            *"... under the null this fires with probability at most X, and
            here is why"*, with the null, the bound and the inequality named. A
            :attr:`vacuous` threshold gets a different sentence, because it has
            no inequality to credit and its zero is a zero for a different
            reason -- it says both that it cannot false-alarm and that it
            cannot detect.

        Examples
        --------
        >>> from sih141.detect.thresholds_rate import (
        ...     matched_count_threshold, mismatch_rate_threshold
        ... )
        >>> print(mismatch_rate_threshold(59, eps=1e-9).claim())
        mismatch_rate [Bob]: fires when e_R >= 1 out of 59; under a point mass at 0 (e_R = 0 with probability one on a noiseless link), this fires with probability at most 0.000e+00, by the point mass at 0 at a budget of 1.000e-09.

        A key too short for the multiplicative form to say anything, which is
        the case that must not read like a working threshold:

        >>> print(
        ...     matched_count_threshold(
        ...         192, 1 / 3, eps=2.0**-64, side="lower", method="chernoff"
        ...     ).claim()
        ... )
        matched_count_low [Bob]: never fires -- no inequality certifies a threshold on Binomial(192, 1/3), the honest law of a verifier's matched count, at a budget of 5.421e-20, so this fires with probability exactly 0, and detects nothing. Unreachable critical count -1 out of 192.
        """
        base, _, party = self.name.partition(":")
        # The party goes in brackets rather than after a second colon, and it
        # is here at all so two members of the same kind are distinguishable
        # in a printed roster. It names the verifier who scored, never the link
        # that was touched -- see F5.
        label = f"{base} [{party}]" if party else base
        if self.vacuous:
            # A silent threshold has no critical count worth printing and no
            # inequality to credit. Both halves of what it is get said: the
            # false-positive probability is exactly zero, and so is the power.
            return (
                f"{label}: never fires -- no inequality certifies a threshold "
                f"on {self.null}, at a budget of {self.budget:.3e}, so this "
                f"fires with probability exactly 0, and detects nothing. "
                f"Unreachable critical count {self.critical_count} out of "
                f"{self.trials}."
            )
        comparison = "<=" if self.side == "lower" else ">="
        return (
            f"{label}: fires when {self.statistic} "
            f"{comparison} {self.critical_count} out of {self.trials}"
            f"; under {self.null}, this fires with probability at most "
            f"{self.false_positive_bound:.3e}, by the {self.inequality} at a "
            f"budget of {self.budget:.3e}."
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
            Every field, plus :attr:`critical_rate`, :attr:`expected` and
            :meth:`claim`. Passes to :func:`json.dumps` unchanged: no field is
            ever ``inf`` or ``nan``.
        """
        return {
            "name": self.name,
            "statistic": self.statistic,
            "null": self.null,
            "inequality": self.inequality,
            "side": self.side,
            "budget": self.budget,
            "trials": self.trials,
            "null_probability": self.null_probability,
            "critical_count": self.critical_count,
            "critical_rate": self.critical_rate,
            "expected": self.expected,
            "false_positive_bound": self.false_positive_bound,
            "derivation": self.derivation,
            "vacuous": self.vacuous,
            "claim": self.claim(),
        }


# --------------------------------------------------------------------------- #
# The three thresholds
# --------------------------------------------------------------------------- #


def _count_threshold(
    *,
    name: str,
    statistic: str,
    null: str,
    trials: int,
    probability: float,
    eps: float,
    side: str,
    method: str,
    extra: str = "",
) -> DerivedThreshold:
    """Build a :class:`DerivedThreshold` from one binomial inversion.

    Shared by the matched, declared and pooled thresholds, which differ only in
    what they name and in the denominator they are stated over. Keeping the
    inversion in one place is what makes "the same budget, the same
    inequality" true of the code and not only of the prose.

    Parameters
    ----------
    name : str
        Roster name.
    statistic : str
        What is compared, in words.
    null : str
        The distribution, written out.
    trials : int
        The null's denominator.
    probability : float
        The null's per-trial success probability.
    eps : float
        This threshold's share of the budget.
    side : {'lower', 'upper'}
        Which tail.
    method : str
        Which proofs to consult.
    extra : str, optional
        A sentence appended to the derivation, for a threshold with a
        provenance worth carrying (the pooled count's conservation argument,
        for instance).

    Returns
    -------
    DerivedThreshold
    """
    total = _as_count(trials, "trials")
    chance = _as_probability(probability, "probability")
    budget = _as_budget(eps)
    tail = _check_side(side)
    how = _check_method(method)
    found = _invert(total, chance, budget, tail, how)
    mean = total * chance
    reference = "D-1" if tail == "lower" else "D-2"
    algebra = (
        f"mu = {total} * {chance:.6f} = {mean:.4f}; "
        f"ln(1/eps) = {-math.log(budget):.4f}; "
        f"{reference} inverted by the {found.method} gives k = "
        f"{found.count}, at which the same argument bounds the honest firing "
        f"probability by {found.bound:.6e} <= eps = {budget:.6e}."
    )
    if extra:
        algebra = f"{algebra} {extra}"
    return DerivedThreshold(
        name=name,
        statistic=statistic,
        null=null,
        inequality=found.method,
        side=tail,
        budget=budget,
        trials=total,
        null_probability=chance,
        critical_count=found.count,
        false_positive_bound=found.bound,
        derivation=algebra,
        vacuous=found.vacuous,
    )


def matched_count_threshold(
    signing_length: int,
    match_probability: float,
    *,
    eps: float,
    side: str,
    method: str = "sharpest",
    party: Party | str | None = None,
) -> DerivedThreshold:
    """Derive a threshold on one verifier's matched count ``|M_R|``.

    Null: ``|M_R| ~ Binomial(n, 1/|B|)`` with ``n`` the **sifted** key length,
    unconditionally over the symmetrisation coins (:ref:`the nulls
    <the-nulls>`). Both tails are useful and they test different things:

    ``side="lower"``
        Evidence denial. The tail the protocol's own floor
        (:func:`~sih141.protocol.verify.minimum_matched_count`) is derived
        from, at the same budget and by the same inequality when
        ``method="chernoff"`` is asked for.
    ``side="upper"``
        Recipient forgery. A forger supplied half the second verifier's
        evidence himself, so his declaration matches there with probability
        one and the count moves from ``n/3`` to ``n *
        forger_scored_fraction = 2n/3`` -- ``9.80`` honest standard deviations
        at ``n = 192`` and ``240`` at
        :data:`~sih141.protocol.params.DEFAULT_PARAMS`
        (:func:`forgery_separation_sigma`). Phase 3's constraint 5: this is the
        discriminator that works where ``transcript.repudiated`` does not.

    Parameters
    ----------
    signing_length : int
        ``n``. **The sifted length**, not the nominal ``L``: at
        ``check_fraction = 0.25`` a null stated over ``L`` would claim a third
        more evidence than the run has, and every bound in the scheme is
        exponential in that count. Read it off
        :attr:`~sih141.detect.statistics.TranscriptStatistics.key_length`,
        which is already sifted.
    match_probability : float
        ``1/|B|``.
    eps : float
        Keyword-only false-positive budget for **this** threshold.
    side : {'lower', 'upper'}
        Keyword-only.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
        Keyword-only.
    party : Party or str, optional
        Keyword-only. Names the roster entry; the threshold itself does not
        depend on it, since both verifiers are scored against the same null.

    Returns
    -------
    DerivedThreshold

    Raises
    ------
    TypeError
        If ``signing_length`` is not an integer or a probability is not a real
        number.
    ValueError
        If a probability or ``eps`` is out of range, or ``side``/``method``
        names nothing.

    See Also
    --------
    pooled_count_threshold : The same null over ``2n`` trials, by conservation.
    forgery_separation_sigma : What the upper tail is separating.

    Examples
    --------
    The lower tail at the protocol's own budget and inequality reproduces the
    protocol's own floor, at both shipped parameter sets:

    >>> from sih141.detect.thresholds_rate import matched_count_threshold
    >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
    >>> from sih141.protocol.verify import (
    ...     HONEST_ABORT_BUDGET, minimum_matched_count
    ... )
    >>> for params in (DEFAULT_PARAMS, ProtocolParams(key_length=600)):
    ...     derived = matched_count_threshold(
    ...         params.signing_length,
    ...         params.match_probability,
    ...         eps=HONEST_ABORT_BUDGET,
    ...         side="lower",
    ...         method="chernoff",
    ...     )
    ...     print(derived.critical_count, minimum_matched_count(params) - 1)
    36554 36554
    66 66

    At the same budget the exact tail certifies a strictly more sensitive
    threshold, which is :ref:`F1 <findings>`:

    >>> sharper = matched_count_threshold(
    ...     600, 1 / 3, eps=HONEST_ABORT_BUDGET, side="lower"
    ... )
    >>> sharper.critical_count, sharper.inequality
    (100, 'exact binomial tail')

    The upper tail against a recipient forgery, at ``L = 192``:

    >>> high = matched_count_threshold(192, 1 / 3, eps=1e-9, side="upper")
    >>> high.critical_count, high.expected
    (106, 64.0)
    >>> high.fires(128)          # the forger's mean, 2n/3
    True
    >>> f"{high.false_positive_bound:.3e}"
    '4.048e-10'
    """
    label = "Bob" if party is None else str(party)
    suffix = "low" if _check_side(side) == "lower" else "high"
    chance = _as_probability(match_probability, "match_probability")
    total = _as_count(signing_length, "signing_length")
    return _count_threshold(
        name=f"matched_count_{suffix}:{label}",
        statistic="|M_R|",
        null=(
            f"Binomial({total}, {_fraction(chance)}), the honest law of a "
            f"verifier's matched count"
        ),
        trials=total,
        probability=chance,
        eps=eps,
        side=side,
        method=method,
        extra=(
            "The null is unconditional over the symmetrisation coins: a swap "
            "permutes an exchangeable pair and leaves the joint law alone. "
            "Conditionally on the records m_C = M - m_B exactly, which is a "
            "different law and is not reachable from a transcript."
        ),
    )


def declared_count_threshold(
    signing_length: int,
    match_probability: float,
    *,
    eps: float,
    side: str,
    method: str = "sharpest",
    party: Party | str | None = None,
) -> DerivedThreshold:
    """Derive a threshold on a Phase C' declared matched count.

    Exactly :func:`matched_count_threshold`'s derivation applied to a different
    **observable**: the integer a recipient put on the wire in
    :mod:`sih141.protocol.tally`, rather than the count his own verdict
    scored. On an honest run the two are the same integer, so they share a
    null; under count starvation they are not, and the gap is the attack.

    The two are still separate roster entries, because they fail differently. A
    starver who understates his own count moves the declared statistic while
    leaving his verdict count alone, and it is the *declared* one that denies
    the other recipient a verdict. Phase 3 named the z-score of the quietest
    denying declaration as the signal to key on: around ``-11.5`` honest
    standard deviations, and essentially flat in ``L``, which is why starvation
    does not get cheaper as the key grows.
    :func:`sih141.attacks.starvation.least_implausible_z` is the authority for
    that number and is deliberately not imported here -- a figure quoted in
    prose drifts, so read it from the function rather than from this sentence.
    (Layer one's :class:`~sih141.detect.statistics.PooledStatistics` gives it
    as ``-11.54`` "at every key length"; that is its value at
    :data:`~sih141.protocol.params.DEFAULT_PARAMS`, and it is nearer ``-11.63``
    at ``L = 360``. Flat, not constant.)

    Parameters
    ----------
    signing_length : int
        ``n``, sifted.
    match_probability : float
        ``1/|B|``.
    eps : float
        Keyword-only budget for this threshold.
    side : {'lower', 'upper'}
        Keyword-only. ``'lower'`` is the starvation tail; ``'upper'`` catches a
        recipient who *inflates* his declaration to push the pooled total over
        ``M_min`` on evidence he does not hold.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
        Keyword-only.
    party : Party or str, optional
        Keyword-only, names the roster entry.

    Returns
    -------
    DerivedThreshold

    Raises
    ------
    TypeError
        If ``signing_length`` is not an integer or a probability is not real.
    ValueError
        If a probability or ``eps`` is out of range, or ``side``/``method``
        names nothing.

    Notes
    -----
    A *declared pooled* threshold is deliberately **not** in the roster. It
    would be a deterministic function of the two entries already there, adding
    no independent evidence while taking a thirteenth of the family budget from
    the entries that do.

    Examples
    --------
    >>> from sih141.detect.thresholds_rate import declared_count_threshold
    >>> starve = declared_count_threshold(
    ...     192, 1 / 3, eps=1e-9, side="lower", party="Charlie"
    ... )
    >>> starve.name, starve.critical_count
    ('declared_count_low:Charlie', 26)
    >>> starve.fires(20), starve.fires(64)
    (True, False)
    """
    label = "Bob" if party is None else str(party)
    suffix = "low" if _check_side(side) == "lower" else "high"
    chance = _as_probability(match_probability, "match_probability")
    total = _as_count(signing_length, "signing_length")
    return _count_threshold(
        name=f"declared_count_{suffix}:{label}",
        statistic="the count declared in Phase C'",
        null=(
            f"Binomial({total}, {_fraction(chance)}), the honest law of the "
            f"count a recipient declares, which on an honest run is the count "
            f"he then scores"
        ),
        trials=total,
        probability=chance,
        eps=eps,
        side=side,
        method=method,
        extra=(
            "Same null and same inversion as the matched count; a separate "
            "roster entry because a starver moves the wire integer while "
            "leaving his own verdict count alone."
        ),
    )


def pooled_count_threshold(
    signing_length: int,
    match_probability: float,
    *,
    eps: float,
    side: str,
    method: str = "sharpest",
) -> DerivedThreshold:
    """Derive a threshold on the pooled matched count ``M = m_B + m_C``.

    Null: ``M ~ Binomial(2n, 1/|B|)``, **exactly, and by conservation rather
    than by independence.** The symmetrisation coins re-assign a fixed multiset
    of ``2n`` entries, so ``M`` is coin-invariant and is a sum of ``2n`` i.i.d.
    indicators. Convolving the two post-exchange marginals lands on the same
    answer and proves less: conditionally on the records ``m_C = M - m_B`` with
    correlation ``-1``, so the two counts are not independent and an argument
    that assumed they were would be wrong about a different question later.
    ``:ref:`pooled-floor``` in :mod:`sih141.protocol.verify` and
    ``tests/test_protocol_tally.py`` both open with that trap.

    ``M`` is the count every repudiation bound in the scheme is exponential in,
    which is why it has a floor of its own and why the recipients exchange a
    message to compute it at all. It is also, by :ref:`F2 <findings>`, the
    *weaker* discriminator against anything one party does alone: a deviation
    localised to one verifier is unchanged while the null's spread grows like
    ``sqrt(2n)``, so the separation drops by exactly ``sqrt(2)``. Both are
    shipped and neither is pooled into the other.

    Parameters
    ----------
    signing_length : int
        ``n`` per verifier, sifted. The threshold is stated over ``2n`` trials
        and this function does the doubling, so a caller cannot pass ``2n`` by
        mistake and get a null over ``4n``.
    match_probability : float
        ``1/|B|``.
    eps : float
        Keyword-only budget for this threshold.
    side : {'lower', 'upper'}
        Keyword-only.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
        Keyword-only.

    Returns
    -------
    DerivedThreshold

    Raises
    ------
    TypeError
        If ``signing_length`` is not an integer or a probability is not real.
    ValueError
        If a probability or ``eps`` is out of range, or ``side``/``method``
        names nothing.

    Examples
    --------
    The lower tail at the protocol's own budget and inequality reproduces the
    protocol's own pooled floor:

    >>> from sih141.detect.thresholds_rate import pooled_count_threshold
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> from sih141.protocol.verify import (
    ...     HONEST_ABORT_BUDGET, minimum_pooled_matched_count
    ... )
    >>> pooled = pooled_count_threshold(
    ...     DEFAULT_PARAMS.signing_length,
    ...     DEFAULT_PARAMS.match_probability,
    ...     eps=HONEST_ABORT_BUDGET,
    ...     side="lower",
    ...     method="chernoff",
    ... )
    >>> pooled.trials, pooled.critical_count
    (230400, 74189)
    >>> minimum_pooled_matched_count(DEFAULT_PARAMS) - 1
    74189

    And the doubling happens here, once:

    >>> pooled_count_threshold(192, 1 / 3, eps=1e-9, side="lower").trials
    384
    """
    chance = _as_probability(match_probability, "match_probability")
    half = _as_count(signing_length, "signing_length")
    suffix = "low" if _check_side(side) == "lower" else "high"
    return _count_threshold(
        name=f"pooled_count_{suffix}",
        statistic="M = m_B + m_C",
        null=(
            f"Binomial({2 * half}, {_fraction(chance)}), exact by "
            f"conservation of the pooled count under the symmetrisation coins"
        ),
        trials=2 * half,
        probability=chance,
        eps=eps,
        side=side,
        method=method,
        extra=(
            "Exactness comes from conservation, not from independence: the "
            "coins re-assign a fixed multiset of 2n entries, so M is a sum of "
            "2n i.i.d. indicators. Given the records m_C = M - m_B with "
            "correlation -1, so convolving the marginals would prove nothing."
        ),
    )


def mismatch_rate_threshold(
    matched_count: int,
    *,
    eps: float,
    channel_error_rate: float = 0.0,
    method: str = "sharpest",
    party: Party | str | None = None,
) -> DerivedThreshold:
    """Derive a threshold on one verifier's mismatch rate ``r_R``.

    Null: ``e_R | |M_R| = m ~ Binomial(m, p_e)``, with ``p_e`` the link's true
    error rate. The threshold is a function of the **conditioning variable**
    ``m`` and of ``eps``, never of ``e_R``, so the tower rule carries the bound
    through unconditionally (:ref:`D-3 <d3>`).

    ``channel_error_rate = 0.0``, the default, is the **noiseless** null: a
    point mass at ``0``, under which firing on ``e_R >= 1`` has a
    false-positive probability of exactly zero. It is the strongest bound
    available and the cost is stated with it -- it is a claim about a noiseless
    link, and a run over a genuinely noisy honest channel violates it. A
    transcript with ``check_fraction = 0`` carries no estimate of ``p_e``
    (:mod:`sih141.detect.statistics`, finding 2), so this module will not
    invent one: pass the noise level in, or accept a noiseless claim and say
    which you did.

    **On flagging a run the protocol accepted**: see :ref:`the module's own
    section <relative>`. ``s_a`` and ``s_v`` are noise and forgery budgets, not
    false-positive budgets, and a flag is not a rejection.
    :func:`dominance_noise_level` is the derived quantity that says whether
    this threshold adds anything over the verifier's own cut.

    Parameters
    ----------
    matched_count : int
        ``|M_R|``, this verifier's realised matched-set size. The conditioning
        variable, and the denominator of ``r_R``: counting unmatched positions
        into a mismatch rate is the classic bug of this protocol family and
        would put an honest run at ``(1 - 1/|B|)/2``.
    eps : float
        Keyword-only budget for this threshold.
    channel_error_rate : float, optional
        Keyword-only ``p_e``, in ``[0, 1]``. Defaults to the noiseless ``0.0``.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
        Keyword-only. Ignored at ``p_e = 0``, where the answer is exact.
    party : Party or str, optional
        Keyword-only, names the roster entry. **It names the verifier who
        scored, never the link that was touched.** Phase A' swaps records
        between the two recipients, so a record damaged on Bob's link is held
        by Charlie half the time and this statistic is already pooled across
        the links by the protocol itself -- see :ref:`F5 <findings>`, where a
        depolariser aimed at Bob alone puts the larger mismatch count on
        Charlie on some runs. Attribution is the check-round family's job.

    Returns
    -------
    DerivedThreshold
        Always an upper tail: a mismatch *deficit* is not an attack anyone has
        to detect, and a two-sided threshold would spend half its budget on it.

    Raises
    ------
    TypeError
        If ``matched_count`` is not an integer or a probability is not real.
    ValueError
        If a probability or ``eps`` is out of range, or ``method`` names
        nothing.

    See Also
    --------
    dominance_noise_level : Whether this threshold beats the verifier's own cut.

    Examples
    --------
    The noiseless null, which is the free and infinitely sensitive one:

    >>> from sih141.detect.thresholds_rate import mismatch_rate_threshold
    >>> clean = mismatch_rate_threshold(38400, eps=1e-9)
    >>> clean.critical_count, clean.false_positive_bound
    (1, 0.0)
    >>> f"{clean.critical_rate:.3e}"
    '2.604e-05'

    Hand it a noise level and the threshold becomes a real inversion. Note it
    is still far below ``s_a = 0.015625``, so a run at this noise level is
    accepted by Bob and flagged here, which is the whole of the
    :ref:`relative <relative>` discussion:

    >>> noisy = mismatch_rate_threshold(
    ...     38400, eps=1e-9, channel_error_rate=0.005
    ... )
    >>> noisy.critical_count, f"{noisy.critical_rate:.6f}"
    (281, '0.007318')

    At the noise level ``s_a`` was actually sized for, ``2 s_a = 0.03125``, the
    derived threshold sits *above* Bob's cut and the detector is dominated by
    his own test:

    >>> design = mismatch_rate_threshold(
    ...     38400, eps=1e-9, channel_error_rate=0.03125
    ... )
    >>> f"{design.critical_rate:.6f}", 1 / 64
    ('0.036745', 0.015625)
    """
    label = "Bob" if party is None else str(party)
    total = _as_count(matched_count, "matched_count")
    noise = _as_probability(channel_error_rate, "channel_error_rate")
    if noise == 0.0:
        null = (
            "a point mass at 0 (e_R = 0 with probability one on a noiseless "
            "link)"
        )
        extra = (
            "Degenerate null, answered exactly rather than bounded: every "
            "matched position reproduces the declared eigenvalue with "
            "probability one on a noiseless link, so P(e_R >= 1) = 0 and the "
            "false-positive probability is exactly zero -- under that null. "
            "The cost is that it is a claim about a noiseless link."
        )
    else:
        null = (
            f"Binomial({total}, {noise:.6g}) conditionally on |M_R| = "
            f"{total}, carried through by the tower rule"
        )
        extra = (
            "Conditioning, not fitting: the threshold is a function of the "
            "conditioning variable |M_R| and of eps, never of e_R, so "
            "P(fire) = E[P(e_R >= k(|M_R|) | |M_R|)] <= eps."
        )
    return _count_threshold(
        name=f"mismatch_rate:{label}",
        statistic="e_R",
        null=null,
        trials=total,
        probability=noise,
        eps=eps,
        side="upper",
        method=method,
        extra=extra,
    )


def _fraction(probability: float) -> str:
    """Render a match probability as a readable fraction where it is one.

    Parameters
    ----------
    probability : float
        In ``(0, 1]``.

    Returns
    -------
    str
        ``"1/3"`` rather than ``"0.3333333333333333"`` when the reciprocal is
        an integer to within floating-point rounding, so a printed null reads
        like the null it is.
    """
    if probability <= 0.0:
        return "0"
    reciprocal = 1.0 / probability
    rounded = round(reciprocal)
    if rounded >= 1 and abs(reciprocal - rounded) < 1e-9:
        return f"1/{rounded}"
    return f"{probability:.6g}"


# --------------------------------------------------------------------------- #
# Derived diagnostics: what the thresholds are separating, and against what
# --------------------------------------------------------------------------- #


def forgery_separation_sigma(
    signing_length: int,
    match_probability: float,
    *,
    pooled: bool = False,
) -> float:
    """Return the recipient forgery's separation, in honest standard deviations.

    A recipient forger supplies half the second verifier's evidence himself, so
    his declaration matches there with probability one and the retained half
    matches at the usual ``1/|B|``: the count's mean moves from ``n p`` to
    ``n (1 + p) / 2 =``
    :attr:`~sih141.protocol.params.ProtocolParams.forger_scored_fraction`
    ``* n``. The separation is that shift over the honest null's standard
    deviation:

    .. code-block:: text

        per verifier   ( n (1 + p)/2 - n p ) / sqrt(n p (1 - p))
        pooled         ( n (1 + p)/2 - n p ) / sqrt(2 n p (1 - p))

    The numerators are identical -- the forgery moves one verifier's count and
    the pooled total by the same absolute amount -- while the pooled
    denominator is larger by ``sqrt(2)``. Hence :ref:`F2 <findings>`: **pooling
    costs exactly a factor of** ``sqrt(2)`` **against a party-localised
    deviation**, at every key length, and the pooled count is kept for what it
    does see rather than for this.

    Parameters
    ----------
    signing_length : int
        ``n``, sifted, at least ``1``.
    match_probability : float
        ``1/|B|``, strictly inside ``(0, 1)``.
    pooled : bool, optional
        Keyword-only. ``True`` for the pooled count's separation.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``signing_length`` is not an integer or ``match_probability`` is not
        a real number.
    ValueError
        If ``signing_length`` is ``0`` or ``match_probability`` is not strictly
        inside ``(0, 1)``.

    Notes
    -----
    A separation, not a threshold: nothing is derived from it and no number in
    this module was chosen by looking at it. It exists so that a report can say
    how far apart the two hypotheses are without measuring the distance on
    attack data.

    Examples
    --------
    Phase 3's constraint 5, confirmed from the closed form:

    >>> from sih141.detect.thresholds_rate import forgery_separation_sigma
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> f"{forgery_separation_sigma(192, 1 / 3):.4f}"
    '9.7980'
    >>> forgery_separation_sigma(
    ...     DEFAULT_PARAMS.signing_length, DEFAULT_PARAMS.match_probability
    ... )
    240.0

    And what pooling costs, exactly:

    >>> import math
    >>> per = forgery_separation_sigma(192, 1 / 3)
    >>> both = forgery_separation_sigma(192, 1 / 3, pooled=True)
    >>> f"{both:.4f}", f"{per / both:.15f}" == f"{math.sqrt(2):.15f}"
    ('6.9282', True)
    """
    total = _as_count(signing_length, "signing_length")
    chance = _as_probability(match_probability, "match_probability")
    if total == 0:
        raise ValueError(
            "signing_length must be at least 1; a separation over no "
            "positions is not a small separation, it is undefined."
        )
    if not 0.0 < chance < 1.0:
        raise ValueError(
            f"match_probability must lie strictly inside (0, 1), got "
            f"{chance}. The degenerate alphabets have no forgery to separate."
        )
    shift = total * (1.0 + chance) / 2.0 - total * chance
    trials = 2 * total if pooled else total
    return shift / math.sqrt(trials * chance * (1.0 - chance))


def dominance_noise_level(
    matched_count: int,
    cut: float,
    *,
    eps: float,
    method: str = "sharpest",
    tolerance: float = 1e-12,
) -> float:
    """Return the link error rate at which the ``r_R`` detector stops adding.

    The largest ``p_e`` for which the threshold
    :func:`mismatch_rate_threshold` derives at this budget still sits at or
    below ``cut``, the party's own acceptance threshold. **Above it the
    detector is dominated**: every run it flags the verifier has already
    rejected, and its marginal information is zero.

    Why this belongs beside every ``r_R`` threshold rather than in a footnote:
    ``s_a`` and ``s_v`` are not false-positive budgets (:ref:`relative
    <relative>`), so "the detector is tighter than the cut" is not automatic
    and is not free. It is bought entirely by assuming the link is quieter than
    the protocol assumes, and this function is how much quieter.

    Parameters
    ----------
    matched_count : int
        ``|M_R|``, at least ``1``.
    cut : float
        The party's acceptance threshold, ``s_a`` or ``s_v``, in ``(0, 1)``.
    eps : float
        Keyword-only budget the threshold is derived at.
    method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
        Keyword-only.
    tolerance : float, optional
        Keyword-only bisection width. The answer is a real number found by
        bisection on a step function, so it is reported to this resolution and
        no further.

    Returns
    -------
    float
        In ``[0, cut]``. The threshold is monotone in ``p_e``, so the bisection
        is exact up to ``tolerance``.

    Raises
    ------
    TypeError
        If ``matched_count`` is not an integer or ``cut`` is not real.
    ValueError
        If ``matched_count`` is ``0``, or ``cut``/``eps``/``tolerance`` is out
        of range.

    Notes
    -----
    Derived, and derived from no data: the bisection runs over the null family
    and the budget only. It never sees a transcript, let alone an attack.

    Examples
    --------
    At :data:`~sih141.protocol.params.DEFAULT_PARAMS` against Bob's own cut:

    >>> from sih141.detect.thresholds_rate import dominance_noise_level
    >>> f"{dominance_noise_level(38400, 1 / 64, eps=1e-9):.6f}"
    '0.012119'

    The noise level ``s_a`` was sized for is ``2 s_a = 0.03125``, which is
    above that, so at the design noise level the detector is dominated by Bob's
    own acceptance test:

    >>> dominance_noise_level(38400, 1 / 64, eps=1e-9) < 2 * (1 / 64)
    True

    Charlie's looser cut buys the detector considerably more room:

    >>> f"{dominance_noise_level(38400, 1 / 16, eps=1e-9):.6f}"
    '0.055355'
    """
    total = _as_count(matched_count, "matched_count")
    if total == 0:
        raise ValueError(
            "matched_count must be at least 1; a mismatch rate over an empty "
            "matched set is what verify() refuses to score at all."
        )
    limit = _as_probability(cut, "cut")
    budget = _as_budget(eps)
    how = _check_method(method)
    if not 0.0 < limit < 1.0:
        raise ValueError(
            f"cut must lie strictly inside (0, 1), got {limit}. It is an "
            f"acceptance threshold, s_a or s_v."
        )
    if (
        isinstance(tolerance, bool)
        or not isinstance(tolerance, (int, float))
        or not 0.0 < float(tolerance) < 1.0
    ):
        raise ValueError(
            f"tolerance must lie strictly inside (0, 1), got {tolerance!r}."
        )

    def dominated(noise: float) -> bool:
        """Return whether the derived threshold still sits at or below the cut."""
        found = _invert(total, noise, budget, "upper", how)
        return found.count / total <= limit

    low, high = 0.0, limit
    if dominated(high):
        return high
    width = float(tolerance)
    while high - low > width:
        middle = (low + high) / 2.0
        if dominated(middle):
            low = middle
        else:
            high = middle
    return low


def floor_comparison(
    params: ProtocolParams, *, eps: float = HONEST_ABORT_BUDGET
) -> dict[str, int]:
    """Return the protocol's matched-count floors beside every derivation of them.

    :ref:`F1 <findings>` as a computation, so the table in the module docstring
    cannot drift away from the arithmetic behind it. Every entry is the
    *critical count* -- the largest count that trips the rule -- so the
    protocol's floors appear as ``m_min - 1`` and ``M_min - 1``, which is what
    ``|M_R| < m_min`` actually means.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set. Its sifted signing length is used, not ``L``.
    eps : float, optional
        Keyword-only budget. Defaults to
        :data:`~sih141.protocol.verify.HONEST_ABORT_BUDGET`, the budget the
        protocol's own floors were derived at, so that the comparison is
        between *proofs* and not between budgets.

    Returns
    -------
    dict
        Keys ``"signing_length"``, ``"protocol_matched"``,
        ``"chernoff_matched"``, ``"hoeffding_matched"``, ``"exact_matched"``,
        ``"protocol_pooled"``, ``"chernoff_pooled"``, ``"hoeffding_pooled"``
        and ``"exact_pooled"``.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.
    ValueError
        If ``eps`` is out of range.

    Notes
    -----
    A comparison, not a proposal. Every one of these thresholds is valid at
    ``eps``; the protocol's is simply the loosest, and raising it is a protocol
    change whose consequences reach
    :func:`~sih141.protocol.verify.enforced_repudiation_bound` and the
    ``(2 - sqrt 2) A`` margin argument, neither of which this module owns.

    Examples
    --------
    >>> from sih141.detect.thresholds_rate import floor_comparison
    >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
    >>> row = floor_comparison(DEFAULT_PARAMS)
    >>> (row["protocol_matched"], row["chernoff_matched"],
    ...  row["hoeffding_matched"], row["exact_matched"])
    (36554, 36554, 36801, 36951)
    >>> row["protocol_pooled"], row["exact_pooled"]
    (74189, 74749)

    At a short key the shipped floor degenerates to "abort only on an empty
    matched set" while the exact tail at the same budget still certifies a
    real one:

    >>> short = floor_comparison(ProtocolParams(key_length=192))
    >>> short["protocol_matched"], short["exact_matched"]
    (0, 11)
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}."
        )
    budget = _as_budget(eps)
    length = params.signing_length
    chance = params.match_probability
    row = {
        "signing_length": length,
        "protocol_matched": minimum_matched_count(params) - 1,
        "protocol_pooled": minimum_pooled_matched_count(params) - 1,
    }
    for name in INEQUALITIES:
        row[f"{name}_matched"] = _invert(
            length, chance, budget, "lower", name
        ).count
        row[f"{name}_pooled"] = _invert(
            2 * length, chance, budget, "lower", name
        ).count
    return row


# --------------------------------------------------------------------------- #
# The family
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RateCountVerdict:
    """What the rate-and-count family says about one run, and what it does not.

    Attributes
    ----------
    flagged : bool
        Whether any member fired. **Not a rejection.** The run's own verdicts
        are on :class:`~sih141.detect.statistics.TranscriptStatistics` and are
        not touched here; a flag says the run departed from a stated null, and
        conflating the two would report a detection that never happened
        (:ref:`relative <relative>`).
    fired : tuple of str
        Roster names that fired, sorted.
    false_positive_bound : float
        The family's proven honest-run firing probability, by the union bound
        of :ref:`D-4 <d4>`. The number a Phase 5 ROC point is plotted at.
    observations : mapping of str to int
        What each evaluated member actually saw. Members that could not be
        evaluated are absent rather than zero.
    not_scored : tuple of str
        Parties who reached no verdict in this run. **Carried separately and
        never counted as a rejection or as a non-detection**: a refusal to
        score is a third outcome, and layer one keeps it in its own type for
        the same reason.
    grouping_key : tuple
        The run's variant markers -- ``count_exchange_timing``, whether it was
        symmetrised, whether counts were exchanged, whether the signer seam saw
        both raw logs, and whether the run carries a security claim at all.
        **Group by this; never average over it.** The two count-exchange
        orderings give different answers to the same attack, so a table mixing
        them averages a forgery rate with a denial-of-service rate.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_rate import RateCountThresholds
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> verdict = RateCountThresholds.for_transcript(
    ...     stats, eps=1e-9
    ... ).evaluate(stats)
    >>> verdict.flagged, verdict.not_scored
    (False, ())
    >>> verdict.grouping_key
    ('before-forwarding', True, True, False, True)
    """

    flagged: bool
    fired: tuple[str, ...]
    false_positive_bound: float
    observations: Mapping[str, int]
    not_scored: tuple[str, ...]
    grouping_key: tuple[Any, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
            ``"grouping_key"`` becomes a list, since JSON has no tuple, and
            keeps its order so a Phase 5 aggregator can group on it.
        """
        return {
            "flagged": self.flagged,
            "fired": list(self.fired),
            "false_positive_bound": self.false_positive_bound,
            "observations": dict(self.observations),
            "not_scored": list(self.not_scored),
            "grouping_key": list(self.grouping_key),
        }


@dataclass(frozen=True)
class RateCountThresholds:
    """The whole rate-and-count family at one budget, with a union bound.

    Twelve budgeted members from :data:`RATE_COUNT_ROSTER`, each derived at
    ``eps / 12``, plus the free structural test of
    :data:`RATE_COUNT_FREE_TESTS`. :ref:`D-4 <d4>` derives the family bound.

    Attributes
    ----------
    eps : float
        The **family** budget. The guarantee is that an honest run trips at
        least one member with probability at most this.
    per_test_budget : float
        ``eps / len(RATE_COUNT_ROSTER)``, the share each budgeted member was
        derived at.
    thresholds : mapping of str to DerivedThreshold
        Keyed by roster name. Complete: every name in
        :data:`RATE_COUNT_ROSTER` is present even when this run cannot
        evaluate it, so the union bound is over the roster and not over the
        run.
    channel_error_rate : float
        The ``p_e`` the mismatch thresholds were derived at. ``0.0`` marks a
        noiseless claim, which is what a transcript with no check rounds can
        support and nothing more.
    method : str
        Which proofs were consulted.
    signing_length : int
        ``n``, the sifted length every null here is stated over.
    match_probability : float
        ``1/|B|``.

    Notes
    -----
    **How a Phase 5 sweep should use this.** At the default noiseless
    ``channel_error_rate`` every threshold in the family is a function of
    ``(n, 1/|B|, eps)``, so one family per ``(parameter set, eps)`` scores an
    entire corpus: build with :meth:`for_params`, then call :meth:`evaluate`
    once per run. That is the cheap pattern *and* the honest one -- a family
    rebuilt per run would look identical and would make it much harder to see
    that no threshold moved with the data. At a positive noise level the two
    mismatch members are conditioned on a particular run's matched counts and
    :meth:`evaluate` refuses to score any other run, so the sweep must build
    per run there; :ref:`D-3 <d3>` says why that is not a limitation but the
    derivation asserting itself.

    Examples
    --------
    >>> from sih141.detect.thresholds_rate import (
    ...     RATE_COUNT_ROSTER, RateCountThresholds
    ... )
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> family = RateCountThresholds.for_params(DEFAULT_PARAMS, eps=1e-9)
    >>> len(family.thresholds) == len(RATE_COUNT_ROSTER)
    True
    >>> f"{family.per_test_budget:.4e}"
    '8.3333e-11'
    >>> family.thresholds["matched_count_low:Bob"].critical_count
    37379
    >>> family.thresholds["pooled_count_high"].critical_count
    78249

    The family bound is the sum of what its members actually prove, which is at
    most the budget and here is well under it -- the two mismatch members
    contribute exactly zero under the noiseless null:

    >>> f"{family.false_positive_bound:.4e}"
    '8.2524e-10'
    >>> family.false_positive_bound <= family.eps
    True
    """

    eps: float
    per_test_budget: float
    thresholds: Mapping[str, DerivedThreshold]
    channel_error_rate: float
    method: str
    signing_length: int
    match_probability: float

    # -- construction ------------------------------------------------------- #

    @classmethod
    def for_params(
        cls,
        params: ProtocolParams,
        *,
        eps: float,
        channel_error_rate: float = 0.0,
        method: str = "sharpest",
        matched_counts: Mapping[str, int] | None = None,
    ) -> RateCountThresholds:
        """Derive the family from a parameter set alone, before any run.

        **The a-priori door.** Everything except the two mismatch thresholds is
        a function of ``(n, 1/|B|, eps)`` and needs no run at all; the mismatch
        thresholds need a matched-set size, and in the absence of one they are
        stated over the null's own mean ``n/|B|`` rounded down, which is the
        honest a-priori denominator.

        Parameters
        ----------
        params : ProtocolParams
            The **sifted** parameter set. Pass
            :attr:`~sih141.detect.statistics.TranscriptStatistics.params`,
            which is already sifted, or call
            :meth:`~sih141.protocol.params.ProtocolParams.sifted` yourself. A
            null stated over ``L`` on a checked run would claim evidence the
            run does not have.
        eps : float
            Keyword-only family budget.
        channel_error_rate : float, optional
            Keyword-only ``p_e``, defaulting to the noiseless ``0.0``.
        method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
            Keyword-only.
        matched_counts : mapping of str to int, optional
            Keyword-only per-party ``|M_R|``, when they are known. Absent
            parties fall back to the null's mean; a party who is not a verifier
            is refused rather than ignored, since a misspelled recipient would
            otherwise fall back silently and produce a threshold derived for a
            run that never happened.

        Returns
        -------
        RateCountThresholds

        Raises
        ------
        TypeError
            If ``params`` is not a
            :class:`~sih141.protocol.params.ProtocolParams`.
        ValueError
            If a probability or ``eps`` is out of range, ``method`` names
            nothing, or ``matched_counts`` names a party who is not a verifier.
        """
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got "
                f"{type(params).__name__}."
            )
        family = _as_budget(eps)
        noise = _as_probability(channel_error_rate, "channel_error_rate")
        how = _check_method(method)
        length = params.signing_length
        chance = params.match_probability
        share = family / len(RATE_COUNT_ROSTER)
        counts = dict(matched_counts or {})
        strangers = set(counts) - {str(party) for party in VERIFIERS}
        if strangers:
            raise ValueError(
                f"matched_counts names {sorted(strangers)}, who are not "
                f"verifiers. Alice reaches no verdict and holds no matched "
                f"set, and a misspelled recipient would have silently fallen "
                f"back to the null's mean -- which is a threshold derived for "
                f"a run that never happened."
            )

        built: dict[str, DerivedThreshold] = {}
        for party in VERIFIERS:
            name = str(party)
            matched = _as_count(
                counts.get(name, int(length * chance)), "matched_count"
            )
            built[f"mismatch_rate:{name}"] = mismatch_rate_threshold(
                matched,
                eps=share,
                channel_error_rate=noise,
                method=how,
                party=name,
            )
            for side, suffix in (("lower", "low"), ("upper", "high")):
                built[f"matched_count_{suffix}:{name}"] = (
                    matched_count_threshold(
                        length,
                        chance,
                        eps=share,
                        side=side,
                        method=how,
                        party=name,
                    )
                )
                built[f"declared_count_{suffix}:{name}"] = (
                    declared_count_threshold(
                        length,
                        chance,
                        eps=share,
                        side=side,
                        method=how,
                        party=name,
                    )
                )
        for side, suffix in (("lower", "low"), ("upper", "high")):
            built[f"pooled_count_{suffix}"] = pooled_count_threshold(
                length, chance, eps=share, side=side, method=how
            )
        # Symmetric on purpose. A missing member would make the union bound a
        # statement about a set nobody computed; an *extra* one would be summed
        # into false_positive_bound without a budget of its own and could push
        # the family past eps. Both directions break D-4, so both are refused.
        if set(built) != set(RATE_COUNT_ROSTER):
            missing = sorted(set(RATE_COUNT_ROSTER) - set(built))
            extra = sorted(set(built) - set(RATE_COUNT_ROSTER))
            raise ValueError(
                f"this constructor and RATE_COUNT_ROSTER disagree: "
                f"not built {missing}, not on the roster {extra}. The union "
                f"bound of D-4 divides eps by len(RATE_COUNT_ROSTER) and sums "
                f"over what was built, so the two must be the same set or the "
                f"family's proven bound is not the one it reports."
            )
        return cls(
            eps=family,
            per_test_budget=share,
            thresholds=built,
            channel_error_rate=noise,
            method=how,
            signing_length=length,
            match_probability=chance,
        )

    @classmethod
    def for_transcript(
        cls,
        stats: TranscriptStatistics,
        *,
        eps: float,
        channel_error_rate: float = 0.0,
        method: str = "sharpest",
    ) -> RateCountThresholds:
        """Derive the family for one run's shape.

        Reads three things off ``stats`` and nothing else: the sifted length,
        the alphabet's match probability, and each verifier's matched-set size
        as the **conditioning variable** of the mismatch thresholds
        (:ref:`D-3 <d3>`). No threshold here is a function of the statistic it
        tests.

        Parameters
        ----------
        stats : TranscriptStatistics
            Layer one's extraction of one JSON-round-tripped transcript.
        eps : float
            Keyword-only family budget.
        channel_error_rate : float, optional
            Keyword-only ``p_e``. Not read off the run: a transcript with no
            check rounds carries no estimate of it, and one with check rounds
            carries an estimate over a *sample* whose validity is conditional
            on assumption (NO-TIMING). Hand it in, or accept the noiseless
            claim.
        method : {'sharpest', 'exact', 'hoeffding', 'chernoff'}, optional
            Keyword-only.

        Returns
        -------
        RateCountThresholds

        Raises
        ------
        TypeError
            If ``stats`` is not a
            :class:`~sih141.detect.statistics.TranscriptStatistics`.
        ValueError
            If a probability or ``eps`` is out of range, or ``method`` names
            nothing.
        """
        if not isinstance(stats, TranscriptStatistics):
            raise TypeError(
                f"stats must be a TranscriptStatistics, got "
                f"{type(stats).__name__}. This layer reads layer one, which "
                f"is what keeps it on the far side of the JSON boundary."
            )
        counts = {
            name: verifier.matched.count
            for name, verifier in stats.verifiers.items()
        }
        return cls.for_params(
            stats.params,
            eps=eps,
            channel_error_rate=channel_error_rate,
            method=method,
            matched_counts=counts,
        )

    # -- derived views ------------------------------------------------------ #

    @property
    def false_positive_bound(self) -> float:
        """float: The family's proven honest-run firing probability.

        The union bound of :ref:`D-4 <d4>`, evaluated at what the members
        actually prove rather than at what they were budgeted -- so it is at
        most :attr:`eps` and usually well below it. Clipped at ``1.0``, which it
        cannot reach for any sane budget but which keeps the field a probability
        by type as well as by argument.

        **Read :attr:`bound_is_unconditional` before plotting a ROC at this
        number.** Ten of the twelve members have thresholds that are functions
        of the parameter set alone, so their bounds are constants of the family.
        The two mismatch members are functions of the observed ``|M_R|``, which
        is the conditioning variable of :ref:`D-3 <d3>`; at
        ``channel_error_rate = 0`` their bounds are exactly zero whatever
        ``|M_R|`` is and this sum is unconditional, but at a positive noise
        level it is a bound on ``P(fire | the matched counts)``. The
        unconditional guarantee is :attr:`eps` in both cases, by the tower rule,
        and it is the one a swept curve should be plotted at when this flag is
        ``False``.
        """
        return min(
            1.0,
            math.fsum(
                threshold.false_positive_bound
                for threshold in self.thresholds.values()
            ),
        )

    @property
    def bound_is_unconditional(self) -> bool:
        """bool: Whether :attr:`false_positive_bound` needs no conditioning.

        ``True`` exactly when :attr:`channel_error_rate` is ``0``, where the two
        mismatch members contribute a bound of exactly zero for every possible
        matched count and every threshold in the family is therefore a function
        of the parameter set alone. ``False`` marks the case a Phase 5 curve has
        to be careful about: the sum is still a correct bound, but on the
        firing probability *given the run's matched counts*, and
        :attr:`eps` is what remains unconditionally true.

        A boolean rather than a docstring sentence because it decides which of
        two numbers a report may quote, and that is not a decision to leave to
        whether somebody read the paragraph.
        """
        return self.channel_error_rate == 0.0

    def threshold(self, name: str) -> DerivedThreshold:
        """Return one member by roster name.

        Parameters
        ----------
        name : str
            A member of :data:`RATE_COUNT_ROSTER`.

        Returns
        -------
        DerivedThreshold

        Raises
        ------
        KeyError
            If ``name`` is not on the roster.
        """
        if name not in self.thresholds:
            raise KeyError(
                f"{name!r} is not a member of this family. The roster is "
                f"fixed at {list(RATE_COUNT_ROSTER)}, plus the free "
                f"structural test(s) {list(RATE_COUNT_FREE_TESTS)}, which "
                f"carry no threshold object because their bound is exactly "
                f"zero."
            )
        return self.thresholds[name]

    # -- evaluation --------------------------------------------------------- #

    def evaluate(self, stats: TranscriptStatistics) -> RateCountVerdict:
        """Apply the family to one run.

        Every member that can be evaluated is, and the verdict records what
        each one saw. A party who reached no verdict contributes **nothing**:
        his members are not evaluated, he is listed in
        :attr:`RateCountVerdict.not_scored`, and no field of the verdict counts
        his refusal as either a rejection or a clean run.

        Parameters
        ----------
        stats : TranscriptStatistics
            The run. May be a different run from the one the family was built
            for, so long as its sifted length and alphabet agree -- which this
            method checks, because a threshold applied to a null it was not
            derived for carries no bound at all. At a positive
            :attr:`channel_error_rate` it must additionally be the run the
            mismatch thresholds were *conditioned* on; see
            :meth:`_check_conditioning`.

        Returns
        -------
        RateCountVerdict

        Raises
        ------
        TypeError
            If ``stats`` is not a
            :class:`~sih141.detect.statistics.TranscriptStatistics`.
        ValueError
            If the run's sifted length or match probability differs from the
            one this family was derived at, or -- at a positive noise level --
            if a verifier's matched count is not the one his mismatch threshold
            was conditioned on.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.detect.statistics import TranscriptStatistics
        >>> from sih141.detect.thresholds_rate import RateCountThresholds
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> stats = TranscriptStatistics.from_transcript(
        ...     QDSSession(
        ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
        ...     ).run(0)
        ... )
        >>> family = RateCountThresholds.for_transcript(stats, eps=1e-9)
        >>> verdict = family.evaluate(stats)
        >>> verdict.flagged, sorted(verdict.observations)[:2]
        (False, ['declaration_gap', 'declared_count_high:Bob'])
        """
        if not isinstance(stats, TranscriptStatistics):
            raise TypeError(
                f"stats must be a TranscriptStatistics, got "
                f"{type(stats).__name__}."
            )
        if stats.key_length != self.signing_length:
            raise ValueError(
                f"this family was derived over n = {self.signing_length} and "
                f"the run has n = {stats.key_length}. A threshold applied to "
                f"a null it was not derived for carries no bound; rebuild the "
                f"family with for_transcript."
            )
        if stats.match_probability != self.match_probability:
            raise ValueError(
                f"this family was derived at p = {self.match_probability} and "
                f"the run has p = {stats.match_probability}. Different "
                f"alphabets are different nulls."
            )

        fired: list[str] = []
        observations: dict[str, int] = {}
        pooled = stats.pooled

        for party in VERIFIERS:
            name = str(party)
            if name not in stats.verifiers:
                continue
            verifier = stats.verifiers[name]
            self._check_conditioning(name, verifier.matched.count)
            self._apply(
                f"mismatch_rate:{name}",
                verifier.mismatch.count,
                fired,
                observations,
            )
            for suffix in ("low", "high"):
                self._apply(
                    f"matched_count_{suffix}:{name}",
                    verifier.matched.count,
                    fired,
                    observations,
                )
            declared = _declared_for(pooled, name)
            if declared is None:
                continue
            for suffix in ("low", "high"):
                self._apply(
                    f"declared_count_{suffix}:{name}",
                    declared.count,
                    fired,
                    observations,
                )

        if pooled.pooled is not None:
            for suffix in ("low", "high"):
                self._apply(
                    f"pooled_count_{suffix}",
                    pooled.pooled.count,
                    fired,
                    observations,
                )

        gap = pooled.declaration_gap
        if gap is not None:
            observations["declaration_gap"] = gap
            if gap != 0:
                fired.append("declaration_gap")

        not_scored = tuple(
            str(party)
            for party in VERIFIERS
            if str(party) not in stats.verifiers
        )
        return RateCountVerdict(
            flagged=bool(fired),
            fired=tuple(sorted(fired)),
            false_positive_bound=self.false_positive_bound,
            observations=observations,
            not_scored=not_scored,
            grouping_key=(
                stats.count_exchange_timing,
                stats.symmetrised,
                stats.counts_exchanged,
                stats.signer_saw_recipient_logs,
                stats.security_claim,
            ),
        )

    def _check_conditioning(self, party: str, matched: int) -> None:
        """Refuse to score a run whose matched count is not the one conditioned on.

        The mismatch threshold's bound holds *given* the matched-set size it
        was derived at (:ref:`D-3 <d3>`). Applying a threshold derived at one
        ``|M_R|`` to a run with another one bounds nothing, and would do it
        silently, so it is refused here rather than published later.

        At ``channel_error_rate = 0`` the threshold is ``e_R >= 1`` for every
        possible ``|M_R|``, so any conditioning variable gives the same rule
        and there is nothing to refuse -- which is why an a-priori family built
        by :meth:`for_params` can score a run at the default noise level and
        only stops being able to when a noise level is supplied.

        Parameters
        ----------
        party : str
            The verifier whose matched count is being checked.
        matched : int
            The run's realised ``|M_R|``.

        Raises
        ------
        ValueError
            If the family's mismatch threshold for this party was conditioned
            on a different matched count and the null is not the point mass.
        """
        if self.channel_error_rate == 0.0:
            return
        threshold = self.thresholds[f"mismatch_rate:{party}"]
        if threshold.trials == matched:
            return
        raise ValueError(
            f"the mismatch threshold for {party} was derived conditionally on "
            f"|M_R| = {threshold.trials} and this run has |M_R| = {matched}. "
            f"A threshold conditioned on one matched-set size bounds nothing "
            f"when applied to another, and the tower rule of D-3 is what "
            f"carries the bound through -- so this is refused rather than "
            f"scored. Build the family with "
            f"RateCountThresholds.for_transcript(stats, ...), which reads the "
            f"conditioning variable off the run it is going to score."
        )

    def _apply(
        self,
        name: str,
        observed: int,
        fired: list[str],
        observations: dict[str, int],
    ) -> None:
        """Evaluate one member and record what it saw.

        Parameters
        ----------
        name : str
            Roster name.
        observed : int
            The statistic's realised value.
        fired : list of str
            Accumulator, appended to in place.
        observations : dict
            Accumulator, written to in place.
        """
        threshold = self.thresholds[name]
        observations[name] = observed
        if threshold.fires(observed):
            fired.append(name)

    def claims(self) -> tuple[str, ...]:
        """Return every member's D7 sentence, in roster order.

        Returns
        -------
        tuple of str

        Examples
        --------
        >>> from sih141.detect.thresholds_rate import RateCountThresholds
        >>> from sih141.protocol.params import DEFAULT_PARAMS
        >>> family = RateCountThresholds.for_params(DEFAULT_PARAMS, eps=1e-9)
        >>> print(family.claims()[-1])
        pooled_count_high: fires when M = m_B + m_C >= 78249 out of 230400; under Binomial(230400, 1/3), exact by conservation of the pooled count under the symmetrisation coins, this fires with probability at most 8.195e-11, by the exact binomial tail at a budget of 8.333e-11.
        """
        return tuple(
            self.thresholds[name].claim() for name in RATE_COUNT_ROSTER
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the whole family.

        Returns
        -------
        dict
            Passes to :func:`json.dumps` unchanged.
        """
        return {
            "eps": self.eps,
            "per_test_budget": self.per_test_budget,
            "false_positive_bound": self.false_positive_bound,
            "bound_is_unconditional": self.bound_is_unconditional,
            "channel_error_rate": self.channel_error_rate,
            "method": self.method,
            "signing_length": self.signing_length,
            "match_probability": self.match_probability,
            "roster": list(RATE_COUNT_ROSTER),
            "free_tests": list(RATE_COUNT_FREE_TESTS),
            "thresholds": {
                name: threshold.to_dict()
                for name, threshold in self.thresholds.items()
            },
        }


def _declared_for(pooled: Any, party: str) -> CountStatistic | None:
    """Return one party's declared Phase C' count, or ``None``.

    Parameters
    ----------
    pooled : PooledStatistics
        Layer one's pooled block.
    party : str
        ``"Bob"`` or ``"Charlie"``.

    Returns
    -------
    CountStatistic or None
        ``None`` on a run whose recipients did not exchange counts, and for any
        party name the exchange does not carry.
    """
    if party == "Bob":
        return pooled.declared_bob
    if party == "Charlie":
        return pooled.declared_charlie
    return None
