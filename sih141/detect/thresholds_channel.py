"""Phase 4, layer two: the **channel** family of derived detection thresholds.

Five statistics of one recipient's link on one message bit -- check-round
QBER, the CHSH statistic, and the three resource summaries fidelity, purity
and concurrence -- each turned into a critical value by the same two-step
recipe convention **D7** requires:

1. write the honest-run null down, exactly, and
2. apply a **named** concentration inequality to it and invert the inequality
   at a false-positive budget ``eps``.

Nothing in this module has seen an attack. Every critical value it returns is
a function of ``eps``, of the sample size the transcript reports, and of one
externally supplied noise level -- and of nothing else. There is no number
here that was chosen because it separated data, and there is no place to put
one: each threshold is a closed-form inversion whose algebra is printed below
and whose false-positive probability is *proved*, not measured.

.. _channel-what-eps-means:

What ``eps`` means, and what it does not
----------------------------------------
``eps`` is a **budget on the probability of firing on an honest run**, and
every :class:`ChannelThreshold` carries the bound its own inequality actually
proves in :attr:`~ChannelThreshold.false_positive_bound`. That number is
always ``<= eps`` and is usually far below it: an integer threshold overshoots
its analytic value, and at the noiseless null **four of the five** are point
masses whose bound is exactly ``0`` -- every one except CHSH, whose ``+-1``
outcomes are random even on a perfect pair. At a positive
``tolerated_depolarising`` none of them is degenerate and all five cost
something.

``eps`` is *not* a detection rate, an accuracy, or a tuning knob. Phase 5
sweeps it to draw a ROC curve; every point on that curve is a separate derived
operating point, and no point on it was reached by looking at what the
adversaries did.

.. _channel-no-timing:

Assumption (NO-TIMING): every threshold in this module is conditioned on it
---------------------------------------------------------------------------
All five statistics are **check-round** statistics, so all five inherit
:ref:`sih141.detect.statistics <no-timing>`'s assumption in full: the
adversary cannot infer the check set from timing. If he can, he spares the
watched rounds, the sample stops describing the link, and every bound here
becomes a bound about a sample the adversary chose. The assumption is bought
by the protocol -- every seam is called for a check round exactly as for a key
round, in the same order, with the same context
(:ref:`sih141.protocol.checkrounds <check-timing>`) -- and it is an
*assumption* rather than a check because a transcript carries no timestamps at
all (:ref:`finding 4 <findings>`).

**Anything published from this module must cite it.** A conditioned claim
stated is rigour; the same claim unstated is an overclaim. The statistics that
do *not* need it -- the verifier mismatch rate, the matched counts, the
declared-count z-score, the abort reasons -- are a different family and live
in a different module.

.. _channel-per-party:

Per party, per message bit, never pooled
-----------------------------------------
Phase 3 established this and it is a constraint rather than a preference:
symmetrisation smears the *records* but never the *check logs*, so a per-link
statistic is the only one that both **detects** a party-targeted channel
attack and **attributes** it. Every function here takes one link's sample.
There is no pooled entry point; a caller who has decided the two links really
are one channel goes through
:func:`~sih141.detect.statistics.pooled_check_qber`, which makes that decision
visible at the call site and says what it costs.

.. _channel-dealing:

The reserved set is dealt between the links, so a link measures half of it
--------------------------------------------------------------------------
The number a threshold is derived from is **the link's own sample size**, and
it is half what a reading of ``params.check_count`` suggests.
:func:`~sih141.protocol.checkrounds.draw_check_plan` splits the reserved
positions into a CHSH arm of ``floor(w * check_count)`` and a QBER arm of the
rest, then deals **each arm round-robin between the two links**, with the
counter running on across the arms so neither link collects both leftovers.
So at ``w = 1/2`` a link measures about ``check_count / 4`` QBER rounds and
``check_count / 4`` CHSH rounds -- ``check_count / 2`` positions in all --
and not ``check_count`` of anything.

Every half-width in this module falls off as ``1 / sqrt(n)``, so reading the
run's arm total where the link's share belongs understates it by exactly

.. code-block:: text

    sqrt(check_count / (check_count / 2))  =  sqrt(2)  =  1.4142...

:func:`link_check_rounds` computes the shares from the parameter set, and
``tests/test_detect_channel.py`` pins them against the plan the shipped dealer
actually draws, because an arithmetic restatement of somebody else's dealing
rule is exactly the kind of prose number this project has shipped wrong
before.

.. _channel-qber:

Derivation 1 -- per-link check-round QBER
------------------------------------------
**Statistic.** ``E``, the number of this link's QBER check rounds whose
product of eigenvalues disagreed with the ideal sign
(:data:`~sih141.protocol.checkrounds.IDEAL_PAULI_CORRELATION`), out of ``n``
such rounds. ``E`` is
:attr:`LinkStatistics.errors.count <sih141.detect.statistics.LinkStatistics>`
and ``n`` is its ``trials``.

**Null.** The check plan is drawn from the recipients' stream, independently
of the channel, so *conditional on the plan* each QBER round is an independent
trial and

.. code-block:: text

    H0(p0):   E ~ Binomial(n, q0),   q0 = depolarising_error_rate(p0) = p0/2

for a link whose honest resource is Werner at strength ``p0``. A conditional
bound at level ``eps`` for every plan is an unconditional bound at level
``eps``, by averaging over plans, so conditioning costs nothing and is what
lets ``n`` be read off the transcript.

The identity behind ``q0 = p0/2`` is the protocol's, not this module's: the
check-round error rate in basis ``a`` equals the key mismatch rate in basis
``a`` exactly, for every Bell-diagonal resource
(:ref:`sih141.protocol.checkrounds <check-round-qber-identity>`).

**The noiseless case is a point mass, and it is the strongest bound here.**
``E >= 0`` always, and ``E[E] = n q0 = 0`` when ``p0 = 0``; a non-negative
random variable with zero mean is zero almost surely. So under ``H0(0)``,
``P(E >= 1) = 0`` **exactly**, the threshold is ``k = 1`` for every ``eps``,
and the budget buys nothing because there is nothing left to buy. What it
costs is stated with it: it is a claim about a *noiseless* link, and a
deployment with genuinely noisy honest pairs must hand in its ``p0`` -- the
transcript cannot supply one (:ref:`finding 2 <findings>`).

**The noisy case, three inequalities, all three shipped.** Each is exact
algebra applied to the same stated null; they differ only in tightness, and
carrying all three lets a report say what distribution-freedom cost.

*Hoeffding* (``method="hoeffding"``), additive and distribution-free:

.. code-block:: text

    P(E >= n q0 + s)  <=  exp(-2 s^2 / n)
    set exp(-2 s^2 / n) = eps   =>   s = sqrt(n ln(1/eps) / 2)
    k(eps) = ceil(n q0 + sqrt(n ln(1/eps) / 2))

*Chernoff* (``method="chernoff"``), multiplicative, and much the better choice
at the small ``q0`` a QBER null actually has -- the multiplicative form knows
the variance is ``n q0 (1 - q0)`` and the additive one does not:

.. code-block:: text

    P(E >= (1 + d) mu)  <=  exp(-d^2 mu / (2 + d)),   mu = n q0
    set d^2 mu / (2 + d) = ln(1/eps)  =>
        d = [ ln(1/eps) + sqrt( ln(1/eps)^2 + 8 mu ln(1/eps) ) ] / (2 mu)
    k(eps) = ceil((1 + d) mu)

*Exact* (``method="exact"``, the default), the binomial upper tail itself:

.. code-block:: text

    k(eps) = min { k : sum_{j=k}^{n} C(n,j) q0^j (1-q0)^(n-j) <= eps }

In every case the shipped ``k`` is an integer at or above the analytic value,
so the reported bound -- the inequality re-evaluated at that integer -- is at
or below ``eps``. When no ``k <= n`` reaches the budget the threshold is
``n + 1``, which can never fire: the honest answer for a sample too small to
detect anything at that budget, and its false-positive bound really is ``0``
because the event is empty.

.. _channel-chsh:

Derivation 2 -- CHSH, against ``2 sqrt(2)`` and against the classical bound
---------------------------------------------------------------------------
**Statistic.** ``S = E00 + E01 + E10 - E11``, each ``E_c`` the mean of ``n_c``
products of ``+-1`` eigenvalues over the rounds that landed in cell ``c``.

**Null.** The honest resource is Werner at strength ``p0``, whose correlation
tensor is the ideal one scaled by ``1 - p0``, so every correlator and
therefore ``S`` scales linearly
(:func:`~sih141.protocol.checkrounds.depolarising_chsh`):

.. code-block:: text

    H0(p0):   E[S] = S0 = (1 - p0) * 2 sqrt(2)

**This is the one channel statistic with genuine sampling noise on a perfect
resource.** The ``+-1`` outcomes are random even on an ideal pair, so unlike
the other four nulls in this family ``H0(0)`` is not a point mass and there is
no free exactly-zero bound. It has to be paid for in rounds.

**Inequality: McDiarmid's bounded-difference inequality**, which is Hoeffding
for a function of independent variables rather than for their sum. ``S`` is a
function of the ``N = sum_c n_c`` independent round outcomes; flipping one
round of cell ``c`` moves ``E_c`` by ``2 / n_c`` and hence ``S`` by exactly
``2 / n_c``, so the bounded-difference constants are

.. code-block:: text

    sum_i c_i^2 = sum_c n_c (2/n_c)^2 = 4 sum_c 1/n_c

and, one-sided,

.. code-block:: text

    P(S <= S0 - t)  <=  exp( -2 t^2 / (4 sum_c 1/n_c) )
                     =  exp( -t^2 / (2 sum_c 1/n_c) )
    t(eps) = sqrt( 2 ln(1/eps) sum_c 1/n_c )

**Detection** fires when ``S <= S0 - t(eps)``; the false-positive probability
is at most ``eps``, for any resource law with mean ``S0``. The threshold uses
the *null's* geometry and never the measured correlators' -- an estimator's
own value has no business setting the width of its own acceptance band.

**McDiarmid asks only for independence, not for identical distribution**, so
this bound survives an honest channel that *drifts*, provided its average
correlator is still the null's. That is a genuinely weaker assumption than the
i.i.d. one the resource summaries below need, and it is worth knowing which of
the two a deployment is relying on.

**What distribution-freedom costs, as a number.** With balanced cells
``n_c = N/4`` the null's own standard deviation is
``sqrt(sum_c (1 - E_c^2)/n_c) = sqrt(8/N)`` at the ideal point, while
``t(eps) = sqrt(32 ln(1/eps) / N)``, so

.. code-block:: text

    t(eps) / sd  =  2 sqrt(ln(1/eps))

-- ``9.10`` standard deviations at ``eps = 1e-09`` where a normal quantile
would ask for ``6.00``. The factor ``1.52`` is the price of a bound that holds
at every sample size instead of asymptotically, and a report that quotes the
normal number should say which one it is quoting.

**Certification against the classical bound is a different claim with a
different null, and it is not an alarm.** Under
``H0': the true statistic satisfies S_true <= 2``
(:data:`~sih141.protocol.checkrounds.CLASSICAL_CHSH_BOUND`), the same
bounded-difference constants give ``P(S >= S_true + t(eps)) <= eps``, so

.. code-block:: text

    observing  S > 2 + t(eps)   licenses "this resource was entangled when it
    arrived", and licenses it wrongly with probability at most eps

:func:`chsh_certificate_threshold` returns that as a
:class:`ChannelThreshold` with :attr:`~ChannelThreshold.is_alarm` ``False``,
and :func:`screen_link` **refuses** to evaluate a non-alarm. The reason is
Phase 3's fourth constraint wearing a channel hat: *failing to certify is not
a detection*. A short sample cannot certify anything, and a screen that
counted "no certificate" as an alarm would report a detection rate equal to
its own sample-size problem.

.. _channel-resource:

Derivation 3 -- the three resource summaries, as bounded means
---------------------------------------------------------------
**Statistic.** The mean over this link's monitored check rounds of one
per-round resource summary ``V``:
:attr:`~sih141.detect.statistics.ResourceStatistics.mean_fidelity`,
``mean_purity`` or ``mean_concurrence``.

**Null.** The rounds' resources are i.i.d. with a stated honest mean, which
for a Werner honest resource at strength ``p0`` is closed form
(:func:`werner_fidelity`, :func:`werner_purity`, :func:`werner_concurrence`).
The i.i.d. part is an assumption about the honest channel -- true of any
memoryless one, false of one that drifts -- and is stated rather than hidden.

**The ideal case is a point mass, and it is forced rather than assumed.**
``V <= b`` for the range's top ``b``, and if ``E[V] = b`` then
``E[b - V] = 0`` with ``b - V >= 0``, so ``V = b`` almost surely: *a bounded
random variable whose mean sits on its own supremum is a point mass there.*
An ideal :math:`|\\Phi^{+}\\rangle` has fidelity, purity and concurrence all
exactly ``1``, so on a run whose honest resource is ideal every round sits on
``1``, the mean does, and so does the **minimum**. A detector firing on
``min <= 1 - tol`` therefore has a false-positive probability of exactly zero,
and the minimum is the sharper reading -- an attack that touches one round in
a thousand moves it and barely moves the mean. The only thing the bound rests
on beyond the null is that the honest run's floating-point dust stays inside
``tol``; that is an arithmetic claim about a four-by-four eigendecomposition,
not a probabilistic one, and ``tol`` defaults to the same
:data:`~sih141.detect.statistics.IDEAL_TOLERANCE` the transcript's own
``is_ideal`` uses.

**The noisy case, Hoeffding for bounded variables.** With ``V`` in ``[a, b]``
and honest mean ``mu0 < b``:

.. code-block:: text

    P( mean_n(V) <= mu0 - t )  <=  exp( -2 n t^2 / (b - a)^2 )
    t(eps) = (b - a) sqrt( ln(1/eps) / (2 n) )

with ``b - a = 3/4`` for a two-qubit purity (which is bounded below by ``1/4``,
not by ``0``) and ``b - a = 1`` for fidelity and concurrence. **Only the mean
gets this**: the minimum of ``n`` bounded variables has no law that follows
from their mean alone, so a threshold on ``min_purity`` exists under the
point-mass null and nowhere else. :func:`purity_threshold` and its siblings
switch which field they name for exactly that reason, and say so in the
object they return.

**Why fidelity is in this family and not an afterthought.** ``Tr(rho^2)`` is
invariant under *every* unitary, and concurrence is invariant under *local*
unitaries. So a channel that applies a local unitary to the travelling half --
a rotation, a Pauli twirl, anything reversible -- leaves purity and
concurrence at ``1.0`` exactly while the pair is no longer
:math:`|\\Phi^{+}\\rangle` at all. A family built on those two alone is blind
to the whole unitary class by a theorem, not by bad luck. Fidelity to
:math:`|\\Phi^{+}\\rangle` is not a local-unitary invariant and is what sees
it. (The QBER and CHSH arms see it too, from the outcome side.)

**Realised per round is not the same as averaged, and the monitor sees the
realisation.** A Pauli twirl of strength ``p`` has the Werner *ensemble*, so
its averaged purity is ``werner_purity(p)`` and looks disturbed -- but a
channel that draws one Pauli per hop hands the monitor a pair that is still
pure and still maximally entangled on **every** round, so ``min_purity`` and
``min_concurrence`` sit on ``1.0`` throughout. A reader who takes the ensemble
purity for the observed one will expect a signal that is not there. It is the
fidelity row, and the outcome arms, that move.

.. _channel-union:

Screening a link: the union bound, and why the split is legitimate
-------------------------------------------------------------------
:func:`screen_link` applies the family to one link at a **budget for the whole
screen**. Firing on any of ``m`` thresholds is a union of ``m`` events, so

.. code-block:: text

    P(any fires | honest)  <=  sum_j P(threshold j fires)  <=  sum_j eps_j

and the budget is divided evenly, ``eps_j = eps / m``. The reported
:attr:`ChannelScreen.false_positive_bound` is the sum of the bounds the
inequalities actually prove, which is at or below ``eps`` and normally far
below it.

Two details that make the split sound rather than merely conventional:

* **``m`` is the number of thresholds the transcript makes evaluable, and that
  set is fixed by the check plan and the run's configuration, not by the
  channel.** Whether a link published QBER rounds, whether all four CHSH cells
  are occupied, whether a monitor ran -- under the null these are properties
  of the plan, and the plan is drawn from the recipients' stream. Conditioning
  on it is legitimate, and a bound that holds for every plan holds on average
  over plans.
* **An unevaluable statistic is recorded as unavailable, never as cleared.**
  :attr:`ChannelScreen.unavailable` is a separate mapping from
  :attr:`~ChannelScreen.cleared`, for the same reason
  :class:`~sih141.detect.statistics.AbortStatistics` is a separate type from
  :class:`~sih141.detect.statistics.VerifierStatistics`: "we could not look"
  read as "we looked and it was fine" is how a Phase 5 table reports a
  detection that never happened.

**A run has more than one link.** Two recipients times two message bits is up
to four screens, and a *run-level* budget must be divided again before it
reaches :func:`screen_link` -- :func:`divide_budget` does that division and
exists so the arithmetic is written down once instead of guessed four times.

.. _channel-limits:

What this family cannot do
---------------------------
1. **It cannot supply its own noise level.** ``tolerated_depolarising`` comes
   from outside because a transcript carries no independent estimate of what
   the honest channel *should* look like (:ref:`finding 2 <findings>`). At
   ``0`` the claims are claims about a noiseless link and say so.
2. **It cannot attribute an attack it cannot see.** A run with
   ``check_fraction = 0`` publishes no check rounds, so the whole family is
   unavailable -- correctly, and reported as unavailable rather than clean.
3. **It cannot see a channel that spares the check rounds.** That is
   (NO-TIMING), above.
4. **It cannot tell which link Eve touched from a single clean link.** It can
   only say *this* link deviates. Ground truth about the adversary's target
   lives on the adversary's log and a detector may not read it
   (:ref:`finding 1 <findings>`); an untargeted link is byte-identical to an
   honest one, correctly.
5. **``wings_agree`` is not here, and no threshold will ever be derived from
   it.** No trace-preserving map on one half of a maximally entangled pair can
   change only that half's marginal, so every channel adversary leaves it
   ``True``:
   :func:`~sih141.detect.statistics.why_wings_agree_is_absent` carries the
   argument and the measurement.
6. **It cannot make a short check budget into a long one.** The noise-tolerant
   arm's power is set by the link's own sample, which is a quarter of the run's
   reserved positions per arm, and at a toy length it is very weak while the
   noiseless arm is unchanged. :ref:`channel-sizing` gives the two thresholds
   side by side; :func:`link_check_rounds` is how a run is sized before it is
   drawn from.

Notes
-----
Determinism (D3)
    Nothing here draws randomness. Every function is a pure function of a
    sample size, a budget and a noise level.
No machine learning (D4)
    Hoeffding in two forms -- a binomial count and a bounded mean -- a
    multiplicative Chernoff tail, McDiarmid's bounded-difference inequality,
    one exact binomial tail, the point-mass argument that needs no inequality
    at all, and three closed forms for the Werner family
    (:func:`werner_fidelity`, :func:`werner_purity`,
    :func:`werner_concurrence`) beside the two the protocol already ships
    (:func:`~sih141.protocol.checkrounds.depolarising_chsh` and
    :func:`~sih141.protocol.analysis.depolarising_error_rate`). There is no
    fitted quantity in this file and no argument that could carry one:
    ``tolerated_depolarising`` is a physical noise level a deployment states,
    and ``epsilon`` is a probability budget.
The boundary
    This module imports from :mod:`sih141.protocol` and from
    :mod:`sih141.detect.statistics`, and from nothing else in the package. It
    never imports :mod:`sih141.attacks`, for the reason
    :ref:`sih141.detect.statistics <the-boundary>` gives.

Examples
--------
The dealing, and the ``sqrt(2)`` it costs a naive reading:

>>> from sih141.detect.thresholds_channel import link_check_rounds
>>> from sih141.protocol.params import ProtocolParams
>>> params = ProtocolParams(key_length=384, check_fraction=0.25)
>>> params.check_count
96
>>> shares = link_check_rounds(params)
>>> [(str(s.party), s.qber_rounds, s.chsh_rounds) for s in shares]
[('Bob', 24, 24), ('Charlie', 24, 24)]
>>> import math
>>> naive = math.sqrt(1.0 / 48)          # "the run drew 48 QBER rounds"
>>> real = math.sqrt(1.0 / 24)           # this link measured 24 of them
>>> f"{real / naive:.4f}"
'1.4142'

A noiseless QBER threshold is one error, and its false-positive probability is
exactly zero at every budget -- the strongest bound in the family, and free:

>>> from sih141.detect.thresholds_channel import qber_threshold
>>> noiseless = qber_threshold(rounds=24, epsilon=1e-09)
>>> noiseless.critical_value, noiseless.false_positive_bound
(1.0, 0.0)
>>> noiseless.inequality
'point mass (exact)'
>>> qber_threshold(rounds=24, epsilon=0.5).critical_value
1.0

Hand it a noise level and the three inequalities separate, at the same proven
budget. This is the sample a run at
:data:`~sih141.protocol.params.CHECKED_PARAMS` gives one link, against the
``s_a = 1/64`` error budget:

>>> for method in ("hoeffding", "chernoff", "exact"):
...     threshold = qber_threshold(
...         rounds=4114,
...         epsilon=1e-09,
...         tolerated_depolarising=1 / 32,
...         method=method,
...     )
...     print(
...         f"{method:10s} k = {threshold.critical_value:6.1f}  "
...         f"P(fire | honest) <= {threshold.false_positive_bound:.3e}"
...     )
hoeffding  k =  271.0  P(fire | honest) <= 9.503e-10
chernoff   k =  128.0  P(fire | honest) <= 6.757e-10
exact      k =  118.0  P(fire | honest) <= 8.776e-10

CHSH is the statistic that is random even on a perfect pair, so a Bell test at
a small budget has to be bought in rounds. Twenty-four rounds put the critical
value *below the classical bound* -- such a sample cannot even see a resource
that arrived unentangled -- where four thousand put it well above:

>>> from sih141.detect.thresholds_channel import chsh_threshold
>>> from sih141.protocol.checkrounds import CLASSICAL_CHSH_BOUND
>>> short = chsh_threshold(counts=(6, 6, 6, 6), epsilon=1e-09)
>>> f"{short.critical_value:.4f}", short.critical_value > CLASSICAL_CHSH_BOUND
('-2.4281', False)
>>> long = chsh_threshold(counts=(1028, 1029, 1029, 1029), epsilon=1e-09)
>>> f"{long.critical_value:.4f}", long.critical_value > CLASSICAL_CHSH_BOUND
('2.4270', True)

The resource summaries, ideal null and Werner null side by side:

>>> from sih141.detect.thresholds_channel import (
...     concurrence_threshold, purity_threshold, werner_purity,
... )
>>> ideal = purity_threshold(samples=48, epsilon=1e-09)
>>> ideal.statistic, ideal.false_positive_bound
('min_purity', 0.0)
>>> noisy = purity_threshold(
...     samples=48, epsilon=1e-09, tolerated_depolarising=0.1
... )
>>> noisy.statistic, f"{werner_purity(0.1):.4f}", f"{noisy.critical_value:.4f}"
('mean_purity', '0.8575', '0.5090')
>>> concurrence_threshold(samples=48, epsilon=1e-09).inequality
'point mass (exact)'

And the whole family against one honest link, at a budget for the screen:

>>> import numpy as np
>>> from sih141.detect.statistics import TranscriptStatistics
>>> from sih141.detect.thresholds_channel import screen_link
>>> from sih141.protocol.session import QDSSession
>>> stats = TranscriptStatistics.from_transcript(
...     QDSSession(
...         ProtocolParams(key_length=384, check_fraction=0.25),
...         rng=np.random.default_rng(7),
...     ).run(0)
... )
>>> screen = screen_link(stats.link("Bob", 0), epsilon=1e-09)
>>> screen.detected, screen.fired
(False, ())
>>> screen.cleared
('chsh', 'min_concurrence', 'min_fidelity', 'min_purity', 'qber_errors')
>>> f"{screen.false_positive_bound:.3e}"
'2.000e-10'

The bound is not ``1e-09``: four of the five nulls are point masses whose
proven bound is exactly ``0``, so the whole screen costs what its one
non-degenerate member costs.

.. _channel-sizing:

**Size the run before drawing a table from it.** The noiseless arm's threshold
is one error and one non-ideal round at every length, so it is insensitive to
the check budget. The *noise-tolerant* arm is not, and the difference is a
factor a short run hides:

>>> from sih141.detect.thresholds_channel import (
...     divide_budget, fidelity_threshold,
... )
>>> share = divide_budget(1e-09, 5)
>>> for rounds, seen, label in ((24, 48, "L = 384"), (4114, 8229, "CHECKED")):
...     errors = qber_threshold(
...         rounds=rounds, epsilon=share, tolerated_depolarising=0.05
...     )
...     mean = fidelity_threshold(
...         samples=seen, epsilon=share, tolerated_depolarising=0.05
...     )
...     print(
...         f"{label:8s} k = {errors.critical_value:5.0f} of {rounds:5d}"
...         f"   mean fidelity <= {mean.critical_value:.4f}"
...     )
L = 384  k =    10 of    24   mean fidelity <= 0.4802
CHECKED  k =   172 of  4114   mean fidelity <= 0.9257

Twenty-four rounds asked for a distribution-free statement at ``2e-10`` buy a
threshold of ten errors out of twenty-four and a fidelity floor below one half;
the same statement at :data:`~sih141.protocol.params.CHECKED_PARAMS`'s sample
buys ``172`` of ``4114`` and a floor at ``0.9257``. A Phase 5 table drawn at a
toy length would report that gap as a detector weakness when it is a
check-budget choice, which is the same trap
:data:`~sih141.protocol.params.CHECKED_PARAMS` exists to avoid on the key side.
**Report the two arms as two rows and never average them.**

See Also
--------
sih141.detect.statistics.LinkStatistics : What these thresholds are read
    against.
sih141.protocol.checkrounds.required_check_rounds : The other direction --
    how many rounds a *reporting* half-width asks for.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from sih141.detect.statistics import IDEAL_TOLERANCE, LinkStatistics
from sih141.protocol.analysis import depolarising_error_rate
from sih141.protocol.checkrounds import (
    CHECK_CHSH_WEIGHT,
    CLASSICAL_CHSH_BOUND,
    IDEAL_CHSH,
    depolarising_chsh,
)
from sih141.protocol.params import VERIFIERS, Party, ProtocolParams, _as_party

__all__ = [
    "CHANNEL_STATISTICS",
    "CONCURRENCE_RANGE",
    "FIDELITY_RANGE",
    "PURITY_RANGE",
    "ChannelScreen",
    "ChannelThreshold",
    "CheckRoundShare",
    "bounded_mean_threshold",
    "chsh_certificate_threshold",
    "chsh_threshold",
    "concurrence_threshold",
    "divide_budget",
    "fidelity_threshold",
    "link_check_rounds",
    "purity_threshold",
    "qber_threshold",
    "screen_link",
    "werner_concurrence",
    "werner_fidelity",
    "werner_purity",
]


#: The five statistics this family derives thresholds for, in the order
#: :func:`screen_link` reports them. Named so that a Phase 5 table and this
#: module cannot disagree about what "the channel family" contains.
CHANNEL_STATISTICS: Final[tuple[str, ...]] = (
    "qber_errors",
    "chsh",
    "fidelity",
    "purity",
    "concurrence",
)

#: ``[a, b]`` for the fidelity :math:`\langle\Phi^{+}|\rho|\Phi^{+}\rangle`,
#: which is an expectation of a projector and so lies in the unit interval.
FIDELITY_RANGE: Final[tuple[float, float]] = (0.0, 1.0)

#: ``[a, b]`` for a **two-qubit** purity. ``Tr(rho^2) >= 1/d`` with ``d = 4``,
#: so the span Hoeffding is charged for is ``3/4`` rather than ``1``: a purity
#: cannot fall to zero, and pretending it could would widen every interval
#: here by a third for nothing.
PURITY_RANGE: Final[tuple[float, float]] = (0.25, 1.0)

#: ``[a, b]`` for concurrence, ``0`` on anything separable and ``1`` on a Bell
#: state.
CONCURRENCE_RANGE: Final[tuple[float, float]] = (0.0, 1.0)

#: The two directions a threshold can fire in. ``"upper"`` fires at or above
#: the critical value, ``"lower"`` at or below it.
_DIRECTIONS: Final[frozenset[str]] = frozenset({"lower", "upper"})

#: The inversions :func:`qber_threshold` will perform.
_QBER_METHODS: Final[frozenset[str]] = frozenset(
    {"exact", "chernoff", "hoeffding"}
)

#: Below this budget the exact binomial tail is summed in arithmetic that can
#: underflow, so the search would stop at a ``k`` whose reported tail is a
#: rounded-down ``0.0`` rather than the true value. The analytic inversions are
#: closed forms and have no such floor, so the guard names them.
_EXACT_METHOD_FLOOR: Final[float] = 1e-300


# --------------------------------------------------------------------------- #
# Argument coercion
# --------------------------------------------------------------------------- #


def _as_epsilon(value: Any, name: str = "epsilon") -> float:
    """Coerce a false-positive budget strictly inside ``(0, 1)``.

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
        If ``value`` is not finite or lies outside the open unit interval.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be a real number, got {type(value).__name__}. It is "
            f"a probability budget, not a count and not a percentage."
        )
    budget = float(value)
    if not math.isfinite(budget) or not 0.0 < budget < 1.0:
        raise ValueError(
            f"{name} must lie strictly inside (0, 1), got {budget!r}. A "
            f"budget of 0 asks for a threshold that can never fire and a "
            f"budget of 1 for one that always does; neither is an operating "
            f"point. Pass 1e-09, not 9."
        )
    return budget


def _as_sample_size(value: Any, name: str) -> int:
    """Coerce a non-negative sample size, refusing booleans.

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
            f"{name} must be an int, got {type(value).__name__}. It counts "
            f"rounds; a float here is usually a rate that has already been "
            f"divided once."
        )
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def _as_strength(value: Any, name: str = "tolerated_depolarising") -> float:
    """Coerce a depolarising strength in ``[0, 1]``, refusing booleans.

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
        If ``value`` is not finite or lies outside ``[0, 1]``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{name} must be a real number, got {type(value).__name__}"
        )
    strength = float(value)
    if not math.isfinite(strength) or not 0.0 <= strength <= 1.0:
        raise ValueError(
            f"{name} must be a finite number in [0, 1], got {strength!r}. It "
            f"is the weight of the maximally mixed component of the honest "
            f"resource, so it is a probability. It is a physical noise level "
            f"the deployment states, never a knob turned until a table looked "
            f"better."
        )
    return strength


# --------------------------------------------------------------------------- #
# The Werner family, in closed form
# --------------------------------------------------------------------------- #


def werner_fidelity(strength: float) -> float:
    """Return the fidelity of a Werner resource of depolarising strength ``p``.

    For ``rho(p) = (1 - p) |Phi+><Phi+| + p I/4`` the identity term contributes
    ``1/4`` of its weight to the overlap with any pure state, so

    .. code-block:: text

        <Phi+| rho(p) |Phi+>  =  (1 - p) + p/4  =  1 - 3p/4

    Parameters
    ----------
    strength : float
        ``p`` in ``[0, 1]``.

    Returns
    -------
    float
        The mean fidelity such a link's check rounds report.

    Raises
    ------
    TypeError
        If ``strength`` is a boolean or not a real number.
    ValueError
        If it is not finite or lies outside ``[0, 1]``.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import werner_fidelity
    >>> werner_fidelity(0.0), werner_fidelity(1.0)
    (1.0, 0.25)
    >>> f"{werner_fidelity(1 / 32):.6f}"
    '0.976562'
    """
    return 1.0 - 0.75 * _as_strength(strength, "strength")


def werner_purity(strength: float) -> float:
    """Return the purity of a Werner resource of depolarising strength ``p``.

    With ``P = |Phi+><Phi+|`` a rank-one projector on four dimensions,
    ``Tr(P^2) = Tr(P) = 1`` and ``Tr(I) = 4``, so

    .. code-block:: text

        Tr(rho(p)^2) = (1-p)^2 + 2 (1-p)(p/4) Tr(P) + (p/4)^2 Tr(I)
                     = (1-p)^2 + p(1-p)/2 + p^2/4
                     = 1 - 3p/2 + 3p^2/4

    which is ``1`` at ``p = 0`` and ``1/4`` at ``p = 1``, the purity of the
    maximally mixed two-qubit state.

    Parameters
    ----------
    strength : float
        ``p`` in ``[0, 1]``.

    Returns
    -------
    float
        The mean purity such a link's check rounds report.

    Raises
    ------
    TypeError
        If ``strength`` is a boolean or not a real number.
    ValueError
        If it is not finite or lies outside ``[0, 1]``.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import werner_purity
    >>> werner_purity(0.0), werner_purity(1.0)
    (1.0, 0.25)
    >>> f"{werner_purity(0.1):.6f}"
    '0.857500'
    """
    p = _as_strength(strength, "strength")
    return 1.0 - 1.5 * p + 0.75 * p * p


def werner_concurrence(strength: float) -> float:
    """Return the concurrence of a Werner resource of strength ``p``.

    ``max(0, 1 - 3p/2)``: the Werner family is entangled exactly for
    ``p < 2/3``, and the concurrence falls linearly to zero there. Equivalently
    ``max(0, 2F - 1)`` in terms of :func:`werner_fidelity`, which is the form a
    reader who knows the fidelity can check in one line.

    Parameters
    ----------
    strength : float
        ``p`` in ``[0, 1]``.

    Returns
    -------
    float
        The mean concurrence such a link's check rounds report.

    Raises
    ------
    TypeError
        If ``strength`` is a boolean or not a real number.
    ValueError
        If it is not finite or lies outside ``[0, 1]``.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import (
    ...     werner_concurrence, werner_fidelity,
    ... )
    >>> werner_concurrence(0.0), werner_concurrence(2 / 3)
    (1.0, 0.0)
    >>> f"{werner_concurrence(0.1):.6f}"
    '0.850000'
    >>> f"{2 * werner_fidelity(0.1) - 1:.6f}"
    '0.850000'
    """
    return max(0.0, 1.0 - 1.5 * _as_strength(strength, "strength"))


# --------------------------------------------------------------------------- #
# How many rounds this link actually measured
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CheckRoundShare:
    """One link's share of a run's reserved check positions.

    The answer to "what ``n`` is this link's threshold derived from?", computed
    from the parameter set rather than read off a transcript, so that a Phase 5
    author can size a run before running it.

    Attributes
    ----------
    party : Party
        Whose link.
    qber_rounds : int
        QBER rounds dealt to this link.
    chsh_rounds : int
        CHSH rounds dealt to this link.
    """

    party: Party
    qber_rounds: int
    chsh_rounds: int

    @property
    def total(self) -> int:
        """int: Reserved positions this link measures, over both arms."""
        return self.qber_rounds + self.chsh_rounds

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "party": str(self.party),
            "qber_rounds": self.qber_rounds,
            "chsh_rounds": self.chsh_rounds,
            "total": self.total,
        }


def _round_robin_share(total: int, offset: int, index: int, links: int) -> int:
    """Count the rounds a round-robin deal gives one link.

    Rounds ``j = 0 .. total - 1`` go to link ``(offset + j) mod links``, which
    is what :func:`~sih141.protocol.checkrounds.draw_check_plan` does with a
    counter that runs on across the two arms.

    Parameters
    ----------
    total : int
        Rounds in this arm.
    offset : int
        Value of the running counter when the arm starts.
    index : int
        Which link, ``0`` based.
    links : int
        How many links share the deal.

    Returns
    -------
    int
    """
    first = (index - offset) % links
    if first >= total:
        return 0
    return (total - first - 1) // links + 1


def link_check_rounds(
    params: ProtocolParams,
    *,
    chsh_weight: float = CHECK_CHSH_WEIGHT,
    parties: Sequence[Party | str] = VERIFIERS,
) -> tuple[CheckRoundShare, ...]:
    """Return each link's share of the reserved check rounds.

    Restates :func:`~sih141.protocol.checkrounds.draw_check_plan`'s dealing
    rule as arithmetic, so a threshold can be sized without drawing a plan:
    the CHSH arm takes ``floor(chsh_weight * check_count)`` positions and the
    QBER arm the rest, each arm is dealt round-robin over ``parties``, and the
    counter runs on across the arms so neither link collects both leftovers.

    **This is where the** ``sqrt(2)`` **lives** (:ref:`channel-dealing`): a
    link measures about half the run's reserved positions, so every half-width
    derived from its sample is ``sqrt(2)`` wider than one derived from the
    run's arm totals.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set. Only
        :attr:`~sih141.protocol.params.ProtocolParams.check_count` is read.
    chsh_weight : float, optional
        Keyword-only. The share of check rounds spent on the CHSH arm, matching
        :func:`~sih141.protocol.checkrounds.draw_check_plan`'s own default
        :data:`~sih141.protocol.checkrounds.CHECK_CHSH_WEIGHT`.
    parties : sequence of Party or str, optional
        Keyword-only. The links the reserved rounds are dealt between, in the
        order the dealer uses. Defaults to
        :data:`~sih141.protocol.params.VERIFIERS`.

    Returns
    -------
    tuple of CheckRoundShare
        One entry per link, in ``parties`` order.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams` or ``chsh_weight`` is
        not a real number.
    ValueError
        If ``chsh_weight`` is outside ``[0, 1)``, or if ``parties`` is empty,
        repeats a link or names Alice.

    Notes
    -----
    A parameter set with ``check_fraction = 0`` returns all-zero shares rather
    than raising. That is the honest answer -- such a run measures nothing, and
    every threshold in this module is unavailable on it -- and it differs from
    :func:`~sih141.protocol.checkrounds.draw_check_plan`, which raises because
    an empty *plan* would let a caller believe estimation was happening.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import link_check_rounds
    >>> from sih141.protocol.params import CHECKED_PARAMS, ProtocolParams
    >>> shares = link_check_rounds(
    ...     ProtocolParams(key_length=120, check_fraction=0.125)
    ... )
    >>> [(str(s.party), s.qber_rounds, s.chsh_rounds) for s in shares]
    [('Bob', 4, 4), ('Charlie', 4, 3)]
    >>> sum(s.total for s in shares) == 15
    True

    At the parameter set that buys its sample back, a link measures a little
    over four thousand rounds in each arm and half the run's reserved set:

    >>> CHECKED_PARAMS.check_count
    16458
    >>> bob, charlie = link_check_rounds(CHECKED_PARAMS)
    >>> bob.qber_rounds, bob.chsh_rounds, bob.total
    (4114, 4115, 8229)
    >>> charlie.qber_rounds, charlie.chsh_rounds
    (4115, 4114)

    A run without check rounds measures nothing, and says so:

    >>> [s.total for s in link_check_rounds(ProtocolParams(key_length=192))]
    [0, 0]
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    if isinstance(chsh_weight, bool) or not isinstance(
        chsh_weight, (int, float)
    ):
        raise TypeError(
            f"chsh_weight must be a real number, got "
            f"{type(chsh_weight).__name__}"
        )
    weight = float(chsh_weight)
    if not math.isfinite(weight) or not 0.0 <= weight < 1.0:
        raise ValueError(
            f"chsh_weight must lie in [0, 1), got {weight!r}; it is the share "
            f"of check rounds spent on the Bell arm, and a weight of 1 would "
            f"leave the QBER arm empty."
        )
    resolved: list[Party] = []
    for entry in parties:
        party = _as_party(entry)
        if party is Party.ALICE:
            raise ValueError(
                "check rounds are dealt between the recipients; Alice "
                "measures every one of them and holds no link of her own."
            )
        if party in resolved:
            raise ValueError(f"parties repeats {party}")
        resolved.append(party)
    if not resolved:
        raise ValueError(
            "parties must name at least one link; an empty deal would report "
            "a sample size of zero for a run that measured something."
        )

    check_count = params.check_count
    chsh_total = int(math.floor(weight * check_count))
    qber_total = check_count - chsh_total
    links = len(resolved)
    return tuple(
        CheckRoundShare(
            party=party,
            qber_rounds=_round_robin_share(
                qber_total, chsh_total, index, links
            ),
            chsh_rounds=_round_robin_share(chsh_total, 0, index, links),
        )
        for index, party in enumerate(resolved)
    )


def divide_budget(epsilon: float, parts: int) -> float:
    """Split a false-positive budget over ``parts`` independent tests.

    ``eps / parts``, by the union bound: firing on any of ``parts`` tests each
    held to ``eps / parts`` has probability at most ``eps``. A one-line
    function because the division is the step a Phase 5 author skips -- four
    screens per run at ``eps`` apiece is a run-level rate of ``4 eps``, and the
    published number would be wrong by a factor of four with nothing in the
    code to catch it.

    Parameters
    ----------
    epsilon : float
        The budget for the whole collection, strictly inside ``(0, 1)``.
    parts : int
        How many tests share it, at least ``1``.

    Returns
    -------
    float
        The per-test budget.

    Raises
    ------
    TypeError
        If ``epsilon`` is not a real number or ``parts`` is not an integer.
    ValueError
        If ``epsilon`` is outside ``(0, 1)`` or ``parts`` is below ``1``.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import divide_budget
    >>> divide_budget(1e-08, 4)
    2.5e-09
    >>> f"{divide_budget(0.05, 5):.4f}"
    '0.0100'
    """
    budget = _as_epsilon(epsilon)
    share = _as_sample_size(parts, "parts")
    if share < 1:
        raise ValueError(
            f"parts must be at least 1, got {share}. A budget divided over no "
            f"tests is not a wider budget, it is the absence of a test."
        )
    return budget / share


# --------------------------------------------------------------------------- #
# The carrier
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ChannelThreshold:
    """One derived critical value, with everything needed to audit it.

    The object every function in this module returns. It carries the *claim*
    (:attr:`null`), the *proof* (:attr:`inequality`, :attr:`derivation`) and
    the *number the proof yields* (:attr:`false_positive_bound`) alongside the
    threshold itself, because a threshold quoted without its null is a tuned
    number wearing a derivation's clothes.

    Attributes
    ----------
    statistic : str
        Which field of :class:`~sih141.detect.statistics.LinkStatistics` this
        is compared against, spelled exactly as that object spells it --
        ``"qber_errors"``, ``"chsh"``, ``"min_purity"``, ``"mean_fidelity"``
        and so on.
    direction : {'lower', 'upper'}
        ``"upper"`` fires at or above :attr:`critical_value`, ``"lower"`` at or
        below it.
    critical_value : float
        The threshold. A float even where the statistic is a count, so that
        ``to_dict`` round-trips through JSON without an integer/float surprise.
    epsilon : float
        The budget it was derived at.
    false_positive_bound : float
        **The proven bound**, at or below :attr:`epsilon`: the probability that
        this threshold fires on a run drawn from :attr:`null` is at most this.
        Not an observed rate, and never fitted.
    null : str
        The honest-run law, written out.
    inequality : str
        The named inequality inverted to get here, or ``"point mass (exact)"``
        where the null is degenerate and no inequality was needed.
    sample_size : int
        The ``n`` the derivation used.
    derivation : str
        The algebra, in one line, so that the number can be recomputed from the
        object alone.
    is_alarm : bool
        Whether firing means "this link deviates from the honest null".
        ``False`` on a *certificate* -- :func:`chsh_certificate_threshold` --
        where firing means the opposite, that the resource was good. A screen
        refuses to evaluate a non-alarm, so that failing to certify can never
        be counted as a detection.
    reaches_its_statistic : bool
        Whether the critical value lies where an observation can reach it, so
        that the threshold can fire at all. ``False`` says the sample is too
        small to detect anything at this budget -- a fact about the run, not a
        defect in the derivation, and reported rather than papered over by
        clipping the value into range. Each function states the predicate it
        used, because "reachable" is not the same question for a count bounded
        by its own denominator, for a statistic bounded algebraically by
        ``+-4``, and for a certificate that only means something below
        Tsirelson's bound.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import qber_threshold
    >>> threshold = qber_threshold(rounds=24, epsilon=1e-09)
    >>> threshold.statistic, threshold.direction, threshold.critical_value
    ('qber_errors', 'upper', 1.0)
    >>> threshold.fires(0), threshold.fires(1)
    (False, True)
    >>> print(threshold.summary())      # doctest: +NORMALIZE_WHITESPACE
    qber_errors >= 1.0 fires; under point mass at 0: E = 0 with probability
    one (a non-negative variable with zero mean) P(fire) <= 0.00e+00
    (budget 1.00e-09, point mass (exact), n = 24)
    """

    statistic: str
    direction: str
    critical_value: float
    epsilon: float
    false_positive_bound: float
    null: str
    inequality: str
    sample_size: int
    derivation: str
    is_alarm: bool = True
    reaches_its_statistic: bool = True

    def __post_init__(self) -> None:
        """Coerce the fields and refuse a bound that exceeds its own budget.

        Raises
        ------
        ValueError
            If ``direction`` names no side, if a required string is empty, or
            if ``false_positive_bound`` exceeds ``epsilon`` -- which would mean
            the derivation did not deliver what it was asked for, and is a bug
            in this module rather than a number to publish.
        """
        object.__setattr__(self, "statistic", str(self.statistic))
        object.__setattr__(self, "direction", str(self.direction))
        object.__setattr__(self, "critical_value", float(self.critical_value))
        object.__setattr__(self, "epsilon", _as_epsilon(self.epsilon))
        object.__setattr__(
            self, "false_positive_bound", float(self.false_positive_bound)
        )
        object.__setattr__(self, "null", str(self.null))
        object.__setattr__(self, "inequality", str(self.inequality))
        object.__setattr__(
            self, "sample_size", _as_sample_size(self.sample_size, "sample_size")
        )
        object.__setattr__(self, "derivation", str(self.derivation))
        object.__setattr__(self, "is_alarm", bool(self.is_alarm))
        object.__setattr__(
            self, "reaches_its_statistic", bool(self.reaches_its_statistic)
        )
        if self.direction not in _DIRECTIONS:
            raise ValueError(
                f"direction must be one of {sorted(_DIRECTIONS)}, got "
                f"{self.direction!r}"
            )
        if not math.isfinite(self.critical_value):
            raise ValueError(
                f"{self.statistic}: critical_value must be finite, got "
                f"{self.critical_value!r}"
            )
        if not 0.0 <= self.false_positive_bound <= 1.0:
            raise ValueError(
                f"{self.statistic}: false_positive_bound must be a "
                f"probability, got {self.false_positive_bound!r}"
            )
        if self.false_positive_bound > self.epsilon:
            # Not a tolerance and not a clamp: every construction site in this
            # module proves its bound analytically before it gets here, so a
            # value above the budget means an inversion is wrong. A caller who
            # ships a new derivation finds out here rather than in a table.
            raise ValueError(
                f"{self.statistic}: the derivation proved only "
                f"{self.false_positive_bound!r} against a budget of "
                f"{self.epsilon!r}. A threshold whose proven bound exceeds its "
                f"own budget has not been derived, it has been asserted; this "
                f"is a defect in the inversion, not a number to publish."
            )
        for field, text in (("null", self.null), ("derivation", self.derivation)):
            if not text:
                raise ValueError(
                    f"{self.statistic}: {field} must be a non-empty sentence. "
                    f"Convention D7: a threshold with no written-down null and "
                    f"no written-down algebra cannot be audited, and an empty "
                    f"string would let one ship anyway."
                )

    def fires(self, observed: float) -> bool:
        """Return whether an observation trips this threshold.

        Parameters
        ----------
        observed : float
            The measured statistic.

        Returns
        -------
        bool
            ``observed >= critical_value`` for ``direction="upper"``,
            ``observed <= critical_value`` for ``"lower"``.

        Raises
        ------
        TypeError
            If ``observed`` is ``None`` or is not a real number. **``None`` is
            refused rather than read as "did not fire"**: an unmonitored link
            has no observation, and silently clearing it is how a screen
            reports a channel as clean because nobody looked at it.
        ValueError
            If ``observed`` is not finite.

        Examples
        --------
        >>> from sih141.detect.thresholds_channel import chsh_threshold
        >>> threshold = chsh_threshold(
        ...     counts=(1028, 1029, 1029, 1029), epsilon=1e-09
        ... )
        >>> threshold.fires(2.83), threshold.fires(2.0)
        (False, True)
        """
        if isinstance(observed, bool) or not isinstance(observed, (int, float)):
            raise TypeError(
                f"{self.statistic}: observed must be a real number, got "
                f"{type(observed).__name__}. A missing observation is not a "
                f"passing one -- an unmonitored link has no value here, and "
                f"reading None as 'did not fire' would report a channel "
                f"nobody looked at as clean."
            )
        value = float(observed)
        if not math.isfinite(value):
            raise ValueError(
                f"{self.statistic}: observed must be finite, got {value!r}"
            )
        if self.direction == "upper":
            return value >= self.critical_value
        return value <= self.critical_value

    def summary(self) -> str:
        """Return a one-line account naming every number behind the threshold.

        Returns
        -------
        str
        """
        comparison = ">=" if self.direction == "upper" else "<="
        return (
            f"{self.statistic} {comparison} {self.critical_value} fires; "
            f"under {self.null} "
            f"P(fire) <= {self.false_positive_bound:.2e} "
            f"(budget {self.epsilon:.2e}, {self.inequality}, "
            f"n = {self.sample_size})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "statistic": self.statistic,
            "direction": self.direction,
            "critical_value": self.critical_value,
            "epsilon": self.epsilon,
            "false_positive_bound": self.false_positive_bound,
            "null": self.null,
            "inequality": self.inequality,
            "sample_size": self.sample_size,
            "derivation": self.derivation,
            "is_alarm": self.is_alarm,
            "reaches_its_statistic": self.reaches_its_statistic,
        }


# --------------------------------------------------------------------------- #
# Derivation 1: per-link check-round QBER
# --------------------------------------------------------------------------- #


def _binomial_upper_tails(trials: int, probability: float) -> list[float]:
    """Return ``P(X >= k)`` for every ``k``, for ``X ~ Binomial(n, q)``.

    One pass over the probability mass function and one pass of suffix sums, so
    the whole table costs ``O(n)`` rather than the ``O(n^2)`` a search that
    re-summed the tail at each candidate would.

    Parameters
    ----------
    trials : int
        ``n``, at least ``0``.
    probability : float
        ``q``, strictly inside ``(0, 1)``.

    Returns
    -------
    list of float
        Length ``n + 2``. Entry ``k`` is ``P(X >= k)``; entry ``0`` is ``1``
        and entry ``n + 1`` is ``0``, the empty event.
    """
    log_q = math.log(probability)
    log_one_minus_q = math.log1p(-probability)
    log_factorial_n = math.lgamma(trials + 1)
    tails = [0.0] * (trials + 2)
    accumulated = 0.0
    for hits in range(trials, -1, -1):
        log_mass = (
            log_factorial_n
            - math.lgamma(hits + 1)
            - math.lgamma(trials - hits + 1)
            + hits * log_q
            + (trials - hits) * log_one_minus_q
        )
        accumulated += math.exp(log_mass) if log_mass > -745.0 else 0.0
        tails[hits] = min(1.0, accumulated)
    return tails


def _qber_critical_hoeffding(
    rounds: int, rate: float, epsilon: float
) -> tuple[int, float]:
    """Invert the additive Hoeffding upper tail for a binomial count.

    Parameters
    ----------
    rounds : int
        ``n``.
    rate : float
        ``q0``, strictly positive.
    epsilon : float
        The budget.

    Returns
    -------
    tuple of (int, float)
        The critical count and the bound the inequality proves at it.
    """
    mean = rounds * rate
    spread = math.sqrt(rounds * -math.log(epsilon) / 2.0)
    critical = max(math.ceil(mean + spread), math.floor(mean) + 1)
    if critical > rounds:
        return rounds + 1, 0.0
    gap = critical - mean
    # The integer ceiling sits at or above the analytic value, so re-evaluating
    # the inequality there can only improve on eps. The min() takes care of the
    # one ulp a round trip through sqrt and exp can add when the two coincide.
    return critical, min(epsilon, math.exp(-2.0 * gap * gap / rounds))


def _qber_critical_chernoff(
    rounds: int, rate: float, epsilon: float
) -> tuple[int, float]:
    """Invert the multiplicative Chernoff upper tail for a binomial count.

    Parameters
    ----------
    rounds : int
        ``n``.
    rate : float
        ``q0``, strictly positive.
    epsilon : float
        The budget.

    Returns
    -------
    tuple of (int, float)
        The critical count and the bound the inequality proves at it.
    """
    mean = rounds * rate
    budget = -math.log(epsilon)
    deviation = (
        budget + math.sqrt(budget * budget + 8.0 * mean * budget)
    ) / (2.0 * mean)
    critical = max(math.ceil((1.0 + deviation) * mean), math.floor(mean) + 1)
    if critical > rounds:
        return rounds + 1, 0.0
    realised = (critical - mean) / mean
    return critical, min(
        epsilon, math.exp(-realised * realised * mean / (2.0 + realised))
    )


def _qber_critical_exact(
    rounds: int, rate: float, epsilon: float
) -> tuple[int, float]:
    """Invert the exact binomial upper tail.

    Parameters
    ----------
    rounds : int
        ``n``.
    rate : float
        ``q0``, strictly positive.
    epsilon : float
        The budget, at or above :data:`_EXACT_METHOD_FLOOR`.

    Returns
    -------
    tuple of (int, float)
        The critical count and the tail at it, which is the exact
        false-positive probability rather than a bound on it.
    """
    tails = _binomial_upper_tails(rounds, rate)
    for critical in range(1, rounds + 1):
        if tails[critical] <= epsilon:
            return critical, tails[critical]
    return rounds + 1, 0.0


def qber_threshold(
    *,
    rounds: int,
    epsilon: float,
    tolerated_depolarising: float = 0.0,
    method: str = "exact",
) -> ChannelThreshold:
    """Derive the check-round error count at which one link is called disturbed.

    The full derivation is :ref:`channel-qber`. In one paragraph: conditional
    on the check plan the link's QBER rounds are independent trials, so the
    honest null is ``Binomial(n, q0)`` with ``q0 = p0/2``
    (:func:`~sih141.protocol.analysis.depolarising_error_rate`); at ``p0 = 0``
    that collapses to a point mass at ``0`` and the threshold is one error with
    a false-positive probability of exactly zero; otherwise the named upper
    tail is inverted at ``epsilon``.

    **Per link, never pooled** (:ref:`channel-per-party`), and **conditioned on
    (NO-TIMING)** (:ref:`channel-no-timing`). ``rounds`` is this link's own
    sample, which is about a quarter of the run's reserved positions rather
    than all of them; :func:`link_check_rounds` computes it.

    Parameters
    ----------
    rounds : int
        Keyword-only. ``n``, the QBER rounds this link published --
        :attr:`LinkStatistics.errors.trials
        <sih141.detect.statistics.LinkStatistics>`.
    epsilon : float
        Keyword-only. The false-positive budget, strictly inside ``(0, 1)``.
    tolerated_depolarising : float, optional
        Keyword-only. ``p0``, the depolarising strength the honest channel is
        allowed. Defaults to ``0``, the noiseless null. **The transcript cannot
        supply this** (:ref:`finding 2 <findings>`): a run with check rounds
        carries an *estimate* of the channel it saw, not a statement of what it
        should have been, so a noise-tolerant threshold has to be handed the
        level from outside.
    method : {'exact', 'chernoff', 'hoeffding'}, optional
        Keyword-only. Which inversion to use when ``tolerated_depolarising`` is
        positive; ignored at ``0``, where the null is degenerate and exact.
        Defaults to ``'exact'``, the binomial tail itself, which is the
        tightest of the three at no cost in rigour. ``'chernoff'`` is the
        multiplicative form and is close behind; ``'hoeffding'`` is the
        additive one and is badly loose at the small ``q0`` a QBER null has,
        because it is charged for a variance of ``n/4`` where the truth is
        ``n q0 (1 - q0)``.

    Returns
    -------
    ChannelThreshold
        With ``statistic="qber_errors"`` and ``direction="upper"``: fire when
        the observed error count is at or above
        :attr:`~ChannelThreshold.critical_value`.

    Raises
    ------
    TypeError
        If an argument has the wrong type.
    ValueError
        If ``epsilon`` is outside ``(0, 1)``, ``rounds`` is negative,
        ``tolerated_depolarising`` is outside ``[0, 1]``, ``method`` names no
        inversion, or ``method='exact'`` is asked for at a budget below
        :data:`_EXACT_METHOD_FLOOR`.

    Notes
    -----
    A link with no QBER rounds gets a threshold of ``1`` that can never fire,
    flagged by :attr:`~ChannelThreshold.reaches_its_statistic` being ``False``.
    That is the honest shape: there is no sample, so there is nothing to
    detect, and returning a threshold that silently never fires without saying
    so is how "no data" becomes "clean".

    Examples
    --------
    The noiseless null needs no inequality and no budget, and its bound is the
    strongest in the family:

    >>> from sih141.detect.thresholds_channel import qber_threshold
    >>> threshold = qber_threshold(rounds=4114, epsilon=1e-09)
    >>> threshold.critical_value, threshold.false_positive_bound
    (1.0, 0.0)
    >>> threshold.inequality
    'point mass (exact)'

    With a noise level in hand the three inversions separate. All three are
    proven at the same budget; they differ in how much of the sample they
    waste:

    >>> for method in ("hoeffding", "chernoff", "exact"):
    ...     value = qber_threshold(
    ...         rounds=4114,
    ...         epsilon=1e-09,
    ...         tolerated_depolarising=1 / 32,
    ...         method=method,
    ...     ).critical_value
    ...     print(f"{method:10s} {value:6.1f}")
    hoeffding   271.0
    chernoff    128.0
    exact       118.0

    Sweeping the budget moves the threshold, which is what a ROC curve is made
    of:

    >>> [
    ...     qber_threshold(
    ...         rounds=4114, epsilon=eps, tolerated_depolarising=1 / 32
    ...     ).critical_value
    ...     for eps in (1e-02, 1e-06, 1e-12)
    ... ]
    [84.0, 106.0, 129.0]

    A sample too small for the budget gets a threshold that cannot fire, and
    says so rather than pretending:

    >>> tiny = qber_threshold(
    ...     rounds=12, epsilon=1e-09, tolerated_depolarising=0.5
    ... )
    >>> tiny.critical_value, tiny.reaches_its_statistic
    (13.0, False)
    >>> tiny.false_positive_bound
    0.0
    """
    sample = _as_sample_size(rounds, "rounds")
    budget = _as_epsilon(epsilon)
    strength = _as_strength(tolerated_depolarising)
    if not isinstance(method, str) or method not in _QBER_METHODS:
        raise ValueError(
            f"method must be one of {sorted(_QBER_METHODS)}, got {method!r}. "
            f"Each names an inequality applied to the same stated null; they "
            f"differ in tightness, not in what they claim."
        )
    rate = depolarising_error_rate(strength)

    if rate == 0.0 or sample == 0:
        # A non-negative count with mean zero is zero almost surely, so the
        # honest null forbids a single error outright. No inequality can
        # improve on a probability of exactly zero, and the budget is
        # therefore not consulted at all.
        return ChannelThreshold(
            statistic="qber_errors",
            direction="upper",
            critical_value=1.0,
            epsilon=budget,
            false_positive_bound=0.0,
            null=(
                "point mass at 0: E = 0 with probability one (a non-negative "
                "variable with zero mean)"
            ),
            inequality="point mass (exact)",
            sample_size=sample,
            derivation=(
                "E >= 0 and E[E] = n * q0 = 0, so E = 0 almost surely and "
                "P(E >= 1) = 0 exactly, at every eps"
            ),
            reaches_its_statistic=sample >= 1,
        )

    if method == "exact":
        if budget < _EXACT_METHOD_FLOOR:
            raise ValueError(
                f"method='exact' needs epsilon at or above "
                f"{_EXACT_METHOD_FLOOR!r}; got {budget!r}. Below that the "
                f"binomial tail is summed in arithmetic that underflows, so "
                f"the search would report a rounded-down 0.0 as a proven "
                f"bound. Use method='chernoff' or 'hoeffding', which are "
                f"closed forms and have no such floor."
            )
        critical, bound = _qber_critical_exact(sample, rate, budget)
        inequality = "exact binomial tail"
        derivation = (
            f"k = min{{k : sum_{{j>=k}} C({sample},j) q0^j (1-q0)^({sample}-j) "
            f"<= eps}} with q0 = {rate!r}"
        )
    elif method == "chernoff":
        critical, bound = _qber_critical_chernoff(sample, rate, budget)
        inequality = "multiplicative Chernoff upper tail"
        derivation = (
            "P(E >= (1+d) mu) <= exp(-d^2 mu / (2+d)); d = [ln(1/eps) + "
            "sqrt(ln(1/eps)^2 + 8 mu ln(1/eps))] / (2 mu); k = ceil((1+d) mu) "
            f"with mu = {sample} * {rate!r}"
        )
    else:
        critical, bound = _qber_critical_hoeffding(sample, rate, budget)
        inequality = "Hoeffding upper tail"
        derivation = (
            "P(E >= n q0 + s) <= exp(-2 s^2 / n); s = sqrt(n ln(1/eps) / 2); "
            f"k = ceil(n q0 + s) with n = {sample} and q0 = {rate!r}"
        )

    return ChannelThreshold(
        statistic="qber_errors",
        direction="upper",
        critical_value=float(critical),
        epsilon=budget,
        false_positive_bound=bound,
        null=f"Binomial({sample}, {rate!r})",
        inequality=inequality,
        sample_size=sample,
        derivation=derivation,
        reaches_its_statistic=critical <= sample,
    )


# --------------------------------------------------------------------------- #
# Derivation 2: CHSH
# --------------------------------------------------------------------------- #


def _as_chsh_counts(counts: Any) -> tuple[int, int, int, int]:
    """Coerce the four CHSH cell counts, refusing an empty cell.

    Parameters
    ----------
    counts : sequence of int
        The four cell counts, in
        :attr:`~sih141.protocol.checkrounds.ChshEstimate.counts` order.

    Returns
    -------
    tuple of int

    Raises
    ------
    TypeError
        If ``counts`` is not a sequence of integers.
    ValueError
        If it does not hold exactly four entries, or if any is ``0``.
    """
    if isinstance(counts, (str, bytes)) or not isinstance(counts, Sequence):
        raise TypeError(
            f"counts must be a sequence of four ints, got "
            f"{type(counts).__name__}"
        )
    values = tuple(_as_sample_size(entry, "counts entry") for entry in counts)
    if len(values) != 4:
        raise ValueError(
            f"a CHSH statistic has exactly four cells -- two settings per wing "
            f"-- got {len(values)}"
        )
    empty = [index for index, value in enumerate(values) if value == 0]
    if empty:
        raise ValueError(
            f"CHSH cell(s) {empty} hold no rounds, so their correlators are "
            f"undefined and the bounded-difference constant 2/n_c is "
            f"infinite. A threshold cannot be derived for a statistic that "
            f"does not exist; the caller should read "
            f"LinkStatistics.chsh_unavailable and record the statistic as "
            f"unavailable rather than as clean."
        )
    return values  # type: ignore[return-value]


def _chsh_half_width(counts: Sequence[int], epsilon: float) -> float:
    """Return the bounded-difference half-width ``t(eps)`` for ``S``.

    Parameters
    ----------
    counts : sequence of int
        The four cell counts, all positive.
    epsilon : float
        The budget.

    Returns
    -------
    float
        ``sqrt(2 ln(1/eps) sum_c 1/n_c)``.
    """
    reciprocal = sum(1.0 / count for count in counts)
    return math.sqrt(2.0 * -math.log(epsilon) * reciprocal)


def chsh_threshold(
    *,
    counts: Sequence[int],
    epsilon: float,
    tolerated_depolarising: float = 0.0,
) -> ChannelThreshold:
    """Derive the ``S`` below which one link's Bell test is called disturbed.

    The full derivation is :ref:`channel-chsh`. In one paragraph: under a
    Werner honest resource of strength ``p0`` the null mean is
    ``S0 = (1 - p0) 2 sqrt(2)``
    (:func:`~sih141.protocol.checkrounds.depolarising_chsh`); ``S`` is a
    function of ``N`` independent round outcomes with bounded differences
    ``2/n_c``, so McDiarmid's inequality gives
    ``P(S <= S0 - t) <= exp(-t^2 / (2 sum_c 1/n_c))``, which inverts to
    ``t(eps) = sqrt(2 ln(1/eps) sum_c 1/n_c)``.

    **This is the only member of the channel family whose ideal null is not a
    point mass.** The ``+-1`` outcomes are random on a perfect pair, so a Bell
    test at a small budget has to be paid for in rounds and cannot be had for
    free the way the resource summaries can.

    **Per link, never pooled** (:ref:`channel-per-party`), and **conditioned on
    (NO-TIMING)** (:ref:`channel-no-timing`).

    Parameters
    ----------
    counts : sequence of int
        Keyword-only. The four cell counts, exactly as
        :attr:`~sih141.protocol.checkrounds.ChshEstimate.counts` reports them.
        All four must be positive: an empty cell has an undefined correlator,
        and a threshold for a statistic that does not exist is not a threshold.
    epsilon : float
        Keyword-only. The false-positive budget, strictly inside ``(0, 1)``.
    tolerated_depolarising : float, optional
        Keyword-only. ``p0``. Defaults to ``0``, the ideal null.

    Returns
    -------
    ChannelThreshold
        With ``statistic="chsh"`` and ``direction="lower"``: fire when the
        observed ``S`` is at or below :attr:`~ChannelThreshold.critical_value`.
        :attr:`~ChannelThreshold.reaches_its_statistic` is ``False`` when that
        value falls below the algebraic floor ``-4``, where no observation can
        trip it.

    Raises
    ------
    TypeError
        If an argument has the wrong type.
    ValueError
        If ``counts`` is not four positive integers, ``epsilon`` is outside
        ``(0, 1)``, or ``tolerated_depolarising`` is outside ``[0, 1]``.

    Notes
    -----
    The threshold is placed relative to the **null's** mean and uses the null's
    own geometry throughout. It never reads the measured correlators, for the
    reason :mod:`sih141.attacks.statistics` gives about tolerances: the
    hypothesis under test is that the ideal analysis is right, and an
    estimator's own value has no business setting the width of its own
    acceptance band.

    **Why this is not the protocol's own Hoeffding interval, inverted.**
    :func:`~sih141.protocol.checkrounds.estimate_chsh`'s ``"hoeffding"`` method
    bounds each cell separately and sums four half-widths
    ``sqrt(2 ln(8/alpha) / n_c)``, where the ``8`` is a union bound over four
    cells and two tails. That is the right shape for a two-sided *reporting*
    interval on all four correlators at once. A threshold needs one bound on
    one number in one direction, and McDiarmid gives it directly -- at a
    comparable level the direct bound is a factor of ``2.25`` tighter, which is
    a factor of five in rounds:

    >>> import math
    >>> from sih141.protocol.checkrounds import CHECK_CONFIDENCE
    >>> alpha = 1.0 - CHECK_CONFIDENCE            # 0.01, two-sided
    >>> summed = 4 * math.sqrt(8 * math.log(8 / alpha))     # x 1/sqrt(N)
    >>> direct = math.sqrt(32 * -math.log(alpha / 2))       # x 1/sqrt(N)
    >>> f"{summed:.2f}", f"{direct:.2f}", f"{summed / direct:.2f}"
    ('29.25', '13.02', '2.25')
    >>> f"{(summed / direct) ** 2:.2f}"
    '5.05'

    Examples
    --------
    A link with a serious Bell sample, at three budgets:

    >>> from sih141.detect.thresholds_channel import chsh_threshold
    >>> counts = (1028, 1029, 1029, 1029)
    >>> for eps in (1e-03, 1e-06, 1e-09):
    ...     threshold = chsh_threshold(counts=counts, epsilon=eps)
    ...     print(f"{eps:.0e}  S <= {threshold.critical_value:.4f}")
    1e-03  S <= 2.5967
    1e-06  S <= 2.5007
    1e-09  S <= 2.4270

    What distribution-freedom costs, as the number a report should quote.
    These cells are balanced to within one round, so the realised half-width
    and the balanced-cell closed form ``2 sqrt(ln(1/eps))`` agree to four
    decimals against the null's own standard deviation ``sqrt(8/N)``:

    >>> import math
    >>> from sih141.protocol.checkrounds import IDEAL_CHSH, normal_quantile
    >>> rounds = sum(counts)
    >>> threshold = chsh_threshold(counts=counts, epsilon=1e-09)
    >>> gap = IDEAL_CHSH - threshold.critical_value
    >>> f"{gap / math.sqrt(8 / rounds):.4f}"
    '9.1046'
    >>> f"{2 * math.sqrt(-math.log(1e-09)):.4f}"
    '9.1046'

    A normal quantile at the same budget would have asked for six standard
    deviations, so the bound that holds at every sample size costs a factor of
    ``1.52`` in resolution -- and a report that quotes the smaller number
    should say which of the two it is quoting:

    >>> f"{normal_quantile(1 - 1e-09):.4f}"
    '5.9978'
    >>> f"{2 * math.sqrt(-math.log(1e-09)) / normal_quantile(1 - 1e-09):.4f}"
    '1.5180'

    A twenty-four-round sample at ``1e-09`` puts the critical value below the
    **classical** bound, and even below zero. Such a threshold is not broken --
    its false-positive bound is as proven as any other -- but it fires only on
    a resource whose correlations have been *inverted*, so a sample that size
    cannot detect an adversary who merely destroys the entanglement and leaves
    ``S`` near zero. The number says so; nothing here clips it into a range
    where it would look useful:

    >>> from sih141.protocol.checkrounds import CLASSICAL_CHSH_BOUND
    >>> short = chsh_threshold(counts=(6, 6, 6, 6), epsilon=1e-09)
    >>> f"{short.critical_value:.4f}"
    '-2.4281'
    >>> short.critical_value > CLASSICAL_CHSH_BOUND, short.reaches_its_statistic
    (False, True)

    A tolerated noise level moves the null down with it:

    >>> noisy = chsh_threshold(
    ...     counts=counts, epsilon=1e-09, tolerated_depolarising=0.1
    ... )
    >>> f"{noisy.critical_value:.4f}"
    '2.1441'
    """
    cells = _as_chsh_counts(counts)
    budget = _as_epsilon(epsilon)
    strength = _as_strength(tolerated_depolarising)
    rounds = sum(cells)
    null_mean = depolarising_chsh(strength)
    half_width = _chsh_half_width(cells, budget)
    critical = null_mean - half_width
    return ChannelThreshold(
        statistic="chsh",
        direction="lower",
        critical_value=critical,
        epsilon=budget,
        # Exactly the budget, by construction rather than by rounding: t(eps)
        # is the value at which the inequality's right-hand side *equals* eps,
        # so a continuous inversion spends its budget exactly and there is
        # nothing left over to report. Re-evaluating exp(-t^2 / ...) here would
        # return eps plus a few ulps of round-trip noise and nothing else.
        false_positive_bound=budget,
        null=(
            f"E[S] = {null_mean!r} for a Werner resource of strength "
            f"{strength!r}, over {rounds} independent rounds in cells {cells}"
        ),
        inequality="McDiarmid bounded differences (one-sided)",
        sample_size=rounds,
        derivation=(
            "flipping one round of cell c moves S by 2/n_c, so sum c_i^2 = "
            "4 sum_c 1/n_c and P(S <= S0 - t) <= exp(-t^2 / (2 sum_c 1/n_c)); "
            f"t = sqrt(2 ln(1/eps) sum_c 1/n_c) = {half_width!r}"
        ),
        reaches_its_statistic=critical >= -4.0,
    )


def chsh_certificate_threshold(
    *, counts: Sequence[int], epsilon: float
) -> ChannelThreshold:
    """Derive the ``S`` above which entanglement on arrival is *certified*.

    A different claim from :func:`chsh_threshold`, against a different null,
    and **not an alarm**. Under
    ``H0': S_true <= 2``
    (:data:`~sih141.protocol.checkrounds.CLASSICAL_CHSH_BOUND`) the same
    bounded-difference constants give
    ``P(S >= S_true + t(eps)) <= eps``, so observing ``S > 2 + t(eps)``
    licenses "this resource was entangled when it arrived" and licenses it
    wrongly with probability at most ``eps``.

    :attr:`~ChannelThreshold.is_alarm` is ``False``, and :func:`screen_link`
    refuses to evaluate it. The refusal is deliberate: *failing to certify is
    not a detection*. A short sample cannot certify anything, and a screen that
    counted a missing certificate as an alarm would publish a detection rate
    equal to its own sample-size problem -- the channel-family form of Phase
    3's rule that a refusal is never a rejection.

    **The certificate is not device-independent, and must never be quoted as
    if it were.** It certifies entanglement *under the assumption that both
    endpoints measured at the announced settings*, which is the architecture
    this scheme has: Alice learns the check set only after the pairs are
    through the channel, and her honesty at that point is assumption **(AUTH)**
    (:ref:`sih141.protocol.checkrounds <check-timing>`). A CHSH number quoted
    without that sentence claims far more than the protocol delivers.

    Parameters
    ----------
    counts : sequence of int
        Keyword-only. The four cell counts, all positive.
    epsilon : float
        Keyword-only. The budget on certifying wrongly, inside ``(0, 1)``.

    Returns
    -------
    ChannelThreshold
        With ``statistic="chsh"``, ``direction="upper"`` and
        ``is_alarm=False``. :attr:`~ChannelThreshold.reaches_its_statistic` is
        ``False`` when the critical value sits at or above the ideal
        ``2 sqrt(2)``, where even a perfect resource could not clear it and the
        sample is simply too small to certify anything at this budget.

    Raises
    ------
    TypeError
        If an argument has the wrong type.
    ValueError
        If ``counts`` is not four positive integers or ``epsilon`` is outside
        ``(0, 1)``.

    Examples
    --------
    >>> import math
    >>> from sih141.detect.thresholds_channel import chsh_certificate_threshold
    >>> certificate = chsh_certificate_threshold(
    ...     counts=(1028, 1029, 1029, 1029), epsilon=1e-09
    ... )
    >>> f"{certificate.critical_value:.4f}", certificate.is_alarm
    ('2.4014', False)
    >>> certificate.reaches_its_statistic
    True

    How many balanced rounds a certificate costs, distribution-free against
    normal theory. The ask is ``t(eps) < 2 sqrt(2) - 2``, i.e.
    ``32 ln(1/eps) / N < (2 sqrt(2) - 2)^2``:

    >>> from sih141.protocol.checkrounds import (
    ...     CLASSICAL_CHSH_BOUND, IDEAL_CHSH, normal_quantile,
    ... )
    >>> gap = IDEAL_CHSH - CLASSICAL_CHSH_BOUND
    >>> math.ceil(32 * -math.log(1e-09) / gap ** 2)
    967
    >>> math.ceil(8 * normal_quantile(1 - 1e-09) ** 2 / gap ** 2)
    420

    A sample too small to certify says so rather than returning an unreachable
    number quietly:

    >>> short = chsh_certificate_threshold(counts=(6, 6, 6, 6), epsilon=1e-09)
    >>> f"{short.critical_value:.4f}", short.reaches_its_statistic
    ('7.2565', False)
    """
    cells = _as_chsh_counts(counts)
    budget = _as_epsilon(epsilon)
    rounds = sum(cells)
    half_width = _chsh_half_width(cells, budget)
    critical = CLASSICAL_CHSH_BOUND + half_width
    return ChannelThreshold(
        statistic="chsh",
        direction="upper",
        critical_value=critical,
        epsilon=budget,
        # Exactly the budget, and for the same reason chsh_threshold gives.
        false_positive_bound=budget,
        null=(
            f"S_true <= {CLASSICAL_CHSH_BOUND!r}, the classical bound, over "
            f"{rounds} independent rounds in cells {cells}"
        ),
        inequality="McDiarmid bounded differences (one-sided)",
        sample_size=rounds,
        derivation=(
            "P(S >= S_true + t) <= exp(-t^2 / (2 sum_c 1/n_c)); with "
            f"S_true <= 2 the certificate fires above 2 + t, t = {half_width!r}"
        ),
        is_alarm=False,
        reaches_its_statistic=critical < IDEAL_CHSH,
    )


# --------------------------------------------------------------------------- #
# Derivation 3: the resource summaries, as bounded means
# --------------------------------------------------------------------------- #


def bounded_mean_threshold(
    *,
    samples: int,
    epsilon: float,
    honest_mean: float,
    span: tuple[float, float],
    statistic: str,
    quantity: str,
    tolerance: float = IDEAL_TOLERANCE,
) -> ChannelThreshold:
    """Derive a lower threshold on the mean of a bounded per-round summary.

    The engine behind :func:`fidelity_threshold`, :func:`purity_threshold` and
    :func:`concurrence_threshold`, exposed because a deployment that monitors
    some other bounded per-round quantity gets the same derivation for free.
    The full argument is :ref:`channel-resource`; in one paragraph:

    * If ``honest_mean`` sits on the **top** of ``span``, the null is a point
      mass there and no inequality is needed. ``V <= b`` and ``E[V] = b`` give
      ``E[b - V] = 0`` with ``b - V >= 0``, so ``V = b`` almost surely -- a
      bounded variable whose mean is its own supremum is degenerate. Every
      round sits on ``b``, so the mean does and so does the minimum, and a
      threshold at ``b - tolerance`` has a false-positive probability of
      exactly zero.
    * Otherwise Hoeffding for bounded variables:
      ``P(mean <= mu0 - t) <= exp(-2 n t^2 / (b - a)^2)``, inverted at
      ``t(eps) = (b - a) sqrt(ln(1/eps) / (2n))``.

    Parameters
    ----------
    samples : int
        Keyword-only. ``n``, the monitored check rounds on this link.
    epsilon : float
        Keyword-only. The false-positive budget, strictly inside ``(0, 1)``.
    honest_mean : float
        Keyword-only. ``mu0``, inside ``span``.
    span : tuple of float
        Keyword-only. ``(a, b)``, the closed range the per-round quantity lives
        in, with ``a < b``. Charging Hoeffding for a wider range than the
        quantity has widens every threshold for nothing, which is why a
        two-qubit purity is given ``(0.25, 1.0)`` and not ``(0.0, 1.0)``.
    statistic : str
        Keyword-only. The field name the returned threshold is to be compared
        against, spelled as
        :class:`~sih141.detect.statistics.ResourceStatistics` spells it.
    quantity : str
        Keyword-only. The quantity's name, for the written-out null.
    tolerance : float, optional
        Keyword-only. How far below ``b`` a point-mass threshold sits, to
        absorb the floating-point dust of a four-by-four eigendecomposition.
        Defaults to :data:`~sih141.detect.statistics.IDEAL_TOLERANCE`.

    Returns
    -------
    ChannelThreshold
        With ``direction="lower"``.

    Raises
    ------
    TypeError
        If an argument has the wrong type.
    ValueError
        If ``span`` is not an ordered pair, ``honest_mean`` lies outside it,
        ``honest_mean`` sits on the bottom of the span -- where the point-mass
        argument would run the other way and a *lower* threshold is
        meaningless -- ``tolerance`` is not positive and finite, or ``samples``
        is negative.

    Notes
    -----
    The i.i.d. assumption is part of the null and is stated in the returned
    object: the rounds' resources are independent and identically distributed,
    which is true of any memoryless honest channel and false of one that
    drifts. A drifting honest channel needs a different null, not a wider
    threshold.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import bounded_mean_threshold
    >>> ideal = bounded_mean_threshold(
    ...     samples=48,
    ...     epsilon=1e-09,
    ...     honest_mean=1.0,
    ...     span=(0.0, 1.0),
    ...     statistic="min_fidelity",
    ...     quantity="fidelity",
    ... )
    >>> ideal.critical_value, ideal.false_positive_bound
    (0.999999999, 0.0)
    >>> noisy = bounded_mean_threshold(
    ...     samples=48,
    ...     epsilon=1e-09,
    ...     honest_mean=0.925,
    ...     span=(0.0, 1.0),
    ...     statistic="mean_fidelity",
    ...     quantity="fidelity",
    ... )
    >>> f"{noisy.critical_value:.6f}", noisy.inequality
    ('0.460385', 'Hoeffding (bounded means, one-sided)')
    """
    size = _as_sample_size(samples, "samples")
    budget = _as_epsilon(epsilon)
    if isinstance(span, (str, bytes)) or not isinstance(span, Sequence):
        raise TypeError(
            f"span must be a pair of floats, got {type(span).__name__}"
        )
    if len(span) != 2:
        raise ValueError(
            f"span must hold exactly two endpoints, got {len(span)}"
        )
    low, high = (float(span[0]), float(span[1]))
    if not (math.isfinite(low) and math.isfinite(high)) or not low < high:
        raise ValueError(
            f"span must be a finite ordered pair a < b, got ({low!r}, {high!r})"
        )
    if isinstance(honest_mean, bool) or not isinstance(
        honest_mean, (int, float)
    ):
        raise TypeError(
            f"honest_mean must be a real number, got "
            f"{type(honest_mean).__name__}"
        )
    mean = float(honest_mean)
    if not math.isfinite(mean) or not low <= mean <= high:
        raise ValueError(
            f"honest_mean must lie inside span [{low!r}, {high!r}], got "
            f"{mean!r}"
        )
    if mean == low:
        raise ValueError(
            f"honest_mean sits on the bottom of span ({low!r}), where the "
            f"quantity is already as low as it can go and a lower-tail "
            f"threshold detects nothing. A concurrence null of 0 is what a "
            f"separable honest resource looks like; there is no deviation "
            f"below it to bound."
        )
    if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)):
        raise TypeError(
            f"tolerance must be a real number, got {type(tolerance).__name__}"
        )
    slack = float(tolerance)
    if not math.isfinite(slack) or slack <= 0.0:
        raise ValueError(
            f"tolerance must be finite and positive, got {slack!r}. It absorbs "
            f"the floating-point dust of a 4x4 eigendecomposition; zero would "
            f"turn that dust into a false alarm."
        )

    if mean == high:
        return ChannelThreshold(
            statistic=statistic,
            direction="lower",
            critical_value=high - slack,
            epsilon=budget,
            false_positive_bound=0.0,
            null=(
                f"point mass at {high!r}: the honest {quantity} is bounded "
                f"above by {high!r} and has mean {high!r}, which forces every "
                f"round onto it"
            ),
            inequality="point mass (exact)",
            sample_size=size,
            derivation=(
                f"V <= {high!r} and E[V] = {high!r} give E[{high!r} - V] = 0 "
                f"with {high!r} - V >= 0, so V = {high!r} almost surely; the "
                f"mean and the minimum both sit on it and "
                f"P(V <= {high!r} - tol) = 0 exactly, at every eps"
            ),
            reaches_its_statistic=size >= 1,
        )

    span_width = high - low
    half_width = (
        span_width * math.sqrt(-math.log(budget) / (2.0 * size))
        if size
        else math.inf
    )
    if not math.isfinite(half_width):
        # No samples: the mean does not exist, so nothing can be compared to
        # it. The threshold is placed strictly *below* the range rather than on
        # its floor, so that it can never fire even on an observation sitting
        # exactly on that floor -- a concurrence of 0 is a real value, and a
        # placeholder threshold must not turn it into an alarm.
        return ChannelThreshold(
            statistic=statistic,
            direction="lower",
            critical_value=low - 1.0,
            epsilon=budget,
            false_positive_bound=0.0,
            null=(
                f"i.i.d. {quantity} in [{low!r}, {high!r}] with mean {mean!r}, "
                f"over 0 rounds -- no sample, so no statistic"
            ),
            inequality="Hoeffding (bounded means, one-sided)",
            sample_size=0,
            derivation=(
                "t(eps) = (b - a) sqrt(ln(1/eps) / (2n)) is unbounded at "
                "n = 0; the threshold is placed one unit below the range's "
                "floor, where no observation can reach it"
            ),
            reaches_its_statistic=False,
        )
    critical = mean - half_width
    return ChannelThreshold(
        statistic=statistic,
        direction="lower",
        critical_value=critical,
        epsilon=budget,
        # Exactly the budget: t(eps) is the value at which the inequality's
        # right-hand side equals eps, so the continuous inversion spends it
        # exactly and a re-evaluation would add round-trip noise, not
        # information.
        false_positive_bound=budget,
        null=(
            f"i.i.d. {quantity} in [{low!r}, {high!r}] with mean {mean!r}, "
            f"over {size} monitored rounds"
        ),
        inequality="Hoeffding (bounded means, one-sided)",
        sample_size=size,
        derivation=(
            "P(mean <= mu0 - t) <= exp(-2 n t^2 / (b - a)^2); "
            f"t = (b - a) sqrt(ln(1/eps) / (2n)) = {half_width!r}"
        ),
        reaches_its_statistic=critical >= low,
    )


def _resource_threshold(
    *,
    samples: int,
    epsilon: float,
    tolerance: float,
    honest: float,
    span: tuple[float, float],
    quantity: str,
) -> ChannelThreshold:
    """Build one resource threshold, naming the field it should be read from.

    Parameters
    ----------
    samples : int
        Monitored rounds on this link.
    epsilon : float
        The budget.
    tolerance : float
        Point-mass slack.
    honest : float
        The Werner mean at ``p0``, which is where the null is stated and is the
        only thing the derivation needs ``p0`` for.
    span : tuple of float
        The quantity's range.
    quantity : str
        ``"fidelity"``, ``"purity"`` or ``"concurrence"``.

    Returns
    -------
    ChannelThreshold
    """
    # Under a point-mass null the minimum is the sharper reading and carries
    # the same exactly-zero bound; under a Hoeffding null only the mean has a
    # law that follows from the stated mean alone.
    field = "min" if honest == span[1] else "mean"
    return bounded_mean_threshold(
        samples=samples,
        epsilon=epsilon,
        honest_mean=honest,
        span=span,
        statistic=f"{field}_{quantity}",
        quantity=quantity,
        tolerance=tolerance,
    )


def fidelity_threshold(
    *,
    samples: int,
    epsilon: float,
    tolerated_depolarising: float = 0.0,
    tolerance: float = IDEAL_TOLERANCE,
) -> ChannelThreshold:
    """Derive the fidelity below which one link's resource is called disturbed.

    **The member of the family that sees a unitary attack.** ``Tr(rho^2)`` is
    invariant under every unitary and concurrence under every *local* one, so a
    channel that merely rotates the travelling half leaves purity and
    concurrence at ``1.0`` exactly. Fidelity to :math:`|\\Phi^{+}\\rangle` is
    not a local-unitary invariant, and is what moves. That is a theorem about
    the quantities, not an observation about any adversary.

    Parameters
    ----------
    samples : int
        Keyword-only. Monitored check rounds on this link --
        :attr:`ResourceStatistics.samples
        <sih141.detect.statistics.ResourceStatistics>`.
    epsilon : float
        Keyword-only. The false-positive budget.
    tolerated_depolarising : float, optional
        Keyword-only. ``p0``; ``0`` gives the ideal point-mass null.
    tolerance : float, optional
        Keyword-only. Point-mass slack. Defaults to
        :data:`~sih141.detect.statistics.IDEAL_TOLERANCE`.

    Returns
    -------
    ChannelThreshold
        Named ``"min_fidelity"`` under the point-mass null and
        ``"mean_fidelity"`` otherwise, because only the mean has a law the
        stated mean implies.

    Raises
    ------
    TypeError
        If an argument has the wrong type.
    ValueError
        If an argument is out of range.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import fidelity_threshold
    >>> ideal = fidelity_threshold(samples=48, epsilon=1e-09)
    >>> ideal.statistic, ideal.false_positive_bound
    ('min_fidelity', 0.0)
    >>> noisy = fidelity_threshold(
    ...     samples=48, epsilon=1e-09, tolerated_depolarising=1 / 32
    ... )
    >>> noisy.statistic, f"{noisy.critical_value:.6f}"
    ('mean_fidelity', '0.511947')
    """
    return _resource_threshold(
        samples=samples,
        epsilon=epsilon,
        tolerance=tolerance,
        honest=werner_fidelity(tolerated_depolarising),
        span=FIDELITY_RANGE,
        quantity="fidelity",
    )


def purity_threshold(
    *,
    samples: int,
    epsilon: float,
    tolerated_depolarising: float = 0.0,
    tolerance: float = IDEAL_TOLERANCE,
) -> ChannelThreshold:
    """Derive the purity below which one link's resource is called disturbed.

    Separates a *mixing* attack from a *unitary* one: a rotated pair is still
    pure and still wrong, so this threshold is blind to the whole unitary class
    by construction and :func:`fidelity_threshold` is what covers it. The span
    charged to Hoeffding is ``[1/4, 1]``, because a two-qubit purity is bounded
    below by ``1/d`` and pretending it could reach zero would widen every
    threshold by a third for nothing.

    Parameters
    ----------
    samples : int
        Keyword-only. Monitored check rounds on this link.
    epsilon : float
        Keyword-only. The false-positive budget.
    tolerated_depolarising : float, optional
        Keyword-only. ``p0``; ``0`` gives the ideal point-mass null.
    tolerance : float, optional
        Keyword-only. Point-mass slack.

    Returns
    -------
    ChannelThreshold
        Named ``"min_purity"`` under the point-mass null and ``"mean_purity"``
        otherwise.

    Raises
    ------
    TypeError
        If an argument has the wrong type.
    ValueError
        If an argument is out of range.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import purity_threshold
    >>> ideal = purity_threshold(samples=48, epsilon=1e-09)
    >>> ideal.statistic, ideal.critical_value, ideal.false_positive_bound
    ('min_purity', 0.999999999, 0.0)
    >>> noisy = purity_threshold(
    ...     samples=48, epsilon=1e-09, tolerated_depolarising=0.1
    ... )
    >>> noisy.statistic, f"{noisy.critical_value:.6f}"
    ('mean_purity', '0.509039')

    The narrower span is worth a third of the half-width, and the difference is
    real rather than cosmetic:

    >>> from sih141.detect.thresholds_channel import bounded_mean_threshold
    >>> wide = bounded_mean_threshold(
    ...     samples=48,
    ...     epsilon=1e-09,
    ...     honest_mean=0.8575,
    ...     span=(0.0, 1.0),
    ...     statistic="mean_purity",
    ...     quantity="purity",
    ... )
    >>> f"{0.8575 - wide.critical_value:.6f}"
    '0.464615'
    >>> f"{0.8575 - noisy.critical_value:.6f}"
    '0.348461'
    """
    return _resource_threshold(
        samples=samples,
        epsilon=epsilon,
        tolerance=tolerance,
        honest=werner_purity(tolerated_depolarising),
        span=PURITY_RANGE,
        quantity="purity",
    )


def concurrence_threshold(
    *,
    samples: int,
    epsilon: float,
    tolerated_depolarising: float = 0.0,
    tolerance: float = IDEAL_TOLERANCE,
) -> ChannelThreshold:
    """Derive the concurrence below which one link's pair is called broken.

    The entanglement of the delivered pair, ``1`` on a Bell state and ``0`` on
    anything separable. Like purity it is a local-unitary invariant and so is
    blind to a rotation; unlike purity it collapses to ``0`` for an
    intercept-resend adversary, who hands the recipient a product state.

    Parameters
    ----------
    samples : int
        Keyword-only. Monitored check rounds on this link.
    epsilon : float
        Keyword-only. The false-positive budget.
    tolerated_depolarising : float, optional
        Keyword-only. ``p0``; ``0`` gives the ideal point-mass null. A Werner
        resource is separable from ``p0 = 2/3`` upward, where the honest null
        is concurrence ``0`` and this threshold refuses to be derived at all --
        there is no deviation below zero to bound.
    tolerance : float, optional
        Keyword-only. Point-mass slack.

    Returns
    -------
    ChannelThreshold
        Named ``"min_concurrence"`` under the point-mass null and
        ``"mean_concurrence"`` otherwise.

    Raises
    ------
    TypeError
        If an argument has the wrong type.
    ValueError
        If an argument is out of range, or if ``tolerated_depolarising`` is at
        or above ``2/3``, where the honest null is already zero.

    Examples
    --------
    >>> from sih141.detect.thresholds_channel import concurrence_threshold
    >>> ideal = concurrence_threshold(samples=48, epsilon=1e-09)
    >>> ideal.statistic, ideal.false_positive_bound
    ('min_concurrence', 0.0)
    >>> noisy = concurrence_threshold(
    ...     samples=48, epsilon=1e-09, tolerated_depolarising=0.1
    ... )
    >>> noisy.statistic, f"{noisy.critical_value:.6f}"
    ('mean_concurrence', '0.385385')

    A tolerated noise level that is already separable has no lower tail left:

    >>> concurrence_threshold(
    ...     samples=48, epsilon=1e-09, tolerated_depolarising=0.7
    ... )                                        # doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    ValueError: honest_mean sits on the bottom of span (0.0), where the...
    """
    return _resource_threshold(
        samples=samples,
        epsilon=epsilon,
        tolerance=tolerance,
        honest=werner_concurrence(tolerated_depolarising),
        span=CONCURRENCE_RANGE,
        quantity="concurrence",
    )


# --------------------------------------------------------------------------- #
# Applying the family to one link
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ChannelScreen:
    """The channel family applied to one link, with its union bound.

    What :func:`screen_link` returns. The three outcomes are kept in three
    separate places on purpose: a statistic that fired, a statistic that was
    evaluated and did not, and a statistic that could not be evaluated at all.
    Folding the third into the second is the channel-family form of the
    mistake Phase 3 named -- "we could not look" read as "we looked and it was
    fine" -- and it is the single most likely way for a Phase 5 table to report
    a detection that never happened.

    Attributes
    ----------
    party : Party
        Whose link.
    message_bit : int
        Which distribution.
    epsilon : float
        The budget for the **whole screen**, divided evenly over the thresholds
        actually evaluated.
    tolerated_depolarising : float
        The honest noise level every null was stated at.
    thresholds : mapping of str to ChannelThreshold
        Keyed by :attr:`ChannelThreshold.statistic`.
    observed : mapping of str to float
        The value each threshold was compared against.
    fired : tuple of str
        Which fired, sorted. Non-empty is the detection.
    cleared : tuple of str
        Which were evaluated and did not fire, sorted.
    unavailable : mapping of str to str
        Which of :data:`CHANNEL_STATISTICS` could not be evaluated, and why.
        **Never counted as cleared.**
    false_positive_bound : float
        The union bound: the sum over evaluated thresholds of the bounds their
        inequalities prove. At or below :attr:`epsilon`, and at the **noiseless
        null** far below it: four of the five members are point masses there
        whose bound is exactly zero, so the screen costs what CHSH alone costs.
        At a positive :attr:`tolerated_depolarising` none of them is degenerate
        and the sum approaches the budget.
    """

    party: Party
    message_bit: int
    epsilon: float
    tolerated_depolarising: float
    thresholds: Mapping[str, ChannelThreshold]
    observed: Mapping[str, float]
    fired: tuple[str, ...]
    cleared: tuple[str, ...]
    unavailable: Mapping[str, str]
    false_positive_bound: float

    @property
    def detected(self) -> bool:
        """bool: Whether any threshold fired."""
        return bool(self.fired)

    @property
    def evaluated(self) -> int:
        """int: How many thresholds were evaluated, the union bound's ``m``."""
        return len(self.thresholds)

    def summary(self) -> str:
        """Return a one-line account of the screen.

        Returns
        -------
        str
        """
        verdict = ",".join(self.fired) if self.fired else "nothing fired"
        return (
            f"{self.party}/{self.message_bit}: {verdict} "
            f"({self.evaluated} evaluated, {len(self.unavailable)} "
            f"unavailable, P(any fire | honest) <= "
            f"{self.false_positive_bound:.2e} at eps = {self.epsilon:.2e})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view.

        Returns
        -------
        dict
        """
        return {
            "party": str(self.party),
            "message_bit": self.message_bit,
            "epsilon": self.epsilon,
            "tolerated_depolarising": self.tolerated_depolarising,
            "thresholds": {
                name: threshold.to_dict()
                for name, threshold in self.thresholds.items()
            },
            "observed": dict(self.observed),
            "fired": list(self.fired),
            "cleared": list(self.cleared),
            "unavailable": dict(self.unavailable),
            "false_positive_bound": self.false_positive_bound,
            "detected": self.detected,
        }


def screen_link(
    link: LinkStatistics,
    *,
    epsilon: float,
    tolerated_depolarising: float = 0.0,
    tolerance: float = IDEAL_TOLERANCE,
    qber_method: str = "exact",
) -> ChannelScreen:
    """Apply the whole channel family to one link at one budget.

    ``epsilon`` is the budget for the **screen**, not for each member: it is
    divided evenly over the thresholds the transcript makes evaluable, and the
    union bound (:ref:`channel-union`) then holds the probability that anything
    fires on an honest run at or below ``epsilon``. The division is legitimate
    because, under the null, which statistics are evaluable is fixed by the
    check plan and the run's configuration rather than by the channel, and a
    bound that holds for every plan holds on average over plans.

    **A run has up to four links.** Two recipients times two message bits is
    four screens, and a run-level budget must be divided again before it
    reaches this function; :func:`divide_budget` does that division.

    Everything here is conditioned on (NO-TIMING) (:ref:`channel-no-timing`).

    Parameters
    ----------
    link : LinkStatistics
        One link's statistics, from a JSON-round-tripped transcript. Nothing
        else is read -- not the session, not the adversary, not any harness
        state.
    epsilon : float
        Keyword-only. The budget for the whole screen, inside ``(0, 1)``.
    tolerated_depolarising : float, optional
        Keyword-only. ``p0``, the honest channel's allowed depolarising
        strength, which fixes all five nulls at once. Defaults to ``0``, the
        noiseless claim.
    tolerance : float, optional
        Keyword-only. Point-mass slack for the resource summaries.
    qber_method : {'exact', 'chernoff', 'hoeffding'}, optional
        Keyword-only. Which inversion the QBER threshold uses.

    Returns
    -------
    ChannelScreen

    Raises
    ------
    TypeError
        If ``link`` is not a
        :class:`~sih141.detect.statistics.LinkStatistics`, or an argument has
        the wrong type.
    ValueError
        If an argument is out of range.

    Notes
    -----
    The CHSH **certificate** is deliberately not part of the screen. It is not
    an alarm, and a screen that read a missing certificate as a detection would
    publish a detection rate equal to its own sample-size problem; see
    :func:`chsh_certificate_threshold`.

    At ``tolerated_depolarising >= 2/3`` a Werner honest resource is separable,
    so the concurrence null is already ``0`` and has no lower tail. The screen
    records concurrence as **unavailable** rather than raising, and the
    decision is taken from the stated ``p0`` alone -- never from the
    observation -- so the budget split stays independent of the data, which is
    what makes the even division legitimate.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.detect.statistics import TranscriptStatistics
    >>> from sih141.detect.thresholds_channel import screen_link
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> stats = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=384, check_fraction=0.25),
    ...         rng=np.random.default_rng(7),
    ...     ).run(0)
    ... )
    >>> screen = screen_link(stats.link("Charlie", 1), epsilon=1e-09)
    >>> screen.detected, screen.evaluated, dict(screen.unavailable)
    (False, 5, {})
    >>> print(screen.summary())         # doctest: +NORMALIZE_WHITESPACE
    Charlie/1: nothing fired (5 evaluated, 0 unavailable,
    P(any fire | honest) <= 2.00e-10 at eps = 1.00e-09)

    A run with no check rounds makes the whole family unavailable, and the
    screen reports that rather than a clean channel:

    >>> plain = TranscriptStatistics.from_transcript(
    ...     QDSSession(
    ...         ProtocolParams(key_length=192), rng=np.random.default_rng(7)
    ...     ).run(0)
    ... )
    >>> plain.links
    {}
    """
    if not isinstance(link, LinkStatistics):
        raise TypeError(
            f"link must be a LinkStatistics, got {type(link).__name__}. The "
            f"detector reads a JSON-round-tripped transcript through "
            f"TranscriptStatistics and nothing else."
        )
    budget = _as_epsilon(epsilon)
    strength = _as_strength(tolerated_depolarising)

    unavailable: dict[str, str] = {}
    observed: dict[str, float] = {}

    # Which members are evaluable is decided here, in one pass, before any
    # budget is divided -- so the division cannot depend on the observations.
    # Under the honest null each of these three questions is answered by the
    # check plan and the run's configuration, never by the channel, which is
    # what makes conditioning on the answer legitimate.
    resource = link.resource
    chsh_counts = None if link.chsh is None else link.chsh.counts
    evaluable: list[tuple[str, float]] = []

    if link.errors.trials == 0:
        unavailable["qber_errors"] = "this link published no QBER check rounds"
    else:
        evaluable.append(("qber_errors", float(link.errors.count)))

    if link.chsh is None or chsh_counts is None:
        unavailable["chsh"] = (
            link.chsh_unavailable or "this link published no CHSH estimate"
        )
    else:
        evaluable.append(("chsh", float(link.chsh.statistic)))

    # Under a point-mass null the minimum is the sharper reading and carries
    # the same exactly-zero bound; under a Hoeffding null only the mean has a
    # law that follows from the stated mean alone.
    prefix = "min" if strength == 0.0 else "mean"
    separable = werner_concurrence(strength) == 0.0
    for quantity in ("fidelity", "purity", "concurrence"):
        value = getattr(resource, f"{prefix}_{quantity}")
        if resource.samples == 0 or value is None:
            unavailable[quantity] = (
                "this link's channel seam was never called, so it has no "
                "resource summary -- an unmonitored link is not a clean one"
            )
        elif quantity == "concurrence" and separable:
            # Decided from the stated noise level alone, never from the
            # observation, so the budget split stays independent of the data.
            unavailable[quantity] = (
                f"a Werner resource at the stated strength "
                f"{strength!r} is separable, so the honest null is already "
                f"zero and there is no lower tail to bound"
            )
        else:
            evaluable.append((quantity, float(value)))

    if not evaluable:
        return ChannelScreen(
            party=link.party,
            message_bit=link.message_bit,
            epsilon=budget,
            tolerated_depolarising=strength,
            thresholds={},
            observed={},
            fired=(),
            cleared=(),
            unavailable=dict(unavailable),
            false_positive_bound=0.0,
        )

    share = divide_budget(budget, len(evaluable))
    thresholds: dict[str, ChannelThreshold] = {}
    for name, value in evaluable:
        if name == "qber_errors":
            threshold = qber_threshold(
                rounds=link.errors.trials,
                epsilon=share,
                tolerated_depolarising=strength,
                method=qber_method,
            )
        elif name == "chsh" and chsh_counts is not None:
            threshold = chsh_threshold(
                counts=chsh_counts,
                epsilon=share,
                tolerated_depolarising=strength,
            )
        else:
            builder = {
                "fidelity": fidelity_threshold,
                "purity": purity_threshold,
                "concurrence": concurrence_threshold,
            }[name]
            threshold = builder(
                samples=resource.samples,
                epsilon=share,
                tolerated_depolarising=strength,
                tolerance=tolerance,
            )
        if not threshold.is_alarm:  # pragma: no cover - none of the five is
            raise ValueError(
                f"{threshold.statistic}: a screen evaluates alarms only. "
                f"Failing to satisfy a certificate is not a detection."
            )
        thresholds[threshold.statistic] = threshold
        observed[threshold.statistic] = value

    fired = tuple(
        sorted(
            name
            for name, threshold in thresholds.items()
            if threshold.fires(observed[name])
        )
    )
    cleared = tuple(sorted(set(thresholds) - set(fired)))
    return ChannelScreen(
        party=link.party,
        message_bit=link.message_bit,
        epsilon=budget,
        tolerated_depolarising=strength,
        thresholds=thresholds,
        observed=observed,
        fired=fired,
        cleared=cleared,
        unavailable=dict(unavailable),
        false_positive_bound=min(
            1.0,
            math.fsum(
                threshold.false_positive_bound
                for threshold in thresholds.values()
            ),
        ),
    )
