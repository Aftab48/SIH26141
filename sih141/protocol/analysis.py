"""Closed-form probabilities for the teleportation-based QDS scheme.

Analytic only. Nothing in this module samples, simulates or calls a quantum
backend: every number returned is a finite sum or an elementary expression in
``(L, |B|, s_a, s_v, p_e)``. That is deliberate. The simulator in
:mod:`sih141.protocol.distribute` and the closed forms here are two *independent*
descriptions of the same protocol, and ``tests/test_protocol_analysis.py``
cross-checks every formula below against a Monte-Carlo simulator rebuilt from the
specification inside the test file. If the two ever disagree, the formula is what
is wrong.

Notation, fixed once
--------------------
======================  =====================================================
``L``                   :attr:`~sih141.protocol.params.ProtocolParams.key_length`
``B``, ``n = |B|``      the basis alphabet, ``{X, Y, Z}`` and ``n = 3`` by default
``a_i``, ``v_i``        Alice's true basis and eigenvalue at position ``i``
``d_i``, ``w_i``        the *declared* basis and eigenvalue (the signature)
``c_i``, ``o_i``        recipient ``R``'s own basis draw and recorded outcome
``M_R``, ``m``          matched set ``{i : c_i == d_i}`` and its size ``|M_R|``
``e_R``                 mismatches inside ``M_R``; ``r_R = e_R / m``
``s``                   the party's threshold: ``s_a`` for Bob, ``s_v`` for Charlie
``p_e``                 per-matched-position error rate of an honest run
======================  =====================================================

All six of ``a_i``, ``v_i``, ``c_i`` for Bob, ``c_i`` for Charlie are drawn
independently and uniformly (``a_i, c_i`` over ``B``; ``v_i`` over ``{+1, -1}``),
independently across positions. Everything below is an application of that.

1. The matched set
------------------
Recipient ``R`` measures position ``i`` in a basis ``c_i`` drawn uniformly from
``B``, independently of Alice. Position ``i`` is *scored* exactly when
``c_i == d_i``, and since ``c_i`` is uniform and independent of ``d_i``,

.. code-block:: text

    p_match = P(c_i == d_i) = 1 / n = 1/3        for B = {X, Y, Z}

whatever ``d_i`` is -- honest or forged. Note what this does **not** depend on:
Alice's true basis ``a_i``, the eigenvalue, the channel, or anything an adversary
declares. The indicators are independent across positions, so

.. code-block:: text

    m = |M_R| ~ Binomial(L, 1/n)
    E[m]   = L / n              = L/3
    Var[m] = L * (1/n)(1 - 1/n) = 2L/9

See :func:`matched_statistics`. ``E[m] = L/3`` is why the useful length of a key
is a third of its nominal length, and why every bound below is exponential in
``m`` rather than in ``L``.

The empty matched set, and why it counts as "not accepted"
    ``m = 0`` happens with probability ``(1 - 1/n)**L`` and makes ``r_R = 0/0``.
    :func:`sih141.protocol.verify.verify` raises there rather than inventing a
    verdict. Every probability in this module therefore uses

    .. code-block:: text

        "accepted"  :=  (m >= 1)  and  (e_R / m <= s)

    i.e. an empty matched set is *not* an acceptance. This is not bookkeeping.
    Under the opposite convention a forger's optimal strategy would be to declare
    bases outside ``B`` entirely, force ``m = 0`` at every position and be
    accepted with probability 1. The convention here closes that door, and
    :func:`forgery_probability` is computed under it.

2. The honest rate
------------------
On a matched position of an honest, noiseless run the recipient measured in the
very basis the state is an eigenstate of, so the Born rule gives ``o_i = v_i =
w_i`` with probability 1. Hence ``e_R = 0`` and

.. code-block:: text

    r_R = 0     exactly, not approximately

on any noiseless honest run, for both verifiers, for every ``L``.

Let ``p_e`` be the probability that a matched position is nevertheless recorded
with the wrong sign -- imperfect Bell pairs, teleportation noise, detector error,
all folded into one number. Then ``e_R | m ~ Binomial(m, p_e)`` and

.. code-block:: text

    E[r_R | m] = p_e            for every m >= 1, hence E[r_R | m >= 1] = p_e
    Var[r_R]   = p_e (1 - p_e) * E[1/m | m >= 1]

The variance is written that way because ``r_R`` is a ratio with a random
denominator: the law of total variance gives ``E[Var(r|m)] + Var(E[r|m])`` and
the second term vanishes identically, since ``E[r|m]`` does not depend on ``m``.
``E[1/m | m >= 1]`` is a finite sum over the binomial pmf, evaluated exactly by
:func:`honest_statistics` -- not approximated by ``1/E[m]``, which is smaller by
Jensen.

A depolarising channel of strength ``p`` (``rho -> (1-p) rho + p I/2``) leaves a
Pauli eigenstate untouched with probability ``1 - p`` and randomises it
otherwise, and a randomised qubit gives the wrong sign half the time, so
``p_e = p/2`` (:func:`depolarising_error_rate`). That is the conversion behind
the ``s_a`` noise budget documented in :mod:`sih141.protocol.params`.

3. Forgery
----------
**Adversary model, stated before any number is computed.** A sloppy model here
silently invalidates everything downstream, so:

*Who.* Eve is an external forger. She is **not** Bob and **not** Charlie: she
never received a copy of the quantum public key and holds no measurement record.

*What she knows.* The protocol, :class:`~sih141.protocol.params.ProtocolParams`,
the message she wants signed, and all public classical traffic from Phase A --
which is exactly the two teleportation correction bits per qubit. Those bits are
useless to her: by the Phase 1 derivation each of the four Bell outcomes occurs
with probability exactly ``1/4`` *for any payload*, so the classical traffic is
statistically independent of ``(a_i, v_i)``. She has zero information about the
private key.

*What she controls.* Everything in the declaration: for each position she picks
``d_i`` and ``w_i`` freely, jointly across positions, adaptively, with unbounded
computation. This is the part that needs care, because **her choice of ``d_i``
decides which positions land in the matched set** -- the matched set is defined
against the *declared* bases, not against Alice's.

*What she does not control.* The verifier's basis draws ``c_i``. Those were made
privately at receipt time in Phase A, before any signature existed, and are never
published.

*Out of scope.* An adversary who touches the quantum channel (intercept-resend,
a tampered entanglement resource) is a Phase 3 attack on the *resource*, not a
declaration-only forger, and is analysed there.

*In scope, separately, and stronger.* A cheating **recipient** holds real
information about the key, is strictly stronger than Eve, and is the case that
binds ``s_v``. He gets his own section, 3b, and his own pair of functions
(:func:`recipient_forgery_probability`, :func:`recipient_forgery_bound`) --
not because his analysis is harder but because quoting Eve's number as "the
forgery probability" understates the real one by hundreds of orders of
magnitude, which is exactly what an earlier version of this module did.

**Derivation.** Fix a position ``i`` and any declaration ``(d_i, w_i)``.

*Step 1 -- she cannot steer the matched set.* ``c_i`` is uniform on ``B`` and
independent of everything Eve knows, so ``P(i in M_R) = 1/n`` for every choice of
``d_i``. She cannot bias the size of ``M_R``, nor which positions it contains.
So ``m ~ Binomial(L, 1/n)``, exactly as in the honest case. (Declaring a symbol
outside ``B`` only shrinks ``M_R``, and by the convention of section 1 an empty
matched set is not an acceptance, so that cannot help her either.)

*Step 2 -- conditioned on a matched position, the outcome is a fair coin.*
Condition on ``i in M_R``, i.e. ``c_i = d_i``. The conditioning event involves
only Eve's own declaration and the verifier's independent draw, so it says
nothing about ``(a_i, v_i)``, which remain uniform and independent. Two branches:

* ``a_i == c_i``, probability ``1/n``. The recipient measured in the preparation
  basis, so ``o_i = v_i`` -- and ``v_i`` is a uniform sign that Eve has no
  information about.
* ``a_i != c_i``, probability ``1 - 1/n``. The recipient measured a conjugate
  observable, so ``o_i`` is a fair coin by the Born rule.

In both branches ``o_i`` is uniform on ``{+1, -1}`` and independent of ``w_i``.
Therefore

.. code-block:: text

    P(o_i == w_i | i in M_R) = 1/2

independently across positions, whatever strategy produced the declaration.
Eve's per-matched-position survival probability is ``1/2`` and no declaration
strategy changes it -- the security here is information-theoretic, not
computational. See :data:`FORGER_MATCHED_MISMATCH_PROBABILITY`.

**The probability.** With ``e_E | m ~ Binomial(m, 1/2)`` and
``t(m) = max{e : e/m <= s}``,

.. code-block:: text

    P_forge(L, s) = sum_{m=1}^{L} C(L,m) (1/n)^m (1-1/n)^(L-m)
                                  * 2^-m * sum_{k=0}^{t(m)} C(m,k)

evaluated exactly by :func:`forgery_probability`. Conditioned on ``m``, Hoeffding
and the Chernoff/relative-entropy bound give

.. code-block:: text

    P(e_E/m <= s | m)  <=  exp(-2 m (1/2 - s)^2)          (Hoeffding)
                       <=  exp(-m D(s || 1/2))            (Chernoff-KL, tighter)

with ``D`` the binary relative entropy in nats (:func:`binary_kl_divergence`).
Averaging a bound of the form ``exp(-m c)`` over ``m ~ Binomial(L, 1/n)`` is
*exact*, because that average is a binomial probability generating function:

.. code-block:: text

    E[exp(-m c)] = (1 - 1/n + exp(-c)/n)^L = exp(-L * lambda),
    lambda = -ln(1 - (1 - exp(-c))/n) > 0

so the bound is exponential in ``L`` itself, not merely in ``m``
(:func:`forgery_bound`). For the shipped defaults ``s_v = 1/16``, ``n = 3``:
``D(1/16 || 1/2) = 0.4594`` nats, ``lambda = 0.1310``, and at ``L = 115200`` the
bound is ``e^-15091`` -- which is to say Eve is not the problem.

3b. Forgery by a recipient -- the case that binds
-------------------------------------------------
*Who.* Bob, who received a copy of the public key, measured it, took part in the
symmetrisation exchange, and now tries to get Charlie to accept a key Alice
never signed. Everything Eve knows, plus his own ``L`` measurement records, plus
the identity of the positions he himself supplied to Charlie.

*What he holds of Charlie's evidence.* After symmetrisation Charlie's record at
position ``i`` is Bob's own entry when the pair was swapped and Charlie's own
otherwise, each with probability ``1/2``, and Bob knows which. So:

* **Swapped** (probability ``1/2``): Bob declares the entry he supplied. Matched
  with probability ``1``, mismatch probability ``0``.
* **Retained** (probability ``1/2``): Bob declares his own record. Matched with
  probability ``1/n``; given a match, both measured the same observable on
  independent copies, so they agree outright when Bob's basis was Alice's
  (probability ``1/n``) and are independent fair coins otherwise -- mismatch
  probability ``(1 - 1/n)/2``.

Collecting, and writing ``p_s`` for the fraction of positions he gets scored:

.. code-block:: text

    p_s  = P(scored)            = (n + 1) / (2n)                = 2/3
    rho  = P(mismatch | scored) = (n - 1) / (2 n (n + 1))        = 1/12

``rho`` is :attr:`sih141.protocol.params.ProtocolParams.forger_floor`, and the
conditional structure is the same double binomial as Eve's with ``(1/n, 1/2)``
replaced by ``(p_s, rho)``: ``m ~ Bin(L, p_s)`` and ``e | m ~ Bin(m, rho)``,
because given "scored" the mismatch indicator is Bernoulli(``rho``) independently
across positions. Hence :func:`recipient_forgery_probability` and, by the same
generating-function average, :func:`recipient_forgery_bound`.

*Optimality.* ``rho`` is not merely the compliant rate; no measurement strategy
beats it. On a retained position Bob must guess Charlie's outcome in the
declared basis from his own copy. Let his POVM be ``{E_k}`` and his declaration
``(d_k, w_k)``; with ``g = P(d = a, w = v)`` and ``h = P(d = a, w != v)`` the
retained mismatch rate is ``(1 - (g - h))/2`` and

.. code-block:: text

    g - h = (1/6) sum_k Tr(E_k w_k sigma_{d_k})
          = (1/6) sum_k alpha_k (m_k . n_k)
          <= (1/6) sum_k alpha_k = (1/6) Tr(I) = 1/3

writing ``E_k = alpha_k (I + m_k . sigma)/2``. The octahedron POVM
``E_k = rho_k / 3`` attains it, tying with the compliant strategy. So ``1/3`` on
retained positions and ``1/12`` overall are floors over *all* strategies, and
:mod:`sih141.protocol.params` sets ``s_v`` below them by an amount chosen for the
exponent it buys rather than as insurance against an unquantified attack.

4. Repudiation
--------------
Alice repudiates when she gets Bob to accept a signature that Charlie will
reject: she can then deny having signed, and Bob cannot forward what he holds.

**Two different statements live here, and conflating them is how this module
previously went wrong.** One is the exact probability under a *particular*,
narrow family of Alice strategies; the other is an upper bound that holds
whatever Alice does. Only the second is a security guarantee.

*4a. The symmetric family, exactly.* Suppose Alice induces the **same**
per-matched-position mismatch probability ``q`` on both recipients' copies --
tilting the prepared Bloch vector away from the declared axis by the same angle
for each. Then the coins of the symmetrisation exchange are irrelevant (the two
copies have the same law), the two records are independent, and

.. code-block:: text

    m_B ~ Bin(L, 1/n),  e_B | m_B ~ Bin(m_B, q)
    m_C ~ Bin(L, 1/n),  e_C | m_C ~ Bin(m_C, q)      independent of Bob's
    P_rep(q) = P(r_B <= s_a) * P(r_C > s_v)

(:func:`repudiation_probability`, with an empty matched set counting as "not
accepted" on both sides, so ``m_B = 0`` contributes nothing and ``m_C = 0``
contributes to Charlie's rejection). At ``q = 0`` the expression is not zero but
``P(m_B >= 1) P(m_C = 0)`` -- the honest runs in which Charlie happens to hold no
evidence at all. That is a transferability failure rather than an attack, it is
of order ``(1 - 1/n)^L``, and section 5 counts it as an abort.

**This is not a supremum over Alice's strategies, and taking its maximum over
``q`` does not make it one.** Alice's actual freedom includes ``q_B != q_C``.
Sending Bob the eigenstate she declares and Charlie its orthogonal partner on a
fraction ``f`` of positions puts her at ``q_B = 0``, ``q_C = 1`` there, which is
outside the family entirely; against *unsymmetrised* records it repudiates with
probability ``1`` at every ``L``, exceeding anything 4a computes by an unbounded
margin. :func:`repudiation_probability` says so in its own docstring and points
here.

*4b. The guarantee, uniform over every Alice strategy.* This is what the
symmetrisation exchange (:mod:`sih141.protocol.symmetrise`) buys, and the
derivation deliberately assumes nothing about Alice at all.

Fix the two recipients' raw records -- whatever she prepared, however
asymmetric, adaptive or entangled. The only randomness left is the recipients'
private coins, one per position, each deciding which verifier scores which of
the two records. Two conservation facts follow immediately, because the coins
only *split* a fixed collection:

.. code-block:: text

    m_B + m_C = M     (total matched records)      coin-independent
    e_B + e_C = E     (total mismatched records)   coin-independent

Put ``s = (s_a + s_v)/2`` and ``W = e_B - s m_B``. By coin symmetry
``E[W] = (E - s M)/2``. Repudiation requires ``r_B <= s_a`` and ``r_C > s_v``,
i.e.

.. code-block:: text

    e_B - s m_B <= (s_a - s) m_B = -(gap/2) m_B
    e_C - s m_C >  (s_v - s) m_C = +(gap/2) m_C        [gap = s_v - s_a]

and adding, using ``(e_C - s m_C) = (E - s M) - W``, gives
``2W < (E - s M) - (gap/2) M``, that is

.. code-block:: text

    W  <  E[W] - (gap/4) M

``W`` is a sum of ``L`` independent two-point variables (one coin each). A
position where neither record is matched contributes the same value under both
coin outcomes, so its range is ``0``; every other position has range at most
``1``, and there are at most ``M`` of them. Hoeffding therefore gives

.. code-block:: text

    P(repudiation | records) <= exp(-2 ((gap/4) M)^2 / M)
                              = exp(-M gap^2 / 8)

conditional on the records, hence for **every** Alice strategy. The one case the
argument does not cover is ``m_C = 0``, where Charlie's "rejection" carries no
evidence; that is bounded separately by ``P(m_C = 0) = (1 - 1/n)^L``. Averaging
over ``M ~ Bin(2L, 1/n)`` -- the recipients' own basis draws, which Alice does
not control either -- is exact by the generating-function identity of section 3:

.. code-block:: text

    P_rep <= (1 - 1/n)^L + (1 - 1/n + exp(-gap^2/8)/n)^(2L)

which is :func:`repudiation_bound`. Note what is *not* in it: no ``q``, no
independence assumption about the two recipients, no model of Alice.

*The older in-model bound* -- split at the midpoint, apply Hoeffding to whichever
of the two verifiers must deviate, optionally sharpen to relative entropy --
survives as :func:`symmetric_repudiation_bound`, correctly labelled as valid
only within family 4a. It is retained because it is the right yardstick for
:func:`repudiation_probability`, not because it is a guarantee. Comparing the
two is instructive: 4b's exponent is ``gap^2/8`` per matched *record* against
4a's ``gap^2/2`` per matched *position* -- a factor of two once the two counts
are put on the same footing -- and that factor, together with the smaller usable
``gap``, is the whole cost of making the statement true.

5. Robustness
-------------
An honest run *aborts* at party ``R`` when ``R`` fails to accept a genuine
signature: ``r_R > s`` or the matched set is empty. With ``e_R | m ~ Bin(m,
p_e)``,

.. code-block:: text

    P_abort(R) = (1-1/n)^L + sum_{m>=1} P(m) * P(Bin(m, p_e) > t(m))

(:func:`honest_abort_probability`). Bob's threshold is the tighter one, so Bob
dominates. For ``p_e < s`` the conditional tail obeys

.. code-block:: text

    P(Bin(m,p_e) > s m | m) <= exp(-2 m (s - p_e)^2)      (Hoeffding)
                            <= exp(-m D(s || p_e))        (Chernoff-KL)

and the whole-run abort probability (either verifier aborting) follows from the
independence of the two records: ``P_B + P_C - P_B P_C`` exactly, or the union
bound ``P_B + P_C`` for the bounded version.

Where each bound is loose
-------------------------
Stated plainly, because a bound quoted without its slack is a number nobody can
argue with.

*Averaging over* ``m``
    Not a source of looseness at all. ``E[exp(-mc)] = (1 - 1/n + e^-c/n)^L`` is
    an identity, so :func:`forgery_bound` and friends give away nothing by
    treating ``m`` as random. The commonly seen alternative -- "assume ``m =
    L/3``" -- is not a bound in either direction, and is why ``matched=`` is an
    opt-in argument here rather than the default.

*Forgery, Hoeffding*
    The Bernoulli parameter is exactly ``1/2``, so Hoeffding's assumption of
    maximal variance is for once not the problem. What it still loses is the
    difference between a Gaussian-shaped exponent and the true large-deviation
    one: ``2(1/2 - s_v)^2 = 0.3828`` against ``D(s_v||1/2) = 0.4594``, about
    17% of the exponent, i.e. a factor of ``exp(0.0766 m)`` at the default
    ``m = 38400``. Enormous in ratio, irrelevant to any decision: both numbers
    are far below any threshold anyone cares about. Both bounds
    additionally drop the ``Theta(1/sqrt(m))`` prefactor of the true binomial
    tail, always in the safe direction.

*Repudiation,* ``exp(-M gap^2 / 8)``
    Loose in the constant, not in the structure. Hoeffding charges every coin
    the full range-``1`` variance, and the required deviation ``(gap/4) M``
    comes from *adding* the two verifiers' conditions when in any realisation
    only one of them has to be extreme; a sharper treatment would buy a factor
    of order two in the exponent. What it is *not* loose about is the adversary:
    the derivation conditions on the records and uses only the recipients'
    private coins, so there is no strategy class it fails to cover and no ``q``
    to maximise over.

    The in-model expression is much tighter and covers much less. At the shipped
    thresholds :func:`symmetric_repudiation_bound` has exponent
    ``min_q [D(s_a||q) + D(s_v||q)] = 0.01563`` per matched *position*, against
    ``gap^2/8 = 0.000275`` per matched *record* here -- a ratio of about ``28``
    once the two counts are put on the same footing (``M = 2m``). That ratio is
    the price of a statement that is true rather than merely tight, and it is
    paid in key length: ``L = 115200`` instead of ``6912``.

*Robustness, Hoeffding*
    This is where Hoeffding is genuinely bad. It charges every summand the
    variance ``1/4`` allowed by its range, while the actual variance is
    ``p_e(1 - p_e)``, which is tiny for a low-noise channel. At ``p_e = 0`` the
    true abort probability on ``m >= 1`` is exactly ``0`` while Hoeffding still
    reports ``exp(-2 m s^2)`` -- unbounded slack in ratio. ``D(s || p_e)``
    diverges as ``p_e -> 0`` and gets this right. **Use** ``method="kl"``
    **whenever** ``p_e`` **is small**, which is the whole operating regime of an
    honest run.

*All bounds*
    Are stated for a fixed per-position parameter identical across positions.
    Non-identical ``q_i`` are covered by the same Hoeffding inequality with the
    mean ``q``-bar; the exact functions assume identical parameters and say so.

Cost
----
The exact functions evaluate a double binomial sum and are ``O(L^2)`` in the
number of terms. Instant at :data:`~sih141.protocol.params.DEMO_PARAMS`; at
:data:`~sih141.protocol.params.DEFAULT_PARAMS` (``L = 115200``) measure about
7 seconds for :func:`forgery_probability` and
:func:`recipient_forgery_probability`, and about 150 seconds for
:func:`repudiation_probability`, whose rejection branch sums the *long* tail at
every matched count. **The bounds are O(1)** -- they are closed forms, not sums
-- so a sweep, a report table or a dashboard should quote
:func:`forgery_bound`, :func:`recipient_forgery_bound` and
:func:`repudiation_bound`, and reserve the exact functions for the short key
lengths where a cross-check against simulation is affordable. That is the
regime ``tests/test_protocol_analysis.py`` works in.

All summation is done in log space with a max-shifted exponential sum, so
probabilities far below ``1e-308`` underflow to ``0.0`` only at the final
exponentiation and never mid-sum.

Notes
-----
Determinism (D3)
    Nothing here consumes randomness. There is no ``rng`` argument to inject and
    no call site would have anywhere to thread one.
No machine learning (D4)
    Binomial sums, two elementary inequalities and one ternary search on a convex
    scalar function.
Qubit ordering (D2)
    No register is built here; positions are key indices ``0 .. L-1``.

References
----------
.. [1] D. Gottesman and I. Chuang, "Quantum Digital Signatures",
       arXiv:quant-ph/0105032 (2001).
.. [2] V. Dunjko, P. Wallden and E. Andersson, "Quantum Digital Signatures
       without Quantum Memory", Phys. Rev. Lett. 112, 040502 (2014).
.. [3] R. Amiri, P. Wallden, A. Kent and E. Andersson, "Secure Quantum
       Signatures Using Insecure Quantum Channels", Phys. Rev. A 93, 032325
       (2016).

See Also
--------
sih141.protocol.params.ProtocolParams : Where ``L``, ``s_a``, ``s_v`` come from.
sih141.protocol.verify.verify : The decision rule these formulas describe.
"""

from __future__ import annotations

import math
import numbers
from dataclasses import dataclass
from typing import Any, Final, Literal

import numpy as np

from sih141.protocol.params import Party, ProtocolParams, _as_party

__all__ = [
    "FORGER_MATCHED_MISMATCH_PROBABILITY",
    "BoundMethod",
    "MatchedStatistics",
    "HonestStatistics",
    "binary_kl_divergence",
    "hoeffding_exponent",
    "max_accepted_mismatches",
    "matched_statistics",
    "matched_count_distribution",
    "depolarising_error_rate",
    "honest_statistics",
    "forgery_probability",
    "forgery_bound",
    "recipient_forgery_probability",
    "recipient_forgery_bound",
    "repudiation_probability",
    "repudiation_bound",
    "symmetric_repudiation_bound",
    "honest_abort_probability",
    "honest_abort_bound",
]

BoundMethod = Literal["hoeffding", "kl"]
"""Which tail inequality a ``*_bound`` function should use.

``"hoeffding"``
    Exponent ``2 (a - b)**2``. The classical, distribution-free form, and the one
    quoted in :mod:`sih141.protocol.params`.
``"kl"``
    Exponent ``D(a || b)``, the binary relative entropy. Never weaker than
    Hoeffding (Pinsker's inequality) and much stronger when the two rates are far
    apart or the underlying probability is near ``0`` or ``1``.
"""

FORGER_MATCHED_MISMATCH_PROBABILITY: Final[float] = 0.5
"""Per-matched-position mismatch probability of an external forger, ``1/2``.

Derived in section 3 of the module docstring. An adversary with no information
about the private key faces a uniform outcome on every position she manages to
get scored, whatever basis and eigenvalue she declares, so she survives each
matched position with probability exactly ``1/2``.

Contrast :attr:`sih141.protocol.params.ProtocolParams.forger_floor`, which is
``(n - 1) / (2 n (n + 1)) = 1/12`` for the three-basis alphabet. That is a
*recipient* turned forger, who holds his own basis and outcome at every position
and supplied half of the other verifier's evidence during symmetrisation; he is
strictly stronger than Eve, he is the case that binds ``s_v``, and he is
computed by :func:`recipient_forgery_probability` -- not by
:func:`forgery_probability`, which models Eve alone.

Eve's rate *is* exactly ``1/2``, the rate of pure noise, because that is what
"no information" means; the recipient's ``1/12`` is far below it. (An earlier
version of this docstring said "both are below the ``1/2`` of pure noise",
which is wrong about Eve by definition.)
"""

_TERNARY_ITERATIONS: Final[int] = 400
"""Ternary-search steps used for the KL repudiation exponent.

The search interval shrinks by ``2/3`` per step, so 400 steps take
``s_v - s_a < 1`` below ``(2/3)**400 ~ 1e-70`` -- far under double precision, so
the returned exponent is the converged one and the count never has to be tuned.
"""


# --------------------------------------------------------------------------- #
# argument coercion
# --------------------------------------------------------------------------- #


def _as_params(params: Any, *, name: str = "params") -> ProtocolParams:
    """Check that ``params`` is a :class:`~sih141.protocol.params.ProtocolParams`.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set to validate.
    name : str, optional
        Argument name quoted in the error message.

    Returns
    -------
    ProtocolParams
        The same object.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`. It is not coerced from a
        mapping on purpose: every guarantee in this module rests on the
        ``s_a < s_v < 1/2`` validation that the class performs, and a duck-typed
        stand-in would skip it.
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"{name} must be a ProtocolParams, got {type(params).__name__}. "
            f"Build one with ProtocolParams(key_length=...) or "
            f"ProtocolParams.from_dict(...); the closed forms in this module are "
            f"only valid for a parameter set that passed its s_a < s_v < 1/2 "
            f"validation."
        )
    return params


def _as_probability(value: Any, name: str) -> float:
    """Coerce and range-check a probability in ``[0, 1]``.

    Parameters
    ----------
    value : float
        The candidate probability.
    name : str
        Argument name quoted in error messages.

    Returns
    -------
    float
        ``value`` as a plain float.

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not a real number.
    ValueError
        If ``value`` is not finite or lies outside ``[0, 1]``.
    """
    if isinstance(value, bool):
        raise TypeError(
            f"{name} must be a real number in [0, 1], got the boolean {value!r}"
        )
    if not isinstance(value, numbers.Real):
        raise TypeError(
            f"{name} must be a real number in [0, 1], got {type(value).__name__}"
        )
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(
            f"{name} must be a finite probability in [0, 1], got {result!r}"
        )
    if not 0.0 <= result <= 1.0:
        raise ValueError(
            f"{name} must lie in [0, 1], got {result!r}. It is a probability, "
            f"not a count or a rate difference."
        )
    return result


def _as_matched(matched: Any) -> int:
    """Coerce and check an explicit matched-set size.

    Parameters
    ----------
    matched : int
        The number of matched positions to condition on. Must be positive: with
        an empty matched set there is no rate and therefore no bound to state.

    Returns
    -------
    int
        ``matched`` as a plain int.

    Raises
    ------
    TypeError
        If ``matched`` is a boolean or not an integer.
    ValueError
        If ``matched`` is not positive.
    """
    if isinstance(matched, bool):
        raise TypeError(
            f"matched must be a positive integer, got the boolean {matched!r}"
        )
    if not isinstance(matched, numbers.Integral):
        raise TypeError(
            f"matched must be a positive integer, got {type(matched).__name__}; "
            f"it counts positions."
        )
    value = int(matched)
    if value < 1:
        raise ValueError(
            f"matched must be at least 1, got {value}. Conditioning on an empty "
            f"matched set states a bound on a decision that is never taken -- "
            f"verify() raises there. Pass matched=None to average over the "
            f"Binomial(L, 1/|B|) distribution of the matched-set size instead, "
            f"which handles m = 0 correctly."
        )
    return value


def _as_method(method: Any) -> BoundMethod:
    """Validate the ``method`` selector of a bound function.

    Parameters
    ----------
    method : str
        ``"hoeffding"`` or ``"kl"``.

    Returns
    -------
    str
        The validated selector.

    Raises
    ------
    ValueError
        If ``method`` names neither inequality.
    TypeError
        If ``method`` is not a string.
    """
    if not isinstance(method, str):
        raise TypeError(
            f"method must be the string 'hoeffding' or 'kl', got "
            f"{type(method).__name__}"
        )
    cleaned = method.strip().lower()
    if cleaned not in ("hoeffding", "kl"):
        raise ValueError(
            f"method must be 'hoeffding' (exponent 2(a-b)^2, the form quoted in "
            f"sih141.protocol.params) or 'kl' (exponent D(a||b), never weaker "
            f"and much tighter near 0 or 1), got {method!r}"
        )
    return cleaned  # type: ignore[return-value]


def _as_verifier(party: Party | str) -> Party:
    """Coerce a party argument and refuse Alice.

    Parameters
    ----------
    party : Party or str
        :attr:`~sih141.protocol.params.Party.BOB` or
        :attr:`~sih141.protocol.params.Party.CHARLIE`.

    Returns
    -------
    Party
        The resolved verifier.

    Raises
    ------
    ValueError
        If ``party`` is Alice, who has no threshold and reaches no verdict.
    """
    resolved = _as_party(party)
    if resolved is Party.ALICE:
        raise ValueError(
            "Alice is not a verifier: she signs, keeps no measurement record and "
            "has no acceptance threshold, so no acceptance or abort probability "
            "is defined for her. Ask for Party.BOB (threshold s_a) or "
            "Party.CHARLIE (threshold s_v)."
        )
    return resolved


# --------------------------------------------------------------------------- #
# elementary quantities
# --------------------------------------------------------------------------- #


def binary_kl_divergence(a: float, b: float) -> float:
    """Binary relative entropy ``D(a || b)`` in nats.

    ``D(a || b) = a ln(a/b) + (1-a) ln((1-a)/(1-b))``, the large-deviation rate
    function of a Bernoulli(``b``) sample mean at the value ``a``. Chernoff's
    bound reads ``P(Bin(m,b)/m >= a) <= exp(-m D(a||b))`` for ``a > b`` and
    ``P(Bin(m,b)/m <= a) <= exp(-m D(a||b))`` for ``a < b``.

    Parameters
    ----------
    a : float
        The observed rate, in ``[0, 1]``.
    b : float
        The underlying Bernoulli parameter, in ``[0, 1]``.

    Returns
    -------
    float
        The divergence in nats. Non-negative, zero exactly at ``a == b``, and
        ``inf`` when ``b`` is ``0`` or ``1`` and ``a`` differs from it -- that
        event is impossible, so the bound is ``exp(-inf) = 0``.

    Raises
    ------
    TypeError
        If either argument is a boolean or not a real number.
    ValueError
        If either argument is non-finite or outside ``[0, 1]``.

    See Also
    --------
    hoeffding_exponent : The weaker, distribution-free exponent.

    Examples
    --------
    >>> from sih141.protocol.analysis import binary_kl_divergence
    >>> round(binary_kl_divergence(1 / 6, 1 / 2), 6)
    0.242586
    >>> binary_kl_divergence(0.25, 0.25)
    0.0
    """
    rate = _as_probability(a, "a")
    reference = _as_probability(b, "b")
    if rate == reference:
        return 0.0
    if reference == 0.0 or reference == 1.0:
        return math.inf
    total = 0.0
    if rate > 0.0:
        total += rate * math.log(rate / reference)
    if rate < 1.0:
        total += (1.0 - rate) * math.log((1.0 - rate) / (1.0 - reference))
    return max(total, 0.0)


def hoeffding_exponent(a: float, b: float) -> float:
    """Hoeffding's per-sample exponent ``2 (a - b)**2``, in nats.

    The distribution-free exponent: ``P(Bin(m,b)/m - b >= d) <= exp(-2 m d^2)``
    for any ``b``. Pinsker's inequality says ``2(a-b)^2 <= D(a||b)``, so this is
    never the better of the two -- it is kept because it is the form the project's
    documented figures are quoted in and because it needs no case analysis at the
    endpoints.

    Parameters
    ----------
    a : float
        The observed rate, in ``[0, 1]``.
    b : float
        The underlying Bernoulli parameter, in ``[0, 1]``.

    Returns
    -------
    float
        ``2 (a - b)**2``, always finite.

    Raises
    ------
    TypeError
        If either argument is a boolean or not a real number.
    ValueError
        If either argument is non-finite or outside ``[0, 1]``.

    Examples
    --------
    >>> from sih141.protocol.analysis import hoeffding_exponent
    >>> round(hoeffding_exponent(1 / 6, 1 / 2), 6)
    0.222222
    """
    rate = _as_probability(a, "a")
    reference = _as_probability(b, "b")
    return 2.0 * (rate - reference) ** 2


def _exponent(a: float, b: float, method: BoundMethod) -> float:
    """Return the per-matched-position exponent selected by ``method``."""
    if method == "kl":
        return binary_kl_divergence(a, b)
    return hoeffding_exponent(a, b)


def max_accepted_mismatches(matched: int, threshold: float) -> int:
    """Largest mismatch count that still passes a threshold, ``t(m)``.

    The acceptance rule :func:`sih141.protocol.verify.verify` applies is
    ``e / m <= s`` evaluated in IEEE double precision, so ``t(m)`` is *defined*
    as the largest ``e`` for which that floating-point comparison holds, and the
    implementation seeds with ``int(threshold * m)`` and then normalises with two
    single-step loops until the definition is met exactly.

    The normalisation is what makes the two agree by construction rather than by
    luck, and the trap it guards against is real: the natural "be exact about it"
    move is ``floor(Fraction(threshold) * m)``, which computes the floor of the
    *rational* value of the float and disagrees with the rule the verifier
    actually runs. At ``m = 6``, ``threshold = 1/6`` the rational product is
    ``0.99999999999999998...`` so that form returns ``0``, while the protocol
    accepts ``e = 1`` because ``1 / 6 <= 1 / 6`` is ``True`` in floats. It
    disagrees at every multiple of 6, and analogously for other thresholds.

    Parameters
    ----------
    matched : int
        ``m``, the size of the matched set. Must be at least ``1``.
    threshold : float
        The party's cut, in ``[0, 1]``.

    Returns
    -------
    int
        ``t(m)`` in ``[0, m]``. Always at least ``0``, since ``0 / m == 0.0``
        passes any non-negative threshold.

    Raises
    ------
    TypeError
        If ``matched`` is not an integer or ``threshold`` is not a real number.
    ValueError
        If ``matched`` is not positive or ``threshold`` is outside ``[0, 1]``.

    Examples
    --------
    >>> from sih141.protocol.analysis import max_accepted_mismatches
    >>> max_accepted_mismatches(6, 1 / 6)
    1
    >>> max_accepted_mismatches(60, 1 / 6)
    10
    >>> max_accepted_mismatches(5, 0.0)
    0
    """
    count = _as_matched(matched)
    cut = _as_probability(threshold, "threshold")
    limit = int(cut * count)
    limit = min(max(limit, 0), count)
    while limit < count and (limit + 1) / count <= cut:
        limit += 1
    while limit > 0 and limit / count > cut:
        limit -= 1
    return limit


def depolarising_error_rate(depolarising_parameter: float) -> float:
    """Matched-position error rate induced by a depolarising channel.

    A depolarising channel ``rho -> (1 - p) rho + p I/2`` leaves the state alone
    with probability ``1 - p`` and replaces it by the maximally mixed state
    otherwise. On a matched position the undisturbed branch reproduces the
    declared eigenvalue with certainty and the randomised branch is a fair coin,
    so ``p_e = p / 2``.

    This is the conversion behind :data:`sih141.protocol.params.DEFAULT_S_A`: at
    ``s_a = 1/64`` an honest run survives up to ``p = 1/32`` of depolarising
    noise in the entanglement resource.

    Parameters
    ----------
    depolarising_parameter : float
        ``p``, in ``[0, 1]``.

    Returns
    -------
    float
        ``p / 2``, the per-matched-position probability of recording the wrong
        sign.

    Raises
    ------
    TypeError
        If the argument is a boolean or not a real number.
    ValueError
        If the argument is non-finite or outside ``[0, 1]``.

    Examples
    --------
    >>> from sih141.protocol.analysis import depolarising_error_rate
    >>> depolarising_error_rate(0.0625)
    0.03125
    """
    return _as_probability(depolarising_parameter, "depolarising_parameter") / 2.0


# --------------------------------------------------------------------------- #
# 1. the matched set
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MatchedStatistics:
    """Exact moments of the matched-set size ``|M_R|``.

    Frozen and made only of ``int``/``float``, so it serialises with
    :func:`json.dumps` and can key a Phase 5 sweep.

    Attributes
    ----------
    key_length : int
        ``L``.
    match_probability : float
        ``1 / |B|`` -- the probability that a recipient's basis draw agrees with
        the declared basis at a given position, honest or forged alike.
    expected : float
        ``E[|M_R|] = L / |B|``.
    variance : float
        ``Var[|M_R|] = L (1/|B|)(1 - 1/|B|)``.
    empty_probability : float
        ``P(|M_R| = 0) = (1 - 1/|B|)**L``, the probability that verification has
        no evidence at all and :func:`sih141.protocol.verify.verify` raises.

    See Also
    --------
    matched_statistics : Builds one from a parameter set.

    Examples
    --------
    >>> from sih141.protocol.analysis import matched_statistics
    >>> from sih141.protocol.params import ProtocolParams
    >>> stats = matched_statistics(ProtocolParams(key_length=9))
    >>> stats.expected, round(stats.variance, 6)
    (3.0, 2.0)
    """

    key_length: int
    match_probability: float
    expected: float
    variance: float
    empty_probability: float

    @property
    def standard_deviation(self) -> float:
        """float: ``sqrt(Var[|M_R|])``.

        The natural scale for "how much does the evidence base wobble between
        runs". At the default ``L = 115200`` it is about ``160`` positions
        against a mean of ``38400``, i.e. under 0.5%.
        """
        return math.sqrt(self.variance)

    @property
    def relative_standard_deviation(self) -> float:
        """float: ``sqrt(Var) / E``, the coefficient of variation of ``|M_R|``.

        Falls as ``1 / sqrt(L)``, which is why the bounds may be stated in terms
        of ``E[|M_R|]`` without much loss once ``L`` is large -- and why they are
        nevertheless averaged over ``m`` here, since averaging is free.
        """
        return math.sqrt(self.variance) / self.expected


def matched_statistics(params: ProtocolParams) -> MatchedStatistics:
    """Return the exact distributional summary of the matched-set size.

    Both Alice and each recipient draw bases uniformly and independently from
    ``params.bases``, so a position is scored with probability ``1/|B|`` and the
    indicators are independent across positions: ``|M_R| ~ Binomial(L, 1/|B|)``.
    Section 1 of the module docstring derives it, including the fact that the
    same distribution holds against a *forged* declaration.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.

    Returns
    -------
    MatchedStatistics
        Match probability, mean, variance and the empty-set probability.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`.

    See Also
    --------
    matched_count_distribution : The full pmf rather than its moments.

    Examples
    --------
    >>> from sih141.protocol.analysis import matched_statistics
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> matched_statistics(DEFAULT_PARAMS).expected
    38400.0
    """
    checked = _as_params(params)
    probability = checked.match_probability
    length = checked.key_length
    return MatchedStatistics(
        key_length=length,
        match_probability=probability,
        expected=length * probability,
        variance=length * probability * (1.0 - probability),
        empty_probability=math.exp(length * math.log1p(-probability)),
    )


def matched_count_distribution(params: ProtocolParams) -> np.ndarray:
    """Return the full pmf of ``|M_R|`` as an array of length ``L + 1``.

    Entry ``m`` is ``C(L, m) (1/|B|)^m (1 - 1/|B|)^(L-m)``. Computed in log space
    from exact log-factorials, so the tail entries are accurate rather than
    catastrophically cancelled.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.

    Returns
    -------
    numpy.ndarray
        A float array of shape ``(L + 1,)`` summing to ``1`` to within a few
        machine epsilons.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.analysis import matched_count_distribution
    >>> from sih141.protocol.params import ProtocolParams
    >>> pmf = matched_count_distribution(ProtocolParams(key_length=3))
    >>> np.round(pmf, 6)
    array([0.296296, 0.444444, 0.222222, 0.037037])
    """
    checked = _as_params(params)
    log_factorial = _log_factorial_table(checked.key_length)
    return np.exp(
        _log_binomial_pmf_table(
            checked.key_length, checked.match_probability, log_factorial
        )
    )


# --------------------------------------------------------------------------- #
# 2. the honest rate
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HonestStatistics:
    """Exact moments of an honest verifier's mismatch rate ``r_R``.

    Attributes
    ----------
    key_length : int
        ``L``.
    error_rate : float
        ``p_e``, the per-matched-position probability of recording the wrong
        sign. ``0`` for a noiseless run.
    expected_rate : float
        ``E[r_R | |M_R| >= 1] = p_e``. Exactly ``p_e`` for *every* value of the
        matched count, so the conditional mean does not depend on ``m`` and the
        unconditional (conditioned only on a non-empty matched set) mean is the
        same number.
    rate_variance : float
        ``Var[r_R | |M_R| >= 1] = p_e (1 - p_e) E[1/|M_R|]``, with the
        expectation taken over the conditional binomial. Exact, not a
        ``1/E[m]`` approximation.
    expected_reciprocal_matched : float
        ``E[1/|M_R|  |  |M_R| >= 1]``, evaluated as a finite sum over the pmf.
        Strictly greater than ``1/E[|M_R|]`` by Jensen, which is why the naive
        substitution understates the variance.
    empty_probability : float
        ``P(|M_R| = 0)``; the conditioning event's complement.

    See Also
    --------
    honest_statistics : Builds one from a parameter set and an error rate.

    Examples
    --------
    >>> from sih141.protocol.analysis import honest_statistics
    >>> from sih141.protocol.params import DEMO_PARAMS
    >>> honest_statistics(DEMO_PARAMS).expected_rate
    0.0
    """

    key_length: int
    error_rate: float
    expected_rate: float
    rate_variance: float
    expected_reciprocal_matched: float
    empty_probability: float

    @property
    def rate_standard_deviation(self) -> float:
        """float: ``sqrt(Var[r_R])``, the run-to-run spread of the honest rate.

        The quantity to compare against ``s_a``: an honest run is comfortable
        when ``s_a - p_e`` is several of these.
        """
        return math.sqrt(self.rate_variance)


def honest_statistics(
    params: ProtocolParams, *, error_rate: float = 0.0
) -> HonestStatistics:
    """Return the exact mean and variance of the honest mismatch rate.

    On a matched position of a noiseless honest run the recipient measured in the
    preparation basis, so the outcome equals the declared eigenvalue with
    certainty and ``r_R = 0`` exactly. With a per-matched-position error rate
    ``p_e``, ``e_R | m ~ Binomial(m, p_e)`` and section 2 of the module docstring
    gives ``E[r_R] = p_e`` and ``Var[r_R] = p_e (1 - p_e) E[1/m]``, the
    expectation being over ``m ~ Binomial(L, 1/|B|)`` conditioned on ``m >= 1``.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    error_rate : float, optional
        ``p_e`` in ``[0, 1]``. Defaults to ``0.0``, the noiseless case. Convert
        from a depolarising strength with :func:`depolarising_error_rate`.

    Returns
    -------
    HonestStatistics
        Mean, variance and the supporting quantities.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, or ``error_rate`` is not
        a real number.
    ValueError
        If ``error_rate`` is outside ``[0, 1]``.

    Notes
    -----
    ``error_rate`` is assumed identical across positions. Position-dependent
    ``p_i`` change the variance (a sum of independent non-identical Bernoullis
    has variance ``sum p_i(1-p_i)``, which is smaller at fixed mean) but leave
    the mean at ``p``-bar.

    Examples
    --------
    >>> from sih141.protocol.analysis import honest_statistics
    >>> from sih141.protocol.params import DEMO_PARAMS
    >>> stats = honest_statistics(DEMO_PARAMS, error_rate=0.02)
    >>> stats.expected_rate
    0.02
    >>> round(stats.rate_standard_deviation, 5)
    0.01759
    """
    checked = _as_params(params)
    rate = _as_probability(error_rate, "error_rate")

    pmf = matched_count_distribution(checked)
    empty = float(pmf[0])
    survivors = pmf[1:]
    counts = np.arange(1, checked.key_length + 1, dtype=float)
    non_empty_mass = float(survivors.sum())
    reciprocal = float((survivors / counts).sum()) / non_empty_mass

    return HonestStatistics(
        key_length=checked.key_length,
        error_rate=rate,
        expected_rate=rate,
        rate_variance=rate * (1.0 - rate) * reciprocal,
        expected_reciprocal_matched=reciprocal,
        empty_probability=empty,
    )


# --------------------------------------------------------------------------- #
# exact tail machinery, shared by sections 3, 4 and 5
# --------------------------------------------------------------------------- #


def _log_factorial_table(n: int) -> np.ndarray:
    """Return ``[ln 0!, ln 1!, ..., ln n!]`` as a float array."""
    return np.array([math.lgamma(k + 1.0) for k in range(n + 1)], dtype=float)


def _log_binomial_pmf_table(
    trials: int, probability: float, log_factorial: np.ndarray
) -> np.ndarray:
    """Return ``[ln P(X = k)]`` for ``X ~ Binomial(trials, probability)``."""
    counts = np.arange(trials + 1)
    if probability == 0.0:
        table = np.full(trials + 1, -np.inf)
        table[0] = 0.0
        return table
    if probability == 1.0:
        table = np.full(trials + 1, -np.inf)
        table[trials] = 0.0
        return table
    return (
        log_factorial[trials]
        - log_factorial[counts]
        - log_factorial[trials - counts]
        + counts * math.log(probability)
        + (trials - counts) * math.log1p(-probability)
    )


def _logsumexp(values: np.ndarray) -> float:
    """Return ``ln sum exp(values)``, ignoring ``-inf`` entries safely."""
    finite = values[np.isfinite(values)]
    if finite.size == 0:
        return -math.inf
    largest = float(finite.max())
    return largest + float(np.log(np.exp(finite - largest).sum()))


def _log_conditional_tail(
    matched: int,
    mismatch_probability: float,
    limit: int,
    *,
    upper: bool,
    log_factorial: np.ndarray,
) -> float:
    """Log of ``P(Bin(matched, q) > limit)`` or ``P(Bin(matched, q) <= limit)``.

    Parameters
    ----------
    matched : int
        ``m``, at least 1.
    mismatch_probability : float
        ``q`` in ``[0, 1]``.
    limit : int
        ``t(m)``, from :func:`max_accepted_mismatches`.
    upper : bool
        ``True`` for the strict upper tail (rejection), ``False`` for the lower
        tail including ``limit`` (acceptance).
    log_factorial : numpy.ndarray
        Table from :func:`_log_factorial_table`, at least ``matched + 1`` long.

    Returns
    -------
    float
        The natural log of the tail probability, possibly ``-inf``.
    """
    if upper:
        low, high = limit + 1, matched
    else:
        low, high = 0, limit
    if low > high:
        return -math.inf
    if mismatch_probability == 0.0:
        return 0.0 if low == 0 else -math.inf
    if mismatch_probability == 1.0:
        return 0.0 if high == matched else -math.inf

    counts = np.arange(low, high + 1)
    log_terms = (
        log_factorial[matched]
        - log_factorial[counts]
        - log_factorial[matched - counts]
        + counts * math.log(mismatch_probability)
        + (matched - counts) * math.log1p(-mismatch_probability)
    )
    return _logsumexp(log_terms)


def _log_decision_probability(
    key_length: int,
    match_probability: float,
    mismatch_probability: float,
    threshold: float,
    *,
    accept: bool,
) -> float:
    """Log-probability that a verifier accepts (or fails to accept) a declaration.

    Averages the conditional binomial tail over ``m ~ Binomial(L, p_match)``.
    "Accepted" means ``m >= 1 and e/m <= threshold``; the ``m = 0`` term
    therefore contributes to the *non*-acceptance branch only, which is the
    convention derived in section 1 of the module docstring.

    Parameters
    ----------
    key_length : int
        ``L``.
    match_probability : float
        ``1/|B|``.
    mismatch_probability : float
        ``q``, the per-matched-position probability of disagreeing with the
        declaration.
    threshold : float
        The party's cut.
    accept : bool
        ``True`` for ``P(accepted)``, ``False`` for ``P(not accepted)``.

    Returns
    -------
    float
        Natural log of the probability, possibly ``-inf``.
    """
    log_factorial = _log_factorial_table(key_length)
    log_pmf = _log_binomial_pmf_table(key_length, match_probability, log_factorial)

    terms = np.full(key_length + 1, -np.inf)
    if not accept:
        terms[0] = log_pmf[0]
    for matched in range(1, key_length + 1):
        weight = float(log_pmf[matched])
        if not math.isfinite(weight):
            continue
        limit = max_accepted_mismatches(matched, threshold)
        terms[matched] = weight + _log_conditional_tail(
            matched,
            mismatch_probability,
            limit,
            upper=not accept,
            log_factorial=log_factorial,
        )
    return _logsumexp(terms)


def _averaged_exponential_bound(
    key_length: int, match_probability: float, exponent: float
) -> float:
    """Average ``exp(-m * exponent)`` over ``m ~ Binomial(key_length, p)``.

    This is the binomial probability generating function evaluated at
    ``exp(-exponent)`` and is an *exact* average of the conditional bound, so it
    converts a bound exponential in ``m`` into one exponential in ``L`` for free:

    .. code-block:: text

        E[exp(-m c)] = (1 - p + p e^-c)^L

    Parameters
    ----------
    key_length : int
        ``L``.
    match_probability : float
        ``p = 1/|B|``.
    exponent : float
        ``c >= 0``, the per-matched-position exponent. ``inf`` is allowed and
        yields ``(1 - p)**L``, i.e. only the ``m = 0`` term survives.

    Returns
    -------
    float
        The averaged bound, clipped into ``[0, 1]``.
    """
    if exponent <= 0.0:
        return 1.0
    factor = 1.0 - match_probability + match_probability * math.exp(-exponent)
    if factor <= 0.0:
        return 0.0
    if factor >= 1.0:
        return 1.0
    return min(1.0, math.exp(key_length * math.log(factor)))


def _conditional_or_averaged(
    key_length: int,
    match_probability: float,
    exponent: float,
    matched: int | None,
) -> float:
    """Return ``exp(-matched * exponent)`` or its binomial average over ``m``."""
    if matched is None:
        return _averaged_exponential_bound(key_length, match_probability, exponent)
    if exponent <= 0.0:
        return 1.0
    if math.isinf(exponent):
        return 0.0
    return min(1.0, math.exp(-matched * exponent))


# --------------------------------------------------------------------------- #
# 3. forgery
# --------------------------------------------------------------------------- #


def forgery_probability(
    params: ProtocolParams, *, party: Party | str = Party.CHARLIE
) -> float:
    """Exact probability that an external forger's declaration is accepted.

    The adversary model is stated in full in section 3 of the module docstring
    and is not negotiable for this number to mean anything: Eve holds *no*
    information about the private key, declares both the basis and the
    eigenvalue at every position with unbounded computation, and does not control
    the verifier's basis draws. Under that model her per-matched-position
    survival probability is exactly ``1/2``
    (:data:`FORGER_MATCHED_MISMATCH_PROBABILITY`) regardless of strategy, and her
    declared bases cannot bias the matched set, so

    .. code-block:: text

        P_forge = sum_{m>=1} P(Bin(L, 1/|B|) = m) * P(Bin(m, 1/2) <= t(m))

    with ``t(m) = max_accepted_mismatches(m, threshold)``. An empty matched set
    is not an acceptance.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    party : Party or str, optional
        The verifier being targeted. Defaults to
        :attr:`~sih141.protocol.params.Party.CHARLIE`, whose threshold ``s_v`` is
        the looser of the two and therefore the easier target for this
        adversary. Pass ``Party.BOB`` for the ``s_a`` variant.

    Returns
    -------
    float
        The acceptance probability, in ``[0, 1]``. Decays exponentially in ``L``;
        underflows to ``0.0`` below about ``1e-308``, in which case use
        :func:`forgery_bound`, which stays meaningful in log space.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`.
    ValueError
        If ``party`` is Alice or names no party.

    See Also
    --------
    forgery_bound : The closed-form exponential upper bound.
    recipient_forgery_probability : The stronger, binding adversary.

    Notes
    -----
    **This is the weakest adversary in the model, and it is not the number a
    security claim should quote.** Eve holds nothing; a recipient holds his own
    measurement record and, after symmetrisation, half of the other verifier's
    evidence. The recipient's per-scored-position mismatch rate is ``1/12``
    against Eve's ``1/2``, and at :data:`~sih141.protocol.params.DEFAULT_PARAMS`
    the two acceptance bounds are ``1e-103`` and ``e^-10800`` -- a difference of
    thousands of orders of magnitude. Quote
    :func:`recipient_forgery_probability`, or both; this function is here to
    show what the *outside* adversary faces and to make the gap between the two
    visible rather than implicit.

    Cost is ``O(L^2)`` summands: instantaneous at
    :data:`~sih141.protocol.params.DEMO_PARAMS`, about 7 seconds at
    :data:`~sih141.protocol.params.DEFAULT_PARAMS`. :func:`forgery_bound` is
    a closed form and is free; prefer it for sweeps and report tables.

    Examples
    --------
    >>> from sih141.protocol.analysis import forgery_probability
    >>> from sih141.protocol.params import ProtocolParams
    >>> round(forgery_probability(ProtocolParams(key_length=30)), 6)
    0.004211
    """
    checked = _as_params(params)
    threshold = checked.threshold_for(_as_verifier(party))
    return math.exp(
        _log_decision_probability(
            checked.key_length,
            checked.match_probability,
            FORGER_MATCHED_MISMATCH_PROBABILITY,
            threshold,
            accept=True,
        )
    )


def forgery_bound(
    params: ProtocolParams,
    *,
    party: Party | str = Party.CHARLIE,
    method: BoundMethod = "hoeffding",
    matched: int | None = None,
) -> float:
    """Closed-form upper bound on :func:`forgery_probability`.

    Conditioned on ``m`` matched positions the forger needs ``Bin(m, 1/2)`` to
    land at or below ``s m``, so

    .. code-block:: text

        P <= exp(-2 m (1/2 - s)^2)      method="hoeffding"
        P <= exp(-m D(s || 1/2))        method="kl"

    Averaging over ``m ~ Binomial(L, 1/|B|)`` is exact -- see
    :func:`_averaged_exponential_bound` -- giving a bound exponential in ``L``.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    party : Party or str, optional
        The targeted verifier; defaults to
        :attr:`~sih141.protocol.params.Party.CHARLIE`.
    method : {'hoeffding', 'kl'}, optional
        Which exponent to use. ``"kl"`` is never weaker; the default is
        ``"hoeffding"`` so the module reproduces the figures documented in
        :mod:`sih141.protocol.params`.
    matched : int or None, optional
        If given, condition on exactly this many matched positions and return the
        conditional bound. If ``None`` (the default), average over the matched
        count, which is exact and is the honest thing to report for a run whose
        ``m`` is not yet known.

    Returns
    -------
    float
        An upper bound in ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, ``matched`` is not an
        integer, or ``method`` is not a string.
    ValueError
        If ``party`` is Alice, ``matched`` is not positive, or ``method`` names
        neither inequality.

    Examples
    --------
    >>> from sih141.protocol.analysis import forgery_bound, forgery_probability
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=30)
    >>> forgery_probability(params) <= forgery_bound(params, method="kl")
    True
    >>> forgery_bound(params, method="kl") <= forgery_bound(params)
    True
    """
    checked = _as_params(params)
    selected = _as_method(method)
    threshold = checked.threshold_for(_as_verifier(party))
    limit = None if matched is None else _as_matched(matched)
    if threshold >= FORGER_MATCHED_MISMATCH_PROBABILITY:
        return 1.0
    exponent = _exponent(threshold, FORGER_MATCHED_MISMATCH_PROBABILITY, selected)
    return _conditional_or_averaged(
        checked.key_length, checked.match_probability, exponent, limit
    )


# --------------------------------------------------------------------------- #
# 3b. forgery by a recipient -- the binding case
# --------------------------------------------------------------------------- #


def _recipient_rates(
    params: ProtocolParams, *, symmetrised: bool
) -> tuple[float, float]:
    """Return ``(scored fraction, mismatch rate given scored)`` for a recipient.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set; only ``len(bases)`` is used.
    symmetrised : bool
        ``True`` for the shipped protocol, in which the forger supplied half of
        the target's evidence during the exchange and therefore knows it
        exactly. ``False`` for the variant with the exchange removed, which
        Phase 3 runs to show why the step exists.

    Returns
    -------
    tuple of float
        ``(p_s, rho)``. Section 3b of the module docstring derives the
        symmetrised pair ``((n+1)/(2n), (n-1)/(2n(n+1)))``; without the exchange
        the recipient is scored on the ordinary ``1/n`` of positions and
        mismatches at ``(1 - 1/n)/2`` there.
    """
    if symmetrised:
        return params.forger_scored_fraction, params.forger_floor
    return params.match_probability, params.unmatched_noise_rate


def recipient_forgery_probability(
    params: ProtocolParams,
    *,
    party: Party | str = Party.CHARLIE,
    symmetrised: bool = True,
) -> float:
    """Exact probability that a *recipient's* forgery is accepted.

    The binding forgery case, and the one a security claim should quote. The
    adversary is Bob: he received and measured a copy of the public key, took
    part in the symmetrisation exchange, and now tries to get Charlie to accept
    a key Alice never signed. Section 3b of the module docstring derives his
    per-position behaviour and shows it is optimal over all POVMs, giving

    .. code-block:: text

        m ~ Bin(L, p_s),  e | m ~ Bin(m, rho)
        p_s = (n + 1) / (2n)   = 2/3     positions he gets scored
        rho = (n - 1) / (2n(n + 1)) = 1/12   mismatch rate among them

    and then the same double binomial sum as :func:`forgery_probability`, under
    the same convention that an empty scored set is not an acceptance.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    party : Party or str, optional
        The verifier being targeted, i.e. the *other* recipient. Defaults to
        :attr:`~sih141.protocol.params.Party.CHARLIE` and his ``s_v``; pass
        ``Party.BOB`` for the ``s_a`` variant, which is the relevant one when
        Charlie is the forger.
    symmetrised : bool, optional
        ``True`` (default) for the shipped protocol. ``False`` computes the same
        quantity for the variant with the exchange removed, where the forger
        neither knows nor supplied any of the target's evidence and sits at
        ``(1/n, (1 - 1/n)/2)`` instead -- the comparison Phase 3 reports.

    Returns
    -------
    float
        The acceptance probability, in ``[0, 1]``. Underflows to ``0.0`` below
        about ``1e-308``; use :func:`recipient_forgery_bound` there.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, or ``symmetrised`` is
        not a bool.
    ValueError
        If ``party`` is Alice or names no party.

    See Also
    --------
    recipient_forgery_bound : The closed-form exponential upper bound.
    forgery_probability : The weaker, outside adversary.
    sih141.protocol.params.ProtocolParams.forger_floor : ``rho``.

    Examples
    --------
    >>> from sih141.protocol.analysis import (
    ...     forgery_probability, recipient_forgery_probability
    ... )
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=30)
    >>> round(recipient_forgery_probability(params), 6)
    0.481427
    >>> recipient_forgery_probability(params) > forgery_probability(params)
    True
    """
    checked = _as_params(params)
    if not isinstance(symmetrised, bool):
        raise TypeError(
            f"symmetrised must be a bool, got {type(symmetrised).__name__}. It "
            f"selects which protocol variant the forger is attacking, not a "
            f"rate."
        )
    threshold = checked.threshold_for(_as_verifier(party))
    scored, rate = _recipient_rates(checked, symmetrised=symmetrised)
    return math.exp(
        _log_decision_probability(
            checked.key_length, scored, rate, threshold, accept=True
        )
    )


def recipient_forgery_bound(
    params: ProtocolParams,
    *,
    party: Party | str = Party.CHARLIE,
    method: BoundMethod = "hoeffding",
    symmetrised: bool = True,
    matched: int | None = None,
) -> float:
    """Closed-form upper bound on :func:`recipient_forgery_probability`.

    Conditioned on ``m`` scored positions the forger needs ``Bin(m, rho)`` to
    land at or below ``s m``, so

    .. code-block:: text

        P <= exp(-2 m (rho - s)^2)      method="hoeffding"
        P <= exp(-m D(s || rho))        method="kl"

    with ``rho = forger_floor``. Averaging over ``m ~ Binomial(L, p_s)`` is
    exact, giving a bound exponential in ``L``.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    party : Party or str, optional
        The targeted verifier; defaults to
        :attr:`~sih141.protocol.params.Party.CHARLIE`.
    method : {'hoeffding', 'kl'}, optional
        Which exponent to use. ``"kl"`` is never weaker.
    symmetrised : bool, optional
        As :func:`recipient_forgery_probability`.
    matched : int or None, optional
        Condition on exactly this many *scored* positions, or average over the
        binomial scored count when ``None`` (the default). Note that the
        relevant count here is ``Bin(L, p_s)`` with ``p_s = 2/3``, not the
        ``Bin(L, 1/n)`` of an outside forger.

    Returns
    -------
    float
        An upper bound in ``[0, 1]``. Returns ``1.0`` when the threshold is at
        or above ``rho``, where no bound is available -- which is precisely the
        parameter set :class:`~sih141.protocol.params.ProtocolParams` refuses
        without ``allow_forgeable=True``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, ``matched`` is not an
        integer, ``method`` is not a string, or ``symmetrised`` is not a bool.
    ValueError
        If ``party`` is Alice, ``matched`` is not positive, or ``method`` names
        neither inequality.

    Examples
    --------
    >>> from sih141.protocol.analysis import (
    ...     recipient_forgery_bound, recipient_forgery_probability
    ... )
    >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
    >>> params = ProtocolParams(key_length=300)
    >>> recipient_forgery_probability(params) <= recipient_forgery_bound(
    ...     params, method="kl"
    ... )
    True
    >>> f"{recipient_forgery_bound(DEFAULT_PARAMS, method='kl'):.2e}"
    '1.12e-103'
    """
    checked = _as_params(params)
    selected = _as_method(method)
    if not isinstance(symmetrised, bool):
        raise TypeError(
            f"symmetrised must be a bool, got {type(symmetrised).__name__}"
        )
    threshold = checked.threshold_for(_as_verifier(party))
    limit = None if matched is None else _as_matched(matched)
    scored, rate = _recipient_rates(checked, symmetrised=symmetrised)
    if threshold >= rate:
        return 1.0
    exponent = _exponent(threshold, rate, selected)
    return _conditional_or_averaged(
        checked.key_length, scored, exponent, limit
    )


# --------------------------------------------------------------------------- #
# 4. repudiation
# --------------------------------------------------------------------------- #


def repudiation_probability(
    params: ProtocolParams, *, mismatch_probability: float
) -> float:
    """Exact repudiation probability for one **symmetric** Alice strategy.

    Suppose Alice induces the *same* per-matched-position mismatch probability
    ``q`` on both recipients' copies -- tilting the prepared Bloch vector away
    from the declared axis by the same angle for each. The two copies then have
    the same law, the symmetrisation coins are irrelevant, the two records are
    independent, and the event factorises:

    .. code-block:: text

        P_rep(q) = P(r_B <= s_a) * P(r_C > s_v)

    with each factor an exact double binomial sum. An empty matched set counts as
    "not accepted" on both sides: ``m_B = 0`` means Bob does not accept, and
    ``m_C = 0`` means Charlie does not accept, which is the rejection branch.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    mismatch_probability : float
        ``q`` in ``[0, 1]``, identical across positions **and across the two
        recipients**. ``0`` is the honest noiseless case, and it does **not**
        give ``0``: it leaves exactly ``P(m_B >= 1) * P(m_C = 0)``, the runs in
        which Bob has evidence and Charlie has none. That residue is a
        transferability failure of an honest run rather than an attack -- it is
        the same event :func:`honest_abort_probability` charges to Charlie --
        and it is of order ``(1 - 1/|B|)**L``, far below every other term.

    Returns
    -------
    float
        The repudiation probability under that one strategy, in ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, or
        ``mismatch_probability`` is not a real number.
    ValueError
        If ``mismatch_probability`` is outside ``[0, 1]``.

    See Also
    --------
    repudiation_bound : The guarantee, uniform over *every* Alice strategy.
    symmetric_repudiation_bound : The uniform-in-``q`` bound for this family.

    Notes
    -----
    **This is not a security number and its maximum over ``q`` is not one
    either.** The single common ``q`` is a modelling restriction on Alice, not a
    description of her freedom: she prepares the two recipients' copies
    separately and can choose ``q_B != q_C``, which breaks the factorisation the
    whole expression rests on. The extreme case ``q_B = 0``, ``q_C = 1`` on a
    fraction of positions repudiates with probability ``1`` against
    *unsymmetrised* records at every ``L``, exceeding
    ``sup_q repudiation_probability`` without limit.

    What makes the scheme safe is not this function but the symmetrisation
    exchange, and the statement that covers every strategy is
    :func:`repudiation_bound`, whose derivation conditions on the records and
    never mentions ``q`` at all. Use this function for what it is good for:
    seeing the exact shape of the in-model probability, and cross-checking the
    closed forms against a simulator built on the same model, which
    ``tests/test_protocol_analysis.py`` does.

    Examples
    --------
    >>> from sih141.protocol.analysis import repudiation_probability
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=30)
    >>> f"{repudiation_probability(params, mismatch_probability=0.0):.3e}"
    '5.215e-06'
    >>> f"{repudiation_probability(params, mismatch_probability=0.2):.3e}"
    '1.100e-01'
    """
    checked = _as_params(params)
    rate = _as_probability(mismatch_probability, "mismatch_probability")
    log_bob_accepts = _log_decision_probability(
        checked.key_length,
        checked.match_probability,
        rate,
        checked.s_a,
        accept=True,
    )
    log_charlie_rejects = _log_decision_probability(
        checked.key_length,
        checked.match_probability,
        rate,
        checked.s_v,
        accept=False,
    )
    total = log_bob_accepts + log_charlie_rejects
    return 0.0 if total == -math.inf else math.exp(total)


def _kl_repudiation_exponent(s_a: float, s_v: float) -> float:
    """Worst-case relative-entropy exponent of the repudiation event.

    Returns ``min_{q in [s_a, s_v]} D(s_a || q) + D(s_v || q)``. The objective is
    a sum of two functions each convex in ``q`` (the relative entropy is convex
    in its second argument), so it is convex on the interval and a ternary search
    converges. Outside ``[s_a, s_v]`` one of the two indicator conditions of the
    bound switches off, but the surviving term is then larger than its value at
    the corresponding endpoint, so the interior minimum is the worst case.

    Parameters
    ----------
    s_a, s_v : float
        The two thresholds, ``s_a < s_v``.

    Returns
    -------
    float
        The exponent in nats, strictly positive.
    """

    def objective(q: float) -> float:
        return binary_kl_divergence(s_a, q) + binary_kl_divergence(s_v, q)

    low, high = s_a, s_v
    for _ in range(_TERNARY_ITERATIONS):
        span = (high - low) / 3.0
        left, right = low + span, high - span
        if objective(left) < objective(right):
            high = right
        else:
            low = left
    return objective(0.5 * (low + high))


def repudiation_bound(
    params: ProtocolParams, *, matched_records: int | None = None
) -> float:
    """Upper bound on repudiation, valid for **every** Alice strategy.

    The scheme's non-repudiation guarantee, and the only function in this module
    that is one. Section 4b of the module docstring derives it; the structure is
    what matters here:

    * It conditions on the two recipients' raw records -- whatever Alice
      prepared, however asymmetric, adaptive or entangled. There is no adversary
      model left to be wrong about, and in particular no per-position ``q``.
    * The only randomness used is the recipients' private symmetrisation coins
      (:mod:`sih141.protocol.symmetrise`), which Alice can neither see nor
      influence. Those coins split a *fixed* total of matched and mismatched
      records between the two verifiers, so ``m_B + m_C`` and ``e_B + e_C`` are
      constants and repudiation demands a large deviation of the split.
    * Hoeffding over ``L`` independent two-point coin variables, of which at
      most ``M`` have non-zero range, gives ``exp(-M gap**2 / 8)``; the
      ``m_C = 0`` corner, where Charlie rejects for want of evidence rather than
      because of it, is added separately as ``(1 - 1/|B|)**L``.

    .. code-block:: text

        P_rep <= (1 - 1/n)^L + E[exp(-M gap^2 / 8)],   M ~ Bin(2L, 1/n)
              =  (1 - 1/n)^L + (1 - 1/n + exp(-gap^2/8)/n)^(2L)

    **Without symmetrisation this bound does not apply and no bound does**: the
    protocol variant produced by
    :func:`sih141.protocol.symmetrise.no_symmetrisation` is repudiable with
    probability ``1`` at every ``L``.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    matched_records : int or None, optional
        Condition on this many matched records **across the two verifiers
        together** -- ``M = m_B + m_C``, whose mean is ``2L/|B|``, not the
        per-verifier ``L/|B|``. ``None`` (the default) averages over
        ``M ~ Binomial(2L, 1/|B|)``, which is exact and is the honest thing to
        report before a run has happened.

    Returns
    -------
    float
        An upper bound in ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams` or ``matched_records`` is
        not an integer.
    ValueError
        If ``matched_records`` is not positive.

    See Also
    --------
    symmetric_repudiation_bound : The tighter bound for the narrow model.
    repudiation_probability : The exact in-model probability.

    Examples
    --------
    >>> from sih141.protocol.analysis import repudiation_bound
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> f"{repudiation_bound(DEFAULT_PARAMS):.2e}"
    '6.92e-10'
    >>> f"{repudiation_bound(DEFAULT_PARAMS, matched_records=76800):.2e}"
    '6.90e-10'
    """
    checked = _as_params(params)
    limit = None if matched_records is None else _as_matched(matched_records)
    exponent = checked.gap**2 / 8.0
    coin_term = _conditional_or_averaged(
        2 * checked.key_length, checked.match_probability, exponent, limit
    )
    # Charlie holding no evidence at all is a rejection the coin argument does
    # not cover, because there is no rate to deviate.
    empty = (1.0 - checked.match_probability) ** checked.key_length
    return min(1.0, coin_term + empty)


def symmetric_repudiation_bound(
    params: ProtocolParams,
    *,
    method: BoundMethod = "hoeffding",
    matched: int | None = None,
) -> float:
    """Upper bound on :func:`repudiation_probability`, uniform in ``q`` **only**.

    The classical in-model expression, kept as the right yardstick for
    :func:`repudiation_probability` and **not** as a security guarantee: it is
    valid across the single-common-``q`` family of section 4a and says nothing
    about an Alice who treats the two recipients differently.

    ``method="hoeffding"``: split at the midpoint ``(s_a + s_v)/2``, note that
    one of the two parties must then deviate by at least ``(s_v - s_a)/2`` from
    its mean, and drop the other factor:

    .. code-block:: text

        P_rep(q) <= exp(-m (s_v - s_a)^2 / 2)        for every q in the family

    ``method="kl"`` keeps both factors and uses the relative entropy, giving the
    exponent ``min_q [D(s_a||q) + D(s_v||q)]`` -- a convex one-dimensional
    problem solved by ternary search. Both forms are averaged over
    ``m ~ Binomial(L, 1/|B|)`` unless ``matched`` is given.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    method : {'hoeffding', 'kl'}, optional
        Which exponent to use. Defaults to ``"hoeffding"``.
    matched : int or None, optional
        Condition on this many matched positions **at one verifier**, or average
        over the binomial matched count when ``None`` (the default).

    Returns
    -------
    float
        An upper bound in ``[0, 1]`` on ``sup_q repudiation_probability(q)``,
        and on nothing wider.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, ``matched`` is not an
        integer, or ``method`` is not a string.
    ValueError
        If ``matched`` is not positive or ``method`` names neither inequality.

    See Also
    --------
    repudiation_bound : The guarantee that covers every Alice strategy.

    Examples
    --------
    >>> from sih141.protocol.analysis import (
    ...     repudiation_bound, symmetric_repudiation_bound
    ... )
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> f"{symmetric_repudiation_bound(DEFAULT_PARAMS, matched=38400):.2e}"
    '4.77e-19'
    >>> symmetric_repudiation_bound(DEFAULT_PARAMS) < repudiation_bound(
    ...     DEFAULT_PARAMS
    ... )
    True
    """
    checked = _as_params(params)
    selected = _as_method(method)
    limit = None if matched is None else _as_matched(matched)
    if selected == "kl":
        exponent = _kl_repudiation_exponent(checked.s_a, checked.s_v)
    else:
        exponent = checked.gap**2 / 2.0
    return _conditional_or_averaged(
        checked.key_length, checked.match_probability, exponent, limit
    )


# --------------------------------------------------------------------------- #
# 5. robustness
# --------------------------------------------------------------------------- #


def honest_abort_probability(
    params: ProtocolParams,
    *,
    error_rate: float = 0.0,
    party: Party | str | None = None,
) -> float:
    """Exact probability that an honest signature fails to be accepted.

    Robustness is the mirror image of unforgeability: a scheme that rejects
    everything is trivially unforgeable and useless. An honest run aborts at
    party ``R`` when ``r_R > s`` or the matched set is empty,

    .. code-block:: text

        P_abort(R) = P(m = 0) + sum_{m>=1} P(m) P(Bin(m, p_e) > t(m))

    With ``p_e = 0`` this is exactly ``P(m = 0) = (1 - 1/|B|)^L`` -- the honest
    noiseless run never produces a single mismatch, so the only way to fail is to
    have no evidence at all.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    error_rate : float, optional
        ``p_e`` in ``[0, 1]``. Defaults to ``0.0``.
    party : Party or str or None, optional
        Which verifier to report. ``None`` (the default) reports the probability
        that **at least one** verifier aborts, computed exactly as
        ``P_B + P_C - P_B P_C`` from the independence of the two records -- the
        number that matters operationally, since a run in which either party
        balks has failed.

    Returns
    -------
    float
        The abort probability, in ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, or ``error_rate`` is not
        a real number.
    ValueError
        If ``error_rate`` is outside ``[0, 1]``, or ``party`` is Alice.

    See Also
    --------
    honest_abort_bound : The exponential bound, for which ``method="kl"`` matters
        a great deal at small ``p_e``.

    Examples
    --------
    >>> from sih141.protocol.analysis import honest_abort_probability
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=30)
    >>> honest_abort_probability(params, party="Bob") < 1e-4
    True
    """
    checked = _as_params(params)
    rate = _as_probability(error_rate, "error_rate")

    if party is None:
        bob = honest_abort_probability(
            checked, error_rate=rate, party=Party.BOB
        )
        charlie = honest_abort_probability(
            checked, error_rate=rate, party=Party.CHARLIE
        )
        return bob + charlie - bob * charlie

    threshold = checked.threshold_for(_as_verifier(party))
    log_probability = _log_decision_probability(
        checked.key_length,
        checked.match_probability,
        rate,
        threshold,
        accept=False,
    )
    return 0.0 if log_probability == -math.inf else math.exp(log_probability)


def honest_abort_bound(
    params: ProtocolParams,
    *,
    error_rate: float = 0.0,
    party: Party | str | None = None,
    method: BoundMethod = "hoeffding",
    matched: int | None = None,
) -> float:
    """Closed-form upper bound on :func:`honest_abort_probability`.

    For ``p_e < s`` the conditional upper tail obeys ``exp(-2 m (s - p_e)^2)``
    (Hoeffding) and ``exp(-m D(s || p_e))`` (Chernoff-KL), and the ``m = 0`` term
    is absorbed by the exact binomial averaging, which values it at ``1``. With
    ``party=None`` the two parties are combined by the union bound rather than by
    the exact inclusion-exclusion, since only the bounded factors are available.

    **This is the bound where the choice of** ``method`` **matters.** Hoeffding
    charges every position the maximal variance ``1/4``, while the true variance
    is ``p_e(1 - p_e)``. At ``p_e = 0`` the true conditional abort probability is
    exactly ``0`` -- a noiseless honest run cannot produce a single mismatch --
    yet Hoeffding still reports ``exp(-2 m s^2)``. The relative entropy
    ``D(s || 0) = -ln(1 - s)`` is also finite, so ``"kl"`` does not close that
    gap either; it merely shrinks it, by a factor of ``exp(m [-ln(1-s) - 2 s^2])``
    which at the default ``s_a`` is about ``exp(0.0298 m)``. Neither bound
    reproduces the exact answer ``P(m = 0)`` in that limit, and neither can: both
    are one-sided tail inequalities with no term that vanishes at ``p_e = 0``.
    Prefer ``method="kl"`` for any low-noise channel, and
    :func:`honest_abort_probability` when the exact number is wanted.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    error_rate : float, optional
        ``p_e`` in ``[0, 1]``. Defaults to ``0.0``.
    party : Party or str or None, optional
        Which verifier, or ``None`` (the default) for the union bound over both.
    method : {'hoeffding', 'kl'}, optional
        Which exponent to use. Defaults to ``"hoeffding"``.
    matched : int or None, optional
        Condition on this many matched positions, or average over the binomial
        matched count when ``None`` (the default).

    Returns
    -------
    float
        An upper bound in ``[0, 1]``. Returns ``1.0`` when ``p_e >= s``, where
        there is no decay to bound: an honest run at or above its own threshold
        is expected to abort.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, ``matched`` is not an
        integer, ``method`` is not a string, or ``error_rate`` is not a real
        number.
    ValueError
        If ``error_rate`` is outside ``[0, 1]``, ``party`` is Alice, ``matched``
        is not positive, or ``method`` names neither inequality.

    Examples
    --------
    >>> from sih141.protocol.analysis import (
    ...     honest_abort_bound, honest_abort_probability)
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=60)
    >>> exact = honest_abort_probability(params, error_rate=0.01, party="Bob")
    >>> exact <= honest_abort_bound(params, error_rate=0.01, party="Bob",
    ...                             method="kl")
    True
    """
    checked = _as_params(params)
    selected = _as_method(method)
    rate = _as_probability(error_rate, "error_rate")
    limit = None if matched is None else _as_matched(matched)

    if party is None:
        bob = honest_abort_bound(
            checked,
            error_rate=rate,
            party=Party.BOB,
            method=selected,
            matched=limit,
        )
        charlie = honest_abort_bound(
            checked,
            error_rate=rate,
            party=Party.CHARLIE,
            method=selected,
            matched=limit,
        )
        return min(1.0, bob + charlie)

    threshold = checked.threshold_for(_as_verifier(party))
    if rate >= threshold:
        return 1.0
    exponent = _exponent(threshold, rate, selected)
    return _conditional_or_averaged(
        checked.key_length, checked.match_probability, exponent, limit
    )
