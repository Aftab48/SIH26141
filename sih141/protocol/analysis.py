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

0. Assumption (IND), stated once and referenced everywhere
----------------------------------------------------------
**(IND) -- the declaration** ``(d_i, w_i)`` **is statistically independent of the
recipients' logged bases** ``c_i``.

Every statement in this module that *averages over a matched count* -- ``m ~
Binomial(L, 1/n)``, ``M ~ Binomial(2L, 1/n)``, and therefore every bound obtained
without passing an explicit observed count -- needs (IND), and is not merely
loose without it but false. The reason is structural, not technical: the matched
set is ``{i : c_i == d_i}``, so whoever chooses ``d`` while knowing ``c`` chooses
the matched set, and a bound whose exponent is linear in the size of that set is
then a bound on a quantity the adversary picked. He picks it small.

(IND) holds for an honest signer, and it holds for the adversaries of sections 3
and 3b *as modelled there*, because each ``c_i`` is drawn privately at receipt
time in Phase A, before any signature exists, and is never published. It does
**not** hold automatically at the shipped seams:
:class:`sih141.protocol.session.QDSSession` hands the ``Signer`` seam both
recipients' raw logs, so an adversary standing in Alice's place reads every
``c_i`` and violates (IND) outright. Section 4b-ii names that strategy and gives
the measured damage; sections 3 and 3b say what the same leak would do to the
forgery numbers.

(IND) is a property of the *interface*, not a theorem about the protocol. Nothing
in this module can check it, so nothing in this module assumes it silently: the
one number that used to be published as unconditional --
:func:`repudiation_bound` averaged over ``M`` -- now lives in
:func:`averaged_repudiation_bound` behind a mandatory
``signer_sees_recipient_bases`` argument, and :func:`repudiation_bound` itself
takes the observed count.

What survives without (IND) is every bound *conditioned on the observed matched
count*. Those use only the recipients' private coins, or the Born rule, and never
the law of ``m``. They are what a run should quote.

0b. Assumption (AUTH), which is load-bearing and is checked nowhere
-------------------------------------------------------------------
**(AUTH) -- the classical and quantum channels from Alice to each recipient are
authenticated: a recipient knows that the states he measured and the declaration
he scores both came from Alice.**

Every bound in this module is a statement about a *named* signer. None of them
is a statement that the signer was Alice, and nothing in the shipped data
carries one: :class:`~sih141.protocol.signature.Signature`,
:class:`~sih141.protocol.records.RecipientRecord`,
:class:`~sih141.protocol.verify.VerificationResult` and
:class:`~sih141.protocol.session.SessionTranscript` hold no signer identity and
no binding to one. An adversary who controls **both** seams -- distributing her
own key states in Phase A *and* signing her own key in Phase B -- is therefore
not forging in the sense sections 3 and 3b bound. She is running the protocol as
the signer, correctly, and every number in this file is on her side: measured
through the shipped seams at ``L = 192``, ``200/200`` accepted by Bob and
``200/200`` by Charlie, ``QBER = 0.0000`` exactly, ``transferable=True`` --
identical to the honest control in every transcript number, which is the
result. No counting rule over the
recipients' own logs can do anything about that, because there is nothing in
those logs to disagree with.

This is inherent to measurement-based QDS rather than a defect of this
implementation: Dunjko-Wallden-Andersson [2]_ and Amiri et al. [3]_ both assume
authenticated channels from the signer and derive what remains. It is written
down here because it is a *precondition of the demonstration* in exactly the way
(IND) is, and Phase 3 and Phase 5 will be asked about it.

**Partial impersonation is a different matter and is caught cold.** An adversary
who seizes only the signing seam -- Alice distributed, Mallory declares -- is
the external forger of section 3, and an adversary who seizes only the
distribution seam is caught by the same arithmetic. Measured through the shipped
seams by :mod:`sih141.attacks.impersonation`, at ``L = 192`` over ``n = 200``
sessions per arm, with the mismatch rate **pooled over scored positions**
(``sum e_R / sum |M_R|``, roughly ``1.3e+04`` positions per arm per verifier)
rather than averaged over per-run rates:

.. code-block:: text

    scope           accepted    r_Bob     r_Charlie
    none (control)   200/200    0.0000    0.0000
    full             200/200    0.0000    0.0000     <- out of model, (AUTH)
    signing            0/200    0.4988    0.5038
    distribution       0/200    0.5031    0.4997

against the ``1/2`` a declaration uncorrelated with the recipients' states
produces; all four Wilson 95% intervals cover it. The table is
:data:`sih141.attacks.impersonation.MEASURED`, whose rows carry their own counts
and re-check their own arithmetic at import, and
:func:`sih141.attacks.impersonation.shipped_summary` prints it.

This paragraph used to read ``0/60`` accepted at ``QBER = 0.4987`` (Bob) and
``0.4806`` (Charlie). The acceptance count reproduces; ``0.4806`` does not, and
it could not have: with no key length, no ``n``, and no statement of which of
the two estimators it was, there was nothing to reproduce. At any plausible
``L`` the pooled standard deviation over 60 runs is at most ``0.0144``, which
puts ``0.4806`` about ``1.3`` sd low while quoting it to four figures. It is
replaced rather than corrected, because the defect was the missing conditions
and not the digits.

Note what did *not* move in those runs: **the matched counts are unchanged**,
because the matched set depends only on the declared bases and the recipients'
own uniform draws (section 1) and no adversary in the channel touches either.
Under the distribution scope this was checked in its sharpest form -- the matched
sets are identical *position for position* to the control at the same session
seed, 200/200 trials -- with the signing scope as the control that stops the
claim being vacuous (0/200 identical there, the counts still Binomial(L, 1/3)).
The mismatch rate is the only signal there is. That is also why the floors of sections 4b-iii
and 4b-iv are an evidence-liveness control rather than an impersonation
detector, and why an end-to-end adversary -- who produces ``r_R = 0`` by
construction, like any honest signer -- is invisible to every rate computed
here. (AUTH) is what excludes her, and only (AUTH).

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

That binomial law is the first and largest consumer of (IND). "``c_i`` is uniform
and independent of ``d_i``" is (IND) written out for one position; a declaration
computed *from* the logged bases has ``P(i in M_R)`` equal to ``0`` or ``1`` at
the adversary's choice, and then ``m`` is not ``Binomial(L, 1/n)``, not
concentrated near ``L/3``, and not anything else this module can predict. Every
appearance of ``Binomial(L, 1/n)`` or ``Binomial(2L, 1/n)`` below carries that
hypothesis with it.

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

A verifier may set the bar higher than ``m >= 1``
    A matched-count *floor* -- score only when ``m >= m_min`` for some
    ``m_min > 1``, abort otherwise -- is a strictly stronger rule, and
    :mod:`sih141.protocol.verify` applies three of them as this is written: each
    verifier's own, the *pooled* ``m_B + m_C >= M_min``, and the requirement
    that the other verifier cleared his. Every function here uses the ``m >= 1``
    convention, which lands as follows. Forgery and recipient-forgery numbers
    are then *over*-estimates, since the forger must clear bars this module does
    not model: still bounds, merely looser.
    :func:`honest_abort_probability` and :func:`honest_abort_bound` cover only
    the rate rule "``r_R > s`` or the matched set is empty" and omit the three
    floors entirely, so neither describes the shipped protocol's honest failure
    probability. The omission is not negligible: at ``p_e = 0`` **the omitted
    term is the larger one** -- the exact rate probability is ``4.429e-106``
    against ``1.740e-34`` from the floors at ``L = 600``, and ``0.0`` against
    ``9.972e-32`` at ``L = 4800``. The floors' own budget is
    ``2.5e-31 + 2.5e-31 + 2.9e-31 = 8.0e-31`` at the shipped parameters, where
    the rate term underflows to ``0`` outright. Compose the two --
    :func:`honest_abort_probability` plus :func:`matched_shortfall_probability`
    at each floor -- whenever the number is meant to describe the protocol
    :mod:`sih141.protocol.verify` actually runs;
    section 5 gives the composition and both functions repeat it. An
    under-estimate of a failure probability flatters the scheme, which is the one
    direction a published number must never err in silently.
    :func:`repudiation_bound` is unaffected, because it
    conditions on the observed counts and its Bob-accepts branch only shrinks.
    The floors' *use* as a security control is sections 4b-iii and 4b-iv, which
    also state the repudiation route a per-verifier floor alone opens rather
    than closes, and what closing it costs.

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
published. **This is (IND), and it is a hypothesis rather than a theorem.** It is
load-bearing here in exactly the way section 0 describes: if some seam handed Eve
the verifier's log she would stop being an adversary who cannot steer the matched
set. Her optimal play would then be to declare a basis that misses ``c_i`` at
every position but one, sit on a matched set of size ``m = 1``, and guess that
single outcome -- accepted with probability ``1/2``, against a ``forgery_bound``
of ``e^-15091``. The conditional form ``forgery_bound(params, matched=1) = 0.68``
is the honest number for that adversary -- it dominates her true ``1/2`` -- and
it is the same repair as section 4b-i: condition on the count instead of
averaging over it.

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

*What he must not hold, and it is (IND) again.* The pair ``(p_s, rho)`` is
computed against Charlie's **retained** positions -- the half of the exchange Bob
did not supply -- and it presumes Bob does not know the bases Charlie logged
there. He is already granted a great deal (his own ``L`` records, the identity of
the swapped positions, Charlie's entry verbatim on each of them); one more item
would end the analysis rather than shift it. Knowing Charlie's retained bases,
Bob declares a basis that misses them at every retained position, so Charlie's
matched set consists only of positions Bob himself supplied, ``rho`` collapses
from ``1/12`` to ``0``, and Charlie accepts with probability ``1`` at every ``L``.
So ``recipient_forgery_bound``'s averaging over ``m ~ Bin(L, p_s)`` is not a
statement about a two-thirds scored fraction that happens to hold; it is a
statement that holds while the exchange leaks nothing but the swapped entries.
:mod:`sih141.protocol.symmetrise` is where that is either true or false, and the
conditional form ``recipient_forgery_bound(params, matched=m)`` is again what
survives if it is false.

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

**Several different statements live here, and conflating them is how this module
went wrong twice.** One is the exact probability under a *particular*, narrow
family of Alice strategies (4a). One is an upper bound that holds whatever Alice
does, evaluated at the matched count a run actually produced (4b-i). One is that
bound averaged over the matched count, which is a smaller and much more quotable
number and is true only under (IND) (4b-ii). Only 4b-i is a guarantee with no
hypothesis attached; 4b-iii says what an unconditional a-priori guarantee costs
and what a *local* abort rule alone still leaves open, and 4b-iv is the pooled
rule that closes it and the number the shipped code earns.

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

*4b. What the symmetrisation exchange actually buys.* Three statements, in
decreasing order of strength. They were previously published as one, which is the
error this section exists to prevent from returning.

**4b-i. The conditional guarantee -- uniform over every Alice strategy, and it
assumes nothing whatever.** This is what the exchange
(:mod:`sih141.protocol.symmetrise`) buys.

Fix the two recipients' raw records -- whatever she prepared, however
asymmetric, adaptive or entangled -- and fix the declaration, whatever she
computed it from, the two raw logs included. The only randomness left is the
recipients' private coins, one per position, each deciding which verifier scores
which of the two records. Two conservation facts follow immediately, because the
coins only *split* a fixed collection:

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

    P(repudiation | records, declaration) <= exp(-2 ((gap/4) M)^2 / M)
                                          = exp(-M gap^2 / 8)

which is :func:`repudiation_bound`, and which takes the observed
``M = m_B + m_C`` as a **mandatory** argument. Note what is not in it: no ``q``,
no independence assumption about the two recipients, no model of Alice, and no
(IND) -- the declaration was fixed before any of the randomness used here was
drawn, so it does not matter what it was computed from.

*The* ``m_C = 0`` *corner is inside the event, not outside it.* Charlie failing
to accept splits into ``m_C >= 1 and r_C > s_v``, handled above, and ``m_C = 0``,
where there is no rate to deviate. The second branch is not an exception:
``m_C = 0`` forces ``m_B = M`` and ``e_B = E``, Bob's acceptance then reads
``E <= s_a M``, and ``W - E[W] = (E - s M)/2 <= (s_a - s) M / 2 = -(gap/4) M`` --
the same deviation event, reached non-strictly, and Hoeffding's inequality is
non-strict. Earlier versions of this module added ``(1 - 1/n)^L`` for that corner.
The term was never needed, and it was the one ingredient of the "guarantee" that
was a statement about the recipients' *basis draws* rather than their coins,
i.e. an (IND) statement smuggled into a bound advertised as assumption-free. It
is gone from the conditional form.

**4b-ii. The M-averaged number -- needs (IND), and the shipped Signer seam gives
(IND) away.** Averaging ``exp(-M gap^2/8)`` over ``M ~ Bin(2L, 1/n)`` is exact by
the generating-function identity of section 3, so

.. code-block:: text

    P_rep <= (1 - 1/n)^L + (1 - 1/n + exp(-gap^2/8)/n)^(2L)     [needs (IND)]

is a bound *on the average over the recipients' basis draws*, which at
:data:`~sih141.protocol.params.DEFAULT_PARAMS` is ``6.9173e-10``. This is
:func:`averaged_repudiation_bound`, and it was published here as the
unconditional non-repudiation guarantee. **It is not one.** ``M ~ Bin(2L, 1/n)``
is the law of the matched count only while (IND) holds, and
:class:`~sih141.protocol.session.QDSSession` hands the ``Signer`` seam both
recipients' raw logs.

The strategy, concretely, and it needs no quantum resource at all. Alice reads
the two raw logs. At every position she declares a basis that appears in
*neither* log -- with ``n = 3`` there is always one, two when the logs agree --
so that position is matched at neither verifier. She keeps twelve exceptions:
eleven positions where the logs used different bases, where she declares Bob's
basis and Bob's outcome (one matched record, correct, whoever ends up holding
it); and one position where the two logs used the *same* basis and recorded
*opposite* outcomes, where she declares that basis and Bob's outcome (two matched
records, exactly one of them wrong). Then

.. code-block:: text

    M = 11 + 2 = 13    for every L, with probability 1
    P(repudiation) = P(the wrong record lands on Charlie) = 1/2   exactly

because exactly one of the ``13`` matched records is wrong and one coin decides
who scores it. If it goes to Charlie, Bob holds between ``1`` and ``12`` matched
records and none of them is wrong (``r_B = 0 <= s_a``, and he does have evidence,
so he accepts), while Charlie holds that mismatch among at most ``12`` matched
records (``r_C >= 1/12 > s_v``, so he rejects). If it goes to Bob instead,
``r_B >= 1/12 > s_a`` and he rejects, which is the other half of the coin.
Measured through this file's own simulator: ``M = 13`` in every trial at both
``L = 600`` and ``L = 115200``, and a repudiation frequency of ``0.45`` to
``0.53`` -- against the ``6.9e-10`` above, and matching the ``0.46`` to ``0.58``
an independent audit measured with a different construction. Note that Charlie
holds evidence in every one of those runs: this is a rejection on a mismatch
rate, not the empty-matched-set corner, so it is not repaired by anything
:mod:`sih141.protocol.verify` does about ``m_C = 0``.

The conditional bound is untouched by all of this:
``repudiation_bound(params, matched_records=13) = 0.9964``, and ``0.5 < 0.9964``.
The mathematics was never wrong. The advertising was.

**4b-iii. Is there an honest unconditional number? Only with an abort rule.**
Worst-casing over ``M`` instead of averaging is legitimate and useless:
``exp(-M gap^2/8)`` decreases in ``M``, ``M = 0`` makes repudiation impossible
(Bob has nothing to accept), so the supremum over everything else is
``exp(-gap^2/8) = 0.99973`` at the shipped parameters. Nor is that slack: the
strategy above achieves ``1/2`` at every ``L``, so **no unconditional bound below
``1/2`` exists for a signer who can read the recipients' logged bases**, at any
key length whatever. Key length does not help, because the failure is not
statistical.

What does help is refusing to score an anomalously small matched set. Suppose Bob
declines to accept unless his own ``|M_B| >= m_min``. Repudiation needs Bob to
accept, so on that event ``M >= m_B >= m_min``, and off it there is nothing to
bound:

.. code-block:: text

    P(repudiation) <= exp(-m_min gap^2 / 8)      every Alice strategy, no (IND)

which is :func:`repudiation_bound_with_abort`. It is a *local* rule -- Bob knows
``m_B`` without asking anyone -- and it is nearly free, because on an honest run
``m_B ~ Bin(L, 1/n)`` is tightly concentrated: at
:data:`~sih141.protocol.params.DEFAULT_PARAMS` the shipped floor
``m_min = 36555`` (:func:`~sih141.protocol.verify.minimum_matched_count`, eleven
standard deviations below ``E[m_B] = 38400``) costs an honest run ``2.5e-31`` in
extra abort probability (:func:`matched_shortfall_probability`) and buys a
genuine unconditional ``4.4e-5``. Requiring *both* verifiers to have cleared it
puts ``M >= 2 m_min`` and buys ``1.9e-9`` -- **on the reject branch only**. Do
not lift that pair of numbers out of this paragraph: the very next one shows
what a per-verifier floor alone leaves open, and neither figure is the shipped
guarantee. That is ``1.4139e-09``
(:func:`~sih141.protocol.verify.enforced_repudiation_bound`) and it needs all
three of the rules in 4b-iv.

**A local floor alone does not finish the job, and here is the hole it leaves.**
What ``exp(-2 m_min gap^2/8)`` bounds is: Bob accepts, and Charlie *reaches a
verdict of reject* -- or holds no matched record at all, which section 4b-i
showed is inside the same Hoeffding event. It does **not** cover a third outcome
that the floor itself creates: Charlie holding a matched set that is non-empty
but below *his* floor, on which he returns no verdict. Read as a transfer failure
counted against the scheme, that is a route the exponent does not close. A
log-reading Alice aims ``M`` at ``2 m_min`` exactly, using only clean matched
records: Bob accepts whenever ``m_B >= m_min``, Charlie is below his floor
whenever ``m_C < m_min``, and one fair coin per record decides the split of a
total whose mean is ``M/2 = m_min``. She wins with probability

.. code-block:: text

    (1 - P[Bin(2 m_min, 1/2) = m_min]) / 2   ->   1/2      as m_min grows

-- ``0.43`` at ``L = 360``, ``0.47`` at ``L = 600``, ``0.4985`` at
:data:`~sih141.protocol.params.DEFAULT_PARAMS`. The exponent is irrelevant
because nothing about the *rate* is being deviated; only the count is. Closed form ``(1 - C(2m,m) 2^-2m)/2``: ``0.432`` at ``L = 360``, ``0.466`` at
``L = 600``. Measured through the shipped seams with the per-verifier floor
alone: ``78/200`` and ``85/200`` -- see :ref:`split-coin-provenance` in
:mod:`sih141.protocol.verify` before quoting the counts.

.. _pooled-floor-analysis:

**4b-iv. The pooled floor, which is what closes it.** The quantity the bound is
exponential in is ``M = m_B + m_C``, and neither verifier knows it. So they
exchange it: one integer each way over the channel they already share for the
symmetrisation coins (:mod:`sih141.protocol.tally`). Two rules ride on that one
message, and they do different jobs.

*The pooled floor itself.* ``M >= M_min``, with ``M_min`` derived exactly as
``m_min`` was, from the same ``eps = 2**-64`` budget applied to the pooled law:

.. code-block:: text

    M ~ Binomial(2L, 1/n)          exactly, and not by independence
    d      = sqrt(2 ln(1/eps) n / (2L))
    M_min  = ceil((1 - d) 2L/n)    = 74190 at DEFAULT_PARAMS

The law needs a word, because the obvious derivation of it is invalid. After the
symmetrisation exchange ``m_B`` and ``m_C`` are **not** independent -- given the
records, ``m_C = M - m_B`` exactly -- so convolving the two marginals proves
nothing even though it happens to give the right answer. What makes the law exact
is *conservation*: the coins re-assign a fixed multiset of ``2L`` entries whose
bases were drawn i.i.d. uniform, so ``M`` is a sum of ``2L`` independent
indicators and the coins cannot move it at all.

The floor is worth having because it strictly exceeds the total the attack aims
at. Writing ``A = sqrt(2 mu ln(1/eps))`` with ``mu = L/n``,

.. code-block:: text

    m_min = mu - A         M_min = 2 mu - sqrt(2) A
    M_min - 2 m_min = (2 - sqrt 2) A ~ 0.586 A > 0,  growing like sqrt(L)

``1080`` records at :data:`~sih141.protocol.params.DEFAULT_PARAMS`, ``78`` at
``L = 600``, and positive at every ``L >= 140``. A declaration aimed at
``2 m_min`` is therefore refused outright rather than priced.

*The joint consequence, which the same message also buys.* The pooled floor alone
would not be enough, and it is worth being exact about why, because the failure
is invisible in the exponent. Against a pooled floor Alice simply re-aims at
``M = M_min`` and hopes the coins leave Charlie under his own floor: a deviation
of ``M_min/2 - m_min = (1 - sqrt2/2) A`` out of ``M_min ~ 2 mu`` fair coins, so

.. code-block:: text

    P <= exp(-2 (M_min/2 - m_min)^2 / M_min)         =  3.8553e-04   [Chernoff]
                       ->  eps ** (3 - 2 sqrt 2)     =  4.9487e-04   [asymptote]
    P  =  P[Bin(74190, 1/2) < 36555]                 =  3.6116e-05   [exact]

An earlier copy of this table quoted ``4.8e-05`` for the exact tail. No variant
of the calculation yields it -- the one-sided exact tail is ``3.6116e-05``, its
two-sided partner ``7.2233e-05``, the Chernoff form ``3.8553e-04`` and the
asymptote ``4.9487e-04``. The same stale figure is carried in
:mod:`sih141.protocol.verify` as this is written and is flagged for that
module's owner. All four values here are doctests below rather than prose, so
the next stale one fails the suite instead of surviving to an auditor.

The three prices are all of the same order and none of them is small enough to
live with, which is the point: the bound is **independent of ``L``**, because
the deviation grows like ``sqrt(L)`` and so does the noise. No key length
closes it, and no choice of the two floors inside the ``eps`` budget closes it
either, because the margin ``M_min/2 - m_min`` is capped by that same budget.
What closes it is making the *consequence* of the per-verifier floor joint: a
verifier below his own floor takes the other down with him
(:attr:`~sih141.protocol.verify.AbortReason.COUNTERPART_BELOW_FLOOR`). Then
"Bob accepts" implies "Charlie reached a verdict", the third outcome is not in
the outcome space at all, and the failure space is exhausted by the two
branches 4b-i already bounds.

**What is implemented, and what it is worth.**
:mod:`sih141.protocol.verify` applies all three floors -- ``m_B >= m_min``,
``m_C >= m_min``, ``m_B + m_C >= M_min`` -- so a verdict implies
``M >= max(2 m_min, M_min)`` and

.. code-block:: text

    P(repudiation) <= exp(-max(2 m_min, M_min) gap^2 / 8) = 1.41e-9

at :data:`~sih141.protocol.params.DEFAULT_PARAMS`, for every Alice strategy,
under both readings of the third outcome, with nothing left to quote beside it.
That is :func:`~sih141.protocol.verify.enforced_repudiation_bound`. The honest
cost is three exact binomial lower tails, ``2.5e-31 + 2.5e-31 + 2.9e-31 =
8.0e-31`` at those parameters, against a per-check budget of ``5.4e-20``.

This module cannot check any of it at import time -- ``analysis`` depends only on
``params`` and never imports ``verify`` -- so :func:`repudiation_bound_with_abort`
takes the floor as an argument, and the caller is responsible for passing one the
deployment actually enforces.

**Sections 4b-iii and 4b-iv as executable claims.** The numbers above are
doctests, not prose, because this project runs ``pytest --doctest-modules`` over
``sih141`` and a prose number is unverifiable by construction -- which is how the
``4.8e-05`` above and the ``1.9e-9`` attribution both survived. The block below
imports :mod:`sih141.protocol.verify`; that is a test-time cross-check against
the floors the shipped verifier really applies, not a module dependency.

>>> import math
>>> from sih141.protocol.analysis import (
...     _log_binomial_pmf_table,
...     _log_factorial_table,
...     _logsumexp,
...     matched_shortfall_probability,
... )
>>> from sih141.protocol.params import DEFAULT_PARAMS
>>> from sih141.protocol.verify import (
...     enforced_repudiation_bound,
...     minimum_matched_count,
...     minimum_pooled_matched_count,
... )
>>> m_min = minimum_matched_count(DEFAULT_PARAMS)
>>> M_min = minimum_pooled_matched_count(DEFAULT_PARAMS)
>>> m_min, M_min, M_min - 2 * m_min
(36555, 74190, 1080)

The four ways of pricing the coin split a pooled floor alone would leave open --
Chernoff, asymptote, exact one-sided, exact two-sided. ``4.8e-05`` is none of
them:

>>> f"{math.exp(-2 * (M_min / 2 - m_min) ** 2 / M_min):.4e}"
'3.8553e-04'
>>> epsilon = 2.0 ** -64
>>> f"{epsilon ** (3 - 2 * math.sqrt(2)):.4e}"
'4.9487e-04'
>>> log_factorial = _log_factorial_table(M_min)
>>> table = _log_binomial_pmf_table(M_min, 0.5, log_factorial)
>>> exact = math.exp(_logsumexp(table[:m_min]))
>>> f"{exact:.4e}", f"{2 * exact:.4e}"
('3.6116e-05', '7.2233e-05')

What the three floors and the joint consequence are worth together, and -- kept
executable so the two are never confused again -- the strictly weaker pair of
numbers the per-verifier floor supports on its own, which 4b-iii refutes as an
unconditional guarantee:

>>> f"{enforced_repudiation_bound(DEFAULT_PARAMS):.4e}"
'1.4139e-09'
>>> f"{math.exp(-max(2 * m_min, M_min) * DEFAULT_PARAMS.gap ** 2 / 8):.4e}"
'1.4139e-09'
>>> f"{math.exp(-2 * m_min * DEFAULT_PARAMS.gap ** 2 / 8):.4e}"
'1.9022e-09'
>>> f"{math.exp(-m_min * DEFAULT_PARAMS.gap ** 2 / 8):.4e}"
'4.3614e-05'

The honest cost of the three floors, against the ``eps = 2 ** -64`` budget each
was derived from:

>>> own = matched_shortfall_probability(DEFAULT_PARAMS, minimum_matched=m_min)
>>> pooled = matched_shortfall_probability(
...     DEFAULT_PARAMS, minimum_matched=M_min, pooled=True)
>>> f"{own:.1e}", f"{pooled:.1e}", f"{2 * own + pooled:.1e}"
('2.5e-31', '2.9e-31', '8.0e-31')
>>> f"{epsilon:.1e}"
'5.4e-20'

**What remains outside the number, named rather than left implicit.** Three
things, none of them a repudiation:

* *Denial of service.* A signer who starves the evidence base makes the run abort
  jointly. Nothing is transferred and Bob holds no signature he can be told he
  should have forwarded. No threshold defends against it -- Alice can equally
  decline to sign -- and section 5 says the same of the honest-abort numbers.
* *A recipient forcing an abort.* The pooled rule lets either verifier take the
  run down by reporting a low count. That is the same availability question: a
  recipient could always refuse to participate, and a false report can only
  withhold an acceptance, never manufacture one, since every acceptance still
  requires the accepting verifier's own rate to clear his own threshold on his
  own log.
* *The ordering cost.* Bob cannot accept before Charlie has reported, so the
  declaration reaches Charlie before Bob's verdict is final. Bob's verdict is no
  longer local. That is a change to the protocol's shape, not to its arithmetic,
  and :mod:`sih141.protocol.tally` states it in those terms.

*The older in-model bound* -- split at the midpoint, apply Hoeffding to whichever
of the two verifiers must deviate, optionally sharpen to relative entropy --
survives as :func:`symmetric_repudiation_bound`, correctly labelled as valid
only within family 4a. It is retained because it is the right yardstick for
:func:`repudiation_probability`, not because it is a guarantee. Comparing the
two is instructive: 4b's exponent is ``gap^2/8`` per matched *record* against
4a's ``gap^2/2`` per matched *position* -- a factor of two once the two counts
are put on the same footing -- and that factor, together with the smaller usable
``gap``, is the whole cost of making the statement true. What it does not buy,
and what no exponent can buy, is freedom from the counting assumption itself.

5. Robustness
-------------
An honest run *aborts* at party ``R`` when ``R`` fails to accept a genuine
signature: ``r_R > s`` or the matched set is empty. With ``e_R | m ~ Bin(m,
p_e)``,

.. code-block:: text

    P_abort(R) = (1-1/n)^L + sum_{m>=1} P(m) * P(Bin(m, p_e) > t(m))

(:func:`honest_abort_probability`). Bob's threshold is the tighter one, so Bob
dominates.

**That is the rate rule, and it is no longer the whole abort rule.**
:mod:`sih141.protocol.verify` also aborts on ``m_B < m_min``, on ``m_C < m_min``
and on ``m_B + m_C < M_min`` (sections 4b-iii and 4b-iv), and none of those three
conditions is modelled above or in :func:`honest_abort_bound`. At ``p_e = 0``
what is modelled is ``(1 - 1/n)^L`` alone, and the omitted term is the larger one
at every ``L``:

.. code-block:: text

    L       modelled (rate rule)     omitted (three floors)
    600     4.429e-106               1.740e-34
    1200    9.807e-212               3.691e-33
    4800    0.0      (underflow)     9.972e-32

so the published figure errs in the **flattering** direction -- the same class of
error as section 4b-ii, applied to robustness instead of repudiation. The honest
failure probability of the shipped protocol is the composition

.. code-block:: text

    P_fail = P_abort(rate rule)
           + 2 * P[m_R < m_min]        (matched_shortfall_probability)
           +     P[M   < M_min]        (matched_shortfall_probability, pooled)

which is what ``README`` and the Phase 5 tables report. The two terms are kept
in separate functions on purpose: they answer different questions -- how noisy a
channel the thresholds tolerate, and how small a matched set the floors tolerate
-- and a single fused number would hide which of the two moved. Both functions
name the omission in their own docstrings.

>>> from sih141.protocol.analysis import (
...     honest_abort_probability, matched_shortfall_probability)
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.verify import (
...     minimum_matched_count, minimum_pooled_matched_count)
>>> for length in (600, 1200, 4800):
...     small = ProtocolParams(key_length=length)
...     own = matched_shortfall_probability(
...         small, minimum_matched=minimum_matched_count(small))
...     pooled = matched_shortfall_probability(
...         small, minimum_matched=minimum_pooled_matched_count(small),
...         pooled=True)
...     print(length,
...           f"{honest_abort_probability(small):.3e}",
...           f"{2 * own + pooled:.3e}")
600 4.429e-106 1.740e-34
1200 9.807e-212 3.691e-33
4800 0.000e+00 9.972e-32

For ``p_e < s`` the conditional tail obeys

.. code-block:: text

    P(Bin(m,p_e) > s m | m) <= exp(-2 m (s - p_e)^2)      (Hoeffding)
                            <= exp(-m D(s || p_e))        (Chernoff-KL)

and the whole-run abort probability (either verifier aborting) follows from the
independence of the two records: ``P_B + P_C - P_B P_C`` exactly, or the union
bound ``P_B + P_C`` for the bounded version.

This is the one section where averaging over ``m`` needs nothing beyond honesty:
on an honest run the declaration *is* the key Alice drew before either recipient
chose a basis, so (IND) holds by construction. What these numbers do not describe
is a party who *wants* an abort. A signer reading the recipients' logs drives
both matched sets to ``0`` and fails the run with probability ``1``; that is a
denial of service against availability, not a break of the signature, no
threshold defends against it, and it is named here so that its absence from the
numbers is deliberate.

Where each bound is loose
-------------------------
Stated plainly, because a bound quoted without its slack is a number nobody can
argue with.

*Averaging over* ``m``
    Not a source of looseness -- a source of *assumption*, which is a different
    and worse axis, so it is listed first. ``E[exp(-mc)] = (1 - 1/n + e^-c/n)^L``
    is an identity and gives away nothing, but it is an identity about a random
    variable whose law is ``Binomial(L, 1/n)``, and that law is (IND). An
    adversary who violates (IND) does not make the average loose; he makes it
    describe a different experiment from the one being run. Every averaged number
    in this module is therefore conditional on a hypothesis about the *interface*
    -- see section 0 -- and the repudiation case, where the interface actually
    fails, is section 4b-ii. The commonly seen alternative, "assume ``m = L/3``",
    is worse still: not a bound in either direction, and it hides the same
    assumption behind a constant. That is why ``matched=`` is an explicit
    argument here, and why :func:`repudiation_bound` makes it mandatory.

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
    the derivation conditions on the records **and on the declaration**, and uses
    only the recipients' private coins, so there is no strategy class it fails to
    cover and no ``q`` to maximise over. That property belongs to the conditional
    statement at the observed ``M``; it does **not** survive the average over
    ``M``, which is a separate claim needing (IND) and is the one that was
    over-advertised. See section 4b.

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
:func:`forgery_bound`, :func:`recipient_forgery_bound` and, for repudiation,
:func:`repudiation_bound` at the run's own ``m_B + m_C``; and reserve the exact
functions for the short key lengths where a cross-check against simulation is
affordable. That is the regime ``tests/test_protocol_analysis.py`` works in.
:func:`matched_shortfall_probability` is ``O(L)`` and also cheap.

A report that has to print one repudiation number *before* a run exists should
print :func:`~sih141.protocol.verify.enforced_repudiation_bound` --
:func:`repudiation_bound_with_abort` evaluated at the pooled floor the shipped
verifier really applies, ``1.41e-9`` at
:data:`~sih141.protocol.params.DEFAULT_PARAMS`. The alternatives are
:func:`averaged_repudiation_bound` with (IND) printed beside it, or the honest
``1/2`` of section 4b-iii for a deployment that enforces no floor at all.
Printing the averaged figure alone is the specific mistake this module refuses to
make convenient.

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
    "matched_shortfall_probability",
    "depolarising_error_rate",
    "honest_statistics",
    "forgery_probability",
    "forgery_bound",
    "recipient_forgery_probability",
    "recipient_forgery_bound",
    "repudiation_probability",
    "repudiation_bound",
    "averaged_repudiation_bound",
    "repudiation_bound_with_abort",
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
    """Validate ``params`` and reduce it to the positions that carry key.

    Every public entry point in this module routes its parameter set through
    here, so this is the one place the two lengths a checked run has can be told
    apart.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set to validate.
    name : str, optional
        Argument name quoted in the error message.

    Returns
    -------
    ProtocolParams
        The same object when no check rounds are reserved, otherwise
        ``params.sifted()`` -- the parameter set describing only the positions
        that actually carry key.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`. It is not coerced from a
        mapping on purpose: every guarantee in this module rests on the
        ``s_a < s_v < 1/2`` validation that the class performs, and a duck-typed
        stand-in would skip it.

    Notes
    -----
    **Why the sifting happens here, and why it is a security fix rather than
    tidiness.** Every closed form below counts Bernoulli trials against
    ``params.key_length`` -- ``Binomial(L, 1/|B|)`` for one verifier's matched
    set, ``Binomial(2L, 1/|B|)`` for the pair -- because when they were written
    every round was a key position. Phase 3 added sampled check rounds, which
    divert a fraction of the positions to parameter estimation and exclude them
    from the key. Handed such a parameter set unreduced, this module counted the
    diverted positions as evidence and returned a bound that was *too good*: at
    ``check_fraction = 0.1`` it claimed 38400 expected matched positions where
    the truth is 34560, an 11% overcount, and the bounds are exponential in that
    count. Erring in the flattering direction is the failure mode this project
    has already shipped three times, so it is closed at the choke point rather
    than at twenty call sites where the twenty-first would be missed.

    ``sifted()`` is idempotent and is the identity on a parameter set that
    reserves no check rounds, so nothing published from ``DEFAULT_PARAMS``
    moves.

    Examples
    --------
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> _as_params(DEFAULT_PARAMS) is DEFAULT_PARAMS
    True
    >>> checked = DEFAULT_PARAMS.with_check_fraction(0.10)
    >>> checked.key_length, _as_params(checked).key_length
    (115200, 103680)
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"{name} must be a ProtocolParams, got {type(params).__name__}. "
            f"Build one with ProtocolParams(key_length=...) or "
            f"ProtocolParams.from_dict(...); the closed forms in this module are "
            f"only valid for a parameter set that passed its s_a < s_v < 1/2 "
            f"validation."
        )
    return params.sifted() if params.check_fraction else params


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


def _as_matched(matched: Any, *, name: str = "matched") -> int:
    """Coerce and check an explicit matched-set size.

    Parameters
    ----------
    matched : int
        The number of matched positions to condition on. Must be positive: with
        an empty matched set there is no rate and therefore no bound to state.
    name : str, optional
        Argument name quoted in the error messages.

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
            f"{name} must be a positive integer, got the boolean {matched!r}"
        )
    if not isinstance(matched, numbers.Integral):
        raise TypeError(
            f"{name} must be a positive integer, got {type(matched).__name__}; "
            f"it counts positions."
        )
    value = int(matched)
    if value < 1:
        raise ValueError(
            f"{name} must be at least 1, got {value}. Conditioning on an empty "
            f"matched set states a bound on a decision that is never taken -- "
            f"verify() raises there. Pass matched=None to average over the "
            f"Binomial(L, 1/|B|) distribution of the matched-set size instead, "
            f"which handles m = 0 correctly."
        )
    return value


def _as_matched_records(matched_records: Any) -> int:
    """Coerce the observed total matched-record count ``M = m_B + m_C``.

    Parameters
    ----------
    matched_records : int
        The number of matched records held by the two verifiers *together*,
        as observed on the run being reported. There is no ``None`` here on
        purpose; see the error message.

    Returns
    -------
    int
        ``matched_records`` as a plain int.

    Raises
    ------
    TypeError
        If ``matched_records`` is a boolean or not an integer.
    ValueError
        If ``matched_records`` is ``None``, or is not positive.
    """
    if matched_records is None:
        raise ValueError(
            "repudiation_bound requires the observed matched-record count "
            "M = m_B + m_C; there is no averaged default. Averaging over "
            "M ~ Binomial(2L, 1/|B|) assumes the declared bases are "
            "independent of the recipients' logged bases (assumption (IND) in "
            "this module's docstring), which a signer reading both raw logs "
            "violates -- that adversary pins M at 13 for every L and repudiates "
            "with probability 1/2, against an averaged bound of 6.9e-10 at the "
            "shipped defaults. Pass matched_records=bob.matched_count + "
            "charlie.matched_count from the run's two VerificationResults for "
            "the per-run guarantee, "
            "repudiation_bound_with_abort(...) for an a-priori one, or "
            "averaged_repudiation_bound(params, signer_sees_recipient_bases="
            "False) if (IND) is genuinely enforced by your deployment."
        )
    return _as_matched(matched_records, name="matched_records")


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
        nevertheless averaged over ``m`` here, since averaging is exact rather
        than approximate. Both statements describe a matched count that is
        binomial, i.e. both assume (IND); an adversary who chooses the
        declaration from the recipient's log is not near ``E[|M_R|]`` at all,
        and this ratio says nothing about him.
        """
        return math.sqrt(self.variance) / self.expected


def matched_statistics(params: ProtocolParams) -> MatchedStatistics:
    """Return the exact distributional summary of the matched-set size.

    Both Alice and each recipient draw bases uniformly and independently from
    ``params.bases``, so a position is scored with probability ``1/|B|`` and the
    indicators are independent across positions: ``|M_R| ~ Binomial(L, 1/|B|)``.
    Section 1 of the module docstring derives it, including the fact that the
    same distribution holds against a *forged* declaration.

    That last clause is assumption (IND), not a theorem: it holds for any
    declaration chosen without sight of the recipient's logged bases, and fails
    outright for one chosen with it, where ``|M_R|`` is whatever the adversary
    wants it to be. Everything returned here is a statement about an honest run
    or an (IND)-respecting adversary.

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

    The binomial law is assumption (IND) -- see section 0 of the module
    docstring. This is the distribution of the matched count on an honest run, or
    against any declaration chosen without sight of the recipient's logged bases;
    it is not the distribution an adversary with that sight produces.

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

    An honest run satisfies (IND) by construction -- Alice declares the key she
    drew before either recipient chose a basis -- so the averaging here needs no
    hypothesis beyond honesty itself. It is a description of a good run, not a
    bound on a bad one.

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
    **It also assumes (IND).** The sum above weights ``P(Bin(L, 1/|B|) = m)``,
    which is the law of the matched count only while Eve's declared bases are
    independent of the verifier's logged ones -- section 0. That is part of the
    stated adversary model rather than an oversight (Eve holds no record and the
    ``c_i`` are never published), but it is an assumption about what the
    surrounding code lets her see, and if it fails her acceptance probability
    rises to ``1/2`` regardless of ``L``. See section 3 for that calculation.

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
        conditional bound -- which needs no assumption about how the declaration
        was chosen. If ``None`` (the default), average over the matched count,
        which is exact under (IND) and is the honest thing to report for a run
        whose ``m`` is not yet known *and* whose forger cannot see the
        verifier's logged bases. Section 0 says what happens when she can; the
        short version is that ``matched=1`` is then the honest number.

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

    ``m ~ Bin(L, p_s)`` presumes the forger cannot see the bases his target
    logged on the *retained* positions -- assumption (IND) in the shape it takes
    for this adversary, spelled out in section 3b. He is granted everything else:
    his own records, which positions were swapped, and Charlie's entry verbatim
    on each of them. One more item and there is no bound at all.

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

        The averaged form assumes the forger cannot see the bases his *target*
        logged on the retained positions -- section 3b. That is (IND) again, in
        the shape it takes for this adversary, and it is a statement about what
        :mod:`sih141.protocol.symmetrise` reveals. If it fails, ``rho`` collapses
        to ``0`` and no bound below ``1`` exists; the conditional form remains
        exactly as valid as the rate it is fed.

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
    repudiation_bound : The guarantee, uniform over *every* Alice strategy, at
        the matched-record count a run actually produced.
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

    The narrowness cuts one useful way: because the family is defined by a
    single ``q`` applied to states Alice prepared, it contains no strategy that
    reads the recipients' logs, so the ``m ~ Bin(L, 1/|B|)`` factors here are
    consistent with the family rather than assumed on top of it. That is the only
    sense in which this expression is safe from the failure of section 4b-ii, and
    it is bought by covering almost nothing.

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


def repudiation_bound(params: ProtocolParams, *, matched_records: int) -> float:
    """Per-run repudiation bound, valid for **every** Alice strategy.

    The scheme's non-repudiation guarantee, and the only statement in this module
    that is one with no hypothesis attached. Section 4b-i of the module docstring
    derives it; the structure is what matters here:

    * It conditions on the two recipients' raw records **and on the
      declaration** -- whatever Alice prepared, however asymmetric, adaptive or
      entangled, and whatever she computed the declaration from, both raw logs
      included. There is no adversary model left to be wrong about, no
      per-position ``q``, and no independence assumption of any kind.
    * The only randomness used is the recipients' private symmetrisation coins
      (:mod:`sih141.protocol.symmetrise`), which Alice can neither see nor
      influence. Those coins split a *fixed* total of matched and mismatched
      records between the two verifiers, so ``M = m_B + m_C`` and ``e_B + e_C``
      are constants and repudiation demands a large deviation of the split.
    * Hoeffding over ``L`` independent two-point coin variables, of which at
      most ``M`` have non-zero range, gives the result. The ``m_C = 0`` corner
      needs no separate term: it forces ``m_B = M`` and ``e_B = E``, and Bob's
      acceptance then *is* the deviation event, reached non-strictly.

    .. code-block:: text

        P(repudiation | records, declaration)  <=  exp(-M gap^2 / 8)

    **Without symmetrisation this bound does not apply and no bound does**: the
    protocol variant produced by
    :func:`sih141.protocol.symmetrise.no_symmetrisation` is repudiable with
    probability ``1`` at every ``L``.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    matched_records : int
        The number of matched records held by the two verifiers **together**,
        ``M = m_B + m_C``, as *observed on the run being reported*. Mandatory,
        and mandatory on purpose: the averaged form is a different claim needing
        a different function (:func:`averaged_repudiation_bound`). Note the
        count is over the pair, so its honest-run mean is ``2L/|B|``, not the
        per-verifier ``L/|B|``.

        Passing an *expected* count rather than an observed one -- ``2L//3``,
        say -- quietly restores the assumption this signature exists to expose,
        because the expectation is only the right number while the declaration is
        independent of the recipients' logged bases. Read ``M`` off the run:
        ``result_bob.matched_count + result_charlie.matched_count``.

        Both counts must be against the **same** declaration. The conservation
        laws ``m_B + m_C = M`` and ``e_B + e_C = E`` hold because the two
        verifiers score one fixed pair of records against one fixed declaration;
        a run in which the forwarding hop altered the signature between them
        (:attr:`sih141.protocol.session.SessionTranscript.forwarded_signature`)
        is not a repudiation experiment at all, and no count from it belongs
        here.

    Returns
    -------
    float
        An upper bound in ``[0, 1]``, decreasing in ``matched_records``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams` or ``matched_records`` is
        not an integer.
    ValueError
        If ``matched_records`` is ``None`` or is not positive.

    See Also
    --------
    averaged_repudiation_bound : The same bound averaged over ``M``, which needs
        assumption (IND) and must not be quoted as unconditional.
    repudiation_bound_with_abort : The a-priori guarantee an abort rule buys.
    symmetric_repudiation_bound : The tighter bound for the narrow model.
    repudiation_probability : The exact in-model probability.

    Notes
    -----
    Small ``M`` is not a hypothetical. A signer who reads both recipients' raw
    logs -- which :class:`~sih141.protocol.session.QDSSession` hands the
    ``Signer`` seam -- can pin ``M = 13`` at every ``L`` and repudiate with
    probability exactly ``1/2`` (section 4b-ii). This function reports ``0.9964``
    for that run, which is correct, useless as reassurance, and exactly the point:
    a bound that stays near ``1`` when the evidence is thin is telling the truth
    about a run with thin evidence.

    Examples
    --------
    >>> from sih141.protocol.analysis import repudiation_bound
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> f"{repudiation_bound(DEFAULT_PARAMS, matched_records=76800):.2e}"
    '6.90e-10'
    >>> round(repudiation_bound(DEFAULT_PARAMS, matched_records=13), 4)
    0.9964
    """
    checked = _as_params(params)
    limit = _as_matched_records(matched_records)
    exponent = checked.gap**2 / 8.0
    return _conditional_or_averaged(
        2 * checked.key_length, checked.match_probability, exponent, limit
    )


def averaged_repudiation_bound(
    params: ProtocolParams, *, signer_sees_recipient_bases: bool
) -> float:
    """Repudiation bound averaged over ``M``. **Requires assumption (IND).**

    The number this package published for a year as its non-repudiation
    guarantee, ``6.9e-10`` at :data:`~sih141.protocol.params.DEFAULT_PARAMS`. It
    is a real bound and it is not a guarantee, because it averages the per-run
    bound of :func:`repudiation_bound` over

    .. code-block:: text

        M ~ Binomial(2L, 1/n)      <-- this line is the assumption

        P_rep <= (1 - 1/n)^L + (1 - 1/n + exp(-gap^2/8)/n)^(2L)

    and ``M`` has that law only while the declared bases are independent of the
    recipients' logged bases -- assumption (IND) of the module docstring. The
    matched set is ``{i : c_i == d_i}``, so a signer who reads the logs chooses
    it, and chooses it small.

    **The concrete strategy that breaks it.** Alice reads both raw logs (the
    ``Signer`` seam of :class:`~sih141.protocol.session.QDSSession` is handed
    them), declares at every position a basis appearing in neither log, and keeps
    twelve exceptions: eleven where she declares Bob's basis and Bob's outcome,
    and one -- where the two logs used the same basis and recorded opposite
    outcomes -- where she declares that basis and Bob's outcome. Then ``M = 13``
    with probability ``1`` at every ``L``, one of the thirteen matched records is
    wrong, one exchange coin decides who scores it, and she repudiates with
    probability exactly ``1/2``. Measured: ``0.45`` to ``0.53`` over this
    package's own simulator at ``L = 600`` and ``L = 115200``; an independent
    audit measured ``0.46`` to ``0.58`` with a different construction. Against
    ``6.9e-10``. The per-run bound at that ``M`` is ``0.9964`` and is not
    violated.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    signer_sees_recipient_bases : bool
        Mandatory, and an assertion about the deployment rather than a switch.
        Pass ``False`` to state that no party able to choose the declaration can
        see either recipient's logged bases -- then (IND) holds and the returned
        number means what it says. ``True`` raises: there is no averaged bound in
        that case, and the honest options are named in the message.

    Returns
    -------
    float
        An upper bound in ``[0, 1]``, valid under (IND).

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, or
        ``signer_sees_recipient_bases`` is not a bool.
    ValueError
        If ``signer_sees_recipient_bases`` is ``True``.

    See Also
    --------
    repudiation_bound : The per-run guarantee, which needs no assumption.
    repudiation_bound_with_abort : The a-priori guarantee an abort rule buys.

    Notes
    -----
    The ``(1 - 1/n)**L`` term is a legacy allowance for the ``m_C = 0`` corner.
    Section 4b-i shows the corner is already inside the Hoeffding event, so the
    term is pure slack -- at the shipped defaults it is ``e^-46679``, i.e. ``0.0``
    in double precision -- but it is retained here because it is the expression
    printed in :mod:`sih141.protocol.params` and ``docs/PHASE2.md``, and dropping
    it would make the published figure and the code disagree by a term that
    cannot matter. It is *also* a statement about the recipients' basis draws
    rather than their coins, so it is (IND)-dependent too, which is a second
    reason it has no business in :func:`repudiation_bound`.

    Examples
    --------
    >>> from sih141.protocol.analysis import averaged_repudiation_bound
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> assuming_ind = averaged_repudiation_bound(
    ...     DEFAULT_PARAMS, signer_sees_recipient_bases=False
    ... )
    >>> f"{assuming_ind:.2e}"
    '6.92e-10'
    >>> averaged_repudiation_bound(
    ...     DEFAULT_PARAMS, signer_sees_recipient_bases=True
    ... )
    Traceback (most recent call last):
        ...
    ValueError: no averaged repudiation bound is valid when the signer can see...
    """
    checked = _as_params(params)
    if not isinstance(signer_sees_recipient_bases, bool):
        raise TypeError(
            f"signer_sees_recipient_bases must be a bool, got "
            f"{type(signer_sees_recipient_bases).__name__}. It asserts a fact "
            f"about the deployment -- whether anyone who can choose the "
            f"declaration can also read the recipients' logged bases -- not a "
            f"rate or a count."
        )
    if signer_sees_recipient_bases:
        raise ValueError(
            "no averaged repudiation bound is valid when the signer can see the "
            "recipients' logged bases: the matched set is {i : c_i == d_i}, so "
            "she chooses M rather than drawing it from Binomial(2L, 1/|B|), and "
            "the strategy in section 4b-ii pins M = 13 at every L and repudiates "
            "with probability 1/2. Use repudiation_bound(params, "
            "matched_records=<observed m_B + m_C>) for the per-run guarantee, or "
            "verify.enforced_repudiation_bound(params) for the a-priori one the "
            "shipped floors earn. repudiation_bound_with_abort(params, "
            "minimum_matched_records=...) is the same expression at a floor you "
            "name, and must be read with the event it covers (sections 4b-iii "
            "and 4b-iv) rather than as a blanket number."
        )
    exponent = checked.gap**2 / 8.0
    coin_term = _averaged_exponential_bound(
        2 * checked.key_length, checked.match_probability, exponent
    )
    # Legacy allowance for the m_C = 0 corner; slack, but it is the published
    # expression. See the Notes section.
    empty = (1.0 - checked.match_probability) ** checked.key_length
    return min(1.0, coin_term + empty)


def repudiation_bound_with_abort(
    params: ProtocolParams, *, minimum_matched_records: int
) -> float:
    """A-priori repudiation bound for a verifier that aborts on thin evidence.

    The honest answer to "what unconditional number can this scheme quote?".
    Section 4b-iii of the module docstring: without an abort rule, none below
    ``1/2``, because a signer who reads the recipients' logs repudiates with
    probability ``1/2`` at every key length. With one, the per-run bound of
    :func:`repudiation_bound` evaluated at the floor the rule enforces:

    .. code-block:: text

        P(repudiation)  <=  exp(-m_min gap^2 / 8)

    for **every** Alice strategy, with no (IND) and no model of her at all. The
    argument is one line. Repudiation requires Bob to accept, the rule lets him
    accept only when his own matched set has at least ``m_min`` entries, and
    ``M = m_B + m_C >= m_B``; so on the repudiation event ``M >= m_min``, and off
    it there is nothing to bound.

    Two rules qualify. A **local** one -- Bob refuses unless ``|M_B| >= m_min`` --
    needs no extra communication, since Bob knows his own count. A **pooled** one
    -- abort unless ``m_B + m_C >= M_min`` -- is stronger for the same standard
    deviation, because the pooled count is twice as large, but costs one extra
    classical message between the verifiers
    (:mod:`sih141.protocol.tally`). Either way the argument here is the floor on
    ``M``, so pass whichever floor the rule guarantees.

    **Read the event carefully.** What is bounded is: Bob accepts, and Charlie
    either reaches a verdict of *reject* or holds no matched record at all. A
    per-verifier floor applied at Charlie as well creates a third outcome -- a
    non-empty matched set below his floor, on which he returns no verdict -- and
    this expression does not cover it. Section 4b-iii gives the attack that
    outcome admits (a log-reading Alice aims ``M`` at ``2 m_min`` and splits the
    coins, winning with probability ``~1/2``, measured ``85/200`` at
    ``L = 600``). Whether this function's number is a guarantee or a
    guarantee-shaped one therefore depends entirely on what the deployment does
    about that outcome, and section 4b-iv gives the two rules that close it: the
    pooled floor, and making the per-verifier floor's consequence *joint* so
    that a verifier below his own floor takes the other down with him.

    :mod:`sih141.protocol.verify` applies both, so on the shipped code "Bob
    accepts" implies "Charlie reached a verdict" and the third outcome does not
    exist. This module cannot check that -- ``analysis`` depends only on
    ``params`` -- so the floor is an argument, and the caller is responsible for
    passing one the deployment actually enforces. **Rather than choose one, call
    :func:`~sih141.protocol.verify.enforced_repudiation_bound`**, which reads
    the shipped floors and evaluates this function at
    ``max(2 m_min, M_min)``. That is ``1.41e-09`` at the shipped defaults, and
    it is the only a-priori repudiation figure this package is entitled to
    publish.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    minimum_matched_records : int
        The floor on ``M = m_B + m_C`` that the abort rule guarantees on any run
        a verifier is willing to accept. For a local rule at Bob this is his own
        ``m_min``; for a pooled rule it is ``M_min``.

    Returns
    -------
    float
        An upper bound in ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams` or
        ``minimum_matched_records`` is not an integer.
    ValueError
        If ``minimum_matched_records`` is not positive.

    See Also
    --------
    matched_shortfall_probability : What the rule costs an honest run.
    repudiation_bound : The same bound at an observed rather than a floored ``M``.

    Examples
    --------
    All three rows use floors :mod:`sih141.protocol.verify` actually enforces, so
    the numbers are the shipped ones rather than an illustration. Bob's own floor
    alone buys ``4.4e-05``; both verifiers' own floors buy ``1.9e-09``; the
    pooled floor buys ``1.4e-09`` and, unlike the other two, leaves no third
    outcome to be quoted beside it. The honest-run cost is far below every other
    failure probability in the scheme, which is what makes the rules worth
    having.

    >>> from sih141.protocol.analysis import (
    ...     matched_shortfall_probability, repudiation_bound_with_abort
    ... )
    >>> from sih141.protocol.params import DEFAULT_PARAMS
    >>> from sih141.protocol.verify import (
    ...     minimum_matched_count, minimum_pooled_matched_count
    ... )
    >>> floor = minimum_matched_count(DEFAULT_PARAMS)
    >>> pooled_floor = minimum_pooled_matched_count(DEFAULT_PARAMS)
    >>> floor, pooled_floor
    (36555, 74190)
    >>> local = repudiation_bound_with_abort(
    ...     DEFAULT_PARAMS, minimum_matched_records=floor
    ... )
    >>> both = repudiation_bound_with_abort(
    ...     DEFAULT_PARAMS, minimum_matched_records=2 * floor
    ... )
    >>> pooled = repudiation_bound_with_abort(
    ...     DEFAULT_PARAMS, minimum_matched_records=pooled_floor
    ... )
    >>> f"{local:.1e}", f"{both:.1e}", f"{pooled:.1e}"
    ('4.4e-05', '1.9e-09', '1.4e-09')
    >>> cost = matched_shortfall_probability(
    ...     DEFAULT_PARAMS, minimum_matched=floor
    ... )
    >>> pooled_cost = matched_shortfall_probability(
    ...     DEFAULT_PARAMS, minimum_matched=pooled_floor, pooled=True
    ... )
    >>> f"{cost:.1e}", f"{pooled_cost:.1e}"
    ('2.5e-31', '2.9e-31')
    """
    checked = _as_params(params)
    floor = _as_matched(minimum_matched_records, name="minimum_matched_records")
    exponent = checked.gap**2 / 8.0
    return _conditional_or_averaged(
        2 * checked.key_length, checked.match_probability, exponent, floor
    )


def matched_shortfall_probability(
    params: ProtocolParams, *, minimum_matched: int, pooled: bool = False
) -> float:
    """Probability that an **honest** run falls short of an abort threshold.

    The price of the rule :func:`repudiation_bound_with_abort` presumes, stated
    as the number it costs robustness. On an honest run the matched count is
    binomial -- ``Bin(L, 1/|B|)`` for one verifier's own count, ``Bin(2L, 1/|B|)``
    for the two pooled -- so

    .. code-block:: text

        P(shortfall) = P(Bin(trials, 1/n) < minimum_matched)

    summed exactly, in log space, over the whole lower tail.

    The count is concentrated: its standard deviation is ``sqrt(2L/9) = 160`` at
    :data:`~sih141.protocol.params.DEFAULT_PARAMS` against a mean of ``38400``,
    so the shipped floor of ``36555``
    (:func:`~sih141.protocol.verify.minimum_matched_count`, eleven standard
    deviations low) costs an honest verifier ``2.5e-31``. The pooled count is
    twice as large with only ``sqrt(2)`` times the spread, so the shipped pooled
    floor of ``74190``
    (:func:`~sih141.protocol.verify.minimum_pooled_matched_count`) costs
    ``2.9e-31`` while flooring ``M`` a further ``1080`` records above the
    ``73110`` the two per-verifier floors give. That asymmetry -- a Gaussian-tail
    cost against an exponential-in-the-floor gain -- is the whole argument for
    the abort rules.

    The pooled law is ``Binomial(2L, 1/n)`` *exactly*, but not because the two
    verifiers' counts are independent: after the symmetrisation exchange they are
    perfectly dependent given the records. It is exact because the coins conserve
    the multiset of ``2L`` entries, whose bases were drawn i.i.d. -- see section
    4b-iv, and ``tests/test_protocol_tally.py``, which measures both halves.

    Like every other honest-run number here this one assumes (IND); an adversary
    who chooses the declaration from the logs can drive the matched count to
    ``0`` at will, which is precisely why the rules are worth having.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set.
    minimum_matched : int
        The abort threshold. The returned probability is for *strictly* fewer
        than this many matched entries, matching the rule "accept only if the
        count is at least ``minimum_matched``". With ``minimum_matched=1`` this
        is exactly :attr:`MatchedStatistics.empty_probability`.
    pooled : bool, optional
        ``False`` (the default) for one verifier's own count, ``Bin(L, 1/|B|)``,
        which is the locally checkable rule. ``True`` for the two verifiers'
        counts pooled, ``Bin(2L, 1/|B|)``, which is the rule needing one extra
        classical message.

    Returns
    -------
    float
        A probability in ``[0, 1]``.

    Raises
    ------
    TypeError
        If ``params`` is not a :class:`ProtocolParams`, ``minimum_matched`` is
        not an integer, or ``pooled`` is not a bool.
    ValueError
        If ``minimum_matched`` is not positive.

    See Also
    --------
    repudiation_bound_with_abort : What the rule buys.
    matched_statistics : Mean, variance and the ``m = 0`` corner.
    honest_abort_probability : The *other* half of the shipped protocol's honest
        failure probability -- the rate rule, which omits these floors and is
        the smaller term at low noise.
    honest_abort_bound : The bounded form of that other half, with the same
        omission.

    Examples
    --------
    >>> from sih141.protocol.analysis import (
    ...     matched_shortfall_probability, matched_statistics
    ... )
    >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
    >>> params = ProtocolParams(key_length=30)
    >>> matched_shortfall_probability(params, minimum_matched=1) == (
    ...     matched_statistics(params).empty_probability
    ... )
    True
    >>> cost = matched_shortfall_probability(
    ...     DEFAULT_PARAMS, minimum_matched=73110, pooled=True
    ... )
    >>> f"{cost:.1e}"
    '1.4e-60'

    The three shipped floors and what they cost an honest run -- the figures
    this docstring quotes, as tests rather than as prose:

    >>> from sih141.protocol.verify import (
    ...     minimum_matched_count, minimum_pooled_matched_count)
    >>> m_min = minimum_matched_count(DEFAULT_PARAMS)
    >>> M_min = minimum_pooled_matched_count(DEFAULT_PARAMS)
    >>> m_min, M_min, M_min - 2 * m_min
    (36555, 74190, 1080)
    >>> own = matched_shortfall_probability(
    ...     DEFAULT_PARAMS, minimum_matched=m_min)
    >>> pooled = matched_shortfall_probability(
    ...     DEFAULT_PARAMS, minimum_matched=M_min, pooled=True)
    >>> f"{own:.1e}", f"{pooled:.1e}", f"{2 * own + pooled:.1e}"
    ('2.5e-31', '2.9e-31', '8.0e-31')
    """
    checked = _as_params(params)
    threshold = _as_matched(minimum_matched, name="minimum_matched")
    if not isinstance(pooled, bool):
        raise TypeError(
            f"pooled must be a bool, got {type(pooled).__name__}. It selects "
            f"which count the abort rule reads -- one verifier's own "
            f"Binomial(L, 1/|B|) or the pair's Binomial(2L, 1/|B|) -- not a "
            f"count itself."
        )
    trials = 2 * checked.key_length if pooled else checked.key_length
    if threshold > trials:
        return 1.0
    log_factorial = _log_factorial_table(trials)
    log_pmf = _log_binomial_pmf_table(
        trials, checked.match_probability, log_factorial
    )
    total = _logsumexp(log_pmf[:threshold])
    return 0.0 if total == -math.inf else min(1.0, math.exp(total))


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
        and on nothing wider. In particular it is *not* an upper bound on
        repudiation: :func:`repudiation_bound` at the observed ``M`` is, and it
        is the larger number.

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

    The in-model number is far below the guarantee at the same evidence -- 38400
    matched positions each, so 76800 matched records -- which is the price of
    covering every strategy rather than one family:

    >>> symmetric_repudiation_bound(
    ...     DEFAULT_PARAMS, matched=38400
    ... ) < repudiation_bound(DEFAULT_PARAMS, matched_records=76800)
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
    noiseless run never produces a single mismatch, so the only way to fail *by
    this rule* is to have no evidence at all.

    **What this function does not include.** The rule above is the rate rule,
    and it is not the whole abort rule the shipped verifier applies.
    :mod:`sih141.protocol.verify` also aborts when ``m_B < m_min``, when
    ``m_C < m_min`` or when ``m_B + m_C < M_min`` (the
    matched-count floors of :mod:`sih141.protocol.analysis` sections 4b-iii and
    4b-iv), and **none of those three conditions is modelled here**. The number
    returned is therefore a *lower* bound on the honest failure probability of
    the shipped protocol, and at low noise it is lower by enormous factors,
    because the omitted term is the larger one:

    .. code-block:: text

        p_e = 0     this function            the three floors
        L = 600     4.429e-106               1.740e-34
        L = 1200    9.807e-212               3.691e-33
        L = 4800    0.0      (underflow)     9.972e-32

    That is an error in the *flattering* direction, so it is named rather than
    left to be discovered. Quote the composition, never this term alone:

    .. code-block:: text

        P_fail = honest_abort_probability(params)
               + 2 * matched_shortfall_probability(
                         params, minimum_matched=m_min)
               +     matched_shortfall_probability(
                         params, minimum_matched=M_min, pooled=True)

    with ``m_min`` from :func:`~sih141.protocol.verify.minimum_matched_count` and
    ``M_min`` from :func:`~sih141.protocol.verify.minimum_pooled_matched_count`.
    ``README`` composes it that way. The split is deliberate -- the rate term
    says what noise the thresholds tolerate and the count term says what matched
    set the floors tolerate, and one fused number would hide which of the two
    moved -- but it means the raw return value of this function is not the
    protocol's robustness figure.

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
        a great deal at small ``p_e``. It omits the same three floors.
    matched_shortfall_probability : The matched-count floors' contribution, which
        this function excludes and which dominates it at low noise. Add it to
        get the shipped protocol's honest failure probability.
    sih141.protocol.verify.minimum_matched_count : The per-verifier floor
        ``m_min`` the composition needs.
    sih141.protocol.verify.minimum_pooled_matched_count : The pooled floor
        ``M_min`` the composition needs.

    Notes
    -----
    This is the one family of numbers here where averaging over ``m`` is not an
    assumption about an adversary: the declaration on an honest run *is* Alice's
    own key, drawn before either recipient chose a basis, so (IND) holds by
    construction. What the number does not cover is a party who wants an abort --
    a signer who reads the recipients' logs can drive both matched sets to ``0``
    and force a failure with probability ``1``. That is a denial of service, not
    a break of the signature, and no threshold defends against it; it is out of
    scope here and is called out in section 0 so that the omission is deliberate
    rather than implied.

    Examples
    --------
    >>> from sih141.protocol.analysis import honest_abort_probability
    >>> from sih141.protocol.params import ProtocolParams
    >>> params = ProtocolParams(key_length=30)
    >>> honest_abort_probability(params, party="Bob") < 1e-4
    True

    The floors this function excludes dominate it at ``p_e = 0``, so the two
    have to be composed:

    >>> from sih141.protocol.analysis import matched_shortfall_probability
    >>> from sih141.protocol.verify import (
    ...     minimum_matched_count, minimum_pooled_matched_count)
    >>> small = ProtocolParams(key_length=600)
    >>> f"{honest_abort_probability(small):.3e}"
    '4.429e-106'
    >>> own = matched_shortfall_probability(
    ...     small, minimum_matched=minimum_matched_count(small))
    >>> pooled = matched_shortfall_probability(
    ...     small, minimum_matched=minimum_pooled_matched_count(small),
    ...     pooled=True)
    >>> f"{2 * own + pooled:.3e}"
    '1.740e-34'
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

    **What this bound does not include.** Exactly what
    :func:`honest_abort_probability` omits, and for the same reason: this
    bounds the *rate* rule ``r_R > s`` (with the empty matched set valued at
    ``1`` by the binomial average) and models none of the three
    matched-count floors the shipped verifier applies -- ``m_B >= m_min``,
    ``m_C >= m_min``, ``m_B + m_C >= M_min``. It is consequently **not** an upper
    bound on the honest failure probability of the shipped protocol; it is an
    upper bound on one of that probability's two terms. Add
    :func:`matched_shortfall_probability` at each floor, as
    :func:`honest_abort_probability` spells out, before publishing a robustness
    figure. At ``p_e = 0`` the floors' term is the larger of the two at every
    ``L`` once the rate term is evaluated honestly -- exactly, or with
    ``method="kl"``. The Hoeffding form is loose enough at small ``L`` to sit
    above the total by accident, which is slack rather than coverage and is not
    something to publish.

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

    See Also
    --------
    honest_abort_probability : The exact rate-rule probability, and the
        composition that turns either of these into the shipped protocol's
        honest failure probability.
    matched_shortfall_probability : The matched-count floors' contribution, which
        this bound excludes.
    sih141.protocol.verify.minimum_matched_count : The per-verifier floor.
    sih141.protocol.verify.minimum_pooled_matched_count : The pooled floor.

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

    It bounds the rate term only, and that is not a technicality. With
    ``method="kl"`` at ``L = 600`` and ``p_e = 0`` the returned value sits over
    seventy orders of magnitude *below* the shipped protocol's honest failure
    probability, because the floors it does not model contribute ``1.740e-34``
    that it never sees:

    >>> from sih141.protocol.analysis import matched_shortfall_probability
    >>> from sih141.protocol.verify import (
    ...     minimum_matched_count, minimum_pooled_matched_count)
    >>> small = ProtocolParams(key_length=600)
    >>> f"{honest_abort_bound(small, method='kl'):.3e}"
    '4.429e-106'
    >>> own = matched_shortfall_probability(
    ...     small, minimum_matched=minimum_matched_count(small))
    >>> pooled = matched_shortfall_probability(
    ...     small, minimum_matched=minimum_pooled_matched_count(small),
    ...     pooled=True)
    >>> f"{2 * own + pooled:.3e}"
    '1.740e-34'

    The Hoeffding form is loose enough at that ``L`` to exceed the total by
    accident -- ``1.0`` against ``1.740e-34`` -- but that is slack, not
    coverage, and it disappears as ``L`` grows.

    >>> honest_abort_bound(small)
    1.0
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
