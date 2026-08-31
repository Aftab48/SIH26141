"""Phase C: scoring a declared key against one recipient's classical log.

Verification is four lines of arithmetic and one rule that implementations get
wrong. Recipient ``R`` holds a :class:`~sih141.protocol.records.RecipientRecord`
of ``(index, chosen_basis, outcome_eigenvalue)`` made at distribution time, and a
:class:`~sih141.protocol.signature.Signature` arrives declaring
``(basis_i, eigenvalue_i)`` for every position. Then::

    M_R = { i : chosen_basis_i == declared_basis_i }        # matched set
    e_R = |{ i in M_R : outcome_i != declared_eigenvalue_i }|
    r_R = e_R / |M_R|
    accept  iff  r_R <= threshold(R)

with ``threshold(Bob) = s_a`` and ``threshold(Charlie) = s_v``. Before any of
that, **six** checks decide whether there is a verdict to reach at all: two that
ask whether this declaration and this record are one undecided transaction --
the right distribution round, and a round not already scored -- then three
counting floors, his own, the pair's pooled total and his counterpart's, and one
provenance check that both counts were taken against the *same* declaration,
which fails both when the counterpart's count names another declaration and when
it names none at all. They are the subject of :ref:`replay`,
:ref:`matched-count-floor`, :ref:`pooled-floor` and :ref:`one-declaration`.

Only matched positions may be scored
------------------------------------
This is the one thing to get right, and getting it wrong is the classic bug in
this protocol family. On an *unmatched* position the recipient measured an
observable conjugate to the one the state was an eigenstate of, so the outcome is
a fair coin **whether or not the signature is honest**. It carries exactly zero
bits about the key. Counting those positions adds ``(1 - 1/|B|) / 2`` of pure
noise to every rate -- ``1/3`` for the ``{X, Y, Z}`` alphabet, see
:attr:`sih141.protocol.params.ProtocolParams.unmatched_noise_rate` -- which sits
above ``s_v`` in any sane parameter set. The symptom is that both verifiers reject
every honest signature on a *perfect* channel, which reads as a hardware noise
problem and sends the debugging off in exactly the wrong direction.

So the discard is not a tidy-up: the matched set is the entire evidence base.
Every security bound in :mod:`sih141.protocol.params` is exponential in
``|M_R|``, not in ``L``, for this reason.
``tests/test_protocol_verify.py`` pins the rule with a record whose unmatched
positions *all* disagree with the declaration and which must still verify at rate
``0.0``.

Why the threshold comes from the record, not from the caller
------------------------------------------------------------
:func:`verify` reads the party off the record and asks ``params`` for that
party's threshold. Bob and Charlie run the identical counting rule and differ
only in where they cut, so "which cut" is a property of *whose log this is* --
never a free parameter at the call site. Letting a caller pass a threshold would
make it possible to check Bob's record against Charlie's looser bound, which is
precisely the confusion the ``s_a < s_v`` gap exists to prevent. Sweep thresholds
with ``params.with_changes(s_v=...)`` instead; that goes through
:class:`~sih141.protocol.params.ProtocolParams` validation and so cannot produce
an inverted pair.

What a verdict does and does not mean
-------------------------------------
``accepted`` means "this record is consistent with this declaration at this
party's threshold". Two verdicts together are what the protocol is actually
about:

* Bob accepts (``r_B <= s_a``) and Charlie accepts (``r_C <= s_v``):
  the signature is **transferable**. Because ``s_a < s_v``, Bob's acceptance
  region is contained in Charlie's, so on identical evidence there is no rate at
  which Bob accepts and Charlie does not; on a clean channel both rates are
  exactly ``0`` and the implication holds with no slack at all.
* Bob accepts but Charlie rejects: **repudiation**, which the gap makes
  exponentially unlikely -- *provided* the two recipients have run the
  symmetrisation exchange (:mod:`sih141.protocol.symmetrise`). Without it the
  two rates are not tied together at all and the event has probability ``1``
  against an asymmetric Alice, which is why :func:`verify_all` refuses a pair of
  raw records.

:func:`verify_all` returns both verdicts side by side so that Phase 5 can count
those events rather than infer them.

When there is not enough evidence to score
------------------------------------------
The matched set is the entire evidence base, and *the declaration chooses which
positions land in it*. Two failures follow from that one fact, and they are the
same failure at two magnitudes:

* ``|M_R| == 0``. The rate is ``0/0`` and no arithmetic exists.
* ``|M_R|`` merely tiny -- thirteen positions where honest operation gives
  ``L/|B|``. The rate is perfectly well defined and means almost nothing: every
  bound the scheme quotes is ``exp(-Theta(|M_R|))``, so a verdict reached on
  thirteen positions carries a confidence of order ``1`` while being *reported*
  with the confidence of a run on ``L/|B|``. The rate is not the number that is
  wrong; the confidence attached to it is.

Neither is a signature failure, and neither is reported as one. :func:`verify`
raises :exc:`MatchedSetTooSmall`, which carries a :class:`VerificationAbort` --
a **no-verdict** outcome that :class:`~sih141.protocol.session.QDSSession`
records alongside the verdicts, distinct from both accept and reject. The
reasoning, since silence in either direction is defensible-sounding and wrong:

* *Accepting* on a starved matched set accepts a signature on approximately zero
  evidence. Any declaration whatsoever would pass, so unforgeability would be
  gone in the one case where it is cheapest to exploit.
* *Rejecting* is not honest either. There is no evidence of dishonesty; a
  ``False`` here would be indistinguishable, in a Phase 5 table, from a genuine
  forgery detection, and would silently bias every rejection statistic.

.. _matched-count-floor:

The matched-count floor, and where it comes from
------------------------------------------------
:func:`minimum_matched_count` turns "not enough evidence" into a number fixed
before the run, derived rather than chosen.

Under honest operation the recipient's basis at each position is drawn uniformly
from ``B``, independently of the declared basis, so

.. code-block:: text

    |M_R| ~ Binomial(L, 1/|B|),        mu = E|M_R| = L / |B|

and the multiplicative Chernoff lower tail gives, for ``0 < d < 1``,

.. code-block:: text

    P[ |M_R| <= (1 - d) mu ] <= exp(-d**2 mu / 2)

Fix an honest-abort budget ``eps`` (:data:`HONEST_ABORT_BUDGET`, ``2**-64``).
Setting ``exp(-d**2 mu / 2) = eps`` and solving,

.. code-block:: text

    d      = sqrt(2 ln(1/eps) / mu)
    m_min  = max(1, ceil((1 - d) mu))          # the floor
    abort  iff  |M_R| < m_min

Because ``ceil(x) - 1 < x``, the event ``|M_R| < m_min`` is contained in
``|M_R| <= (1 - d) mu``, so an honest verifier aborts with probability at most
``eps``, and an honest *run* -- two verifiers plus the pooled check of
:ref:`pooled-floor` -- with probability at most ``3 eps`` by a union bound. That
is ``1.6e-19``, ten orders of magnitude below
the ``1e-9``-ish forgery and repudiation bounds
:mod:`sih141.protocol.analysis` quotes for
:data:`~sih141.protocol.params.DEFAULT_PARAMS`, so the abort rule can never
become the dominant way an honest run fails. ``eps`` is a design target rather
than a tuned constant: it does not have to be revisited when ``L`` changes.

Two consequences worth stating out loud:

* ``d < 1`` requires ``mu > 2 ln(1/eps)``, i.e. ``L > 2 |B| ln(1/eps)``, which
  is ``L > 266.2`` for ``|B| = 3``. Below that the Chernoff form says nothing at
  this budget and ``m_min`` clamps to ``1`` -- exactly the "a rate needs a
  denominator" rule that was always here. A short demonstration key therefore
  behaves as before, and honestly so: there is no statistical power to spend.
* At :data:`~sih141.protocol.params.DEFAULT_PARAMS` (``L = 115200``,
  ``|B| = 3``) ``mu = 38400`` and ``m_min = 36555``. Every verdict this module
  emits at those parameters therefore rests on at least ``36555`` matched
  positions, within 5% of the mean, so a bound evaluated at the *observed*
  matched count is never worse than the bound at the floor.

This is a protocol control, not a heuristic and not a detector (D4): the floor
is a closed form in ``(L, |B|, eps)``, computed from the parameter set alone,
with no data, no fitting and no thresholding of anything learned at run time.
It uses evidence the verifier already held and was throwing away.

.. _pooled-floor:

The pooled floor, and the route a per-verifier floor leaves open
----------------------------------------------------------------
A per-verifier floor is not enough, and the reason is worth stating carefully
because it is invisible in every exponent the scheme quotes.

*The route.* Every repudiation bound is exponential in the **pooled** count
``M = m_B + m_C``, not in either verifier's own. A signer who reads both
recipients' raw logs -- which
:class:`~sih141.protocol.session.QDSSession` hands the ``Signer`` seam -- aims
``M`` at exactly ``2 m_min``, placing every matched record on a position where
the two logs used *different* bases and declaring it truthfully. Each matched
record is then held by exactly one verifier, the symmetrisation coins decide
which, and every record is correct, so **no rate deviates anywhere**:

.. code-block:: text

    m_B ~ Binomial(2 m_min, 1/2),   m_C = 2 m_min - m_B,   e_B = e_C = 0

    m_B > m_min  =>  Bob clears his floor and accepts at rate 0,
                     Charlie is below his and returns no verdict.

That is Bob holding a signature Charlie cannot score, with probability
``(1 - P[m_B = m_min]) / 2``, which tends to ``1/2`` as ``m_min`` grows -- ``0.432``
at ``L = 360`` and ``0.466`` at ``L = 600``, against a published ``4.4e-05``. Key
length does not help, because ``m_min`` grows with ``L`` and so does the target.

.. _split-coin-provenance:

*Provenance of the measured counts.* Runs through the shipped seams gave
``78/200`` and ``87/200`` at ``L = 360`` and ``85/200`` at ``L = 600``. Those runs
predate the two-stream change (see ``:ref:`two-streams``` in
:mod:`sih141.protocol.session`), which moved every seeded transcript, so the
individual counts are **not reproducible from this tree** -- independent
re-measurement on the canonical seed set gives ``86/200``. All of them agree with
the closed form to within sampling error, and the closed form is the number to
quote. The counts are kept because a measured attack is worth more than a formula
alone, and dropped provenance is how a figure becomes folklore.

*The pooled law, which is the one step that is not a copy.* Fix the two raw
records and the declaration. The symmetrisation coins re-assign a **fixed
multiset** of ``2L`` entries, so ``M`` is the same number before and after the
exchange -- while ``m_B`` moves. Under honest operation those ``2L`` bases are
drawn i.i.d. uniform, so

.. code-block:: text

    M ~ Binomial(2L, 1/|B|),        mu_M = E[M] = 2L / |B|

*exactly*. Note what this is **not** derived from: ``m_B`` and ``m_C`` are not
independent -- given the records, ``m_C = M - m_B`` with correlation ``-1`` --
so convolving the two post-exchange marginals proves nothing, even though it
happens to land on the same answer. Conservation is the reason;
``tests/test_protocol_tally.py`` measures both halves.

*The floor.* Same Chernoff lower tail, same ``eps``, the doubled mean:

.. code-block:: text

    d      = sqrt(2 ln(1/eps) / mu_M)
    M_min  = max(1, ceil((1 - d) mu_M))     # 74190 at DEFAULT_PARAMS
    abort  iff  m_B + m_C < M_min

:func:`minimum_pooled_matched_count`. What makes it worth the message is that it
strictly exceeds the total the attack aims at. With
``A = sqrt(2 mu ln(1/eps))`` and ``mu = L/|B|``,

.. code-block:: text

    m_min = mu - A          M_min = 2 mu - sqrt(2) A
    M_min - 2 m_min = (2 - sqrt 2) A ~ 0.586 A,   growing like sqrt(L)

-- ``1080`` records at :data:`~sih141.protocol.params.DEFAULT_PARAMS`, ``78`` at
``L = 600``, positive at every ``L >= 140``. So the aimed-at declaration is
refused rather than priced, and the closure is not an artefact of a short
demonstration key: the margin *grows*.

*Why the floor alone is still not enough.* Alice re-aims at ``M = M_min`` and
needs only the coins to leave Charlie under his own floor -- a deviation of
``M_min/2 - m_min = (1 - sqrt2/2) A`` out of ``M_min ~ 2 mu`` fair coins:

.. code-block:: text

    P <= exp(-2 (M_min/2 - m_min)^2 / M_min)  ->  eps ** (3 - 2 sqrt 2)

Both figures are computed rather than quoted, so neither can drift:

>>> from math import exp, sqrt
>>> from sih141.protocol.params import DEFAULT_PARAMS
>>> m_min = minimum_matched_count(DEFAULT_PARAMS)
>>> M_min = minimum_pooled_matched_count(DEFAULT_PARAMS)
>>> f"{exp(-2 * (M_min / 2 - m_min) ** 2 / M_min):.2e}"   # the Chernoff form
'3.86e-04'
>>> f"{HONEST_ABORT_BUDGET ** (3 - 2 * sqrt(2)):.2e}"     # its L-independent limit
'4.95e-04'

The *exact* one-sided tail ``P[Bin(M_min, 1/2) < m_min]`` is ``3.61e-05`` (two-sided
``7.22e-05``); the Chernoff form above bounds it about eleven-fold loosely. An earlier
revision of this docstring quoted ``4.8e-05`` here, which matches none of the four
candidates -- it survived because it was prose, and prose is the one thing
``--doctest-modules`` cannot check. Hence the doctests above.

**independent of ``L``**, because the deviation and the noise both grow like
``sqrt(L)``. No key length reduces it, and no choice of the two floors inside the
``eps`` budget does either -- the margin ``M_min/2 - m_min`` is capped by that
same budget.

*What closes it.* Making the per-verifier floor's **consequence joint**: a
verifier below his own floor takes the other down with him
(:attr:`AbortReason.COUNTERPART_BELOW_FLOOR`). The same message already carries
the number, so it costs nothing further. Then "Bob accepts" implies "Charlie
reached a verdict", the asymmetric outcome is not in the outcome space at all,
and the failure space is exhausted by the two branches
:func:`~sih141.protocol.analysis.repudiation_bound` already covers. The three
*floors* together give ``M >= max(2 m_min, M_min)`` on any run that reaches a
verdict, which is :func:`enforced_repudiation_bound`: ``1.41e-09`` at the shipped
defaults, unconditional, with nothing left to quote beside it. (The fourth check,
:ref:`one-declaration`, contributes no term to that inequality -- it guarantees the
two counts in it describe the same declaration, without which the sum is a mixture
of two runs and the inequality is about nothing.)

*What it costs.* One classical message each way between the recipients
(:mod:`sih141.protocol.tally`), on the channel they already share for the coins;
three exact honest-abort tails summing to ``8.0e-31`` instead of one at
``2.5e-31``; and the ordering change that Bob's verdict is no longer local -- he
must forward the declaration and hear Charlie's count before he can accept.
:mod:`sih141.protocol.tally` states all three, and the availability consequence
(either recipient can now force an abort) with them.

.. _one-declaration:

Both counts, or neither: the pooled rule needs one declaration
--------------------------------------------------------------
``m_B + m_C`` is a quantity of *one* experiment: one pair of records, one
declaration. Conservation under the symmetrisation coins -- the step the pooled
law of :ref:`pooled-floor` rests on -- is the statement that the coins re-assign
a fixed multiset of ``2L`` entries **scored against a fixed declaration**. Change
the declaration between the two counts and nothing survives: the two numbers
count matches to two different basis strings, their sum is not ``M`` for either
of them, and no floor derived from a law about ``M`` says anything about it.

*How the counts can come apart.* The recipients compare counts before either of
them scores -- Phase C' is upstream of Phase C -- so the declaration they count
against is the one Alice sent Bob and Bob forwarded in order to *ask* for a
count. If the hop from Bob to Charlie then delivers a **different** declaration,
Charlie scores that one while the count he was handed is Bob's against the
original. The pooled floor would then be enforced on

.. code-block:: text

    m_C(forwarded) + m_B(original)

which is no run's pooled count. It is not a weakened check but a check on a
number nobody produced: it can pass where the real total would fail and fail
where the real total would pass, and either outcome is a fabrication.
:class:`~sih141.protocol.session.QDSSession` already *reported* the incoherence
-- :attr:`~sih141.protocol.session.SessionTranscript.forwarding_altered_signature`
is set and
:attr:`~sih141.protocol.session.SessionTranscript.pooled_matched_count` returns
``None``, because such a run is two experiments rather than one -- and it now
refuses to *enforce* on it as well, which is the same statement made where it
has consequences.

*The rule.* A count crosses the wire together with a fingerprint of the
declaration it was computed against
(:attr:`~sih141.protocol.tally.MatchedCountMessage.declaration_digest`,
:func:`_declaration_digest`).
:func:`~sih141.protocol.tally.exchange_matched_counts` refuses two messages that
name different declarations, and :func:`verify` refuses a counterpart count that
names a declaration other than the one it is scoring
(:attr:`AbortReason.COUNTS_FROM_TWO_DECLARATIONS`). The refusal is a no-verdict
like every other entry in :class:`AbortReason`: it is not evidence of forgery,
and the verifier holding it has learned nothing about the signature.

*And the rule cannot be declined.* The fingerprint was optional once, and a
count that named no declaration had the check skipped -- "no claim, so no
disagreement". That is the wrong reading when the party supplying the count is
the adversary, and it was demonstrated: a ``count_exchange`` seam doing the
honest arithmetic and returning
``PooledMatchedCounts(..., declaration_digest=None)`` restored the exact
behaviour this check was added to stop, reaching a verdict on a count whose
evidence base under the scored declaration was zero. So the binding is now
mandatory where the count is built, the carrier cannot be subclassed to strip
it, and :func:`verify` refuses a count that arrives through the exchange with
the slot empty (:attr:`AbortReason.COUNT_OF_UNRECORDED_PROVENANCE`) instead of
skipping the check. :ref:`sih141.protocol.tally's <binding-is-mandatory>`
section gives all three and what each one closes.

*What this is and is not.* The adversary here is **Bob** -- or whoever holds the
Bob-to-Charlie hop -- and not Alice; every non-repudiation claim is a claim
about a signer, so no bound in :mod:`sih141.protocol.analysis` moves. Nor was the
outcome often wrong. At the shipped defaults the per-verifier floor does almost
all of the work: once both counts clear ``m_min = 36555`` the pooled check can
only fire inside the ``M_min - 2 m_min = 1080`` records between ``73110`` and
``74190``, a band ``1.4%`` of ``mu_M = 76800`` wide, so a total that is off by
some amount usually lands on the same side of it. That is a statement about
:data:`~sih141.protocol.params.DEFAULT_PARAMS` and about today's outcome space
rather than about the rule. The band is *relatively* wider the shorter the key
-- the gap grows like ``sqrt(L)`` while the mean grows like ``L``, so at
``L = 1200`` a verifier on his floor of ``212`` refuses any counterpart below
``322``, a window ``27%`` of the mean ``400`` wide -- and Phase 3 builds attacks
on the forwarding hop, where "which declaration was that count about?" stops
being a rhetorical question.

.. _replay:

One round, one verdict: the replay defence
-------------------------------------------
The scoring rule above is a pure function of ``(signature, record, params)``,
and for most of this package's life that was the whole of it. A pure function
cannot tell the *first* time it is asked from the fourth, and it cannot tell
this run's evidence from last run's, so two attacks in the problem statement
were open with no defence at all. Both were measured before anything was built,
at :data:`~sih141.protocol.params.DEMO_PARAMS`:

* a captured signature re-presented after its run was finished verified again at
  rate ``0.0`` and was accepted, 6 times out of 6;
* a signature paired with **another run's** records was refused by nothing --
  the transcript constructed without complaint and reported
  ``transferable=True`` -- and a fresh scoring of the pair failed only on the
  mismatch rate, mean ``0.507`` over 40 seed pairs. That is an accident of the
  arithmetic, not a rule: it is the ``(1 - 1/|B|)/2`` chance noise of scoring
  against an unrelated key, and nothing in it says "wrong run".

Two mechanisms answer this, and they answer different halves of it.

*Which round is this?* Both sides now carry an identifier of the distribution
round -- :attr:`sih141.protocol.signature.Signature.session_id`, derived from an
opening the signer reveals in Phase B, and
:attr:`sih141.protocol.records.RecipientRecord.session_id`, stamped on the log
when Alice announced it in Phase A. :func:`verify` recomputes the first and
compares it with the second, and refuses on disagreement
(:attr:`AbortReason.SESSION_MISMATCH`). Key states in QDS are genuinely
one-time, so a declaration and a set of records belong to exactly one round;
after this, pairing them across rounds fails by construction rather than by
luck. :ref:`sih141.protocol.signature's <session-binding>` section says what the
identifier is derived from and why the declared key is deliberately *not* in it.

**The record is the anchor, not the signature.** The comparison is driven by
whichever side an adversary cannot reach: a verifier who holds a stamped record
requires the declaration to name that round, and refuses one that names another
or names none. A verifier whose record names no round has nothing to compare and
scores exactly as he did before -- which is what keeps every hand-built pair in
the test suite, and every log written before the binding existed, working
unchanged. This is not the omission route of :ref:`one-declaration` in another
guise: there the party who could omit the binding was the adversary the check
existed to catch, whereas here the side that can omit it is the verifier's own
record, and a verifier who blinds himself only loses his own protection.

*Has this evidence already been spent?* One distribution round yields one
verdict per verifier, so :func:`verify` also accepts a
:class:`ConsumedRecords` -- the verifier's own ledger of rounds he has already
decided. A second verification against a spent round refuses
(:attr:`AbortReason.RECORD_ALREADY_VERIFIED`) instead of re-deciding. The ledger
is what closes the case the identifier cannot: a replay *within* the round it
belongs to, where the identifier legitimately matches.

The ledger is an object the verifier holds and passes, never a module-level
default, and that is a security property rather than a style choice: Bob's
ledger is constructed for Bob, refuses a record belonging to anyone else, and
offers no way to read Charlie's, so one verifier's history cannot leak into the
other's decision. A process-wide default would also be wrong for a second and
more practical reason -- two runs made from the same seed produce the same
identifier by design, so a shared ledger would refuse the second of two
identically seeded experiments as a replay of the first.

*What it costs, priced rather than waved away.* Entries are spent only when a
verdict is actually reached; a refusal spends nothing, so no floor failure and
no provenance failure can burn a round. An adversary therefore cannot poison a
verifier's ledger from outside: the only way to add an entry is to make that
verifier reach the verdict he was entitled to reach. Under the standing
authentication assumption (see
:mod:`sih141.protocol.signature`) the one party who can spend a round on a
declaration that will be *rejected* is the signer herself, and a signer who
wants to deny service can simply decline to sign. Storage is one 32-character
identifier per round per verifier, roughly ``10**2`` bytes; a ledger is
prunable by round because that is exactly what it is keyed on.

*And what it does not claim.* An adversary holding the Bob-to-Charlie hop can
rewrite a declaration's opening as freely as he can rewrite its key -- the
channel to Charlie is exactly where Phase 3 puts him. He gains nothing: to make
one round's declaration pass another round's binding he needs an opening hashing
to that round's identifier, and if he had that round's opening he would have
that round's signature and no relabelling would be needed. What he can do is
turn a refusal into a rejection by relabelling with garbage, which trades a
no-verdict for a detected forgery and is strictly worse for him.

How small a matched set is reachable, and by whom
-------------------------------------------------
No *channel* attack can starve it. The matched set depends only on the declared
bases and the recipient's own uniform draws, neither of which the channel
touches, so an adversary who owns the entire quantum link cannot move it. Under
honest declarations an empty set has probability ``(1 - 1/|B|)**L`` -- about
``1e-34`` even for the short :data:`~sih141.protocol.params.DEMO_PARAMS`.

A *signer* can, and the shipped seams let him. The
:class:`~sih141.protocol.session.Signer` seam is handed **both** recipients'
raw, pre-exchange logs (see :ref:`phase3-seams`), which is strictly more than
any single adversary in the threat model holds. A declaration avoiding only
*Bob's* raw log is indeed defused by Phase A': each verifier is scored on his
post-symmetrisation record -- his own entry where he retained it, the other's
where the pair was swapped -- so such a declaration still matches with
probability ``(1/2)(1/|B|) = 1/6`` per position and ``E|M_B| = L/6``. But a
declaration avoiding *both* raw logs leaves nothing for either verifier: every
post-exchange entry is one of the two raw entries, and both were avoided. It
drives ``|M_B| = |M_C| = 0`` with probability ``1``, measured 20/20 at
``L = 600``.

An earlier version of this docstring claimed the branch was "not reachable
through the shipped seams". **That claim was false and is withdrawn**; the
paragraph above replaces it. What the seams cannot do is turn it into a crash:
the abort is a recorded outcome, :meth:`~sih141.protocol.session.QDSSession.run`
completes, and a harness that does not wrap the call keeps its run. The same
two-log signer can also pin ``|M_R|`` at a handful of positions for any ``L``
without emptying it, which is the case the per-verifier floor exists for, and
can *split* a total sized to slip between the floors, which is the case the
pooled floor exists for -- :ref:`pooled-floor` is that route and its closure.

``tests/test_protocol_verify.py`` pins the surviving halves: a *Bob*-log-avoiding
signer completes a run with a real evidence base, and a record wired to disagree
everywhere still refuses to invent a verdict.

Notes
-----
Determinism (D3)
    Nothing here consumes randomness; there is no ``rng`` argument to inject.
    Verification is a pure function of ``(signature, record, params)`` unless
    the verifier hands it his own :class:`ConsumedRecords`, in which case one
    round is marked spent on the way out -- see :ref:`replay` for why one
    verdict per round is a rule rather than a convenience, and why the state
    lives on an object the verifier owns.
Immutability
    :func:`verify` cannot modify the record or the signature it is handed. Both
    are frozen dataclasses holding tuples, it only reads derived views, and a
    test asserts equality across the call. A verifier that could edit its own
    evidence would not be one. The one thing a verification can change is the
    ledger its own verifier passed in.
Qubit ordering (D2)
    Positions are key indices ``0 .. L-1``, matching
    :class:`~sih141.protocol.keys.PrivateKey` element order and the record's
    validated index sequence, so the comparison is positional and safe. No
    multi-qubit register label is involved.
No machine learning (D4)
    Counting and one division.

See Also
--------
sih141.protocol.records.RecipientRecord : The evidence being scored.
sih141.protocol.signature.Signature : The claim being tested.
sih141.protocol.params.ProtocolParams.threshold_for : Where the cut comes from.
minimum_matched_count : The per-verifier floor, and its derivation.
minimum_pooled_matched_count : The pooled floor, and its derivation.
sih141.protocol.tally : Phase C', the message that makes the pooled floor
    checkable.
enforced_repudiation_bound : The unconditional repudiation number those floors
    buy, which is the only a-priori one this package publishes.
"""

from __future__ import annotations

import enum
import hashlib
import math
import numbers
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from sih141.protocol.params import (
    VERIFIERS,
    Party,
    ProtocolParams,
    _as_message_bit,
    _as_party,
)
from sih141.protocol.records import RecipientRecord
from sih141.protocol.signature import Signature

__all__ = [
    "HONEST_ABORT_BUDGET",
    "AbortReason",
    "ConsumedRecords",
    "MatchedSetTooSmall",
    "VerificationAbort",
    "VerificationResult",
    "enforced_repudiation_bound",
    "guaranteed_pooled_matched_count",
    "matched_positions",
    "minimum_matched_count",
    "minimum_pooled_matched_count",
    "mismatch_positions",
    "verify",
    "verify_all",
    "verify_or_abort",
]


HONEST_ABORT_BUDGET: Final[float] = 2.0**-64
"""float: The per-verifier probability an honest run is allowed to abort.

``2**-64``, about ``5.42e-20``. The one free parameter of the matched-count
floor (:func:`minimum_matched_count`), and a target rather than a tuning knob:
it must stay negligible next to every other failure probability the scheme
quotes -- the forgery and repudiation bounds at
:data:`~sih141.protocol.params.DEFAULT_PARAMS` are of order ``1e-9`` -- so that
the abort rule can never become the dominant way an honest run fails. The
derivation is in the module docstring under :ref:`matched-count-floor`.
"""

_LOG_ABORT_BUDGET: Final[float] = -math.log(HONEST_ABORT_BUDGET)
"""float: ``ln(1/eps) = 64 ln 2``, precomputed for :func:`minimum_matched_count`."""


class AbortReason(enum.StrEnum):
    """Why verification reached no verdict.

    A :class:`enum.StrEnum` like :class:`~sih141.protocol.params.Party`, so it
    passes through :func:`json.dumps` and into a Phase 5 table unchanged.

    The eight members are ordered by which check fires first in :func:`verify`,
    and they fall into three groups. First the two that ask whether this
    declaration and this record are even the same transaction -- the right round
    (:attr:`SESSION_MISMATCH`) and a round not already decided
    (:attr:`RECORD_ALREADY_VERIFIED`), the subject of :ref:`replay`. Then the
    verifier's own count. Then four about the pair: whether the counterpart's
    count is about the same declaration -- which has two ways to fail, naming
    none and naming another -- then the pooled total, then the counterpart's own
    count. Those four exist only on a run where the recipients ran the count
    exchange of :mod:`sih141.protocol.tally`.

    Attributes
    ----------
    SESSION_MISMATCH
        The declaration names a different distribution round from the one this
        verifier's log was made in -- or names none while the log names one.
        Refused rather than scored: the key states are one-time, so a
        declaration and a record belong to exactly one round, and a rate
        computed across two of them measures nothing but the ``(1 - 1/|B|)/2``
        chance noise of an unrelated key. Reported as a no-verdict and never as
        a rejection, because the verifier has learned nothing about the
        signature: he has learned that he was handed the wrong pair. See
        :ref:`replay`.
    RECORD_ALREADY_VERIFIED
        This verifier has already reached a verdict on this round, and his
        :class:`ConsumedRecords` ledger says so. One distribution round yields
        one verdict per verifier; a second decision on spent evidence is a
        replay whether it arrives from an attacker or from a harness bug, and
        the honest answer to both is the same refusal. Only reachable when a
        ledger was supplied. See :ref:`replay`.
    EMPTY_MATCHED_SET
        ``|M_R| == 0``: the recipient's basis differed from the declared one at
        every position, so the mismatch rate is ``0/0`` and no arithmetic
        exists.
    BELOW_FLOOR
        ``0 < |M_R| < m_min``: a rate could be computed, but on so little
        evidence that no bound in the scheme applies to it. See
        :func:`minimum_matched_count`.
    COUNT_OF_UNRECORDED_PROVENANCE
        The counterpart's count arrived carrying the count exchange's
        provenance slot with nothing in it: it does not say which declaration
        it was computed against, so it cannot be shown to be about the one this
        verifier is scoring. Refused rather than taken at its word, because the
        party who supplies that count is an adversary in this threat model and
        a check he can switch off by declining to answer is not a check at all
        -- see :ref:`one-declaration` and
        :ref:`sih141.protocol.tally's <binding-is-mandatory>` account of the
        omission route. Like the next member it names no floor.
    COUNTS_FROM_TWO_DECLARATIONS
        The counterpart's count was computed against a *different* declaration
        from the one this verifier is scoring, so ``m_B + m_C`` is not a pooled
        count and the pooled floor has nothing to be applied to. The refusal is
        about the numbers' provenance rather than their size, and it names no
        floor: see :ref:`one-declaration`.
    POOLED_BELOW_FLOOR
        ``m_B + m_C < M_min``: this verifier cleared his own floor, but the two
        of them together hold less evidence than the *pooled* floor demands. See
        :func:`minimum_pooled_matched_count` and :ref:`pooled-floor`. This is
        the label a declaration aimed at a low total earns, and the one to look
        for when a run ends with no verdict and no verifier looks starved on his
        own.
    COUNTERPART_BELOW_FLOOR
        The other verifier's reported count is below *his* floor, so neither
        verifier scores. This verifier's own evidence may be ample; he refuses
        anyway, because a signature the other verifier cannot score is not one
        this verifier can be told he should have transferred. The consequence of
        the per-verifier floor is joint, and :ref:`pooled-floor` explains why
        that is what closes the split-coin route rather than merely pricing it.
    """

    SESSION_MISMATCH = "session-identifier-mismatch"
    RECORD_ALREADY_VERIFIED = "records-already-verified"
    EMPTY_MATCHED_SET = "empty-matched-set"
    BELOW_FLOOR = "matched-count-below-floor"
    COUNT_OF_UNRECORDED_PROVENANCE = "counterpart-count-of-unrecorded-provenance"
    COUNTS_FROM_TWO_DECLARATIONS = "counts-from-two-declarations"
    POOLED_BELOW_FLOOR = "pooled-matched-count-below-floor"
    COUNTERPART_BELOW_FLOOR = "counterpart-matched-count-below-floor"


#: Reasons that describe *this* verifier's own matched set, as opposed to the
#: four that describe the pair and the two that describe the pairing itself.
#: Used to keep the label and the numbers a single observation; see
#: :class:`VerificationAbort`.
_OWN_COUNT_REASONS: Final[frozenset[AbortReason]] = frozenset(
    {AbortReason.EMPTY_MATCHED_SET, AbortReason.BELOW_FLOOR}
)

#: Reasons that refuse before any counting rule is reached at all: the
#: declaration and the record are not the same transaction, either because they
#: belong to different distribution rounds or because this round has already
#: been decided (:ref:`replay`). They make no claim about any count -- the
#: counts are recorded for diagnosis and nothing is asserted about their
#: relation to any floor -- so :class:`VerificationAbort` checks nothing further
#: on them and :attr:`VerificationAbort.shortfall` is ``0``.
_ROUND_REASONS: Final[frozenset[AbortReason]] = frozenset(
    {AbortReason.SESSION_MISMATCH, AbortReason.RECORD_ALREADY_VERIFIED}
)

#: Reasons that are statements about the two verifiers together, and therefore
#: need both exchanged numbers. The complement of the two sets above, written
#: out rather than derived so that adding a member to :class:`AbortReason`
#: without deciding which group it belongs to fails a test instead of silently
#: joining this one.
_PAIR_REASONS: Final[frozenset[AbortReason]] = frozenset(
    {
        AbortReason.COUNT_OF_UNRECORDED_PROVENANCE,
        AbortReason.COUNTS_FROM_TWO_DECLARATIONS,
        AbortReason.POOLED_BELOW_FLOOR,
        AbortReason.COUNTERPART_BELOW_FLOOR,
    }
)

#: Pair reasons that refuse to *apply* the pooled rule rather than reporting it
#: failed: the two counts cannot be shown to belong to one declaration, either
#: because the counterpart's names another or because it names none at all. No
#: arithmetic relation between the two numbers is being claimed on either, so
#: neither has a floor to quote a distance from -- see
#: :attr:`VerificationAbort.shortfall` and :ref:`one-declaration`.
_UNPOOLABLE_REASONS: Final[frozenset[AbortReason]] = frozenset(
    {
        AbortReason.COUNT_OF_UNRECORDED_PROVENANCE,
        AbortReason.COUNTS_FROM_TWO_DECLARATIONS,
    }
)

#: Bytes of :func:`hashlib.blake2b` output kept in a declaration digest. Sixteen
#: is far more than a collision-resistance requirement here: the digest guards
#: against a *wiring* mistake -- two counts pooled across two declarations --
#: rather than against a search, and the declarations being told apart are both
#: fixed before the check runs.
_DECLARATION_DIGEST_BYTES: Final[int] = 16


def _declaration_digest(signature: Signature) -> str:
    """Return a stable fingerprint of one declaration.

    The binding a matched count travels with, so that two counts can be shown
    to be about the same declaration before they are added together
    (:ref:`one-declaration`). It is a fingerprint rather than the declaration
    itself because the count exchange puts integers on the wire, not keys: a
    32-character string keeps a
    :class:`~sih141.protocol.tally.MatchedCountMessage` a scalar message and a
    :class:`~sih141.protocol.session.SessionTranscript` from carrying a second
    copy of every key it already holds.

    :func:`hashlib.blake2b` rather than the builtin :func:`hash`, which is salted
    per process: this value is compared across a message that was serialised and
    restored, so it has to be the same number in two runs of the interpreter.

    Parameters
    ----------
    signature : Signature
        The declaration being counted or scored against.

    Returns
    -------
    str
        A 32-character lowercase hex digest, determined by the message bit and
        the declared ``(basis, eigenvalue)`` sequence and by nothing else. Two
        equal :class:`~sih141.protocol.signature.Signature` objects therefore
        digest alike, which is what makes an honest forwarding hop -- one that
        rebuilds an identical declaration rather than passing the object on --
        indistinguishable from no hop at all.

    Raises
    ------
    TypeError
        If ``signature`` is not a
        :class:`~sih141.protocol.signature.Signature`.

    Notes
    -----
    Consumes no randomness (D3): an unkeyed hash of a fixed encoding.

    One pass over the declaration, about ``16 ms`` at
    :data:`~sih141.protocol.params.DEFAULT_PARAMS`, and computed only where a
    binding is actually being compared -- :func:`verify` skips it entirely when
    the count it was handed names no declaration.

    Examples
    --------
    >>> from sih141.protocol.keys import KeyElement, PrivateKey
    >>> from sih141.protocol.signature import Signature
    >>> from sih141.protocol.verify import _declaration_digest
    >>> key = PrivateKey(0, (KeyElement("X", 1), KeyElement("Z", -1)))
    >>> flipped = PrivateKey(0, (KeyElement("X", 1), KeyElement("Z", 1)))
    >>> first = _declaration_digest(Signature(0, key))
    >>> len(first), first == _declaration_digest(Signature(0, key))
    (32, True)
    >>> first == _declaration_digest(Signature(0, flipped))
    False
    """
    if not isinstance(signature, Signature):
        raise TypeError(
            f"signature must be a Signature, got {type(signature).__name__}; "
            f"a declaration digest fingerprints a declaration."
        )
    # The encoding is injective, which is what the comparison downstream needs:
    # the length is fixed first, every basis is one character of the fixed
    # {X, Y, Z} alphabet, and every eigenvalue is one byte of the equally long
    # bit string that follows, so exactly one declaration produces any payload.
    header = f"{signature.message_bit}|{len(signature)}|"
    payload = (header + "".join(signature.bases)).encode("utf-8") + bytes(
        signature.bits
    )
    return hashlib.blake2b(
        payload, digest_size=_DECLARATION_DIGEST_BYTES
    ).hexdigest()


class _BoundMatchedCount(int):
    """A matched count that remembers which declaration produced it.

    An :class:`int` in every respect -- it compares, adds, serialises and prints
    as the number it is -- carrying one extra attribute naming the declaration
    it was counted against. The presence of that attribute is also what marks a
    count as having come *through* the exchange, which is how :func:`verify`
    tells an omitted binding from a caller who never had one
    (:func:`_claims_provenance`). That is what lets
    :meth:`sih141.protocol.tally.PooledMatchedCounts.counterpart_of` hand
    :func:`verify` a count *and* its provenance through the existing
    ``counterpart_matched`` argument, so that every call site which already
    passes an integer keeps working and gains the check for free. A count whose
    provenance travels separately from the count is a count that can be pooled
    with the wrong one, which is :ref:`one-declaration`.

    Nothing stores this type: :class:`VerificationAbort` coerces the value with
    :func:`_as_count`, so a recorded refusal holds a plain :class:`int` and the
    binding lives only on the wire.

    Parameters
    ----------
    value : int
        The count.
    declaration_digest : str or None
        :func:`_declaration_digest` of the declaration it was computed against.
        ``None`` is representable so that this check has something to refuse:
        no path through :mod:`sih141.protocol.tally` produces it any more
        (:ref:`binding-is-mandatory`), and :func:`verify` treats a count that
        carries this slot empty as an omission rather than as an absence of
        claim -- see :attr:`AbortReason.COUNT_OF_UNRECORDED_PROVENANCE`.

    Attributes
    ----------
    declaration_digest : str or None
        As passed.

    Examples
    --------
    >>> from sih141.protocol.verify import _BoundMatchedCount
    >>> bound = _BoundMatchedCount(212, "0f1e")
    >>> bound, bound + 1, bound == 212
    (212, 213, True)
    >>> bound.declaration_digest
    '0f1e'
    """

    declaration_digest: str | None

    def __new__(
        cls, value: int, declaration_digest: str | None = None
    ) -> _BoundMatchedCount:
        """Build the count and attach its declaration.

        Parameters
        ----------
        value : int
            The count.
        declaration_digest : str or None, optional
            The declaration it was counted against.

        Returns
        -------
        _BoundMatchedCount

        Raises
        ------
        TypeError
            If ``declaration_digest`` is neither a string nor ``None``.
        """
        if declaration_digest is not None and not isinstance(
            declaration_digest, str
        ):
            raise TypeError(
                f"declaration_digest must be a string or None, got "
                f"{type(declaration_digest).__name__}"
            )
        count = super().__new__(cls, value)
        count.declaration_digest = declaration_digest
        return count


def _counterpart_binding(value: Any) -> str | None:
    """Return the declaration a reported count was computed against, if it says.

    Parameters
    ----------
    value : Any
        Whatever was passed as ``counterpart_matched``: ``None``, a plain
        :class:`int` from a caller that tracks provenance elsewhere, or a
        :class:`_BoundMatchedCount` from the count exchange.

    Returns
    -------
    str or None
        The digest, or ``None`` when the count carries no usable one. An empty
        string counts as absent: a binding that names nothing cannot name the
        declaration being scored either.
    """
    digest = getattr(value, "declaration_digest", None)
    return digest if isinstance(digest, str) and digest else None


def _claims_provenance(value: Any) -> bool:
    """Return whether a reported count arrived through the count exchange.

    The distinction :func:`verify` needs in order to refuse an omission rather
    than skip a check. A count that has a ``declaration_digest`` attribute at
    all came from :mod:`sih141.protocol.tally` -- it is the slot
    :meth:`~sih141.protocol.tally.PooledMatchedCounts.counterpart_of` fills --
    so an *empty* slot on such a count is a Phase C' step that declined to say
    what it counted, and Phase C' is run by the party this check exists to
    catch. A plain :class:`int` has no slot to leave empty; it is a number a
    caller supplied from outside the exchange entirely, and it is refused for
    nothing, exactly as before.

    Parameters
    ----------
    value : Any
        Whatever was passed as ``counterpart_matched``.

    Returns
    -------
    bool
        ``True`` iff the value carries the exchange's provenance slot, filled
        or not.
    """
    return hasattr(value, "declaration_digest")


class ConsumedRecords:
    """One verifier's ledger of distribution rounds he has already decided.

    The stateful half of the replay defence (:ref:`replay`). One distribution
    round yields one verdict per verifier, so a verifier who has scored a round
    refuses to score it again: :func:`verify` consults the ledger it is handed
    before it counts anything, and marks the round spent only after a verdict is
    actually reached.

    **Per verifier, never global.** A ledger is constructed for one party,
    refuses a record belonging to anyone else, and exposes no way to read
    another party's, so Bob's history cannot reach Charlie's decision. That is a
    threat-model requirement rather than tidiness -- the two verifiers are
    adversaries to each other in half of this package's attacks -- and it also
    avoids a practical trap: two runs made with the same seed produce the same
    round identifier by design, so a process-wide ledger would refuse the second
    of two identically seeded experiments as a replay of the first.

    **What it keys on.** The record's
    :attr:`~sih141.protocol.records.RecipientRecord.session_id` together with
    its message bit. Deliberately *not* the record's contents: two structurally
    identical logs from two different rounds are two rounds, and content
    addressing would confuse an unlucky coincidence with a replay. A record
    that names no round is therefore untracked -- :meth:`spend` on one is a
    no-op and :meth:`is_spent` is ``False`` -- because there is nothing to spend
    and inventing an identity for it would refuse honest re-verifications of
    hand-built pairs across the whole test suite.

    **What it costs.** One 32-character identifier per round; a ledger is
    prunable by round because that is what it is keyed on. Nothing an adversary
    controls can add an entry: the only way in is a verdict this verifier
    reached, and a refusal spends nothing, so no floor failure and no
    provenance failure can burn a round. See :ref:`replay` for the residual
    denial-of-service surface and why it prices out at zero under the standing
    channel-authentication assumption.

    Parameters
    ----------
    party : Party or str
        The verifier this ledger belongs to. Alice is refused: she signs, holds
        no record and reaches no verdict, so there is nothing for her to spend.

    Raises
    ------
    ValueError
        If ``party`` is Alice or names no party.

    Attributes
    ----------
    party : Party
        As passed, resolved.

    See Also
    --------
    verify : Consults one, and spends into it.
    AbortReason.RECORD_ALREADY_VERIFIED : The refusal it produces.

    Notes
    -----
    Consumes no randomness (D3). Not thread-safe and deliberately not: a
    verifier is one party, and a ledger that could be updated from two places at
    once would be a ledger whose "one verdict per round" was a race.

    Examples
    --------
    >>> from sih141.protocol.records import RecipientRecord
    >>> from sih141.protocol.verify import ConsumedRecords
    >>> ledger = ConsumedRecords("Bob")
    >>> record = RecipientRecord.from_measurements(
    ...     "Bob", 0, ["X"], [1], session_id="9f3c"
    ... )
    >>> ledger.is_spent(record)
    False
    >>> ledger.spend(record)
    >>> ledger.is_spent(record), len(ledger)
    (True, 1)

    A log that names no round is not tracked, and nothing about it is invented:

    >>> unbound = RecipientRecord.from_measurements("Bob", 0, ["X"], [1])
    >>> ledger.spend(unbound)
    >>> ledger.is_spent(unbound), len(ledger)
    (False, 1)

    And one verifier's ledger will not hold the other's evidence:

    >>> ledger.spend(RecipientRecord.from_measurements(
    ...     "Charlie", 0, ["X"], [1], session_id="9f3c"
    ... ))
    Traceback (most recent call last):
        ...
    ValueError: this ledger belongs to Bob and was handed Charlie's record, ...
    """

    __slots__ = ("_party", "_spent")

    def __init__(self, party: Party | str) -> None:
        resolved = _as_party(party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice keeps no ledger of consumed records: she is the signer, "
                "holds no measurement record and reaches no verdict, so there "
                "is no round for her to spend. A ConsumedRecords belongs to "
                "Party.BOB or Party.CHARLIE."
            )
        self._party: Final[Party] = resolved
        self._spent: set[tuple[str, int]] = set()

    @property
    def party(self) -> Party:
        """Party: The verifier this ledger belongs to."""
        return self._party

    def __len__(self) -> int:
        """int: How many rounds this verifier has decided."""
        return len(self._spent)

    def __repr__(self) -> str:
        """Return a debugging representation naming the party and the count."""
        return (
            f"ConsumedRecords({self._party.value!r}, "
            f"{len(self._spent)} round(s) spent)"
        )

    def _key(self, record: RecipientRecord) -> tuple[str, int] | None:
        """Return the ledger key for ``record``, or ``None`` if untracked.

        Parameters
        ----------
        record : RecipientRecord
            The log being looked up or spent.

        Returns
        -------
        tuple of (str, int) or None
            ``(session_id, message_bit)``, or ``None`` when the record names no
            round.

        Raises
        ------
        TypeError
            If ``record`` is not a
            :class:`~sih141.protocol.records.RecipientRecord`.
        ValueError
            If the record belongs to a different party.
        """
        if not isinstance(record, RecipientRecord):
            raise TypeError(
                f"record must be a RecipientRecord, got "
                f"{type(record).__name__}; a ledger spends rounds of evidence, "
                f"not declarations."
            )
        if record.party is not self._party:
            raise ValueError(
                f"this ledger belongs to {self._party.value} and was handed "
                f"{record.party.value}'s record, which it must not see. A "
                f"consumed-records ledger is per verifier: the two verifiers "
                f"are adversaries to each other in half of this package's "
                f"attacks, so one verifier's history must not reach the "
                f"other's decision. Give {record.party.value} his own "
                f"ConsumedRecords."
            )
        if record.session_id is None:
            return None
        return (record.session_id, record.message_bit)

    def is_spent(self, record: RecipientRecord) -> bool:
        """Return whether this verifier has already decided ``record``'s round.

        Parameters
        ----------
        record : RecipientRecord
            The log about to be scored.

        Returns
        -------
        bool
            ``False`` for a record that names no round, always: there is no
            round to have spent, and answering ``True`` would refuse an honest
            first verification.

        Raises
        ------
        TypeError
            If ``record`` is not a
            :class:`~sih141.protocol.records.RecipientRecord`.
        ValueError
            If the record belongs to another party.
        """
        key = self._key(record)
        return key is not None and key in self._spent

    def spend(self, record: RecipientRecord) -> None:
        """Record that this verifier has reached a verdict on ``record``'s round.

        Idempotent, and a no-op for a record that names no round. Called by
        :func:`verify` **after** a verdict, never after a refusal: an abort has
        decided nothing, and spending on one would let a starved counterpart
        count or a mis-provenanced one burn a round the verifier never scored.

        Parameters
        ----------
        record : RecipientRecord
            The log a verdict was just reached on.

        Raises
        ------
        TypeError
            If ``record`` is not a
            :class:`~sih141.protocol.records.RecipientRecord`.
        ValueError
            If the record belongs to another party.
        """
        key = self._key(record)
        if key is not None:
            self._spent.add(key)

    def spent_rounds(self) -> frozenset[tuple[str, int]]:
        """Return the ``(session_id, message_bit)`` pairs already decided.

        A snapshot, so a caller that iterates it cannot be surprised by a
        concurrent verification, and a frozen one, so it cannot be used to
        forge an entry.

        Returns
        -------
        frozenset of (str, int)
        """
        return frozenset(self._spent)


def minimum_matched_count(params: ProtocolParams) -> int:
    """Return ``m_min``, the smallest matched set a verifier will score.

    The matched-count abort rule's threshold, derived from a Chernoff bound on
    the binomial lower tail rather than picked. The full derivation, and why the
    rule is a security control rather than a tidy-up, is in the module docstring
    under :ref:`matched-count-floor`; in brief, with ``mu = L/|B|`` and
    ``eps =`` :data:`HONEST_ABORT_BUDGET`::

        d      = sqrt(2 ln(1/eps) / mu)
        m_min  = max(1, ceil((1 - d) mu))

    so that an honest verifier aborts with probability at most ``eps`` and an
    honest run with probability at most ``2 eps``.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set the run executes under. Only
        :attr:`~sih141.protocol.params.ProtocolParams.key_length` and the
        alphabet size are used, through
        :attr:`~sih141.protocol.params.ProtocolParams.expected_matched`.

    Returns
    -------
    int
        At least ``1``, at most ``params.key_length``. Equal to ``1`` whenever
        ``L <= 2 |B| ln(1/eps)`` (``L <= 266`` for the three-basis alphabet),
        where the tail bound is vacuous at this budget and the rule degenerates
        to the standing requirement that a rate have a denominator.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.

    See Also
    --------
    verify : Applies the floor.
    VerificationAbort : What a verifier records when the floor is not met.
    enforced_repudiation_bound : What the floor buys, as a number.

    Notes
    -----
    Pure, deterministic and cheap: a square root and a ceiling over the
    parameter set, consuming no randomness (D3) and reading no run data (D4).

    This is the **per-verifier** floor -- ``verify`` computes one record's
    matched set, so this is the only floor it can evaluate without help. The
    pooled quantity the repudiation bounds are stated over, ``M = m_B + m_C``,
    gets its own floor from :func:`minimum_pooled_matched_count`, which is
    strictly larger than twice this one wherever either is non-degenerate, and
    which needs the count exchange of :mod:`sih141.protocol.tally` to evaluate.
    :func:`enforced_repudiation_bound` combines the two and
    ``tests/test_protocol_reconciliation.py`` pins the combination.

    Examples
    --------
    >>> from sih141.protocol.params import (
    ...     DEFAULT_PARAMS, DEMO_PARAMS, ProtocolParams
    ... )
    >>> from sih141.protocol.verify import minimum_matched_count
    >>> minimum_matched_count(DEFAULT_PARAMS)      # mu = 38400
    36555
    >>> minimum_matched_count(ProtocolParams(key_length=600))   # mu = 200
    67
    >>> minimum_matched_count(DEMO_PARAMS)  # L = 192: no power to spend
    1
    """
    return _chernoff_floor(_as_protocol_params(params).expected_matched)


def minimum_pooled_matched_count(params: ProtocolParams) -> int:
    """Return ``M_min``, the smallest *pooled* matched set a run will score.

    The pooled counterpart of :func:`minimum_matched_count`: the floor on
    ``M = m_B + m_C``, the matched records the two verifiers hold **together**,
    which is the count every repudiation bound in
    :mod:`sih141.protocol.analysis` is exponential in. It is the threshold of
    the check the recipients' count exchange
    (:func:`sih141.protocol.tally.exchange_matched_counts`) exists to make
    possible, and the module docstring derives it under :ref:`pooled-floor`.

    Same budget, same inequality, different variable::

        mu_M   = 2 L / |B|                                  = E[M]
        d      = sqrt(2 ln(1/eps) / mu_M)
        M_min  = max(1, ceil((1 - d) mu_M))

    The law being bounded is ``M ~ Binomial(2L, 1/|B|)`` **exactly**, which is
    the one step of this derivation that is not a copy of the per-verifier one
    and the one place it is easy to get wrong: after the symmetrisation exchange
    ``m_B`` and ``m_C`` are *not* independent, so the pooled law is not the
    convolution of the two marginals. It is the same distribution for a
    different reason -- conservation -- and :ref:`pooled-floor` gives the
    argument.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set the run executes under. Only
        :attr:`~sih141.protocol.params.ProtocolParams.key_length` and the
        alphabet size are used.

    Returns
    -------
    int
        At least ``1``, and ``1`` exactly when ``2L <= 2 |B| ln(1/eps)``, i.e.
        ``L <= 133`` for the three-basis alphabet -- half the crossover of the
        per-verifier floor, because the pooled count has twice the mean. Below
        it the tail bound says nothing at this budget and the pooled rule is
        implied by the per-verifier one rather than adding to it.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.

    See Also
    --------
    minimum_matched_count : The per-verifier floor, which this does not replace.
    sih141.protocol.tally.exchange_matched_counts : The message that makes this
        floor checkable at all.
    enforced_repudiation_bound : What the pair of floors buys, as a number.

    Notes
    -----
    ``M_min > 2 m_min`` wherever the per-verifier floor is non-degenerate, and
    that strict inequality is the whole content of the rule. Writing
    ``A = sqrt(2 mu ln(1/eps))`` with ``mu = L/|B|``, and ignoring the two
    ceilings,

    .. code-block:: text

        m_min = mu - A          M_min = 2 mu - sqrt(2) A
        M_min - 2 m_min = (2 - sqrt(2)) A ~ 0.586 A  >  0

    -- ``1080`` records at :data:`~sih141.protocol.params.DEFAULT_PARAMS` and
    growing like ``sqrt(L)``. A declaration aimed at ``2 m_min``, which is the
    largest total that leaves a per-verifier floor satisfiable at both ends
    while starving one of them, therefore lands *below* ``M_min`` at every key
    length. That is the split-coin route closed rather than priced.

    Pure, deterministic and cheap; consumes no randomness (D3) and reads no run
    data (D4).

    Examples
    --------
    >>> from sih141.protocol.params import (
    ...     DEFAULT_PARAMS, DEMO_PARAMS, ProtocolParams
    ... )
    >>> from sih141.protocol.verify import (
    ...     minimum_matched_count, minimum_pooled_matched_count
    ... )
    >>> minimum_pooled_matched_count(DEFAULT_PARAMS)     # mu_M = 76800
    74190
    >>> 2 * minimum_matched_count(DEFAULT_PARAMS)        # what the attack aims at
    73110
    >>> minimum_pooled_matched_count(ProtocolParams(key_length=600))
    212
    >>> minimum_pooled_matched_count(DEMO_PARAMS)   # L = 192, mu_M = 128
    22
    """
    checked = _as_protocol_params(params)
    return _chernoff_floor(2.0 * checked.expected_matched)


def _as_protocol_params(params: Any) -> ProtocolParams:
    """Return ``params`` unchanged, refusing anything that is not a set of them.

    Parameters
    ----------
    params : ProtocolParams
        The candidate.

    Returns
    -------
    ProtocolParams

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}; "
            f"the floor is a function of the key length and the alphabet size, "
            f"so it can only be read off a parameter set."
        )
    return params


def _chernoff_floor(mean_matched: float) -> int:
    """Return the largest floor whose honest lower tail stays inside the budget.

    The shared arithmetic of :func:`minimum_matched_count` and
    :func:`minimum_pooled_matched_count`: the two differ only in the mean they
    are handed, ``L/|B|`` for one verifier's own count and ``2L/|B|`` for the
    pair's. Keeping it in one place is what makes "the same budget, the same
    inequality" true of the code and not only of the prose.

    Parameters
    ----------
    mean_matched : float
        The honest mean of the binomial count being floored.

    Returns
    -------
    int
        ``max(1, ceil((1 - d) mu))`` with ``d = sqrt(2 ln(1/eps) / mu)``, and
        ``1`` where ``d >= 1`` leaves the Chernoff form vacuous.
    """
    # d < 1 -- the range the Chernoff form is stated for -- exactly when
    # 2 ln(1/eps) < mu. Outside it the bound says nothing and the floor is the
    # standing "a rate needs a denominator" rule.
    slack = 2.0 * _LOG_ABORT_BUDGET
    if slack >= mean_matched:
        return 1
    deviation = math.sqrt(slack / mean_matched)
    return max(1, math.ceil((1.0 - deviation) * mean_matched))


def enforced_repudiation_bound(params: ProtocolParams) -> float:
    """The unconditional repudiation bound *this module's* floor actually buys.

    The wiring between the rule and the number, so that no caller has to guess a
    threshold. :func:`~sih141.protocol.analysis.repudiation_bound_with_abort`
    takes the floor as an argument because ``analysis`` depends only on
    ``params`` and cannot see what a deployment enforces; this function supplies
    the floor :func:`verify` really applies, and is therefore the only
    a-priori repudiation figure this package is entitled to publish.

    **The event it bounds, exactly.** *Bob accepts and Charlie does not honour
    the signature* -- by returning a verdict of reject, by holding no matched
    record at all, or by reaching no verdict for any other reason the shipped
    rules allow. Under the pooled rule that is the whole of the failure space,
    because a verifier reaches a verdict only when

    .. code-block:: text

        m_B >= m_min   and   m_C >= m_min   and   m_B + m_C >= M_min

    all hold, and those conditions are the *same* for both verifiers: whenever
    Bob accepts, Charlie has reached a verdict too. So the guaranteed evidence
    base is ``M >= max(2 m_min, M_min)`` and

    .. code-block:: text

        P(repudiation)  <=  exp(-max(2 m_min, M_min) gap^2 / 8)

    holds for **every** Alice strategy, with no independence assumption and no
    model of her at all -- unlike
    :func:`~sih141.protocol.analysis.averaged_repudiation_bound`, whose
    ``6.9e-10`` needs the declaration to be independent of the recipients'
    logged bases and is false against the shipped ``Signer`` seam.

    **What changed, and why the number moved.** An earlier version of this
    function evaluated the bound at ``2 m_min`` and had to be quoted with a
    caveat: the per-verifier floor creates a third outcome -- *Bob accepts and
    Charlie returns no verdict*, his own matched set being non-empty but under
    his floor -- which no exponent covers, and which a log-reading signer
    reaches about half the time by aiming ``M`` at ``2 m_min`` and letting the
    symmetrisation coins split it. Closed form ``0.432`` at ``L = 360`` and
    ``0.466`` at ``L = 600``, against a published ``4.4e-05``; for the measured
    counts and their provenance see :ref:`split-coin-provenance`. Two things close it, and both ride on the one extra
    classical message of :mod:`sih141.protocol.tally`:

    * the **pooled floor** ``M >= M_min`` (:func:`minimum_pooled_matched_count`),
      which exceeds ``2 m_min`` at every non-degenerate key length, so the
      aimed-at total is refused outright; and
    * the **joint consequence** of the per-verifier floor -- a verifier below
      his own floor takes the other down with him
      (:attr:`AbortReason.COUNTERPART_BELOW_FLOOR`) -- which removes the
      asymmetric no-verdict from the outcome space altogether rather than
      pricing it.

    The second is what makes this function's event exhaustive; the first is what
    makes its exponent bigger. Both are needed, and :ref:`pooled-floor` shows
    why the first alone would leave ``eps ** (3 - 2 sqrt 2) = 4.9e-04``
    unclosed at *every* key length.

    **What is still outside it.** A signer who starves the evidence base
    produces a *joint* no-verdict: the run fails, nothing is transferred, and
    Bob holds no signature he can be told he should have been able to forward.
    That is a denial of service against availability, it is recorded rather than
    silent (:attr:`~sih141.protocol.session.SessionTranscript.aborted`), and no
    threshold defends against it -- a signer can equally decline to sign. It is
    named here so that its absence from the number is deliberate.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set the run executes under.

    Returns
    -------
    float
        An upper bound in ``[0, 1]``. Order one at short key lengths, where the
        floors degenerate and there is no statistical power to spend -- which is
        the honest reading of a demonstration key, not a defect.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.

    See Also
    --------
    minimum_matched_count : The per-verifier floor.
    minimum_pooled_matched_count : The pooled floor, which usually dominates.
    sih141.protocol.tally.exchange_matched_counts : The message both floors'
        joint enforcement rests on.
    sih141.protocol.analysis.repudiation_bound : The per-run form, at the
        *observed* ``M``, which is the number a completed run should quote.
    sih141.protocol.analysis.averaged_repudiation_bound : The (IND)-dependent
        average that must not be quoted as unconditional.

    Notes
    -----
    This number is earned only by a run whose recipients actually exchanged
    counts. A run made with
    :func:`sih141.protocol.tally.no_count_exchange` -- the Phase 3 seam for
    measuring the attack -- enforces the per-verifier floor alone, and the most
    it is entitled to is
    ``repudiation_bound_with_abort(params, minimum_matched_records=2 * m_min)``
    *plus* the split-coin route, which is of order ``1/2``.
    :attr:`~sih141.protocol.session.SessionTranscript.counts_exchanged` says
    which kind of run a transcript is.

    Pure and deterministic; consumes no randomness (D3) and reads no run data
    (D4).

    Examples
    --------
    >>> from sih141.protocol.params import DEFAULT_PARAMS, DEMO_PARAMS
    >>> from sih141.protocol.verify import enforced_repudiation_bound
    >>> f"{enforced_repudiation_bound(DEFAULT_PARAMS):.2e}"
    '1.41e-09'
    >>> round(enforced_repudiation_bound(DEMO_PARAMS), 4)  # no claim at L=192
    0.994
    """
    # Imported here rather than at module scope: ``analysis`` is a leaf that
    # depends only on ``params``, and keeping the edge local documents that
    # verification's *rule* does not depend on the analysis of it.
    from sih141.protocol.analysis import repudiation_bound_with_abort

    return repudiation_bound_with_abort(
        params, minimum_matched_records=guaranteed_pooled_matched_count(params)
    )


def guaranteed_pooled_matched_count(params: ProtocolParams) -> int:
    """Return the floor on ``M = m_B + m_C`` that the shipped rules guarantee.

    ``max(2 * minimum_matched_count(params), minimum_pooled_matched_count(params))``
    -- the two conditions a run must satisfy to reach any verdict at all, read
    as a single lower bound on the pooled evidence base. The pooled floor
    dominates wherever the per-verifier one is non-degenerate; the doubled
    per-verifier floor takes over at key lengths so short that the pooled
    Chernoff form has nothing to say.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set the run executes under.

    Returns
    -------
    int
        At least ``1``.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.

    See Also
    --------
    enforced_repudiation_bound : Evaluates the repudiation bound here.

    Examples
    --------
    >>> from sih141.protocol.params import DEFAULT_PARAMS, ProtocolParams
    >>> from sih141.protocol.verify import guaranteed_pooled_matched_count
    >>> guaranteed_pooled_matched_count(DEFAULT_PARAMS)
    74190
    >>> guaranteed_pooled_matched_count(ProtocolParams(key_length=24))
    2
    """
    checked = _as_protocol_params(params)
    return max(
        2 * minimum_matched_count(checked),
        minimum_pooled_matched_count(checked),
    )


@dataclass(frozen=True)
class VerificationAbort:
    """A recorded **no-verdict**: verification refused to score, and why.

    Not an acceptance and not a rejection, and deliberately a different type
    from :class:`VerificationResult` so that no Phase 4 or Phase 5 aggregation
    can average it into either. It carries no ``accepted`` field, no ``rate``
    and no ``threshold``, because none of those exist for a run that reached no
    decision -- a plumbing failure and a signature failure must not be reported
    through the same channel.

    Frozen, hashable and made only of :class:`int`, :class:`float` and
    :class:`enum.StrEnum` members, so it drops straight into :func:`json.dumps`
    and into a :class:`~sih141.protocol.session.SessionTranscript` beside the
    verdicts.

    Parameters
    ----------
    party : Party or str
        The verifier who reached no verdict. Alice is refused: she signs and
        keeps no record.
    reason : AbortReason or str
        Which floor was not met -- or, for the two unpoolable cases, which floor
        could not be applied at all; or, for the two round cases of
        :ref:`replay`, that no counting rule was reached because the declaration
        and the record are not one transaction. Cross-checked against the
        counts, so the label and the numbers cannot disagree: see
        :class:`AbortReason` for the eight cases and the order :func:`verify`
        tests them in.
    matched_count : int
        ``|M_R|`` as observed. May be ``0``. Below ``minimum_matched`` for the
        two own-count reasons and at or above it for the four pair reasons,
        since a verifier only reaches those checks having cleared his own floor.
        Unconstrained for the two round reasons, which are recorded before any
        floor is applied and carry the count for diagnosis only.
    minimum_matched : int
        ``m_min`` from :func:`minimum_matched_count` for the parameter set the
        run executed under. Carried rather than recomputed so that a stored
        transcript still says what the rule was when the run happened.
    expected_matched : float
        ``L/|B|``, the honest mean. Carried because it is the number that makes
        the shortfall legible: ``13`` matched positions is unremarkable until it
        is set beside ``38400``.
    key_length : int
        ``L``.
    message_bit : int
        The bit that was being signed, ``0`` or ``1``.
    counterpart_matched : int or None, optional
        ``m`` as the *other* verifier reported it over the count exchange
        (:mod:`sih141.protocol.tally`), or ``None`` on a run whose recipients
        did not exchange counts. Required by the four pair reasons, which are
        statements about the pair and are unreadable without it; carried as
        context by the other four when it happens to be known.
    minimum_pooled : int or None, optional
        ``M_min`` from :func:`minimum_pooled_matched_count`, or ``None`` when no
        exchange happened. Required by the four pair reasons, for the same
        reason ``minimum_matched`` is carried: a stored transcript has to say
        what the rule was -- including on the refusals that say the rule could
        not be applied.

    Raises
    ------
    TypeError
        If a count is not an integer or ``None`` where optional, or
        ``expected_matched`` is not a real number.
    ValueError
        If ``party`` is Alice or names no party; if ``reason`` is not an
        :class:`AbortReason`; if the counts are negative, if
        ``minimum_matched < 1``, if a per-verifier count exceeds ``key_length``;
        if an own-count reason has ``matched_count >= minimum_matched`` (that is
        a verdict, not an abort) or a pair reason has
        ``matched_count < minimum_matched`` (that is an own-count abort); if a
        pair reason is missing ``counterpart_matched`` or ``minimum_pooled``;
        or if ``reason`` disagrees with the counts in any other way.

    See Also
    --------
    MatchedSetTooSmall : The exception that carries one out of :func:`verify`.
    VerificationResult : The other outcome of Phase C.
    sih141.protocol.tally.PooledMatchedCounts : The exchange the two pooled
        reasons are read off.

    Examples
    --------
    >>> from sih141.protocol.verify import AbortReason, VerificationAbort
    >>> abort = VerificationAbort(
    ...     party="Bob",
    ...     reason=AbortReason.EMPTY_MATCHED_SET,
    ...     matched_count=0,
    ...     minimum_matched=67,
    ...     expected_matched=200.0,
    ...     key_length=600,
    ...     message_bit=0,
    ... )
    >>> abort.shortfall, abort.accepted_is_undefined
    (67, True)
    """

    party: Party
    reason: AbortReason
    matched_count: int
    minimum_matched: int
    expected_matched: float
    key_length: int
    message_bit: int
    counterpart_matched: int | None = None
    minimum_pooled: int | None = None

    def __post_init__(self) -> None:
        """Coerce the fields and enforce that this really is a no-verdict."""
        resolved = _as_party(self.party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice reaches no verdict to abort: she is the signer, holds "
                "no measurement record and has no acceptance threshold. A "
                "VerificationAbort belongs to Party.BOB or Party.CHARLIE."
            )
        object.__setattr__(self, "party", resolved)
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        object.__setattr__(self, "reason", _as_abort_reason(self.reason))
        object.__setattr__(
            self, "key_length", _as_count(self.key_length, "key_length")
        )
        object.__setattr__(
            self, "matched_count", _as_count(self.matched_count, "matched_count")
        )
        object.__setattr__(
            self,
            "minimum_matched",
            _as_count(self.minimum_matched, "minimum_matched"),
        )
        object.__setattr__(
            self,
            "counterpart_matched",
            _as_optional_count(
                self.counterpart_matched, "counterpart_matched"
            ),
        )
        object.__setattr__(
            self,
            "minimum_pooled",
            _as_optional_count(self.minimum_pooled, "minimum_pooled"),
        )
        if isinstance(self.expected_matched, bool) or not isinstance(
            self.expected_matched, numbers.Real
        ):
            raise TypeError(
                f"expected_matched must be a real number, got "
                f"{type(self.expected_matched).__name__}; it is L/|B|."
            )
        object.__setattr__(
            self, "expected_matched", float(self.expected_matched)
        )

        if self.key_length < 1:
            raise ValueError(
                f"key_length must be at least 1, got {self.key_length}; a run "
                f"with no key positions has nothing to verify."
            )
        if self.minimum_matched < 1:
            raise ValueError(
                f"minimum_matched must be at least 1, got "
                f"{self.minimum_matched}. Even where the Chernoff tail is "
                f"vacuous the floor is 1, because a rate needs a denominator; "
                f"see minimum_matched_count."
            )
        for name, value in (
            ("matched_count", self.matched_count),
            ("minimum_matched", self.minimum_matched),
            ("counterpart_matched", self.counterpart_matched),
        ):
            if value is not None and value > self.key_length:
                raise ValueError(
                    f"{name} ({value}) cannot exceed key_length "
                    f"({self.key_length}); the matched set is a subset of the "
                    f"key positions."
                )
        if (
            self.minimum_pooled is not None
            and self.minimum_pooled > 2 * self.key_length
        ):
            raise ValueError(
                f"minimum_pooled ({self.minimum_pooled}) cannot exceed "
                f"2 * key_length ({2 * self.key_length}); the pooled count is "
                f"over the two verifiers' matched sets together, so its "
                f"largest possible value is 2 L."
            )
        if not math.isfinite(self.expected_matched) or not (
            0.0 < self.expected_matched <= self.key_length
        ):
            raise ValueError(
                f"expected_matched must be finite and lie in "
                f"(0, {self.key_length}], got {self.expected_matched!r}. It is "
                f"L/|B|, the mean of Binomial(L, 1/|B|)."
            )
        self._check_reason_against_counts()

    def _check_reason_against_counts(self) -> None:
        """Enforce that the label and the numbers are one observation.

        The verifier reaches the checks in the order :func:`verify` tests them:
        first whether this is even the right, undecided round; then his own
        count; then whether the counterpart's count is about the same
        declaration; then the pooled total; then his counterpart's count. So
        the four pair reasons *imply* that this verifier cleared his own floor,
        which is asserted rather than assumed -- an abort labelled ``pooled`` on
        a verifier who was starved himself would misattribute a local failure to
        the pair. The two round reasons imply nothing about any count and are
        checked against nothing.

        :attr:`AbortReason.COUNTS_FROM_TWO_DECLARATIONS` is the one reason with
        nothing further to check: its whole content is that ``matched_count``
        and ``counterpart_matched`` are not comparable, so no relation between
        them can be insisted on without contradicting the refusal itself.

        Raises
        ------
        ValueError
            If the reason and the counts describe different runs, or if a pair
            reason is missing the exchanged numbers it is a statement about.
        """
        if self.reason in _ROUND_REASONS:
            # Nothing to cross-check. These two refuse *before* any counting
            # rule is reached -- the declaration and the record are not the same
            # transaction, or the transaction is already closed -- so the counts
            # they carry are context for a reader and are not a claim about any
            # floor. Insisting on a relation here would assert something the
            # refusal explicitly declines to assert; see :ref:`replay`.
            return
        own_short = self.matched_count < self.minimum_matched
        if self.reason in _OWN_COUNT_REASONS:
            if not own_short:
                raise ValueError(
                    f"matched_count ({self.matched_count}) is at or above "
                    f"minimum_matched ({self.minimum_matched}), so this "
                    f"verifier met his own floor. Record a VerificationResult, "
                    f"or -- if the pair's evidence is what fell short -- one of "
                    f"the pooled reasons "
                    f"({AbortReason.POOLED_BELOW_FLOOR.value!r}, "
                    f"{AbortReason.COUNTERPART_BELOW_FLOOR.value!r}). A "
                    f"no-verdict outcome that a Phase 5 table could not "
                    f"distinguish from a decision would defeat the point of "
                    f"having two types."
                )
            expected_reason = (
                AbortReason.EMPTY_MATCHED_SET
                if self.matched_count == 0
                else AbortReason.BELOW_FLOOR
            )
            if self.reason is not expected_reason:
                raise ValueError(
                    f"reason={self.reason.value!r} contradicts matched_count="
                    f"{self.matched_count}: "
                    f"{AbortReason.EMPTY_MATCHED_SET.value!r} means exactly "
                    f"|M_R| == 0 and {AbortReason.BELOW_FLOOR.value!r} exactly "
                    f"0 < |M_R| < m_min. The label and the numbers have to be "
                    f"the same observation."
                )
            return

        # A reason about the pair. Both exchanged numbers are mandatory, and
        # this verifier must have cleared his own floor to have reached the
        # check.
        if self.counterpart_matched is None or self.minimum_pooled is None:
            raise ValueError(
                f"reason={self.reason.value!r} is a statement about the two "
                f"verifiers together, so it needs both counterpart_matched "
                f"(got {self.counterpart_matched!r}) and minimum_pooled (got "
                f"{self.minimum_pooled!r}). Those numbers arrive over the "
                f"recipients' count exchange -- see sih141.protocol.tally -- "
                f"and an abort that quoted neither would be unreadable and "
                f"uncheckable."
            )
        if own_short:
            raise ValueError(
                f"reason={self.reason.value!r} says the pair's evidence fell "
                f"short, but this verifier's own matched_count "
                f"({self.matched_count}) is already below his floor "
                f"({self.minimum_matched}). verify() tests the local floor "
                f"first, so that run aborts as "
                f"{AbortReason.EMPTY_MATCHED_SET.value!r} or "
                f"{AbortReason.BELOW_FLOOR.value!r}; labelling it pooled would "
                f"blame the pair for a local failure."
            )
        if self.reason in _UNPOOLABLE_REASONS:
            # The two counts cannot be shown to be about one declaration --
            # either the counterpart's names another or it names none -- so
            # their sum is not a pooled count and no arithmetic relation
            # between them is being claimed. Both numbers are recorded exactly
            # because a reader has to be able to see the total that was *not*
            # enforced.
            return
        pooled = self.matched_count + self.counterpart_matched
        if self.reason is AbortReason.POOLED_BELOW_FLOOR:
            if pooled >= self.minimum_pooled:
                raise ValueError(
                    f"reason={self.reason.value!r} but m_B + m_C = "
                    f"{self.matched_count} + {self.counterpart_matched} = "
                    f"{pooled}, which meets the pooled floor "
                    f"({self.minimum_pooled}). The label and the numbers have "
                    f"to be the same observation."
                )
            return
        # COUNTERPART_BELOW_FLOOR: the pooled total was fine and the other
        # verifier was not, which is the imbalance the joint rule refuses.
        if pooled < self.minimum_pooled:
            raise ValueError(
                f"reason={self.reason.value!r} but m_B + m_C = {pooled} is "
                f"below the pooled floor ({self.minimum_pooled}), which "
                f"verify() tests first. That run aborts as "
                f"{AbortReason.POOLED_BELOW_FLOOR.value!r}."
            )
        if self.counterpart_matched >= self.minimum_matched:
            raise ValueError(
                f"reason={self.reason.value!r} but the counterpart reported "
                f"{self.counterpart_matched} matched records, which meets the "
                f"per-verifier floor ({self.minimum_matched}). Both verifiers "
                f"cleared every floor, so both reached a verdict."
            )

    # -- derived views ------------------------------------------------------ #

    @property
    def pooled_count(self) -> int | None:
        """int or None: ``M = m_B + m_C``, or ``None`` with no exchange.

        The evidence base every repudiation bound is exponential in, as this run
        actually produced it. ``None`` exactly when
        :attr:`counterpart_matched` is, i.e. on a run whose recipients did not
        compare counts.
        """
        if self.counterpart_matched is None:
            return None
        return self.matched_count + self.counterpart_matched

    @property
    def shortfall(self) -> int:
        """int: How far under *the floor that was missed* this run fell.

        Always about the floor named by :attr:`reason`: the verifier's own for
        the two own-count reasons, the pooled floor for
        :attr:`AbortReason.POOLED_BELOW_FLOOR`, and the counterpart's own for
        :attr:`AbortReason.COUNTERPART_BELOW_FLOOR`. Reading it against any
        other floor would report a shortfall nobody measured.

        At least ``1`` on each of those four, and exactly ``0`` on the four that
        name no floor -- :attr:`AbortReason.COUNTS_FROM_TWO_DECLARATIONS` and
        :attr:`AbortReason.COUNT_OF_UNRECORDED_PROVENANCE`, which report that
        the pooled rule could not be *applied*, and
        :attr:`AbortReason.SESSION_MISMATCH` and
        :attr:`AbortReason.RECORD_ALREADY_VERIFIED`, which report that no
        counting rule was reached at all. Quoting a distance from a floor nobody
        evaluated would invite a reader to treat "one record short" and "not the
        same experiment" as the same finding.
        """
        if self.reason in _UNPOOLABLE_REASONS or self.reason in _ROUND_REASONS:
            return 0
        if self.reason is AbortReason.POOLED_BELOW_FLOOR:
            assert self.minimum_pooled is not None  # enforced in __post_init__
            pooled = self.pooled_count
            assert pooled is not None
            return self.minimum_pooled - pooled
        if self.reason is AbortReason.COUNTERPART_BELOW_FLOOR:
            assert self.counterpart_matched is not None
            return self.minimum_matched - self.counterpart_matched
        return self.minimum_matched - self.matched_count

    @property
    def is_pooled(self) -> bool:
        """bool: ``True`` iff the refusal is a statement about the pair.

        The four pair reasons need the count exchange to have happened and
        carry :attr:`counterpart_matched`; the two own-count reasons are
        reachable with or without it, and the two round reasons of
        :ref:`replay` are about the pairing rather than about anybody's
        evidence and answer ``False`` here. Phase 4 and Phase 5 read this to
        separate "this verifier had nothing to score" from "the two of them
        together did not clear the pooled rule", which are different findings
        about a run. Read :attr:`reason` to separate the two cases where the
        pooled rule was never evaluated --
        :attr:`AbortReason.COUNTS_FROM_TWO_DECLARATIONS` and
        :attr:`AbortReason.COUNT_OF_UNRECORDED_PROVENANCE` -- from the two where
        it was and failed.
        """
        return self.reason in _PAIR_REASONS

    @property
    def accepted_is_undefined(self) -> bool:
        """bool: Always ``True``, and it exists to be read.

        A caller that reaches for ``.accepted`` on this object gets an
        :exc:`AttributeError` rather than a plausible ``False``. This property
        is the answer to "what did the verifier decide?" -- nothing -- in a form
        that survives duck-typed code paths shared with
        :class:`VerificationResult`.
        """
        return True

    def summary(self) -> str:
        """Return a one-line human-readable account of the refusal.

        Returns
        -------
        str
            Party, bit, the counts, the floor and the reason, e.g.
            ``'Bob NO VERDICT bit 0: 0/600 positions matched, floor 67,
            honest mean 200.0 (empty-matched-set). Not a rejection.'`` A refusal
            about the pair adds the pair's numbers, because on one of those this
            verifier's own count is *fine* and quoting it alone would read as a
            contradiction. On
            :attr:`AbortReason.COUNTS_FROM_TWO_DECLARATIONS` the pair's total is
            printed with the two counts, since seeing the number that was *not*
            enforced is the point.

        Examples
        --------
        >>> from sih141.protocol.verify import AbortReason, VerificationAbort
        >>> VerificationAbort(
        ...     "Charlie", AbortReason.BELOW_FLOOR, 13, 67, 200.0, 600, 1
        ... ).summary()[:19]
        'Charlie NO VERDICT '
        >>> VerificationAbort(
        ...     "Bob", AbortReason.POOLED_BELOW_FLOOR, 80, 67, 200.0, 600, 0,
        ...     counterpart_matched=60, minimum_pooled=212,
        ... ).summary()
        'Bob NO VERDICT bit 0: 80/600 positions matched, floor 67, honest mean \
200.0; pooled M = 80 + 60 = 140, pooled floor 212 \
(pooled-matched-count-below-floor). Not a rejection.'
        """
        pooled = ""
        if self.counterpart_matched is not None:
            pooled = (
                f"; pooled M = {self.matched_count} + "
                f"{self.counterpart_matched} = {self.pooled_count}, pooled "
                f"floor {self.minimum_pooled}"
            )
        return (
            f"{self.party.value} NO VERDICT bit {self.message_bit}: "
            f"{self.matched_count}/{self.key_length} positions matched, floor "
            f"{self.minimum_matched}, honest mean {self.expected_matched:.1f}"
            f"{pooled} ({self.reason.value}). Not a rejection."
        )

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the refusal.

        Returns
        -------
        dict
            One key per field. :class:`~sih141.protocol.params.Party` and
            :class:`AbortReason` are :class:`enum.StrEnum` members, so the
            result passes to :func:`json.dumps` unchanged.

        Examples
        --------
        >>> import json
        >>> from sih141.protocol.verify import AbortReason, VerificationAbort
        >>> blob = VerificationAbort(
        ...     "Bob", AbortReason.EMPTY_MATCHED_SET, 0, 1, 3.0, 9, 0
        ... ).to_dict()
        >>> json.loads(json.dumps(blob))["reason"]
        'empty-matched-set'
        """
        return {
            "party": self.party,
            "reason": self.reason,
            "matched_count": self.matched_count,
            "minimum_matched": self.minimum_matched,
            "expected_matched": self.expected_matched,
            "key_length": self.key_length,
            "message_bit": self.message_bit,
            "counterpart_matched": self.counterpart_matched,
            "minimum_pooled": self.minimum_pooled,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationAbort:
        """Rebuild a refusal from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain every key :meth:`to_dict` emits, except
            ``"counterpart_matched"`` and ``"minimum_pooled"``, which default to
            ``None`` so that a transcript written before the count exchange
            existed still restores. It can only have recorded an own-count
            refusal, and those two fields are optional for exactly that reason.

        Returns
        -------
        VerificationAbort

        Raises
        ------
        KeyError
            If a required field is missing.
        ValueError
            If the restored fields are not self-consistent.
        """
        return cls(
            party=data["party"],
            reason=data["reason"],
            matched_count=data["matched_count"],
            minimum_matched=data["minimum_matched"],
            expected_matched=data["expected_matched"],
            key_length=data["key_length"],
            message_bit=data["message_bit"],
            counterpart_matched=data.get("counterpart_matched"),
            minimum_pooled=data.get("minimum_pooled"),
        )


class MatchedSetTooSmall(ValueError):
    """Verification reached no verdict: the matched set was too small to score.

    A :class:`ValueError` subclass, so callers written before the abort rule
    existed still catch it, and a named type so that callers written after it
    can tell a no-verdict outcome from a wiring error (wrong message bit, wrong
    length, wrong parameter set) without matching on message text.

    :meth:`~sih141.protocol.session.QDSSession.verify` records
    :attr:`abort` on the session before letting this propagate, and
    :meth:`~sih141.protocol.session.QDSSession.run` catches it, so an attacker
    who starves the evidence base costs the harness a verdict rather than a run.

    Parameters
    ----------
    abort : VerificationAbort
        The structured no-verdict outcome. The exception message is built from
        it, so the text a human reads and the record a table aggregates cannot
        drift apart.

    Attributes
    ----------
    abort : VerificationAbort
        As passed.

    See Also
    --------
    verify_or_abort : The same decision without the exception.
    """

    def __init__(self, abort: VerificationAbort) -> None:
        if not isinstance(abort, VerificationAbort):
            raise TypeError(
                f"abort must be a VerificationAbort, got "
                f"{type(abort).__name__}; the exception's message is derived "
                f"from it."
            )
        self.abort = abort
        super().__init__(_abort_message(abort))


def _as_abort_reason(reason: AbortReason | str) -> AbortReason:
    """Coerce a label to an :class:`AbortReason`.

    Parameters
    ----------
    reason : AbortReason or str
        The member, or its value.

    Returns
    -------
    AbortReason

    Raises
    ------
    TypeError
        If ``reason`` is neither an :class:`AbortReason` nor a string.
    ValueError
        If the string names no reason.
    """
    if isinstance(reason, AbortReason):
        return reason
    if not isinstance(reason, str):
        raise TypeError(
            f"reason must be an AbortReason or its string value, got "
            f"{type(reason).__name__}"
        )
    try:
        return AbortReason(reason)
    except ValueError:
        known = ", ".join(member.value for member in AbortReason)
        raise ValueError(
            f"reason must be one of {known}, got {reason!r}"
        ) from None


def _abort_message(abort: VerificationAbort) -> str:
    """Build the human-facing message for a :class:`MatchedSetTooSmall`.

    Parameters
    ----------
    abort : VerificationAbort
        The refusal being reported.

    Returns
    -------
    str
        A message that says which kind of failure this is, since the reader's
        first instinct -- logging it as a rejection -- is the one thing that
        must not happen.
    """
    party = abort.party.value
    # Split so that the one refusal which is *not* about a starved matched set
    # can keep the framing -- and the sentence a caller greps for -- without
    # claiming the verifier had no evidence.
    not_a_signature_failure = (
        "This is not a signature failure and is not reported as one"
    )
    recorded_not_lost = (
        "QDSSession records it as a no-verdict outcome (VerificationAbort) "
        "rather than losing the run."
    )
    common = (
        f"{not_a_signature_failure}: accepting would accept any declaration "
        f"whatsoever on zero evidence, and rejecting would be recorded as a "
        f"forgery detection when no evidence of forgery exists. "
        f"{recorded_not_lost}"
    )
    if abort.reason is AbortReason.SESSION_MISMATCH:
        return (
            f"the declaration does not name the distribution round "
            f"{party}'s log was made in, so there is nothing here to score. "
            f"The key states are one-time: a declaration and a record belong to "
            f"exactly one round, and a rate computed across two of them is not "
            f"a weak measurement of anything -- it is the chance noise of "
            f"scoring against an unrelated key, near (1 - 1/|B|)/2, which is "
            f"why this was refused instead of being reported as the rejection "
            f"it would usually have looked like. "
            f"{not_a_signature_failure}: the verifier has learned nothing about "
            f"the signature, only that he was handed the wrong pair. "
            f"{recorded_not_lost} The usual causes are a captured signature "
            f"re-presented after its round closed and a harness that paired one "
            f"run's declaration with another run's logs -- see "
            f"sih141.protocol.verify on the replay defence -- so what to "
            f"investigate is which round each half came from."
        )
    if abort.reason is AbortReason.RECORD_ALREADY_VERIFIED:
        return (
            f"{party} has already reached a verdict on this distribution round "
            f"and will not reach a second one. One round yields one verdict per "
            f"verifier: the evidence is spent, and re-deciding it would let a "
            f"replayed declaration collect as many acceptances as it was "
            f"presented times. "
            f"{not_a_signature_failure}: nothing new was learned about the "
            f"signature, and the verdict already reached still stands -- read "
            f"it there rather than asking again. {recorded_not_lost} "
            f"If this is a harness verifying twice on purpose, give that "
            f"verification its own ConsumedRecords, or none; if it is not, the "
            f"second presentation is the replay this ledger exists for."
        )
    if abort.reason is AbortReason.POOLED_BELOW_FLOOR:
        return (
            f"the two verifiers together hold {abort.pooled_count} matched "
            f"records ({party} {abort.matched_count}, the other verifier "
            f"{abort.counterpart_matched}), below the pooled matched-count "
            f"floor of {abort.minimum_pooled}, so neither scores. {common} "
            f"{party} cleared his own floor of {abort.minimum_matched}: this "
            f"is a statement about the pair, and it is the check the "
            f"recipients' count exchange exists to make. Under honest "
            f"operation M = m_B + m_C is Binomial(2L, 1/|B|) with mean "
            f"{2 * abort.expected_matched:.1f}, and a Chernoff lower tail puts "
            f"the chance of an honest run falling below the pooled floor at "
            f"{HONEST_ABORT_BUDGET:.3g}. A declaration whose *total* matched "
            f"count is aimed low is what this refuses -- see "
            f"sih141.protocol.verify on the split-coin route -- so investigate "
            f"the declaration, not the verifiers."
        )
    if abort.reason is AbortReason.COUNTERPART_BELOW_FLOOR:
        return (
            f"the other verifier reported only {abort.counterpart_matched} "
            f"matched records, below the per-verifier floor of "
            f"{abort.minimum_matched}, so {party} reaches no verdict either -- "
            f"even though his own matched set holds {abort.matched_count} of "
            f"the {abort.key_length} key positions and would have been scored. "
            f"{common} The floor's consequence is joint on purpose: a "
            f"signature the other verifier cannot score is not one this "
            f"verifier can be told he should have transferred, and accepting "
            f"here is exactly the asymmetric outcome a signer who splits the "
            f"evidence base is aiming for. The pair's total was "
            f"{abort.pooled_count} against a pooled floor of "
            f"{abort.minimum_pooled}, so the shortfall is in the *split*, not "
            f"in the total."
        )
    if abort.reason is AbortReason.COUNT_OF_UNRECORDED_PROVENANCE:
        return (
            f"the count {party} was given names no declaration, so it cannot "
            f"be shown to have been computed against the one he is scoring: "
            f"the two numbers ({party} {abort.matched_count}, the other "
            f"verifier {abort.counterpart_matched}) may or may not be a pooled "
            f"count, and the pooled floor of {abort.minimum_pooled} is not "
            f"applied to a sum that might belong to no run. "
            f"{not_a_signature_failure}: what failed is the bookkeeping, the "
            f"verifier has learned nothing about the signature either way, and "
            f"a rejection here would be recorded as a forgery detection when "
            f"no evidence of forgery exists. {recorded_not_lost} "
            f"An unprovenanced count is refused rather than taken at its word "
            f"because Phase C' is the recipients' own step and a recipient is "
            f"the adversary this check exists for: a check that can be "
            f"switched off by declining to answer is not one. The usual cause "
            f"is a count exchange that does not fill in the declaration it "
            f"counted -- see sih141.protocol.tally on the binding being "
            f"mandatory -- so what to investigate is the exchange, not the "
            f"verifiers."
        )
    if abort.reason is AbortReason.COUNTS_FROM_TWO_DECLARATIONS:
        return (
            f"the count {party} was given was computed against a different "
            f"declaration from the one he is scoring, so the two numbers "
            f"({party} {abort.matched_count}, the other verifier "
            f"{abort.counterpart_matched}) are not a pooled count and the "
            f"pooled floor of {abort.minimum_pooled} has nothing to be applied "
            f"to. Their sum, {abort.pooled_count}, is no run's M. "
            f"{not_a_signature_failure}: what failed is the bookkeeping, the "
            f"verifier has learned nothing about the signature either way, and "
            f"a rejection here would be recorded as a forgery detection when "
            f"no evidence of forgery exists. {recorded_not_lost} "
            f"m_B + m_C is conserved across one fixed pair of records against "
            f"one fixed declaration and means nothing across two, so the run "
            f"is refused rather than scored on a mixed total -- see "
            f"sih141.protocol.verify on counting against one declaration. The "
            f"usual cause is a forwarding hop that altered the declaration "
            f"after the recipients had already exchanged counts: what to "
            f"investigate is the hop, not the verifiers."
        )
    if abort.reason is AbortReason.EMPTY_MATCHED_SET:
        return (
            f"{party}'s matched set is empty: his measurement basis differed "
            f"from the declared one at all {abort.key_length} positions, so the "
            f"mismatch rate is 0/0 and there is no verdict to reach. {common} "
            f"Honest operation puts |M| near {abort.expected_matched:.1f}, and "
            f"the matched-count floor for this parameter set is "
            f"{abort.minimum_matched}. In practice this means the key is far "
            f"too short, the record was paired with the wrong key, or the "
            f"declaration was built to avoid both recipients' logged bases -- "
            f"see sih141.protocol.verify on who can reach it."
        )
    return (
        f"{party}'s matched set holds only {abort.matched_count} of the "
        f"{abort.key_length} key positions, below the matched-count floor of "
        f"{abort.minimum_matched}, so verification aborts instead of scoring. "
        f"{common} Under honest operation |M| is Binomial(L, 1/|B|) with mean "
        f"{abort.expected_matched:.1f}, and a Chernoff lower tail puts the "
        f"chance of an honest verifier falling below the floor at "
        f"{HONEST_ABORT_BUDGET:.3g}. Every bound the scheme quotes is "
        f"exp(-Theta(|M|)), so a rate computed from {abort.matched_count} "
        f"positions would carry a confidence it does not have -- which is "
        f"precisely what a signer who starves the matched set is buying. "
        f"Investigate the declaration and the distribution; raising L raises "
        f"the floor with it, and lowering the floor is not a fix."
    )


@dataclass(frozen=True)
class VerificationResult:
    """One verifier's decision, together with the numbers it was reached from.

    Frozen, hashable and entirely made of :class:`int`, :class:`float`,
    :class:`bool` and :class:`~sih141.protocol.params.Party` (a
    :class:`enum.StrEnum`), so it drops straight into :func:`json.dumps`, into a
    Phase 5 results table and into the Phase 6 dashboard with no encoder.

    The counts are carried rather than just the verdict because a bare
    ``accepted`` is unusable for the things the project has to show: the size of
    the evidence base (:attr:`matched_count`), how close to the cut the run
    landed (:attr:`margin`), and how the same physical channel can fall on
    opposite sides of ``s_a`` and ``s_v``.

    Parameters
    ----------
    party : Party or str
        The verifier this decision belongs to,
        :attr:`~sih141.protocol.params.Party.BOB` or
        :attr:`~sih141.protocol.params.Party.CHARLIE`. Alice is refused: she
        signs and keeps no record.
    accepted : bool
        The verdict. Must equal ``rate <= threshold``; the invariant is enforced
        so that a displayed number and a displayed verdict can never disagree.
    matched_count : int
        ``|M_R|``, the number of positions where the recipient's basis equalled
        the declared one. Must be at least ``1``: a rate needs a denominator.
    mismatches : int
        ``e_R``, disagreements *within* the matched set. Never more than
        :attr:`matched_count`.
    rate : float
        ``r_R = mismatches / matched_count``.
    threshold : float
        The party's cut -- ``s_a`` for Bob, ``s_v`` for Charlie.
    key_length : int
        ``L``. Carried so that :attr:`unmatched_count` -- the evidence that was
        correctly *discarded* -- is visible rather than inferred.
    message_bit : int
        The bit that was signed, ``0`` or ``1``. A run holds two independent
        verifications at any time and they must never be confused.

    Raises
    ------
    TypeError
        If ``accepted`` is not a :class:`bool`, a count is not an integer, or a
        rate/threshold is not a real number.
    ValueError
        If ``party`` is Alice or names no party; if the counts are negative or
        violate ``1 <= matched_count <= key_length`` or
        ``mismatches <= matched_count``; if ``rate`` is not
        ``mismatches / matched_count``; or if ``accepted`` disagrees with
        ``rate <= threshold``.

    See Also
    --------
    verify : The only thing that should normally construct one of these.

    Examples
    --------
    >>> from sih141.protocol.verify import VerificationResult
    >>> result = VerificationResult(
    ...     party="Bob",
    ...     accepted=True,
    ...     matched_count=32,
    ...     mismatches=1,
    ...     rate=1 / 32,
    ...     threshold=1 / 32,
    ...     key_length=96,
    ...     message_bit=0,
    ... )
    >>> result.unmatched_count, result.margin
    (64, 0.0)
    """

    party: Party
    accepted: bool
    matched_count: int
    mismatches: int
    rate: float
    threshold: float
    key_length: int
    message_bit: int

    def __post_init__(self) -> None:
        """Coerce the fields and enforce the internal consistency of the verdict."""
        resolved = _as_party(self.party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice reaches no verdict: she is the signer, holds no "
                "measurement record and has no acceptance threshold. A "
                "VerificationResult belongs to Party.BOB or Party.CHARLIE."
            )
        object.__setattr__(self, "party", resolved)
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )

        if not isinstance(self.accepted, bool):
            raise TypeError(
                f"accepted must be a bool, got {type(self.accepted).__name__}; "
                f"it is a verdict, not a count"
            )
        object.__setattr__(
            self, "key_length", _as_count(self.key_length, "key_length")
        )
        object.__setattr__(
            self, "matched_count", _as_count(self.matched_count, "matched_count")
        )
        object.__setattr__(
            self, "mismatches", _as_count(self.mismatches, "mismatches")
        )
        object.__setattr__(self, "rate", _as_rate(self.rate, "rate"))
        object.__setattr__(
            self, "threshold", _as_rate(self.threshold, "threshold")
        )

        if self.matched_count < 1:
            raise ValueError(
                "matched_count must be at least 1: with an empty matched set "
                "the mismatch rate is 0/0 and no decision exists. verify() "
                "raises rather than manufacturing one; see its documentation "
                "for why neither accepting nor rejecting is honest there."
            )
        if self.matched_count > self.key_length:
            raise ValueError(
                f"matched_count ({self.matched_count}) cannot exceed key_length "
                f"({self.key_length}); the matched set is a subset of the key "
                f"positions."
            )
        if self.mismatches > self.matched_count:
            raise ValueError(
                f"mismatches ({self.mismatches}) cannot exceed matched_count "
                f"({self.matched_count}); disagreements are counted only within "
                f"the matched set, never over the whole key. Counting the "
                f"unmatched positions too is the classic bug in this protocol "
                f"family -- see sih141.protocol.verify."
            )

        expected_rate = self.mismatches / self.matched_count
        if not math.isclose(self.rate, expected_rate, rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError(
                f"rate must be mismatches / matched_count = "
                f"{self.mismatches} / {self.matched_count} = {expected_rate!r}, "
                f"got {self.rate!r}. The reported rate and the reported counts "
                f"have to be the same measurement."
            )
        if self.accepted != (self.rate <= self.threshold):
            raise ValueError(
                f"accepted={self.accepted!r} contradicts rate={self.rate!r} and "
                f"threshold={self.threshold!r}: the rule is accept iff "
                f"rate <= threshold. A result whose verdict and numbers "
                f"disagree would show one thing on a dashboard and mean another."
            )

    # -- derived views ------------------------------------------------------ #

    @property
    def unmatched_count(self) -> int:
        """int: Positions discarded because the bases differed, ``L - |M_R|``.

        Reported rather than hidden: these positions were measured, logged and
        deliberately not scored, and that discard is the correctness point of
        the whole module.
        """
        return self.key_length - self.matched_count

    @property
    def margin(self) -> float:
        """float: ``threshold - rate``.

        Non-negative exactly when the signature was accepted. How much noise the
        run had left in its budget, which is the quantity a Phase 5 sweep plots
        against the injected noise level.
        """
        return self.threshold - self.rate

    @property
    def agreements(self) -> int:
        """int: Matched positions whose outcome agreed with the declaration."""
        return self.matched_count - self.mismatches

    def summary(self) -> str:
        """Return a one-line human-readable account of the decision.

        Returns
        -------
        str
            Verdict, counts, rate and threshold, e.g.
            ``'Bob ACCEPTED bit 0: 0/32 mismatches on matched positions (64
            discarded), rate 0.00000 <= 0.01562'``. Five decimals, because
            ``s_a = 1/64 = 0.015625`` and rounding a threshold *down* in the one
            line a human reads is how a boundary case gets misreported.

        Examples
        --------
        >>> from sih141.protocol.verify import VerificationResult
        >>> VerificationResult(
        ...     "Charlie", False, 30, 12, 0.4, 1 / 6, 90, 1
        ... ).summary()[:16]
        'Charlie REJECTED'
        """
        verdict = "ACCEPTED" if self.accepted else "REJECTED"
        relation = "<=" if self.accepted else ">"
        return (
            f"{self.party.value} {verdict} bit {self.message_bit}: "
            f"{self.mismatches}/{self.matched_count} mismatches on matched "
            f"positions ({self.unmatched_count} discarded), rate "
            f"{self.rate:.5f} {relation} {self.threshold:.5f}"
        )

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the decision.

        Returns
        -------
        dict
            One key per field. :class:`~sih141.protocol.params.Party` is a
            :class:`enum.StrEnum`, so the result passes to :func:`json.dumps`
            unchanged.

        Examples
        --------
        >>> import json
        >>> from sih141.protocol.verify import VerificationResult
        >>> result = VerificationResult("Bob", True, 4, 0, 0.0, 0.5, 12, 0)
        >>> json.loads(json.dumps(result.to_dict()))["party"]
        'Bob'
        """
        return {
            "party": self.party,
            "accepted": self.accepted,
            "matched_count": self.matched_count,
            "mismatches": self.mismatches,
            "rate": self.rate,
            "threshold": self.threshold,
            "key_length": self.key_length,
            "message_bit": self.message_bit,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationResult:
        """Rebuild a decision from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain every key :meth:`to_dict` emits.

        Returns
        -------
        VerificationResult

        Raises
        ------
        KeyError
            If a field is missing.
        ValueError
            If the restored fields are not self-consistent.
        """
        return cls(
            party=data["party"],
            accepted=data["accepted"],
            matched_count=data["matched_count"],
            mismatches=data["mismatches"],
            rate=data["rate"],
            threshold=data["threshold"],
            key_length=data["key_length"],
            message_bit=data["message_bit"],
        )


def _as_count(value: Any, name: str) -> int:
    """Validate a non-negative integer count.

    Parameters
    ----------
    value : int
        The count.
    name : str
        The field name, quoted in error messages.

    Returns
    -------
    int
        ``value`` as a plain int.

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not an integer.
    ValueError
        If ``value`` is negative.
    """
    if isinstance(value, bool) or not isinstance(value, numbers.Integral):
        raise TypeError(
            f"{name} must be a non-negative integer, got "
            f"{type(value).__name__}"
        )
    result = int(value)
    if result < 0:
        raise ValueError(f"{name} must be non-negative, got {result}")
    return result


def _as_optional_count(value: Any, name: str) -> int | None:
    """Validate a count that is allowed to be absent.

    Parameters
    ----------
    value : int or None
        The count, or ``None`` where the run produced no such number -- which
        for the exchanged fields of :class:`VerificationAbort` means the
        recipients did not compare counts at all.
    name : str
        The field name, quoted in error messages.

    Returns
    -------
    int or None

    Raises
    ------
    TypeError
        If ``value`` is neither ``None`` nor an integer.
    ValueError
        If ``value`` is negative.
    """
    if value is None:
        return None
    return _as_count(value, name)


def _as_rate(value: Any, name: str) -> float:
    """Validate a mismatch rate or threshold in ``[0, 1]``.

    Parameters
    ----------
    value : float
        The rate.
    name : str
        The field name, quoted in error messages.

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
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        raise TypeError(
            f"{name} must be a real number in [0, 1], got "
            f"{type(value).__name__}"
        )
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite, got {result!r}")
    if not 0.0 <= result <= 1.0:
        raise ValueError(
            f"{name} must lie in [0, 1], got {result!r}. It is a fraction of "
            f"the matched positions."
        )
    return result


def _check_pairing(signature: Signature, record: RecipientRecord) -> None:
    """Check that a signature and a record describe the same distribution run.

    Parameters
    ----------
    signature : Signature
        The declaration under test.
    record : RecipientRecord
        The verifier's classical log.

    Raises
    ------
    TypeError
        If either argument is of the wrong type.
    ValueError
        If they are tagged with different message bits, or have different
        lengths.

    Notes
    -----
    Both failures produce the same *symptom* if they are not caught -- a
    mismatch rate near ``(1 - 1/|B|) / 2`` that looks like channel noise -- so
    they are refused explicitly and named.
    """
    if not isinstance(signature, Signature):
        raise TypeError(
            f"signature must be a Signature, got {type(signature).__name__}. "
            f"Build one with sign(message_bit, keys)."
        )
    if not isinstance(record, RecipientRecord):
        raise TypeError(
            f"record must be a RecipientRecord, got {type(record).__name__}. "
            f"It is produced by distribute_to_recipient(...)."
        )
    if signature.message_bit != record.message_bit:
        raise ValueError(
            f"the signature declares message bit {signature.message_bit} but "
            f"{record.party.value}'s record was made during the distribution "
            f"for bit {record.message_bit}. The two distribution runs use "
            f"independent keys, so scoring one against the other measures "
            f"nothing but chance: the rate would sit near (1 - 1/|B|)/2 and "
            f"look like a noisy channel."
        )
    if len(signature) != len(record):
        raise ValueError(
            f"the signature declares {len(signature)} key positions but "
            f"{record.party.value}'s record holds {len(record)} entries. "
            f"Verification is positional -- entry i is the measurement of key "
            f"qubit i -- so a length mismatch means the record and the "
            f"signature came from different runs."
        )


def matched_positions(
    signature: Signature, record: RecipientRecord
) -> tuple[int, ...]:
    """Return the positions the verifier is allowed to score, ``M_R``.

    The positions where the recipient's freely chosen measurement basis happened
    to be the one the signature declares. Everything else is discarded; see the
    module docstring for why that is the correctness point of the whole phase.

    Parameters
    ----------
    signature : Signature
        The declaration under test.
    record : RecipientRecord
        The verifier's classical log, of the same length and message bit.

    Returns
    -------
    tuple of int
        Key indices in ascending order. Possibly empty, which
        :func:`verify` treats as a hard error.

    Raises
    ------
    TypeError
        If either argument is of the wrong type.
    ValueError
        If the two are tagged with different message bits or have different
        lengths.

    Examples
    --------
    >>> from sih141.protocol.keys import KeyElement, PrivateKey
    >>> from sih141.protocol.records import RecipientRecord
    >>> from sih141.protocol.signature import sign
    >>> from sih141.protocol.verify import matched_positions
    >>> key = PrivateKey(0, (KeyElement("X", 1), KeyElement("Z", -1)))
    >>> record = RecipientRecord.from_measurements("Bob", 0, ["X", "Y"], [1, 1])
    >>> matched_positions(sign(0, key), record)
    (0,)
    """
    _check_pairing(signature, record)
    declared = signature.bases
    chosen = record.bases
    return tuple(
        index for index in range(len(record)) if chosen[index] == declared[index]
    )


def mismatch_positions(
    signature: Signature, record: RecipientRecord
) -> tuple[int, ...]:
    """Return the matched positions whose outcome contradicts the declaration.

    A subset of :func:`matched_positions` by construction: an unmatched position
    can never be a mismatch, because it is not evidence at all.

    Parameters
    ----------
    signature : Signature
        The declaration under test.
    record : RecipientRecord
        The verifier's classical log.

    Returns
    -------
    tuple of int
        Key indices in ascending order, the ones counted into ``e_R``.

    Raises
    ------
    TypeError
        If either argument is of the wrong type.
    ValueError
        If the two do not describe the same distribution run.

    Examples
    --------
    >>> from sih141.protocol.keys import KeyElement, PrivateKey
    >>> from sih141.protocol.records import RecipientRecord
    >>> from sih141.protocol.signature import sign
    >>> from sih141.protocol.verify import mismatch_positions
    >>> key = PrivateKey(0, (KeyElement("X", 1), KeyElement("Z", -1)))
    >>> record = RecipientRecord.from_measurements("Bob", 0, ["X", "Z"], [-1, -1])
    >>> mismatch_positions(sign(0, key), record)
    (0,)
    """
    declared = signature.eigenvalues
    measured = record.eigenvalues
    return tuple(
        index
        for index in matched_positions(signature, record)
        if measured[index] != declared[index]
    )


def _round_refusal(
    signature: Signature,
    record: RecipientRecord,
    ledger: ConsumedRecords | None,
    *,
    matched_count: int,
    params: ProtocolParams,
    floor: int,
) -> VerificationAbort | None:
    """Apply the two replay checks and return the first refusal.

    Runs before any counting rule, because a count taken across two rounds --
    or a second count of a round already decided -- is not a weaker measurement
    but a measurement of nothing. :ref:`replay` is the reasoning.

    The record drives the session comparison, not the signature. A verifier
    holding a log stamped with a round demands that the declaration name that
    round and refuses one naming another or naming none; a verifier whose log
    names no round has nothing to compare and is left exactly as he was. That
    asymmetry is the point: the record is the end of the comparison no signer
    can reach, and a verifier who declines to stamp his own log gives up only
    his own protection, which is not the omission route of
    :ref:`one-declaration` where the party who could omit the binding was the
    adversary it was aimed at.

    Parameters
    ----------
    signature : Signature
        The declaration under test.
    record : RecipientRecord
        The verifier's log.
    ledger : ConsumedRecords or None
        The verifier's own ledger of rounds already decided, or ``None`` for a
        caller keeping no such state.
    matched_count : int
        ``|M_R|``, carried into the refusal for diagnosis. Neither check makes
        any claim about it.
    params : ProtocolParams
        The parameter set the run executes under.
    floor : int
        ``m_min``, passed in because the caller has already paid for it.

    Returns
    -------
    VerificationAbort or None
        ``None`` when the declaration and the record are the same, undecided
        transaction, which is when a count is worth taking.
    """
    common = {
        "party": record.party,
        "matched_count": matched_count,
        "minimum_matched": floor,
        "expected_matched": params.expected_matched,
        "key_length": params.key_length,
        "message_bit": record.message_bit,
    }
    stamped = record.session_id
    if stamped is not None and signature.session_id != stamped:
        return VerificationAbort(reason=AbortReason.SESSION_MISMATCH, **common)
    if ledger is not None and ledger.is_spent(record):
        return VerificationAbort(
            reason=AbortReason.RECORD_ALREADY_VERIFIED, **common
        )
    return None


def _evidence_refusal(
    *,
    party: Party,
    matched_count: int,
    counterpart_matched: int | None,
    params: ProtocolParams,
    floor: int,
    message_bit: int,
    counterpart_declaration: str | None = None,
    scored_declaration: str | None = None,
    counterpart_binding_missing: bool = False,
) -> VerificationAbort | None:
    """Apply the matched-count rule and return the first refusal.

    The whole abort rule in one place, so that :func:`verify` and any future
    caller cannot apply two different versions of it. The order is the order a
    verifier can reach the checks in -- his own count needs nobody, everything
    after it needs the exchange -- and it is also the order that attributes a
    failure to the smallest thing that explains it: a starved verifier is a
    local finding, counts against two declarations are a finding about the
    wiring, a low total is a finding about the declaration, and a lopsided split
    is a finding about the split.

    The binding check sits directly after the local floor and before both
    pooled ones, because a pooled floor evaluated on two declarations' counts is
    not a weaker check than the real one -- it is a check on a quantity no run
    produced, and reporting its outcome either way would be a fabrication. It
    has two failure modes and refuses on both: the count names *another*
    declaration, or -- the omission this rule is enforced against rather than
    merely documented for -- it names *none*. Skipping the check on an
    unprovenanced count would let the party who supplies it turn the check off
    by declining to answer; see :ref:`one-declaration` and
    :ref:`sih141.protocol.tally's <binding-is-mandatory>` account.

    Parameters
    ----------
    party : Party
        The verifier reaching (or not reaching) a verdict.
    matched_count : int
        ``|M_R|``, this verifier's own count.
    counterpart_matched : int or None
        What the other verifier reported, or ``None`` if the recipients did not
        exchange counts. Every check after the first is skipped when it is
        ``None``.
    params : ProtocolParams
        The parameter set the run executes under.
    floor : int
        ``m_min``, passed in rather than recomputed because the caller has
        already paid for it.
    message_bit : int
        The bit being signed.
    counterpart_declaration : str or None, optional
        :func:`_declaration_digest` of the declaration ``counterpart_matched``
        was counted against, when the count says which.
    scored_declaration : str or None, optional
        The digest of the declaration *this* verifier is scoring. Computed by
        the caller only when there is a binding to compare it against, since
        digesting a full-length declaration is not free.
    counterpart_binding_missing : bool, optional
        ``True`` when the count arrived through the count exchange carrying an
        *empty* provenance slot (:func:`_claims_provenance`). Refused outright:
        this is the omission route, and it is the one case where saying "no
        claim, so no disagreement" hands the adversary the check.

    Returns
    -------
    VerificationAbort or None
        ``None`` when every applicable floor is met, which is when a verdict
        may be reached.
    """
    common = {
        "party": party,
        "minimum_matched": floor,
        "expected_matched": params.expected_matched,
        "key_length": params.key_length,
        "message_bit": message_bit,
        "counterpart_matched": counterpart_matched,
        "minimum_pooled": (
            None
            if counterpart_matched is None
            else minimum_pooled_matched_count(params)
        ),
    }
    if matched_count < floor:
        return VerificationAbort(
            reason=(
                AbortReason.EMPTY_MATCHED_SET
                if matched_count == 0
                else AbortReason.BELOW_FLOOR
            ),
            matched_count=matched_count,
            **common,
        )
    if counterpart_matched is None:
        return None
    if counterpart_binding_missing:
        return VerificationAbort(
            reason=AbortReason.COUNT_OF_UNRECORDED_PROVENANCE,
            matched_count=matched_count,
            **common,
        )
    if (
        counterpart_declaration is not None
        and scored_declaration is not None
        and counterpart_declaration != scored_declaration
    ):
        return VerificationAbort(
            reason=AbortReason.COUNTS_FROM_TWO_DECLARATIONS,
            matched_count=matched_count,
            **common,
        )
    pooled_floor = minimum_pooled_matched_count(params)
    if matched_count + counterpart_matched < pooled_floor:
        return VerificationAbort(
            reason=AbortReason.POOLED_BELOW_FLOOR,
            matched_count=matched_count,
            **common,
        )
    if counterpart_matched < floor:
        return VerificationAbort(
            reason=AbortReason.COUNTERPART_BELOW_FLOOR,
            matched_count=matched_count,
            **common,
        )
    return None


def verify(
    signature: Signature,
    record: RecipientRecord,
    params: ProtocolParams,
    *,
    counterpart_matched: int | None = None,
    ledger: ConsumedRecords | None = None,
) -> VerificationResult:
    """Score a signature against one recipient's record and reach a verdict.

    Phase C for a single verifier. Checks that the declaration and the record
    are one undecided transaction, builds the matched set, checks there is
    enough evidence to carry a verdict at all, counts disagreements **within it
    only**, divides, and compares against the threshold ``params`` assigns to
    the party the record belongs to.

    The checks that precede a verdict, in the order a verifier can actually
    apply them::

        signature names the record's round      the replay binding
        this round has not been decided yet     the consumed-records ledger
        |M_R| >= m_min                          his own, computed locally
        counterpart said which declaration      provenance was recorded at all
        counterpart counted this declaration    the counts are one experiment
        |M_R| + counterpart_matched >= M_min    the pooled floor
        counterpart_matched >= m_min            the counterpart's own floor

    The first two are the replay defence of :ref:`replay`, and each is inert
    unless the caller supplies the state it reads: a record stamped with a
    distribution round, and a ledger of rounds already decided. Then ``m_min``
    from :func:`minimum_matched_count` and ``M_min`` from
    :func:`minimum_pooled_matched_count`. The last four need ``counterpart``'s
    count, which arrives over the recipients' count exchange
    (:mod:`sih141.protocol.tally`); they are skipped when it is not supplied,
    and :ref:`pooled-floor` says exactly what a run gives up by skipping them.
    The second and third are :ref:`one-declaration`: adding a count made against
    another declaration to this one produces a number no run ever had, so such a
    pair is refused rather than pooled -- and so is a count that came through
    the exchange without saying which declaration it counted, because the party
    who runs Phase C' is an adversary here and a check he can switch off by
    declining to answer is not a check. Any failed check scores nothing and
    raises
    :exc:`MatchedSetTooSmall` carrying a :class:`VerificationAbort`; use
    :func:`verify_or_abort` to get that as a returned outcome instead.

    Parameters
    ----------
    signature : Signature
        Alice's declaration, as received over the authenticated classical
        channel in Phase B.
    record : RecipientRecord
        The verifier's own classical log from Phase A. It is read, never
        modified: both arguments are frozen and this function is pure.
    params : ProtocolParams
        The parameter set the run was executed under. Supplies the key length
        and alphabet both inputs are checked against, and the threshold --
        ``s_a`` for Bob, ``s_v`` for Charlie.
    counterpart_matched : int or None, optional
        Keyword-only. ``|M|`` as the **other** verifier reported it over the
        count exchange, against this same declaration. ``None`` -- the default,
        and what a caller with only one record can honestly pass -- applies the
        per-verifier floor alone, which is the rule the package shipped before
        the pooled one and which leaves the split-coin route of
        :ref:`pooled-floor` open at about ``1/2``. It is an :class:`int` rather
        than the other record because that is all that crosses the wire: the
        counterpart sends a count, never his log, and modelling it as a number
        keeps it impossible for this function to read evidence its verifier
        does not hold.

        "Against this same declaration" is checked rather than trusted.
        :meth:`sih141.protocol.tally.PooledMatchedCounts.counterpart_of` returns
        a count that names the declaration it counted, and such a count with the
        name *missing* is refused
        (:attr:`AbortReason.COUNT_OF_UNRECORDED_PROVENANCE`) rather than having
        the check skipped -- otherwise the recipients' own Phase C' step, run by
        the party this check exists to catch, could switch the check off by
        declining to answer. A plain :class:`int` is still taken at its word,
        and that is not the same concession: it carries no provenance slot to
        leave empty, so it cannot be a count exchange declining to fill one. It
        can only come from the verifier's own call site. Nothing an adversary
        controls can produce one here --
        :class:`~sih141.protocol.tally.PooledMatchedCounts` is the sole thing a
        ``count_exchange`` seam hands
        :class:`~sih141.protocol.session.QDSSession`, it cannot be built
        without a declaration, and it cannot be subclassed to hand on a bare
        integer instead (:ref:`binding-is-mandatory`).
    ledger : ConsumedRecords or None, optional
        Keyword-only. **This verifier's own** ledger of distribution rounds he
        has already decided. When given, a round already spent is refused
        (:attr:`AbortReason.RECORD_ALREADY_VERIFIED`) and a round newly decided
        is spent on the way out -- so this is the one argument that makes the
        call stateful, and the state lives on an object the verifier holds
        rather than anywhere this module could share between two of them.
        ``None`` -- the default -- keeps the function pure and is what a caller
        with no replay surface to defend can honestly pass. A ledger built for
        the other party raises rather than answering; see :ref:`replay`.

    Returns
    -------
    VerificationResult
        The verdict together with ``matched_count``, ``mismatches``, ``rate``,
        ``threshold``, ``key_length`` and ``message_bit``.

    Raises
    ------
    TypeError
        If any argument is of the wrong type, including a
        ``counterpart_matched`` that is neither ``None`` nor an integer and a
        ``ledger`` that is neither ``None`` nor a :class:`ConsumedRecords`.
    ValueError
        If the signature and the record describe different runs (different
        message bit or length), if either does not belong to ``params``, if
        ``counterpart_matched`` exceeds the key length, or if ``ledger``
        belongs to a different party. These are wiring errors.
    MatchedSetTooSmall
        A :class:`ValueError` subclass, if any of the checks above refuses --
        including the ``0/0`` case, a counterpart count computed against another
        declaration, a declaration naming another distribution round, and a
        round this verifier has already decided. This is a plumbing failure
        rather than a signature failure, is explained at length in the module
        docstring, and must never be recorded as a rejection.

    See Also
    --------
    verify_or_abort : The same decision, with the refusal returned not raised.
    verify_all : Both verifiers at once, which is what transferability needs.
    minimum_matched_count : The per-verifier floor, and the bound behind it.
    minimum_pooled_matched_count : The pooled floor.
    ConsumedRecords : The ledger, and what it does and does not cost.
    sih141.protocol.tally.exchange_matched_counts : Where
        ``counterpart_matched`` comes from.
    matched_positions : The evidence base this decision rests on.
    sih141.protocol.params.ProtocolParams.threshold_for : The cut per party.

    Notes
    -----
    A noiseless honest run gives ``rate == 0.0`` exactly -- teleportation over a
    clean pair is exact, so on a matched position the recipient re-measured the
    very observable the state was an eigenstate of. Both thresholds are noise
    budgets measured from that zero, and the acceptance test is ``<=``, so a run
    landing exactly on its threshold is accepted.

    Consumes no randomness (D3). Pure unless a ``ledger`` is supplied, and then
    the only thing it writes is that ledger.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.distribute import distribute_to_recipient
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.signature import sign
    >>> from sih141.protocol.verify import verify
    >>> params = ProtocolParams(key_length=24)
    >>> key = generate_private_key(params, 0, rng=np.random.default_rng(1))
    >>> record = distribute_to_recipient(
    ...     key, params, party=Party.BOB, rng=np.random.default_rng(2)
    ... )
    >>> result = verify(sign(0, key, params), record, params)
    >>> result.accepted, result.rate, result.mismatches
    (True, 0.0, 0)

    Bind the pair to one distribution round and a declaration from another round
    is refused rather than scored on chance noise:

    >>> from sih141.protocol.signature import Signature
    >>> from sih141.protocol.verify import verify_or_abort
    >>> bound = record.with_session_id(
    ...     Signature(0, key, session_opening="round-a").session_id
    ... )
    >>> verify(sign(0, key, params, session_opening="round-a"), bound, params).rate
    0.0
    >>> verify_or_abort(
    ...     sign(0, key, params, session_opening="round-b"), bound, params
    ... ).reason.value
    'session-identifier-mismatch'

    One round, one verdict, once the verifier keeps a ledger:

    >>> from sih141.protocol.verify import ConsumedRecords
    >>> ledger = ConsumedRecords(Party.BOB)
    >>> declaration = sign(0, key, params, session_opening="round-a")
    >>> verify(declaration, bound, params, ledger=ledger).accepted
    True
    >>> verify_or_abort(
    ...     declaration, bound, params, ledger=ledger
    ... ).reason.value
    'records-already-verified'
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    if ledger is not None and not isinstance(ledger, ConsumedRecords):
        raise TypeError(
            f"ledger must be a ConsumedRecords or None, got "
            f"{type(ledger).__name__}. It is the verifier's own record of "
            f"rounds he has already decided; build one per verifier with "
            f"ConsumedRecords(record.party)."
        )
    _check_pairing(signature, record)
    signature.check_against(params)
    record.check_against(params)
    # Read the provenance off the count *before* coercing it: _as_count returns
    # a plain int, and the declaration a count was computed against is the one
    # thing that cannot be recovered afterwards.
    counterpart_declaration = _counterpart_binding(counterpart_matched)
    binding_missing = (
        counterpart_matched is not None
        and _claims_provenance(counterpart_matched)
        and counterpart_declaration is None
    )
    reported = _as_optional_count(counterpart_matched, "counterpart_matched")
    if reported is not None and reported > params.key_length:
        raise ValueError(
            f"counterpart_matched ({reported}) exceeds the key length "
            f"({params.key_length}); the other verifier's matched set is a "
            f"subset of the same key positions, so a larger count means the "
            f"two verifiers scored different runs."
        )

    matched = matched_positions(signature, record)
    floor = minimum_matched_count(params)
    # The replay checks first. A count taken across two distribution rounds, or
    # a second count of a round already decided, is not a weaker measurement of
    # the same thing; it is a measurement of nothing, so no floor is applied to
    # it and none is quoted. See :ref:`replay`.
    refusal = _round_refusal(
        signature,
        record,
        ledger,
        matched_count=len(matched),
        params=params,
        floor=floor,
    )
    if refusal is not None:
        raise MatchedSetTooSmall(refusal)
    refusal = _evidence_refusal(
        party=record.party,
        matched_count=len(matched),
        counterpart_matched=reported,
        params=params,
        floor=floor,
        message_bit=record.message_bit,
        counterpart_declaration=counterpart_declaration,
        # Only worth fingerprinting the declaration when there is a binding to
        # compare it against. A count that came through the exchange with an
        # empty slot is refused without one being computed: there is nothing to
        # compare, and that is precisely why it is refused.
        scored_declaration=(
            None
            if counterpart_declaration is None
            else _declaration_digest(signature)
        ),
        counterpart_binding_missing=binding_missing,
    )
    if refusal is not None:
        # A no-verdict outcome, not a rejection: see the module docstring.
        raise MatchedSetTooSmall(refusal)

    mismatches = len(mismatch_positions(signature, record))
    rate = mismatches / len(matched)
    threshold = params.threshold_for(record.party)

    # Spent on a verdict and only on a verdict: a refusal has decided nothing,
    # so spending on one would let a starved counterpart count or a
    # mis-provenanced one burn a round this verifier never scored. That is also
    # what keeps the ledger unpoisonable from outside -- see :ref:`replay`.
    if ledger is not None:
        ledger.spend(record)

    return VerificationResult(
        party=record.party,
        accepted=rate <= threshold,
        matched_count=len(matched),
        mismatches=mismatches,
        rate=rate,
        threshold=threshold,
        key_length=params.key_length,
        message_bit=record.message_bit,
    )


def verify_or_abort(
    signature: Signature,
    record: RecipientRecord,
    params: ProtocolParams,
    *,
    counterpart_matched: int | None = None,
    ledger: ConsumedRecords | None = None,
) -> VerificationResult | VerificationAbort:
    """Score a signature, returning the refusal instead of raising it.

    :func:`verify` with the matched-count abort delivered as a value. For code
    that has to *record* what happened to every run --
    :meth:`~sih141.protocol.session.QDSSession.run`, a Phase 3 attack harness, a
    Phase 5 sweep -- an abort is an outcome, not an exception, and losing a run
    to an uncaught exception is the failure mode this exists to prevent.

    Only :exc:`MatchedSetTooSmall` is converted. Wiring errors -- a record
    paired with the wrong message bit, a signature of the wrong length, a
    parameter-set mismatch -- still raise, because they are bugs in the caller
    rather than outcomes of the protocol, and swallowing them would turn a
    mis-wired experiment into a table full of silent no-verdicts.

    Parameters
    ----------
    signature : Signature
        Alice's declaration.
    record : RecipientRecord
        The verifier's own classical log.
    params : ProtocolParams
        The parameter set the run was executed under.
    counterpart_matched : int or None, optional
        Keyword-only, forwarded to :func:`verify` unchanged: the count the other
        verifier reported over the exchange, or ``None`` for the per-verifier
        rule alone.
    ledger : ConsumedRecords or None, optional
        Keyword-only, forwarded to :func:`verify` unchanged: this verifier's own
        ledger of rounds already decided, or ``None``. A round is spent only
        when a verdict is returned, so the refusals this function hands back
        leave the ledger untouched -- which is what lets a harness retry a run
        that aborted for an unrelated reason.

    Returns
    -------
    VerificationResult or VerificationAbort
        A verdict when every applicable floor was met, a recorded no-verdict
        otherwise. The two are different types precisely so
        that a caller cannot average them together; check with
        ``isinstance(outcome, VerificationResult)``.

    Raises
    ------
    TypeError
        If any argument is of the wrong type.
    ValueError
        For the wiring errors listed above. :exc:`MatchedSetTooSmall`, its one
        subclass that is an outcome rather than a bug, is returned instead.

    See Also
    --------
    verify : The raising form, and where the rule is documented.

    Examples
    --------
    >>> from sih141.protocol.keys import KeyElement, PrivateKey
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.records import RecipientRecord
    >>> from sih141.protocol.signature import sign
    >>> from sih141.protocol.verify import verify_or_abort
    >>> params = ProtocolParams(key_length=8, bases=("X", "Z"))
    >>> key = PrivateKey(0, tuple(KeyElement("X", 1) for _ in range(8)))
    >>> record = RecipientRecord.from_measurements("Bob", 0, ["Z"] * 8, [1] * 8)
    >>> outcome = verify_or_abort(sign(0, key, params), record, params)
    >>> outcome.reason.value, outcome.matched_count, outcome.minimum_matched
    ('empty-matched-set', 0, 1)
    """
    try:
        return verify(
            signature,
            record,
            params,
            counterpart_matched=counterpart_matched,
            ledger=ledger,
        )
    except MatchedSetTooSmall as too_small:
        return too_small.abort


def verify_all(
    signature: Signature,
    records: Mapping[Party | str, RecipientRecord],
    params: ProtocolParams,
    *,
    require_symmetrised: bool = True,
    exchange_counts: bool = True,
    ledgers: Mapping[Party | str, ConsumedRecords] | None = None,
) -> dict[Party, VerificationResult]:
    """Verify one signature against every recipient's record.

    Takes the output of
    :func:`sih141.protocol.symmetrise.symmetrise_records` directly. Both
    verdicts are needed together to say anything about the protocol's actual
    claims: transferability is "Bob accepted **and** Charlie accepted",
    repudiation is "Bob accepted **and** Charlie did not". Neither is visible
    from one verdict.

    Because this is the function that produces *both* verdicts, it is also
    where the pair's provenance is checked. Scoring two raw logs against one
    declaration supports no non-repudiation claim at all -- Alice prepared the
    two recipients' copies independently and can simply send them different
    states -- so a pair that has not been through symmetrisation is refused
    rather than scored.

    For the same reason it is where the recipients' **count exchange** (Phase
    C', :mod:`sih141.protocol.tally`) happens. Holding both records is not the
    same as the two verifiers having compared anything: the exchange is a real
    message, it is run here explicitly rather than assumed, and each verifier is
    then handed nothing but the other's *count*. Without it the pooled floor
    cannot be evaluated and a signer who splits the evidence base wins at about
    ``1/2`` (:ref:`pooled-floor`), so it is on by default and turning it off
    takes a keyword with a loud name.

    Parameters
    ----------
    signature : Signature
        Alice's declaration.
    records : mapping of Party to RecipientRecord
        One log per verifier, keyed by party. Iteration order is preserved in
        the result.
    params : ProtocolParams
        The parameter set the run was executed under.
    require_symmetrised : bool, optional
        Keyword-only, default ``True``: every record must carry
        :attr:`~sih141.protocol.records.RecipientRecord.symmetrised`. Pass
        ``False`` to score raw logs anyway, which is what a Phase 3 experiment
        does when it is *demonstrating* the repudiation attack and therefore
        wants the insecure variant on purpose. It is a keyword with a loud name
        precisely so that no run gets there by accident.
    exchange_counts : bool, optional
        Keyword-only, default ``True``: run Phase C', so that each verifier
        applies the pooled floor and the counterpart's floor as well as his own.
        Requires both :data:`~sih141.protocol.params.VERIFIERS` to be present --
        with one record there is nobody to exchange with and the flag is
        inert. ``False`` scores each record under the per-verifier floor alone,
        which is what the package enforced before the pooled rule and what a
        Phase 3 experiment passes when it is measuring the split-coin attack the
        rule closes.
    ledgers : mapping of Party to ConsumedRecords or None, optional
        Keyword-only. One ledger **per verifier**, forwarded to that verifier's
        own :func:`verify` call. A mapping rather than a single object because
        the two histories must stay apart (:ref:`replay`); a ledger filed under
        the wrong party raises there rather than answering. Parties absent from
        the mapping are verified without one, and ``None`` -- the default --
        keeps every verification pure, which is what a caller scoring a run once
        wants.

    Returns
    -------
    dict of Party to VerificationResult
        One decision per party, in the order given. Each carries its own
        threshold, so Bob's is scored against ``s_a`` and Charlie's against
        ``s_v`` without the caller choosing.

    Raises
    ------
    TypeError
        If ``records`` is not a mapping, any value is not a
        :class:`~sih141.protocol.records.RecipientRecord`,
        ``exchange_counts`` is not a :class:`bool`, or ``ledgers`` is neither a
        mapping nor ``None``.
    ValueError
        If ``records`` is empty, if a key disagrees with the party its record is
        tagged with, if a record is unsymmetrised while ``require_symmetrised``
        is set, or for any reason :func:`verify` raises.
    MatchedSetTooSmall
        Propagated unchanged from :func:`verify` if the evidence base does not
        clear every applicable floor. This function reaches *both* verdicts or
        none: a pair in which one verifier could not be scored says nothing
        about transferability or repudiation, both of which are statements about
        the two together. A caller that needs the partial picture should call
        :func:`verify_or_abort` per record.

    See Also
    --------
    sih141.protocol.symmetrise.symmetrise_records : Produces an acceptable pair.
    sih141.protocol.tally.exchange_matched_counts : The Phase C' step this runs.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.distribute import distribute_public_key
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.signature import sign
    >>> from sih141.protocol.symmetrise import symmetrise_records
    >>> from sih141.protocol.verify import verify_all
    >>> params = ProtocolParams(key_length=24)
    >>> key = generate_private_key(params, 0, rng=np.random.default_rng(3))
    >>> raw = distribute_public_key(key, params, rng=np.random.default_rng(4))
    >>> records = symmetrise_records(raw, rng=np.random.default_rng(5))
    >>> results = verify_all(sign(0, key, params), records, params)
    >>> [results[party].accepted for party in (Party.BOB, Party.CHARLIE)]
    [True, True]
    >>> results[Party.BOB].threshold < results[Party.CHARLIE].threshold
    True
    >>> verify_all(sign(0, key, params), raw, params)
    Traceback (most recent call last):
        ...
    ValueError: Bob's record has not been symmetrised, ...
    """
    if not isinstance(records, Mapping):
        raise TypeError(
            f"records must be a mapping of Party to RecipientRecord, got "
            f"{type(records).__name__}; distribute_public_key returns exactly "
            f"that."
        )
    if not records:
        raise ValueError(
            "records must hold at least one recipient's log. Verifying against "
            "nobody reaches no verdict, and the protocol's claims are about "
            "two verifiers: transferability and non-repudiation are both "
            "statements about Bob and Charlie together."
        )
    if not isinstance(exchange_counts, bool):
        raise TypeError(
            f"exchange_counts must be a bool, got "
            f"{type(exchange_counts).__name__}; it selects whether the "
            f"recipients run Phase C', not a count."
        )
    if ledgers is not None and not isinstance(ledgers, Mapping):
        raise TypeError(
            f"ledgers must be a mapping of Party to ConsumedRecords or None, "
            f"got {type(ledgers).__name__}. One ledger per verifier: a single "
            f"shared object would put one verifier's history inside the "
            f"other's decision."
        )
    by_party: dict[Party, ConsumedRecords] = (
        {}
        if ledgers is None
        else {_as_party(party): held for party, held in ledgers.items()}
    )

    # Shape first, then the exchange, then the verdicts: a mis-wired pair must
    # fail on the wiring rather than somewhere inside a protocol step it should
    # never have reached.
    checked: dict[Party, RecipientRecord] = {}
    for party, record in records.items():
        resolved = _as_party(party)
        if not isinstance(record, RecipientRecord):
            raise TypeError(
                f"records[{resolved.value!r}] must be a RecipientRecord, got "
                f"{type(record).__name__}"
            )
        if record.party is not resolved:
            raise ValueError(
                f"records is keyed by {resolved.value!r} but the record stored "
                f"there belongs to {record.party.value!r}. The key selects the "
                f"acceptance threshold, so a swap would score one verifier's "
                f"evidence against the other's cut -- which is precisely the "
                f"confusion the s_a < s_v gap exists to prevent."
            )
        if require_symmetrised and not record.symmetrised:
            raise ValueError(
                f"{resolved.value}'s record has not been symmetrised, so this "
                f"pair supports no non-repudiation claim. Alice prepares the "
                f"two recipients' copies independently and consumes separate "
                f"entanglement for each, so against raw logs she can send Bob "
                f"the eigenstate she declares and Charlie its orthogonal "
                f"partner: Bob accepts at rate 0 and Charlie rejects, with "
                f"probability 1, at every key length. Pass the pair through "
                f"symmetrise_records(records, rng=...) first -- "
                f"QDSSession.distribute() already does. If you are deliberately "
                f"running the insecure variant to measure that attack, say so "
                f"with verify_all(..., require_symmetrised=False)."
            )
        checked[resolved] = record

    reported = _exchanged_counts(
        signature, checked, params, enabled=exchange_counts
    )
    return {
        party: verify(
            signature,
            record,
            params,
            counterpart_matched=reported.get(party),
            ledger=by_party.get(party),
        )
        for party, record in checked.items()
    }


def _exchanged_counts(
    signature: Signature,
    records: Mapping[Party, RecipientRecord],
    params: ProtocolParams,
    *,
    enabled: bool,
) -> dict[Party, int]:
    """Run Phase C' for :func:`verify_all` and return each party's *counterpart* count.

    The mapping is keyed by the verifier who will *receive* the number, so the
    caller never has to invert it at the call site and cannot hand a verifier
    his own count by accident.

    Parameters
    ----------
    signature : Signature
        The declaration both counts are computed against. One declaration, or
        the conservation laws the pooled floor rests on do not hold.
    records : mapping of Party to RecipientRecord
        The logs, already validated by :func:`verify_all`.
    params : ProtocolParams
        The parameter set.
    enabled : bool
        ``False`` skips the exchange entirely and returns an empty mapping.

    Returns
    -------
    dict of Party to int
        Empty when the exchange did not happen or when the mapping does not
        hold both verifiers. Each count carries the declaration it was computed
        against, so :func:`verify` can check that the number it is handed is
        about the declaration it is scoring (:ref:`one-declaration`).
    """
    if not enabled or set(records) != set(VERIFIERS):
        # Nobody to exchange with. A single-verifier call makes no cross-party
        # claim in the first place, so there is nothing to weaken.
        return {}
    # Deferred rather than module-level: ``tally`` imports the floors from this
    # module, and keeping the edge one-directional at import time documents
    # which of the two is the rule and which is the message that carries it.
    from sih141.protocol.tally import (
        exchange_matched_counts,
        matched_count_message,
    )

    messages = {
        party: matched_count_message(signature, record, params)
        for party, record in records.items()
    }
    pooled = exchange_matched_counts(messages, params)
    if pooled is None:
        return {}
    # counterpart_of, never the two count fields by hand: inverting the mapping
    # here is the one way a verifier is handed his own count and clears the
    # pooled floor twice over. tests/test_protocol_verify_abort.py pins the
    # direction on a pair whose two counts differ, which is the only kind of
    # pair that can tell the two mappings apart at all.
    return {party: pooled.counterpart_of(party) for party in VERIFIERS}
