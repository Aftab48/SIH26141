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

with ``threshold(Bob) = s_a`` and ``threshold(Charlie) = s_v``.

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
``eps``, and an honest *run* -- two verifiers -- with probability at most
``2 eps`` by a union bound. That is ``1.1e-19``, ten orders of magnitude below
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
without emptying it, which is the case the floor exists for --
:mod:`sih141.protocol.session` documents what that costs the published bounds.

``tests/test_protocol_verify.py`` pins the surviving halves: a *Bob*-log-avoiding
signer completes a run with a real evidence base, and a record wired to disagree
everywhere still refuses to invent a verdict.

Notes
-----
Determinism (D3)
    Nothing here consumes randomness; verification is a pure function of
    ``(signature, record, params)``. There is no ``rng`` argument to inject.
Immutability
    :func:`verify` cannot modify the record or the signature it is handed. Both
    are frozen dataclasses holding tuples, it only reads derived views, and a
    test asserts equality across the call. A verifier that could edit its own
    evidence would not be one.
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
minimum_matched_count : The abort rule's floor, and its derivation.
enforced_repudiation_bound : The unconditional repudiation number that floor
    buys, which is the only a-priori one this package publishes.
"""

from __future__ import annotations

import enum
import math
import numbers
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from sih141.protocol.params import (
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
    "MatchedSetTooSmall",
    "VerificationAbort",
    "VerificationResult",
    "enforced_repudiation_bound",
    "matched_positions",
    "minimum_matched_count",
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

    Attributes
    ----------
    EMPTY_MATCHED_SET
        ``|M_R| == 0``: the recipient's basis differed from the declared one at
        every position, so the mismatch rate is ``0/0`` and no arithmetic
        exists.
    BELOW_FLOOR
        ``0 < |M_R| < m_min``: a rate could be computed, but on so little
        evidence that no bound in the scheme applies to it. See
        :func:`minimum_matched_count`.
    """

    EMPTY_MATCHED_SET = "empty-matched-set"
    BELOW_FLOOR = "matched-count-below-floor"


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

    This is a **per-verifier** floor -- ``verify`` sees one record at a time, so
    it can only bound ``m_R``. The pooled quantity the repudiation bounds are
    stated over, ``M = m_B + m_C``, is floored at *twice* this on any run that
    reaches two verdicts, which is the factor
    :func:`enforced_repudiation_bound` supplies and
    ``tests/test_protocol_reconciliation.py`` pins.

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
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}; "
            f"the floor is a function of the key length and the alphabet size, "
            f"so it can only be read off a parameter set."
        )
    mean_matched = params.expected_matched
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

    **The event it bounds, exactly.** *Bob accepts and Charlie returns a verdict
    of reject* -- the classical repudiation event -- together with the
    ``m_C = 0`` corner, which the Hoeffding argument already contains. Both
    verifiers reaching a verdict means both cleared the floor, so
    ``M = m_B + m_C >= 2 m_min`` on that event and

    .. code-block:: text

        P(repudiation)  <=  exp(-2 m_min gap^2 / 8)

    holds for **every** Alice strategy, with no independence assumption and no
    model of her at all -- unlike
    :func:`~sih141.protocol.analysis.averaged_repudiation_bound`, whose
    ``6.9e-10`` needs the declaration to be independent of the recipients'
    logged bases and is false against the shipped ``Signer`` seam.

    **The event it does not bound**, and this must be quoted with it: *Bob
    accepts and Charlie returns no verdict* because his own matched set fell
    below the floor. That third outcome is created by the floor itself, and a
    log-reading signer can aim ``M`` at ``2 m_min`` and reach it about a third
    of the time (measured 14/40 at ``L = 600``; ``0/40`` of those runs produced a
    reject verdict, so none is a repudiation under the first reading). It is a
    *recorded, visibly anomalous no-verdict* -- an honest run trips the floor
    with probability ``~1e-31`` -- not a silent transfer, and
    :attr:`~sih141.protocol.session.SessionTranscript.aborted` reports it. What
    closes it is a **pooled** floor ``m_B + m_C >= M_min``, which costs one extra
    classical message between the verifiers and is not implemented here. Section
    4b-iii of :mod:`sih141.protocol.analysis` prices it.

    Parameters
    ----------
    params : ProtocolParams
        The parameter set the run executes under.

    Returns
    -------
    float
        An upper bound in ``[0, 1]``. Order one below ``L = 267``, where
        :func:`minimum_matched_count` degenerates to ``1`` and there is no
        statistical power to spend -- which is the honest reading of a short
        demonstration key, not a defect.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`.

    See Also
    --------
    minimum_matched_count : The floor this evaluates at.
    sih141.protocol.analysis.repudiation_bound : The per-run form, at the
        *observed* ``M``, which is the number a completed run should quote.
    sih141.protocol.analysis.averaged_repudiation_bound : The (IND)-dependent
        average that must not be quoted as unconditional.

    Notes
    -----
    Pure and deterministic; consumes no randomness (D3) and reads no run data
    (D4).

    Examples
    --------
    >>> from sih141.protocol.params import DEFAULT_PARAMS, DEMO_PARAMS
    >>> from sih141.protocol.verify import enforced_repudiation_bound
    >>> f"{enforced_repudiation_bound(DEFAULT_PARAMS):.2e}"
    '1.90e-09'
    >>> round(enforced_repudiation_bound(DEMO_PARAMS), 4)  # no claim at L=192
    0.9995
    """
    # Imported here rather than at module scope: ``analysis`` is a leaf that
    # depends only on ``params``, and keeping the edge local documents that
    # verification's *rule* does not depend on the analysis of it.
    from sih141.protocol.analysis import repudiation_bound_with_abort

    floor = minimum_matched_count(params)
    return repudiation_bound_with_abort(
        params, minimum_matched_records=2 * floor
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
        :attr:`AbortReason.EMPTY_MATCHED_SET` when ``matched_count == 0``,
        :attr:`AbortReason.BELOW_FLOOR` otherwise. The two are cross-checked
        against ``matched_count``, so the label and the numbers cannot disagree.
    matched_count : int
        ``|M_R|`` as observed. May be ``0``; must be below
        ``minimum_matched``, since a run that met the floor is a verdict.
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

    Raises
    ------
    TypeError
        If a count is not an integer or ``expected_matched`` is not a real
        number.
    ValueError
        If ``party`` is Alice or names no party; if ``reason`` is not an
        :class:`AbortReason`; if the counts are negative, if
        ``minimum_matched < 1``, if either count exceeds ``key_length``, if
        ``matched_count >= minimum_matched`` (that is a verdict, not an abort),
        or if ``reason`` disagrees with ``matched_count``.

    See Also
    --------
    MatchedSetTooSmall : The exception that carries one out of :func:`verify`.
    VerificationResult : The other outcome of Phase C.

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
        ):
            if value > self.key_length:
                raise ValueError(
                    f"{name} ({value}) cannot exceed key_length "
                    f"({self.key_length}); the matched set is a subset of the "
                    f"key positions."
                )
        if not math.isfinite(self.expected_matched) or not (
            0.0 < self.expected_matched <= self.key_length
        ):
            raise ValueError(
                f"expected_matched must be finite and lie in "
                f"(0, {self.key_length}], got {self.expected_matched!r}. It is "
                f"L/|B|, the mean of Binomial(L, 1/|B|)."
            )
        if self.matched_count >= self.minimum_matched:
            raise ValueError(
                f"matched_count ({self.matched_count}) is at or above "
                f"minimum_matched ({self.minimum_matched}), so this run met the "
                f"floor and reached a verdict. Record a VerificationResult, not "
                f"a VerificationAbort: a no-verdict outcome that a Phase 5 "
                f"table could not distinguish from a decision would defeat the "
                f"point of having two types."
            )
        expected_reason = (
            AbortReason.EMPTY_MATCHED_SET
            if self.matched_count == 0
            else AbortReason.BELOW_FLOOR
        )
        if self.reason is not expected_reason:
            raise ValueError(
                f"reason={self.reason.value!r} contradicts matched_count="
                f"{self.matched_count}: {AbortReason.EMPTY_MATCHED_SET.value!r} "
                f"means exactly |M_R| == 0 and "
                f"{AbortReason.BELOW_FLOOR.value!r} exactly 0 < |M_R| < m_min. "
                f"The label and the numbers have to be the same observation."
            )

    # -- derived views ------------------------------------------------------ #

    @property
    def shortfall(self) -> int:
        """int: ``minimum_matched - matched_count``, always at least ``1``."""
        return self.minimum_matched - self.matched_count

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
            honest mean 200.0 (empty-matched-set). Not a rejection.'``

        Examples
        --------
        >>> from sih141.protocol.verify import AbortReason, VerificationAbort
        >>> VerificationAbort(
        ...     "Charlie", AbortReason.BELOW_FLOOR, 13, 67, 200.0, 600, 1
        ... ).summary()[:19]
        'Charlie NO VERDICT '
        """
        return (
            f"{self.party.value} NO VERDICT bit {self.message_bit}: "
            f"{self.matched_count}/{self.key_length} positions matched, floor "
            f"{self.minimum_matched}, honest mean {self.expected_matched:.1f} "
            f"({self.reason.value}). Not a rejection."
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
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationAbort:
        """Rebuild a refusal from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain every key :meth:`to_dict` emits.

        Returns
        -------
        VerificationAbort

        Raises
        ------
        KeyError
            If a field is missing.
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
    common = (
        f"This is not a signature failure and is not reported as one: "
        f"accepting would accept any declaration whatsoever on zero evidence, "
        f"and rejecting would be recorded as a forgery detection when no "
        f"evidence of forgery exists. QDSSession records it as a no-verdict "
        f"outcome (VerificationAbort) rather than losing the run."
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


def verify(
    signature: Signature,
    record: RecipientRecord,
    params: ProtocolParams,
) -> VerificationResult:
    """Score a signature against one recipient's record and reach a verdict.

    Phase C for a single verifier. Builds the matched set, checks it is large
    enough to carry a verdict at all, counts disagreements **within it only**,
    divides, and compares against the threshold ``params`` assigns to the party
    the record belongs to.

    The size check is the matched-count abort rule: if ``|M_R|`` falls below
    :func:`minimum_matched_count` -- which an honest run does with probability
    at most :data:`HONEST_ABORT_BUDGET` -- nothing is scored and
    :exc:`MatchedSetTooSmall` is raised carrying a :class:`VerificationAbort`.
    Use :func:`verify_or_abort` to get that as a returned outcome instead.

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

    Returns
    -------
    VerificationResult
        The verdict together with ``matched_count``, ``mismatches``, ``rate``,
        ``threshold``, ``key_length`` and ``message_bit``.

    Raises
    ------
    TypeError
        If any argument is of the wrong type.
    ValueError
        If the signature and the record describe different runs (different
        message bit or length), or if either does not belong to ``params``.
        These are wiring errors.
    MatchedSetTooSmall
        A :class:`ValueError` subclass, if ``|M_R|`` is below
        :func:`minimum_matched_count` -- including the ``0/0`` case. This is a
        plumbing failure rather than a signature failure, is explained at length
        in the module docstring, and must never be recorded as a rejection.

    See Also
    --------
    verify_or_abort : The same decision, with the refusal returned not raised.
    verify_all : Both verifiers at once, which is what transferability needs.
    minimum_matched_count : The floor, and the Chernoff bound behind it.
    matched_positions : The evidence base this decision rests on.
    sih141.protocol.params.ProtocolParams.threshold_for : The cut per party.

    Notes
    -----
    A noiseless honest run gives ``rate == 0.0`` exactly -- teleportation over a
    clean pair is exact, so on a matched position the recipient re-measured the
    very observable the state was an eigenstate of. Both thresholds are noise
    budgets measured from that zero, and the acceptance test is ``<=``, so a run
    landing exactly on its threshold is accepted.

    Consumes no randomness (D3).

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
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    _check_pairing(signature, record)
    signature.check_against(params)
    record.check_against(params)

    matched = matched_positions(signature, record)
    floor = minimum_matched_count(params)
    if len(matched) < floor:
        # A no-verdict outcome, not a rejection: see the module docstring.
        raise MatchedSetTooSmall(
            VerificationAbort(
                party=record.party,
                reason=(
                    AbortReason.EMPTY_MATCHED_SET
                    if not matched
                    else AbortReason.BELOW_FLOOR
                ),
                matched_count=len(matched),
                minimum_matched=floor,
                expected_matched=params.expected_matched,
                key_length=params.key_length,
                message_bit=record.message_bit,
            )
        )

    mismatches = len(mismatch_positions(signature, record))
    rate = mismatches / len(matched)
    threshold = params.threshold_for(record.party)

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

    Returns
    -------
    VerificationResult or VerificationAbort
        A verdict when the matched set met :func:`minimum_matched_count`, a
        recorded no-verdict otherwise. The two are different types precisely so
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
        return verify(signature, record, params)
    except MatchedSetTooSmall as too_small:
        return too_small.abort


def verify_all(
    signature: Signature,
    records: Mapping[Party | str, RecipientRecord],
    params: ProtocolParams,
    *,
    require_symmetrised: bool = True,
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

    Returns
    -------
    dict of Party to VerificationResult
        One decision per party, in the order given. Each carries its own
        threshold, so Bob's is scored against ``s_a`` and Charlie's against
        ``s_v`` without the caller choosing.

    Raises
    ------
    TypeError
        If ``records`` is not a mapping, or any value is not a
        :class:`~sih141.protocol.records.RecipientRecord`.
    ValueError
        If ``records`` is empty, if a key disagrees with the party its record is
        tagged with, if a record is unsymmetrised while ``require_symmetrised``
        is set, or for any reason :func:`verify` raises.
    MatchedSetTooSmall
        Propagated unchanged from :func:`verify` if either verifier's matched
        set is below :func:`minimum_matched_count`. This function reaches *both*
        verdicts or none: a pair in which one verifier could not be scored says
        nothing about transferability or repudiation, both of which are
        statements about the two together. A caller that needs the partial
        picture should call :func:`verify_or_abort` per record.

    See Also
    --------
    sih141.protocol.symmetrise.symmetrise_records : Produces an acceptable pair.

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

    results: dict[Party, VerificationResult] = {}
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
        results[resolved] = verify(signature, record, params)
    return results
