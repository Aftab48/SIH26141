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

The empty matched set
---------------------
If ``|M_R| == 0`` the rate is ``0/0`` and :func:`verify` raises
:exc:`ValueError`. The reasoning, since silence in either direction is
defensible-sounding and wrong:

* *Accepting* on an empty matched set is accepting a signature on zero evidence.
  Any declaration whatsoever would pass, so unforgeability would be gone in the
  one case where it is cheapest to exploit.
* *Rejecting* is not honest either. There is no evidence of dishonesty; a
  ``False`` here would be indistinguishable, in a Phase 5 table, from a genuine
  forgery detection, and would silently bias every rejection statistic.
* No *channel* attack can force it. The matched set depends only on the declared
  bases and the recipient's own uniform draws, neither of which the channel
  touches, so an adversary who owns the entire quantum link cannot reach this
  branch. Under honest declarations it happens with probability
  ``(1 - 1/|B|)**L`` -- about ``1e-34`` even for the short
  :data:`~sih141.protocol.params.DEMO_PARAMS`.

That is a plumbing failure, not a signature failure, and the two must not be
reported through the same channel. So it raises, with a message that says which.

**A signer with the right knowledge could force it, and callers should expect
the exception rather than assume it away.** An adversary who knew, per position,
the basis a verifier had logged could declare a different one everywhere, drive
``|M_R|`` to ``0`` and turn this branch into an uncaught :exc:`ValueError` in the
middle of :meth:`~sih141.protocol.session.QDSSession.run`. It would gain him
nothing -- no verdict is reached, so nothing is accepted -- but an experiment
harness that does not wrap ``run()`` loses the run rather than recording a
refusal. An earlier version of this docstring claimed flatly that *no* Phase 3
attack could reach the branch; that was true of the channel and overstated in
general, which is why it now says what is and is not reachable.

Through the shipped seams it is *not* reachable, and the reason is worth
recording. The :class:`~sih141.protocol.session.Signer` seam receives the
**raw**, pre-exchange logs, while each verifier is scored on his
post-symmetrisation record -- his own entry at the positions he retained and the
other verifier's at the positions that were swapped. A declaration built to
avoid every basis in Bob's raw log therefore still matches with probability
``(1/2)(1/|B|) = 1/6`` per position, so ``E[|M_B|] = L/6`` and the empty set
stays a small-``L`` curiosity rather than a denial of service. Phase A' bought
this incidentally, on top of what it was added for.
``tests/test_protocol_verify.py`` pins both halves: a basis-avoiding signer
completes a run, and a record wired to disagree everywhere still raises.

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
"""

from __future__ import annotations

import math
import numbers
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sih141.protocol.params import (
    Party,
    ProtocolParams,
    _as_message_bit,
    _as_party,
)
from sih141.protocol.records import RecipientRecord
from sih141.protocol.signature import Signature

__all__ = [
    "VerificationResult",
    "matched_positions",
    "mismatch_positions",
    "verify",
    "verify_all",
]


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

    Phase C for a single verifier. Builds the matched set, counts disagreements
    **within it only**, divides, and compares against the threshold ``params``
    assigns to the party the record belongs to.

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
        message bit or length); if either does not belong to ``params``; or if
        the matched set is empty, which is a plumbing failure rather than a
        signature failure and is explained at length in the module docstring.

    See Also
    --------
    verify_all : Both verifiers at once, which is what transferability needs.
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
    if not matched:
        probability = (1.0 - params.match_probability) ** params.key_length
        raise ValueError(
            f"{record.party.value}'s matched set is empty: his measurement "
            f"basis differed from the declared one at all "
            f"{params.key_length} positions, so the mismatch rate is 0/0 and "
            f"there is no verdict to reach. This is not a signature failure and "
            f"is not reported as one: accepting would accept any declaration "
            f"whatsoever on zero evidence, and rejecting would be recorded as a "
            f"forgery detection when no evidence of forgery exists. With "
            f"|B| = {len(params.bases)} the honest probability of this is "
            f"(1 - 1/|B|)**L = {probability:.3g}, so in practice it means the "
            f"key is far too short or the record was paired with the wrong key."
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
