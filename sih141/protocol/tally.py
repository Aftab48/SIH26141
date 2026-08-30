"""Phase C': the recipients compare how much evidence each of them holds.

One integer each way over the channel Bob and Charlie already share, and it is
the whole of the extra communication the pooled matched-count floor costs. Like
:mod:`sih141.protocol.symmetrise` this is a step **between the two recipients**:
Alice is not in it, cannot see it and cannot influence it.

Why a message is needed at all
------------------------------
:func:`sih141.protocol.verify.minimum_matched_count` floors ``|M_R|`` at each
verifier separately, and each verifier can check his own count alone. The
quantity every repudiation bound is actually exponential in is the *pooled*
count

.. code-block:: text

    M = m_B + m_C

and neither verifier knows it. That is not a detail. Section 4b-iii of
:mod:`sih141.protocol.analysis` shows that a per-verifier floor, applied on its
own, creates a route it does not close:

.. code-block:: text

    a signer who reads both raw logs declares a key whose *total* matched
    count is exactly 2 m_min, all of it on clean records at positions where
    the two logs used different bases.  Each matched record is then held by
    exactly one verifier, and the symmetrisation coins decide which.
    m_B ~ Binomial(2 m_min, 1/2), m_C = 2 m_min - m_B.

    m_B > m_min  =>  Bob clears his floor and accepts at rate 0,
                     Charlie is below his and returns no verdict.

That happens with probability ``(1 - P[m_B = m_min]) / 2``, which tends to
``1/2``: no rate deviates anywhere, so no exponent bounds it, and no key length
helps because ``m_min`` grows with ``L`` and the attack's target grows with it.
Measured through the shipped seams before this module existed: ``78/200`` at
``L = 360`` and ``85/200`` at ``L = 600``.

Both verifiers checking ``M`` closes it, and ``M`` is not local to either. So
they exchange it. This module is that exchange.

What crosses the wire
---------------------
A :class:`MatchedCountMessage`: the sender's party, the message bit, ``|M_R|``
and the key length. **A count, never a log.** That distinction is the reason
this is modelled as a message rather than as two functions sharing a Python
object: a recipient who could see *which* positions the other matched would hold
evidence the threat model does not give him -- half of it is exactly what
symmetrisation hid -- and a forging recipient's advantage is positional. A
single integer, arriving after the declaration is already fixed, tells him
nothing he can aim.

Nothing about this message is secret. It is sent over the same private,
authenticated recipient-to-recipient channel the symmetrisation coins use, so
**no new channel assumption is introduced**; but even a fully public count would
be harmless to the bound, which conditions on the records and the declaration
and uses only the coins.

What it costs, stated plainly
-----------------------------
*Bob's verdict stops being local.* He cannot accept until Charlie has reported a
count, which means the declaration has to reach Charlie first. A deployment
orders it: Bob scores his own log, and only if he would accept does he pass the
declaration on and ask for the count. So a signature Bob would reject is still
never forwarded, but a signature he would accept is no longer accepted on his
own evidence alone.

*Either recipient can force an abort.* A verifier who reports a count of zero
takes the run down. That is availability, not integrity: a recipient could
always refuse to participate, and under-reporting can only ever *withhold* an
acceptance, never manufacture one -- every acceptance still requires the
accepting verifier's own rate to clear his own threshold on his own log, which
no message from the other verifier touches.

*The guarantee is now conditional on the counterpart's report being honest, and
that is a real change.* Over-reporting is the direction that costs something: if
Charlie inflates ``m_C``, the pooled floor clears on a total the run did not have,
and Bob's unconditional bound degrades from
``exp(-M_min gap^2/8)`` to ``exp(-(M_min - delta) gap^2/8)`` for an inflation of
``delta`` -- gracefully, and only by what was inflated. It does not, however, hand
anyone a new capability. Bob's non-repudiation guarantee is a guarantee *against
Alice*, and the party it protects him from being denied by is Charlie: a Charlie
who would collude with Alice to weaken it can simply reject the signature outright
and has never needed a false count to do so. So the requirement added here --
"the counterpart reports honestly" -- is implied by the threat model that made
non-repudiation worth stating in the first place, and it is written down rather
than assumed silently.

*One more round trip.* Two integers, against ``2 |B| L`` teleported qubits.

The Phase 3 seam
----------------
:func:`no_count_exchange` is a drop-in replacement that returns ``None``, wired
through :class:`~sih141.protocol.session.QDSSession`'s ``count_exchange``
argument. It exists so Phase 3 can *measure* the split-coin attack rather than
take this docstring's word for it, exactly as
:func:`sih141.protocol.symmetrise.no_symmetrisation` exists for the earlier one,
and so the two runs differ in one callable. A run made with it enforces the
per-verifier floor alone and has no unconditional non-repudiation guarantee
below ``1/2``; :attr:`~sih141.protocol.session.SessionTranscript.counts_exchanged`
reports which kind of run a transcript is, and
:meth:`~sih141.protocol.session.SessionTranscript.summary` says so out loud.

Notes
-----
Determinism (D3)
    Nothing here consumes randomness. The exchange is counting and comparison;
    there is no ``rng`` argument to inject, and the session's generator stream
    is identical with and without it, so a run made with
    :func:`no_count_exchange` and one made with :func:`exchange_matched_counts`
    are comparable position by position.
Immutability
    Every type here is a frozen dataclass over integers and
    :class:`enum.StrEnum` members, so it drops straight into :func:`json.dumps`
    and into a :class:`~sih141.protocol.session.SessionTranscript`.
Canonical state type (D1), qubit ordering (D2)
    No state is touched; this phase is entirely classical bookkeeping over
    already-measured records.
No machine learning (D4)
    Two counts, one addition and two comparisons against a closed form in
    ``(L, |B|, eps)``.

See Also
--------
sih141.protocol.verify.minimum_pooled_matched_count : The floor this checks.
sih141.protocol.verify.verify : Applies the result, one verifier at a time.
sih141.protocol.symmetrise.symmetrise_records : The other recipients-only step.

Examples
--------
>>> import numpy as np
>>> from sih141.protocol.distribute import distribute_public_key
>>> from sih141.protocol.keys import generate_private_key
>>> from sih141.protocol.params import Party, ProtocolParams
>>> from sih141.protocol.signature import sign
>>> from sih141.protocol.symmetrise import symmetrise_records
>>> from sih141.protocol.tally import (
...     exchange_matched_counts, matched_count_message
... )
>>> params = ProtocolParams(key_length=600)
>>> key = generate_private_key(params, 0, rng=np.random.default_rng(1))
>>> raw = distribute_public_key(key, params, rng=np.random.default_rng(2))
>>> records = symmetrise_records(raw, rng=np.random.default_rng(3))
>>> declaration = sign(0, key, params)
>>> messages = {
...     party: matched_count_message(declaration, record, params)
...     for party, record in records.items()
... }
>>> pooled = exchange_matched_counts(messages, params)
>>> pooled.pooled == pooled.bob_count + pooled.charlie_count
True
>>> pooled.meets_pooled_floor, pooled.meets_every_floor
(True, True)
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from sih141.protocol.params import (
    VERIFIERS,
    Party,
    ProtocolParams,
    _as_message_bit,
    _as_party,
)
from sih141.protocol.records import RecipientRecord
from sih141.protocol.signature import Signature
from sih141.protocol.verify import (
    _as_count,
    matched_positions,
    minimum_matched_count,
    minimum_pooled_matched_count,
)

__all__ = [
    "CountExchange",
    "MatchedCountMessage",
    "PooledMatchedCounts",
    "exchange_matched_counts",
    "matched_count_message",
    "no_count_exchange",
]


@dataclass(frozen=True)
class MatchedCountMessage:
    """One recipient's Phase C' message: how many positions he can score.

    The only thing this step puts on the wire. Frozen, hashable and made of
    :class:`int` and :class:`~sih141.protocol.params.Party` (a
    :class:`enum.StrEnum`), so it passes to :func:`json.dumps` unchanged and can
    be recorded in a transcript.

    It carries a **count and no positions**, which is the point: see the module
    docstring on what the recipients are and are not allowed to learn about each
    other.

    Parameters
    ----------
    party : Party or str
        The sender. Alice is refused: she holds no measurement record and is not
        in this exchange.
    message_bit : int
        The bit whose declaration the count was computed against, ``0`` or
        ``1``. Carried so that two runs' messages cannot be crossed.
    matched_count : int
        ``|M_R|`` against that declaration. May be ``0``.
    key_length : int
        ``L``, so a receiver can tell at once that the two messages describe the
        same run.

    Raises
    ------
    TypeError
        If a count is not an integer.
    ValueError
        If ``party`` is Alice or names no party, if ``message_bit`` is not
        ``0``/``1``, if ``key_length < 1``, or if ``matched_count`` exceeds
        ``key_length``.

    See Also
    --------
    matched_count_message : Computes one.
    exchange_matched_counts : Combines the two.

    Examples
    --------
    >>> from sih141.protocol.tally import MatchedCountMessage
    >>> message = MatchedCountMessage("Bob", 0, 204, 600)
    >>> message.party.value, message.matched_count
    ('Bob', 204)
    """

    party: Party
    message_bit: int
    matched_count: int
    key_length: int

    def __post_init__(self) -> None:
        """Coerce the fields and refuse a message no recipient could have sent."""
        resolved = _as_party(self.party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice sends no matched-count message: she is the signer, "
                "holds no measurement record and is not a party to the "
                "recipients' exchange. A MatchedCountMessage belongs to "
                "Party.BOB or Party.CHARLIE."
            )
        object.__setattr__(self, "party", resolved)
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        object.__setattr__(
            self, "matched_count", _as_count(self.matched_count, "matched_count")
        )
        object.__setattr__(
            self, "key_length", _as_count(self.key_length, "key_length")
        )
        if self.key_length < 1:
            raise ValueError(
                f"key_length must be at least 1, got {self.key_length}; a run "
                f"with no key positions has nothing to count."
            )
        if self.matched_count > self.key_length:
            raise ValueError(
                f"matched_count ({self.matched_count}) cannot exceed "
                f"key_length ({self.key_length}); the matched set is a subset "
                f"of the key positions."
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the message.

        Returns
        -------
        dict
            One key per field.

        Examples
        --------
        >>> import json
        >>> from sih141.protocol.tally import MatchedCountMessage
        >>> json.loads(json.dumps(MatchedCountMessage("Bob", 1, 3, 9).to_dict()))
        {'party': 'Bob', 'message_bit': 1, 'matched_count': 3, 'key_length': 9}
        """
        return {
            "party": self.party,
            "message_bit": self.message_bit,
            "matched_count": self.matched_count,
            "key_length": self.key_length,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MatchedCountMessage:
        """Rebuild a message from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain every key :meth:`to_dict` emits.

        Returns
        -------
        MatchedCountMessage

        Raises
        ------
        KeyError
            If a field is missing.
        ValueError
            If the restored fields are not self-consistent.
        """
        return cls(
            party=data["party"],
            message_bit=data["message_bit"],
            matched_count=data["matched_count"],
            key_length=data["key_length"],
        )


@dataclass(frozen=True)
class PooledMatchedCounts:
    """What both recipients know once the two messages have crossed.

    The record of one Phase C' exchange, identical at both verifiers because
    both hold both messages. Frozen and JSON-serialisable, and carried into
    :attr:`sih141.protocol.session.SessionTranscript.pooled` so that a Phase 4
    or Phase 5 reader can see the evidence base a run was scored on -- and see
    that the recipients compared it at all.

    The floors are stored rather than recomputed on access, for the same reason
    :class:`~sih141.protocol.verify.VerificationAbort` stores its own: a
    transcript on disk has to say what the rule *was* when the run happened.

    Parameters
    ----------
    bob_count, charlie_count : int
        ``m_B`` and ``m_C``, as each verifier reported them.
    minimum_matched : int
        ``m_min`` from
        :func:`~sih141.protocol.verify.minimum_matched_count`.
    minimum_pooled : int
        ``M_min`` from
        :func:`~sih141.protocol.verify.minimum_pooled_matched_count`.
    key_length : int
        ``L``.
    message_bit : int
        The bit being signed.

    Raises
    ------
    TypeError
        If a count is not an integer.
    ValueError
        If ``message_bit`` is not ``0``/``1``, if ``key_length < 1``, if a floor
        is below ``1``, if either count exceeds ``key_length``, or if
        ``minimum_pooled`` exceeds ``2 * key_length``.

    See Also
    --------
    exchange_matched_counts : Produces one.
    sih141.protocol.verify.verify : Consumes the counts, one verifier at a time.

    Examples
    --------
    >>> from sih141.protocol.tally import PooledMatchedCounts
    >>> pooled = PooledMatchedCounts(
    ...     bob_count=204, charlie_count=196, minimum_matched=67,
    ...     minimum_pooled=212, key_length=600, message_bit=0,
    ... )
    >>> pooled.pooled, pooled.meets_every_floor
    (400, True)
    >>> pooled.counterpart_of("Bob")
    196
    """

    bob_count: int
    charlie_count: int
    minimum_matched: int
    minimum_pooled: int
    key_length: int
    message_bit: int

    def __post_init__(self) -> None:
        """Coerce the fields and check the two messages describe one run."""
        for name in ("bob_count", "charlie_count", "key_length"):
            object.__setattr__(self, name, _as_count(getattr(self, name), name))
        for name in ("minimum_matched", "minimum_pooled"):
            object.__setattr__(self, name, _as_count(getattr(self, name), name))
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        if self.key_length < 1:
            raise ValueError(
                f"key_length must be at least 1, got {self.key_length}; a run "
                f"with no key positions has nothing to count."
            )
        for name in ("minimum_matched", "minimum_pooled"):
            if getattr(self, name) < 1:
                raise ValueError(
                    f"{name} must be at least 1, got {getattr(self, name)}. "
                    f"Even where the Chernoff tail is vacuous a floor is 1, "
                    f"because a rate needs a denominator; see "
                    f"sih141.protocol.verify.minimum_matched_count."
                )
        for name in ("bob_count", "charlie_count"):
            if getattr(self, name) > self.key_length:
                raise ValueError(
                    f"{name} ({getattr(self, name)}) cannot exceed key_length "
                    f"({self.key_length}); each matched set is a subset of the "
                    f"same key positions."
                )
        if self.minimum_pooled > 2 * self.key_length:
            raise ValueError(
                f"minimum_pooled ({self.minimum_pooled}) cannot exceed "
                f"2 * key_length ({2 * self.key_length}); the pooled count is "
                f"over both verifiers' matched sets, so 2 L is its ceiling."
            )

    # -- derived views ------------------------------------------------------ #

    @property
    def pooled(self) -> int:
        """int: ``M = m_B + m_C``, the evidence base of the whole run.

        The quantity :func:`sih141.protocol.analysis.repudiation_bound` is
        exponential in, and the reason this exchange exists: neither verifier
        can compute it alone.
        """
        return self.bob_count + self.charlie_count

    @property
    def meets_pooled_floor(self) -> bool:
        """bool: ``True`` iff ``M >= M_min``."""
        return self.pooled >= self.minimum_pooled

    @property
    def parties_below_floor(self) -> tuple[Party, ...]:
        """tuple of Party: verifiers whose own count is below ``m_min``.

        In :data:`~sih141.protocol.params.VERIFIERS` order, and empty on a
        healthy run. Any entry takes *both* verifiers down: the per-verifier
        floor's consequence is joint, which is what removes the asymmetric
        no-verdict from the outcome space.
        """
        return tuple(
            party
            for party in VERIFIERS
            if self.count_for(party) < self.minimum_matched
        )

    @property
    def meets_every_floor(self) -> bool:
        """bool: ``True`` iff every floor is met and both verifiers may score."""
        return self.meets_pooled_floor and not self.parties_below_floor

    def count_for(self, party: Party | str) -> int:
        """Return the count one verifier reported.

        Parameters
        ----------
        party : Party or str
            :attr:`~sih141.protocol.params.Party.BOB` or
            :attr:`~sih141.protocol.params.Party.CHARLIE`.

        Returns
        -------
        int

        Raises
        ------
        ValueError
            If ``party`` is :attr:`~sih141.protocol.params.Party.ALICE`, who
            reports nothing.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.
        """
        resolved = _as_verifier(party)
        return (
            self.bob_count if resolved is Party.BOB else self.charlie_count
        )

    def counterpart_of(self, party: Party | str) -> int:
        """Return the count the **other** verifier reported to ``party``.

        The number :func:`sih141.protocol.verify.verify` takes as
        ``counterpart_matched``. Provided as a method so that no call site has
        to invert the mapping by hand, which is the one way a verifier could be
        handed his own count and clear the pooled floor twice over.

        Parameters
        ----------
        party : Party or str
            The *receiving* verifier.

        Returns
        -------
        int

        Raises
        ------
        ValueError
            If ``party`` is :attr:`~sih141.protocol.params.Party.ALICE`.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.
        """
        resolved = _as_verifier(party)
        return (
            self.charlie_count if resolved is Party.BOB else self.bob_count
        )

    def summary(self) -> str:
        """Return a one-line human-readable account of the exchange.

        Returns
        -------
        str
            The two counts, the pooled total and both floors, followed by
            whether the run may be scored.

        Examples
        --------
        >>> from sih141.protocol.tally import PooledMatchedCounts
        >>> PooledMatchedCounts(204, 196, 67, 212, 600, 0).summary()
        'POOLED EVIDENCE bit 0: m_B = 204, m_C = 196, M = 400 (floors: \
m_min = 67, M_min = 212). Every floor met.'
        """
        if self.meets_every_floor:
            verdict = "Every floor met."
        elif not self.meets_pooled_floor:
            verdict = (
                f"Pooled floor NOT met: M = {self.pooled} < "
                f"{self.minimum_pooled}. Neither verifier scores."
            )
        else:
            short = ", ".join(
                party.value for party in self.parties_below_floor
            )
            verdict = (
                f"Below the per-verifier floor: {short}. Neither verifier "
                f"scores."
            )
        return (
            f"POOLED EVIDENCE bit {self.message_bit}: m_B = {self.bob_count}, "
            f"m_C = {self.charlie_count}, M = {self.pooled} (floors: "
            f"m_min = {self.minimum_matched}, M_min = {self.minimum_pooled}). "
            f"{verdict}"
        )

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the exchange.

        Returns
        -------
        dict
            One key per field. Nothing derived is stored: :attr:`pooled` and
            the floor tests are recomputed on the way back in, so a stored
            exchange cannot disagree with itself.

        Examples
        --------
        >>> import json
        >>> from sih141.protocol.tally import PooledMatchedCounts
        >>> blob = PooledMatchedCounts(204, 196, 67, 212, 600, 0).to_dict()
        >>> json.loads(json.dumps(blob))["bob_count"]
        204
        """
        return {
            "bob_count": self.bob_count,
            "charlie_count": self.charlie_count,
            "minimum_matched": self.minimum_matched,
            "minimum_pooled": self.minimum_pooled,
            "key_length": self.key_length,
            "message_bit": self.message_bit,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PooledMatchedCounts:
        """Rebuild an exchange from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain every key :meth:`to_dict` emits.

        Returns
        -------
        PooledMatchedCounts

        Raises
        ------
        KeyError
            If a field is missing.
        ValueError
            If the restored fields are not self-consistent.
        """
        return cls(
            bob_count=data["bob_count"],
            charlie_count=data["charlie_count"],
            minimum_matched=data["minimum_matched"],
            minimum_pooled=data["minimum_pooled"],
            key_length=data["key_length"],
            message_bit=data["message_bit"],
        )


class CountExchange(Protocol):
    """Callable that runs Phase C' on one declaration's pair of messages.

    :func:`exchange_matched_counts` is the honest implementation and the
    default; :func:`no_count_exchange` is the Phase 3 replacement that skips the
    step so that the split-coin attack it defends against can be measured. A
    replacement returns either a :class:`PooledMatchedCounts` over the two
    messages it was given, or ``None`` to mean "the recipients did not compare",
    in which case only the per-verifier floor applies.
    """

    def __call__(
        self,
        messages: Mapping[Party | str, MatchedCountMessage],
        params: ProtocolParams,
    ) -> PooledMatchedCounts | None:
        """Return the pooled view both recipients end up holding."""
        ...


def matched_count_message(
    signature: Signature,
    record: RecipientRecord,
    params: ProtocolParams,
) -> MatchedCountMessage:
    """Compute what one recipient sends in Phase C'.

    Purely local: the recipient intersects his own logged bases with the
    declared ones -- the same
    :func:`sih141.protocol.verify.matched_positions` the verdict will use, so
    the count he announces and the count he scores on cannot drift apart -- and
    announces the size.

    Parameters
    ----------
    signature : Signature
        The declaration he was asked to score. Both recipients must count
        against the **same** declaration: ``m_B + m_C = M`` and ``e_B + e_C = E``
        are conserved across one fixed pair of records and one fixed
        declaration, and the pooled floor means nothing without that.
    record : RecipientRecord
        His own post-symmetrisation log. Read, never modified.
    params : ProtocolParams
        The parameter set the run executes under; both inputs are checked
        against it.

    Returns
    -------
    MatchedCountMessage
        Ready to hand to :func:`exchange_matched_counts`.

    Raises
    ------
    TypeError
        If any argument is of the wrong type.
    ValueError
        If the signature and the record describe different runs, or if either
        does not belong to ``params``.

    See Also
    --------
    exchange_matched_counts : What the two messages are combined by.

    Notes
    -----
    Consumes no randomness (D3), and reads nothing but this recipient's own
    record.

    Examples
    --------
    >>> from sih141.protocol.keys import KeyElement, PrivateKey
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.records import RecipientRecord
    >>> from sih141.protocol.signature import sign
    >>> from sih141.protocol.tally import matched_count_message
    >>> params = ProtocolParams(key_length=2)
    >>> key = PrivateKey(0, (KeyElement("X", 1), KeyElement("Z", -1)))
    >>> record = RecipientRecord.from_measurements("Bob", 0, ["X", "Y"], [1, 1])
    >>> matched_count_message(sign(0, key, params), record, params)
    MatchedCountMessage(party=<Party.BOB: 'Bob'>, message_bit=0, \
matched_count=1, key_length=2)
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
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
    signature.check_against(params)
    record.check_against(params)
    return MatchedCountMessage(
        party=record.party,
        message_bit=record.message_bit,
        matched_count=len(matched_positions(signature, record)),
        key_length=params.key_length,
    )


def _checked_messages(
    messages: Mapping[Party | str, MatchedCountMessage],
    params: ProtocolParams,
) -> tuple[MatchedCountMessage, MatchedCountMessage]:
    """Validate the mapping and return ``(Bob's message, Charlie's message)``.

    Parameters
    ----------
    messages : mapping of Party to MatchedCountMessage
        One message per verifier.
    params : ProtocolParams
        The parameter set the run executes under.

    Returns
    -------
    tuple of MatchedCountMessage
        Bob's then Charlie's, in :data:`~sih141.protocol.params.VERIFIERS` order
        regardless of the mapping's own order.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, ``messages`` is not a
        mapping, or a value is not a :class:`MatchedCountMessage`.
    ValueError
        If either verifier is missing, if a message is filed under the wrong
        party, if there are extra entries, or if the two messages disagree about
        the run's message bit or key length -- or disagree with ``params``.
    """
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}; "
            f"the two floors are read off it."
        )
    if not isinstance(messages, Mapping):
        raise TypeError(
            f"messages must be a mapping of Party to MatchedCountMessage, got "
            f"{type(messages).__name__}; build one with "
            f"matched_count_message(...) per recipient."
        )
    resolved: dict[Party, MatchedCountMessage] = {}
    for party, message in messages.items():
        key = _as_party(party)
        if not isinstance(message, MatchedCountMessage):
            raise TypeError(
                f"messages[{key.value!r}] must be a MatchedCountMessage, got "
                f"{type(message).__name__}"
            )
        if message.party is not key:
            raise ValueError(
                f"messages is keyed by {key.value!r} but the message stored "
                f"there was sent by {message.party.value!r}. The key decides "
                f"whose count is whose, so a mislabelled entry would hand each "
                f"verifier his own number back as the counterpart's."
            )
        resolved[key] = message

    missing = [party.value for party in VERIFIERS if party not in resolved]
    if missing:
        raise ValueError(
            f"the count exchange needs both verifiers' messages, missing "
            f"{missing}. The step *is* a comparison between Bob and Charlie: "
            f"with one recipient there is no pooled count, and with one "
            f"recipient the protocol has no transferability and no "
            f"non-repudiation to protect in the first place."
        )
    extra = sorted(set(resolved) - set(VERIFIERS))
    if extra:
        raise ValueError(
            f"the count exchange takes exactly the two verifiers' messages, "
            f"got extra entries for {[party.value for party in extra]}. The "
            f"comparison is defined pairwise."
        )

    bob, charlie = resolved[Party.BOB], resolved[Party.CHARLIE]
    if bob.message_bit != charlie.message_bit:
        raise ValueError(
            f"the two messages are from different runs: Bob's counts a "
            f"declaration for message bit {bob.message_bit} and Charlie's for "
            f"bit {charlie.message_bit}. Only counts against the *same* "
            f"declaration may be pooled -- m_B + m_C is conserved for one "
            f"declaration and means nothing across two."
        )
    for message in (bob, charlie):
        if message.key_length != params.key_length:
            raise ValueError(
                f"{message.party.value}'s message reports key_length "
                f"{message.key_length} but these parameters say "
                f"{params.key_length}. The floors are derived from the key "
                f"length, so a mismatch means the message and the rule come "
                f"from different runs."
            )
    return bob, charlie


def exchange_matched_counts(
    messages: Mapping[Party | str, MatchedCountMessage],
    params: ProtocolParams,
) -> PooledMatchedCounts:
    """Combine the two recipients' messages into the pooled view. Phase C'.

    Each recipient sends :func:`matched_count_message` and receives the other's;
    both then hold the same :class:`PooledMatchedCounts` and apply the same two
    floors to it. The function is symmetric in the two messages precisely so
    that "both verifiers reach the same conclusion" is a property of the code
    rather than a hope.

    Parameters
    ----------
    messages : mapping of Party to MatchedCountMessage
        One message per verifier, against the same declaration, same message
        bit, same key length.
    params : ProtocolParams
        The parameter set the run executes under. Supplies both floors, which
        are stored in the result rather than recomputed later.

    Returns
    -------
    PooledMatchedCounts
        Never ``None``: the honest exchange always happens. The result says
        whether the floors were met; it does not itself refuse anything, because
        the refusal is a verifier's, and :func:`sih141.protocol.verify.verify`
        is where a verifier's outcome is decided.

    Raises
    ------
    TypeError
        If ``params`` or ``messages`` is of the wrong type.
    ValueError
        If a verifier is missing, a message is filed under the wrong party, or
        the two messages do not describe one run under ``params``.

    See Also
    --------
    no_count_exchange : The Phase 3 replacement that skips the step.
    sih141.protocol.verify.minimum_pooled_matched_count : The pooled floor.

    Notes
    -----
    Consumes no randomness (D3) and reads no positions -- only two integers
    (D4).

    Examples
    --------
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.tally import (
    ...     MatchedCountMessage, exchange_matched_counts
    ... )
    >>> params = ProtocolParams(key_length=600)
    >>> messages = {
    ...     Party.BOB: MatchedCountMessage("Bob", 0, 68, 600),
    ...     Party.CHARLIE: MatchedCountMessage("Charlie", 0, 66, 600),
    ... }
    >>> pooled = exchange_matched_counts(messages, params)
    >>> pooled.pooled, pooled.minimum_pooled, pooled.meets_pooled_floor
    (134, 212, False)
    >>> pooled.parties_below_floor        # Charlie is under m_min = 67 too
    (<Party.CHARLIE: 'Charlie'>,)
    """
    bob, charlie = _checked_messages(messages, params)
    return PooledMatchedCounts(
        bob_count=bob.matched_count,
        charlie_count=charlie.matched_count,
        minimum_matched=minimum_matched_count(params),
        minimum_pooled=minimum_pooled_matched_count(params),
        key_length=params.key_length,
        message_bit=bob.message_bit,
    )


def no_count_exchange(
    messages: Mapping[Party | str, MatchedCountMessage],
    params: ProtocolParams,
) -> None:
    """Skip Phase C'. **Leaves the split-coin repudiation route open.**

    The Phase 3 replacement for :func:`exchange_matched_counts`, provided so
    that the attack the exchange defends against can be run and measured rather
    than asserted: pass it as
    ``QDSSession(..., count_exchange=no_count_exchange)`` and a signer that reads
    both raw logs, aims ``M`` at ``2 m_min`` and lets the coins split it gets Bob
    to accept a signature Charlie cannot score, about half the time, at any key
    length.

    Parameters
    ----------
    messages : mapping of Party to MatchedCountMessage
        The two messages. Validated exactly as
        :func:`exchange_matched_counts` validates them, so that a mis-wired
        experiment fails the same way in both arms.
    params : ProtocolParams
        The parameter set. Used only for that validation.

    Returns
    -------
    None
        Meaning "the recipients did not compare counts". Every downstream
        verifier then applies the per-verifier floor alone, and the run carries
        no unconditional non-repudiation guarantee below ``1/2``:
        :attr:`sih141.protocol.session.SessionTranscript.counts_exchanged` is
        ``False`` and :meth:`~sih141.protocol.session.SessionTranscript.summary`
        says so.

    Raises
    ------
    TypeError
        As :func:`exchange_matched_counts`.
    ValueError
        As :func:`exchange_matched_counts`.

    Examples
    --------
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.tally import (
    ...     MatchedCountMessage, no_count_exchange
    ... )
    >>> params = ProtocolParams(key_length=600)
    >>> messages = {
    ...     Party.BOB: MatchedCountMessage("Bob", 0, 68, 600),
    ...     Party.CHARLIE: MatchedCountMessage("Charlie", 0, 66, 600),
    ... }
    >>> no_count_exchange(messages, params) is None
    True
    """
    _checked_messages(messages, params)
    return None


def _as_verifier(party: Party | str) -> Party:
    """Coerce a label to a verifier, refusing Alice.

    Parameters
    ----------
    party : Party or str
        The party.

    Returns
    -------
    Party
        :attr:`~sih141.protocol.params.Party.BOB` or
        :attr:`~sih141.protocol.params.Party.CHARLIE`.

    Raises
    ------
    ValueError
        If ``party`` is :attr:`~sih141.protocol.params.Party.ALICE` or names no
        party.
    TypeError
        If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor a
        string.
    """
    resolved = _as_party(party)
    if resolved is Party.ALICE:
        raise ValueError(
            "Alice holds no matched count: she is the signer and is not a "
            "party to the recipients' exchange. Ask for Party.BOB or "
            "Party.CHARLIE."
        )
    return resolved
