"""Orchestration: one QDS run, from entanglement to a transferred signature.

The six modules under :mod:`sih141.protocol` each own one step. This one owns
the *order* of the steps, and the object that remembers what happened:

.. code-block:: text

    QDSSession(params, rng=...)
        .distribute()        Phase A   k_0, k_1 drawn; both public keys
                                       teleported to Bob AND to Charlie,
                                       measured on arrival -> 4 classical logs
                             Phase A'  Bob and Charlie privately re-assign
                                       their two copies of every position
                                       between themselves (symmetrisation)
        .sign(b)             Phase B   Alice declares k_b over the
                                       authenticated classical channel
        .verify(Party.BOB)   Phase C   Bob scores his own log,  cut at s_a
        .transfer()          Phase C   Bob forwards to Charlie, who scores his
                                       own log, cut at s_v
        .transcript()                  the whole run as one frozen,
                                       JSON-serialisable record

``run(b)`` performs the four calls in that order and returns the transcript.

Why Phase A' is inside ``distribute()`` and not a seam of the distributor
------------------------------------------------------------------------
Symmetrisation is performed *by the recipients*, over their own authenticated
channel, after the quantum phase is over. It is what makes non-repudiation true
at all (:mod:`sih141.protocol.symmetrise`), so it must not sit anywhere an
adversary standing in Alice's place can reach: a malicious ``distributor``
returns records and the session symmetrises whatever it returns. There is a
separate ``symmetriser`` seam for Phase 3, but it replaces *the recipients'*
step, not Alice's, and the honest default is the secure one.

Why Charlie is in the constructor and not an option
---------------------------------------------------
Every claim the scheme makes is a claim about a *second* verifier.
Transferability is "Bob accepted **and** Charlie accepted"; non-repudiation is
the impossibility of "Bob accepted **and** Charlie did not". Neither statement
is even expressible with one recipient, so a session always distributes to both
:data:`~sih141.protocol.params.VERIFIERS` and there is no knob to turn that off.
For the same reason both message bits are distributed for: Alice must commit to
``k_0`` and ``k_1`` before she learns which bit she will be asked to sign, so a
session that distributed only for the bit it later signs would be a session in
which Alice chose her key after seeing the message.

Cost, stated plainly: a session teleports ``2 message bits * 2 recipients * L``
qubits. With :data:`~sih141.protocol.params.DEMO_PARAMS` that is 768 hops; with
:data:`~sih141.protocol.params.DEFAULT_PARAMS`, 27648.

.. _phase3-seams:

The Phase 3 seams -- how attacks attach without editing this file
------------------------------------------------------------------
This module is deliberately a *scheduler*, not a policy. Each of the three
places where an adversary can stand is a keyword-only constructor argument
holding a callable that defaults to the honest implementation. Phase 3 mounts
its entire attack suite by passing different callables; **nothing in this file
changes for any attack**, which is what makes an attacked run and a clean run
comparable rather than two different programs.

``resource_factory`` -- the quantum channel
    Zero-argument callable returning the two-qubit entanglement resource for one
    hop, invoked once per key position per recipient and forwarded verbatim to
    :func:`~sih141.protocol.distribute.distribute_to_recipient`. Defaults to
    :func:`~sih141.protocol.distribute.ideal_resource`. This is where channel
    manipulation lives: a Werner or amplitude-damped pair is injected noise, a
    factory that degrades only some calls is an intermittent eavesdropper, and a
    factory closing over its own :class:`numpy.random.Generator` is a randomised
    one. Because the resource is drawn per position, the attack can vary at the
    finest granularity the protocol has.

``distributor`` -- Phase A as a whole
    Callable with the signature of
    :func:`~sih141.protocol.distribute.distribute_public_key`, which is the
    default. Replacing it replaces the entire distribution step for one message
    bit, which is where an impersonator standing between Alice and the
    recipients belongs -- one who substitutes his own states rather than merely
    degrading Alice's. Its return value is checked (both verifiers present,
    right message bit, right length) before the session will use it, so a
    mis-wired attack fails loudly instead of quietly producing a clean run.

``signer`` -- Phase B, i.e. who is holding the pen
    Callable matching :class:`Signer`, defaulting to :func:`honest_signer`. It
    receives the message bit, the key pair, the parameters, **and the
    recipients' records**, and returns the :class:`~sih141.protocol.signature.Signature`
    that will be verified. Handing it the records is what makes the interesting
    adversaries expressible: a forging Bob ignores ``keys`` and reconstructs a
    declaration from ``records[b][Party.BOB]``, his own measurement log, which is
    genuinely all he holds; a repudiating Alice starts from her real ``k_b`` and
    perturbs it, aiming to land under ``s_a`` at Bob and over ``s_v`` at
    Charlie. The honest signer ignores ``records`` entirely -- it is not evidence
    Alice has -- and that asymmetry is the point.

    *Which records, and why it matters.* The seam is handed the **raw**,
    pre-exchange logs -- what each recipient actually measured -- and not the
    post-symmetrisation ones the verifiers will be scored on. That is the
    faithful choice in both directions. It is what a forging Bob needs: after
    the exchange, half of Charlie's evidence *is* Bob's own raw record, so
    declaring that record at every position is his optimal strategy and reaches
    the ``1/12`` floor, whereas his post-exchange record is precisely the half
    Charlie does *not* hold and is worth nothing to him. And it is what a
    repudiating Alice must not have: the exchange is private to the recipients,
    so its outcome is never offered to the signer, which is the whole basis of
    the non-repudiation bound.

    .. _two-log-signer:

    **Security caveat: the seam hands over BOTH recipients' raw logs, which is
    more than any single adversary in the threat model holds.** A forging Bob
    legitimately reads ``records[b][Party.BOB]`` and nothing else; a repudiating
    Alice holds neither log. A signer that reads both is therefore outside the
    model the scheme's bounds are stated for -- but it is squarely *inside* what
    this file makes reachable, and two published consequences follow, so it is
    named here rather than scoped away. Nothing below is a defect in the
    mathematics; each is a limit on what a number may be published as.

    *It can empty the matched set outright.* A declaration that avoids both raw
    logs at every position leaves nothing for either verifier: after the
    exchange each verifier's entry is one of the two raw entries, and both were
    avoided, so ``|M_B| = |M_C| = 0`` with probability ``1`` -- measured 20/20
    at ``L = 600``. (Avoiding only *Bob's* log is defused by Phase A', which
    leaves ``E|M_B| = L/6``; it is the *pair* of logs that is fatal.) It forges
    nothing and repudiates nothing, since no verdict is reached, but it used to
    surface as an uncaught :exc:`ValueError` in the middle of
    :meth:`QDSSession.run` -- a verifier an attacker could crash, and a run an
    experiment harness silently lost. It is now a recorded no-verdict outcome:
    see :class:`~sih141.protocol.verify.VerificationAbort` and
    :attr:`SessionTranscript.aborts`.

    *It can starve the matched set without emptying it.* The same signer can pin
    ``|M_B| + |M_C|`` at a handful of positions for any ``L``, where honest
    operation gives ``2L/|B|``. The repudiation bound in
    :mod:`sih141.protocol.analysis`, in its default form, averages over
    ``M ~ Binomial(2L, 1/|B|)``, and that average assumes **the declared bases
    are independent of the recipients' logged bases** -- exactly the assumption
    this seam breaks. The bound *conditional* on an observed matched count is
    not violated; what would be wrong is quoting the ``M``-averaged number as if
    it held unconditionally against every signer. Phase 3 and Phase 5 should
    read the per-run conditional bound from the observed ``m_B + m_C``, which
    every transcript carries
    (:attr:`~sih141.protocol.verify.VerificationResult.matched_count`).
    :func:`~sih141.protocol.verify.minimum_matched_count` now refuses to score
    such a run at all, so any verdict this session emits rests on at least that
    many matched positions per verifier -- which bounds how far the conditional
    number can drift from the averaged one, but does not by itself make the
    averaged one unconditional.

    One further seam-reachable behaviour is plumbing rather than an attack: a
    signer returning a signature for the other bit is refused by
    :meth:`QDSSession.sign`.

``forwarder`` -- the Bob-to-Charlie classical hop
    Callable taking ``(signature, params)`` and returning the declaration
    Charlie actually scores, defaulting to :func:`honest_forwarder`, which
    returns its argument unchanged. This is the seam for an attack *between* the
    two verifications -- Bob altering what he passes on, or an adversary on the
    forwarding link -- and it is the reason
    :class:`SessionTranscript` carries both declarations rather than one: a run
    in which Bob and Charlie scored different declarations is now representable,
    where before Charlie's verdict was silently attributed to Bob's declaration
    and a Phase 4 statistic would have read an attacked run as a clean one.

Everything downstream of the seams is fixed: the matched/unmatched split, the
matched-count floor, the two thresholds and the accept rule are computed by
:func:`~sih141.protocol.verify.verify` from the record, the declaration and the
parameter set alone, so no adversary can reach them. Phase A' is likewise not an
Alice-side seam; see above.

A verifier whose matched set falls below that floor reaches **no verdict** --
neither an acceptance nor a rejection. :meth:`QDSSession.run` records it and
carries on, so a starved declaration costs a verdict rather than the whole run,
and :class:`SessionTranscript` keeps verdicts and refusals in separate fields
(:attr:`~SessionTranscript.results` and :attr:`~SessionTranscript.aborts`) so
that no Phase 4 or Phase 5 statistic can conflate the two.

What the session is not
-----------------------
Not a channel, not a detector and not a ledger. It holds no quantum state at
any point -- by the time :meth:`QDSSession.distribute` returns, every teleported
qubit has been measured and discarded and the session's memory is four tables of
integers (:mod:`sih141.protocol.records`). Detection statistics are Phase 4's
job and read a :class:`SessionTranscript`; replay defence is a ledger over
transcripts, not a field on one.

The ledger does, however, need something to key on, and content is not it: two
runs made with the same seed produce byte-identical transcripts, by design and
by test, so a content hash cannot tell a replay from a legitimate repeat. So a
session takes an optional ``run_id``, carried verbatim into the transcript and
used by nothing here. It is deliberately caller-supplied rather than generated:
a generated identifier would either be random -- breaking the reproducibility
that Phase 5 rests on -- or derived from the seed, in which case it would repeat
exactly when a replay does and defeat its own purpose. The harness that owns the
ledger owns the namespace.

Notes
-----
Single use (replay)
    A session distributes once and signs once. A second
    :meth:`~QDSSession.distribute` or a second :meth:`~QDSSession.sign` is
    refused, because the security of the scheme rests on the public key states
    being consumed: signing both bits against one distribution would hand a
    verifier two declarations scored against logs that are not independent of
    each other. Build a new session per run.
Determinism (D3)
    One keyword-only ``rng``, resolved once in the constructor through
    :func:`sih141.core.rng.resolve_rng` and threaded through key generation and
    both distributions in that order. The same seed therefore reproduces the
    entire transcript, byte for byte through :meth:`SessionTranscript.to_json`,
    and ``tests/test_protocol_session.py`` pins that.
Canonical state type (D1), qubit ordering (D2)
    Inherited from :mod:`sih141.protocol.distribute`; nothing here touches a
    state.
No machine learning (D4)
    Nothing is learned, fitted or thresholded from data. The two cuts come from
    :class:`~sih141.protocol.params.ProtocolParams` and were fixed before the
    run started.

See Also
--------
sih141.protocol.distribute.distribute_public_key : Phase A, both recipients.
sih141.protocol.signature.sign : Phase B.
sih141.protocol.verify.verify : Phase C, one verifier.

Examples
--------
>>> import numpy as np
>>> from sih141.protocol.params import ProtocolParams
>>> from sih141.protocol.session import QDSSession
>>> params = ProtocolParams(key_length=24)
>>> transcript = QDSSession(params, rng=np.random.default_rng(0)).run(1)
>>> transcript.transferable
True
>>> transcript.bob.rate, transcript.charlie.rate
(0.0, 0.0)
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

import numpy as np

from sih141.core.rng import resolve_rng
from sih141.protocol.analysis import repudiation_bound
from sih141.protocol.distribute import ResourceFactory, distribute_public_key
from sih141.protocol.keys import PrivateKey, generate_key_pair
from sih141.protocol.params import (
    DEMO_PARAMS,
    VERIFIERS,
    Party,
    ProtocolParams,
    _as_message_bit,
    _as_party,
)
from sih141.protocol.records import RecipientRecord
from sih141.protocol.signature import Signature, sign
from sih141.protocol.symmetrise import Symmetriser, symmetrise_records
from sih141.protocol.verify import (
    MatchedSetTooSmall,
    VerificationAbort,
    VerificationResult,
    minimum_matched_count,
    verify,
)

__all__ = [
    "MESSAGE_BITS",
    "Distributor",
    "Signer",
    "Forwarder",
    "honest_signer",
    "honest_forwarder",
    "SessionTranscript",
    "QDSSession",
]


MESSAGE_BITS: Final[tuple[int, int]] = (0, 1)
"""The message bits a session distributes for, in order.

Both of them, always: Alice commits to ``k_0`` and ``k_1`` before she learns
which bit she will sign (see the module docstring).
"""


# --------------------------------------------------------------------------- #
# The two callable seams (see :ref:`phase3-seams`)
# --------------------------------------------------------------------------- #


class Distributor(Protocol):
    """Callable that runs Phase A for one message bit.

    :func:`~sih141.protocol.distribute.distribute_public_key` is the honest
    implementation and the default. A Phase 3 replacement stands between Alice
    and the recipients and may return any records it likes; the session checks
    the shape of the result (see :meth:`QDSSession.distribute`) but not its
    contents, because "the contents are wrong" is exactly what verification is
    for.
    """

    def __call__(
        self,
        key: PrivateKey,
        params: ProtocolParams,
        *,
        parties: Sequence[Party | str] = VERIFIERS,
        resource_factory: ResourceFactory | None = None,
        rng: np.random.Generator | None = None,
    ) -> dict[Party, RecipientRecord]:
        """Distribute ``key`` and return one record per party."""
        ...


class Signer(Protocol):
    """Callable that runs Phase B and produces the declaration to be verified.

    :func:`honest_signer` is the default. The parameters are everything any of
    the three parties could hold at signing time; an adversarial signer simply
    uses a different subset of them, which is how "who is cheating" is expressed
    without a flag.
    """

    def __call__(
        self,
        message_bit: int,
        keys: tuple[PrivateKey, PrivateKey],
        params: ProtocolParams,
        *,
        records: Mapping[int, Mapping[Party, RecipientRecord]],
    ) -> Signature:
        """Return the signature declared for ``message_bit``."""
        ...


def honest_signer(
    message_bit: int,
    keys: tuple[PrivateKey, PrivateKey],
    params: ProtocolParams,
    *,
    records: Mapping[int, Mapping[Party, RecipientRecord]],
) -> Signature:
    """Declare exactly the key whose states were distributed. The default signer.

    A thin :class:`Signer`-shaped adapter over
    :func:`sih141.protocol.signature.sign`. It exists as a named function rather
    than a lambda so that Phase 3 can wrap it, and so that a test can assert the
    default really is the honest one.

    Parameters
    ----------
    message_bit : int
        ``0`` or ``1``, the bit being signed.
    keys : tuple of PrivateKey
        ``(k_0, k_1)``, Alice's committed pair. ``keys[message_bit]`` is
        declared verbatim.
    params : ProtocolParams
        Checked against the selected key, so a key from another parameter set is
        refused at signing time rather than as an unexplained rejection at both
        verifiers.
    records : mapping
        Keyword-only. The recipients' **raw**, pre-exchange logs, keyed by
        message bit and then by party. **Ignored**, deliberately: those logs are
        Bob's and Charlie's private evidence, not Alice's, and an honest Alice
        signs without them. The parameter is present because the
        :class:`Signer` seam must offer them to the adversaries that
        legitimately hold them -- see :ref:`phase3-seams` on why the raw logs
        rather than the post-symmetrisation ones.

    Returns
    -------
    Signature
        ``sign(message_bit, keys, params)``.

    Raises
    ------
    ValueError
        If ``message_bit`` is not ``0``/``1``, or ``keys`` is not the ordered
        pair ``(k_0, k_1)``.
    TypeError
        As :func:`sih141.protocol.signature.sign`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_key_pair
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import honest_signer
    >>> params = ProtocolParams(key_length=9)
    >>> keys = generate_key_pair(params, rng=np.random.default_rng(5))
    >>> honest_signer(1, keys, params, records={}).declared_key is keys[1]
    True
    """
    del records  # An honest Alice holds no recipient's measurement log.
    return sign(message_bit, keys, params)


class Forwarder(Protocol):
    """Callable that carries the declaration from Bob to Charlie.

    :func:`honest_forwarder` is the default and is the identity. A Phase 3
    replacement models Bob altering what he passes on, or an adversary sitting
    on the forwarding link; whatever it returns is what Charlie scores, and the
    transcript records both declarations separately.
    """

    def __call__(
        self, signature: Signature, params: ProtocolParams
    ) -> Signature:
        """Return the declaration Charlie will be given."""
        ...


def honest_forwarder(
    signature: Signature, params: ProtocolParams
) -> Signature:
    """Forward the declaration unchanged. The default forwarder.

    Bob forwards the declaration, never his own evidence -- which is why an
    honest Bob cannot help a signature along, and why a dishonest one cannot
    either without altering the declaration, which is exactly what this seam
    makes visible.

    Parameters
    ----------
    signature : Signature
        What Bob received and scored.
    params : ProtocolParams
        The parameter set. **Ignored** by the honest forwarder; present because
        a replacement that rebuilds a declaration needs the alphabet and the
        key length to build a valid one.

    Returns
    -------
    Signature
        ``signature`` itself, unchanged and identical by object identity, so a
        test can assert the honest path really did nothing.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.keys import generate_key_pair
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import honest_forwarder
    >>> from sih141.protocol.signature import sign
    >>> params = ProtocolParams(key_length=9)
    >>> keys = generate_key_pair(params, rng=np.random.default_rng(5))
    >>> declaration = sign(0, keys, params)
    >>> honest_forwarder(declaration, params) is declaration
    True
    """
    del params  # An honest hop needs nothing but the declaration itself.
    return signature


# --------------------------------------------------------------------------- #
# The transcript
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SessionTranscript:
    """Everything one run produced, frozen and JSON-serialisable end to end.

    The hand-off object for the rest of the project: Phase 4 computes detection
    statistics from it, Phase 5 aggregates many of them, and Phase 6 renders
    one. It therefore contains no quantum state, no generator and no callable --
    only the parameter set, the declaration, the classical logs and the
    verdicts. :meth:`to_dict` output passes to :func:`json.dumps` unchanged, and
    :meth:`from_dict` round-trips it back to an equal object.

    Being a frozen dataclass over frozen fields, two transcripts compare equal
    exactly when the two runs were identical, which is what makes "the same seed
    reproduces the run" a one-line assertion.

    Attributes
    ----------
    params : ProtocolParams
        The parameter set the run executed under, thresholds included.
    message_bit : int
        The bit that was signed.
    signature : Signature
        The declaration **Bob** scored. On an attacked run this is whatever the
        :class:`Signer` seam produced, which need not be a key Alice ever
        distributed -- that is the point of a forgery.
    records : tuple of RecipientRecord
        All ``len(MESSAGE_BITS) * 2`` logs from Phase A, in distribution order:
        bit 0 for Bob then Charlie, then bit 1 for Bob then Charlie. Each one
        carries its own party, message bit and
        :attr:`~sih141.protocol.records.RecipientRecord.symmetrised` flag, so
        the flat tuple is unambiguous and survives JSON without integer
        dictionary keys.
    results : tuple of VerificationResult
        The verdicts reached, in the order they were reached -- Bob's first,
        then Charlie's after the transfer. May be shorter than two if a run was
        abandoned part-way, or if a verifier reached no verdict at all (see
        ``aborts``).
    aborts : tuple of VerificationAbort, optional
        The verifiers who reached **no verdict**, because the declaration left
        them a matched set below
        :func:`~sih141.protocol.verify.minimum_matched_count`. Empty on every
        healthy run. A separate field from ``results``, and a separate type,
        because a refusal to score is neither an acceptance nor a rejection: a
        plumbing failure counted as a rejection would show up in a Phase 5 table
        as a forgery detection that never happened. A party appears in exactly
        one of the two, never both.
    forwarded_signature : Signature or None, optional
        The declaration **Charlie** scored, when it differs from
        :attr:`signature`. ``None`` on every honest run, where Bob forwards what
        he received unchanged. Carried because a run in which the two verifiers
        scored different declarations is otherwise unrepresentable, and a
        transcript that recorded only Bob's would attribute Charlie's verdict to
        a declaration he never saw -- which a Phase 4 statistic would read as a
        clean run.
    run_id : str or None, optional
        An identifier for the replay ledger, supplied by whoever owns the
        ledger's namespace. Carried and otherwise unused. ``None`` by default:
        the transcript deliberately generates nothing, because a random
        identifier would break seed reproducibility and a seed-derived one would
        repeat exactly when a replay does.

    See Also
    --------
    QDSSession.transcript : Produces one.

    Examples
    --------
    >>> import json
    >>> import numpy as np
    >>> from sih141.protocol.params import ProtocolParams
    >>> from sih141.protocol.session import QDSSession, SessionTranscript
    >>> transcript = QDSSession(
    ...     ProtocolParams(key_length=24), rng=np.random.default_rng(11)
    ... ).run(0)
    >>> restored = SessionTranscript.from_json(transcript.to_json())
    >>> restored == transcript
    True
    >>> transcript.symmetrised, transcript.forwarded_signature is None
    (True, True)
    """

    params: ProtocolParams
    message_bit: int
    signature: Signature
    records: tuple[RecipientRecord, ...]
    results: tuple[VerificationResult, ...]
    forwarded_signature: Signature | None = None
    run_id: str | None = None
    aborts: tuple[VerificationAbort, ...] = ()

    def __post_init__(self) -> None:
        """Coerce the sequence fields to tuples and check the run hangs together.

        Raises
        ------
        TypeError
            If any field is of the wrong type.
        ValueError
            If ``message_bit`` is not ``0``/``1``, if either signature declares a
            different bit, if one party holds two outcomes (two verdicts, two
            refusals, or one of each), or if a result's ``threshold`` or an
            outcome's ``key_length`` disagrees with ``params``.
        """
        if not isinstance(self.params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got "
                f"{type(self.params).__name__}"
            )
        object.__setattr__(
            self, "message_bit", _as_message_bit(self.message_bit)
        )
        if not isinstance(self.signature, Signature):
            raise TypeError(
                f"signature must be a Signature, got "
                f"{type(self.signature).__name__}"
            )
        if self.signature.message_bit != self.message_bit:
            raise ValueError(
                f"transcript is tagged with message bit {self.message_bit} but "
                f"holds a signature for bit {self.signature.message_bit}. The "
                f"bit selects which distribution the verifiers scored against, "
                f"so a mismatch means the verdicts in this transcript were "
                f"reached on the wrong records."
            )
        object.__setattr__(self, "records", tuple(self.records))
        for position, record in enumerate(self.records):
            if not isinstance(record, RecipientRecord):
                raise TypeError(
                    f"records[{position}] must be a RecipientRecord, got "
                    f"{type(record).__name__}"
                )
        if self.forwarded_signature is not None:
            if not isinstance(self.forwarded_signature, Signature):
                raise TypeError(
                    f"forwarded_signature must be a Signature or None, got "
                    f"{type(self.forwarded_signature).__name__}"
                )
            if self.forwarded_signature.message_bit != self.message_bit:
                raise ValueError(
                    f"the forwarded declaration is for message bit "
                    f"{self.forwarded_signature.message_bit} but the transcript "
                    f"is tagged with bit {self.message_bit}. Bob forwards the "
                    f"declaration he was asked to verify; a different bit means "
                    f"Charlie was scored against another run entirely."
                )
        if self.run_id is not None and not isinstance(self.run_id, str):
            raise TypeError(
                f"run_id must be a string or None, got "
                f"{type(self.run_id).__name__}. It is a ledger key, carried "
                f"verbatim and interpreted by nothing in this module."
            )

        object.__setattr__(self, "results", tuple(self.results))
        seen: set[Party] = set()
        for position, result in enumerate(self.results):
            if not isinstance(result, VerificationResult):
                raise TypeError(
                    f"results[{position}] must be a VerificationResult, got "
                    f"{type(result).__name__}"
                )
            if result.party in seen:
                raise ValueError(
                    f"results holds two verdicts for "
                    f"{result.party.value!r}. One verifier reaches one decision "
                    f"per signature; a duplicate would make "
                    f"'did Charlie accept?' depend on which entry is read."
                )
            seen.add(result.party)
            _check_result_against(result, self.params, self.message_bit)

        object.__setattr__(self, "aborts", tuple(self.aborts))
        for position, abort in enumerate(self.aborts):
            if not isinstance(abort, VerificationAbort):
                raise TypeError(
                    f"aborts[{position}] must be a VerificationAbort, got "
                    f"{type(abort).__name__}"
                )
            if abort.party in seen:
                raise ValueError(
                    f"{abort.party.value} appears in both results and aborts, "
                    f"or twice in aborts. Phase C leaves each verifier with "
                    f"exactly one outcome -- a verdict or a refusal to score, "
                    f"never both -- and a party in both fields would let "
                    f"'did Charlie accept?' depend on which field is read."
                )
            seen.add(abort.party)
            _check_abort_against(abort, self.params, self.message_bit)

    # -- derived views ------------------------------------------------------ #

    @property
    def results_by_party(self) -> dict[Party, VerificationResult]:
        """dict: The verdicts keyed by party, in the order they were reached."""
        return {result.party: result for result in self.results}

    @property
    def bob(self) -> VerificationResult | None:
        """VerificationResult or None: Bob's verdict, if he reached one."""
        return self.results_by_party.get(Party.BOB)

    @property
    def charlie(self) -> VerificationResult | None:
        """VerificationResult or None: Charlie's verdict, if he reached one."""
        return self.results_by_party.get(Party.CHARLIE)

    @property
    def aborts_by_party(self) -> dict[Party, VerificationAbort]:
        """dict: The refusals to score, keyed by party, in the order recorded."""
        return {abort.party: abort for abort in self.aborts}

    @property
    def aborted(self) -> bool:
        """bool: ``True`` iff some verifier reached no verdict at all.

        Distinct from ``not is_complete``, which is also ``True`` for a run
        simply abandoned before :meth:`QDSSession.transfer`. This one says a
        verifier *was* asked and refused to score, because the declaration left
        him a matched set below
        :func:`~sih141.protocol.verify.minimum_matched_count`. On an honest run
        it is ``False`` with probability at least
        ``1 - 2 * HONEST_ABORT_BUDGET``; when it is ``True``, the declaration or
        the distribution is what to investigate, not the verifiers.
        """
        return bool(self.aborts)

    @property
    def is_complete(self) -> bool:
        """bool: ``True`` when both verifiers have reached a verdict.

        ``False`` on an aborted run: a refusal to score is not a decision. Read
        :attr:`aborted` to tell "no verdict" from "not asked yet".
        """
        return self.bob is not None and self.charlie is not None

    @property
    def symmetrised(self) -> bool:
        """bool: ``True`` iff every log went through Phase A'.

        ``False`` marks a run of the *insecure* variant -- one made with
        :func:`sih141.protocol.symmetrise.no_symmetrisation`, which Phase 3 uses
        to demonstrate the repudiation attack. No non-repudiation claim attaches
        to such a run at any key length, and :meth:`summary` says so out loud.
        """
        return bool(self.records) and all(
            record.symmetrised for record in self.records
        )

    def signature_for(self, party: Party | str) -> Signature:
        """Return the declaration a given verifier actually scored.

        Parameters
        ----------
        party : Party or str
            :attr:`~sih141.protocol.params.Party.BOB` or
            :attr:`~sih141.protocol.params.Party.CHARLIE`.

        Returns
        -------
        Signature
            :attr:`signature` for Bob; :attr:`forwarded_signature` for Charlie
            when the forwarding hop altered it, and :attr:`signature` otherwise.

        Raises
        ------
        ValueError
            If ``party`` is :attr:`~sih141.protocol.params.Party.ALICE`, who
            scores nothing.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.
        """
        resolved = _as_party(party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice scores no declaration: she is the signer. Ask for "
                "Party.BOB (who received it) or Party.CHARLIE (who was "
                "forwarded it)."
            )
        if resolved is Party.CHARLIE and self.forwarded_signature is not None:
            return self.forwarded_signature
        return self.signature

    @property
    def forwarding_altered_signature(self) -> bool:
        """bool: ``True`` iff Charlie scored a different declaration from Bob."""
        return (
            self.forwarded_signature is not None
            and self.forwarded_signature != self.signature
        )

    @property
    def transferable(self) -> bool:
        """bool: ``True`` iff Bob accepted **and** Charlie accepted.

        The property the ``s_a < s_v`` gap exists to deliver: a signature Bob
        accepts is one he can forward. ``False`` while either verdict is still
        missing -- an unfinished run has not demonstrated transferability.
        """
        return (
            self.bob is not None
            and self.charlie is not None
            and self.bob.accepted
            and self.charlie.accepted
        )

    @property
    def repudiated(self) -> bool:
        """bool: ``True`` iff Bob accepted and Charlie rejected.

        The repudiation event, in which Bob holds a signature he cannot make
        stick. The scheme's non-repudiation claim is that this has probability
        exponentially small in ``L`` for any signer strategy **provided the
        recipients symmetrised** (:attr:`symmetrised`); without that step the
        claim is false at every ``L``, which is what
        :func:`sih141.protocol.symmetrise.no_symmetrisation` exists to show. On
        honest runs it should never be seen; Phase 3 tries to force it and Phase
        5 counts how often it succeeds.
        """
        return (
            self.bob is not None
            and self.charlie is not None
            and self.bob.accepted
            and not self.charlie.accepted
        )

    @property
    def pooled_matched_count(self) -> int | None:
        """int or None: ``M = m_B + m_C`` as this run actually produced it.

        The evidence base the non-repudiation guarantee is stated over. ``None``
        unless the run is a repudiation experiment at all, which needs three
        things:

        * both verifiers reached a **verdict** -- a refusal to score
          (:attr:`aborts`) has no matched count to contribute, and counting it
          as zero would flatter the bound rather than weaken it;
        * both scored the **same declaration**, since ``m_B + m_C = M`` and
          ``e_B + e_C = E`` are conserved only across one fixed pair of records
          against one fixed declaration -- a run the forwarding hop altered
          (:attr:`forwarding_altered_signature`) is not one experiment but two;
        * the recipients **symmetrised** (:attr:`symmetrised`), because the
          coins are the only randomness the bound uses and without them there
          are none.
        """
        if self.forwarding_altered_signature or not self.symmetrised:
            return None
        bob, charlie = self.bob, self.charlie
        if bob is None or charlie is None:
            return None
        return bob.matched_count + charlie.matched_count

    @property
    def repudiation_guarantee(self) -> float | None:
        """float or None: the per-run repudiation bound, from the observed ``M``.

        **The number this run is entitled to quote**, and the reason the
        property exists: it is
        :func:`sih141.protocol.analysis.repudiation_bound` evaluated at
        :attr:`pooled_matched_count`, which conditions on the two records *and*
        on the declaration and therefore holds for every Alice strategy with no
        independence assumption of any kind.

        Do **not** quote
        :func:`~sih141.protocol.analysis.averaged_repudiation_bound` for a run.
        Its ``6.9e-10`` at :data:`~sih141.protocol.params.DEFAULT_PARAMS`
        averages over ``M ~ Binomial(2L, 1/|B|)``, which is the law of the
        matched count only while the declaration is independent of the
        recipients' logged bases -- an assumption the ``Signer`` seam breaks by
        construction (see :ref:`two-log-signer`). This property reads ``M`` off
        the run instead, so a starved run reports a number near ``1`` and says
        so, rather than inheriting a guarantee it did not earn.

        ``None`` exactly when :attr:`pooled_matched_count` is, plus the
        degenerate ``M = 0`` case, which cannot arise alongside two verdicts
        under the shipped floor.

        See Also
        --------
        sih141.protocol.verify.enforced_repudiation_bound : The a-priori
            counterpart, evaluated at the floor
            :func:`~sih141.protocol.verify.minimum_matched_count` enforces
            rather than at an observed count.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> transcript = QDSSession(
        ...     ProtocolParams(key_length=600), rng=np.random.default_rng(3)
        ... ).run(0)
        >>> transcript.pooled_matched_count > 2 * 600 // 3 - 60
        True
        >>> 0.0 < transcript.repudiation_guarantee < 1.0
        True
        """
        pooled = self.pooled_matched_count
        if pooled is None or pooled < 1:
            return None
        return repudiation_bound(self.params, matched_records=pooled)

    def records_for(self, message_bit: int) -> dict[Party, RecipientRecord]:
        """Return the logs distributed for one message bit, keyed by party.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        dict of Party to RecipientRecord
            The recipients' logs for that bit.

        Raises
        ------
        ValueError
            If ``message_bit`` is not ``0``/``1``.
        """
        bit = _as_message_bit(message_bit)
        return {
            record.party: record
            for record in self.records
            if record.message_bit == bit
        }

    def verdict_for(self, party: Party | str) -> VerificationResult:
        """Return one verifier's decision.

        Parameters
        ----------
        party : Party or str
            :attr:`~sih141.protocol.params.Party.BOB` or
            :attr:`~sih141.protocol.params.Party.CHARLIE`.

        Returns
        -------
        VerificationResult

        Raises
        ------
        ValueError
            If ``party`` names no verifier, or reached no verdict in this run --
            distinguishing "rejected" from "never asked" and from "asked and
            refused to score", none of which a ``None`` or a ``False`` would
            keep apart. When the party appears in :attr:`aborts` the message
            quotes the refusal.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.
        """
        resolved = _as_party(party)
        result = self.results_by_party.get(resolved)
        if result is None:
            reached = sorted(item.value for item in self.results_by_party)
            abort = self.aborts_by_party.get(resolved)
            because = (
                f" He was asked and refused to score: {abort.summary()}"
                if abort is not None
                else ""
            )
            advice = (
                " Read transcript.aborts for the refusal."
                if abort is not None
                else (
                    " Run the session to completion with "
                    "QDSSession.run(message_bit), or call verify(Party.BOB) "
                    "and then transfer()."
                )
            )
            raise ValueError(
                f"{resolved.value} reached no verdict in this run; verdicts "
                f"present: {reached or 'none'}. This is not a rejection: no "
                f"decision was made.{because}{advice}"
            )
        return result

    def summary(self) -> str:
        """Return a short human-readable account of the whole run.

        Returns
        -------
        str
            One line of context followed by one line per verdict, each from
            :meth:`~sih141.protocol.verify.VerificationResult.summary`, then one
            line per refusal to score from
            :meth:`~sih141.protocol.verify.VerificationAbort.summary`, then --
            on any run that is a repudiation experiment -- the evidence line
            carrying :attr:`pooled_matched_count` and
            :attr:`repudiation_guarantee`, and a closing line naming the outcome
            in protocol terms. The evidence line is printed rather than left to
            be looked up because the number a reader reaches for otherwise is
            the ``M``-averaged one, which is not valid against a signer who
            reads the recipients' logs. On a run where a
            verifier reached no verdict the closing line says so instead of
            naming a composite event, because none of ``TRANSFERABLE``,
            ``REPUDIATION`` and ``REJECTED`` is true of a run with no decision
            in it.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> text = QDSSession(
        ...     ProtocolParams(key_length=24), rng=np.random.default_rng(4)
        ... ).run(0).summary()
        >>> text.splitlines()[-1]
        'TRANSFERABLE: Bob accepted and Charlie accepted.'
        """
        lines = [
            f"QDS run on message bit {self.message_bit}: L="
            f"{self.params.key_length}, |B|={len(self.params.bases)}, "
            f"s_a={self.params.s_a:.5f}, s_v={self.params.s_v:.5f}"
        ]
        if not self.symmetrised:
            lines.append(
                "UNSYMMETRISED: the recipients did not exchange their copies, "
                "so this run has no non-repudiation guarantee at any L."
            )
        if self.forwarding_altered_signature:
            lines.append(
                "FORWARDING ALTERED THE DECLARATION: Charlie scored a "
                "different key from the one Bob was given."
            )
        lines.extend(result.summary() for result in self.results)
        lines.extend(abort.summary() for abort in self.aborts)
        guarantee = self.repudiation_guarantee
        if guarantee is not None:
            lines.append(
                f"EVIDENCE: M = m_B + m_C = {self.pooled_matched_count} matched "
                f"records, so P(repudiation | this run) <= {guarantee:.3e}. "
                f"This is the per-run bound and the only one that assumes "
                f"nothing about the signer."
            )
        if self.aborted:
            refused = ", ".join(abort.party.value for abort in self.aborts)
            lines.append(
                f"NO VERDICT: {refused} could not score this declaration -- the "
                f"matched set was below the floor. This is not a rejection and "
                f"must not be counted as one."
            )
        elif not self.is_complete:
            lines.append("INCOMPLETE: not every verifier reached a verdict.")
        elif self.transferable:
            lines.append("TRANSFERABLE: Bob accepted and Charlie accepted.")
        elif self.repudiated:
            lines.append(
                "REPUDIATION: Bob accepted a signature Charlie rejected."
            )
        else:
            lines.append("REJECTED: Bob did not accept the signature.")
        return "\n".join(lines)

    # -- serialisation ------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable view of the entire run.

        Nothing derived is stored: :attr:`transferable` and friends are
        recomputed from the verdicts on the way back in, so a transcript on disk
        cannot disagree with itself.

        Returns
        -------
        dict
            Keys ``"params"``, ``"message_bit"``, ``"signature"``, ``"records"``,
            ``"results"``, ``"aborts"``, ``"forwarded_signature"`` and
            ``"run_id"``. Every leaf is an :class:`int`, :class:`float`,
            :class:`bool`, :class:`str` or a :class:`enum.StrEnum` member (which
            *is* a string), so the result passes to :func:`json.dumps`
            unchanged.

        Examples
        --------
        >>> import json
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> blob = QDSSession(
        ...     ProtocolParams(key_length=24), rng=np.random.default_rng(6)
        ... ).run(1).to_dict()
        >>> json.loads(json.dumps(blob))["message_bit"]
        1
        """
        return {
            "params": self.params.to_dict(),
            "message_bit": self.message_bit,
            "signature": self.signature.to_dict(),
            "records": [record.to_dict() for record in self.records],
            "results": [result.to_dict() for result in self.results],
            "aborts": [abort.to_dict() for abort in self.aborts],
            "forwarded_signature": (
                None
                if self.forwarded_signature is None
                else self.forwarded_signature.to_dict()
            ),
            "run_id": self.run_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SessionTranscript:
        """Rebuild a transcript from :meth:`to_dict` output.

        Parameters
        ----------
        data : mapping
            Must contain ``"params"``, ``"message_bit"``, ``"signature"``,
            ``"records"`` and ``"results"``. ``"forwarded_signature"`` and
            ``"run_id"`` are optional and default to ``None``; ``"aborts"`` is
            optional and defaults to empty, so a transcript written before the
            matched-count abort rule existed still restores.

        Returns
        -------
        SessionTranscript
            Equal to the original.

        Raises
        ------
        KeyError
            If a field is missing.
        ValueError
            If the restored run is not self-consistent -- which now includes
            each verdict's ``threshold`` and ``key_length`` agreeing with
            ``params``. This is the hand-off boundary for Phases 4 to 6, so a
            transcript whose Bob verdict carries Charlie's ``s_v`` -- internally
            consistent, and reporting ``transferable=True`` for a run Bob
            genuinely rejected -- is refused here rather than believed.
        """
        forwarded = data.get("forwarded_signature")
        return cls(
            params=ProtocolParams.from_dict(data["params"]),
            message_bit=data["message_bit"],
            signature=Signature.from_dict(data["signature"]),
            records=tuple(
                RecipientRecord.from_dict(item) for item in data["records"]
            ),
            results=tuple(
                VerificationResult.from_dict(item) for item in data["results"]
            ),
            forwarded_signature=(
                None if forwarded is None else Signature.from_dict(forwarded)
            ),
            run_id=data.get("run_id"),
            # Optional, and defaulting to none, so that a transcript written
            # before the abort rule existed still restores: it can only have
            # recorded verdicts.
            aborts=tuple(
                VerificationAbort.from_dict(item)
                for item in data.get("aborts", ())
            ),
        )

    def to_json(self, **kwargs: Any) -> str:
        """Serialise the run to a JSON string.

        Parameters
        ----------
        **kwargs
            Forwarded to :func:`json.dumps` -- ``indent=2`` for a file a human
            will read, nothing for the compact form a Phase 6 endpoint returns.

        Returns
        -------
        str
            JSON text that :meth:`from_json` restores exactly.
        """
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_json(cls, text: str) -> SessionTranscript:
        """Rebuild a transcript from :meth:`to_json` output.

        Parameters
        ----------
        text : str
            JSON text.

        Returns
        -------
        SessionTranscript
        """
        return cls.from_dict(json.loads(text))


# --------------------------------------------------------------------------- #
# The session
# --------------------------------------------------------------------------- #


class QDSSession:
    """One run of the protocol: distribute, sign, verify, transfer.

    Stateful by nature -- the four phases happen in order and each depends on
    the last -- so this is a class rather than a function, and it refuses calls
    made out of order with a message saying what to call instead. It is
    single-use: see the module docstring on replay.

    Parameters
    ----------
    params : ProtocolParams, optional
        The parameter set. Defaults to
        :data:`~sih141.protocol.params.DEMO_PARAMS` (``L = 192``), which is fast
        enough to watch run and carries **no security claim**; use
        :data:`~sih141.protocol.params.DEFAULT_PARAMS` for a number worth
        quoting.
    resource_factory : callable or None, optional
        Keyword-only. The quantum-channel seam, forwarded verbatim to the
        distributor and invoked once per key position per recipient. ``None``
        selects :func:`~sih141.protocol.distribute.ideal_resource`. See
        :ref:`phase3-seams`.
    distributor : Distributor or None, optional
        Keyword-only. The Phase A seam. ``None`` selects
        :func:`~sih141.protocol.distribute.distribute_public_key`.
    symmetriser : Symmetriser or None, optional
        Keyword-only. The Phase A' seam -- the *recipients'* step, not Alice's.
        ``None`` selects
        :func:`~sih141.protocol.symmetrise.symmetrise_records`. Phase 3 passes
        :func:`~sih141.protocol.symmetrise.no_symmetrisation` to run the
        insecure variant and measure the repudiation attack the step defends
        against.
    signer : Signer or None, optional
        Keyword-only. The Phase B seam. ``None`` selects
        :func:`honest_signer`.
    forwarder : Forwarder or None, optional
        Keyword-only. The Bob-to-Charlie hop. ``None`` selects
        :func:`honest_forwarder`, the identity.
    run_id : str or None, optional
        Keyword-only. Carried verbatim into the transcript for a replay ledger
        to key on; used by nothing here. See the module docstring on why it is
        not generated.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Resolved once, in this constructor, and threaded
        through key generation, both distributions and both symmetrisations in
        that order, so one seed reproduces the whole run.

    Raises
    ------
    TypeError
        If ``params`` is not a
        :class:`~sih141.protocol.params.ProtocolParams`, if any seam is neither
        ``None`` nor callable, if ``run_id`` is neither ``None`` nor a string,
        or if ``rng`` is neither ``None`` nor a
        :class:`numpy.random.Generator`.

    See Also
    --------
    SessionTranscript : What a finished run leaves behind.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> from sih141.protocol.session import QDSSession
    >>> session = QDSSession(
    ...     ProtocolParams(key_length=24), rng=np.random.default_rng(2)
    ... )
    >>> _ = session.distribute()
    >>> _ = session.sign(0)
    >>> session.verify(Party.BOB).accepted
    True
    >>> session.transfer().accepted
    True
    >>> session.transcript().transferable
    True
    """

    def __init__(
        self,
        params: ProtocolParams = DEMO_PARAMS,
        *,
        resource_factory: ResourceFactory | None = None,
        distributor: Distributor | None = None,
        symmetriser: Symmetriser | None = None,
        signer: Signer | None = None,
        forwarder: Forwarder | None = None,
        run_id: str | None = None,
        rng: np.random.Generator | None = None,
    ) -> None:
        if not isinstance(params, ProtocolParams):
            raise TypeError(
                f"params must be a ProtocolParams, got {type(params).__name__}. "
                f"Use DEMO_PARAMS for a quick run or DEFAULT_PARAMS for the "
                f"security-grade set."
            )
        _check_seam(
            resource_factory,
            "resource_factory",
            "a callable returning a two-qubit entanglement resource, taking "
            "either no arguments or one ResourceContext; leave it None for the "
            "ideal |Phi+> pair",
        )
        _check_seam(
            distributor,
            "distributor",
            "a callable with the signature of distribute_public_key",
        )
        _check_seam(
            symmetriser,
            "symmetriser",
            "a callable with the signature of symmetrise_records; pass "
            "no_symmetrisation to run the insecure variant deliberately",
        )
        _check_seam(
            signer, "signer", "a callable with the signature of honest_signer"
        )
        _check_seam(
            forwarder,
            "forwarder",
            "a callable with the signature of honest_forwarder",
        )
        if run_id is not None and not isinstance(run_id, str):
            raise TypeError(
                f"run_id must be a string or None, got "
                f"{type(run_id).__name__}. It is a ledger key carried into the "
                f"transcript verbatim; this module never reads it."
            )

        self._params = params
        self._resource_factory = resource_factory
        self._distributor: Distributor = (
            distribute_public_key if distributor is None else distributor
        )
        self._symmetriser: Symmetriser = (
            symmetrise_records if symmetriser is None else symmetriser
        )
        self._signer: Signer = honest_signer if signer is None else signer
        self._forwarder: Forwarder = (
            honest_forwarder if forwarder is None else forwarder
        )
        self._run_id = run_id
        self._rng = resolve_rng(rng)

        self._keys: tuple[PrivateKey, PrivateKey] | None = None
        self._raw_records: dict[int, dict[Party, RecipientRecord]] = {}
        self._records: dict[int, dict[Party, RecipientRecord]] = {}
        self._signature: Signature | None = None
        self._forwarded: Signature | None = None
        self._results: dict[Party, VerificationResult] = {}
        self._aborts: dict[Party, VerificationAbort] = {}

    def __repr__(self) -> str:
        """Return a debugging representation naming the phase reached.

        Refusals to score are named as well as verdicts, because "verified by
        B" and "verified by B, no verdict from Charlie" are very different runs
        and the first would otherwise stand for both.
        """
        if self._signature is None:
            stage = "distributed" if self._keys is not None else "new"
        else:
            reached = "".join(
                party.value[0]
                for party in VERIFIERS
                if party in self._results
            )
            refused = ", ".join(
                party.value for party in VERIFIERS if party in self._aborts
            )
            stage = (
                f"signed bit {self._signature.message_bit}"
                + (f", verified by {reached}" if reached else "")
                + (f", no verdict from {refused}" if refused else "")
            )
        return (
            f"QDSSession(L={self._params.key_length}, "
            f"s_a={self._params.s_a}, s_v={self._params.s_v}, {stage})"
        )

    # -- read-only state ---------------------------------------------------- #

    @property
    def params(self) -> ProtocolParams:
        """ProtocolParams: The parameter set this run executes under."""
        return self._params

    @property
    def is_distributed(self) -> bool:
        """bool: ``True`` once Phase A has run."""
        return self._keys is not None

    @property
    def is_signed(self) -> bool:
        """bool: ``True`` once Phase B has run."""
        return self._signature is not None

    @property
    def is_complete(self) -> bool:
        """bool: ``True`` once both verifiers have reached a verdict."""
        return self.is_signed and all(
            party in self._results for party in VERIFIERS
        )

    @property
    def keys(self) -> tuple[PrivateKey, PrivateKey]:
        """tuple of PrivateKey: Alice's committed pair ``(k_0, k_1)``.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run, when no keys exist.
        """
        if self._keys is None:
            raise self._not_yet(
                "no keys have been drawn", "session.distribute()"
            )
        return self._keys

    @property
    def records(self) -> dict[int, dict[Party, RecipientRecord]]:
        """dict: Recipients' logs, keyed by message bit then by party.

        A fresh nested :class:`dict` per access, so a caller cannot reach in and
        edit the session's evidence; the
        :class:`~sih141.protocol.records.RecipientRecord` values are frozen
        anyway.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run.
        """
        if not self._records:
            raise self._not_yet(
                "nothing has been distributed", "session.distribute()"
            )
        return {bit: dict(byparty) for bit, byparty in self._records.items()}

    @property
    def raw_records(self) -> dict[int, dict[Party, RecipientRecord]]:
        """dict: The recipients' logs *before* the symmetrisation exchange.

        What each recipient measured for himself, keyed by message bit then by
        party. The verifiers are scored on :attr:`records`, not on these; this
        view exists because it is what the :class:`Signer` seam is handed (a
        forging recipient holds his own measurements, and after the exchange
        half of them *are* the other verifier's evidence) and because Phase 3
        needs to compare the two.

        A fresh nested :class:`dict` per access, as :attr:`records`.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run.
        """
        if not self._raw_records:
            raise self._not_yet(
                "nothing has been distributed", "session.distribute()"
            )
        return {bit: dict(byparty) for bit, byparty in self._raw_records.items()}

    @property
    def signature(self) -> Signature:
        """Signature: The declaration under verification.

        Raises
        ------
        ValueError
            Before :meth:`sign` has run.
        """
        if self._signature is None:
            raise self._not_yet(
                "nothing has been signed", "session.sign(message_bit)"
            )
        return self._signature

    @property
    def results(self) -> dict[Party, VerificationResult]:
        """dict: Verdicts so far, keyed by party, in the order reached."""
        return dict(self._results)

    @property
    def aborts(self) -> dict[Party, VerificationAbort]:
        """dict: Verifiers who were asked and reached no verdict, keyed by party.

        A verifier lands here instead of in :attr:`results` when the declaration
        left him a matched set below
        :func:`~sih141.protocol.verify.minimum_matched_count`. Empty on every
        healthy run, and a party is never in both mappings.
        """
        return dict(self._aborts)

    # -- Phase A ------------------------------------------------------------ #

    def distribute(self) -> dict[int, dict[Party, RecipientRecord]]:
        """Run Phase A: draw both keys and teleport both public keys to both.

        Draws ``(k_0, k_1)`` with
        :func:`~sih141.protocol.keys.generate_key_pair`, then calls the
        :class:`Distributor` seam once per message bit, each call serving both
        :data:`~sih141.protocol.params.VERIFIERS`. Four classical logs come back
        and every teleported qubit has already been measured and discarded: when
        this returns, the session holds no quantum state.

        Returns
        -------
        dict of int to (dict of Party to RecipientRecord)
            The logs, keyed by message bit then by party.

        Raises
        ------
        ValueError
            If this session has already distributed (it is single-use -- see the
            module docstring on replay), or if the :class:`Distributor` seam
            returned something that is not one well-formed record per verifier
            for the bit requested.
        TypeError
            If the seam returned a non-mapping, or a non-record value.

        Notes
        -----
        Consumes ``4 * L`` variates for the key pair, ``3 * L`` per recipient
        per bit for the teleportation and measurement, and one ``L``-long array
        of symmetrisation coins per bit, all from the session's single generator
        (D3).

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> records = QDSSession(
        ...     ProtocolParams(key_length=12), rng=np.random.default_rng(8)
        ... ).distribute()
        >>> sorted(records), sorted(records[0])
        ([0, 1], [<Party.BOB: 'Bob'>, <Party.CHARLIE: 'Charlie'>])
        """
        if self._keys is not None:
            raise ValueError(
                "this session has already distributed its public keys. A "
                "session is single-use: the key states are consumed on receipt, "
                "and redistributing under the same session would either reuse a "
                "key whose states are gone or silently replace evidence the "
                "verifiers have already been scored against. Build a new "
                "QDSSession for the next message."
            )

        keys = generate_key_pair(self._params, rng=self._rng)
        raw_records: dict[int, dict[Party, RecipientRecord]] = {}
        records: dict[int, dict[Party, RecipientRecord]] = {}
        for bit in MESSAGE_BITS:
            returned = self._distributor(
                keys[bit],
                self._params,
                parties=VERIFIERS,
                resource_factory=self._resource_factory,
                rng=self._rng,
            )
            raw = self._check_distribution(returned, bit)
            # Phase A': the recipients' own step, applied to whatever the
            # distributor produced -- an adversary standing in Alice's place
            # cannot skip it, because he does not run it.
            exchanged = self._symmetriser(raw, rng=self._rng)
            raw_records[bit] = raw
            records[bit] = self._check_distribution(exchanged, bit)

        self._keys = keys
        self._raw_records = raw_records
        self._records = records
        return self.records

    def _check_distribution(
        self, returned: Any, message_bit: int
    ) -> dict[Party, RecipientRecord]:
        """Validate one distributor call's return value.

        The :class:`Distributor` seam is the widest hole in the module, so its
        output is checked for *shape* before the session will build on it: an
        attack that returns the wrong party, the wrong bit or the wrong length
        must fail here, loudly, rather than surface later as an unexplained
        rejection that would be scored as a successful detection.

        Parameters
        ----------
        returned : Any
            Whatever the seam produced.
        message_bit : int
            The bit it was asked to distribute for.

        Returns
        -------
        dict of Party to RecipientRecord
            ``returned``, keyed by :class:`~sih141.protocol.params.Party`.

        Raises
        ------
        TypeError
            If ``returned`` is not a mapping, or holds a non-record value.
        ValueError
            If a verifier is missing, if a record is tagged with another party
            or another message bit, or if a record does not belong to
            ``self.params``.
        """
        if not isinstance(returned, Mapping):
            raise TypeError(
                f"the distributor seam must return a mapping of Party to "
                f"RecipientRecord, got {type(returned).__name__} for message "
                f"bit {message_bit}; distribute_public_key returns exactly that."
            )
        checked: dict[Party, RecipientRecord] = {}
        for party, record in returned.items():
            resolved = _as_party(party)
            if not isinstance(record, RecipientRecord):
                raise TypeError(
                    f"the distributor seam returned "
                    f"{type(record).__name__} for {resolved.value} on message "
                    f"bit {message_bit}; a RecipientRecord is required."
                )
            if record.party is not resolved:
                raise ValueError(
                    f"the distributor seam keyed a record by "
                    f"{resolved.value!r} that is tagged {record.party.value!r}. "
                    f"The key selects the acceptance threshold, so a swap would "
                    f"score one verifier's evidence against the other's cut."
                )
            if record.message_bit != message_bit:
                raise ValueError(
                    f"the distributor seam returned a record for message bit "
                    f"{record.message_bit} while distributing for bit "
                    f"{message_bit}. Each bit gets its own key and its own "
                    f"distribution; crossing them would verify a declaration "
                    f"against states that were never sent for it."
                )
            record.check_against(self._params)
            checked[resolved] = record

        missing = [party.value for party in VERIFIERS if party not in checked]
        if missing:
            raise ValueError(
                f"the distributor seam produced no record for {missing} on "
                f"message bit {message_bit}. Both verifiers are required: "
                f"transferability and non-repudiation are statements about Bob "
                f"and Charlie together, and a session without Charlie cannot "
                f"express either."
            )
        return checked

    # -- Phase B ------------------------------------------------------------ #

    def sign(self, message_bit: int) -> Signature:
        """Run Phase B: declare a key for ``message_bit``.

        Calls the :class:`Signer` seam, which on an honest run
        (:func:`honest_signer`) declares ``keys[message_bit]`` verbatim. The
        declaration travels to Bob over an authenticated classical channel; this
        module models that channel as reliable, because authentication of the
        *classical* link is an assumption of the scheme rather than something it
        provides.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        Signature
            The declaration the verifiers will score.

        Raises
        ------
        ValueError
            If :meth:`distribute` has not run; if this session has already
            signed; if ``message_bit`` is not ``0``/``1``; or if the
            :class:`Signer` seam returned a signature for a different bit or of
            the wrong length.
        TypeError
            If the seam returned something that is not a
            :class:`~sih141.protocol.signature.Signature`.

        Notes
        -----
        Consumes no randomness (D3): an adversarial signer that wants some draws
        its own generator over, which keeps the session's stream -- and
        therefore the distribution -- identical between a clean run and an
        attacked one.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> session = QDSSession(
        ...     ProtocolParams(key_length=12), rng=np.random.default_rng(9)
        ... )
        >>> _ = session.distribute()
        >>> session.sign(1).declared_key is session.keys[1]
        True
        """
        if self._keys is None:
            raise self._not_yet(
                "there is nothing to sign against", "session.distribute()"
            )
        if self._signature is not None:
            raise ValueError(
                f"this session has already signed message bit "
                f"{self._signature.message_bit}. One distribution supports one "
                f"signature: signing the other bit as well would hand a "
                f"verifier two declarations scored against logs drawn from the "
                f"same run, and the independence every bound assumes would be "
                f"gone. Build a new QDSSession."
            )
        bit = _as_message_bit(message_bit)

        # The *raw* logs, not the post-exchange ones: see the seam section of
        # the module docstring. The exchange is private to the recipients and
        # its outcome is never offered to whoever is holding the pen.
        signature = self._signer(
            bit, self._keys, self._params, records=self.raw_records
        )
        if not isinstance(signature, Signature):
            raise TypeError(
                f"the signer seam must return a Signature, got "
                f"{type(signature).__name__}. Even a forgery is a Signature -- "
                f"it is a declaration, and what makes it a forgery is that the "
                f"key inside it is not the one whose states were distributed."
            )
        if signature.message_bit != bit:
            raise ValueError(
                f"the signer seam was asked for message bit {bit} and returned "
                f"a signature for bit {signature.message_bit}. The bit selects "
                f"which distribution the verifiers score against, so the two "
                f"must agree; a signer that wants to attack the other bit "
                f"should be asked to sign that bit."
            )
        signature.check_against(self._params)

        self._signature = signature
        return signature

    # -- Phase C ------------------------------------------------------------ #

    def verify(self, party: Party | str = Party.BOB) -> VerificationResult:
        """Run Phase C for one verifier against his own log.

        Delegates to :func:`sih141.protocol.verify.verify`, which builds the
        matched set, counts disagreements **within it only** and compares the
        rate against the threshold ``params`` assigns to ``party`` -- ``s_a``
        for Bob, ``s_v`` for Charlie. The session chooses neither the threshold
        nor the rule.

        Parameters
        ----------
        party : Party or str, optional
            The verifier. Defaults to
            :attr:`~sih141.protocol.params.Party.BOB`, who is the first
            recipient and the one Alice signs to.

        Returns
        -------
        VerificationResult
            The verdict, also stored on the session.

        Raises
        ------
        ValueError
            If :meth:`sign` has not run; if ``party`` is
            :attr:`~sih141.protocol.params.Party.ALICE`, who verifies nothing;
            or for any reason :func:`sih141.protocol.verify.verify` raises.
        MatchedSetTooSmall
            A :class:`ValueError` subclass, if the declaration left this
            verifier a matched set below
            :func:`~sih141.protocol.verify.minimum_matched_count`. The
            corresponding :class:`~sih141.protocol.verify.VerificationAbort` is
            recorded in :attr:`aborts` **before** the exception propagates, so a
            caller that catches it -- :meth:`run` does -- still gets the run in
            the transcript. It is not a rejection and must not be counted as
            one.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.

        Notes
        -----
        Pure and repeatable: verifying twice recomputes the same verdict from
        the same frozen inputs and consumes no randomness (D3). Each verifier
        holds exactly one current outcome, so a call that reaches a verdict
        clears any refusal recorded for that party, and vice versa.
        """
        if self._signature is None:
            raise self._not_yet(
                "there is no signature to verify", "session.sign(message_bit)"
            )
        resolved = _as_party(party)
        if resolved is Party.ALICE:
            raise ValueError(
                "Alice cannot verify: she is the signer, holds no measurement "
                "record and has no acceptance threshold. Verify at Party.BOB "
                "(cut at s_a) or Party.CHARLIE (cut at s_v)."
            )

        record = self._records[self._signature.message_bit][resolved]
        declaration = self._signature
        if resolved is Party.CHARLIE and self._forwarded is not None:
            # Charlie scores what the forwarding hop actually delivered, which
            # on an honest run is the same object Bob scored.
            declaration = self._forwarded
        try:
            # The module-level verify(), not this method.
            result = verify(declaration, record, self._params)
        except MatchedSetTooSmall as too_small:
            # Recorded *before* it propagates, so that run() -- and any harness
            # that catches it -- reports a no-verdict outcome instead of losing
            # the run. A starved matched set is a plumbing failure, never a
            # rejection, so it is stored in a different field and a different
            # type from the verdicts.
            self._results.pop(resolved, None)
            self._aborts[resolved] = too_small.abort
            raise
        # Phase C leaves each verifier exactly one current outcome. Re-verifying
        # Charlie against a forwarded declaration after an abort on the
        # unforwarded one must replace the refusal, not sit beside it.
        self._aborts.pop(resolved, None)
        self._results[resolved] = result
        return result

    def transfer(self) -> VerificationResult:
        """Forward the signature from Bob to Charlie and verify it there.

        The step the whole construction exists for. Charlie scores **his own**
        log -- Bob forwards the declaration, never his evidence, which is why
        Bob cannot help a signature along -- and cuts at ``s_v``. Because
        ``s_v > s_a``, a signature inside Bob's tight cut is overwhelmingly
        likely to sit inside Charlie's looser one, and that is transferability;
        because ``s_a > 0`` *and* the recipients symmetrised, Alice cannot aim a
        declaration into the gap between them, and that is non-repudiation.

        The declaration passes through the ``forwarder`` seam on the way, so an
        attack on the Bob-to-Charlie hop is expressible; on an honest run
        :func:`honest_forwarder` returns the same object and the transcript's
        :attr:`~SessionTranscript.forwarded_signature` stays ``None``.

        Returns
        -------
        VerificationResult
            Charlie's verdict, also stored on the session. Pair it with Bob's:
            :attr:`SessionTranscript.transferable` and
            :attr:`SessionTranscript.repudiated` are the two events worth
            naming, and neither is visible from one verdict.

        Raises
        ------
        TypeError
            If the ``forwarder`` seam returned something that is not a
            :class:`~sih141.protocol.signature.Signature`.
        ValueError
            If Bob has not run Phase C at all -- there is nothing to *transfer*
            before the holder has looked, and running the two verifications in
            the wrong order would misrepresent what Bob knew when he forwarded
            -- or if the forwarded declaration is for another message bit.
        MatchedSetTooSmall
            A :class:`ValueError` subclass, propagated from ``verify`` if the
            forwarded declaration leaves *Charlie* a matched set below the
            floor. His :class:`~sih141.protocol.verify.VerificationAbort` is
            recorded in :attr:`aborts` first; :meth:`run` catches it.

        Notes
        -----
        Neither a rejection nor an abort at Bob blocks the call. A real Bob
        forwards only what he accepted, so the honest composite event is
        ``bob.accepted and charlie.accepted``; but Phase 3 needs Charlie's
        outcome on runs Bob rejected too, to measure both error rates of the
        pair rather than one, and on runs Bob could not score at all, because a
        declaration that starves one verifier almost always starves the other
        and the transcript should say so rather than stop at the first
        refusal. So the refusal is left to the transcript's derived properties
        instead of being baked in here.
        """
        if Party.BOB not in self._results and Party.BOB not in self._aborts:
            raise self._not_yet(
                "Bob has not run Phase C, so there is nothing for him to "
                "forward",
                "session.verify(Party.BOB)",
            )
        assert self._signature is not None  # implied by Bob's verdict existing
        forwarded = self._forwarder(self._signature, self._params)
        if not isinstance(forwarded, Signature):
            raise TypeError(
                f"the forwarder seam must return a Signature, got "
                f"{type(forwarded).__name__}. Charlie scores a declaration; an "
                f"attack on the forwarding hop alters that declaration, it does "
                f"not remove it."
            )
        if forwarded.message_bit != self._signature.message_bit:
            raise ValueError(
                f"the forwarder seam returned a signature for message bit "
                f"{forwarded.message_bit} while forwarding one for bit "
                f"{self._signature.message_bit}. The bit selects which "
                f"distribution Charlie scores against, so changing it would "
                f"verify against states that were never sent for this run."
            )
        forwarded.check_against(self._params)
        self._forwarded = forwarded
        return self.verify(Party.CHARLIE)

    # -- the whole run ------------------------------------------------------ #

    def run(self, message_bit: int) -> SessionTranscript:
        """Execute the entire protocol for one message bit and report.

        Equivalent to :meth:`distribute`, :meth:`sign`, ``verify(Party.BOB)``,
        :meth:`transfer`, :meth:`transcript` -- in that order, which is the
        order the protocol fixes.

        A verifier who cannot score the declaration does **not** end the run.
        :exc:`~sih141.protocol.verify.MatchedSetTooSmall` is caught at each of
        the two Phase C steps and the refusal, already recorded by
        :meth:`verify`, is carried into
        :attr:`SessionTranscript.aborts`; the other verifier is still asked. So
        an attacker who starves the matched set -- a signer reading both raw
        logs can drive it to zero, see :ref:`two-log-signer` -- costs the
        harness a verdict, not a run, and cannot crash a verifier.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        SessionTranscript
            The run, frozen and JSON-serialisable.
            :attr:`~SessionTranscript.is_complete` says whether both verifiers
            reached a verdict, :attr:`~SessionTranscript.aborted` whether either
            refused to score.

        Raises
        ------
        ValueError
            As the individual phases; in particular if the session has already
            been used. **Not** for a matched set too small to score: that is an
            outcome and is recorded, never raised out of here.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> params = ProtocolParams(key_length=24)
        >>> first = QDSSession(params, rng=np.random.default_rng(3)).run(0)
        >>> second = QDSSession(params, rng=np.random.default_rng(3)).run(0)
        >>> first == second
        True
        >>> first.transferable, first.aborted
        (True, False)
        """
        self.distribute()
        self.sign(message_bit)
        # Both Phase C steps record their own refusal on the session before
        # raising, so catching MatchedSetTooSmall here loses nothing: it turns
        # "this verifier reached no verdict" from a lost run into a line in the
        # transcript. Only that one exception is caught -- a wiring error still
        # fails loudly, and the second verifier is still asked, because a
        # declaration that starves one usually starves both and the transcript
        # should say so rather than stop at the first refusal.
        try:
            self.verify(Party.BOB)
        except MatchedSetTooSmall:
            pass
        try:
            self.transfer()
        except MatchedSetTooSmall:
            pass
        return self.transcript()

    def transcript(self) -> SessionTranscript:
        """Freeze what has happened so far into a :class:`SessionTranscript`.

        Returns
        -------
        SessionTranscript
            The parameters, the declaration, all four classical logs, the
            verdicts reached so far and any refusals to score, in protocol
            order. Records are ordered by message bit and then by
            :data:`~sih141.protocol.params.VERIFIERS`; verdicts and refusals in
            the order they were reached.

        Raises
        ------
        ValueError
            If the session has not signed yet: before Phase B there is no
            declaration, and a transcript of a run with nothing to verify would
            be a record of nothing.

        Notes
        -----
        Callable on an unfinished run -- a transcript with one verdict, or
        none, is exactly what a Phase 3 experiment that abandons a run needs to
        report. :attr:`SessionTranscript.is_complete` says which it is.
        """
        if self._signature is None:
            raise self._not_yet(
                "nothing has been signed, so there is no run to report",
                "session.sign(message_bit)",
            )
        records = tuple(
            self._records[bit][party]
            for bit in MESSAGE_BITS
            for party in VERIFIERS
        )
        forwarded = self._forwarded
        return SessionTranscript(
            params=self._params,
            message_bit=self._signature.message_bit,
            signature=self._signature,
            records=records,
            results=tuple(self._results.values()),
            aborts=tuple(self._aborts.values()),
            # None whenever the hop was the identity, so an honest transcript
            # carries one declaration and compares equal across runs.
            forwarded_signature=(
                None
                if forwarded is None or forwarded == self._signature
                else forwarded
            ),
            run_id=self._run_id,
        )

    # -- helpers ------------------------------------------------------------ #

    @staticmethod
    def _not_yet(problem: str, call: str) -> ValueError:
        """Build the out-of-order error, which always names the fix.

        Parameters
        ----------
        problem : str
            What is missing, phrased as a clause.
        call : str
            The call that would supply it.

        Returns
        -------
        ValueError
            To be raised by the caller.
        """
        return ValueError(
            f"the session is not far enough along: {problem}. The phases run "
            f"in order -- distribute, sign, verify(Party.BOB), transfer -- so "
            f"call {call} first, or run(message_bit) for all of them."
        )


def _check_result_against(
    result: VerificationResult,
    params: ProtocolParams,
    message_bit: int,
) -> None:
    """Check one verdict against the parameter set the transcript claims.

    :class:`~sih141.protocol.verify.VerificationResult` enforces only its own
    internal consistency -- ``accepted == (rate <= threshold)`` -- so a verdict
    carrying the *wrong party's* threshold is perfectly self-consistent and
    survives a JSON round trip unchallenged. Since
    :meth:`SessionTranscript.from_json` is the hand-off boundary for Phases 4 to
    6, that is exactly how a run Bob rejected comes back reporting
    ``transferable=True``: rewrite each verdict's ``threshold`` to ``s_v``,
    recompute ``accepted``, and nothing downstream objects. So the transcript
    re-derives the threshold from ``params`` and the party and insists they
    agree. It is the same confusion :func:`sih141.protocol.verify.verify_all`
    guards against at the live boundary, closed at the persistence one.

    Parameters
    ----------
    result : VerificationResult
        One verdict.
    params : ProtocolParams
        The parameter set the transcript is tagged with.
    message_bit : int
        The bit the transcript is tagged with.

    Raises
    ------
    ValueError
        If the verdict's threshold, key length or message bit disagrees with
        the transcript's own parameters.
    """
    expected_threshold = params.threshold_for(result.party)
    if result.threshold != expected_threshold:
        raise ValueError(
            f"{result.party.value}'s verdict carries threshold "
            f"{result.threshold!r} but this transcript's parameters put his cut "
            f"at {expected_threshold!r} (s_a={params.s_a!r}, "
            f"s_v={params.s_v!r}). The threshold is a property of *whose* log "
            f"was scored, never a free field: a verdict holding the other "
            f"verifier's cut is internally consistent and still wrong, and it "
            f"would make this transcript report transferability for a run the "
            f"verifier rejected."
        )
    if result.key_length != params.key_length:
        raise ValueError(
            f"{result.party.value}'s verdict reports key_length "
            f"{result.key_length} but this transcript's parameters say "
            f"{params.key_length}. The verdict's discarded-position count, and "
            f"every Phase 4 statistic derived from it, would be computed "
            f"against the wrong denominator."
        )
    if result.message_bit != message_bit:
        raise ValueError(
            f"{result.party.value}'s verdict is for message bit "
            f"{result.message_bit} but this transcript is tagged with bit "
            f"{message_bit}. The bit selects which distribution was scored."
        )


def _check_abort_against(
    abort: VerificationAbort,
    params: ProtocolParams,
    message_bit: int,
) -> None:
    """Check one refusal to score against the parameters the transcript claims.

    The same persistence-boundary argument as :func:`_check_result_against`.
    :class:`~sih141.protocol.verify.VerificationAbort` enforces only its own
    internal consistency, so a refusal quoting another run's key length -- or a
    floor that was never this parameter set's -- survives a JSON round trip
    unchallenged and would put a fabricated shortfall in front of a Phase 5
    reader. The floor is re-derived from ``params`` and insisted on.

    Parameters
    ----------
    abort : VerificationAbort
        One refusal.
    params : ProtocolParams
        The parameter set the transcript is tagged with.
    message_bit : int
        The bit the transcript is tagged with.

    Raises
    ------
    ValueError
        If the refusal's key length, expected matched count, floor or message
        bit disagrees with the transcript's own parameters.
    """
    if abort.key_length != params.key_length:
        raise ValueError(
            f"{abort.party.value}'s refusal reports key_length "
            f"{abort.key_length} but this transcript's parameters say "
            f"{params.key_length}. The shortfall it records would be measured "
            f"against the wrong number of positions."
        )
    expected_floor = minimum_matched_count(params)
    if abort.minimum_matched != expected_floor:
        raise ValueError(
            f"{abort.party.value}'s refusal quotes a matched-count floor of "
            f"{abort.minimum_matched} but this transcript's parameters put it "
            f"at {expected_floor} (L={params.key_length}, "
            f"|B|={len(params.bases)}). The floor is derived from the "
            f"parameter set, never a free field: a refusal carrying a floor "
            f"nobody applied would make a scored run look starved, or a "
            f"starved one look scored."
        )
    if abort.expected_matched != params.expected_matched:
        raise ValueError(
            f"{abort.party.value}'s refusal reports an honest mean of "
            f"{abort.expected_matched!r} but this transcript's parameters give "
            f"L/|B| = {params.expected_matched!r}. That number is what makes "
            f"the shortfall legible, so it has to be this run's."
        )
    if abort.message_bit != message_bit:
        raise ValueError(
            f"{abort.party.value}'s refusal is for message bit "
            f"{abort.message_bit} but this transcript is tagged with bit "
            f"{message_bit}. The bit selects which distribution was scored."
        )


def _check_seam(seam: Any, name: str, expected: str) -> None:
    """Reject a non-callable seam at construction rather than mid-run.

    Parameters
    ----------
    seam : Any
        The injected callable, or ``None`` for the honest default.
    name : str
        The parameter name, quoted in the message.
    expected : str
        A description of what the seam should be, quoted in the message.

    Returns
    -------
    None

    Raises
    ------
    TypeError
        If ``seam`` is neither ``None`` nor callable. Caught here because a
        session that fails only once it reaches the seam would have teleported
        a whole key first.
    """
    if seam is not None and not callable(seam):
        raise TypeError(
            f"{name} must be None or {expected}, got "
            f"{type(seam).__name__}. See the Phase 3 seams section of "
            f"sih141.protocol.session for what each seam replaces."
        )
