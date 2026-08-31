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
        .exchange_counts()   Phase C'  Bob and Charlie announce to each other
                                       how many positions each can score,
                                       one integer each way
        .verify(Party.BOB)   Phase C   Bob scores his own log,  cut at s_a
        .transfer()          Phase C   Bob forwards to Charlie, who scores his
                                       own log, cut at s_v
        .transcript()                  the whole run as one frozen,
                                       JSON-serialisable record

``run(b)`` performs the five calls in that order and returns the transcript.

Why Phase A' is inside ``distribute()`` and not a seam of the distributor
------------------------------------------------------------------------
Symmetrisation is performed *by the recipients*, over their own authenticated
channel, after the quantum phase is over. It is what makes non-repudiation true
at all (:mod:`sih141.protocol.symmetrise`), so it must not sit anywhere an
adversary standing in Alice's place can reach: a malicious ``distributor``
returns records and the session symmetrises whatever it returns. There is a
separate ``symmetriser`` seam for Phase 3, but it replaces *the recipients'*
step, not Alice's, and the honest default is the secure one.

Phase C' has exactly the same standing. It is the recipients' own step, on the
same private channel, and its seam (``count_exchange``) replaces what *they* do,
never what Alice does. What it moves is one integer each way -- how many
positions each verifier can score against the declaration -- which is what makes
the pooled matched-count floor checkable at all: the count every repudiation
bound is exponential in is ``M = m_B + m_C``, and neither verifier knows it
alone. Without it a signer who reads both raw logs aims ``M`` at twice the
per-verifier floor, splits it with the symmetrisation coins, and leaves Bob
accepting a signature Charlie cannot score, about half the time and at every key
length. See :mod:`sih141.protocol.tally` and
:ref:`sih141.protocol.verify <pooled-floor>`.

The price is stated where it belongs, in ``tally``, but one part of it is this
module's shape: **Bob's verdict is no longer local.** He cannot accept before
Charlie has reported a count, and Charlie cannot count before he holds the
declaration, so the declaration reaches Charlie before Bob decides. A deployment
orders it so that a signature Bob would reject on his own rate is still never
forwarded; a signature he would accept is simply no longer accepted on his own
evidence alone.

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

    It is the one *Alice-side* seam handed a generator, because it stands where
    the quantum channel is and a channel is random. What it gets is the
    **Alice-side** stream and not the session's only one: the symmetrisation
    coins come from a second stream this seam is never shown, and cannot
    predict from the one it is shown. See :ref:`two-streams`, which is a
    threat-model boundary rather than a detail of plumbing.

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

    *It can also aim the total and let the coins split it,* which is the subtler
    version and the one a per-verifier floor does not catch: a declaration whose
    pooled matched count is exactly ``2 m_min``, all of it correct, leaves Bob
    over his floor and Charlie under his about half the time, with no rate
    deviating anywhere. Phase C'
    (:meth:`QDSSession.exchange_counts`,
    :mod:`sih141.protocol.tally`) closes it: the pooled floor refuses the aimed
    total outright, and a verifier under his own floor takes the other down with
    him, so "Bob accepts" now implies "Charlie reached a verdict". Every verdict
    this session emits therefore rests on ``m_R >= m_min`` at *both* verifiers
    and ``m_B + m_C >= M_min``, which is what
    :func:`~sih141.protocol.verify.enforced_repudiation_bound` evaluates --
    unconditionally, and without making the averaged number unconditional.

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

.. _two-streams:

Two streams: Alice's generator and the recipients'
--------------------------------------------------
A seam is isolated only as far as the objects it is handed, and one object this
file used to hand out was the session's single generator. ``distributor`` is
given an ``rng`` -- it stands where the quantum channel is, and a channel is
random -- and Phase A' then drew its ``L`` symmetrisation coins from that same
generator object, two lines later. A distributor that cloned
``rng.bit_generator.state`` on entry therefore held every coin before the
recipients tossed them, and a ``signer`` sharing that clone with it could
declare, position by position, the eigenvalue the coin was about to hand Bob.
Measured through otherwise unmodified code at
:data:`~sih141.protocol.params.DEFAULT_PARAMS`: Bob's mismatch rate ``0.00000``
and Charlie's ``1.00000``, with ``m_B = m_C = 37095`` and ``M = 74190`` clearing
both floors, five runs out of five -- a recorded repudiation on a run whose
transcript printed ``P(repudiation | this run) <= 1.414e-09``.

Nothing there is a defect in the bound. The Hoeffding argument assumes the coins
are private, and a real Alice has no way to read a coin two other people toss on
their own authenticated channel, so the mathematics stands exactly as written.
The defect is in the *harness*: it let an Alice-side seam read them. Every
attack number this repository publishes comes out of this harness, so those
numbers were right only by the convention that the attack implementations
happened not to peek -- and nothing enforced the convention.

The constructor therefore splits the generator it resolves into two, and a seam
is handed at most one of them:

``self._alice_rng``
    Key generation and the ``distributor`` seam: everything Alice does, and
    everything an adversary standing in her place may see.
``self._recipient_rng``
    The symmetrisation coins, and any recipient-side randomness added later. It
    is built in the constructor, passed only to the ``symmetriser`` seam -- the
    recipients' own step -- and reachable from no accessor, no record and no
    transcript.

Both come from the caller's generator: 32 bytes of material are drawn from it
once, at construction, and each stream is seeded with a SHA-256 digest of that
material under its own label (:func:`_derive_stream`). The split holds in the
direction that matters. Rewinding the Alice-side generator -- PCG64's transition
is invertible, so ``advance(-n)`` is available to an adversary -- reaches only
earlier states of *that* stream, and its ``bit_generator.seed_seq.entropy`` is
the digest rather than the material, so neither the state nor the seed sequence
of the stream a seam holds says anything about the stream it does not. The
caller's own generator is used for that one draw and then dropped, so no seam
ever holds it either. Determinism is untouched: one seed gives one material,
hence the same two streams and the same transcript byte for byte
(``tests/test_protocol_session.py`` pins both halves of that).

One consequence is a small gain rather than a cost. With the coins out of
Alice's stream, a run made with
:func:`~sih141.protocol.symmetrise.no_symmetrisation` and one made with the
honest exchange now draw the *identical* Alice stream, so the two arms of that
Phase 3 comparison differ in one callable and in nothing else -- which is what
:mod:`sih141.protocol.symmetrise` already claimed for them, and what the coin
draw sitting in the shared stream used to spoil for the second message bit.

The rest of the seams, audited for the same class of leak and left as they are:

* ``signer`` gets no generator, and is called after Phase A' has drawn its
  coins. It is handed the recipients' **raw** logs, which is the deliberate
  over-provision documented at :ref:`two-log-signer`, but the post-exchange
  records and the coins that produced them are never offered.
* ``forwarder`` and ``count_exchange`` get no generator and no records; two
  declarations and two integers pass through them.
* ``resource_factory`` gets a :class:`~sih141.protocol.distribute.ResourceContext`
  -- party, message bit, position -- and no generator, so a channel-only
  adversary cannot reach the coins even indirectly. A factory that wants
  randomness closes over its own generator, which is the documented way.
* ``symmetriser`` *is* handed ``self._recipient_rng``, which is correct: it
  replaces the recipients' step and the coins are theirs. It is the one seam
  from which the coins are readable, and reading your own coins is not an
  attack; a Phase 3 run that replaces it is running the recipients dishonestly,
  which is what :func:`~sih141.protocol.symmetrise.no_symmetrisation` already
  makes visible in the transcript.

What none of this defends against is an attack handed the seed by the harness
that built it: a Phase 3 experiment that closes over the same
``default_rng(seed)`` it passes to the session can predict every stream in it.
No boundary inside this file can stop that, which is precisely why a Phase 3
attack should take its own generator rather than reach for the session's.

Everything downstream of the seams is fixed: the matched/unmatched split, the
three matched-count floors, the two thresholds and the accept rule are computed
by :func:`~sih141.protocol.verify.verify` from the record, the declaration, the
counterpart's reported count and the parameter set alone, so no adversary can
reach them. Phases A' and C' are likewise not Alice-side seams, and Phase A' now
draws its coins from a generator no Alice-side seam is given; see above.

A verifier whose evidence falls below one of those floors reaches **no verdict** --
neither an acceptance nor a rejection. :meth:`QDSSession.run` records it and
carries on, so a starved declaration costs a verdict rather than the whole run,
and :class:`SessionTranscript` keeps verdicts and refusals in separate fields
(:attr:`~SessionTranscript.results` and :attr:`~SessionTranscript.aborts`) so
that no Phase 4 or Phase 5 statistic can conflate the two.

What the session is not
-----------------------
Not a channel and not a detector. It holds no quantum state at any point -- by
the time :meth:`QDSSession.distribute` returns, every teleported qubit has been
measured and discarded and the session's memory is four tables of integers
(:mod:`sih141.protocol.records`). Detection statistics are Phase 4's job and
read a :class:`SessionTranscript`.

It *is*, now, a ledger -- of one specific thing. Each verifier holds a
:class:`~sih141.protocol.verify.ConsumedRecords` of the distribution rounds he
has already decided, and :meth:`~QDSSession.verify` hands each verifier his own
and nobody else's. That is the replay defence, and it changed a documented
promise: verifying the same party twice used to recompute the same verdict and
now refuses as
:attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`. One
distribution round yields one verdict per verifier;
:ref:`sih141.protocol.verify <replay>` says why, and what it costs.

The application-level ledger is still somebody else's, and it still needs
something to key on. Content is not it: two runs made with the same seed produce
byte-identical transcripts, by design and by test, so a content hash cannot tell
a replay from a legitimate repeat. So a session takes an optional ``run_id``,
carried verbatim into the transcript and used by nothing here. It is
deliberately caller-supplied rather than generated: a generated identifier would
either be random -- breaking the reproducibility that Phase 5 rests on -- or
derived from the seed, in which case it would repeat exactly when a replay does
and defeat its own purpose. The harness that owns that ledger owns the
namespace. Distinct from :attr:`QDSSession.session_ids`, which is *this* run's
per-bit round identifier, is derived rather than supplied, and is the thing the
verifiers actually check.

Notes
-----
Single use (replay)
    A session distributes once and signs once. A second
    :meth:`~QDSSession.distribute` or a second :meth:`~QDSSession.sign` is
    refused, because the security of the scheme rests on the public key states
    being consumed: signing both bits against one distribution would hand a
    verifier two declarations scored against logs that are not independent of
    each other. Build a new session per run.

    Each *verification* is single-use too, for the same reason and by the same
    logic one level down: see :meth:`~QDSSession.verify`.
Determinism (D3)
    One keyword-only ``rng``, resolved once in the constructor through
    :func:`sih141.core.rng.resolve_rng`. It is drawn from exactly once, for the
    32 bytes of material the two session streams are derived from
    (:ref:`two-streams`); the Alice-side stream is then threaded through key
    generation and both distributions in that order, and the recipient-side
    stream through both symmetrisations. Deriving rather than sharing is a
    threat-model requirement, not a stylistic one, and it costs nothing here:
    the same seed still reproduces the entire transcript, byte for byte through
    :meth:`SessionTranscript.to_json`, and ``tests/test_protocol_session.py``
    pins that.
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

import hashlib
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
from sih141.protocol.signature import (
    Signature,
    fresh_opening,
    session_identifier,
    sign,
)
from sih141.protocol.symmetrise import Symmetriser, symmetrise_records
from sih141.protocol.tally import (
    CountExchange,
    MatchedCountMessage,
    PooledMatchedCounts,
    exchange_matched_counts,
    matched_count_message,
)
from sih141.protocol.verify import (
    AbortReason,
    ConsumedRecords,
    MatchedSetTooSmall,
    VerificationAbort,
    VerificationResult,
    minimum_matched_count,
    minimum_pooled_matched_count,
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
# The two session streams (see :ref:`two-streams`)
# --------------------------------------------------------------------------- #


_STREAM_MATERIAL_BYTES: Final[int] = 32
"""Bytes drawn from the caller's generator to derive the session's two streams.

One draw, in the constructor, and the caller's generator is then dropped. Thirty
two bytes because that is the width of the digest each stream is seeded with;
fewer would be the real seed length whatever the digest claimed.
"""

_ALICE_STREAM_LABEL: Final[bytes] = b"sih141.protocol.session/alice"
"""Domain separator for the stream Alice and her seams draw from."""

_RECIPIENT_STREAM_LABEL: Final[bytes] = b"sih141.protocol.session/recipients"
"""Domain separator for the stream Bob and Charlie's coins come from.

Distinct from :data:`_ALICE_STREAM_LABEL` and hashed with the same material, so
the two streams are independent for anyone who cannot invert SHA-256. Changing
either label changes every seeded transcript in the project, which is why they
are named constants rather than literals at the call site.
"""

_BINDING_STREAM_LABEL: Final[bytes] = b"sih141.protocol.session/binding"
"""Domain separator for the stream the session openings are drawn from.

A third label rather than a third *place to draw from the first*: the openings
that name a run's distribution rounds (:ref:`sih141.protocol.signature
<session-binding>`) have to come from somewhere, and taking them from the Alice
stream would shift every subsequent draw and change every seeded transcript in
the project for a value none of them depend on. Deriving a stream instead costs
one SHA-256 and leaves the other two byte-identical, which is what keeps "the
same seed reproduces the run" true across this change.

It is also the stream no seam is ever handed. That is not load-bearing -- Alice
knows her own openings, and they are revealed in Phase B anyway -- but it means
a ``distributor`` cannot read the opening of the *other* message bit, which is
the one that stays sealed.
"""


def _derive_stream(material: bytes, label: bytes) -> np.random.Generator:
    """Derive one labelled generator from the session's seed material.

    The mechanism behind :ref:`two-streams`. The generator is seeded with
    ``SHA-256(label + b":" + material)``, so that the two streams a session runs
    are reproducible from one seed and yet unpredictable from each other: what a
    seam holding one of them can read -- its ``bit_generator.state``, which
    rewinds only within its own stream, and its
    ``bit_generator.seed_seq.entropy``, which is the digest -- is a preimage
    problem away from the material, and therefore from the other stream.

    Parameters
    ----------
    material : bytes
        The session's seed material, drawn once from the caller's generator.
    label : bytes
        The stream's domain separator, :data:`_ALICE_STREAM_LABEL` or
        :data:`_RECIPIENT_STREAM_LABEL`.

    Returns
    -------
    numpy.random.Generator
        A fresh PCG64 generator, deterministic in ``(material, label)`` and
        independent of every other label's.

    Notes
    -----
    Deliberately *not* :meth:`numpy.random.Generator.spawn` or a
    :class:`numpy.random.SeedSequence` child. Both leave the parent's entropy
    sitting in the child's ``seed_seq.entropy`` in clear, so a seam holding one
    child could rebuild the seed sequence and spawn its sibling -- which is the
    very leak this split exists to close. A digest is one-way; a spawn key is
    not.

    D3 forbids reaching for :func:`numpy.random.default_rng` at a call site
    because that *restarts* a stream where one should have been threaded. This
    call is the opposite: it happens once, in the constructor, from the
    generator :func:`~sih141.core.rng.resolve_rng` has already resolved, and
    each generator it returns is then threaded through the whole run. If a
    second module ever needs a private sub-stream, this function belongs beside
    :func:`~sih141.core.rng.resolve_rng` in :mod:`sih141.core.rng`; it lives
    here while it has one caller.

    Examples
    --------
    >>> import hashlib
    >>> from sih141.protocol.session import _derive_stream
    >>> material = bytes(32)
    >>> _derive_stream(material, b"one").bytes(4) == _derive_stream(
    ...     material, b"one"
    ... ).bytes(4)
    True
    >>> _derive_stream(material, b"one").bytes(4) == _derive_stream(
    ...     material, b"two"
    ... ).bytes(4)
    False
    >>> seeded = _derive_stream(material, b"one")
    >>> seeded.bit_generator.seed_seq.entropy == int.from_bytes(
    ...     hashlib.sha256(b"one:" + material).digest(), "big"
    ... )
    True
    """
    digest = hashlib.sha256(label + b":" + material).digest()
    return np.random.default_rng(int.from_bytes(digest, "big"))


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

    The ``rng`` it is passed is the session's **Alice-side** stream. Cloning its
    state, rewinding it or rebuilding its seed sequence says nothing about the
    symmetrisation coins, which are drawn from a stream derived under a
    different label and never shown to this seam (:ref:`two-streams`). An
    implementation that wants randomness of its own should still close over its
    own generator, so that what it draws does not move Alice's stream.
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
    pooled : PooledMatchedCounts or None, optional
        What the recipients learned from each other in Phase C'
        (:mod:`sih141.protocol.tally`): the two matched counts, their total, and
        the two floors the run was scored under. ``None`` marks a run whose
        recipients did **not** compare counts -- the pre-pooled variant, which
        :func:`~sih141.protocol.tally.no_count_exchange` produces and which has
        no unconditional non-repudiation guarantee below ``1/2``. A separate
        field from ``results`` and ``aborts`` because it is neither: it is the
        evidence base all three of them were decided on, and a Phase 5 table
        that could not see it could not tell an aimed-low declaration from an
        unlucky one.

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
    pooled: PooledMatchedCounts | None = None

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

        if self.pooled is not None:
            if not isinstance(self.pooled, PooledMatchedCounts):
                raise TypeError(
                    f"pooled must be a PooledMatchedCounts or None, got "
                    f"{type(self.pooled).__name__}; "
                    f"tally.exchange_matched_counts returns exactly that."
                )
            _check_pooled_against(self.pooled, self.params, self.message_bit)

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
    def counts_exchanged(self) -> bool:
        """bool: ``True`` iff the recipients ran Phase C'.

        The pooled matched-count floor is checkable only after Bob and Charlie
        have compared counts (:mod:`sih141.protocol.tally`), so this says which
        rule the run's verdicts were reached under. ``False`` marks a run of the
        *pre-pooled* variant -- one made with
        :func:`sih141.protocol.tally.no_count_exchange`, which Phase 3 uses to
        demonstrate the split-coin repudiation route. Such a run enforces the
        per-verifier floor alone, has no unconditional non-repudiation guarantee
        below ``1/2``, and :meth:`summary` says so out loud.
        """
        return self.pooled is not None

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
    def session_coherent(self) -> bool:
        """bool: ``True`` iff every scored log belongs to the declaration's round.

        A transcript is a record, so it will hold whatever it is given -- but
        two of its derived claims are claims about a *transaction*, and a
        declaration scored against another run's logs is not one. This is the
        check that says so. It was the missing one: before it existed, a
        transcript pairing one run's signature with another run's records and
        verdicts constructed without complaint and reported
        ``transferable=True``.

        Each verifier's log for the signed bit is compared against the
        declaration that verifier actually scored -- :attr:`signature` for Bob,
        :attr:`forwarded_signature` where there was one for Charlie -- using
        :attr:`~sih141.protocol.signature.Signature.session_id` and
        :attr:`~sih141.protocol.records.RecipientRecord.session_id`. A log that
        names no round is coherent with anything, which is what keeps every
        transcript written before the binding existed readable exactly as
        before.

        See Also
        --------
        sih141.protocol.verify.verify : Where the same comparison refuses to
            score rather than merely reporting.
        """
        for record in self.records:
            if (
                record.message_bit != self.message_bit
                or record.session_id is None
            ):
                continue
            scored = self.signature_for(record.party)
            if scored.session_id != record.session_id:
                return False
        return True

    @property
    def transferable(self) -> bool:
        """bool: ``True`` iff Bob accepted **and** Charlie accepted, in one round.

        The property the ``s_a < s_v`` gap exists to deliver: a signature Bob
        accepts is one he can forward. ``False`` while either verdict is still
        missing -- an unfinished run has not demonstrated transferability -- and
        ``False`` on a transcript whose verdicts and declaration come from
        different distribution rounds (:attr:`session_coherent`), because "both
        verifiers accepted" is a statement about one transaction and such a
        transcript records two.
        """
        return (
            self.bob is not None
            and self.charlie is not None
            and self.bob.accepted
            and self.charlie.accepted
            and self.session_coherent
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

        Gated on :attr:`session_coherent` for the same reason
        :attr:`transferable` is: "Bob accepted and Charlie did not" is a
        statement about one transaction, and on a transcript assembled from two
        rounds it would name a repudiation that no signer performed. On every
        run this module produces the gate is open, since a session stamps its
        own round on every log it hands out.
        """
        return (
            self.bob is not None
            and self.charlie is not None
            and self.bob.accepted
            and not self.charlie.accepted
            and self.session_coherent
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

        Note what is *not* on that list: :attr:`counts_exchanged`. The per-run
        bound is a statement about the ``M`` a run produced, and a run produces
        one whether or not the recipients compared notes; what the exchange
        changes is which ``M`` values were *reachable*, which is the a-priori
        statement :func:`~sih141.protocol.verify.enforced_repudiation_bound`
        makes. On a run that did exchange, this agrees with
        :attr:`sih141.protocol.tally.PooledMatchedCounts.pooled` by
        construction.
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
        if not self.counts_exchanged:
            lines.append(
                "UNPOOLED: the recipients did not compare matched counts, so "
                "only the per-verifier floor applied and a signer who splits "
                "the evidence base repudiates at about 1/2 at any L."
            )
        if self.forwarding_altered_signature:
            lines.append(
                "FORWARDING ALTERED THE DECLARATION: Charlie scored a "
                "different key from the one Bob was given."
            )
        if self.pooled is not None:
            lines.append(self.pooled.summary())
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
            # Name the reason each verifier actually gave. A hardcoded cause here
            # was wrong for six of the eight AbortReason members, and on an
            # altered-forwarding run it read "the matched set was below the floor"
            # two lines under "Every floor met." -- the reason must come from the
            # abort, never from an assumption about which one fired.
            refused = ", ".join(
                f"{abort.party.value} ({abort.reason.value})" for abort in self.aborts
            )
            lines.append(
                f"NO VERDICT: {refused} could not score this declaration. "
                f"This is not a rejection and must not be counted as one."
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
            ``"results"``, ``"aborts"``, ``"pooled"``,
            ``"forwarded_signature"`` and
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
            "pooled": None if self.pooled is None else self.pooled.to_dict(),
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
            ``"records"`` and ``"results"``. ``"forwarded_signature"``,
            ``"run_id"`` and ``"pooled"`` are optional and default to ``None``;
            ``"aborts"`` is optional and defaults to empty, so a transcript
            written before the matched-count abort rule or the count exchange
            existed still restores.

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
            # Optional for the same reason: a transcript written before the
            # count exchange existed restores as one whose recipients did not
            # compare counts, which is exactly what it was.
            pooled=(
                None
                if data.get("pooled") is None
                else PooledMatchedCounts.from_dict(data["pooled"])
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
    count_exchange : CountExchange or None, optional
        Keyword-only. The Phase C' seam -- again the *recipients'* step, not
        Alice's. ``None`` selects
        :func:`~sih141.protocol.tally.exchange_matched_counts`. Phase 3 passes
        :func:`~sih141.protocol.tally.no_count_exchange` to run the pre-pooled
        variant and measure the split-coin repudiation route the exchange
        closes.
    forwarder : Forwarder or None, optional
        Keyword-only. The Bob-to-Charlie hop. ``None`` selects
        :func:`honest_forwarder`, the identity.
    run_id : str or None, optional
        Keyword-only. Carried verbatim into the transcript for an
        application-level ledger to key on; used by nothing here. See the module
        docstring on why it is not generated.
    context : str or None, optional
        Keyword-only. What the signed bit *means* to the application, together
        with a freshness nonce --
        :func:`sih141.protocol.signature.fresh_context` builds one. It is hashed
        into every round identifier this session announces, so it is fixed here,
        at distribution time, and not at signing time: a context chosen after
        the recipients had already recorded their identifiers would be a label
        nothing covers, which is exactly what
        :mod:`sih141.protocol.signature` refuses to carry. Two authorisations of
        one instruction under different nonces are two rounds, and each verifier
        decides each round once, which is how a valid signed instruction is
        stopped from being executed twice.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Resolved once, in this constructor, and drawn from
        once: :data:`_STREAM_MATERIAL_BYTES` bytes of material, from which two
        independent streams are derived (:ref:`two-streams`). Alice's is
        threaded through key generation and both distributions and is what the
        ``distributor`` seam receives; the recipients' supplies both
        symmetrisations and is shown to no Alice-side seam. One seed still
        reproduces the whole run. The generator passed in is not retained, so
        constructing two sessions from one generator gives two different runs,
        as before.

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
        count_exchange: CountExchange | None = None,
        forwarder: Forwarder | None = None,
        run_id: str | None = None,
        context: str | None = None,
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
            count_exchange,
            "count_exchange",
            "a callable with the signature of exchange_matched_counts; pass "
            "no_count_exchange to run the pre-pooled variant deliberately",
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
        if context is not None and not isinstance(context, str):
            raise TypeError(
                f"context must be a string or None, got "
                f"{type(context).__name__}. It is the application's "
                f"instruction-and-nonce string -- build one with "
                f"sih141.protocol.signature.fresh_context(instruction, nonce) "
                f"-- and it is hashed into every round identifier this session "
                f"announces, so it is fixed here and not at signing time."
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
        self._count_exchange: CountExchange = (
            exchange_matched_counts
            if count_exchange is None
            else count_exchange
        )
        self._forwarder: Forwarder = (
            honest_forwarder if forwarder is None else forwarder
        )
        self._run_id = run_id
        self._context = context
        # One draw from the caller's generator, then three independent streams
        # derived from it -- Alice's, which the seams may see, the recipients',
        # which they may not, and the binding stream the session keeps to
        # itself. See :ref:`two-streams` and :data:`_BINDING_STREAM_LABEL`. The
        # caller's generator is not retained: a seam that was handed it could
        # rewind it to whatever the other streams were derived from.
        material = resolve_rng(rng).bytes(_STREAM_MATERIAL_BYTES)
        self._alice_rng = _derive_stream(material, _ALICE_STREAM_LABEL)
        self._recipient_rng = _derive_stream(material, _RECIPIENT_STREAM_LABEL)
        self._binding_rng = _derive_stream(material, _BINDING_STREAM_LABEL)

        self._keys: tuple[PrivateKey, PrivateKey] | None = None
        self._openings: dict[int, str] = {}
        self._session_ids: dict[int, str] = {}
        self._raw_records: dict[int, dict[Party, RecipientRecord]] = {}
        self._records: dict[int, dict[Party, RecipientRecord]] = {}
        self._signature: Signature | None = None
        self._forwarded: Signature | None = None
        self._pooled: PooledMatchedCounts | None = None
        self._counts_compared = False
        self._results: dict[Party, VerificationResult] = {}
        self._aborts: dict[Party, VerificationAbort] = {}
        # One ledger per verifier, never one shared between them: the two are
        # adversaries to each other in half of this package's attacks, so Bob's
        # history must not be reachable from Charlie's decision. See
        # :ref:`sih141.protocol.verify <replay>`.
        self._ledgers: dict[Party, ConsumedRecords] = {
            party: ConsumedRecords(party) for party in VERIFIERS
        }

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

        A verifier lands here instead of in :attr:`results` when the evidence
        base failed one of the matched-count floors -- his own, the pooled one,
        or his counterpart's. Empty on every healthy run, and a party is never
        in both mappings.
        """
        return dict(self._aborts)

    @property
    def pooled(self) -> PooledMatchedCounts | None:
        """PooledMatchedCounts or None: what Phase C' produced.

        ``None`` before :meth:`exchange_counts` has run, and also after it on a
        session wired with
        :func:`~sih141.protocol.tally.no_count_exchange`. Read
        :attr:`counts_compared` to tell those two apart.
        """
        return self._pooled

    @property
    def counts_compared(self) -> bool:
        """bool: ``True`` once Phase C' has been attempted.

        Distinct from ``pooled is not None``, which is also ``False`` when the
        seam deliberately skipped the comparison.
        """
        return self._counts_compared

    @property
    def session_ids(self) -> dict[int, str]:
        """dict: The identifier of each distribution round, keyed by message bit.

        What Alice announced with the states in Phase A and what every log from
        this run is stamped with. Public from distribution time -- it names a
        round, it does not open it.

        Raises
        ------
        ValueError
            Before :meth:`distribute` has run, when no round exists to name.
        """
        if not self._session_ids:
            raise self._not_yet(
                "no distribution round has been opened", "session.distribute()"
            )
        return dict(self._session_ids)

    def opening_for(self, message_bit: int) -> str:
        """Return the secret opening of one round, for a dispute.

        The value the round identifier commits to. It is revealed on the
        signature for the bit that gets signed, and this accessor is how an
        auditor obtains the *other* one -- the round Alice never signed -- in
        order to check that the identifier she announced for it was really a
        commitment and not a fabricated string. Recomputing
        :func:`~sih141.protocol.signature.session_identifier` from it must
        reproduce :attr:`session_ids`; nothing else can, short of a preimage
        search.

        Parameters
        ----------
        message_bit : int
            ``0`` or ``1``.

        Returns
        -------
        str
            The 32-hex-character opening.

        Raises
        ------
        ValueError
            If ``message_bit`` is not ``0``/``1``, or before :meth:`distribute`
            has run.
        """
        bit = _as_message_bit(message_bit)
        if not self._openings:
            raise self._not_yet(
                "no distribution round has been opened", "session.distribute()"
            )
        return self._openings[bit]

    def ledger_for(self, party: Party | str) -> ConsumedRecords:
        """Return one verifier's ledger of rounds he has already decided.

        Read-only in practice: the object is the live one this session hands
        :func:`sih141.protocol.verify.verify`, and it is exposed so that a
        harness can see what a verifier has spent, not so that anything can
        spend on his behalf. Each verifier has his own; there is no way to
        obtain a view of both, which is the point (:ref:`sih141.protocol.verify
        <replay>`).

        Parameters
        ----------
        party : Party or str
            :attr:`~sih141.protocol.params.Party.BOB` or
            :attr:`~sih141.protocol.params.Party.CHARLIE`.

        Returns
        -------
        ConsumedRecords

        Raises
        ------
        ValueError
            If ``party`` is Alice, who reaches no verdict and spends nothing.
        """
        resolved = _as_party(party)
        if resolved not in self._ledgers:
            raise ValueError(
                f"{resolved.value} keeps no consumed-records ledger: only the "
                f"verifiers reach verdicts, so only they have rounds to spend. "
                f"Ask for Party.BOB or Party.CHARLIE."
            )
        return self._ledgers[resolved]

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
        Consumes, from the **Alice-side** stream, ``4 * L`` variates for the key
        pair and ``3 * L`` per recipient per bit for the teleportation and
        measurement; and from the **recipient-side** stream, one ``L``-long
        array of symmetrisation coins per bit. Two streams, not one, and the
        seams are handed only the first (D3, :ref:`two-streams`): the coins are
        the only randomness the non-repudiation bound uses, and a generator an
        Alice-side seam can read is a generator that has no coins in it.

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

        keys = generate_key_pair(self._params, rng=self._alice_rng)
        openings: dict[int, str] = {}
        session_ids: dict[int, str] = {}
        raw_records: dict[int, dict[Party, RecipientRecord]] = {}
        records: dict[int, dict[Party, RecipientRecord]] = {}
        for bit in MESSAGE_BITS:
            # The round's opening, drawn from the session's own stream so that
            # the two the seams and the recipients use are untouched, and its
            # identifier, which Alice announces with the distribution. The
            # opening stays here until Phase B reveals it on the signature. See
            # :ref:`sih141.protocol.signature <session-binding>`.
            openings[bit] = fresh_opening(rng=self._binding_rng)
            session_ids[bit] = session_identifier(
                bit,
                self._params.key_length,
                opening=openings[bit],
                context=self._context,
            )
            returned = self._distributor(
                keys[bit],
                self._params,
                parties=VERIFIERS,
                resource_factory=self._resource_factory,
                # Alice's stream, and only ever Alice's: a distributor that
                # clones this generator's state learns nothing about the coins
                # tossed on the next line. See :ref:`two-streams`.
                rng=self._alice_rng,
            )
            raw = {
                party: record.with_session_id(session_ids[bit])
                for party, record in self._check_distribution(
                    returned, bit
                ).items()
            }
            # Phase A': the recipients' own step, applied to whatever the
            # distributor produced -- an adversary standing in Alice's place
            # cannot skip it, because he does not run it, and cannot read its
            # coins, because they are drawn from a generator he is never given.
            exchanged = self._symmetriser(raw, rng=self._recipient_rng)
            raw_records[bit] = raw
            # Re-stamped after the exchange as well as before it. Each recipient
            # heard the announcement himself and re-attaches it to whatever log
            # he ends up holding, so a symmetriser seam cannot strip the
            # recipients' own binding on the way through -- which would leave
            # them scoring unbound evidence and quietly reopen the replay route.
            records[bit] = {
                party: record.with_session_id(session_ids[bit])
                for party, record in self._check_distribution(
                    exchanged, bit
                ).items()
            }

        self._keys = keys
        self._openings = openings
        self._session_ids = session_ids
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
        its own generator over, which keeps the session's two streams -- and
        therefore the distribution and the coins -- identical between a clean
        run and an attacked one. It is offered no generator to draw from in any
        case; see :ref:`two-streams`.

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
        signature = self._bind_to_round(signature)

        self._signature = signature
        return signature

    def _bind_to_round(self, signature: Signature) -> Signature:
        """Attach this run's opening and context to a declaration.

        Phase B reveals the opening of the round whose states were distributed,
        and it is *this* session that ran that distribution, so the opening is
        supplied here rather than taken from whatever the seam returned. A seam
        is free to declare any key it likes -- that is the point of the
        :class:`Signer` and :class:`Forwarder` seams -- but it does not get to
        say which round the declaration belongs to, and overriding rather than
        trusting is what keeps that true.

        The consequence is worth stating, because it is the difference between
        a useful measurement and an empty one: a forging seam's declaration
        carries the *correct* round identifier, so it is scored and rejected on
        its mismatch rate exactly as before. If the seam could leave the round
        unnamed, every forgery would abort as
        :attr:`~sih141.protocol.verify.AbortReason.SESSION_MISMATCH` and the
        whole of Phase 3's forgery table would empty into the no-verdict column.
        The binding is a replay defence, never a key check; see
        :ref:`sih141.protocol.verify <replay>`.

        Parameters
        ----------
        signature : Signature
            Whatever the seam produced, already checked for bit and shape.

        Returns
        -------
        Signature
            The same declaration, naming this session's round for its bit. The
            declared key object is shared, not copied.
        """
        opening = self._openings.get(signature.message_bit)
        if opening is None:
            return signature
        return Signature(
            message_bit=signature.message_bit,
            declared_key=signature.declared_key,
            session_opening=opening,
            context=self._context,
        )

    # -- Phase C' ----------------------------------------------------------- #

    def exchange_counts(self) -> PooledMatchedCounts | None:
        """Run Phase C': Bob and Charlie compare how much evidence each holds.

        Each recipient computes :func:`~sih141.protocol.tally.matched_count_message`
        from **his own** post-symmetrisation log against the declaration, the two
        messages cross, and the ``count_exchange`` seam combines them into the
        :class:`~sih141.protocol.tally.PooledMatchedCounts` both of them end up
        holding. Nothing but two integers moves between the verifiers here; the
        reason that matters is in :mod:`sih141.protocol.tally`.

        Idempotent, and called automatically by :meth:`verify` the first time a
        verdict is asked for, so a caller who follows the older
        ``distribute / sign / verify / transfer`` sequence still gets the pooled
        rule. :meth:`run` calls it explicitly, in phase order, because the step
        is a message rather than an implementation detail.

        **Which declaration is counted.** The one Alice sent Bob -- the
        declaration Bob forwards to Charlie in order to *ask* for a count.
        Charlie therefore holds it before Bob's verdict is final, which is the
        real ordering cost of the pooled rule: Bob's acceptance is no longer
        local. If the ``forwarder`` seam later hands Charlie a *different*
        declaration, the counts pooled here are not the counts Charlie scored,
        the run is not one repudiation experiment but two, and
        :attr:`SessionTranscript.pooled_matched_count` already returns ``None``
        for it (:attr:`SessionTranscript.forwarding_altered_signature`).

        Returns
        -------
        PooledMatchedCounts or None
            ``None`` when the seam declined to compare -- which is what
            :func:`~sih141.protocol.tally.no_count_exchange` does, and what a
            Phase 3 experiment measuring the split-coin route wants.

        Raises
        ------
        ValueError
            If :meth:`sign` has not run: there is no declaration to count
            against, and counting against a key nobody declared would pool two
            numbers about nothing.
        TypeError
            If the ``count_exchange`` seam returned something that is neither a
            :class:`~sih141.protocol.tally.PooledMatchedCounts` nor ``None``.

        Notes
        -----
        Consumes no randomness (D3), so a session with the exchange and one
        without draw the identical generator sequence and stay comparable
        position by position.

        Examples
        --------
        >>> import numpy as np
        >>> from sih141.protocol.params import ProtocolParams
        >>> from sih141.protocol.session import QDSSession
        >>> session = QDSSession(
        ...     ProtocolParams(key_length=600), rng=np.random.default_rng(4)
        ... )
        >>> _ = session.distribute()
        >>> _ = session.sign(0)
        >>> pooled = session.exchange_counts()
        >>> pooled.pooled == pooled.bob_count + pooled.charlie_count
        True
        >>> pooled.meets_every_floor
        True
        """
        if self._signature is None:
            raise self._not_yet(
                "there is no declaration for the recipients to count against",
                "session.sign(message_bit)",
            )
        if self._counts_compared:
            return self._pooled

        bit = self._signature.message_bit
        # Each message is built from that recipient's own log and nothing else:
        # the count is local, the comparison is not.
        messages: dict[Party, MatchedCountMessage] = {
            party: matched_count_message(
                self._signature, self._records[bit][party], self._params
            )
            for party in VERIFIERS
        }
        pooled = self._count_exchange(messages, self._params)
        if pooled is not None and not isinstance(pooled, PooledMatchedCounts):
            raise TypeError(
                f"the count_exchange seam must return a PooledMatchedCounts or "
                f"None, got {type(pooled).__name__}. Returning None means the "
                f"recipients did not compare counts, which is what "
                f"no_count_exchange does; anything else is a wiring error."
            )
        self._pooled = pooled
        self._counts_compared = True
        return pooled

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
            A :class:`ValueError` subclass, if the evidence base failed one of
            the matched-count floors: this verifier's own
            (:func:`~sih141.protocol.verify.minimum_matched_count`), the pooled
            one (:func:`~sih141.protocol.verify.minimum_pooled_matched_count`),
            or the other verifier's own -- which takes this one down with it,
            because the floor's consequence is joint. The corresponding
            :class:`~sih141.protocol.verify.VerificationAbort` is recorded in
            :attr:`aborts` **before** the exception propagates, so a caller that
            catches it -- :meth:`run` does -- still gets the run in the
            transcript. It is not a rejection and must not be counted as one.
        TypeError
            If ``party`` is neither a :class:`~sih141.protocol.params.Party` nor
            a string.

        Notes
        -----
        **One verdict per verifier per round, and asking twice is refused.**
        This used to be a repeatable pure call; it is now backed by a
        per-verifier :class:`~sih141.protocol.verify.ConsumedRecords`, so a
        second :meth:`verify` for the same party aborts as
        :attr:`~sih141.protocol.verify.AbortReason.RECORD_ALREADY_VERIFIED`
        rather than re-deciding. That is the replay defence and not an
        implementation accident: a captured declaration re-presented after the
        run collected a fresh acceptance every time it was offered, measured
        3/3 before the ledger existed. Read the verdict already reached from
        :attr:`results` instead of asking again. Consumes no randomness (D3).

        A refusal spends nothing, so a verifier who aborted can be asked again
        once the cause is fixed -- which is what lets :meth:`transfer` re-verify
        Charlie against a forwarded declaration after an abort on the
        unforwarded one. Each verifier holds exactly one current outcome, so a
        call that reaches a verdict clears any refusal recorded for that party,
        and vice versa -- with the single exception of the replay refusal, which
        leaves the standing verdict alone. Recording it as this verifier's
        outcome would let a replayed presentation *delete* the acceptance that
        spent the round, which would be a larger hole than the one the ledger
        closes.
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
        # Phase C' if it has not happened yet: a verifier applies the pooled
        # floor, so he needs the number the other one sent him. Lazily here
        # rather than only in run(), so that the older
        # distribute/sign/verify/transfer sequence gets the pooled rule too.
        pooled = self.exchange_counts()
        counterpart = None if pooled is None else pooled.counterpart_of(resolved)
        try:
            # The module-level verify(), not this method. The ledger handed over
            # is this verifier's own and nobody else's, so asking twice is
            # refused as the replay it is, and Bob's history stays out of
            # Charlie's decision. See :ref:`sih141.protocol.verify <replay>`.
            result = verify(
                declaration,
                record,
                self._params,
                counterpart_matched=counterpart,
                ledger=self._ledgers[resolved],
            )
        except MatchedSetTooSmall as too_small:
            # Recorded *before* it propagates, so that run() -- and any harness
            # that catches it -- reports a no-verdict outcome instead of losing
            # the run. A starved matched set is a plumbing failure, never a
            # rejection, so it is stored in a different field and a different
            # type from the verdicts.
            #
            # With one exception, and it matters: a refusal to decide a round
            # *again* is not a new outcome for this verifier, it is the old one
            # standing. Overwriting the verdict with it would let a replayed
            # presentation delete the acceptance that spent the round -- turning
            # the replay defence into a way of erasing the very decision it
            # protects, which is a worse hole than the one it closes.
            if (
                too_small.abort.reason is AbortReason.RECORD_ALREADY_VERIFIED
                and resolved in self._results
            ):
                raise
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
        # Bound to this run's round for the same reason the signed declaration
        # is: the hop can alter the declaration -- that is what the seam is for
        # -- but Charlie is still in this round, and a hop that could also
        # unname the round would convert every altered-forwarding detection
        # into a no-verdict. See _bind_to_round.
        self._forwarded = self._bind_to_round(forwarded)
        return self.verify(Party.CHARLIE)

    # -- the whole run ------------------------------------------------------ #

    def run(self, message_bit: int) -> SessionTranscript:
        """Execute the entire protocol for one message bit and report.

        Equivalent to :meth:`distribute`, :meth:`sign`, :meth:`exchange_counts`,
        ``verify(Party.BOB)``, :meth:`transfer`, :meth:`transcript` -- in that
        order, which is the order the protocol fixes.

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
        # Phase C', explicitly and in order: the recipients compare matched
        # counts before either of them reaches a verdict. verify() would trigger
        # it anyway, but the step is one classical message each way and belongs
        # in the list of phases rather than inside one of them.
        self.exchange_counts()
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
            pooled=self._pooled,
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


def _check_pooled_against(
    pooled: PooledMatchedCounts,
    params: ProtocolParams,
    message_bit: int,
) -> None:
    """Check one count exchange against the parameters the transcript claims.

    The same persistence-boundary argument as :func:`_check_result_against` and
    :func:`_check_abort_against`.
    :class:`~sih141.protocol.tally.PooledMatchedCounts` enforces only its own
    internal consistency, so an exchange quoting floors nobody applied survives
    a JSON round trip unchallenged -- and floors are exactly the field an
    editor would reach for to make a starved run look scored. Both are
    re-derived from ``params`` and insisted on.

    Parameters
    ----------
    pooled : PooledMatchedCounts
        The recorded exchange.
    params : ProtocolParams
        The parameter set the transcript is tagged with.
    message_bit : int
        The bit the transcript is tagged with.

    Raises
    ------
    ValueError
        If the exchange's key length, either floor, or its message bit
        disagrees with the transcript's own parameters.
    """
    if pooled.key_length != params.key_length:
        raise ValueError(
            f"the recorded count exchange reports key_length "
            f"{pooled.key_length} but this transcript's parameters say "
            f"{params.key_length}. Both floors are derived from the key "
            f"length, so the two cannot be from the same run."
        )
    for name, recorded, expected in (
        (
            "per-verifier",
            pooled.minimum_matched,
            minimum_matched_count(params),
        ),
        (
            "pooled",
            pooled.minimum_pooled,
            minimum_pooled_matched_count(params),
        ),
    ):
        if recorded != expected:
            raise ValueError(
                f"the recorded count exchange quotes a {name} matched-count "
                f"floor of {recorded} but this transcript's parameters put it "
                f"at {expected} (L={params.key_length}, "
                f"|B|={len(params.bases)}). A floor is derived from the "
                f"parameter set, never a free field: an exchange carrying a "
                f"floor nobody applied would make a run that failed the rule "
                f"look like one that passed it."
            )
    if pooled.message_bit != message_bit:
        raise ValueError(
            f"the recorded count exchange is for message bit "
            f"{pooled.message_bit} but this transcript is tagged with bit "
            f"{message_bit}. The bit selects which distribution was counted."
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
