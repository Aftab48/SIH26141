"""Phase A: teleporting the quantum public key and measuring it on arrival.

This module is the only place in the protocol where quantum information moves.
It executes, once per recipient and once per future message bit, the two steps
that turn Alice's classical private key into a recipient's classical log:

.. code-block:: text

    for i in 0 .. L-1:
        Alice    prepares  |basis_i, eigenvalue_i>          from k_b
        Alice    teleports it to R, consuming a fresh Bell pair
        R        measures  it IMMEDIATELY in a uniformly random basis
        R        stores    (i, chosen_basis, outcome_eigenvalue)   -- and nothing else

The result is a :class:`~sih141.protocol.records.RecipientRecord`: a purely
classical table, and a **raw** one -- it has not yet been through the
recipients' private exchange (:mod:`sih141.protocol.symmetrise`), which runs
next and which every non-repudiation claim depends on.
:func:`sih141.protocol.verify.verify_all` refuses a pair of raw records for that
reason; :meth:`sih141.protocol.session.QDSSession.distribute` runs both steps in
order.

When :func:`distribute_to_recipient` returns, **no quantum state from this run
exists anywhere** -- not in Alice's hands, not in the channel, not in the
recipient's. That is the whole design rationale (see
:mod:`sih141.protocol` and :mod:`sih141.protocol.records`): Gottesman-Chuang QDS
asks recipients to hold the public key in quantum memory until a signature
arrives, and the measurement-based line of Dunjko-Wallden-Andersson (2014) and
Amiri et al. (2016) removes that requirement by measuring on receipt. Combining
it with teleportation-based delivery is what the problem statement means by
"reduces some of the practical deployment complexities associated with earlier
QDS schemes".

Why preparing the same state twice is not cloning
-------------------------------------------------
:func:`distribute_public_key` calls :func:`distribute_to_recipient` once for Bob
and once for Charlie, and each call builds its own
:class:`~qiskit.quantum_info.Statevector` for every key position via
:meth:`~sih141.protocol.keys.KeyElement.state`. This is the single most common
reviewer objection to the construction, and the answer is that **Alice holds the
classical description**: ``(basis_i, eigenvalue_i)`` is written down in her
private key, so she prepares :math:`|\\psi_i\\rangle` from scratch as many times
as she has recipients. The no-cloning theorem forbids a machine that maps an
*unknown* :math:`|\\psi\\rangle` to :math:`|\\psi\\rangle|\\psi\\rangle`; it says
nothing about a state-preparation device driven by a known label, which is what
every laboratory single-photon source is. Nothing in this module ever copies a
state it received: what arrives from the channel is measured once and destroyed.

The same point in the other direction: a recipient cannot make a second copy of
what he was sent, which is exactly why he cannot forge -- he holds one
measurement outcome per position, in a basis of his own choosing, and learns
Alice's basis only later.

What actually crosses the channel
---------------------------------
Nothing that carries the key. Each position consumes one fresh Bell pair, plus
two classical bits from Alice's Bell measurement. An adversary who owns the
entire forward channel sees an entangled half that is locally maximally mixed for
the ideal resource, and two bits that are uniform and independent of the payload
(the derivation is in :mod:`sih141.core.teleport`). He can *degrade* the delivery
-- and degradation is exactly what shows up as a raised mismatch rate at
verification -- but he cannot read the key off the wire.

The ``resource_factory`` seam
-----------------------------
:func:`distribute_to_recipient` takes a ``resource_factory``: a callable invoked
**once per key position**, returning the two-qubit entanglement resource that hop
consumes. It defaults to :func:`ideal_resource`, a clean
:math:`|\\Phi^{+}\\rangle`.

This is deliberately the *only* injection point in the module, and it is how
Phase 3 mounts channel-manipulation attacks **without editing a line of this
file**: a Werner or amplitude-damped pair models a noisy or eavesdropped link, a
factory that returns a degraded pair on a subset of calls models an intermittent
attacker, and a factory that closes over its own generator models a randomised
one. Because the resource is drawn per position rather than once per run, an
attack can be time-varying at the finest granularity the protocol has.

The seam comes in two shapes and the module picks between them by inspecting the
callable once, before any qubit moves:

``factory()``
    Callable with no arguments, the original form. Simple, and enough for an
    attack that does not care where in the run it is.
``factory(context)``
    Takes one **required** positional :class:`ResourceContext`, carrying the
    ``party``, the ``message_bit`` and the key ``position`` this hop belongs to.
    The parameter must be required, because a factory that can be called with no
    arguments is called with none -- ``lambda pair=pair: pair`` closes over a
    fixed resource and must not be mistaken for a context-aware one. Prefer it for
    anything targeted. A factory that wants to degrade *Charlie's* link and not
    Bob's used to have to reverse-engineer the call ordering from the loops in
    :func:`distribute_public_key` and
    :meth:`~sih141.protocol.session.QDSSession.distribute` -- documented, but not
    an enforced contract, so re-ordering the loops would have silently redirected
    every party-targeted attack at the wrong party with no error and no test
    failure. With the context the seam says what it is being asked for, and the
    ordering stops being load-bearing.

The seam is load-bearing only if the teleportation is genuinely in the data path,
so it is: each position goes through :func:`sih141.core.teleport.teleport`, whose
received state -- correction applied, consumed qubits traced out -- is the state
the recipient measures. Nothing is short-cut by re-preparing the eigenstate at
the recipient, and ``tests/test_protocol_distribute.py`` pins that down by
checking that a degraded factory measurably raises the mismatch rate and that the
generator is advanced by the teleportation's own variate.

A factory that returns ``None`` is rejected rather than forwarded. ``None`` is
:func:`~sih141.core.teleport.teleport`'s way of asking for the *ideal* pair, so
forwarding it would turn a mis-wired attack into a perfect channel and let a
Phase 3 test pass vacuously.

.. _payload-seam:

The ``payload_map`` seam
------------------------
The resource seam owns the *channel*; this one owns the **payload line** -- the
qubit Alice prepares, between her preparation and her Bell measurement.
:func:`distribute_to_recipient` takes a ``payload_map``: a callable invoked once
per **position** with the eigenstate prepared for it and the same
:class:`ResourceContext` the resource factory saw, returning the state that is
actually sent. It defaults to ``None``, which calls nothing at all, so the
honest path is unchanged down to the last variate.

It exists because the alternative is worse. Without it, an attack on what Alice
sends has to be mounted from the ``distributor`` seam, which means
reimplementing this loop -- the basis draw, the teleportation, the measurement,
the three-variate budget and the check-round branch -- inside the attack. That
copy drifts the first time this file changes, and its bugs are invisible,
because the honest path never executes it. A seam that substitutes one state for
another is one line of attack code and cannot drift.

Three properties of the seam are worth stating because they are consequences
rather than decisions:

* **It is called on every position, its answer is read on every position, and
  what it returns on a check round is thrown away after that read.** A check
  round prepares no payload of its own; it spends its pair on measuring the
  channel. But *being called* is a signal, and this seam used to be called on
  key rounds only -- which made the gaps in its call sequence the check set,
  exactly, and recoverable in one pass. So the call is now made everywhere and
  the result discarded where it has no use, the same way the recipient's basis
  draw is made everywhere and discarded on a check round. *Being used* is a
  signal for the same reason and was the next one to fall: with the call
  equalised, a mapped payload was still read by
  :func:`~sih141.core.teleport.teleport` on a key round and by nothing at all
  on a check round, so a seam returning an instrumented state counted its own
  reads and recovered the check set again, at precision 1.0. It is now adopted
  the moment it is returned (:func:`_adopt_state`) -- one read per position,
  both branches -- and the object thrown away on a check round is this
  module's copy, not the seam's. See :ref:`check-round-lockstep`.
* **A payload attack still cannot reach the watched positions.** What is
  discarded is discarded: the substituted state is never teleported on a check
  round, so neither the QBER nor the CHSH estimate can move because of one.
  What moves is the verification rate, which is where a payload substitution
  belongs -- it is a statement about the *key*, not about the link. The
  difference from before is that the seam can no longer *tell* which positions
  those are.
* **It consumes no randomness** from this run's generator, like the resource
  seam: a map that wants some closes over its own (D6). The variate budget here
  is three per position on every branch either way. A randomised map now
  advances its own generator on every position rather than on key rounds only,
  which is the point: a map whose own stream advanced only on key rounds would
  have carried the check set out with it.

The payload may be pure or mixed: :func:`~sih141.core.teleport.teleport` accepts
both, and measures its reported fidelity against whatever it was given, so a map
returning a :class:`~qiskit.quantum_info.DensityMatrix` is a legitimate
noisy-preparation attack rather than a type error. Returning ``None`` is refused
for the same reason a ``resource_factory`` returning ``None`` is.

.. _check-round-lockstep:

Check rounds, and the variate budget that hides them
----------------------------------------------------
Passing a :class:`~sih141.protocol.checkrounds.CheckRoundPlan` turns a
designated subset of positions into *check rounds*: the pair that position drew
is spent on measuring the channel rather than on teleporting a key element, the
two wings' outcomes are logged, and the position is left out of the record
entirely. :func:`distribute_to_recipient_with_checks` returns both halves --
the shortened :class:`~sih141.protocol.records.RecipientRecord` and the
:class:`~sih141.protocol.checkrounds.CheckLog` -- and
:mod:`sih141.protocol.checkrounds` explains what the statistics mean and why the
key is drawn at full length and sifted afterwards.

The one thing this module has to get right is that **nothing distinguishes a
check round from a key round on the wire**, because an adversary who could tell
them apart would behave on the ones that are watched and misbehave on the ones
that are not, and every estimate here would be a fiction. Four invariants
secure it, and all four are tested:

* **Every seam is called on every position**, in the same order, with the same
  :class:`ResourceContext`, before the branch is taken. That is the
  ``resource_factory``, the ``payload_map`` here, and the ``channel_monitor``
  in :mod:`sih141.protocol.session`; the declared channel-side adversary holds
  all three, so it is the union of their call sequences that has to be
  undifferentiated, not any one of them.
  ``test_the_factory_cannot_tell_a_check_round_from_a_key_round`` drives all
  three together and pins it. It used to drive the factory alone, and passed
  against code that published the whole check set through the other two.
* **Every seam's answer is read exactly once, on both branches**, and the
  protocol never touches the seam's own object again. Equalising the calls left
  the *use* differing: a resource was read once on a key round (inside
  :func:`~sih141.core.teleport.teleport`) and twice on a check round (once to
  summarise the pair, once to measure it), a mapped payload once and not at
  all, and the ``channel_monitor``'s mapping was iterated at check positions
  alone. All three tallies separated the branches at precision 1.0 and recall
  1.0 -- the whole check set, in one pass, no statistics -- for an adversary
  who returned an instrumented object and counted. So each seam's answer is now
  **adopted** at the boundary (:func:`_adopt_state` for the two state seams,
  :func:`~sih141.protocol.session._call_monitor` for the mapping) before the
  branch is taken. The tally is ``1`` at every position of every link: a
  constant, and a constant carries no bits. Equalising by construction rather
  than by matching reads downstream is deliberate -- a matched count is one
  edit away from unmatched, and nothing would fail.
  ``test_the_payload_seams_answer_is_read_once_on_both_branches`` here and
  ``test_no_seam_learns_the_check_set_by_counting_its_own_reads`` in
  ``tests/test_protocol_session.py`` -- where the session's channel tap is in
  place, which is what makes the resource and monitor halves visible -- run the
  recovery both ways round: each asserts the tally is flat, and each then
  asserts that the same scorer *does* recover the set from a deliberately
  unbalanced control, so a probe that has stopped measuring anything cannot
  pass quietly.
* **Exactly three variates are consumed per position, on both branches.** A key
  round spends them on the recipient's basis draw, the Bell measurement inside
  :func:`~sih141.core.teleport.teleport`, and the recipient's projective
  measurement; a check round spends them on the same basis draw -- made and
  *discarded*, because the draw must not be correlated with the round's role --
  and the two wings' measurements. The generator is therefore in the same state
  at the start of every position whether or not a plan is in force, so a
  retained position of a checked run is **bit-identical** to the same position
  of an unchecked run under the same seed. That is a far stronger statement than
  "the retained key tests uniform", and
  ``test_retained_positions_are_bit_identical_to_an_unchecked_run`` asserts the
  equality outright.
* **The two links do not run the same check rounds.** A plan reserves one set
  of positions -- shared, because both recipients must retain the same key --
  but deals them between the links, so recovering the check set on the link an
  adversary sees first does not hand over the second's
  (:ref:`sih141.protocol.checkrounds <check-round-links>`). The first three
  invariants say the set cannot be recovered at all; this one says what it
  would buy if it ever were.

**What these invariants do not cover, stated here rather than left implicit.**
A check round and a key round do different amounts of *work*: the key round
teleports and measures once, the check round measures both wings and does not
teleport. The two therefore take different wall-clock times -- measured, the
check round is the slower branch -- and a seam that timed the gap between its
own consecutive calls would classify the branch without instrumenting anything.
That route is not closed in code. Closing it would mean every position
performing the **union** of the two branches and discarding the half it does not
need, which a little more than doubles the cost of every checked session; adding
a discarded teleportation to check rounds alone would not even equalise them,
since a check round would then do strictly more work than a key round. It is
out of scope instead, because this module models the protocol's **information
flow and not its physical execution**: it represents no wall-clock timing, no
power draw and no emission, so a timing side channel here is an artefact of
Python's execution speed rather than a property of the protocol. The argument is
made in full, with what it costs and the assumption it leaves behind, in
``docs/PHASE3.md`` section 12.

Notes
-----
Canonical state type (D1)
    Public-key factors are handed to :func:`~sih141.core.teleport.teleport` as
    :class:`~qiskit.quantum_info.Statevector` objects, which is both what
    :func:`~sih141.protocol.keys.public_key_states` produces and the exact
    fidelity path in that function. The resource may be given in either
    representation.
Qubit ordering (D2)
    Each hop is a standalone one-qubit teleportation, so the received state is a
    one-qubit density matrix and the measured qubit index is always ``0``. No
    multi-qubit bitstring label is formed anywhere, and the record's index is a
    position in the key, not a register position.
Determinism (D3)
    All randomness is drawn from one injected keyword-only ``rng``, resolved
    through :func:`sih141.core.rng.resolve_rng`. **Exactly three variates are
    consumed per key position**, in this order: the recipient's basis choice,
    the sender's Bell measurement inside
    :func:`~sih141.core.teleport.teleport`, and the recipient's projective
    measurement. The count does not depend on the resource *or on whether the
    position is a check round* (:ref:`check-round-lockstep`), so for a fixed seed
    the sequence of *chosen bases* is the same under every ``resource_factory``
    and only the outcomes move -- which is what makes a clean run and an attacked
    run directly comparable position by position.

    Do not share a generator between key generation and distribution unless you
    intend to: :func:`~sih141.protocol.keys.generate_private_key` consumes two
    variates per element from the same stream, so interleaving changes the key.
No machine learning (D4)
    Linear algebra and uniform draws only.

See Also
--------
sih141.protocol.keys.public_key_states : The states being distributed.
sih141.protocol.records.RecipientRecord : What a recipient is left holding.
sih141.core.teleport.teleport : The single-qubit hop each position takes.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TypeAlias

import numpy as np
from qiskit.quantum_info import DensityMatrix, Statevector

from sih141.core.measure import projective_measure
from sih141.core.paulis import PauliBasis
from sih141.core.rng import resolve_rng
from sih141.core.states import BellState, StateLike, bell_state
from sih141.core.teleport import teleport
from sih141.protocol.checkrounds import (
    CheckLog,
    CheckRoundPlan,
    ChshObservation,
    ChshRound,
    QberObservation,
    QberRound,
    observe_chsh_round,
    observe_qber_round,
)
from sih141.protocol.keys import PrivateKey
from sih141.protocol.params import (
    VERIFIERS,
    Party,
    ProtocolParams,
    _as_party,
)
from sih141.protocol.records import RecipientRecord

__all__ = [
    "RecipientDistribution",
    "ResourceContext",
    "ResourceFactory",
    "PayloadMap",
    "ideal_resource",
    "identity_payload",
    "distribute_to_recipient",
    "distribute_to_recipient_with_checks",
    "distribute_public_key",
    "distribute_public_key_with_checks",
    "accepts_context",
]


@dataclass(frozen=True)
class ResourceContext:
    """Which hop a ``resource_factory`` is being asked for.

    Passed positionally to a factory that accepts one argument, so that a Phase
    3 attack can name its target instead of counting calls. Frozen and made of
    plain values, so it can be logged or accumulated by an attack that wants a
    record of what it did.

    Attributes
    ----------
    party : Party
        The recipient this hop is delivering to,
        :attr:`~sih141.protocol.params.Party.BOB` or
        :attr:`~sih141.protocol.params.Party.CHARLIE`. This is what an attack
        on one recipient's link keys on.
    message_bit : int
        ``0`` or ``1``: which of the two distributions this hop belongs to.
    position : int
        The key index ``0 .. L-1`` being teleported.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.distribute import (
    ...     ResourceContext, distribute_public_key, ideal_resource
    ... )
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> seen = []
    >>> def watcher(context: ResourceContext):
    ...     seen.append((context.party, context.position))
    ...     return ideal_resource()
    >>> params = ProtocolParams(key_length=4)
    >>> key = generate_private_key(params, 1, rng=np.random.default_rng(0))
    >>> _ = distribute_public_key(
    ...     key, params, resource_factory=watcher, rng=np.random.default_rng(1)
    ... )
    >>> seen[0], seen[-1]
    ((<Party.BOB: 'Bob'>, 0), (<Party.CHARLIE: 'Charlie'>, 3))
    """

    party: Party
    message_bit: int
    position: int


ResourceFactory: TypeAlias = (
    Callable[[], StateLike] | Callable[[ResourceContext], StateLike]
)
"""A callable returning one two-qubit entanglement resource.

Called once per key position, in key order, so the returned pair may differ from
call to call: close over a counter for a position-dependent attack, or over a
:class:`numpy.random.Generator` for a randomised one. It must return a state,
never ``None``.

Two shapes are accepted and the choice is made by inspecting the callable's
signature once per distribution run: a ``factory()`` callable with no arguments,
or a ``factory(context)`` taking one **required** positional
:class:`ResourceContext` naming the party, message bit and key position. Prefer
the second for any attack aimed at a particular recipient or a particular
stretch of the key -- it does not depend on the order in which the loops happen
to run. Anything callable with no arguments is called with none, so
``lambda pair=pair: pair`` keeps working and is not mistaken for a
context-aware factory.
"""


PayloadMap: TypeAlias = Callable[[StateLike, ResourceContext], StateLike]
"""A callable standing on the payload line, between preparation and Bell measurement.

Called once per **position** -- check rounds included, since a seam called only
on key rounds publishes the check set as the gaps in its call sequence -- as
``payload_map(state, context)``, with the eigenstate
:meth:`~sih141.protocol.keys.KeyElement.state` produced for that
position and the same :class:`ResourceContext` the ``resource_factory`` was given
for the same hop. Whatever it returns is read once, immediately, into a copy the
protocol owns (:func:`_adopt_state`), and on a key round that copy is what is
teleported; on a check round it is discarded unread. Both arguments are
positional, and unlike :data:`ResourceFactory` there is only one accepted shape:
this seam is new, so there is no historical arity to keep working, and a single
shape means no inspection and no way to be called wrongly.

It must return a one-qubit state -- pure or mixed, since
:func:`~sih141.core.teleport.teleport` accepts both -- and never ``None``. See
:ref:`payload-seam` for what it is for and what it deliberately cannot reach.
"""


def ideal_resource() -> Statevector:
    """Return a fresh, clean :math:`|\\Phi^{+}\\rangle` pair.

    The default ``resource_factory``. A separate named function rather than a
    lambda so that Phase 3 can wrap it -- ``lambda: attack(ideal_resource())`` --
    and so that a test can assert the default really is the ideal pair.

    Returns
    -------
    qiskit.quantum_info.Statevector
        :math:`(|00\\rangle + |11\\rangle)/\\sqrt{2}`, a new object per call.

    Examples
    --------
    >>> from sih141.protocol.distribute import ideal_resource
    >>> ideal_resource().data.round(6)
    array([0.707107+0.j, 0.      +0.j, 0.      +0.j, 0.707107+0.j])
    """
    return bell_state(BellState.PHI_PLUS)


def identity_payload(payload: StateLike, context: ResourceContext) -> StateLike:
    """Send exactly the eigenstate Alice prepared. The honest payload line.

    Semantically the default, though the default is spelled ``None`` so that an
    unattacked run calls nothing at all. It exists as a named function for the
    same two reasons :func:`ideal_resource` does: an attack can wrap it
    (``lambda state, ctx: damp(identity_payload(state, ctx))``), and a test can
    assert that the honest path really is the identity.

    Parameters
    ----------
    payload : StateLike
        The state about to be teleported.
    context : ResourceContext
        Which hop this is. **Ignored** -- an honest preparation does not depend
        on who is receiving it or where in the key it sits, and that is the
        whole content of "honest" here.

    Returns
    -------
    StateLike
        ``payload`` itself, identical by object identity.

    Examples
    --------
    >>> from sih141.protocol.distribute import ResourceContext, identity_payload
    >>> from sih141.protocol.keys import KeyElement
    >>> from sih141.protocol.params import Party
    >>> state = KeyElement("X", 1).state()
    >>> context = ResourceContext(party=Party.BOB, message_bit=0, position=3)
    >>> identity_payload(state, context) is state
    True
    """
    del context  # An honest preparation is the same wherever it is sent.
    return payload


def _adopt_state(state: StateLike) -> StateLike:
    """Read a seam's state **once**, into a copy the protocol owns.

    The one-line answer to the read-count side channel
    (:ref:`check-round-lockstep`). Equalising how often a seam is *called* was
    not enough: what the protocol then *did* with the returned object differed
    between the branches, so an adversary returning an instrumented state --
    a :class:`~qiskit.quantum_info.Statevector` subclass whose ``data``
    property increments a counter, say -- read the check set off the tally.
    A resource was read once on a key round (inside
    :func:`~sih141.core.teleport.teleport`) and twice on a check round (once to
    summarise the pair, once to measure it); a mapped payload was read once on a
    key round and not at all on a check round. Either tally separated the
    branches at precision 1.0.

    Counting reads downstream and matching them branch for branch would fix
    today's tally and break on the next edit that touches either branch. This
    does it by construction instead: the object a seam returns is read exactly
    once, here, before the branch is taken, and **nothing downstream ever
    touches it again** -- every later read is of a plain object this module
    built. The tally an adversary keeps is therefore ``1`` at every position of
    every link, which is a constant, and a constant carries no bits.

    Purity is preserved, because it is load-bearing: a pure payload handed to
    :func:`~sih141.core.teleport.teleport` as a
    :class:`~qiskit.quantum_info.Statevector` takes that function's exact
    fidelity path, and coercing everything to a density matrix here would
    silently move honest runs off it (D1). Dimensions are preserved for the
    same reason -- ``num_qubits`` is what
    :func:`~sih141.protocol.session._as_pair` refuses a non-pair on.

    Parameters
    ----------
    state : StateLike
        Whatever a seam returned: either Qiskit representation (D1), or a raw
        amplitude vector or density array.

    Returns
    -------
    StateLike
        The same state, same representation, same numbers, in an object backed
        by memory this module allocated. A seam that kept a handle on the array
        it returned can no longer write through it either, which closes the
        narrower "edit the pair after handing it over" route at the same time.
        Anything that is not a state and not array-like is passed through
        untouched, so the existing validator downstream still produces its own
        error message rather than one from here.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.distribute import _adopt_state, ideal_resource
    >>> pair = ideal_resource()
    >>> adopted = _adopt_state(pair)
    >>> type(adopted).__name__
    'Statevector'
    >>> bool(np.allclose(adopted.data, pair.data))
    True
    >>> adopted is pair
    False

    A counting subclass is read exactly once and then left alone:

    >>> from qiskit.quantum_info import Statevector
    >>> class Counting(Statevector):
    ...     reads = 0
    ...     @property
    ...     def data(self):
    ...         Counting.reads += 1
    ...         return self._data
    >>> adopted = _adopt_state(Counting(ideal_resource().data))
    >>> Counting.reads
    1
    >>> type(adopted).__name__
    'Statevector'
    """
    if isinstance(state, DensityMatrix):
        return DensityMatrix(
            np.array(state.data, copy=True), dims=state.dims()
        )
    if isinstance(state, Statevector):
        return Statevector(np.array(state.data, copy=True), dims=state.dims())
    try:
        return np.array(state, dtype=np.complex128)
    except (TypeError, ValueError):
        # Not a state and not array-like. Let it through: the validator it is
        # about to meet says what is wrong with it in the vocabulary of the
        # seam that produced it, and duplicating that message here would give
        # two different errors for one mistake.
        return state


def _map_payload(
    payload_map: PayloadMap | None,
    payload: StateLike,
    context: ResourceContext,
) -> StateLike:
    """Put one key round's payload through the seam, if there is one.

    Parameters
    ----------
    payload_map : callable or None
        The seam described at :ref:`payload-seam`. ``None`` skips the call
        entirely rather than routing through :func:`identity_payload`, so an
        unattacked run does not depend on the seam existing at all.
    payload : StateLike
        The eigenstate Alice prepared for this position.
    context : ResourceContext
        The hop being prepared for, quoted in the error message.

    Returns
    -------
    StateLike
        What will actually be teleported, **adopted** by
        :func:`_adopt_state`. The seam's own object is read once, here, on
        every position; the copy is what the branch below either teleports or
        discards. Being *used* was the signal once being *called* stopped
        being one -- a mapped payload is read by
        :func:`~sih141.core.teleport.teleport` on a key round and by nothing at
        all on a check round, so an instrumented state recovered the check set
        from its own read tally at precision 1.0
        (:ref:`check-round-lockstep`).

    Raises
    ------
    TypeError
        If ``payload_map`` is not callable.
    ValueError
        If it returned ``None``. ``teleport`` would raise on ``None`` anyway,
        but from inside the payload validator and without saying which position
        or which recipient produced it; a seam is worth naming when it
        misfires, because the alternative is an attack author reading a
        traceback about state coercion.
    """
    if payload_map is None:
        return payload
    if not callable(payload_map):
        raise TypeError(
            f"payload_map must be a callable payload_map(state, context) "
            f"returning a one-qubit state, got "
            f"{type(payload_map).__name__}. Leave it None for the honest "
            f"payload line, or pass identity_payload to say so explicitly."
        )
    mapped = payload_map(payload, context)
    if mapped is None:
        raise ValueError(
            f"payload_map returned None for {context.party.value} at key "
            f"position {context.position} of message bit "
            f"{context.message_bit}; it must return the one-qubit state to "
            f"teleport. Return the payload it was given -- or "
            f"identity_payload(state, context) -- to send the eigenstate "
            f"unaltered."
        )
    return _adopt_state(mapped)


def _resolve_factory(
    resource_factory: ResourceFactory | None,
) -> tuple[ResourceFactory, bool]:
    """Validate the injected factory and decide how it wants to be called.

    Parameters
    ----------
    resource_factory : callable or None
        The seam described in the module docstring.

    Returns
    -------
    callable
        ``resource_factory`` itself, or :func:`ideal_resource`.
    bool
        ``True`` when the callable accepts a positional
        :class:`ResourceContext`, ``False`` when it takes no arguments.

    Raises
    ------
    TypeError
        If ``resource_factory`` is neither ``None`` nor callable. A bare state
        is the likely mistake and the message says how to wrap it.

    Notes
    -----
    The arity is decided once, here, rather than by catching a
    :exc:`TypeError` at each call: a factory whose *body* raises
    :exc:`TypeError` must not be silently re-tried with a different signature.
    :func:`inspect.signature` refuses some C-implemented callables, which are
    then treated as zero-argument -- the historical shape, and the one every
    such callable in fact has.
    """
    if resource_factory is None:
        return ideal_resource, False
    if not callable(resource_factory):
        raise TypeError(
            f"resource_factory must be a callable returning a two-qubit state "
            f"-- either factory() or factory(context) -- got "
            f"{type(resource_factory).__name__}. It is invoked once per key "
            f"position so that the resource may vary along the run; to use one "
            f"fixed pair, wrap it: resource_factory=lambda: my_pair."
        )
    return resource_factory, accepts_context(resource_factory)


def accepts_context(resource_factory: ResourceFactory) -> bool:
    """Return ``True`` when ``resource_factory`` *requires* a positional argument.

    Public for the same reason
    :func:`sih141.protocol.session.forwarder_wants_view` is: which of the two
    shapes a seam has is part of the seam's contract, and a Phase 3 attack that
    mounts a bound method on ``resource_factory`` needs to be able to assert that
    the session will hand it the context.

    The test is "can it be called with no arguments at all?", not "can it accept
    one?". The difference matters: ``lambda pair=pair: pair`` is a common way to
    close over a fixed resource, and it *accepts* one positional argument
    although it wants none -- passing it a :class:`ResourceContext` would
    silently hand the context to ``teleport`` as the entanglement resource. So a
    callable that can be invoked with nothing is invoked with nothing, which is
    also the historical shape of the seam; only one that demands an argument
    gets the context.

    Parameters
    ----------
    resource_factory : callable
        The validated factory.

    Returns
    -------
    bool
        ``True`` if the callable cannot be invoked with zero arguments but can
        be invoked with one, ``False`` if it can be invoked with none.

    Raises
    ------
    TypeError
        If the callable accepts neither shape, which is a wiring error that
        would otherwise surface as a confusing failure inside ``teleport`` after
        the first hop.
    """
    try:
        signature = inspect.signature(resource_factory)
    except (TypeError, ValueError):
        # A C-implemented callable with no introspectable signature. Every such
        # callable in this codebase is zero-argument, and guessing the other way
        # would break the historical shape of the seam.
        return False
    try:
        signature.bind()
    except TypeError:
        pass
    else:
        return False
    try:
        signature.bind(
            ResourceContext(party=Party.BOB, message_bit=0, position=0)
        )
    except TypeError:
        raise TypeError(
            f"resource_factory must be callable either with no arguments or "
            f"with one positional ResourceContext, but {resource_factory!r} "
            f"accepts neither: its signature is {signature}. The context "
            f"carries the party, message bit and key position of the hop being "
            f"requested; a factory that does not want it should take no "
            f"arguments at all."
        ) from None
    return True


_accepts_context = accepts_context
"""Deprecated private alias of :func:`accepts_context`.

Kept because it was imported by name before the public spelling existed.
"""


def _draw_resource(
    resource_factory: ResourceFactory,
    wants_context: bool,
    context: ResourceContext,
) -> StateLike:
    """Call the factory for one key position and reject a ``None`` result.

    Parameters
    ----------
    resource_factory : callable
        The validated factory.
    wants_context : bool
        Whether to pass ``context`` positionally, as decided once by
        :func:`_resolve_factory`.
    context : ResourceContext
        The party, message bit and key position this hop belongs to. Quoted in
        the error message even when the factory did not ask for it.

    Returns
    -------
    StateLike
        What the factory returned, **adopted** by :func:`_adopt_state` -- same
        representation, same numbers, a copy this module owns. Its physicality
        and qubit count are still checked downstream, by
        :func:`sih141.core.teleport.teleport` on a key round and by
        :func:`~sih141.protocol.checkrounds.observe_qber_round` or
        :func:`~sih141.protocol.checkrounds.observe_chsh_round` on a check one.

        The adoption is the fix for the resource read-count side channel: the
        factory's object used to be read once on a key round and twice on a
        check round, so a factory returning an instrumented pair recovered the
        whole check set from its own read tally. It is now read exactly once,
        here, before the branch (:ref:`check-round-lockstep`). Every seam that
        hands the protocol an object crosses this boundary, including
        :class:`~sih141.protocol.session._ChannelTap` when it stands in for a
        session's factory, so the adoption happens once per crossing rather
        than once per run.

    Raises
    ------
    ValueError
        If the factory returned ``None``. Forwarding it would silently select
        the *ideal* pair inside :func:`~sih141.core.teleport.teleport`, so a
        mis-wired attack would look like a perfect channel and a Phase 3 test
        would pass vacuously.
    """
    resource = (
        resource_factory(context)  # type: ignore[call-arg]
        if wants_context
        else resource_factory()  # type: ignore[call-arg]
    )
    index = context.position
    if resource is None:
        raise ValueError(
            f"resource_factory returned None for key position {index}; it must "
            f"return a two-qubit entanglement resource. None is not forwarded "
            f"to teleport(), where it would silently select the ideal "
            f"|Phi+> pair -- a mis-wired attack would then be indistinguishable "
            f"from a clean channel. Return ideal_resource() explicitly if a "
            f"clean pair is what you meant."
        )
    return _adopt_state(resource)


def _resolve_verifier(party: Party | str) -> Party:
    """Coerce ``party`` to a :class:`Party` and refuse Alice.

    Parameters
    ----------
    party : Party or str
        The recipient this distribution run is for.

    Returns
    -------
    Party
        :attr:`Party.BOB` or :attr:`Party.CHARLIE`.

    Raises
    ------
    ValueError
        If ``party`` is :attr:`Party.ALICE` or names no party.
    TypeError
        If ``party`` is neither a :class:`Party` nor a string.

    Notes
    -----
    :class:`~sih141.protocol.records.RecipientRecord` refuses Alice too; the
    check is repeated here so that the refusal happens *before* a whole key is
    teleported rather than after.
    """
    resolved = _as_party(party)
    if resolved is Party.ALICE:
        raise ValueError(
            "cannot distribute a public key to Alice: she is the signer, "
            "prepares the states and keeps the private key, and never measures, "
            "so she has no record to build. Distribute to Party.BOB and "
            "Party.CHARLIE -- both, since transferability is a statement about "
            "a second verifier."
        )
    return resolved


@dataclass(frozen=True)
class RecipientDistribution:
    """Everything one recipient is left holding after Phase A.

    The full-information return of
    :func:`distribute_to_recipient_with_checks`: the classical log that carries
    key, and -- separately -- the classical log that carries channel
    diagnostics. They are separate objects because they have different
    audiences. The record is private evidence a verifier scores; the check log
    is **published**, and it is safe to publish precisely because its positions
    were spent on measurement and never entered the key.

    Attributes
    ----------
    record : RecipientRecord
        The recipient's key log, already sifted: ``plan.signing_length`` entries
        when a plan was in force, re-indexed to ``0 .. signing_length - 1``.
        Check it against ``params.sifted()``, not against ``params``.
    log : CheckLog
        The check-round observations. Empty on a run with no plan, which is the
        honest representation of "this run published no channel statistics".
    plan : CheckRoundPlan or None
        The plan that was executed, kept so that a caller can map a record index
        back to a run position through
        :attr:`~sih141.protocol.checkrounds.CheckRoundPlan.signing_positions`.
        ``None`` when no plan was given.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.checkrounds import draw_check_plan, estimate_qber
    >>> from sih141.protocol.distribute import (
    ...     distribute_to_recipient_with_checks
    ... )
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> params = ProtocolParams(key_length=64, check_fraction=0.25)
    >>> plan = draw_check_plan(params, rng=np.random.default_rng(1))
    >>> key = generate_private_key(params, 0, rng=np.random.default_rng(2))
    >>> outcome = distribute_to_recipient_with_checks(
    ...     key, params, party=Party.BOB, check_plan=plan,
    ...     rng=np.random.default_rng(3),
    ... )
    >>> len(outcome.record) == params.signing_length == 48
    True
    >>> outcome.record.check_against(params.sifted())

    The run reserves ``params.check_count`` positions; this link measures its
    own half of them and the other half are Charlie's
    (:ref:`sih141.protocol.checkrounds <check-round-links>`):

    >>> params.check_count, outcome.log.round_count
    (16, 8)
    >>> outcome.log.positions == plan.positions_for(Party.BOB)
    True
    >>> estimate_qber(outcome.log.qber).errors        # an ideal channel
    0
    """

    record: RecipientRecord
    log: CheckLog
    plan: CheckRoundPlan | None


def _resolve_plan(
    check_plan: CheckRoundPlan | None, params: ProtocolParams
) -> CheckRoundPlan | None:
    """Validate a check-round plan against the parameter set it will run under.

    Parameters
    ----------
    check_plan : CheckRoundPlan or None
        The plan, or ``None`` for a run with no sampled estimation.
    params : ProtocolParams
        The parameter set.

    Returns
    -------
    CheckRoundPlan or None
        ``check_plan`` unchanged.

    Raises
    ------
    TypeError
        If ``check_plan`` is neither ``None`` nor a
        :class:`~sih141.protocol.checkrounds.CheckRoundPlan`.
    ValueError
        If a plan disagrees with ``params`` about the key length or the check
        count, or if ``params`` asks for check rounds and no plan was supplied.

    Notes
    -----
    The second refusal is the important one, and it is a *security* check rather
    than tidiness. ``params.check_fraction > 0`` shortens
    :attr:`~sih141.protocol.params.ProtocolParams.signing_length`, and both
    matched-count floors are derived from that; distributing such a parameter
    set without actually holding check rounds back would produce a full-length
    record scored against floors sized for a shorter one -- every published
    bound weakened, silently, with nothing in the transcript to show it. So the
    combination is refused here, at the only boundary that can see both facts.
    """
    if check_plan is None:
        if params.has_check_rounds:
            raise ValueError(
                f"params.check_fraction is {params.check_fraction!r}, which "
                f"reserves {params.check_count} of {params.key_length} "
                f"positions for sampled parameter estimation and shortens the "
                f"effective key to {params.signing_length}, but no check_plan "
                f"was given. Distributing anyway would build a full-length "
                f"record and then score it against matched-count floors "
                f"computed for the shorter key -- every bound weakened with "
                f"nothing to show for it. Draw a plan from the RECIPIENTS' "
                f"stream: draw_check_plan(params, rng=recipient_rng). To run "
                f"without estimation, use params.with_check_fraction(0.0)."
            )
        return None
    if not isinstance(check_plan, CheckRoundPlan):
        raise TypeError(
            f"check_plan must be a CheckRoundPlan or None, got "
            f"{type(check_plan).__name__}. Draw one with "
            f"draw_check_plan(params, rng=...)."
        )
    if check_plan.key_length != params.key_length:
        raise ValueError(
            f"check_plan was drawn for a key length of "
            f"{check_plan.key_length} but params.key_length is "
            f"{params.key_length}. A plan indexes positions of one specific "
            f"run and is not portable to another length."
        )
    if check_plan.check_count != params.check_count:
        raise ValueError(
            f"check_plan designates {check_plan.check_count} check rounds but "
            f"params.check_fraction={params.check_fraction!r} implies "
            f"{params.check_count} at L={params.key_length}. The two must "
            f"agree: params.signing_length is what every matched-count floor "
            f"is derived from, and the plan is what actually decides how many "
            f"positions survive."
        )
    return check_plan


def distribute_to_recipient(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    party: Party | str,
    resource_factory: ResourceFactory | None = None,
    rng: np.random.Generator | None = None,
    check_plan: CheckRoundPlan | None = None,
    payload_map: PayloadMap | None = None,
) -> RecipientRecord:
    """Teleport one copy of the quantum public key and measure it on arrival.

    Runs Phase A for a single recipient. For each of the ``L`` key positions, in
    order:

    1. the recipient draws a measurement basis uniformly from ``params.bases``,
       independently of Alice and before the qubit lands;
    2. Alice prepares the eigenstate named by key element ``i`` and teleports it
       over a fresh pair from ``resource_factory``
       (:func:`sih141.core.teleport.teleport`);
    3. the recipient measures the received qubit **immediately**
       (:func:`sih141.core.measure.projective_measure`) and keeps only
       ``(i, basis, eigenvalue)``.

    The collapsed post-measurement state is discarded at the end of each
    iteration: the returned record is entirely classical, and after this call no
    quantum state from the run survives.

    Parameters
    ----------
    key : PrivateKey
        Alice's private key for one message bit. Its elements name the states to
        prepare; the key itself never leaves Alice in this phase.
    params : ProtocolParams
        The parameter set. Supplies the basis alphabet the recipient draws from
        and the key length the record is checked against.
    party : Party or str
        Keyword-only. :attr:`~sih141.protocol.params.Party.BOB` or
        :attr:`~sih141.protocol.params.Party.CHARLIE`. Required: a record is
        meaningless without the verifier it belongs to, and Alice is refused.
    resource_factory : callable or None, optional
        Keyword-only. Zero-argument callable returning the two-qubit
        entanglement resource for one hop, invoked once per key position.
        Defaults to :func:`ideal_resource`. This is the Phase 3 attack seam; see
        the module docstring.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Resolved through
        :func:`sih141.core.rng.resolve_rng`. Exactly three variates are consumed
        per key position: basis choice, Bell measurement, projective
        measurement.
    check_plan : CheckRoundPlan or None, optional
        Keyword-only. A plan drawn from the *recipients'* stream by
        :func:`~sih141.protocol.checkrounds.draw_check_plan`, designating which
        positions are spent on sampled parameter estimation instead of on key.
        Defaults to ``None``, which is the historical behaviour exactly. With a
        plan the returned record is already **sifted** and the check-round
        diagnostics are discarded -- use
        :func:`distribute_to_recipient_with_checks` to keep them, which is the
        only reason to pass a plan here at all.
    payload_map : callable or None, optional
        Keyword-only. The payload-line seam (:ref:`payload-seam`), called
        ``payload_map(state, context)`` once per **position** -- check rounds
        included, where what it returns is discarded -- with the eigenstate
        prepared for that position. ``None``, the default, calls nothing and
        sends the eigenstate itself. It draws no randomness *from this run's
        generator*; an attack that wants some closes over its own (D6), and
        will now advance that one on every position rather than on key rounds
        only.

    Returns
    -------
    RecipientRecord
        A classical log tagged with ``party`` and with ``key.message_bit``:
        ``len(key)`` entries indexed ``0 .. L-1`` without a plan, and
        ``check_plan.signing_length`` entries re-indexed from ``0`` with one.

    Raises
    ------
    ValueError
        If ``party`` is Alice or names no party; if ``key`` does not belong to
        ``params`` (length or alphabet mismatch, via
        :meth:`~sih141.protocol.keys.PrivateKey.check_against`); if
        ``resource_factory`` returns ``None``; if it returns something that is
        not a physical two-qubit state; if ``params`` reserves check rounds and
        no ``check_plan`` was given; or if a given plan disagrees with ``params``
        about the key length or the check count.
    TypeError
        If ``key`` is not a :class:`~sih141.protocol.keys.PrivateKey`, ``params``
        is not a :class:`~sih141.protocol.params.ProtocolParams`,
        ``resource_factory`` is not callable, ``check_plan`` is neither ``None``
        nor a :class:`~sih141.protocol.checkrounds.CheckRoundPlan`, or ``rng``
        is neither ``None`` nor a :class:`numpy.random.Generator`.

    See Also
    --------
    distribute_to_recipient_with_checks : Keeps the check-round diagnostics.
    distribute_public_key : Both recipients in protocol order.
    sih141.protocol.records.RecipientRecord.check_against : The reverse check.

    Notes
    -----
    On an ideal resource the hop is exact, so a matched position -- one where the
    recipient happened to choose Alice's basis -- reproduces her declared
    eigenvalue with probability one, and a noiseless honest run gives a mismatch
    rate of exactly ``0``. On the other ``1 - 1/|B|`` of positions the recipient
    measured a conjugate observable and the outcome is a fair coin carrying no
    information about the key; those positions are kept in the log but must be
    discarded at verification (:mod:`sih141.protocol.records` explains why
    counting them is the classic bug in this protocol family).

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.distribute import distribute_to_recipient
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> params = ProtocolParams(key_length=6)
    >>> key = generate_private_key(params, 0, rng=np.random.default_rng(1))
    >>> record = distribute_to_recipient(
    ...     key, params, party=Party.BOB, rng=np.random.default_rng(2)
    ... )
    >>> len(record), record.party, record.message_bit
    (6, <Party.BOB: 'Bob'>, 0)
    >>> matched = [
    ...     i for i in range(len(key)) if record.bases[i] == key.bases[i]
    ... ]
    >>> all(record.eigenvalues[i] == key.eigenvalues[i] for i in matched)
    True
    """
    return distribute_to_recipient_with_checks(
        key,
        params,
        party=party,
        resource_factory=resource_factory,
        rng=rng,
        check_plan=check_plan,
        payload_map=payload_map,
    ).record


def distribute_to_recipient_with_checks(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    party: Party | str,
    resource_factory: ResourceFactory | None = None,
    rng: np.random.Generator | None = None,
    check_plan: CheckRoundPlan | None = None,
    payload_map: PayloadMap | None = None,
) -> RecipientDistribution:
    """Run Phase A for one recipient, keeping the check-round diagnostics.

    The full-information form of :func:`distribute_to_recipient`, which is a
    thin wrapper over this. Every position draws a resource from the seam and
    puts a payload through the payload seam; the plan then decides what that
    resource is spent on:

    * a **key round** teleports the key element and the recipient measures what
      arrives, exactly as before;
    * a **check round** measures both halves of the pair instead
      (:func:`~sih141.protocol.checkrounds.observe_qber_round` or
      :func:`~sih141.protocol.checkrounds.observe_chsh_round`), discards the
      payload the seam returned, and contributes nothing to the record.

    A plan reserves positions for the run and designates which of them **this
    link** measures (:ref:`sih141.protocol.checkrounds <check-round-links>`).
    A reserved position designated for the *other* link runs as a key round
    here and is then dropped from the record, since the signing key does not
    contain it either.

    See :ref:`check-round-lockstep` for the three invariants that keep the two
    branches indistinguishable from outside, and
    :mod:`sih141.protocol.checkrounds` for what the diagnostics mean.

    Parameters
    ----------
    key : PrivateKey
        Alice's **full-length** key for one message bit. She draws all ``L``
        elements because she does not know which positions the recipients will
        check; the ones that land on this link's check rounds are prepared and
        then thrown away, because the payload seam is offered every position
        (:ref:`payload-seam`) and a seam offered fewer would publish the gaps.
    params : ProtocolParams
        The parameter set.
    party : Party or str
        Keyword-only. The recipient. Alice is refused.
    resource_factory : callable or None, optional
        Keyword-only. The Phase 3 attack seam, called once per position on both
        branches alike.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). Exactly three variates per position, on both
        branches.
    check_plan : CheckRoundPlan or None, optional
        Keyword-only. The plan, whose reserved *set* is shared by both
        recipients of a message bit and whose rounds are dealt between their
        links (:ref:`sih141.protocol.checkrounds <check-round-links>`).
        ``None`` runs the historical all-key distribution and returns an empty
        log.
    payload_map : callable or None, optional
        Keyword-only. The payload-line seam (:ref:`payload-seam`), called
        ``payload_map(state, context)`` once per **position** -- check rounds
        included, where what it returns is discarded -- with the eigenstate
        prepared for that position. ``None``, the default, calls nothing and
        sends the eigenstate itself. It draws no randomness *from this run's
        generator*; an attack that wants some closes over its own (D6), and
        will now advance that one on every position rather than on key rounds
        only.

    Returns
    -------
    RecipientDistribution
        The sifted record, the check log, and the plan that produced them.

    Raises
    ------
    ValueError
        As :func:`distribute_to_recipient`.
    TypeError
        As :func:`distribute_to_recipient`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.checkrounds import draw_check_plan, estimate_chsh
    >>> from sih141.protocol.distribute import (
    ...     distribute_to_recipient_with_checks
    ... )
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> params = ProtocolParams(key_length=800, check_fraction=0.5)
    >>> plan = draw_check_plan(params, rng=np.random.default_rng(41))
    >>> key = generate_private_key(params, 1, rng=np.random.default_rng(42))
    >>> outcome = distribute_to_recipient_with_checks(
    ...     key, params, party=Party.CHARLIE, check_plan=plan,
    ...     rng=np.random.default_rng(43),
    ... )
    >>> len(outcome.record), outcome.log.round_count
    (400, 200)
    >>> estimate_chsh(outcome.log.chsh).violates_classical_bound
    True

    The payload seam sees every position, in order, and so learns nothing about
    which of them the plan reserved:

    >>> small = ProtocolParams(key_length=40, check_fraction=0.25)
    >>> small_plan = draw_check_plan(small, rng=np.random.default_rng(1))
    >>> small_key = generate_private_key(small, 0, rng=np.random.default_rng(2))
    >>> seen = []
    >>> def watch(state, context):
    ...     seen.append(context.position)
    ...     return state
    >>> watched = distribute_to_recipient_with_checks(
    ...     small_key, small, party=Party.BOB, check_plan=small_plan,
    ...     payload_map=watch, rng=np.random.default_rng(3),
    ... )
    >>> seen == list(range(40))
    True
    >>> set(seen) >= set(small_plan.positions)
    True
    """
    if not isinstance(key, PrivateKey):
        raise TypeError(
            f"key must be a PrivateKey, got {type(key).__name__}. Draw one with "
            f"generate_private_key(params, message_bit, rng=...)."
        )
    if not isinstance(params, ProtocolParams):
        raise TypeError(
            f"params must be a ProtocolParams, got {type(params).__name__}"
        )
    recipient = _resolve_verifier(party)
    key.check_against(params)
    plan = _resolve_plan(check_plan, params)
    factory, wants_context = _resolve_factory(resource_factory)
    generator = resolve_rng(rng)

    alphabet = params.bases
    chosen_bases: list[PauliBasis] = []
    eigenvalues: list[int] = []
    qber_seen: list[QberObservation] = []
    chsh_seen: list[ChshObservation] = []
    # What THIS link spends on the channel, and what the RUN reserves. They
    # differ on a split plan: a position reserved for the other link is an
    # ordinary key round here whose outcome is dropped, because it carries no
    # key either way (:ref:`sih141.protocol.checkrounds <check-round-links>`).
    planned = {} if plan is None else plan.rounds_by_position(recipient)
    reserved: frozenset[int] = (
        frozenset() if plan is None else frozenset(plan.positions)
    )

    for index, element in enumerate(key.elements):
        # 1. The recipient commits to a basis before the qubit arrives; his draw
        #    is independent of Alice's and is what makes the matched set random.
        #    It is made on EVERY position, check rounds included, and discarded
        #    there: the draw must not be correlated with the round's role, and
        #    the constant variate budget is what keeps a checked run and an
        #    unchecked one in lockstep (:ref:`check-round-lockstep`).
        basis = alphabet[int(generator.integers(len(alphabet)))]

        # 2. One resource per position, drawn from the seam BEFORE the branch
        #    below, with a context that says nothing about which branch it is,
        #    and READ ONCE on the way in -- _draw_resource adopts it, so what
        #    the branch below teleports or measures is this module's copy and
        #    the seam's own object is never touched again. An adversary who
        #    could tell a watched round from an unwatched one would behave on
        #    the watched ones and every estimate here would be fiction, so the
        #    call is deliberately identical on both branches and so, now, is
        #    the use made of what it returned.
        context = ResourceContext(
            party=recipient,
            message_bit=key.message_bit,
            position=index,
        )
        resource = _draw_resource(factory, wants_context, context)

        # 3. The payload seam stands on EVERY position, before the branch and
        #    after the resource has been drawn, so that the two seams see the
        #    same hop in the same order and neither can tell the branches apart.
        #    Alice re-prepares the eigenstate from its classical label
        #    (preparation, not cloning) and hands it over as a Statevector,
        #    which is teleport()'s exact fidelity path for a pure payload. On a
        #    check round the mapped state is DISCARDED, unteleported and
        #    unmeasured -- the pair is spent on the channel instead -- exactly
        #    as the recipient's basis draw above is made and discarded. Both
        #    the call AND the read have to be identical: the call used to be
        #    made on key rounds only, and the gaps in the call sequence were
        #    the check set, recovered whole; once that was closed, being USED
        #    became the same signal, because a mapped payload was read by
        #    teleport() on a key round and by nothing on a check round. So
        #    _map_payload adopts what the seam returned -- one read, every
        #    position -- and what is discarded below is this module's copy
        #    (:ref:`payload-seam`).
        payload = _map_payload(payload_map, element.state(), context)

        scheduled = planned.get(index)
        if scheduled is None:
            # 3a. Key round: a genuine teleportation. The received state is a
            #     one-qubit density matrix, so the measured index is 0 (D2).
            hop = teleport(payload, resource=resource, rng=generator)
            outcome = projective_measure(hop.received, 0, basis, rng=generator)
            if index not in reserved:
                chosen_bases.append(basis)
                eigenvalues.append(outcome.eigenvalue)
            # A position reserved for the OTHER link falls through here with
            # nothing appended. It was teleported and measured like any key
            # round -- which is what makes it indistinguishable from one -- but
            # it is not in the signing key, so recording it would leave this
            # record longer than the declaration it is scored against.
            #
            # `hop` and `outcome.post_state` are rebound on the next iteration
            # and never stored: no quantum memory is retained anywhere (see the
            # module docstring). Only the two classical columns above survive.
        elif isinstance(scheduled, QberRound):
            # 3b. Check round, QBER arm. The pair is spent here and `payload`
            #     goes no further, which is why the position carries no key and
            #     is safe to publish.
            qber_seen.append(
                observe_qber_round(resource, scheduled, rng=generator)
            )
        elif isinstance(scheduled, ChshRound):
            # 3c. Check round, CHSH arm.
            chsh_seen.append(
                observe_chsh_round(resource, scheduled, rng=generator)
            )
        else:
            # Unreachable through draw_check_plan, and stated rather than
            # assumed: a future third check role that reached this loop without
            # a branch would otherwise be silently dropped, quietly shrinking
            # the published sample while the key stayed sifted for it.
            raise TypeError(
                f"check_plan schedules an unknown kind of round at position "
                f"{index}: {type(scheduled).__name__}. Expected a QberRound or "
                f"a ChshRound."
            )

    return RecipientDistribution(
        record=RecipientRecord.from_measurements(
            recipient, key.message_bit, chosen_bases, eigenvalues
        ),
        log=CheckLog(
            party=recipient,
            message_bit=key.message_bit,
            qber=tuple(qber_seen),
            chsh=tuple(chsh_seen),
        ),
        plan=plan,
    )


def distribute_public_key(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    parties: Sequence[Party | str] = VERIFIERS,
    resource_factory: ResourceFactory | None = None,
    rng: np.random.Generator | None = None,
    check_plan: CheckRoundPlan | None = None,
    payload_map: PayloadMap | None = None,
) -> dict[Party, RecipientRecord]:
    """Distribute one copy of the public key to each recipient.

    Calls :func:`distribute_to_recipient` once per party, in the order given,
    threading a single generator through all of them so that one seed reproduces
    the whole distribution phase. Each call re-prepares every eigenstate from the
    private key's classical description and consumes its own fresh entanglement,
    so the two recipients hold two independent preparations rather than two
    halves of anything shared -- see the module docstring on why that is not
    cloning.

    Parameters
    ----------
    key : PrivateKey
        Alice's private key for one message bit.
    params : ProtocolParams
        The parameter set.
    parties : sequence of Party or str, optional
        Keyword-only. Defaults to
        :data:`~sih141.protocol.params.VERIFIERS`, i.e. ``(Bob, Charlie)``.
        Charlie is not optional in a meaningful run: transferability is a claim
        about a second verifier.
    resource_factory : callable or None, optional
        Keyword-only. Shared by every party's run, and invoked once per key
        position *per party* -- ``len(parties) * len(key)`` times in total, in
        the order ``parties`` gives. An attack that targets one recipient and
        not the other should take a :class:`ResourceContext` and switch on
        ``context.party`` rather than count calls: the ordering is documented
        but is not a contract, and a context-free factory that infers the party
        from a call counter would silently follow a re-ordering to the wrong
        target.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3).
    check_plan : CheckRoundPlan or None, optional
        Keyword-only. Shared by every party, which is not an optimisation: the
        two recipients' records are exchanged position by position during
        symmetrisation and scored against one declaration, so they must retain
        the *same* positions or they stop indexing the same key.
        :class:`~sih141.protocol.checkrounds.CheckRoundPlan` explains the
        reasoning in full. The diagnostics are discarded here; use
        :func:`distribute_public_key_with_checks` to keep them.
    payload_map : callable or None, optional
        Keyword-only. The payload-line seam (:ref:`payload-seam`), called
        ``payload_map(state, context)`` once per **position** -- check rounds
        included, where what it returns is discarded -- with the eigenstate
        prepared for that position. ``None``, the default, calls nothing and
        sends the eigenstate itself. It draws no randomness *from this run's
        generator*; an attack that wants some closes over its own (D6), and
        will now advance that one on every position rather than on key rounds
        only.

    Returns
    -------
    dict of Party to RecipientRecord
        One **raw** record per party, keyed by
        :class:`~sih141.protocol.params.Party`, in the order given, and already
        sifted when a plan was in force. Pass the pair through
        :func:`sih141.protocol.symmetrise.symmetrise_records` before verifying:
        two raw logs support no non-repudiation claim, and
        :func:`sih141.protocol.verify.verify_all` refuses them.

    Raises
    ------
    ValueError
        If ``parties`` is empty, holds a duplicate, or holds Alice; or for any
        reason :func:`distribute_to_recipient` raises.
    TypeError
        If ``parties`` is not a sequence of parties, or as
        :func:`distribute_to_recipient`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.distribute import distribute_public_key
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> params = ProtocolParams(key_length=8)
    >>> key = generate_private_key(params, 1, rng=np.random.default_rng(3))
    >>> records = distribute_public_key(key, params, rng=np.random.default_rng(4))
    >>> sorted(records)
    [<Party.BOB: 'Bob'>, <Party.CHARLIE: 'Charlie'>]
    >>> records[Party.BOB].bases == records[Party.CHARLIE].bases
    False
    """
    return {
        party: outcome.record
        for party, outcome in distribute_public_key_with_checks(
            key,
            params,
            parties=parties,
            resource_factory=resource_factory,
            rng=rng,
            check_plan=check_plan,
            payload_map=payload_map,
        ).items()
    }


def distribute_public_key_with_checks(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    parties: Sequence[Party | str] = VERIFIERS,
    resource_factory: ResourceFactory | None = None,
    rng: np.random.Generator | None = None,
    check_plan: CheckRoundPlan | None = None,
    payload_map: PayloadMap | None = None,
) -> dict[Party, RecipientDistribution]:
    """Distribute to each recipient, keeping every check-round diagnostic.

    The full-information form of :func:`distribute_public_key`, which is a thin
    wrapper over this. One generator is threaded through every party, so one
    seed reproduces the whole distribution phase, and one plan is executed on
    every link, so the two recipients retain the same positions -- while each
    measuring only the reserved rounds dealt to *its* link
    (:ref:`sih141.protocol.checkrounds <check-round-links>`), so that learning
    one link's check set does not hand over the other's.

    The two logs it returns are **separate samples of two different channels**,
    and should stay separate unless the links are believed identical: pooling
    Bob's and Charlie's check rounds into one rate reports the average of two
    things and detects neither, which is precisely the shape of a one-sided
    attack.

    Parameters
    ----------
    key : PrivateKey
        Alice's full-length key for one message bit.
    params : ProtocolParams
        The parameter set.
    parties : sequence of Party or str, optional
        Keyword-only. Defaults to
        :data:`~sih141.protocol.params.VERIFIERS`.
    resource_factory : callable or None, optional
        Keyword-only. Shared by every party's run, and invoked once per position
        *per party* on both branches alike.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3).
    check_plan : CheckRoundPlan or None, optional
        Keyword-only. Shared by every party; see
        :func:`distribute_public_key`.
    payload_map : callable or None, optional
        Keyword-only. The payload-line seam (:ref:`payload-seam`), called
        ``payload_map(state, context)`` once per **position** -- check rounds
        included, where what it returns is discarded -- with the eigenstate
        prepared for that position. ``None``, the default, calls nothing and
        sends the eigenstate itself. It draws no randomness *from this run's
        generator*; an attack that wants some closes over its own (D6), and
        will now advance that one on every position rather than on key rounds
        only.

    Returns
    -------
    dict of Party to RecipientDistribution
        One record, one check log and the plan, per party.

    Raises
    ------
    ValueError
        If ``parties`` is empty, holds a duplicate, or holds Alice; or for any
        reason :func:`distribute_to_recipient_with_checks` raises.
    TypeError
        If ``parties`` is not a sequence of parties, or as
        :func:`distribute_to_recipient_with_checks`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.protocol.checkrounds import draw_check_plan, estimate_qber
    >>> from sih141.protocol.distribute import (
    ...     distribute_public_key_with_checks
    ... )
    >>> from sih141.protocol.keys import generate_private_key
    >>> from sih141.protocol.params import Party, ProtocolParams
    >>> params = ProtocolParams(key_length=200, check_fraction=0.5)
    >>> plan = draw_check_plan(params, rng=np.random.default_rng(8))
    >>> key = generate_private_key(params, 0, rng=np.random.default_rng(9))
    >>> outcomes = distribute_public_key_with_checks(
    ...     key, params, check_plan=plan, rng=np.random.default_rng(10)
    ... )

    The two links measure disjoint halves of the reserved set, and between them
    all of it (:ref:`sih141.protocol.checkrounds <check-round-links>`):

    >>> bob = set(outcomes[Party.BOB].log.positions)
    >>> charlie = set(outcomes[Party.CHARLIE].log.positions)
    >>> bob & charlie, bob | charlie == set(plan.positions)
    (set(), True)
    >>> estimate_qber(outcomes[Party.BOB].log.qber).estimate
    0.0
    """
    if isinstance(parties, (str, bytes)) or not isinstance(parties, Sequence):
        raise TypeError(
            f"parties must be a sequence of Party members, got "
            f"{type(parties).__name__}; the default is VERIFIERS, "
            f"(Party.BOB, Party.CHARLIE)."
        )
    resolved = [_resolve_verifier(party) for party in parties]
    if not resolved:
        raise ValueError(
            "parties must name at least one recipient; distributing to nobody "
            "produces no record and no verification is possible."
        )
    if len(set(resolved)) != len(resolved):
        raise ValueError(
            f"parties must be distinct, got "
            f"{[party.value for party in resolved]}. One recipient holds one "
            f"record per message bit; a repeat would silently overwrite it."
        )
    generator = resolve_rng(rng)
    return {
        party: distribute_to_recipient_with_checks(
            key,
            params,
            party=party,
            resource_factory=resource_factory,
            rng=generator,
            check_plan=check_plan,
            payload_map=payload_map,
        )
        for party in resolved
    }
