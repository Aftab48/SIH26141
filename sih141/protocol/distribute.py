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
    measurement. The count does not depend on the resource, so for a fixed seed
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
from qiskit.quantum_info import Statevector

from sih141.core.measure import projective_measure
from sih141.core.paulis import PauliBasis
from sih141.core.rng import resolve_rng
from sih141.core.states import BellState, StateLike, bell_state
from sih141.core.teleport import teleport
from sih141.protocol.keys import PrivateKey
from sih141.protocol.params import (
    VERIFIERS,
    Party,
    ProtocolParams,
    _as_party,
)
from sih141.protocol.records import RecipientRecord

__all__ = [
    "ResourceContext",
    "ResourceFactory",
    "ideal_resource",
    "distribute_to_recipient",
    "distribute_public_key",
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
    return resource_factory, _accepts_context(resource_factory)


def _accepts_context(resource_factory: ResourceFactory) -> bool:
    """Return ``True`` when ``resource_factory`` *requires* a positional argument.

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
        Whatever the factory returned; its physicality and qubit count are
        checked by :func:`sih141.core.teleport.teleport`.

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
    return resource


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


def distribute_to_recipient(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    party: Party | str,
    resource_factory: ResourceFactory | None = None,
    rng: np.random.Generator | None = None,
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

    Returns
    -------
    RecipientRecord
        A classical log of ``len(key)`` entries, indexed ``0 .. L-1``, tagged
        with ``party`` and with ``key.message_bit``.

    Raises
    ------
    ValueError
        If ``party`` is Alice or names no party; if ``key`` does not belong to
        ``params`` (length or alphabet mismatch, via
        :meth:`~sih141.protocol.keys.PrivateKey.check_against`); if
        ``resource_factory`` returns ``None``; or if it returns something that is
        not a physical two-qubit state.
    TypeError
        If ``key`` is not a :class:`~sih141.protocol.keys.PrivateKey`, ``params``
        is not a :class:`~sih141.protocol.params.ProtocolParams`,
        ``resource_factory`` is not callable, or ``rng`` is neither ``None`` nor
        a :class:`numpy.random.Generator`.

    See Also
    --------
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
    factory, wants_context = _resolve_factory(resource_factory)
    generator = resolve_rng(rng)

    alphabet = params.bases
    chosen_bases: list[PauliBasis] = []
    eigenvalues: list[int] = []

    for index, element in enumerate(key.elements):
        # 1. The recipient commits to a basis before the qubit arrives; his draw
        #    is independent of Alice's and is what makes the matched set random.
        basis = alphabet[int(generator.integers(len(alphabet)))]

        # 2. A genuine teleportation over a fresh pair. Alice re-prepares the
        #    eigenstate from its classical label (preparation, not cloning) and
        #    hands it over as a Statevector, which is teleport()'s exact
        #    fidelity path for a pure payload.
        hop = teleport(
            element.state(),
            resource=_draw_resource(
                factory,
                wants_context,
                ResourceContext(
                    party=recipient,
                    message_bit=key.message_bit,
                    position=index,
                ),
            ),
            rng=generator,
        )

        # 3. Immediate measurement. The received state is a one-qubit density
        #    matrix, so the measured index is 0 (D2).
        outcome = projective_measure(hop.received, 0, basis, rng=generator)

        chosen_bases.append(basis)
        eigenvalues.append(outcome.eigenvalue)
        # `hop` and `outcome.post_state` are rebound on the next iteration and
        # never stored: no quantum memory is retained anywhere (see the module
        # docstring). Only the two classical columns above survive the loop.

    return RecipientRecord.from_measurements(
        recipient, key.message_bit, chosen_bases, eigenvalues
    )


def distribute_public_key(
    key: PrivateKey,
    params: ProtocolParams,
    *,
    parties: Sequence[Party | str] = VERIFIERS,
    resource_factory: ResourceFactory | None = None,
    rng: np.random.Generator | None = None,
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

    Returns
    -------
    dict of Party to RecipientRecord
        One **raw** record per party, keyed by
        :class:`~sih141.protocol.params.Party`, in the order given. Pass the
        pair through
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
        party: distribute_to_recipient(
            key,
            params,
            party=party,
            resource_factory=resource_factory,
            rng=generator,
        )
        for party in resolved
    }
