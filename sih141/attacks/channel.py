"""Channel manipulation: an eavesdropper between Alice and one recipient.

Phase 3's adversary on the *wire*. Everything in this module attacks the
distribution of Phase A and nothing else: it never touches a key, a record, a
declaration, a matched count or a verdict, because an eavesdropper on a
teleportation link cannot reach any of those. What it can reach is the
entanglement resource each hop consumes and the payload line that hop carries,
and this project exposes exactly those two seams --
:data:`~sih141.protocol.distribute.ResourceFactory` and
:data:`~sih141.protocol.distribute.PayloadMap` -- so an attack is a state
transformation and not a reimplementation of the distribution loop.

Four attacks, two seams, one targeting knob
-------------------------------------------
=============================  =====================================================
:class:`DepolarisingChannel`   A Pauli twirl. ``strength`` p of the hops take a
                               uniformly drawn Pauli; the ensemble is the Werner
                               resource :math:`(1-p)|\\Phi^+\\rangle\\langle\\Phi^+| + p I/4`.
:class:`InterceptResend`       Eve measures the travelling half in a Pauli basis of
                               her choosing and re-sends what she found.
:class:`KeptShareSwap`         Eve copies the travelling half onto an ancilla she
                               keeps, leaving a GHZ whose two-qubit marginal is
                               what Alice and the recipient share.
=============================  =====================================================

Each is mounted on either seam through a bound method -- ``attack.resource`` for
:data:`~sih141.protocol.distribute.ResourceFactory`, ``attack.payload`` for
:data:`~sih141.protocol.distribute.PayloadMap` -- and each takes ``target``,
which restricts it to one recipient's link via
:attr:`~sih141.protocol.distribute.ResourceContext.party`. That is the
party-targeted attack; it is a parameter rather than a fourth class because
targeting is orthogonal to physics and a class per combination would be twelve
classes saying three things.

.. _channel-two-lines:

The two lines are not equally visible, and that is structural
-------------------------------------------------------------
A check round spends its pair on measuring the channel, so the resource seam is
called on it. A check round prepares no payload, so the payload seam is **not**
(:ref:`sih141.protocol.distribute <payload-seam>`). The consequence is worth
stating as a number rather than a sentiment: at equal damage to the key, a
resource-line attack moves the published QBER and CHSH estimates and a
payload-line attack moves neither. See :func:`payload_line_is_unwatched` for the
measured version and the module's Phase 4 notes below.

.. _channel-tensor:

Predicting all of it from one 3-vector
--------------------------------------
Every resource this module produces is Bell-diagonal or a collapse of one, so
its correlation tensor is diagonal: :math:`T = \\mathrm{diag}(T_{xx}, T_{yy},
T_{zz})` with :math:`T_{bb} = \\langle \\sigma_b \\otimes \\sigma_b \\rangle`.
Both published statistics follow from those three numbers alone.

**CHSH.** With the shipped settings (Alice at :math:`0, \\pi/2`; the recipient at
:math:`\\pm\\pi/4`) the observable at angle :math:`\\theta` is
:math:`\\cos\\theta\\,Z + \\sin\\theta\\,X`, so

.. math::

    E(\\theta_a, \\theta_b) = T_{zz}\\cos\\theta_a\\cos\\theta_b
                            + T_{xx}\\sin\\theta_a\\sin\\theta_b ,

and the four cells collapse to :math:`S = \\sqrt{2}\\,(T_{zz} + T_{xx})`. The
:math:`y` axis never enters: the settings lie in the :math:`x`-:math:`z` plane.
:func:`chsh_from_tensor` is that identity.

**QBER.** A QBER round draws a basis :math:`b` uniformly and scores an error
when the product of the two eigenvalues differs from
:data:`~sih141.protocol.checkrounds.IDEAL_PAULI_CORRELATION`, whose signs are
:math:`s = (+1, -1, +1)`. So :math:`P(\\text{error} \\mid b) = (1 - s_b
T_{bb})/2`, and averaging over the three bases gives
:func:`qber_from_tensor`.

Two tensors generate every number this module reports:

* :func:`depolarising_tensor` -- :math:`(1-p)\\,(1, -1, 1)`, the Werner family;
* :func:`collapse_tensor` -- the average of the signed unit tensors of the axes
  Eve draws from, which is what *both* :class:`InterceptResend` and
  :class:`KeptShareSwap` leave behind.

That coincidence is not an accident and it is a Phase 4 result: measuring one
half of :math:`|\\Phi^+\\rangle` in axis :math:`a` and re-sending, and dephasing
that half into a retained ancilla in axis :math:`a`, produce the *same* average
state. The two attacks are therefore indistinguishable to the QBER arm and to
the CHSH arm, at every sample size. They are told apart only by
:attr:`~sih141.protocol.session.ChannelSample.purity`, because intercept-resend
leaves a *pure* product state on each round while the kept share leaves a rank-2
mixture. See :ref:`channel-detector-signals`.

.. _channel-detector-signals:

What Phase 4 can actually see
------------------------------
Reachable from a :class:`~sih141.protocol.session.SessionTranscript` alone:

==========================  ========================================================
signal                      where it lives
==========================  ========================================================
QBER per link               :meth:`SessionTranscript.check_log_for`, one
                            :class:`~sih141.protocol.checkrounds.CheckLog` per
                            ``(party, message_bit)``, through
                            :func:`~sih141.protocol.checkrounds.estimate_qber`.
CHSH per link               the same logs through
                            :func:`~sih141.protocol.checkrounds.estimate_chsh`.
resource fidelity/purity/   :attr:`SessionTranscript.channel`, one
concurrence                 :class:`~sih141.protocol.session.ChannelSample` per
                            check round. Recorded on every **checked** run, with
                            or without a ``channel_monitor``; the monitor only
                            adds :attr:`~sih141.protocol.session.ChannelSample.extra`.
                            A run with ``check_fraction = 0`` publishes none.
verification rate           :attr:`~sih141.protocol.verify.VerificationResult.rate`,
                            always present.
==========================  ========================================================

The three built-in summaries separate all four attacks where the two correlators
cannot, and this is the table Phase 4 should threshold on. Means over the check
rounds of one link:

=========================  ==========  ========  ============
resource                   fidelity    purity    concurrence
=========================  ==========  ========  ============
clean pair                 ``1.00``    ``1.00``  ``1.00``
depolarising ``p``         ``1-3p/4``  ``1.00``  ``1.00``
intercept-resend           ``0.50``    ``1.00``  ``0.00``
kept share                 ``0.50``    ``0.50``  ``0.00``
=========================  ==========  ========  ============

Two consequences worth stating. **Purity and concurrence are blind to a
depolarising channel**: a Pauli-twirled Bell pair is still a Bell pair, so only
fidelity moves, and it moves to ``0`` on the engaged rounds rather than drifting.
And :attr:`~sih141.protocol.session.ChannelSample.wings_agree` is **not** a
detector for any of these. It is documented as the signature of a channel that
acted on one leg, and all three of these do act on one leg -- but the pair they
act on is maximally entangled, so collapsing or mixing the travelling half
disturbs Alice's half exactly as much. All four rows above have
``alice_purity == recipient_purity``.

**The check logs are per-party and are taken before Phase A'.** Symmetrisation
swaps *records*; it never touches a :class:`~sih141.protocol.checkrounds.CheckLog`.
So a party-targeted attack that is smeared across both post-exchange records --
one link at strength ``q`` looking like two links at ``q/2`` in the verification
rates -- is **not** smeared in the check logs, and per-link attribution survives.
:func:`attribution_survives_symmetrisation` measures both halves of that claim
in one run.

Notes
-----
Convention D6
    Every class here takes its own keyword-only ``rng`` and draws from nothing
    else. The per-hop draw is sequential rather than keyed on the context, which
    is safe because the sequence of hops -- both message bits, both recipients,
    every position, check rounds included -- is fixed by the loop and does not
    depend on the session's seed. :func:`sih141.attacks.isolation.check_attack_isolation`
    is what actually establishes this, and ``tests/test_attack_channel.py``
    applies it to every class in the module.
Convention D4
    No model is fitted to anything. Every predicted number in this file comes
    out of the two-line derivation above.
Qubit ordering (D2)
    Resource qubit ``0`` is Alice's half and qubit ``1`` is the half that
    travels, matching :mod:`sih141.protocol.checkrounds` and
    :class:`~sih141.protocol.session.ChannelSample`. An attack on the wire
    touches qubit ``1`` only, which is what makes
    :attr:`~sih141.protocol.session.ChannelSample.wings_agree` mean something.

Examples
--------
The reference values, all four, from the identity rather than from a fit:

>>> from sih141.attacks.channel import (
...     chsh_from_tensor, collapse_tensor, depolarising_tensor
... )
>>> f"{chsh_from_tensor(depolarising_tensor(0.0)):.4f}"
'2.8284'
>>> f"{chsh_from_tensor(depolarising_tensor(0.3)):.4f}"
'1.9799'
>>> f"{chsh_from_tensor(collapse_tensor()):.4f}"
'0.9428'
>>> f"{chsh_from_tensor(collapse_tensor(('Z',))):.4f}"
'1.4142'
"""

from __future__ import annotations

import math
import numbers
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, TypeAlias

import numpy as np
from qiskit.quantum_info import DensityMatrix, Operator, Statevector

from sih141.core.paulis import PauliBasis, pauli_matrix
from sih141.core.rng import resolve_rng
from sih141.core.states import BellState, StateLike, as_density, bell_state
from sih141.protocol.checkrounds import (
    ChshEstimate,
    ChshRound,
    QberEstimate,
    QberRound,
    estimate_chsh,
    estimate_qber,
    observe_chsh_round,
    observe_qber_round,
)
from sih141.protocol.distribute import ResourceContext
from sih141.protocol.params import Party, ProtocolParams, _as_party
from sih141.protocol.symmetrise import no_symmetrisation

__all__ = [
    "PAULI_AXES",
    "IDEAL_TENSOR",
    "AttackDecision",
    "ChannelAttack",
    "DepolarisingChannel",
    "InterceptResend",
    "KeptShareSwap",
    "CorrelationTensor",
    "attribution_survives_symmetrisation",
    "chsh_from_tensor",
    "collapse_tensor",
    "depolarising_tensor",
    "measure_chsh",
    "measure_qber",
    "payload_line_is_unwatched",
    "qber_from_tensor",
]


PAULI_AXES: Final[tuple[PauliBasis, PauliBasis, PauliBasis]] = (
    PauliBasis.X,
    PauliBasis.Y,
    PauliBasis.Z,
)
"""The three axes an eavesdropper draws from unless told otherwise.

The same alphabet the protocol itself uses, which is the point: an Eve who
guesses from a *smaller* set is more often caught by the QBER arm, and one who
guesses from a larger set does not exist.
"""

CorrelationTensor: TypeAlias = tuple[float, float, float]
"""``(T_xx, T_yy, T_zz)``, the diagonal of a Bell-diagonal correlation tensor."""

IDEAL_TENSOR: Final[CorrelationTensor] = (1.0, -1.0, 1.0)
""":math:`|\\Phi^{+}\\rangle`'s tensor: correlated in :math:`X` and :math:`Z`,
**anti**-correlated in :math:`Y`.

The sign on :math:`y` is the one that is easy to get wrong and the one that
makes :func:`qber_from_tensor` return ``0.0`` on a clean channel rather than
``1/3``. It is the same statement
:data:`~sih141.protocol.checkrounds.IDEAL_PAULI_CORRELATION` makes, in vector
form.
"""

#: Resource qubit Alice keeps (D2).
_ALICE_QUBIT: Final[int] = 0

#: Resource qubit that travels to the recipient, and the only one Eve touches.
_TRAVELLING_QUBIT: Final[int] = 1

_AXIS_INDEX: Final[Mapping[PauliBasis, int]] = {
    PauliBasis.X: 0,
    PauliBasis.Y: 1,
    PauliBasis.Z: 2,
}

_TWIRL_LABELS: Final[tuple[str, str, str, str]] = ("I", "X", "Y", "Z")


# --------------------------------------------------------------------------- #
# Analytic predictions                                                         #
# --------------------------------------------------------------------------- #


def _as_tensor(tensor: Any, name: str = "tensor") -> CorrelationTensor:
    """Coerce and range-check a correlation tensor.

    Parameters
    ----------
    tensor : sequence of float
        Three correlators, each in ``[-1, 1]``.
    name : str, optional
        Quoted in error messages.

    Returns
    -------
    CorrelationTensor
        The three values as floats.

    Raises
    ------
    TypeError
        If ``tensor`` is not a sequence of three real numbers.
    ValueError
        If it does not have exactly three entries, or one is outside ``[-1, 1]``
        or not finite.
    """
    if isinstance(tensor, (str, bytes)) or not isinstance(tensor, Sequence):
        raise TypeError(
            f"{name} must be a sequence (T_xx, T_yy, T_zz) of three "
            f"correlators, got {type(tensor).__name__}. Build one with "
            f"depolarising_tensor(p) or collapse_tensor(axes)."
        )
    if len(tensor) != 3:
        raise ValueError(
            f"{name} must hold exactly three correlators (T_xx, T_yy, T_zz), "
            f"got {len(tensor)}. A tensor with a missing axis would silently "
            f"read as zero correlation on that axis, which is a maximally "
            f"noisy channel and not a missing measurement."
        )
    values: list[float] = []
    for axis, entry in zip("xyz", tensor, strict=True):
        if isinstance(entry, bool) or not isinstance(entry, numbers.Real):
            raise TypeError(
                f"{name}[T_{axis}{axis}] must be a real number in [-1, 1], got "
                f"{type(entry).__name__}"
            )
        value = float(entry)
        if not math.isfinite(value) or not -1.0 <= value <= 1.0:
            raise ValueError(
                f"{name}[T_{axis}{axis}] must be a finite correlator in "
                f"[-1, 1], got {value!r}. It is the expectation of a product of "
                f"two eigenvalues, so it cannot leave that range."
            )
        values.append(value)
    return values[0], values[1], values[2]


def chsh_from_tensor(tensor: Sequence[float]) -> float:
    """Return ``S = sqrt(2) * (T_zz + T_xx)`` for a Bell-diagonal resource.

    The identity derived under :ref:`channel-tensor`. The :math:`y` correlator is
    accepted and ignored: the shipped CHSH settings lie in the :math:`x`-:math:`z`
    plane, so nothing on the :math:`y` axis can reach the statistic. That is a
    real blind spot and not a rounding of one -- a resource whose only defect is
    on :math:`y` passes the Bell test untouched and is caught by the QBER arm
    instead.

    Parameters
    ----------
    tensor : sequence of float
        ``(T_xx, T_yy, T_zz)``.

    Returns
    -------
    float
        The predicted CHSH statistic.

    Raises
    ------
    TypeError, ValueError
        As :func:`_as_tensor`.

    See Also
    --------
    sih141.protocol.checkrounds.depolarising_chsh : The same number for the
        Werner family, expressed in ``p``.

    Examples
    --------
    >>> from sih141.attacks.channel import IDEAL_TENSOR, chsh_from_tensor
    >>> f"{chsh_from_tensor(IDEAL_TENSOR):.4f}"
    '2.8284'

    A defect confined to the ``y`` axis is invisible here:

    >>> chsh_from_tensor((1.0, 0.0, 1.0)) == chsh_from_tensor(IDEAL_TENSOR)
    True
    """
    t_xx, _t_yy, t_zz = _as_tensor(tensor)
    return math.sqrt(2.0) * (t_zz + t_xx)


def qber_from_tensor(
    tensor: Sequence[float],
    bases: Iterable[PauliBasis | str] = PAULI_AXES,
) -> float:
    """Return the matched-basis error rate a Bell-diagonal resource produces.

    ``mean_b (1 - s_b T_bb) / 2`` with ``s = (+1, -1, +1)``, the signs of
    :data:`~sih141.protocol.checkrounds.IDEAL_PAULI_CORRELATION`. This is both
    the QBER arm's error rate and -- by the identity in
    :mod:`sih141.protocol.checkrounds` -- the rate at which a *matched key
    position* over the same resource would mismatch, which is why one number
    predicts both halves of every measurement in this module.

    Parameters
    ----------
    tensor : sequence of float
        ``(T_xx, T_yy, T_zz)``.
    bases : iterable of PauliBasis or str, optional
        The alphabet the round's basis is drawn from, uniformly. Defaults to all
        three.

    Returns
    -------
    float
        The predicted error rate.

    Raises
    ------
    TypeError, ValueError
        As :func:`_as_tensor`, or if ``bases`` is empty or names an unknown
        basis.

    Examples
    --------
    >>> from sih141.attacks.channel import (
    ...     IDEAL_TENSOR, collapse_tensor, depolarising_tensor,
    ...     qber_from_tensor,
    ... )
    >>> qber_from_tensor(IDEAL_TENSOR)
    0.0
    >>> f"{qber_from_tensor(depolarising_tensor(0.14)):.5f}"
    '0.07000'
    >>> f"{qber_from_tensor(collapse_tensor()):.5f}"
    '0.33333'

    A ``Z``-axis collapse is perfect on ``Z`` rounds and a coin toss on the
    other two, which is the same ``1/3`` by a different route:

    >>> [
    ...     f"{qber_from_tensor(collapse_tensor(('Z',)), (basis,)):.4f}"
    ...     for basis in "XYZ"
    ... ]
    ['0.5000', '0.5000', '0.0000']
    """
    values = _as_tensor(tensor)
    alphabet = [PauliBasis(str(basis).upper()) for basis in bases]
    if not alphabet:
        raise ValueError(
            "qber_from_tensor needs at least one basis to average over: an "
            "empty alphabet has no error rate, it has no rounds."
        )
    total = 0.0
    for basis in alphabet:
        index = _AXIS_INDEX[basis]
        total += (1.0 - IDEAL_TENSOR[index] * values[index]) / 2.0
    return total / len(alphabet)


def depolarising_tensor(strength: float) -> CorrelationTensor:
    """Return ``(1 - p) * IDEAL_TENSOR``, the Werner family's tensor.

    A Pauli twirl of weight ``p`` on one wing maps
    :math:`|\\Phi^{+}\\rangle` to the equal mixture of all four Bell states,
    which is :math:`I/4`; the surviving :math:`|\\Phi^{+}\\rangle` component is
    :math:`1-p`, so the whole tensor scales by :math:`1-p`.

    Parameters
    ----------
    strength : float
        ``p`` in ``[0, 1]``.

    Returns
    -------
    CorrelationTensor

    Raises
    ------
    TypeError
        If ``strength`` is a boolean or not a real number.
    ValueError
        If it is not finite or lies outside ``[0, 1]``.

    Examples
    --------
    >>> from sih141.attacks.channel import chsh_from_tensor, depolarising_tensor
    >>> depolarising_tensor(0.0)
    (1.0, -1.0, 1.0)
    >>> depolarising_tensor(1.0)
    (0.0, -0.0, 0.0)

    It reproduces :func:`~sih141.protocol.checkrounds.depolarising_chsh`, which
    is the point -- the protocol's prediction and the attack's must be one
    number:

    >>> from sih141.protocol.checkrounds import depolarising_chsh
    >>> all(
    ...     abs(chsh_from_tensor(depolarising_tensor(p / 20))
    ...         - depolarising_chsh(p / 20)) < 1e-12
    ...     for p in range(21)
    ... )
    True
    """
    value = _as_strength(strength, "strength")
    return (
        (1.0 - value) * IDEAL_TENSOR[0],
        (1.0 - value) * IDEAL_TENSOR[1],
        (1.0 - value) * IDEAL_TENSOR[2],
    )


def collapse_tensor(
    axes: Iterable[PauliBasis | str] = PAULI_AXES,
) -> CorrelationTensor:
    """Return the tensor left by collapsing :math:`|\\Phi^{+}\\rangle` onto ``axes``.

    Each axis contributes the signed unit tensor of that axis --
    :math:`(1,0,0)` for :math:`X`, :math:`(0,-1,0)` for :math:`Y`,
    :math:`(0,0,1)` for :math:`Z`, the signs being
    :data:`IDEAL_TENSOR`'s -- and the result is their mean, because Eve draws
    her axis uniformly.

    This one function predicts **both** :class:`InterceptResend` and
    :class:`KeptShareSwap`. Measuring one half of a maximally entangled pair in
    axis :math:`a` and re-sending what was found, and dephasing that half into a
    retained ancilla in axis :math:`a`, leave the same average state; the round
    is a pure product in the first case and a rank-2 mixture in the second, but
    no correlator can tell.

    Parameters
    ----------
    axes : iterable of PauliBasis or str, optional
        The axes Eve draws from, uniformly. Repeats are honoured, so a biased
        Eve is expressed as ``("Z", "Z", "X")``.

    Returns
    -------
    CorrelationTensor

    Raises
    ------
    ValueError
        If ``axes`` is empty or names an unknown basis.

    Examples
    --------
    >>> from sih141.attacks.channel import (
    ...     chsh_from_tensor, collapse_tensor, qber_from_tensor
    ... )
    >>> collapse_tensor(("Z",))
    (0.0, 0.0, 1.0)
    >>> tuple(round(value, 6) for value in collapse_tensor())
    (0.333333, -0.333333, 0.333333)

    A ``Z``-only Eve is *more* visible to the Bell test than a random-axis one,
    and exactly as visible to the QBER arm:

    >>> f"{chsh_from_tensor(collapse_tensor(('Z',))):.4f}"
    '1.4142'
    >>> f"{chsh_from_tensor(collapse_tensor()):.4f}"
    '0.9428'
    >>> qber_from_tensor(collapse_tensor(("Z",))) == qber_from_tensor(
    ...     collapse_tensor()
    ... )
    True
    """
    alphabet = _as_axes(axes)
    totals = [0.0, 0.0, 0.0]
    for basis in alphabet:
        index = _AXIS_INDEX[basis]
        totals[index] += IDEAL_TENSOR[index]
    count = float(len(alphabet))
    return (totals[0] / count, totals[1] / count, totals[2] / count)


def _as_strength(value: Any, name: str) -> float:
    """Coerce and range-check a probability-valued attack strength.

    Parameters
    ----------
    value : float
        The candidate.
    name : str
        Quoted in error messages.

    Returns
    -------
    float

    Raises
    ------
    TypeError
        If ``value`` is a boolean or not a real number.
    ValueError
        If it is not finite or lies outside ``[0, 1]``.
    """
    if isinstance(value, bool):
        raise TypeError(
            f"{name} must be a real number in [0, 1], got the boolean "
            f"{value!r}"
        )
    if not isinstance(value, numbers.Real):
        raise TypeError(
            f"{name} must be a real number in [0, 1], got "
            f"{type(value).__name__}"
        )
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(
            f"{name} must be a finite probability in [0, 1], got {result!r}. "
            f"It is the fraction of hops the attack acts on."
        )
    return result


def _as_axes(axes: Any) -> tuple[PauliBasis, ...]:
    """Coerce an axis alphabet, refusing an empty one.

    Parameters
    ----------
    axes : iterable of PauliBasis or str
        The candidate alphabet.

    Returns
    -------
    tuple of PauliBasis

    Raises
    ------
    ValueError
        If it is empty, or names something that is not ``X``, ``Y`` or ``Z``.
    TypeError
        If ``axes`` is not iterable.
    """
    if isinstance(axes, (str, bytes)):
        raise TypeError(
            f"axes must be an iterable of PauliBasis, not the string "
            f"{axes!r}; a bare string would iterate character by character and "
            f"'XY' would silently mean two axes. Pass ('X', 'Y')."
        )
    try:
        candidates = tuple(axes)
    except TypeError:
        raise TypeError(
            f"axes must be an iterable of PauliBasis or their labels, got "
            f"{type(axes).__name__}"
        ) from None
    if not candidates:
        raise ValueError(
            "axes must name at least one measurement axis: an eavesdropper "
            "with no basis to guess in is not an attack, and an empty "
            "alphabet would divide by zero in collapse_tensor."
        )
    resolved: list[PauliBasis] = []
    for candidate in candidates:
        try:
            resolved.append(PauliBasis(str(candidate).upper()))
        except ValueError:
            raise ValueError(
                f"axes must name Pauli bases X, Y or Z, got {candidate!r}. "
                f"The default PAULI_AXES is the protocol's own alphabet."
            ) from None
    return tuple(resolved)


def _as_target(target: Any) -> Party | None:
    """Coerce the party-targeting argument.

    Parameters
    ----------
    target : Party, str or None
        The recipient whose link is attacked, or ``None`` for both.

    Returns
    -------
    Party or None

    Raises
    ------
    ValueError
        If ``target`` names Alice -- she is the common endpoint of both links,
        so "attack Alice's link" designates no link at all -- or names no party.
    """
    if target is None:
        return None
    resolved = _as_party(target)
    if resolved is Party.ALICE:
        raise ValueError(
            "target names the recipient whose link is attacked, and Alice is "
            "at the far end of both links, so targeting her designates no "
            "link. Pass Party.BOB, Party.CHARLIE, or None to attack both."
        )
    return resolved


# --------------------------------------------------------------------------- #
# What an attack records about itself                                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AttackDecision:
    """One hop, and what Eve chose to do to it.

    The adversary's own log. It exists for two reasons and neither is
    cosmetic: it is what :func:`sih141.attacks.isolation.check_attack_isolation`
    probes to establish D6, and it is the ground truth a Phase 4 detector's
    output is scored against -- a detector that flags a link Eve never touched
    is a false positive, and only this log knows which link that is.

    Attributes
    ----------
    party : Party
        The recipient whose hop this was.
    message_bit : int
        Which distribution.
    position : int
        The key index, in the unsifted ``0 .. L-1`` numbering.
    engaged : bool
        Whether the attack acted. ``False`` on a hop skipped because of
        ``target``, and on a hop the twirl left alone.
    choice : str
        What was done, as a short label: ``"pass"`` for an untouched hop, a
        Pauli label for a twirl, an axis label for a measurement or a dephasing.

    Examples
    --------
    >>> from sih141.attacks.channel import AttackDecision
    >>> from sih141.protocol.params import Party
    >>> AttackDecision(Party.BOB, 0, 7, True, "Z").as_tuple()
    ('Bob', 0, 7, True, 'Z')
    """

    party: Party
    message_bit: int
    position: int
    engaged: bool
    choice: str

    def as_tuple(self) -> tuple[str, int, int, bool, str]:
        """Return a plain comparable tuple.

        Returns
        -------
        tuple
            ``(party, message_bit, position, engaged, choice)``, with the party
            as its label so the value survives
            :func:`sih141.attacks.isolation.canonical` and :func:`json.dumps`
            unchanged.
        """
        return (
            self.party.value,
            self.message_bit,
            self.position,
            self.engaged,
            self.choice,
        )


# --------------------------------------------------------------------------- #
# The adversaries                                                              #
# --------------------------------------------------------------------------- #


class ChannelAttack:
    """Base class: an eavesdropper who owns a generator and targets a link.

    Not usable on its own -- :meth:`_act_on_resource` and
    :meth:`_act_on_payload` are abstract -- but it holds everything the three
    concrete attacks share: the D6 generator, the ``target`` filter, the
    decision log, and the two bound methods that mount the attack on the two
    seams.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only, and **required** (D6). Eve's own stream. She must never be
        handed, and must never reconstruct, the generator
        :class:`~sih141.protocol.session.QDSSession` was given: an attack that
        shares the session's seed can predict every symmetrisation coin, and
        every rate it publishes is then fiction.
    target : Party, str or None, optional
        Keyword-only. Restrict the attack to one recipient's link, read off
        :attr:`~sih141.protocol.distribute.ResourceContext.party`. ``None``, the
        default, attacks both.

    Attributes
    ----------
    log : tuple of AttackDecision
        Every hop the attack was offered, in call order.

    Raises
    ------
    TypeError
        If ``rng`` is not a :class:`numpy.random.Generator`. ``None`` is refused
        here although :func:`~sih141.core.rng.resolve_rng` would accept it: an
        entropy-seeded adversary cannot be replayed, and an unreplayable
        adversary cannot be audited for D6.
    ValueError
        If ``target`` names Alice or names no party.

    See Also
    --------
    sih141.attacks.isolation.check_attack_isolation : The D6 check every
        subclass is required to pass.
    """

    def __init__(
        self,
        *,
        rng: np.random.Generator,
        target: Party | str | None = None,
    ) -> None:
        if not isinstance(rng, np.random.Generator):
            raise TypeError(
                f"rng must be a numpy.random.Generator and is required, got "
                f"{type(rng).__name__}. An adversary owns its randomness (D6): "
                f"it is constructed with a generator of its own, never with the "
                f"session's seed and never with None, because an adversary that "
                f"cannot be replayed cannot be shown to be isolated."
            )
        self._rng = rng
        self._target = _as_target(target)
        self._log: list[AttackDecision] = []

    # -- introspection ------------------------------------------------------ #

    @property
    def target(self) -> Party | None:
        """Party or None: The link this attack is restricted to."""
        return self._target

    @property
    def log(self) -> tuple[AttackDecision, ...]:
        """tuple of AttackDecision: Every hop offered, in call order."""
        return tuple(self._log)

    @property
    def engaged_count(self) -> int:
        """int: How many hops the attack actually acted on."""
        return sum(1 for entry in self._log if entry.engaged)

    def decisions(self) -> tuple[tuple[str, int, int, bool, str], ...]:
        """Return the log as plain tuples, for an isolation probe.

        Returns
        -------
        tuple of tuple
            One :meth:`AttackDecision.as_tuple` per hop.
        """
        return tuple(entry.as_tuple() for entry in self._log)

    def __repr__(self) -> str:
        """Return a debugging representation naming the target and the log size."""
        where = "both links" if self._target is None else self._target.value
        return (
            f"<{type(self).__name__} on {where}, {self.engaged_count} of "
            f"{len(self._log)} hop(s) engaged>"
        )

    # -- the two seams ------------------------------------------------------ #

    def resource(self, context: ResourceContext) -> StateLike:
        """Mount the attack on the entanglement resource. A ``ResourceFactory``.

        Called once per key position on **both** branches of a checked run, so
        this is the line the QBER and CHSH arms watch.

        Parameters
        ----------
        context : ResourceContext
            The hop being served.

        Returns
        -------
        StateLike
            The two-qubit pair actually delivered. A clean
            :math:`|\\Phi^{+}\\rangle` on a hop this attack does not target.
        """
        pair = bell_state(BellState.PHI_PLUS)
        if not self._targets(context):
            self._record(context, engaged=False, choice="pass")
            return pair
        return self._act_on_resource(pair, context)

    def payload(self, state: StateLike, context: ResourceContext) -> StateLike:
        """Mount the attack on the payload line. A ``PayloadMap``.

        Called once per **key round** and never on a check round, so an attack
        mounted here is invisible to both published statistics
        (:ref:`channel-two-lines`).

        Parameters
        ----------
        state : StateLike
            The eigenstate Alice prepared for this position.
        context : ResourceContext
            The hop being served.

        Returns
        -------
        StateLike
            The one-qubit state actually teleported.
        """
        if not self._targets(context):
            self._record(context, engaged=False, choice="pass")
            return state
        return self._act_on_payload(state, context)

    # -- subclass hooks ----------------------------------------------------- #

    def _act_on_resource(
        self, pair: Statevector, context: ResourceContext
    ) -> StateLike:
        """Transform one targeted hop's entanglement resource.

        Parameters
        ----------
        pair : qiskit.quantum_info.Statevector
            A fresh :math:`|\\Phi^{+}\\rangle`.
        context : ResourceContext
            The hop.

        Returns
        -------
        StateLike
            The pair Alice and the recipient will actually share.

        Raises
        ------
        NotImplementedError
            Always, on the base class.
        """
        raise NotImplementedError(
            f"{type(self).__name__} must implement _act_on_resource to be "
            f"mounted on the resource_factory seam."
        )

    def _act_on_payload(
        self, state: StateLike, context: ResourceContext
    ) -> StateLike:
        """Transform one targeted hop's payload.

        Parameters
        ----------
        state : StateLike
            The eigenstate Alice prepared.
        context : ResourceContext
            The hop.

        Returns
        -------
        StateLike
            The state actually teleported.

        Raises
        ------
        NotImplementedError
            Always, on the base class.
        """
        raise NotImplementedError(
            f"{type(self).__name__} must implement _act_on_payload to be "
            f"mounted on the payload_map seam."
        )

    # -- shared machinery --------------------------------------------------- #

    def _targets(self, context: ResourceContext) -> bool:
        """Return whether this hop is on the attacked link.

        Parameters
        ----------
        context : ResourceContext
            The hop.

        Returns
        -------
        bool
        """
        return self._target is None or context.party is self._target

    def _record(
        self, context: ResourceContext, *, engaged: bool, choice: str
    ) -> None:
        """Append one decision to the log.

        Parameters
        ----------
        context : ResourceContext
            The hop.
        engaged : bool
            Whether the attack acted.
        choice : str
            The short label of what was done.
        """
        self._log.append(
            AttackDecision(
                party=context.party,
                message_bit=context.message_bit,
                position=context.position,
                engaged=engaged,
                choice=choice,
            )
        )

    def _draw_axis(self, axes: tuple[PauliBasis, ...]) -> PauliBasis:
        """Draw one measurement axis from Eve's own stream.

        Parameters
        ----------
        axes : tuple of PauliBasis
            The alphabet.

        Returns
        -------
        PauliBasis
        """
        return axes[int(self._rng.integers(len(axes)))]


class DepolarisingChannel(ChannelAttack):
    """Injected depolarising noise, realised as a Pauli twirl on the wire.

    With probability ``strength`` the travelling half takes a Pauli drawn
    uniformly from :math:`\\{I, X, Y, Z\\}`; otherwise it passes untouched. The
    ensemble is exactly the Werner resource
    :math:`(1-p)|\\Phi^{+}\\rangle\\langle\\Phi^{+}| + p\\,I/4`, because the
    three non-identity Paulis carry :math:`|\\Phi^{+}\\rangle` to the other three
    Bell states and an equal mixture of all four is :math:`I/4`.

    Realised per round rather than returned as the mixed state, for two
    reasons. It is what a physical channel does, and it is what makes the
    adversary's behaviour a function of *its own* generator, which is what D6
    asks for and what a returned constant could never demonstrate. The
    difference is invisible to both published estimates -- the outcome
    distributions are identical -- and very visible to a channel monitor: see
    :ref:`channel-detector-signals`.

    Parameters
    ----------
    strength : float
        ``p`` in ``[0, 1]``.
    rng : numpy.random.Generator
        Keyword-only, required (D6).
    target : Party, str or None, optional
        Keyword-only. One link, or both.

    Raises
    ------
    TypeError, ValueError
        As :class:`ChannelAttack`, or if ``strength`` is not a probability.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.channel import DepolarisingChannel
    >>> from sih141.protocol.distribute import ResourceContext
    >>> from sih141.protocol.params import Party
    >>> attack = DepolarisingChannel(0.5, rng=np.random.default_rng(7))
    >>> hops = [
    ...     ResourceContext(party=Party.BOB, message_bit=0, position=i)
    ...     for i in range(6)
    ... ]
    >>> [attack.resource(hop) is not None for hop in hops]
    [True, True, True, True, True, True]
    >>> [entry.choice for entry in attack.log]
    ['pass', 'pass', 'pass', 'I', 'pass', 'X']

    Targeting is read off the context, so Charlie's link is untouched:

    >>> aimed = DepolarisingChannel(
    ...     1.0, rng=np.random.default_rng(7), target=Party.BOB
    ... )
    >>> charlie = ResourceContext(
    ...     party=Party.CHARLIE, message_bit=0, position=0
    ... )
    >>> _ = aimed.resource(charlie)
    >>> aimed.log[0].engaged, aimed.engaged_count
    (False, 0)
    """

    def __init__(
        self,
        strength: float,
        *,
        rng: np.random.Generator,
        target: Party | str | None = None,
    ) -> None:
        super().__init__(rng=rng, target=target)
        self._strength = _as_strength(strength, "strength")

    @property
    def strength(self) -> float:
        """float: ``p``, the fraction of hops that take a Pauli."""
        return self._strength

    @property
    def tensor(self) -> CorrelationTensor:
        """CorrelationTensor: The correlation tensor of the resource ensemble."""
        return depolarising_tensor(self._strength)

    def _draw_twirl(self) -> str:
        """Draw this hop's Pauli label from Eve's own stream.

        Returns
        -------
        str
            ``"pass"`` when the hop is left alone, otherwise ``"I"``, ``"X"``,
            ``"Y"`` or ``"Z"``. ``"I"`` is distinguished from ``"pass"``
            deliberately: both leave the state alone, but only ``"I"`` consumed
            a decision, and a log that conflated them would misreport how often
            the attack engaged.
        """
        if float(self._rng.random()) >= self._strength:
            return "pass"
        return _TWIRL_LABELS[int(self._rng.integers(len(_TWIRL_LABELS)))]

    def _act_on_resource(
        self, pair: Statevector, context: ResourceContext
    ) -> StateLike:
        """Apply the drawn Pauli to the travelling half only (D2)."""
        label = self._draw_twirl()
        self._record(context, engaged=label != "pass", choice=label)
        if label in ("pass", "I"):
            return pair
        return as_density(pair).evolve(
            Operator(pauli_matrix(label)), qargs=[_TRAVELLING_QUBIT]
        )

    def _act_on_payload(
        self, state: StateLike, context: ResourceContext
    ) -> StateLike:
        """Apply the drawn Pauli to the one-qubit payload."""
        label = self._draw_twirl()
        self._record(context, engaged=label != "pass", choice=label)
        if label in ("pass", "I"):
            return state
        return as_density(state).evolve(Operator(pauli_matrix(label)))


class InterceptResend(ChannelAttack):
    """Eve measures the travelling half and re-sends what she found.

    The textbook attack, and the one that destroys the most entanglement per
    unit of effort: the pair Alice and the recipient end up sharing is a **pure
    product state**, with no entanglement at all, so the CHSH arm sees a
    statistic far below the classical bound and the QBER arm sees ``1/3``.

    Measuring one half of :math:`|\\Phi^{+}\\rangle` in axis :math:`a` collapses
    *both* halves onto that axis, so re-sending the eigenstate she found is
    exactly as damaging as it looks; averaged over her uniform choice of axis
    the resource has tensor :func:`collapse_tensor`.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only, required (D6). Her basis choice **and** her measurement
        outcome are drawn from it -- the outcome as much as the choice, because
        an outcome drawn from the session's generator would correlate her
        results with the recipient's.
    target : Party, str or None, optional
        Keyword-only. One link, or both.
    axes : iterable of PauliBasis or str, optional
        Keyword-only. The alphabet she guesses in. Defaults to
        :data:`PAULI_AXES`; ``("Z",)`` gives the fixed-basis variant, which is
        *more* visible to the Bell test and exactly as visible to the QBER arm.

    Raises
    ------
    TypeError, ValueError
        As :class:`ChannelAttack`, or if ``axes`` is empty or unknown.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.channel import InterceptResend
    >>> from sih141.core.states import concurrence, purity
    >>> from sih141.protocol.distribute import ResourceContext
    >>> from sih141.protocol.params import Party
    >>> attack = InterceptResend(rng=np.random.default_rng(11))
    >>> hop = ResourceContext(party=Party.BOB, message_bit=0, position=0)
    >>> delivered = attack.resource(hop)
    >>> attack.log[0].choice
    'X'

    What arrives is pure, and not entangled at all:

    >>> round(purity(delivered), 9), round(concurrence(delivered), 9)
    (1.0, 0.0)
    """

    def __init__(
        self,
        *,
        rng: np.random.Generator,
        target: Party | str | None = None,
        axes: Iterable[PauliBasis | str] = PAULI_AXES,
    ) -> None:
        super().__init__(rng=rng, target=target)
        self._axes = _as_axes(axes)

    @property
    def axes(self) -> tuple[PauliBasis, ...]:
        """tuple of PauliBasis: The alphabet Eve guesses in."""
        return self._axes

    @property
    def tensor(self) -> CorrelationTensor:
        """CorrelationTensor: The correlation tensor of the resource ensemble."""
        return collapse_tensor(self._axes)

    def _act_on_resource(
        self, pair: Statevector, context: ResourceContext
    ) -> StateLike:
        """Measure qubit 1 in a drawn axis and hand on the collapsed register."""
        from sih141.core.measure import projective_measure

        axis = self._draw_axis(self._axes)
        self._record(context, engaged=True, choice=axis.value)
        outcome = projective_measure(
            as_density(pair), _TRAVELLING_QUBIT, axis, rng=self._rng
        )
        return outcome.post_state

    def _act_on_payload(
        self, state: StateLike, context: ResourceContext
    ) -> StateLike:
        """Measure the payload in a drawn axis and re-send the eigenstate found."""
        from sih141.core.measure import projective_measure

        axis = self._draw_axis(self._axes)
        self._record(context, engaged=True, choice=axis.value)
        outcome = projective_measure(as_density(state), 0, axis, rng=self._rng)
        return outcome.post_state


class KeptShareSwap(ChannelAttack):
    """Eve copies the travelling half onto an ancilla and keeps it.

    Entanglement swapping in the form that matters here: Eve does not relay the
    entanglement, she *joins* it. A controlled copy of the travelling qubit onto
    a fresh ancilla, in the axis :math:`a` she draws, turns
    :math:`|\\Phi^{+}\\rangle \\otimes |0\\rangle_E` into a three-party GHZ state.
    Alice and the recipient are left with its two-qubit marginal, which is
    :math:`|\\Phi^{+}\\rangle` dephased in :math:`a`:

    .. math::

        \\rho \\;\\longrightarrow\\; \\tfrac{1}{2}\\bigl(\\rho
            + \\sigma_a^{(1)} \\rho\\, \\sigma_a^{(1)}\\bigr).

    For :math:`a = Z` that is :math:`(|00\\rangle\\langle 00| +
    |11\\rangle\\langle 11|)/2`, the marginal of the ordinary GHZ state, and its
    CHSH statistic is :math:`\\sqrt{2} = 1.4142` -- **not** ``2.0000``. The
    classical bound is what a kept share *cannot exceed*, and it is not what a
    kept share attains; see the module's Phase 3 notes.

    Averaged over a uniformly drawn axis the tensor is :func:`collapse_tensor`,
    identical to :class:`InterceptResend`'s. The two attacks part company only
    on :attr:`~sih141.protocol.session.ChannelSample.purity`: this one leaves a
    rank-2 mixture of purity ``0.5``, intercept-resend leaves a pure product.

    Parameters
    ----------
    rng : numpy.random.Generator
        Keyword-only, required (D6). Only the axis is drawn from it -- there is
        no measurement here, which is the whole idea: Eve holds her share and
        decides later.
    target : Party, str or None, optional
        Keyword-only. One link, or both.
    axes : iterable of PauliBasis or str, optional
        Keyword-only. The axes she copies in. Defaults to :data:`PAULI_AXES`.

    Raises
    ------
    TypeError, ValueError
        As :class:`ChannelAttack`, or if ``axes`` is empty or unknown.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.channel import KeptShareSwap
    >>> from sih141.core.states import concurrence, purity
    >>> from sih141.protocol.distribute import ResourceContext
    >>> from sih141.protocol.params import Party
    >>> attack = KeptShareSwap(rng=np.random.default_rng(5), axes=("Z",))
    >>> hop = ResourceContext(party=Party.CHARLIE, message_bit=1, position=2)
    >>> delivered = attack.resource(hop)
    >>> [round(value, 9) for value in (purity(delivered), concurrence(delivered))]
    [0.5, 0.0]

    The marginal really is the GHZ state's:

    >>> delivered.data.real.round(6).tolist()
    [[0.5, 0.0, 0.0, 0.0], [0.0, 0.0, 0.0, 0.0], [0.0, 0.0, 0.0, 0.0], [0.0, 0.0, 0.0, 0.5]]
    """

    def __init__(
        self,
        *,
        rng: np.random.Generator,
        target: Party | str | None = None,
        axes: Iterable[PauliBasis | str] = PAULI_AXES,
    ) -> None:
        super().__init__(rng=rng, target=target)
        self._axes = _as_axes(axes)

    @property
    def axes(self) -> tuple[PauliBasis, ...]:
        """tuple of PauliBasis: The axes Eve copies in."""
        return self._axes

    @property
    def tensor(self) -> CorrelationTensor:
        """CorrelationTensor: The correlation tensor of the resource ensemble."""
        return collapse_tensor(self._axes)

    @staticmethod
    def _dephase(
        state: DensityMatrix, axis: PauliBasis, qubit: int | None
    ) -> DensityMatrix:
        """Return ``(rho + sigma_a rho sigma_a) / 2`` on one qubit.

        The two-qubit marginal of the GHZ state Eve creates, computed directly
        rather than by building the three-qubit register and tracing her ancilla
        out. The two are equal by construction and the direct form is a
        ``4 x 4`` operation instead of an ``8 x 8`` one -- which matters at
        ``L = 115200``.

        Parameters
        ----------
        state : qiskit.quantum_info.DensityMatrix
            The state to dephase.
        axis : PauliBasis
            The axis Eve copies in.
        qubit : int or None
            Which qubit, or ``None`` for a one-qubit state.

        Returns
        -------
        qiskit.quantum_info.DensityMatrix
        """
        operator = Operator(pauli_matrix(axis.value))
        flipped = (
            state.evolve(operator)
            if qubit is None
            else state.evolve(operator, qargs=[qubit])
        )
        return DensityMatrix(
            (np.asarray(state.data) + np.asarray(flipped.data)) / 2.0
        )

    def _act_on_resource(
        self, pair: Statevector, context: ResourceContext
    ) -> StateLike:
        """Dephase the travelling half into Eve's retained ancilla."""
        axis = self._draw_axis(self._axes)
        self._record(context, engaged=True, choice=axis.value)
        return self._dephase(as_density(pair), axis, _TRAVELLING_QUBIT)

    def _act_on_payload(
        self, state: StateLike, context: ResourceContext
    ) -> StateLike:
        """Dephase the payload into Eve's retained ancilla."""
        axis = self._draw_axis(self._axes)
        self._record(context, engaged=True, choice=axis.value)
        return self._dephase(as_density(state), axis, None)


# --------------------------------------------------------------------------- #
# Measuring an attack                                                          #
# --------------------------------------------------------------------------- #


def _sample_contexts(
    rounds: int, party: Party, message_bit: int
) -> list[ResourceContext]:
    """Build ``rounds`` consecutive hop contexts for one link.

    Parameters
    ----------
    rounds : int
        How many hops.
    party : Party
        The recipient.
    message_bit : int
        Which distribution.

    Returns
    -------
    list of ResourceContext

    Raises
    ------
    ValueError
        If ``rounds`` is not positive.
    """
    if not isinstance(rounds, numbers.Integral) or isinstance(rounds, bool):
        raise TypeError(
            f"rounds must be a positive integer, got {type(rounds).__name__}"
        )
    count = int(rounds)
    if count < 1:
        raise ValueError(
            f"rounds must be at least 1, got {count}: an estimate needs a "
            f"denominator, the same rule estimate_qber and estimate_chsh apply."
        )
    return [
        ResourceContext(party=party, message_bit=message_bit, position=index)
        for index in range(count)
    ]


def measure_qber(
    factory: Any,
    *,
    rounds: int,
    rng: np.random.Generator | None = None,
    party: Party | str = Party.BOB,
    message_bit: int = 0,
    bases: Iterable[PauliBasis | str] = PAULI_AXES,
    **kwargs: Any,
) -> QberEstimate:
    """Run the QBER arm against a resource factory and return the estimate.

    A standalone check-round campaign: it does exactly what
    :func:`~sih141.protocol.distribute.distribute_to_recipient_with_checks` does
    on a QBER position, and nothing else, so a rate can be measured to several
    thousand rounds without paying for the teleportations of a full session. The
    statistic is the same statistic; only the surrounding protocol is absent.

    Parameters
    ----------
    factory : callable
        A :data:`~sih141.protocol.distribute.ResourceFactory` taking a
        :class:`~sih141.protocol.distribute.ResourceContext` -- normally
        ``attack.resource``.
    rounds : int
        Keyword-only. Sample size.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). The **recipients'** measurement randomness, and it
        must not be the generator the attack was built with: pooling them would
        correlate Eve's choices with the outcomes she is being scored by.
    party : Party or str, optional
        Keyword-only. Which link the contexts name, so a targeted attack can be
        measured on the link it targets and on the one it does not.
    message_bit : int, optional
        Keyword-only. Which distribution the contexts name.
    bases : iterable of PauliBasis or str, optional
        Keyword-only. The alphabet the round's basis is drawn from, uniformly.
    **kwargs
        Forwarded to :func:`~sih141.protocol.checkrounds.estimate_qber`, e.g.
        ``method="hoeffding"`` or ``confidence=0.999``.

    Returns
    -------
    QberEstimate
        Count, sample size and interval.

    Raises
    ------
    TypeError
        If ``factory`` is not callable or ``rounds`` is not an integer.
    ValueError
        If ``rounds`` is not positive.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.channel import (
    ...     InterceptResend, measure_qber, qber_from_tensor
    ... )
    >>> attack = InterceptResend(rng=np.random.default_rng(101))
    >>> estimate = measure_qber(
    ...     attack.resource, rounds=3000, rng=np.random.default_rng(202)
    ... )
    >>> f"{estimate.estimate:.4f}"
    '0.3233'
    >>> estimate.interval.covers(qber_from_tensor(attack.tensor))
    True

    A clean channel is measured the same way and lands on zero:

    >>> from sih141.protocol.distribute import ideal_resource
    >>> clean = measure_qber(
    ...     lambda context: ideal_resource(),
    ...     rounds=500,
    ...     rng=np.random.default_rng(303),
    ... )
    >>> clean.errors
    0
    """
    if not callable(factory):
        raise TypeError(
            f"factory must be a callable factory(context) returning a "
            f"two-qubit resource, got {type(factory).__name__}. Pass the "
            f"attack's bound method, e.g. attack.resource."
        )
    generator = resolve_rng(rng)
    alphabet = _as_axes(bases)
    contexts = _sample_contexts(rounds, _as_party(party), message_bit)
    observations = []
    for context in contexts:
        basis = alphabet[int(generator.integers(len(alphabet)))]
        resource = factory(context)
        observations.append(
            observe_qber_round(
                resource, QberRound(context.position, basis), rng=generator
            )
        )
    return estimate_qber(observations, **kwargs)


def measure_chsh(
    factory: Any,
    *,
    rounds: int,
    rng: np.random.Generator | None = None,
    party: Party | str = Party.BOB,
    message_bit: int = 0,
    **kwargs: Any,
) -> ChshEstimate:
    """Run the CHSH arm against a resource factory and return the estimate.

    The Bell-test counterpart of :func:`measure_qber`. Settings are assigned
    round-robin over the four cells so that the counts are balanced to within
    one, which is the condition the plug-in variance in
    :func:`~sih141.protocol.checkrounds.estimate_chsh` was derived under.

    Parameters
    ----------
    factory : callable
        As :func:`measure_qber`.
    rounds : int
        Keyword-only. Sample size; at least four, one per cell.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3). The recipients' measurement randomness, distinct from
        the attack's.
    party : Party or str, optional
        Keyword-only. Which link the contexts name.
    message_bit : int, optional
        Keyword-only. Which distribution.
    **kwargs
        Forwarded to :func:`~sih141.protocol.checkrounds.estimate_chsh`.

    Returns
    -------
    ChshEstimate
        The four correlators, their counts and the interval on ``S``.

    Raises
    ------
    TypeError
        If ``factory`` is not callable or ``rounds`` is not an integer.
    ValueError
        If ``rounds`` is below four -- with fewer, some cell is empty and the
        statistic is undefined.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.attacks.channel import chsh_from_tensor, measure_chsh
    >>> from sih141.protocol.distribute import ideal_resource
    >>> ideal = measure_chsh(
    ...     lambda context: ideal_resource(),
    ...     rounds=4000,
    ...     rng=np.random.default_rng(404),
    ... )
    >>> f"{ideal.statistic:.4f}"
    '2.7600'
    >>> ideal.violates_classical_bound, ideal.consistent_with_ideal
    (True, True)

    An intercepted-and-resent link does not come close to the classical bound:

    >>> from sih141.attacks.channel import InterceptResend
    >>> attack = InterceptResend(rng=np.random.default_rng(505))
    >>> broken = measure_chsh(
    ...     attack.resource, rounds=4000, rng=np.random.default_rng(606)
    ... )
    >>> f"{broken.statistic:.4f}"
    '0.8400'
    >>> broken.violates_classical_bound
    False
    >>> broken.interval.covers(chsh_from_tensor(attack.tensor))
    True
    """
    if not callable(factory):
        raise TypeError(
            f"factory must be a callable factory(context) returning a "
            f"two-qubit resource, got {type(factory).__name__}. Pass the "
            f"attack's bound method, e.g. attack.resource."
        )
    contexts = _sample_contexts(rounds, _as_party(party), message_bit)
    if len(contexts) < 4:
        raise ValueError(
            f"a CHSH estimate needs at least one round in each of the four "
            f"cells, so rounds must be at least 4, got {len(contexts)}."
        )
    generator = resolve_rng(rng)
    observations = []
    for index, context in enumerate(contexts):
        alice_setting = (index // 2) % 2
        recipient_setting = index % 2
        resource = factory(context)
        observations.append(
            observe_chsh_round(
                resource,
                ChshRound(context.position, alice_setting, recipient_setting),
                rng=generator,
            )
        )
    return estimate_chsh(observations, **kwargs)


# --------------------------------------------------------------------------- #
# The two questions Phase 4 asked for                                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AttributionOutcome:
    """What a party-targeted attack looked like from each of the two vantages.

    The result of :func:`attribution_survives_symmetrisation`. Every field is a
    plain number or a pair of them, so it drops into a Phase 5 table unmodified.

    Attributes
    ----------
    target : Party
        The link the attack was aimed at.
    check_qber : dict of Party to float
        Each recipient's own QBER, from his own
        :class:`~sih141.protocol.checkrounds.CheckLog`s, pooled over both
        message bits because both tested the same link. Check logs are taken
        during distribution and are **never** symmetrised, so this is the
        per-link view.
    check_qber_interval : dict of Party to tuple of float
        The Wilson interval around each, at
        :data:`~sih141.protocol.checkrounds.CHECK_CONFIDENCE`.
    check_chsh : dict of Party to float
        The same logs' CHSH statistics.
    check_chsh_interval : dict of Party to tuple of float
        Their intervals.
    record_rate : dict of Party to float
        Each recipient's matched-position mismatch rate against Alice's declared
        key, **after** Phase A'. This is the smeared view.
    unsymmetrised_rate : dict of Party to float
        The same rate from a companion run with
        :func:`~sih141.protocol.symmetrise.no_symmetrisation`, which is what the
        smearing is smearing.

    Examples
    --------
    >>> from sih141.attacks.channel import AttributionOutcome
    >>> from sih141.protocol.params import Party
    >>> outcome = AttributionOutcome(
    ...     target=Party.BOB,
    ...     check_qber={Party.BOB: 0.07, Party.CHARLIE: 0.0},
    ...     check_qber_interval={
    ...         Party.BOB: (0.04, 0.10), Party.CHARLIE: (0.0, 0.02)
    ...     },
    ...     check_chsh={Party.BOB: 2.43, Party.CHARLIE: 2.83},
    ...     check_chsh_interval={
    ...         Party.BOB: (2.2, 2.7), Party.CHARLIE: (2.6, 3.0)
    ...     },
    ...     record_rate={Party.BOB: 0.034, Party.CHARLIE: 0.039},
    ...     unsymmetrised_rate={Party.BOB: 0.069, Party.CHARLIE: 0.0},
    ... )
    >>> outcome.attributable(margin=0.02)
    True
    >>> outcome.records_attributable(margin=0.02)
    False

    The separation is called *disjoint* only when the intervals do not overlap,
    which is the statement a detector can act on:

    >>> outcome.intervals_disjoint()
    True
    """

    target: Party
    check_qber: Mapping[Party, float]
    check_qber_interval: Mapping[Party, tuple[float, float]]
    check_chsh: Mapping[Party, float]
    check_chsh_interval: Mapping[Party, tuple[float, float]]
    record_rate: Mapping[Party, float]
    unsymmetrised_rate: Mapping[Party, float]

    def _separates(
        self, values: Mapping[Party, float], margin: float
    ) -> bool:
        """Return whether ``values`` puts the target clear of the other link.

        Parameters
        ----------
        values : mapping of Party to float
            One number per recipient.
        margin : float
            How far apart they must be.

        Returns
        -------
        bool
        """
        others = [
            value for party, value in values.items() if party is not self.target
        ]
        if not others:
            return False
        return values[self.target] - max(others) >= margin

    def attributable(self, *, margin: float = 0.0) -> bool:
        """bool: Whether the **check logs** name the attacked link.

        Parameters
        ----------
        margin : float, optional
            Keyword-only. How far the targeted link's QBER must exceed the
            other's before the separation is called real.

        Returns
        -------
        bool
        """
        return self._separates(self.check_qber, margin)

    def records_attributable(self, *, margin: float = 0.0) -> bool:
        """bool: Whether the **post-exchange records** name the attacked link.

        Expected ``False`` for any margin above the sampling noise: that is what
        symmetrisation does, and it is the reason the check logs exist.

        Parameters
        ----------
        margin : float, optional
            Keyword-only. As :meth:`attributable`.

        Returns
        -------
        bool
        """
        return self._separates(self.record_rate, margin)

    def intervals_disjoint(self) -> bool:
        """bool: Whether the two links' QBER intervals fail to overlap.

        The form of the claim a detector can act on. A gap between point
        estimates can be sampling noise; two disjoint intervals at
        :data:`~sih141.protocol.checkrounds.CHECK_CONFIDENCE` cannot be, at that
        level.

        Returns
        -------
        bool
        """
        target_low = self.check_qber_interval[self.target][0]
        others = [
            high
            for party, (_low, high) in self.check_qber_interval.items()
            if party is not self.target
        ]
        return bool(others) and target_low > max(others)


def _record_rates(session: Any, message_bit: int) -> dict[Party, float]:
    """Return each recipient's matched-position mismatch rate.

    Computed with :func:`~sih141.protocol.verify.matched_positions` and
    :func:`~sih141.protocol.verify.mismatch_positions` rather than by
    re-deriving the rule here, so that this number and the one a verifier
    reaches cannot drift apart.

    Parameters
    ----------
    session : QDSSession
        A session that has distributed and signed.
    message_bit : int
        The bit that was signed.

    Returns
    -------
    dict of Party to float
        ``e_R / |M_R|`` per recipient. A link with no matched positions at all
        is reported as ``nan`` rather than ``0.0``: no evidence is not clean
        evidence.
    """
    from sih141.protocol.verify import matched_positions, mismatch_positions

    signature = session.signature
    rates: dict[Party, float] = {}
    for party, record in session.records[message_bit].items():
        matched = len(matched_positions(signature, record))
        errors = len(mismatch_positions(signature, record))
        rates[party] = errors / matched if matched else float("nan")
    return rates


def attribution_survives_symmetrisation(
    strength: float = 0.14,
    *,
    key_length: int = 960,
    check_fraction: float = 0.5,
    target: Party | str = Party.BOB,
    attack_seed: int = 3141,
    session_seed: int = 2718,
    message_bit: int = 0,
) -> AttributionOutcome:
    """Mount one party-targeted attack and read it from both vantages.

    Answers the question Phase 4 has to have answered before it designs a
    detector: **symmetrisation smears a one-link attack across both records, so
    does anything still say which link it was?**

    It does, and this is where. Phase A' exchanges *records*; a
    :class:`~sih141.protocol.checkrounds.CheckLog` is built during distribution,
    one per ``(party, message_bit)``, and no symmetriser ever sees one. So the
    check arms keep the per-link view that the verification rates lose. The
    returned :class:`AttributionOutcome` holds both so a caller can see the loss
    and the recovery side by side.

    Two sessions are run: the one under test, and a companion with
    :func:`~sih141.protocol.symmetrise.no_symmetrisation` under identical seeds,
    which is the unsmeared record rate the first is compared against. Each
    party's two check logs -- one per message bit -- are pooled, because both
    tested the same link and pooling doubles the sample for nothing.

    Parameters
    ----------
    strength : float, optional
        The depolarising strength on the targeted link.
    key_length : int, optional
        Keyword-only. ``L``. The default ``960`` is chosen for statistics, not
        for security: it is far below the ``115200`` of
        :data:`~sih141.protocol.params.DEFAULT_PARAMS`, and no result at this
        length is a security claim. What carries to full scale is the
        *mechanism* -- that check logs are per-party and records are not --
        which is structural and independent of ``L``; the sampling error on
        every rate here shrinks as ``L**-0.5``, so the separation this function
        reports can only widen.
    check_fraction : float, optional
        Keyword-only. The share of positions spent on check rounds. The default
        ``0.5`` is likewise a statistics choice and far above the ``0.1170``
        :func:`~sih141.protocol.checkrounds.required_check_rounds` asks for at
        ``L = 115200``: a demo length has to buy its check sample from a much
        shorter key.
    target : Party or str, optional
        Keyword-only. The attacked link.
    attack_seed, session_seed : int, optional
        Keyword-only, and **deliberately different** (D6). The attack is built
        from ``default_rng(attack_seed)`` and the session from
        ``default_rng(session_seed)``; passing one integer for both is the exact
        defect :mod:`sih141.attacks.isolation` exists to catch.
    message_bit : int, optional
        Keyword-only. Which bit is signed, and so which records are scored.

    Returns
    -------
    AttributionOutcome

    Raises
    ------
    ValueError
        If ``attack_seed == session_seed``.

    Examples
    --------
    >>> from sih141.attacks.channel import attribution_survives_symmetrisation
    >>> outcome = attribution_survives_symmetrisation()

    The check logs put the attacked link clear of the clean one, and the two
    intervals do not overlap:

    >>> f"{outcome.check_qber[outcome.target]:.4f}"
    '0.0708'
    >>> f"{min(outcome.check_qber.values()):.4f}"
    '0.0000'
    >>> outcome.attributable(margin=0.02), outcome.intervals_disjoint()
    (True, True)

    The post-exchange records do not -- the two land on top of each other, at
    about half the unsymmetrised rate each:

    >>> outcome.records_attributable(margin=0.02)
    False
    >>> sorted(f"{value:.4f}" for value in outcome.record_rate.values())
    ['0.0204', '0.0292']
    >>> sorted(f"{value:.4f}" for value in outcome.unsymmetrised_rate.values())
    ['0.0000', '0.0567']
    """
    from sih141.protocol.session import QDSSession

    if attack_seed == session_seed:
        raise ValueError(
            f"attack_seed and session_seed must differ, got {attack_seed!r} "
            f"for both. An adversary built from the session's seed can rebuild "
            f"the session's streams and predict every symmetrisation coin "
            f"(D6), and the smearing this function measures would then be "
            f"reported from a run in which Eve already knew the answer."
        )
    aimed = _as_target(target)
    params = ProtocolParams(
        key_length=key_length, check_fraction=check_fraction
    )

    def run(symmetriser: Any) -> Any:
        """Run one session to the end of Phase B and return it."""
        attack = DepolarisingChannel(
            strength, rng=np.random.default_rng(attack_seed), target=aimed
        )
        session = QDSSession(
            params,
            resource_factory=attack.resource,
            symmetriser=symmetriser,
            rng=np.random.default_rng(session_seed),
        )
        session.distribute()
        session.sign(message_bit)
        return session

    session = run(None)
    plain = run(no_symmetrisation)

    check_qber: dict[Party, float] = {}
    check_qber_interval: dict[Party, tuple[float, float]] = {}
    check_chsh: dict[Party, float] = {}
    check_chsh_interval: dict[Party, tuple[float, float]] = {}
    for party in (Party.BOB, Party.CHARLIE):
        logs = [session.check_logs[(party, bit)] for bit in (0, 1)]
        qber = estimate_qber([entry for log in logs for entry in log.qber])
        chsh = estimate_chsh([entry for log in logs for entry in log.chsh])
        check_qber[party] = qber.estimate
        check_qber_interval[party] = (qber.interval.low, qber.interval.high)
        check_chsh[party] = chsh.statistic
        check_chsh_interval[party] = (chsh.interval.low, chsh.interval.high)
    return AttributionOutcome(
        target=aimed,
        check_qber=check_qber,
        check_qber_interval=check_qber_interval,
        check_chsh=check_chsh,
        check_chsh_interval=check_chsh_interval,
        record_rate=_record_rates(session, message_bit),
        unsymmetrised_rate=_record_rates(plain, message_bit),
    )


def payload_line_is_unwatched(
    *,
    key_length: int = 960,
    check_fraction: float = 0.5,
    attack_seed: int = 271828,
    session_seed: int = 314159,
    message_bit: int = 0,
) -> dict[str, float]:
    """Show that a payload-line attack moves the key and not the statistics.

    The same adversary -- :class:`InterceptResend`, which is the most damaging
    thing in this module -- is mounted twice under identical seeds: once on the
    ``resource_factory`` seam and once on ``payload_map``. Both wreck the key.
    Only the first is visible to the published channel statistics, because a
    check round prepares no payload and the payload seam is therefore never
    called on one (:ref:`channel-two-lines`).

    This is a *consequence* of the seam design and is documented as one in
    :mod:`sih141.protocol.distribute`; what is added here is the measurement,
    because "invisible" is a claim about numbers and Phase 4 has to plan around
    the size of it.

    Parameters
    ----------
    key_length : int, optional
        Keyword-only. ``L``, chosen for statistics. See
        :func:`attribution_survives_symmetrisation` for the scaling argument.
    check_fraction : float, optional
        Keyword-only.
    attack_seed, session_seed : int, optional
        Keyword-only, and required to differ (D6).
    message_bit : int, optional
        Keyword-only.

    Returns
    -------
    dict of str to float
        ``"resource_qber"`` / ``"resource_chsh"`` / ``"resource_record_rate"``
        and the three ``"payload_"`` counterparts, each pooled over both
        recipients.

    Raises
    ------
    ValueError
        If ``attack_seed == session_seed``.

    Examples
    --------
    >>> from sih141.attacks.channel import payload_line_is_unwatched
    >>> seen = payload_line_is_unwatched()

    On the resource line the channel statistics collapse, exactly as the
    tensor predicts:

    >>> f"{seen['resource_qber']:.4f}", f"{seen['resource_chsh']:.4f}"
    ('0.3177', '0.8813')

    On the payload line, at a comparable rate of damage to the key, they are
    pristine -- a perfect QBER and a Tsirelson-grade Bell violation:

    >>> f"{seen['payload_qber']:.4f}", f"{seen['payload_chsh']:.4f}"
    ('0.0000', '2.7561')
    >>> f"{seen['resource_record_rate']:.4f}"
    '0.3535'
    >>> f"{seen['payload_record_rate']:.4f}"
    '0.3613'
    """
    from sih141.protocol.session import QDSSession

    if attack_seed == session_seed:
        raise ValueError(
            f"attack_seed and session_seed must differ, got {attack_seed!r} "
            f"for both; an adversary sharing the session's seed is the defect "
            f"D6 forbids."
        )
    params = ProtocolParams(
        key_length=key_length, check_fraction=check_fraction
    )
    seen: dict[str, float] = {}
    for line in ("resource", "payload"):
        attack = InterceptResend(rng=np.random.default_rng(attack_seed))
        seams = (
            {"resource_factory": attack.resource}
            if line == "resource"
            else {"payload_map": attack.payload}
        )
        session = QDSSession(
            params, rng=np.random.default_rng(session_seed), **seams
        )
        session.distribute()
        session.sign(message_bit)
        qber = []
        chsh = []
        for party in (Party.BOB, Party.CHARLIE):
            for bit in (0, 1):
                log = session.check_logs[(party, bit)]
                qber.extend(log.qber)
                chsh.extend(log.chsh)
        rates = _record_rates(session, message_bit)
        seen[f"{line}_qber"] = estimate_qber(qber).estimate
        seen[f"{line}_chsh"] = estimate_chsh(chsh).statistic
        seen[f"{line}_record_rate"] = sum(rates.values()) / len(rates)
    return seen
