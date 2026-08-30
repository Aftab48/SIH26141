"""Quantum state teleportation: the centrepiece of the Phase 1 physics core.

Teleportation is the primitive the whole problem statement rests on.  A sender
consumes one half of a shared entangled pair together with the qubit carrying an
unknown payload state, performs a joint Bell-basis measurement, and sends two
classical bits; the receiver applies one of four Pauli corrections and holds the
payload exactly.  No quantum information crosses the channel -- only two
classical bits -- so an eavesdropper who touches the entangled resource cannot
learn the payload, but *does* degrade it.  That asymmetry is what Phase 3's
attacks exploit and what Phase 4's detector measures, which is why this module's
one non-negotiable behaviour is:

**a degraded resource must produce a degraded fidelity, with the right number.**

The module is pure linear algebra (design decision D4): no machine learning, no
fitted models, no heuristics.

Three entry points, in order of generality
------------------------------------------
:func:`teleport_in_register`
    The primitive.  Moves **one qubit of an existing register** and preserves
    that qubit's correlations with every other qubit in it, so the payload may
    be entangled with a reference.  Entanglement swapping, multi-hop relays and
    any attack that touches the forward payload line are expressed here.
:func:`teleport`
    The one-qubit special case, a thin wrapper over the primitive.  Takes a
    standalone payload -- **pure or mixed** -- and reports the received state
    and the fidelity against what was submitted.
:func:`teleport_channel`
    The *average* effect of a given resource, as a completely positive
    trace-preserving map on one qubit.  Exact and sampling-free, which is what
    lets Phases 4 and 5 predict a QBER analytically instead of estimating it.
    It is always a Pauli channel; see that function's Notes.

Conventions
-----------
Qubit ordering (D2)
    **Qiskit little-endian.**  Qubit 0 is the *rightmost* character of a
    bitstring label, so ``"01"`` means qubit 1 is :math:`|0\\rangle` and qubit 0
    is :math:`|1\\rangle`.  In the three-qubit teleportation register built by
    :func:`teleport` the **payload occupies qubit 0** and the entangled resource
    occupies qubits 1 and 2, with qubit 2 -- the highest index -- held by the
    receiver.  This is exactly ``resource.tensor(payload)``, since Qiskit's
    :meth:`~qiskit.quantum_info.DensityMatrix.tensor` places its *argument* on
    the low-index qubits.  A big-endian reading would put the payload on qubit 2
    and teleport the wrong half of the pair; ``tests/test_teleport.py`` pins the
    layout down with an asymmetric payload.

Canonical state type (D1)
    :func:`teleport` accepts a :class:`~qiskit.quantum_info.Statevector`, a
    :class:`~qiskit.quantum_info.DensityMatrix` or a raw array for both the
    payload and the resource, normalising through
    :func:`sih141.core.states.as_density`, and returns the receiver's state as a
    :class:`~qiskit.quantum_info.DensityMatrix`.

Determinism (D3)
    The Bell measurement is genuinely stochastic and takes a keyword-only
    ``rng`` resolved through :func:`sih141.core.rng.resolve_rng`.  Exactly one
    uniform variate is consumed per :func:`teleport` call, so a seeded generator
    reproduces a whole experiment bit for bit.

The correction table, derived
-----------------------------
Write the payload as :math:`|\\psi\\rangle = a|0\\rangle + b|1\\rangle` on qubit
0 and the resource as :math:`|\\Phi^{+}\\rangle_{12} =
(|0\\rangle_1|0\\rangle_2 + |1\\rangle_1|1\\rangle_2)/\\sqrt{2}`.  The joint
state is

.. math::
    |\\psi\\rangle_0 \\otimes |\\Phi^{+}\\rangle_{12} = \\tfrac{1}{\\sqrt2}\\big[
        a|0\\rangle_0|0\\rangle_1|0\\rangle_2 + a|0\\rangle_0|1\\rangle_1|1\\rangle_2
      + b|1\\rangle_0|0\\rangle_1|0\\rangle_2 + b|1\\rangle_0|1\\rangle_1|1\\rangle_2
    \\big].

Now expand qubits 0 and 1 in the Bell basis.  Per the pair convention of
:func:`sih141.core.measure.bell_measure`, ``qubits[0] = 0`` plays the role of the
Bell label's qubit 0 (its rightmost bit) and ``qubits[1] = 1`` its qubit 1, so
with :math:`|q_1 q_0\\rangle` labelling,

.. math::
    |0\\rangle_0|0\\rangle_1 &= (|\\Phi^{+}\\rangle + |\\Phi^{-}\\rangle)/\\sqrt2, &
    |1\\rangle_0|1\\rangle_1 &= (|\\Phi^{+}\\rangle - |\\Phi^{-}\\rangle)/\\sqrt2, \\\\
    |1\\rangle_0|0\\rangle_1 &= (|\\Psi^{+}\\rangle + |\\Psi^{-}\\rangle)/\\sqrt2, &
    |0\\rangle_0|1\\rangle_1 &= (|\\Psi^{+}\\rangle - |\\Psi^{-}\\rangle)/\\sqrt2.

Substituting and collecting the four Bell terms gives the teleportation identity

.. math::
    |\\psi\\rangle_0 \\otimes |\\Phi^{+}\\rangle_{12} = \\tfrac{1}{2}\\big[
        |\\Phi^{+}\\rangle(a|0\\rangle + b|1\\rangle)
      + |\\Psi^{+}\\rangle(b|0\\rangle + a|1\\rangle)
      + |\\Phi^{-}\\rangle(a|0\\rangle - b|1\\rangle)
      + |\\Psi^{-}\\rangle(b|0\\rangle - a|1\\rangle)
    \\big]_2,

listed here in :data:`~sih141.core.states.BELL_ORDER`.  Every branch carries
amplitude :math:`1/2`, so each Bell outcome is equiprobable at :math:`1/4` --
which is precisely why the sender's two bits reveal nothing about
:math:`(a, b)`, the information-theoretic reason teleportation is secure.

Reading off the four conditional states of qubit 2 and inverting each one:

===== ============ ============= =============== ==================
index outcome      conditional   :math:`(m_0, m_1)`  correction
===== ============ ============= =============== ==================
0     ``Phi+``     ``(a,  b)``   ``(0, 0)``      :math:`I`
1     ``Psi+``     ``(b,  a)``   ``(1, 0)``      :math:`X`
2     ``Phi-``     ``(a, -b)``   ``(0, 1)``      :math:`Z`
3     ``Psi-``     ``(b, -a)``   ``(1, 1)``      :math:`XZ`
===== ============ ============= =============== ==================

Each row is checked by inverting the conditional column: :math:`X(b, a) =
(a, b)`; :math:`Z(a, -b) = (a, b)`; and :math:`XZ(b, -a) = X(b, a) = (a, b)`.
The :math:`|\\Psi^{-}\\rangle` row is the one that is easy to get wrong.  The
operator order matters there and only up to a global phase, since
:math:`ZX = -XZ`; the product :math:`X^{m_0} Z^{m_1}` (apply :math:`Z` first) is
the form that recovers the payload with *no* residual phase under this module's
sign conventions.  Textbooks that define :math:`|\\Psi^{-}\\rangle` with the
opposite overall sign quote the conditional as :math:`a|1\\rangle - b|0\\rangle`
instead; that differs from the row above by an overall :math:`-1`, physically
irrelevant but enough to break an exact amplitude comparison.

The correction index is the little-endian two-bit number
:math:`2 m_1 + m_0 = ` ``BELL_ORDER.index(outcome)``, with :math:`m_0` the
:math:`X` exponent and :math:`m_1` the :math:`Z` exponent.  These are exactly
the two classical bits the sender transmits, and in the circuit of
:func:`teleport_circuit` they are literally the measured bits: :math:`m_1` is
qubit 0's result and :math:`m_0` is qubit 1's.

Because the derivation is linear in :math:`\\rho`, the same table applies
unchanged to a mixed resource -- the receiver simply ends up with a mixed state
and a fidelity below 1.  For the Werner family
:math:`\\rho(p) = (1 - p)|\\Phi^{+}\\rangle\\!\\langle\\Phi^{+}| + p\\,I/4`
every Bell outcome stays equiprobable and the corrected receiver state is
:math:`(1 - p)|\\psi\\rangle\\!\\langle\\psi| + p\\,I/2`, giving the exact
teleportation fidelity

.. math::
    F(p) = 1 - \\tfrac{p}{2},

which runs from ``1`` (pristine pair) down to ``0.5`` (maximally mixed pair, the
best any classical measure-and-prepare strategy can do).  Phase 3's channel
attacks are calibrated against that line, so the test suite asserts it to
``1e-9`` rather than merely checking that fidelity "goes down".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import numpy as np
from numpy.typing import NDArray
from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
from qiskit.quantum_info import DensityMatrix, Kraus, Statevector, partial_trace

from sih141.core.measure import bell_measure
from sih141.core.paulis import PAULI_X, PAULI_Z
from sih141.core.rng import resolve_rng
from sih141.core.states import (
    BELL_ORDER,
    BellState,
    StateLike,
    as_density,
    bell_state,
)
from sih141.core.states import fidelity as state_fidelity

# `_coerce_state` is imported rather than reimplemented so that the validation
# rules for "is this a physical state" live in exactly one place (states.py).
# It is the only helper that preserves purity, which is what lets this module
# keep a pure payload's exact amplitudes (and global phase) for the result
# record while still accepting a mixed one.  `_psd_eigenvalues` supplies the
# project's single numerical-rank rule, reused by `teleport_channel` when it
# splits a mixed resource into pure branches.
from sih141.core.states import _coerce_state, _psd_eigenvalues

# `_embed_single` *is* the little-endian convention (D2) for operator
# embedding.  Importing it rather than re-deriving a kron loop here keeps the
# endianness of the Pauli correction identical to the endianness of the Bell
# projectors it is paired with; a private re-implementation is exactly how the
# two would silently drift apart.
from sih141.core.measure import _embed_single

__all__ = [
    "TeleportationResult",
    "RegisterTeleportationResult",
    "pauli_correction",
    "correction_bits",
    "teleport",
    "teleport_in_register",
    "teleport_channel",
    "teleport_circuit",
]

ComplexMatrix = NDArray[np.complex128]
"""A dense complex matrix (``numpy.complex128``)."""

#: Payload qubit index in the three-qubit teleportation register (D2).
_PAYLOAD_QUBIT: Final[int] = 0

#: The sender's half of the entangled resource.
_SENDER_QUBIT: Final[int] = 1

#: The receiver's half of the entangled resource; holds the payload at the end.
_RECEIVER_QUBIT: Final[int] = 2


# --------------------------------------------------------------------------- #
# Correction table                                                             #
# --------------------------------------------------------------------------- #


def _validate_outcome(bell_outcome: BellState) -> BellState:
    """Validate a Bell-outcome argument.

    Parameters
    ----------
    bell_outcome : BellState
        The sender's Bell-basis result.

    Returns
    -------
    BellState
        The argument unchanged.

    Raises
    ------
    ValueError
        If ``bell_outcome`` is not a :class:`~sih141.core.states.BellState`
        member.  Passing the raw string ``"Phi+"`` is the expected mistake, so
        the message names the fix.
    """
    if not isinstance(bell_outcome, BellState):
        raise ValueError(
            f"bell_outcome must be a BellState member, got {bell_outcome!r}. "
            "Use e.g. BellState.PHI_PLUS; strings are not coerced because a "
            "typo would silently select the wrong Pauli correction."
        )
    return bell_outcome


def correction_bits(bell_outcome: BellState) -> tuple[int, int]:
    """Return the two classical bits ``(m0, m1)`` the sender transmits.

    These are the *entire* classical message of the teleportation protocol.
    They are read straight off the canonical Bell ordering,

    .. math:: 2 m_1 + m_0 = \\texttt{BELL\\_ORDER.index(outcome)},

    with :math:`m_0` the exponent of :math:`X` and :math:`m_1` the exponent of
    :math:`Z` in the receiver's correction :math:`X^{m_0} Z^{m_1}` (see the
    module docstring for the derivation).  Both outcomes are equiprobable at
    :math:`1/4` for any payload, so the pair carries no information about the
    payload itself -- the reason a classical eavesdropper who reads the two bits
    learns nothing.

    Parameters
    ----------
    bell_outcome : BellState
        The sender's Bell-basis measurement result.

    Returns
    -------
    tuple of int
        ``(m0, m1)``, each ``0`` or ``1``.  ``m0`` is the ``X`` exponent and
        corresponds to the measured bit of qubit 1; ``m1`` is the ``Z`` exponent
        and corresponds to the measured bit of qubit 0.

    Raises
    ------
    ValueError
        If ``bell_outcome`` is not a :class:`~sih141.core.states.BellState`.

    Examples
    --------
    >>> from sih141.core.states import BellState
    >>> correction_bits(BellState.PHI_PLUS)
    (0, 0)
    >>> correction_bits(BellState.PSI_MINUS)
    (1, 1)
    """
    index = BELL_ORDER.index(_validate_outcome(bell_outcome))
    return index & 1, (index >> 1) & 1


def _build_correction(bell_outcome: BellState) -> ComplexMatrix:
    """Construct :math:`X^{m_0} Z^{m_1}` for one Bell outcome.

    Parameters
    ----------
    bell_outcome : BellState
        The sender's Bell-basis result.

    Returns
    -------
    numpy.ndarray
        A read-only ``(2, 2)`` unitary, so a caller who mutates a returned
        matrix cannot corrupt the table for the rest of the process.

    Notes
    -----
    The factors are built with :func:`numpy.linalg.matrix_power` rather than an
    ``if``-ladder so that the code reads as the algebra it implements, with
    ``matrix_power(P, 0) == I`` covering the identity row.  The product order is
    ``X @ Z``: ``Z`` acts on the state first.
    """
    m0, m1 = correction_bits(bell_outcome)
    x_part = np.linalg.matrix_power(np.asarray(PAULI_X, dtype=np.complex128), m0)
    z_part = np.linalg.matrix_power(np.asarray(PAULI_Z, dtype=np.complex128), m1)
    matrix: ComplexMatrix = np.asarray(x_part @ z_part, dtype=np.complex128)
    matrix.setflags(write=False)
    return matrix


_CORRECTIONS: Final[dict[BellState, ComplexMatrix]] = {
    which: _build_correction(which) for which in BELL_ORDER
}


def pauli_correction(bell_outcome: BellState) -> ComplexMatrix:
    """Return the 2x2 unitary the receiver applies for a given Bell outcome.

    Implements the table derived in the module docstring,

    .. math:: U_B = X^{m_0} Z^{m_1}, \\qquad 2 m_1 + m_0 =
              \\texttt{BELL\\_ORDER.index}(B),

    which maps the receiver's conditional state back onto the payload:
    :math:`I` for :math:`|\\Phi^{+}\\rangle`, :math:`X` for
    :math:`|\\Psi^{+}\\rangle`, :math:`Z` for :math:`|\\Phi^{-}\\rangle` and
    :math:`XZ` for :math:`|\\Psi^{-}\\rangle`.  Every one is Hermitian and
    unitary up to a phase, and :math:`U_B^{\\dagger} = U_B^{-1}` is what is
    applied to a density matrix as :math:`U \\rho U^{\\dagger}`.

    Parameters
    ----------
    bell_outcome : BellState
        The sender's Bell-basis measurement result.

    Returns
    -------
    numpy.ndarray
        A fresh, writeable ``(2, 2)`` ``complex128`` unitary.  A copy is made on
        every call so that callers may scale or modify it without disturbing the
        shared table.

    Raises
    ------
    ValueError
        If ``bell_outcome`` is not a :class:`~sih141.core.states.BellState`.

    Examples
    --------
    >>> from sih141.core.states import BellState
    >>> pauli_correction(BellState.PHI_PLUS)
    array([[1.+0.j, 0.+0.j],
           [0.+0.j, 1.+0.j]])
    >>> pauli_correction(BellState.PSI_MINUS)
    array([[ 0.+0.j, -1.+0.j],
           [ 1.+0.j,  0.+0.j]])
    """
    return _CORRECTIONS[_validate_outcome(bell_outcome)].copy()


# --------------------------------------------------------------------------- #
# Result record                                                                #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TeleportationResult:
    """The complete record of one teleportation run.

    Everything a later phase needs to audit the run is kept: the payload that
    was sent, the sender's Bell outcome, the two classical bits that were
    transmitted, the receiver's actual state, and the fidelity between the two.
    Phase 4's detector consumes ``fidelity`` (and, for the entanglement-based
    tests, ``received``); Phase 5's ROC curves are built from many of these.

    Attributes
    ----------
    payload : StateLike
        The single-qubit state that was sent.  A pure payload is kept as the
        :class:`~qiskit.quantum_info.Statevector` it was given as, with its
        exact amplitudes and global phase preserved; a *mixed* payload is kept
        as the :class:`~qiskit.quantum_info.DensityMatrix` it was given as,
        never purified.  ``fidelity`` is always measured against this object,
        so the reported number means what it says in both cases.
    bell_outcome : sih141.core.states.BellState
        Which Bell state the sender's pair was projected onto.  Equiprobable at
        :math:`1/4` for an ideal resource.
    classical_bits : tuple of int
        The transmitted pair ``(m0, m1)``; see :func:`correction_bits`.
        Always equal to ``correction_bits(bell_outcome)``.
    received : qiskit.quantum_info.DensityMatrix
        The receiver's final single-qubit state, **after** the Pauli correction
        (D1).  Mixed whenever the resource was noisy.
    fidelity : float
        :math:`F(\\rho_{\\text{payload}}, \\rho_{\\text{recv}})` in the squared
        (Uhlmann) convention of :func:`sih141.core.states.fidelity`, so ``1.0``
        means the payload arrived exactly.  ``0.5`` is the classical-strategy
        floor reached with a maximally mixed resource *for a pure payload*; a
        mixed payload is harder to disturb and floors higher.

    Raises
    ------
    ValueError
        If ``classical_bits`` disagrees with ``bell_outcome``, the payload or
        the received state is not a single qubit, or ``fidelity`` lies outside
        ``[0, 1]``.  These are internal-consistency checks: a violation means a
        bug in this module, not bad user input.
    """

    payload: StateLike
    bell_outcome: BellState
    classical_bits: tuple[int, int]
    received: DensityMatrix
    fidelity: float

    def __post_init__(self) -> None:
        """Validate the record's internal consistency."""
        expected_bits = correction_bits(self.bell_outcome)
        if tuple(self.classical_bits) != expected_bits:
            raise ValueError(
                f"classical_bits {self.classical_bits!r} disagree with "
                f"bell_outcome {self.bell_outcome!r}, which requires "
                f"{expected_bits!r}. The bits are 2*m1 + m0 == "
                "BELL_ORDER.index(outcome)."
            )
        # `payload` is StateLike, so its qubit count is read through the shared
        # validator rather than off an attribute that a raw array would lack.
        if _coerce_state(self.payload).num_qubits != 1:
            raise ValueError(
                f"payload must be a single-qubit state, got "
                f"{_coerce_state(self.payload).num_qubits} qubits."
            )
        if self.received.num_qubits != 1:
            raise ValueError(
                f"received must be a single-qubit state, got "
                f"{self.received.num_qubits} qubits."
            )
        if not 0.0 <= float(self.fidelity) <= 1.0:
            raise ValueError(
                f"fidelity must lie in [0, 1], got {self.fidelity!r}."
            )


@dataclass(frozen=True)
class RegisterTeleportationResult:
    """The record of one :func:`teleport_in_register` run.

    The general primitive moves *one qubit of a larger register* and keeps every
    correlation that qubit had with the rest of it, so there is no single
    "received state" to report and no fidelity that would be meaningful without
    a reference: the answer is the whole post-teleportation register together
    with the index the payload now occupies.  Phase 2's signature relay and
    Phase 3's entanglement-swapping attacks consume this record;
    :class:`TeleportationResult` is the one-qubit special case built on top.

    Attributes
    ----------
    register : qiskit.quantum_info.DensityMatrix
        The post-teleportation register (D1), with the two consumed qubits --
        the payload qubit and the sender's half of the resource -- traced out,
        and the Pauli correction already applied.  It therefore has two fewer
        qubits than the input register, with the surviving qubits keeping their
        relative order.
    bell_outcome : sih141.core.states.BellState
        Which Bell state the sender's pair was projected onto.
    classical_bits : tuple of int
        The transmitted pair ``(m0, m1)``; see :func:`correction_bits`.
        Always equal to ``correction_bits(bell_outcome)``.
    payload_index : int
        Where the teleported qubit lives in ``register``.  This is the
        receiver's half of the resource, re-indexed for the two removed qubits:
        ``resource_qubits[1] - (number of consumed indices below it)``.

    Raises
    ------
    ValueError
        If ``classical_bits`` disagrees with ``bell_outcome`` or
        ``payload_index`` is not a valid index into ``register``.  These are
        internal-consistency checks: a violation means a bug in this module.
    """

    register: DensityMatrix
    bell_outcome: BellState
    classical_bits: tuple[int, int]
    payload_index: int

    def __post_init__(self) -> None:
        """Validate the record's internal consistency."""
        expected_bits = correction_bits(self.bell_outcome)
        if tuple(self.classical_bits) != expected_bits:
            raise ValueError(
                f"classical_bits {self.classical_bits!r} disagree with "
                f"bell_outcome {self.bell_outcome!r}, which requires "
                f"{expected_bits!r}. The bits are 2*m1 + m0 == "
                "BELL_ORDER.index(outcome)."
            )
        num_qubits = self.register.num_qubits
        if not 0 <= int(self.payload_index) < num_qubits:
            raise ValueError(
                f"payload_index {self.payload_index!r} is out of range for a "
                f"{num_qubits}-qubit register; it must satisfy "
                f"0 <= payload_index < {num_qubits}."
            )


# --------------------------------------------------------------------------- #
# Input normalisation                                                          #
# --------------------------------------------------------------------------- #


def _payload_state(payload: StateLike) -> Statevector | DensityMatrix:
    """Normalise the payload argument to a validated single-qubit state.

    Accepts either representation (D1) and, since the Phase 1 audit, **either
    purity**.  A :class:`~qiskit.quantum_info.Statevector` or 1-D array is
    returned as a ``Statevector``, preserving its amplitudes and global phase
    exactly; a 2-D input is returned as a
    :class:`~qiskit.quantum_info.DensityMatrix` *unchanged*, pure or mixed.

    Nothing is purified.  The earlier version rejected a mixed payload on the
    grounds that :class:`TeleportationResult` reported the payload as a
    statevector; the record now carries whatever was submitted and measures
    ``fidelity`` against it, so the number means the same thing either way and
    the restriction has been removed.  It was blocking two real Phase 3
    scenarios -- noise or an intercept-resend acting on the *forward payload
    line* rather than on the entanglement resource, and relaying a key qubit
    over more than one hop -- neither of which is faithfully modelled by
    degrading the resource instead.

    Parameters
    ----------
    payload : StateLike
        The single-qubit state to teleport, pure or mixed.

    Returns
    -------
    qiskit.quantum_info.Statevector or qiskit.quantum_info.DensityMatrix
        ``Statevector`` for 1-D input, ``DensityMatrix`` for 2-D input.

    Raises
    ------
    ValueError
        If the payload is not a valid physical state or is not a single qubit.
    """
    coerced = _coerce_state(payload)
    if coerced.num_qubits != 1:
        raise ValueError(
            f"payload must be a single-qubit state, got "
            f"{coerced.num_qubits} qubits (dimension {coerced.dim}). "
            "Teleportation as modelled here moves one qubit."
        )
    if isinstance(coerced, Statevector):
        return Statevector(np.asarray(coerced.data, dtype=np.complex128))
    return coerced


def _resource_density(resource: StateLike | None) -> DensityMatrix:
    """Normalise the entanglement resource to a two-qubit density matrix.

    Parameters
    ----------
    resource : StateLike or None
        The shared pair.  ``None`` selects the ideal
        :math:`|\\Phi^{+}\\rangle = (|00\\rangle + |11\\rangle)/\\sqrt{2}`.
        Any pure or mixed two-qubit state is accepted, which is what lets
        Phase 3 hand this function a depolarised or intercepted pair.

    Returns
    -------
    qiskit.quantum_info.DensityMatrix
        The resource as a validated density operator (D1).

    Raises
    ------
    ValueError
        If the resource is not a valid state or is not a two-qubit state.
    """
    if resource is None:
        return as_density(bell_state(BellState.PHI_PLUS))
    density = as_density(resource)
    if density.num_qubits != 2:
        raise ValueError(
            f"resource must be a two-qubit state (the shared entangled pair), "
            f"got {density.num_qubits} qubits (dimension {density.dim})."
        )
    return density


def _check_register_index(index: int, num_qubits: int, *, name: str) -> int:
    """Validate one qubit index against a register size.

    Parameters
    ----------
    index : int
        Candidate qubit index.
    num_qubits : int
        Size of the register the index must address.
    name : str
        Parameter name, used to make the error message actionable.

    Returns
    -------
    int
        The index as a plain :class:`int`.

    Raises
    ------
    ValueError
        If ``index`` is not an integer or lies outside ``[0, num_qubits)``.
        :class:`bool` is rejected explicitly: ``True`` would otherwise silently
        mean qubit 1.
    """
    if isinstance(index, bool) or not isinstance(index, (int, np.integer)):
        raise ValueError(
            f"{name} must be an integer qubit index, got {index!r} of type "
            f"{type(index).__name__!r}."
        )
    value = int(index)
    if not 0 <= value < num_qubits:
        raise ValueError(
            f"{name} must satisfy 0 <= {name} < {num_qubits} for this "
            f"{num_qubits}-qubit register, got {value}."
        )
    return value


# --------------------------------------------------------------------------- #
# The protocol                                                                 #
# --------------------------------------------------------------------------- #


def teleport_in_register(
    register: StateLike,
    *,
    payload_qubit: int,
    resource_qubits: tuple[int, int],
    rng: np.random.Generator | None = None,
) -> RegisterTeleportationResult:
    """Teleport one qubit of an existing register, keeping its correlations.

    This is the general primitive; :func:`teleport` is the one-qubit special
    case expressed in terms of it.  The payload qubit does **not** have to be a
    standalone pure state: it may be entangled with any number of spectator
    qubits in the same register, and those correlations are carried over to the
    receiver's qubit intact.  That is what makes entanglement swapping, relaying
    a signature qubit over several hops, and any Phase 3 attack that touches the
    forward payload line expressible at all.

    Mechanically the routine is the same three steps :func:`teleport` runs, only
    without assuming where anything lives: a genuine Bell-basis collapse on
    ``(payload_qubit, resource_qubits[0])`` sampled from the Born distribution
    by :func:`sih141.core.measure.bell_measure`, a partial trace over those two
    consumed qubits, and the Pauli correction of :func:`pauli_correction`
    applied to the receiver's qubit *in place inside the surviving register*.
    Because the Bell projector acts as the identity on every spectator, the
    spectators are left in their correct conditional state rather than being
    disturbed -- see the derivation in the module docstring, which is linear in
    :math:`\\rho` and so never needed the payload to be pure or standalone.

    Parameters
    ----------
    register : StateLike
        The whole register, pure or mixed, of at least three qubits (D1).
    payload_qubit : int
        Keyword-only.  Index of the qubit being teleported.  It plays the role
        of the Bell label's qubit 0 in the sender's measurement.
    resource_qubits : tuple of int
        Keyword-only.  ``(sender_half, receiver_half)``.  ``resource_qubits[0]``
        is the sender's half -- the qubit consumed alongside the payload -- and
        plays the role of the Bell label's qubit 1; ``resource_qubits[1]`` is
        the receiver's half, which survives and ends up holding the payload.
        Getting these two the wrong way round teleports in the wrong direction,
        so the order is not symmetric even though :math:`|\\Phi^{+}\\rangle`
        itself is.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3).  Resolved through
        :func:`sih141.core.rng.resolve_rng`.  Exactly one uniform variate is
        consumed, by the Bell measurement.

    Returns
    -------
    RegisterTeleportationResult
        The post-teleportation register (two qubits smaller), the Bell outcome,
        the two classical bits, and the index the payload now occupies.

    Raises
    ------
    ValueError
        If ``register`` is not a valid state or has fewer than three qubits, if
        ``resource_qubits`` is not a pair, if any index is out of range, if the
        three indices are not distinct, or if the collapsed branch cannot be
        renormalised.
    TypeError
        If ``rng`` is neither ``None`` nor a :class:`numpy.random.Generator`.

    Notes
    -----
    Index bookkeeping: tracing out two qubits renumbers everything above them.
    The surviving qubits keep their *relative* order, so a qubit that sat at
    index ``q`` moves to ``q`` minus the number of consumed indices below ``q``.
    ``payload_index`` is that image of ``resource_qubits[1]``; every spectator
    is re-indexed by the same rule.

    Examples
    --------
    Teleport half of a Bell pair and watch the entanglement survive.  The pair
    ``(A, R)`` sits on qubits 0 and 1 and the resource on qubits 2 and 3, so the
    survivors are the reference (index 0) and the teleported qubit (index 1):

    >>> import numpy as np
    >>> from qiskit.quantum_info import DensityMatrix
    >>> from sih141.core.states import bell_state, concurrence
    >>> pair = DensityMatrix(bell_state())
    >>> register = DensityMatrix(bell_state()).tensor(pair)
    >>> moved = teleport_in_register(
    ...     register,
    ...     payload_qubit=0,
    ...     resource_qubits=(2, 3),
    ...     rng=np.random.default_rng(20260141),
    ... )
    >>> moved.payload_index
    1
    >>> round(concurrence(moved.register), 12)
    1.0
    """
    generator = resolve_rng(rng)
    density = as_density(register)
    num_qubits = density.num_qubits
    if num_qubits < 3:
        raise ValueError(
            f"teleport_in_register needs at least three qubits (payload, "
            f"sender's half, receiver's half), got a {num_qubits}-qubit "
            "register. Use teleport() for a standalone single-qubit payload; "
            "it builds the three-qubit register for you."
        )
    if not isinstance(resource_qubits, tuple) or len(resource_qubits) != 2:
        raise ValueError(
            "resource_qubits must be a tuple of two distinct qubit indices "
            f"(sender's half, receiver's half), got {resource_qubits!r}."
        )
    payload = _check_register_index(payload_qubit, num_qubits, name="payload_qubit")
    sender = _check_register_index(
        resource_qubits[0], num_qubits, name="resource_qubits[0]"
    )
    receiver = _check_register_index(
        resource_qubits[1], num_qubits, name="resource_qubits[1]"
    )
    if len({payload, sender, receiver}) != 3:
        raise ValueError(
            f"payload_qubit ({payload}) and resource_qubits "
            f"({sender}, {receiver}) must be three distinct qubits: the "
            "payload and the sender's half are both consumed by the Bell "
            "measurement and the receiver's half must survive it."
        )

    outcome, collapsed = bell_measure(density, (payload, sender), rng=generator)

    # Tracing out the two consumed qubits leaves the spectators and the
    # receiver's half in their joint *conditional* state -- entanglement with
    # the spectators included, which is the whole point of this primitive.
    reduced = partial_trace(collapsed, [payload, sender])
    remaining = num_qubits - 2
    new_index = receiver - sum(1 for consumed in (payload, sender) if consumed < receiver)

    unitary = _embed_single(_CORRECTIONS[outcome], new_index, remaining)
    corrected = (
        unitary
        @ np.asarray(reduced.data, dtype=np.complex128)
        @ unitary.conj().T
    )
    # Re-symmetrise and renormalise: partial_trace plus the triple product leave
    # an anti-Hermitian residue of order 1e-17 that would otherwise trip the
    # Hermiticity check in states.as_density downstream.
    corrected = 0.5 * (corrected + corrected.conj().T)
    trace = float(np.trace(corrected).real)
    if not np.isfinite(trace) or trace <= 0.0:
        raise ValueError(
            f"the collapsed register has non-positive trace {trace!r} and "
            "cannot be renormalised; the input register was accepted as "
            "physical, so this indicates a bug in the Bell projectors."
        )
    corrected = corrected / trace

    return RegisterTeleportationResult(
        register=DensityMatrix(corrected, dims=(2,) * remaining),
        bell_outcome=outcome,
        classical_bits=correction_bits(outcome),
        payload_index=new_index,
    )


def teleport(
    payload: StateLike,
    *,
    resource: StateLike | None = None,
    rng: np.random.Generator | None = None,
) -> TeleportationResult:
    """Teleport a single-qubit payload across a shared entangled pair.

    A thin wrapper over :func:`teleport_in_register`: the payload and the
    resource are combined into one three-qubit register and the general
    primitive does the work, so the two cannot disagree about the correction
    table, the endianness or the collapse.  Nothing is short-cut -- qubits 0 and
    1 are genuinely projected onto the Bell basis by
    :func:`sih141.core.measure.bell_measure`, sampled from the Born
    distribution, the consumed qubits are traced out, and the receiver's state
    is read out of the collapsed register -- so a noisy resource propagates its
    noise through the whole chain instead of being special-cased.

    Register layout (D2, little-endian): payload on qubit 0, sender's half of
    the resource on qubit 1, receiver's half on qubit 2.

    Use :func:`teleport_in_register` instead when the qubit being moved is
    correlated with something that has to survive the hop, and
    :func:`teleport_channel` when the *average* effect of a resource is wanted
    analytically rather than sampled.

    Parameters
    ----------
    payload : StateLike
        The single-qubit state to send, **pure or mixed**: a
        :class:`~qiskit.quantum_info.Statevector`, a 1-D amplitude array, or any
        physical :class:`~qiskit.quantum_info.DensityMatrix`.  A mixed payload is
        teleported by exactly the same algebra and is *not* purified; the
        reported ``fidelity`` is measured against what was actually submitted.
        This is the path Phase 3 uses when noise or an interception acts on the
        forward payload line rather than on the resource, and when a key qubit
        is relayed over more than one hop.
    resource : StateLike or None, optional
        Keyword-only.  The shared two-qubit pair, pure or mixed.  Defaults to
        :math:`|\\Phi^{+}\\rangle`.  Degrading it is the whole point of the
        Phase 3 attack model: the returned ``fidelity`` falls accordingly, and
        for the Werner family
        :math:`(1-p)|\\Phi^{+}\\rangle\\!\\langle\\Phi^{+}| + p\\,I/4` it is
        exactly :math:`1 - p/2`.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3).  Resolved through
        :func:`sih141.core.rng.resolve_rng`.  Exactly one uniform variate is
        consumed, by the Bell measurement, so a seeded generator makes the run
        reproducible.

    Returns
    -------
    TeleportationResult
        The payload, the Bell outcome, the two classical bits, the receiver's
        density matrix and the fidelity.

    Raises
    ------
    ValueError
        If the payload is not a valid single-qubit state, if the resource is
        not a valid two-qubit state, or if the sampled Bell branch cannot be
        renormalised.
    TypeError
        If ``rng`` is neither ``None`` nor a :class:`numpy.random.Generator`.

    Notes
    -----
    No-cloning is respected by construction: the Bell measurement destroys the
    payload qubit, and ``received`` is obtained by tracing the payload and
    sender qubits *out* of the collapsed register, so the payload never exists
    in two places at once.  This is also why the protocol cannot be used to
    signal: the receiver's marginal state before the correction does not depend
    on the payload at all, so no measurement the receiver can make reveals
    anything until the two classical bits -- which must travel classically, at
    or below light speed -- arrive.

    That payload-independent marginal is the resource's own reduced state on the
    receiver's qubit, :math:`\\mathrm{Tr}_{1}\\rho_{\\text{res}}`.  It equals
    :math:`I/2` only when the resource is *locally* maximally mixed, which every
    Bell state and every Werner state is -- but which an amplitude-damped
    resource is **not**, and Phase 3 passes exactly those in.  The
    no-signalling argument needs only the payload-independence, not the
    :math:`I/2`; the two were run together in an earlier version of this
    docstring and the second half was simply wrong for the damped family.

    Examples
    --------
    >>> import numpy as np
    >>> from qiskit.quantum_info import Statevector
    >>> payload = Statevector(np.array([0.6, 0.8j]))
    >>> result = teleport(payload, rng=np.random.default_rng(20260141))
    >>> round(result.fidelity, 12)
    1.0
    >>> result.classical_bits == correction_bits(result.bell_outcome)
    True
    """
    generator = resolve_rng(rng)
    payload_state = _payload_state(payload)
    resource_state = _resource_density(resource)

    # resource.tensor(payload) puts the payload on the LOW qubit index, so the
    # register is (q2, q1 = resource) (x) (q0 = payload) in little-endian order.
    register = resource_state.tensor(as_density(payload_state))

    moved = teleport_in_register(
        register,
        payload_qubit=_PAYLOAD_QUBIT,
        resource_qubits=(_SENDER_QUBIT, _RECEIVER_QUBIT),
        rng=generator,
    )
    # Only the receiver's qubit survives, so the reduced register *is* the
    # received state and `payload_index` is necessarily 0.
    received = moved.register

    return TeleportationResult(
        payload=payload_state,
        bell_outcome=moved.bell_outcome,
        classical_bits=moved.classical_bits,
        received=received,
        # states.fidelity, not qiskit's raw state_fidelity: the raw function
        # returns 1.000000000000001 for a sizeable fraction of pure-vs-pure
        # comparisons, which TeleportationResult.__post_init__ hard-rejects.
        # The clipped helper makes the [0, 1] invariant true by construction
        # rather than by luck of the rounding.
        fidelity=state_fidelity(payload_state, received),
    )


# --------------------------------------------------------------------------- #
# The induced channel (analytic, for Phases 4 and 5)                           #
# --------------------------------------------------------------------------- #


def _branch_map(bell_vector: ComplexMatrix, resource_vector: ComplexMatrix) -> ComplexMatrix:
    """Build the unnormalised payload map for one Bell outcome and one branch.

    Contracts the payload index against a Bell bra on ``(payload, sender)`` and
    a pure resource ket on ``(sender, receiver)``, leaving a ``(2, 2)`` matrix
    that carries the payload's Hilbert space onto the receiver's:

    .. math::
        M[r, p] = \\sum_{s} \\overline{B_{2s + p}}\\; \\chi_{2r + s}.

    The index arithmetic *is* the little-endian convention (D2) plus the pair
    convention of :func:`sih141.core.measure.bell_measure`: in the Bell label
    the payload is qubit 0 and the sender is qubit 1, so the Bell amplitude
    index is ``2*s + p``; in the resource the sender is qubit 0 and the receiver
    is qubit 1, so the resource amplitude index is ``2*r + s``.

    Parameters
    ----------
    bell_vector : numpy.ndarray
        The 4-amplitude Bell state, in the order of
        :func:`sih141.core.states.bell_state`.
    resource_vector : numpy.ndarray
        One pure branch of the resource, scaled by the square root of its
        weight, so that the branches sum back to the mixed resource.

    Returns
    -------
    numpy.ndarray
        A ``(2, 2)`` ``complex128`` matrix.
    """
    bra = np.conj(bell_vector).reshape(2, 2)  # [s, p]
    ket = resource_vector.reshape(2, 2)  # [r, s]
    return np.asarray(ket @ bra, dtype=np.complex128)  # [r, p]


def teleport_channel(resource: StateLike | None = None) -> Kraus:
    """Return the single-qubit quantum channel induced by a teleportation.

    :func:`teleport` samples one Bell outcome and returns one conditional state.
    Averaging that over the outcomes -- each weighted by its own Born
    probability, with its correction applied -- gives a completely positive,
    trace-preserving map on the payload qubit:

    .. math::
        \\mathcal{E}_{\\rho_{\\text{res}}}(\\rho) = \\sum_{B}
            U_B\\,\\mathrm{Tr}_{p,s}\\!\\left[
                \\Pi_B\\,(\\rho \\otimes \\rho_{\\text{res}})\\,\\Pi_B
            \\right] U_B^{\\dagger}.

    This is the object Phases 4 and 5 need.  A QBER or an average fidelity
    predicted from it is **exact**, where the same number obtained by calling
    :func:`teleport` many times carries a :math:`1/\\sqrt{N}` sampling error;
    ROC curves built on a sampled threshold inherit that error, and an analytic
    threshold does not.

    The Kraus operators are written down in closed form rather than by
    tomography.  Diagonalising the resource as
    :math:`\\rho_{\\text{res}} = \\sum_k \\lambda_k |v_k\\rangle\\!\\langle v_k|`
    and writing :math:`|\\chi_k\\rangle = \\sqrt{\\lambda_k}\\,|v_k\\rangle`,
    each ``(B, k)`` pair contributes

    .. math:: K_{B,k} = U_B M_{B,k}, \\qquad
              M_{B,k}[r, p] = \\sum_s \\overline{(B)_{2s+p}}\\,(\\chi_k)_{2r+s},

    which is just the teleportation identity of the module docstring with the
    payload left as a free index.  Branches whose weight falls below the
    project's numerical-rank cutoff (:func:`sih141.core.states._psd_eigenvalues`)
    are dropped, so a pure resource yields four Kraus operators and a rank-four
    one sixteen.

    Parameters
    ----------
    resource : StateLike or None, optional
        The shared two-qubit pair, pure or mixed, with qubit 0 the sender's half
        and qubit 1 the receiver's -- the same convention :func:`teleport` uses.
        ``None`` selects the ideal :math:`|\\Phi^{+}\\rangle`.

    Returns
    -------
    qiskit.quantum_info.Kraus
        The induced channel.  Convert with
        :class:`qiskit.quantum_info.Choi` or
        :class:`qiskit.quantum_info.SuperOp` to compose or compare channels;
        ``Choi`` is the representation to compare *by*, since the Kraus set
        itself is only defined up to an isometry.

    Raises
    ------
    ValueError
        If ``resource`` is not a valid two-qubit state.

    Notes
    -----
    **The induced channel is always a Pauli channel.**  The corrections twirl
    the resource, so only its *diagonal in the Bell basis* survives: writing
    :math:`q_B = \\langle B|\\rho_{\\text{res}}|B\\rangle`,

    .. math:: \\mathcal{E}(\\rho) = \\sum_{B} q_B\\, U_B \\rho\\, U_B^{\\dagger}.

    Phase 4 can therefore read a QBER off four inner products with no tomography
    and no sampling at all, and Phase 5 can rely on multi-hop chains depending
    only on the *multiset* of hops: every teleportation channel is unital and
    any two of them commute, even when the noise processes that produced the two
    resources do not.  A non-unital resource does not give a non-unital channel;
    amplitude damping on the resource appears here purely as a lopsided
    :math:`q_B`.  ``tests/test_teleport.py`` asserts this identity against the
    closed form above for five resources.

    Two limits pin the construction down and are asserted in the test suite via
    the Choi matrix rather than by sampling:
    :math:`\\mathcal{E}_{|\\Phi^{+}\\rangle}` is the **identity** channel (all
    four Kraus operators come out as :math:`\\pm I/2`; the minus lands on the
    :math:`|\\Psi^{-}\\rangle` branch, from the global sign of :math:`XZ`, and a
    Kraus operator is free to carry a phase), and :math:`\\mathcal{E}_{I/4}` is
    the **completely depolarising** channel :math:`\\rho \\mapsto I/2`.  The
    Werner family interpolates linearly between them as the depolarising channel
    :math:`\\rho \\mapsto (1-p)\\rho + p\\,I/2`, which is where the fidelity law
    :math:`F = 1 - p/2` of the module docstring comes from, and which is why two
    hops through Werner resources compose as :math:`(1-p_1)(1-p_2)`.

    Examples
    --------
    >>> import numpy as np
    >>> from qiskit.quantum_info import Choi, Operator
    >>> channel = teleport_channel()
    >>> bool(np.allclose(Choi(channel).data, Choi(Operator(np.eye(2))).data))
    True
    """
    density = np.asarray(
        _resource_density(resource).data, dtype=np.complex128
    )
    # eigh reads one triangle only, so symmetrise first: as_density has already
    # bounded the anti-Hermitian residue but not removed it.
    weights, vectors = np.linalg.eigh(0.5 * (density + density.conj().T))
    weights = _psd_eigenvalues(np.asarray(weights, dtype=np.float64))

    bell_vectors = {
        which: np.asarray(bell_state(which).data, dtype=np.complex128)
        for which in BELL_ORDER
    }

    operators: list[ComplexMatrix] = []
    for index, weight in enumerate(weights):
        if weight <= 0.0:
            continue
        branch = np.sqrt(weight) * np.asarray(
            vectors[:, index], dtype=np.complex128
        )
        for which in BELL_ORDER:
            operators.append(
                _CORRECTIONS[which] @ _branch_map(bell_vectors[which], branch)
            )
    return Kraus(operators)


# --------------------------------------------------------------------------- #
# Circuit form (documentation / visualisation)                                 #
# --------------------------------------------------------------------------- #


def _teleport_core() -> QuantumCircuit:
    """Return the measurement-free unitary part of the teleportation circuit.

    Two blocks, in circuit (time) order:

    1. ``h(1); cx(1, 2)`` -- the entangler of
       :func:`sih141.core.states.bell_circuit`, preparing
       :math:`|\\Phi^{+}\\rangle` on qubits 1 and 2 from :math:`|00\\rangle`.
    2. ``cx(0, 1); h(0)`` -- the *inverse* of that entangler acting on qubits 0
       and 1, which rotates the Bell basis of the pair onto the computational
       basis so the joint measurement becomes two ordinary Z measurements.

    Splitting this out from :func:`teleport_circuit` is what lets the test suite
    verify the gate order exactly, with a plain
    :class:`~qiskit.quantum_info.Operator`, instead of needing a simulator that
    can execute mid-circuit conditionals.

    Returns
    -------
    qiskit.QuantumCircuit
        A three-qubit, measurement-free, classical-register-free circuit.

    Notes
    -----
    Applying this to :math:`|0\\rangle_2|0\\rangle_1|\\psi\\rangle_0` gives

    .. math::
        \\tfrac{1}{2}\\big[ |00\\rangle(a|0\\rangle + b|1\\rangle)
        + |01\\rangle(a|0\\rangle - b|1\\rangle)
        + |10\\rangle(b|0\\rangle + a|1\\rangle)
        - |11\\rangle(b|0\\rangle - a|1\\rangle) \\big],

    labelled :math:`|q_1 q_0\\rangle`.  Comparing with the Bell-basis expansion
    in the module docstring identifies :math:`m_1` with qubit 0's bit and
    :math:`m_0` with qubit 1's bit; the sign on the :math:`|11\\rangle` branch is
    a global phase on that branch and does not affect the correction.
    """
    circuit = QuantumCircuit(3, name="teleport_core")
    circuit.h(_SENDER_QUBIT)
    circuit.cx(_SENDER_QUBIT, _RECEIVER_QUBIT)
    circuit.barrier()
    circuit.cx(_PAYLOAD_QUBIT, _SENDER_QUBIT)
    circuit.h(_PAYLOAD_QUBIT)
    return circuit


def teleport_circuit() -> QuantumCircuit:
    """Return the textbook three-qubit teleportation circuit.

    Provided for documentation, teaching and the Phase 6 dashboard: it draws the
    protocol that :func:`teleport` implements with linear algebra.  The two
    agree by construction -- ``tests/test_teleport.py`` runs this circuit on a
    simulator and checks that the receiver ends up in the payload state -- but
    :func:`teleport` is the function every other phase should call, because it
    accepts a *mixed* resource and reports the fidelity.

    Layout (D2, little-endian): ``q0`` carries the payload (prepare it before
    composing this circuit), ``q1`` and ``q2`` start in :math:`|00\\rangle` and
    are entangled by the circuit itself, and ``q2`` holds the payload at the
    end.  The classical register ``m`` stores ``m[0] = m0`` (qubit 1's result,
    the :math:`X` exponent) and ``m[1] = m1`` (qubit 0's result, the :math:`Z`
    exponent), so its little-endian value :math:`2 m_1 + m_0` is exactly
    ``BELL_ORDER.index(outcome)``.

    Returns
    -------
    qiskit.QuantumCircuit
        A circuit on three qubits and two classical bits, containing mid-circuit
        measurements and two classically conditioned Pauli gates (expressed with
        Qiskit's ``if_test`` control-flow builder).

    Notes
    -----
    The correction is applied as :math:`Z` *then* :math:`X`, matching the matrix
    product :math:`X^{m_0} Z^{m_1}` of :func:`pauli_correction`; on the
    :math:`|\\Psi^{-}\\rangle` branch the opposite order would differ by a global
    phase.  The conditional gates are genuinely classically controlled, which is
    what makes the circuit an honest picture of the protocol: no quantum
    information flows from sender to receiver, only the two bits in ``m``.
    """
    qreg = QuantumRegister(3, "q")
    creg = ClassicalRegister(2, "m")
    circuit = QuantumCircuit(qreg, creg, name="teleport")
    circuit.compose(_teleport_core(), qubits=qreg, inplace=True)

    circuit.measure(_SENDER_QUBIT, creg[0])  # m0: the X exponent
    circuit.measure(_PAYLOAD_QUBIT, creg[1])  # m1: the Z exponent
    circuit.barrier()

    with circuit.if_test((creg[1], 1)):
        circuit.z(_RECEIVER_QUBIT)
    with circuit.if_test((creg[0], 1)):
        circuit.x(_RECEIVER_QUBIT)
    return circuit
