"""Projective measurement: Born probabilities, collapse, sampling, expectations.

This is the module the rest of the project measures *through*.  Phase 2's QDS
protocol reads out signature qubits with it, Phase 3's intercept-resend attacker
uses it to eavesdrop, Phase 4's detector consumes the counts and expectation
values it produces, and :mod:`sih141.core.teleport` is built directly on
:func:`bell_measure`.  It contains linear algebra and one multinomial draw --
no machine learning of any kind (design decision D4).

Conventions
-----------
Qubit ordering (D2)
    **Qiskit little-endian.**  Qubit 0 is the *rightmost* character of a
    bitstring label.  A single-qubit operator acting on qubit ``q`` of an
    ``n``-qubit register is embedded as

    .. math::
        \\mathbb{1}_{n-1} \\otimes \\cdots \\otimes A_q \\otimes \\cdots
        \\otimes \\mathbb{1}_0,

    i.e. ``kron`` runs from the *highest* qubit index down to qubit 0 (see
    :func:`_embed_single`).  Amplitude index and bit values are related by
    ``index = sum_q b_q * 2**q``.  Bitstring keys returned by
    :func:`sample_counts` are written most-significant-measured-qubit first, so
    the rightmost character is the lowest measured qubit index.  The test suite
    pins this down with asymmetric states such as :math:`|01\\rangle`, which a
    big-endian implementation would get demonstrably wrong.

Canonical state type (D1)
    Every function here *accepts* a :class:`~qiskit.quantum_info.Statevector`, a
    :class:`~qiskit.quantum_info.DensityMatrix` or a raw array, normalising the
    input through the single shared helper
    :func:`sih141.core.states.as_density`, and every function that *returns* a
    post-measurement state returns a :class:`~qiskit.quantum_info.DensityMatrix`.
    Mixed states are therefore first-class from the start, which is what lets
    Phase 3 push depolarised and intercepted states through these same call
    sites unchanged.

Determinism (D3)
    Everything stochastic takes a keyword-only ``rng`` resolved through
    :func:`sih141.core.rng.resolve_rng`.  ``numpy.random.*`` module-level
    functions and the stdlib :mod:`random` module are never used.

Eigenvalues and bits
    Measurement results are reported as the physical Pauli eigenvalue
    :math:`\\pm 1` *and* as the classical bit, with the project-wide mapping
    ``+1 -> bit 0`` and ``-1 -> bit 1``.  This agrees with the basis-change
    circuits of :mod:`sih141.core.paulis`, which satisfy
    :math:`U_B|b_{+1}\\rangle = |0\\rangle`.

Physics implemented here
------------------------
For a Pauli observable :math:`\\sigma` on qubit ``q`` the two spectral
projectors are

.. math::
    P_{\\pm} = \\frac{\\mathbb{1} \\pm \\sigma}{2},
    \\qquad P_{\\pm}^{2} = P_{\\pm} = P_{\\pm}^{\\dagger},
    \\qquad P_{+} + P_{-} = \\mathbb{1},

embedded at position ``q``.  The **Born rule** gives the outcome probability

.. math::
    \\Pr(\\pm) = \\mathrm{Tr}(\\rho P_{\\pm}),

which is written as a trace rather than as :math:`|\\langle\\psi|P|\\psi\\rangle|`
precisely so that it is correct for mixed :math:`\\rho`.  The **projection
postulate** (Lueders form) gives the collapsed state

.. math::
    \\rho \\longrightarrow \\rho' = \\frac{P_{\\pm}\\,\\rho\\,P_{\\pm}}
                                        {\\mathrm{Tr}(\\rho P_{\\pm})},

which is again the mixed-state statement; the pure-state rule
:math:`|\\psi\\rangle \\to P|\\psi\\rangle / \\lVert P|\\psi\\rangle\\rVert` is
the special case.  Because :math:`P` is an idempotent projector, measuring the
same qubit twice in the same basis returns the same eigenvalue with probability
exactly 1 -- a property the test suite asserts rather than assumes.

Rare branches: an approximation the collapse path makes and the sampler does not
--------------------------------------------------------------------------------
Every function here that *collapses* the state -- :func:`projective_measure`,
:func:`measure_qubits`, :func:`bell_measure` -- samples from the exact Born
distribution **except** that a branch whose probability is at or below
:data:`_MIN_BRANCH_PROB` (:math:`\\approx 2.2\\times10^{-8}`) is unreachable: it
is skipped by :func:`_select_branch` and its weight is effectively redistributed
over the surviving branches.  The total distortion is bounded by the number of
branches times the floor, i.e. below :math:`4\\times 2.2\\times10^{-8}` for a
Bell measurement.  The reason is stated in full at :data:`_MIN_BRANCH_PROB`: the
collapsed state of such a branch is not a representable density operator, so
reporting it would hand the caller an object the rest of the module rejects.

:func:`sample_counts` does **not** collapse and carries **no** such floor -- it
draws from the exact multinomial over the full joint distribution, so a branch of
probability :math:`10^{-12}` is sampled at its true rate.  Rare-event and
distribution-tail statistics should therefore be gathered with
:func:`sample_counts`, and the collapsing functions reserved for the cases where
the post-measurement state is actually needed.

:func:`bell_measure` is the same machinery with the four rank-:math:`2^{n-2}`
projectors :math:`|B\\rangle\\!\\langle B| \\otimes \\mathbb{1}_{\\text{rest}}`
built from the Bell basis of :mod:`sih141.core.states`.  Because the projector
acts only on the measured pair, the *other* qubits are left in their correct
conditional state -- that conditional state is exactly the teleported payload,
so Phase 1's teleportation module depends on getting this right on registers
larger than the measured pair.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

import numpy as np
from numpy.typing import NDArray
from qiskit.quantum_info import DensityMatrix, Operator, Pauli

# `_as_basis` is imported rather than reimplemented so that the string/enum
# coercion rules and their error messages live in exactly one place (paulis.py).
from sih141.core.paulis import (
    PAULI_I,
    PauliBasis,
    _as_basis,
    basis_change_circuit,
    pauli_matrix,
)
from sih141.core.rng import resolve_rng
from sih141.core.states import (
    BELL_ORDER,
    BellState,
    StateLike,
    _VALIDATION_TOL,
    as_density,
    bell_state,
)

__all__ = [
    "MeasurementOutcome",
    "born_probabilities",
    "projective_measure",
    "measure_qubits",
    "joint_probability",
    "sample_counts",
    "expectation",
    "bell_measure",
]

ComplexMatrix = NDArray[np.complex128]
"""A dense complex matrix (``numpy.complex128``)."""

#: Tolerance on the completeness relation ``p_plus + p_minus == 1``.
#:
#: Deliberately *tied* to :data:`sih141.core.states._VALIDATION_TOL` rather than
#: chosen independently.  :func:`~sih141.core.states.as_density` is the project's
#: canonical state validator and it admits a trace deviation of up to
#: ``_VALIDATION_TOL`` without renormalising, so any tolerance tighter than that
#: here would reject states the project itself declares legal -- and would blame
#: "malformed projectors" for ordinary input drift.  Every measurement entry
#: point must therefore accept exactly what ``as_density`` accepts.  A violation
#: of *this* bound really does indicate an internal projector bug.
_PROB_TOL: Final[float] = _VALIDATION_TOL

#: A measurement branch whose Born probability falls at or below this is treated
#: as physically unreachable and is never selected.
#:
#: The value is **derived, not chosen**.  Collapse evaluates the triple product
#: :math:`P\\rho P`, whose entries carry an *absolute* floating-point residue of
#: order :math:`\\varepsilon = 2.2\\times10^{-16}` while the true result has
#: entries of order :math:`p`.  Renormalising to unit trace therefore inflates
#: that residue to a *relative* error of order :math:`\\varepsilon / p`, which
#: shows up as negative eigenvalues of that size.  Requiring the result to stay
#: within the project's positive-semidefiniteness tolerance,
#: :math:`\\varepsilon / p \\le` ``_VALIDATION_TOL``, gives
#:
#: .. math:: p \\ge \\varepsilon / \\texttt{_VALIDATION_TOL} \\approx 2.2
#:           \\times 10^{-8}.
#:
#: The previous value of ``1e-12`` was four orders of magnitude too permissive:
#: it admitted branches whose collapsed state was *not* a valid density operator
#: and was rejected by :func:`~sih141.core.states.as_density`, so it could not be
#: fed back into any other function in this module.  The cost of the stricter
#: bound is that an outcome of probability below ~2e-8 is never reported; that
#: is a documented, quantified approximation, and it is the only regime in which
#: the collapsed state could not be represented faithfully anyway.
_MIN_BRANCH_PROB: Final[float] = float(np.finfo(np.float64).eps) / _VALIDATION_TOL

#: Largest fraction of the trace that :func:`_collapse` is willing to remove when
#: projecting a numerically-noisy collapsed matrix back onto the positive
#: semidefinite cone.  Round-off admitted by :data:`_MIN_BRANCH_PROB` is bounded
#: by ``_VALIDATION_TOL``; anything two orders of magnitude beyond that is a real
#: defect (a non-physical input state or a broken projector), not noise, and is
#: raised rather than silently repaired.
_PSD_REPAIR_LIMIT: Final[float] = 100.0 * _VALIDATION_TOL

_BIT_FROM_EIGENVALUE: Final[dict[int, int]] = {1: 0, -1: 1}

_PAULI_LABEL_CHARS: Final[frozenset[str]] = frozenset("IXYZ")


# --------------------------------------------------------------------------- #
# Internal helpers                                                             #
# --------------------------------------------------------------------------- #


def _embed_single(operator: ComplexMatrix, qubit: int, num_qubits: int) -> ComplexMatrix:
    """Embed a one-qubit operator at ``qubit`` of an ``n``-qubit register.

    This function *is* the little-endian convention (D2) for this module: the
    Kronecker product is taken from the highest qubit index down to qubit 0, so
    that the resulting matrix acts on amplitude indices ordered as
    ``index = sum_q b_q * 2**q``.

    Parameters
    ----------
    operator : numpy.ndarray
        A ``(2, 2)`` complex matrix.
    qubit : int
        The qubit the operator acts on, ``0 <= qubit < num_qubits``.
    num_qubits : int
        Register size.

    Returns
    -------
    numpy.ndarray
        A ``(2**num_qubits, 2**num_qubits)`` ``complex128`` matrix.

    Examples
    --------
    Embedding ``Z`` on qubit 0 of two qubits gives ``diag(1, -1, 1, -1)``: the
    sign flips on the odd indices, which are exactly the ones with ``q0 == 1``.
    A big-endian implementation would produce ``diag(1, 1, -1, -1)`` instead.
    """
    result: ComplexMatrix = np.asarray(
        operator if num_qubits - 1 == qubit else PAULI_I, dtype=np.complex128
    )
    for index in range(num_qubits - 2, -1, -1):
        factor = operator if index == qubit else PAULI_I
        result = np.kron(result, np.asarray(factor, dtype=np.complex128))
    return np.asarray(result, dtype=np.complex128)


def _check_qubit(qubit: int, num_qubits: int, *, name: str = "qubit") -> int:
    """Validate a qubit index against the register size.

    Parameters
    ----------
    qubit : int
        Candidate index.
    num_qubits : int
        Register size.
    name : str, optional
        Argument name used in the error message.

    Returns
    -------
    int
        The index as a plain :class:`int`.

    Raises
    ------
    ValueError
        If ``qubit`` is not an integer in ``range(num_qubits)``.  Negative
        (Python-style) indices are rejected explicitly rather than wrapped,
        because a silently wrapped index measures the wrong qubit.
    """
    if isinstance(qubit, bool) or not isinstance(qubit, (int, np.integer)):
        raise ValueError(
            f"{name} must be an integer index, got {qubit!r} "
            f"({type(qubit).__name__})."
        )
    index = int(qubit)
    if not 0 <= index < num_qubits:
        raise ValueError(
            f"{name} must satisfy 0 <= {name} < {num_qubits} for this "
            f"{num_qubits}-qubit state, got {index}. Qubit 0 is the rightmost "
            f"bit of a little-endian label; negative indices are not wrapped."
        )
    return index


def _projectors(
    basis: PauliBasis, qubit: int, num_qubits: int
) -> tuple[ComplexMatrix, ComplexMatrix]:
    """Return the embedded spectral projectors ``(P_plus, P_minus)``.

    Implements :math:`P_{\\pm} = (\\mathbb{1} \\pm \\sigma)/2` for the Pauli
    observable naming ``basis``, embedded at ``qubit`` per :func:`_embed_single`.

    Parameters
    ----------
    basis : PauliBasis
        The measured observable.
    qubit : int
        Qubit index (already validated).
    num_qubits : int
        Register size.

    Returns
    -------
    tuple of numpy.ndarray
        ``(P_plus, P_minus)``, each ``(2**n, 2**n)``, Hermitian, idempotent, and
        summing to the identity.
    """
    sigma = _embed_single(pauli_matrix(basis.value), qubit, num_qubits)
    identity = np.eye(2**num_qubits, dtype=np.complex128)
    return 0.5 * (identity + sigma), 0.5 * (identity - sigma)


def _collapse(
    rho: ComplexMatrix, projector: ComplexMatrix, probability: float
) -> ComplexMatrix:
    """Apply the projection postulate ``rho -> P rho P / Tr(rho P)``.

    Parameters
    ----------
    rho : numpy.ndarray
        The pre-measurement density matrix.
    projector : numpy.ndarray
        The (Hermitian, idempotent) projector of the realised outcome.
    probability : float
        The outcome's Born probability.  Used only as a *conditioning guard*: it
        must exceed :data:`_MIN_BRANCH_PROB`, which callers guarantee by never
        selecting a vanishing branch.  It is deliberately **not** used as the
        renormalisation constant -- the realised trace of the computed triple
        product is, so that the returned matrix has unit trace exactly rather
        than up to the accuracy of ``probability``.

    Returns
    -------
    numpy.ndarray
        The collapsed density matrix.  Guaranteed to be Hermitian, of unit
        trace, and positive semidefinite *by construction*, hence always
        accepted by :func:`~sih141.core.states.as_density` and safe to feed back
        into any other function in this module.

    Raises
    ------
    ValueError
        If ``probability`` is at or below :data:`_MIN_BRANCH_PROB`, if the
        realised trace is non-positive, or if restoring positivity would require
        discarding more than :data:`_PSD_REPAIR_LIMIT` of the trace (which means
        the input was not a physical state, not that rounding occurred).

    Notes
    -----
    Implements the Lueders projection postulate
    :math:`\\rho \\to P\\rho P / \\mathrm{Tr}(\\rho P)`.

    The naive expression ``P @ rho @ P / probability`` is *not* numerically
    safe.  The triple product carries an absolute round-off residue of order
    :math:`\\varepsilon`, so dividing by a small ``probability`` inflates it to a
    relative error of order :math:`\\varepsilon/p` and the result acquires
    negative eigenvalues of that size -- it is then no longer a density
    operator at all.  Two things prevent that here:

    1. :data:`_MIN_BRANCH_PROB` is derived from :math:`\\varepsilon` and the
       project's validation tolerance so the amplified residue stays inside it.
    2. The spectrum is then explicitly projected back onto the positive
       semidefinite cone (negative eigenvalues clipped to zero, trace
       renormalised), which makes the documented guarantee true by construction
       instead of true only up to round-off.

    Both steps are cheap: the register is at most three qubits, so this is an
    eigendecomposition of a matrix no larger than 8x8.
    """
    if probability <= _MIN_BRANCH_PROB:
        raise ValueError(
            f"cannot renormalise a measurement branch of probability "
            f"{probability!r}: it is at or below {_MIN_BRANCH_PROB} "
            "(= float64 eps / the project's state-validation tolerance), below "
            "which the quotient P rho P / p is dominated by round-off and is "
            "not a valid density operator."
        )
    collapsed = projector @ rho @ projector
    # Re-symmetrise first: eigh reads a single triangle, so an anti-Hermitian
    # residue of order 1e-17 would otherwise be silently ignored rather than
    # averaged away.
    collapsed = 0.5 * (collapsed + collapsed.conj().T)

    eigenvalues, vectors = np.linalg.eigh(collapsed)
    trace = float(eigenvalues.sum())
    if trace <= 0.0:
        raise ValueError(
            f"collapsed branch has non-positive trace {trace!r}; the projector "
            "or the input density matrix is malformed."
        )
    negative_mass = -float(eigenvalues[eigenvalues < 0.0].sum())
    if negative_mass > _PSD_REPAIR_LIMIT * trace:
        raise ValueError(
            f"collapsed branch is not positive semidefinite: {negative_mass!r} "
            f"of negative eigenvalue mass against a trace of {trace!r}, which "
            f"exceeds the round-off budget {_PSD_REPAIR_LIMIT}. This is a "
            "malformed projector or a non-physical input state, not numerical "
            "noise."
        )
    weights = np.clip(eigenvalues, 0.0, None)
    weights /= weights.sum()
    repaired: ComplexMatrix = np.asarray(
        (vectors * weights) @ vectors.conj().T, dtype=np.complex128
    )
    # eigh's reconstruction is Hermitian only to round-off; average once more so
    # the result satisfies states.as_density's Hermiticity check exactly.
    return 0.5 * (repaired + repaired.conj().T)


def _density_array(state: StateLike) -> tuple[ComplexMatrix, DensityMatrix]:
    """Normalise state input and return ``(array, DensityMatrix)``.

    Parameters
    ----------
    state : StateLike
        Any accepted state representation.

    Returns
    -------
    tuple
        The raw ``complex128`` array and the validated
        :class:`~qiskit.quantum_info.DensityMatrix` it came from (kept so that
        ``dims()`` can be preserved on the returned states).

    Raises
    ------
    ValueError
        If the state is not a valid density operator.
    """
    rho = as_density(state)
    return np.asarray(rho.data, dtype=np.complex128), rho


def _as_dm(array: ComplexMatrix, template: DensityMatrix) -> DensityMatrix:
    """Wrap a raw matrix as a :class:`DensityMatrix` with ``template``'s dims.

    Parameters
    ----------
    array : numpy.ndarray
        The density-matrix data.
    template : qiskit.quantum_info.DensityMatrix
        The state whose subsystem dimensions should be carried over, so that
        ``num_qubits`` and ``partial_trace`` keep working on the result.

    Returns
    -------
    qiskit.quantum_info.DensityMatrix
        The wrapped state.
    """
    return DensityMatrix(array, dims=template.dims())


def _validate_bases(
    bases: Mapping[int, PauliBasis], num_qubits: int
) -> dict[int, PauliBasis]:
    """Validate and normalise a ``{qubit: basis}`` mapping.

    Parameters
    ----------
    bases : Mapping[int, PauliBasis]
        Measurement basis per qubit.  Values may be :class:`PauliBasis` members
        or the strings ``"X"``/``"Y"``/``"Z"`` (case-insensitive).
    num_qubits : int
        Register size.

    Returns
    -------
    dict
        A new dict with :class:`int` keys sorted ascending and
        :class:`PauliBasis` values.

    Raises
    ------
    ValueError
        If a key is not a valid qubit index or a value is not a valid basis.
    TypeError
        If ``bases`` is not a mapping.
    """
    if not isinstance(bases, Mapping):
        raise TypeError(
            "bases must be a mapping from qubit index to PauliBasis, e.g. "
            f"{{0: PauliBasis.Z}}; got {type(bases).__name__}."
        )
    resolved: dict[int, PauliBasis] = {}
    for qubit, basis in bases.items():
        index = _check_qubit(qubit, num_qubits, name="basis key")
        resolved[index] = _as_basis(basis)
    return {index: resolved[index] for index in sorted(resolved)}


def _bell_projectors(
    num_qubits: int, qubits: tuple[int, int]
) -> dict[BellState, ComplexMatrix]:
    """Build the four Bell projectors on ``qubits``, padded to ``num_qubits``.

    Each projector is

    .. math::
        \\Pi_B = |B\\rangle\\!\\langle B|_{q_a q_b} \\otimes
                 \\mathbb{1}_{\\text{rest}},

    constructed by summing the outer products of the full-register vectors
    obtained by fixing every unmeasured qubit to a computational basis value.
    Building it this way -- rather than by ``kron`` plus a permutation -- keeps
    the little-endian index arithmetic explicit and correct even when the two
    measured qubits are not adjacent.

    The pair convention is: ``qubits[0]`` plays the role of the Bell state's
    qubit 0 (the *rightmost*, least significant bit of its label) and
    ``qubits[1]`` its qubit 1.  It fixes how the vectors are laid out, but it
    has **no effect on the returned projectors**: swapping the pair reproduces
    them bit-for-bit (measured maximum absolute difference exactly ``0.0`` for
    all four members, on two- and three-qubit registers, adjacent pairs and
    not).  Three of the Bell vectors are symmetric under the exchange, and the
    antisymmetric :attr:`~sih141.core.states.BellState.PSI_MINUS` maps to
    :math:`-|\\Psi^{-}\\rangle`, whose outer product
    :math:`(-v)(-v)^{\\dagger} = vv^{\\dagger}` is unchanged -- the sign lands on
    the vector and the outer product erases it.

    Parameters
    ----------
    num_qubits : int
        Register size.
    qubits : tuple of int
        The measured pair ``(q_a, q_b)``, already validated as distinct, valid
        indices.

    Returns
    -------
    dict
        Mapping from :class:`~sih141.core.states.BellState` to its
        ``(2**n, 2**n)`` projector.
    """
    dim = 2**num_qubits
    spectators = [q for q in range(num_qubits) if q not in qubits]
    projectors: dict[BellState, ComplexMatrix] = {}
    for which in BELL_ORDER:
        amplitudes = np.asarray(bell_state(which).data, dtype=np.complex128)
        projector = np.zeros((dim, dim), dtype=np.complex128)
        for assignment in itertools.product((0, 1), repeat=len(spectators)):
            base = 0
            for bit, spectator in zip(assignment, spectators):
                base |= bit << spectator
            vector = np.zeros(dim, dtype=np.complex128)
            for pair_index, amplitude in enumerate(amplitudes):
                if amplitude == 0:
                    continue
                # pair_index is the little-endian label of the pair:
                # bit 0 -> qubits[0], bit 1 -> qubits[1].
                full_index = (
                    base
                    | ((pair_index & 1) << qubits[0])
                    | (((pair_index >> 1) & 1) << qubits[1])
                )
                vector[full_index] = amplitude
            projector += np.outer(vector, vector.conj())
        projectors[which] = projector
    return projectors


def _select_branch(
    probabilities: Iterable[float], rng: np.random.Generator | None
) -> int:
    """Draw one index from a discrete distribution using inverse-CDF sampling.

    A single uniform variate is consumed per call, so a seeded generator gives a
    reproducible stream of measurement results (D3).  Branches whose probability
    is below :data:`_MIN_BRANCH_PROB` are never returned: the running cumulative
    sum can only reach them through rounding, and they cannot be renormalised.

    Parameters
    ----------
    probabilities : iterable of float
        A distribution summing to 1.
    rng : numpy.random.Generator or None
        Resolved through :func:`~sih141.core.rng.resolve_rng`.

    Returns
    -------
    int
        The index of the selected branch.

    Raises
    ------
    ValueError
        If every branch is below :data:`_MIN_BRANCH_PROB`, which cannot happen
        for a trace-one state and would indicate a projector bug.
    """
    values = [float(p) for p in probabilities]
    draw = float(resolve_rng(rng).random())
    cumulative = 0.0
    fallback = -1
    for index, probability in enumerate(values):
        if probability > _MIN_BRANCH_PROB:
            fallback = index
            cumulative += probability
            if draw < cumulative:
                return index
    if fallback < 0:
        raise ValueError(
            "no measurement branch has non-negligible probability; the state "
            f"is not trace-one (probabilities were {values!r})."
        )
    # Reached only when the cumulative sum falls a few ULPs short of the draw.
    # The last viable branch is the correct rounding-safe choice.
    return fallback


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class MeasurementOutcome:
    """The full record of one single-qubit projective measurement.

    Both the physical eigenvalue and the classical bit are stored because both
    are needed downstream and the conversion is the classic off-by-a-sign trap:
    Phase 2 transmits *bits*, while Phase 4's correlation statistics are sums of
    :math:`\\pm 1` *eigenvalues*.

    Attributes
    ----------
    eigenvalue : int
        The realised Pauli eigenvalue, ``+1`` or ``-1``.
    bit : int
        The classical bit, ``0`` for eigenvalue ``+1`` and ``1`` for ``-1``.
        Consistent with :func:`sih141.core.paulis.basis_change_circuit`, whose
        rotation sends the ``+1`` eigenstate to :math:`|0\\rangle`.
    basis : PauliBasis
        The basis actually measured in.
    qubit : int
        The measured qubit index (little-endian: qubit 0 is the rightmost bit).
    probability : float
        The Born-rule probability :math:`\\mathrm{Tr}(\\rho P)` that this
        outcome had *given the state passed to the call that produced it*, in
        ``[0, 1]``.  This is the realised branch's weight, not a frequency
        estimate.

        .. warning::
           **This is a conditional probability, not a marginal one.**  When a
           record comes from :func:`measure_qubits`, the "state passed to the
           call" is the state already collapsed by every *earlier* qubit in the
           sequence, so ``probability`` is
           :math:`\\Pr(\\text{this outcome} \\mid \\text{the preceding
           outcomes})`.  On :math:`|\\Phi^{+}\\rangle` with
           ``{0: Z, 1: Z}`` the two records read ``0.5`` and ``1.0``: the second
           qubit is certain *once the first has been seen*, and its marginal
           probability is ``0.5``, not ``1.0``.

           Consequently **averaging these values across qubits computes nothing
           physical**.  The joint probability of the whole record is their
           *product*; use :func:`joint_probability`, which is the chain rule
           written once so no caller has to remember it.  For per-qubit
           marginals, call :func:`born_probabilities` on the original
           pre-measurement state, or read them off :func:`sample_counts`.
    post_state : qiskit.quantum_info.DensityMatrix
        The collapsed, renormalised state of the **whole** register (D1), not
        just the measured qubit.

    Raises
    ------
    ValueError
        If ``eigenvalue`` is not ``+1``/``-1``, ``bit`` does not match it, or
        ``probability`` lies outside ``[0, 1]``.

    See Also
    --------
    joint_probability : Chain-rule product of a list of these records.
    """

    eigenvalue: int
    bit: int
    basis: PauliBasis
    qubit: int
    probability: float
    post_state: DensityMatrix

    def __post_init__(self) -> None:
        """Validate the eigenvalue/bit correspondence and the probability."""
        if self.eigenvalue not in (1, -1):
            raise ValueError(
                f"eigenvalue must be +1 or -1, got {self.eigenvalue!r}. These "
                "are Pauli eigenvalues, not measurement bits."
            )
        expected_bit = _BIT_FROM_EIGENVALUE[int(self.eigenvalue)]
        if self.bit != expected_bit:
            raise ValueError(
                f"bit {self.bit!r} is inconsistent with eigenvalue "
                f"{self.eigenvalue!r}; the project-wide mapping is "
                "+1 -> bit 0 and -1 -> bit 1 (bit = (1 - eigenvalue) // 2)."
            )
        if not 0.0 <= float(self.probability) <= 1.0:
            raise ValueError(
                f"probability must lie in [0, 1], got {self.probability!r}."
            )


def born_probabilities(
    state: StateLike, qubit: int, basis: PauliBasis
) -> tuple[float, float]:
    """Born-rule outcome probabilities for measuring one qubit in one basis.

    Computes :math:`\\Pr(\\pm) = \\mathrm{Tr}(\\rho P_{\\pm})` with
    :math:`P_{\\pm} = (\\mathbb{1} \\pm \\sigma)/2` embedded at ``qubit``.  The
    trace form is used rather than :math:`\\langle\\psi|P|\\psi\\rangle` so that
    the result is correct for mixed states -- which is the whole point of D1,
    since Phase 3 feeds this function depolarised and intercepted states.

    Parameters
    ----------
    state : StateLike
        A :class:`~qiskit.quantum_info.Statevector`,
        :class:`~qiskit.quantum_info.DensityMatrix` or raw array.
    qubit : int
        Which qubit to measure, little-endian (qubit 0 is the rightmost bit of a
        bitstring label).
    basis : PauliBasis
        The measurement basis; the string ``"X"``/``"Y"``/``"Z"`` is also
        accepted.

    Returns
    -------
    tuple of float
        ``(p_plus, p_minus)`` for eigenvalues ``+1`` and ``-1``.  Both lie in
        ``[0, 1]`` and they sum to exactly ``1.0`` in floating point:
        ``p_plus`` is clipped and ``p_minus`` is computed as its complement, so
        that a caller can use either as a cumulative threshold without the sum
        drifting.

    Raises
    ------
    ValueError
        If the state is invalid, ``qubit`` is out of range, ``basis`` is not a
        known basis, or the two traces fail to satisfy the completeness relation
        ``p_plus + p_minus == 1`` within :data:`_PROB_TOL` (which would mean the
        projectors themselves are wrong).  That tolerance is tied to the one
        used by :func:`~sih141.core.states.as_density`, so every state the
        project considers valid is accepted here.

    Examples
    --------
    :math:`|01\\rangle` has qubit 0 in :math:`|1\\rangle` and qubit 1 in
    :math:`|0\\rangle`, so a Z measurement of qubit 0 is certainly ``-1`` while
    the same measurement of qubit 1 is certainly ``+1``:

    >>> import numpy as np
    >>> from qiskit.quantum_info import Statevector
    >>> from sih141.core.paulis import PauliBasis
    >>> ket01 = Statevector(np.array([0, 1, 0, 0], dtype=complex))
    >>> born_probabilities(ket01, 0, PauliBasis.Z)
    (0.0, 1.0)
    >>> born_probabilities(ket01, 1, PauliBasis.Z)
    (1.0, 0.0)
    """
    rho, dm = _density_array(state)
    index = _check_qubit(qubit, dm.num_qubits)
    resolved_basis = _as_basis(basis)

    proj_plus, proj_minus = _projectors(resolved_basis, index, dm.num_qubits)
    p_plus = float(np.real(np.trace(rho @ proj_plus)))
    p_minus = float(np.real(np.trace(rho @ proj_minus)))

    total = p_plus + p_minus
    if abs(total - 1.0) > _PROB_TOL:
        raise ValueError(
            f"Born probabilities do not sum to 1 (got {total!r} for qubit "
            f"{index} in basis {resolved_basis.value}, tolerance {_PROB_TOL}); "
            "the projectors are malformed, since any state as_density accepts "
            "is trace-one to within this tolerance."
        )
    # Divide by the realised total rather than trusting it to be 1: as_density
    # admits (without renormalising) a trace deviation up to _VALIDATION_TOL, and
    # that drift would otherwise leak straight into the reported probabilities.
    clipped = float(np.clip(p_plus / total, 0.0, 1.0))
    return clipped, 1.0 - clipped


def projective_measure(
    state: StateLike,
    qubit: int,
    basis: PauliBasis,
    *,
    rng: np.random.Generator | None = None,
) -> MeasurementOutcome:
    """Measure one qubit and genuinely collapse the register.

    Samples an outcome from the Born distribution and applies the projection
    postulate :math:`\\rho \\to P\\rho P / \\mathrm{Tr}(\\rho P)`.  The returned
    ``post_state`` is the *real* collapsed state of the whole register, not a
    copy of the input: correlations with the unmeasured qubits are updated,
    which is what makes entanglement-based detection work in later phases.

    Parameters
    ----------
    state : StateLike
        The pre-measurement state, pure or mixed.
    qubit : int
        Which qubit to measure (little-endian).
    basis : PauliBasis
        The measurement basis.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3).  Resolved through
        :func:`sih141.core.rng.resolve_rng`; exactly one uniform variate is
        consumed.

    Returns
    -------
    MeasurementOutcome
        The eigenvalue, bit, Born probability and collapsed
        :class:`~qiskit.quantum_info.DensityMatrix`.

    Raises
    ------
    ValueError
        If the state is invalid, ``qubit`` is out of range, ``basis`` is
        unknown, or the realised branch cannot be renormalised.
    TypeError
        If ``rng`` is neither ``None`` nor a :class:`numpy.random.Generator`.

    Notes
    -----
    **Sampling is exact Born sampling with one documented exception.**  A branch
    whose probability is at or below :data:`_MIN_BRANCH_PROB`
    (:math:`\\approx 2.2\\times10^{-8}`, derived as float64 epsilon divided by
    the project's state-validation tolerance) is *never selected*, and its
    weight is effectively redistributed over the surviving branch; see
    :func:`_select_branch`.  For the two branches here the realised distribution
    is therefore within :math:`2 \\times 2.2\\times10^{-8}` of the Born
    distribution, and an outcome rarer than that is reported at rate zero rather
    than at its true rate.  The floor is what keeps the normalisation of
    :math:`P\\rho P` well conditioned: below it the quotient is dominated by
    round-off and is not a density operator at all.

    If the quantity of interest lives in that tail -- rare-event rates,
    distribution tails, anything whose expected count is comparable to
    :math:`10^{-8}` -- use :func:`sample_counts` instead.  It draws from an exact
    multinomial over the joint distribution and has **no** such floor.  The price
    is that it does not collapse the state; it answers "how often", not "and then
    what".

    The returned ``post_state`` is additionally projected onto the positive
    semidefinite cone, so it is always a valid density operator and can be fed
    straight back into this function.  Because :math:`P^2 = P`, re-measuring the
    same qubit in the same basis reproduces the same eigenvalue with
    probability 1.
    """
    rho, dm = _density_array(state)
    index = _check_qubit(qubit, dm.num_qubits)
    resolved_basis = _as_basis(basis)

    p_plus, p_minus = born_probabilities(rho, index, resolved_basis)
    branch = _select_branch((p_plus, p_minus), rng)

    proj_plus, proj_minus = _projectors(resolved_basis, index, dm.num_qubits)
    if branch == 0:
        eigenvalue, probability, projector = 1, p_plus, proj_plus
    else:
        eigenvalue, probability, projector = -1, p_minus, proj_minus

    collapsed = _collapse(rho, projector, probability)
    return MeasurementOutcome(
        eigenvalue=eigenvalue,
        bit=_BIT_FROM_EIGENVALUE[eigenvalue],
        basis=resolved_basis,
        qubit=index,
        probability=probability,
        post_state=_as_dm(collapsed, dm),
    )


def measure_qubits(
    state: StateLike,
    bases: Mapping[int, PauliBasis],
    *,
    rng: np.random.Generator | None = None,
) -> tuple[list[MeasurementOutcome], DensityMatrix]:
    """Measure several qubits, threading the collapse through each one.

    Measurements are performed sequentially in **ascending qubit order**, each
    acting on the state collapsed by the previous one.  Because the projectors
    of distinct qubits commute, the joint outcome distribution does not depend
    on that order; fixing it merely makes the consumed random stream
    reproducible (D3).

    Parameters
    ----------
    state : StateLike
        The pre-measurement state.
    bases : Mapping[int, PauliBasis]
        Which basis to measure each qubit in, e.g. ``{0: PauliBasis.Z, 2:
        PauliBasis.X}``.  Qubits absent from the mapping are left unmeasured
        (and end up in their correct conditional state).  May be empty.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3).  One uniform variate is consumed per measured qubit.

    Returns
    -------
    outcomes : list of MeasurementOutcome
        One record per measured qubit, ordered by ascending qubit index.  Each
        record's ``post_state`` is the register state immediately after *that*
        measurement.  Empty when ``bases`` is empty.
    final_state : qiskit.quantum_info.DensityMatrix
        The register state after all the measurements; identical to
        ``outcomes[-1].post_state``, or to ``as_density(state)`` when ``bases``
        is empty.

    Raises
    ------
    ValueError
        If the state is invalid, or a key/value of ``bases`` is not a valid
        qubit index / basis.
    TypeError
        If ``bases`` is not a mapping, or ``rng`` is of the wrong type.

    Warnings
    --------
    **Each outcome's ``probability`` is conditional on the outcomes before it,
    not marginal.**  Measurement ``k`` is performed on the state already
    collapsed by measurements ``0 .. k-1``, so the list is a chain-rule
    factorisation

    .. math::
        \\Pr(o_0, \\ldots, o_{k}) = \\prod_{i} \\Pr(o_i \\mid o_0 \\ldots
        o_{i-1}),

    and the correct way to combine the entries is to **multiply** them --
    :func:`joint_probability` does exactly that.  Averaging or summing them
    computes no physical quantity.  The trap is easy to hit and silent: on
    :math:`|\\Phi^{+}\\rangle` with ``{0: Z, 1: Z}`` the two records read ``0.5``
    and ``1.0``, whose mean is ``0.75`` -- a number that is neither qubit's
    marginal (both are ``0.5``) nor the joint probability (``0.5``).  For
    marginals use :func:`born_probabilities` on the *original* state, or
    :func:`sample_counts`.

    Notes
    -----
    Sampling inherits the :data:`_MIN_BRANCH_PROB` floor of
    :func:`projective_measure`: per measured qubit, a branch of probability at or
    below :math:`\\approx 2.2\\times10^{-8}` is never selected, so the realised
    joint distribution over ``k`` measured qubits differs from the exact Born
    distribution by at most :math:`2k \\times 2.2\\times10^{-8}`.  Prefer
    :func:`sample_counts` -- an exact multinomial with no floor -- whenever the
    statistic of interest is a rare-event rate rather than a post-measurement
    state.
    """
    _, dm = _density_array(state)
    resolved = _validate_bases(bases, dm.num_qubits)

    generator = resolve_rng(rng)
    current: DensityMatrix = dm
    outcomes: list[MeasurementOutcome] = []
    for qubit, basis in resolved.items():
        outcome = projective_measure(current, qubit, basis, rng=generator)
        outcomes.append(outcome)
        current = outcome.post_state
    return outcomes, current


def joint_probability(outcomes: Sequence[MeasurementOutcome]) -> float:
    """Combine a sequential measurement record into one joint probability.

    :func:`measure_qubits` returns *conditional* probabilities -- record ``k``
    was drawn from the state already collapsed by records ``0 .. k-1`` -- so the
    probability of the record as a whole is the chain-rule **product**, not the
    mean:

    .. math::
        \\Pr(o_0, \\ldots, o_{k-1}) = \\prod_{i=0}^{k-1}
        \\Pr(o_i \\mid o_0 \\ldots o_{i-1}).

    This function is that product, provided so that the correct combination is
    also the convenient one.  A Phase 4 detector that averages the ``probability``
    fields instead is computing nothing physical, and nothing about the resulting
    number looks wrong.

    Parameters
    ----------
    outcomes : sequence of MeasurementOutcome
        A record produced by a *single* :func:`measure_qubits` call, in the order
        returned.  Records from independent calls (independent preparations) may
        also be combined this way, since independent events multiply too.

    Returns
    -------
    float
        The joint probability, in ``[0, 1]``.  An empty record gives ``1.0``: the
        empty conjunction of events is certain, which is the value that keeps
        this function composable in a loop over a possibly-empty basis map.

    Raises
    ------
    TypeError
        If ``outcomes`` is not a sequence, or contains anything other than
        :class:`MeasurementOutcome` instances.  Passing the ``(outcomes,
        final_state)`` tuple of :func:`measure_qubits` whole is the expected
        mistake, and it is named in the message.

    See Also
    --------
    measure_qubits : Produces the conditional records this consumes.
    born_probabilities : Per-qubit *marginal* probabilities on an uncollapsed
        state.

    Examples
    --------
    On :math:`|\\Phi^{+}\\rangle`, measuring both qubits in Z gives conditional
    probabilities ``0.5`` and ``1.0``; the joint probability of the pair of
    outcomes is ``0.5``, not their mean of ``0.75``.

    >>> import numpy as np
    >>> from sih141.core.states import BellState, bell_state
    >>> from sih141.core.paulis import PauliBasis
    >>> records, _ = measure_qubits(
    ...     bell_state(BellState.PHI_PLUS),
    ...     {0: PauliBasis.Z, 1: PauliBasis.Z},
    ...     rng=np.random.default_rng(20260141),
    ... )
    >>> [round(record.probability, 3) for record in records]
    [0.5, 1.0]
    >>> round(joint_probability(records), 3)
    0.5
    """
    if isinstance(outcomes, MeasurementOutcome) or not isinstance(
        outcomes, Sequence
    ):
        raise TypeError(
            f"outcomes must be a sequence of MeasurementOutcome, got "
            f"{type(outcomes).__name__}. measure_qubits returns the pair "
            f"(outcomes, final_state); pass the first element, e.g. "
            f"joint_probability(measure_qubits(state, bases)[0])."
        )
    product = 1.0
    for position, outcome in enumerate(outcomes):
        if not isinstance(outcome, MeasurementOutcome):
            raise TypeError(
                f"outcomes[{position}] must be a MeasurementOutcome, got "
                f"{type(outcome).__name__}. This function multiplies the "
                f"conditional probabilities of one measurement record; pass the "
                f"list measure_qubits returned, not raw floats."
            )
        product *= float(outcome.probability)
    return float(np.clip(product, 0.0, 1.0))


def sample_counts(
    state: StateLike,
    bases: Mapping[int, PauliBasis],
    shots: int,
    *,
    rng: np.random.Generator | None = None,
) -> dict[str, int]:
    """Sample many shots of a multi-qubit measurement, efficiently.

    The joint outcome distribution is computed **once**, by rotating the
    measured qubits onto the computational basis with the circuits of
    :func:`sih141.core.paulis.basis_change_circuit` and reading the diagonal of
    the rotated density matrix (the Born rule in the rotated frame), then
    marginalising over the unmeasured qubits.  All ``shots`` results are then
    drawn in one :meth:`numpy.random.Generator.multinomial` call.  There is
    deliberately no per-shot collapse loop: the cost is independent of
    ``shots``, which is what makes the Phase 5 evaluation (many thousands of
    shots per configuration) tractable.

    Parameters
    ----------
    state : StateLike
        The state to sample from, pure or mixed.
    bases : Mapping[int, PauliBasis]
        Basis per measured qubit.  Unmeasured qubits are traced out implicitly
        by the marginalisation.  **May be empty**, exactly as in
        :func:`measure_qubits`: measuring nothing is a degenerate but legal
        request, and a loop that builds a basis map dynamically must not have to
        special-case it at one call site and not the other.
    shots : int
        Number of repetitions, ``>= 0``.  Each shot is understood as an
        independent preparation of ``state``.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3).  Exactly one multinomial draw is consumed.

    Returns
    -------
    dict
        Maps a bitstring to its count.  The bitstring contains one character per
        **measured** qubit, ordered by *descending* qubit index, so the
        rightmost character is the lowest measured index (little-endian, D2).
        Measuring ``{0: Z, 1: Z}`` on :math:`|01\\rangle` therefore gives the
        key ``"01"``.  Bit ``0`` means eigenvalue ``+1``.  Outcomes with zero
        counts are omitted, matching Qiskit's ``counts`` convention -- use
        ``counts.get(key, 0)``.  The counts sum to ``shots``.

        When ``bases`` is empty there is exactly one outcome, the empty
        bitstring, and the result is ``{"": shots}`` -- the general code path,
        not a special case: :math:`2^0 = 1` outcome of probability 1.  It is
        ``{}`` for ``shots == 0``, because zero counts are omitted.

    Raises
    ------
    ValueError
        If the state is invalid, ``shots`` is negative or not an integer, or a
        key/value of ``bases`` is invalid.  An empty ``bases`` is **not** an
        error.
    TypeError
        If ``bases`` is not a mapping, or ``rng`` is of the wrong type.

    Notes
    -----
    Unlike the collapsing entry points (:func:`projective_measure`,
    :func:`measure_qubits`, :func:`bell_measure`), this function carries **no**
    :data:`_MIN_BRANCH_PROB` floor: the multinomial is drawn from the exact joint
    distribution, so an outcome of probability :math:`10^{-12}` is sampled at its
    true rate.  It is therefore the right tool for rare-event and tail
    statistics; the collapsing functions are for when the post-measurement state
    is needed.


    Rotating and reading the diagonal is exactly equivalent to
    :math:`\\mathrm{Tr}(\\rho\\,\\Pi_{\\mathbf{b}})` for the joint projector
    :math:`\\Pi_{\\mathbf{b}}`, because
    :math:`U^{\\dagger}|\\mathbf{b}\\rangle\\!\\langle\\mathbf{b}|U` *is* that
    projector.  It is used here instead of building :math:`2^{k}` projectors
    because one 8x8 conjugation replaces the whole set.
    """
    if isinstance(shots, bool) or not isinstance(shots, (int, np.integer)):
        raise ValueError(
            f"shots must be a non-negative integer, got {shots!r} "
            f"({type(shots).__name__})."
        )
    shot_count = int(shots)
    if shot_count < 0:
        raise ValueError(f"shots must be non-negative, got {shot_count}.")

    rho, dm = _density_array(state)
    num_qubits = dm.num_qubits
    resolved = _validate_bases(bases, num_qubits)
    measured = list(resolved)

    # Rotate every measured qubit onto the Z basis.  The single-qubit rotations
    # act on distinct qubits, so they commute and the product order is free.
    rotation = np.eye(2**num_qubits, dtype=np.complex128)
    for qubit, basis in resolved.items():
        gate = np.asarray(
            Operator(basis_change_circuit(basis)).data, dtype=np.complex128
        )
        rotation = _embed_single(gate, qubit, num_qubits) @ rotation
    rotated = rotation @ rho @ rotation.conj().T

    # Born rule in the rotated frame, then marginalise the spectators away.
    diagonal = np.clip(np.real(np.diag(rotated)), 0.0, None)
    num_outcomes = 2 ** len(measured)
    probabilities = np.zeros(num_outcomes, dtype=np.float64)
    for full_index in range(2**num_qubits):
        outcome_index = 0
        for position, qubit in enumerate(measured):  # ascending -> weight 2**position
            outcome_index |= ((full_index >> qubit) & 1) << position
        probabilities[outcome_index] += diagonal[full_index]

    total = float(probabilities.sum())
    if abs(total - 1.0) > _PROB_TOL:
        raise ValueError(
            f"measurement distribution does not sum to 1 (got {total!r}, "
            f"tolerance {_PROB_TOL}); the basis-change rotation or the "
            "spectator marginalisation is malformed, since any state "
            "as_density accepts is trace-one to within this tolerance."
        )
    probabilities /= total

    draws = resolve_rng(rng).multinomial(shot_count, probabilities)
    keys = [
        "".join(
            str((outcome_index >> position) & 1)
            for position in reversed(range(len(measured)))
        )
        for outcome_index in range(num_outcomes)
    ]
    return {
        key: int(count) for key, count in zip(keys, draws) if int(count) > 0
    }


def expectation(state: StateLike, pauli_label: str) -> float:
    """Expectation value :math:`\\langle P \\rangle = \\mathrm{Tr}(\\rho P)`.

    The workhorse of the Phase 4 detector: correlation statistics such as the
    CHSH combination are sums of these.  The value is real because ``P`` and
    ``rho`` are both Hermitian.

    Parameters
    ----------
    state : StateLike
        Any accepted state representation.
    pauli_label : str
        A Pauli string of length ``num_qubits`` over ``"IXYZ"``,
        case-insensitive.  **Qiskit ordering**: the *rightmost* character acts
        on qubit 0 (D2).  So on a two-qubit register ``"ZI"`` means ``Z`` on
        qubit 1 and identity on qubit 0, while ``"IZ"`` means ``Z`` on qubit 0.
        Phase-carrying labels such as ``"-iXY"`` are rejected: the observable
        must be Hermitian.

    Returns
    -------
    float
        The expectation value, in ``[-1, 1]`` for any Pauli string.

    Raises
    ------
    ValueError
        If the state is invalid, the label has the wrong length, or it contains
        a character outside ``"IXYZ"``.
    TypeError
        If ``pauli_label`` is not a string.

    Examples
    --------
    On :math:`|01\\rangle` (qubit 0 in :math:`|1\\rangle`), ``"IZ"`` measures
    qubit 0 and gives ``-1`` while ``"ZI"`` measures qubit 1 and gives ``+1``.
    A big-endian reading of the label would swap the two.
    """
    if not isinstance(pauli_label, str):
        raise TypeError(
            f"pauli_label must be a string over 'IXYZ', got "
            f"{type(pauli_label).__name__}."
        )
    rho, dm = _density_array(state)
    label = pauli_label.strip().upper()
    if not label or not set(label) <= _PAULI_LABEL_CHARS:
        raise ValueError(
            f"pauli_label {pauli_label!r} must be a non-empty string over "
            "'IXYZ' (case-insensitive). Signed or phase-prefixed labels such "
            "as '-iXY' are not accepted: the observable must be Hermitian."
        )
    if len(label) != dm.num_qubits:
        raise ValueError(
            f"pauli_label {pauli_label!r} has length {len(label)} but the "
            f"state has {dm.num_qubits} qubits. Pad with 'I', remembering that "
            "the rightmost character acts on qubit 0."
        )
    observable = np.asarray(Pauli(label).to_matrix(), dtype=np.complex128)
    return float(np.real(np.trace(rho @ observable)))


def bell_measure(
    state: StateLike,
    qubits: tuple[int, int] = (0, 1),
    *,
    rng: np.random.Generator | None = None,
) -> tuple[BellState, DensityMatrix]:
    """Measure a qubit pair in the four-element Bell basis.

    Projects onto :math:`\\Pi_B = |B\\rangle\\!\\langle B| \\otimes
    \\mathbb{1}_{\\text{rest}}` for :math:`B` running over
    :data:`~sih141.core.states.BELL_ORDER`, samples an outcome from
    :math:`\\Pr(B) = \\mathrm{Tr}(\\rho\\,\\Pi_B)`, and returns the collapsed
    register.

    The projector acts as the identity on every other qubit, so those qubits are
    left in their correct **conditional** state rather than being disturbed.
    That conditional state is precisely the teleported payload (up to the Pauli
    correction indexed by ``BELL_ORDER``), which is why
    :mod:`sih141.core.teleport` is a thin wrapper over this function and why the
    behaviour is tested on a three-qubit register, not just on the measured
    pair.

    Parameters
    ----------
    state : StateLike
        A register of at least two qubits, pure or mixed.
    qubits : tuple of int, optional
        The measured pair ``(q_a, q_b)``, default ``(0, 1)``.  The two indices
        must be distinct.  ``qubits[0]`` plays the role of the Bell state's
        qubit 0 (the rightmost bit of its label) and ``qubits[1]`` its qubit 1;
        the pair need not be adjacent.  Swapping the two is a **no-op**: the
        four projectors are bit-for-bit identical under the exchange (the
        antisymmetric :attr:`~sih141.core.states.BellState.PSI_MINUS` vector
        picks up a sign, which its outer product erases), so outcome labels,
        probabilities and the collapsed state are all unchanged.
    rng : numpy.random.Generator or None, optional
        Keyword-only (D3).  Exactly one uniform variate is consumed.

    Returns
    -------
    outcome : sih141.core.states.BellState
        Which Bell state the pair was projected onto.
    post_state : qiskit.quantum_info.DensityMatrix
        The collapsed state of the whole register (D1).  Tracing out the
        spectators leaves :math:`|B\\rangle\\!\\langle B|` on the pair; tracing
        out the pair leaves the spectators' conditional state.

    Raises
    ------
    ValueError
        If the state is invalid, has fewer than two qubits, ``qubits`` is not a
        pair of distinct valid indices, or the realised branch cannot be
        renormalised.
    TypeError
        If ``rng`` is of the wrong type.

    Notes
    -----
    For an unentangled input the four outcomes are *not* generally equiprobable;
    the familiar uniform 1/4 arises in the teleportation setting because the
    payload is maximally entangled with nothing and the resource is maximally
    entangled (see the identity in :mod:`sih141.core.states`).

    **Sampling is exact Born sampling with one documented exception.**  As in
    :func:`projective_measure`, a branch whose probability is at or below
    :data:`_MIN_BRANCH_PROB` (:math:`\\approx 2.2\\times10^{-8}`) is never
    selected and its weight is redistributed over the surviving branches, so the
    realised distribution over the four outcomes is within
    :math:`4 \\times 2.2\\times10^{-8}` of the Born distribution.  A Bell outcome
    rarer than that is reported at rate zero.  The floor is what keeps the
    collapsed state a representable density operator.  Note that
    :func:`sample_counts` -- the exact, floor-free multinomial sampler
    recommended elsewhere in this module for tail statistics -- measures in the
    *Pauli* bases and cannot stand in for a Bell measurement.  For rare-event
    work in the Bell basis, use the closed-form probabilities
    :math:`\\mathrm{Tr}(\\rho\\,\\Pi_B)` (what this function computes internally
    before sampling) rather than counting realised outcomes.
    """
    rho, dm = _density_array(state)
    if dm.num_qubits < 2:
        raise ValueError(
            f"bell_measure needs at least two qubits, got a "
            f"{dm.num_qubits}-qubit state."
        )
    if not isinstance(qubits, tuple) or len(qubits) != 2:
        raise ValueError(
            f"qubits must be a tuple of two distinct qubit indices, got "
            f"{qubits!r}."
        )
    pair = (
        _check_qubit(qubits[0], dm.num_qubits, name="qubits[0]"),
        _check_qubit(qubits[1], dm.num_qubits, name="qubits[1]"),
    )
    if pair[0] == pair[1]:
        raise ValueError(
            f"qubits must be two distinct indices, got {pair[0]} twice. A Bell "
            "measurement acts on a pair."
        )

    projectors = _bell_projectors(dm.num_qubits, pair)
    probabilities = [
        float(np.real(np.trace(rho @ projectors[which]))) for which in BELL_ORDER
    ]
    total = sum(probabilities)
    if abs(total - 1.0) > _PROB_TOL:
        raise ValueError(
            f"Bell-basis probabilities do not sum to 1 (got {total!r}, "
            f"tolerance {_PROB_TOL}); the Bell projectors are malformed, since "
            "any state as_density accepts is trace-one to within this "
            "tolerance."
        )
    probabilities = [float(np.clip(p, 0.0, 1.0)) / total for p in probabilities]

    branch = _select_branch(probabilities, rng)
    outcome = BELL_ORDER[branch]
    collapsed = _collapse(rho, projectors[outcome], probabilities[branch])
    return outcome, _as_dm(collapsed, dm)
