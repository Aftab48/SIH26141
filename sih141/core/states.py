"""Quantum state construction and state metrics.

This module owns the *canonical state type* for the whole project and the small
set of scalar metrics (fidelity, purity, concurrence) that Phase 4's statistical
detector and Phase 5's ROC evaluation are built on.  It contains pure linear
algebra only: no machine learning, no fitted models, no heuristics (design
decision D4).

Conventions
-----------
Qubit ordering (D2)
    **Qiskit little-endian.**  Qubit 0 is the *rightmost* character of a
    bitstring label.  The label ``"01"`` therefore means ``q1 = 0, q0 = 1`` and
    occupies statevector index ``1``; the label ``"10"`` means ``q1 = 1,
    q0 = 0`` and occupies index ``2``.  A general 2-qubit amplitude vector is
    indexed as ``index = 2 * q1 + q0``.  This is the single most common source
    of silent bugs in code of this kind, so every Bell state below is written
    with its explicit amplitude vector and the test suite pins the convention
    down with the asymmetric state :math:`|01\\rangle`.

Canonical state type (D1)
    :class:`qiskit.quantum_info.DensityMatrix`.  Pure states are *built* as
    :class:`~qiskit.quantum_info.Statevector` for convenience and exactness, but
    :func:`as_density` is the single shared normaliser that every public
    function in the project routes untyped state input through.  Accepting both
    types from the start is what lets Phase 3 push mixed states (depolarising
    noise, intercept-resend attacks) through the same call sites.  That
    normaliser enforces the full definition of a physical state -- unit trace,
    Hermiticity *and* positive semidefiniteness -- so an unphysical matrix is
    rejected at the boundary instead of quietly producing a plausible-looking
    metric further downstream.

Fidelity convention
    :func:`fidelity` returns the Uhlmann fidelity **F**, *not* its square root:

    .. math::
        F(\\rho, \\sigma) =
            \\left(\\mathrm{Tr}\\sqrt{\\sqrt{\\rho}\\,\\sigma\\,\\sqrt{\\rho}}\\right)^{2}

    which for a pure :math:`\\rho = |\\psi\\rangle\\!\\langle\\psi|` collapses to
    :math:`F = \\langle\\psi|\\sigma|\\psi\\rangle`, and for two pure states to
    :math:`F = |\\langle\\psi|\\phi\\rangle|^{2}`.  This matches
    :func:`qiskit.quantum_info.state_fidelity`.  ``F = 1`` means identical
    states; an ideal teleportation therefore scores ``1.0``, and the Phase 5
    metrics must be read as squared-overlap quantities throughout.

Bell states
-----------
.. math::
    |\\Phi^{\\pm}\\rangle = \\frac{|00\\rangle \\pm |11\\rangle}{\\sqrt{2}},
    \\qquad
    |\\Psi^{\\pm}\\rangle = \\frac{|01\\rangle \\pm |10\\rangle}{\\sqrt{2}}

All four are maximally entangled (concurrence 1) and form an orthonormal basis
of the two-qubit Hilbert space.
"""

from __future__ import annotations

import enum
from typing import Final, TypeAlias

import numpy as np
from numpy.typing import NDArray
from qiskit import QuantumCircuit
from qiskit.quantum_info import DensityMatrix, Statevector, state_fidelity

__all__ = [
    "BellState",
    "BELL_ORDER",
    "StateLike",
    "bell_state",
    "bell_circuit",
    "as_density",
    "fidelity",
    "purity",
    "concurrence",
    "is_normalised",
]

#: Anything the public API will accept where a quantum state is expected.
#: Any nested sequence of numbers also works at runtime -- it is converted with
#: :func:`numpy.asarray` -- but is left out of the alias to keep the annotation
#: readable.
StateLike: TypeAlias = (
    Statevector
    | DensityMatrix
    | NDArray[np.complexfloating]
    | NDArray[np.floating]
)

_SQRT1_2: Final[float] = float(np.sqrt(0.5))

#: Default tolerance used when validating input states.  Deliberately looser
#: than the 1e-9 used by :func:`is_normalised`, because states handed to
#: :func:`as_density` have usually been through several 8x8 matrix products.
_VALIDATION_TOL: Final[float] = 1e-8

#: How close ``Tr(rho^2)`` must sit to 1 before :func:`fidelity` may use the
#: exact pure-state closed form ``F = Tr(rho sigma)`` instead of the ``sqrtm``
#: Uhlmann formula.  Three orders tighter than :data:`_VALIDATION_TOL`, because
#: this constant chooses between an exact expression and an approximate one
#: rather than accepting or rejecting a state: a matrix that misses it still
#: gets the right answer, just by the slower route.
_PURE_STATE_TOL: Final[float] = 1e-12


#: Member *names* in canonical Bell order, in one place, before the enum body so
#: that :meth:`BellState.order_index` can use it without a forward reference.
#: :data:`BELL_ORDER` below is the public form, written out literally next to the
#: teleportation identity that fixes it; the two are pinned to agree by
#: ``tests/test_states.py::test_bell_order_matches_the_sort_order``.
_BELL_SORT_ORDER: Final[tuple[str, ...]] = (
    "PHI_PLUS",
    "PSI_PLUS",
    "PHI_MINUS",
    "PSI_MINUS",
)


class BellState(enum.StrEnum):
    """The four maximally entangled two-qubit Bell states.

    Members follow the standard definitions, written in the little-endian
    labelling of D2 (rightmost bit is qubit 0):

    ``PHI_PLUS``
        :math:`(|00\\rangle + |11\\rangle)/\\sqrt{2}`
    ``PHI_MINUS``
        :math:`(|00\\rangle - |11\\rangle)/\\sqrt{2}`
    ``PSI_PLUS``
        :math:`(|01\\rangle + |10\\rangle)/\\sqrt{2}`
    ``PSI_MINUS``
        :math:`(|01\\rangle - |10\\rangle)/\\sqrt{2}`

    Serialisation
    -------------
    The class is a :class:`enum.StrEnum`, so every member *is* its own label:
    ``BellState.PHI_PLUS == "Phi+"``, ``str(BellState.PHI_PLUS) == "Phi+"``, and
    :func:`json.dumps` accepts members directly, both as values and as
    dictionary keys::

        >>> import json
        >>> json.dumps({BellState.PHI_PLUS: 2, BellState.PSI_MINUS: 1})
        '{"Phi+": 2, "Psi-": 1}'

    This is what lets a Phase 4 Bell histogram, a Phase 5 result record and the
    Phase 6 dashboard write the enum out without a bespoke encoder.  ``repr``
    still shows ``<BellState.PHI_PLUS: 'Phi+'>``, so error messages built with
    ``{which!r}`` are unchanged.

    Ordering
    --------
    Members are ordered by :data:`BELL_ORDER` -- the teleportation-correction
    index, which is also the canonical row order of any Bell-basis histogram --
    **not** by the lexicographic order of their values, which would interleave
    the phases as ``Phi+ < Phi- < Psi+ < Psi-``.  So ``sorted(counts)`` produces
    histogram rows in protocol order for free:

        >>> [b.value for b in sorted(BellState)]
        ['Phi+', 'Psi+', 'Phi-', 'Psi-']

    Comparison against a plain :class:`str` is deliberately left to ``str``
    (there is no Bell order to appeal to), so mixed comparisons remain
    lexicographic.  Equality and hashing are ``str``'s throughout and are
    untouched by the ordering.

    Attributes
    ----------
    order_index : int
        Position in :data:`BELL_ORDER`, i.e. the two classical teleportation
        bits read as ``2 * m1 + m0``.
    """

    PHI_PLUS = "Phi+"
    PHI_MINUS = "Phi-"
    PSI_PLUS = "Psi+"
    PSI_MINUS = "Psi-"

    @property
    def order_index(self) -> int:
        """Position of this member in :data:`BELL_ORDER`.

        Returns
        -------
        int
            An integer in ``range(4)``.  Identical to
            ``BELL_ORDER.index(member)``, and equal to ``2 * m1 + m0`` for the
            classical bits of :func:`sih141.core.teleport.correction_bits`.
        """
        return _BELL_SORT_ORDER.index(self.name)

    def __lt__(self, other: object) -> bool:
        """Order by :data:`BELL_ORDER`, not by the string value."""
        if isinstance(other, BellState):
            return self.order_index < other.order_index
        return NotImplemented

    def __le__(self, other: object) -> bool:
        """Order by :data:`BELL_ORDER`, not by the string value."""
        if isinstance(other, BellState):
            return self.order_index <= other.order_index
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        """Order by :data:`BELL_ORDER`, not by the string value."""
        if isinstance(other, BellState):
            return self.order_index > other.order_index
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        """Order by :data:`BELL_ORDER`, not by the string value."""
        if isinstance(other, BellState):
            return self.order_index >= other.order_index
        return NotImplemented


#: Canonical index order of the Bell basis, used for the teleportation
#: correction in :mod:`sih141.core.teleport` and as the row order of any
#: Bell-basis histogram.
#:
#: The order is fixed by the teleportation identity, written below with the
#: exact signs this module's conventions produce (for a payload
#: :math:`|\psi\rangle = a|0\rangle + b|1\rangle` on qubit 0 and the resource
#: :math:`|\Phi^{+}\rangle` on qubits 1 and 2):
#:
#: .. math::
#:     |\psi\rangle_0 \otimes |\Phi^{+}\rangle_{12} = \tfrac{1}{2} \big[
#:       |\Phi^{+}\rangle(a|0\rangle + b|1\rangle)
#:     + |\Psi^{+}\rangle(b|0\rangle + a|1\rangle)
#:     + |\Phi^{-}\rangle(a|0\rangle - b|1\rangle)
#:     + |\Psi^{-}\rangle(b|0\rangle - a|1\rangle) \big]
#:
#: Note the :math:`|\Psi^{-}\rangle` branch is :math:`b|0\rangle - a|1\rangle`,
#: not the :math:`a|1\rangle - b|0\rangle` quoted by textbooks that define the
#: Bell phases differently; the two differ by an overall sign.  All four
#: branches carry equal amplitude weight :math:`1/2`, so each Bell outcome is
#: equiprobable at :math:`1/4`.
#:
#: so that ``BELL_ORDER.index(outcome)`` is the integer ``2 * m1 + m0`` whose
#: bits select the receiver's correction ``X**m0 @ Z**m1`` -- that is, apply
#: ``Z`` first and then ``X``:
#:
#: ===== ============ ======== ============
#: index outcome      (m1, m0) correction
#: ===== ============ ======== ============
#: 0     ``Phi+``     (0, 0)   ``I``
#: 1     ``Psi+``     (0, 1)   ``X``
#: 2     ``Phi-``     (1, 0)   ``Z``
#: 3     ``Psi-``     (1, 1)   ``X @ Z``
#: ===== ============ ======== ============
#:
#: The operator order matters for the ``Psi-`` row only, and only up to a global
#: phase: ``Z @ X == -(X @ Z)``.  ``X**m0 @ Z**m1`` is the form that recovers the
#: payload with *no* residual phase under the sign conventions of this module,
#: and ``tests/test_states.py`` derives all four rows from the teleportation
#: identity rather than assuming them.
BELL_ORDER: Final[tuple[BellState, ...]] = (
    BellState.PHI_PLUS,
    BellState.PSI_PLUS,
    BellState.PHI_MINUS,
    BellState.PSI_MINUS,
)

# Explicit amplitude vectors in little-endian index order
# [ |00>, |01>, |10>, |11> ]  ==  [ index 0, 1, 2, 3 ].
_BELL_AMPLITUDES: Final[dict[BellState, tuple[float, float, float, float]]] = {
    BellState.PHI_PLUS: (_SQRT1_2, 0.0, 0.0, _SQRT1_2),
    BellState.PHI_MINUS: (_SQRT1_2, 0.0, 0.0, -_SQRT1_2),
    BellState.PSI_PLUS: (0.0, _SQRT1_2, _SQRT1_2, 0.0),
    BellState.PSI_MINUS: (0.0, _SQRT1_2, -_SQRT1_2, 0.0),
}

# Pauli gates applied to qubit 0 *after* the H(0), CX(0, 1) core, listed in
# circuit (application) order.  Starting from |Phi+> = (|00> + |11>)/sqrt(2):
#   Z on q0 flips the sign of index 3 (q0 = 1)   -> |Phi->
#   X on q0 maps index 0 <-> 1 and index 2 <-> 3 -> |Psi+>
#   Z applied first, then X, composes the two    -> |Psi->
# The application order matters for |Psi-> only: applying X first and Z second
# gives -|Psi->, a global phase that is physically irrelevant but would break
# the exact amplitude comparison in tests/test_states.py.
#
# As a matrix product this is X @ Z (rightmost factor acts first), matching the
# correction column of the BELL_ORDER table above.
_BELL_FIXUP: Final[dict[BellState, tuple[str, ...]]] = {
    BellState.PHI_PLUS: (),
    BellState.PHI_MINUS: ("z",),
    BellState.PSI_PLUS: ("x",),
    BellState.PSI_MINUS: ("z", "x"),
}


def _as_array(state: StateLike) -> NDArray[np.complex128]:
    """Return the raw complex array backing ``state`` without validating it.

    Parameters
    ----------
    state : StateLike
        A Qiskit state object or a raw array.

    Returns
    -------
    numpy.ndarray
        A 1-D amplitude vector or a 2-D density matrix, ``complex128``.

    Raises
    ------
    ValueError
        If ``state`` cannot be interpreted as a numeric array.
    """
    if isinstance(state, (Statevector, DensityMatrix)):
        return np.asarray(state.data, dtype=np.complex128)
    try:
        arr = np.asarray(state, dtype=np.complex128)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "state must be a Statevector, a DensityMatrix or a numeric array; "
            f"got {type(state).__name__!r} which could not be converted: {exc}"
        ) from exc
    return arr


def _check_dimension(arr: NDArray[np.complex128]) -> int:
    """Validate array shape and return the Hilbert-space dimension.

    Parameters
    ----------
    arr : numpy.ndarray
        Candidate amplitude vector (1-D) or density matrix (2-D).

    Returns
    -------
    int
        The Hilbert-space dimension ``d``, guaranteed to be a power of two.

    Raises
    ------
    ValueError
        If the array is not 1-D or square 2-D, or if ``d`` is not a power of two.
    """
    if arr.ndim == 1:
        dim = arr.shape[0]
    elif arr.ndim == 2:
        if arr.shape[0] != arr.shape[1]:
            raise ValueError(
                "a density matrix must be square; got shape "
                f"{arr.shape}. Pass a 1-D array for a statevector."
            )
        dim = arr.shape[0]
    else:
        raise ValueError(
            "a state array must be 1-D (statevector) or 2-D (density matrix); "
            f"got {arr.ndim} dimensions with shape {arr.shape}."
        )
    if dim < 2 or (dim & (dim - 1)) != 0:
        raise ValueError(
            f"state dimension must be a power of two and at least 2; got {dim}. "
            "This project only models qubit systems."
        )
    return dim


def _coerce_state(
    state: StateLike, *, tol: float = _VALIDATION_TOL
) -> Statevector | DensityMatrix:
    """Normalise arbitrary state input to a validated Qiskit state object.

    This is the shared helper mandated by D1: every public function that accepts
    a state routes through it.  Purity is *preserved* -- a pure input comes back
    as a :class:`~qiskit.quantum_info.Statevector` -- which lets
    :func:`fidelity` take Qiskit's exact pure-state shortcut instead of an
    ``sqrtm``.

    The returned object always owns a **copy** of the data.  Qiskit's
    constructors wrap a ``complex128`` array by reference, so without the copy a
    caller mutating ``as_density(arr).data`` would silently write through to
    ``arr`` -- a trap for the Phase 3 channel code, which builds noisy states by
    manipulating matrices in place.

    Parameters
    ----------
    state : StateLike
        Statevector, density matrix, or raw array.
    tol : float, optional
        Absolute tolerance for the normalisation check.

    Returns
    -------
    qiskit.quantum_info.Statevector or qiskit.quantum_info.DensityMatrix
        ``Statevector`` for 1-D input, ``DensityMatrix`` for 2-D input, backed
        by data independent of the input.

    Raises
    ------
    ValueError
        If the state is non-finite, wrongly shaped, not normalised
        (:math:`\\langle\\psi|\\psi\\rangle = 1` or :math:`\\mathrm{Tr}\\rho = 1`),
        or -- for a density matrix -- not Hermitian or not positive
        semidefinite.

    Notes
    -----
    The three density-matrix checks together are exactly the definition of a
    physical state: :math:`\\mathrm{Tr}\\rho = 1`,
    :math:`\\rho = \\rho^{\\dagger}` and :math:`\\rho \\succeq 0`.  The last one
    is not decoration.  A Hermitian trace-one matrix with a negative eigenvalue
    is *not* a state, but it still has a well-defined trace, spectrum and
    overlap, so every metric downstream will happily return a number for it --
    and because :func:`purity`, :func:`fidelity` and :func:`concurrence` clip
    into ``[0, 1]``, that number is biased towards ``1``, i.e. towards
    "pure, maximally entangled, undisturbed".  That is precisely the direction
    that would *hide* an attack in Phases 3-5, so the failure is rejected here
    rather than absorbed later.  The realistic way to produce such a matrix is
    a Kraus-operator or mixing-probability slip in the Phase 3 channel code
    (e.g. a depolarising strength outside ``[0, 1]``).
    """
    arr = _as_array(state)
    if not np.isfinite(arr).all():
        raise ValueError("state contains NaN or infinite entries.")

    _check_dimension(arr)

    if arr.ndim == 1:
        norm_sq = float(np.vdot(arr, arr).real)
        if abs(norm_sq - 1.0) > tol:
            raise ValueError(
                f"statevector is not normalised: <psi|psi> = {norm_sq!r}, expected 1 "
                f"within {tol}. Divide by numpy.linalg.norm(amplitudes) first."
            )
        return Statevector(arr.copy())

    trace = complex(np.trace(arr))
    if abs(trace - 1.0) > tol:
        raise ValueError(
            f"density matrix is not normalised: Tr(rho) = {trace!r}, expected 1 "
            f"within {tol}. Divide by numpy.trace(rho) first."
        )
    if not np.allclose(arr, arr.conj().T, atol=tol, rtol=0.0):
        raise ValueError(
            "density matrix is not Hermitian: rho != rho.conj().T within "
            f"{tol}. A physical density operator must be self-adjoint."
        )
    # Symmetrise before eigvalsh: it reads one triangle only, so feeding it the
    # raw array would silently ignore an anti-Hermitian residue that has already
    # been bounded by `tol` above.
    smallest = float(np.linalg.eigvalsh(0.5 * (arr + arr.conj().T))[0])
    if smallest < -tol:
        raise ValueError(
            "density matrix is not positive semidefinite; smallest eigenvalue "
            f"{smallest!r}, expected >= {-tol}. A physical density operator has "
            "no negative eigenvalues -- check the Kraus operators or mixing "
            "probability that produced it (a depolarising strength outside "
            "[0, 1] is the usual cause)."
        )
    return DensityMatrix(arr.copy())


def _psd_eigenvalues(vals: NDArray[np.floating]) -> NDArray[np.float64]:
    """Clean the spectrum of a nominally PSD operator for safe square-rooting.

    Eigenvalues below a numerical-rank cutoff are snapped to exactly zero and
    residual negatives are clipped away.

    Why this matters: taking a square root is *infinitely steep at the origin*,
    so it amplifies absolute error near zero.  A null-space eigenvalue of
    ``1e-17`` -- ordinary rounding debris, since every pure state is
    rank-deficient -- becomes ``3e-9`` after ``sqrt``, which is large enough to
    swamp the alternating-sign sum in :func:`concurrence` and make a genuine
    product state score ``6e-9`` instead of ``0``.

    The cutoff is :func:`numpy.linalg.matrix_rank`'s rule,
    ``d * eps * max(lambda)``, with the largest eigenvalue floored at ``1``.
    That floor is the important part and is physically justified: every operator
    this helper sees is built from trace-one density matrices, so ``1`` is the
    problem's natural scale and its spectrum lies in ``[0, 1]``.  Using the
    matrix's own maximum alone would give a cutoff of *zero* for a matrix that
    is numerically zero, leaving exactly the noise this is meant to remove.

    The resulting resolution floor is ``sqrt(d * eps) ~ 3e-8``: a concurrence
    genuinely smaller than that is reported as ``0``.  Double precision cannot
    resolve it either way, and it is many orders below any Phase 4 detection
    threshold.

    Parameters
    ----------
    vals : numpy.ndarray
        Real eigenvalues as returned by :func:`numpy.linalg.eigvalsh`.

    Returns
    -------
    numpy.ndarray
        Non-negative eigenvalues, sub-threshold values snapped to zero.
    """
    real_vals = np.asarray(vals, dtype=np.float64)
    if real_vals.size == 0:
        return real_vals
    scale = max(float(real_vals.max()), 1.0)
    cutoff = scale * real_vals.size * float(np.finfo(np.float64).eps)
    return np.where(real_vals > cutoff, real_vals, 0.0)


def _sqrtm_psd(mat: NDArray[np.complex128]) -> NDArray[np.complex128]:
    """Principal square root of a Hermitian positive-semidefinite matrix.

    Computed by eigendecomposition rather than a general ``sqrtm``, which is
    both faster and numerically better behaved for the small (at most 8x8)
    Hermitian operators used here.

    Parameters
    ----------
    mat : numpy.ndarray
        Hermitian positive-semidefinite matrix.

    Returns
    -------
    numpy.ndarray
        The unique PSD matrix ``S`` with ``S @ S == mat``.
    """
    vals, vecs = np.linalg.eigh(mat)
    return (vecs * np.sqrt(_psd_eigenvalues(vals))) @ vecs.conj().T


def bell_state(which: BellState = BellState.PHI_PLUS) -> Statevector:
    """Return a Bell state as an exact statevector.

    Amplitudes are written out literally in little-endian index order
    ``[|00>, |01>, |10>, |11>]`` rather than being derived from a circuit, so
    this function is the ground truth that :func:`bell_circuit` is checked
    against.

    Parameters
    ----------
    which : BellState, optional
        Which of the four Bell states to build.  Defaults to
        :attr:`BellState.PHI_PLUS`, the standard entanglement resource
        :math:`|\\Phi^{+}\\rangle = (|00\\rangle + |11\\rangle)/\\sqrt{2}`.

    Returns
    -------
    qiskit.quantum_info.Statevector
        A normalised 2-qubit statevector with ``dims() == (2, 2)``.

    Raises
    ------
    ValueError
        If ``which`` is not a :class:`BellState` member.

    Examples
    --------
    >>> bell_state(BellState.PSI_PLUS).data.round(3)
    array([0.   +0.j, 0.707+0.j, 0.707+0.j, 0.   +0.j])
    """
    if not isinstance(which, BellState):
        raise ValueError(
            f"which must be a BellState member, got {which!r}. "
            "Use e.g. BellState.PHI_PLUS."
        )
    return Statevector(np.asarray(_BELL_AMPLITUDES[which], dtype=np.complex128))


def bell_circuit(which: BellState = BellState.PHI_PLUS) -> QuantumCircuit:
    """Return a circuit preparing ``which`` from :math:`|00\\rangle`.

    The core is the textbook entangler ``H(q0)`` then ``CX(q0 -> q1)``, which
    yields :math:`|\\Phi^{+}\\rangle`; the remaining three states are reached by
    single-qubit Pauli fixups on qubit 0.  The fixup order is chosen so that the
    circuit reproduces :func:`bell_state` *exactly*, including global phase, not
    merely up to it -- the test suite asserts amplitude equality rather than
    :meth:`~qiskit.quantum_info.Statevector.equiv`.

    Parameters
    ----------
    which : BellState, optional
        Which Bell state the circuit should prepare.

    Returns
    -------
    qiskit.QuantumCircuit
        A 2-qubit, measurement-free circuit.

    Raises
    ------
    ValueError
        If ``which`` is not a :class:`BellState` member.
    """
    if not isinstance(which, BellState):
        raise ValueError(
            f"which must be a BellState member, got {which!r}. "
            "Use e.g. BellState.PHI_PLUS."
        )
    circuit = QuantumCircuit(2, name=f"bell_{which.value}")
    circuit.h(0)
    circuit.cx(0, 1)
    for gate in _BELL_FIXUP[which]:
        getattr(circuit, gate)(0)
    return circuit


def as_density(state: StateLike, *, tol: float = _VALIDATION_TOL) -> DensityMatrix:
    """Convert any accepted state representation to the canonical density matrix.

    This is the project-wide entry point mandated by D1.  A pure input
    :math:`|\\psi\\rangle` becomes :math:`\\rho = |\\psi\\rangle\\!\\langle\\psi|`;
    a density matrix is returned unchanged (as a fresh object).

    Parameters
    ----------
    state : StateLike
        A :class:`~qiskit.quantum_info.Statevector`, a
        :class:`~qiskit.quantum_info.DensityMatrix`, a 1-D amplitude array, or a
        2-D density-matrix array.
    tol : float, optional
        Absolute tolerance for the normalisation and Hermiticity checks.

    Returns
    -------
    qiskit.quantum_info.DensityMatrix
        The state as a density operator.

    Raises
    ------
    ValueError
        If the input is malformed, non-finite, unnormalised, non-Hermitian, or
        (for a density matrix) not positive semidefinite.  Every state returned
        by this function is therefore physical, which is what lets the metrics
        below clip their results without hiding anything.

    Examples
    --------
    >>> round(float(as_density(bell_state()).data[0, 0].real), 6)
    0.5
    >>> as_density(bell_state()).dims()
    (2, 2)
    """
    coerced = _coerce_state(state, tol=tol)
    if isinstance(coerced, DensityMatrix):
        return coerced
    return DensityMatrix(coerced)


def fidelity(a: StateLike, b: StateLike) -> float:
    """Uhlmann fidelity ``F`` between two states, valid for mixed states.

    Uses the **squared** convention (see the module docstring):

    .. math::
        F(\\rho, \\sigma) =
            \\left(\\mathrm{Tr}\\sqrt{\\sqrt{\\rho}\\,\\sigma\\,\\sqrt{\\rho}}\\right)^{2}

    so ``F == 1`` for identical states and ``F == 0`` for orthogonal ones.  Every
    fidelity reported anywhere in this project -- teleportation fidelity, channel
    fidelity, the Phase 5 ROC features -- uses this same convention.

    Parameters
    ----------
    a, b : StateLike
        The two states.  Either may be pure or mixed; both are routed through
        the shared normaliser.  When both are pure this reduces to the exact
        squared overlap :math:`|\\langle a|b\\rangle|^{2}`.

    Returns
    -------
    float
        The fidelity, clipped into ``[0.0, 1.0]`` to absorb rounding.  Both
        inputs have already been validated positive semidefinite by
        :func:`_coerce_state`, so the exact value provably lies in ``[0, 1]``
        and the clip can only remove ``O(eps)`` overshoot -- it is not
        load-bearing and cannot mask an unphysical input.

    Raises
    ------
    ValueError
        If either state is invalid, or if the two states have different
        dimensions.

    Notes
    -----
    **Representation independence.**  The value depends only on the two states,
    never on how they were spelled.  That is not automatic: Qiskit's
    :func:`~qiskit.quantum_info.state_fidelity` takes the exact
    :math:`\\langle\\psi|\\rho|\\psi\\rangle` shortcut when one argument is a
    :class:`~qiskit.quantum_info.Statevector` but the ``sqrtm``-based Uhlmann
    formula when both are :class:`~qiskit.quantum_info.DensityMatrix`, and the
    ``sqrtm`` route carries about ``1e-8`` of absolute error.  A pure payload
    handed in as a 2-D array would then report a *different* number from the
    identical payload handed in as a ket, which broke the ``1e-9`` calibration
    contract of :mod:`sih141.core.teleport`.

    Whenever either state is pure the Uhlmann expression collapses exactly to
    :math:`F = \\mathrm{Tr}(\\rho\\sigma)`, so this function detects purity
    (:math:`|\\mathrm{Tr}(\\rho^{2}) - 1| \\le` :data:`_PURE_STATE_TOL`) and
    takes that closed form.  It is a single matrix product: exact to machine
    epsilon, and cheaper than the eigendecomposition it replaces.  Only the
    genuinely mixed-vs-mixed case, which has no closed form, still goes through
    ``sqrtm``.
    """
    state_a = _coerce_state(a)
    state_b = _coerce_state(b)
    if state_a.dim != state_b.dim:
        raise ValueError(
            "cannot compare states of different dimension: "
            f"{state_a.dim} vs {state_b.dim}. Trace out the extra subsystems "
            "with qiskit.quantum_info.partial_trace first."
        )
    if isinstance(state_a, Statevector) or isinstance(state_b, Statevector):
        # Qiskit's exact <psi|rho|psi> branch; no square root is taken.
        value = float(np.real(state_fidelity(state_a, state_b, validate=False)))
    else:
        rho = np.asarray(state_a.data, dtype=np.complex128)
        sigma = np.asarray(state_b.data, dtype=np.complex128)
        if _is_pure_matrix(rho) or _is_pure_matrix(sigma):
            value = float(np.real(np.trace(rho @ sigma)))
        else:
            value = float(
                np.real(state_fidelity(state_a, state_b, validate=False))
            )
    return float(np.clip(value, 0.0, 1.0))


def _is_pure_matrix(rho: NDArray[np.complex128]) -> bool:
    """Return ``True`` when a density matrix is pure to numerical tolerance.

    Parameters
    ----------
    rho : numpy.ndarray
        A validated density matrix.

    Returns
    -------
    bool
        ``True`` when :math:`|\\mathrm{Tr}(\\rho^{2}) - 1|` is at most
        :data:`_PURE_STATE_TOL`.  The tolerance is deliberately far tighter
        than :data:`_VALIDATION_TOL`: it gates an exact closed form against an
        approximate one, so it must only fire when the closed form really is
        exact.  A state that misses it by more than ``1e-12`` still gets the
        correct Uhlmann answer, merely by the slower route.
    """
    return abs(float(np.real(np.trace(rho @ rho))) - 1.0) <= _PURE_STATE_TOL


def purity(state: StateLike) -> float:
    """Return the purity :math:`\\mathrm{Tr}(\\rho^{2})`.

    Equals ``1`` for a pure state and ``1/d`` for the maximally mixed state of
    dimension ``d``, so it is the cheapest scalar witness that a channel or an
    eavesdropper has decohered a signal -- Phase 3 and Phase 4 both consume it.

    Parameters
    ----------
    state : StateLike
        Any accepted state representation.

    Returns
    -------
    float
        The purity, clipped into ``[0.0, 1.0]``.  :func:`as_density` has already
        rejected any non-PSD input, so :math:`\\mathrm{Tr}(\\rho^{2}) \\le 1`
        holds exactly and the clip only removes ``O(eps)`` overshoot.

    Raises
    ------
    ValueError
        If the state is invalid.
    """
    rho = np.asarray(as_density(state).data, dtype=np.complex128)
    value = float(np.real(np.trace(rho @ rho)))
    return float(np.clip(value, 0.0, 1.0))


def concurrence(state: StateLike) -> float:
    """Wootters concurrence of a two-qubit state.

    Implements Wootters' closed form for the entanglement of formation.  With
    the spin-flipped state

    .. math::
        \\tilde{\\rho} = (\\sigma_y \\otimes \\sigma_y)\\,\\rho^{*}\\,
                         (\\sigma_y \\otimes \\sigma_y)

    (the conjugation is taken in the computational basis) and
    :math:`\\lambda_1 \\ge \\lambda_2 \\ge \\lambda_3 \\ge \\lambda_4` the
    eigenvalues of :math:`R = \\rho\\tilde{\\rho}` in **descending** order,

    .. math::
        C(\\rho) = \\max\\!\\left(0,\\;
            \\sqrt{\\lambda_1} - \\sqrt{\\lambda_2}
            - \\sqrt{\\lambda_3} - \\sqrt{\\lambda_4}\\right).

    The eigenvalues are obtained from the Hermitian similarity transform
    :math:`\\sqrt{\\rho}\\,\\tilde{\\rho}\\,\\sqrt{\\rho}`, which shares its
    spectrum with the non-Hermitian :math:`R` but can be diagonalised with
    :func:`numpy.linalg.eigvalsh` and so yields real, ordered eigenvalues
    without spurious imaginary parts.

    ``C == 1`` for every Bell state, ``C == 0`` for any product state and for the
    maximally mixed state :math:`I/4`.  Because :math:`\\sigma_y \\otimes
    \\sigma_y` is invariant under exchanging the two qubits, the value does not
    depend on the endianness convention.

    Parameters
    ----------
    state : StateLike
        A two-qubit state (dimension 4).

    Returns
    -------
    float
        The concurrence, clipped into ``[0.0, 1.0]``.  :func:`as_density` has
        already rejected any non-PSD input, so ``C <= 1`` holds exactly and the
        clip only removes ``O(eps)`` overshoot.

    Raises
    ------
    ValueError
        If the state is invalid or is not two-qubit.
    """
    rho = np.asarray(as_density(state).data, dtype=np.complex128)
    if rho.shape != (4, 4):
        raise ValueError(
            "concurrence is only defined for two-qubit states (4x4 density "
            f"matrix); got shape {rho.shape}. Trace the system down to two "
            "qubits with qiskit.quantum_info.partial_trace first."
        )

    sigma_y = np.array([[0.0, -1.0j], [1.0j, 0.0]], dtype=np.complex128)
    yy = np.kron(sigma_y, sigma_y)
    rho_tilde = yy @ rho.conj() @ yy

    sqrt_rho = _sqrtm_psd(rho)
    hermitian_r = sqrt_rho @ rho_tilde @ sqrt_rho
    # Re-symmetrise to kill the ~1e-17 anti-Hermitian residue of the products.
    hermitian_r = 0.5 * (hermitian_r + hermitian_r.conj().T)

    eigenvalues = _psd_eigenvalues(np.linalg.eigvalsh(hermitian_r).real)
    roots = np.sqrt(np.sort(eigenvalues)[::-1])  # descending
    value = float(roots[0] - roots[1] - roots[2] - roots[3])
    return float(np.clip(value, 0.0, 1.0))


def is_normalised(state: StateLike, tol: float = 1e-9) -> bool:
    """Test whether a state carries unit norm (pure) or unit trace (mixed).

    Unlike :func:`as_density` this never raises for an unnormalised state; it is
    the predicate form, intended for assertions and for guarding a renormalise
    step.  It still raises for input that is not a state at all (wrong shape,
    non-numeric), because that is a programming error rather than a physical
    one.

    Parameters
    ----------
    state : StateLike
        Any accepted state representation.
    tol : float, optional
        Absolute tolerance, by default ``1e-9``.

    Returns
    -------
    bool
        ``True`` if :math:`\\langle\\psi|\\psi\\rangle = 1` (1-D input) or
        :math:`\\mathrm{Tr}\\rho = 1` (2-D input) within ``tol``.  ``False`` for
        non-finite entries.

    Raises
    ------
    ValueError
        If ``state`` is not array-like or has an inadmissible shape, or if
        ``tol`` is negative.
    """
    if tol < 0.0:
        raise ValueError(f"tol must be non-negative, got {tol!r}.")
    arr = _as_array(state)
    _check_dimension(arr)
    if not np.isfinite(arr).all():
        return False
    if arr.ndim == 1:
        return bool(abs(float(np.vdot(arr, arr).real) - 1.0) <= tol)
    return bool(abs(complex(np.trace(arr)) - 1.0) <= tol)
