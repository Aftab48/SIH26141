"""Pauli algebra and the three single-qubit measurement bases.

This module is the bottom of the physics stack. It defines the Pauli matrices,
the six single-qubit basis eigenstates, and the Clifford rotations that map an
arbitrary Pauli basis onto the computational (Z) basis so that a measurement in
that basis can be performed as a Z measurement.

Conventions
-----------
Qubit ordering
    Qiskit little-endian, project-wide. Qubit 0 is the **rightmost** character of
    a bitstring label, so ``"01"`` means qubit 1 is :math:`|0\\rangle` and qubit 0
    is :math:`|1\\rangle`. Everything in this module is single-qubit, but the
    circuits it produces are applied to individual qubits of larger registers by
    :mod:`sih141.core.measure`, where the ordering matters.
Eigenvalues, not bits
    ``eigenvalue`` arguments are the physical Pauli eigenvalues :math:`\\pm 1`,
    never the classical bits 0/1. The bit mapping used elsewhere in the project
    is ``+1 -> bit 0`` and ``-1 -> bit 1``.
Determinism
    :func:`random_basis` takes a keyword-only ``rng`` resolved through
    :func:`sih141.core.rng.resolve_rng`.

Definitions implemented here
----------------------------
The Pauli matrices in the computational basis are

.. math::

    I = \\begin{pmatrix}1&0\\\\0&1\\end{pmatrix},\\quad
    X = \\begin{pmatrix}0&1\\\\1&0\\end{pmatrix},\\quad
    Y = \\begin{pmatrix}0&-i\\\\i&0\\end{pmatrix},\\quad
    Z = \\begin{pmatrix}1&0\\\\0&-1\\end{pmatrix},

each Hermitian and unitary with :math:`P^2 = I`, hence spectrum
:math:`\\{+1, -1\\}`. Their eigenvectors are

.. math::

    Z:\\; |0\\rangle,\\; |1\\rangle \\qquad
    X:\\; |\\pm\\rangle = \\tfrac{1}{\\sqrt 2}(|0\\rangle \\pm |1\\rangle) \\qquad
    Y:\\; |{\\pm}i\\rangle = \\tfrac{1}{\\sqrt 2}(|0\\rangle \\pm i|1\\rangle).

The basis-change (measurement rotation) circuits satisfy
:math:`U_B |b_{+1}\\rangle = |0\\rangle` and :math:`U_B |b_{-1}\\rangle = |1\\rangle`:

.. math::

    U_X = H, \\qquad U_Y = H S^{\\dagger}, \\qquad U_Z = I.

The Y case is the easy one to get wrong. Working it out rather than recalling it:
:math:`S^{\\dagger} = \\mathrm{diag}(1, -i)`, so
:math:`S^{\\dagger}|{+}i\\rangle = \\tfrac{1}{\\sqrt 2}(|0\\rangle + i(-i)|1\\rangle)
= |+\\rangle`, and then :math:`H|+\\rangle = |0\\rangle`. Using :math:`S` instead of
:math:`S^{\\dagger}` swaps the two outcomes, which would silently invert every
Y-basis result. In circuit order the gates are ``sdg`` *then* ``h`` (matrix order
:math:`H S^{\\dagger}`, since circuits compose left-to-right in time but
right-to-left as matrices).
"""

from __future__ import annotations

import enum
from typing import Final

import numpy as np
from numpy.typing import NDArray
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from sih141.core.rng import resolve_rng

__all__ = [
    "PauliBasis",
    "PAULI_I",
    "PAULI_X",
    "PAULI_Y",
    "PAULI_Z",
    "pauli_matrix",
    "eigenstate",
    "eigenstate_label",
    "BASIS_CHANGE",
    "basis_change_circuit",
    "random_basis",
    "verify_eigenstate",
]

ComplexMatrix = NDArray[np.complex128]
"""A dense complex matrix (``numpy.complex128``)."""


class PauliBasis(enum.StrEnum):
    """A single-qubit measurement basis, named by its Pauli observable.

    Attributes
    ----------
    X : PauliBasis
        The :math:`\\{|+\\rangle, |-\\rangle\\}` basis.
    Y : PauliBasis
        The :math:`\\{|{+}i\\rangle, |{-}i\\rangle\\}` basis.
    Z : PauliBasis
        The computational basis :math:`\\{|0\\rangle, |1\\rangle\\}`.

    Serialisation
    -------------
    The class is a :class:`enum.StrEnum`, so every member *is* its own label:
    ``PauliBasis.X == "X"``, ``str(PauliBasis.X) == "X"``, and :func:`json.dumps`
    accepts members directly, both as values and as dictionary keys::

        >>> import json
        >>> json.dumps({PauliBasis.Z: 12, PauliBasis.X: 4})
        '{"Z": 12, "X": 4}'

    That is what lets a Phase 4 basis histogram, a Phase 5 result record and the
    Phase 6 dashboard write a basis out with no bespoke encoder.  ``repr`` still
    shows ``<PauliBasis.X: 'X'>``, so error messages built with ``{basis!r}``
    are unchanged, and the ``.value`` accessor used throughout this project
    keeps working.

    Ordering
    --------
    Members sort as their one-character labels do, which is ``X < Y < Z`` --
    the same order :func:`random_basis` draws from.  ``sorted()`` on a set, or
    on the keys of a ``{basis: count}`` histogram, therefore produces the same
    stable, documented order everywhere in the project.

        >>> [b.value for b in sorted(PauliBasis)]
        ['X', 'Y', 'Z']
    """

    X = "X"
    Y = "Y"
    Z = "Z"


def _make_pauli(rows: list[list[complex]]) -> ComplexMatrix:
    """Build a read-only 2x2 complex128 matrix for use as a module constant.

    Parameters
    ----------
    rows : list of list of complex
        The matrix entries, row-major.

    Returns
    -------
    ComplexMatrix
        A non-writeable array, so that a caller who mutates in place gets an
        error instead of silently corrupting the constant for every other
        module in the process.
    """
    matrix = np.array(rows, dtype=np.complex128)
    matrix.setflags(write=False)
    return matrix


PAULI_I: Final[ComplexMatrix] = _make_pauli([[1, 0], [0, 1]])
"""Identity :math:`I`. Read-only; use :func:`pauli_matrix` for a writeable copy."""

PAULI_X: Final[ComplexMatrix] = _make_pauli([[0, 1], [1, 0]])
"""Pauli :math:`X` (bit flip). Read-only."""

PAULI_Y: Final[ComplexMatrix] = _make_pauli([[0, -1j], [1j, 0]])
"""Pauli :math:`Y`. Read-only."""

PAULI_Z: Final[ComplexMatrix] = _make_pauli([[1, 0], [0, -1]])
"""Pauli :math:`Z` (phase flip). Read-only."""

_PAULI_BY_LABEL: Final[dict[str, ComplexMatrix]] = {
    "I": PAULI_I,
    "X": PAULI_X,
    "Y": PAULI_Y,
    "Z": PAULI_Z,
}

_INV_SQRT2: Final[float] = float(1.0 / np.sqrt(2.0))

_BASIS_ORDER: Final[tuple[PauliBasis, ...]] = (
    PauliBasis.X,
    PauliBasis.Y,
    PauliBasis.Z,
)

_EIGENSTATE_AMPLITUDES: Final[dict[tuple[PauliBasis, int], tuple[complex, complex]]] = {
    (PauliBasis.Z, 1): (1.0 + 0.0j, 0.0 + 0.0j),
    (PauliBasis.Z, -1): (0.0 + 0.0j, 1.0 + 0.0j),
    (PauliBasis.X, 1): (_INV_SQRT2 + 0.0j, _INV_SQRT2 + 0.0j),
    (PauliBasis.X, -1): (_INV_SQRT2 + 0.0j, -_INV_SQRT2 + 0.0j),
    (PauliBasis.Y, 1): (_INV_SQRT2 + 0.0j, 1j * _INV_SQRT2),
    (PauliBasis.Y, -1): (_INV_SQRT2 + 0.0j, -1j * _INV_SQRT2),
}

_EIGENSTATE_LABELS: Final[dict[tuple[PauliBasis, int], str]] = {
    (PauliBasis.Z, 1): "0",
    (PauliBasis.Z, -1): "1",
    (PauliBasis.X, 1): "+",
    (PauliBasis.X, -1): "-",
    (PauliBasis.Y, 1): "+i",
    (PauliBasis.Y, -1): "-i",
}


def _as_basis(basis: PauliBasis | str) -> PauliBasis:
    """Coerce a basis argument to :class:`PauliBasis`.

    Parameters
    ----------
    basis : PauliBasis or str
        A :class:`PauliBasis` member, or its name as a case-insensitive string
        (``"x"``, ``"X"``, ...). Strings are accepted so that configuration
        files and the Phase 6 dashboard can pass user input straight through.

    Returns
    -------
    PauliBasis
        The corresponding enum member.

    Raises
    ------
    ValueError
        If ``basis`` is a string that does not name a basis.
    TypeError
        If ``basis`` is neither a :class:`PauliBasis` nor a string.
    """
    if isinstance(basis, PauliBasis):
        return basis
    if isinstance(basis, str):
        try:
            return PauliBasis(basis.strip().upper())
        except ValueError:
            raise ValueError(
                f"unknown measurement basis {basis!r}; expected one of "
                f"'X', 'Y', 'Z' (case-insensitive) or a PauliBasis member"
            ) from None
    raise TypeError(
        f"basis must be a PauliBasis (or the string 'X', 'Y', 'Z'), got "
        f"{type(basis).__name__}"
    )


def _as_eigenvalue(eigenvalue: int) -> int:
    """Validate a Pauli eigenvalue and return it as a plain :class:`int`.

    Parameters
    ----------
    eigenvalue : int
        Must be ``+1`` or ``-1``.

    Returns
    -------
    int
        ``1`` or ``-1``.

    Raises
    ------
    ValueError
        If ``eigenvalue`` is anything else. The classical bits ``0``/``1`` and
        booleans are the expected mistake, so the message names the fix.
    """
    if isinstance(eigenvalue, bool):
        raise ValueError(
            f"eigenvalue must be the Pauli eigenvalue +1 or -1, got the boolean "
            f"{eigenvalue!r}. Booleans look like measurement bits; convert with "
            f"eigenvalue = 1 - 2 * bit (bit 0 -> +1, bit 1 -> -1)."
        )
    if eigenvalue == 1:
        return 1
    if eigenvalue == -1:
        return -1
    raise ValueError(
        f"eigenvalue must be +1 or -1, got {eigenvalue!r}. These are Pauli "
        f"eigenvalues, not measurement bits; convert with "
        f"eigenvalue = 1 - 2 * bit (bit 0 -> +1, bit 1 -> -1)."
    )


def pauli_matrix(label: str) -> ComplexMatrix:
    """Return the 2x2 matrix of a single-qubit Pauli operator.

    Parameters
    ----------
    label : str
        One of ``"I"``, ``"X"``, ``"Y"``, ``"Z"``, case-insensitive.

    Returns
    -------
    ComplexMatrix
        A fresh, writeable ``(2, 2)`` ``complex128`` array. A copy is returned on
        every call so that callers may scale or modify it without disturbing the
        module constants ``PAULI_I``/``PAULI_X``/``PAULI_Y``/``PAULI_Z``.

    Raises
    ------
    ValueError
        If ``label`` is not a single character from ``"IXYZ"``.
    TypeError
        If ``label`` is not a string.

    Notes
    -----
    Multi-qubit Pauli strings are deliberately not supported here, because the
    tensor-factor ordering of a string like ``"XZ"`` is exactly the little-endian
    trap this project is trying to avoid. Use
    :class:`qiskit.quantum_info.Pauli` (or :func:`sih141.core.measure.expectation`)
    for those, where the convention is Qiskit's and documented.

    Examples
    --------
    >>> from sih141.core.paulis import pauli_matrix
    >>> pauli_matrix("z")
    array([[ 1.+0.j,  0.+0.j],
           [ 0.+0.j, -1.+0.j]])
    """
    if not isinstance(label, str):
        raise TypeError(
            f"label must be a string from 'IXYZ', got {type(label).__name__}"
        )
    key = label.strip().upper()
    if key not in _PAULI_BY_LABEL:
        raise ValueError(
            f"unknown Pauli label {label!r}; expected a single character from "
            f"'IXYZ' (case-insensitive). Multi-qubit Pauli strings are not "
            f"handled here: use qiskit.quantum_info.Pauli instead."
        )
    return _PAULI_BY_LABEL[key].copy()


def eigenstate(basis: PauliBasis, eigenvalue: int) -> Statevector:
    """Return the eigenvector of a Pauli operator for a given eigenvalue.

    Parameters
    ----------
    basis : PauliBasis
        The Pauli observable whose eigenbasis is wanted.
    eigenvalue : int
        ``+1`` or ``-1`` (a Pauli eigenvalue, not a measurement bit).

    Returns
    -------
    qiskit.quantum_info.Statevector
        A freshly constructed normalised single-qubit state. Amplitudes are
        given in the computational basis, ordered ``[<0|psi>, <1|psi>]``:

        ===========  =============  =========================================
        ``basis``    ``eigenvalue``  state
        ===========  =============  =========================================
        ``Z``        ``+1``          :math:`|0\\rangle = (1, 0)`
        ``Z``        ``-1``          :math:`|1\\rangle = (0, 1)`
        ``X``        ``+1``          :math:`|+\\rangle = (1, 1)/\\sqrt 2`
        ``X``        ``-1``          :math:`|-\\rangle = (1, -1)/\\sqrt 2`
        ``Y``        ``+1``          :math:`|{+}i\\rangle = (1, i)/\\sqrt 2`
        ``Y``        ``-1``          :math:`|{-}i\\rangle = (1, -i)/\\sqrt 2`
        ===========  =============  =========================================

    Raises
    ------
    ValueError
        If ``eigenvalue`` is not ``+1`` or ``-1``, or ``basis`` is not a known
        basis.

    Notes
    -----
    Satisfies :math:`P|\\psi\\rangle = \\lambda|\\psi\\rangle`; see
    :func:`verify_eigenstate`, which checks exactly that relation numerically.
    The global phase convention is fixed (amplitude of :math:`|0\\rangle` is real
    and positive) so that tests can compare amplitudes directly rather than
    up to phase.

    Examples
    --------
    >>> from sih141.core.paulis import PauliBasis, eigenstate
    >>> eigenstate(PauliBasis.Z, -1).data
    array([0.+0.j, 1.+0.j])
    """
    key = (_as_basis(basis), _as_eigenvalue(eigenvalue))
    amplitudes = _EIGENSTATE_AMPLITUDES[key]
    return Statevector(np.array(amplitudes, dtype=np.complex128))


def eigenstate_label(basis: PauliBasis, eigenvalue: int) -> str:
    """Return the conventional ket label of a Pauli eigenstate.

    Parameters
    ----------
    basis : PauliBasis
        The Pauli observable.
    eigenvalue : int
        ``+1`` or ``-1``.

    Returns
    -------
    str
        One of ``"0"``, ``"1"``, ``"+"``, ``"-"``, ``"+i"``, ``"-i"`` -- the
        symbol inside the ket, without the bra-ket delimiters, suitable for
        logs, plots and the Phase 6 dashboard.

    Raises
    ------
    ValueError
        If ``eigenvalue`` is not ``+1`` or ``-1``, or ``basis`` is not a known
        basis.

    Examples
    --------
    >>> from sih141.core.paulis import PauliBasis, eigenstate_label
    >>> eigenstate_label(PauliBasis.Y, -1)
    '-i'
    """
    return _EIGENSTATE_LABELS[(_as_basis(basis), _as_eigenvalue(eigenvalue))]


def _build_basis_change(basis: PauliBasis) -> QuantumCircuit:
    """Construct the canonical rotation from ``basis`` onto the Z basis.

    Parameters
    ----------
    basis : PauliBasis
        The basis to rotate onto the computational basis.

    Returns
    -------
    qiskit.QuantumCircuit
        A one-qubit circuit ``U`` with ``U|b_{+1}> = |0>`` and
        ``U|b_{-1}> = |1>``.
    """
    circuit = QuantumCircuit(1, name=f"basis_change_{basis.value}")
    if basis is PauliBasis.X:
        # H|+> = |0>, H|-> = |1>.
        circuit.h(0)
    elif basis is PauliBasis.Y:
        # S-dagger first, then H: S-dagger|+i> = |+> and then H|+> = |0>.
        # Using S instead of S-dagger swaps the two outcomes.
        circuit.sdg(0)
        circuit.h(0)
    # PauliBasis.Z needs no rotation: the empty circuit is the identity.
    return circuit


BASIS_CHANGE: Final[dict[PauliBasis, QuantumCircuit]] = {
    basis: _build_basis_change(basis) for basis in _BASIS_ORDER
}
"""Canonical basis-change circuit templates, one per :class:`PauliBasis`.

Each circuit ``U`` rotates its basis onto the computational basis, so that
``U|b_{+1}> = |0>`` and ``U|b_{-1}> = |1>``: ``X -> H``, ``Y -> sdg`` then ``h``,
``Z -> `` the empty (identity) circuit.

These are shared templates and must not be mutated. Call
:func:`basis_change_circuit` to obtain a private copy to compose into a larger
circuit.
"""


def basis_change_circuit(basis: PauliBasis) -> QuantumCircuit:
    """Return a fresh circuit rotating ``basis`` onto the computational basis.

    Measuring an observable :math:`P` is equivalent to applying this rotation and
    then measuring :math:`Z`; this is how :mod:`sih141.core.measure` implements
    X- and Y-basis measurement, and how the Phase 2 protocol prepares its
    measurement layer.

    Parameters
    ----------
    basis : PauliBasis
        The basis to rotate onto the Z basis.

    Returns
    -------
    qiskit.QuantumCircuit
        A one-qubit circuit, independent of :data:`BASIS_CHANGE` so it is safe to
        extend or compose. ``X`` gives ``[h]``, ``Y`` gives ``[sdg, h]`` and
        ``Z`` gives an empty circuit on one qubit.

    Raises
    ------
    ValueError
        If ``basis`` is not a known basis.

    Notes
    -----
    Gate order is circuit order (time order), which is the reverse of matrix
    order: the ``Y`` circuit ``[sdg, h]`` implements the unitary
    :math:`H S^{\\dagger}`.

    Examples
    --------
    >>> from sih141.core.paulis import PauliBasis, basis_change_circuit
    >>> [inst.operation.name for inst in basis_change_circuit(PauliBasis.Y).data]
    ['sdg', 'h']
    """
    return BASIS_CHANGE[_as_basis(basis)].copy()


def random_basis(*, rng: np.random.Generator | None = None) -> PauliBasis:
    """Draw a measurement basis uniformly from ``{X, Y, Z}``.

    Used by the Phase 2 protocol to choose per-qubit measurement bases and by the
    Phase 3 eavesdropper to choose interception bases.

    Parameters
    ----------
    rng : numpy.random.Generator or None, optional
        Keyword-only. Resolved through :func:`sih141.core.rng.resolve_rng`; pass
        a seeded generator for reproducible runs.

    Returns
    -------
    PauliBasis
        One of the three bases, each with probability 1/3.

    Raises
    ------
    TypeError
        If ``rng`` is neither ``None`` nor a :class:`numpy.random.Generator`.

    Examples
    --------
    >>> import numpy as np
    >>> from sih141.core.paulis import random_basis
    >>> random_basis(rng=np.random.default_rng(7)) == random_basis(
    ...     rng=np.random.default_rng(7)
    ... )
    True
    """
    generator = resolve_rng(rng)
    return _BASIS_ORDER[int(generator.integers(len(_BASIS_ORDER)))]


def verify_eigenstate(
    basis: PauliBasis, eigenvalue: int, tol: float = 1e-9
) -> bool:
    """Check numerically that :func:`eigenstate` satisfies the eigen relation.

    Confirms :math:`P|\\psi\\rangle = \\lambda|\\psi\\rangle` for the state returned
    by ``eigenstate(basis, eigenvalue)``, entry by entry. This exists so that the
    hand-written amplitude tables in this module are validated against the Pauli
    matrices rather than trusted, and so downstream phases can assert the
    physics layer is sane before running an experiment.

    Parameters
    ----------
    basis : PauliBasis
        The Pauli observable.
    eigenvalue : int
        ``+1`` or ``-1``.
    tol : float, optional
        Absolute tolerance for the comparison, default ``1e-9``. Must be
        positive.

    Returns
    -------
    bool
        ``True`` if the relation holds within ``tol``.

    Raises
    ------
    ValueError
        If ``eigenvalue`` is not ``+1`` or ``-1``, ``basis`` is unknown, or
        ``tol`` is not positive.

    Examples
    --------
    >>> from sih141.core.paulis import PauliBasis, verify_eigenstate
    >>> all(
    ...     verify_eigenstate(basis, value)
    ...     for basis in PauliBasis
    ...     for value in (1, -1)
    ... )
    True
    """
    resolved_basis = _as_basis(basis)
    value = _as_eigenvalue(eigenvalue)
    if not tol > 0:
        raise ValueError(f"tol must be a positive tolerance, got {tol!r}")
    vector = eigenstate(resolved_basis, value).data
    observable = _PAULI_BY_LABEL[resolved_basis.value]
    return bool(
        np.allclose(observable @ vector, value * vector, atol=float(tol), rtol=0.0)
    )
