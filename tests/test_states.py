"""Tests for :mod:`sih141.core.states`.

These are value assertions, not smoke tests.  Everything that a later phase can
silently get wrong is pinned numerically here:

* the exact little-endian amplitude vector of all four Bell states (D2),
* that :func:`bell_circuit` really produces what :func:`bell_state` claims,
  including global phase,
* that :func:`fidelity` uses the **squared** Uhlmann convention ``F``, not
  ``sqrt(F)``,
* that :func:`concurrence` reproduces closed-form analytic values,
* the ``BELL_ORDER`` -> teleportation-correction mapping that
  :mod:`sih141.core.teleport` will code against.

This file imports from ``sih141.core.states`` only, so it runs before the other
Phase 1 modules exist.
"""

from __future__ import annotations

import json
import math
import pathlib

import numpy as np
import pytest
from qiskit.quantum_info import DensityMatrix, Operator, Statevector, partial_trace

from sih141.core.states import (
    BELL_ORDER,
    _BELL_SORT_ORDER,
    BellState,
    _coerce_state,
    as_density,
    bell_circuit,
    bell_state,
    concurrence,
    fidelity,
    is_normalised,
    purity,
)

SQRT1_2 = math.sqrt(0.5)
TOL = 1e-9

#: Hand-written expected amplitudes in little-endian index order
#: ``[|00>, |01>, |10>, |11>]``, i.e. ``index == 2 * q1 + q0``.
EXPECTED_BELL_AMPLITUDES: dict[BellState, list[complex]] = {
    BellState.PHI_PLUS: [SQRT1_2, 0.0, 0.0, SQRT1_2],
    BellState.PHI_MINUS: [SQRT1_2, 0.0, 0.0, -SQRT1_2],
    BellState.PSI_PLUS: [0.0, SQRT1_2, SQRT1_2, 0.0],
    BellState.PSI_MINUS: [0.0, SQRT1_2, -SQRT1_2, 0.0],
}

PAULI_X = np.array([[0.0, 1.0], [1.0, 0.0]], dtype=complex)
PAULI_Z = np.array([[1.0, 0.0], [0.0, -1.0]], dtype=complex)
IDENTITY_2 = np.eye(2, dtype=complex)

KET_0 = Statevector([1.0, 0.0])
KET_1 = Statevector([0.0, 1.0])
KET_PLUS = Statevector([SQRT1_2, SQRT1_2])
MAXMIX_1Q = DensityMatrix(np.eye(2, dtype=complex) / 2.0)
MAXMIX_2Q = DensityMatrix(np.eye(4, dtype=complex) / 4.0)


def random_pure(n_qubits: int, rng: np.random.Generator) -> Statevector:
    """Draw a Haar-ish random pure state from an explicit ``rng`` (D3)."""
    dim = 2**n_qubits
    vec = rng.normal(size=dim) + 1j * rng.normal(size=dim)
    vec = vec / np.linalg.norm(vec)
    return Statevector(vec)


# --------------------------------------------------------------------------- #
# Bell state amplitudes                                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("which", list(BellState))
def test_bell_state_exact_amplitudes(which: BellState) -> None:
    """Each Bell state matches a hand-written amplitude vector exactly."""
    got = bell_state(which).data
    expected = np.asarray(EXPECTED_BELL_AMPLITUDES[which], dtype=complex)
    assert got.shape == (4,)
    np.testing.assert_allclose(got, expected, atol=TOL, rtol=0.0)


def test_bell_state_dims_are_two_qubits() -> None:
    """A Bell state is a 2-qubit system, not one 4-level system."""
    assert bell_state().dims() == (2, 2)


def test_bell_state_default_is_phi_plus() -> None:
    """The default entanglement resource is |Phi+>."""
    np.testing.assert_allclose(bell_state().data, bell_state(BellState.PHI_PLUS).data)


@pytest.mark.parametrize("which", list(BellState))
def test_bell_states_are_normalised(which: BellState) -> None:
    assert is_normalised(bell_state(which))
    assert is_normalised(as_density(bell_state(which)))


def test_bell_basis_is_orthonormal() -> None:
    """<B_i|B_j> == delta_ij for the four Bell states."""
    vectors = np.stack([bell_state(b).data for b in BELL_ORDER])
    gram = vectors.conj() @ vectors.T
    np.testing.assert_allclose(gram, np.eye(4, dtype=complex), atol=TOL, rtol=0.0)


def test_bell_basis_is_complete() -> None:
    """sum_i |B_i><B_i| == I_4, so the Bell basis spans the 2-qubit space."""
    total = np.zeros((4, 4), dtype=complex)
    for which in BELL_ORDER:
        vec = bell_state(which).data
        total += np.outer(vec, vec.conj())
    np.testing.assert_allclose(total, np.eye(4, dtype=complex), atol=TOL, rtol=0.0)


def test_bell_state_rejects_non_member() -> None:
    with pytest.raises(ValueError, match="BellState"):
        bell_state("Phi+")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# bell_circuit really produces bell_state                                      #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("which", list(BellState))
def test_bell_circuit_reproduces_bell_state_exactly(which: BellState) -> None:
    """The circuit output equals the declared statevector amplitude by amplitude.

    Deliberately *not* ``Statevector.equiv``: a global phase slip here would be
    invisible to ``equiv`` but would corrupt any interference experiment built
    on top of it in Phase 2.
    """
    produced = Statevector(bell_circuit(which))
    np.testing.assert_allclose(
        produced.data, bell_state(which).data, atol=TOL, rtol=0.0
    )


@pytest.mark.parametrize("which", list(BellState))
def test_bell_circuit_shape(which: BellState) -> None:
    circuit = bell_circuit(which)
    assert circuit.num_qubits == 2
    assert circuit.num_clbits == 0
    assert circuit.count_ops().get("measure", 0) == 0


def test_bell_circuit_rejects_non_member() -> None:
    with pytest.raises(ValueError, match="BellState"):
        bell_circuit(0)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# D2: little-endian ordering, pinned with an ASYMMETRIC state                  #
# --------------------------------------------------------------------------- #


def test_endianness_label_01_is_index_1() -> None:
    """|01> lives at index 1, so the rightmost label character is qubit 0.

    ``|01>`` is asymmetric: under a big-endian reading it would sit at index 2
    instead.  Symmetric states such as |Phi+> cannot tell the two apart, so the
    convention must be pinned here.
    """
    ket_01 = Statevector.from_label("01")
    np.testing.assert_allclose(ket_01.data, [0.0, 1.0, 0.0, 0.0], atol=TOL, rtol=0.0)
    # The big-endian reading would be [0, 0, 1, 0]; assert it is NOT that.
    assert abs(ket_01.data[2]) < TOL


def test_endianness_asymmetric_state_partial_traces() -> None:
    """For the label ``"01"``: qubit 0 is |1> and qubit 1 is |0>."""
    rho = as_density(Statevector.from_label("01"))
    qubit0 = partial_trace(rho, [1])  # trace out qubit 1, keep qubit 0
    qubit1 = partial_trace(rho, [0])  # trace out qubit 0, keep qubit 1
    assert fidelity(qubit0, KET_1) == pytest.approx(1.0, abs=TOL)
    assert fidelity(qubit1, KET_0) == pytest.approx(1.0, abs=TOL)
    # And explicitly not the swapped (big-endian) reading.
    assert fidelity(qubit0, KET_0) == pytest.approx(0.0, abs=TOL)


def test_endianness_asymmetric_product_state() -> None:
    """|1>_q0 tensor |0>_q1 == index 1, built without any label parsing."""
    # Statevector.tensor(b) puts b on the LOW qubits, so this is q0=|1>, q1=|0>.
    combined = KET_0.tensor(KET_1)
    np.testing.assert_allclose(combined.data, [0.0, 1.0, 0.0, 0.0], atol=TOL, rtol=0.0)


def test_endianness_of_psi_states_is_asymmetric() -> None:
    """|Psi-> is antisymmetric, so its component signs pin the qubit order.

    ``|Psi-> = (|01> - |10>)/sqrt(2)`` must carry ``+1/sqrt(2)`` at index 1
    (the ``|01>`` term, q0 = 1) and ``-1/sqrt(2)`` at index 2 (the ``|10>``
    term, q0 = 0).  A big-endian implementation flips both signs.
    """
    amps = bell_state(BellState.PSI_MINUS).data
    assert amps[1].real == pytest.approx(SQRT1_2, abs=TOL)
    assert amps[2].real == pytest.approx(-SQRT1_2, abs=TOL)


def test_endianness_survives_density_conversion() -> None:
    """as_density preserves the index convention: rho[1, 1] == 1 for |01>."""
    rho = as_density(Statevector.from_label("01")).data
    assert rho[1, 1].real == pytest.approx(1.0, abs=TOL)
    assert abs(rho[2, 2]) < TOL


# --------------------------------------------------------------------------- #
# as_density                                                                   #
# --------------------------------------------------------------------------- #


def test_as_density_from_statevector_is_outer_product() -> None:
    vec = KET_PLUS.data
    expected = np.outer(vec, vec.conj())
    np.testing.assert_allclose(as_density(KET_PLUS).data, expected, atol=TOL, rtol=0.0)


def test_as_density_of_phi_plus_explicit_matrix() -> None:
    """|Phi+><Phi+| has 1/2 in the four corners and zeros elsewhere."""
    expected = np.zeros((4, 4), dtype=complex)
    for i in (0, 3):
        for j in (0, 3):
            expected[i, j] = 0.5
    np.testing.assert_allclose(
        as_density(bell_state()).data, expected, atol=TOL, rtol=0.0
    )


def test_as_density_is_idempotent() -> None:
    once = as_density(bell_state(BellState.PSI_MINUS))
    twice = as_density(once)
    np.testing.assert_allclose(twice.data, once.data, atol=TOL, rtol=0.0)


def test_as_density_accepts_raw_arrays() -> None:
    from_1d = as_density(np.array([SQRT1_2, SQRT1_2]))
    from_2d = as_density(np.array([[0.5, 0.5], [0.5, 0.5]], dtype=complex))
    assert isinstance(from_1d, DensityMatrix)
    assert isinstance(from_2d, DensityMatrix)
    np.testing.assert_allclose(from_1d.data, from_2d.data, atol=TOL, rtol=0.0)


def test_as_density_accepts_python_list() -> None:
    np.testing.assert_allclose(
        as_density([1.0, 0.0]).data, [[1.0, 0.0], [0.0, 0.0]], atol=TOL, rtol=0.0
    )


def test_as_density_returns_trace_one_hermitian() -> None:
    rho = as_density(random_pure(3, np.random.default_rng(7)))
    assert rho.data.shape == (8, 8)
    assert np.trace(rho.data).real == pytest.approx(1.0, abs=TOL)
    np.testing.assert_allclose(rho.data, rho.data.conj().T, atol=TOL, rtol=0.0)


def test_as_density_preserves_qubit_subsystem_dims() -> None:
    """dims() must stay per-qubit, or partial_trace silently breaks downstream.

    ``measure`` and ``teleport`` both trace out subsystems by qubit index; a
    state that reported ``(4,)`` instead of ``(2, 2)`` would be a single 4-level
    system and could not be traced at all.
    """
    assert as_density(bell_state()).dims() == (2, 2)
    assert as_density(np.eye(4, dtype=complex) / 4).dims() == (2, 2)
    assert as_density(np.array([1.0, 0.0, 0.0, 0.0])).dims() == (2, 2)
    assert as_density(np.eye(8, dtype=complex) / 8).dims() == (2, 2, 2)
    assert as_density(random_pure(3, np.random.default_rng(3))).dims() == (2, 2, 2)


def test_qiskit_state_constructors_alias_by_reference() -> None:
    """The premise of the two tests below, asserted rather than assumed.

    If a future Qiskit release started copying in its constructors, the copies
    in ``_coerce_state`` would become dead weight and the aliasing tests would
    become vacuous without failing.  This assertion fails instead.
    """
    vector = np.array([1.0, 0.0], dtype=np.complex128)
    Statevector(vector).data[0] = 42.0
    assert vector[0] == pytest.approx(42.0, abs=TOL), "Statevector no longer aliases"

    matrix = np.eye(2, dtype=np.complex128) / 2
    DensityMatrix(matrix).data[0, 0] = 99.0
    assert matrix[0, 0] == pytest.approx(
        99.0, abs=TOL
    ), "DensityMatrix no longer aliases"


def test_as_density_does_not_alias_a_density_matrix_input() -> None:
    """The result owns its data; mutating it must not touch the caller's array.

    Qiskit wraps a complex128 array by reference, so this is a genuine trap for
    the Phase 3 channel code that edits matrices in place.

    Scope note: only the 2-D path is testable through ``as_density``.  For 1-D
    input the final ``DensityMatrix(statevector)`` step allocates a fresh outer
    product regardless, so a mutation of the returned 2-D ``.data`` could never
    reach a 1-D caller array even with the copy removed.  The 1-D copy is a
    contract of the shared normaliser and is tested there, in
    ``test_coerce_state_does_not_alias_1d_input``.
    """
    source = np.eye(4, dtype=np.complex128) / 4
    result = as_density(source)
    result.data[0, 0] = 99.0
    assert source[0, 0] == pytest.approx(0.25, abs=TOL)

    dm = DensityMatrix(np.eye(4, dtype=np.complex128) / 4)
    as_density(dm).data[0, 0] = 99.0
    assert dm.data[0, 0] == pytest.approx(0.25, abs=TOL)


def test_coerce_state_does_not_alias_1d_input() -> None:
    """``_coerce_state`` returns a Statevector backed by its own buffer.

    Tested against the shared normaliser directly because that is where the
    guarantee lives and the only place it is observable: ``_coerce_state``
    documents that "the returned object always owns a copy of the data", and
    Phase 2/3 code that wants the pure-state fast path (teleportation payloads,
    per-qubit eigenstates) will call it and hold the ``Statevector``.  Asserting
    this through ``as_density`` instead would pass with the copy deleted.
    """
    vector = np.array([1.0, 0.0], dtype=np.complex128)
    coerced = _coerce_state(vector)
    assert isinstance(coerced, Statevector)
    coerced.data[0] = 42.0
    assert vector[0] == pytest.approx(1.0, abs=TOL)

    sv = Statevector(np.array([1.0, 0.0], dtype=np.complex128))
    from_sv = _coerce_state(sv)
    from_sv.data[0] = 7.0
    assert sv.data[0] == pytest.approx(1.0, abs=TOL)


def test_coerce_state_does_not_alias_2d_input() -> None:
    """The same guarantee on the density-matrix branch of the normaliser."""
    matrix = np.eye(4, dtype=np.complex128) / 4
    coerced = _coerce_state(matrix)
    assert isinstance(coerced, DensityMatrix)
    coerced.data[0, 0] = 99.0
    assert matrix[0, 0] == pytest.approx(0.25, abs=TOL)


def test_as_density_rejects_unnormalised_statevector() -> None:
    with pytest.raises(ValueError, match="not normalised"):
        as_density(np.array([1.0, 1.0]))


def test_as_density_rejects_unnormalised_density_matrix() -> None:
    with pytest.raises(ValueError, match="not normalised"):
        as_density(np.eye(2, dtype=complex))


def test_as_density_rejects_non_hermitian() -> None:
    bad = np.array([[0.5, 1.0], [0.0, 0.5]], dtype=complex)
    with pytest.raises(ValueError, match="Hermitian"):
        as_density(bad)


#: Hermitian, trace-one matrices that are NOT positive semidefinite, i.e. not
#: physical states.  Each is a plausible product of a Phase 3 slip:
#: a two-qubit population that went negative, a one-qubit one, and
#: ``(1 + p) rho - (p / d) I`` -- a depolarising channel called with p = -0.2.
NON_PSD_MATRICES: dict[str, np.ndarray] = {
    "2q_negative_population": np.diag([1.5, -0.5, 0.0, 0.0]).astype(complex),
    "1q_negative_population": np.diag([1.2, -0.2]).astype(complex),
    "negative_depolarising_strength": 1.2
    * np.outer(
        bell_state().data, bell_state().data.conj()
    ).astype(complex)
    - 0.05 * np.eye(4, dtype=complex),
}


@pytest.mark.parametrize("name", sorted(NON_PSD_MATRICES))
def test_as_density_rejects_non_positive_semidefinite(name: str) -> None:
    """A Hermitian trace-one matrix with a negative eigenvalue is not a state.

    Unit trace and Hermiticity alone do not make a density operator; positivity
    is the third axiom and it is the one a Kraus/normalisation slip in the
    Phase 3 channel code actually breaks.  Without this check the metrics below
    still return numbers, and because they clip into ``[0, 1]`` those numbers
    are biased towards "pure, maximally entangled, undisturbed" -- the direction
    that hides an attack rather than revealing one.
    """
    bad = NON_PSD_MATRICES[name]
    smallest = float(np.linalg.eigvalsh(bad)[0])
    assert smallest < -1e-3, "fixture must actually be non-PSD"
    assert np.trace(bad).real == pytest.approx(1.0, abs=TOL)
    np.testing.assert_allclose(bad, bad.conj().T, atol=TOL, rtol=0.0)

    with pytest.raises(ValueError, match="positive semidefinite") as excinfo:
        as_density(bad)
    # The message must name the offending eigenvalue, as the trace and
    # Hermiticity messages name their offending quantity.
    assert f"{smallest!r}" in str(excinfo.value)


@pytest.mark.parametrize("name", sorted(NON_PSD_MATRICES))
def test_metrics_reject_non_positive_semidefinite(name: str) -> None:
    """purity/fidelity/concurrence must raise, not clip, on an unphysical input.

    Pinned because the pre-fix behaviour was silent and maximally misleading:
    ``purity`` reported ``1.0`` for a matrix with ``Tr(rho^2) == 2.5``,
    ``fidelity`` reported ``1.0`` against a state it was nowhere near, and a
    one-qubit variant reported ``0.0`` for a true overlap of ``-0.2``.
    """
    bad = NON_PSD_MATRICES[name]
    with pytest.raises(ValueError, match="positive semidefinite"):
        purity(bad)
    with pytest.raises(ValueError, match="positive semidefinite"):
        fidelity(bad, np.eye(len(bad), dtype=complex) / len(bad))
    with pytest.raises(ValueError, match="positive semidefinite"):
        fidelity(np.eye(len(bad), dtype=complex) / len(bad), bad)
    if bad.shape == (4, 4):
        with pytest.raises(ValueError, match="positive semidefinite"):
            concurrence(bad)


def test_as_density_tolerates_rounding_level_negative_eigenvalues() -> None:
    """The PSD check must not reject genuine states with eps-scale spectra.

    Every pure state is rank-deficient, so an 8x8 product of noisy channels
    routinely comes back with eigenvalues of order ``-1e-17``.  Rejecting those
    would make the check useless in exactly the Phase 3 code path it exists for,
    so the gate is the shared validation tolerance, not zero.
    """
    nearly_pure = np.diag([1.0 + 1e-12, -1e-12]).astype(complex)
    assert float(np.linalg.eigvalsh(nearly_pure)[0]) < 0.0
    assert purity(nearly_pure) == pytest.approx(1.0, abs=1e-9)

    # ... but a violation two orders of magnitude past the tolerance is caught.
    with pytest.raises(ValueError, match="positive semidefinite"):
        as_density(np.diag([1.0 + 1e-6, -1e-6]).astype(complex))


def test_valid_mixed_and_pure_states_still_pass_the_psd_check() -> None:
    """Regression guard: the new check must not reject anything physical."""
    rng = np.random.default_rng(20260830)
    for state in (
        MAXMIX_1Q,
        MAXMIX_2Q,
        bell_state(),
        bell_state(BellState.PSI_MINUS),
        DensityMatrix(np.eye(8, dtype=complex) / 8),
        random_pure(3, rng),
    ):
        rho = as_density(state)
        assert float(np.linalg.eigvalsh(rho.data)[0]) >= -1e-9
        assert 0.0 <= purity(rho) <= 1.0 + TOL

    # A 50/50 classical mixture of two random pure states is the generic rank-2
    # case (smallest eigenvalue exactly 0, twice) and must survive untouched.
    first, second = random_pure(2, rng).data, random_pure(2, rng).data
    mixture = 0.5 * np.outer(first, first.conj()) + 0.5 * np.outer(
        second, second.conj()
    )
    assert as_density(mixture).is_valid()
    assert purity(mixture) < 1.0


def test_as_density_rejects_non_square() -> None:
    with pytest.raises(ValueError, match="square"):
        as_density(np.zeros((2, 4), dtype=complex))


def test_as_density_rejects_non_power_of_two() -> None:
    vec = np.zeros(3, dtype=complex)
    vec[0] = 1.0
    with pytest.raises(ValueError, match="power of two"):
        as_density(vec)


def test_as_density_rejects_nan() -> None:
    with pytest.raises(ValueError, match="NaN or infinite"):
        as_density(np.array([np.nan, 0.0]))


def test_as_density_rejects_rank_three_array() -> None:
    with pytest.raises(ValueError, match="1-D .* or 2-D"):
        as_density(np.zeros((2, 2, 2), dtype=complex))


def test_as_density_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        as_density("not a state")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# fidelity                                                                     #
# --------------------------------------------------------------------------- #


def test_fidelity_of_identical_pure_states_is_one() -> None:
    psi = random_pure(2, np.random.default_rng(11))
    assert fidelity(psi, psi) == pytest.approx(1.0, abs=TOL)


def test_fidelity_of_orthogonal_bell_states_is_zero() -> None:
    for i, first in enumerate(BELL_ORDER):
        for j, second in enumerate(BELL_ORDER):
            expected = 1.0 if i == j else 0.0
            assert fidelity(bell_state(first), bell_state(second)) == pytest.approx(
                expected, abs=TOL
            )


def test_fidelity_uses_squared_convention() -> None:
    """F(|0>, |+>) == 1/2, not 1/sqrt(2).

    This is the load-bearing convention assertion: Qiskit's ``state_fidelity``
    returns ``F = |<a|b>|^2`` and this project follows it everywhere.  The
    square-root convention would give ~0.7071 here, so the two are cleanly
    distinguishable.
    """
    value = fidelity(KET_0, KET_PLUS)
    assert value == pytest.approx(0.5, abs=TOL)
    assert value != pytest.approx(SQRT1_2, abs=1e-3)


def test_fidelity_pure_versus_maximally_mixed() -> None:
    """F(|psi>, I/d) == <psi|I/d|psi> == 1/d."""
    assert fidelity(KET_0, MAXMIX_1Q) == pytest.approx(0.5, abs=TOL)
    assert fidelity(bell_state(), MAXMIX_2Q) == pytest.approx(0.25, abs=TOL)


def test_fidelity_of_maximally_mixed_with_itself_is_one() -> None:
    """The Uhlmann form must give 1 for identical mixed states too."""
    assert fidelity(MAXMIX_2Q, MAXMIX_2Q) == pytest.approx(1.0, abs=TOL)


def test_fidelity_of_two_mixed_states_matches_closed_form() -> None:
    """F(rho, sigma) for commuting diagonal states is (sum sqrt(p_i q_i))^2."""
    p = np.array([0.7, 0.3])
    q = np.array([0.4, 0.6])
    rho = DensityMatrix(np.diag(p).astype(complex))
    sigma = DensityMatrix(np.diag(q).astype(complex))
    expected = float(np.sum(np.sqrt(p * q)) ** 2)
    assert fidelity(rho, sigma) == pytest.approx(expected, abs=1e-9)


def test_fidelity_is_symmetric() -> None:
    rng = np.random.default_rng(2024)
    a = random_pure(2, rng)
    b = as_density(random_pure(2, rng))
    assert fidelity(a, b) == pytest.approx(fidelity(b, a), abs=TOL)


def test_fidelity_is_bounded() -> None:
    rng = np.random.default_rng(99)
    for _ in range(20):
        value = fidelity(random_pure(2, rng), random_pure(2, rng))
        assert 0.0 <= value <= 1.0


def test_fidelity_statevector_and_density_agree() -> None:
    """Wrapping an input in as_density must not change the fidelity."""
    a = bell_state(BellState.PSI_PLUS)
    b = bell_state(BellState.PSI_MINUS)
    assert fidelity(a, b) == pytest.approx(fidelity(as_density(a), as_density(b)), abs=TOL)
    assert fidelity(a, a) == pytest.approx(fidelity(a, as_density(a)), abs=TOL)


def test_fidelity_rejects_dimension_mismatch() -> None:
    with pytest.raises(ValueError, match="different dimension"):
        fidelity(KET_0, bell_state())


# --------------------------------------------------------------------------- #
# purity                                                                       #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("which", list(BellState))
def test_purity_of_pure_state_is_one(which: BellState) -> None:
    assert purity(bell_state(which)) == pytest.approx(1.0, abs=TOL)


def test_purity_of_maximally_mixed_is_one_over_d() -> None:
    assert purity(MAXMIX_1Q) == pytest.approx(0.5, abs=TOL)
    assert purity(MAXMIX_2Q) == pytest.approx(0.25, abs=TOL)


def test_purity_of_reduced_bell_half_is_one_half() -> None:
    """Tracing out half of |Phi+> leaves the maximally mixed qubit."""
    reduced = partial_trace(as_density(bell_state()), [1])
    assert purity(reduced) == pytest.approx(0.5, abs=TOL)


def test_purity_of_werner_matches_closed_form() -> None:
    """Tr(rho^2) for p|Phi+> + (1-p)I/4 is p^2 + (1-p)^2/4 + p(1-p)/2."""
    p = 0.6
    rho = p * as_density(bell_state()).data + (1 - p) * np.eye(4) / 4
    expected = float(np.real(np.trace(rho @ rho)))
    assert purity(rho) == pytest.approx(expected, abs=TOL)
    assert purity(rho) < 1.0


def test_purity_decreases_under_mixing() -> None:
    pure = purity(bell_state())
    noisy = purity(0.5 * as_density(bell_state()).data + 0.5 * np.eye(4) / 4)
    assert noisy < pure


# --------------------------------------------------------------------------- #
# concurrence                                                                  #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("which", list(BellState))
def test_concurrence_of_bell_states_is_one(which: BellState) -> None:
    """All four Bell states are maximally entangled."""
    assert concurrence(bell_state(which)) == pytest.approx(1.0, abs=1e-12)
    assert concurrence(as_density(bell_state(which))) == pytest.approx(1.0, abs=1e-12)


@pytest.mark.parametrize("label", ["00", "01", "10", "11"])
def test_concurrence_of_computational_product_states_is_zero(label: str) -> None:
    """Separable states score exactly zero, not merely 'small'.

    The rank cutoff inside the implementation is what makes this exact: without
    it, ``sqrt`` of a ``1e-17`` rounding residue leaks in at the ``1e-9`` level.
    """
    assert concurrence(Statevector.from_label(label)) == 0.0


def test_concurrence_of_superposed_product_state_is_zero() -> None:
    """|+> tensor |+> is unentangled despite being fully delocalised."""
    assert concurrence(KET_PLUS.tensor(KET_PLUS)) == 0.0


def test_concurrence_of_maximally_mixed_two_qubit_state_is_zero() -> None:
    assert concurrence(MAXMIX_2Q) == 0.0


def test_concurrence_of_classically_correlated_mixture_is_zero() -> None:
    """0.5|00><00| + 0.5|11><11| is correlated but separable."""
    rho = 0.5 * as_density(Statevector.from_label("00")).data
    rho += 0.5 * as_density(Statevector.from_label("11")).data
    assert concurrence(rho) == 0.0


@pytest.mark.parametrize("theta", [0.0, 0.1, math.pi / 8, math.pi / 4, 1.0])
def test_concurrence_of_partially_entangled_pure_state(theta: float) -> None:
    """cos(t)|00> + sin(t)|11> has concurrence |sin(2t)|."""
    amps = np.array([math.cos(theta), 0.0, 0.0, math.sin(theta)], dtype=complex)
    assert concurrence(Statevector(amps)) == pytest.approx(
        abs(math.sin(2 * theta)), abs=1e-12
    )


def test_concurrence_resolves_weak_entanglement() -> None:
    """Entanglement well above the documented ~3e-8 floor must survive.

    Phase 3's weakest attack signatures live here, so the rank cutoff must not
    swallow them.
    """
    for theta in (1e-3, 1e-5, 1e-7):
        amps = np.array([math.cos(theta), 0.0, 0.0, math.sin(theta)], dtype=complex)
        value = concurrence(Statevector(amps))
        assert value == pytest.approx(abs(math.sin(2 * theta)), rel=1e-6, abs=0)
        assert value > 0.0


@pytest.mark.parametrize("p", [0.0, 0.2, 1 / 3, 0.34, 0.5, 0.9, 1.0])
def test_concurrence_of_werner_state_matches_closed_form(p: float) -> None:
    """Werner state p|Psi-> + (1-p)I/4 has C = max(0, (3p - 1)/2).

    ``p = 1/3`` is the separability threshold and ``p = 0.34`` sits just above
    it, so this also checks the implementation does not clip away a small but
    genuine value near the kink.
    """
    rho = p * as_density(bell_state(BellState.PSI_MINUS)).data
    rho = rho + (1 - p) * np.eye(4, dtype=complex) / 4
    expected = max(0.0, (3 * p - 1) / 2)
    assert concurrence(rho) == pytest.approx(expected, abs=1e-12)


def test_concurrence_matches_pure_state_formula_for_random_states() -> None:
    """For a pure a|00>+b|01>+c|10>+d|11>, C == 2|ad - bc|."""
    rng = np.random.default_rng(4242)
    for _ in range(200):
        psi = random_pure(2, rng)
        a, b, c, d = psi.data
        expected = float(2 * abs(a * d - b * c))
        assert concurrence(psi) == pytest.approx(expected, abs=1e-12)


def test_concurrence_of_random_product_states_is_exactly_zero() -> None:
    """No separable state may leak a non-zero entanglement score."""
    rng = np.random.default_rng(31337)
    for _ in range(200):
        product = random_pure(1, rng).tensor(random_pure(1, rng))
        assert concurrence(product) == 0.0


def test_concurrence_is_invariant_under_local_unitaries() -> None:
    """Entanglement cannot be created or destroyed by local operations."""
    rng = np.random.default_rng(5150)
    for which in BellState:
        base = as_density(bell_state(which))
        for _ in range(10):
            u0 = Operator(
                np.linalg.qr(rng.normal(size=(2, 2)) + 1j * rng.normal(size=(2, 2)))[0]
            )
            u1 = Operator(
                np.linalg.qr(rng.normal(size=(2, 2)) + 1j * rng.normal(size=(2, 2)))[0]
            )
            evolved = base.evolve(u0, [0]).evolve(u1, [1])
            assert concurrence(evolved) == pytest.approx(1.0, abs=1e-12)


def test_concurrence_is_bounded_for_random_mixed_states() -> None:
    """0 <= C <= 1 for arbitrary physical two-qubit density matrices."""
    rng = np.random.default_rng(808)
    for _ in range(200):
        ginibre = rng.normal(size=(4, 4)) + 1j * rng.normal(size=(4, 4))
        rho = ginibre @ ginibre.conj().T
        rho = rho / np.trace(rho).real
        assert 0.0 <= concurrence(rho) <= 1.0


def test_concurrence_decreases_under_depolarising_noise() -> None:
    """Monotone decay under white noise -- the Phase 3 attack signature."""
    values = [
        concurrence(
            (1 - q) * as_density(bell_state()).data + q * np.eye(4, dtype=complex) / 4
        )
        for q in (0.0, 0.1, 0.3, 0.5, 0.7)
    ]
    assert values == sorted(values, reverse=True)
    assert values[0] == pytest.approx(1.0, abs=1e-12)
    assert values[-1] == 0.0


def test_concurrence_rejects_wrong_qubit_count() -> None:
    with pytest.raises(ValueError, match="two-qubit"):
        concurrence(KET_0)
    with pytest.raises(ValueError, match="two-qubit"):
        concurrence(random_pure(3, np.random.default_rng(1)))


# --------------------------------------------------------------------------- #
# is_normalised                                                                #
# --------------------------------------------------------------------------- #


def test_is_normalised_true_cases() -> None:
    assert is_normalised(bell_state())
    assert is_normalised(MAXMIX_2Q)
    assert is_normalised(np.array([SQRT1_2, -SQRT1_2]))
    assert is_normalised(np.array([[0.3, 0.0], [0.0, 0.7]], dtype=complex))


def test_is_normalised_false_cases_do_not_raise() -> None:
    """The predicate form must tolerate the very states as_density rejects."""
    assert not is_normalised(np.array([1.0, 1.0]))
    assert not is_normalised(np.zeros(4, dtype=complex))
    assert not is_normalised(np.eye(2, dtype=complex))
    assert not is_normalised(np.array([np.nan, 0.0]))


def test_is_normalised_respects_tolerance() -> None:
    slightly_off = np.array([math.sqrt(1.0 + 1e-6), 0.0])
    assert not is_normalised(slightly_off)
    assert is_normalised(slightly_off, tol=1e-5)


def test_is_normalised_rejects_bad_shape_and_tol() -> None:
    with pytest.raises(ValueError, match="square"):
        is_normalised(np.zeros((2, 4), dtype=complex))
    with pytest.raises(ValueError, match="non-negative"):
        is_normalised(bell_state(), tol=-1.0)


# --------------------------------------------------------------------------- #
# BELL_ORDER and the teleportation correction it fixes                         #
# --------------------------------------------------------------------------- #


def test_bell_order_is_a_permutation_of_the_enum() -> None:
    assert len(BELL_ORDER) == 4
    assert len(set(BELL_ORDER)) == 4
    assert set(BELL_ORDER) == set(BellState)


def test_bell_order_documented_positions() -> None:
    """Index i encodes (m1, m0) with correction ``X**m0 @ Z**m1``.

    Matrix order, so Z acts *first*.  This is the same order as the BELL_ORDER
    table in states.py and as the derivation in
    ``test_bell_order_encodes_the_teleportation_correction`` below; the reversed
    ``Z**m1 @ X**m0`` is a different operator on the Psi- row, since
    ``Z @ X == -(X @ Z)``.
    """
    assert BELL_ORDER == (
        BellState.PHI_PLUS,
        BellState.PSI_PLUS,
        BellState.PHI_MINUS,
        BellState.PSI_MINUS,
    )


#: The correction matrix documented for each BELL_ORDER index, written out
#: literally rather than derived, so a drift in either the table or the
#: derivation is caught.  Index i -> (m1, m0) = (i >> 1, i & 1).
EXPECTED_CORRECTIONS: list[np.ndarray] = [
    IDENTITY_2,
    PAULI_X,
    PAULI_Z,
    PAULI_X @ PAULI_Z,
]


def test_documented_correction_table_matches_x_after_z() -> None:
    """The literal correction column of the BELL_ORDER table is ``X**m0 @ Z**m1``.

    Guards the prose, which no other assertion touches: the derivation test
    below computes the correction from ``(m1, m0)``, so it would keep passing if
    the documented table said something else entirely.
    """
    for index in range(4):
        m1, m0 = index >> 1, index & 1
        x_after_z = np.linalg.matrix_power(PAULI_X, m0) @ np.linalg.matrix_power(
            PAULI_Z, m1
        )
        np.testing.assert_allclose(
            x_after_z, EXPECTED_CORRECTIONS[index], atol=TOL, rtol=0.0
        )


def test_reversed_operator_order_is_wrong_on_the_psi_minus_row_only() -> None:
    """``Z**m1 @ X**m0`` differs from the contract by -1 for Psi-, and only there.

    This is the exact sign trap states.py warns about.  It is pinned as its own
    assertion because ``fidelity`` cannot see it -- a global -1 leaves every
    fidelity at 1.0 -- so nothing else in the suite would ever notice
    ``teleport.pauli_correction`` implementing the reversed order.
    """
    differing = []
    for index in range(4):
        m1, m0 = index >> 1, index & 1
        x_after_z = np.linalg.matrix_power(PAULI_X, m0) @ np.linalg.matrix_power(
            PAULI_Z, m1
        )
        z_after_x = np.linalg.matrix_power(PAULI_Z, m1) @ np.linalg.matrix_power(
            PAULI_X, m0
        )
        if not np.allclose(x_after_z, z_after_x, atol=TOL):
            differing.append(BELL_ORDER[index])
            np.testing.assert_allclose(z_after_x, -x_after_z, atol=TOL, rtol=0.0)
    assert differing == [BellState.PSI_MINUS]


def test_states_module_documents_the_correction_in_matrix_order() -> None:
    """states.py's BELL_ORDER note must say ``X**m0 @ Z**m1``, never the reverse.

    Phase 2's ``teleport.pauli_correction`` is written against that prose, and a
    reader who follows the reversed form gets ``-payload`` on one branch in four.
    """
    source = (
        pathlib.Path(__file__)
        .resolve()
        .parents[1]
        .joinpath("sih141", "core", "states.py")
        .read_text(encoding="utf-8")
    )
    assert "X**m0 @ Z**m1" in source
    assert "Z**m1 @ X**m0" not in source


@pytest.mark.parametrize("seed", [0, 1, 17])
def test_bell_order_encodes_the_teleportation_correction(seed: int) -> None:
    """Derive the correction from the teleportation identity and check BELL_ORDER.

    Build ``|psi>_q0 (x) |Phi+>_{q1,q2}``, project qubits (0, 1) onto each Bell
    state, and confirm that ``X**m0 @ Z**m1`` -- with ``(m1, m0)`` read off the
    outcome's position in ``BELL_ORDER`` -- maps the receiver's unnormalised
    branch back onto ``payload / 2``.  Phase 2's ``teleport`` codes against
    exactly this mapping, so it is pinned here rather than assumed.

    The operator order is load-bearing for the ``Psi-`` row: ``Z @ X`` would
    return ``-payload / 2``.  That is only a global phase, and so invisible to
    ``fidelity``, but it would show up in any later interference experiment.
    """
    rng = np.random.default_rng(seed)
    payload = random_pure(1, rng)
    # tensor(b) places b on the LOW qubits: payload is q0, the pair is q1, q2.
    total = bell_state().tensor(payload).data

    for index, outcome in enumerate(BELL_ORDER):
        m1, m0 = index >> 1, index & 1
        correction = np.linalg.matrix_power(PAULI_X, m0) @ np.linalg.matrix_power(
            PAULI_Z, m1
        )
        bell_vec = bell_state(outcome).data

        # Receiver branch: <B|_{q1 q0} applied, leaving q2 free.
        # Full index is  i = 4*q2 + 2*q1 + q0.
        branch = np.zeros(2, dtype=complex)
        for q2 in (0, 1):
            for q1 in (0, 1):
                for q0 in (0, 1):
                    branch[q2] += (
                        np.conj(bell_vec[2 * q1 + q0]) * total[4 * q2 + 2 * q1 + q0]
                    )

        # Every branch carries equal weight 1/2 in amplitude (1/4 in probability).
        assert np.linalg.norm(branch) == pytest.approx(0.5, abs=TOL)
        np.testing.assert_allclose(
            correction @ branch, payload.data / 2.0, atol=1e-9, rtol=0.0
        )


def test_teleportation_identity_branch_amplitudes_are_exact() -> None:
    """Pin the exact signs of the identity documented on ``BELL_ORDER``.

    With payload ``a|0> + b|1>`` the four branches are, in ``BELL_ORDER``:
    ``a|0>+b|1>``, ``b|0>+a|1>``, ``a|0>-b|1>``, ``b|0>-a|1>``.  The last one is
    *not* the ``a|1>-b|0>`` some textbooks quote -- they differ by an overall
    sign because the Bell phase conventions differ -- and that sign is exactly
    what decides between ``X @ Z`` and ``Z @ X`` in ``teleport``.
    """
    a, b = 0.6 + 0.0j, 0.8 + 0.0j
    payload = Statevector(np.array([a, b]))
    total = bell_state().tensor(payload).data

    expected_branches = {
        BellState.PHI_PLUS: [a, b],
        BellState.PSI_PLUS: [b, a],
        BellState.PHI_MINUS: [a, -b],
        BellState.PSI_MINUS: [b, -a],
    }

    for outcome, expected in expected_branches.items():
        bell_vec = bell_state(outcome).data
        branch = np.zeros(2, dtype=complex)
        for q2 in (0, 1):
            for q1 in (0, 1):
                for q0 in (0, 1):
                    branch[q2] += (
                        np.conj(bell_vec[2 * q1 + q0]) * total[4 * q2 + 2 * q1 + q0]
                    )
        np.testing.assert_allclose(
            2.0 * branch, np.asarray(expected), atol=TOL, rtol=0.0
        )


def test_bell_states_are_local_pauli_images_of_phi_plus() -> None:
    """(I (x) P) |Phi+> reproduces the Bell basis, P acting on qubit 0.

    Consistency check on the sign conventions baked into ``_BELL_FIXUP``.
    """
    phi_plus = as_density(bell_state())
    expected = {
        BellState.PHI_PLUS: IDENTITY_2,
        BellState.PSI_PLUS: PAULI_X,
        BellState.PHI_MINUS: PAULI_Z,
        BellState.PSI_MINUS: PAULI_X @ PAULI_Z,
    }
    for which, gate in expected.items():
        evolved = phi_plus.evolve(Operator(gate), [0])
        assert fidelity(evolved, bell_state(which)) == pytest.approx(1.0, abs=TOL)


# --------------------------------------------------------------------------- #
# Determinism and the D3/D4 source-level bans                                  #
# --------------------------------------------------------------------------- #


def test_repeated_calls_are_bit_identical() -> None:
    """states.py is deterministic: no hidden randomness anywhere."""
    first = bell_state(BellState.PSI_MINUS).data
    second = bell_state(BellState.PSI_MINUS).data
    np.testing.assert_array_equal(first, second)
    assert bell_circuit(BellState.PSI_MINUS).count_ops() == bell_circuit(
        BellState.PSI_MINUS
    ).count_ops()


def test_same_seed_gives_identical_metrics() -> None:
    """Seeded input reproduces every metric exactly (D3)."""

    def run(seed: int) -> tuple[float, float, float]:
        rng = np.random.default_rng(seed)
        psi = random_pure(2, rng)
        return purity(psi), concurrence(psi), fidelity(psi, bell_state())

    assert run(1234) == run(1234)
    assert run(1234) != run(1235)


def test_module_source_has_no_banned_randomness_or_ml() -> None:
    """D3/D4 guard: no module-level numpy.random, no stdlib random, no ML deps."""
    source = pathlib.Path(
        __file__
    ).resolve().parents[1].joinpath("sih141", "core", "states.py").read_text(
        encoding="utf-8"
    )
    banned = [
        "np.random.",
        "numpy.random.",
        "import random",
        "sklearn",
        "torch",
        "tensorflow",
        "keras",
    ]
    for token in banned:
        assert token not in source, f"states.py must not reference {token!r}"


# --------------------------------------------------------------------------- #
# BellState as a serialisable, sortable value type                             #
# --------------------------------------------------------------------------- #


def test_bell_state_members_are_strings() -> None:
    """A StrEnum member *is* its label, so no bespoke encoder is ever needed."""
    assert isinstance(BellState.PHI_PLUS, str)
    assert BellState.PHI_PLUS == "Phi+"
    assert str(BellState.PSI_MINUS) == "Psi-"
    assert BellState.PSI_MINUS.value == "Psi-"


def test_bell_state_is_json_serialisable_as_value_and_as_key() -> None:
    """Phase 4 histograms, Phase 5 records and the Phase 6 dashboard need this.

    Before the change ``json.dumps`` raised ``TypeError: Object of type
    BellState is not JSON serializable`` for both positions.
    """
    payload = {which: index for index, which in enumerate(BELL_ORDER)}
    assert json.dumps(payload) == '{"Phi+": 0, "Psi+": 1, "Phi-": 2, "Psi-": 3}'
    assert json.dumps(list(BELL_ORDER)) == '["Phi+", "Psi+", "Phi-", "Psi-"]'
    assert json.loads(json.dumps(payload)) == {
        "Phi+": 0,
        "Psi+": 1,
        "Phi-": 2,
        "Psi-": 3,
    }


def test_bell_state_sorts_in_bell_order_not_alphabetically() -> None:
    """The documented order is the protocol one, not the lexicographic one.

    Lexicographically ``"Phi+" < "Phi-" < "Psi+" < "Psi-"`` ('+' is 0x2B, '-'
    is 0x2D), which interleaves the phases and would put a histogram's rows out
    of correction-index order.  ``BELL_ORDER`` is the order that matters.
    """
    assert tuple(sorted(BellState)) == BELL_ORDER
    assert tuple(sorted(reversed(BELL_ORDER))) == BELL_ORDER
    assert [b.value for b in sorted(BellState)] == [
        "Phi+",
        "Psi+",
        "Phi-",
        "Psi-",
    ]
    # ... and it is genuinely different from the string order it overrides.
    assert tuple(sorted(b.value for b in BellState)) != tuple(
        b.value for b in BELL_ORDER
    )


def test_bell_state_comparisons_are_consistent_in_all_four_directions() -> None:
    """``<``, ``<=``, ``>`` and ``>=`` must all follow BELL_ORDER, not ``str``."""
    for lower_index, lower in enumerate(BELL_ORDER):
        for upper_index, upper in enumerate(BELL_ORDER):
            assert (lower < upper) == (lower_index < upper_index)
            assert (lower <= upper) == (lower_index <= upper_index)
            assert (lower > upper) == (lower_index > upper_index)
            assert (lower >= upper) == (lower_index >= upper_index)


def test_bell_state_order_index_matches_bell_order() -> None:
    for index, which in enumerate(BELL_ORDER):
        assert which.order_index == index
        assert BELL_ORDER.index(which) == index


def test_bell_order_matches_the_sort_order() -> None:
    """``_BELL_SORT_ORDER`` and ``BELL_ORDER`` are two spellings of one fact.

    The names tuple exists only because the enum body cannot forward-reference
    ``BELL_ORDER``; if the two ever drift, sorting and the teleportation
    correction table would silently disagree.
    """
    assert tuple(b.name for b in BELL_ORDER) == _BELL_SORT_ORDER


def test_bell_state_equality_and_hashing_still_work_as_before() -> None:
    """The value type changed; identity, lookup and set semantics did not."""
    assert BellState("Phi+") is BellState.PHI_PLUS
    assert BellState.PHI_PLUS is not BellState.PHI_MINUS
    assert BellState.PHI_PLUS != BellState.PHI_MINUS
    assert len(set(BELL_ORDER)) == 4
    lookup = {which: which.value for which in BELL_ORDER}
    assert lookup[BellState.PSI_PLUS] == "Psi+"
    assert bell_state(BellState.PSI_PLUS).equiv(bell_state(BellState.PSI_PLUS))


def test_bell_state_repr_is_unchanged_so_error_messages_are_unchanged() -> None:
    """Several messages interpolate ``{which!r}``; ``repr`` must stay explicit."""
    assert repr(BellState.PHI_PLUS) == "<BellState.PHI_PLUS: 'Phi+'>"
    with pytest.raises(ValueError, match="BellState member"):
        bell_state("Phi+")  # type: ignore[arg-type]


def test_bell_state_string_inputs_are_still_rejected_by_bell_state() -> None:
    """Members being strings must not make bare strings acceptable states."""
    for bad in ("Phi+", "PHI_PLUS", 0):
        with pytest.raises(ValueError, match="BellState member"):
            bell_state(bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="BellState member"):
            bell_circuit(bad)  # type: ignore[arg-type]
