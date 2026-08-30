"""Tests for :mod:`sih141.core.paulis`.

These assert values, not "it ran": every amplitude is compared against a
hand-written expected vector, the Pauli algebra is checked as algebra, the
basis-change circuits are checked to map eigenstates onto ``|0>``/``|1>`` in the
right order, and the little-endian qubit convention (D2) is pinned with an
asymmetric two-qubit state that big-endian ordering would get wrong.
"""

from __future__ import annotations

import json

import numpy as np
import pytest
from qiskit import QuantumCircuit
from qiskit.quantum_info import Operator, Statevector

from sih141.core.paulis import (
    BASIS_CHANGE,
    PAULI_I,
    PAULI_X,
    PAULI_Y,
    PAULI_Z,
    PauliBasis,
    basis_change_circuit,
    eigenstate,
    eigenstate_label,
    pauli_matrix,
    random_basis,
    verify_eigenstate,
)

R2 = 1.0 / np.sqrt(2.0)

#: Hand-written expected amplitudes, in the computational basis, ordered
#: [<0|psi>, <1|psi>]. Written out independently of the module under test.
EXPECTED_EIGENSTATES: dict[tuple[PauliBasis, int], np.ndarray] = {
    (PauliBasis.Z, +1): np.array([1.0, 0.0], dtype=complex),
    (PauliBasis.Z, -1): np.array([0.0, 1.0], dtype=complex),
    (PauliBasis.X, +1): np.array([R2, R2], dtype=complex),
    (PauliBasis.X, -1): np.array([R2, -R2], dtype=complex),
    (PauliBasis.Y, +1): np.array([R2, 1j * R2], dtype=complex),
    (PauliBasis.Y, -1): np.array([R2, -1j * R2], dtype=complex),
}

ALL_CASES = list(EXPECTED_EIGENSTATES)

TOL = 1e-12


# --------------------------------------------------------------------------
# Pauli matrices
# --------------------------------------------------------------------------


def test_pauli_matrices_have_the_textbook_entries() -> None:
    """Explicit entry-by-entry check against the standard definitions."""
    assert np.array_equal(PAULI_I, np.array([[1, 0], [0, 1]], dtype=complex))
    assert np.array_equal(PAULI_X, np.array([[0, 1], [1, 0]], dtype=complex))
    assert np.array_equal(PAULI_Y, np.array([[0, -1j], [1j, 0]], dtype=complex))
    assert np.array_equal(PAULI_Z, np.array([[1, 0], [0, -1]], dtype=complex))
    for matrix in (PAULI_I, PAULI_X, PAULI_Y, PAULI_Z):
        assert matrix.dtype == np.complex128
        assert matrix.shape == (2, 2)


@pytest.mark.parametrize("label", ["I", "X", "Y", "Z"])
def test_paulis_are_hermitian_unitary_and_square_to_identity(label: str) -> None:
    """P = P-dagger, P P-dagger = I and P^2 = I, hence eigenvalues +-1."""
    matrix = pauli_matrix(label)
    identity = np.eye(2, dtype=complex)
    assert np.allclose(matrix, matrix.conj().T, atol=TOL)
    assert np.allclose(matrix @ matrix.conj().T, identity, atol=TOL)
    assert np.allclose(matrix @ matrix, identity, atol=TOL)


@pytest.mark.parametrize("label", ["X", "Y", "Z"])
def test_nonidentity_paulis_are_traceless_with_determinant_minus_one(
    label: str,
) -> None:
    """Tr(P) = 0 and det(P) = -1 for X, Y, Z: spectrum is exactly {+1, -1}."""
    matrix = pauli_matrix(label)
    assert np.isclose(np.trace(matrix), 0.0, atol=TOL)
    assert np.isclose(np.linalg.det(matrix), -1.0, atol=TOL)
    assert np.allclose(np.sort(np.linalg.eigvalsh(matrix)), [-1.0, 1.0], atol=TOL)


def test_pauli_algebra_relations() -> None:
    """Distinct Paulis anticommute, and XY = iZ, YZ = iX, ZX = iY."""
    x, y, z = pauli_matrix("X"), pauli_matrix("Y"), pauli_matrix("Z")
    zero = np.zeros((2, 2), dtype=complex)
    assert np.allclose(x @ y + y @ x, zero, atol=TOL)
    assert np.allclose(y @ z + z @ y, zero, atol=TOL)
    assert np.allclose(z @ x + x @ z, zero, atol=TOL)
    assert np.allclose(x @ y, 1j * z, atol=TOL)
    assert np.allclose(y @ z, 1j * x, atol=TOL)
    assert np.allclose(z @ x, 1j * y, atol=TOL)
    # Ordering matters: YX = -iZ, so a transposed convention would fail here.
    assert np.allclose(y @ x, -1j * z, atol=TOL)


@pytest.mark.parametrize("label", ["i", "x", "y", "z", " X ", "Z"])
def test_pauli_matrix_is_case_and_whitespace_insensitive(label: str) -> None:
    """Labels are normalised before lookup."""
    assert np.array_equal(pauli_matrix(label), pauli_matrix(label.strip().upper()))


def test_pauli_matrix_returns_an_independent_writeable_copy() -> None:
    """Mutating a returned matrix must not corrupt the module constant."""
    matrix = pauli_matrix("X")
    assert matrix.flags.writeable
    matrix[0, 0] = 99.0
    assert np.array_equal(PAULI_X, np.array([[0, 1], [1, 0]], dtype=complex))
    assert np.array_equal(pauli_matrix("X"), np.array([[0, 1], [1, 0]], dtype=complex))


def test_module_constants_are_read_only() -> None:
    """The shared constants reject in-place mutation instead of silently changing."""
    for matrix in (PAULI_I, PAULI_X, PAULI_Y, PAULI_Z):
        assert not matrix.flags.writeable
        with pytest.raises(ValueError):
            matrix[0, 0] = 0.0


@pytest.mark.parametrize("bad", ["A", "", "XZ", "II", "1"])
def test_pauli_matrix_rejects_unknown_labels(bad: str) -> None:
    """Unknown or multi-character labels raise ValueError, not a KeyError."""
    with pytest.raises(ValueError, match="Pauli label"):
        pauli_matrix(bad)


def test_pauli_matrix_rejects_non_string_labels() -> None:
    with pytest.raises(TypeError):
        pauli_matrix(0)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Eigenstates
# --------------------------------------------------------------------------


@pytest.mark.parametrize(("basis", "value"), ALL_CASES)
def test_eigenstate_amplitudes_match_hand_written_vectors(
    basis: PauliBasis, value: int
) -> None:
    """Amplitudes are compared entry-by-entry against the expected table."""
    state = eigenstate(basis, value)
    assert isinstance(state, Statevector)
    assert state.dims() == (2,)
    np.testing.assert_allclose(
        state.data, EXPECTED_EIGENSTATES[(basis, value)], atol=TOL
    )


@pytest.mark.parametrize(("basis", "value"), ALL_CASES)
def test_eigenstates_are_normalised(basis: PauliBasis, value: int) -> None:
    """<psi|psi> = 1."""
    data = eigenstate(basis, value).data
    assert np.isclose(np.vdot(data, data).real, 1.0, atol=TOL)
    assert np.isclose(np.vdot(data, data).imag, 0.0, atol=TOL)


@pytest.mark.parametrize(("basis", "value"), ALL_CASES)
def test_eigen_relation_holds_explicitly(basis: PauliBasis, value: int) -> None:
    """P|psi> = lambda|psi>, computed directly from the Pauli matrix."""
    vector = eigenstate(basis, value).data
    observable = pauli_matrix(basis.value)
    np.testing.assert_allclose(observable @ vector, value * vector, atol=TOL)


@pytest.mark.parametrize(("basis", "value"), ALL_CASES)
def test_verify_eigenstate_agrees(basis: PauliBasis, value: int) -> None:
    """The module's own self-check returns True for every (basis, eigenvalue)."""
    assert verify_eigenstate(basis, value) is True


#: Wrong amplitudes to substitute into the module's eigenstate table, chosen so
#: that each is a normalised one-qubit state (so nothing else can reject it) and
#: a plausible real mistake:
#:   Z,-1 -> |0>       an off-by-one in the eigenvalue -> row mapping
#:   X,+1 -> |->       a dropped minus sign
#:   Y,+1 -> |+>       a dropped factor of i, the exact failure
#:                     ``test_y_eigenstates_carry_the_imaginary_phase`` warns about
#:   X,-1 -> |+i>      an X row wired to a Y state
WRONG_AMPLITUDES: dict[tuple[PauliBasis, int], tuple[complex, complex]] = {
    (PauliBasis.Z, -1): (1.0 + 0.0j, 0.0 + 0.0j),
    (PauliBasis.X, +1): (R2 + 0.0j, -R2 + 0.0j),
    (PauliBasis.Y, +1): (R2 + 0.0j, R2 + 0.0j),
    (PauliBasis.X, -1): (R2 + 0.0j, 1j * R2),
}


@pytest.mark.parametrize("case", sorted(WRONG_AMPLITUDES, key=repr))
def test_verify_eigenstate_returns_false_for_a_corrupted_table(
    case: tuple[PauliBasis, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The self-check must have discriminating power, not just say ``True``.

    ``verify_eigenstate`` exists so downstream phases can assert the physics
    layer is sane before running an experiment.  A check that is only ever
    exercised on cases that pass proves nothing: ``return True`` would satisfy
    it.  Here the module's own amplitude table is corrupted with a normalised
    but wrong state and the check is required to notice.
    """
    import sih141.core.paulis as paulis

    basis, value = case
    monkeypatch.setitem(paulis._EIGENSTATE_AMPLITUDES, case, WRONG_AMPLITUDES[case])

    # The substituted vector is a legitimate normalised state, so only the
    # eigen relation itself can distinguish it.
    substituted = eigenstate(basis, value).data
    assert np.isclose(np.vdot(substituted, substituted).real, 1.0, atol=TOL)
    observable = pauli_matrix(basis.value)
    assert not np.allclose(observable @ substituted, value * substituted, atol=1e-9)

    assert verify_eigenstate(basis, value) is False


def test_verify_eigenstate_negative_case_survives_only_within_tolerance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``tol`` is honoured in both directions on a genuinely perturbed state.

    Rotating ``|0>`` by a small angle breaks ``Z|psi> = |psi>`` by ``~2*theta``
    in the lower amplitude.  With ``theta = 1e-6`` the default ``1e-9``
    tolerance must reject it and a ``1e-4`` tolerance must accept it -- which
    also proves the comparison is a real numerical one and not a constant.
    """
    import sih141.core.paulis as paulis

    theta = 1e-6
    perturbed = (np.cos(theta) + 0.0j, np.sin(theta) + 0.0j)
    monkeypatch.setitem(
        paulis._EIGENSTATE_AMPLITUDES, (PauliBasis.Z, 1), perturbed
    )

    assert verify_eigenstate(PauliBasis.Z, +1) is False
    assert verify_eigenstate(PauliBasis.Z, +1, tol=1e-4) is True


def test_y_eigenstates_carry_the_imaginary_phase() -> None:
    """|+i> is (|0> + i|1>)/sqrt2, not (|0> + |1>)/sqrt2.

    A dropped ``i`` would make the Y basis a duplicate of the X basis and quietly
    break every Y-basis result downstream.
    """
    y_plus = eigenstate(PauliBasis.Y, +1).data
    y_minus = eigenstate(PauliBasis.Y, -1).data
    assert np.isclose(y_plus[1], 1j * R2, atol=TOL)
    assert np.isclose(y_minus[1], -1j * R2, atol=TOL)
    assert not np.allclose(y_plus, eigenstate(PauliBasis.X, +1).data, atol=1e-6)
    assert not np.allclose(y_minus, eigenstate(PauliBasis.X, -1).data, atol=1e-6)


@pytest.mark.parametrize("basis", list(PauliBasis))
def test_eigenstates_of_one_basis_are_orthonormal(basis: PauliBasis) -> None:
    """<b_+1|b_-1> = 0 within each basis."""
    plus = eigenstate(basis, +1).data
    minus = eigenstate(basis, -1).data
    assert np.isclose(abs(np.vdot(plus, minus)), 0.0, atol=TOL)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (PauliBasis.X, PauliBasis.Y),
        (PauliBasis.X, PauliBasis.Z),
        (PauliBasis.Y, PauliBasis.Z),
    ],
)
def test_distinct_bases_are_mutually_unbiased(
    first: PauliBasis, second: PauliBasis
) -> None:
    """|<a|b>|^2 = 1/2 across different bases -- the basis mismatch that Phase 2
    relies on for its sifting step."""
    for value_a in (+1, -1):
        for value_b in (+1, -1):
            overlap = np.vdot(
                eigenstate(first, value_a).data, eigenstate(second, value_b).data
            )
            assert np.isclose(abs(overlap) ** 2, 0.5, atol=TOL)


@pytest.mark.parametrize("bad", [0, 2, -2, "1", None, 0.5])
def test_eigenstate_rejects_values_other_than_plus_or_minus_one(bad: object) -> None:
    """0/1 measurement bits are the expected mistake and must fail loudly."""
    with pytest.raises(ValueError, match=r"\+1 or -1"):
        eigenstate(PauliBasis.Z, bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [True, False])
def test_eigenstate_rejects_booleans(bad: bool) -> None:
    """``True`` equals 1 in Python, so booleans must be rejected explicitly."""
    with pytest.raises(ValueError, match="boolean"):
        eigenstate(PauliBasis.Z, bad)  # type: ignore[arg-type]


def test_eigenstate_returns_a_fresh_object_each_call() -> None:
    """Callers may mutate the returned Statevector's data without side effects."""
    first = eigenstate(PauliBasis.X, +1)
    assert first is not eigenstate(PauliBasis.X, +1)
    first.data[0] = 0.0
    np.testing.assert_allclose(
        eigenstate(PauliBasis.X, +1).data, np.array([R2, R2], dtype=complex), atol=TOL
    )


def test_eigenstate_accepts_basis_names_as_strings() -> None:
    """Convenience widening for config files and the Phase 6 dashboard."""
    np.testing.assert_allclose(
        eigenstate("y", +1).data,  # type: ignore[arg-type]
        eigenstate(PauliBasis.Y, +1).data,
        atol=TOL,
    )


def test_unknown_basis_string_raises_value_error() -> None:
    with pytest.raises(ValueError, match="unknown measurement basis"):
        eigenstate("W", +1)  # type: ignore[arg-type]


def test_non_basis_object_raises_type_error() -> None:
    with pytest.raises(TypeError):
        eigenstate(3, +1)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Labels
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("basis", "value", "expected"),
    [
        (PauliBasis.Z, +1, "0"),
        (PauliBasis.Z, -1, "1"),
        (PauliBasis.X, +1, "+"),
        (PauliBasis.X, -1, "-"),
        (PauliBasis.Y, +1, "+i"),
        (PauliBasis.Y, -1, "-i"),
    ],
)
def test_eigenstate_labels(basis: PauliBasis, value: int, expected: str) -> None:
    assert eigenstate_label(basis, value) == expected


def test_eigenstate_labels_are_unique() -> None:
    """Six distinct states must have six distinct names."""
    labels = [
        eigenstate_label(basis, value) for basis in PauliBasis for value in (+1, -1)
    ]
    assert len(set(labels)) == 6


def test_eigenstate_label_rejects_bit_values() -> None:
    with pytest.raises(ValueError, match=r"\+1 or -1"):
        eigenstate_label(PauliBasis.X, 0)


# --------------------------------------------------------------------------
# Basis-change circuits
# --------------------------------------------------------------------------


def _gate_names(circuit: QuantumCircuit) -> list[str]:
    return [instruction.operation.name for instruction in circuit.data]


@pytest.mark.parametrize(
    ("basis", "expected"),
    [(PauliBasis.X, ["h"]), (PauliBasis.Y, ["sdg", "h"]), (PauliBasis.Z, [])],
)
def test_basis_change_gate_sequences(
    basis: PauliBasis, expected: list[str]
) -> None:
    """Structural pin on the decomposition, including S-dagger (not S) for Y."""
    circuit = basis_change_circuit(basis)
    assert circuit.num_qubits == 1
    assert _gate_names(circuit) == expected


@pytest.mark.parametrize("basis", list(PauliBasis))
def test_basis_change_maps_eigenstates_onto_computational_basis(
    basis: PauliBasis,
) -> None:
    """U|b_+1> = |0> and U|b_-1> = |1>, exactly -- not merely up to a phase.

    The ordering is what matters: swapping the two would invert every measured
    bit in that basis.
    """
    circuit = basis_change_circuit(basis)
    ket_0 = np.array([1.0, 0.0], dtype=complex)
    ket_1 = np.array([0.0, 1.0], dtype=complex)

    rotated_plus = eigenstate(basis, +1).evolve(circuit).data
    rotated_minus = eigenstate(basis, -1).evolve(circuit).data
    np.testing.assert_allclose(rotated_plus, ket_0, atol=1e-12)
    np.testing.assert_allclose(rotated_minus, ket_1, atol=1e-12)


@pytest.mark.parametrize("basis", list(PauliBasis))
def test_basis_change_is_unitary_and_diagonalises_its_pauli(
    basis: PauliBasis,
) -> None:
    """U P U-dagger = Z, the defining property of a measurement rotation."""
    unitary = Operator(basis_change_circuit(basis)).data
    identity = np.eye(2, dtype=complex)
    assert np.allclose(unitary @ unitary.conj().T, identity, atol=TOL)
    observable = pauli_matrix(basis.value)
    np.testing.assert_allclose(
        unitary @ observable @ unitary.conj().T, pauli_matrix("Z"), atol=TOL
    )


def test_using_s_instead_of_sdagger_would_swap_the_y_outcomes() -> None:
    """Guard on the exact mistake the Y rotation invites.

    Building the rotation with ``s`` instead of ``sdg`` maps |+i> onto |1> and
    |-i> onto |0>, i.e. it inverts every Y-basis bit while still looking like a
    valid basis change. This test asserts the wrong circuit really is wrong, so
    the correctness test above is known to have teeth.
    """
    wrong = QuantumCircuit(1)
    wrong.s(0)
    wrong.h(0)
    np.testing.assert_allclose(
        eigenstate(PauliBasis.Y, +1).evolve(wrong).data,
        np.array([0.0, 1.0], dtype=complex),
        atol=TOL,
    )
    np.testing.assert_allclose(
        eigenstate(PauliBasis.Y, -1).evolve(wrong).data,
        np.array([1.0, 0.0], dtype=complex),
        atol=TOL,
    )
    assert not np.allclose(
        Operator(wrong).data, Operator(basis_change_circuit(PauliBasis.Y)).data
    )


def test_basis_change_circuit_returns_an_independent_copy() -> None:
    """Composing onto the returned circuit must not edit the shared template."""
    circuit = basis_change_circuit(PauliBasis.X)
    circuit.x(0)
    assert _gate_names(circuit) == ["h", "x"]
    assert _gate_names(BASIS_CHANGE[PauliBasis.X]) == ["h"]
    assert _gate_names(basis_change_circuit(PauliBasis.X)) == ["h"]


def test_basis_change_table_covers_every_basis() -> None:
    assert set(BASIS_CHANGE) == set(PauliBasis)
    for basis, circuit in BASIS_CHANGE.items():
        assert isinstance(circuit, QuantumCircuit)
        assert circuit.num_qubits == 1
        assert basis.value in circuit.name


def test_basis_change_circuit_rejects_unknown_basis() -> None:
    with pytest.raises(ValueError, match="unknown measurement basis"):
        basis_change_circuit("Q")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# D2: little-endian qubit ordering, pinned with an asymmetric state
# --------------------------------------------------------------------------


def test_bitstring_label_is_little_endian() -> None:
    """|01> has qubit 0 = 1 and qubit 1 = 0, i.e. amplitude at index 1.

    Under big-endian labelling the amplitude would sit at index 2, so this
    distinguishes the two conventions.
    """
    np.testing.assert_allclose(
        Statevector.from_label("01").data,
        np.array([0.0, 1.0, 0.0, 0.0], dtype=complex),
        atol=TOL,
    )
    np.testing.assert_allclose(
        Statevector.from_label("10").data,
        np.array([0.0, 0.0, 1.0, 0.0], dtype=complex),
        atol=TOL,
    )


def test_basis_change_acts_on_the_rightmost_character_of_the_label() -> None:
    """Applying the X rotation to qubit 0 of |0>_1 |->_0 must give |01>.

    The two-qubit register is deliberately asymmetric (qubit 1 in the Z basis,
    qubit 0 in the X basis): under big-endian ordering the rotation would land on
    the wrong factor and the result would not be a computational basis state at
    all. A symmetric state such as (|00> + |11>)/sqrt2 could not tell the two
    conventions apart.
    """
    # Qiskit tensor order: higher qubit index on the left of `.tensor`.
    register = eigenstate(PauliBasis.Z, +1).tensor(eigenstate(PauliBasis.X, -1))
    np.testing.assert_allclose(
        register.data, np.array([R2, -R2, 0.0, 0.0], dtype=complex), atol=TOL
    )

    rotation = basis_change_circuit(PauliBasis.X)
    on_qubit_0 = register.evolve(rotation, qargs=[0])
    np.testing.assert_allclose(
        on_qubit_0.data, Statevector.from_label("01").data, atol=TOL
    )

    # Sanity: the same rotation on qubit 1 does something entirely different,
    # so the assertion above is genuinely sensitive to the qubit index.
    on_qubit_1 = register.evolve(rotation, qargs=[1])
    assert not np.allclose(on_qubit_1.data, on_qubit_0.data, atol=1e-6)


def test_asymmetric_two_qubit_eigenstate_product_ordering() -> None:
    """|1>_1 |0>_0 is the label "10" -- index 2, not index 1."""
    register = eigenstate(PauliBasis.Z, -1).tensor(eigenstate(PauliBasis.Z, +1))
    np.testing.assert_allclose(
        register.data, np.array([0.0, 0.0, 1.0, 0.0], dtype=complex), atol=TOL
    )
    assert register.equiv(Statevector.from_label("10"))


# --------------------------------------------------------------------------
# random_basis / determinism (D3)
# --------------------------------------------------------------------------


def test_random_basis_is_reproducible_for_a_given_seed() -> None:
    """Same seed => identical sequence of bases."""
    first = [random_basis(rng=np.random.default_rng(20260141)) for _ in range(50)]
    second = [random_basis(rng=np.random.default_rng(20260141)) for _ in range(50)]
    assert first == second
    assert all(isinstance(basis, PauliBasis) for basis in first)


def test_random_basis_advances_a_shared_generator() -> None:
    """One generator threaded through many calls yields a varying stream."""
    rng = np.random.default_rng(20260141)
    sequence = [random_basis(rng=rng) for _ in range(50)]
    assert len(set(sequence)) == 3, "a stalled generator would repeat one basis"

    replay_rng = np.random.default_rng(20260141)
    assert [random_basis(rng=replay_rng) for _ in range(50)] == sequence


def test_random_basis_differs_across_seeds() -> None:
    seed_a = [random_basis(rng=np.random.default_rng(1)) for _ in range(30)]
    seed_b = [random_basis(rng=np.random.default_rng(2)) for _ in range(30)]
    assert seed_a != seed_b


def test_random_basis_is_uniform_over_the_three_bases() -> None:
    """Counts sit within a wide band around n/3 for a seeded draw."""
    rng = np.random.default_rng(4242)
    draws = 3000
    counts = {basis: 0 for basis in PauliBasis}
    for _ in range(draws):
        counts[random_basis(rng=rng)] += 1
    assert sum(counts.values()) == draws
    for basis, count in counts.items():
        assert abs(count - draws / 3) < 200, f"{basis} drawn {count} times"


def test_random_basis_works_without_an_explicit_generator() -> None:
    assert isinstance(random_basis(), PauliBasis)
    assert isinstance(random_basis(rng=None), PauliBasis)


def test_random_basis_rejects_a_bare_seed() -> None:
    """An int seed would restart the stream on every call; reject it."""
    with pytest.raises(TypeError):
        random_basis(rng=7)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# verify_eigenstate argument handling
# --------------------------------------------------------------------------


def test_verify_eigenstate_rejects_non_positive_tolerance() -> None:
    with pytest.raises(ValueError, match="tol"):
        verify_eigenstate(PauliBasis.X, +1, tol=0.0)
    with pytest.raises(ValueError, match="tol"):
        verify_eigenstate(PauliBasis.X, +1, tol=-1e-9)


def test_verify_eigenstate_rejects_bit_valued_eigenvalues() -> None:
    with pytest.raises(ValueError, match=r"\+1 or -1"):
        verify_eigenstate(PauliBasis.X, 0)


def test_verify_eigenstate_returns_a_plain_bool() -> None:
    result = verify_eigenstate(PauliBasis.Y, -1)
    assert isinstance(result, bool)
    assert not isinstance(result, np.bool_)


# --------------------------------------------------------------------------
# PauliBasis as a serialisable, sortable value type
# --------------------------------------------------------------------------


def test_pauli_basis_members_are_strings() -> None:
    """A StrEnum member *is* its label, so no bespoke encoder is ever needed."""
    assert isinstance(PauliBasis.X, str)
    assert PauliBasis.X == "X"
    assert str(PauliBasis.Y) == "Y"
    assert PauliBasis.Z.value == "Z"


def test_pauli_basis_is_json_serialisable_as_value_and_as_key() -> None:
    """Phase 5 result records and the Phase 6 dashboard write these out.

    Before the change ``json.dumps`` raised ``TypeError: Object of type
    PauliBasis is not JSON serializable`` for both positions.
    """
    counts = {PauliBasis.X: 4, PauliBasis.Y: 5, PauliBasis.Z: 6}
    assert json.dumps(counts) == '{"X": 4, "Y": 5, "Z": 6}'
    assert json.dumps([PauliBasis.Z, PauliBasis.X]) == '["Z", "X"]'
    assert json.loads(json.dumps(counts)) == {"X": 4, "Y": 5, "Z": 6}


def test_pauli_basis_sorts_x_then_y_then_z() -> None:
    """The documented, stable order for histogram rows and report tables."""
    assert list(sorted(PauliBasis)) == [PauliBasis.X, PauliBasis.Y, PauliBasis.Z]
    assert list(sorted([PauliBasis.Z, PauliBasis.X, PauliBasis.Y])) == [
        PauliBasis.X,
        PauliBasis.Y,
        PauliBasis.Z,
    ]
    assert PauliBasis.X < PauliBasis.Y < PauliBasis.Z
    assert not PauliBasis.Z < PauliBasis.X


def test_pauli_basis_sorting_a_histogram_gives_the_documented_row_order() -> None:
    """The Phase 4 use: ``sorted(counts)`` must be X, Y, Z regardless of build order."""
    counts = {PauliBasis.Z: 6, PauliBasis.X: 4, PauliBasis.Y: 5}
    assert [b.value for b in sorted(counts)] == ["X", "Y", "Z"]


def test_pauli_basis_equality_and_lookup_still_work_as_before() -> None:
    """The value type changed; identity, lookup and coercion did not."""
    assert PauliBasis("X") is PauliBasis.X
    assert PauliBasis("Z") is not PauliBasis.X
    assert len(set(PauliBasis)) == 3
    lookup = {basis: basis.value for basis in PauliBasis}
    assert lookup[PauliBasis.Y] == "Y"
    assert eigenstate_label(PauliBasis.X, +1) == "+"


def test_pauli_basis_repr_is_unchanged_so_error_messages_are_unchanged() -> None:
    """Messages built with ``{basis!r}`` and ``.value`` must read as before."""
    assert repr(PauliBasis.X) == "<PauliBasis.X: 'X'>"
    with pytest.raises(ValueError, match="unknown measurement basis"):
        eigenstate("W", +1)  # type: ignore[arg-type]
