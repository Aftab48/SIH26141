"""Tests for :mod:`sih141.core.measure`.

Value assertions, not smoke tests.  The things a later phase can silently get
wrong are pinned numerically here:

* the little-endian embedding of a single-qubit projector (D2), pinned with the
  **asymmetric** state :math:`|01\\rangle` and with an explicit ``diag`` check --
  a big-endian implementation gives demonstrably different numbers for both,
* Born probabilities as ``Tr(rho P)``, so that they are right for **mixed**
  states and not only for pure ones,
* that the post-measurement state is a genuine collapse: Hermitian, unit trace,
  positive semidefinite, and *idempotent* (re-measuring the same qubit in the
  same basis reproduces the same eigenvalue with probability 1),
* the exact bitstring key convention of :func:`sample_counts`,
* the Qiskit character order of :func:`expectation`'s Pauli labels,
* that :func:`bell_measure` leaves the **spectator** qubits in their correct
  conditional state on a three-qubit register -- this is the property
  :mod:`sih141.core.teleport` is built on,
* determinism under a seeded ``numpy.random.Generator`` (D3).
"""

from __future__ import annotations

import math
import time
from collections import Counter

import numpy as np
import pytest
from qiskit.quantum_info import DensityMatrix, Statevector, partial_trace

from sih141.core.measure import (
    _MIN_BRANCH_PROB,
    _PROB_TOL,
    MeasurementOutcome,
    _collapse,
    _embed_single,
    _projectors,
    _select_branch,
    bell_measure,
    born_probabilities,
    expectation,
    joint_probability,
    measure_qubits,
    projective_measure,
    sample_counts,
)
from sih141.core.paulis import PAULI_X, PAULI_Y, PAULI_Z, PauliBasis, eigenstate
from sih141.core.states import (
    BELL_ORDER,
    BellState,
    _VALIDATION_TOL,
    as_density,
    bell_state,
)

SQRT1_2 = math.sqrt(0.5)
TOL = 1e-9

#: Asymmetric two-qubit state |01>: qubit 1 is |0>, qubit 0 is |1>.
#: Little-endian index == 2*q1 + q0 == 1.  A big-endian implementation would
#: place it at index 2, so every assertion using this state distinguishes the
#: two conventions.
KET_01 = Statevector(np.array([0.0, 1.0, 0.0, 0.0], dtype=complex))

MAXMIX_1Q = DensityMatrix(np.eye(2, dtype=complex) / 2.0)
MAXMIX_2Q = DensityMatrix(np.eye(4, dtype=complex) / 4.0)

ALL_BASES = list(PauliBasis)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def random_pure(n_qubits: int, rng: np.random.Generator) -> Statevector:
    """Draw a random pure state from an explicit generator (D3)."""
    dim = 2**n_qubits
    vec = rng.normal(size=dim) + 1j * rng.normal(size=dim)
    return Statevector(vec / np.linalg.norm(vec))


def random_mixed(
    n_qubits: int, rng: np.random.Generator, rank: int = 3
) -> DensityMatrix:
    """Draw a random full-rank-ish mixed state as a convex mixture of pures."""
    weights = rng.random(rank)
    weights /= weights.sum()
    dim = 2**n_qubits
    rho = np.zeros((dim, dim), dtype=complex)
    for weight in weights:
        vec = random_pure(n_qubits, rng).data
        rho += weight * np.outer(vec, vec.conj())
    return DensityMatrix(rho)


def assert_valid_density(state: DensityMatrix, n_qubits: int) -> None:
    """Assert the three defining properties of a physical density operator."""
    assert isinstance(state, DensityMatrix)
    assert state.num_qubits == n_qubits
    rho = np.asarray(state.data)
    assert rho.shape == (2**n_qubits, 2**n_qubits)
    # Unit trace.
    assert abs(complex(np.trace(rho)) - 1.0) < TOL
    # Hermitian.
    assert np.allclose(rho, rho.conj().T, atol=TOL)
    # Positive semidefinite.
    assert float(np.linalg.eigvalsh(0.5 * (rho + rho.conj().T))[0]) > -TOL


def pauli_label_for(qubit: int, basis: PauliBasis, n_qubits: int) -> str:
    """Build the Qiskit Pauli label acting with ``basis`` on ``qubit`` only."""
    return "I" * (n_qubits - 1 - qubit) + basis.value + "I" * qubit


# --------------------------------------------------------------------------- #
# D2: little-endian embedding                                                  #
# --------------------------------------------------------------------------- #


def test_embed_single_is_little_endian() -> None:
    """Z on qubit 0 of two qubits is diag(1, -1, 1, -1), not diag(1, 1, -1, -1).

    This is the D2 pin at the lowest level: the sign flips on the *odd* indices,
    which are exactly those with ``q0 == 1``.
    """
    embedded = _embed_single(np.asarray(PAULI_Z), 0, 2)
    assert np.allclose(embedded, np.diag([1.0, -1.0, 1.0, -1.0]), atol=TOL)

    embedded_q1 = _embed_single(np.asarray(PAULI_Z), 1, 2)
    assert np.allclose(embedded_q1, np.diag([1.0, 1.0, -1.0, -1.0]), atol=TOL)

    # The two differ, so the test genuinely distinguishes the conventions.
    assert not np.allclose(embedded, embedded_q1)


def test_embed_single_matches_explicit_kron() -> None:
    """The embedding equals kron(high, ..., low) for a three-qubit example."""
    identity = np.eye(2, dtype=complex)
    expected = np.kron(np.kron(identity, np.asarray(PAULI_X)), identity)
    assert np.allclose(_embed_single(np.asarray(PAULI_X), 1, 3), expected, atol=TOL)


def test_embed_single_one_qubit_register() -> None:
    """A one-qubit register embeds the operator unchanged."""
    assert np.allclose(_embed_single(np.asarray(PAULI_Y), 0, 1), np.asarray(PAULI_Y))


# --------------------------------------------------------------------------- #
# born_probabilities                                                           #
# --------------------------------------------------------------------------- #


def test_born_probabilities_endianness_pin_asymmetric_state() -> None:
    """|01> is certainly -1 on qubit 0 and certainly +1 on qubit 1 (D2).

    Symmetric states such as (|00> + |11>)/sqrt(2) cannot distinguish the two
    endianness conventions; |01> can, and does.
    """
    assert born_probabilities(KET_01, 0, PauliBasis.Z) == (0.0, 1.0)
    assert born_probabilities(KET_01, 1, PauliBasis.Z) == (1.0, 0.0)


@pytest.mark.parametrize(
    ("basis", "eigenvalue"),
    [(basis, value) for basis in ALL_BASES for value in (1, -1)],
)
def test_born_probabilities_on_eigenstates_are_certain(
    basis: PauliBasis, eigenvalue: int
) -> None:
    """Measuring an eigenstate in its own basis is deterministic."""
    p_plus, p_minus = born_probabilities(eigenstate(basis, eigenvalue), 0, basis)
    if eigenvalue == 1:
        assert p_plus == pytest.approx(1.0, abs=TOL)
        assert p_minus == pytest.approx(0.0, abs=TOL)
    else:
        assert p_plus == pytest.approx(0.0, abs=TOL)
        assert p_minus == pytest.approx(1.0, abs=TOL)


@pytest.mark.parametrize("basis", ALL_BASES)
def test_born_probabilities_unbiased_in_conjugate_bases(basis: PauliBasis) -> None:
    """|0> is unbiased in X and Y; |+> is unbiased in Y and Z."""
    if basis is not PauliBasis.Z:
        assert born_probabilities(eigenstate(PauliBasis.Z, 1), 0, basis) == pytest.approx(
            (0.5, 0.5), abs=TOL
        )
    if basis is not PauliBasis.X:
        assert born_probabilities(eigenstate(PauliBasis.X, 1), 0, basis) == pytest.approx(
            (0.5, 0.5), abs=TOL
        )


def test_born_probabilities_explicit_biased_value() -> None:
    """A hand-computed non-trivial value: cos^2(pi/8) for a rotated qubit.

    For |psi> = cos(t)|0> + sin(t)|1>, the Born rule gives
    Pr(+1 | Z) = cos^2(t) and Pr(+1 | X) = (1 + sin(2t)) / 2.
    """
    theta = math.pi / 8
    psi = Statevector(np.array([math.cos(theta), math.sin(theta)], dtype=complex))
    assert born_probabilities(psi, 0, PauliBasis.Z)[0] == pytest.approx(
        math.cos(theta) ** 2, abs=TOL
    )
    assert born_probabilities(psi, 0, PauliBasis.X)[0] == pytest.approx(
        (1.0 + math.sin(2 * theta)) / 2.0, abs=TOL
    )
    assert born_probabilities(psi, 0, PauliBasis.Y)[0] == pytest.approx(0.5, abs=TOL)


@pytest.mark.parametrize("basis", ALL_BASES)
def test_born_probabilities_maximally_mixed_is_unbiased(basis: PauliBasis) -> None:
    """Tr(rho P) is 1/2 for I/2 in every basis -- the mixed-state path."""
    assert born_probabilities(MAXMIX_1Q, 0, basis) == pytest.approx((0.5, 0.5), abs=TOL)


def test_born_probabilities_mixed_state_matches_convex_combination() -> None:
    """Tr(rho P) is linear in rho, unlike |<psi|P|psi>|.

    A 70/30 mixture of |0> and |1> must give exactly (0.7, 0.3) in Z.  Any
    implementation that only handles pure states cannot produce this.
    """
    rho = DensityMatrix(np.diag([0.7, 0.3]).astype(complex))
    assert born_probabilities(rho, 0, PauliBasis.Z) == pytest.approx(
        (0.7, 0.3), abs=TOL
    )
    # The same mixture is unbiased in X, because the coherences are gone.
    assert born_probabilities(rho, 0, PauliBasis.X) == pytest.approx(
        (0.5, 0.5), abs=TOL
    )


def test_born_probabilities_sum_to_one_for_random_states() -> None:
    """Completeness P_+ + P_- = 1 holds for random pure and mixed states."""
    rng = np.random.default_rng(20260141)
    for _ in range(20):
        for state in (random_pure(3, rng), random_mixed(3, rng)):
            for qubit in range(3):
                for basis in ALL_BASES:
                    p_plus, p_minus = born_probabilities(state, qubit, basis)
                    assert 0.0 <= p_plus <= 1.0
                    assert 0.0 <= p_minus <= 1.0
                    assert p_plus + p_minus == pytest.approx(1.0, abs=1e-12)


def test_born_probabilities_rejects_bad_arguments() -> None:
    """Out-of-range qubits and unknown bases raise actionable ValueErrors."""
    with pytest.raises(ValueError, match="0 <= qubit < 2"):
        born_probabilities(KET_01, 2, PauliBasis.Z)
    with pytest.raises(ValueError, match="0 <= qubit < 2"):
        born_probabilities(KET_01, -1, PauliBasis.Z)
    with pytest.raises(ValueError, match="unknown measurement basis"):
        born_probabilities(KET_01, 0, "W")


def test_born_probabilities_accepts_basis_strings() -> None:
    """Strings are coerced through the shared paulis helper, case-insensitively."""
    assert born_probabilities(KET_01, 0, "z") == born_probabilities(
        KET_01, 0, PauliBasis.Z
    )


# --------------------------------------------------------------------------- #
# projective_measure: genuine collapse                                         #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("basis", "eigenvalue"),
    [(basis, value) for basis in ALL_BASES for value in (1, -1)],
)
def test_projective_measure_eigenstate_is_deterministic(
    basis: PauliBasis, eigenvalue: int
) -> None:
    """An eigenstate returns its own eigenvalue, unchanged, for any seed."""
    psi = eigenstate(basis, eigenvalue)
    expected = DensityMatrix(psi)
    for seed in range(8):
        outcome = projective_measure(
            psi, 0, basis, rng=np.random.default_rng(seed)
        )
        assert outcome.eigenvalue == eigenvalue
        assert outcome.bit == (0 if eigenvalue == 1 else 1)
        assert outcome.basis is basis
        assert outcome.qubit == 0
        assert outcome.probability == pytest.approx(1.0, abs=TOL)
        assert np.allclose(outcome.post_state.data, expected.data, atol=TOL)


def test_projective_measure_collapse_is_exact_on_bell_state() -> None:
    """Measuring qubit 0 of |Phi+> in Z collapses the pair to |00> or |11>.

    The post-state is checked against a hand-written density matrix, so a
    function that merely returned the input state would fail.
    """
    phi_plus = bell_state(BellState.PHI_PLUS)
    ket_00 = DensityMatrix(Statevector(np.array([1, 0, 0, 0], dtype=complex)))
    ket_11 = DensityMatrix(Statevector(np.array([0, 0, 0, 1], dtype=complex)))

    seen: set[int] = set()
    rng = np.random.default_rng(11)
    for _ in range(40):
        outcome = projective_measure(phi_plus, 0, PauliBasis.Z, rng=rng)
        seen.add(outcome.eigenvalue)
        assert outcome.probability == pytest.approx(0.5, abs=TOL)
        expected = ket_00 if outcome.eigenvalue == 1 else ket_11
        assert np.allclose(outcome.post_state.data, expected.data, atol=TOL)
    assert seen == {1, -1}


def test_projective_measure_post_state_is_a_valid_density_matrix() -> None:
    """Hermitian, unit trace, positive semidefinite -- for pure and mixed input."""
    rng = np.random.default_rng(4242)
    for _ in range(10):
        for state in (random_pure(3, rng), random_mixed(3, rng)):
            for qubit in range(3):
                for basis in ALL_BASES:
                    outcome = projective_measure(state, qubit, basis, rng=rng)
                    assert_valid_density(outcome.post_state, 3)


def test_projective_measure_is_idempotent() -> None:
    """Re-measuring the same qubit in the same basis repeats the eigenvalue.

    This is the projection postulate's defining consequence (P^2 = P): after the
    first collapse the Born probability of the realised branch is exactly 1.
    """
    rng = np.random.default_rng(777)
    for _ in range(15):
        state = random_pure(2, rng)
        for basis in ALL_BASES:
            first = projective_measure(state, 0, basis, rng=rng)
            p_plus, p_minus = born_probabilities(first.post_state, 0, basis)
            certain = p_plus if first.eigenvalue == 1 else p_minus
            assert certain == pytest.approx(1.0, abs=1e-12)
            for _ in range(3):
                again = projective_measure(first.post_state, 0, basis, rng=rng)
                assert again.eigenvalue == first.eigenvalue
                assert again.probability == pytest.approx(1.0, abs=1e-12)
                assert np.allclose(
                    again.post_state.data, first.post_state.data, atol=TOL
                )


def test_projective_measure_does_not_disturb_an_unmeasured_qubit() -> None:
    """A product state |1> (x) |+> keeps qubit 1 intact when qubit 0 is measured."""
    # Qubit 0 in |+>, qubit 1 in |1>: amplitudes at indices 2 and 3.
    state = Statevector(np.array([0.0, 0.0, SQRT1_2, SQRT1_2], dtype=complex))
    outcome = projective_measure(state, 0, PauliBasis.Z, rng=np.random.default_rng(3))
    reduced_q1 = partial_trace(outcome.post_state, [0])
    assert np.allclose(reduced_q1.data, np.array([[0, 0], [0, 1]]), atol=TOL)


def test_projective_measure_reports_the_prior_probability() -> None:
    """``probability`` is Tr(rho P) for the pre-measurement state."""
    theta = math.pi / 5
    psi = Statevector(np.array([math.cos(theta), math.sin(theta)], dtype=complex))
    rng = np.random.default_rng(99)
    for _ in range(20):
        outcome = projective_measure(psi, 0, PauliBasis.Z, rng=rng)
        expected = (
            math.cos(theta) ** 2 if outcome.eigenvalue == 1 else math.sin(theta) ** 2
        )
        assert outcome.probability == pytest.approx(expected, abs=TOL)


def test_projective_measure_frequencies_match_born_rule() -> None:
    """The sampler is unbiased: empirical frequency tracks Tr(rho P)."""
    theta = math.pi / 5
    psi = Statevector(np.array([math.cos(theta), math.sin(theta)], dtype=complex))
    rng = np.random.default_rng(2026)
    trials = 4000
    plus = sum(
        1
        for _ in range(trials)
        if projective_measure(psi, 0, PauliBasis.Z, rng=rng).eigenvalue == 1
    )
    expected = math.cos(theta) ** 2
    # 4 sigma of a binomial with p ~ 0.65, n = 4000 is about 0.030.
    assert abs(plus / trials - expected) < 0.03


def test_projective_measure_is_deterministic_under_a_seed() -> None:
    """Same seed, same everything (D3)."""
    state = random_pure(3, np.random.default_rng(5))
    first = projective_measure(
        state, 1, PauliBasis.Y, rng=np.random.default_rng(31337)
    )
    second = projective_measure(
        state, 1, PauliBasis.Y, rng=np.random.default_rng(31337)
    )
    assert first.eigenvalue == second.eigenvalue
    assert first.probability == second.probability
    assert np.array_equal(first.post_state.data, second.post_state.data)


# --------------------------------------------------------------------------- #
# MeasurementOutcome dataclass                                                 #
# --------------------------------------------------------------------------- #


def test_measurement_outcome_is_frozen() -> None:
    """The record is immutable, so a consumer cannot rewrite history."""
    outcome = projective_measure(
        KET_01, 0, PauliBasis.Z, rng=np.random.default_rng(0)
    )
    with pytest.raises(Exception):
        outcome.eigenvalue = 1  # type: ignore[misc]


def test_measurement_outcome_rejects_inconsistent_bit() -> None:
    """+1 must carry bit 0 and -1 must carry bit 1."""
    post = DensityMatrix(eigenstate(PauliBasis.Z, 1))
    with pytest.raises(ValueError, match="inconsistent with eigenvalue"):
        MeasurementOutcome(
            eigenvalue=1,
            bit=1,
            basis=PauliBasis.Z,
            qubit=0,
            probability=1.0,
            post_state=post,
        )
    with pytest.raises(ValueError, match="must be \\+1 or -1"):
        MeasurementOutcome(
            eigenvalue=0,
            bit=0,
            basis=PauliBasis.Z,
            qubit=0,
            probability=1.0,
            post_state=post,
        )
    with pytest.raises(ValueError, match="probability"):
        MeasurementOutcome(
            eigenvalue=1,
            bit=0,
            basis=PauliBasis.Z,
            qubit=0,
            probability=1.5,
            post_state=post,
        )


# --------------------------------------------------------------------------- #
# measure_qubits                                                               #
# --------------------------------------------------------------------------- #


def test_measure_qubits_endianness_pin() -> None:
    """|01> gives eigenvalue -1 on qubit 0 and +1 on qubit 1 (D2)."""
    outcomes, final = measure_qubits(
        KET_01,
        {1: PauliBasis.Z, 0: PauliBasis.Z},
        rng=np.random.default_rng(1),
    )
    # Results come back in ascending qubit order regardless of mapping order.
    assert [o.qubit for o in outcomes] == [0, 1]
    assert [o.eigenvalue for o in outcomes] == [-1, 1]
    assert [o.bit for o in outcomes] == [1, 0]
    assert np.allclose(final.data, DensityMatrix(KET_01).data, atol=TOL)


def test_measure_qubits_final_state_is_the_last_post_state() -> None:
    """The returned state is the fully collapsed one, and is valid."""
    rng = np.random.default_rng(808)
    state = random_pure(3, rng)
    outcomes, final = measure_qubits(
        state, {0: PauliBasis.X, 2: PauliBasis.Y}, rng=rng
    )
    assert len(outcomes) == 2
    assert np.array_equal(final.data, outcomes[-1].post_state.data)
    assert_valid_density(final, 3)


def test_measure_qubits_perfect_correlation_on_bell_state() -> None:
    """Measuring both halves of |Phi+> in Z always yields equal eigenvalues."""
    rng = np.random.default_rng(606)
    for _ in range(30):
        outcomes, _ = measure_qubits(
            bell_state(BellState.PHI_PLUS),
            {0: PauliBasis.Z, 1: PauliBasis.Z},
            rng=rng,
        )
        assert outcomes[0].eigenvalue == outcomes[1].eigenvalue
        assert outcomes[0].probability == pytest.approx(0.5, abs=TOL)
        # The second measurement is certain: the first one already collapsed it.
        assert outcomes[1].probability == pytest.approx(1.0, abs=1e-12)


def test_measure_qubits_empty_mapping_is_a_no_op() -> None:
    """No bases means no measurement and the state comes back unchanged."""
    outcomes, final = measure_qubits(KET_01, {}, rng=np.random.default_rng(0))
    assert outcomes == []
    assert np.allclose(final.data, DensityMatrix(KET_01).data, atol=TOL)


def test_measure_qubits_matches_sequential_projective_measures() -> None:
    """It really is a thread of single-qubit collapses on one rng stream."""
    state = random_pure(3, np.random.default_rng(12))
    bases = {0: PauliBasis.X, 1: PauliBasis.Z, 2: PauliBasis.Y}

    rng_a = np.random.default_rng(555)
    outcomes, final = measure_qubits(state, bases, rng=rng_a)

    rng_b = np.random.default_rng(555)
    current: object = state
    manual = []
    for qubit in (0, 1, 2):
        step = projective_measure(current, qubit, bases[qubit], rng=rng_b)
        manual.append(step)
        current = step.post_state

    assert [o.eigenvalue for o in outcomes] == [o.eigenvalue for o in manual]
    assert np.allclose(final.data, manual[-1].post_state.data, atol=TOL)


def test_measure_qubits_rejects_bad_mapping() -> None:
    """Bad keys, bad values and non-mappings all fail loudly."""
    with pytest.raises(ValueError, match="basis key"):
        measure_qubits(KET_01, {5: PauliBasis.Z})
    with pytest.raises(ValueError, match="unknown measurement basis"):
        measure_qubits(KET_01, {0: "Q"})
    with pytest.raises(TypeError, match="mapping"):
        measure_qubits(KET_01, [(0, PauliBasis.Z)])  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# joint_probability                                                            #
# --------------------------------------------------------------------------- #


def test_joint_probability_is_the_product_not_the_mean() -> None:
    """The trap this helper exists to close, pinned numerically.

    On |Phi+> with {0: Z, 1: Z} the conditional probabilities are 0.5 and 1.0.
    Their product, 0.5, is the joint probability of the record; their mean,
    0.75, is neither that nor either qubit's marginal (both 0.5).  A Phase 4
    detector that averages instead of multiplying gets 0.75 and no error.
    """
    outcomes, _ = measure_qubits(
        bell_state(BellState.PHI_PLUS),
        {0: PauliBasis.Z, 1: PauliBasis.Z},
        rng=np.random.default_rng(20260141),
    )
    probabilities = [o.probability for o in outcomes]
    assert probabilities[0] == pytest.approx(0.5, abs=TOL)
    assert probabilities[1] == pytest.approx(1.0, abs=1e-12)

    assert joint_probability(outcomes) == pytest.approx(0.5, abs=TOL)
    assert joint_probability(outcomes) != pytest.approx(
        float(np.mean(probabilities)), abs=1e-3
    )


def test_joint_probability_matches_the_marginal_of_sample_counts() -> None:
    """The chain-rule product is the true joint probability, not a proxy.

    ``sample_counts`` computes the joint distribution directly and has no
    collapse, so its frequency for the realised bitstring must match the
    product of the conditional probabilities to sampling accuracy.
    """
    state = random_pure(3, np.random.default_rng(31))
    bases = {0: PauliBasis.X, 1: PauliBasis.Z, 2: PauliBasis.Y}
    outcomes, _ = measure_qubits(state, bases, rng=np.random.default_rng(99))

    # Key order is descending qubit index; outcomes are ascending.
    key = "".join(str(o.bit) for o in reversed(outcomes))
    shots = 400_000
    counts = sample_counts(state, bases, shots, rng=np.random.default_rng(4))
    frequency = counts.get(key, 0) / shots

    predicted = joint_probability(outcomes)
    assert predicted == pytest.approx(frequency, abs=4e-3)


def test_joint_probability_of_an_empty_record_is_one() -> None:
    """The empty conjunction is certain, which keeps loops composable."""
    outcomes, _ = measure_qubits(KET_01, {})
    assert joint_probability(outcomes) == 1.0
    assert joint_probability([]) == 1.0


def test_joint_probability_of_a_single_record_is_that_probability() -> None:
    outcome = projective_measure(
        KET_01, 1, PauliBasis.X, rng=np.random.default_rng(5)
    )
    assert joint_probability([outcome]) == pytest.approx(
        outcome.probability, abs=TOL
    )


def test_joint_probability_stays_in_the_unit_interval() -> None:
    """Repeated multiplication must not drift out of [0, 1]."""
    state = random_pure(3, np.random.default_rng(77))
    bases = {0: PauliBasis.X, 1: PauliBasis.Y, 2: PauliBasis.Z}
    rng = np.random.default_rng(303)
    for _ in range(20):
        outcomes, _ = measure_qubits(state, bases, rng=rng)
        value = joint_probability(outcomes)
        assert 0.0 <= value <= 1.0


def test_joint_probability_rejects_the_measure_qubits_tuple() -> None:
    """The expected mistake is passing the (outcomes, final_state) pair whole."""
    result = measure_qubits(KET_01, {0: PauliBasis.Z})
    with pytest.raises(TypeError, match="MeasurementOutcome"):
        joint_probability(result)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [0.5, None, {0: 0.5}, 7])
def test_joint_probability_rejects_non_records(bad: object) -> None:
    with pytest.raises(TypeError, match="MeasurementOutcome"):
        joint_probability(bad)  # type: ignore[arg-type]


def test_joint_probability_rejects_a_list_of_floats() -> None:
    """Raw probabilities are the other expected mistake."""
    with pytest.raises(TypeError, match="MeasurementOutcome"):
        joint_probability([0.5, 1.0])  # type: ignore[list-item]


# --------------------------------------------------------------------------- #
# sample_counts                                                                #
# --------------------------------------------------------------------------- #


def test_sample_counts_key_convention_is_little_endian() -> None:
    """|01> measured in Z on both qubits yields only the key ``"01"`` (D2).

    The key is the little-endian label itself: leftmost character is the highest
    measured qubit, rightmost is qubit 0, and bit 0 means eigenvalue +1.  A
    big-endian implementation would return ``"10"``.
    """
    counts = sample_counts(
        KET_01, {0: PauliBasis.Z, 1: PauliBasis.Z}, 500, rng=np.random.default_rng(0)
    )
    assert counts == {"01": 500}


def test_sample_counts_three_qubit_key_order() -> None:
    """On a 3-qubit basis state the key reproduces the little-endian label."""
    # |110>: q0 = 0, q1 = 1, q2 = 1 -> index 6.
    amplitudes = np.zeros(8, dtype=complex)
    amplitudes[6] = 1.0
    state = Statevector(amplitudes)
    counts = sample_counts(
        state,
        {0: PauliBasis.Z, 1: PauliBasis.Z, 2: PauliBasis.Z},
        64,
        rng=np.random.default_rng(1),
    )
    assert counts == {"110": 64}


def test_sample_counts_partial_measurement_marginalises_spectators() -> None:
    """Measuring a subset gives one character per measured qubit only."""
    amplitudes = np.zeros(8, dtype=complex)
    amplitudes[6] = 1.0  # |110>
    state = Statevector(amplitudes)

    only_q2 = sample_counts(state, {2: PauliBasis.Z}, 32, rng=np.random.default_rng(2))
    assert only_q2 == {"1": 32}

    only_q0 = sample_counts(state, {0: PauliBasis.Z}, 32, rng=np.random.default_rng(2))
    assert only_q0 == {"0": 32}

    q2_q0 = sample_counts(
        state, {0: PauliBasis.Z, 2: PauliBasis.Z}, 32, rng=np.random.default_rng(2)
    )
    # Descending measured-qubit order: q2 then q0.
    assert q2_q0 == {"10": 32}


def test_sample_counts_respects_the_measurement_basis() -> None:
    """|+> is certain in X, unbiased in Z."""
    plus = eigenstate(PauliBasis.X, 1)
    assert sample_counts(
        plus, {0: PauliBasis.X}, 200, rng=np.random.default_rng(3)
    ) == {"0": 200}

    minus = eigenstate(PauliBasis.X, -1)
    assert sample_counts(
        minus, {0: PauliBasis.X}, 200, rng=np.random.default_rng(3)
    ) == {"1": 200}

    plus_i = eigenstate(PauliBasis.Y, 1)
    assert sample_counts(
        plus_i, {0: PauliBasis.Y}, 200, rng=np.random.default_rng(3)
    ) == {"0": 200}


def test_sample_counts_bell_correlations() -> None:
    """|Phi+> is perfectly correlated in ZZ and in XX, uniform in ZX."""
    phi = bell_state(BellState.PHI_PLUS)
    shots = 20_000

    zz = sample_counts(
        phi, {0: PauliBasis.Z, 1: PauliBasis.Z}, shots, rng=np.random.default_rng(7)
    )
    assert set(zz) == {"00", "11"}
    assert sum(zz.values()) == shots

    xx = sample_counts(
        phi, {0: PauliBasis.X, 1: PauliBasis.X}, shots, rng=np.random.default_rng(7)
    )
    assert set(xx) == {"00", "11"}

    # <YY> = -1 for |Phi+>, so the bits must be *anti*-correlated.
    yy = sample_counts(
        phi, {0: PauliBasis.Y, 1: PauliBasis.Y}, shots, rng=np.random.default_rng(7)
    )
    assert set(yy) == {"01", "10"}

    zx = sample_counts(
        phi, {0: PauliBasis.X, 1: PauliBasis.Z}, shots, rng=np.random.default_rng(7)
    )
    assert set(zx) == {"00", "01", "10", "11"}
    for count in zx.values():
        assert abs(count / shots - 0.25) < 0.02


def test_sample_counts_frequencies_match_born_probabilities() -> None:
    """Empirical frequencies converge to Tr(rho P) for a biased qubit."""
    theta = math.pi / 7
    psi = Statevector(np.array([math.cos(theta), math.sin(theta)], dtype=complex))
    shots = 200_000
    counts = sample_counts(
        psi, {0: PauliBasis.Z}, shots, rng=np.random.default_rng(20260141)
    )
    assert sum(counts.values()) == shots
    p_plus, _ = born_probabilities(psi, 0, PauliBasis.Z)
    assert abs(counts["0"] / shots - p_plus) < 0.005


def test_sample_counts_handles_mixed_states() -> None:
    """The maximally mixed 2-qubit state is uniform over all four keys."""
    shots = 40_000
    counts = sample_counts(
        MAXMIX_2Q,
        {0: PauliBasis.Z, 1: PauliBasis.X},
        shots,
        rng=np.random.default_rng(17),
    )
    assert set(counts) == {"00", "01", "10", "11"}
    for count in counts.values():
        assert abs(count / shots - 0.25) < 0.02


def test_sample_counts_cost_is_independent_of_shots() -> None:
    """Two million shots must be effectively free.

    A regression guard on the implementation, not just its output: the
    distribution is built once and drawn from with a single multinomial, so this
    takes microseconds.  A per-shot loop of full 8x8 collapses -- the obvious
    wrong implementation -- would need minutes and blow the bound by orders of
    magnitude.  Phase 5's ROC sweep depends on this staying true.
    """
    state = random_pure(3, np.random.default_rng(88))
    bases = {0: PauliBasis.X, 1: PauliBasis.Y, 2: PauliBasis.Z}
    shots = 2_000_000
    start = time.perf_counter()
    counts = sample_counts(state, bases, shots, rng=np.random.default_rng(1))
    elapsed = time.perf_counter() - start
    assert sum(counts.values()) == shots
    assert elapsed < 2.0, f"sample_counts took {elapsed:.2f}s for {shots} shots"


def test_sample_counts_zero_shots() -> None:
    """Zero shots is legal and gives an empty histogram."""
    assert sample_counts(KET_01, {0: PauliBasis.Z}, 0) == {}


def test_sample_counts_is_deterministic_under_a_seed() -> None:
    """Same seed, identical histogram (D3)."""
    state = random_pure(3, np.random.default_rng(9))
    bases = {0: PauliBasis.X, 1: PauliBasis.Y, 2: PauliBasis.Z}
    first = sample_counts(state, bases, 5000, rng=np.random.default_rng(1234))
    second = sample_counts(state, bases, 5000, rng=np.random.default_rng(1234))
    assert first == second
    different = sample_counts(state, bases, 5000, rng=np.random.default_rng(4321))
    assert different != first


def test_sample_counts_rejects_bad_arguments() -> None:
    """Negative or non-integer shots raise.

    An empty basis mapping does *not*: see
    :func:`test_empty_bases_is_accepted_by_both_entry_points`.
    """
    with pytest.raises(ValueError, match="non-negative"):
        sample_counts(KET_01, {0: PauliBasis.Z}, -1)
    with pytest.raises(ValueError, match="non-negative integer"):
        sample_counts(KET_01, {0: PauliBasis.Z}, 10.0)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The empty basis map: measure_qubits and sample_counts must agree             #
# --------------------------------------------------------------------------- #


def test_empty_bases_is_accepted_by_both_entry_points() -> None:
    """A Phase 4 loop may build an empty basis map; neither call may blow up.

    The two entry points used to disagree -- ``measure_qubits`` returned an
    empty-but-valid result while ``sample_counts`` raised -- so which of them a
    caller happened to reach decided whether the run survived.  Both now return
    the degenerate result.
    """
    outcomes, final_state = measure_qubits(KET_01, {})
    assert outcomes == []
    assert isinstance(final_state, DensityMatrix)
    np.testing.assert_allclose(
        final_state.data, as_density(KET_01).data, atol=TOL
    )

    counts = sample_counts(KET_01, {}, 10)
    assert counts == {"": 10}, "measuring nothing yields the empty bitstring"
    assert sum(counts.values()) == 10, "the counts-sum-to-shots contract holds"


def test_empty_bases_with_zero_shots_gives_an_empty_histogram() -> None:
    """Zero-count outcomes are omitted, so this is ``{}``, not ``{"": 0}``."""
    assert sample_counts(KET_01, {}, 0) == {}


def test_empty_bases_consumes_no_randomness_in_measure_qubits() -> None:
    """Nothing measured, nothing drawn: the caller's stream must not advance."""
    rng = np.random.default_rng(20260141)
    measure_qubits(KET_01, {}, rng=rng)
    assert rng.random() == np.random.default_rng(20260141).random()


def test_empty_bases_accepts_a_mixed_state_too() -> None:
    """The degenerate path must not be pure-state-only."""
    mixed = DensityMatrix(np.eye(4, dtype=complex) / 4.0)
    outcomes, final_state = measure_qubits(mixed, {})
    assert outcomes == []
    np.testing.assert_allclose(final_state.data, mixed.data, atol=TOL)
    assert sample_counts(mixed, {}, 7) == {"": 7}


# --------------------------------------------------------------------------- #
# expectation                                                                  #
# --------------------------------------------------------------------------- #


def test_expectation_label_order_is_qiskit_endianness() -> None:
    """On |01>, ``"IZ"`` reads qubit 0 (-1) and ``"ZI"`` reads qubit 1 (+1).

    This is the D2 pin for Pauli strings: swapping the two characters flips the
    answer, so a big-endian reading is detected.
    """
    assert expectation(KET_01, "IZ") == pytest.approx(-1.0, abs=TOL)
    assert expectation(KET_01, "ZI") == pytest.approx(1.0, abs=TOL)
    assert expectation(KET_01, "ZZ") == pytest.approx(-1.0, abs=TOL)
    assert expectation(KET_01, "II") == pytest.approx(1.0, abs=TOL)
    assert expectation(KET_01, "IX") == pytest.approx(0.0, abs=TOL)


def test_expectation_bell_state_correlators() -> None:
    """The Bell-state signature: <XX>, <YY>, <ZZ> = (+1, -1, +1) for |Phi+>."""
    phi_plus = bell_state(BellState.PHI_PLUS)
    assert expectation(phi_plus, "XX") == pytest.approx(1.0, abs=TOL)
    assert expectation(phi_plus, "YY") == pytest.approx(-1.0, abs=TOL)
    assert expectation(phi_plus, "ZZ") == pytest.approx(1.0, abs=TOL)
    # Single-qubit marginals of a maximally entangled state are unbiased.
    for label in ("IX", "IY", "IZ", "XI", "YI", "ZI"):
        assert expectation(phi_plus, label) == pytest.approx(0.0, abs=TOL)

    psi_minus = bell_state(BellState.PSI_MINUS)
    for label in ("XX", "YY", "ZZ"):
        assert expectation(psi_minus, label) == pytest.approx(-1.0, abs=TOL)


def test_expectation_matches_born_probability_difference() -> None:
    """<sigma_q> = p_plus - p_minus, for pure and mixed states alike."""
    rng = np.random.default_rng(64)
    for _ in range(10):
        for state in (random_pure(3, rng), random_mixed(3, rng)):
            for qubit in range(3):
                for basis in ALL_BASES:
                    p_plus, p_minus = born_probabilities(state, qubit, basis)
                    label = pauli_label_for(qubit, basis, 3)
                    assert expectation(state, label) == pytest.approx(
                        p_plus - p_minus, abs=1e-10
                    )


def test_expectation_maximally_mixed_state() -> None:
    """I/4 has zero expectation for every non-identity Pauli string."""
    for label in ("IX", "XI", "XX", "YZ", "ZZ", "YY"):
        assert expectation(MAXMIX_2Q, label) == pytest.approx(0.0, abs=TOL)
    assert expectation(MAXMIX_2Q, "II") == pytest.approx(1.0, abs=TOL)


def test_expectation_is_case_insensitive() -> None:
    """Lowercase labels are accepted."""
    assert expectation(KET_01, "iz") == pytest.approx(-1.0, abs=TOL)


def test_expectation_rejects_bad_labels() -> None:
    """Wrong length, unknown characters and phase prefixes all raise."""
    with pytest.raises(ValueError, match="length"):
        expectation(KET_01, "Z")
    with pytest.raises(ValueError, match="'IXYZ'"):
        expectation(KET_01, "AB")
    with pytest.raises(ValueError, match="'IXYZ'"):
        expectation(KET_01, "-iXY")
    with pytest.raises(TypeError, match="must be a string"):
        expectation(KET_01, 3)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# bell_measure                                                                 #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("which", list(BellState))
def test_bell_measure_on_a_bell_state_is_deterministic(which: BellState) -> None:
    """A Bell state is an eigenstate of the Bell measurement."""
    expected = DensityMatrix(bell_state(which))
    for seed in range(6):
        outcome, post = bell_measure(
            bell_state(which), (0, 1), rng=np.random.default_rng(seed)
        )
        assert outcome is which
        assert np.allclose(post.data, expected.data, atol=TOL)
        assert_valid_density(post, 2)


@pytest.mark.parametrize("which", list(BellState))
def test_bell_measure_pair_order_only_changes_a_global_phase(
    which: BellState,
) -> None:
    """Swapping ``qubits`` cannot change the outcome or the density matrix.

    Only |Psi-> is antisymmetric under the exchange, and a sign on the branch is
    a global phase, which a density matrix does not carry.
    """
    forward, post_f = bell_measure(
        bell_state(which), (0, 1), rng=np.random.default_rng(5)
    )
    reverse, post_r = bell_measure(
        bell_state(which), (1, 0), rng=np.random.default_rng(5)
    )
    assert forward is reverse is which
    assert np.allclose(post_f.data, post_r.data, atol=TOL)


def test_bell_measure_on_a_product_state_hits_only_the_phi_branches() -> None:
    """|00> = (|Phi+> + |Phi->)/sqrt(2): the Psi outcomes have probability 0."""
    ket_00 = Statevector(np.array([1, 0, 0, 0], dtype=complex))
    rng = np.random.default_rng(21)
    seen: Counter[BellState] = Counter()
    for _ in range(300):
        outcome, post = bell_measure(ket_00, (0, 1), rng=rng)
        seen[outcome] += 1
        assert np.allclose(post.data, DensityMatrix(bell_state(outcome)).data, atol=TOL)
    assert set(seen) == {BellState.PHI_PLUS, BellState.PHI_MINUS}
    for count in seen.values():
        assert abs(count / 300 - 0.5) < 0.1


def test_bell_measure_leaves_spectator_in_the_conditional_state() -> None:
    """The teleportation identity, verified on a three-qubit register.

    With payload ``a|0> + b|1>`` on qubit 0 and |Phi+> on qubits 1 and 2,

        |psi>_0 (x) |Phi+>_12 = 1/2 [ |Phi+>(a|0> + b|1>)
                                    + |Psi+>(b|0> + a|1>)
                                    + |Phi->(a|0> - b|1>)
                                    + |Psi->(b|0> - a|1>) ]_2

    so each Bell outcome has probability 1/4 and the spectator qubit 2 is left
    in the corresponding conditional state.  This is exactly what
    ``sih141.core.teleport`` will consume, which is why it is tested on three
    qubits and not only on the measured pair.
    """
    a = 0.6 + 0.0j
    b = 0.0 + 0.8j
    payload = Statevector(np.array([a, b], dtype=complex))
    register = bell_state(BellState.PHI_PLUS).tensor(payload)
    assert register.num_qubits == 3
    # Sanity: qubit 0 really is the payload in this register.
    assert np.allclose(
        partial_trace(register, [1, 2]).data,
        DensityMatrix(payload).data,
        atol=TOL,
    )

    conditional = {
        BellState.PHI_PLUS: np.array([a, b], dtype=complex),
        BellState.PSI_PLUS: np.array([b, a], dtype=complex),
        BellState.PHI_MINUS: np.array([a, -b], dtype=complex),
        BellState.PSI_MINUS: np.array([b, -a], dtype=complex),
    }

    rng = np.random.default_rng(20260141)
    trials = 400
    seen: Counter[BellState] = Counter()
    for _ in range(trials):
        outcome, post = bell_measure(register, (0, 1), rng=rng)
        seen[outcome] += 1
        assert_valid_density(post, 3)

        # The spectator carries the conditional payload.
        spectator = partial_trace(post, [0, 1])
        expected = DensityMatrix(Statevector(conditional[outcome]))
        assert np.allclose(spectator.data, expected.data, atol=TOL)

        # The measured pair is left in the Bell state that was found.
        pair = partial_trace(post, [2])
        assert np.allclose(
            pair.data, DensityMatrix(bell_state(outcome)).data, atol=TOL
        )

    assert set(seen) == set(BELL_ORDER)
    for count in seen.values():
        assert abs(count / trials - 0.25) < 0.06


def test_bell_measure_outcome_index_matches_the_bell_order_correction() -> None:
    """``BELL_ORDER.index(outcome)`` really is the ``2*m1 + m0`` of the fixup.

    ``sih141.core.states`` documents that the receiver's correction is
    ``X**m0 @ Z**m1`` with ``2*m1 + m0 == BELL_ORDER.index(outcome)``.  Phase 1's
    teleportation module codes against that table, so it is checked here against
    the conditional states that :func:`bell_measure` actually produces, rather
    than assumed.
    """
    pauli_x = np.array([[0, 1], [1, 0]], dtype=complex)
    pauli_z = np.array([[1, 0], [0, -1]], dtype=complex)

    a, b = 0.6 + 0.0j, 0.0 + 0.8j
    payload = Statevector(np.array([a, b], dtype=complex))
    register = bell_state(BellState.PHI_PLUS).tensor(payload)
    expected_payload = DensityMatrix(payload).data

    rng = np.random.default_rng(4)
    seen: set[BellState] = set()
    while seen != set(BELL_ORDER):
        outcome, post = bell_measure(register, (0, 1), rng=rng)
        seen.add(outcome)
        index = BELL_ORDER.index(outcome)
        m0, m1 = index & 1, (index >> 1) & 1
        correction = np.linalg.matrix_power(pauli_x, m0) @ np.linalg.matrix_power(
            pauli_z, m1
        )
        conditional = np.asarray(partial_trace(post, [0, 1]).data)
        corrected = correction @ conditional @ correction.conj().T
        assert np.allclose(corrected, expected_payload, atol=TOL)


def test_bell_measure_on_non_adjacent_qubits() -> None:
    """The pair need not be adjacent: measure qubits 0 and 2, spectator is 1."""
    # |Psi+> across qubits (0, 2) with qubit 1 fixed to |1>.
    # index = q0 + 2*q1 + 4*q2 -> (q0=1, q1=1, q2=0) = 3 and (q0=0, q1=1, q2=1) = 6.
    amplitudes = np.zeros(8, dtype=complex)
    amplitudes[3] = SQRT1_2
    amplitudes[6] = SQRT1_2
    state = Statevector(amplitudes)

    for seed in range(5):
        outcome, post = bell_measure(state, (0, 2), rng=np.random.default_rng(seed))
        assert outcome is BellState.PSI_PLUS
        spectator = partial_trace(post, [0, 2])
        assert np.allclose(spectator.data, np.array([[0, 0], [0, 1]]), atol=TOL)
        assert np.allclose(post.data, DensityMatrix(state).data, atol=TOL)


def test_bell_measure_probabilities_sum_over_a_mixed_state() -> None:
    """The four projectors are complete: I/4 gives 1/4 each."""
    rng = np.random.default_rng(313)
    seen: Counter[BellState] = Counter()
    trials = 800
    for _ in range(trials):
        outcome, post = bell_measure(MAXMIX_2Q, (0, 1), rng=rng)
        seen[outcome] += 1
        assert_valid_density(post, 2)
    assert set(seen) == set(BELL_ORDER)
    for count in seen.values():
        assert abs(count / trials - 0.25) < 0.05


def test_bell_measure_is_deterministic_under_a_seed() -> None:
    """Same seed, same outcome and same collapsed state (D3)."""
    register = bell_state(BellState.PHI_PLUS).tensor(
        Statevector(np.array([0.6, 0.8], dtype=complex))
    )
    first = bell_measure(register, (0, 1), rng=np.random.default_rng(2718))
    second = bell_measure(register, (0, 1), rng=np.random.default_rng(2718))
    assert first[0] is second[0]
    assert np.array_equal(first[1].data, second[1].data)


def test_bell_measure_is_unchanged_by_swapping_the_measured_pair() -> None:
    """Pinning the corrected docstring: the pair order is a genuine no-op.

    The docstring used to claim the order mattered for the antisymmetric
    ``Psi-`` branch, "where swapping the pair would flip the sign".  It does flip
    the sign of the *vector*, but the projector is an outer product and erases
    it, so nothing observable changes: same outcome label, same collapsed state,
    bit for bit.  Asserted on an asymmetric three-qubit register with a
    non-adjacent pair, where a real ordering dependence would show up.
    """
    register = bell_state(BellState.PSI_MINUS).tensor(
        Statevector(np.array([0.6, 0.8], dtype=complex))
    )
    for pair in ((0, 1), (0, 2), (1, 2)):
        forward = bell_measure(register, pair, rng=np.random.default_rng(4242))
        reversed_pair = bell_measure(
            register, (pair[1], pair[0]), rng=np.random.default_rng(4242)
        )
        assert forward[0] is reversed_pair[0], f"outcome changed for {pair}"
        assert np.array_equal(forward[1].data, reversed_pair[1].data), (
            f"collapsed state changed for {pair}"
        )


def test_bell_measure_rejects_bad_arguments() -> None:
    """One qubit, a repeated index, a bad index and a non-pair all raise."""
    with pytest.raises(ValueError, match="at least two qubits"):
        bell_measure(eigenstate(PauliBasis.Z, 1))
    with pytest.raises(ValueError, match="distinct"):
        bell_measure(bell_state(), (1, 1))
    with pytest.raises(ValueError, match="qubits\\[1\\]"):
        bell_measure(bell_state(), (0, 5))
    with pytest.raises(ValueError, match="tuple of two"):
        bell_measure(bell_state(), (0, 1, 2))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Regression: numerical conditioning of the collapse, and tolerance coherence  #
#                                                                             #
# These tests exist because the suite was previously blind to the whole        #
# low-probability-branch policy: mutating _MIN_BRANCH_PROB from 1e-12 to 1e-3, #
# widening _PROB_TOL from 1e-9 to 1e-2, and replacing _select_branch's         #
# rounding-shortfall `return fallback` with `return 0` all left it green.      #
# Every assertion below kills at least one of those mutations.                 #
# --------------------------------------------------------------------------- #


class FixedDrawRng(np.random.Generator):
    """A real :class:`numpy.random.Generator` whose ``random()`` is pinned.

    ``resolve_rng`` accepts it (it genuinely *is* a ``Generator``), so a test can
    force :func:`_select_branch` down a chosen path -- including paths that
    honest sampling reaches with probability below 1e-8 and would therefore
    never exercise.
    """

    def __init__(self, draw: float) -> None:
        super().__init__(np.random.PCG64(0))
        self._draw = float(draw)

    def random(self, *args: object, **kwargs: object) -> float:  # type: ignore[override]
        """Return the pinned uniform variate."""
        return self._draw


def tilted_state(
    basis: PauliBasis, qubit: int, n_qubits: int, tilt: float, rng: np.random.Generator
) -> Statevector:
    """Build a pure state whose ``+1`` branch under ``basis`` has tiny weight.

    The state is, up to normalisation, the ``-1`` eigencomponent of a random
    vector plus ``tilt`` times its ``+1`` eigencomponent, so the ``+1`` Born
    probability is approximately ``tilt**2``.  This is exactly the regime in
    which ``P rho P`` is ill conditioned: the triple product's absolute
    round-off is of order eps while its true entries are of order ``p``, so
    renormalising inflates the noise to a relative error of order ``eps / p``.
    """
    vector = np.asarray(random_pure(n_qubits, rng).data, dtype=complex)
    proj_plus, proj_minus = _projectors(basis, qubit, n_qubits)
    plus_part = proj_plus @ vector
    minus_part = proj_minus @ vector
    combined = minus_part / np.linalg.norm(minus_part) + tilt * plus_part / np.linalg.norm(
        plus_part
    )
    return Statevector(combined / np.linalg.norm(combined))


def test_min_branch_prob_is_derived_from_epsilon_and_the_validation_tolerance() -> None:
    """The guard constant is derived, not hand-picked.

    ``P rho P`` carries absolute round-off of order float64 epsilon while its
    true entries are of order ``p``, so renormalising amplifies that to a
    relative error of order ``eps / p``.  Demanding that this stay inside the
    project's positive-semidefiniteness tolerance forces
    ``p >= eps / _VALIDATION_TOL``.  Pinning the identity here is what stops the
    constant drifting back to a value (such as the historical ``1e-12``) that
    admits branches whose collapsed state is not a density operator at all.
    """
    assert _MIN_BRANCH_PROB == float(np.finfo(np.float64).eps) / _VALIDATION_TOL
    assert 1e-8 < _MIN_BRANCH_PROB < 1e-7
    # Sanity on the physics the constant encodes: at the threshold the amplified
    # relative error is exactly the PSD tolerance.
    assert float(np.finfo(np.float64).eps) / _MIN_BRANCH_PROB == pytest.approx(
        _VALIDATION_TOL, rel=1e-12
    )


def test_prob_tol_is_not_tighter_than_the_canonical_state_validator() -> None:
    """Measurement must accept every state ``as_density`` accepts.

    ``as_density`` admits a trace deviation of up to ``_VALIDATION_TOL`` and does
    **not** renormalise, so a completeness tolerance tighter than that would
    reject states the project itself declares legal, and would blame "malformed
    projectors" for ordinary input drift.
    """
    assert _PROB_TOL == _VALIDATION_TOL


def test_measurement_accepts_every_state_the_validator_accepts() -> None:
    """Regression: trace drift inside ``as_density``'s tolerance must not raise.

    ``numpy.diag([0.7, 0.3]) * (1 + 5e-9)`` is Hermitian, positive semidefinite
    and trace-one to within ``_VALIDATION_TOL``, so ``as_density`` returns it
    unchanged (it validates, it does not renormalise).  Every measurement entry
    point must therefore accept it.  Before the fix each of them raised "Born
    probabilities do not sum to 1", because ``_PROB_TOL`` was 1e-9.
    """
    drift = 5e-9
    assert drift < _VALIDATION_TOL  # the canonical validator accepts this
    one_qubit = np.diag([0.7, 0.3]).astype(complex) * (1.0 + drift)
    two_qubit = np.eye(4, dtype=complex) / 4.0 * (1.0 + drift)
    assert isinstance(as_density(one_qubit), DensityMatrix)
    assert isinstance(as_density(two_qubit), DensityMatrix)

    p_plus, p_minus = born_probabilities(one_qubit, 0, PauliBasis.Z)
    # The drift is divided out rather than propagated: the pair sums to exactly
    # 1 and the values are the drift-free ones.
    assert p_plus + p_minus == 1.0
    assert p_plus == pytest.approx(0.7, abs=1e-12)

    outcome = projective_measure(
        one_qubit, 0, PauliBasis.Z, rng=np.random.default_rng(0)
    )
    assert_valid_density(outcome.post_state, 1)
    assert expectation(one_qubit, "Z") == pytest.approx(0.4, abs=1e-8)
    counts = sample_counts(
        one_qubit, {0: PauliBasis.Z}, 100, rng=np.random.default_rng(0)
    )
    assert sum(counts.values()) == 100
    which, post = bell_measure(two_qubit, (0, 1), rng=np.random.default_rng(0))
    assert which in BELL_ORDER
    assert_valid_density(post, 2)


def test_collapse_of_a_low_probability_branch_is_still_a_valid_state() -> None:
    """The realised ``post_state`` is a density operator however small ``p`` is.

    Regression for the defect that motivated the derived guard: a branch of
    probability just above the old 1e-12 threshold came back with a smallest
    eigenvalue near -1.8e-7, seventeen times worse than the project's own -1e-8
    tolerance, so ``as_density`` rejected it and it could not be fed back into
    any other function in this module.  ``_collapse`` now projects the spectrum
    onto the positive semidefinite cone, so the guarantee holds by construction.
    """
    rng = np.random.default_rng(20260141)
    checked = 0
    for _ in range(8):
        for qubit in range(3):
            for basis in ALL_BASES:
                for tilt in (1e-3, 3e-4, 1e-4):
                    state = tilted_state(basis, qubit, 3, tilt, rng)
                    p_plus, _ = born_probabilities(state, qubit, basis)
                    if not _MIN_BRANCH_PROB < p_plus < 1e-4:
                        continue
                    proj_plus, _ = _projectors(basis, qubit, 3)
                    rho = np.asarray(DensityMatrix(state).data, dtype=complex)
                    collapsed = _collapse(rho, proj_plus, p_plus)
                    # The strong claim: accepted by the canonical validator.
                    as_density(collapsed)
                    assert_valid_density(DensityMatrix(collapsed), 3)
                    # And it really is the projected state, not a repaired mess:
                    # it lies inside the +1 eigenspace.
                    assert np.allclose(
                        proj_plus @ collapsed @ proj_plus, collapsed, atol=1e-9
                    )
                    checked += 1
    assert checked >= 20, f"the low-probability regime was never reached ({checked})"


def test_collapse_rejects_a_branch_at_or_below_the_guard() -> None:
    """``_collapse`` refuses exactly the branches ``_select_branch`` refuses.

    The two constants must agree, or a branch could be selected and then fail to
    collapse.
    """
    rho = np.asarray(DensityMatrix(KET_01).data, dtype=complex)
    proj_plus, _ = _projectors(PauliBasis.Z, 0, 2)
    with pytest.raises(ValueError, match="cannot renormalise"):
        _collapse(rho, proj_plus, _MIN_BRANCH_PROB)
    with pytest.raises(ValueError, match="cannot renormalise"):
        _collapse(rho, proj_plus, _MIN_BRANCH_PROB / 2.0)


def test_a_branch_above_the_guard_is_reachable_by_the_sampler() -> None:
    """A branch of probability around 1e-4 must still be selectable.

    This is the behavioural bound on ``_MIN_BRANCH_PROB`` from above: raising it
    to, say, 1e-3 would make the sampler silently unable to ever report an
    outcome of probability below 0.1%, which is a real change to the modelled
    physics rather than a numerical detail.
    """
    rng = np.random.default_rng(31415)
    state = tilted_state(PauliBasis.Z, 0, 1, 1e-2, rng)
    p_plus, _ = born_probabilities(state, 0, PauliBasis.Z)
    assert 1e-5 < p_plus < 1e-3, p_plus

    # Force the low branch with a draw of exactly 0: inverse-CDF sampling must
    # land on branch 0, because it is above the guard.
    outcome = projective_measure(state, 0, PauliBasis.Z, rng=FixedDrawRng(0.0))
    assert outcome.eigenvalue == 1
    assert outcome.probability == pytest.approx(p_plus, rel=1e-12)
    assert_valid_density(outcome.post_state, 1)

    # ...and it is genuinely rare under honest sampling.
    hits = sum(
        projective_measure(state, 0, PauliBasis.Z, rng=rng).eigenvalue == 1
        for _ in range(2000)
    )
    assert hits == 0


def test_a_branch_below_the_guard_is_never_selected() -> None:
    """Sub-threshold branches are skipped even when the draw points at them."""
    rng = np.random.default_rng(2718)
    state = tilted_state(PauliBasis.Z, 0, 1, 1e-6, rng)
    p_plus, _ = born_probabilities(state, 0, PauliBasis.Z)
    assert p_plus < _MIN_BRANCH_PROB, p_plus
    for draw in (0.0, 1e-15, 0.5):
        outcome = projective_measure(state, 0, PauliBasis.Z, rng=FixedDrawRng(draw))
        assert outcome.eigenvalue == -1
        assert_valid_density(outcome.post_state, 1)


@pytest.mark.parametrize(
    ("probabilities", "expected"),
    [
        # A draw of 1.0 can never be strictly below a cumulative sum that tops
        # out at 1.0, so the rounding-shortfall fallback fires.  It must return
        # the LAST viable branch, not branch 0.
        ((0.5, 0.5), 1),
        ((0.25, 0.25, 0.25, 0.25), 3),
        # A trailing sub-threshold branch is not viable, so the fallback is the
        # last branch that is.
        ((0.5, 0.5, 0.0), 1),
        ((0.5, 0.5, _MIN_BRANCH_PROB / 10.0), 1),
        # A leading sub-threshold branch is skipped rather than returned.
        ((0.0, 1.0), 1),
    ],
)
def test_select_branch_rounding_fallback_is_the_last_viable_branch(
    probabilities: tuple[float, ...], expected: int
) -> None:
    """The cumulative sum can fall a few ULPs short of the draw.

    When it does, the rounding-safe choice is the last branch that was actually
    viable.  Returning branch 0 instead would bias the sampler towards the first
    listed outcome by the size of the shortfall, and could return a branch below
    the guard, which then cannot be collapsed at all.
    """
    assert _select_branch(probabilities, FixedDrawRng(1.0)) == expected


def test_select_branch_raises_when_no_branch_is_viable() -> None:
    """An all-negligible distribution is a projector bug, and says so."""
    with pytest.raises(ValueError, match="non-negligible"):
        _select_branch((0.0, 0.0), FixedDrawRng(0.5))


def test_collapse_rejects_a_genuinely_non_positive_input() -> None:
    """PSD repair is a round-off eraser, not a bug eraser.

    Clipping the spectrum must not turn a non-physical input into a
    plausible-looking state: a matrix carrying O(1) negative mass is rejected
    rather than quietly repaired.
    """
    bad = np.diag([1.5, -0.5]).astype(complex)
    identity = np.eye(2, dtype=complex)
    with pytest.raises(ValueError, match="not positive semidefinite"):
        _collapse(bad, identity, 1.0)


def test_collapse_repairs_round_off_negativity_it_is_handed() -> None:
    """The collapse never propagates negativity that ``as_density`` let through.

    ``as_density`` accepts a smallest eigenvalue down to ``-_VALIDATION_TOL``
    (1e-8), so a state carrying round-off-scale negativity is legal input to
    every function in this module.  ``_collapse`` must not pass that negativity
    on -- and must not amplify it -- because its own contract promises a valid
    density operator and its output is fed straight back into ``as_density`` by
    the next call.  Clipping the spectrum makes the output positive
    semidefinite to machine precision, which is strictly stronger than what the
    input guaranteed.
    """
    negativity = 5e-9
    assert negativity < _VALIDATION_TOL  # legal input by the project's own rule
    rho = np.diag([1.0 + negativity, -negativity]).astype(complex)
    as_density(rho)  # precondition: the canonical validator accepts it
    assert float(np.linalg.eigvalsh(rho)[0]) == pytest.approx(-negativity, rel=1e-9)

    collapsed = _collapse(rho, np.eye(2, dtype=complex), 1.0)
    smallest = float(np.linalg.eigvalsh(0.5 * (collapsed + collapsed.conj().T))[0])
    assert smallest >= -1e-14, smallest
    assert complex(np.trace(collapsed)).real == pytest.approx(1.0, abs=1e-14)
    # The repair moves only the noise: the physical part is untouched.
    assert collapsed[0, 0].real == pytest.approx(1.0, abs=1e-8)
