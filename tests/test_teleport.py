"""Tests for :mod:`sih141.core.teleport`.

Value assertions, not smoke tests.  Teleportation is the centrepiece of the
problem statement, so the properties later phases will silently depend on are
pinned numerically here:

* the Bell-outcome -> Pauli-correction table, checked against the **hand-derived
  conditional states** for a generic complex payload (not :math:`|0\\rangle`,
  which is symmetric enough to pass with a wrong table),
* the little-endian register layout (D2): the payload really is on qubit 0 and
  the receiver really is qubit 2, pinned with an *asymmetric* payload and an
  asymmetric product state, both of which a big-endian implementation gets
  demonstrably wrong,
* fidelity exactly ``1`` for **all four** Bell outcomes and for random seeded
  payloads,
* the noisy-resource line: a maximally mixed pair gives exactly ``0.5`` and the
  Werner family gives exactly :math:`1 - p/2`, monotonically decreasing.  Phase
  3's channel attacks are calibrated against this, so it is asserted to ``1e-9``
  rather than as a vague "fidelity drops",
* determinism under a seeded generator (D3),
* that :func:`teleport_circuit` is the same protocol, verified end to end on a
  simulator by un-preparing the payload on the receiver's qubit.

Post-audit additions
--------------------
The Phase 1 adversarial audit found the physics sound but the *API* too narrow
in two ways that would have blocked Phase 3, so three further properties are
pinned here:

* :func:`~sih141.core.teleport.teleport_in_register` moves a qubit that is
  **entangled with a reference** and the entanglement survives -- concurrence
  still exactly ``1`` afterwards, and the joint state is the original one, not
  merely an equally entangled one,
* :func:`~sih141.core.teleport.teleport` accepts a **mixed** payload (noise on
  the forward payload line, and multi-hop relaying, which the old
  "degrade the resource instead" advice does not model), with the fidelity
  measured against what was actually submitted,
* :func:`~sih141.core.teleport.teleport_channel` reproduces the sampled
  behaviour **analytically**, checked through the Choi matrix against the two
  fixed points (identity and completely depolarising) and against Monte-Carlo
  runs on four non-trivial resources.
"""

from __future__ import annotations

import dataclasses
from collections import Counter

import numpy as np
import pytest
from qiskit.quantum_info import (
    Choi,
    DensityMatrix,
    Kraus,
    Operator,
    Statevector,
    SuperOp,
    partial_trace,
)

from sih141.core.states import (
    BELL_ORDER,
    BellState,
    as_density,
    bell_state,
    concurrence,
    fidelity,
    purity,
)
from sih141.core.teleport import (
    RegisterTeleportationResult,
    TeleportationResult,
    _teleport_core,
    correction_bits,
    pauli_correction,
    teleport,
    teleport_channel,
    teleport_circuit,
    teleport_in_register,
)

TOL = 1e-9

PAULI_I = np.eye(2, dtype=complex)
PAULI_X = np.array([[0, 1], [1, 0]], dtype=complex)
PAULI_Y = np.array([[0, -1j], [1j, 0]], dtype=complex)
PAULI_Z = np.array([[1, 0], [0, -1]], dtype=complex)

#: A deliberately generic payload: both amplitudes non-zero, unequal in
#: magnitude, and one of them imaginary.  |0> or |+> would be invariant under
#: some of the four corrections and so could not distinguish a wrong table.
GENERIC_A = 0.6 + 0.0j
GENERIC_B = 0.0 + 0.8j
GENERIC_PAYLOAD = Statevector(np.array([GENERIC_A, GENERIC_B], dtype=complex))

MAXMIX_2Q = DensityMatrix(np.eye(4, dtype=complex) / 4.0)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def random_qubit(rng: np.random.Generator) -> Statevector:
    """Draw a Haar-ish random single-qubit pure state from an explicit rng (D3)."""
    vec = rng.normal(size=2) + 1j * rng.normal(size=2)
    return Statevector(vec / np.linalg.norm(vec))


def werner(p: float) -> DensityMatrix:
    """Return the Werner state ``(1 - p)|Phi+><Phi+| + p I/4``.

    ``p = 0`` is the pristine resource, ``p = 1`` the maximally mixed one.
    """
    phi = np.asarray(as_density(bell_state(BellState.PHI_PLUS)).data, dtype=complex)
    return DensityMatrix((1.0 - p) * phi + p * np.eye(4, dtype=complex) / 4.0)


def mixed_qubit(target_purity: float, *, rotate: bool = True) -> DensityMatrix:
    """Return a one-qubit state of exactly ``target_purity``.

    ``rho = diag(a, 1 - a)`` has ``Tr(rho^2) = 2a^2 - 2a + 1``, so a chosen
    purity is reached at ``a = (1 + sqrt(2 * purity - 1)) / 2``.  The state is
    then conjugated by a Hadamard unless ``rotate=False``, so that it is not
    diagonal in the computational basis: a diagonal payload is invariant under
    the ``Z`` correction and so could not distinguish a wrong table.
    """
    weight = (1.0 + np.sqrt(2.0 * target_purity - 1.0)) / 2.0
    rho = np.diag([weight, 1.0 - weight]).astype(complex)
    if rotate:
        hadamard = np.array([[1.0, 1.0], [1.0, -1.0]], dtype=complex) / np.sqrt(2.0)
        rho = hadamard @ rho @ hadamard.conj().T
    return DensityMatrix(rho)


def amplitude_damped_resource(gamma: float) -> DensityMatrix:
    """Return ``|Phi+>`` with amplitude damping of strength ``gamma`` on qubit 1.

    Unlike the Werner family this resource is **not** locally maximally mixed:
    its reduced state on the receiver's qubit is
    ``diag((1 + gamma)/2, (1 - gamma)/2)``, not ``I/2``.  That is exactly the
    family the old ``teleport`` docstring got wrong.  Its Bell-basis diagonal is
    also lopsided and non-degenerate, which takes ``teleport_channel`` well off
    the depolarising line.
    """
    kraus_0 = np.array([[1.0, 0.0], [0.0, np.sqrt(1.0 - gamma)]], dtype=complex)
    kraus_1 = np.array([[0.0, np.sqrt(gamma)], [0.0, 0.0]], dtype=complex)
    phi = np.asarray(as_density(bell_state(BellState.PHI_PLUS)).data, dtype=complex)
    total = np.zeros((4, 4), dtype=complex)
    for kraus in (kraus_0, kraus_1):
        # Qubit 1 is the receiver's half; little-endian embedding is kron(K, I).
        embedded = np.kron(kraus, PAULI_I)
        total += embedded @ phi @ embedded.conj().T
    return DensityMatrix(total)


def assert_valid_qubit_density(rho: DensityMatrix) -> None:
    """Assert a one-qubit density matrix is Hermitian, unit trace and PSD."""
    data = np.asarray(rho.data)
    assert data.shape == (2, 2)
    assert rho.num_qubits == 1
    assert np.allclose(data, data.conj().T, atol=TOL)
    assert abs(complex(np.trace(data)) - 1.0) < TOL
    assert float(np.linalg.eigvalsh(data)[0]) > -TOL


# --------------------------------------------------------------------------- #
# The correction table, derived rather than recalled                           #
# --------------------------------------------------------------------------- #


def test_correction_bits_are_the_bell_order_index() -> None:
    """``2*m1 + m0 == BELL_ORDER.index(outcome)`` for all four outcomes."""
    expected = {
        BellState.PHI_PLUS: (0, 0),
        BellState.PSI_PLUS: (1, 0),
        BellState.PHI_MINUS: (0, 1),
        BellState.PSI_MINUS: (1, 1),
    }
    for outcome, bits in expected.items():
        assert correction_bits(outcome) == bits
        m0, m1 = bits
        assert 2 * m1 + m0 == BELL_ORDER.index(outcome)

    # All four bit patterns occur exactly once: the message is two full bits.
    assert sorted(correction_bits(b) for b in BELL_ORDER) == [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
    ]


def test_pauli_correction_matrices_are_the_derived_table() -> None:
    """Explicit hand-written matrices, compared entry by entry."""
    expected = {
        BellState.PHI_PLUS: PAULI_I,
        BellState.PSI_PLUS: PAULI_X,
        BellState.PHI_MINUS: PAULI_Z,
        BellState.PSI_MINUS: PAULI_X @ PAULI_Z,
    }
    for outcome, matrix in expected.items():
        assert np.allclose(pauli_correction(outcome), matrix, atol=1e-15)

    # X @ Z, written out, is [[0, -1], [1, 0]] -- NOT [[0, 1], [-1, 0]], which is
    # Z @ X and differs by the global sign that would break an exact comparison.
    assert np.allclose(
        pauli_correction(BellState.PSI_MINUS),
        np.array([[0, -1], [1, 0]], dtype=complex),
        atol=1e-15,
    )


def test_pauli_correction_matrices_are_unitary() -> None:
    """Every correction is unitary, so ``U rho U^dagger`` stays a state."""
    for outcome in BELL_ORDER:
        u = pauli_correction(outcome)
        assert np.allclose(u @ u.conj().T, PAULI_I, atol=1e-15)


def test_pauli_correction_returns_a_private_copy() -> None:
    """Mutating a returned matrix must not corrupt the shared table."""
    first = pauli_correction(BellState.PHI_PLUS)
    first[0, 0] = 99.0
    assert np.allclose(pauli_correction(BellState.PHI_PLUS), PAULI_I, atol=1e-15)


def test_pauli_correction_inverts_the_hand_derived_conditional_states() -> None:
    """The algebraic core: invert each branch of the teleportation identity.

    From the module docstring, for payload ``a|0> + b|1>`` and resource |Phi+>,

        |psi>_0 (x) |Phi+>_12 = 1/2 [ |Phi+>(a|0> + b|1>)
                                    + |Psi+>(b|0> + a|1>)
                                    + |Phi->(a|0> - b|1>)
                                    + |Psi->(b|0> - a|1>) ]_2

    so applying ``pauli_correction(outcome)`` to the corresponding conditional
    vector must give back ``(a, b)`` exactly -- including global phase, not
    merely up to it.
    """
    a, b = GENERIC_A, GENERIC_B
    conditional = {
        BellState.PHI_PLUS: np.array([a, b], dtype=complex),
        BellState.PSI_PLUS: np.array([b, a], dtype=complex),
        BellState.PHI_MINUS: np.array([a, -b], dtype=complex),
        BellState.PSI_MINUS: np.array([b, -a], dtype=complex),
    }
    payload = np.array([a, b], dtype=complex)
    for outcome, vector in conditional.items():
        recovered = pauli_correction(outcome) @ vector
        assert np.allclose(recovered, payload, atol=1e-14), outcome

    # The generic payload is genuinely generic: no correction other than the
    # right one recovers it, so the test could not pass with a shuffled table.
    for outcome, vector in conditional.items():
        for other in BELL_ORDER:
            if other is outcome:
                continue
            assert not np.allclose(
                pauli_correction(other) @ vector, payload, atol=1e-6
            ), (outcome, other)


def test_correction_table_rejects_non_bellstate_input() -> None:
    """Strings are not coerced: a typo must not select the wrong correction."""
    with pytest.raises(ValueError, match="BellState member"):
        pauli_correction("Phi+")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="BellState member"):
        correction_bits(0)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Register layout: the endianness pin (D2)                                     #
# --------------------------------------------------------------------------- #


def test_register_layout_puts_the_payload_on_qubit_zero() -> None:
    """``resource.tensor(payload)`` is little-endian: payload on qubit 0.

    Pinned with an asymmetric payload, so a big-endian construction (payload on
    qubit 2) fails loudly rather than passing by symmetry.
    """
    resource = as_density(bell_state(BellState.PHI_PLUS))
    register = resource.tensor(DensityMatrix(GENERIC_PAYLOAD))
    assert register.num_qubits == 3

    # Qubit 0 is the payload...
    assert np.allclose(
        partial_trace(register, [1, 2]).data,
        DensityMatrix(GENERIC_PAYLOAD).data,
        atol=TOL,
    )
    # ...and qubit 2 is the receiver's half of the pair, maximally mixed before
    # the protocol runs.  |0.6|^2 = 0.36 != 0.5, so these two are distinguishable.
    assert np.allclose(
        partial_trace(register, [0, 1]).data, np.eye(2) / 2.0, atol=TOL
    )
    # Qubits 1 and 2 still carry the full entanglement.
    assert concurrence(partial_trace(register, [0])) == pytest.approx(1.0, abs=TOL)


def test_register_layout_pinned_with_an_asymmetric_product_resource() -> None:
    """A second endianness pin using an asymmetric (unentangled) resource.

    With resource ``|10>`` (qubit 1 of the *pair* is |1>, its qubit 0 is |0>),
    the three-qubit register must be ``|1>_2 |0>_1 |psi>_0``, i.e. amplitude
    index ``4 + 0 + payload bit``.  A big-endian tensor would place the |1> on
    qubit 0.
    """
    resource = Statevector(np.array([0, 0, 1, 0], dtype=complex))  # |10>
    payload = Statevector(np.array([GENERIC_A, GENERIC_B], dtype=complex))
    register = as_density(resource).tensor(DensityMatrix(payload))
    diagonal = np.real(np.diag(np.asarray(register.data)))
    expected = np.zeros(8)
    expected[4] = abs(GENERIC_A) ** 2  # q2=1, q1=0, q0=0
    expected[5] = abs(GENERIC_B) ** 2  # q2=1, q1=0, q0=1
    assert np.allclose(diagonal, expected, atol=TOL)


# --------------------------------------------------------------------------- #
# Perfect teleportation                                                        #
# --------------------------------------------------------------------------- #


def test_teleport_is_exact_for_all_four_bell_outcomes() -> None:
    """Fidelity 1 for every branch, each forced by exhausting a seeded stream.

    All four outcomes are equiprobable, so a seeded run reaches every branch;
    the loop asserts on each one as it appears and then checks that all four
    were in fact visited (otherwise a broken branch could be skipped silently).
    """
    rng = np.random.default_rng(20260141)
    seen: dict[BellState, TeleportationResult] = {}
    for _ in range(400):
        result = teleport(GENERIC_PAYLOAD, rng=rng)
        seen.setdefault(result.bell_outcome, result)

        assert result.fidelity == pytest.approx(1.0, abs=TOL)
        assert result.classical_bits == correction_bits(result.bell_outcome)
        assert_valid_qubit_density(result.received)
        assert purity(result.received) == pytest.approx(1.0, abs=TOL)
        # The received state equals the payload as an operator, not just in
        # fidelity: the correction leaves no residual phase.
        assert np.allclose(
            result.received.data,
            DensityMatrix(GENERIC_PAYLOAD).data,
            atol=TOL,
        )
        assert np.allclose(result.payload.data, GENERIC_PAYLOAD.data, atol=TOL)

    assert set(seen) == set(BELL_ORDER)


def test_teleport_bell_outcomes_are_equiprobable() -> None:
    """Each outcome occurs with probability 1/4 -- the bits leak nothing.

    This is the information-theoretic security statement: the sender's two
    classical bits are uniform regardless of the payload, so an eavesdropper who
    reads them learns nothing about ``(a, b)``.
    """
    rng = np.random.default_rng(7)
    trials = 1200
    seen: Counter[BellState] = Counter()
    for _ in range(trials):
        seen[teleport(GENERIC_PAYLOAD, rng=rng).bell_outcome] += 1
    assert set(seen) == set(BELL_ORDER)
    for count in seen.values():
        assert abs(count / trials - 0.25) < 0.04


def test_teleport_is_exact_for_random_seeded_payloads() -> None:
    """Random payloads from a seeded generator all arrive with fidelity 1."""
    rng = np.random.default_rng(31337)
    outcomes: set[BellState] = set()
    for _ in range(60):
        payload = random_qubit(rng)
        result = teleport(payload, rng=rng)
        outcomes.add(result.bell_outcome)
        assert result.fidelity == pytest.approx(1.0, abs=TOL)
        assert np.allclose(
            result.received.data, DensityMatrix(payload).data, atol=TOL
        )
    assert outcomes == set(BELL_ORDER)


def test_teleport_accepts_a_pure_density_matrix_payload() -> None:
    """D1: a state argument may be a DensityMatrix as well as a Statevector."""
    result = teleport(
        DensityMatrix(GENERIC_PAYLOAD), rng=np.random.default_rng(5)
    )
    assert result.fidelity == pytest.approx(1.0, abs=TOL)
    # The extracted statevector matches up to global phase (eigh fixes no phase),
    # so compare as operators.
    assert np.allclose(
        DensityMatrix(result.payload).data,
        DensityMatrix(GENERIC_PAYLOAD).data,
        atol=TOL,
    )


def test_teleport_works_without_an_explicit_rng() -> None:
    """``rng=None`` is the documented fresh-entropy path, not a bug."""
    for _ in range(20):
        assert teleport(GENERIC_PAYLOAD).fidelity == pytest.approx(1.0, abs=TOL)


def test_teleport_accepts_an_explicit_phi_plus_resource() -> None:
    """Passing |Phi+> explicitly matches the default."""
    for resource in (bell_state(BellState.PHI_PLUS), as_density(bell_state())):
        result = teleport(
            GENERIC_PAYLOAD, resource=resource, rng=np.random.default_rng(2)
        )
        assert result.fidelity == pytest.approx(1.0, abs=TOL)


# --------------------------------------------------------------------------- #
# Degraded resources -- the behaviour Phase 3 depends on                       #
# --------------------------------------------------------------------------- #


def test_teleport_with_maximally_mixed_resource_gives_one_half() -> None:
    """A maximally mixed pair carries no entanglement: fidelity is exactly 1/2.

    ``I/4`` is uncorrelated, so the receiver's qubit is ``I/2`` whatever the
    payload and whatever the Bell outcome, giving
    ``F = <psi| I/2 |psi> = 1/2`` -- the classical measure-and-prepare floor.
    """
    rng = np.random.default_rng(101)
    seen: set[BellState] = set()
    for _ in range(80):
        payload = random_qubit(rng)
        result = teleport(payload, resource=MAXMIX_2Q, rng=rng)
        seen.add(result.bell_outcome)
        assert result.fidelity == pytest.approx(0.5, abs=TOL)
        assert np.allclose(result.received.data, np.eye(2) / 2.0, atol=TOL)
        assert purity(result.received) == pytest.approx(0.5, abs=TOL)
    assert seen == set(BELL_ORDER)


@pytest.mark.parametrize(
    "p", [0.0, 0.1, 0.25, 0.4, 0.5, 0.6, 0.75, 0.9, 1.0]
)
def test_werner_resource_gives_exactly_one_minus_half_p(p: float) -> None:
    """The calibration line ``F(p) = 1 - p/2`` for the Werner family.

    Linearity of the protocol in the resource gives a corrected receiver state
    ``(1 - p)|psi><psi| + p I/2``, hence ``F = (1 - p) + p/2``.  Phase 3's
    depolarising channel is calibrated against this exact number, so it is
    asserted to 1e-9 rather than as a loose inequality.
    """
    rng = np.random.default_rng(2026 + int(p * 100))
    resource = werner(p)
    for _ in range(12):
        payload = random_qubit(rng)
        result = teleport(payload, resource=resource, rng=rng)
        assert result.fidelity == pytest.approx(1.0 - p / 2.0, abs=TOL)
        assert_valid_qubit_density(result.received)


def test_werner_fidelity_decreases_monotonically_with_noise() -> None:
    """Strictly decreasing in the noise parameter, for a fixed payload and seed.

    Monotonicity is the property the Phase 4 detector's threshold rests on: more
    channel noise must never look *less* suspicious.
    """
    noise = [0.0, 0.05, 0.15, 0.3, 0.45, 0.6, 0.8, 1.0]
    fidelities = [
        teleport(
            GENERIC_PAYLOAD,
            resource=werner(p),
            rng=np.random.default_rng(20260141),
        ).fidelity
        for p in noise
    ]
    assert fidelities[0] == pytest.approx(1.0, abs=TOL)
    assert fidelities[-1] == pytest.approx(0.5, abs=TOL)
    for earlier, later in zip(fidelities, fidelities[1:]):
        assert later < earlier - 1e-6
    assert all(
        f == pytest.approx(1.0 - p / 2.0, abs=TOL)
        for f, p in zip(fidelities, noise)
    )


def test_werner_resource_intermediate_state_is_the_expected_mixture() -> None:
    """The received state itself, not just its fidelity, is ``(1-p)psi + p I/2``."""
    p = 0.3
    result = teleport(
        GENERIC_PAYLOAD, resource=werner(p), rng=np.random.default_rng(99)
    )
    expected = (1.0 - p) * np.asarray(
        DensityMatrix(GENERIC_PAYLOAD).data
    ) + p * np.eye(2) / 2.0
    assert np.allclose(result.received.data, expected, atol=TOL)
    assert 0.5 < result.fidelity < 1.0


def test_wrong_bell_resource_is_not_corrected_by_the_standard_table() -> None:
    """A substituted resource breaks teleportation -- a Phase 3 attack model.

    The correction table is derived for |Phi+>.  If an adversary swaps the pair
    for another Bell state, the receiver applies the wrong Pauli and ends up
    with ``P|psi>`` for some Pauli ``P``, so the fidelity drops to
    ``|<psi|P|psi>|^2 < 1``.  The state is still *pure* -- an entanglement or
    purity witness alone would not see this, which is why Phase 4 needs the
    fidelity as well.
    """
    expected = {
        # |<psi|X|psi>|^2 with (a, b) = (0.6, 0.8i): the overlap vanishes.
        BellState.PSI_PLUS: 0.0,
        # |<psi|Z|psi>|^2 = (|a|^2 - |b|^2)^2 = (0.36 - 0.64)^2.
        BellState.PHI_MINUS: (0.36 - 0.64) ** 2,
        # |<psi|Y|psi>|^2 = 0.96^2.
        BellState.PSI_MINUS: 0.96**2,
    }
    for which, value in expected.items():
        result = teleport(
            GENERIC_PAYLOAD,
            resource=bell_state(which),
            rng=np.random.default_rng(17),
        )
        assert result.fidelity == pytest.approx(value, abs=1e-9)
        assert result.fidelity < 1.0 - 1e-6
        assert purity(result.received) == pytest.approx(1.0, abs=TOL)


def test_separable_resource_degenerates_to_measure_and_prepare() -> None:
    """A product pair |00> reduces the protocol to a classical strategy.

    Without entanglement the receiver's qubit stays in |0> and the correction
    can only leave it in |0> or |1> -- **two fixed states, independent of the
    payload**.  With the pair in |0>_1 the Bell measurement is just a Z
    measurement of the payload in disguise: for ``psi = a|0> + b|1>`` the
    outcomes ``Phi+/Phi-`` occur with total probability ``|a|^2`` and deliver
    |0>, while ``Psi+/Psi-`` occur with probability ``|b|^2`` and deliver |1>.
    So the per-run fidelity is ``|a|^2`` or ``|b|^2``, and the mean over runs is
    ``|a|^4 + |b|^4`` -- exactly measure-and-prepare, whose Haar average is the
    classical bound 2/3, comfortably below the ``1.0`` an entangled pair gives.
    Asserting a per-run bound of 1/2 here would be wrong physics: 1/2 is the
    floor for an *uncorrelated* resource (see the maximally mixed case), not for
    this one.
    """
    resource = Statevector(np.array([1, 0, 0, 0], dtype=complex))
    ket0 = np.array([[1, 0], [0, 0]], dtype=complex)
    ket1 = np.array([[0, 0], [0, 1]], dtype=complex)

    # Fixed payload: the two possible fidelities and their frequencies are exact.
    p0, p1 = abs(GENERIC_A) ** 2, abs(GENERIC_B) ** 2  # 0.36 and 0.64
    rng = np.random.default_rng(64)
    trials = 800
    delivered: Counter[str] = Counter()
    fidelities: list[float] = []
    for _ in range(trials):
        result = teleport(GENERIC_PAYLOAD, resource=resource, rng=rng)
        received = np.asarray(result.received.data)
        if np.allclose(received, ket0, atol=TOL):
            delivered["0"] += 1
            assert result.fidelity == pytest.approx(p0, abs=TOL)
        else:
            assert np.allclose(received, ket1, atol=TOL)
            delivered["1"] += 1
            assert result.fidelity == pytest.approx(p1, abs=TOL)
        fidelities.append(result.fidelity)

    assert delivered["0"] / trials == pytest.approx(p0, abs=0.06)
    assert float(np.mean(fidelities)) == pytest.approx(p0**2 + p1**2, abs=0.02)

    # Haar-averaged, this is the classical measure-and-prepare bound of 2/3.
    haar_rng = np.random.default_rng(99)
    haar = [
        teleport(random_qubit(haar_rng), resource=resource, rng=haar_rng).fidelity
        for _ in range(800)
    ]
    assert float(np.mean(haar)) == pytest.approx(2.0 / 3.0, abs=0.04)
    assert float(np.mean(haar)) < 1.0 - 1e-6


# --------------------------------------------------------------------------- #
# Determinism (D3)                                                             #
# --------------------------------------------------------------------------- #


def test_teleport_is_deterministic_under_a_seed() -> None:
    """Same seed, same everything -- outcome, bits, state and fidelity."""
    resource = werner(0.35)
    for seed in (0, 1, 2, 20260141):
        first = teleport(
            GENERIC_PAYLOAD, resource=resource, rng=np.random.default_rng(seed)
        )
        second = teleport(
            GENERIC_PAYLOAD, resource=resource, rng=np.random.default_rng(seed)
        )
        assert first.bell_outcome is second.bell_outcome
        assert first.classical_bits == second.classical_bits
        assert first.fidelity == second.fidelity
        assert np.array_equal(first.received.data, second.received.data)


def test_teleport_consumes_exactly_one_variate() -> None:
    """One uniform draw per call, so a shared generator stays in lockstep.

    Six teleportations must advance a generator by exactly six uniform variates:
    after them, the next draw equals the seventh draw of an untouched generator
    with the same seed.  Phase 5 threads a single seeded generator through a
    whole experiment, so an accidental extra draw here would silently decorrelate
    every downstream result.
    """
    shared = np.random.default_rng(555)
    outcomes = [teleport(GENERIC_PAYLOAD, rng=shared).bell_outcome for _ in range(6)]
    assert len(outcomes) == 6
    assert set(outcomes) <= set(BELL_ORDER)

    reference = np.random.default_rng(555)
    for _ in range(6):
        reference.random()
    assert float(shared.random()) == float(reference.random())

    # The mapping from variate to branch is the documented inverse-CDF one:
    # each quarter of [0, 1) selects the corresponding BELL_ORDER entry.
    expected = [
        BELL_ORDER[min(3, int(u * 4))]
        for u in np.random.default_rng(555).random(6)
    ]
    assert outcomes == expected


# --------------------------------------------------------------------------- #
# Input validation                                                             #
# --------------------------------------------------------------------------- #


def test_teleport_rejects_wrong_sized_payload_and_resource() -> None:
    """Sizes are checked with actionable messages, not assumed."""
    with pytest.raises(ValueError, match="single-qubit"):
        teleport(bell_state(BellState.PHI_PLUS))
    with pytest.raises(ValueError, match="two-qubit"):
        teleport(GENERIC_PAYLOAD, resource=GENERIC_PAYLOAD)
    with pytest.raises(ValueError, match="two-qubit"):
        teleport(GENERIC_PAYLOAD, resource=DensityMatrix(np.eye(8) / 8.0))


def test_teleport_rejects_unnormalised_input() -> None:
    """Normalisation is enforced by the shared helper in states.py."""
    with pytest.raises(ValueError, match="not normalised"):
        teleport(np.array([1.0, 1.0], dtype=complex))
    with pytest.raises(ValueError, match="not normalised"):
        teleport(GENERIC_PAYLOAD, resource=np.eye(4, dtype=complex))


def test_teleport_rejects_a_seed_instead_of_a_generator() -> None:
    """D3: integer seeds are refused, because they would restart the stream."""
    with pytest.raises(TypeError, match="numpy.random.default_rng"):
        teleport(GENERIC_PAYLOAD, rng=42)  # type: ignore[arg-type]


def test_teleportation_result_validates_its_own_consistency() -> None:
    """The record cannot be built with bits that contradict the outcome."""
    with pytest.raises(ValueError, match="disagree"):
        TeleportationResult(
            payload=GENERIC_PAYLOAD,
            bell_outcome=BellState.PHI_PLUS,
            classical_bits=(1, 1),
            received=DensityMatrix(GENERIC_PAYLOAD),
            fidelity=1.0,
        )
    with pytest.raises(ValueError, match=r"fidelity must lie in \[0, 1\]"):
        TeleportationResult(
            payload=GENERIC_PAYLOAD,
            bell_outcome=BellState.PHI_PLUS,
            classical_bits=(0, 0),
            received=DensityMatrix(GENERIC_PAYLOAD),
            fidelity=1.5,
        )


def test_teleportation_result_is_frozen() -> None:
    """The record is immutable, so a downstream phase cannot rewrite history."""
    result = teleport(GENERIC_PAYLOAD, rng=np.random.default_rng(3))
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.fidelity = 0.0  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# The circuit form                                                             #
# --------------------------------------------------------------------------- #


def test_teleport_core_circuit_reproduces_the_correction_table() -> None:
    """The gate order of the circuit matches the algebra, exactly.

    Applying ``h(1); cx(1,2); cx(0,1); h(0)`` to ``|0>_2 |0>_1 |psi>_0`` must
    give the expansion documented in ``_teleport_core``; projecting qubits 0 and
    1 onto ``|q0>, |q1>`` and applying ``X**q1 @ Z**q0`` must recover the
    payload.  This identifies ``m1`` with qubit 0's bit and ``m0`` with qubit
    1's -- the identification ``teleport_circuit`` wires up.
    """
    a, b = GENERIC_A, GENERIC_B
    amplitudes = np.zeros(8, dtype=complex)
    amplitudes[0] = a  # q2=0, q1=0, q0=0
    amplitudes[1] = b  # q2=0, q1=0, q0=1
    evolved = np.asarray(
        Statevector(amplitudes).evolve(_teleport_core()).data, dtype=complex
    )

    expected_branch = {
        (0, 0): np.array([a, b], dtype=complex),
        (0, 1): np.array([a, -b], dtype=complex),  # q0 = 1 -> Z applied
        (1, 0): np.array([b, a], dtype=complex),  # q1 = 1 -> X applied
        (1, 1): np.array([-b, a], dtype=complex),  # global -1 on this branch
    }
    for (q1, q0), branch in expected_branch.items():
        indices = [q0 + 2 * q1 + 4 * q2 for q2 in (0, 1)]
        actual = evolved[indices]
        assert np.allclose(actual, 0.5 * branch, atol=1e-12), (q1, q0)

        # m0 is qubit 1's bit (X exponent), m1 is qubit 0's bit (Z exponent).
        correction = np.linalg.matrix_power(
            PAULI_X, q1
        ) @ np.linalg.matrix_power(PAULI_Z, q0)
        recovered = correction @ (actual / np.linalg.norm(actual))
        assert np.allclose(
            np.outer(recovered, recovered.conj()),
            DensityMatrix(GENERIC_PAYLOAD).data,
            atol=1e-12,
        )

    # Each branch has weight 1/4, matching the equiprobable Bell outcomes.
    for (q1, q0) in expected_branch:
        indices = [q0 + 2 * q1 + 4 * q2 for q2 in (0, 1)]
        assert float(np.sum(np.abs(evolved[indices]) ** 2)) == pytest.approx(
            0.25, abs=1e-12
        )


def test_teleport_core_creates_phi_plus_on_the_resource_qubits() -> None:
    """The first block of the core really is the |Phi+> entangler on (1, 2)."""
    entangler = _teleport_core().copy_empty_like()
    entangler.h(1)
    entangler.cx(1, 2)
    state = Statevector.from_int(0, dims=(2, 2, 2)).evolve(entangler)
    pair = partial_trace(state, [0])
    assert np.allclose(
        pair.data, DensityMatrix(bell_state(BellState.PHI_PLUS)).data, atol=TOL
    )
    assert concurrence(pair) == pytest.approx(1.0, abs=TOL)


def test_teleport_circuit_structure() -> None:
    """Three qubits, two classical bits, two measurements, two conditionals."""
    circuit = teleport_circuit()
    assert circuit.num_qubits == 3
    assert circuit.num_clbits == 2
    names = [inst.operation.name for inst in circuit.data]
    assert names.count("measure") == 2
    assert names.count("h") == 2
    assert names.count("cx") == 2
    # Two classically conditioned corrections, expressed as control flow.
    assert names.count("if_else") == 2
    # The circuit is a real protocol drawing: it must be unitary-free after the
    # measurements except for the conditional corrections.
    assert names.index("measure") < names.index("if_else")


def test_teleport_circuit_is_a_no_op_operator_free_of_direct_pauli_gates() -> None:
    """The corrections are conditional, never unconditional.

    A circuit that applied ``x``/``z`` unconditionally would "work" for one Bell
    branch and silently corrupt the other three, so the absence of top-level
    Pauli gates is asserted explicitly.
    """
    names = [inst.operation.name for inst in teleport_circuit().data]
    assert "x" not in names
    assert "z" not in names


def test_teleport_circuit_teleports_on_a_simulator() -> None:
    """End-to-end check of the drawn circuit against the payload.

    The trick avoids needing a density-matrix save through mid-circuit
    conditionals: prepare the payload with a unitary ``U`` on qubit 0, run the
    circuit, then apply ``U^dagger`` to the receiver's qubit 2 and measure it.
    If teleportation is exact, qubit 2 is back in ``|0>`` and that bit is ``0``
    on **every** shot.  All four ``(m1, m0)`` patterns must also appear.
    """
    aer = pytest.importorskip("qiskit_aer")
    from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister, transpile
    from qiskit.circuit.library import UnitaryGate

    a, b = GENERIC_A, GENERIC_B
    # A unitary whose first column is the payload, so U|0> = |psi>.
    prep = np.array([[a, -np.conj(b)], [b, np.conj(a)]], dtype=complex)
    assert np.allclose(prep @ prep.conj().T, PAULI_I, atol=1e-12)

    qreg = QuantumRegister(3, "q")
    creg = ClassicalRegister(3, "c")
    circuit = QuantumCircuit(qreg, creg)
    circuit.append(UnitaryGate(prep, label="prep"), [0])
    circuit.compose(
        teleport_circuit(), qubits=qreg, clbits=[creg[0], creg[1]], inplace=True
    )
    circuit.append(UnitaryGate(prep.conj().T, label="unprep"), [2])
    circuit.measure(2, creg[2])

    simulator = aer.AerSimulator()
    counts = (
        simulator.run(transpile(circuit, simulator), shots=512, seed_simulator=11)
        .result()
        .get_counts()
    )
    assert sum(counts.values()) == 512
    # Keys are "c2 c1 c0" with c2 leftmost: the un-prepared receiver bit.
    assert {key[0] for key in counts} == {"0"}
    assert {key[1:] for key in counts} == {"00", "01", "10", "11"}
    for key, count in counts.items():
        assert abs(count / 512 - 0.25) < 0.06, key


# --------------------------------------------------------------------------- #
# MAJOR 1 (audit): a MIXED payload is teleported, not rejected                  #
#                                                                              #
# The old code raised on Tr(rho^2) != 1 and advised "degrade the resource       #
# instead".  That is an equivalent model for *some* attacks only: it cannot     #
# express noise or an interception acting on the forward payload line, and it   #
# cannot express relaying a key qubit over more than one hop.  The teleport-    #
# ation algebra is linear in rho and never needed the restriction, so these     #
# tests assert the general behaviour rather than the old error.                 #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("target_purity", [0.5, 0.6, 0.82, 0.95, 0.999])
def test_mixed_payload_teleports_at_fidelity_one(target_purity: float) -> None:
    """A mixed payload arrives *exactly*, at fidelity 1, through a clean pair.

    The headline case required by the audit is ``target_purity == 0.82``.  An
    ideal resource induces the identity channel, so the received state must
    equal the submitted matrix entry for entry -- not merely score well against
    its dominant eigenvector, which is what the old purification path would have
    reported.
    """
    payload = mixed_qubit(target_purity)
    assert purity(payload) == pytest.approx(target_purity, abs=1e-12)

    for seed in range(8):
        result = teleport(payload, rng=np.random.default_rng(seed))
        assert result.fidelity == pytest.approx(1.0, abs=TOL)
        assert purity(result.received) == pytest.approx(target_purity, abs=TOL)
        assert np.allclose(
            np.asarray(result.received.data),
            np.asarray(payload.data),
            atol=TOL,
        )


def test_mixed_payload_is_recorded_unpurified() -> None:
    """``TeleportationResult.payload`` is the state that was actually submitted.

    The reported fidelity is only meaningful if the record keeps the mixed
    matrix; purifying it to the dominant eigenvector would silently change what
    the number is measured against.
    """
    payload = mixed_qubit(0.82)
    result = teleport(payload, rng=np.random.default_rng(4))

    assert isinstance(result.payload, DensityMatrix)
    assert purity(result.payload) == pytest.approx(0.82, abs=1e-12)
    assert np.allclose(
        np.asarray(result.payload.data), np.asarray(payload.data), atol=1e-15
    )
    assert result.fidelity == pytest.approx(
        fidelity(payload, result.received), abs=1e-15
    )


def test_maximally_mixed_payload_is_a_fixed_point_of_every_correction() -> None:
    """``I/2`` teleports to ``I/2`` on all four branches: no correction moves it.

    The old code rejected this state outright.  It is the extreme case of the
    payload-line noise model and the one where a wrong correction table would be
    invisible, so it is checked branch by branch rather than on average.
    """
    payload = DensityMatrix(np.eye(2, dtype=complex) / 2.0)
    seen = set()
    for seed in range(40):
        result = teleport(payload, rng=np.random.default_rng(seed))
        seen.add(result.bell_outcome)
        assert result.fidelity == pytest.approx(1.0, abs=TOL)
        assert np.allclose(
            np.asarray(result.received.data), np.eye(2) / 2.0, atol=TOL
        )
    assert seen == set(BELL_ORDER)


@pytest.mark.parametrize("p", [0.0, 0.25, 0.5, 0.75, 1.0])
def test_mixed_payload_through_a_werner_resource_is_the_predicted_state(
    p: float,
) -> None:
    """A mixed payload down a noisy line gives ``(1-p) rho + p I/2``, exactly.

    The Werner resource induces the depolarising channel with strength ``p`` on
    *whatever* is teleported, mixed included.  Pinning the whole matrix -- not
    just a scalar fidelity -- is what makes the two-hop composition test below
    meaningful.
    """
    payload = mixed_qubit(0.82)
    expected = (1.0 - p) * np.asarray(payload.data) + p * np.eye(2) / 2.0

    for seed in range(6):
        result = teleport(payload, resource=werner(p), rng=np.random.default_rng(seed))
        assert np.allclose(np.asarray(result.received.data), expected, atol=TOL)
        assert result.fidelity == pytest.approx(
            fidelity(payload, DensityMatrix(expected)), abs=TOL
        )


def test_teleport_accepts_a_pure_payload_given_as_a_density_matrix() -> None:
    """A rank-one ``rho`` still works, and is likewise kept as a density matrix.

    The complement of the mixed cases -- otherwise "accept everything and do
    nothing" would pass.  Global phase is unobservable in a density matrix, so
    the comparison is between operators.
    """
    amplitudes = np.array([0.6, 0.8j], dtype=complex)
    rho = np.outer(amplitudes, amplitudes.conj())
    assert purity(rho) == pytest.approx(1.0, abs=1e-12)

    result = teleport(rho, rng=np.random.default_rng(20260141))
    assert result.fidelity == pytest.approx(1.0, abs=TOL)
    assert purity(result.received) == pytest.approx(1.0, abs=TOL)
    assert np.allclose(np.asarray(result.received.data), rho, atol=TOL)


def test_teleport_fidelity_is_the_clipped_helper_never_above_one() -> None:
    """Regression (audit item a): the ``[0, 1]`` invariant is by construction.

    Qiskit's raw ``state_fidelity`` returns ``1.000000000000001`` for a
    sizeable fraction of pure-vs-pure comparisons, which
    ``TeleportationResult.__post_init__`` hard-rejects; the module must route
    through ``states.fidelity``, which clips.  Two thousand random payloads is
    enough to hit the overshoot many times over -- with the raw function this
    loop raises.
    """
    rng = np.random.default_rng(20260141)
    for _ in range(2000):
        result = teleport(random_qubit(rng), rng=rng)
        assert 0.0 <= result.fidelity <= 1.0
        assert result.fidelity == pytest.approx(1.0, abs=TOL)
        assert result.fidelity == fidelity(result.payload, result.received)


# --------------------------------------------------------------------------- #
# MAJOR 2 (audit): teleport_in_register moves a CORRELATED qubit                #
# --------------------------------------------------------------------------- #


def two_pair_register(pair: DensityMatrix, resource: DensityMatrix) -> DensityMatrix:
    """Build ``|payload, reference> (x) |sender, receiver>`` on four qubits.

    ``tensor`` places its *argument* on the low indices (D2), so the returned
    register has the payload on qubit 0, the reference on qubit 1, the sender's
    half on qubit 2 and the receiver's half on qubit 3.
    """
    return resource.tensor(pair)


def test_teleporting_half_a_bell_pair_preserves_the_entanglement() -> None:
    """The headline MAJOR-2 requirement: concurrence stays exactly 1.

    Qubit A of an entangled pair ``(A, R)`` is teleported away from R.  If the
    primitive silently traced A out, measured it, or applied the correction to
    the wrong qubit, the surviving pair would be separable (concurrence 0) or
    partially mixed; it must instead still be maximally entangled to ``1e-9``.
    """
    pair = DensityMatrix(bell_state(BellState.PHI_PLUS))
    register = two_pair_register(pair, DensityMatrix(bell_state(BellState.PHI_PLUS)))

    seen = set()
    for seed in range(40):
        moved = teleport_in_register(
            register,
            payload_qubit=0,
            resource_qubits=(2, 3),
            rng=np.random.default_rng(seed),
        )
        seen.add(moved.bell_outcome)
        assert moved.register.num_qubits == 2
        # Survivors keep their relative order: reference (was 1) -> 0,
        # receiver's half (was 3) -> 1.
        assert moved.payload_index == 1
        assert concurrence(moved.register) == pytest.approx(1.0, abs=TOL)
        assert purity(moved.register) == pytest.approx(1.0, abs=TOL)
    assert seen == set(BELL_ORDER), "not every Bell branch was exercised"


def test_teleported_half_pair_is_the_original_state_not_just_as_entangled() -> None:
    """Concurrence 1 alone is too weak: the exact joint state must survive.

    An *asymmetric*, non-maximally-entangled reference state is used, because
    ``|Phi+>`` is invariant under too much (swap, and several correction
    mistakes) to distinguish a wrong table.  ``sqrt(0.3)|00> + i sqrt(0.7)|11>``
    has concurrence ``2 sqrt(0.3 * 0.7)``, an unusual number that a Pauli slip
    on either qubit would change.
    """
    alpha, beta = np.sqrt(0.3), 1j * np.sqrt(0.7)
    entangled = Statevector(np.array([alpha, 0.0, 0.0, beta], dtype=complex))
    expected_concurrence = 2.0 * np.sqrt(0.3 * 0.7)

    register = two_pair_register(
        DensityMatrix(entangled), DensityMatrix(bell_state(BellState.PHI_PLUS))
    )
    for seed in range(20):
        moved = teleport_in_register(
            register,
            payload_qubit=0,
            resource_qubits=(2, 3),
            rng=np.random.default_rng(seed),
        )
        # The original register held (payload=q0, reference=q1); the survivor
        # holds (reference=q0, payload=q1).  This state has support only on
        # |00> and |11>, so it is invariant under that relabelling and can be
        # compared with itself directly.
        assert fidelity(entangled, moved.register) == pytest.approx(1.0, abs=TOL)
        assert concurrence(moved.register) == pytest.approx(
            expected_concurrence, abs=TOL
        )


def test_entanglement_swapping_through_the_primitive() -> None:
    """Two independent pairs become one shared pair between the outer qubits.

    Pairs ``(A, B)`` and ``(C, D)``; teleporting B through the ``(C, D)`` pair
    leaves A and D entangled although they never interacted.  This is the flow
    Phase 3 needs for a relay attack, and it was impossible with the old API.
    """
    register = two_pair_register(
        DensityMatrix(bell_state(BellState.PHI_PLUS)),
        DensityMatrix(bell_state(BellState.PHI_PLUS)),
    )
    for seed in range(12):
        # Teleport qubit 1 (B) using (2, 3) = (C, D); survivors are A and D.
        moved = teleport_in_register(
            register,
            payload_qubit=1,
            resource_qubits=(2, 3),
            rng=np.random.default_rng(seed),
        )
        assert moved.register.num_qubits == 2
        # A (was 0) -> 0; D (was 3) -> 1, two consumed indices below it.
        assert moved.payload_index == 1
        assert concurrence(moved.register) == pytest.approx(1.0, abs=TOL)


def test_register_indices_need_not_be_adjacent_or_ordered() -> None:
    """The primitive is index-agnostic: the payload may sit above the resource.

    Layout here is receiver=0, sender=1, payload=2, reference=3, i.e. the
    reverse of the convenient one.  The bookkeeping rule -- subtract the number
    of consumed indices *below* the receiver -- must still land the payload on
    index 0, with the reference on index 1.
    """
    pair = DensityMatrix(bell_state(BellState.PHI_PLUS))  # (payload, reference)
    resource = DensityMatrix(bell_state(BellState.PHI_PLUS))  # (sender, receiver)
    # tensor puts its argument low, so build the resource with its halves
    # exchanged to get receiver on qubit 0 and sender on qubit 1.
    swapped_resource = DensityMatrix(
        np.asarray(resource.data)[np.ix_([0, 2, 1, 3], [0, 2, 1, 3])]
    )
    register = pair.tensor(swapped_resource)  # q0=recv, q1=send, q2=pay, q3=ref

    for seed in range(12):
        moved = teleport_in_register(
            register,
            payload_qubit=2,
            resource_qubits=(1, 0),
            rng=np.random.default_rng(seed),
        )
        assert moved.payload_index == 0
        assert concurrence(moved.register) == pytest.approx(1.0, abs=TOL)


def test_teleport_is_exactly_the_primitive_on_a_three_qubit_register() -> None:
    """``teleport`` is a thin wrapper, bit for bit, not a parallel implementation.

    Both are driven from the same seed, so if the wrapper had its own copy of
    the register layout or the correction table the two would diverge on some
    branch.
    """
    payload = mixed_qubit(0.7)
    resource = werner(0.35)
    for seed in range(15):
        direct = teleport(
            payload, resource=resource, rng=np.random.default_rng(seed)
        )
        register = resource.tensor(as_density(payload))
        moved = teleport_in_register(
            register,
            payload_qubit=0,
            resource_qubits=(1, 2),
            rng=np.random.default_rng(seed),
        )
        assert moved.bell_outcome is direct.bell_outcome
        assert moved.classical_bits == direct.classical_bits
        assert moved.payload_index == 0
        assert np.allclose(
            np.asarray(moved.register.data),
            np.asarray(direct.received.data),
            atol=1e-14,
        )


def test_teleport_in_register_consumes_exactly_one_variate() -> None:
    """D3: one Bell measurement, one uniform draw -- the stream stays aligned."""
    register = two_pair_register(
        DensityMatrix(bell_state(BellState.PHI_PLUS)),
        DensityMatrix(bell_state(BellState.PHI_PLUS)),
    )
    generator = np.random.default_rng(99)
    teleport_in_register(
        register, payload_qubit=0, resource_qubits=(2, 3), rng=generator
    )
    assert generator.random() == np.random.default_rng(99).random(2)[1]


def test_teleport_in_register_validates_its_arguments() -> None:
    """Every way of misaddressing the register raises an actionable ValueError."""
    register = two_pair_register(
        DensityMatrix(bell_state(BellState.PHI_PLUS)),
        DensityMatrix(bell_state(BellState.PHI_PLUS)),
    )
    with pytest.raises(ValueError, match="at least three qubits"):
        teleport_in_register(
            DensityMatrix(bell_state()), payload_qubit=0, resource_qubits=(1, 1)
        )
    with pytest.raises(ValueError, match="tuple of two distinct qubit indices"):
        teleport_in_register(
            register,
            payload_qubit=0,
            resource_qubits=(1, 2, 3),  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match=r"resource_qubits\[1\] must satisfy"):
        teleport_in_register(register, payload_qubit=0, resource_qubits=(2, 9))
    with pytest.raises(ValueError, match="payload_qubit must satisfy"):
        teleport_in_register(register, payload_qubit=-1, resource_qubits=(2, 3))
    with pytest.raises(ValueError, match="must be three distinct qubits"):
        teleport_in_register(register, payload_qubit=2, resource_qubits=(2, 3))
    with pytest.raises(ValueError, match="integer qubit index"):
        teleport_in_register(
            register,
            payload_qubit=0.0,  # type: ignore[arg-type]
            resource_qubits=(2, 3),
        )
    with pytest.raises(TypeError, match="numpy.random.default_rng"):
        teleport_in_register(
            register,
            payload_qubit=0,
            resource_qubits=(2, 3),
            rng=7,  # type: ignore[arg-type]
        )


def test_register_result_validates_and_is_frozen() -> None:
    """The record checks its own consistency and cannot be rewritten later."""
    register = two_pair_register(
        DensityMatrix(bell_state(BellState.PHI_PLUS)),
        DensityMatrix(bell_state(BellState.PHI_PLUS)),
    )
    moved = teleport_in_register(
        register, payload_qubit=0, resource_qubits=(2, 3), rng=np.random.default_rng(0)
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        moved.payload_index = 0  # type: ignore[misc]
    with pytest.raises(ValueError, match="disagree"):
        RegisterTeleportationResult(
            register=moved.register,
            bell_outcome=BellState.PHI_PLUS,
            classical_bits=(1, 1),
            payload_index=0,
        )
    with pytest.raises(ValueError, match="out of range"):
        RegisterTeleportationResult(
            register=moved.register,
            bell_outcome=BellState.PHI_PLUS,
            classical_bits=(0, 0),
            payload_index=5,
        )


# --------------------------------------------------------------------------- #
# teleport_channel: the same physics, analytically                             #
# --------------------------------------------------------------------------- #


def reference_channel(resource: DensityMatrix) -> np.ndarray:
    """Independently compute the induced channel's Choi matrix by brute force.

    Deliberately *not* the implementation's method: this builds the three-qubit
    register, the four Bell projectors and the partial trace explicitly and sums
    ``U_B Tr_{0,1}[Pi_B (rho_res (x) rho) Pi_B] U_B^dagger`` over the outcomes,
    then assembles the Choi matrix from the channel's action on the four matrix
    units.  A shared bug would have to occur twice, in two different
    formulations, to slip through.
    """
    resource_data = np.asarray(resource.data, dtype=complex)
    projectors = {}
    for which in BELL_ORDER:
        vec = np.asarray(bell_state(which).data, dtype=complex)
        # Qubits 0 (payload) and 1 (sender) are the low indices, so the
        # identity on qubit 2 is the LEFT kron factor (D2).
        projectors[which] = np.kron(PAULI_I, np.outer(vec, vec.conj()))

    def apply(rho: np.ndarray) -> np.ndarray:
        register = np.kron(resource_data, rho)  # payload on the low qubit
        total = np.zeros((2, 2), dtype=complex)
        for which in BELL_ORDER:
            projector = projectors[which]
            branch = projector @ register @ projector
            # Trace out qubits 0 and 1 by hand.  The 8x8 matrix indexes as
            # (q2, q1, q0) on each side, so reshaping to (2,)*6 and contracting
            # the two low index pairs leaves the receiver's 2x2 block.
            tensor = branch.reshape(2, 2, 2, 2, 2, 2)
            reduced = np.einsum("aijbij->ab", tensor)
            unitary = pauli_correction(which)
            total += unitary @ reduced @ unitary.conj().T
        return total

    # Choi = sum_ij |i><j| (x) E(|i><j|), qiskit's column-stacking convention.
    choi = np.zeros((4, 4), dtype=complex)
    for i in range(2):
        for j in range(2):
            unit = np.zeros((2, 2), dtype=complex)
            unit[i, j] = 1.0
            choi[2 * i : 2 * i + 2, 2 * j : 2 * j + 2] = apply(unit)
    return choi


NON_TRIVIAL_RESOURCES = {
    "werner_0.30": werner(0.30),
    "werner_0.75": werner(0.75),
    "damped_0.40": amplitude_damped_resource(0.40),
    "psi_minus": DensityMatrix(bell_state(BellState.PSI_MINUS)),
    "separable_mix": DensityMatrix(
        0.7 * np.asarray(as_density(bell_state(BellState.PHI_MINUS)).data)
        + 0.3 * np.diag([0.5, 0.0, 0.0, 0.5]).astype(complex)
    ),
}


def test_teleport_channel_of_phi_plus_is_the_identity_channel() -> None:
    """A pristine pair induces the identity channel -- checked via the Choi matrix.

    Not by sampling: the Choi matrix is the complete fingerprint of a channel,
    so equality here rules out every input the sampler might not have tried.
    """
    channel = teleport_channel()
    assert np.allclose(
        Choi(channel).data, Choi(Operator(np.eye(2, dtype=complex))).data, atol=1e-12
    )
    # An explicit resource argument must agree with the default.
    assert np.allclose(
        Choi(teleport_channel(bell_state(BellState.PHI_PLUS))).data,
        Choi(channel).data,
        atol=1e-12,
    )
    # Every branch contributes +-I/2 (the Psi- branch carries the global minus
    # sign of X @ Z, which a Kraus operator is free to have), so a pure resource
    # needs only four operators.
    assert len(channel.data) == 4
    for operator in channel.data:
        assert np.allclose(np.abs(operator), np.eye(2) / 2.0, atol=1e-12)
        assert np.allclose(
            operator @ operator.conj().T, np.eye(2) / 4.0, atol=1e-12
        )


def test_teleport_channel_of_maximally_mixed_is_completely_depolarising() -> None:
    """``I/4`` induces ``rho -> I/2``, the channel with no memory of its input."""
    channel = teleport_channel(MAXMIX_2Q)
    depolarising = Kraus(
        [PAULI_I / 2.0, PAULI_X / 2.0, PAULI_Y / 2.0, PAULI_Z / 2.0]
    )
    assert np.allclose(Choi(channel).data, Choi(depolarising).data, atol=1e-12)
    assert np.allclose(Choi(channel).data, np.eye(4) / 2.0, atol=1e-12)
    # Rank-four resource -> four branches x four outcomes.
    assert len(channel.data) == 16


@pytest.mark.parametrize("p", [0.0, 0.1, 0.35, 0.6, 0.9, 1.0])
def test_werner_resource_induces_the_depolarising_channel(p: float) -> None:
    """The Werner line is exactly ``rho -> (1-p) rho + p I/2``.

    This is where the module's ``F = 1 - p/2`` law comes from, and it is what
    makes two hops compose as ``(1-p1)(1-p2)``.
    """
    channel = teleport_channel(werner(p))
    expected = Choi(
        Kraus(
            [
                np.sqrt(1.0 - 3.0 * p / 4.0) * PAULI_I,
                np.sqrt(p / 4.0) * PAULI_X,
                np.sqrt(p / 4.0) * PAULI_Y,
                np.sqrt(p / 4.0) * PAULI_Z,
            ]
        )
    )
    assert np.allclose(Choi(channel).data, expected.data, atol=1e-12)


@pytest.mark.parametrize("name", sorted(NON_TRIVIAL_RESOURCES))
def test_teleport_channel_is_cptp_and_matches_the_brute_force_reference(
    name: str,
) -> None:
    """The channel is trace-preserving, completely positive, and independently right.

    ``sum_k K_k^dagger K_k == I`` is trace preservation; a PSD Choi matrix is
    complete positivity; and the comparison is against ``reference_channel``,
    which computes the same object by explicit Bell projection and partial trace
    rather than in closed form.
    """
    resource = NON_TRIVIAL_RESOURCES[name]
    channel = teleport_channel(resource)

    total = sum(op.conj().T @ op for op in channel.data)
    assert np.allclose(total, np.eye(2), atol=1e-12), name

    choi = np.asarray(Choi(channel).data)
    assert np.allclose(choi, choi.conj().T, atol=1e-12), name
    assert float(np.linalg.eigvalsh(0.5 * (choi + choi.conj().T))[0]) > -1e-12, name

    assert np.allclose(choi, reference_channel(resource), atol=1e-12), name


@pytest.mark.parametrize("name", sorted(NON_TRIVIAL_RESOURCES))
def test_teleport_channel_matches_monte_carlo_teleport(name: str) -> None:
    """The analytic channel reproduces sampled ``teleport`` within sampling error.

    Five non-trivial resources, three mutually unbiased payloads each, averaged
    over ``shots`` runs.  The average of a bounded estimator converges as
    ``1/sqrt(N)``, so the tolerance is set from the shot count rather than
    tuned: at 1500 shots the standard error on a density-matrix entry is about
    ``0.013``, and ``0.06`` is a comfortable band.
    """
    shots = 1500
    resource = NON_TRIVIAL_RESOURCES[name]
    channel = teleport_channel(resource)
    rng = np.random.default_rng(20260141)

    payloads = [
        Statevector(np.array([1.0, 0.0], dtype=complex)),  # |0>, a Z eigenstate
        Statevector(np.array([1.0, 1.0], dtype=complex) / np.sqrt(2.0)),  # |+>
        Statevector(np.array([1.0, 1.0j], dtype=complex) / np.sqrt(2.0)),  # |+i>
    ]
    for payload in payloads:
        total = np.zeros((2, 2), dtype=complex)
        fidelity_sum = 0.0
        for _ in range(shots):
            result = teleport(payload, resource=resource, rng=rng)
            total += np.asarray(result.received.data, dtype=complex)
            fidelity_sum += result.fidelity
        sampled = total / shots

        predicted = DensityMatrix(payload).evolve(channel)
        assert np.allclose(
            sampled, np.asarray(predicted.data), atol=0.06
        ), f"{name}: sampled {sampled} vs predicted {predicted.data}"
        # The mean *fidelity* is a separate statistic from the fidelity of the
        # mean, so it is checked against the analytic average too.
        assert fidelity_sum / shots == pytest.approx(
            fidelity(payload, predicted), abs=0.06
        )


def test_teleport_channel_predicts_an_entangled_payload_too() -> None:
    """The Kraus set is the full CP map, so it also governs a correlated qubit.

    Averaging ``teleport_in_register`` over its Bell branches must equal
    ``(id (x) E)`` applied to the joint state -- a property no single-qubit
    sampling run can establish, and the reason Phase 3 can trust the channel for
    entanglement-swapping flows too.
    """
    resource = amplitude_damped_resource(0.4)
    pair = DensityMatrix(bell_state(BellState.PHI_PLUS))
    register = two_pair_register(pair, resource)

    rng = np.random.default_rng(4242)
    shots = 2000
    total = np.zeros((4, 4), dtype=complex)
    for _ in range(shots):
        moved = teleport_in_register(
            register, payload_qubit=0, resource_qubits=(2, 3), rng=rng
        )
        total += np.asarray(moved.register.data, dtype=complex)
    sampled = total / shots

    # Survivor layout is (reference = 0, payload = 1), so the channel acts on
    # qubit 1 of the pair -- and |Phi+> is symmetric under exchanging its
    # halves, so the pair itself needs no relabelling.
    predicted = pair.evolve(teleport_channel(resource), qargs=[1])
    assert np.allclose(sampled, np.asarray(predicted.data), atol=0.05)


def test_two_hop_chaining_composes_as_the_channels_predict() -> None:
    """Relaying over two noisy hops: fidelities compose, they do not multiply.

    Hop 1 through a Werner resource of strength ``p1``, hop 2 -- feeding the
    *mixed* output of hop 1 straight back in, which the old API forbade --
    through ``p2``.  Both are depolarising, so the composite is depolarising
    with ``1 - eta`` where ``eta = (1-p1)(1-p2)``, and the fidelity against the
    ORIGINAL payload is ``1 - (1 - eta)/2``.  Note this is *not* ``F1 * F2``:
    the naive product gives ``0.7225`` at ``p1 = p2 = 0.3`` where the truth is
    ``0.7450``.
    """
    for p1, p2 in [(0.0, 0.0), (0.3, 0.3), (0.2, 0.5), (0.45, 0.9), (1.0, 0.4)]:
        payload = GENERIC_PAYLOAD
        eta = (1.0 - p1) * (1.0 - p2)
        expected_state = eta * np.asarray(as_density(payload).data) + (
            1.0 - eta
        ) * np.eye(2) / 2.0
        expected_fidelity = 1.0 - (1.0 - eta) / 2.0

        rng = np.random.default_rng(2026)
        hop1 = teleport(payload, resource=werner(p1), rng=rng)
        hop2 = teleport(hop1.received, resource=werner(p2), rng=rng)

        assert np.allclose(
            np.asarray(hop2.received.data), expected_state, atol=TOL
        ), (p1, p2)
        assert fidelity(payload, hop2.received) == pytest.approx(
            expected_fidelity, abs=TOL
        ), (p1, p2)
        # hop2.fidelity is measured against hop1's *mixed* output, which is a
        # different (and larger) number -- exactly the distinction the widened
        # API makes it possible to state.
        assert hop2.fidelity == pytest.approx(
            fidelity(hop1.received, hop2.received), abs=1e-15
        )

        # And the same answer from channel composition alone, no sampling.
        composed = SuperOp(teleport_channel(werner(p1))).compose(
            SuperOp(teleport_channel(werner(p2)))
        )
        predicted = DensityMatrix(payload).evolve(composed)
        assert np.allclose(np.asarray(predicted.data), expected_state, atol=1e-12)


def test_two_hop_chaining_composes_off_the_depolarising_line() -> None:
    """Composition also holds when the two hops are unequal and non-depolarising.

    Hop 1 through an amplitude-damped pair (a lopsided, non-degenerate Bell
    diagonal), hop 2 through a Werner pair.  The mixed output of hop 1 is fed
    straight into hop 2 -- the multi-hop relay the old API could not express --
    and the sampled result must match the composed channels.
    """
    payload = GENERIC_PAYLOAD
    first = amplitude_damped_resource(0.5)
    second = werner(0.3)

    rng = np.random.default_rng(31337)
    shots = 2000
    total = np.zeros((2, 2), dtype=complex)
    for _ in range(shots):
        hop1 = teleport(payload, resource=first, rng=rng)
        hop2 = teleport(hop1.received, resource=second, rng=rng)
        total += np.asarray(hop2.received.data, dtype=complex)
    sampled = total / shots

    composed = SuperOp(teleport_channel(first)).compose(
        SuperOp(teleport_channel(second))
    )
    predicted = DensityMatrix(payload).evolve(composed)
    assert np.allclose(sampled, np.asarray(predicted.data), atol=0.05)
    # The composite is not either hop on its own, so this is a real two-hop
    # statement rather than an identity in disguise.
    for single in (first, second):
        assert not np.allclose(
            np.asarray(predicted.data),
            np.asarray(DensityMatrix(payload).evolve(teleport_channel(single)).data),
            atol=1e-3,
        )


@pytest.mark.parametrize("name", sorted(NON_TRIVIAL_RESOURCES))
def test_induced_channel_is_the_pauli_channel_of_the_bell_diagonal(
    name: str,
) -> None:
    """Structure: the induced channel is always a **Pauli** channel.

    The Pauli corrections twirl the resource, so only its *diagonal in the Bell
    basis* survives: with ``q_B = <B|rho_res|B>``,

        E(rho) = sum_B q_B U_B rho U_B^dagger.

    Two consequences Phases 4 and 5 rely on.  First, a QBER is a linear function
    of four numbers that can be read straight off the resource -- no channel
    tomography and no sampling.  Second, every teleportation channel is unital
    and any two of them commute, so a multi-hop chain depends only on the
    *multiset* of hops, not their order; the ``eta = (1-p1)(1-p2)`` composition
    above is an instance of that.

    A non-unital resource does **not** give a non-unital channel: amplitude
    damping on the resource shows up here purely as a lopsided ``q_B``.
    """
    resource = NON_TRIVIAL_RESOURCES[name]
    data = np.asarray(resource.data, dtype=complex)

    weights = [
        float(
            np.real(
                np.asarray(bell_state(which).data).conj()
                @ data
                @ np.asarray(bell_state(which).data)
            )
        )
        for which in BELL_ORDER
    ]
    assert sum(weights) == pytest.approx(1.0, abs=1e-12)

    pauli_channel = Kraus(
        [
            np.sqrt(weight) * pauli_correction(which)
            for weight, which in zip(weights, BELL_ORDER)
            if weight > 0.0
        ]
    )
    assert np.allclose(
        Choi(teleport_channel(resource)).data,
        Choi(pauli_channel).data,
        atol=1e-12,
    ), name


def test_teleportation_channels_commute_because_they_are_pauli_channels() -> None:
    """The order-independence implied by the structure above, asserted directly.

    Worth pinning because it is counter-intuitive: amplitude damping and
    depolarising noise do *not* commute as channels in general, yet the
    teleportation channels they induce do.
    """
    first = teleport_channel(amplitude_damped_resource(0.5))
    second = teleport_channel(werner(0.3))
    forward = SuperOp(first).compose(SuperOp(second))
    reverse = SuperOp(second).compose(SuperOp(first))
    assert np.allclose(np.asarray(forward.data), np.asarray(reverse.data), atol=1e-12)


def test_teleport_channel_rejects_a_non_two_qubit_resource() -> None:
    """The resource is validated exactly as ``teleport`` validates it."""
    with pytest.raises(ValueError, match="two-qubit"):
        teleport_channel(GENERIC_PAYLOAD)
    with pytest.raises(ValueError, match="not normalised"):
        teleport_channel(np.eye(4, dtype=complex))


# --------------------------------------------------------------------------- #
# Regression (audit item b): the receiver's pre-correction marginal            #
# --------------------------------------------------------------------------- #


def test_receiver_marginal_is_payload_independent_but_not_always_one_half() -> None:
    """No-signalling needs payload-independence; ``I/2`` is a stronger, false claim.

    Before the classical bits arrive the receiver holds
    ``Tr_sender(rho_resource)`` whatever the payload was -- that is the whole
    no-signalling argument.  For a Bell or Werner resource that marginal happens
    to be ``I/2``, and the old docstring generalised from those two.  An
    amplitude-damped resource, which Phase 3 supplies, makes it
    ``diag((1 + gamma)/2, (1 - gamma)/2)`` instead -- damping pushes population
    towards ``|0>`` from the ``I/2`` that ``|Phi+>`` started with.
    """
    gamma = 0.4
    resource = amplitude_damped_resource(gamma)
    marginal = np.asarray(partial_trace(resource, [0]).data, dtype=complex)

    assert np.allclose(
        marginal,
        np.diag([(1.0 + gamma) / 2.0, (1.0 - gamma) / 2.0]),
        atol=TOL,
    )
    assert not np.allclose(marginal, np.eye(2) / 2.0, atol=1e-3)

    # Payload-independence: averaged over the Bell outcomes with their Born
    # weights -- which is exactly "before the two bits arrive" -- the receiver's
    # state is the same for two very different payloads.
    for payload in (
        Statevector(np.array([1.0, 0.0], dtype=complex)),
        GENERIC_PAYLOAD,
    ):
        register = DensityMatrix(
            np.kron(
                np.asarray(resource.data, dtype=complex),
                np.asarray(as_density(payload).data, dtype=complex),
            )
        )
        averaged = np.asarray(partial_trace(register, [0, 1]).data, dtype=complex)
        assert np.allclose(averaged, marginal, atol=TOL)


# --------------------------------------------------------------------------- #
# Post-hardening additions                                                     #
#                                                                              #
# Four properties the hardening audit found unpinned.  Each is written so that  #
# the specific mutation that survived the old suite now fails, and the mutation #
# is named in the docstring so a future reader can re-run it.                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("p", [0.0, 0.1, 0.3, 0.5, 0.75, 1.0])
def test_density_matrix_payload_reports_the_same_fidelity_as_the_ket(
    p: float,
) -> None:
    """A pure payload's fidelity must not depend on how it was spelled.

    ``teleport`` accepts both representations (D1).  For a *pure* payload the
    two are the same state, the received density matrix is bit-for-bit
    identical, and so the reported fidelity has to be identical too.  It was
    not: Qiskit's ``state_fidelity`` takes the exact ``<psi|rho|psi>`` shortcut
    when one argument is a ``Statevector`` but the ``sqrtm`` Uhlmann formula
    when both are ``DensityMatrix``, and the ``sqrtm`` route carried ~1e-8 of
    error -- an order of magnitude outside the 1e-9 calibration contract this
    file asserts everywhere else.  ``states.fidelity`` now detects a pure
    argument and uses ``F = Tr(rho sigma)``, which is exact.
    """
    rng = np.random.default_rng(31337 + int(p * 100))
    resource = werner(p)
    for _ in range(9):
        ket = random_qubit(rng)
        vector = np.asarray(ket.data, dtype=complex)
        matrix = DensityMatrix(np.outer(vector, vector.conj()))

        seed = int(rng.integers(0, 2**32 - 1))
        from_ket = teleport(
            ket, resource=resource, rng=np.random.default_rng(seed)
        )
        from_matrix = teleport(
            matrix, resource=resource, rng=np.random.default_rng(seed)
        )

        # Same branch, same physics: only the payload's *representation* differs.
        assert from_ket.bell_outcome == from_matrix.bell_outcome
        assert np.allclose(
            from_ket.received.data, from_matrix.received.data, atol=0.0, rtol=0.0
        )
        # ... so the two reported fidelities must agree to machine precision,
        # and both must sit on the calibration line to the file's own 1e-9.
        assert from_matrix.fidelity == pytest.approx(from_ket.fidelity, abs=1e-14)
        assert from_matrix.fidelity == pytest.approx(1.0 - p / 2.0, abs=TOL)


def test_mixed_versus_mixed_fidelity_still_uses_the_uhlmann_formula() -> None:
    """The pure-state shortcut must not have replaced the general case.

    Two commuting mixed states have the closed form
    ``F = (sum_k sqrt(a_k b_k))**2``, which is *not* ``Tr(rho sigma)``; this
    pins that the mixed-vs-mixed branch still computes the real Uhlmann
    fidelity rather than the overlap.
    """
    first = DensityMatrix(np.diag([0.7, 0.3]).astype(complex))
    second = DensityMatrix(np.diag([0.4, 0.6]).astype(complex))
    expected = (np.sqrt(0.7 * 0.4) + np.sqrt(0.3 * 0.6)) ** 2

    assert fidelity(first, second) == pytest.approx(expected, abs=TOL)
    # Tr(rho sigma) = 0.46 -- materially different, so this really is a
    # distinguishing assertion rather than a coincidence of the numbers.
    assert abs(expected - 0.46) > 0.4


@pytest.mark.parametrize(
    ("payload_qubit", "resource_qubits", "num_qubits"),
    [
        (3, (4, 2), 5),  # receiver below both consumed qubits
        (1, (4, 2), 5),  # receiver below one of them
        (4, (3, 0), 5),  # receiver at index 0 with both consumed above it
        (2, (3, 1), 4),
        (0, (3, 1), 4),
    ],
)
def test_register_teleport_reindexes_a_downward_hop_correctly(
    payload_qubit: int, resource_qubits: tuple[int, int], num_qubits: int
) -> None:
    """The receiver's post-trace index for layouts that move a qubit *down*.

    ``teleport_in_register`` traces out the payload and the sender's half, so
    the receiver's index shifts down by the number of consumed qubits *below*
    it::

        new_index = receiver - sum(c < receiver for c in (payload, sender))

    The old suite only ever used the layouts ``(0,1,2)``, ``(0,2,3)``,
    ``(1,2,3)`` and ``(2,1,0)``, on all of which the wrong rule
    ``max(0, receiver - 2)`` agrees with the right one -- so that mutation
    passed 480 tests.  Every layout below separates them.  The check is a
    physical one: the payload arrives on the receiver's qubit, so tracing out
    everything *except* ``new_index`` must return the payload itself.
    """
    payload = GENERIC_PAYLOAD
    spectators = [
        index
        for index in range(num_qubits)
        if index not in {payload_qubit, *resource_qubits}
    ]

    # The entangled pair cannot be written as a product of single-qubit kets,
    # so assemble the register amplitude by amplitude in little-endian order
    # (D2) rather than by kron of factors.
    sender, receiver = resource_qubits
    payload_amplitudes = np.asarray(payload.data, dtype=complex)
    amplitudes = np.zeros(2**num_qubits, dtype=complex)
    for basis_index in range(2**num_qubits):
        bits = [(basis_index >> q) & 1 for q in range(num_qubits)]
        if bits[sender] != bits[receiver]:
            continue  # |Phi+> has no |01> or |10> component
        if any(bits[index] for index in spectators):
            continue  # every spectator is |0>
        amplitudes[basis_index] = (
            payload_amplitudes[bits[payload_qubit]] / np.sqrt(2.0)
        )
    register = Statevector(amplitudes)
    assert abs(np.vdot(amplitudes, amplitudes) - 1.0) < TOL

    moved = teleport_in_register(
        register,
        payload_qubit=payload_qubit,
        resource_qubits=resource_qubits,
        rng=np.random.default_rng(4041),
    )

    expected_index = receiver - sum(
        1 for consumed in (payload_qubit, sender) if consumed < receiver
    )
    assert moved.payload_index == expected_index
    assert moved.register.num_qubits == num_qubits - 2

    # The physical check: the payload really is on that wire.
    others = [
        index for index in range(num_qubits - 2) if index != moved.payload_index
    ]
    delivered = (
        partial_trace(moved.register, others) if others else moved.register
    )
    assert fidelity(payload, delivered) == pytest.approx(1.0, abs=TOL)
    # ... and the mutant index would have been a spectator |0>, so make sure the
    # two are actually distinguishable for this layout.
    mutant_index = max(0, receiver - 2)
    if mutant_index != moved.payload_index:
        mutant_others = [
            index for index in range(num_qubits - 2) if index != mutant_index
        ]
        mutant = (
            partial_trace(moved.register, mutant_others)
            if mutant_others
            else moved.register
        )
        assert fidelity(payload, mutant) < 0.99


@pytest.mark.parametrize("p", [0.005, 0.02, 0.05, 0.08])
def test_channel_keeps_every_non_zero_resource_eigenvalue(p: float) -> None:
    """A nearly-pure resource must not silently lose its small branches.

    ``teleport_channel`` skips eigenvalues at or below zero.  Raising that floor
    to ``0.02`` left the old suite green because the smallest Werner ``p`` it
    used was ``0.1`` (branch weight ``p/4 = 0.025``), yet the resulting Kraus
    map is not trace preserving: it loses up to ``3p/4``.  Both consequences are
    pinned here for ``0 < p <= 0.08``, where ``p/4 <= 0.02``.
    """
    channel = teleport_channel(werner(p))

    # Four Bell outcomes times four non-zero resource eigenvalues.
    assert len(Kraus(channel).data) == 16

    # Trace preservation, read off the Choi matrix.
    choi = np.asarray(Choi(channel).data, dtype=complex)
    traced = choi.reshape(2, 2, 2, 2).trace(axis1=1, axis2=3)
    assert np.allclose(traced, np.eye(2), atol=1e-12)

    # And the channel is the depolarising one it is documented to be.
    received = DensityMatrix(GENERIC_PAYLOAD).evolve(channel)
    expected = (1.0 - p) * np.asarray(
        DensityMatrix(GENERIC_PAYLOAD).data
    ) + p * np.eye(2) / 2.0
    assert np.allclose(received.data, expected, atol=TOL)


@pytest.mark.parametrize("name", ["payload_qubit", "resource_qubits"])
def test_register_indices_reject_booleans(name: str) -> None:
    """``True`` must not silently address qubit 1.

    ``bool`` is a subclass of ``int``, so without the explicit guard
    ``payload_qubit=True`` teleports qubit 1 and returns a perfectly ordinary
    result -- the wrong qubit, with no error anywhere.  Deleting the
    ``isinstance(index, bool)`` clause left the old suite green; it does not
    now.  The analogous guard in ``rng.seed_to_generator`` is already pinned,
    so this closes the pair.
    """
    register = DensityMatrix(
        np.kron(
            np.asarray(as_density(bell_state(BellState.PHI_PLUS)).data),
            np.kron(
                np.eye(2, dtype=complex) / 2.0,
                np.asarray(as_density(GENERIC_PAYLOAD).data),
            ),
        )
    )
    assert register.num_qubits == 4

    arguments: dict[str, object] = {
        "payload_qubit": 0,
        "resource_qubits": (2, 3),
    }
    arguments[name] = True if name == "payload_qubit" else (True, 3)

    with pytest.raises(ValueError, match="bool"):
        teleport_in_register(
            register,
            rng=np.random.default_rng(0),
            **arguments,  # type: ignore[arg-type]
        )
