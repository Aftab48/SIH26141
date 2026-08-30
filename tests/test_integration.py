"""End-to-end integration tests for the Phase 1 quantum core.

The per-module suites pin each function against hand-written values.  This file
does something the others deliberately do not: it drives the *whole stack* --
``paulis`` -> ``states`` -> ``measure`` -> ``teleport`` -- through the public
package surface (:mod:`sih141.core`) rather than through the submodules, and
checks the two properties that every later phase silently assumes.

1.  **Correctness of the protocol on a complete basis of payloads.**  Fidelity
    ``1.0`` for all six Pauli eigenstates, not just for the computational ones.
    :math:`\\{|0\\rangle, |1\\rangle\\}` alone cannot detect a missing or wrong
    ``Z`` correction (both are ``Z`` eigenstates, so ``Z`` acts as a global
    phase on them), and :math:`\\{|0\\rangle, |1\\rangle, |+\\rangle,
    |-\\rangle\\}` alone cannot detect a swapped ``X``/``Z`` pair.  The
    :math:`|\\pm i\\rangle` pair is what makes the set discriminating: the six
    states span the Bloch sphere's three axes, so any non-identity Pauli error
    is visible on at least one of them.

2.  **Uniformity of the Bell-measurement branch.**  For a maximally entangled
    resource the sender's four outcomes are equiprobable at exactly 1/4 for
    *any* payload.  That is the information-theoretic core of the protocol -- it
    is why the two classical bits leak nothing about the payload -- and Phase 3's
    attack detection is a hypothesis test against precisely this distribution.
    A biased sampler would not fail any fidelity assertion (the correction is
    applied per outcome, so every branch still reconstructs the payload) but
    would quietly invalidate every Phase 4/5 statistic.

Both checks run under an explicitly seeded generator (D3), so a failure here is
reproducible rather than a flake.  The statistical bounds are *computed* from
the sample size below, not guessed.
"""

from __future__ import annotations

import math
from collections import Counter

import numpy as np
import pytest

from sih141.core import (
    BELL_ORDER,
    BellState,
    PauliBasis,
    as_density,
    bell_state,
    concurrence,
    correction_bits,
    eigenstate,
    eigenstate_label,
    fidelity,
    pauli_correction,
    purity,
    teleport,
)

TOL = 1e-9

#: The six Pauli eigenstates: the +1 and -1 eigenvectors of X, Y and Z.  These
#: are the endpoints of the three Bloch axes, so they form a state set on which
#: every single-qubit Pauli error is detectable.
PAULI_EIGENSTATES: list[tuple[PauliBasis, int]] = [
    (basis, eigenvalue)
    for basis in (PauliBasis.X, PauliBasis.Y, PauliBasis.Z)
    for eigenvalue in (1, -1)
]

#: Number of teleportation runs in the uniformity test.  Chosen so that the
#: four-sigma band on a frequency estimate is under three percentage points
#: (see :func:`frequency_sigma`), which is tight enough to catch a one-branch
#: bias of the size a real indexing bug produces (25% -> 0% or 50%), while
#: keeping the test to a couple of seconds.
N_RUNS = 4000


def frequency_sigma(n_runs: int, probability: float = 0.25) -> float:
    """Standard deviation of an observed frequency under the null hypothesis.

    Each of the ``n_runs`` Bell measurements is an independent trial, so the
    count of any one outcome is Binomial(``n_runs``, ``probability``) and the
    observed *frequency* has standard deviation
    :math:`\\sqrt{p(1-p)/n}`.

    Parameters
    ----------
    n_runs : int
        Number of independent runs.
    probability : float, optional
        The null-hypothesis probability of the outcome, ``0.25`` here.

    Returns
    -------
    float
        The standard deviation of the observed frequency.
    """
    return math.sqrt(probability * (1.0 - probability) / n_runs)


def chi_square_sf_3dof(statistic: float) -> float:
    """Upper-tail probability of the chi-square distribution with 3 dof.

    Written out in closed form so the test does not depend on SciPy (which is
    not a project dependency) and does not hard-code a quantile from a table.
    For three degrees of freedom,

    .. math::
        \\Pr(X > x) = \\mathrm{erfc}\\!\\left(\\sqrt{x/2}\\right)
                      + \\sqrt{\\tfrac{2x}{\\pi}}\\, e^{-x/2},

    which is the standard result obtained by integrating the chi-square density
    :math:`f(x) = \\sqrt{x/(2\\pi)}\\,e^{-x/2}` by parts.  Three degrees of
    freedom is right for a four-category goodness-of-fit test with no fitted
    parameters.

    Parameters
    ----------
    statistic : float
        The observed chi-square statistic, ``>= 0``.

    Returns
    -------
    float
        The p-value :math:`\\Pr(X > \\texttt{statistic})`.
    """
    if statistic < 0.0:
        raise ValueError(f"chi-square statistic must be non-negative, got {statistic!r}.")
    return math.erfc(math.sqrt(statistic / 2.0)) + math.sqrt(
        2.0 * statistic / math.pi
    ) * math.exp(-statistic / 2.0)


def test_chi_square_sf_matches_known_quantiles() -> None:
    """Sanity-check the closed form against textbook chi-square(3) quantiles.

    A statistical test is only as trustworthy as its critical values, so the
    helper is validated before it is relied on.
    """
    assert chi_square_sf_3dof(0.0) == pytest.approx(1.0, abs=1e-12)
    assert chi_square_sf_3dof(7.815) == pytest.approx(0.05, abs=5e-4)
    assert chi_square_sf_3dof(11.345) == pytest.approx(0.01, abs=5e-4)
    assert chi_square_sf_3dof(16.266) == pytest.approx(0.001, abs=5e-5)


# --------------------------------------------------------------------------- #
# 1. Teleportation of a complete single-qubit basis                            #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("basis", "eigenvalue"),
    PAULI_EIGENSTATES,
    ids=[
        f"{basis.value}{'+' if eigenvalue == 1 else '-'}"
        for basis, eigenvalue in PAULI_EIGENSTATES
    ],
)
def test_teleport_each_pauli_eigenstate_through_a_fresh_resource(
    basis: PauliBasis, eigenvalue: int
) -> None:
    """Every Bloch-axis endpoint teleports with fidelity 1.

    A *fresh* :math:`|\\Phi^{+}\\rangle` is built for each run so that no state
    is silently reused between runs -- the resource is consumed by the protocol,
    and a shared one would let an earlier collapse contaminate a later run.
    """
    payload = eigenstate(basis, eigenvalue)
    label = eigenstate_label(basis, eigenvalue)
    rng = np.random.default_rng(20260141)

    seen: set[BellState] = set()
    for _ in range(64):
        resource = bell_state(BellState.PHI_PLUS)
        # Precondition on the resource, asserted rather than assumed: it must be
        # pure and maximally entangled, or fidelity 1 is not achievable at all.
        assert purity(resource) == pytest.approx(1.0, abs=TOL)
        assert concurrence(resource) == pytest.approx(1.0, abs=TOL)

        result = teleport(payload, resource=resource, rng=rng)

        assert result.fidelity == pytest.approx(1.0, abs=TOL)
        # The dataclass field and an independent recomputation must agree: the
        # reported number is the real one, not a constant.
        assert fidelity(payload, result.received) == pytest.approx(1.0, abs=TOL)
        # The receiver holds a pure state -- the payload itself, not a mixture
        # that merely overlaps it.
        assert purity(result.received) == pytest.approx(1.0, abs=TOL)
        assert np.allclose(
            np.asarray(result.received.data),
            np.asarray(as_density(payload).data),
            atol=1e-9,
        ), label
        # The record is self-consistent end to end.
        assert result.classical_bits == correction_bits(result.bell_outcome)
        assert np.allclose(
            np.asarray(result.payload.data), np.asarray(payload.data), atol=TOL
        )
        seen.add(result.bell_outcome)

    # 64 runs miss all four branches with probability 3 * (3/4)**64 ~ 2e-8, and
    # the seed is fixed, so requiring all four is safe and makes the fidelity
    # assertions above cover every correction in the table.
    assert seen == set(BELL_ORDER), f"{label}: only reached {sorted(s.value for s in seen)}"


def test_every_correction_in_the_table_is_exercised_by_the_eigenstate_sweep() -> None:
    """The six-state sweep really does discriminate all four corrections.

    Guards the *premise* of the test above.  If some correction happened to act
    trivially on all six payloads, the sweep would pass even with that entry
    wrong.  Here we check the contrapositive directly: for each non-identity
    correction there is at least one Pauli eigenstate it visibly moves.
    """
    def moved_states(unitary: np.ndarray) -> list[str]:
        """Eigenstates that ``unitary`` changes, ignoring global phase only.

        The right invariant is the overlap :math:`|\\langle\\psi|U|\\psi\\rangle|`,
        not an elementwise comparison of magnitudes: ``Z`` maps
        :math:`|+\\rangle` to :math:`|-\\rangle`, which has *identical* amplitude
        magnitudes, so a magnitude comparison would wrongly call ``Z`` inert on
        the X axis.
        """
        moved = []
        for basis, eigenvalue in PAULI_EIGENSTATES:
            vector = np.asarray(eigenstate(basis, eigenvalue).data)
            overlap = abs(complex(np.vdot(vector, unitary @ vector)))
            if overlap < 1.0 - 1e-9:
                moved.append(eigenstate_label(basis, eigenvalue))
        return moved

    for which in BELL_ORDER:
        unitary = pauli_correction(which)
        assert unitary.shape == (2, 2)
        moved = moved_states(unitary)
        if which is BellState.PHI_PLUS:
            assert np.allclose(unitary, np.eye(2), atol=TOL)
            assert moved == []
        else:
            # A non-identity Pauli anticommutes with two of the three axes, so
            # it moves exactly the four eigenstates on those two axes -- and
            # moves them to the orthogonal state, the most visible error there
            # is.  Anything less would mean the sweep could not see a wrong
            # entry in the table.
            assert len(moved) == 4, f"{which.value}: moved {moved}"

    # The four corrections are also pairwise distinguishable on this state set:
    # no two of them act identically, so the sweep cannot confuse one for
    # another.
    for first in BELL_ORDER:
        for second in BELL_ORDER:
            if first is second:
                continue
            difference = pauli_correction(first) @ pauli_correction(second).conj().T
            distinguishing = moved_states(difference)
            assert distinguishing, f"{first.value} and {second.value} are indistinguishable"


def test_teleportation_is_reproducible_across_the_whole_stack(
) -> None:
    """Same seed, same sequence of outcomes, bits and fidelities (D3).

    Reproducibility is checked on the *sequence*, not on a single call: a
    generator that was accidentally re-seeded per call would still match on run
    one and diverge afterwards.
    """
    def run(seed: int) -> list[tuple[str, tuple[int, int], float]]:
        rng = np.random.default_rng(seed)
        records = []
        for basis, eigenvalue in PAULI_EIGENSTATES:
            for _ in range(5):
                result = teleport(eigenstate(basis, eigenvalue), rng=rng)
                records.append(
                    (result.bell_outcome.value, result.classical_bits, result.fidelity)
                )
        return records

    assert run(7) == run(7)
    assert run(7) != run(8), "different seeds produced an identical stream"


# --------------------------------------------------------------------------- #
# 2. Uniformity of the sender's Bell-measurement outcome                       #
# --------------------------------------------------------------------------- #


def test_bell_outcomes_are_uniform_over_many_seeded_runs() -> None:
    """All four Bell outcomes occur with frequency 1/4.

    Tolerances are derived, not chosen:

    * Each run is an independent Bernoulli trial per outcome, so an observed
      frequency has standard deviation ``sqrt(p(1-p)/N)`` with ``p = 0.25``.
      With ``N = 4000`` that is about 0.0068, and the per-outcome band used
      below is four of those (~0.0274).  Under the null a single outcome
      breaches a four-sigma band with probability ~6.3e-5, so the chance that
      *any* of the four does is under 3e-4.
    * The four frequencies are not independent (they sum to 1), so the joint
      claim is tested properly with a chi-square goodness-of-fit statistic on
      three degrees of freedom, requiring a p-value above 0.001.

    The seed is fixed, so this is deterministic in practice; the bounds exist so
    that a *genuine* bias -- the kind a ``BELL_ORDER`` off-by-one or a broken
    inverse-CDF sampler produces, which shifts a branch by 25 percentage points,
    i.e. roughly 36 sigma -- is caught with certainty rather than by luck.
    """
    rng = np.random.default_rng(26141)
    payload = eigenstate(PauliBasis.Y, 1)  # off every computational axis

    counts: Counter[BellState] = Counter()
    for _ in range(N_RUNS):
        result = teleport(payload, resource=bell_state(BellState.PHI_PLUS), rng=rng)
        counts[result.bell_outcome] += 1
        # Uniformity must not come at the cost of correctness: every branch
        # still reconstructs the payload exactly.
        assert result.fidelity == pytest.approx(1.0, abs=TOL)

    assert sum(counts.values()) == N_RUNS
    assert set(counts) == set(BELL_ORDER), "a Bell outcome was never produced"

    expected = N_RUNS / 4.0
    sigma = frequency_sigma(N_RUNS)
    band = 4.0 * sigma
    assert band < 0.03, band  # the sample size really is large enough to bind

    for which in BELL_ORDER:
        frequency = counts[which] / N_RUNS
        assert abs(frequency - 0.25) < band, (
            f"{which.value}: frequency {frequency:.4f} is more than 4 sigma "
            f"({band:.4f}) from 0.25 over {N_RUNS} runs"
        )

    statistic = sum(
        (counts[which] - expected) ** 2 / expected for which in BELL_ORDER
    )
    p_value = chi_square_sf_3dof(statistic)
    assert p_value > 1e-3, (
        f"Bell outcomes are not uniform: chi-square {statistic:.3f} on 3 dof, "
        f"p = {p_value:.2e}, counts {[counts[w] for w in BELL_ORDER]}"
    )


def test_bell_outcome_uniformity_is_payload_independent() -> None:
    """The 1/4 distribution holds for every payload, which is why it leaks nothing.

    If the outcome frequencies depended on the payload, the two classical bits
    would carry information about it and the protocol's security argument would
    collapse.  A smaller sample per payload is enough here: the claim under test
    is "no payload is grossly different", and the pooled chi-square over all six
    still has the full sample behind it.

    The per-payload seeds are literals (D3).  They used to be derived from
    ``basis.value.__hash__()``, which under Python's randomised string hashing
    varies from process to process: the pooled chi-square then failed on about
    0.57% of runs (``PYTHONHASHSEED=216`` reproduces it deterministically), so
    the suite was not reproducible inside the very file that enforces D3.  The
    six constants below are the seeds this assertion is calibrated against.
    """
    per_payload = 600
    sigma = frequency_sigma(per_payload)
    band = 5.0 * sigma  # six payloads x four outcomes = 24 comparisons

    payload_seeds = (141_001, 141_002, 141_003, 141_004, 141_005, 141_006)
    assert len(payload_seeds) == len(PAULI_EIGENSTATES)

    pooled: Counter[BellState] = Counter()
    for (basis, eigenvalue), seed in zip(PAULI_EIGENSTATES, payload_seeds):
        rng = np.random.default_rng(seed)
        counts: Counter[BellState] = Counter()
        for _ in range(per_payload):
            result = teleport(eigenstate(basis, eigenvalue), rng=rng)
            counts[result.bell_outcome] += 1
        pooled.update(counts)
        for which in BELL_ORDER:
            frequency = counts[which] / per_payload
            assert abs(frequency - 0.25) < band, (
                f"payload {eigenstate_label(basis, eigenvalue)}, outcome "
                f"{which.value}: frequency {frequency:.4f} outside "
                f"0.25 +/- {band:.4f}"
            )

    total = sum(pooled.values())
    expected = total / 4.0
    statistic = sum((pooled[w] - expected) ** 2 / expected for w in BELL_ORDER)
    assert chi_square_sf_3dof(statistic) > 1e-3, (
        f"pooled Bell outcomes are not uniform: chi-square {statistic:.3f}, "
        f"counts {[pooled[w] for w in BELL_ORDER]}"
    )


def test_classical_bits_are_uniform_and_independent() -> None:
    """Both transmitted bits are unbiased, and neither predicts the other.

    ``(m0, m1)`` is the entire classical channel of the protocol.  Marginal
    uniformity of each bit follows from outcome uniformity, but independence is
    a separate claim and is the one that matters for Phase 2's key material.
    """
    rng = np.random.default_rng(31337)
    runs = 2000
    pairs = Counter(
        teleport(eigenstate(PauliBasis.X, 1), rng=rng).classical_bits
        for _ in range(runs)
    )
    assert set(pairs) == {(0, 0), (1, 0), (0, 1), (1, 1)}

    band = 4.0 * frequency_sigma(runs)
    for pair, count in pairs.items():
        assert abs(count / runs - 0.25) < band, (pair, count)

    m0_ones = sum(count for (m0, _), count in pairs.items() if m0 == 1)
    m1_ones = sum(count for (_, m1), count in pairs.items() if m1 == 1)
    marginal_band = 4.0 * frequency_sigma(runs, 0.5)
    assert abs(m0_ones / runs - 0.5) < marginal_band
    assert abs(m1_ones / runs - 0.5) < marginal_band

    # Independence: Pr(m0=1, m1=1) should match Pr(m0=1) Pr(m1=1).
    joint = pairs[(1, 1)] / runs
    product = (m0_ones / runs) * (m1_ones / runs)
    assert abs(joint - product) < 4.0 * frequency_sigma(runs)


# --------------------------------------------------------------------------- #
# 3. The public package surface                                                #
# --------------------------------------------------------------------------- #


def test_public_api_is_importable_and_complete() -> None:
    """Everything in ``sih141.core.__all__`` resolves, and nothing is a stub.

    Later phases import from :mod:`sih141.core` directly, so a name that is
    listed but not bound would only fail once Phase 2 was already being written.
    """
    import sih141.core as core

    assert core.__all__, "the package exports nothing"
    assert len(set(core.__all__)) == len(core.__all__), "duplicate export name"
    for name in core.__all__:
        assert hasattr(core, name), f"{name} is exported but not bound"
    # No wildcard leakage: the public surface is exactly what is declared, plus
    # dunders and the submodules Python attaches on import.
    submodules = {"paulis", "states", "measure", "rng"}
    leaked = {
        name
        for name in vars(core)
        if not name.startswith("_") and name not in core.__all__ and name not in submodules
    }
    assert not leaked, f"unexported public names leaked into sih141.core: {leaked}"


def test_teleport_name_resolves_to_the_function_not_the_submodule() -> None:
    """The documented overload of the name ``teleport`` behaves as promised.

    ``sih141.core`` re-exports the *function* ``teleport``, which shadows the
    submodule attribute of the same name.  This is deliberate (the function is
    what callers want), but it has one sharp edge that later phases must know
    about, so it is pinned here rather than left to be discovered: the statement
    ``import sih141.core.teleport as x`` binds ``x`` to the **function**, not the
    module, because the ``as`` form performs an attribute lookup on the parent
    package.  ``importlib.import_module`` returns the module regardless, and
    ``from sih141.core.teleport import <member>`` is unaffected because it
    resolves through :data:`sys.modules`.
    """
    import importlib
    import sys

    import sih141.core as core
    from sih141.core.teleport import teleport as teleport_function
    from sih141.core.teleport import teleport_circuit

    assert callable(core.teleport)
    assert core.teleport is teleport_function
    # from-import of a submodule member is unaffected by the shadowing.
    assert teleport_circuit().num_qubits == 3

    # The module itself is still reachable, two documented ways.
    module = importlib.import_module("sih141.core.teleport")
    assert module is sys.modules["sih141.core.teleport"]
    assert module.teleport is core.teleport
    assert module.teleport_circuit().num_qubits == 3

    # ...and the sharp edge, asserted so that it is a documented fact rather
    # than a surprise in Phase 2.
    import sih141.core.teleport as shadowed  # noqa: PLC0414

    assert shadowed is core.teleport
    assert shadowed is not module
